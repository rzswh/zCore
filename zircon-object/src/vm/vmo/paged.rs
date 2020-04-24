use {
    super::*,
    crate::util::block_range::BlockIter,
    alloc::sync::Arc,
    alloc::vec::Vec,
    core::arch::x86_64::{__cpuid, _mm_clflush, _mm_mfence},
    core::ops::Range,
    kernel_hal::{PageTable, PhysFrame, PAGE_SIZE, PHYSMAP_BASE, PHYSMAP_BASE_PHYS},
    spin::Mutex,
};

/// The main VM object type, holding a list of pages.
pub struct VMObjectPaged {
    inner: Mutex<VMObjectPagedInner>,
}

/// The mutable part of `VMObjectPaged`.
struct VMObjectPagedInner {
    parent: Option<Arc<VMObjectPaged>>,
    parent_offset: usize,
    frames: Vec<Option<PhysFrame>>,
    cache_policy: u32,
}

impl VMObjectPaged {
    /// Create a new VMO backing on physical memory allocated in pages.
    pub fn new(pages: usize) -> Arc<Self> {
        let mut frames = Vec::new();
        frames.resize_with(pages, Default::default);

        Arc::new(VMObjectPaged {
            inner: Mutex::new(VMObjectPagedInner {
                parent: None,
                parent_offset: 0usize,
                frames,
                cache_policy: CachePolicy::Cached as u32,
            }),
        })
    }

    /// Helper function to split range into sub-ranges within pages.
    ///
    /// All covered pages will be committed implicitly.
    ///
    /// ```text
    /// VMO range:
    /// |----|----|----|----|----|
    ///
    /// buf:
    ///            [====len====]
    /// |--offset--|
    ///
    /// sub-ranges:
    ///            [===]
    ///                [====]
    ///                     [==]
    /// ```
    ///
    /// `f` is a function to process in-page ranges.
    /// It takes 2 arguments:
    /// * `paddr`: the start physical address of the in-page range.
    /// * `buf_range`: the range in view of the input buffer.
    fn for_each_page(
        &self,
        offset: usize,
        buf_len: usize,
        for_write: bool,
        mut f: impl FnMut(PhysAddr, Range<usize>),
    ) {
        let iter = BlockIter {
            begin: offset,
            end: offset + buf_len,
            block_size_log2: 12,
        };
        for block in iter {
            let paddr = self.inner.lock().get_page(block.block, for_write);
            let buf_range = block.origin_begin() - offset..block.origin_end() - offset;
            f(paddr + block.begin, buf_range);
        }
    }

    fn get_page(&self, page_idx: usize, for_write: bool) -> PhysAddr {
        self.inner.lock().get_page(page_idx, for_write)
    }
}

impl VMObjectTrait for VMObjectPaged {
    fn read(&self, offset: usize, buf: &mut [u8]) {
        self.for_each_page(offset, buf.len(), false, |paddr, buf_range| {
            kernel_hal::pmem_read(paddr, &mut buf[buf_range]);
        });
    }

    fn write(&self, offset: usize, buf: &[u8]) {
        self.for_each_page(offset, buf.len(), true, |paddr, buf_range| {
            kernel_hal::pmem_write(paddr, &buf[buf_range]);
        });
    }

    fn len(&self) -> usize {
        self.inner.lock().frames.len() * PAGE_SIZE
    }

    fn set_len(&self, len: usize) {
        assert!(page_aligned(len));
        // FIXME parent and children? len < old_len?
        let mut inner = self.inner.lock();
        let old_pages = inner.frames.len();
        let new_pages = len / PAGE_SIZE;
        if old_pages < new_pages {
            inner.frames.resize_with(new_pages, Default::default);
            (old_pages..new_pages).for_each(|idx| {
                inner.commit(idx);
            });
        } else if inner.parent.is_none() {
            inner.frames.resize_with(new_pages, Default::default);
            (old_pages..new_pages).for_each(|idx| {
                inner.get_page(idx, true);
            });
        } else {
            unimplemented!()
        }
    }

    fn map_to(
        &self,
        page_table: &mut PageTable,
        vaddr: usize,
        offset: usize,
        len: usize,
        flags: MMUFlags,
    ) {
        let start_page = offset / PAGE_SIZE;
        let pages = len / PAGE_SIZE;
        let mut inner = self.inner.lock();
        for i in 0..pages {
            let paddr = inner.get_page(start_page + i, true);
            page_table
                .map(vaddr + i * PAGE_SIZE, paddr, flags)
                .expect("failed to map");
        }
    }

    fn commit(&self, offset: usize, len: usize) {
        let start_page = offset / PAGE_SIZE;
        let pages = len / PAGE_SIZE;
        let mut inner = self.inner.lock();
        for i in 0..pages {
            inner.commit(start_page + i);
        }
    }

    fn decommit(&self, offset: usize, len: usize) {
        let start_page = offset / PAGE_SIZE;
        let pages = len / PAGE_SIZE;
        let mut inner = self.inner.lock();
        for i in 0..pages {
            inner.decommit(start_page + i);
        }
    }

    fn create_child(&self, offset: usize, len: usize) -> Arc<dyn VMObjectTrait> {
        assert!(page_aligned(offset));
        assert!(page_aligned(len));
        let mut frames = Vec::new();
        let pages = self.len() / PAGE_SIZE;
        let mut inner = self.inner.lock();
        frames.append(&mut inner.frames);
        let old_parent = inner.parent.take();

        // construct hidden_vmo as shared parent
        let hidden_vmo = Arc::new(VMObjectPaged {
            inner: Mutex::new(VMObjectPagedInner {
                parent: old_parent,
                parent_offset: 0usize,
                frames,
                cache_policy: CachePolicy::Cached as u32, // ?
            }),
        });

        // change current vmo's parent
        inner.parent = Some(hidden_vmo.clone());
        inner.frames.resize_with(pages, Default::default);

        // create hidden_vmo's another child as result
        let mut child_frames = Vec::new();
        child_frames.resize_with(len / PAGE_SIZE, Default::default);
        Arc::new(VMObjectPaged {
            inner: Mutex::new(VMObjectPagedInner {
                parent: Some(hidden_vmo),
                parent_offset: offset,
                frames: child_frames,
                cache_policy: inner.cache_policy,
            }),
        })
    }

    fn create_clone(&self, offset: usize, len: usize) -> Arc<dyn VMObjectTrait> {
        assert!(page_aligned(offset));
        assert!(page_aligned(len));
        let frames_offset = pages(offset);
        let clone_size = pages(len);
        let mut frames = Vec::new();
        frames.resize_with(clone_size, || {
            Some(PhysFrame::alloc().expect("faild to alloc frame"))
        });
        let inner = self.inner.lock();
        // TODO: when contiguous implemented
        // if inner.cache_policy != CACHE_POLICY_CACHED && !self.is_contiguous() {
        //     return ZxResult(ZxError::BAD_STATE);
        // }
        // copy physical memory
        for (i, new_frame) in frames.iter().enumerate() {
            if let Some(frame) = &inner.frames[frames_offset + i] {
                kernel_hal::frame_copy(frame.addr(), new_frame.as_ref().unwrap().addr());
            }
        }
        Arc::new(VMObjectPaged {
            inner: Mutex::new(VMObjectPagedInner {
                parent: None,
                parent_offset: offset,
                frames,
                cache_policy: CachePolicy::Cached as u32,
            }),
        })
    }

    fn get_cache_policy(&self) -> u32 {
        self.inner.lock().cache_policy
    }

    fn set_cache_policy(&self, policy: u32) -> ZxResult {
        if (policy & !CACHE_POLICY_MASK) != 0 {
            Err(ZxError::INVALID_ARGS)
        } else {
            // conditions for allowing the cache policy to be set:
            // 1) vmo either has no pages committed currently or is transitioning from being cached
            // 2) vmo has no pinned pages
            // 3) vmo has no mappings
            // 4) vmo has no children
            // 5) vmo is not a child
            let mut inner = self.inner.lock();
            if inner.frames.is_empty() && inner.cache_policy == CachePolicy::Cached as u32 {
                return Err(ZxError::BAD_STATE);
            }
            if let Some(_) = inner.parent {
                return Err(ZxError::BAD_STATE);
            }
            if inner.cache_policy == CachePolicy::Cached as u32
                && policy != CachePolicy::Cached as u32
            {
                for p in inner.frames.iter() {
                    if let Some(p) = p {
                        let addr = p.addr();
                        let physmap_addr =
                            addr - PHYSMAP_BASE_PHYS as usize + PHYSMAP_BASE as usize;
                        clean_invalid_cache(physmap_addr, PAGE_SIZE);
                    }
                }
            }
            inner.cache_policy = policy;
            Ok(())
        }
    }

    // TODO: for vmo_create_contiguous
    // fn is_contiguous(&self) -> bool {
    //     false
    // }
}

impl VMObjectPagedInner {
    fn commit(&mut self, page_idx: usize) -> &PhysFrame {
        self.frames[page_idx]
            .get_or_insert_with(|| PhysFrame::alloc().expect("failed to alloc frame"))
    }

    fn decommit(&mut self, page_idx: usize) {
        self.frames[page_idx] = None;
    }

    fn get_page(&mut self, page_idx: usize, for_write: bool) -> PhysAddr {
        if let Some(frame) = &self.frames[page_idx] {
            return frame.addr();
        }
        let parent_idx_offset = self.parent_offset / PAGE_SIZE;
        if for_write {
            let target_addr = self.commit(page_idx).addr();
            if let Some(parent) = &self.parent {
                // copy on write
                kernel_hal::frame_copy(
                    parent.get_page(parent_idx_offset + page_idx, false),
                    target_addr,
                );
            } else {
                // zero the page
                kernel_hal::pmem_write(target_addr, &[0u8; PAGE_SIZE]);
            }
            target_addr
        } else if let Some(parent) = &self.parent {
            parent.get_page(parent_idx_offset + page_idx, false)
        } else {
            self.commit(page_idx).addr()
        }
    }
}

// sse2
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub fn clean_invalid_cache(addr: usize, len: usize) {
    let clsize = unsafe { get_cacheline_flush_size() };
    let end = addr + len;
    let mut start = addr & !(clsize - 1);
    while start < end {
        unsafe {
            _mm_clflush(start as *const u8);
        }
        start = start + PAGE_SIZE;
    }
    unsafe {
        _mm_mfence();
    }
}

#[allow(unsafe_code)]
unsafe fn get_cacheline_flush_size() -> usize {
    let leaf = __cpuid(1).ebx;
    (((leaf >> 8) & 0xff) << 3) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write() {
        let vmo = VmObject::new_paged(2);
        super::super::tests::read_write(&*vmo);
    }

    #[test]
    fn create_child() {
        let vmo = VmObject::new_paged(10);
        vmo.write(0, &[1, 2, 3, 4]);
        let mut buf = [0u8; 4];
        vmo.read(0, &mut buf);
        assert_eq!(&buf, &[1, 2, 3, 4]);
        let child_vmo = vmo.create_child(0, 4 * 4096);
        child_vmo.read(0, &mut buf);
        assert_eq!(&buf, &[1, 2, 3, 4]);
        child_vmo.write(0, &[6, 7, 8, 9]);
        vmo.read(0, &mut buf);
        assert_eq!(&buf, &[1, 2, 3, 4]);
        child_vmo.read(0, &mut buf);
        assert_eq!(&buf, &[6, 7, 8, 9]);
    }
}

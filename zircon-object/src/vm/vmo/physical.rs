#[allow(unused_imports)]
use core::convert::TryFrom;
use {super::*, alloc::sync::Arc, spin::Mutex};

/// VMO representing a physical range of memory.
pub struct VMObjectPhysical {
    paddr: PhysAddr,
    pages: usize,
    /// Lock this when access physical memory.
    data_lock: Mutex<()>,
    inner: Mutex<VMObjectPhysicalInner>,
}

struct VMObjectPhysicalInner {
    mapping_count: u32,
    cache_policy: u32,
}

impl VMObjectPhysicalInner {
    pub fn new() -> VMObjectPhysicalInner {
        VMObjectPhysicalInner {
            mapping_count: 0,
            cache_policy: CachePolicy::Uncached as u32,
        }
    }
}

impl VMObjectPhysical {
    /// Create a new VMO representing a piece of contiguous physical memory.
    ///
    /// # Safety
    ///
    /// You must ensure nobody has the ownership of this piece of memory yet.
    #[allow(unsafe_code)]
    pub unsafe fn new(paddr: PhysAddr, pages: usize) -> Arc<Self> {
        assert!(page_aligned(paddr));
        Arc::new(VMObjectPhysical {
            paddr,
            pages,
            data_lock: Mutex::default(),
            inner: Mutex::new(VMObjectPhysicalInner::new()),
        })
    }
}

impl VMObjectTrait for VMObjectPhysical {
    fn read(&self, offset: usize, buf: &mut [u8]) {
        let _ = self.data_lock.lock();
        assert!(offset + buf.len() <= self.len());
        kernel_hal::pmem_read(self.paddr + offset, buf);
    }

    fn write(&self, offset: usize, buf: &[u8]) {
        let _ = self.data_lock.lock();
        assert!(offset + buf.len() <= self.len());
        kernel_hal::pmem_write(self.paddr + offset, buf);
    }

    fn len(&self) -> usize {
        self.pages * PAGE_SIZE
    }

    fn set_len(&self, _len: usize) {
        unimplemented!()
    }

    fn map_to(
        &self,
        page_table: &mut PageTable,
        vaddr: usize,
        offset: usize,
        len: usize,
        flags: MMUFlags,
    ) {
        let pages = len / PAGE_SIZE;
        let mut inner = self.inner.lock();
        inner.mapping_count += 1;
        page_table
            .map_cont(vaddr, self.paddr + offset, pages, flags)
            .expect("failed to map")
    }

    fn unmap_from(&self, page_table: &mut PageTable, vaddr: VirtAddr, _offset: usize, len: usize) {
        let mut inner = self.inner.lock();
        inner.mapping_count -= 1;
        // TODO _offset unused?
        let pages = len / PAGE_SIZE;
        page_table
            .unmap_cont(vaddr, pages)
            .expect("failed to unmap")
    }

    // TODO empty function should be denied
    fn commit(&self, _offset: usize, _len: usize) {
        unimplemented!()
    }

    fn decommit(&self, _offset: usize, _len: usize) {
        unimplemented!()
    }

    fn create_child(&self, _offset: usize, _len: usize) -> Arc<dyn VMObjectTrait> {
        unimplemented!()
    }

    fn create_clone(&self, _offset: usize, _len: usize) -> Arc<dyn VMObjectTrait> {
        unimplemented!()
    }

    fn get_cache_policy(&self) -> u32 {
        let inner = self.inner.lock();
        inner.cache_policy
    }

    fn set_cache_policy(&self, policy: u32) -> ZxResult {
        if (policy & !CACHE_POLICY_MASK) != 0 {
            Err(ZxError::INVALID_ARGS)
        } else {
            let mut inner = self.inner.lock();
            if inner.cache_policy == policy {
                Ok(())
            } else {
                // if (mapping_list_len_ != 0 || children_list_len_ != 0 || parent_)
                inner.cache_policy = policy;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]
    #[allow(unused_imports)]
    use super::vmar::*;
    use super::*;
    use kernel_hal::CachePolicy;

    #[test]
    fn read_write() {
        let vmo = unsafe { VmObject::new_physical(0x1000, 2) };
        let vmphy = vmo.inner.clone();
        assert_eq!(
            CachePolicy::try_from(vmphy.get_cache_policy()).unwrap(),
            CachePolicy::Uncached
        );
        super::super::tests::read_write(&vmo);
    }

    // #[test]
    // fn cache_test() -> ZxResult {
    //     let cache_policy_flags = CachePolicy::UncachedDevice.into();
    //     let vmo = unsafe { VmObject::new_physical(0x1000, 2) };
    //     // Test that changing policy while mapped is blocked
    //     let vmar = VmAddressRegion::new(None, 0x0, 0x1000000, VmarFlags::ROOT_FLAGS);
    //     let addr = vmar.map(
    //         None,
    //         vmo.clone(),
    //         0,
    //         (*vmo).len(),
    //         MMUFlags::READ | MMUFlags::WRITE,
    //     )?;
    //     let vmphy = (*vmo).inner.clone();
    //     if let Err(msg) = vmphy.set_cache_policy(cache_policy_flags) {
    //         assert_eq!(msg, ZxError::BAD_STATE);
    //     } else {
    //         return Err(ZxError::CANCELED);
    //     }
    //     vmar.unmap(addr, (*vmo).len())?;
    //     vmphy.set_cache_policy(cache_policy_flags)?;
    //     let addr = vmar.map(
    //         None,
    //         vmo.clone(),
    //         0,
    //         (*vmo).len(),
    //         MMUFlags::READ | MMUFlags::WRITE,
    //     )?;
    //     vmar.unmap(addr, (*vmo).len())?;
    //     Ok(())
    // }
}

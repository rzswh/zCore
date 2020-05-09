#![allow(warnings)]
use {
    crate::object::*,
    alloc::sync::Arc,
    spin::Mutex,
    bitflags::bitflags,
    crate::signal::*,
};

// Interrupt refers to virtual_interrupt in zircon
pub struct Interrupt {
    base: KObjectBase,
    hasvcpu: bool,
    inner: Mutex<InterruptInner>,
}

pub trait InterruptTrait {
    fn mask_interrupt(&self);
}


struct InterruptInner {
    state: InterruptState,
    port: Option<Arc<Port>>,
    key: u64,
    timestamp: i64,
    defer_unmask: bool,
    packet_id: u64,
    flags: InterruptFlags,
}

impl_kobject!(Interrupt);

impl Interrupt {
    pub fn create() -> Arc<Self> {
        // virtual_interrupt, should be rewriten to trait later
        Arc::new(Interrupt {
            base: KObjectBase::new(),
            hasvcpu: false,
            inner: Mutex::new(InterruptInner {
                state: InterruptState::IDLE,
                port: Option::None,
                key: 0,
                timestamp: 0,
                defer_unmask: false,
                packet_id: 0,
                flags: InterruptFlags::VIRTUAL,
            })
        })
    }

    pub fn bind(&self, port: Arc<Port>, key: u64) -> ZxResult {
        let mut inner = self.inner.lock();
        match inner.state {
            InterruptState::DESTORY => return Err(ZxError::CANCELED),
            InterruptState::WAITING => return Err(ZxError::BAD_STATE),
            _ => (),
        }
        if inner.port.is_some() || self.hasvcpu {
            return Err(ZxError::ALREADY_BOUND);
        }
        if inner.flags.contains(InterruptFlags::UNMASK_PREWAIT_UNLOCKED | InterruptFlags::MASK_POSTWAIT) {
            return Err(ZxError::INVALID_ARGS);
        }
        inner.port = Some(port.clone());
        inner.key = key;
        if inner.state == InterruptState::TRIGGERED {
            inner.packet_id = port.as_ref().push_interrupt(inner.timestamp, inner.key);
            inner.state = InterruptState::NEEDACK;
        }
        Ok(())
    }

    pub fn unbind(&self, port: Arc<Port>) -> ZxResult {
        unimplemented!();
        Ok(())
    }

    pub fn trigger(&self, timestamp: i64) -> ZxResult {
        let mut inner = self.inner.lock();
        if !inner.flags.contains(InterruptFlags::VIRTUAL) {
            return Err(ZxError::BAD_STATE);
        }
        if inner.timestamp == 0 {
            inner.timestamp = timestamp;
        }
        if inner.state == InterruptState::DESTORY {
            return Err(ZxError::CANCELED);
        }
        if (inner.state == InterruptState::NEEDACK && inner.port.is_some()) {
            return Ok(());
        }
        if let Some(port) = &inner.port {
            inner.packet_id = port.as_ref().push_interrupt(timestamp, inner.key);
            if inner.flags.contains(InterruptFlags::MASK_POSTWAIT) {
                self.mask_interrupt_locked();
            }
            inner.timestamp = 0;
            inner.state = InterruptState::NEEDACK;
        } else {
            inner.state = InterruptState::TRIGGERED;
            unimplemented!(); // Signal() in zircon
        }
        Ok(())
    }

    pub fn ack(&self) -> ZxResult {
        let mut inner = self.inner.lock();
        if inner.port.is_none() {
            return Err(ZxError::BAD_STATE);
        }
        if inner.state == InterruptState::DESTORY {
            return Err(ZxError::CANCELED);
        }
        if inner.state == InterruptState::NEEDACK {
            if inner.flags.contains(InterruptFlags::UNMASK_PREWAIT) {
                self.unmask_interrupt_locked();
            } else if inner.flags.contains(InterruptFlags::UNMASK_PREWAIT_UNLOCKED) {
                inner.defer_unmask = true;
            }
            if inner.timestamp > 0 {
                // TODO: use a function to send the package
                inner.packet_id = inner.port.as_ref().unwrap().as_ref().push_interrupt(inner.timestamp, inner.key);
                if inner.flags.contains(InterruptFlags::MASK_POSTWAIT) {
                    self.mask_interrupt_locked();
                }
                inner.timestamp = 0;
            } else {
                inner.state = InterruptState::IDLE; 
            }
        }
        if inner.defer_unmask {
            self.unmask_interrupt_locked();
        }
        Ok(())
    }

    pub fn destroy(&self) -> ZxResult {
        // WARNING: a simplified version, the packet should be removed from port.
        self.mask_interrupt_locked();
        self.unregister_interrupt_handler();
        let mut inner = self.inner.lock();
        if let Some(port) = &inner.port {
            let in_queue = port.remove_interrupt(inner.packet_id);
            warn!("state {:?} in_queue {:?} packet_id {:?}", inner.state, in_queue, inner.packet_id);
            match inner.state {
                InterruptState::NEEDACK => {
                    inner.state = InterruptState::DESTORY;
                    if !in_queue { Err(ZxError::NOT_FOUND) } else { Ok(()) }
                }

                InterruptState::IDLE => {
                    inner.state = InterruptState::DESTORY;
                    Ok(())
                }

                _ => Ok(())
            }
        } else {
            inner.state = InterruptState::DESTORY;
            // Signal() in zircon
            Ok(())
        }
    }

    // empty function in VirtualInterruptDispatcher of zircon
    // should be rewritten to trait later
    pub fn mask_interrupt_locked(&self) {}
    pub fn unmask_interrupt_locked(&self) {}
    pub fn unregister_interrupt_handler(&self) {} 
}

#[derive(PartialEq, Debug)]
enum InterruptState {
    WAITING = 0,
    DESTORY = 1,
    TRIGGERED = 2,
    NEEDACK = 3,
    IDLE = 4,
}

bitflags! {
    pub struct InterruptFlags: u32 {
        #[allow(clippy::identity_op)]
        const VIRTUAL                  = 1 << 0;
        const UNMASK_PREWAIT           = 1 << 1;
        const UNMASK_PREWAIT_UNLOCKED  = 1 << 2;
        const MASK_POSTWAIT            = 1 << 4;
    }
}
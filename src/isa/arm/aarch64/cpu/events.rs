//! Stable per-PE event latch shared with the owning software platform.
use super::AArch64Cpu;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

impl AArch64Cpu {
    pub(crate) fn event_pending(&self) -> bool {
        self.event_register.load(Ordering::Acquire)
    }

    pub(super) fn set_event(&self) {
        self.event_register.store(true, Ordering::Release);
    }

    pub(super) fn clear_event(&self) {
        self.event_register.store(false, Ordering::Release);
    }

    pub(super) fn take_event(&self) -> bool {
        self.event_register.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn event_register_handle(&self) -> Arc<AtomicBool> {
        self.event_register.clone()
    }

    /// Bind a prepared CPU without publishing its saved latch value.
    pub(crate) fn bind_event_register(&mut self, handle: Arc<AtomicBool>) {
        self.event_register = handle;
    }
}

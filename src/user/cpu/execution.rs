//! CPU-local admission state, separate from architectural registers.

use std::sync::atomic::{AtomicU64, Ordering};

use super::arm::A32AddressSpace;

pub(crate) struct Entry {
    consumer: u64,
    epoch: Option<u64>,
}

impl Entry {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let consumer = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("CPU admission identities exhausted");
        Self {
            consumer,
            epoch: None,
        }
    }

    /// Returns whether caches and local reservations belong to an earlier
    /// execution generation. A fresh CPU has no retained cache to discard.
    pub(crate) fn enter(&mut self, space: &impl A32AddressSpace) -> Result<bool, String> {
        if let Some(error) = space.fatal_error() {
            return Err(error);
        }
        let epoch = space.execution_epoch(self.consumer)?;
        let changed = self.epoch.is_some_and(|previous| previous != epoch);
        self.epoch = Some(epoch);
        Ok(changed)
    }
}

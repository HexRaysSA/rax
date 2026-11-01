//! VM lifetime and exclusion shared by every permanent Intel vCPU owner.
use super::{bindings::*, native_memory};
use crate::backend::CheckpointBoundary;
use crate::error::{Error, Result};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

#[derive(Default)]
pub(super) struct Lifetime {
    pub(super) quiescence: RwLock<()>,
    pub(super) memory_layout: native_memory::Shared,
    pub(super) pending_irqs: Mutex<Vec<u32>>,
    pub(super) cpus: Mutex<BTreeSet<u32>>,
    pub(super) configured: Mutex<Option<(u8, u64)>>,
    pub(super) capture_clock: AtomicU64,
    pub(super) resume_clock: Mutex<Option<u64>>,
    failure: Mutex<Option<String>>,
}

impl Lifetime {
    pub(super) fn ready(&self) -> Result<()> {
        self.failure
            .lock()
            .map_err(|_| Error::Emulator("Intel HVF lifetime failure latch poisoned".into()))?
            .clone()
            .map_or(Ok(()), |error| Err(Error::Emulator(error)))
    }

    pub(super) fn poison(&self, reason: String) {
        if let Ok(mut failure) = self.failure.lock() {
            if failure.is_none() {
                *failure = Some(format!("Intel HVF VM entry/capture prohibited: {reason}"));
            }
        }
    }

    pub(super) fn identity(&self) -> usize {
        self as *const Self as usize
    }

    pub(super) fn stopped(&self) -> Result<CheckpointBoundary<'_>> {
        let guard = self
            .quiescence
            .write()
            .map_err(|_| Error::Emulator("Intel HVF exclusion lock poisoned".into()))?;
        self.ready()?;
        self.capture_clock
            .store(super::intel_clock::Api::load()?.now(), Ordering::Release);
        Ok(CheckpointBoundary::held(self.identity(), guard))
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        // SAFETY: the final Arc proves that all public VM/CPU owners are gone.
        // CPU owners join before releasing their lifetime. Registered RAM is
        // still retained until successful SDK VM destruction below.
        let result = unsafe { hv_vm_destroy() };
        if result != HV_SUCCESS {
            tracing::warn!(
                "Intel HVF VM destruction failed: {}",
                hv_error_string(result)
            );
            // The SDK may retain mappings after failure. Quarantine their
            // backing instead of leaving it pointing at freed host memory.
            if let Some(mapping) = self
                .memory_layout
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                std::mem::forget(mapping);
            }
        }
    }
}

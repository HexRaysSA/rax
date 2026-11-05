//! One native CPU owner and VM-wide exclusion for entry and state publication.
//! Admission gate precedes VM exclusion, profile/membership, then one CPU core.
//! Writers release VM exclusion before reopening admission to readers.
//! Device callbacks run after the CPU guard and entry lease have been released.
use super::{KvmVcpu, MemoryOwner, NativeCore};
use crate::backend::CheckpointBoundary;
use crate::error::{Error, Result};
use kvm_ioctls::VcpuFd;
use std::ops::Deref;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, RwLockReadGuard, RwLockWriteGuard};

struct WriterIntent<'a> {
    owner: &'a MemoryOwner,
}

/// Retained through the first native attempt. Release exclusion before
/// reopening readers, matching the ordinary checkpoint boundary.
pub(super) struct ExclusiveEntry<'a> {
    _exclusion: RwLockWriteGuard<'a, ()>,
    _intent: WriterIntent<'a>,
}

impl Drop for WriterIntent<'_> {
    fn drop(&mut self) {
        let mut writers = match self.owner.waiting_writers.lock() {
            Ok(writers) => writers,
            Err(poisoned) => {
                self.owner.poisoned.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        };
        match writers.checked_sub(1) {
            Some(remaining) => *writers = remaining,
            None => {
                self.owner.poisoned.store(true, Ordering::Release);
                *writers = 0;
            }
        }
        if *writers == 0 {
            self.owner.entry_ready.notify_all();
        }
    }
}

impl MemoryOwner {
    pub(super) fn exclusive_entry(&self) -> Result<ExclusiveEntry<'_>> {
        let intent = self.writer_intent()?;
        let exclusion = self.exclusion.write().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM resume exclusion poisoned; guest entry disabled".into())
        })?;
        self.ready()?;
        Ok(ExclusiveEntry {
            _exclusion: exclusion,
            _intent: intent,
        })
    }

    fn writer_intent(&self) -> Result<WriterIntent<'_>> {
        let mut writers = self.waiting_writers.lock().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM entry gate poisoned; guest entry disabled".into())
        })?;
        self.ready()?;
        *writers = writers
            .checked_add(1)
            .ok_or_else(|| Error::Emulator("native KVM checkpoint writer count overflow".into()))?;
        Ok(WriterIntent { owner: self })
    }

    pub(super) fn ready(&self) -> Result<()> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(Error::Emulator(
                "native KVM owner is unavailable; guest entry disabled".into(),
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn entry(&self) -> Result<RwLockReadGuard<'_, ()>> {
        // RwLock does not guarantee writer fairness. Prevent a public run
        // loop from repeatedly reacquiring a reader lease before a woken
        // checkpoint writer can acquire exclusion. Sleep while writers wait
        // or hold their boundary; do not spin during long checkpoint work.
        let mut writers = self.waiting_writers.lock().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM entry gate poisoned; guest entry disabled".into())
        })?;
        loop {
            self.ready()?;
            if *writers == 0 {
                break;
            }
            writers = self.entry_ready.wait(writers).map_err(|_| {
                self.poisoned.store(true, Ordering::Release);
                Error::Emulator("native KVM entry gate poisoned; guest entry disabled".into())
            })?;
        }
        let lease = self.exclusion.read().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM exclusion lock poisoned; guest entry disabled".into())
        })?;
        drop(writers);
        self.ready()?;
        Ok(lease)
    }

    pub(super) fn identity(&self) -> usize {
        self as *const Self as usize
    }

    /// Called after the device callback, with no CPU guard or entry lease.
    /// Reject new work immediately, then wait for every managed entry to yield.
    pub(super) fn power_off(&self) -> Result<()> {
        self.powered_off.store(true, Ordering::Release);
        let _intent = self.writer_intent()?;
        let _exclusion = self.exclusion.write().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM power-off exclusion lock poisoned".into())
        })?;
        self.ready()
    }

    pub(super) fn boundary(&self, count: Option<u8>) -> Result<CheckpointBoundary<'_>> {
        let intent = self.writer_intent()?;
        let exclusion = self.exclusion.write().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM exclusion lock poisoned; guest entry disabled".into())
        })?;
        self.ready()?;
        if self.external_vm_access.load(Ordering::Acquire) {
            return Err(Error::InvalidConfig(
                "native checkpoint includes unmanaged SDK VM access".into(),
            ));
        }
        if self.sdk_cpus.load(Ordering::Acquire) != 0 {
            return Err(Error::InvalidConfig(
                "native checkpoint includes externally created SDK CPU IDs".into(),
            ));
        }
        let registry = self
            .managed_cpus
            .lock()
            .map_err(|_| Error::Emulator("native KVM CPU membership lock poisoned".into()))?;
        let count = count.ok_or_else(|| {
            Error::InvalidConfig("native checkpoint CPU topology is not configured".into())
        })?;
        if registry.len() != usize::from(count) || registry.keys().copied().ne(0..u32::from(count))
        {
            return Err(Error::InvalidConfig(
                "native checkpoint CPU membership is incomplete".into(),
            ));
        }
        let cpus = registry
            .values()
            .map(|cpu| {
                cpu.upgrade().ok_or_else(|| {
                    Error::InvalidConfig("native checkpoint CPU owner was destroyed".into())
                })
            })
            .collect::<Result<Vec<_>>>()?;
        drop(registry);
        // Pin every FD for the lease even if an external wrapper is dropped.
        // Field order releases exclusion before reopening reader admission
        // and before dropping the retained cores.
        struct Held<'a> {
            _exclusion: RwLockWriteGuard<'a, ()>,
            _intent: WriterIntent<'a>,
            _cpus: Vec<Arc<Mutex<NativeCore>>>,
        }
        Ok(CheckpointBoundary::held(
            self.identity(),
            Held {
                _exclusion: exclusion,
                _intent: intent,
                _cpus: cpus,
            },
        ))
    }
}

/// A retained native descriptor borrowed under both VM and CPU exclusion.
/// Mutable run-buffer access remains owned by the managed adapter.
pub struct NativeVcpuFd<'a> {
    _exclusion: RwLockReadGuard<'a, ()>,
    core: MutexGuard<'a, NativeCore>,
}

impl Deref for NativeVcpuFd<'_> {
    type Target = VcpuFd;
    fn deref(&self) -> &VcpuFd {
        &self.core.vcpu_fd
    }
}

impl KvmVcpu {
    pub(super) fn with_checkpoint<T>(
        &self,
        boundary: &CheckpointBoundary<'_>,
        operation: impl FnOnce(&mut NativeCore) -> Result<T>,
    ) -> Result<T> {
        boundary.require_owner(self.memory_owner.identity())?;
        self.memory_owner.ready()?;
        let mut core = self.core.lock().map_err(|_| {
            self.memory_owner.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM CPU owner lock poisoned; guest entry disabled".into())
        })?;
        operation(&mut core)
    }

    pub(super) fn with_native<T>(
        &self,
        operation: impl FnOnce(&mut NativeCore) -> Result<T>,
    ) -> Result<T> {
        let _entry = self.memory_owner.entry()?;
        let mut core = self.core.lock().map_err(|_| {
            self.memory_owner.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM CPU owner lock poisoned; guest entry disabled".into())
        })?;
        operation(&mut core)
    }

    /// Borrow the SDK descriptor while retaining VM and CPU exclusion.
    ///
    /// # Safety
    /// The caller must preserve the managed adapter's pending I/O and native
    /// run/signal-mask invariants when issuing SDK setters. Raw FD aliases must
    /// not outlive this guard or bypass checkpoint exclusion. No pointer into
    /// the run mapping may escape. Prefer the managed VCpu API for state/entry.
    pub unsafe fn vcpu_fd(&self) -> Result<NativeVcpuFd<'_>> {
        let exclusion = self.memory_owner.entry()?;
        let core = self.core.lock().map_err(|_| {
            self.memory_owner.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM CPU owner lock poisoned; guest entry disabled".into())
        })?;
        Ok(NativeVcpuFd {
            _exclusion: exclusion,
            core,
        })
    }
}

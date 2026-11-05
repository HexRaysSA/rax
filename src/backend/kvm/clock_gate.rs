//! A restored common clock starts at managed entry, after stopped publication.
use super::{KvmVcpu, MemoryOwner, NativeCore, deadline};
use crate::error::{Error, Result};
use crate::vm::timing::TimingContext;
use crate::vm::vcpu::VcpuExit;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

pub(super) struct PendingClock {
    pub(super) native: super::checkpoint::ClockImage,
    pub(super) devices: Option<(Arc<TimingContext>, u64)>,
}

impl PendingClock {
    pub(super) fn validate_device_phase(&self) -> Result<()> {
        if let Some((devices, nanos)) = &self.devices
            && !devices.is_stopped_at(*nanos)
        {
            return Err(invalid("staged device clock phase changed before entry"));
        }
        Ok(())
    }

    /// A new restoration may replace the saved phase, but cannot detach the
    /// still-stopped software clock or transfer it to an unrelated VM owner.
    pub(super) fn validate_device_owner(&self, next: Option<&Arc<TimingContext>>) -> Result<()> {
        if let Some((owner, _)) = &self.devices
            && !next.is_some_and(|next| Arc::ptr_eq(owner, next))
        {
            return Err(invalid("staged device clock owner cannot be replaced"));
        }
        Ok(())
    }
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("native KVM first entry: {message}"))
}

impl MemoryOwner {
    pub(super) fn resume_clock_pending(&self) -> Result<bool> {
        self.resume_clock
            .lock()
            .map(|clock| clock.is_some())
            .map_err(|_| {
                self.poisoned.store(true, Ordering::Release);
                invalid("resume clock lock poisoned; guest entry disabled")
            })
    }
}

impl KvmVcpu {
    fn run_core(&self) -> Result<MutexGuard<'_, NativeCore>> {
        self.core.lock().map_err(|_| {
            self.memory_owner.poisoned.store(true, Ordering::Release);
            Error::Emulator("native KVM CPU owner lock poisoned; guest entry disabled".into())
        })
    }

    pub(super) fn run_native_host_slice(&self, limit: Duration) -> Result<Option<VcpuExit>> {
        let entry = self.memory_owner.entry()?;
        let mut core = self.run_core()?;
        if !self.memory_owner.resume_clock_pending()? || !core.will_enter_native()? {
            return core.run_host_slice(limit);
        }
        // Never upgrade a read lock while retaining it or a CPU guard.
        drop(core);
        drop(entry);
        let _exclusive = self.memory_owner.exclusive_entry()?;
        let mut core = self.run_core()?;
        // A competing entry may already have consumed the epoch, or a stopped
        // writer may have changed this CPU into a non-entry state.
        if self.memory_owner.resume_clock_pending()? && core.will_enter_native()? {
            deadline::run_at_resume(&mut core, limit)
        } else {
            core.run_host_slice(limit)
        }
    }
}

impl NativeCore {
    fn will_enter_native(&self) -> Result<bool> {
        if self.memory_owner.powered_off.load(Ordering::Acquire)
            || self.userspace_halted
            || self.deferred_exit.is_some()
        {
            return Ok(false);
        }
        self.state_ready()?;
        // Returning an owned request does not enter KVM. Missing input replies
        // still fail in the ordinary entry validator without consuming phase.
        Ok(self.io.event().map_err(Error::Emulator)?.is_none())
    }

    /// Only the private deadline worker calls this, while its parent retains
    /// VM write exclusion and this CPU's guard. All other managed CPU guards
    /// are therefore free: ordinary SDK borrows and state operations retain a
    /// VM read lease before taking a CPU guard. This exceptional all-CPU path
    /// may lock the selected CPU first without a competing lock-order cycle.
    pub(super) fn activate_resume_clock(&mut self) -> Result<()> {
        let owner = self.memory_owner.clone();
        let result = (|| {
            owner.ready()?;
            if owner.sdk_cpus.load(Ordering::Acquire) != 0
                || owner.external_vm_access.load(Ordering::Acquire)
            {
                return Err(invalid("unmanaged descriptors changed the resume owner"));
            }
            let mut pending = owner
                .resume_clock
                .lock()
                .map_err(|_| invalid("resume clock lock poisoned"))?;
            let Some(clock) = pending.as_ref() else {
                return Ok(());
            };
            clock.validate_device_phase()?;
            let handles = owner
                .managed_cpus
                .lock()
                .map_err(|_| invalid("CPU membership lock poisoned"))?
                .iter()
                .map(|(&id, handle)| {
                    handle
                        .upgrade()
                        .map(|handle| (id, handle))
                        .ok_or_else(|| invalid("a managed CPU was destroyed before first entry"))
                })
                .collect::<Result<Vec<_>>>()?;
            if !handles.iter().any(|(id, _)| *id == self.id) {
                return Err(invalid("entering CPU is absent from the managed graph"));
            }
            let mut peers = Vec::with_capacity(handles.len().saturating_sub(1));
            for (id, handle) in &handles {
                if *id != self.id {
                    let peer = handle
                        .lock()
                        .map_err(|_| invalid("peer CPU owner poisoned"))?;
                    if peer.id != *id {
                        return Err(invalid("peer identity differs from its registry key"));
                    }
                    peers.push(peer);
                }
            }
            let khz = self
                .native_tsc_khz
                .filter(|khz| *khz != 0)
                .ok_or_else(|| invalid("native TSC rate was unavailable at CPU creation"))?;
            for core in std::iter::once(&*self).chain(peers.iter().map(|core| &**core)) {
                core.state_ready()?;
                if core.native_tsc_khz != Some(khz)
                    || core.servicing_io
                    || core.native_io_unsettled
                    || core.io.has_native_completion()
                {
                    return Err(invalid(
                        "CPU rate or in-flight ownership changed before resume",
                    ));
                }
                // A peer's owned direct result awaits userspace delivery; it
                // neither enters KVM nor holds a native completion buffer.
                super::checkpoint::DeferredImage::capture(core.deferred_exit.as_ref())?;
            }
            let mut descriptors = Vec::with_capacity(handles.len());
            descriptors.push((self.id, &self.vcpu_fd));
            descriptors.extend(peers.iter().map(|core| (core.id, &core.vcpu_fd)));
            descriptors.sort_unstable_by_key(|(id, _)| *id);
            let applied = clock
                .native
                .restore_at_resume(&owner.vm_fd, &descriptors, khz)
                .map_err(invalid)?;
            if let Some((devices, _)) = &clock.devices
                && !devices.resume_wall_at(applied.resume_instant)
            {
                return Err(invalid("staged device clock was resumed independently"));
            }
            // Keep the canonical record on every failure, and remove it only
            // after all offsets and the common VM clock have been published.
            *pending = None;
            Ok(())
        })();
        if result.is_err() {
            // Native setters can have changed a prefix. No other CPU may
            // enter after an incomplete common-epoch activation.
            owner.poisoned.store(true, Ordering::Release);
        }
        result
    }
}

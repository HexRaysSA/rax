//! Actual managed-owner admission for the native CPU and common clock banks.
//!
//! This is an internal composition layer. PIT/timer state, terminal I/O,
//! physical RAM publication, rollback and first-entry
//! activation belong to the complete producer; public snapshot hooks remain
//! inactive until those components are composed.
use super::{bounded, clock, cpu, deferred, shared};
use crate::backend::CheckpointBoundary;
use crate::backend::kvm::{KvmVm, NativeCore};
use crate::error::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::backend::kvm) struct Image {
    version: u16,
    #[serde(deserialize_with = "cpu_images")]
    cpus: Vec<cpu::Image>,
    #[serde(deserialize_with = "deferred_images")]
    deferred: Vec<Option<deferred::Image>>,
    powered_off: bool,
    #[serde(deserialize_with = "terminal_images")]
    terminal: Vec<Option<super::super::io::TerminalImage>>,
    clock: clock::Image,
    shared: Option<shared::Image>,
}

fn cpu_images<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<cpu::Image>, D::Error> {
    bounded::sequence::<_, _, { u8::MAX as usize }>(deserializer)
}

fn deferred_images<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Option<deferred::Image>>, D::Error> {
    bounded::sequence::<_, _, { u8::MAX as usize }>(deserializer)
}

fn terminal_images<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Option<super::super::io::TerminalImage>>, D::Error> {
    bounded::sequence::<_, _, { u8::MAX as usize }>(deserializer)
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("managed native checkpoint banks: {message}"))
}

fn ready(core: &NativeCore) -> Result<()> {
    core.state_ready()?;
    if core.servicing_io {
        return Err(invalid("device callback is still active"));
    }
    if (core.native_io_unsettled || core.io.has_native_completion())
        && !core.memory_owner.powered_off.load(Ordering::Acquire)
    {
        return Err(invalid("pending native I/O needs its complete producer"));
    }
    core.io.capture_terminal().map_err(invalid)?;
    deferred::Image::capture(core.deferred_exit.as_ref())?;
    Ok(())
}

fn native_rate(cpus: &[MutexGuard<'_, NativeCore>]) -> Result<u32> {
    let first = cpus
        .first()
        .and_then(|cpu| cpu.native_tsc_khz)
        .filter(|khz| *khz != 0)
        .ok_or_else(|| invalid("native TSC rate was unavailable at CPU creation"))?;
    if cpus.iter().any(|cpu| cpu.native_tsc_khz != Some(first)) {
        return Err(invalid("managed CPUs have different native TSC rates"));
    }
    Ok(first)
}

fn lock_cpus<'a>(
    vm: &KvmVm,
    handles: &'a [Arc<Mutex<NativeCore>>],
) -> Result<Vec<MutexGuard<'a, NativeCore>>> {
    let mut cpus = Vec::with_capacity(handles.len());
    for handle in handles {
        cpus.push(handle.lock().map_err(|_| {
            vm.memory.poisoned.store(true, Ordering::Release);
            Error::Emulator("native CPU owner poisoned during checkpoint bank capture".into())
        })?);
    }
    Ok(cpus)
}

impl KvmVm {
    fn checkpoint_cpu_handles(
        &self,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<Vec<Arc<Mutex<NativeCore>>>> {
        boundary.require_owner(self.memory.identity())?;
        self.memory.ready()?;
        let count = self
            .profile
            .lock()
            .map_err(|_| invalid("CPU profile lock poisoned"))?
            .count
            .ok_or_else(|| invalid("CPU topology is not configured"))?;
        let registry = self
            .memory
            .managed_cpus
            .lock()
            .map_err(|_| invalid("CPU membership lock poisoned"))?;
        if registry.len() != usize::from(count)
            || registry.keys().copied().ne(0..u32::from(count))
            || self.memory.sdk_cpus.load(Ordering::Acquire) != 0
            || self.memory.external_vm_access.load(Ordering::Acquire)
        {
            return Err(invalid("CPU membership differs from the managed topology"));
        }
        registry
            .values()
            .map(|cpu| {
                cpu.upgrade()
                    .ok_or_else(|| invalid("managed CPU owner was destroyed"))
            })
            .collect()
    }

    /// Derive all CPU images and the common clock from the actual stopped
    /// owner set. The caller cannot substitute descriptors, IDs or profiles.
    pub(in crate::backend::kvm) fn capture_native_banks(
        &self,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<Image> {
        let handles = self.checkpoint_cpu_handles(boundary)?;
        let cores = lock_cpus(self, &handles)?;
        let irqchip = self.memory.irqchip_created.load(Ordering::Acquire);
        let native_khz = native_rate(&cores)?;
        // GET_MP_STATE can accept INIT/SIPI. Admit every CPU's existing
        // native I/O/deferred phase before the first such observation.
        for core in &cores {
            ready(core)?;
        }
        // Admit a stopped software phase before native CPU getters, including
        // GET_MP_STATE, can accept pending events. A second capture cannot pair
        // the saved native epoch with an independently changed device clock.
        let pending = self
            .memory
            .resume_clock
            .lock()
            .map_err(|_| invalid("native resume clock lock poisoned"))?;
        if let Some(pending) = &*pending {
            pending.validate_device_phase()?;
        }
        let pending_clock = pending.as_ref().map(|clock| clock.native.clone());
        drop(pending);
        let mut cpus = Vec::with_capacity(cores.len());
        for core in &cores {
            cpus.push(cpu::Image::capture(
                &self.memory.checkpoint_kvm,
                &self.memory.vm_fd,
                &core.vcpu_fd,
                core.id,
                &core.configured_cpuid,
                irqchip,
                core.userspace_halted,
            )?);
        }
        let descriptors: Vec<_> = cores.iter().map(|cpu| (cpu.id, &cpu.vcpu_fd)).collect();
        // A second stopped capture before entry must retain the saved phase,
        // rather than count the destination's RAM/device-publication delay.
        let clock = match pending_clock {
            Some(clock) => clock,
            None => clock::Image::capture(&self.memory.vm_fd, &descriptors, native_khz)
                .map_err(invalid)?,
        };
        let shared = irqchip
            .then(|| {
                let lines = self
                    .memory
                    .irq_lines
                    .lock()
                    .map_err(|_| invalid("IRQ line ownership lock poisoned"))?;
                shared::Image::capture(&self.memory.vm_fd, &lines)
            })
            .transpose()?;
        let image = Image {
            version: 4,
            cpus,
            deferred: cores
                .iter()
                .map(|core| deferred::Image::capture(core.deferred_exit.as_ref()))
                .collect::<Result<_>>()?,
            powered_off: self.memory.powered_off.load(Ordering::Acquire),
            terminal: cores
                .iter()
                .map(|core| core.io.capture_terminal().map_err(invalid))
                .collect::<Result<_>>()?,
            clock,
            shared,
        };
        image.validate_locked(self, &cores)?;
        Ok(image)
    }
}

impl Image {
    fn validate_locked(&self, vm: &KvmVm, cores: &[MutexGuard<'_, NativeCore>]) -> Result<()> {
        if self.version != 4
            || self.cpus.len() != cores.len()
            || self.deferred.len() != cores.len()
            || self.terminal.len() != cores.len()
            || self.cpus.is_empty()
            || self
                .cpus
                .iter()
                .zip(cores)
                .any(|(saved, target)| saved.id != target.id)
        {
            return Err(invalid("version or CPU identity set differs"));
        }
        let irqchip = vm.memory.irqchip_created.load(Ordering::Acquire);
        if self.shared.is_some() != irqchip {
            return Err(invalid("shared controller profile differs"));
        }
        if let Some(shared) = &self.shared {
            shared.validate()?;
        }
        for result in self.deferred.iter().flatten() {
            result.validate()?;
        }
        if !self.powered_off && self.terminal.iter().any(Option::is_some) {
            return Err(invalid("native I/O records require VM-wide power-off"));
        }
        for result in self.terminal.iter().flatten() {
            result.restore().map_err(invalid)?;
        }
        if !self.powered_off && cores.iter().any(|core| core.native_io_unsettled) {
            return Err(invalid(
                "active restore requires a fresh native owner after terminal I/O",
            ));
        }
        for core in cores {
            ready(core)?;
        }
        for (image, core) in self.cpus.iter().zip(cores) {
            image.validate(
                &vm.memory.checkpoint_kvm,
                &vm.memory.vm_fd,
                &core.vcpu_fd,
                core.id,
                &core.configured_cpuid,
                irqchip,
            )?;
        }
        let descriptors: Vec<_> = cores.iter().map(|cpu| (cpu.id, &cpu.vcpu_fd)).collect();
        self.clock
            .validate_target(&descriptors, native_rate(cores)?)
            .map_err(invalid)
    }

    /// Resolve all profile/identity admission before the enclosing producer
    /// installs any CPU, device or physical memory state.
    pub(in crate::backend::kvm) fn validate_target(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<()> {
        let handles = vm.checkpoint_cpu_handles(boundary)?;
        self.validate_locked(vm, &lock_cpus(vm, &handles)?)
    }

    /// Install stored banks on a disposable graph or inside the complete
    /// producer's rollback transaction. This deliberately does not rebase the
    /// clocks or activate entry before shared state and RAM are installed.
    pub(in crate::backend::kvm) fn restore_stored(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<()> {
        let handles = vm.checkpoint_cpu_handles(boundary)?;
        let mut cores = lock_cpus(vm, &handles)?;
        self.validate_locked(vm, &cores)?;
        // Own and validate every result before the first native setter. The
        // destination queue is replaced only after all native banks succeed.
        let deferred = self
            .deferred
            .iter()
            .map(|result| result.as_ref().map(deferred::Image::restore).transpose())
            .collect::<Result<Vec<_>>>()?;
        let terminal = self
            .terminal
            .iter()
            .map(|result| {
                result
                    .as_ref()
                    .map(super::super::io::TerminalImage::restore)
                    .transpose()
                    .map_err(invalid)
            })
            .collect::<Result<Vec<_>>>()?;
        let irqchip = vm.memory.irqchip_created.load(Ordering::Acquire);
        if let Some(shared) = &self.shared {
            let mut lines = vm
                .memory
                .irq_lines
                .lock()
                .map_err(|_| invalid("IRQ line ownership lock poisoned"))?;
            shared.restore_lines(&vm.memory.vm_fd, &mut lines)?;
        }
        for (image, core) in self.cpus.iter().zip(&mut cores) {
            let core = &mut **core;
            image.restore_stored(
                &vm.memory.checkpoint_kvm,
                &vm.memory.vm_fd,
                &mut core.vcpu_fd,
                core.id,
                &core.configured_cpuid,
                irqchip,
            )?;
            core.userspace_halted = image.userspace_halted;
        }
        if let Some(shared) = &self.shared {
            shared.restore_controllers(&vm.memory.vm_fd)?;
        }
        for ((core, result), terminal) in cores.iter_mut().zip(deferred).zip(terminal) {
            core.deferred_exit = result;
            core.io = terminal.unwrap_or_default();
            // Terminal records retain owned bytes only. They never import a
            // pointer into the source run mapping or authorize native entry.
            core.pending_io_in = None;
        }
        vm.memory
            .powered_off
            .store(self.powered_off, Ordering::Release);
        Ok(())
    }

    /// Complete the common unscaled clock sample under real VM exclusion.
    /// The enclosing producer must call this at its actual first-entry gate;
    /// calling it early would include stopped RAM-publication time as runtime.
    pub(in crate::backend::kvm) fn rebase_clock(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<()> {
        let handles = vm.checkpoint_cpu_handles(boundary)?;
        let cores = lock_cpus(vm, &handles)?;
        self.validate_locked(vm, &cores)?;
        let descriptors: Vec<_> = cores.iter().map(|cpu| (cpu.id, &cpu.vcpu_fd)).collect();
        self.clock
            .restore_at_resume(&vm.memory.vm_fd, &descriptors, native_rate(&cores)?)
            .map_err(invalid)?;
        Ok(())
    }

    /// Arm the common first-entry gate after installing the CPU banks. The
    /// enclosing producer retains exclusion through all RAM/device publication.
    /// No native clock setter runs here, and another stopped capture preserves
    /// this canonical phase until managed guest entry consumes it.
    pub(in crate::backend::kvm) fn stage_resume_clock(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<()> {
        self.stage_clock(vm, boundary, None)
    }

    /// Couple the retained software-device clock to this native epoch. The
    /// incoming phase stays frozen until actual guest entry, including across
    /// HLT polling, readiness probes and a second stopped checkpoint capture.
    pub(in crate::backend::kvm) fn stage_resume_clock_with_timing(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
        timing: Arc<crate::vm::timing::TimingContext>,
        state: crate::vm::timing::ClockState,
    ) -> Result<()> {
        self.stage_clock(vm, boundary, Some((timing, state)))
    }

    fn stage_clock(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
        devices: Option<(
            Arc<crate::vm::timing::TimingContext>,
            crate::vm::timing::ClockState,
        )>,
    ) -> Result<()> {
        self.validate_target(vm, boundary)?;
        let prepared = devices
            .as_ref()
            .map(|(timing, state)| timing.prepare_stopped_checkpoint_state(state))
            .transpose()?;
        let mut pending = vm
            .memory
            .resume_clock
            .lock()
            .map_err(|_| invalid("native resume clock lock poisoned"))?;
        if let Some(previous) = &*pending {
            previous.validate_device_owner(devices.as_ref().map(|(owner, _)| owner))?;
        }
        // All fallible admission precedes publication. The stopped VM boundary
        // excludes entry while both clock owners acquire the canonical phase.
        if let Some(prepared) = prepared {
            prepared.commit();
        }
        *pending = Some(crate::backend::kvm::clock_gate::PendingClock {
            native: self.clock.clone(),
            devices: devices.map(|(owner, state)| (owner, state.elapsed_nanos)),
        });
        Ok(())
    }
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;

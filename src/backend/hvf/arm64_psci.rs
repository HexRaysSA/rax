//! Native firmware calls and owner-thread CPU entry publication.
use super::*;
use crate::backend::arm64_hvf_power::{ENTRY_PSTATE, Power, State};
use crate::vm::vcpu::CpuPowerRequest;

impl NativeVmLifetime {
    fn power(&self) -> Result<std::sync::MutexGuard<'_, Option<Power>>> {
        self.power
            .lock()
            .map_err(|_| Error::Emulator("native power lock poisoned".into()))
    }
    pub(super) fn power_requests(&self) -> Result<Vec<CpuPowerRequest>> {
        Ok(self.power()?.as_ref().map_or_else(Vec::new, |power| {
            power.pending.iter().map(|p| p.request.clone()).collect()
        }))
    }
    pub(super) fn complete_power(&self, id: u32, start: bool) -> Result<()> {
        self.power()?
            .as_mut()
            .ok_or_else(|| Error::InvalidConfig("native CPU topology is not configured".into()))?
            .complete(id, start)
    }
}

impl HvfArm64Core {
    pub(super) fn native_shutdown(&self) -> Result<bool> {
        // Configured VMMs have one VM-wide terminal state. A stale local latch
        // from before an explicit restart must not shut the VM down again.
        Ok(self._vm.power()?.as_ref().map_or_else(
            || self._vm.standalone_shutdown.load(Ordering::Acquire),
            |power| power.shutdown,
        ))
    }
    pub(super) fn power_entry_exit(&self) -> Result<Option<VcpuExit>> {
        let power = self._vm.power()?;
        let Some(power) = power.as_ref() else {
            return Ok(None);
        };
        if power.shutdown {
            return Ok(Some(VcpuExit::Shutdown));
        }
        if power.states.get(self.id as usize) != Some(&State::On) {
            return Ok(Some(VcpuExit::Hlt));
        }
        Ok(None)
    }
    pub(super) fn clear_system_shutdown(&self) -> Result<()> {
        if let Some(power) = self._vm.power()?.as_mut() {
            power.shutdown = false;
        } else {
            self._vm.standalone_shutdown.store(false, Ordering::Release);
        }
        Ok(())
    }
    pub(super) fn psci_cpu_on(&self, call64: bool) -> Result<u64> {
        let argument = |reg| {
            self.read_gpr(reg)
                .map(|v| if call64 { v } else { u64::from(v as u32) })
        };
        let target = argument(HV_REG_X1)?;
        let entry = argument(HV_REG_X2)?;
        let context = argument(HV_REG_X3)?;
        let big_endian = self.read_sys_reg(HV_SYS_REG_SCTLR_EL1)? & (1 << 25) != 0;
        let mapping = self
            ._vm
            .mapping
            .lock()
            .map_err(|_| Error::Emulator("native RAM mapping lock poisoned".into()))?;
        let Some(mapping) = mapping.as_ref() else {
            return Ok(-9i64 as u64);
        };
        Ok(self._vm.power()?.as_mut().map_or(-1i64 as u64, |power| {
            power.cpu_on(
                target,
                entry,
                context,
                big_endian,
                mapping.ram_base,
                mapping.ram_size,
            )
        }))
    }
    pub(super) fn psci_affinity_info(&self, call64: bool) -> Result<u64> {
        let target = self.read_gpr(HV_REG_X1)?;
        // DEN0022D 5.1.5: lowest_affinity_level is uint32 for both FIDs.
        let level = u64::from(self.read_gpr(HV_REG_X2)? as u32);
        let target = if call64 {
            target
        } else {
            u64::from(target as u32)
        };
        Ok(self
            ._vm
            .power()?
            .as_ref()
            .map_or(-1i64 as u64, |power| power.affinity_info(target, level)))
    }
    pub(super) fn psci_cpu_off(&self) -> Result<bool> {
        let mut power = self._vm.power()?;
        let Some(power) = power.as_mut() else {
            return Ok(false);
        };
        power.cpu_off(self.id)?;
        Ok(true)
    }
    pub(super) fn psci_system_shutdown(&self) -> Result<()> {
        if let Some(power) = self._vm.power()?.as_mut() {
            power.shutdown = true;
        } else {
            self._vm.standalone_shutdown.store(true, Ordering::Release);
        }
        Ok(())
    }
    pub(super) fn start_cpu(&mut self, entry: u64, context: u64, pstate: u64) -> Result<()> {
        let big_endian = self
            ._vm
            .power()?
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("native CPU topology is not configured".into()))?
            .start_endianness(self.id, entry, context, pstate)?;
        if pstate != ENTRY_PSTATE {
            return Err(Error::InvalidConfig(
                "native CPU_ON requires EL1h with DAIF masked".into(),
            ));
        }
        // DEN0022D 6.4.3: preserve the SDK platform's initial SCTLR RES bits,
        // clear I/C/M, and copy the caller's EL1 data endianness.
        let mut state = Aarch64CpuState::default();
        state.regs.pc = entry;
        state.regs.pstate = pstate;
        state.regs.x[0] = context;
        state.sregs.sctlr_el1 = (self.startup_sctlr & !((1 << 25) | (1 << 12) | (1 << 2) | 1))
            | (u64::from(big_endian) << 25);
        // No power acknowledgement occurs until every fallible owner operation
        // succeeds. Retrying the retained request reinitializes the whole entry.
        checkpoint_api::prepare_cpu_start(
            self.vcpu,
            self.ever_entered,
            self.read_sys_reg(0xc021)? >> 24 & 15 != 0,
        )?;
        self.restore_native_state(&CpuState::Aarch64(state))?;
        // SAFETY: the permanent owner holds the live SDK CPU; the enclosing
        // request excludes checkpoint publication and these calls take no pointers.
        checkpoint_api::check(
            unsafe { hv_vcpu_set_vtimer_offset(self.vcpu, 0) },
            "CPU_ON virtual timer offset",
        )?;
        // SAFETY: same owner-thread and live-handle invariant as above.
        checkpoint_api::check(
            unsafe { hv_vcpu_set_vtimer_mask(self.vcpu, false) },
            "CPU_ON virtual timer mask",
        )?;
        self.pending_mmio_read = None;
        self.pending_mmio_write = None;
        self.pending_io_reply = None;
        self.io_completion_error = None;
        self.shutdown = false;
        Ok(())
    }
}

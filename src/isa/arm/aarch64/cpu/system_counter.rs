//! Fixed-frequency system-counter binding retained by the target VM.
use super::{AArch64Cpu, ArmError};
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::timing::{ClockMode, TimingContext};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SystemCounterState {
    pub mode: ClockMode,
    pub frequency_hz: u64,
}

#[derive(Clone)]
pub(super) struct SystemCounterBinding {
    clock: Arc<TimingContext>,
    frequency_hz: u64,
}

impl SystemCounterBinding {
    pub(super) fn ticks(&self) -> u64 {
        self.clock.counter_ticks(self.frequency_hz)
    }

    fn state(&self) -> SystemCounterState {
        SystemCounterState {
            mode: self.clock.mode(),
            frequency_hz: self.frequency_hz,
        }
    }
}

impl AArch64Cpu {
    pub(crate) fn has_legacy_counter_offset(&self) -> bool {
        self.sysregs
            .impl_defined
            .contains_key(&Aarch64SysRegEncoding::new(3, 4, 14, 0, 3).encode())
    }

    /// Before this register was modeled, guest MSR/MRS used the generic bank.
    /// Import its visible value and remove the shadow, without polling timers
    /// or publishing any controller state during offside preparation.
    pub(crate) fn migrate_legacy_counter_offset(&mut self) {
        if let Some(offset) = self
            .sysregs
            .impl_defined
            .remove(&Aarch64SysRegEncoding::new(3, 4, 14, 0, 3).encode())
        {
            self.sysregs.cntvoff_el2 = offset;
            self.sysregs.tick_timers(0);
        }
    }

    /// A deferred synchronous native fault keeps priority over timer polling.
    pub(crate) fn poll_system_counter(&mut self) -> Result<(), ArmError> {
        let outputs_active = self.sysregs.cntp_ctl_el0 & 3 == 1
            || self.sysregs.cntv_ctl_el0 & 3 == 1
            || self.timer_levels != (false, false);
        if self.system_counter.is_some() && self.execution.native_fault.is_none() && outputs_active
        {
            self.tick_system(0)?;
        }
        Ok(())
    }

    /// The platform frequency is fixed at binding, independently of later
    /// firmware writes to the CNTFRQ frequency-description register.
    pub(crate) fn bind_system_counter(&mut self, clock: Arc<TimingContext>) {
        self.system_counter = Some(SystemCounterBinding {
            clock,
            frequency_hz: self.sysregs.cntfrq_el0,
        });
    }

    pub(crate) fn system_counter_state(&self) -> Option<SystemCounterState> {
        self.system_counter
            .as_ref()
            .map(SystemCounterBinding::state)
    }

    /// Called only on an offside replacement. No counter sampling, device
    /// publication or source-clock ownership is imported from the record.
    pub(crate) fn restore_system_counter_binding(
        &mut self,
        state: Option<SystemCounterState>,
        target: &Self,
    ) -> Result<(), ArmError> {
        self.system_counter = match state {
            None => None, // Explicit legacy/standalone instruction-counter domain.
            Some(state) if target.system_counter_state() == Some(state) => {
                target.system_counter.clone()
            }
            Some(_) => {
                return Err(ArmError::Configuration(
                    "system counter clock/frequency differs from target".into(),
                ));
            }
        };
        Ok(())
    }
}

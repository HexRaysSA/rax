//! Fixed-frequency system-counter binding retained by the target VM.
use super::{AArch64Cpu, ArmError};
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::timing::{CLOCK_EPOCH_QUANTA, ClockMode, RETIREMENT_FREQUENCY_HZ, TimingContext};
use crate::vm::vcpu::ClockIdle;
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
    pub(crate) fn clock_idle(&self) -> Result<ClockIdle, ArmError> {
        let Some(counter) = &self.system_counter else {
            return Ok(ClockIdle::Runnable);
        };
        // A deferred synchronous exit, a runnable instruction or a pending
        // interrupt can all make progress at the current clock value.
        if self.halted
            || !self.wfi
            || self.wfe
            || self.execution.native_fault.is_some()
            || self.pending_interrupts(true)?.any()
        {
            return Ok(ClockIdle::Runnable);
        }
        let regs = &self.sysregs;
        let clock = counter.clock.checkpoint_state();
        let elapsed = clock.elapsed_quanta();
        let ticks = clock.counter_ticks(counter.frequency_hz);
        let timer_delay_quanta = [
            (regs.cntp_ctl_el0, regs.cntp_cval_el0, 0),
            (regs.cntv_ctl_el0, regs.cntv_cval_el0, regs.cntvoff_el2),
        ]
        .into_iter()
        .filter_map(|(control, compare, offset)| {
            timer_delay(
                control,
                compare,
                offset,
                ticks,
                elapsed,
                counter.frequency_hz,
            )
        })
        .min();
        Ok(ClockIdle::Waiting { timer_delay_quanta })
    }

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

fn timer_delay(
    control: u64,
    compare: u64,
    offset: u64,
    ticks: u64,
    elapsed: u128,
    frequency_hz: u64,
) -> Option<u128> {
    if control & 7 != 1 || compare == 0 {
        return None;
    }
    // Within one elapsed-time epoch the physical counter increases without
    // wrapping. A timer asserts at its compare and deasserts when its local
    // count wraps to zero. Convert each transition back to physical ticks.
    let transition = |physical: u64| {
        let count = physical.wrapping_sub(offset);
        let ticks_to_change = if count < compare {
            u128::from(compare - count)
        } else {
            (1u128 << 64) - u128::from(count)
        };
        ((u128::from(physical) + ticks_to_change) * u128::from(RETIREMENT_FREQUENCY_HZ))
            .div_ceil(u128::from(frequency_hz))
    };
    let deadline = transition(ticks);
    if deadline < CLOCK_EPOCH_QUANTA {
        return Some(deadline - elapsed);
    }
    // The counter sample jumps to zero at elapsed wrap. Even a timer
    // currently blocked at the GIC must publish a falling edge here if its
    // comparison changes, so later rising edges can be observed in order.
    let active = ticks.wrapping_sub(offset) >= compare;
    let next_epoch = if (offset.wrapping_neg() >= compare) != active {
        0
    } else {
        transition(0)
    };
    (next_epoch < elapsed).then_some(CLOCK_EPOCH_QUANTA - elapsed + next_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FREQ: u64 = 62_500_000;

    #[test]
    fn idle_timer_uses_offset_and_rounds_up_from_a_fractional_phase() {
        // One 62.5 MHz tick takes 48 clock quanta. At tick 10, virtual
        // time is 7. Its compare at 8 is the physical tick 11.
        let elapsed = 10 * 48 + 13;
        assert_eq!(timer_delay(1, 8, 3, 10, elapsed, FREQ), Some(35));
        assert_eq!(timer_delay(1, 0, 3, 10, elapsed, FREQ), None);
        assert_eq!(timer_delay(3, 8, 3, 10, elapsed, FREQ), None);
        assert_eq!(timer_delay(1, u64::MAX, 0, 10, elapsed, FREQ), None);
    }

    #[test]
    fn elapsed_wrap_can_assert_the_virtual_output_without_a_physical_crossing() {
        let elapsed = CLOCK_EPOCH_QUANTA - 4;
        let ticks = (elapsed / 48) as u64;
        // At elapsed wrap, physical ticks reset and virtual time becomes
        // u64::MAX for an offset of one. The physical timer stays future.
        assert_eq!(timer_delay(1, ticks + 2, 1, ticks, elapsed, FREQ), Some(4));
        assert_eq!(timer_delay(1, ticks + 2, 0, ticks, elapsed, FREQ), None);
        assert_eq!(timer_delay(1, ticks, 0, ticks, elapsed, FREQ), Some(4));
        let elapsed = 10 * 48 + 13;
        assert_eq!(timer_delay(1, 8, 11, 10, elapsed, FREQ), Some(35));
    }
}

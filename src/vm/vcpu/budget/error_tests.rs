//! Explicit completed-counter errors and unchanged failed-attempt meters.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::CpuState;
use std::cell::Cell;
use std::sync::Arc;

struct Script {
    count: u64,
    remaining: u64,
    failure_delta: u64,
    calls: u64,
    probes: Cell<u64>,
    stepping: bool,
}

impl Script {
    fn new(count: u64, remaining: u64, failure_delta: u64) -> Self {
        Self {
            count,
            remaining,
            failure_delta,
            calls: 0,
            probes: Cell::new(0),
            stepping: true,
        }
    }
}

impl VCpu for Script {
    fn run(&mut self) -> Result<VcpuExit> {
        panic!("unbounded entry must not run")
    }
    fn get_state(&self) -> Result<CpuState> {
        Ok(CpuState::x86_64(Default::default(), Default::default()))
    }
    fn set_state(&mut self, _: &CpuState) -> Result<()> {
        Ok(())
    }
    fn complete_io_in(&mut self, _: &[u8]) {}
    fn id(&self) -> u32 {
        0
    }
    fn instruction_count(&self) -> u64 {
        self.probes.set(self.probes.get() + 1);
        self.count
    }
    fn supports_stepping(&self) -> bool {
        self.stepping
    }
    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.calls += 1;
        if self.remaining != 0 {
            self.remaining -= 1;
            self.count = self.count.wrapping_add(1);
            Ok(None)
        } else {
            self.count = self.count.wrapping_add(self.failure_delta);
            Err(Error::Emulator("sentinel host failure".into()))
        }
    }
}

fn assert_original_error(result: RetirementRun, retired: u64) {
    assert_eq!(result.retired, retired);
    match result.stop {
        RetirementStop::Fault(Error::Emulator(message)) => {
            assert_eq!(message, "sentinel host failure")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn committed_error_counter_preserves_work_wrap_and_error_at_budget_boundary() {
    for initial in [0, u64::MAX] {
        for prefix in [0, 1, 3] {
            for budget in [prefix + 1, 1000] {
                let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
                let _binding = clock.enter();
                let mut cpu = Script::new(initial, prefix, 1);
                let result = run(&mut cpu, budget, ErrorRetirement::CounterDelta).unwrap();
                assert_original_error(result, prefix + 1);
                assert_eq!(clock.checkpoint_state().retired_units, prefix + 1);
                assert_eq!(cpu.count, initial.wrapping_add(prefix + 1));
                assert_eq!(cpu.calls, prefix + 1);
            }
        }
    }
}

#[test]
fn default_error_policy_preserves_charged_meter_without_charging_retirement_clock() {
    for initial in [0, u64::MAX] {
        for charge in [0, 1] {
            let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            let _binding = clock.enter();
            let mut cpu = Script::new(initial, 3, charge);
            let result = run(&mut cpu, 1000, ErrorRetirement::NoRetirement).unwrap();
            assert_original_error(result, 3);
            assert_eq!(clock.checkpoint_state().retired_units, 3);
            assert_eq!(cpu.count, initial.wrapping_add(3 + charge));
            assert_eq!(cpu.calls, 4);
        }
    }
}

#[test]
fn committed_error_with_zero_delta_keeps_retirement_and_clock_zero() {
    for initial in [0, u64::MAX] {
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _binding = clock.enter();
        let mut cpu = Script::new(initial, 0, 0);
        let result = run(&mut cpu, 1, ErrorRetirement::CounterDelta).unwrap();
        assert_original_error(result, 0);
        assert_eq!(clock.checkpoint_state().retired_units, 0);
        assert_eq!(cpu.count, initial);
        assert_eq!(cpu.calls, 1);
    }
}

#[test]
fn invalid_error_delta_cannot_publish_unverified_retirement_units() {
    for initial in [0, u64::MAX] {
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _binding = clock.enter();
        let mut cpu = Script::new(initial, 3, 2);
        let result = run(&mut cpu, 1000, ErrorRetirement::CounterDelta).unwrap();
        assert_eq!(result.retired, 3);
        match result.stop {
            RetirementStop::Fault(Error::Emulator(message)) => assert_eq!(
                message,
                "single step reported 2 retired units; expected at most one"
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(clock.checkpoint_state().retired_units, 3);
        assert_eq!(cpu.calls, 4);
    }
}

#[test]
fn zero_budget_never_probes_either_error_accounting_policy() {
    for policy in [ErrorRetirement::NoRetirement, ErrorRetirement::CounterDelta] {
        let mut cpu = Script::new(u64::MAX, 0, 1);
        cpu.stepping = false;
        let result = run(&mut cpu, 0, policy).unwrap();
        assert_eq!(result.retired, 0);
        assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
        assert_eq!((cpu.calls, cpu.probes.get()), (0, 0));
        assert_eq!(cpu.count, u64::MAX);
    }
}

#[test]
fn unsupported_stepping_rejects_before_attempts_under_either_policy() {
    for policy in [ErrorRetirement::NoRetirement, ErrorRetirement::CounterDelta] {
        let mut cpu = Script::new(0, 0, 1);
        cpu.stepping = false;
        assert!(run(&mut cpu, 1, policy).is_err());
        assert_eq!((cpu.calls, cpu.probes.get()), (0, 0));
    }
}

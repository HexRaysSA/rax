//! Exact instruction boundaries before/after the AArch64 JIT hot threshold.
use rax::backend::emulator::aarch64::Aarch64Vcpu;
use rax::vm::vcpu::{CpuState, RetirementStop, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
const ENTRY: u64 = 0x1000;
fn machine(system: bool) -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let program = [
        0x91000400u32,
        0x91000421,
        0xf13ffc1f,
        0x54ffffa3,
        0xd4200000,
    ];
    let bytes: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    m.write_slice(&bytes, GuestAddress(ENTRY)).unwrap();
    let mut cpu = if system {
        Aarch64Vcpu::new(0, m.clone())
    } else {
        Aarch64Vcpu::new_micro(0, m.clone())
    };
    cpu.set_current_pc(ENTRY).unwrap();
    (cpu, m)
}
fn state(cpu: &Aarch64Vcpu) -> (u64, u64, u64) {
    let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    (state.regs.pc, state.regs.x[0], state.regs.x[1])
}
fn expected(n: u64) -> (u64, u64, u64) {
    (ENTRY + 4 * (n % 4), (n + 3) / 4, (n + 2) / 4)
}
fn exact(cpu: &Aarch64Vcpu, n: u64) {
    assert_eq!(state(cpu), expected(n));
    assert_eq!(cpu.instruction_count(), n);
}
#[test]
fn micro_budgets_cross_hot_threshold_without_running_a_region() {
    let (mut cpu, _) = machine(false);
    for n in 1..=1000 {
        let r = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(r.retired, 1);
        assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
        exact(&cpu, n);
    }
}
#[test]
fn full_machine_budgets_cross_hot_threshold_without_running_a_region() {
    let (mut cpu, _) = machine(true);
    for n in 1..=1000 {
        let r = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(r.retired, 1);
        assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
        exact(&cpu, n);
    }
}
#[test]
fn one_thousand_unit_budget_is_exact_for_each_adapter_mode() {
    for system in [false, true] {
        let (mut cpu, _) = machine(system);
        let r = cpu.run_retirement_budget(1000).unwrap();
        assert_eq!(r.retired, 1000);
        assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
        exact(&cpu, 1000);
    }
}
#[test]
fn direct_steps_retain_one_instruction_after_hot_threshold() {
    for system in [false, true] {
        let (mut cpu, _) = machine(system);
        for n in 1..=1000 {
            assert!(cpu.step_insn().unwrap().is_none());
            exact(&cpu, n);
        }
    }
}
#[test]
fn heterogeneous_budget_boundaries_follow_the_same_instruction_trace() {
    for system in [false, true] {
        let (mut cpu, _) = machine(system);
        let mut total = 0;
        for budget in [0, 1, 2, 999, 1000, 1001] {
            let r = cpu.run_retirement_budget(budget).unwrap();
            assert_eq!(r.retired, budget);
            assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
            total += budget;
            exact(&cpu, total);
        }
    }
}
fn warmed() -> Aarch64Vcpu {
    let (mut cpu, _) = machine(false);
    let failure = cpu.run().unwrap_err();
    assert!(matches!(
        failure,
        rax::error::Error::InvalidInstruction { .. }
    ));
    assert_eq!(state(&cpu).1, 4095);
    let mut saved = cpu.get_state().unwrap();
    let CpuState::Aarch64(s) = &mut saved else {
        panic!()
    };
    s.regs.pc = ENTRY;
    s.regs.x[0] = 0;
    s.regs.x[1] = 0;
    cpu.update_state(&saved).unwrap();
    cpu
}
#[test]
fn an_already_cached_region_is_bypassed_by_single_instruction_budget() {
    let mut cpu = warmed();
    let before = cpu.instruction_count();
    let r = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(r.retired, 1);
    assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
    assert_eq!(state(&cpu), (ENTRY + 4, 1, 0));
    assert_eq!(cpu.instruction_count(), before + 1);
}
#[test]
fn an_already_cached_region_is_bypassed_by_direct_step() {
    let mut cpu = warmed();
    let before = cpu.instruction_count();
    assert!(cpu.step_insn().unwrap().is_none());
    assert_eq!(state(&cpu), (ENTRY + 4, 1, 0));
    assert_eq!(cpu.instruction_count(), before + 1);
}
#[test]
fn diagnostic_fetch_fault_reports_no_retirement() {
    let (mut cpu, m) = machine(false);
    m.write_slice(&0u32.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap();
    let r = cpu.run_retirement_budget(1000).unwrap();
    assert_eq!(r.retired, 0);
    assert!(matches!(
        r.stop,
        RetirementStop::Fault(rax::error::Error::InvalidInstruction { .. })
    ));
    assert_eq!(cpu.instruction_count(), 0);
}
pub fn emit_reference(path: &std::path::Path) {
    let mut bytes = Vec::new();
    for system in [false, true] {
        let (mut cpu, _) = machine(system);
        for n in 1..=1000 {
            let r = cpu.run_retirement_budget(1).unwrap();
            assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
            let (pc, x0, x1) = state(&cpu);
            for word in [
                u64::from(system),
                n,
                r.retired,
                cpu.instruction_count(),
                pc,
                x0,
                x1,
            ] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        let (mut cpu, _) = machine(system);
        for budget in [0, 1, 2, 999, 1000, 1001] {
            let r = cpu.run_retirement_budget(budget).unwrap();
            assert!(matches!(r.stop, RetirementStop::BudgetExhausted));
            let (pc, x0, x1) = state(&cpu);
            for word in [
                u64::from(system),
                budget,
                r.retired,
                cpu.instruction_count(),
                pc,
                x0,
                x1,
            ] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
    }
    std::fs::write(path, bytes).unwrap();
}

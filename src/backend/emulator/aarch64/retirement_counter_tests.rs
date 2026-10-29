//! Full private-record admission and budget/clock continuation across wrap.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::RetirementStop;
use vm_memory::Bytes;

const ENTRY: u64 = 0x100;

fn restored(
    kind: usize,
    micro: bool,
    instructions: u64,
    cycles: u64,
    observed: u64,
) -> Aarch64Vcpu {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let words: [&[u8]; 4] = [
        &[0x00, 0x04, 0x00, 0x91],
        &[0x01, 0x00, 0x80, 0xe2],
        &[0x01, 0x30],
        &[0x00, 0xf1, 0x01, 0x00],
    ];
    memory
        .write_slice(words[kind], GuestAddress(ENTRY))
        .unwrap();
    let construct = || {
        if micro {
            Aarch64Vcpu::new_micro(0, memory.clone())
        } else {
            Aarch64Vcpu::new(0, memory.clone())
        }
    };
    let mut source = construct();
    let mut controls = source.cpu.pauth_controls();
    controls.scr_el3 |= 1 | (1 << 10);
    controls.hcr_el2 |= 1 << 31;
    source.cpu.set_pauth_controls(controls).unwrap();
    if kind != 0 {
        source
            .cpu
            .set_pstate_bits(0x10 | (u64::from(kind >= 2) << 5))
            .unwrap();
    }
    source.cpu.set_pc(ENTRY);
    source.cpu.set_x(0, 7);
    source.cpu.set_jit_enabled(false);
    let state = source.get_state().unwrap();
    let mut raw = source.capture_backend_context().unwrap().unwrap();
    let mut payload = Context::decode(&raw.data, &source).unwrap();
    payload.core = payload
        .core
        .with_test_retirement_counters(instructions, cycles);
    payload.observed_instructions = observed;
    raw.data = TAG.to_vec();
    raw.data
        .extend_from_slice(&crate::codec::serialize(&payload).unwrap());
    let mut target = construct();
    target
        .validate_checkpoint_context(&state, &Default::default(), Some(&raw))
        .unwrap();
    target
        .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
        .unwrap();
    assert_eq!(target.cpu.instruction_count(), instructions);
    assert_eq!(target.cpu.cycle_count(), Some(cycles));
    assert_eq!(target.instruction_count(), observed);
    target
}

fn budget_case(instructions: u64, cycles: u64) {
    for micro in [false, true] {
        for kind in 0..4 {
            for observed in [17, u64::MAX] {
                let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
                let _binding = clock.enter();
                let mut cpu = restored(kind, micro, instructions, cycles, observed);
                assert_eq!(cpu.run_retirement_budget(0).unwrap().retired, 0);
                assert_eq!(cpu.cpu.instruction_count(), instructions);
                let result = cpu.run_retirement_budget(1).unwrap();
                assert!(
                    matches!(result.stop, RetirementStop::BudgetExhausted),
                    "{result:?}"
                );
                assert_eq!(result.retired, 1);
                assert_eq!(cpu.cpu.instruction_count(), instructions.wrapping_add(1));
                assert_eq!(cpu.cpu.cycle_count(), Some(cycles.wrapping_add(1)));
                assert_eq!(cpu.instruction_count(), observed.wrapping_add(1));
                assert_eq!(cpu.cpu.get_x(0), 8);
                assert_eq!(cpu.current_pc(), ENTRY + if kind == 2 { 2 } else { 4 });
                assert_eq!(clock.checkpoint_state().retired_units, 1);
            }
        }
    }
}

#[test]
fn admitted_adapter_instruction_maximum_resumes_one_budget_unit() {
    budget_case(u64::MAX, 0);
}

#[test]
fn admitted_adapter_cycle_maximum_resumes_one_budget_unit() {
    budget_case(0, u64::MAX);
}

#[test]
fn admitted_adapter_maximum_counters_do_not_charge_a_fetch_fault() {
    for kind in 0..4 {
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _binding = clock.enter();
        let mut cpu = restored(kind, true, u64::MAX, u64::MAX, 17);
        cpu.cpu.set_pc(0x5000);
        let result = cpu.run_retirement_budget(1).unwrap();
        assert!(
            matches!(result.stop, RetirementStop::Fault(_)),
            "{result:?}"
        );
        assert_eq!(result.retired, 0);
        assert_eq!(cpu.cpu.instruction_count(), u64::MAX);
        assert_eq!(cpu.cpu.cycle_count(), Some(u64::MAX));
        assert_eq!(cpu.instruction_count(), 17);
        assert_eq!(clock.checkpoint_state().retired_units, 0);
    }
}

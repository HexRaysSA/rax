//! Actual guest timestamp instructions under selected retirement clocks.
use rax::isa::x86_64::X86_64Vcpu;
use rax::vm::timing::{ClockMode, TimingContext};
use rax::vm::vcpu::{CpuState, Registers, RetirementStop, SystemRegisters, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
const CODE: u64 = 0x1000;
fn clock() -> Arc<TimingContext> {
    Arc::new(TimingContext::with_mode(ClockMode::Retired))
}
fn machine(code: &[u8], adjust: u64, aux: u32) -> X86_64Vcpu {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    m.write_slice(&code.repeat(32), GuestAddress(CODE)).unwrap();
    let mut cpu = X86_64Vcpu::new(0, m);
    cpu.set_state(&CpuState::x86_64(
        Registers {
            rip: CODE,
            rflags: 2,
            ..Default::default()
        },
        SystemRegisters::default(),
    ))
    .unwrap();
    let mut private = cpu.get_emulator_state().unwrap();
    private.tsc_adjust = adjust;
    private.tsc_aux = aux;
    cpu.set_emulator_state(&private).unwrap();
    cpu
}
fn read(cpu: &mut X86_64Vcpu, rcx: u64) -> (u64, u64) {
    let mut r = cpu.get_regs().unwrap();
    r.rax = u64::MAX;
    r.rdx = u64::MAX;
    r.rcx = rcx;
    cpu.set_regs(&r).unwrap();
    let run = cpu.run_retirement_budget(1).unwrap();
    assert_eq!(run.retired, 1);
    assert!(matches!(run.stop, RetirementStop::BudgetExhausted));
    let r = cpu.get_regs().unwrap();
    assert!(r.rax <= u64::from(u32::MAX) && r.rdx <= u64::from(u32::MAX));
    (r.rax | (r.rdx << 32), r.rcx)
}
#[test]
fn guest_reads_inside_one_budget_observe_prior_instructions() {
    let c = clock();
    let _binding = c.enter();
    let mut cpu = machine(
        &[0x0f, 0x31, 0x89, 0xc3, 0x0f, 0x31, 0x89, 0xc6, 0x0f, 0x31],
        0,
        0,
    );
    let result = cpu.run_retirement_budget(5).unwrap();
    assert_eq!(result.retired, 5);
    let registers = cpu.get_regs().unwrap();
    assert_eq!((registers.rbx, registers.rsi, registers.rax), (0, 2, 4));
    assert_eq!(c.retirement_count(), Some(5));
}
#[test]
fn rdtsc_observes_each_fractional_unit_within_budgeted_execution() {
    let c = clock();
    let _g = c.enter();
    let mut cpu = machine(&[0x0f, 0x31], 0, 0);
    for n in 0..9 {
        assert_eq!(read(&mut cpu, 0).0, n);
    }
    assert_eq!(c.retirement_count(), Some(9));
    assert_eq!(c.elapsed_nanos(), 3);
}
#[test]
fn rdtscp_uses_exact_counter_aux_and_zero_extended_destinations() {
    let c = clock();
    c.advance_retired(0xffff_fffe).unwrap();
    let _g = c.enter();
    let mut cpu = machine(&[0x0f, 0x01, 0xf9], 0, 0xfedc_ba98);
    for n in 0xffff_fffe..=0x1_0000_0002 {
        assert_eq!(read(&mut cpu, u64::MAX), (n, 0xfedc_ba98));
    }
}
#[test]
fn rdmsr_tsc_reads_the_same_selected_counter() {
    let c = clock();
    let _g = c.enter();
    let mut cpu = machine(&[0x0f, 0x32], 0, 0);
    for n in 0..6 {
        assert_eq!(read(&mut cpu, 0x10).0, n);
    }
}
#[test]
fn positive_and_negative_tsc_adjust_offsets_wrap_in_cycles() {
    for units in [0, 1, 2, 1000, u64::MAX] {
        for offset in [0, 1, 0x1_0000_0001, u64::MAX] {
            let c = clock();
            c.advance_retired(units).unwrap();
            let _g = c.enter();
            let mut cpu = machine(&[0x0f, 0x31], offset, 0);
            assert_eq!(read(&mut cpu, 0).0, units.wrapping_add(offset));
        }
    }
}
#[test]
fn wrmsr_tsc_rebase_and_adjust_read_share_the_same_domain() {
    let c = clock();
    c.advance_retired(2).unwrap();
    let _g = c.enter();
    let mut cpu = machine(&[0x0f, 0x30, 0x0f, 0x32], 0, 0);
    let mut r = cpu.get_regs().unwrap();
    r.rcx = 0x10;
    r.rax = 100;
    r.rdx = 0;
    cpu.set_regs(&r).unwrap();
    cpu.run_retirement_budget(1).unwrap();
    assert_eq!(read(&mut cpu, 0x10).0, 101);
    let private = cpu.get_emulator_state().unwrap();
    assert_eq!(private.tsc_adjust, 98);
    assert_eq!(c.retirement_count(), Some(4));
}
#[test]
fn pmc_profile_remains_unadjusted_when_tsc_adjust_changes() {
    let c = clock();
    c.advance_retired(1001).unwrap();
    let _g = c.enter();
    let mut cpu = machine(&[0x0f, 0x33], u64::MAX, 0);
    assert_eq!(read(&mut cpu, 0).0, 1001);
    assert_eq!(read(&mut cpu, 0x8000_0000).0, 1002);
}
#[test]
fn nested_retired_clocks_select_independent_guest_timestamp_domains() {
    let a = clock();
    let b = clock();
    a.advance_retired(1).unwrap();
    b.advance_retired(1001).unwrap();
    let _a = a.enter();
    let mut cpu = machine(&[0x0f, 0x31], 0, 0);
    assert_eq!(read(&mut cpu, 0).0, 1);
    {
        let _b = b.enter();
        assert_eq!(read(&mut cpu, 0).0, 1001);
    }
    assert_eq!(read(&mut cpu, 0).0, 2);
}
#[test]
fn wall_binding_preserves_elapsed_nanosecond_conversion() {
    let c = Arc::new(TimingContext::new());
    let _g = c.enter();
    let mut cpu = machine(&[0x0f, 0x31], 7, 0);
    let before = c.elapsed_nanos();
    let value = read(&mut cpu, 0).0;
    let after = c.elapsed_nanos();
    assert!(value >= before * 3 + 7 && value <= after * 3 + 7);
    assert_eq!(c.retirement_count(), None);
}
pub fn emit_reference(path: &std::path::Path) {
    let mut bytes = Vec::new();
    for kind in 0..4 {
        for units in [0, 1, 2, 1000, 0x1_0000_0001, u64::MAX] {
            for adjust in [0, 1, u64::MAX] {
                let c = clock();
                c.advance_retired(units).unwrap();
                let _g = c.enter();
                let instruction: &[u8] = match kind {
                    0 => &[0x0f, 0x31],
                    1 => &[0x0f, 0x01, 0xf9],
                    2 => &[0x0f, 0x32],
                    _ => &[0x0f, 0x33],
                };
                let mut cpu = machine(instruction, adjust, 0xa5a5_1234);
                let selector = if kind == 2 { 0x10 } else { 0 };
                let (value, rcx) = read(&mut cpu, selector);
                for word in [
                    kind,
                    units,
                    adjust,
                    value,
                    rcx,
                    c.retirement_count().unwrap(),
                    cpu.current_pc(),
                ] {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
            }
        }
    }
    std::fs::write(path, bytes).unwrap();
}

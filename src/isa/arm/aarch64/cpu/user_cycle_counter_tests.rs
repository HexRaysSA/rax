//! The user cycle-counter binding is an explicit, read-only host policy.
use super::*;
use std::cell::Cell;

const ENTRY: u64 = 0x100;
const MRS_PMCCNTR: u32 = 0xD53B_9D00;
const SAMPLE_XOR: u64 = 0xFEDC_BA98_7654_3210;

thread_local! {
    static READS: Cell<usize> = const { Cell::new(0) };
}

fn sample(cycles: u64) -> u64 {
    READS.set(READS.get() + 1);
    cycles ^ SAMPLE_XOR
}

fn cpu(rt: u32) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            gic_config: None,
            ..AArch64Config::default()
        },
        Box::new(crate::isa::arm::common::memory::FlatMemory::new(0, 0x1000)),
    );
    cpu.enter_el0();
    cpu.write_memory(ENTRY, &(MRS_PMCCNTR | rt).to_le_bytes())
        .unwrap();
    cpu.set_pc(ENTRY);
    cpu
}

#[test]
fn bound_user_counter_preserves_full_width_and_wrapping_retirement() {
    for cycles in [0, 1, u32::MAX as u64, 1 << 32, u64::MAX] {
        let mut cpu = cpu(7);
        cpu.bind_el0_cycle_counter(sample);
        cpu.cycle_count = cycles;
        cpu.insn_count = cycles;
        cpu.nzcv = 0b1011;
        READS.set(0);
        assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
        assert_eq!(cpu.get_x(7), cycles ^ SAMPLE_XOR);
        assert_eq!(cpu.cycle_count, cycles.wrapping_add(1));
        assert_eq!(cpu.insn_count, cycles.wrapping_add(1));
        assert_eq!(cpu.nzcv, 0b1011);
        assert_eq!(cpu.pc, ENTRY + 4);
        assert_eq!(READS.get(), 1);
    }
}

#[test]
fn bound_user_counter_samples_even_when_destination_is_xzr() {
    let mut cpu = cpu(31);
    cpu.bind_el0_cycle_counter(sample);
    READS.set(0);
    assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
    assert_eq!(READS.get(), 1);
    assert_eq!(cpu.get_x(31), 0);
    assert_eq!(cpu.cycle_count, 1);
}

#[test]
fn bound_user_counter_does_not_run_ahead_of_instruction_breakpoints() {
    let mut cpu = cpu(0);
    cpu.bind_el0_cycle_counter(sample);
    cpu.breakpoints.insert(ENTRY);
    READS.set(0);
    assert!(matches!(cpu.step().unwrap(), CpuExit::Breakpoint(_)));
    assert_eq!(READS.get(), 0);
    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
}

#[test]
fn bound_user_counter_is_cleared_by_reset_and_fresh_el0_entry() {
    let encoding = Aarch64SysRegEncoding::new(3, 3, 9, 13, 0);
    let mut cpu = cpu(0);
    cpu.bind_el0_cycle_counter(sample);
    assert_eq!(cpu.read_sysreg(encoding).unwrap(), SAMPLE_XOR);
    cpu.enter_el0();
    assert!(matches!(
        cpu.read_sysreg(encoding),
        Err(ArmError::InvalidExceptionLevel(0))
    ));
    cpu.bind_el0_cycle_counter(sample);
    cpu.reset();
    assert!(cpu.el0_cycle_counter.is_none());
    cpu.current_el = 0;
    assert!(matches!(
        cpu.read_sysreg(encoding),
        Err(ArmError::InvalidExceptionLevel(0))
    ));
}

#[test]
fn bound_user_counter_is_not_a_privileged_register_override() {
    let mut cpu = cpu(0);
    cpu.bind_el0_cycle_counter(sample);
    READS.set(0);
    for el in 1..=3 {
        cpu.current_el = el;
        let _ = cpu.read_sysreg(Aarch64SysRegEncoding::new(3, 3, 9, 13, 0));
    }
    assert_eq!(READS.get(), 0);
}

#[test]
fn bound_user_counter_cannot_be_exported_as_a_machine_checkpoint() {
    let mut cpu = cpu(0);
    assert!(CoreCheckpoint::capture(&cpu).is_ok());
    cpu.bind_el0_cycle_counter(sample);
    assert!(matches!(
        CoreCheckpoint::capture(&cpu),
        Err(ArmError::Configuration(_))
    ));
}

#[test]
fn machine_checkpoint_rejects_a_bound_user_counter_before_mutation() {
    let checkpoint = CoreCheckpoint::capture(&cpu(0)).unwrap();
    let mut target = cpu(0);
    target.bind_el0_cycle_counter(sample);
    target.set_x(0, 0x1234_5678_9ABC_DEF0);
    target.set_pc(ENTRY + 4);
    assert!(checkpoint.install_in_prepared(&mut target).is_err());
    assert_eq!(target.get_x(0), 0x1234_5678_9ABC_DEF0);
    assert_eq!(target.pc, ENTRY + 4);
    assert_eq!(target.insn_count, 0);
    assert_eq!(
        target
            .read_sysreg(Aarch64SysRegEncoding::new(3, 3, 9, 13, 0))
            .unwrap(),
        SAMPLE_XOR
    );
}

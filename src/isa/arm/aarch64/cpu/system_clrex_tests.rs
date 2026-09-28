//! Direct A64 local-exclusive monitor behavior for CLREX.
//!
//! Arm ASL `aarch64_system_monitors` has fixed Rt=31, ignores all four CRm
//! bits, and calls `ClearExclusiveLocal(ProcessorID())`.

use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const DATA: u64 = 0x100;
const OLD: u64 = 0x1122_3344_5566_7788;
const REPLACEMENT: u64 = 0x8877_6655_4433_2211;
const LDXR_X0_X1: u32 = 0xC85F_7C20;
const STXR_W2_X3_X1: u32 = 0xC802_7C23;

fn clrex(crm: u32) -> u32 {
    assert!(crm < 16);
    0xD503_305F | (crm << 8)
}

fn cpu_with_program(instructions: &[u32]) -> AArch64Cpu {
    let mut config = AArch64Config::default();
    config.initial_el = 0;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x1000)));
    for (index, instruction) in instructions.iter().enumerate() {
        cpu.write_memory((index * 4) as u64, &instruction.to_le_bytes())
            .unwrap();
    }
    cpu.write_memory(DATA, &OLD.to_le_bytes()).unwrap();
    cpu.set_x(1, DATA);
    cpu.set_x(3, REPLACEMENT);
    cpu.set_nzcv(true, false, true, false);
    cpu
}

fn data(cpu: &AArch64Cpu) -> u64 {
    u64::from_le_bytes(cpu.read_memory(DATA, 8).unwrap().try_into().unwrap())
}

#[test]
fn clrex_all_immediates_clear_ldxr_reservation_before_stxr() {
    for crm in 0..16 {
        let mut cpu = cpu_with_program(&[LDXR_X0_X1, clrex(crm), STXR_W2_X3_X1]);
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "LDXR, CRm={crm}");
        assert_eq!(cpu.get_x(0), OLD);
        assert_eq!(cpu.get_pc(), 4);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "CLREX, CRm={crm}");
        assert_eq!(cpu.get_pc(), 8);
        assert_eq!(cpu.get_x(0), OLD, "CLREX changed a GPR, CRm={crm}");
        assert_eq!(data(&cpu), OLD, "CLREX changed data, CRm={crm}");
        assert!(cpu.get_n() && !cpu.get_z() && cpu.get_c() && !cpu.get_v());

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "STXR, CRm={crm}");
        assert_eq!(cpu.get_x(2), 1, "STXR succeeded after CLREX, CRm={crm}");
        assert_eq!(data(&cpu), OLD, "STXR wrote after CLREX, CRm={crm}");
        assert_eq!(cpu.get_pc(), 12);
    }
}

#[test]
fn clrex_then_ldxr_rearms_local_monitor() {
    let mut cpu = cpu_with_program(&[LDXR_X0_X1, clrex(0), LDXR_X0_X1, STXR_W2_X3_X1]);
    for _ in 0..4 {
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    }
    assert_eq!(cpu.get_x(2), 0);
    assert_eq!(data(&cpu), REPLACEMENT);
}

#[test]
fn ordinary_barriers_do_not_clear_local_monitor() {
    for (name, barrier) in [
        ("DMB SY", 0xD503_3FBF),
        ("DSB SY", 0xD503_3F9F),
        ("ISB", 0xD503_3FDF),
        ("SB", 0xD503_30FF),
    ] {
        let mut cpu = cpu_with_program(&[LDXR_X0_X1, barrier, STXR_W2_X3_X1]);
        for _ in 0..3 {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{name}");
        }
        assert_eq!(cpu.get_x(2), 0, "{name} cleared the local monitor");
        assert_eq!(data(&cpu), REPLACEMENT, "{name} blocked STXR");
    }
}

#[test]
fn clrex_non_xzr_rt_is_undefined_without_clearing_reservation() {
    let invalid = clrex(15) & !31; // Rt=0, whereas the CLREX class fixes Rt=31.
    let mut cpu = cpu_with_program(&[LDXR_X0_X1, invalid]);
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(raw)) if raw == invalid));
    assert_eq!(cpu.get_pc(), 4);
    assert_eq!(data(&cpu), OLD);
    assert!(cpu.memory.check_exclusive(DATA, 8));
}

//! CPU reference for lowered SIMD/FP code with explicit FP16 availability.
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use crate::isa::arm::common::cpu::{ArmCpu, CpuExit};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::FlatMemory;

pub(super) fn run_aarch64_code_with_regs_simd_and_fpcr(
    code: &[u8],
    regs: &[(u8, u64)],
    simd_regs: &[(u8, u64, u64)],
    fpcr: u32,
) -> ([u64; 31], [(u64, u64); 32], u64, u32) {
    let mut image = vec![0u8; 0x10000];
    image[..code.len()].copy_from_slice(code);
    image[code.len()..code.len() + 4].copy_from_slice(&0xd420_0000u32.to_le_bytes());

    let memory = FlatMemory::with_data(0, image);
    let mut config = AArch64Config::default();
    config.features.insert(ArmFeatures::FP16);
    let mut cpu = AArch64Cpu::new(config, Box::new(memory));
    cpu.set_pc(0);
    cpu.set_current_sp(0x8000);
    cpu.set_x(30, code.len() as u64);
    cpu.set_fpcr(fpcr).unwrap();
    for &(reg, value) in regs {
        cpu.set_x(reg, value);
    }
    for &(reg, low, high) in simd_regs {
        cpu.set_simd_reg(reg, low, high).unwrap();
    }

    let max_steps = code.len() / 4 + 4096;
    let mut saw_break = false;
    for _ in 0..max_steps {
        match cpu.step().unwrap() {
            CpuExit::Continue => {}
            CpuExit::Breakpoint(_) => {
                saw_break = true;
                break;
            }
            other => panic!("unexpected AArch64 CPU exit: {other:?}"),
        }
    }
    assert!(saw_break, "lowered code did not return to BRK sentinel");

    let mut out_regs = [0u64; 31];
    for reg in 0..31 {
        out_regs[reg] = cpu.get_x(reg as u8);
    }
    let mut out_simd = [(0u64, 0u64); 32];
    for reg in 0..32 {
        out_simd[reg] = cpu.get_simd_reg(reg as u8).unwrap();
    }
    (
        out_regs,
        out_simd,
        cpu.current_sp(),
        cpu.get_fpcr().unwrap(),
    )
}

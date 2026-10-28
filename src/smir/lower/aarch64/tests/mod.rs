//! tests.rs

use super::*;

// ---- split test submodules ----
#[cfg(test)]
mod apx;
#[cfg(test)]
mod arithmetic;
#[cfg(test)]
mod atomic;
#[cfg(test)]
mod bit;
#[cfg(test)]
mod fence;
#[cfg(test)]
mod flags;
#[cfg(test)]
mod fp;
mod fp_execution;
use fp_execution::run_aarch64_code_with_regs_simd_and_fpcr;
#[cfg(test)]
mod lane;
#[cfg(test)]
mod leave;
#[cfg(test)]
mod logic;
#[cfg(test)]
mod memory;
#[cfg(test)]
mod misc;
#[cfg(test)]
mod require_apx;
#[cfg(test)]
mod require_tbm;
#[cfg(test)]
mod shift;
#[cfg(test)]
mod tbm;
#[cfg(test)]
mod vector;
#[cfg(test)]
mod xchg;
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use crate::isa::arm::cpu_trait::{ArmCpu, CpuExit};
use crate::isa::arm::memory::FlatMemory;
use crate::isa::riscv::float::{
    F16, F32, RoundingMode, fcvt_round, sf_add, sf_div, sf_mul, sf_sub,
};
use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::types::{DispSize, FunctionId, SrcOperand, X86Reg};
use crate::smir::ir::{FunctionBuilder, SmirFunction, Terminator, TrapKind};

fn x(n: u8) -> VReg {
    VReg::Arch(ArchReg::Arm(ArmReg::X(n)))
}

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn v(n: u8) -> VReg {
    VReg::Arch(ArchReg::Arm(ArmReg::V(n)))
}

fn bextr_flags() -> FlagUpdate {
    FlagUpdate::Specific(FlagSet::CF.union(FlagSet::ZF).union(FlagSet::OF))
}

fn bzhi_flags() -> FlagUpdate {
    FlagUpdate::Specific(
        FlagSet::CF
            .union(FlagSet::ZF)
            .union(FlagSet::SF)
            .union(FlagSet::OF),
    )
}

fn rotate_flags() -> FlagUpdate {
    FlagUpdate::Specific(FlagSet::CF.union(FlagSet::OF))
}

fn bls_flags() -> FlagUpdate {
    FlagUpdate::Specific(
        FlagSet::CF
            .union(FlagSet::ZF)
            .union(FlagSet::SF)
            .union(FlagSet::OF),
    )
}

fn adx_flags(kind: X86AdxKind) -> FlagUpdate {
    FlagUpdate::Specific(match kind {
        X86AdxKind::Adcx => FlagSet::CF,
        X86AdxKind::Adox => FlagSet::OF,
    })
}

fn lower_single_op(kind: OpKind) -> Vec<u8> {
    lower_ops(vec![kind])
}

fn try_lower_single_op(kind: OpKind) -> Result<Vec<u8>, LowerError> {
    try_lower_ops(vec![kind])
}

fn try_lower_ops(kinds: Vec<OpKind>) -> Result<Vec<u8>, LowerError> {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0);
    for kind in kinds {
        builder.push_op(0, kind);
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();

    let mut lowerer = Aarch64Lowerer::new();
    lowerer.lower_function(&func)?;
    lowerer.finalize()
}

fn lower_ops(kinds: Vec<OpKind>) -> Vec<u8> {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0);
    for kind in kinds {
        builder.push_op(0, kind);
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();

    let mut lowerer = Aarch64Lowerer::new();
    lowerer.lower_function(&func).unwrap();
    lowerer.finalize().unwrap()
}

fn func_with_ops(kinds: Vec<OpKind>) -> SmirFunction {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0);
    for kind in kinds {
        builder.push_op(0, kind);
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    builder.finish()
}

fn lower_ops_with_flagm_features(kinds: Vec<OpKind>, flagm: bool, flagm2: bool) -> Vec<u8> {
    let func = func_with_ops(kinds);

    let mut lowerer = Aarch64Lowerer::new();
    lowerer.set_flagm_features_for_test(flagm, flagm2);
    lowerer.lower_function(&func).unwrap();
    lowerer.finalize().unwrap()
}

fn try_lower_ops_with_crc_feature(
    kinds: Vec<OpKind>,
    available: bool,
) -> Result<Vec<u8>, LowerError> {
    let func = func_with_ops(kinds);

    let mut lowerer = Aarch64Lowerer::new();
    lowerer.set_crc_available_for_test(available);
    lowerer.lower_function(&func)?;
    lowerer.finalize()
}

fn code_words(code: &[u8]) -> Vec<u32> {
    code.chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

fn code_has_flagm(code: &[u8], op2: u32) -> bool {
    code_words(code).contains(&enc_flagm(op2))
}

fn nzcv_word(nzcv: u8) -> u32 {
    (((nzcv & 0b1000) as u32) << 28)
        | (((nzcv & 0b0100) as u32) << 28)
        | (((nzcv & 0b0010) as u32) << 28)
        | (((nzcv & 0b0001) as u32) << 28)
}

fn nzcv_from_word(word: u32) -> u8 {
    (((word & NZCV_N as u32) != 0) as u8) << 3
        | (((word & NZCV_Z as u32) != 0) as u8) << 2
        | (((word & NZCV_C as u32) != 0) as u8) << 1
        | ((word & NZCV_V as u32) != 0) as u8
}

fn expected_axflag_nzcv(nzcv: u8) -> u8 {
    let flags = nzcv_word(nzcv);
    let result = ((flags | flags.wrapping_shl(2)) & NZCV_Z as u32)
        | ((flags & NZCV_C as u32) & !flags.wrapping_shl(1));
    nzcv_from_word(result)
}

fn expected_xaflag_nzcv(nzcv: u8) -> u8 {
    let flags = nzcv_word(nzcv);
    let result = (NZCV_N as u32 & !(flags.wrapping_shl(1) | flags.wrapping_shl(2)))
        | ((flags & NZCV_Z as u32) & flags.wrapping_shl(1))
        | ((flags | (flags >> 1)) & NZCV_C as u32)
        | (((flags >> 2) & !(flags >> 1)) & NZCV_V as u32);
    nzcv_from_word(result)
}

fn masked_carry_xor_op() -> OpKind {
    OpKind::Xor {
        dst: VReg::Arch(ArchReg::Arm(ArmReg::Nzcv)),
        src1: VReg::Arch(ArchReg::Arm(ArmReg::Nzcv)),
        src2: SrcOperand::Imm64(0x1_2000_0000),
        width: OpWidth::W32,
        flags: FlagUpdate::None,
    }
}

fn axflag_ops() -> Vec<OpKind> {
    let nzcv = VReg::Arch(ArchReg::Arm(ArmReg::Nzcv));
    let v_to_z = VReg::virt(0);
    let z_or_v = VReg::virt(1);
    let z_bit = VReg::virt(2);
    let v_to_c = VReg::virt(3);
    let c_raw = VReg::virt(4);
    let c_bit = VReg::virt(5);
    let result = VReg::virt(6);

    vec![
        OpKind::Shl {
            dst: v_to_z,
            src: nzcv,
            amount: SrcOperand::Imm64(66),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: z_or_v,
            src1: nzcv,
            src2: SrcOperand::Reg(v_to_z),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: z_bit,
            src1: z_or_v,
            src2: SrcOperand::Imm64(0x1_4000_0000),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Shl {
            dst: v_to_c,
            src: nzcv,
            amount: SrcOperand::Imm64(65),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: c_raw,
            src1: nzcv,
            src2: SrcOperand::Imm64(0x1_2000_0000),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::AndNot {
            dst: c_bit,
            src1: c_raw,
            src2: SrcOperand::Reg(v_to_c),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: result,
            src1: z_bit,
            src2: SrcOperand::Reg(c_bit),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Mov {
            dst: nzcv,
            src: SrcOperand::Reg(result),
            width: OpWidth::W32,
        },
    ]
}

fn xaflag_ops() -> Vec<OpKind> {
    let nzcv = VReg::Arch(ArchReg::Arm(ArmReg::Nzcv));
    let shl1 = VReg::virt(0);
    let shl2 = VReg::virt(1);
    let has_c_or_z_as_n = VReg::virt(2);
    let n_bit = VReg::virt(3);
    let z_raw = VReg::virt(4);
    let z_bit = VReg::virt(5);
    let shr1 = VReg::virt(6);
    let c_or_z = VReg::virt(7);
    let c_bit = VReg::virt(8);
    let shr2 = VReg::virt(9);
    let v_unmasked = VReg::virt(10);
    let v_bit = VReg::virt(11);
    let nz = VReg::virt(12);
    let cv = VReg::virt(13);
    let result = VReg::virt(14);

    vec![
        OpKind::Shl {
            dst: shl1,
            src: nzcv,
            amount: SrcOperand::Imm64(65),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Shl {
            dst: shl2,
            src: nzcv,
            amount: SrcOperand::Imm64(66),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: has_c_or_z_as_n,
            src1: shl1,
            src2: SrcOperand::Reg(shl2),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::AndNot {
            dst: n_bit,
            src1: VReg::Imm(NZCV_N),
            src2: SrcOperand::Reg(has_c_or_z_as_n),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: z_raw,
            src1: nzcv,
            src2: SrcOperand::Imm64(0x1_4000_0000),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: z_bit,
            src1: z_raw,
            src2: SrcOperand::Reg(shl1),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Shr {
            dst: shr1,
            src: nzcv,
            amount: SrcOperand::Imm64(65),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: c_or_z,
            src1: nzcv,
            src2: SrcOperand::Reg(shr1),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: c_bit,
            src1: c_or_z,
            src2: SrcOperand::Imm64(0x1_2000_0000),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Shr {
            dst: shr2,
            src: nzcv,
            amount: SrcOperand::Imm64(66),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::AndNot {
            dst: v_unmasked,
            src1: shr2,
            src2: SrcOperand::Reg(shr1),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: v_bit,
            src1: v_unmasked,
            src2: SrcOperand::Imm64(0x1_1000_0000),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: nz,
            src1: n_bit,
            src2: SrcOperand::Reg(z_bit),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: cv,
            src1: c_bit,
            src2: SrcOperand::Reg(v_bit),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: result,
            src1: nz,
            src2: SrcOperand::Reg(cv),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::Mov {
            dst: nzcv,
            src: SrcOperand::Reg(result),
            width: OpWidth::W32,
        },
    ]
}

fn run_aarch64_code(code: &[u8], regs: &[(u8, u64)], nzcv: u8) -> ([u64; 31], u8, u64) {
    let mut image = vec![0u8; 0x10000];
    image[..code.len()].copy_from_slice(code);
    image[code.len()..code.len() + 4].copy_from_slice(&0xd420_0000u32.to_le_bytes());

    let memory = FlatMemory::with_data(0, image);
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(memory));
    cpu.set_pc(0);
    cpu.set_current_sp(0x8000);
    cpu.set_x(30, code.len() as u64);
    cpu.set_nzcv(
        (nzcv & 0b1000) != 0,
        (nzcv & 0b0100) != 0,
        (nzcv & 0b0010) != 0,
        (nzcv & 0b0001) != 0,
    );
    for &(reg, value) in regs {
        cpu.set_x(reg, value);
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

    let mut out = [0u64; 31];
    for reg in 0..31 {
        out[reg] = cpu.get_x(reg as u8);
    }
    let out_nzcv = ((cpu.get_n() as u8) << 3)
        | ((cpu.get_z() as u8) << 2)
        | ((cpu.get_c() as u8) << 1)
        | (cpu.get_v() as u8);
    (out, out_nzcv, cpu.current_sp())
}

fn run_aarch64_code_with_simd(code: &[u8], simd_regs: &[(u8, u64, u64)]) -> [(u64, u64); 32] {
    run_aarch64_code_with_simd_and_nzcv(code, simd_regs, 0).0
}

fn run_aarch64_code_with_simd_and_nzcv(
    code: &[u8],
    simd_regs: &[(u8, u64, u64)],
    nzcv: u8,
) -> ([(u64, u64); 32], u8) {
    let mut image = vec![0u8; 0x10000];
    image[..code.len()].copy_from_slice(code);
    image[code.len()..code.len() + 4].copy_from_slice(&0xd420_0000u32.to_le_bytes());

    let memory = FlatMemory::with_data(0, image);
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(memory));
    cpu.set_pc(0);
    cpu.set_current_sp(0x8000);
    cpu.set_x(30, code.len() as u64);
    cpu.set_nzcv(
        (nzcv & 0b1000) != 0,
        (nzcv & 0b0100) != 0,
        (nzcv & 0b0010) != 0,
        (nzcv & 0b0001) != 0,
    );
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

    let mut out = [(0u64, 0u64); 32];
    for reg in 0..32 {
        out[reg] = cpu.get_simd_reg(reg as u8).unwrap();
    }
    let out_nzcv = ((cpu.get_n() as u8) << 3)
        | ((cpu.get_z() as u8) << 2)
        | ((cpu.get_c() as u8) << 1)
        | (cpu.get_v() as u8);
    (out, out_nzcv)
}

fn run_aarch64_code_with_regs_and_simd(
    code: &[u8],
    regs: &[(u8, u64)],
    simd_regs: &[(u8, u64, u64)],
) -> ([u64; 31], [(u64, u64); 32], u64) {
    let (regs, simd, sp, _) = run_aarch64_code_with_regs_simd_and_fpcr(code, regs, simd_regs, 0);
    (regs, simd, sp)
}

fn run_aarch64_code_with_regs_simd_and_memory(
    code: &[u8],
    regs: &[(u8, u64)],
    simd_regs: &[(u8, u64, u64)],
    mem_init: &[(u64, &[u8])],
    mem_read_addr: u64,
    mem_read_len: usize,
) -> ([u64; 31], [(u64, u64); 32], Vec<u8>) {
    let mut image = vec![0u8; 0x10000];
    image[..code.len()].copy_from_slice(code);
    image[code.len()..code.len() + 4].copy_from_slice(&0xd420_0000u32.to_le_bytes());
    for &(addr, data) in mem_init {
        let offset = addr as usize;
        image[offset..offset + data.len()].copy_from_slice(data);
    }

    let memory = FlatMemory::with_data(0, image);
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(memory));
    cpu.set_pc(0);
    cpu.set_current_sp(0x8000);
    cpu.set_x(30, code.len() as u64);
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
    let mem = cpu.read_memory(mem_read_addr, mem_read_len).unwrap();
    (out_regs, out_simd, mem)
}

fn run_aarch64_code_with_memory(
    code: &[u8],
    regs: &[(u8, u64)],
    nzcv: u8,
    mem_addr: u64,
    mem_value: u64,
    width: MemWidth,
) -> ([u64; 31], u8, u64, u64) {
    let mut image = vec![0u8; 0x10000];
    image[..code.len()].copy_from_slice(code);
    image[code.len()..code.len() + 4].copy_from_slice(&0xd420_0000u32.to_le_bytes());
    let mem_len = width.bytes() as usize;
    let mem_offset = mem_addr as usize;
    image[mem_offset..mem_offset + mem_len].copy_from_slice(&mem_value.to_le_bytes()[..mem_len]);

    let memory = FlatMemory::with_data(0, image);
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(memory));
    cpu.set_pc(0);
    cpu.set_current_sp(0x8000);
    cpu.set_x(30, code.len() as u64);
    cpu.set_nzcv(
        (nzcv & 0b1000) != 0,
        (nzcv & 0b0100) != 0,
        (nzcv & 0b0010) != 0,
        (nzcv & 0b0001) != 0,
    );
    for &(reg, value) in regs {
        cpu.set_x(reg, value);
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

    let mut out = [0u64; 31];
    for reg in 0..31 {
        out[reg] = cpu.get_x(reg as u8);
    }
    let out_nzcv = ((cpu.get_n() as u8) << 3)
        | ((cpu.get_z() as u8) << 2)
        | ((cpu.get_c() as u8) << 1)
        | (cpu.get_v() as u8);
    let mem = cpu.read_memory(mem_addr, mem_len).unwrap();
    let mut bytes = [0u8; 8];
    bytes[..mem_len].copy_from_slice(&mem);
    (out, out_nzcv, cpu.current_sp(), u64::from_le_bytes(bytes))
}

fn width_mask(width: OpWidth) -> u64 {
    match width {
        OpWidth::W64 => u64::MAX,
        _ => (1_u64 << width.bits()) - 1,
    }
}

fn simd_pair_bytes(pair: (u64, u64)) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&pair.0.to_le_bytes());
    bytes[8..].copy_from_slice(&pair.1.to_le_bytes());
    bytes
}

fn simd_pair_from_bytes(bytes: [u8; 16]) -> (u64, u64) {
    let mut low = [0u8; 8];
    let mut high = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    high.copy_from_slice(&bytes[8..]);
    (u64::from_le_bytes(low), u64::from_le_bytes(high))
}

fn set_simd_lane(pair: (u64, u64), elem: VecElementType, lane: u8, value: u64) -> (u64, u64) {
    let mut bytes = simd_pair_bytes(pair);
    let elem_bytes = elem.bytes() as usize;
    let base = lane as usize * elem_bytes;
    bytes[base..base + elem_bytes].copy_from_slice(&value.to_le_bytes()[..elem_bytes]);
    simd_pair_from_bytes(bytes)
}

fn get_simd_lane(pair: (u64, u64), elem: VecElementType, lane: u8) -> u64 {
    let bytes = simd_pair_bytes(pair);
    let elem_bytes = elem.bytes() as usize;
    let base = lane as usize * elem_bytes;
    let mut value = [0u8; 8];
    value[..elem_bytes].copy_from_slice(&bytes[base..base + elem_bytes]);
    u64::from_le_bytes(value)
}

fn sign_extend_simd_lane(value: u64, elem: VecElementType) -> u64 {
    let bits = elem.bytes() * 8;
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

fn simd_pair_from_f32(values: [f32; 4]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 4..idx * 4 + 4].copy_from_slice(&value.to_bits().to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn simd_pair_from_f32_bits(values: [u32; 4]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 4..idx * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn simd_pair_from_i32(values: [i32; 4]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 4..idx * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn simd_pair_from_i64(values: [i64; 2]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 8..idx * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn simd_pair_from_u64(values: [u64; 2]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 8..idx * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn simd_pair_from_f64(values: [f64; 2]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 8..idx * 8 + 8].copy_from_slice(&value.to_bits().to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn f16_bits(value: f32) -> u16 {
    let mut flags = 0;
    fcvt_round(
        F32,
        F16,
        value.to_bits() as u64,
        RoundingMode::Rne,
        &mut flags,
    ) as u16
}

fn simd_pair_from_f16(values: [u16; 8]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 2..idx * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn simd_pair_from_bf16(values: [u16; 8]) -> (u64, u64) {
    let mut bytes = [0u8; 16];
    for (idx, value) in values.iter().enumerate() {
        bytes[idx * 2..idx * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    simd_pair_from_bytes(bytes)
}

fn ref_f16_binop(a: u16, b: u16, op: Avx10FP16Op) -> u16 {
    let mut flags = 0;
    let a = a as u64;
    let b = b as u64;
    (match op {
        Avx10FP16Op::Add => sf_add(F16, a, b, RoundingMode::Rne, &mut flags),
        Avx10FP16Op::Sub => sf_sub(F16, a, b, RoundingMode::Rne, &mut flags),
        Avx10FP16Op::Mul => sf_mul(F16, a, b, RoundingMode::Rne, &mut flags),
        Avx10FP16Op::Div => sf_div(F16, a, b, RoundingMode::Rne, &mut flags),
        other => panic!("unsupported FP16 reference op {other:?}"),
    }) as u16
}

fn apply_f16_lanes(a: [u16; 8], b: [u16; 8], lanes: usize, op: Avx10FP16Op) -> (u64, u64) {
    let mut out = [0u16; 8];
    for lane in 0..lanes {
        out[lane] = ref_f16_binop(a[lane], b[lane], op);
    }
    simd_pair_from_f16(out)
}

fn ref_i8_dot(
    acc: [i32; 4],
    src1: [u8; 16],
    src2: [u8; 16],
    src1_unsigned: bool,
    lanes: usize,
) -> (u64, u64) {
    let mut out = [0i32; 4];
    for lane in 0..lanes {
        let mut sum = acc[lane];
        for elem in 0..4 {
            let idx = lane * 4 + elem;
            let a = if src1_unsigned {
                src1[idx] as i32
            } else {
                src1[idx] as i8 as i32
            };
            let b = src2[idx] as i8 as i32;
            sum = sum.wrapping_add(a * b);
        }
        out[lane] = sum;
    }
    simd_pair_from_i32(out)
}

fn ref_i8_dot_ext(
    acc: [i32; 4],
    src1: [u8; 16],
    src2: [u8; 16],
    src1_signed: bool,
    src2_signed: bool,
    lanes: usize,
) -> (u64, u64) {
    let mut out = [0i32; 4];
    for lane in 0..lanes {
        let mut sum = acc[lane];
        for elem in 0..4 {
            let idx = lane * 4 + elem;
            let a = if src1_signed {
                src1[idx] as i8 as i32
            } else {
                src1[idx] as i32
            };
            let b = if src2_signed {
                src2[idx] as i8 as i32
            } else {
                src2[idx] as i32
            };
            sum = sum.wrapping_add(a.wrapping_mul(b));
        }
        out[lane] = sum;
    }
    simd_pair_from_i32(out)
}

fn ref_bf16_dot(acc: [f32; 4], src1: [u16; 8], src2: [u16; 8], lanes: usize) -> (u64, u64) {
    let mut out = [0f32; 4];
    for lane in 0..lanes {
        let a0 = f32::from_bits((src1[lane * 2] as u32) << 16);
        let a1 = f32::from_bits((src1[lane * 2 + 1] as u32) << 16);
        let b0 = f32::from_bits((src2[lane * 2] as u32) << 16);
        let b1 = f32::from_bits((src2[lane * 2 + 1] as u32) << 16);
        out[lane] = acc[lane] + a0 * b0 + a1 * b1;
    }
    simd_pair_from_f32(out)
}

fn bf16_from_f32_bits(bits: u32) -> u16 {
    if (bits & 0x7f80_0000) == 0x7f80_0000 {
        if (bits & 0x007f_ffff) != 0 {
            return ((bits >> 16) as u16) | 0x0040;
        }
        return (bits >> 16) as u16;
    }
    let lsb = (bits >> 16) & 1;
    (bits.wrapping_add(0x7fff + lsb) >> 16) as u16
}

fn bf16_pair_from_f32_bits(values: [u32; 4]) -> (u64, u64) {
    let mut out = [0u16; 8];
    for lane in 0..4 {
        out[lane] = bf16_from_f32_bits(values[lane]);
    }
    simd_pair_from_f16(out)
}

fn bf16_pair_from_two_f32_bits(low_src: [u32; 4], high_src: [u32; 4]) -> (u64, u64) {
    let mut out = [0u16; 8];
    for lane in 0..4 {
        out[lane] = bf16_from_f32_bits(low_src[lane]);
        out[lane + 4] = bf16_from_f32_bits(high_src[lane]);
    }
    simd_pair_from_f16(out)
}

fn ref_shift_reg(src: u64, amount: u64, shift: ShiftOp, width: OpWidth) -> u64 {
    let bits = width.bits();
    let mask = width_mask(width);
    let src = src & mask;
    match shift {
        ShiftOp::Lsl => {
            let count = (amount & 0x3f) as u32;
            if count >= bits {
                0
            } else {
                (src << count) & mask
            }
        }
        ShiftOp::Lsr => {
            let count = (amount & 0x3f) as u32;
            if count >= bits { 0 } else { src >> count }
        }
        ShiftOp::Asr => {
            let count = (amount & 0x3f) as u32;
            let sign = 1_u64 << (bits - 1);
            if count == 0 {
                src
            } else if count >= bits {
                if (src & sign) != 0 { mask } else { 0 }
            } else if (src & sign) != 0 {
                ((src | !mask) as i64 >> count) as u64 & mask
            } else {
                src >> count
            }
        }
        ShiftOp::Ror => {
            let cmask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
            let count = ((amount & cmask) as u32) % bits;
            if count == 0 {
                src
            } else {
                ((src >> count) | (src << (bits - count))) & mask
            }
        }
        ShiftOp::Rrx => unreachable!(),
    }
}

fn ref_bidir_shift(src: u64, amount: u64, kind: u8, width: OpWidth) -> u64 {
    let bits = width.bits();
    let mask = width_mask(width);
    let src = src & mask;
    let low7 = (amount & 0x7f) as i64;
    let count = (low7 << 57) >> 57;
    let signed = if width == OpWidth::W64 {
        src as i64 as i128
    } else {
        (((src as i64) << (64 - bits)) >> (64 - bits)) as i128
    };
    let unsigned = src as u128;
    let result = match kind {
        0 => {
            if count < 0 {
                signed >> (-count as u32)
            } else {
                signed << (count as u32)
            }
        }
        1 => {
            if count < 0 {
                signed << (-count as u32)
            } else {
                signed >> (count as u32)
            }
        }
        2 => {
            if count < 0 {
                (unsigned >> (-count as u32)) as i128
            } else {
                (unsigned << (count as u32)) as i128
            }
        }
        _ => {
            if count < 0 {
                (unsigned << (-count as u32)) as i128
            } else {
                (unsigned >> (count as u32)) as i128
            }
        }
    };
    result as u64 & mask
}

fn shift_flag_left(src: u64, shift: ShiftOp, width: OpWidth) -> u64 {
    let src = src & width_mask(width);
    if shift != ShiftOp::Asr || width == OpWidth::W64 {
        return src;
    }

    let sign = 1_u64 << (width.bits() - 1);
    if (src & sign) != 0 {
        src | !width_mask(width)
    } else {
        src
    }
}

fn expected_shift_nzcv(
    old_nzcv: u8,
    src: u64,
    amount: u64,
    shift: ShiftOp,
    width: OpWidth,
    flags: FlagUpdate,
) -> u8 {
    let count = amount & 0x3f;
    if count == 0 || !flags.updates_any() {
        return old_nzcv;
    }

    let bits = u64::from(width.bits());
    let result = ref_shift_reg(src, amount, shift, width);
    let negative = ((result >> (width.bits() - 1)) & 1) != 0;
    let zero = result == 0;
    let left = shift_flag_left(src, shift, width);
    let carry = match shift {
        ShiftOp::Lsl => count <= bits && ((left >> (bits - count)) & 1) != 0,
        ShiftOp::Lsr => count <= bits && ((left >> (count - 1)) & 1) != 0,
        ShiftOp::Asr => ((left >> (count - 1)) & 1) != 0,
        ShiftOp::Ror | ShiftOp::Rrx => unreachable!(),
    };
    let overflow = match shift {
        ShiftOp::Lsl if count == 1 => carry != negative,
        ShiftOp::Lsr if count == 1 => (left & (1_u64 << (width.bits() - 1))) != 0,
        ShiftOp::Asr | ShiftOp::Lsl | ShiftOp::Lsr => false,
        ShiftOp::Ror | ShiftOp::Rrx => unreachable!(),
    };

    ((negative as u8) << 3) | ((zero as u8) << 2) | ((carry as u8) << 1) | (overflow as u8)
}

fn ref_rol_reg(src: u64, amount: u64, width: OpWidth) -> u64 {
    let bits = width.bits();
    let mask = width_mask(width);
    let src = src & mask;
    let cmask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
    let count = ((amount & cmask) as u32) % bits;
    if count == 0 {
        src
    } else {
        ((src << count) | (src >> (bits - count))) & mask
    }
}

fn ref_ror_reg(src: u64, amount: u64, width: OpWidth) -> u64 {
    let bits = width.bits();
    let mask = width_mask(width);
    let src = src & mask;
    let cmask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
    let count = ((amount & cmask) as u32) % bits;
    if count == 0 {
        src
    } else {
        ((src >> count) | (src << (bits - count))) & mask
    }
}

fn expected_rotate_nzcv(
    old_nzcv: u8,
    result: u64,
    amount: u64,
    width: OpWidth,
    flags: FlagUpdate,
    right: bool,
) -> u8 {
    let cmask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
    let masked = amount & cmask;
    if masked == 0 || !flags.updates_any() {
        return old_nzcv;
    }

    let sign = 1_u64 << (width.bits() - 1);
    let carry = if right {
        (result & sign) != 0
    } else {
        (result & 1) != 0
    };
    let overflow = if masked == 1 {
        if right {
            let second = (result & (sign >> 1)) != 0;
            carry != second
        } else {
            carry != ((result & sign) != 0)
        }
    } else {
        false
    };

    (old_nzcv & 0b1100) | ((carry as u8) << 1) | (overflow as u8)
}

fn ref_double_shift_imm(dst: u64, src: u64, amount: i64, left: bool, width: OpWidth) -> u64 {
    let bits = width.bits();
    let mask = width_mask(width);
    let dst = dst & mask;
    let src = src & mask;
    let count = (amount as u64 & 0x1f) as u32;
    if count == 0 {
        dst
    } else if count > bits {
        dst
    } else if count == bits {
        src
    } else if left {
        ((dst << count) | (src >> (bits - count))) & mask
    } else {
        ((dst >> count) | (src << (bits - count))) & mask
    }
}

fn ref_bfi(dst_in: u64, src: u64, lsb: u8, width_bits: u8, width: OpWidth) -> u64 {
    let field_bits = if width_bits == 64 {
        u64::MAX
    } else {
        (1_u64 << width_bits) - 1
    };
    let mask = (field_bits << lsb) & width_mask(width);
    ((dst_in & !mask) | ((src << lsb) & mask)) & width_mask(width)
}

fn ref_bfxil(dst_in: u64, src: u64, lsb: u8, width_bits: u8, width: OpWidth) -> u64 {
    let field_bits = if width_bits == 64 {
        u64::MAX
    } else {
        (1_u64 << width_bits) - 1
    };
    let mask = field_bits & width_mask(width);
    ((dst_in & !mask) | ((src >> lsb) & mask)) & width_mask(width)
}

fn ref_bextr(src: u64, control: u64, width: OpWidth) -> u64 {
    let src = src & width_mask(width);
    let start = (control & 0xff) as u32;
    let len = ((control >> 8) & 0xff) as u32;
    let bits = width.bits();
    if start >= bits || len == 0 {
        0
    } else {
        let shifted = src >> start;
        let result = if len >= bits {
            shifted
        } else {
            shifted & ((1_u64 << len) - 1)
        };
        result & width_mask(width)
    }
}

fn ref_bsf(src: u64, width: OpWidth) -> u64 {
    let src = src & width_mask(width);
    if src == 0 {
        0
    } else {
        u64::from(src.trailing_zeros())
    }
}

fn ref_bsr(src: u64, width: OpWidth) -> u64 {
    let src = src & width_mask(width);
    if src == 0 {
        0
    } else {
        u64::from(u64::BITS - 1 - src.leading_zeros())
    }
}

fn bit_test_index(index: u64, width: OpWidth) -> u32 {
    (index & u64::from(width.bits() - 1)) as u32
}

fn expected_bit_test_nzcv(old_nzcv: u8, src: u64, index: u64, width: OpWidth) -> u8 {
    let src = src & width_mask(width);
    let bit = ((src >> bit_test_index(index, width)) & 1) as u8;
    (old_nzcv & !0b0010) | (bit << 1)
}

fn ref_bit_update(src: u64, index: u64, action: BitTestAction, width: OpWidth) -> u64 {
    let src = src & width_mask(width);
    let mask = 1_u64 << bit_test_index(index, width);
    (match action {
        BitTestAction::Test => src,
        BitTestAction::Set => src | mask,
        BitTestAction::Reset => src & !mask,
        BitTestAction::Toggle => src ^ mask,
    }) & width_mask(width)
}

fn expected_logic_source_nzcv(old_nzcv: u8, src: u64, width: OpWidth, flags: FlagUpdate) -> u8 {
    let src = src & width_mask(width);
    let negative = ((src >> (width.bits() - 1)) & 1) != 0;
    let zero = src == 0;
    let produced = ((negative as u8) << 3) | ((zero as u8) << 2);
    match flags {
        FlagUpdate::None => old_nzcv,
        FlagUpdate::All => produced,
        FlagUpdate::Specific(set) => {
            let mut mask = 0;
            if set.contains(FlagSet::SF) {
                mask |= 0b1000;
            }
            if set.contains(FlagSet::ZF) {
                mask |= 0b0100;
            }
            if set.contains(FlagSet::CF) {
                mask |= 0b0010;
            }
            if set.contains(FlagSet::OF) {
                mask |= 0b0001;
            }
            (old_nzcv & !mask) | (produced & mask)
        }
    }
}

fn ref_logic(src1: u64, src2: u64, opc: u32, n: bool, width: OpWidth) -> u64 {
    let mask = width_mask(width);
    let src1 = src1 & mask;
    let mut src2 = src2 & mask;
    if n {
        src2 = (!src2) & mask;
    }
    (match opc {
        0b00 | 0b11 => src1 & src2,
        0b01 => src1 | src2,
        0b10 => src1 ^ src2,
        _ => unreachable!("invalid logical opc"),
    }) & mask
}

fn ref_inc_dec(src: u64, decrement: bool, width: OpWidth) -> u64 {
    let mask = width_mask(width);
    let src = src & mask;
    if decrement {
        src.wrapping_sub(1) & mask
    } else {
        src.wrapping_add(1) & mask
    }
}

fn expected_inc_dec_nzcv(old_nzcv: u8, src: u64, decrement: bool, width: OpWidth) -> u8 {
    let mask = width_mask(width);
    let src = src & mask;
    let result = ref_inc_dec(src, decrement, width);
    let sign = 1_u64 << (width.bits() - 1);
    let negative = (result & sign) != 0;
    let zero = result == 0;
    let overflow = if decrement {
        src == sign
    } else {
        src == sign - 1
    };

    ((negative as u8) << 3) | ((zero as u8) << 2) | (old_nzcv & 0b0010) | (overflow as u8)
}

fn ref_addsub(src1: u64, src2: u64, subtract: bool, width: OpWidth) -> u64 {
    let mask = width_mask(width);
    let src1 = src1 & mask;
    let src2 = src2 & mask;
    if subtract {
        src1.wrapping_sub(src2) & mask
    } else {
        src1.wrapping_add(src2) & mask
    }
}

fn expected_addsub_nzcv(src1: u64, src2: u64, subtract: bool, width: OpWidth) -> u8 {
    let mask = width_mask(width);
    let src1 = src1 & mask;
    let src2 = src2 & mask;
    let result = ref_addsub(src1, src2, subtract, width);
    let sign = 1_u64 << (width.bits() - 1);
    let negative = (result & sign) != 0;
    let zero = result == 0;
    let carry = if subtract {
        src1 >= src2
    } else {
        src1 + src2 > mask
    };
    let overflow = if subtract {
        ((src1 ^ src2) & (src1 ^ result) & sign) != 0
    } else {
        (!(src1 ^ src2) & (src1 ^ result) & sign) != 0
    };

    ((negative as u8) << 3) | ((zero as u8) << 2) | ((carry as u8) << 1) | (overflow as u8)
}

fn condition_holds_nzcv(cond: Condition, nzcv: u8) -> bool {
    let n = (nzcv & 0b1000) != 0;
    let z = (nzcv & 0b0100) != 0;
    let c = (nzcv & 0b0010) != 0;
    let v = (nzcv & 0b0001) != 0;
    match cond {
        Condition::Eq => z,
        Condition::Ne => !z,
        Condition::Uge => c,
        Condition::Ult => !c,
        Condition::Negative => n,
        Condition::Positive => !n,
        Condition::Overflow => v,
        Condition::NoOverflow => !v,
        Condition::Ugt => c && !z,
        Condition::Ule => !c || z,
        Condition::Sge => n == v,
        Condition::Slt => n != v,
        Condition::Sgt => !z && n == v,
        Condition::Sle => z || n != v,
        Condition::Always => true,
        Condition::Parity | Condition::NoParity => {
            unreachable!("unsupported AArch64 condition")
        }
    }
}

fn find_cond_compare_word(code: &[u8]) -> Option<u32> {
    code.chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .find(|word| {
            ((word >> 21) & 0x1ff) == 0b111010010
                && ((word >> 10) & 1) == 0
                && ((word >> 4) & 1) == 0
        })
}

fn ref_addsub_carry(src1: u64, src2: u64, carry_in: bool, subtract: bool, width: OpWidth) -> u64 {
    let mask = width_mask(width);
    let src1 = src1 & mask;
    let src2 = src2 & mask;
    if subtract {
        let borrow = u64::from(!carry_in);
        src1.wrapping_sub(src2).wrapping_sub(borrow) & mask
    } else {
        src1.wrapping_add(src2).wrapping_add(u64::from(carry_in)) & mask
    }
}

fn expected_addsub_carry_nzcv(
    src1: u64,
    src2: u64,
    carry_in: bool,
    subtract: bool,
    width: OpWidth,
) -> u8 {
    let mask = width_mask(width);
    let src1 = src1 & mask;
    let src2 = src2 & mask;
    let result = ref_addsub_carry(src1, src2, carry_in, subtract, width);
    let sign = 1_u64 << (width.bits() - 1);
    let negative = (result & sign) != 0;
    let zero = result == 0;
    let carry = if subtract {
        u128::from(src1) >= u128::from(src2) + u128::from(!carry_in)
    } else {
        u128::from(src1) + u128::from(src2) + u128::from(carry_in) > u128::from(mask)
    };
    let overflow = if subtract {
        ((src1 ^ src2) & (src1 ^ result) & sign) != 0
    } else {
        (!(src1 ^ src2) & (src1 ^ result) & sign) != 0
    };

    ((negative as u8) << 3) | ((zero as u8) << 2) | ((carry as u8) << 1) | (overflow as u8)
}

fn ref_x86_sbb(src1: u64, src2: u64, borrow_in: bool, width: OpWidth) -> u64 {
    let mask = width_mask(width);
    (src1 & mask)
        .wrapping_sub(src2 & mask)
        .wrapping_sub(u64::from(borrow_in))
        & mask
}

fn expected_x86_sbb_nzcv(src1: u64, src2: u64, borrow_in: bool, width: OpWidth) -> u8 {
    let mask = width_mask(width);
    let src1 = src1 & mask;
    let src2 = src2 & mask;
    let result = ref_x86_sbb(src1, src2, borrow_in, width);
    let sign = 1_u64 << (width.bits() - 1);
    let negative = (result & sign) != 0;
    let zero = result == 0;
    let borrow = u128::from(src1) < u128::from(src2) + u128::from(borrow_in);
    let overflow = ((src1 ^ src2) & (src1 ^ result) & sign) != 0;

    ((negative as u8) << 3) | ((zero as u8) << 2) | ((borrow as u8) << 1) | (overflow as u8)
}

fn sign_extend_width(value: u64, width: OpWidth) -> i64 {
    let shift = 64 - width.bits();
    ((value & width_mask(width)) << shift) as i64 >> shift
}

fn ref_mul(src1: u64, src2: u64, signed: bool, width: OpWidth) -> u64 {
    let mask = width_mask(width);
    if signed {
        let product =
            (sign_extend_width(src1, width) as i128) * (sign_extend_width(src2, width) as i128);
        product as u64 & mask
    } else {
        ((src1 & mask) as u128 * (src2 & mask) as u128) as u64 & mask
    }
}

fn ref_div(src1: u64, src2: u64, signed: bool, width: OpWidth) -> (u64, u64) {
    let mask = width_mask(width);
    if signed {
        let dividend = sign_extend_width(src1, width) as i128;
        let divisor = sign_extend_width(src2, width) as i128;
        (
            (dividend / divisor) as u64 & mask,
            (dividend % divisor) as u64 & mask,
        )
    } else {
        let dividend = src1 & mask;
        let divisor = src2 & mask;
        (dividend / divisor, dividend % divisor)
    }
}

fn expected_mul_nzcv(src1: u64, src2: u64, signed: bool, width: OpWidth) -> u8 {
    let mask = width_mask(width);
    let result = ref_mul(src1, src2, signed, width);
    let sign = 1_u64 << (width.bits() - 1);
    let negative = (result & sign) != 0;
    let zero = result == 0;
    let overflow = if signed {
        let product =
            (sign_extend_width(src1, width) as i128) * (sign_extend_width(src2, width) as i128);
        product != sign_extend_width(result, width) as i128
    } else {
        ((src1 & mask) as u128 * (src2 & mask) as u128) > mask as u128
    };

    ((negative as u8) << 3) | ((zero as u8) << 2) | ((overflow as u8) << 1) | (overflow as u8)
}

fn assert_inc_dec_flags_lowering(
    label: &str,
    decrement: bool,
    dst_reg: u8,
    src_reg: u8,
    src_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let op = if decrement {
        OpKind::Dec {
            dst: x(dst_reg),
            src: x(src_reg),
            width,
            flags: FlagUpdate::All,
        }
    } else {
        OpKind::Inc {
            dst: x(dst_reg),
            src: x(src_reg),
            width,
            flags: FlagUpdate::All,
        }
    };
    let code = lower_single_op(op);
    let expected = ref_inc_dec(src_value, decrement, width);
    let expected_nzcv = expected_inc_dec_nzcv(old_nzcv, src_value, decrement, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != src_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_subword_neg_flags_lowering(
    label: &str,
    dst: VReg,
    src_reg: u8,
    src_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let op = OpKind::Neg {
        dst,
        src: x(src_reg),
        width,
        flags: FlagUpdate::All,
    };
    let dst_reg = if let VReg::Arch(ArchReg::Arm(ArmReg::X(reg))) = dst {
        Some(reg)
    } else {
        None
    };
    let code = lower_single_op(op);
    let expected = ref_addsub(0, src_value, true, width);
    let expected_nzcv = expected_addsub_nzcv(0, src_value, true, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if let Some(reg) = dst_reg {
        assert_eq!(out[reg as usize], expected, "{label}: result");
    }
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if Some(src_reg) != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if Some(reg) != dst_reg && reg != src_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_subword_addsub_flags_lowering(
    label: &str,
    subtract: bool,
    dst_reg: u8,
    src1_reg: u8,
    src1_value: u64,
    src2: SrcOperand,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let op = if subtract {
        OpKind::Sub {
            dst: x(dst_reg),
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        }
    } else {
        OpKind::Add {
            dst: x(dst_reg),
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        }
    };
    let code = lower_single_op(op);
    let expected = ref_addsub(src1_value, src2_value, subtract, width);
    let expected_nzcv = expected_addsub_nzcv(src1_value, src2_value, subtract, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
        (13, 0x1313_1313_1313_1313),
        (12, 0x1212_1212_1212_1212),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    let src2_reg = if let SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg)))) = src2 {
        regs.push((reg, src2_value));
        Some(reg)
    } else {
        None
    };

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src1_reg != dst_reg {
        assert_eq!(
            out[src1_reg as usize], src1_value,
            "{label}: src1 preserved"
        );
    }
    if let Some(reg) = src2_reg {
        if reg != dst_reg {
            assert_eq!(out[reg as usize], src2_value, "{label}: src2 preserved");
        }
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != src1_reg && Some(reg) != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_addsub_carry_lowering(
    label: &str,
    subtract: bool,
    set_flags: bool,
    dst: VReg,
    src1_reg: u8,
    src1_value: u64,
    src2: SrcOperand,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let flags = if set_flags {
        FlagUpdate::All
    } else {
        FlagUpdate::None
    };
    let op = if subtract {
        OpKind::Sbb {
            dst,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags,
        }
    } else {
        OpKind::Adc {
            dst,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags,
        }
    };
    let dst_reg = if let VReg::Arch(ArchReg::Arm(ArmReg::X(reg))) = dst {
        Some(reg)
    } else {
        None
    };
    let code = lower_single_op(op);
    let carry_in = (old_nzcv & 0b0010) != 0;
    let expected = ref_addsub_carry(src1_value, src2_value, carry_in, subtract, width);
    let expected_nzcv = if set_flags {
        expected_addsub_carry_nzcv(src1_value, src2_value, carry_in, subtract, width)
    } else {
        old_nzcv
    };
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    let src2_reg = if let SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg)))) = src2 {
        regs.push((reg, src2_value));
        Some(reg)
    } else {
        None
    };

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if let Some(reg) = dst_reg {
        assert_eq!(out[reg as usize], expected, "{label}: result");
    }
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if Some(src1_reg) != dst_reg {
        assert_eq!(
            out[src1_reg as usize], src1_value,
            "{label}: src1 preserved"
        );
    }
    if let Some(reg) = src2_reg {
        if Some(reg) != dst_reg {
            assert_eq!(out[reg as usize], src2_value, "{label}: src2 preserved");
        }
    }
    for (reg, value) in sentinels {
        if Some(reg) != dst_reg && reg != src1_reg && Some(reg) != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_subword_addsub_carry_flags_lowering(
    label: &str,
    subtract: bool,
    dst_reg: u8,
    src1_reg: u8,
    src2_reg: u8,
    src1_value: u64,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let op = if subtract {
        OpKind::Sbb {
            dst: x(dst_reg),
            src1: x(src1_reg),
            src2: SrcOperand::Reg(x(src2_reg)),
            width,
            flags: FlagUpdate::All,
        }
    } else {
        OpKind::Adc {
            dst: x(dst_reg),
            src1: x(src1_reg),
            src2: SrcOperand::Reg(x(src2_reg)),
            width,
            flags: FlagUpdate::All,
        }
    };
    let code = lower_single_op(op);
    let carry_in = (old_nzcv & 0b0010) != 0;
    let expected = ref_addsub_carry(src1_value, src2_value, carry_in, subtract, width);
    let expected_nzcv =
        expected_addsub_carry_nzcv(src1_value, src2_value, carry_in, subtract, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
        (13, 0x1313_1313_1313_1313),
        (12, 0x1212_1212_1212_1212),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    regs.push((src2_reg, src2_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src1_reg != dst_reg {
        assert_eq!(
            out[src1_reg as usize], src1_value,
            "{label}: src1 preserved"
        );
    }
    if src2_reg != dst_reg {
        assert_eq!(
            out[src2_reg as usize], src2_value,
            "{label}: src2 preserved"
        );
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != src1_reg && reg != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_cond_compare_imm_lowering(
    label: &str,
    subtract: bool,
    cond: Condition,
    src1_reg: u8,
    src1_value: u64,
    src2: SrcOperand,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
    fallback_nzcv: u8,
) {
    let cond_vreg = VReg::virt(0);
    let cmp_nzcv = VReg::virt(2);
    let final_nzcv = VReg::virt(3);
    let cmp_op = if subtract {
        OpKind::Sub {
            dst: VReg::virt(1),
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        }
    } else {
        OpKind::Add {
            dst: VReg::virt(1),
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        }
    };
    let code = lower_ops(vec![
        OpKind::TestCondition {
            dst: cond_vreg,
            cond,
        },
        cmp_op,
        OpKind::Mov {
            dst: cmp_nzcv,
            src: SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::Nzcv))),
            width: OpWidth::W32,
        },
        OpKind::Select {
            dst: final_nzcv,
            cond: cond_vreg,
            src_true: cmp_nzcv,
            src_false: VReg::Imm(i64::from(fallback_nzcv & 0xf) << 28),
            width: OpWidth::W32,
        },
        OpKind::Mov {
            dst: VReg::Arch(ArchReg::Arm(ArmReg::Nzcv)),
            src: SrcOperand::Reg(final_nzcv),
            width: OpWidth::W32,
        },
    ]);
    let cond_compare = find_cond_compare_word(&code)
        .unwrap_or_else(|| panic!("{label}: expected fused conditional compare"));
    assert_eq!(
        (cond_compare >> 11) & 1,
        0,
        "{label}: expected register-form conditional compare"
    );

    let expected_nzcv = if condition_holds_nzcv(cond, old_nzcv) {
        expected_addsub_nzcv(src1_value, src2_value, subtract, width)
    } else {
        fallback_nzcv & 0xf
    };
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(
        out[src1_reg as usize], src1_value,
        "{label}: src1 preserved"
    );
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != src1_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_cmp_lowering(
    label: &str,
    src1_reg: u8,
    src1_value: u64,
    src2: SrcOperand,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let code = lower_single_op(OpKind::Cmp {
        src1: x(src1_reg),
        src2: src2.clone(),
        width,
    });
    let expected_nzcv = expected_addsub_nzcv(src1_value, src2_value, true, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    let src2_reg = if let SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg)))) = src2 {
        regs.push((reg, src2_value));
        Some(reg)
    } else {
        None
    };

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(
        out[src1_reg as usize], src1_value,
        "{label}: src1 preserved"
    );
    if let Some(reg) = src2_reg {
        assert_eq!(out[reg as usize], src2_value, "{label}: src2 preserved");
    }
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != src1_reg && Some(reg) != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_test_lowering(
    label: &str,
    src1_reg: u8,
    src1_value: u64,
    src2: SrcOperand,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let code = lower_single_op(OpKind::Test {
        src1: x(src1_reg),
        src2: src2.clone(),
        width,
    });
    let result = ref_logic(src1_value, src2_value, 0b00, false, width);
    let expected_nzcv = expected_logic_source_nzcv(old_nzcv, result, width, FlagUpdate::All);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    let src2_reg = if let SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg)))) = src2 {
        regs.push((reg, src2_value));
        Some(reg)
    } else {
        None
    };

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(
        out[src1_reg as usize], src1_value,
        "{label}: src1 preserved"
    );
    if let Some(reg) = src2_reg {
        assert_eq!(out[reg as usize], src2_value, "{label}: src2 preserved");
    }
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != src1_reg && Some(reg) != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_subword_logic_flags_lowering(
    label: &str,
    opc: u32,
    n: bool,
    dst: VReg,
    src1_reg: u8,
    src2: SrcOperand,
    src1_value: u64,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let op = match (opc, n) {
        (0b00, false) => OpKind::And {
            dst,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        },
        (0b00, true) => OpKind::AndNot {
            dst,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        },
        (0b01, false) => OpKind::Or {
            dst,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        },
        (0b10, false) => OpKind::Xor {
            dst,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        },
        _ => unreachable!("unsupported logical test shape"),
    };
    let dst_reg = if let VReg::Arch(ArchReg::Arm(ArmReg::X(reg))) = dst {
        Some(reg)
    } else {
        None
    };
    let code = lower_single_op(op);
    let expected = ref_logic(src1_value, src2_value, opc, n, width);
    let expected_nzcv = expected_logic_source_nzcv(old_nzcv, expected, width, FlagUpdate::All);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    let src2_reg = if let SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg)))) = src2 {
        regs.push((reg, src2_value));
        Some(reg)
    } else {
        None
    };

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if let Some(reg) = dst_reg {
        assert_eq!(out[reg as usize], expected, "{label}: result");
    }
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if Some(src1_reg) != dst_reg {
        assert_eq!(
            out[src1_reg as usize], src1_value,
            "{label}: src1 preserved"
        );
    }
    if let Some(reg) = src2_reg {
        if Some(reg) != dst_reg {
            assert_eq!(out[reg as usize], src2_value, "{label}: src2 preserved");
        }
    }
    for (reg, value) in sentinels {
        if Some(reg) != dst_reg && reg != src1_reg && Some(reg) != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_subword_mul_flags_lowering(
    label: &str,
    signed: bool,
    dst_reg: u8,
    src1_reg: u8,
    src2: SrcOperand,
    src1_value: u64,
    src2_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let op = if signed {
        OpKind::MulS {
            dst_lo: x(dst_reg),
            dst_hi: None,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        }
    } else {
        OpKind::MulU {
            dst_lo: x(dst_reg),
            dst_hi: None,
            src1: x(src1_reg),
            src2: src2.clone(),
            width,
            flags: FlagUpdate::All,
        }
    };
    let code = lower_single_op(op);
    let expected = ref_mul(src1_value, src2_value, signed, width);
    let expected_nzcv = expected_mul_nzcv(src1_value, src2_value, signed, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
        (13, 0x1313_1313_1313_1313),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    let src2_reg = if let SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg)))) = src2 {
        regs.push((reg, src2_value));
        Some(reg)
    } else {
        None
    };

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src1_reg != dst_reg {
        assert_eq!(
            out[src1_reg as usize], src1_value,
            "{label}: src1 preserved"
        );
    }
    if let Some(reg) = src2_reg {
        if reg != dst_reg {
            assert_eq!(out[reg as usize], src2_value, "{label}: src2 preserved");
        }
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != src1_reg && Some(reg) != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_sparse_logic_imm_lowering(
    label: &str,
    op: OpKind,
    src_reg: u8,
    src_value: u64,
    dst_reg: Option<u8>,
    expected: u64,
    expected_nzcv: u8,
) {
    let code = lower_single_op(op);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));

    let old_nzcv = 0b0011;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if let Some(dst_reg) = dst_reg {
        assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    }
    assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if Some(reg) != dst_reg && reg != src_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_full_width_mul_lowering(
    label: &str,
    signed: bool,
    dst_lo: u8,
    dst_hi: u8,
    src1_reg: u8,
    src2_reg: u8,
    src1_value: u64,
    src2_value: u64,
) {
    let op = if signed {
        OpKind::MulS {
            dst_lo: x(dst_lo),
            dst_hi: Some(x(dst_hi)),
            src1: x(src1_reg),
            src2: SrcOperand::Reg(x(src2_reg)),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        }
    } else {
        OpKind::MulU {
            dst_lo: x(dst_lo),
            dst_hi: Some(x(dst_hi)),
            src1: x(src1_reg),
            src2: SrcOperand::Reg(x(src2_reg)),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        }
    };
    let code = lower_single_op(op);
    let product = if signed {
        (src1_value as i64 as i128 * src2_value as i64 as i128) as u128
    } else {
        (src1_value as u128) * (src2_value as u128)
    };
    let expected_lo = product as u64;
    let expected_hi = (product >> 64) as u64;
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    regs.push((src2_reg, src2_value));

    let old_nzcv = 0b1010;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if dst_lo != dst_hi {
        assert_eq!(out[dst_lo as usize], expected_lo, "{label}: low half");
    }
    assert_eq!(out[dst_hi as usize], expected_hi, "{label}: high half");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != dst_lo && reg != dst_hi && reg != src1_reg && reg != src2_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_full_width_mul_imm_lowering(
    label: &str,
    signed: bool,
    dst_lo: u8,
    dst_hi: u8,
    src1_reg: u8,
    src1_value: u64,
    src2: SrcOperand,
    src2_value: u64,
) {
    let op = if signed {
        OpKind::MulS {
            dst_lo: x(dst_lo),
            dst_hi: Some(x(dst_hi)),
            src1: x(src1_reg),
            src2,
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        }
    } else {
        OpKind::MulU {
            dst_lo: x(dst_lo),
            dst_hi: Some(x(dst_hi)),
            src1: x(src1_reg),
            src2,
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        }
    };
    let code = lower_single_op(op);
    let product = if signed {
        (src1_value as i64 as i128 * src2_value as i64 as i128) as u128
    } else {
        (src1_value as u128) * (src2_value as u128)
    };
    let expected_lo = product as u64;
    let expected_hi = (product >> 64) as u64;
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));

    let old_nzcv = 0b1010;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_lo as usize], expected_lo, "{label}: low half");
    assert_eq!(out[dst_hi as usize], expected_hi, "{label}: high half");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != dst_lo && reg != dst_hi && reg != src1_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_sub64_full_mul_lowering(
    label: &str,
    signed: bool,
    width: OpWidth,
    dst_lo: u8,
    dst_hi: u8,
    src1_reg: u8,
    src2_reg: u8,
    src1_value: u64,
    src2_value: u64,
) {
    assert!(matches!(width, OpWidth::W16 | OpWidth::W32));
    let op = if signed {
        OpKind::MulS {
            dst_lo: x(dst_lo),
            dst_hi: Some(x(dst_hi)),
            src1: x(src1_reg),
            src2: SrcOperand::Reg(x(src2_reg)),
            width,
            flags: FlagUpdate::None,
        }
    } else {
        OpKind::MulU {
            dst_lo: x(dst_lo),
            dst_hi: Some(x(dst_hi)),
            src1: x(src1_reg),
            src2: SrcOperand::Reg(x(src2_reg)),
            width,
            flags: FlagUpdate::None,
        }
    };
    let code = lower_single_op(op);

    let mut initial = [0_u64; 31];
    for reg in 0..18_u8 {
        initial[reg as usize] = 0xA000_0000_0000_0000 | u64::from(reg) * 0x0101_0101_0101;
    }
    initial[src1_reg as usize] = src1_value;
    initial[src2_reg as usize] = src2_value;
    let mask = width.mask();
    let product = if signed {
        let shift = 64 - width.bits();
        let lhs = (((src1_value & mask) << shift) as i64) >> shift;
        let rhs = (((src2_value & mask) << shift) as i64) >> shift;
        (i128::from(lhs) * i128::from(rhs)) as u128
    } else {
        u128::from(src1_value & mask) * u128::from(src2_value & mask)
    };
    let low = product as u64 & mask;
    let high = (product >> width.bits()) as u64 & mask;
    let merge = |old: u64, half: u64| {
        if width == OpWidth::W16 {
            (old & !mask) | half
        } else {
            half
        }
    };
    let expected_lo = merge(initial[dst_lo as usize], low);
    let expected_hi = merge(initial[dst_hi as usize], high);
    let regs = (0..18_u8)
        .map(|reg| (reg, initial[reg as usize]))
        .collect::<Vec<_>>();

    let old_nzcv = 0b1010;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if dst_lo != dst_hi {
        assert_eq!(out[dst_lo as usize], expected_lo, "{label}: low half");
    }
    assert_eq!(out[dst_hi as usize], expected_hi, "{label}: high half");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for reg in 0..18_u8 {
        if reg != dst_lo && reg != dst_hi {
            assert_eq!(
                out[reg as usize], initial[reg as usize],
                "{label}: x{reg} restored"
            );
        }
    }
}

fn assert_div_w64_lowering(
    label: &str,
    signed: bool,
    quot: u8,
    rem: Option<u8>,
    src1_reg: u8,
    src2: SrcOperand,
    src2_reg: Option<u8>,
    src1_value: u64,
    src2_value: u64,
    flags: FlagUpdate,
) {
    let op = if signed {
        OpKind::DivS {
            quot: x(quot),
            rem: rem.map(x),
            src1: x(src1_reg),
            src2,
            width: OpWidth::W64,
            flags,
        }
    } else {
        OpKind::DivU {
            quot: x(quot),
            rem: rem.map(x),
            src1: x(src1_reg),
            src2,
            width: OpWidth::W64,
            flags,
        }
    };
    let code = lower_single_op(op);
    let (expected_quot, expected_rem) = if signed {
        let dividend = src1_value as i64 as i128;
        let divisor = src2_value as i64 as i128;
        (
            (dividend / divisor) as i64 as u64,
            (dividend % divisor) as i64 as u64,
        )
    } else {
        (src1_value / src2_value, src1_value % src2_value)
    };
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    if let Some(src2_reg) = src2_reg {
        regs.push((src2_reg, src2_value));
    }

    let old_nzcv = 0b0101;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if rem != Some(quot) {
        assert_eq!(out[quot as usize], expected_quot, "{label}: quotient");
    }
    if let Some(rem) = rem {
        assert_eq!(out[rem as usize], expected_rem, "{label}: remainder");
    }
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != quot && rem != Some(reg) && reg != src1_reg && src2_reg != Some(reg) {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_div_runtime_lowering(
    label: &str,
    signed: bool,
    quot: u8,
    rem: Option<u8>,
    src1_reg: u8,
    src2: SrcOperand,
    src2_reg: Option<u8>,
    src1_value: u64,
    src2_value: u64,
    width: OpWidth,
) {
    let op = if signed {
        OpKind::DivS {
            quot: x(quot),
            rem: rem.map(x),
            src1: x(src1_reg),
            src2,
            width,
            flags: FlagUpdate::None,
        }
    } else {
        OpKind::DivU {
            quot: x(quot),
            rem: rem.map(x),
            src1: x(src1_reg),
            src2,
            width,
            flags: FlagUpdate::None,
        }
    };
    let code = lower_single_op(op);
    let (expected_quot, expected_rem) = ref_div(src1_value, src2_value, signed, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src1_reg, src1_value));
    if let Some(src2_reg) = src2_reg {
        regs.push((src2_reg, src2_value));
    }

    let old_nzcv = 0b0101;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    if rem != Some(quot) {
        assert_eq!(out[quot as usize], expected_quot, "{label}: quotient");
    }
    if let Some(rem) = rem {
        assert_eq!(out[rem as usize], expected_rem, "{label}: remainder");
    }
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src1_reg != quot && rem != Some(src1_reg) {
        assert_eq!(
            out[src1_reg as usize], src1_value,
            "{label}: src1 preserved"
        );
    }
    if let Some(src2_reg) = src2_reg {
        if src2_reg != quot && rem != Some(src2_reg) {
            assert_eq!(
                out[src2_reg as usize], src2_value,
                "{label}: src2 preserved"
            );
        }
    }
    for (reg, value) in sentinels {
        if reg != quot && rem != Some(reg) && reg != src1_reg && src2_reg != Some(reg) {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_cas_lowering(
    label: &str,
    dst: u8,
    success: Option<u8>,
    expected: u8,
    new_val: u8,
    width: MemWidth,
    mem_value: u64,
    expected_value: u64,
    new_value: u64,
) {
    let success_vreg = success.map(x).unwrap_or_else(|| VReg::virt(0));
    let code = lower_single_op(OpKind::Cas {
        dst: x(dst),
        success: success_vreg,
        addr: Address::Direct(x(1)),
        expected: x(expected),
        new_val: x(new_val),
        width,
        order: MemoryOrder::AcqRel,
    });
    let mask = match width {
        MemWidth::B1 => 0xff,
        MemWidth::B2 => 0xffff,
        MemWidth::B4 => 0xffff_ffff,
        MemWidth::B8 => u64::MAX,
        other => panic!("unsupported CAS test width {other:?}"),
    };
    let old = mem_value & mask;
    let expected_masked = expected_value & mask;
    let new_masked = new_value & mask;
    let succeeded = old == expected_masked;
    let expected_mem = if succeeded { new_masked } else { old };
    let mem_addr = 0x9000;
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((1, mem_addr));
    regs.push((expected, expected_value));
    regs.push((new_val, new_value));

    let old_nzcv = 0b1011;
    let (out, out_nzcv, sp, mem) =
        run_aarch64_code_with_memory(&code, &regs, old_nzcv, mem_addr, mem_value, width);
    if success != Some(dst) {
        assert_eq!(out[dst as usize], old, "{label}: old value");
    }
    if let Some(success) = success {
        assert_eq!(out[success as usize], succeeded as u64, "{label}: success");
    }
    if expected != dst && success != Some(expected) {
        assert_eq!(
            out[expected as usize], expected_value,
            "{label}: expected preserved"
        );
    }
    if new_val != dst && success != Some(new_val) && new_val != expected {
        assert_eq!(
            out[new_val as usize], new_value,
            "{label}: new value preserved"
        );
    }
    assert_eq!(mem, expected_mem, "{label}: memory");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != dst && success != Some(reg) && reg != expected && reg != new_val {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn set_initial_reg(regs: &mut Vec<(u8, u64)>, reg: u8, value: u64) {
    if let Some(entry) = regs.iter_mut().find(|(existing, _)| *existing == reg) {
        entry.1 = value;
    } else {
        regs.push((reg, value));
    }
}

fn ref_atomic_cmpxadd(
    old: u64,
    cmp: u64,
    add: u64,
    cond: Condition,
    width: MemWidth,
) -> (u64, u64, u8) {
    let flags_width = match width {
        MemWidth::B1 => OpWidth::W8,
        MemWidth::B2 => OpWidth::W16,
        MemWidth::B4 => OpWidth::W32,
        MemWidth::B8 => OpWidth::W64,
        other => panic!("unsupported AtomicCmpXadd test width {other:?}"),
    };
    let mask = mem_width_mask(width);
    let old = old & mask;
    let cmp = cmp & mask;
    let add = add & mask;
    let nzcv = expected_addsub_nzcv(old, cmp, true, flags_width);
    let new = if condition_holds_nzcv(cond, nzcv) {
        old.wrapping_add(add) & mask
    } else {
        old
    };
    (old, new, nzcv)
}

fn assert_atomic_cmpxadd_lowering(
    label: &str,
    dst_old: u8,
    base: u8,
    cmp: u8,
    add: u8,
    cond: Condition,
    width: MemWidth,
    mem_value: u64,
    cmp_value: u64,
    add_value: u64,
) {
    let code = lower_single_op(OpKind::AtomicCmpXadd {
        dst_old: x(dst_old),
        addr: Address::Direct(x(base)),
        cmp: x(cmp),
        add: x(add),
        cond,
        width,
        order: MemoryOrder::SeqCst,
    });
    let (expected_old, expected_mem, expected_nzcv) =
        ref_atomic_cmpxadd(mem_value, cmp_value, add_value, cond, width);
    let mem_addr = 0x9000;
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    set_initial_reg(&mut regs, base, mem_addr);
    set_initial_reg(&mut regs, cmp, cmp_value);
    set_initial_reg(&mut regs, add, add_value);

    let old_nzcv = 0b0110;
    let (out, out_nzcv, sp, mem) =
        run_aarch64_code_with_memory(&code, &regs, old_nzcv, mem_addr, mem_value, width);
    assert_eq!(out[dst_old as usize], expected_old, "{label}: old value");
    assert_eq!(mem, expected_mem, "{label}: memory");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if base != dst_old && base != cmp && base != add {
        assert_eq!(out[base as usize], mem_addr, "{label}: base preserved");
    }
    if cmp != dst_old && cmp != base {
        assert_eq!(out[cmp as usize], cmp_value, "{label}: cmp preserved");
    }
    if add != dst_old && add != base && add != cmp {
        assert_eq!(out[add as usize], add_value, "{label}: add preserved");
    }
    for (reg, value) in sentinels {
        if reg != dst_old && reg != base && reg != cmp && reg != add {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn mem_width_mask(width: MemWidth) -> u64 {
    let bits = width.bytes() * 8;
    if bits >= 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    }
}

fn ref_atomic_rmw(old: u64, operand: u64, width: MemWidth, op: AtomicOp) -> (u64, u64) {
    let bits = width.bytes() * 8;
    let mask = mem_width_mask(width);
    let old = old & mask;
    let operand = operand & mask;
    let sext = |value: u64| -> i64 {
        if bits >= 64 {
            value as i64
        } else {
            ((value << (64 - bits)) as i64) >> (64 - bits)
        }
    };
    let new = match op {
        AtomicOp::Add => old.wrapping_add(operand),
        AtomicOp::Sub => old.wrapping_sub(operand),
        AtomicOp::Neg => 0u64.wrapping_sub(old),
        AtomicOp::And => old & operand,
        AtomicOp::Or => old | operand,
        AtomicOp::Xor => old ^ operand,
        AtomicOp::Nand => !(old & operand),
        AtomicOp::Max => std::cmp::max(sext(old), sext(operand)) as u64,
        AtomicOp::Min => std::cmp::min(sext(old), sext(operand)) as u64,
        AtomicOp::Umax => std::cmp::max(old, operand),
        AtomicOp::Umin => std::cmp::min(old, operand),
        AtomicOp::Swap => operand,
    } & mask;
    (old, new)
}

fn assert_atomic_rmw_lowering(
    label: &str,
    op: AtomicOp,
    dst: u8,
    base: u8,
    src: VReg,
    src_reg: Option<u8>,
    src_value: u64,
    width: MemWidth,
    order: MemoryOrder,
    mem_value: u64,
) {
    let code = lower_single_op(OpKind::AtomicRmw {
        dst: x(dst),
        addr: Address::Direct(x(base)),
        src,
        op,
        width,
        order,
    });
    let (expected_old, expected_mem) = ref_atomic_rmw(mem_value, src_value, width, op);
    let mem_addr = 0x9000;
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((base, mem_addr));
    if let Some(src_reg) = src_reg {
        regs.push((src_reg, src_value));
    }

    let old_nzcv = 0b0111;
    let (out, out_nzcv, sp, mem) =
        run_aarch64_code_with_memory(&code, &regs, old_nzcv, mem_addr, mem_value, width);
    assert_eq!(out[dst as usize], expected_old, "{label}: old value");
    assert_eq!(mem, expected_mem, "{label}: memory");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if base != dst {
        assert_eq!(out[base as usize], mem_addr, "{label}: base preserved");
    }
    if let Some(src_reg) = src_reg {
        if src_reg != dst {
            assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
        }
    }
    for (reg, value) in sentinels {
        if reg != dst && reg != base && src_reg != Some(reg) {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_bit_scan_lowering(
    label: &str,
    reverse: bool,
    dst_reg: u8,
    src_reg: u8,
    src_value: u64,
    width: OpWidth,
    flags: FlagUpdate,
    old_nzcv: u8,
) {
    let op = if reverse {
        OpKind::Bsr {
            dst: x(dst_reg),
            src: x(src_reg),
            width,
            flags,
        }
    } else {
        OpKind::Bsf {
            dst: x(dst_reg),
            src: x(src_reg),
            width,
            flags,
        }
    };
    let code = lower_single_op(op);
    let expected = if reverse {
        ref_bsr(src_value, width)
    } else {
        ref_bsf(src_value, width)
    };
    let expected_nzcv = expected_logic_source_nzcv(old_nzcv, src_value, width, flags);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_shift_reg_count_alias_lowering(
    label: &str,
    shift: ShiftOp,
    src_reg: u8,
    src_value: u64,
    amount_reg: u8,
    amount_value: u64,
    width: OpWidth,
    dst_reg: u8,
) {
    let amount = SrcOperand::Reg(x(amount_reg));
    let op = match shift {
        ShiftOp::Lsl => OpKind::Shl {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags: FlagUpdate::None,
        },
        ShiftOp::Lsr => OpKind::Shr {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags: FlagUpdate::None,
        },
        ShiftOp::Asr => OpKind::Sar {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags: FlagUpdate::None,
        },
        ShiftOp::Ror => OpKind::Ror {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags: FlagUpdate::None,
        },
        ShiftOp::Rrx => unreachable!(),
    };
    let code = lower_single_op(op);
    let expected = ref_shift_reg(src_value, amount_value, shift, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    regs.push((amount_reg, amount_value));

    let old_nzcv = 0b1011;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if amount_reg != dst_reg {
        assert_eq!(
            out[amount_reg as usize], amount_value,
            "{label}: count preserved"
        );
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != amount_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_shift_flags_lowering(
    label: &str,
    shift: ShiftOp,
    src_reg: u8,
    src_value: u64,
    amount_reg: Option<u8>,
    amount_value: u64,
    width: OpWidth,
    dst_reg: u8,
    old_nzcv: u8,
) {
    let amount = amount_reg
        .map(|reg| SrcOperand::Reg(x(reg)))
        .unwrap_or_else(|| SrcOperand::Imm(amount_value as i64));
    let flags = FlagUpdate::All;
    let op = match shift {
        ShiftOp::Lsl => OpKind::Shl {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags,
        },
        ShiftOp::Lsr => OpKind::Shr {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags,
        },
        ShiftOp::Asr => OpKind::Sar {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags,
        },
        ShiftOp::Ror | ShiftOp::Rrx => unreachable!(),
    };
    let code = lower_single_op(op);
    let expected = ref_shift_reg(src_value, amount_value, shift, width);
    let expected_nzcv = expected_shift_nzcv(old_nzcv, src_value, amount_value, shift, width, flags);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    if let Some(amount_reg) = amount_reg {
        regs.push((amount_reg, amount_value));
    }

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if let Some(amount_reg) = amount_reg {
        if amount_reg != dst_reg {
            assert_eq!(
                out[amount_reg as usize], amount_value,
                "{label}: count preserved"
            );
        }
    }
    for (reg, value) in sentinels {
        if reg != src_reg && amount_reg != Some(reg) && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_rotate_flags_lowering(
    label: &str,
    right: bool,
    src_reg: u8,
    src_value: u64,
    amount_reg: Option<u8>,
    amount_value: u64,
    width: OpWidth,
    dst_reg: u8,
    old_nzcv: u8,
) {
    let amount = amount_reg
        .map(|reg| SrcOperand::Reg(x(reg)))
        .unwrap_or_else(|| SrcOperand::Imm(amount_value as i64));
    let flags = FlagUpdate::All;
    let op = if right {
        OpKind::Ror {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags,
        }
    } else {
        OpKind::Rol {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags,
        }
    };
    let code = lower_single_op(op);
    let expected = if right {
        ref_ror_reg(src_value, amount_value, width)
    } else {
        ref_rol_reg(src_value, amount_value, width)
    };
    let expected_nzcv = expected_rotate_nzcv(old_nzcv, expected, amount_value, width, flags, right);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    if let Some(amount_reg) = amount_reg {
        regs.push((amount_reg, amount_value));
    }

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if let Some(amount_reg) = amount_reg {
        if amount_reg != dst_reg {
            assert_eq!(
                out[amount_reg as usize], amount_value,
                "{label}: count preserved"
            );
        }
    }
    for (reg, value) in sentinels {
        if reg != src_reg && amount_reg != Some(reg) && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_rol_reg_lowering(
    label: &str,
    src_reg: u8,
    src_value: u64,
    amount_reg: u8,
    amount_value: u64,
    width: OpWidth,
    dst_reg: u8,
) {
    let code = lower_single_op(OpKind::Rol {
        dst: x(dst_reg),
        src: x(src_reg),
        amount: SrcOperand::Reg(x(amount_reg)),
        width,
        flags: FlagUpdate::None,
    });
    let expected = ref_rol_reg(src_value, amount_value, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    regs.push((amount_reg, amount_value));

    let old_nzcv = 0b0110;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if amount_reg != dst_reg {
        assert_eq!(
            out[amount_reg as usize], amount_value,
            "{label}: count preserved"
        );
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != amount_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_double_shift_imm_lowering(
    label: &str,
    left: bool,
    dst_reg: u8,
    dst_value: u64,
    src_reg: u8,
    src_value: u64,
    amount: i64,
    width: OpWidth,
) {
    let op = if left {
        OpKind::Shld {
            dst: x(dst_reg),
            src: x(src_reg),
            amount: SrcOperand::Imm(amount),
            width,
            flags: FlagUpdate::None,
        }
    } else {
        OpKind::Shrd {
            dst: x(dst_reg),
            src: x(src_reg),
            amount: SrcOperand::Imm(amount),
            width,
            flags: FlagUpdate::None,
        }
    };
    let code = lower_single_op(op);
    let expected = ref_double_shift_imm(dst_value, src_value, amount, left, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((dst_reg, dst_value));
    regs.push((src_reg, src_value));

    let old_nzcv = 0b1001;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_shrd_imm_src_lowering(
    label: &str,
    dst_value: u64,
    src_value: i64,
    amount: i64,
    width: OpWidth,
) {
    let op = OpKind::Shrd {
        dst: x(0),
        src: VReg::Imm(src_value),
        amount: SrcOperand::Imm(amount),
        width,
        flags: FlagUpdate::None,
    };
    let code = lower_single_op(op);
    let expected = ref_double_shift_imm(dst_value, src_value as u64, amount, false, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((0, dst_value));

    let old_nzcv = 0b1001;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[0] & width_mask(width), expected, "{label}: result");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
    }
}

fn ref_double_shift_reg(dst: u64, src: u64, amount: u64, left: bool, width: OpWidth) -> u64 {
    let bits = width.bits();
    let mask = width_mask(width);
    let dst = dst & mask;
    let src = src & mask;
    let count_mask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
    let count = (amount & count_mask) as u32;
    if count == 0 {
        dst
    } else if count > bits {
        dst
    } else if count == bits {
        src
    } else if left {
        ((dst << count) | (src >> (bits - count))) & mask
    } else {
        ((dst >> count) | (src << (bits - count))) & mask
    }
}

fn assert_double_shift_reg_lowering(
    label: &str,
    left: bool,
    dst_reg: u8,
    dst_value: u64,
    src_reg: u8,
    src_value: u64,
    amount_reg: u8,
    amount_value: u64,
    width: OpWidth,
) {
    if dst_reg == src_reg {
        assert_eq!(dst_value, src_value, "{label}: aliased dst/src setup");
    }
    if dst_reg == amount_reg {
        assert_eq!(dst_value, amount_value, "{label}: aliased dst/count setup");
    }
    if src_reg == amount_reg {
        assert_eq!(src_value, amount_value, "{label}: aliased src/count setup");
    }

    let op = if left {
        OpKind::Shld {
            dst: x(dst_reg),
            src: x(src_reg),
            amount: SrcOperand::Reg(x(amount_reg)),
            width,
            flags: FlagUpdate::None,
        }
    } else {
        OpKind::Shrd {
            dst: x(dst_reg),
            src: x(src_reg),
            amount: SrcOperand::Reg(x(amount_reg)),
            width,
            flags: FlagUpdate::None,
        }
    };
    let code = lower_single_op(op);
    let expected = ref_double_shift_reg(dst_value, src_value, amount_value, left, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((dst_reg, dst_value));
    regs.push((src_reg, src_value));
    regs.push((amount_reg, amount_value));

    let old_nzcv = 0b1010;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if amount_reg != dst_reg {
        assert_eq!(
            out[amount_reg as usize], amount_value,
            "{label}: count preserved"
        );
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != src_reg && reg != amount_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn ref_double_shift_flags_value(
    dst: u64,
    src: u64,
    amount: u64,
    left: bool,
    width: OpWidth,
) -> u64 {
    let bits = width.bits();
    let mask = width_mask(width);
    let dst = dst & mask;
    let src = src & mask;
    let count_mask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
    let count = (amount & count_mask) as u32;
    if count == 0 {
        dst
    } else if count >= bits {
        src
    } else if left {
        ((dst << count) | (src >> (bits - count))) & mask
    } else {
        ((dst >> count) | (src << (bits - count))) & mask
    }
}

fn expected_double_shift_nzcv(
    old_nzcv: u8,
    dst: u64,
    result: u64,
    amount: u64,
    left: bool,
    width: OpWidth,
    flags: FlagUpdate,
) -> u8 {
    let count_mask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
    let count = (amount & count_mask) as u32;
    if count == 0 || !flags.updates_any() {
        return old_nzcv;
    }

    let bits = width.bits();
    let mask = width_mask(width);
    let dst = dst & mask;
    let result = result & mask;
    let sign = 1_u64 << (bits - 1);
    let negative = (result & sign) != 0;
    let zero = result == 0;
    let carry = if left {
        ((dst >> (bits - count)) & 1) != 0
    } else {
        ((dst >> (count - 1)) & 1) != 0
    };
    let overflow = count == 1 && ((result ^ dst) & sign) != 0;

    ((negative as u8) << 3) | ((zero as u8) << 2) | ((carry as u8) << 1) | (overflow as u8)
}

fn assert_double_shift_flags_lowering(
    label: &str,
    left: bool,
    dst_reg: u8,
    dst_value: u64,
    src_reg: u8,
    src_value: u64,
    amount_reg: Option<u8>,
    amount_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    if dst_reg == src_reg {
        assert_eq!(dst_value, src_value, "{label}: aliased dst/src setup");
    }
    if amount_reg == Some(dst_reg) {
        assert_eq!(dst_value, amount_value, "{label}: aliased dst/count setup");
    }
    if amount_reg == Some(src_reg) {
        assert_eq!(src_value, amount_value, "{label}: aliased src/count setup");
    }

    let flags = FlagUpdate::All;
    let amount = amount_reg
        .map(|reg| SrcOperand::Reg(x(reg)))
        .unwrap_or_else(|| SrcOperand::Imm(amount_value as i64));
    let op = if left {
        OpKind::Shld {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags,
        }
    } else {
        OpKind::Shrd {
            dst: x(dst_reg),
            src: x(src_reg),
            amount,
            width,
            flags,
        }
    };
    let code = lower_single_op(op);
    let expected = ref_double_shift_flags_value(dst_value, src_value, amount_value, left, width);
    let expected_nzcv = expected_double_shift_nzcv(
        old_nzcv,
        dst_value,
        expected,
        amount_value,
        left,
        width,
        flags,
    );
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((dst_reg, dst_value));
    regs.push((src_reg, src_value));
    if let Some(amount_reg) = amount_reg {
        regs.push((amount_reg, amount_value));
    }

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if let Some(amount_reg) = amount_reg {
        if amount_reg != dst_reg {
            assert_eq!(
                out[amount_reg as usize], amount_value,
                "{label}: count preserved"
            );
        }
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != src_reg && amount_reg != Some(reg) {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_bfi_lowering(
    label: &str,
    dst_reg: u8,
    dst_in_reg: u8,
    dst_in_value: u64,
    src_reg: u8,
    src_value: u64,
    lsb: u8,
    width_bits: u8,
    width: OpWidth,
) {
    let code = lower_single_op(OpKind::Bfi {
        dst: x(dst_reg),
        dst_in: x(dst_in_reg),
        src: x(src_reg),
        lsb,
        width_bits,
        op_width: width,
    });
    let expected = ref_bfi(dst_in_value, src_value, lsb, width_bits, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((dst_in_reg, dst_in_value));
    regs.push((src_reg, src_value));

    let old_nzcv = 0b1101;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if dst_in_reg != dst_reg {
        assert_eq!(
            out[dst_in_reg as usize], dst_in_value,
            "{label}: dst_in preserved"
        );
    }
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != dst_in_reg && reg != src_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_fused_bfxil_lowering(
    label: &str,
    dst_reg: u8,
    dst_in_reg: u8,
    dst_in_value: u64,
    src_reg: u8,
    src_value: u64,
    lsb: u8,
    width_bits: u8,
    width: OpWidth,
) {
    let extracted = VReg::virt(0);
    let code = lower_ops(vec![
        OpKind::Bfx {
            dst: extracted,
            src: x(src_reg),
            lsb,
            width_bits,
            sign_extend: false,
            op_width: width,
        },
        OpKind::Bfi {
            dst: x(dst_reg),
            dst_in: x(dst_in_reg),
            src: extracted,
            lsb: 0,
            width_bits,
            op_width: width,
        },
    ]);
    let expected = ref_bfxil(dst_in_value, src_value, lsb, width_bits, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((dst_in_reg, dst_in_value));
    regs.push((src_reg, src_value));

    let old_nzcv = 0b0011;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected,
        "{label}: result"
    );
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if dst_in_reg != dst_reg {
        assert_eq!(
            out[dst_in_reg as usize], dst_in_value,
            "{label}: dst_in preserved"
        );
    }
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != dst_in_reg && reg != src_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn ref_bzhi(src: u64, index: u64, width: OpWidth) -> (u64, bool) {
    let index = (index & 0xff) as u32;
    let mask = width_mask(width);
    if index >= width.bits() {
        (src & mask, true)
    } else if index == 0 {
        (0, false)
    } else {
        (src & ((1_u64 << index) - 1) & mask, false)
    }
}

fn expected_bzhi_nzcv(
    old_nzcv: u8,
    result: u64,
    carry: bool,
    width: OpWidth,
    flags: FlagUpdate,
) -> u8 {
    if !flags.updates_any() {
        return old_nzcv;
    }

    let result = result & width_mask(width);
    let negative = ((result >> (width.bits() - 1)) & 1) != 0;
    let zero = result == 0;
    ((negative as u8) << 3) | ((zero as u8) << 2) | ((carry as u8) << 1)
}

fn expected_bextr_nzcv(old_nzcv: u8, result: u64, width: OpWidth, flags: FlagUpdate) -> u8 {
    if !flags.updates_any() {
        return old_nzcv;
    }
    (old_nzcv & 0b1000) | (u8::from(result & width.mask() == 0) << 2)
}

fn expected_bextr_flag_merge_words(sf: u32, result: u32) -> [u32; 11] {
    [
        enc_ldst_simm_regs(3, 0b00, 0b11, -16, 16, 31), // str x16,[sp,#-16]!
        enc_ldst_simm_regs(3, 0b00, 0b11, -16, 17, 31), // str x17,[sp,#-16]!
        0xd53b_4210,                                    // mrs x16,nzcv
        enc_logical_reg_n(sf, 0b11, 0, 31, result, result), // ands xzr,result,result
        0xd53b_4211,                                    // mrs x17,nzcv
        0x1201_7210,                                    // and w16,w16,#0x8fffffff
        0x1204_0a31,                                    // and w17,w17,#0x70000000
        enc_logical_reg_n(0, 0b01, 0, 16, 16, 17),      // orr w16,w16,w17
        0xd51b_4210,                                    // msr nzcv,x16
        enc_ldst_simm_regs(3, 0b01, 0b01, 16, 17, 31),  // ldr x17,[sp],#16
        enc_ldst_simm_regs(3, 0b01, 0b01, 16, 16, 31),  // ldr x16,[sp],#16
    ]
}

fn assert_bzhi_imm_index_lowering(
    label: &str,
    src_reg: u8,
    src_value: u64,
    index: i64,
    width: OpWidth,
    dst_reg: u8,
    flags: FlagUpdate,
    old_nzcv: u8,
) {
    let code = lower_single_op(OpKind::Bzhi {
        dst: x(dst_reg),
        src: x(src_reg),
        index: VReg::Imm(index),
        width,
        flags,
    });

    let (expected, carry) = ref_bzhi(src_value, index as u64, width);
    let expected_nzcv = expected_bzhi_nzcv(old_nzcv, expected, carry, width, flags);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_bextr_runtime_control_lowering(
    label: &str,
    dst_reg: u8,
    src_reg: u8,
    src_value: u64,
    control_reg: u8,
    control_value: u64,
    width: OpWidth,
    flags: FlagUpdate,
    old_nzcv: u8,
) {
    let code = lower_single_op(OpKind::Bextr {
        dst: x(dst_reg),
        src: x(src_reg),
        control: x(control_reg),
        width,
        flags,
    });
    assert!(
        code.len() > 32,
        "{label}: runtime BEXTR should include scratch save/restore"
    );

    let expected = ref_bextr(src_value, control_value, width);
    let expected_nzcv = expected_bextr_nzcv(old_nzcv, expected, width, flags);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    regs.push((control_reg, control_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if control_reg != dst_reg {
        assert_eq!(
            out[control_reg as usize], control_value,
            "{label}: control preserved"
        );
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != control_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_bzhi_runtime_index_lowering(
    label: &str,
    src_reg: u8,
    src_value: u64,
    index_reg: u8,
    index_value: u64,
    width: OpWidth,
    dst_reg: u8,
    flags: FlagUpdate,
    old_nzcv: u8,
) {
    let code = lower_single_op(OpKind::Bzhi {
        dst: x(dst_reg),
        src: x(src_reg),
        index: x(index_reg),
        width,
        flags,
    });
    if dst_reg == src_reg || dst_reg == index_reg {
        assert!(
            code.len() > 32,
            "{label}: aliasing runtime BZHI should save and restore a scratch register"
        );
    }

    let (expected, carry) = ref_bzhi(src_value, index_value, width);
    let expected_nzcv = expected_bzhi_nzcv(old_nzcv, expected, carry, width, flags);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    regs.push((index_reg, index_value));

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if index_reg != dst_reg {
        assert_eq!(
            out[index_reg as usize], index_value,
            "{label}: index preserved"
        );
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != index_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn ref_rotate_carry(
    value: u64,
    count: u64,
    carry_in: bool,
    width: OpWidth,
    right: bool,
) -> (u64, bool, u64) {
    let bits = width.bits() as u64;
    let cmask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
    let effective = (count & cmask) % (bits + 1);
    let mask = width_mask(width);
    let mut result = value & mask;
    let mut carry = carry_in;

    for _ in 0..effective {
        if right {
            let next = (result & 1) != 0;
            result = (result >> 1) | (u64::from(carry) << (bits - 1));
            carry = next;
        } else {
            let next = ((result >> (bits - 1)) & 1) != 0;
            result = ((result << 1) | u64::from(carry)) & mask;
            carry = next;
        }
    }

    (result & mask, carry, effective)
}

fn expected_rotate_carry_nzcv(
    old_nzcv: u8,
    result: u64,
    carry: bool,
    effective: u64,
    width: OpWidth,
    flags: FlagUpdate,
    right: bool,
) -> u8 {
    if effective == 0 || !flags.updates_any() {
        return old_nzcv;
    }

    let sign = 1_u64 << (width.bits() - 1);
    let overflow = if effective == 1 {
        if right {
            let msb = (result & sign) != 0;
            let second = (result & (sign >> 1)) != 0;
            msb != second
        } else {
            ((result & sign) != 0) != carry
        }
    } else {
        false
    };

    (old_nzcv & 0b1100) | ((carry as u8) << 1) | (overflow as u8)
}

fn assert_rotate_carry_lowering(
    label: &str,
    op: OpKind,
    src_value: u64,
    count_value: u64,
    old_nzcv: u8,
    width: OpWidth,
    flags: FlagUpdate,
    right: bool,
    dst_reg: u8,
    amount_reg: Option<u8>,
) {
    let old_carry = (old_nzcv & 0b0010) != 0;
    let (expected_value, expected_carry, effective) =
        ref_rotate_carry(src_value, count_value, old_carry, width, right);
    let expected_nzcv = expected_rotate_carry_nzcv(
        old_nzcv,
        expected_value,
        expected_carry,
        effective,
        width,
        flags,
        right,
    );
    let code = lower_single_op(op);
    if amount_reg.is_some() || effective != 0 {
        assert!(
            code.len() > 16,
            "{label}: carry rotate lowering should include scratch save/restore"
        );
    }

    let mut regs = vec![
        (1, src_value),
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    if let Some(amount_reg) = amount_reg {
        regs.push((amount_reg, count_value));
    }

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[dst_reg as usize] & width_mask(width),
        expected_value,
        "{label}: result"
    );
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    assert_eq!(out[16], 0x1616_1616_1616_1616, "{label}: x16 restored");
    assert_eq!(out[17], 0x1717_1717_1717_1717, "{label}: x17 restored");
    assert_eq!(out[15], 0x1515_1515_1515_1515, "{label}: x15 restored");
    assert_eq!(out[14], 0x1414_1414_1414_1414, "{label}: x14 restored");
}

fn assert_pdep_pext_runtime_mask_lowering(
    label: &str,
    deposit: bool,
    src_reg: Option<u8>,
    src_value: u64,
    mask_reg: u8,
    mask_value: u64,
    width: OpWidth,
    dst_reg: u8,
) {
    let src = src_reg
        .map(x)
        .unwrap_or_else(|| VReg::Imm(src_value as i64));
    let op = if deposit {
        OpKind::Pdep {
            dst: x(dst_reg),
            src,
            mask: x(mask_reg),
            width,
        }
    } else {
        OpKind::Pext {
            dst: x(dst_reg),
            src,
            mask: x(mask_reg),
            width,
        }
    };
    let code = lower_single_op(op);
    let expected = if deposit {
        Aarch64Lowerer::eval_pdep(src_value & width_mask(width), mask_value, width.bits())
    } else {
        Aarch64Lowerer::eval_pext(src_value & width_mask(width), mask_value, width.bits())
    } & width_mask(width);

    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    if let Some(src_reg) = src_reg {
        regs.push((src_reg, src_value));
    }
    regs.push((mask_reg, mask_value));

    let old_nzcv = 0b1011;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");

    if let Some(src_reg) = src_reg {
        if src_reg != dst_reg {
            assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
        }
    }
    if mask_reg != dst_reg {
        assert_eq!(
            out[mask_reg as usize], mask_value,
            "{label}: mask preserved"
        );
    }
    for (reg, value) in sentinels {
        if Some(reg) != src_reg && reg != mask_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_pdep_pext_const_mask_lowering(
    label: &str,
    deposit: bool,
    src_reg: u8,
    src_value: u64,
    mask_value: u64,
    width: OpWidth,
    dst_reg: u8,
) {
    let op = if deposit {
        OpKind::Pdep {
            dst: x(dst_reg),
            src: x(src_reg),
            mask: VReg::Imm(mask_value as i64),
            width,
        }
    } else {
        OpKind::Pext {
            dst: x(dst_reg),
            src: x(src_reg),
            mask: VReg::Imm(mask_value as i64),
            width,
        }
    };
    let code = lower_single_op(op);
    if dst_reg == src_reg {
        assert!(
            code.len() > 32,
            "{label}: aliasing sparse immediate mask should save and restore a scratch register"
        );
    }

    let mask_value = mask_value & width_mask(width);
    let expected = if deposit {
        Aarch64Lowerer::eval_pdep(src_value & width_mask(width), mask_value, width.bits())
    } else {
        Aarch64Lowerer::eval_pext(src_value & width_mask(width), mask_value, width.bits())
    } & width_mask(width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));

    let old_nzcv = 0b0110;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    for (reg, value) in sentinels {
        if reg != src_reg && reg != dst_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn enc_ldst_simm(size: u32, opc: u32, mode: u32, imm9: i64) -> u32 {
    (size << 30)
        | (0b111 << 27)
        | (opc << 22)
        | (((imm9 as u32) & 0x1ff) << 12)
        | (mode << 10)
        | (1 << 5)
}

fn enc_ldst_simm_regs(size: u32, opc: u32, mode: u32, imm9: i64, rt: u32, rn: u32) -> u32 {
    (size << 30)
        | (0b111 << 27)
        | (opc << 22)
        | (((imm9 as u32) & 0x1ff) << 12)
        | (mode << 10)
        | (rn << 5)
        | rt
}

fn enc_simd_ldst_simm_regs(size: u32, opc: u32, mode: u32, imm9: i64, rt: u32, rn: u32) -> u32 {
    (size << 30)
        | (0b111 << 27)
        | (1 << 26)
        | (opc << 22)
        | (((imm9 as u32) & 0x1ff) << 12)
        | (mode << 10)
        | (rn << 5)
        | rt
}

fn enc_ldst_uimm(size: u32, opc: u32, imm12: u32) -> u32 {
    (size << 30) | (0b111 << 27) | (0b01 << 24) | (opc << 22) | (imm12 << 10) | (1 << 5)
}

fn enc_ldst_uimm_regs(size: u32, opc: u32, imm12: u32, rt: u32, rn: u32) -> u32 {
    (size << 30) | (0b111 << 27) | (0b01 << 24) | (opc << 22) | (imm12 << 10) | (rn << 5) | rt
}

fn enc_ldst_reg(size: u32, opc: u32, rm: u32, option: u32, s: u32) -> u32 {
    enc_ldst_reg_regs(size, opc, rm, 1, 0, option, s)
}

fn enc_ldst_reg_regs(size: u32, opc: u32, rm: u32, rn: u32, rt: u32, option: u32, s: u32) -> u32 {
    (size << 30)
        | (0b111 << 27)
        | (opc << 22)
        | (1 << 21)
        | (rm << 16)
        | (option << 13)
        | (s << 12)
        | (0b10 << 10)
        | (rn << 5)
        | rt
}

fn enc_prfm_lit(rt: u32, imm19: i32) -> u32 {
    (0b11 << 30) | (0b011 << 27) | (((imm19 as u32) & 0x7ffff) << 5) | (rt & 0x1f)
}

fn enc_ldp(opc: u32, mode: u32, load: bool, imm7: i64) -> u32 {
    (opc << 30)
        | (0b101 << 27)
        | (mode << 23)
        | ((load as u32) << 22)
        | (((imm7 as u32) & 0x7f) << 15)
        | (2 << 10)
        | (1 << 5)
}

fn enc_ldp_regs(opc: u32, mode: u32, load: bool, imm7: i64, rt: u32, rt2: u32, rn: u32) -> u32 {
    (opc << 30)
        | (0b101 << 27)
        | (mode << 23)
        | ((load as u32) << 22)
        | (((imm7 as u32) & 0x7f) << 15)
        | (rt2 << 10)
        | (rn << 5)
        | rt
}

fn enc_ldxr(size: u32) -> u32 {
    enc_ldxr_regs(size, 0, 1)
}

fn enc_ldxr_regs(size: u32, rt: u32, rn: u32) -> u32 {
    (size << 30) | (0b001000 << 24) | (1 << 22) | (0b11111 << 16) | (0b11111 << 10) | (rn << 5) | rt
}

fn enc_stxr(size: u32) -> u32 {
    enc_stxr_regs(size, 2, 3, 1)
}

fn enc_stxr_regs(size: u32, rs: u32, rt: u32, rn: u32) -> u32 {
    (size << 30) | (0b001000 << 24) | (rs << 16) | (0b11111 << 10) | (rn << 5) | rt
}

fn enc_ldar(size: u32) -> u32 {
    enc_ldar_regs(size, 0, 1)
}

fn enc_ldar_regs(size: u32, rt: u32, rn: u32) -> u32 {
    (size << 30)
        | (0b001000 << 24)
        | (1 << 23)
        | (1 << 22)
        | (0b11111 << 16)
        | (1 << 15)
        | (0b11111 << 10)
        | (rn << 5)
        | rt
}

fn enc_stlr_regs(size: u32, rt: u32, rn: u32) -> u32 {
    (size << 30)
        | (0b001000 << 24)
        | (1 << 23)
        | (0b11111 << 16)
        | (1 << 15)
        | (0b11111 << 10)
        | (rn << 5)
        | rt
}

fn enc_stlr(size: u32) -> u32 {
    enc_stlr_regs(size, 3, 1)
}

fn enc_atomic_rmw_regs(
    size: u32,
    acquire: u32,
    release: u32,
    o3: u32,
    opc: u32,
    rs: u32,
    rn: u32,
    rt: u32,
) -> u32 {
    (size << 30)
        | (0b111 << 27)
        | (acquire << 23)
        | (release << 22)
        | (1 << 21)
        | (rs << 16)
        | (o3 << 15)
        | (opc << 12)
        | (rn << 5)
        | rt
}

fn enc_atomic_rmw(size: u32, acquire: u32, release: u32, o3: u32, opc: u32) -> u32 {
    enc_atomic_rmw_regs(size, acquire, release, o3, opc, 2, 1, 0)
}

fn enc_cas(size: u32, acquire: u32, release: u32) -> u32 {
    enc_cas_regs(size, acquire, release, 2, 1, 0)
}

fn enc_cas_regs(size: u32, acquire: u32, release: u32, rs: u32, rn: u32, rt: u32) -> u32 {
    (size << 30)
        | (0b001000 << 24)
        | (1 << 23)
        | (acquire << 22)
        | (1 << 21)
        | (rs << 16)
        | (release << 15)
        | (0b11111 << 10)
        | (rn << 5)
        | rt
}

fn enc_extract(sf: u32, rn: u32, rm: u32, lsb: u32) -> u32 {
    (sf << 31) | (0b100111 << 23) | (sf << 22) | (rm << 16) | (lsb << 10) | (rn << 5)
}

fn enc_b(imm26: i32) -> u32 {
    0x1400_0000 | ((imm26 as u32) & 0x03ff_ffff)
}

fn enc_b_cond(cond: u32, imm19: i32) -> u32 {
    0x5400_0000 | (((imm19 as u32) & 0x7ffff) << 5) | (cond & 0xf)
}

fn enc_cbz(rt: u32, imm19: i32) -> u32 {
    0xb400_0000 | (((imm19 as u32) & 0x7ffff) << 5) | (rt & 0x1f)
}

fn enc_cbnz(rt: u32, imm19: i32) -> u32 {
    0xb500_0000 | (((imm19 as u32) & 0x7ffff) << 5) | (rt & 0x1f)
}

fn enc_dp1_regs(sf: u32, opcode: u32, rn: u32, rd: u32) -> u32 {
    (sf << 31) | (0b1011010110 << 21) | (opcode << 10) | (rn << 5) | rd
}

fn enc_dp1(sf: u32, opcode: u32) -> u32 {
    enc_dp1_regs(sf, opcode, 1, 0)
}

fn enc_dp2_regs(sf: u32, opcode2: u32, rn: u32, rm: u32, rd: u32) -> u32 {
    (sf << 31) | (0b0011010110 << 21) | (rm << 16) | (opcode2 << 10) | (rn << 5) | rd
}

fn enc_addsub_carry_regs(sf: u32, op: u32, s: u32, rd: u32, rn: u32, rm: u32) -> u32 {
    (sf << 31) | (op << 30) | (s << 29) | (0b11010000 << 21) | (rm << 16) | (rn << 5) | rd
}

fn enc_dp3_regs(sf: u32, op31: u32, o0: u32, rd: u32, rn: u32, rm: u32, ra: u32) -> u32 {
    (sf << 31)
        | (0b11011 << 24)
        | (op31 << 21)
        | (rm << 16)
        | (o0 << 15)
        | (ra << 10)
        | (rn << 5)
        | rd
}

fn enc_bitfield_regs(sf: u32, opc: u32, immr: u32, imms: u32, rn: u32, rd: u32) -> u32 {
    (sf << 31)
        | (opc << 29)
        | (0b100110 << 23)
        | (sf << 22)
        | (immr << 16)
        | (imms << 10)
        | (rn << 5)
        | rd
}

fn enc_bitfield(sf: u32, opc: u32, immr: u32, imms: u32) -> u32 {
    enc_bitfield_regs(sf, opc, immr, imms, 1, 0)
}

fn enc_logical_imm(sf: u32, opc: u32, n: u32, immr: u32, imms: u32, rd: u32, rn: u32) -> u32 {
    (sf << 31)
        | (opc << 29)
        | (0b100100 << 23)
        | (n << 22)
        | (immr << 16)
        | (imms << 10)
        | (rn << 5)
        | rd
}

fn enc_orr_single_bit(sf: u32, rd: u32, rn: u32, bit: u32) -> u32 {
    let width = if sf == 0 { OpWidth::W32 } else { OpWidth::W64 };
    let (n, immr, imms) =
        Aarch64Lowerer::logical_bitmask_imm((1_u64 << bit) as i64, width).unwrap();
    enc_logical_imm(sf, 0b01, n, immr, imms, rd, rn)
}

fn enc_addsub_imm(sf: u32, op: u32, s: u32, imm12: u32) -> u32 {
    (sf << 31) | (op << 30) | (s << 29) | (0b10001 << 24) | (imm12 << 10) | (1 << 5)
}

fn enc_addsub_imm_regs(sf: u32, op: u32, s: u32, shift: u32, imm12: u32, rd: u32, rn: u32) -> u32 {
    (sf << 31)
        | (op << 30)
        | (s << 29)
        | (0b10001 << 24)
        | (shift << 22)
        | (imm12 << 10)
        | (rn << 5)
        | rd
}

fn enc_simd_two_reg_misc(rd: u32, rn: u32, q: u32, u: u32, size: u32, opcode: u32) -> u32 {
    0x0e20_0800 | (q << 30) | (u << 29) | (size << 22) | (opcode << 12) | (rn << 5) | rd
}

fn enc_simd_shift_imm(rd: u32, rn: u32, q: u32, u: u32, immh: u32, immb: u32, opcode: u32) -> u32 {
    0x0f00_0400
        | (q << 30)
        | (u << 29)
        | (immh << 19)
        | (immb << 16)
        | (opcode << 11)
        | (rn << 5)
        | rd
}

fn enc_simd_umov(rd: u32, rn: u32, imm5: u32, to_x: bool) -> u32 {
    let base = if to_x { 0x4e00_3c00 } else { 0x0e00_3c00 };
    base | (imm5 << 16) | (rn << 5) | rd
}

fn enc_simd_ins_general(rd: u32, rn: u32, imm5: u32) -> u32 {
    0x4e00_1c00 | (imm5 << 16) | (rn << 5) | rd
}

fn enc_simd_tbl(rd: u32, rn: u32, rm: u32, q: u32, len: u32, op: u32) -> u32 {
    (q << 30) | (0b01110 << 24) | (rm << 16) | (len << 13) | (op << 12) | (rn << 5) | rd
}

fn enc_simd_orr(rd: u32, rn: u32, rm: u32) -> u32 {
    0x0e20_0400 | (1 << 30) | (0b10 << 22) | (rm << 16) | (0b00011 << 11) | (rn << 5) | rd
}

fn enc_addsub_shift_regs(
    sf: u32,
    op: u32,
    s: u32,
    shift: u32,
    imm6: u32,
    rd: u32,
    rn: u32,
    rm: u32,
) -> u32 {
    (sf << 31)
        | (op << 30)
        | (s << 29)
        | (0b01011 << 24)
        | (shift << 22)
        | (rm << 16)
        | (imm6 << 10)
        | (rn << 5)
        | rd
}

fn enc_addsub_ext_regs(
    sf: u32,
    op: u32,
    s: u32,
    option: u32,
    imm3: u32,
    rd: u32,
    rn: u32,
    rm: u32,
) -> u32 {
    (sf << 31)
        | (op << 30)
        | (s << 29)
        | (0b01011 << 24)
        | (1 << 21)
        | (rm << 16)
        | (option << 13)
        | (imm3 << 10)
        | (rn << 5)
        | rd
}

fn zero_base_extended_flags_words(sf: u32, op: u32, option: u32, imm3: u32, rm: u32) -> Vec<u32> {
    let scratch = if rm == 16 { 17 } else { 16 };
    let regbits = if sf == 1 { 64 } else { 32 };
    let ext_bits = match option & 0b011 {
        0b00 => 8,
        0b01 => 16,
        0b10 => 32,
        _ => 64,
    };
    let mut words = vec![enc_ldst_simm_regs(3, 0b00, 0b11, -16, scratch, 31)];
    if ext_bits >= regbits {
        if imm3 == 0 {
            words.push(enc_mov_reg(sf, scratch, rm));
        } else {
            words.push(enc_bitfield_regs(
                sf,
                0b10,
                regbits - imm3,
                regbits - 1 - imm3,
                rm,
                scratch,
            ));
        }
    } else {
        words.push(enc_bitfield_regs(
            sf,
            if (option & 0b100) != 0 { 0b00 } else { 0b10 },
            (regbits - imm3) & (regbits - 1),
            ext_bits - 1,
            rm,
            scratch,
        ));
    }
    words.push(enc_addsub_shift_regs(sf, op, 1, 0, 0, 31, 31, scratch));
    words.push(enc_ldst_simm_regs(3, 0b01, 0b01, 16, scratch, 31));
    words
}

fn enc_logical_reg_n(sf: u32, opc: u32, n: u32, rd: u32, rn: u32, rm: u32) -> u32 {
    enc_logical_shift_regs(sf, opc, n, 0, 0, rd, rn, rm)
}

fn enc_logical_shift_regs(
    sf: u32,
    opc: u32,
    n: u32,
    shift: u32,
    imm6: u32,
    rd: u32,
    rn: u32,
    rm: u32,
) -> u32 {
    (sf << 31)
        | (opc << 29)
        | (0b01010 << 24)
        | (shift << 22)
        | (n << 21)
        | (rm << 16)
        | (imm6 << 10)
        | (rn << 5)
        | rd
}

fn enc_logical_shifted(
    sf: u32,
    opc: u32,
    shift: u32,
    n: bool,
    rd: u32,
    rn: u32,
    rm: u32,
    amount: u32,
) -> u32 {
    (sf << 31)
        | (opc << 29)
        | (0b01010 << 24)
        | (shift << 22)
        | ((n as u32) << 21)
        | (rm << 16)
        | (amount << 10)
        | (rn << 5)
        | rd
}

fn enc_logical_reg(sf: u32, opc: u32, rd: u32, rn: u32, rm: u32) -> u32 {
    enc_logical_reg_n(sf, opc, 0, rd, rn, rm)
}

fn enc_mov_reg(sf: u32, rd: u32, rm: u32) -> u32 {
    (sf << 31) | (0b01 << 29) | (0b01010 << 24) | (31 << 5) | (rm << 16) | rd
}

fn enc_mov_wide(sf: u32, opc: u32, hw: u32, imm16: u32, rd: u32) -> u32 {
    (sf << 31) | (opc << 29) | (0b100101 << 23) | (hw << 21) | (imm16 << 5) | rd
}

fn enc_flagm(op2: u32) -> u32 {
    0xd500_401f | (op2 << 5)
}

fn enc_condcmp(sf: u32, op: u32, imm: bool, rm_imm5: u32, cond: u32, rn: u32, nzcv: u32) -> u32 {
    (sf << 31)
        | (op << 30)
        | (0b111010010 << 21)
        | (rm_imm5 << 16)
        | (cond << 12)
        | ((imm as u32) << 11)
        | (rn << 5)
        | (nzcv & 0xf)
}

fn enc_mrs_sysreg(rt: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    0xd500_0000
        | (1 << 21)
        | (3 << 19)
        | (op1 << 16)
        | (crn << 12)
        | (crm << 8)
        | (op2 << 5)
        | (rt & 0x1f)
}

fn enc_msr_sysreg(rt: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    0xd500_0000 | (3 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | (rt & 0x1f)
}

fn enc_csel_regs(sf: u32, op: u32, op2: u32, rn: u32, rm: u32, cond: u32, rd: u32) -> u32 {
    (sf << 31)
        | (op << 30)
        | (0b11010100 << 21)
        | (rm << 16)
        | (cond << 12)
        | (op2 << 10)
        | (rn << 5)
        | rd
}

fn enc_test_branch(rt: u32, bit: u32, nonzero: bool, offset: i32) -> u32 {
    let b5 = bit >> 5;
    let b40 = bit & 0x1f;
    let imm14 = ((offset >> 2) as u32) & 0x3fff;
    (b5 << 31) | (0b011011 << 25) | ((nonzero as u32) << 24) | (b40 << 19) | (imm14 << 5) | rt
}

fn assert_fp_binary_f32(label: &str, kind: OpKind, src1: f32, src2: f32, expected: f32) {
    let src1_bits = u64::from(src1.to_bits());
    let src2_bits = u64::from(src2.to_bits());
    let expected_bits = u64::from(expected.to_bits());
    let code = lower_single_op(kind);
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src1_bits, 0x1111_1111_1111_1111),
            (2, src2_bits, 0x2222_2222_2222_2222),
        ],
    );

    assert_eq!(out[0].0, expected_bits, "{label}: low result");
    assert_eq!(out[0].1, 0, "{label}: high result");
    assert_eq!(
        out[1],
        (src1_bits, 0x1111_1111_1111_1111),
        "{label}: src1 preserved",
    );
    assert_eq!(
        out[2],
        (src2_bits, 0x2222_2222_2222_2222),
        "{label}: src2 preserved",
    );
}

fn assert_fp_binary_f64(label: &str, kind: OpKind, src1: f64, src2: f64, expected: f64) {
    let src1_bits = src1.to_bits();
    let src2_bits = src2.to_bits();
    let expected_bits = expected.to_bits();
    let code = lower_single_op(kind);
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src1_bits, 0x1111_1111_1111_1111),
            (2, src2_bits, 0x2222_2222_2222_2222),
        ],
    );

    assert_eq!(out[0].0, expected_bits, "{label}: low result");
    assert_eq!(out[0].1, 0, "{label}: high result");
    assert_eq!(
        out[1],
        (src1_bits, 0x1111_1111_1111_1111),
        "{label}: src1 preserved",
    );
    assert_eq!(
        out[2],
        (src2_bits, 0x2222_2222_2222_2222),
        "{label}: src2 preserved",
    );
}

fn assert_fp_fma_f32(label: &str, kind: OpKind, src1: f32, src2: f32, src3: f32, expected: f32) {
    let src1_bits = u64::from(src1.to_bits());
    let src2_bits = u64::from(src2.to_bits());
    let src3_bits = u64::from(src3.to_bits());
    let expected_bits = u64::from(expected.to_bits());
    let code = lower_single_op(kind);
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src1_bits, 0x1111_1111_1111_1111),
            (2, src2_bits, 0x2222_2222_2222_2222),
            (3, src3_bits, 0x3333_3333_3333_3333),
        ],
    );

    assert_eq!(out[0].0, expected_bits, "{label}: low result");
    assert_eq!(out[0].1, 0, "{label}: high result");
    assert_eq!(
        out[1],
        (src1_bits, 0x1111_1111_1111_1111),
        "{label}: src1 preserved",
    );
    assert_eq!(
        out[2],
        (src2_bits, 0x2222_2222_2222_2222),
        "{label}: src2 preserved",
    );
    assert_eq!(
        out[3],
        (src3_bits, 0x3333_3333_3333_3333),
        "{label}: src3 preserved",
    );
}

fn assert_fp_fma_f64(label: &str, kind: OpKind, src1: f64, src2: f64, src3: f64, expected: f64) {
    let src1_bits = src1.to_bits();
    let src2_bits = src2.to_bits();
    let src3_bits = src3.to_bits();
    let expected_bits = expected.to_bits();
    let code = lower_single_op(kind);
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src1_bits, 0x1111_1111_1111_1111),
            (2, src2_bits, 0x2222_2222_2222_2222),
            (3, src3_bits, 0x3333_3333_3333_3333),
        ],
    );

    assert_eq!(out[0].0, expected_bits, "{label}: low result");
    assert_eq!(out[0].1, 0, "{label}: high result");
    assert_eq!(
        out[1],
        (src1_bits, 0x1111_1111_1111_1111),
        "{label}: src1 preserved",
    );
    assert_eq!(
        out[2],
        (src2_bits, 0x2222_2222_2222_2222),
        "{label}: src2 preserved",
    );
    assert_eq!(
        out[3],
        (src3_bits, 0x3333_3333_3333_3333),
        "{label}: src3 preserved",
    );
}

fn assert_fp_unary_f32(label: &str, kind: OpKind, src: f32, expected: f32) {
    let src_bits = u64::from(src.to_bits());
    let expected_bits = u64::from(expected.to_bits());
    let code = lower_single_op(kind);
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src_bits, 0x1111_1111_1111_1111),
        ],
    );

    assert_eq!(out[0].0, expected_bits, "{label}: low result");
    assert_eq!(out[0].1, 0, "{label}: high result");
    assert_eq!(
        out[1],
        (src_bits, 0x1111_1111_1111_1111),
        "{label}: src preserved",
    );
}

fn assert_fp_unary_f64(label: &str, kind: OpKind, src: f64, expected: f64) {
    let src_bits = src.to_bits();
    let expected_bits = expected.to_bits();
    let code = lower_single_op(kind);
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src_bits, 0x1111_1111_1111_1111),
        ],
    );

    assert_eq!(out[0].0, expected_bits, "{label}: low result");
    assert_eq!(out[0].1, 0, "{label}: high result");
    assert_eq!(
        out[1],
        (src_bits, 0x1111_1111_1111_1111),
        "{label}: src preserved",
    );
}

fn assert_fp_compare_f32(label: &str, src1: f32, src2: f32, expected_nzcv: u8) {
    let src1_bits = u64::from(src1.to_bits());
    let src2_bits = u64::from(src2.to_bits());
    let code = lower_single_op(OpKind::FCmp {
        src1: v(1),
        src2: v(2),
        precision: FpPrecision::F32,
    });
    let (out, out_nzcv) = run_aarch64_code_with_simd_and_nzcv(
        &code,
        &[
            (1, src1_bits, 0x1111_1111_1111_1111),
            (2, src2_bits, 0x2222_2222_2222_2222),
        ],
        0b1111,
    );

    assert_eq!(out_nzcv, expected_nzcv, "{label}: nzcv");
    assert_eq!(
        out[1],
        (src1_bits, 0x1111_1111_1111_1111),
        "{label}: src1 preserved",
    );
    assert_eq!(
        out[2],
        (src2_bits, 0x2222_2222_2222_2222),
        "{label}: src2 preserved",
    );
}

fn assert_fp_compare_f64(label: &str, src1: f64, src2: f64, expected_nzcv: u8) {
    let src1_bits = src1.to_bits();
    let src2_bits = src2.to_bits();
    let code = lower_single_op(OpKind::FCmp {
        src1: v(1),
        src2: v(2),
        precision: FpPrecision::F64,
    });
    let (out, out_nzcv) = run_aarch64_code_with_simd_and_nzcv(
        &code,
        &[
            (1, src1_bits, 0x1111_1111_1111_1111),
            (2, src2_bits, 0x2222_2222_2222_2222),
        ],
        0b1111,
    );

    assert_eq!(out_nzcv, expected_nzcv, "{label}: nzcv");
    assert_eq!(
        out[1],
        (src1_bits, 0x1111_1111_1111_1111),
        "{label}: src1 preserved",
    );
    assert_eq!(
        out[2],
        (src2_bits, 0x2222_2222_2222_2222),
        "{label}: src2 preserved",
    );
}

fn assert_fp_convert_f32_to_f64(label: &str, src: f32) {
    let src_bits = u64::from(src.to_bits());
    let expected_bits = (src as f64).to_bits();
    let code = lower_single_op(OpKind::FConvert {
        dst: v(0),
        src: v(1),
        from: FpPrecision::F32,
        to: FpPrecision::F64,
    });
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src_bits, 0x1111_1111_1111_1111),
        ],
    );

    assert_eq!(out[0], (expected_bits, 0), "{label}: converted result");
    assert_eq!(
        out[1],
        (src_bits, 0x1111_1111_1111_1111),
        "{label}: src preserved",
    );
}

fn assert_fp_convert_f64_to_f32(label: &str, src: f64) {
    let src_bits = src.to_bits();
    let expected_bits = u64::from((src as f32).to_bits());
    let code = lower_single_op(OpKind::FConvert {
        dst: v(0),
        src: v(1),
        from: FpPrecision::F64,
        to: FpPrecision::F32,
    });
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src_bits, 0x1111_1111_1111_1111),
        ],
    );

    assert_eq!(out[0], (expected_bits, 0), "{label}: converted result");
    assert_eq!(
        out[1],
        (src_bits, 0x1111_1111_1111_1111),
        "{label}: src preserved",
    );
}

fn assert_fp_convert_same_f32(label: &str, src: f32) {
    let src_bits = u64::from(src.to_bits());
    let code = lower_single_op(OpKind::FConvert {
        dst: v(0),
        src: v(1),
        from: FpPrecision::F32,
        to: FpPrecision::F32,
    });
    let out = run_aarch64_code_with_simd(
        &code,
        &[
            (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
            (1, src_bits, 0x1111_1111_1111_1111),
        ],
    );

    assert_eq!(out[0], (src_bits, 0), "{label}: copied result");
    assert_eq!(
        out[1],
        (src_bits, 0x1111_1111_1111_1111),
        "{label}: src preserved",
    );
}

fn assert_int_to_fp_f32(label: &str, kind: OpKind, src_value: u64, expected: f32) {
    let code = lower_single_op(kind);
    let (regs, simd, sp) = run_aarch64_code_with_regs_and_simd(
        &code,
        &[(1, src_value), (16, 0x1234_5678_9abc_def0)],
        &[(0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa)],
    );

    assert_eq!(
        simd[0],
        (u64::from(expected.to_bits()), 0),
        "{label}: converted result",
    );
    assert_eq!(regs[1], src_value, "{label}: src preserved");
    assert_eq!(regs[16], 0x1234_5678_9abc_def0, "{label}: scratch restored");
    assert_eq!(sp, 0x8000, "{label}: sp restored");
}

fn assert_int_to_fp_f64(label: &str, kind: OpKind, src_value: u64, expected: f64) {
    let code = lower_single_op(kind);
    let (regs, simd, sp) = run_aarch64_code_with_regs_and_simd(
        &code,
        &[(1, src_value), (16, 0x1234_5678_9abc_def0)],
        &[(0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa)],
    );

    assert_eq!(
        simd[0],
        (expected.to_bits(), 0),
        "{label}: converted result"
    );
    assert_eq!(regs[1], src_value, "{label}: src preserved");
    assert_eq!(regs[16], 0x1234_5678_9abc_def0, "{label}: scratch restored");
    assert_eq!(sp, 0x8000, "{label}: sp restored");
}

fn assert_fp_to_int_f32(label: &str, kind: OpKind, src: f32, expected: u64) {
    let src_bits = u64::from(src.to_bits());
    let code = lower_single_op(kind);
    let (regs, simd, sp) = run_aarch64_code_with_regs_and_simd(
        &code,
        &[(0, 0x1234_5678_9abc_def0)],
        &[(1, src_bits, 0x1111_1111_1111_1111)],
    );

    assert_eq!(regs[0], expected, "{label}: converted result");
    assert_eq!(
        simd[1],
        (src_bits, 0x1111_1111_1111_1111),
        "{label}: src preserved",
    );
    assert_eq!(sp, 0x8000, "{label}: sp restored");
}

fn assert_fp_to_int_f64(label: &str, kind: OpKind, src: f64, expected: u64) {
    let src_bits = src.to_bits();
    let code = lower_single_op(kind);
    let (regs, simd, sp) = run_aarch64_code_with_regs_and_simd(
        &code,
        &[(0, 0x1234_5678_9abc_def0)],
        &[(1, src_bits, 0x1111_1111_1111_1111)],
    );

    assert_eq!(regs[0], expected, "{label}: converted result");
    assert_eq!(
        simd[1],
        (src_bits, 0x1111_1111_1111_1111),
        "{label}: src preserved",
    );
    assert_eq!(sp, 0x8000, "{label}: sp restored");
}

fn assert_bidir_shift_runtime(
    label: &str,
    src: SrcOperand,
    amount: SrcOperand,
    src_value: u64,
    amount_value: u64,
    kind: u8,
    width: OpWidth,
) {
    let code = lower_single_op(OpKind::BidirShift {
        dst: x(0),
        src: src.clone(),
        amount: amount.clone(),
        kind,
        width,
    });
    let expected = ref_bidir_shift(src_value, amount_value, kind, width);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
    ];
    let mut regs = sentinels.to_vec();
    if matches!(src, SrcOperand::Reg(_)) {
        regs.push((1, src_value));
    }
    if matches!(amount, SrcOperand::Reg(_)) {
        regs.push((2, amount_value));
    }

    let old_nzcv = 0b1011;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(
        out[0] & width_mask(width),
        expected,
        "{label}: BidirShift result"
    );
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if matches!(src, SrcOperand::Reg(_)) {
        assert_eq!(out[1], src_value, "{label}: source preserved");
    }
    if matches!(amount, SrcOperand::Reg(_)) {
        assert_eq!(out[2], amount_value, "{label}: count preserved");
    }
    for (reg, value) in sentinels {
        assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
    }
}

fn ref_clmul_product(a: u32, b: u32, bits: u8) -> u64 {
    let mut product = 0u64;
    for bit in 0..bits {
        if ((b >> bit) & 1) != 0 {
            product ^= u64::from(a) << bit;
        }
    }
    product
}

fn ref_clmul(a: u32, b: u32, elem_bits: u8, lanes: u8, acc: bool, init: (u32, u32)) -> (u32, u32) {
    let (mut lo, mut hi) = if (elem_bits, lanes) == (32, 1) {
        let product = ref_clmul_product(a, b, 32);
        (product as u32, (product >> 32) as u32)
    } else {
        let p0 = ref_clmul_product(a & 0xffff, b & 0xffff, 16);
        let p1 = ref_clmul_product(a >> 16, b >> 16, 16);
        let lo = ((p0 as u32) & 0xffff) | (((p1 as u32) & 0xffff) << 16);
        let hi = (((p0 >> 16) as u32) & 0xffff) | (((p1 >> 16) as u32) << 16);
        (lo, hi)
    };
    if acc {
        lo ^= init.0;
        hi ^= init.1;
    }
    (lo, hi)
}

fn assert_clmul_runtime(
    label: &str,
    src1: SrcOperand,
    src2: SrcOperand,
    a: u32,
    b: u32,
    elem_bits: u8,
    lanes: u8,
    acc: bool,
    init: (u32, u32),
    with_hi: bool,
) {
    let dst_hi = with_hi.then_some(x(1));
    let code = lower_single_op(OpKind::ClMul {
        dst: x(0),
        dst_hi,
        src1: src1.clone(),
        src2: src2.clone(),
        elem_bits,
        lanes,
        acc,
    });
    let expected = ref_clmul(a, b, elem_bits, lanes, acc, init);
    let hi_init = 0x7777_0000_0000_0000u64 | u64::from(init.1);
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
        (13, 0x1313_1313_1313_1313),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((0, 0x5555_0000_0000_0000u64 | u64::from(init.0)));
    regs.push((1, hi_init));
    if matches!(src1, SrcOperand::Reg(_)) {
        regs.push((2, 0xaaaa_0000_0000_0000u64 | u64::from(a)));
    }
    if matches!(src2, SrcOperand::Reg(_)) {
        regs.push((3, 0xbbbb_0000_0000_0000u64 | u64::from(b)));
    }

    let old_nzcv = 0b0110;
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    assert_eq!(out[0], u64::from(expected.0), "{label}: ClMul low result");
    if with_hi {
        assert_eq!(out[1], u64::from(expected.1), "{label}: ClMul high result");
    } else {
        assert_eq!(out[1], hi_init, "{label}: x1 preserved without dst_hi");
    }
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    if matches!(src1, SrcOperand::Reg(_)) {
        assert_eq!(
            out[2],
            0xaaaa_0000_0000_0000u64 | u64::from(a),
            "{label}: src1 preserved"
        );
    }
    if matches!(src2, SrcOperand::Reg(_)) {
        assert_eq!(
            out[3],
            0xbbbb_0000_0000_0000u64 | u64::from(b),
            "{label}: src2 preserved"
        );
    }
    for (reg, value) in sentinels {
        assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
    }
}

fn ref_rep_stos_window(initial: u64, value: u64, width: MemWidth, count: u64) -> u64 {
    let mut bytes = initial.to_le_bytes();
    let store = value.to_le_bytes();
    let width = width.bytes() as usize;
    for idx in 0..count as usize {
        let start = idx * width;
        let end = start + width;
        if end <= bytes.len() {
            bytes[start..end].copy_from_slice(&store[..width]);
        }
    }
    u64::from_le_bytes(bytes)
}

#[allow(clippy::too_many_arguments)]
fn assert_rep_stos_runtime(
    label: &str,
    width: MemWidth,
    dst_reg: u8,
    src_reg: u8,
    count_reg: u8,
    base: u64,
    value: u64,
    count: u64,
    initial: u64,
) {
    let code = lower_single_op(OpKind::RepStos {
        dst: x(dst_reg),
        src: x(src_reg),
        count: x(count_reg),
        width,
    });
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
    ];
    let mut regs = sentinels.to_vec();
    for (reg, reg_value) in [(dst_reg, base), (src_reg, value), (count_reg, count)] {
        if let Some((_, existing)) = regs.iter().find(|(existing, _)| *existing == reg) {
            assert_eq!(*existing, reg_value, "{label}: conflicting x{reg} input");
        } else {
            regs.push((reg, reg_value));
        }
    }

    let old_nzcv = 0b1101;
    let (out, out_nzcv, sp, mem) =
        run_aarch64_code_with_memory(&code, &regs, old_nzcv, base, initial, MemWidth::B8);
    let expected_mem = ref_rep_stos_window(initial, value, width, count);
    let expected_dst = base.wrapping_add(u64::from(width.bytes()).wrapping_mul(count));

    assert_eq!(mem, expected_mem, "{label}: memory window");
    assert_eq!(out[dst_reg as usize], expected_dst, "{label}: final dst");
    assert_eq!(out[count_reg as usize], 0, "{label}: final count");
    if src_reg != dst_reg && src_reg != count_reg {
        assert_eq!(out[src_reg as usize], value, "{label}: source preserved");
    }
    assert_eq!(out_nzcv, old_nzcv, "{label}: NZCV preserved");
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
    }
}

fn bit_index_reg(index: &SrcOperand) -> Option<u8> {
    if let SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg)))) = index {
        Some(*reg)
    } else {
        None
    }
}

fn assert_bt_lowering(
    label: &str,
    src_reg: u8,
    src_value: u64,
    index: SrcOperand,
    index_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let code = lower_single_op(OpKind::Bt {
        src: x(src_reg),
        index: index.clone(),
        width,
    });
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    let index_reg = bit_index_reg(&index);
    if let Some(reg) = index_reg {
        regs.push((reg, index_value));
    }

    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    let expected_nzcv = expected_bit_test_nzcv(old_nzcv, src_value, index_value, width);
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    if let Some(reg) = index_reg {
        assert_eq!(out[reg as usize], index_value, "{label}: index preserved");
    }
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != src_reg && Some(reg) != index_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_bit_update_lowering(
    label: &str,
    action: BitTestAction,
    dst_reg: u8,
    src_reg: u8,
    src_value: u64,
    index: SrcOperand,
    index_value: u64,
    width: OpWidth,
    old_nzcv: u8,
) {
    let dst = x(dst_reg);
    let src = x(src_reg);
    let kind = match action {
        BitTestAction::Set => OpKind::Bts {
            dst,
            src,
            index: index.clone(),
            width,
        },
        BitTestAction::Reset => OpKind::Btr {
            dst,
            src,
            index: index.clone(),
            width,
        },
        BitTestAction::Toggle => OpKind::Btc {
            dst,
            src,
            index: index.clone(),
            width,
        },
        BitTestAction::Test => unreachable!("bit update helper requires an update action"),
    };
    let sentinels = [
        (16, 0x1616_1616_1616_1616),
        (17, 0x1717_1717_1717_1717),
        (15, 0x1515_1515_1515_1515),
        (14, 0x1414_1414_1414_1414),
    ];
    let mut regs = sentinels.to_vec();
    regs.push((src_reg, src_value));
    let index_reg = bit_index_reg(&index);
    if let Some(reg) = index_reg {
        regs.push((reg, index_value));
    }

    let code = lower_single_op(kind);
    let (out, out_nzcv, sp) = run_aarch64_code(&code, &regs, old_nzcv);
    let expected = ref_bit_update(src_value, index_value, action, width);
    let expected_nzcv = expected_bit_test_nzcv(old_nzcv, src_value, index_value, width);
    assert_eq!(out[dst_reg as usize], expected, "{label}: result");
    assert_eq!(out_nzcv, expected_nzcv, "{label}: NZCV");
    if src_reg != dst_reg {
        assert_eq!(out[src_reg as usize], src_value, "{label}: src preserved");
    }
    if let Some(reg) = index_reg {
        if reg != dst_reg && reg != src_reg {
            assert_eq!(out[reg as usize], index_value, "{label}: index preserved");
        }
    }
    assert_eq!(sp, 0x8000, "{label}: stack restored");
    for (reg, value) in sentinels {
        if reg != dst_reg && reg != src_reg && Some(reg) != index_reg {
            assert_eq!(out[reg as usize], value, "{label}: x{reg} restored");
        }
    }
}

fn assert_popcnt_lowering(name: &str, dst: u8, src: u8, value: u64, width: OpWidth) {
    let code = lower_single_op(OpKind::Popcnt {
        dst: x(dst),
        src: x(src),
        width,
    });
    let scratch16 = 0x1616_1616_1616_1616;
    let scratch17 = 0x1717_1717_1717_1717;
    let old_nzcv = 0b1011;
    let expected = (value & width_mask(width)).count_ones() as u64;
    let (out, out_nzcv, sp) = run_aarch64_code(
        &code,
        &[(src, value), (16, scratch16), (17, scratch17)],
        old_nzcv,
    );

    assert_eq!(out[dst as usize], expected, "{name}: result");
    if dst != src {
        assert_eq!(out[src as usize], value, "{name}: source preserved");
    }
    assert_eq!(out[16], scratch16, "{name}: x16 restored");
    assert_eq!(out[17], scratch17, "{name}: x17 preserved");
    assert_eq!(out_nzcv, old_nzcv, "{name}: flags preserved");
    assert_eq!(sp, 0x8000, "{name}: stack restored");
}

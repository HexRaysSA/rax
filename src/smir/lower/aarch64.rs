//! Native AArch64 code generator for SMIR.
//!
//! This lowerer currently targets identity-mapped AArch64 scalar SMIR: architectural
//! AArch64 X registers in SMIR are emitted as the same native X registers. It is
//! intentionally small and strict; unsupported virtual-register and memory forms
//! fail rather than silently changing semantics.

use std::collections::HashMap;

use crate::smir::flags::FlagUpdate;
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator, TrapKind};
use crate::smir::ops::{OpKind, SmirOp};
use crate::smir::types::{
    Address, ArchReg, ArmReg, AtomicOp, BlockId, Condition, ExtendOp, FenceKind, MemWidth,
    MemoryOrder, OpWidth, ShiftOp, SignExtend, SrcOperand, VReg,
};

use super::{CodeBuffer, LowerError, LowerResult, Relocation, SmirLowerer};

const NZCV_N: i64 = 1_i64 << 31;
const NZCV_Z: i64 = 1_i64 << 30;
const NZCV_C: i64 = 1_i64 << 29;
const NZCV_V: i64 = 1_i64 << 28;
const NZCV_MASK: i64 = NZCV_N | NZCV_Z | NZCV_C | NZCV_V;
const SYSREG_NZCV: u32 = (3 << 14) | (3 << 11) | (4 << 7) | (2 << 3);
const SYSREG_FPCR: u32 = (3 << 14) | (3 << 11) | (4 << 7) | (4 << 3);
const SYSREG_FPSR: u32 = (3 << 14) | (3 << 11) | (4 << 7) | (4 << 3) | 1;

/// Native AArch64 lowerer for identity-mapped AArch64 scalar SMIR.
pub struct Aarch64Lowerer {
    code: CodeBuffer,
    block_offsets: HashMap<BlockId, usize>,
    branch_fixups: Vec<BranchFixup>,
    relocations: Vec<Relocation>,
}

#[derive(Clone, Copy)]
struct BranchFixup {
    offset: usize,
    target: BlockId,
    kind: BranchFixupKind,
}

#[derive(Clone, Copy)]
enum BranchFixupKind {
    Uncond,
    Cond { cond: u32 },
    CompareAndBranch { rt: u8, nonzero: bool },
}

impl Aarch64Lowerer {
    pub fn new() -> Self {
        Self {
            code: CodeBuffer::with_capacity(1024),
            block_offsets: HashMap::new(),
            branch_fixups: Vec::new(),
            relocations: Vec::new(),
        }
    }

    fn emit(&mut self, word: u32) {
        self.code.emit_u32(word);
    }

    fn emit_branch_placeholder(&mut self, target: BlockId) {
        let offset = self.code.position();
        self.emit(0x1400_0000);
        self.branch_fixups.push(BranchFixup {
            offset,
            target,
            kind: BranchFixupKind::Uncond,
        });
    }

    fn emit_cond_branch_placeholder(&mut self, cond: u32, target: BlockId) {
        let offset = self.code.position();
        self.emit(0x5400_0000 | (cond & 0xf));
        self.branch_fixups.push(BranchFixup {
            offset,
            target,
            kind: BranchFixupKind::Cond { cond: cond & 0xf },
        });
    }

    fn emit_compare_branch_placeholder(&mut self, rt: u8, nonzero: bool, target: BlockId) {
        let offset = self.code.position();
        self.emit(if nonzero { 0xb500_0000 } else { 0xb400_0000 } | (rt as u32));
        self.branch_fixups.push(BranchFixup {
            offset,
            target,
            kind: BranchFixupKind::CompareAndBranch { rt, nonzero },
        });
    }

    fn emit_br_reg(&mut self, rn: u8) {
        self.emit(0xd61f_0000 | ((rn as u32) << 5));
    }

    fn branch_scaled_imm(
        offset: usize,
        target_offset: usize,
        bits: u32,
    ) -> Result<u32, LowerError> {
        let delta = target_offset as i64 - offset as i64;
        if delta % 4 != 0 {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 block branch".into(),
                operand: format!("unaligned target offset {target_offset}"),
            });
        }

        let scaled = delta / 4;
        let min = -(1_i64 << (bits - 1));
        let max = (1_i64 << (bits - 1)) - 1;
        if scaled < min || scaled > max {
            return Err(LowerError::RelocationOutOfRange {
                offset,
                target: target_offset,
            });
        }

        Ok((scaled as u32) & ((1_u32 << bits) - 1))
    }

    fn fixup_branches(&mut self) -> Result<(), LowerError> {
        for fixup in self.branch_fixups.drain(..).collect::<Vec<_>>() {
            let Some(&target_offset) = self.block_offsets.get(&fixup.target) else {
                return Err(LowerError::UndefinedLabel {
                    label: format!("block_{}", fixup.target.0),
                });
            };

            let word = match fixup.kind {
                BranchFixupKind::Uncond => {
                    let imm26 = Self::branch_scaled_imm(fixup.offset, target_offset, 26)?;
                    0x1400_0000 | imm26
                }
                BranchFixupKind::Cond { cond } => {
                    let imm19 = Self::branch_scaled_imm(fixup.offset, target_offset, 19)?;
                    0x5400_0000 | (imm19 << 5) | (cond & 0xf)
                }
                BranchFixupKind::CompareAndBranch { rt, nonzero } => {
                    let imm19 = Self::branch_scaled_imm(fixup.offset, target_offset, 19)?;
                    let base = if nonzero { 0xb500_0000 } else { 0xb400_0000 };
                    base | (imm19 << 5) | (rt as u32)
                }
            };
            self.code.patch_i32(fixup.offset, word as i32);
        }
        Ok(())
    }

    fn patch_branch_to_current(&mut self, insn_offset: usize) -> Result<(), LowerError> {
        let target = self.code.position();
        let imm26 = Self::branch_scaled_imm(insn_offset, target, 26)?;
        self.code
            .patch_i32(insn_offset, (0x1400_0000 | imm26) as i32);
        Ok(())
    }

    fn patch_compare_branch_to_current(
        &mut self,
        insn_offset: usize,
        rt: u8,
        nonzero: bool,
    ) -> Result<(), LowerError> {
        let target = self.code.position();
        let imm19 = Self::branch_scaled_imm(insn_offset, target, 19)?;
        let base = if nonzero { 0xb500_0000 } else { 0xb400_0000 };
        self.code
            .patch_i32(insn_offset, (base | (imm19 << 5) | (rt as u32)) as i32);
        Ok(())
    }

    fn patch_cond_branch_to_current(
        &mut self,
        insn_offset: usize,
        cond: u32,
    ) -> Result<(), LowerError> {
        let target = self.code.position();
        let imm19 = Self::branch_scaled_imm(insn_offset, target, 19)?;
        self.code.patch_i32(
            insn_offset,
            (0x5400_0000 | (imm19 << 5) | (cond & 0xf)) as i32,
        );
        Ok(())
    }

    fn sf(width: OpWidth) -> Result<u32, LowerError> {
        match width {
            OpWidth::W32 => Ok(0),
            OpWidth::W64 => Ok(1),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native scalar width {other:?}"),
            }),
        }
    }

    fn gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            VReg::Imm(0) => Ok(31),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected X register, got {other:?}"
            ))),
        }
    }

    fn dst_gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected writable X register, got {other:?}"
            ))),
        }
    }

    fn branch_gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected branch target X register, got {other:?}"
            ))),
        }
    }

    fn base_gpr(vreg: VReg) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            VReg::Arch(ArchReg::Arm(ArmReg::Sp)) => Ok(31),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected memory base register, got {other:?}"
            ))),
        }
    }

    fn dst_or_zero_for_flags(vreg: VReg, set_flags: bool) -> Result<u8, LowerError> {
        match vreg {
            VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n < 31 => Ok(n),
            VReg::Virtual(_) if set_flags => Ok(31),
            other => Err(LowerError::InvalidRegister(format!(
                "AArch64 native lowerer expected writable X register, got {other:?}"
            ))),
        }
    }

    fn emit_mov_reg(&mut self, dst: u8, src: u8, width: OpWidth) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (0b01 << 29)
                | (0b01010 << 24)
                | (31 << 5)
                | ((src as u32) << 16)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_mov_imm(&mut self, dst: u8, imm: i64, width: OpWidth) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        let bits = match width {
            OpWidth::W32 => imm as u32 as u64,
            OpWidth::W64 => imm as u64,
            _ => unreachable!(),
        };
        let chunks = if width == OpWidth::W32 { 2 } else { 4 };
        let mut emitted = false;
        for idx in 0..chunks {
            let chunk = ((bits >> (idx * 16)) & 0xffff) as u32;
            if !emitted || chunk != 0 {
                let opc = if emitted { 0b11 } else { 0b10 };
                self.emit(
                    (sf << 31)
                        | (opc << 29)
                        | (0b100101 << 23)
                        | ((idx as u32) << 21)
                        | (chunk << 5)
                        | (dst as u32),
                );
                emitted = true;
            }
        }
        Ok(())
    }

    fn emit_movn_zero(&mut self, dst: u8, width: OpWidth) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit((sf << 31) | (0b100101 << 23) | (dst as u32));
        Ok(())
    }

    fn emit_addsub_shifted(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        subtract: bool,
        set_flags: bool,
        shift: u32,
        amount: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | ((subtract as u32) << 30)
                | ((set_flags as u32) << 29)
                | (0b01011 << 24)
                | (shift << 22)
                | ((rm as u32) << 16)
                | (amount << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_addsub_reg(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        subtract: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        self.emit_addsub_shifted(dst, rn, rm, subtract, set_flags, 0, 0, width)
    }

    fn emit_addsub_extended(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        subtract: bool,
        set_flags: bool,
        option: u32,
        amount: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | ((subtract as u32) << 30)
                | ((set_flags as u32) << 29)
                | (0b01011 << 24)
                | (1 << 21)
                | ((rm as u32) << 16)
                | (option << 13)
                | (amount << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_addsub_carry(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        subtract: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | ((subtract as u32) << 30)
                | ((set_flags as u32) << 29)
                | (0b11010000 << 21)
                | ((rm as u32) << 16)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_addsub_imm(
        &mut self,
        dst: u8,
        rn: u8,
        imm: i64,
        subtract: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if imm < 0 {
            return Err(LowerError::InvalidOperand {
                op: if subtract { "SUB" } else { "ADD" }.into(),
                operand: format!("negative immediate {imm}"),
            });
        }
        let imm = imm as u64;
        let (shift, imm12) = if imm <= 0xfff {
            (0, imm as u32)
        } else if imm & 0xfff == 0 && (imm >> 12) <= 0xfff {
            (1, (imm >> 12) as u32)
        } else {
            return Err(LowerError::InvalidOperand {
                op: if subtract { "SUB" } else { "ADD" }.into(),
                operand: format!("immediate {imm:#x} does not fit AArch64 add/sub immediate"),
            });
        };
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | ((subtract as u32) << 30)
                | ((set_flags as u32) << 29)
                | (0b10001 << 24)
                | (shift << 22)
                | (imm12 << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_logic_reg_n(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        opc: u32,
        n: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        self.emit_logic_shifted(dst, rn, rm, opc, n, 0, 0, width)
    }

    fn emit_logic_shifted(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        opc: u32,
        n: bool,
        shift: u32,
        amount: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (opc << 29)
                | (0b01010 << 24)
                | (shift << 22)
                | ((n as u32) << 21)
                | ((rm as u32) << 16)
                | (amount << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_logic_imm(
        &mut self,
        dst: u8,
        rn: u8,
        opc: u32,
        n: u32,
        immr: u32,
        imms: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (opc << 29)
                | (0b100100 << 23)
                | (n << 22)
                | (immr << 16)
                | (imms << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_orr_imm_one(&mut self, dst: u8, rn: u8, width: OpWidth) -> Result<(), LowerError> {
        let n = Self::sf(width)?;
        self.emit_logic_imm(dst, rn, 0b01, n, 0, 0, width)
    }

    fn emit_bitfield(
        &mut self,
        dst: u8,
        rn: u8,
        opc: u32,
        immr: u32,
        imms: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (opc << 29)
                | (0b100110 << 23)
                | (sf << 22)
                | (immr << 16)
                | (imms << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_extract(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        lsb: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (0b100111 << 23)
                | (sf << 22)
                | ((rm as u32) << 16)
                | (lsb << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_dp2(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        opcode2: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (0b0011010110 << 21)
                | ((rm as u32) << 16)
                | (opcode2 << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_test_branch(
        &mut self,
        rt: u8,
        bit: u32,
        nonzero: bool,
        offset: i32,
    ) -> Result<(), LowerError> {
        self.emit(Self::test_branch_word(rt, bit, nonzero, offset)?);
        Ok(())
    }

    fn test_branch_word(
        rt: u8,
        bit: u32,
        nonzero: bool,
        offset: i32,
    ) -> Result<u32, LowerError> {
        if bit >= 64 {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 test branch".into(),
                operand: format!("bit={bit}"),
            });
        }
        if offset % 4 != 0 {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 test branch".into(),
                operand: format!("offset={offset}"),
            });
        }
        let imm14 = offset / 4;
        if !(-8192..=8191).contains(&imm14) {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 test branch".into(),
                operand: format!("offset={offset}"),
            });
        }

        let b5 = bit >> 5;
        let b40 = bit & 0x1f;
        Ok(
            (b5 << 31)
                | (0b011011 << 25)
                | ((nonzero as u32) << 24)
                | (b40 << 19)
                | (((imm14 as u32) & 0x3fff) << 5)
                | (rt as u32),
        )
    }

    fn patch_test_branch_to_current(
        &mut self,
        insn_offset: usize,
        rt: u8,
        bit: u32,
        nonzero: bool,
    ) -> Result<(), LowerError> {
        let target = self.code.position();
        let offset = target as i64 - insn_offset as i64;
        if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
            return Err(LowerError::RelocationOutOfRange {
                offset: insn_offset,
                target,
            });
        }
        let word = Self::test_branch_word(rt, bit, nonzero, offset as i32)?;
        self.code.patch_i32(insn_offset, word as i32);
        Ok(())
    }

    fn emit_dp3(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        ra: u8,
        op31: u32,
        o0: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (0b11011 << 24)
                | (op31 << 21)
                | ((rm as u32) << 16)
                | (o0 << 15)
                | ((ra as u32) << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_dp1(
        &mut self,
        dst: u8,
        rn: u8,
        opcode: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (0b1011010110 << 21)
                | (opcode << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_ldst_unsigned(&mut self, rt: u8, rn: u8, size: u32, opc: u32, imm12: u32) {
        self.emit(
            (size << 30)
                | (0b111 << 27)
                | (0b01 << 24)
                | (opc << 22)
                | (imm12 << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_ldst_simm(&mut self, rt: u8, rn: u8, size: u32, opc: u32, imm9: i64, mode: u32) {
        self.emit(
            (size << 30)
                | (0b111 << 27)
                | (opc << 22)
                | (((imm9 as u32) & 0x1ff) << 12)
                | (mode << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_ldst_unscaled(&mut self, rt: u8, rn: u8, size: u32, opc: u32, imm9: i64) {
        self.emit_ldst_simm(rt, rn, size, opc, imm9, 0b00);
    }

    fn emit_ldst_reg_offset(
        &mut self,
        rt: u8,
        rn: u8,
        rm: u8,
        size: u32,
        opc: u32,
        option: u32,
        s: u32,
    ) {
        self.emit(
            (size << 30)
                | (0b111 << 27)
                | (opc << 22)
                | (1 << 21)
                | ((rm as u32) << 16)
                | (option << 13)
                | (s << 12)
                | (0b10 << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_ldst_pair(
        &mut self,
        rt: u8,
        rt2: u8,
        rn: u8,
        opc: u32,
        load: bool,
        imm7: i64,
        mode: u32,
    ) {
        self.emit(
            (opc << 30)
                | (0b101 << 27)
                | (mode << 23)
                | ((load as u32) << 22)
                | (((imm7 as u32) & 0x7f) << 15)
                | ((rt2 as u32) << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_load_exclusive(&mut self, rt: u8, rn: u8, size: u32) {
        self.emit(
            (size << 30)
                | (0b001000 << 24)
                | (1 << 22)
                | (0b11111 << 16)
                | (0b11111 << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_store_exclusive(&mut self, rs: u8, rt: u8, rn: u8, size: u32) {
        self.emit(
            (size << 30)
                | (0b001000 << 24)
                | ((rs as u32) << 16)
                | (0b11111 << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_atomic_load(&mut self, rt: u8, rn: u8, size: u32) {
        self.emit(
            (size << 30)
                | (0b001000 << 24)
                | (1 << 23)
                | (1 << 22)
                | (0b11111 << 16)
                | (1 << 15)
                | (0b11111 << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_atomic_store(&mut self, rt: u8, rn: u8, size: u32) {
        self.emit(
            (size << 30)
                | (0b001000 << 24)
                | (1 << 23)
                | (0b11111 << 16)
                | (1 << 15)
                | (0b11111 << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_atomic_rmw(
        &mut self,
        rt: u8,
        rn: u8,
        rs: u8,
        size: u32,
        acquire: u32,
        release: u32,
        o3: u32,
        opc: u32,
    ) {
        self.emit(
            (size << 30)
                | (0b111 << 27)
                | (acquire << 23)
                | (release << 22)
                | (1 << 21)
                | ((rs as u32) << 16)
                | (o3 << 15)
                | (opc << 12)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_cas(&mut self, rs: u8, rt: u8, rn: u8, size: u32, acquire: u32, release: u32) {
        self.emit(
            (size << 30)
                | (0b001000 << 24)
                | (1 << 23)
                | (acquire << 22)
                | (1 << 21)
                | ((rs as u32) << 16)
                | (release << 15)
                | (0b11111 << 10)
                | ((rn as u32) << 5)
                | (rt as u32),
        );
    }

    fn emit_cond_select(
        &mut self,
        dst: u8,
        rn: u8,
        rm: u8,
        cond: u32,
        op: u32,
        op2: u32,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (op << 30)
                | (0b11010100 << 21)
                | ((rm as u32) << 16)
                | (cond << 12)
                | (op2 << 10)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
    }

    fn emit_cond_compare(
        &mut self,
        rn: u8,
        rm_imm5: u8,
        cond: u32,
        nzcv: u32,
        subtract: bool,
        immediate: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | ((subtract as u32) << 30)
                | (0b111010010 << 21)
                | ((rm_imm5 as u32) << 16)
                | (cond << 12)
                | ((immediate as u32) << 11)
                | ((rn as u32) << 5)
                | (nzcv & 0xf),
        );
        Ok(())
    }

    fn emit_sysreg(&mut self, rt: u8, reg: ArmReg, read: bool) -> Result<(), LowerError> {
        let Some(info) = Self::sysreg_info(reg) else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native system register {reg:?}"),
            });
        };
        self.emit(
            0xd500_0000
                | ((read as u32) << 21)
                | (3 << 19)
                | (info.op1 << 16)
                | (info.crn << 12)
                | (info.crm << 8)
                | (info.op2 << 5)
                | u32::from(rt),
        );
        Ok(())
    }

    fn emit_flagm(&mut self, op2: u32) {
        self.emit(0xd500_401f | (op2 << 5));
    }

    fn emit_brk(&mut self, imm16: u16) {
        self.emit(0xd420_0000 | (u32::from(imm16) << 5));
    }

    fn emit_svc(&mut self, imm16: u16) {
        self.emit(0xd400_0001 | (u32::from(imm16) << 5));
    }

    fn emit_hlt(&mut self, imm16: u16) {
        self.emit(0xd440_0000 | (u32::from(imm16) << 5));
    }

    fn emit_udf(&mut self, imm16: u16) {
        self.emit(u32::from(imm16) << 5);
    }

    fn exception_imm16(op: &str, imm: u32) -> Result<u16, LowerError> {
        u16::try_from(imm).map_err(|_| LowerError::InvalidOperand {
            op: format!("AArch64 native {op}"),
            operand: format!("imm={imm:#x}"),
        })
    }

    fn bitfield_args(
        op: &str,
        lsb: u8,
        width_bits: u8,
        op_width: OpWidth,
    ) -> Result<u32, LowerError> {
        Self::sf(op_width)?;
        let op_bits = op_width.bits();
        if width_bits == 0
            || u32::from(lsb) >= op_bits
            || u32::from(width_bits) > op_bits
            || u32::from(lsb) + u32::from(width_bits) > op_bits
        {
            return Err(LowerError::InvalidOperand {
                op: op.into(),
                operand: format!(
                    "lsb={lsb}, width_bits={width_bits}, op_width={op_width:?}"
                ),
            });
        }
        Ok(op_bits)
    }

    fn mem_size(width: MemWidth) -> Result<u32, LowerError> {
        match width {
            MemWidth::B1 => Ok(0),
            MemWidth::B2 => Ok(1),
            MemWidth::B4 => Ok(2),
            MemWidth::B8 => Ok(3),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native scalar memory width {other:?}"),
            }),
        }
    }

    fn pair_width(width: MemWidth) -> Result<(u32, i64), LowerError> {
        match width {
            MemWidth::B4 => Ok((0b00, 4)),
            MemWidth::B8 => Ok((0b10, 8)),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native pair memory width {other:?}"),
            }),
        }
    }

    fn load_opc(width: MemWidth, sign: SignExtend) -> Result<u32, LowerError> {
        match (sign, width) {
            (SignExtend::Zero, _) | (SignExtend::Sign, MemWidth::B8) => Ok(0b01),
            (SignExtend::Sign, MemWidth::B1 | MemWidth::B2 | MemWidth::B4) => Ok(0b10),
            _ => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native signed load width {width:?}"),
            }),
        }
    }

    fn mem_access_parts(
        kind: &OpKind,
    ) -> Result<Option<(u8, &Address, u32, u32)>, LowerError> {
        match kind {
            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => Ok(Some((
                Self::dst_gpr(*dst)?,
                addr,
                Self::mem_size(*width)?,
                Self::load_opc(*width, *sign)?,
            ))),
            OpKind::Store { src, addr, width } => Ok(Some((
                Self::gpr(*src)?,
                addr,
                Self::mem_size(*width)?,
                0b00,
            ))),
            _ => Ok(None),
        }
    }

    fn signed_load_w_parts<'a>(
        load: &'a OpKind,
        extend: &OpKind,
    ) -> Result<Option<(u8, &'a Address, u32, u32)>, LowerError> {
        match (load, extend) {
            (
                OpKind::Load {
                    dst: load_dst,
                    addr,
                    width,
                    sign: SignExtend::Sign,
                },
                OpKind::ZeroExtend {
                    dst,
                    src,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ) if *src == *load_dst => {
                let size = match width {
                    MemWidth::B1 | MemWidth::B2 => Self::mem_size(*width)?,
                    _ => return Ok(None),
                };
                Ok(Some((Self::dst_gpr(*dst)?, addr, size, 0b11)))
            }
            _ => Ok(None),
        }
    }

    fn mem_access_sequence_parts(
        ops: &[SmirOp],
    ) -> Result<Option<(u8, &Address, u32, u32, usize)>, LowerError> {
        if let [load, extend, ..] = ops {
            if let Some((rt, addr, size, opc)) =
                Self::signed_load_w_parts(&load.kind, &extend.kind)?
            {
                return Ok(Some((rt, addr, size, opc, 2)));
            }
        }

        if let [access, ..] = ops {
            if let Some((rt, addr, size, opc)) = Self::mem_access_parts(&access.kind)? {
                return Ok(Some((rt, addr, size, opc, 1)));
            }
        }

        Ok(None)
    }

    fn pair_access_parts(
        kind: &OpKind,
    ) -> Result<Option<(u8, u8, &Address, MemWidth, bool)>, LowerError> {
        match kind {
            OpKind::LoadPair {
                dst1,
                dst2,
                addr,
                width,
            } => Ok(Some((
                Self::dst_gpr(*dst1)?,
                Self::dst_gpr(*dst2)?,
                addr,
                *width,
                true,
            ))),
            OpKind::StorePair {
                src1,
                src2,
                addr,
                width,
            } => Ok(Some((
                Self::gpr(*src1)?,
                Self::gpr(*src2)?,
                addr,
                *width,
                false,
            ))),
            _ => Ok(None),
        }
    }

    fn lifted_ldpsw_pair_parts<'a>(
        first: &'a SmirOp,
        second: &'a SmirOp,
    ) -> Result<Option<(u8, u8, &'a Address)>, LowerError> {
        if first.guest_pc != second.guest_pc {
            return Ok(None);
        }

        match (&first.kind, &second.kind) {
            (
                OpKind::Load {
                    dst: dst1,
                    addr: addr1,
                    width,
                    sign: SignExtend::Sign,
                },
                OpKind::Load {
                    dst: dst2,
                    addr: addr2,
                    width: width2,
                    sign: SignExtend::Sign,
                },
            ) if width == width2 => {
                if *width != MemWidth::B8 {
                    return Ok(None);
                }
                if !Self::addr_plus_eq(addr1, addr2, 8) {
                    return Ok(None);
                }
                Ok(Some((Self::dst_gpr(*dst1)?, Self::dst_gpr(*dst2)?, addr1)))
            }
            _ => Ok(None),
        }
    }

    fn direct_addr_reg(addr: &Address) -> Option<VReg> {
        match addr {
            Address::Direct(reg) => Some(*reg),
            _ => None,
        }
    }

    fn addr_base_offset(addr: &Address) -> Option<(VReg, i64)> {
        match addr {
            Address::Direct(base) => Some((*base, 0)),
            Address::BaseOffset { base, offset, .. } => Some((*base, *offset)),
            _ => None,
        }
    }

    fn addr_plus_eq(base_addr: &Address, plus_addr: &Address, delta: i64) -> bool {
        match (Self::addr_base_offset(base_addr), Self::addr_base_offset(plus_addr)) {
            (Some((base, offset)), Some((plus_base, plus_offset))) => {
                base == plus_base && plus_offset == offset + delta
            }
            _ => false,
        }
    }

    fn src_imm(src: &SrcOperand) -> Option<i64> {
        match src {
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => Some(*imm),
            _ => None,
        }
    }

    fn writeback_add_parts(kind: &OpKind) -> Option<(VReg, i64)> {
        match kind {
            OpKind::Add {
                dst,
                src1,
                src2,
                width: OpWidth::W64,
                flags,
            } if *dst == *src1 && !flags.updates_any() => {
                Some((*dst, Self::src_imm(src2)?))
            }
            _ => None,
        }
    }

    fn transfer_reg_aliases_base(rt: u8, base: VReg) -> bool {
        matches!(base, VReg::Arch(ArchReg::Arm(ArmReg::X(n))) if n == rt)
    }

    fn mem_extend_option(from_width: OpWidth, signed: bool) -> Option<u32> {
        match (from_width, signed) {
            (OpWidth::W32, false) => Some(0b010),
            (OpWidth::W64, false) => Some(0b011),
            (OpWidth::W32, true) => Some(0b110),
            (OpWidth::W64, true) => Some(0b111),
            _ => None,
        }
    }

    fn mem_extend_parts(kind: &OpKind) -> Option<(VReg, VReg, u32)> {
        match kind {
            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width: OpWidth::W64,
            } => Some((*dst, *src, Self::mem_extend_option(*from_width, false)?)),
            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width: OpWidth::W64,
            } => Some((*dst, *src, Self::mem_extend_option(*from_width, true)?)),
            _ => None,
        }
    }

    fn mem_shift_bit(amount: &SrcOperand, size: u32) -> Option<u32> {
        if Self::src_imm_eq(amount, 0) {
            Some(0)
        } else if size != 0 && Self::src_imm_eq(amount, i64::from(size)) {
            Some(1)
        } else {
            None
        }
    }

    fn mem_index_scale_bit(scale: u8, size: u32) -> Result<u32, LowerError> {
        if scale == 1 {
            return Ok(0);
        }
        if size != 0 && u32::from(scale) == (1_u32 << size) {
            return Ok(1);
        }

        Err(LowerError::UnsupportedOp {
            op: format!("AArch64 native memory index scale {scale} for access size {size}"),
        })
    }

    fn lower_mem_access(
        &mut self,
        rt: u8,
        addr: &Address,
        size: u32,
        opc: u32,
    ) -> Result<(), LowerError> {
        if let Address::BaseIndexScale {
            base,
            index,
            scale,
            disp,
            ..
        } = addr
        {
            return self.lower_mem_base_index_scale_access(
                rt, *base, *index, *scale, *disp, size, opc,
            );
        }

        let (base, offset) = match addr {
            Address::Direct(base) => (Self::base_gpr(*base)?, 0),
            Address::BaseOffset { base, offset, .. } => (Self::base_gpr(*base)?, *offset),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native memory address {other:?}"),
                });
            }
        };

        let scale = 1_i64 << size;
        if offset >= 0 && offset % scale == 0 {
            let imm12 = offset / scale;
            if imm12 <= 0xfff {
                self.emit_ldst_unsigned(rt, base, size, opc, imm12 as u32);
                return Ok(());
            }
        }

        if (-256..=255).contains(&offset) {
            self.emit_ldst_unscaled(rt, base, size, opc, offset);
            return Ok(());
        }

        Err(LowerError::InvalidOperand {
            op: "AArch64 native memory offset".into(),
            operand: format!("{offset:#x} for size {size}"),
        })
    }

    fn lower_mem_indexed_access(
        &mut self,
        rt: u8,
        base: VReg,
        size: u32,
        opc: u32,
        imm9: i64,
        mode: u32,
    ) -> Result<(), LowerError> {
        if !(-256..=255).contains(&imm9) {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 native indexed memory offset".into(),
                operand: format!("{imm9:#x} for size {size}"),
            });
        }

        let rn = Self::base_gpr(base)?;
        self.emit_ldst_simm(rt, rn, size, opc, imm9, mode);
        Ok(())
    }

    fn pair_scaled_imm(width: MemWidth, offset: i64) -> Result<Option<(u32, i64)>, LowerError> {
        let (opc, scale) = Self::pair_width(width)?;
        if offset % scale != 0 {
            return Ok(None);
        }

        let imm7 = offset / scale;
        if (-64..=63).contains(&imm7) {
            Ok(Some((opc, imm7)))
        } else {
            Ok(None)
        }
    }

    fn ldpsw_scaled_imm(offset: i64) -> Option<i64> {
        if offset % 4 != 0 {
            return None;
        }
        let imm7 = offset / 4;
        (-64..=63).contains(&imm7).then_some(imm7)
    }

    fn lower_load(
        &mut self,
        dst: VReg,
        addr: &Address,
        width: MemWidth,
        sign: SignExtend,
    ) -> Result<(), LowerError> {
        let rt = Self::dst_gpr(dst)?;
        let size = Self::mem_size(width)?;
        let opc = Self::load_opc(width, sign)?;
        self.lower_mem_access(rt, addr, size, opc)
    }

    fn lower_store(&mut self, src: VReg, addr: &Address, width: MemWidth) -> Result<(), LowerError> {
        let rt = Self::gpr(src)?;
        let size = Self::mem_size(width)?;
        self.lower_mem_access(rt, addr, size, 0b00)
    }

    fn pred_store_src_to_vreg(src: &SrcOperand) -> Result<VReg, LowerError> {
        match src {
            SrcOperand::Reg(reg) => Ok(*reg),
            SrcOperand::Imm(0) | SrcOperand::Imm64(0) => Ok(VReg::Imm(0)),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native PredStore source {other:?}"),
            }),
        }
    }

    fn lower_pred_load(
        &mut self,
        dst: VReg,
        cond: VReg,
        addr: &Address,
        width: MemWidth,
        signed: SignExtend,
    ) -> Result<(), LowerError> {
        let cond = Self::gpr(cond)?;
        let branch = self.code.position();
        self.emit_test_branch(cond, 0, false, 0)?;
        self.lower_load(dst, addr, width, signed)?;
        self.patch_test_branch_to_current(branch, cond, 0, false)
    }

    fn lower_pred_store(
        &mut self,
        src: &SrcOperand,
        cond: VReg,
        addr: &Address,
        width: MemWidth,
    ) -> Result<(), LowerError> {
        let cond = Self::gpr(cond)?;
        let branch = self.code.position();
        self.emit_test_branch(cond, 0, false, 0)?;
        self.lower_store(Self::pred_store_src_to_vreg(src)?, addr, width)?;
        self.patch_test_branch_to_current(branch, cond, 0, false)
    }

    fn exclusive_base_gpr(addr: &Address) -> Result<u8, LowerError> {
        match addr {
            Address::Direct(base) => Self::base_gpr(*base),
            Address::BaseOffset { base, offset, .. } if *offset == 0 => Self::base_gpr(*base),
            Address::BaseOffset { offset, .. } => Err(LowerError::InvalidOperand {
                op: "AArch64 native exclusive memory offset".into(),
                operand: format!("{offset:#x}"),
            }),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native exclusive memory address {other:?}"),
            }),
        }
    }

    fn lower_load_exclusive(
        &mut self,
        dst: VReg,
        addr: &Address,
        width: MemWidth,
    ) -> Result<(), LowerError> {
        let rt = Self::dst_gpr(dst)?;
        let rn = Self::exclusive_base_gpr(addr)?;
        let size = Self::mem_size(width)?;
        self.emit_load_exclusive(rt, rn, size);
        Ok(())
    }

    fn lower_store_exclusive(
        &mut self,
        status: VReg,
        src: VReg,
        addr: &Address,
        width: MemWidth,
    ) -> Result<(), LowerError> {
        let rs = Self::dst_gpr(status)?;
        let rt = Self::gpr(src)?;
        let rn = Self::exclusive_base_gpr(addr)?;
        let size = Self::mem_size(width)?;
        self.emit_store_exclusive(rs, rt, rn, size);
        Ok(())
    }

    fn atomic_order_bits(order: MemoryOrder) -> (u32, u32) {
        match order {
            MemoryOrder::Relaxed => (0, 0),
            MemoryOrder::Acquire => (1, 0),
            MemoryOrder::Release => (0, 1),
            MemoryOrder::AcqRel | MemoryOrder::SeqCst => (1, 1),
        }
    }

    fn lower_atomic_load(
        &mut self,
        dst: VReg,
        addr: &Address,
        width: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), LowerError> {
        let rt = Self::dst_gpr(dst)?;
        let size = Self::mem_size(width)?;
        match order {
            MemoryOrder::Relaxed => self.lower_mem_access(rt, addr, size, 0b01),
            MemoryOrder::Acquire | MemoryOrder::SeqCst => {
                let rn = Self::exclusive_base_gpr(addr)?;
                self.emit_atomic_load(rt, rn, size);
                Ok(())
            }
            MemoryOrder::Release | MemoryOrder::AcqRel => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native atomic load order {order:?}"),
            }),
        }
    }

    fn lower_atomic_store(
        &mut self,
        src: VReg,
        addr: &Address,
        width: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), LowerError> {
        let rt = Self::gpr(src)?;
        let size = Self::mem_size(width)?;
        match order {
            MemoryOrder::Relaxed => self.lower_mem_access(rt, addr, size, 0b00),
            MemoryOrder::Release | MemoryOrder::SeqCst => {
                let rn = Self::exclusive_base_gpr(addr)?;
                self.emit_atomic_store(rt, rn, size);
                Ok(())
            }
            MemoryOrder::Acquire | MemoryOrder::AcqRel => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native atomic store order {order:?}"),
            }),
        }
    }

    fn atomic_rmw_op_encoding(op: AtomicOp) -> Result<(u32, u32), LowerError> {
        match op {
            AtomicOp::Add => Ok((0, 0b000)),
            AtomicOp::Xor => Ok((0, 0b010)),
            AtomicOp::Or => Ok((0, 0b011)),
            AtomicOp::Max => Ok((0, 0b100)),
            AtomicOp::Min => Ok((0, 0b101)),
            AtomicOp::Umax => Ok((0, 0b110)),
            AtomicOp::Umin => Ok((0, 0b111)),
            AtomicOp::Swap => Ok((1, 0b000)),
            AtomicOp::And | AtomicOp::Sub | AtomicOp::Nand => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native atomic RMW op {op:?}"),
            }),
        }
    }

    fn lower_atomic_rmw(
        &mut self,
        dst: VReg,
        addr: &Address,
        src: VReg,
        op: AtomicOp,
        width: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), LowerError> {
        let rt = Self::dst_gpr(dst)?;
        let rn = Self::exclusive_base_gpr(addr)?;
        let rs = Self::gpr(src)?;
        let size = Self::mem_size(width)?;
        let (acquire, release) = Self::atomic_order_bits(order);
        let (o3, opc) = Self::atomic_rmw_op_encoding(op)?;
        self.emit_atomic_rmw(rt, rn, rs, size, acquire, release, o3, opc);
        Ok(())
    }

    fn lower_ldclr(
        &mut self,
        dst: VReg,
        addr: &Address,
        src: VReg,
        width: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), LowerError> {
        let rt = Self::dst_gpr(dst)?;
        let rn = Self::exclusive_base_gpr(addr)?;
        let rs = Self::gpr(src)?;
        let size = Self::mem_size(width)?;
        let (acquire, release) = Self::atomic_order_bits(order);
        self.emit_atomic_rmw(rt, rn, rs, size, acquire, release, 0, 0b001);
        Ok(())
    }

    fn lower_cas(
        &mut self,
        dst: VReg,
        success: VReg,
        addr: &Address,
        expected: VReg,
        new_val: VReg,
        width: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), LowerError> {
        if dst != expected {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 native CAS compare/destination register".into(),
                operand: format!("dst={dst:?}, expected={expected:?}"),
            });
        }
        if !matches!(success, VReg::Virtual(_)) {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native CAS observable success {success:?}"),
            });
        }

        let rs = Self::dst_gpr(dst)?;
        let rt = Self::gpr(new_val)?;
        let rn = Self::exclusive_base_gpr(addr)?;
        let size = Self::mem_size(width)?;
        let (acquire, release) = Self::atomic_order_bits(order);
        self.emit_cas(rs, rt, rn, size, acquire, release);
        Ok(())
    }

    fn lower_pair_mem_access(
        &mut self,
        rt: u8,
        rt2: u8,
        addr: &Address,
        width: MemWidth,
        load: bool,
    ) -> Result<(), LowerError> {
        let (base, offset) = match addr {
            Address::Direct(base) => (Self::base_gpr(*base)?, 0),
            Address::BaseOffset { base, offset, .. } => (Self::base_gpr(*base)?, *offset),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native pair memory address {other:?}"),
                });
            }
        };
        let Some((opc, imm7)) = Self::pair_scaled_imm(width, offset)? else {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 native pair memory offset".into(),
                operand: format!("{offset:#x} for width {width:?}"),
            });
        };
        self.emit_ldst_pair(rt, rt2, base, opc, load, imm7, 0b10);
        Ok(())
    }

    fn lower_pair_indexed_access(
        &mut self,
        rt: u8,
        rt2: u8,
        base: VReg,
        width: MemWidth,
        load: bool,
        offset: i64,
        mode: u32,
    ) -> Result<(), LowerError> {
        let Some((opc, imm7)) = Self::pair_scaled_imm(width, offset)? else {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 native indexed pair memory offset".into(),
                operand: format!("{offset:#x} for width {width:?}"),
            });
        };

        let rn = Self::base_gpr(base)?;
        self.emit_ldst_pair(rt, rt2, rn, opc, load, imm7, mode);
        Ok(())
    }

    fn lower_ldpsw_pair_access(
        &mut self,
        rt: u8,
        rt2: u8,
        base: VReg,
        offset: i64,
        mode: u32,
    ) -> Result<(), LowerError> {
        let Some(imm7) = Self::ldpsw_scaled_imm(offset) else {
            return Err(LowerError::InvalidOperand {
                op: "AArch64 native LDPSW pair offset".into(),
                operand: format!("{offset:#x}"),
            });
        };

        self.emit_ldst_pair(rt, rt2, Self::base_gpr(base)?, 0b01, true, imm7, mode);
        Ok(())
    }

    fn lower_load_pair(
        &mut self,
        dst1: VReg,
        dst2: VReg,
        addr: &Address,
        width: MemWidth,
    ) -> Result<(), LowerError> {
        self.lower_pair_mem_access(
            Self::dst_gpr(dst1)?,
            Self::dst_gpr(dst2)?,
            addr,
            width,
            true,
        )
    }

    fn lower_store_pair(
        &mut self,
        src1: VReg,
        src2: VReg,
        addr: &Address,
        width: MemWidth,
    ) -> Result<(), LowerError> {
        self.lower_pair_mem_access(Self::gpr(src1)?, Self::gpr(src2)?, addr, width, false)
    }

    fn lower_mem_base_index_scale_access(
        &mut self,
        rt: u8,
        base: Option<VReg>,
        index: VReg,
        scale: u8,
        disp: i32,
        size: u32,
        opc: u32,
    ) -> Result<(), LowerError> {
        let Some(base) = base else {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native memory index without base".into(),
            });
        };
        if disp != 0 {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native memory index displacement {disp:#x}"),
            });
        }

        let s = Self::mem_index_scale_bit(scale, size)?;
        self.lower_mem_reg_offset_access(rt, base, index, size, opc, 0b011, s)
    }

    fn lower_mem_reg_offset_access(
        &mut self,
        rt: u8,
        base: VReg,
        index: VReg,
        size: u32,
        opc: u32,
        option: u32,
        s: u32,
    ) -> Result<(), LowerError> {
        self.emit_ldst_reg_offset(
            rt,
            Self::base_gpr(base)?,
            Self::gpr(index)?,
            size,
            opc,
            option,
            s,
        );
        Ok(())
    }

    fn lower_mov(&mut self, dst: VReg, src: &SrcOperand, width: OpWidth) -> Result<(), LowerError> {
        if let Some(reg) = Self::sysreg_vreg(dst) {
            return self.lower_sysreg_write(reg, src, width);
        }
        if let SrcOperand::Reg(src_reg) = src {
            if let Some(reg) = Self::sysreg_vreg(*src_reg) {
                return self.lower_sysreg_read(dst, reg, width);
            }
        }

        let dst = Self::dst_gpr(dst)?;
        match src {
            SrcOperand::Reg(reg) => self.emit_mov_reg(dst, Self::gpr(*reg)?, width),
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => self.emit_mov_imm(dst, *imm, width),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Mov source {other:?}"),
            }),
        }
    }

    fn emit_add_signed_imm(
        &mut self,
        dst: u8,
        rn: u8,
        offset: i64,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let (subtract, imm) = if offset < 0 {
            (
                true,
                offset.checked_neg().ok_or_else(|| LowerError::InvalidOperand {
                    op: "AArch64 native signed immediate".into(),
                    operand: format!("{offset:#x}"),
                })?,
            )
        } else {
            (false, offset)
        };
        self.emit_addsub_imm(dst, rn, imm, subtract, false, width)
    }

    fn lea_scale_shift(scale: u8) -> Result<u32, LowerError> {
        match scale {
            1 => Ok(0),
            2 => Ok(1),
            4 => Ok(2),
            8 => Ok(3),
            _ => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native LEA scale {scale}"),
            }),
        }
    }

    fn lower_lea(&mut self, dst: VReg, addr: &Address) -> Result<(), LowerError> {
        let dst = Self::dst_gpr(dst)?;
        match addr {
            Address::Direct(base) => {
                self.emit_add_signed_imm(dst, Self::base_gpr(*base)?, 0, OpWidth::W64)
            }
            Address::BaseOffset { base, offset, .. } => {
                self.emit_add_signed_imm(dst, Self::base_gpr(*base)?, *offset, OpWidth::W64)
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                ..
            } => {
                let shift = Self::lea_scale_shift(*scale)?;
                let rn = match base {
                    Some(base) => Self::base_gpr(*base)?,
                    None => 31,
                };
                self.emit_addsub_shifted(
                    dst,
                    rn,
                    Self::gpr(*index)?,
                    false,
                    false,
                    0,
                    shift,
                    OpWidth::W64,
                )?;
                if *disp == 0 {
                    Ok(())
                } else {
                    self.emit_add_signed_imm(dst, dst, i64::from(*disp), OpWidth::W64)
                }
            }
            Address::Absolute(addr) => self.emit_mov_imm(dst, *addr as i64, OpWidth::W64),
            Address::PcRel { offset, base, .. } => {
                let addr = base.unwrap_or(0).wrapping_add(*offset as u64);
                self.emit_mov_imm(dst, addr as i64, OpWidth::W64)
            }
            Address::GpRel { .. } | Address::SegmentRel { .. } => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native LEA address {addr:?}"),
            }),
        }
    }

    fn lower_sysreg_read(
        &mut self,
        dst: VReg,
        reg: ArmReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        Self::validate_sysreg_width("MRS", width)?;
        self.emit_sysreg(Self::dst_gpr(dst)?, reg, true)
    }

    fn lower_sysreg_write(
        &mut self,
        reg: ArmReg,
        src: &SrcOperand,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        Self::validate_sysreg_width("MSR", width)?;
        let rt = match src {
            SrcOperand::Reg(src) => Self::gpr(*src)?,
            SrcOperand::Imm(0) | SrcOperand::Imm64(0) => 31,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native system register write source {other:?}"),
                });
            }
        };
        self.emit_sysreg(rt, reg, false)
    }

    fn lower_raw_sysreg_read(&mut self, dst: VReg, reg: u32) -> Result<(), LowerError> {
        let Some(reg) = Self::raw_sysreg(reg) else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native MRS sysreg {reg:#06x}"),
            });
        };
        self.emit_sysreg(Self::dst_gpr(dst)?, reg, true)
    }

    fn lower_raw_sysreg_write(&mut self, reg: u32, src: VReg) -> Result<(), LowerError> {
        let Some(reg) = Self::raw_sysreg(reg) else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native MSR sysreg {reg:#06x}"),
            });
        };
        self.emit_sysreg(Self::gpr(src)?, reg, false)
    }

    fn lower_addsub(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: &SrcOperand,
        subtract: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let dst = Self::dst_or_zero_for_flags(dst, set_flags)?;
        let rn = Self::gpr(src1)?;
        match src2 {
            SrcOperand::Reg(_) | SrcOperand::Shifted { .. } => {
                let (rm, shift, amount) = Self::addsub_src2(src2, width)?;
                self.emit_addsub_shifted(dst, rn, rm, subtract, set_flags, shift, amount, width)
            }
            SrcOperand::Extended { .. } => {
                let (rm, option, amount) = Self::addsub_ext_src2(src2)?;
                self.emit_addsub_extended(dst, rn, rm, subtract, set_flags, option, amount, width)
            }
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                self.emit_addsub_imm(dst, rn, *imm, subtract, set_flags, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native add/sub source {other:?}"),
            }),
        }
    }

    fn lower_addsub_carry(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: &SrcOperand,
        subtract: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let dst = Self::dst_or_zero_for_flags(dst, set_flags)?;
        let rn = Self::gpr(src1)?;
        match src2 {
            SrcOperand::Reg(reg) => {
                self.emit_addsub_carry(dst, rn, Self::gpr(*reg)?, subtract, set_flags, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native add/sub carry source {other:?}"),
            }),
        }
    }

    fn lower_logic(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: &SrcOperand,
        opc: u32,
        n: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if set_flags && opc != 0b11 {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native logical flags are only supported for ANDS/BICS".into(),
            });
        }
        match src2 {
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                let imm = if n {
                    Self::inverted_logical_imm(*imm, width)?
                } else {
                    *imm
                };
                if self.lower_logic_special_imm(dst, src1, opc, set_flags, width, imm)? {
                    return Ok(());
                }
                let (imm_n, immr, imms) = Self::logical_bitmask_imm(imm, width)?;
                self.emit_logic_imm(
                    Self::dst_or_zero_for_flags(dst, set_flags)?,
                    Self::gpr(src1)?,
                    opc,
                    imm_n,
                    immr,
                    imms,
                    width,
                )
            }
            _ => {
                let (src2, shift, amount) = Self::logical_src2(src2, width)?;
                self.emit_logic_shifted(
                    Self::dst_or_zero_for_flags(dst, set_flags)?,
                    Self::gpr(src1)?,
                    src2,
                    opc,
                    n,
                    shift,
                    amount,
                    width,
                )
            }
        }
    }

    fn lower_logic_special_imm(
        &mut self,
        dst: VReg,
        src1: VReg,
        opc: u32,
        set_flags: bool,
        width: OpWidth,
        imm: i64,
    ) -> Result<bool, LowerError> {
        let (_, value, all_ones) = Self::logical_imm_value(imm, width)?;
        if value != 0 && value != all_ones {
            return Ok(false);
        }

        let dst = Self::dst_or_zero_for_flags(dst, set_flags)?;
        let rn = Self::gpr(src1)?;
        match (opc, value == all_ones) {
            (0b00, false) => self.emit_mov_imm(dst, 0, width)?,
            (0b00, true) => self.emit_mov_reg(dst, rn, width)?,
            (0b01, false) | (0b10, false) => self.emit_mov_reg(dst, rn, width)?,
            (0b01, true) => self.emit_movn_zero(dst, width)?,
            (0b10, true) => self.emit_logic_reg_n(dst, 31, rn, 0b01, true, width)?,
            (0b11, false) => self.emit_logic_reg_n(dst, 31, 31, 0b11, false, width)?,
            (0b11, true) => self.emit_logic_reg_n(dst, rn, rn, 0b11, false, width)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn inverted_logical_imm(imm: i64, width: OpWidth) -> Result<i64, LowerError> {
        match width {
            OpWidth::W32 => Ok((!(imm as u32)) as i64),
            OpWidth::W64 => Ok((!(imm as u64)) as i64),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native inverted logical immediate width {other:?}"),
            }),
        }
    }

    fn logical_bitmask_imm(imm: i64, width: OpWidth) -> Result<(u32, u32, u32), LowerError> {
        let (bits, value, all_ones) = Self::logical_imm_value(imm, width)?;
        if value != 0 && value != all_ones {
            for element_bits in [2_u32, 4, 8, 16, 32, 64] {
                if element_bits > bits {
                    break;
                }
                let element_mask = if element_bits == 64 {
                    u64::MAX
                } else {
                    (1_u64 << element_bits) - 1
                };
                for ones in 1..element_bits {
                    let low_mask = (1_u64 << ones) - 1;
                    for immr in 0..element_bits {
                        let element = if immr == 0 {
                            low_mask
                        } else {
                            ((low_mask >> immr) | (low_mask << (element_bits - immr)))
                                & element_mask
                        };
                        let mut mask = 0_u64;
                        let mut offset = 0;
                        while offset < bits {
                            mask |= element << offset;
                            offset += element_bits;
                        }
                        if mask == value {
                            let len = element_bits.trailing_zeros();
                            let n = if element_bits == 64 { 1 } else { 0 };
                            let imms = (ones - 1) | ((!0_u32 << (len + 1)) & 0x3f);
                            return Ok((n, immr, imms));
                        }
                    }
                }
            }
        }
        Err(LowerError::UnsupportedOp {
            op: format!("AArch64 native logical immediate {value:#x} for {width:?}"),
        })
    }

    fn logical_imm_value(imm: i64, width: OpWidth) -> Result<(u32, u64, u64), LowerError> {
        let bits = match width {
            OpWidth::W32 => 32,
            OpWidth::W64 => 64,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native logical immediate width {other:?}"),
                });
            }
        };
        let value = match width {
            OpWidth::W32 => u64::from(imm as u32),
            OpWidth::W64 => imm as u64,
            _ => unreachable!(),
        };
        let all_ones = if bits == 64 {
            u64::MAX
        } else {
            (1_u64 << bits) - 1
        };
        Ok((bits, value, all_ones))
    }

    fn lower_neg(
        &mut self,
        dst: VReg,
        src: VReg,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        self.emit_addsub_reg(
            Self::dst_gpr(dst)?,
            31,
            Self::gpr(src)?,
            true,
            set_flags,
            width,
        )
    }

    fn lower_inc_dec(
        &mut self,
        dst: VReg,
        src: VReg,
        decrement: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if set_flags {
            return Err(LowerError::UnsupportedOp {
                op: if decrement {
                    "AArch64 native flag-setting Dec".into()
                } else {
                    "AArch64 native flag-setting Inc".into()
                },
            });
        }

        self.lower_addsub(
            dst,
            src,
            &SrcOperand::Imm(1),
            decrement,
            false,
            width,
        )
    }

    fn lower_cwd(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let sign_bit = width.bits() - 1;
            let dst = Self::dst_gpr(dst)?;
            self.emit_bitfield(
                dst,
                Self::gpr(src)?,
                0b00,
                sign_bit,
                sign_bit,
                OpWidth::W32,
            )?;
            return self.emit_bitfield(dst, dst, 0b10, 0, sign_bit, OpWidth::W32);
        }
        let bits = width.bits();
        self.lower_shift_imm(
            Self::dst_gpr(dst)?,
            Self::gpr(src)?,
            i64::from(bits - 1),
            ShiftOp::Asr,
            width,
        )
    }

    fn lower_xchg(&mut self, reg1: VReg, reg2: VReg, width: OpWidth) -> Result<(), LowerError> {
        let reg1 = Self::dst_gpr(reg1)?;
        let reg2 = Self::dst_gpr(reg2)?;
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let top_bit = width.bits() - 1;
            if reg1 == reg2 {
                return self.emit_bitfield(reg1, reg1, 0b10, 0, top_bit, OpWidth::W32);
            }

            self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, OpWidth::W32)?;
            self.emit_logic_reg_n(reg2, reg1, reg2, 0b10, false, OpWidth::W32)?;
            self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, OpWidth::W32)?;
            self.emit_bitfield(reg1, reg1, 0b10, 0, top_bit, OpWidth::W32)?;
            return self.emit_bitfield(reg2, reg2, 0b10, 0, top_bit, OpWidth::W32);
        }
        if reg1 == reg2 {
            return self.emit_mov_reg(reg1, reg1, width);
        }

        self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, width)?;
        self.emit_logic_reg_n(reg2, reg1, reg2, 0b10, false, width)?;
        self.emit_logic_reg_n(reg1, reg1, reg2, 0b10, false, width)
    }

    fn lower_not(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        self.emit_logic_reg_n(
            Self::dst_gpr(dst)?,
            31,
            Self::gpr(src)?,
            0b01,
            true,
            width,
        )
    }

    fn lower_cmp(
        &mut self,
        src1: VReg,
        src2: &SrcOperand,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let rn = Self::gpr(src1)?;
        match src2 {
            SrcOperand::Reg(_) | SrcOperand::Shifted { .. } => {
                let (rm, shift, amount) = Self::addsub_src2(src2, width)?;
                self.emit_addsub_shifted(31, rn, rm, true, true, shift, amount, width)
            }
            SrcOperand::Extended { .. } => {
                let (rm, option, amount) = Self::addsub_ext_src2(src2)?;
                self.emit_addsub_extended(31, rn, rm, true, true, option, amount, width)
            }
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                self.emit_addsub_imm(31, rn, *imm, true, true, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native CMP source {other:?}"),
            }),
        }
    }

    fn addsub_src2(
        src2: &SrcOperand,
        width: OpWidth,
    ) -> Result<(u8, u32, u32), LowerError> {
        let bits = width.bits();
        match src2 {
            SrcOperand::Reg(reg) => Ok((Self::gpr(*reg)?, 0, 0)),
            SrcOperand::Shifted { reg, shift, amount } => {
                let shift = match shift {
                    ShiftOp::Lsl => 0,
                    ShiftOp::Lsr => 1,
                    ShiftOp::Asr => 2,
                    ShiftOp::Ror | ShiftOp::Rrx => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("AArch64 native add/sub {shift:?} source"),
                        });
                    }
                };
                if u32::from(*amount) >= bits {
                    return Err(LowerError::InvalidOperand {
                        op: "AArch64 add/sub shifted register".into(),
                        operand: format!("amount={amount}, width={width:?}"),
                    });
                }
                Ok((Self::gpr(*reg)?, shift, u32::from(*amount)))
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native add/sub source {other:?}"),
            }),
        }
    }

    fn addsub_ext_src2(src2: &SrcOperand) -> Result<(u8, u32, u32), LowerError> {
        match src2 {
            SrcOperand::Extended { reg, extend, shift } => {
                let option = match extend {
                    ExtendOp::Uxtb => 0b000,
                    ExtendOp::Uxth => 0b001,
                    ExtendOp::Uxtw => 0b010,
                    ExtendOp::Uxtx => 0b011,
                    ExtendOp::Sxtb => 0b100,
                    ExtendOp::Sxth => 0b101,
                    ExtendOp::Sxtw => 0b110,
                    ExtendOp::Sxtx => 0b111,
                };
                if *shift > 4 {
                    return Err(LowerError::InvalidOperand {
                        op: "AArch64 add/sub extended register".into(),
                        operand: format!("shift={shift}"),
                    });
                }
                Ok((Self::gpr(*reg)?, option, u32::from(*shift)))
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native add/sub extended source {other:?}"),
            }),
        }
    }

    fn lower_test(
        &mut self,
        src1: VReg,
        src2: &SrcOperand,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match src2 {
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                let (_, value, all_ones) = Self::logical_imm_value(*imm, width)?;
                if value == 0 {
                    return self.emit_logic_reg_n(31, 31, 31, 0b11, false, width);
                }
                if value == all_ones {
                    let rn = Self::gpr(src1)?;
                    return self.emit_logic_reg_n(31, rn, rn, 0b11, false, width);
                }
                let (n, immr, imms) = Self::logical_bitmask_imm(*imm, width)?;
                self.emit_logic_imm(31, Self::gpr(src1)?, 0b11, n, immr, imms, width)
            }
            _ => {
                let (src2, shift, amount) = Self::logical_src2(src2, width)?;
                self.emit_logic_shifted(
                    31,
                    Self::gpr(src1)?,
                    src2,
                    0b11,
                    false,
                    shift,
                    amount,
                    width,
                )
            }
        }
    }

    fn logical_src2(
        src2: &SrcOperand,
        width: OpWidth,
    ) -> Result<(u8, u32, u32), LowerError> {
        let bits = width.bits();
        match src2 {
            SrcOperand::Reg(reg) => Ok((Self::gpr(*reg)?, 0, 0)),
            SrcOperand::Shifted { reg, shift, amount } => {
                let shift = match shift {
                    ShiftOp::Lsl => 0,
                    ShiftOp::Lsr => 1,
                    ShiftOp::Asr => 2,
                    ShiftOp::Ror => 3,
                    ShiftOp::Rrx => {
                        return Err(LowerError::UnsupportedOp {
                            op: "AArch64 native logical RRX source".into(),
                        });
                    }
                };
                if u32::from(*amount) >= bits {
                    return Err(LowerError::InvalidOperand {
                        op: "AArch64 logical shifted register".into(),
                        operand: format!("amount={amount}, width={width:?}"),
                    });
                }
                Ok((Self::gpr(*reg)?, shift, u32::from(*amount)))
            }
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native logical source {other:?}"),
                });
            }
        }
    }

    fn lower_clz(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, 0b000100, width)
    }

    fn lower_ctz(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        let dst = Self::dst_gpr(dst)?;
        let src = Self::gpr(src)?;
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let sentinel = if width == OpWidth::W8 { 0x100 } else { 0x1_0000 };
            let (imm_n, immr, imms) = Self::logical_bitmask_imm(sentinel, OpWidth::W32)?;
            self.emit_logic_imm(dst, src, 0b01, imm_n, immr, imms, OpWidth::W32)?;
            self.emit_dp1(dst, dst, 0b000000, OpWidth::W32)?;
            return self.emit_dp1(dst, dst, 0b000100, OpWidth::W32);
        }
        self.emit_dp1(dst, src, 0b000000, width)?;
        self.emit_dp1(dst, dst, 0b000100, width)
    }

    fn lower_bsf(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    ) -> Result<(), LowerError> {
        if flags.updates_any() {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native flag-setting Bsf".into(),
            });
        }

        let (mask_bits, mask_width) = match width {
            OpWidth::W8 => (3, OpWidth::W32),
            OpWidth::W16 => (4, OpWidth::W32),
            OpWidth::W32 => (5, OpWidth::W32),
            OpWidth::W64 => (6, OpWidth::W64),
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Bsf width {other:?}"),
                });
            }
        };
        self.lower_ctz(dst, src, width)?;
        self.lower_bfx(dst, dst, 0, mask_bits, false, mask_width)
    }

    fn lower_bsr(
        &mut self,
        dst: VReg,
        src: VReg,
        width: OpWidth,
        flags: FlagUpdate,
    ) -> Result<(), LowerError> {
        if flags.updates_any() {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native flag-setting Bsr".into(),
            });
        }

        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let top_bit = width.bits() - 1;
            let dst = Self::dst_gpr(dst)?;
            self.emit_bitfield(dst, Self::gpr(src)?, 0b10, 0, top_bit, OpWidth::W32)?;
            self.emit_orr_imm_one(dst, dst, OpWidth::W32)?;
            self.emit_dp1(dst, dst, 0b000100, OpWidth::W32)?;
            return self.emit_logic_imm(dst, dst, 0b10, 0, 0, 4, OpWidth::W32);
        }

        let mask_imms = match width {
            OpWidth::W32 => 4,
            OpWidth::W64 => 5,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Bsr width {other:?}"),
                });
            }
        };
        let dst = Self::dst_gpr(dst)?;
        self.emit_orr_imm_one(dst, Self::gpr(src)?, width)?;
        self.emit_dp1(dst, dst, 0b000100, width)?;
        let n = Self::sf(width)?;
        self.emit_logic_imm(dst, dst, 0b10, n, 0, mask_imms, width)
    }

    fn lower_cls(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, 0b000101, width)
    }

    fn lower_rbit(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            return self.emit_mov_reg(Self::dst_gpr(dst)?, Self::gpr(src)?, OpWidth::W64);
        }
        self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, 0b000000, width)
    }

    fn lower_bswap(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        let opcode = match width {
            OpWidth::W8 => {
                return self.emit_mov_reg(
                    Self::dst_gpr(dst)?,
                    Self::gpr(src)?,
                    OpWidth::W64,
                );
            }
            OpWidth::W16 => {
                let dst = Self::dst_gpr(dst)?;
                self.emit_dp1(dst, Self::gpr(src)?, 0b000001, OpWidth::W32)?;
                return self.emit_bitfield(dst, dst, 0b10, 0, 15, OpWidth::W32);
            }
            OpWidth::W32 => 0b000010,
            OpWidth::W64 => 0b000011,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Bswap width {other:?}"),
                });
            }
        };
        self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, opcode, width)
    }

    fn lower_rev16(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        match width {
            OpWidth::W32 | OpWidth::W64 => {
                self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, 0b000001, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Rev16 width {other:?}"),
            }),
        }
    }

    fn lower_rev32(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        match width {
            OpWidth::W32 | OpWidth::W64 => {
                self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, 0b000010, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Rev32 width {other:?}"),
            }),
        }
    }

    fn lower_bfx(
        &mut self,
        dst: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        sign_extend: bool,
        op_width: OpWidth,
    ) -> Result<(), LowerError> {
        Self::bitfield_args("Bfx", lsb, width_bits, op_width)?;
        let opc = if sign_extend { 0b00 } else { 0b10 };
        self.emit_bitfield(
            Self::dst_gpr(dst)?,
            Self::gpr(src)?,
            opc,
            u32::from(lsb),
            u32::from(lsb + width_bits - 1),
            op_width,
        )
    }

    fn lower_bfi(
        &mut self,
        dst: VReg,
        dst_in: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        op_width: OpWidth,
    ) -> Result<(), LowerError> {
        let op_bits = Self::bitfield_args("Bfi", lsb, width_bits, op_width)?;
        let dst = Self::dst_gpr(dst)?;
        let dst_in = Self::gpr(dst_in)?;
        let src = Self::gpr(src)?;

        if u32::from(width_bits) == op_bits && lsb == 0 {
            return self.emit_mov_reg(dst, src, op_width);
        }
        if dst != dst_in {
            if dst == src {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native Bfi needs a scratch when dst != dst_in and dst == src"
                        .into(),
                });
            }
            self.emit_mov_reg(dst, dst_in, op_width)?;
        }

        let immr = if lsb == 0 {
            0
        } else {
            op_bits - u32::from(lsb)
        };
        self.emit_bitfield(
            dst,
            src,
            0b01,
            immr,
            u32::from(width_bits - 1),
            op_width,
        )
    }

    fn lower_bitfield_insert_zero(
        &mut self,
        dst: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        sign_extend: bool,
        op_width: OpWidth,
    ) -> Result<(), LowerError> {
        let op_bits = Self::bitfield_args("Bfiz", lsb, width_bits, op_width)?;
        if lsb == 0 {
            return self.lower_bfx(dst, src, 0, width_bits, sign_extend, op_width);
        }
        self.emit_bitfield(
            Self::dst_gpr(dst)?,
            Self::gpr(src)?,
            if sign_extend { 0b00 } else { 0b10 },
            op_bits - u32::from(lsb),
            u32::from(width_bits - 1),
            op_width,
        )
    }

    fn lower_bitfield_insert_low(
        &mut self,
        dst: VReg,
        dst_in: VReg,
        src: VReg,
        lsb: u8,
        width_bits: u8,
        op_width: OpWidth,
    ) -> Result<(), LowerError> {
        Self::bitfield_args("Bfxil", lsb, width_bits, op_width)?;
        let dst = Self::dst_gpr(dst)?;
        let dst_in = Self::gpr(dst_in)?;
        let src = Self::gpr(src)?;

        if dst != dst_in {
            if dst == src {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native Bfxil needs a scratch when dst != dst_in and dst == src"
                        .into(),
                });
            }
            self.emit_mov_reg(dst, dst_in, op_width)?;
        }

        self.emit_bitfield(
            dst,
            src,
            0b01,
            u32::from(lsb),
            u32::from(lsb + width_bits - 1),
            op_width,
        )
    }

    fn lower_extend(
        &mut self,
        dst: VReg,
        src: VReg,
        from_width: OpWidth,
        to_width: OpWidth,
        sign_extend: bool,
    ) -> Result<(), LowerError> {
        let from_bits = from_width.bits();
        let to_bits = to_width.bits();
        if from_bits > to_bits
            || !matches!(
                to_width,
                OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
            )
        {
            return Err(LowerError::UnsupportedOp {
                op: format!(
                    "AArch64 native extend from {from_width:?} to {to_width:?}"
                ),
            });
        }

        let dst = Self::dst_gpr(dst)?;
        let src = Self::gpr(src)?;
        if from_bits == to_bits {
            if matches!(to_width, OpWidth::W8 | OpWidth::W16) {
                return self.emit_bitfield(dst, src, 0b10, 0, from_bits - 1, OpWidth::W32);
            }
            return self.emit_mov_reg(dst, src, to_width);
        }
        let emit_width = if to_width == OpWidth::W64 {
            OpWidth::W64
        } else {
            OpWidth::W32
        };
        self.emit_bitfield(
            dst,
            src,
            if sign_extend { 0b00 } else { 0b10 },
            0,
            from_bits - 1,
            emit_width,
        )?;
        if sign_extend && matches!(to_width, OpWidth::W8 | OpWidth::W16) {
            self.emit_bitfield(dst, dst, 0b10, 0, to_bits - 1, OpWidth::W32)?;
        }
        Ok(())
    }

    fn lower_truncate(
        &mut self,
        dst: VReg,
        src: VReg,
        to_width: OpWidth,
    ) -> Result<(), LowerError> {
        match to_width {
            OpWidth::W8 | OpWidth::W16 => {
                self.lower_bfx(dst, src, 0, to_width.bits() as u8, false, OpWidth::W64)
            }
            OpWidth::W32 | OpWidth::W64 => {
                self.emit_mov_reg(Self::dst_gpr(dst)?, Self::gpr(src)?, to_width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Truncate width {other:?}"),
            }),
        }
    }

    fn lower_mul(
        &mut self,
        dst_lo: VReg,
        dst_hi: Option<VReg>,
        src1: VReg,
        src2: &SrcOperand,
        width: OpWidth,
        set_flags: bool,
        signed: bool,
    ) -> Result<(), LowerError> {
        if set_flags {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native flag-setting multiply".into(),
            });
        }
        let SrcOperand::Reg(src2) = src2 else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native multiply source {src2:?}"),
            });
        };
        let rn = Self::gpr(src1)?;
        let rm = Self::gpr(*src2)?;

        if let Some(dst_hi) = dst_hi {
            if width != OpWidth::W64 {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native high-half multiply width {width:?}"),
                });
            }
            let dst_hi = Self::dst_gpr(dst_hi)?;
            let op31 = if signed { 0b010 } else { 0b110 };
            if matches!(dst_lo, VReg::Virtual(_)) {
                return self.emit_dp3(dst_hi, rn, rm, 31, op31, 0, width);
            }

            let dst_lo = Self::dst_gpr(dst_lo)?;
            let lo_aliases_source = dst_lo == rn || dst_lo == rm;
            let hi_aliases_source = dst_hi == rn || dst_hi == rm;
            if lo_aliases_source && hi_aliases_source {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native full-width multiply with overlapping sources".into(),
                });
            }
            if lo_aliases_source {
                self.emit_dp3(dst_hi, rn, rm, 31, op31, 0, width)?;
                return self.emit_dp3(dst_lo, rn, rm, 31, 0b000, 0, width);
            }
            self.emit_dp3(dst_lo, rn, rm, 31, 0b000, 0, width)?;
            return self.emit_dp3(dst_hi, rn, rm, 31, op31, 0, width);
        }

        self.emit_dp3(Self::dst_gpr(dst_lo)?, rn, rm, 31, 0b000, 0, width)
    }

    fn lower_mul_acc(
        &mut self,
        dst: VReg,
        acc: VReg,
        src1: VReg,
        src2: VReg,
        width: OpWidth,
        subtract: bool,
    ) -> Result<(), LowerError> {
        self.emit_dp3(
            Self::dst_gpr(dst)?,
            Self::gpr(src1)?,
            Self::gpr(src2)?,
            Self::gpr(acc)?,
            0b000,
            subtract as u32,
            width,
        )
    }

    fn lower_div(
        &mut self,
        quot: VReg,
        rem: Option<VReg>,
        src1: VReg,
        src2: &SrcOperand,
        width: OpWidth,
        flags_set: bool,
        signed: bool,
    ) -> Result<(), LowerError> {
        if flags_set {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native flag-setting divide".into(),
            });
        }
        let SrcOperand::Reg(src2) = src2 else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native divide source {src2:?}"),
            });
        };
        let quot = Self::dst_gpr(quot)?;
        let rn = Self::gpr(src1)?;
        let rm = Self::gpr(*src2)?;
        let opcode2 = if signed { 0b0011 } else { 0b0010 };
        if let Some(rem) = rem {
            let rem = Self::dst_gpr(rem)?;
            if quot == rn || quot == rm {
                if rem == rn || rem == rm {
                    return Err(LowerError::UnsupportedOp {
                        op: "AArch64 native divide remainder with overlapping sources".into(),
                    });
                }
                self.emit_dp2(rem, rn, rm, opcode2, width)?;
                self.emit_dp3(rem, rem, rm, rn, 0b000, 1, width)?;
                return self.emit_dp2(quot, rn, rm, opcode2, width);
            }
            self.emit_dp2(quot, rn, rm, opcode2, width)?;
            return self.emit_dp3(rem, quot, rm, rn, 0b000, 1, width);
        }
        self.emit_dp2(quot, rn, rm, opcode2, width)
    }

    fn lower_subword_shift_imm(
        &mut self,
        dst: u8,
        src: u8,
        amount: i64,
        shift: ShiftOp,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let bits = width.bits();
        let top_bit = bits - 1;
        let amount = match shift {
            ShiftOp::Ror | ShiftOp::Rrx => (amount as u64 & u64::from(bits - 1)) as u32,
            ShiftOp::Lsl | ShiftOp::Lsr | ShiftOp::Asr => (amount as u64 & 0x3f) as u32,
        };

        match shift {
            ShiftOp::Lsl => {
                if amount == 0 {
                    self.emit_bitfield(dst, src, 0b10, 0, top_bit, OpWidth::W32)
                } else if amount >= bits {
                    self.emit_mov_imm(dst, 0, OpWidth::W32)
                } else {
                    self.emit_bitfield(
                        dst,
                        src,
                        0b10,
                        OpWidth::W32.bits() - amount,
                        top_bit - amount,
                        OpWidth::W32,
                    )
                }
            }
            ShiftOp::Lsr => {
                if amount == 0 {
                    self.emit_bitfield(dst, src, 0b10, 0, top_bit, OpWidth::W32)
                } else if amount >= bits {
                    self.emit_mov_imm(dst, 0, OpWidth::W32)
                } else {
                    self.emit_bitfield(dst, src, 0b10, amount, top_bit, OpWidth::W32)
                }
            }
            ShiftOp::Asr => {
                self.emit_bitfield(
                    dst,
                    src,
                    0b00,
                    amount.min(top_bit),
                    top_bit,
                    OpWidth::W32,
                )?;
                self.emit_bitfield(dst, dst, 0b10, 0, top_bit, OpWidth::W32)
            }
            ShiftOp::Ror => {
                if amount == 0 {
                    return self.emit_bitfield(dst, src, 0b10, 0, top_bit, OpWidth::W32);
                }
                self.emit_bitfield(dst, src, 0b10, 0, top_bit, OpWidth::W32)?;
                self.emit_bitfield(
                    dst,
                    dst,
                    0b01,
                    OpWidth::W32.bits() - bits,
                    top_bit,
                    OpWidth::W32,
                )?;
                self.emit_bitfield(dst, dst, 0b10, amount, amount + top_bit, OpWidth::W32)
            }
            ShiftOp::Rrx => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native {width:?} immediate {shift:?}"),
            }),
        }
    }

    fn emit_subword_shift_oob_guards(
        &mut self,
        amount: u8,
        width: OpWidth,
    ) -> Result<Vec<(usize, u32)>, LowerError> {
        let guard_bits: &[u32] = match width {
            OpWidth::W8 => &[3, 4, 5],
            OpWidth::W16 => &[4, 5],
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native subword shift guard width {width:?}"),
                });
            }
        };

        let mut guards = Vec::with_capacity(guard_bits.len());
        for &bit in guard_bits {
            let offset = self.code.position();
            self.emit_test_branch(amount, bit, true, 0)?;
            guards.push((offset, bit));
        }
        Ok(guards)
    }

    fn patch_subword_shift_oob_guards(
        &mut self,
        amount: u8,
        guards: &[(usize, u32)],
    ) -> Result<(), LowerError> {
        for &(offset, bit) in guards {
            self.patch_test_branch_to_current(offset, amount, bit, true)?;
        }
        Ok(())
    }

    fn lower_subword_shift_reg(
        &mut self,
        dst: u8,
        src: u8,
        amount: u8,
        shift: ShiftOp,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match shift {
            ShiftOp::Lsr if dst == amount => {
                return Err(LowerError::UnsupportedOp {
                    op: format!(
                        "AArch64 native {width:?} variable Lsr needs a scratch when dst == count"
                    ),
                });
            }
            ShiftOp::Asr if dst == amount => {
                return Err(LowerError::UnsupportedOp {
                    op: format!(
                        "AArch64 native {width:?} variable Asr needs a scratch when dst == count"
                    ),
                });
            }
            ShiftOp::Ror | ShiftOp::Rrx => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native {width:?} variable {shift:?}"),
                });
            }
            _ => {}
        }

        let top_bit = width.bits() - 1;
        let guards = self.emit_subword_shift_oob_guards(amount, width)?;

        match shift {
            ShiftOp::Lsl => {
                self.emit_dp2(dst, src, amount, 0b1000, OpWidth::W32)?;
                self.emit_bitfield(dst, dst, 0b10, 0, top_bit, OpWidth::W32)?;
                let end_branch = self.code.position();
                self.emit(0x1400_0000);
                self.patch_subword_shift_oob_guards(amount, &guards)?;
                self.emit_mov_imm(dst, 0, OpWidth::W32)?;
                self.patch_branch_to_current(end_branch)
            }
            ShiftOp::Lsr => {
                self.emit_bitfield(dst, src, 0b10, 0, top_bit, OpWidth::W32)?;
                self.emit_dp2(dst, dst, amount, 0b1001, OpWidth::W32)?;
                let end_branch = self.code.position();
                self.emit(0x1400_0000);
                self.patch_subword_shift_oob_guards(amount, &guards)?;
                self.emit_mov_imm(dst, 0, OpWidth::W32)?;
                self.patch_branch_to_current(end_branch)
            }
            ShiftOp::Asr => {
                let align_sign_shift = OpWidth::W32.bits() - width.bits();
                self.emit_bitfield(
                    dst,
                    src,
                    0b10,
                    OpWidth::W32.bits() - align_sign_shift,
                    top_bit,
                    OpWidth::W32,
                )?;
                self.emit_dp2(dst, dst, amount, 0b1010, OpWidth::W32)?;
                self.emit_bitfield(
                    dst,
                    dst,
                    0b10,
                    align_sign_shift,
                    OpWidth::W32.bits() - 1,
                    OpWidth::W32,
                )?;
                let end_branch = self.code.position();
                self.emit(0x1400_0000);
                self.patch_subword_shift_oob_guards(amount, &guards)?;
                self.emit_bitfield(dst, src, 0b00, top_bit, top_bit, OpWidth::W32)?;
                self.emit_bitfield(dst, dst, 0b10, 0, top_bit, OpWidth::W32)?;
                self.patch_branch_to_current(end_branch)
            }
            ShiftOp::Ror | ShiftOp::Rrx => unreachable!(),
        }
    }

    fn lower_shift_imm(
        &mut self,
        dst: u8,
        src: u8,
        amount: i64,
        shift: ShiftOp,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            return self.lower_subword_shift_imm(dst, src, amount, shift, width);
        }

        let bits = width.bits();
        let amount = match shift {
            ShiftOp::Ror | ShiftOp::Rrx => (amount as u64 & u64::from(bits - 1)) as u32,
            ShiftOp::Lsl | ShiftOp::Lsr | ShiftOp::Asr => (amount as u64 & 0x3f) as u32,
        };

        match shift {
            ShiftOp::Lsl => {
                if amount == 0 {
                    self.emit_mov_reg(dst, src, width)
                } else if amount >= bits {
                    self.emit_mov_imm(dst, 0, width)
                } else {
                    self.emit_bitfield(
                        dst,
                        src,
                        0b10,
                        bits - amount,
                        bits - 1 - amount,
                        width,
                    )
                }
            }
            ShiftOp::Lsr => {
                if amount == 0 {
                    self.emit_mov_reg(dst, src, width)
                } else if amount >= bits {
                    self.emit_mov_imm(dst, 0, width)
                } else {
                    self.emit_bitfield(dst, src, 0b10, amount, bits - 1, width)
                }
            }
            ShiftOp::Asr => {
                if amount == 0 {
                    self.emit_mov_reg(dst, src, width)
                } else {
                    let amount = amount.min(bits - 1);
                    self.emit_bitfield(dst, src, 0b00, amount, bits - 1, width)
                }
            }
            ShiftOp::Ror | ShiftOp::Rrx => {
                if amount == 0 {
                    self.emit_mov_reg(dst, src, width)
                } else {
                    self.emit_extract(dst, src, src, amount, width)
                }
            }
        }
    }

    fn lower_shift_reg(
        &mut self,
        dst: u8,
        src: u8,
        amount: u8,
        shift: ShiftOp,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            return self.lower_subword_shift_reg(dst, src, amount, shift, width);
        }

        if width == OpWidth::W32 {
            match shift {
                ShiftOp::Lsl | ShiftOp::Lsr => {
                    if dst == amount {
                        return Err(LowerError::UnsupportedOp {
                            op: format!(
                                "AArch64 native W32 variable {shift:?} needs a scratch when dst == count"
                            ),
                        });
                    }
                    let opcode2 = match shift {
                        ShiftOp::Lsl => 0b1000,
                        ShiftOp::Lsr => 0b1001,
                        _ => unreachable!(),
                    };
                    self.emit_dp2(dst, src, amount, opcode2, width)?;
                    self.emit_test_branch(amount, 5, false, 8)?;
                    return self.emit_mov_reg(dst, 31, width);
                }
                ShiftOp::Asr => {
                    if dst == amount {
                        return Err(LowerError::UnsupportedOp {
                            op: "AArch64 native W32 variable Asr needs a scratch when dst == count"
                                .into(),
                        });
                    }
                    self.emit_dp2(dst, src, amount, 0b1010, width)?;
                    self.emit_test_branch(amount, 5, false, 8)?;
                    return self.emit_bitfield(dst, dst, 0b00, 31, 31, width);
                }
                ShiftOp::Ror => {}
                ShiftOp::Rrx => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!(
                            "AArch64 native W32 variable {shift:?} count semantics differ from SMIR"
                        ),
                    });
                }
            }
        }

        let opcode2 = match shift {
            ShiftOp::Lsl => 0b1000,
            ShiftOp::Lsr => 0b1001,
            ShiftOp::Asr => 0b1010,
            ShiftOp::Ror => 0b1011,
            ShiftOp::Rrx => {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native RRX variable shift".into(),
                });
            }
        };
        self.emit_dp2(dst, src, amount, opcode2, width)
    }

    fn arm_cond_code(cond: Condition) -> Result<u32, LowerError> {
        match cond {
            Condition::Eq => Ok(0),
            Condition::Ne => Ok(1),
            Condition::Uge => Ok(2),
            Condition::Ult => Ok(3),
            Condition::Negative => Ok(4),
            Condition::Positive => Ok(5),
            Condition::Overflow => Ok(6),
            Condition::NoOverflow => Ok(7),
            Condition::Ugt => Ok(8),
            Condition::Ule => Ok(9),
            Condition::Sge => Ok(10),
            Condition::Slt => Ok(11),
            Condition::Sgt => Ok(12),
            Condition::Sle => Ok(13),
            Condition::Always => Ok(14),
            Condition::Parity | Condition::NoParity => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native condition {cond:?}"),
            }),
        }
    }

    fn inverted_arm_cond_code(cond: Condition) -> Result<u32, LowerError> {
        let code = Self::arm_cond_code(cond)?;
        if code < 14 {
            Ok(code ^ 1)
        } else {
            Err(LowerError::UnsupportedOp {
                op: "AArch64 native inverted AL condition".into(),
            })
        }
    }

    fn sysreg_vreg(vreg: VReg) -> Option<ArmReg> {
        match vreg {
            VReg::Arch(ArchReg::Arm(reg @ (ArmReg::Nzcv | ArmReg::Fpcr | ArmReg::Fpsr))) => {
                Some(reg)
            }
            _ => None,
        }
    }

    fn raw_sysreg(reg: u32) -> Option<ArmReg> {
        match reg {
            SYSREG_NZCV => Some(ArmReg::Nzcv),
            SYSREG_FPCR => Some(ArmReg::Fpcr),
            SYSREG_FPSR => Some(ArmReg::Fpsr),
            _ => None,
        }
    }

    fn sysreg_info(reg: ArmReg) -> Option<SysRegInfo> {
        match reg {
            ArmReg::Nzcv => Some(SysRegInfo {
                op1: 3,
                crn: 4,
                crm: 2,
                op2: 0,
                mask: NZCV_MASK,
                read_width: OpWidth::W32,
                write_width: OpWidth::W32,
            }),
            ArmReg::Fpcr => Some(SysRegInfo {
                op1: 3,
                crn: 4,
                crm: 4,
                op2: 0,
                mask: 0xffff_ffff,
                read_width: OpWidth::W64,
                write_width: OpWidth::W64,
            }),
            ArmReg::Fpsr => Some(SysRegInfo {
                op1: 3,
                crn: 4,
                crm: 4,
                op2: 1,
                mask: 0xffff_ffff,
                read_width: OpWidth::W64,
                write_width: OpWidth::W64,
            }),
            _ => None,
        }
    }

    fn validate_sysreg_width(op: &str, width: OpWidth) -> Result<(), LowerError> {
        match width {
            OpWidth::W32 | OpWidth::W64 => Ok(()),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native {op} width {other:?}"),
            }),
        }
    }

    fn src_imm_eq(src: &SrcOperand, value: i64) -> bool {
        matches!(src, SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) if *imm == value)
    }

    fn vreg_src(reg: VReg) -> SrcOperand {
        match reg {
            VReg::Imm(value) => SrcOperand::Imm(value),
            other => SrcOperand::Reg(other),
        }
    }

    fn rev16_masks(width: OpWidth) -> Option<(i64, i64)> {
        match width {
            OpWidth::W32 => Some((0x00ff_00ff, 0xff00_ff00)),
            OpWidth::W64 => Some((
                0x00ff_00ff_00ff_00ff_u64 as i64,
                0xff00_ff00_ff00_ff00_u64 as i64,
            )),
            _ => None,
        }
    }

    fn is_nzcv(vreg: VReg) -> bool {
        matches!(vreg, VReg::Arch(ArchReg::Arm(ArmReg::Nzcv)))
    }

    fn op_dst(op: &OpKind) -> Option<VReg> {
        match op {
            OpKind::Shl { dst, .. }
            | OpKind::Shr { dst, .. }
            | OpKind::And { dst, .. }
            | OpKind::AndNot { dst, .. }
            | OpKind::Or { dst, .. }
            | OpKind::Xor { dst, .. }
            | OpKind::Mov { dst, .. } => Some(*dst),
            _ => None,
        }
    }

    fn src_reg_eq(src: &SrcOperand, reg: VReg) -> bool {
        matches!(src, SrcOperand::Reg(src) if *src == reg)
    }

    fn flagm_shl(op: &OpKind, dst: VReg, src: VReg, amount: i64) -> bool {
        matches!(
            op,
            OpKind::Shl {
                dst: op_dst,
                src: op_src,
                amount: op_amount,
                width: OpWidth::W32,
                flags,
            } if *op_dst == dst
                && *op_src == src
                && Self::src_imm_eq(op_amount, amount)
                && !flags.updates_any()
        )
    }

    fn flagm_shr(op: &OpKind, dst: VReg, src: VReg, amount: i64) -> bool {
        matches!(
            op,
            OpKind::Shr {
                dst: op_dst,
                src: op_src,
                amount: op_amount,
                width: OpWidth::W32,
                flags,
            } if *op_dst == dst
                && *op_src == src
                && Self::src_imm_eq(op_amount, amount)
                && !flags.updates_any()
        )
    }

    fn flagm_or_reg(op: &OpKind, dst: VReg, src1: VReg, src2: VReg) -> bool {
        matches!(
            op,
            OpKind::Or {
                dst: op_dst,
                src1: op_src1,
                src2: op_src2,
                width: OpWidth::W32,
                flags,
            } if *op_dst == dst
                && *op_src1 == src1
                && Self::src_reg_eq(op_src2, src2)
                && !flags.updates_any()
        )
    }

    fn flagm_and_imm(op: &OpKind, dst: VReg, src1: VReg, imm: i64) -> bool {
        matches!(
            op,
            OpKind::And {
                dst: op_dst,
                src1: op_src1,
                src2: op_src2,
                width: OpWidth::W32,
                flags,
            } if *op_dst == dst
                && *op_src1 == src1
                && Self::src_imm_eq(op_src2, imm)
                && !flags.updates_any()
        )
    }

    fn flagm_and_reg(op: &OpKind, dst: VReg, src1: VReg, src2: VReg) -> bool {
        matches!(
            op,
            OpKind::And {
                dst: op_dst,
                src1: op_src1,
                src2: op_src2,
                width: OpWidth::W32,
                flags,
            } if *op_dst == dst
                && *op_src1 == src1
                && Self::src_reg_eq(op_src2, src2)
                && !flags.updates_any()
        )
    }

    fn flagm_andnot_reg(op: &OpKind, dst: VReg, src1: VReg, src2: VReg) -> bool {
        matches!(
            op,
            OpKind::AndNot {
                dst: op_dst,
                src1: op_src1,
                src2: op_src2,
                width: OpWidth::W32,
                flags,
            } if *op_dst == dst
                && *op_src1 == src1
                && Self::src_reg_eq(op_src2, src2)
                && !flags.updates_any()
        )
    }

    fn flagm_mov_to_nzcv(op: &OpKind, src: VReg) -> bool {
        matches!(
            op,
            OpKind::Mov {
                dst,
                src: op_src,
                width: OpWidth::W32,
            } if Self::is_nzcv(*dst) && Self::src_reg_eq(op_src, src)
        )
    }

    fn matches_axflag_ops(ops: &[SmirOp]) -> bool {
        if ops.len() < 8 {
            return false;
        }
        let nzcv = VReg::Arch(ArchReg::Arm(ArmReg::Nzcv));
        let Some(v_to_z) = Self::op_dst(&ops[0].kind) else {
            return false;
        };
        let Some(z_or_v) = Self::op_dst(&ops[1].kind) else {
            return false;
        };
        let Some(z_bit) = Self::op_dst(&ops[2].kind) else {
            return false;
        };
        let Some(v_to_c) = Self::op_dst(&ops[3].kind) else {
            return false;
        };
        let Some(c_raw) = Self::op_dst(&ops[4].kind) else {
            return false;
        };
        let Some(c_bit) = Self::op_dst(&ops[5].kind) else {
            return false;
        };
        let Some(result) = Self::op_dst(&ops[6].kind) else {
            return false;
        };

        Self::flagm_shl(&ops[0].kind, v_to_z, nzcv, 2)
            && Self::flagm_or_reg(&ops[1].kind, z_or_v, nzcv, v_to_z)
            && Self::flagm_and_imm(&ops[2].kind, z_bit, z_or_v, NZCV_Z)
            && Self::flagm_shl(&ops[3].kind, v_to_c, nzcv, 1)
            && Self::flagm_and_imm(&ops[4].kind, c_raw, nzcv, NZCV_C)
            && Self::flagm_andnot_reg(&ops[5].kind, c_bit, c_raw, v_to_c)
            && Self::flagm_or_reg(&ops[6].kind, result, z_bit, c_bit)
            && Self::flagm_mov_to_nzcv(&ops[7].kind, result)
    }

    fn matches_xaflag_ops(ops: &[SmirOp]) -> bool {
        if ops.len() < 16 {
            return false;
        }
        let nzcv = VReg::Arch(ArchReg::Arm(ArmReg::Nzcv));
        let Some(shl1) = Self::op_dst(&ops[0].kind) else {
            return false;
        };
        let Some(shl2) = Self::op_dst(&ops[1].kind) else {
            return false;
        };
        let Some(has_c_or_z_as_n) = Self::op_dst(&ops[2].kind) else {
            return false;
        };
        let Some(n_bit) = Self::op_dst(&ops[3].kind) else {
            return false;
        };
        let Some(z_raw) = Self::op_dst(&ops[4].kind) else {
            return false;
        };
        let Some(z_bit) = Self::op_dst(&ops[5].kind) else {
            return false;
        };
        let Some(shr1) = Self::op_dst(&ops[6].kind) else {
            return false;
        };
        let Some(c_or_z) = Self::op_dst(&ops[7].kind) else {
            return false;
        };
        let Some(c_bit) = Self::op_dst(&ops[8].kind) else {
            return false;
        };
        let Some(shr2) = Self::op_dst(&ops[9].kind) else {
            return false;
        };
        let Some(v_unmasked) = Self::op_dst(&ops[10].kind) else {
            return false;
        };
        let Some(v_bit) = Self::op_dst(&ops[11].kind) else {
            return false;
        };
        let Some(nz) = Self::op_dst(&ops[12].kind) else {
            return false;
        };
        let Some(cv) = Self::op_dst(&ops[13].kind) else {
            return false;
        };
        let Some(result) = Self::op_dst(&ops[14].kind) else {
            return false;
        };

        Self::flagm_shl(&ops[0].kind, shl1, nzcv, 1)
            && Self::flagm_shl(&ops[1].kind, shl2, nzcv, 2)
            && Self::flagm_or_reg(&ops[2].kind, has_c_or_z_as_n, shl1, shl2)
            && Self::flagm_andnot_reg(
                &ops[3].kind,
                n_bit,
                VReg::Imm(NZCV_N),
                has_c_or_z_as_n,
            )
            && Self::flagm_and_imm(&ops[4].kind, z_raw, nzcv, NZCV_Z)
            && Self::flagm_and_reg(&ops[5].kind, z_bit, z_raw, shl1)
            && Self::flagm_shr(&ops[6].kind, shr1, nzcv, 1)
            && Self::flagm_or_reg(&ops[7].kind, c_or_z, nzcv, shr1)
            && Self::flagm_and_imm(&ops[8].kind, c_bit, c_or_z, NZCV_C)
            && Self::flagm_shr(&ops[9].kind, shr2, nzcv, 2)
            && Self::flagm_andnot_reg(&ops[10].kind, v_unmasked, shr2, shr1)
            && Self::flagm_and_imm(&ops[11].kind, v_bit, v_unmasked, NZCV_V)
            && Self::flagm_or_reg(&ops[12].kind, nz, n_bit, z_bit)
            && Self::flagm_or_reg(&ops[13].kind, cv, c_bit, v_bit)
            && Self::flagm_or_reg(&ops[14].kind, result, nz, cv)
            && Self::flagm_mov_to_nzcv(&ops[15].kind, result)
    }

    fn lower_shift(
        &mut self,
        dst: VReg,
        src: VReg,
        amount: &SrcOperand,
        shift: ShiftOp,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if set_flags {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native flag-setting {shift:?}"),
            });
        }

        let dst = Self::dst_gpr(dst)?;
        let src = Self::gpr(src)?;
        match amount {
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                self.lower_shift_imm(dst, src, *imm, shift, width)
            }
            SrcOperand::Reg(reg) => self.lower_shift_reg(dst, src, Self::gpr(*reg)?, shift, width),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native shift amount {other:?}"),
            }),
        }
    }

    fn lower_rol(
        &mut self,
        dst: VReg,
        src: VReg,
        amount: &SrcOperand,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if set_flags {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native flag-setting Rol".into(),
            });
        }

        let dst = Self::dst_gpr(dst)?;
        let src = Self::gpr(src)?;
        let bits = width.bits();
        match amount {
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                let amount = (*imm as u64 & u64::from(bits - 1)) as u32;
                let ror = if amount == 0 { 0 } else { bits - amount };
                self.lower_shift_imm(dst, src, i64::from(ror), ShiftOp::Ror, width)
            }
            SrcOperand::Reg(reg) => {
                if dst == src {
                    return Err(LowerError::UnsupportedOp {
                        op: "AArch64 native Rol register amount needs a scratch when dst == src"
                            .into(),
                    });
                }
                let amount = Self::gpr(*reg)?;
                self.emit_addsub_reg(dst, 31, amount, true, false, width)?;
                self.emit_dp2(dst, src, dst, 0b1011, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Rol amount {other:?}"),
            }),
        }
    }

    fn lower_double_shift(
        &mut self,
        dst: VReg,
        src: VReg,
        amount: &SrcOperand,
        left: bool,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if set_flags {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native flag-setting double shift".into(),
            });
        }
        let Some(amount) = Self::src_imm(amount) else {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native register-count double shift".into(),
            });
        };

        let bits = width.bits();
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            let amount = (amount as u64 & 0x1f) as u32;
            let top_bit = bits - 1;
            let dst_reg = Self::dst_gpr(dst)?;
            let rn = Self::gpr(dst)?;
            if amount == 0 {
                return self.emit_bitfield(dst_reg, rn, 0b10, 0, top_bit, OpWidth::W32);
            }
            if amount > bits {
                return Err(LowerError::UnsupportedOp {
                    op: format!(
                        "AArch64 native {width:?} {} count greater than width",
                        if left { "Shld" } else { "Shrd" }
                    ),
                });
            }
            let src = Self::gpr(src)?;
            if amount == bits {
                return self.emit_bitfield(dst_reg, src, 0b10, 0, top_bit, OpWidth::W32);
            }
            if dst_reg == src {
                return Err(LowerError::UnsupportedOp {
                    op: format!(
                        "AArch64 native {width:?} {} needs a scratch when dst == src",
                        if left { "Shld" } else { "Shrd" }
                    ),
                });
            }
            if left {
                self.lower_shift_imm(dst_reg, rn, i64::from(amount), ShiftOp::Lsl, OpWidth::W32)?;
                self.emit_bitfield(dst_reg, src, 0b01, bits - amount, top_bit, OpWidth::W32)?;
            } else {
                self.lower_shift_imm(dst_reg, rn, i64::from(amount), ShiftOp::Lsr, OpWidth::W32)?;
                let lsb = bits - amount;
                let immr = if lsb == 0 { 0 } else { OpWidth::W32.bits() - lsb };
                self.emit_bitfield(dst_reg, src, 0b01, immr, amount - 1, OpWidth::W32)?;
            }
            return self.emit_bitfield(dst_reg, dst_reg, 0b10, 0, top_bit, OpWidth::W32);
        }

        let mask = match width {
            OpWidth::W32 => 0x1f,
            OpWidth::W64 => 0x3f,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native double shift width {other:?}"),
                });
            }
        };
        let amount = (amount as u64 & mask) as u32;
        let dst_reg = Self::dst_gpr(dst)?;
        let rn = Self::gpr(dst)?;
        if amount == 0 {
            return self.emit_mov_reg(dst_reg, rn, width);
        }

        let src = Self::gpr(src)?;
        let (rn, rm, lsb) = if left {
            (rn, src, bits - amount)
        } else {
            (src, rn, amount)
        };
        self.emit_extract(dst_reg, rn, rm, lsb, width)
    }

    fn lower_test_condition(&mut self, dst: VReg, cond: Condition) -> Result<(), LowerError> {
        if cond == Condition::Always {
            return self.emit_mov_imm(Self::dst_gpr(dst)?, 1, OpWidth::W64);
        }
        self.emit_cond_select(
            Self::dst_gpr(dst)?,
            31,
            31,
            Self::inverted_arm_cond_code(cond)?,
            0,
            1,
            OpWidth::W64,
        )
    }

    fn lower_setcc(
        &mut self,
        dst: VReg,
        cond: Condition,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match width {
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64 => {
                self.lower_test_condition(dst, cond)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native SetCC width {other:?}"),
            }),
        }
    }

    fn lower_cmove(
        &mut self,
        dst: VReg,
        src: VReg,
        cond: Condition,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if !matches!(
            width,
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
        ) {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native CMove width {width:?}"),
            });
        }

        if let VReg::Imm(value) = src {
            return self.lower_cmove_imm(dst, value, cond, width);
        }

        let dst = Self::dst_gpr(dst)?;
        let src = Self::gpr(src)?;
        if matches!(width, OpWidth::W8 | OpWidth::W16) {
            self.emit_cond_select(
                dst,
                src,
                dst,
                Self::arm_cond_code(cond)?,
                0,
                0,
                OpWidth::W32,
            )?;
            let imms = if width == OpWidth::W8 { 7 } else { 15 };
            return self.emit_bitfield(dst, dst, 0b10, 0, imms, OpWidth::W32);
        }
        self.emit_cond_select(
            dst,
            src,
            dst,
            Self::arm_cond_code(cond)?,
            0,
            0,
            width,
        )
    }

    fn lower_cmove_imm(
        &mut self,
        dst: VReg,
        value: i64,
        cond: Condition,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let dst = Self::dst_gpr(dst)?;
        if cond == Condition::Always {
            let mov_width = if width == OpWidth::W64 {
                OpWidth::W64
            } else {
                OpWidth::W32
            };
            self.emit_mov_imm(dst, value, mov_width)?;
            return self.finish_cmove_width(dst, width);
        }

        let skip_mov = self.code.position();
        let inverted = Self::inverted_arm_cond_code(cond)?;
        self.emit(0x5400_0000 | inverted);

        let mov_width = if width == OpWidth::W64 {
            OpWidth::W64
        } else {
            OpWidth::W32
        };
        self.emit_mov_imm(dst, value, mov_width)?;
        self.patch_cond_branch_to_current(skip_mov, inverted)?;
        self.finish_cmove_width(dst, width)
    }

    fn finish_cmove_width(&mut self, dst: u8, width: OpWidth) -> Result<(), LowerError> {
        match width {
            OpWidth::W8 | OpWidth::W16 => {
                let imms = if width == OpWidth::W8 { 7 } else { 15 };
                self.emit_bitfield(dst, dst, 0b10, 0, imms, OpWidth::W32)
            }
            OpWidth::W32 => self.emit_mov_reg(dst, dst, OpWidth::W32),
            OpWidth::W64 => Ok(()),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native CMove width {other:?}"),
            }),
        }
    }

    fn lower_select(
        &mut self,
        dst: VReg,
        cond: VReg,
        src_true: VReg,
        src_false: VReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match cond {
            VReg::Imm(value) => {
                let src = match if value != 0 { src_true } else { src_false } {
                    VReg::Imm(value) => SrcOperand::Imm(value),
                    reg => SrcOperand::Reg(reg),
                };
                self.lower_select_mov(dst, &src, width)
            }
            other => {
                let cond = Self::gpr(other)?;
                let true_src = Self::vreg_src(src_true);
                let false_src = Self::vreg_src(src_false);

                let false_branch = self.code.position();
                self.emit(0xb400_0000 | (cond as u32));
                self.lower_select_mov(dst, &true_src, width)?;

                let end_branch = self.code.position();
                self.emit(0x1400_0000);
                self.patch_compare_branch_to_current(false_branch, cond, false)?;

                self.lower_select_mov(dst, &false_src, width)?;
                self.patch_branch_to_current(end_branch)
            }
        }
    }

    fn lower_select_mov(
        &mut self,
        dst: VReg,
        src: &SrcOperand,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let mov_width = match width {
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 => OpWidth::W32,
            OpWidth::W64 => OpWidth::W64,
            other => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("AArch64 native Select width {other:?}"),
                });
            }
        };
        self.lower_mov(dst, src, mov_width)?;
        self.finish_select_width(dst, width)
    }

    fn finish_select_width(&mut self, dst: VReg, width: OpWidth) -> Result<(), LowerError> {
        match width {
            OpWidth::W8 | OpWidth::W16 => {
                let imms = if width == OpWidth::W8 { 7 } else { 15 };
                let dst = Self::dst_gpr(dst)?;
                self.emit_bitfield(dst, dst, 0b10, 0, imms, OpWidth::W32)
            }
            OpWidth::W32 | OpWidth::W64 => Ok(()),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Select width {other:?}"),
            }),
        }
    }

    fn lower_fused_select(
        &mut self,
        dst: VReg,
        cond: Condition,
        src_true: VReg,
        src_false_base: VReg,
        false_op: CondSelectFalseOp,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let (op, op2) = match false_op {
            CondSelectFalseOp::Identity => (0, 0),
            CondSelectFalseOp::Increment => (0, 1),
            CondSelectFalseOp::Invert => (1, 0),
            CondSelectFalseOp::Negate => (1, 1),
        };
        self.emit_cond_select(
            Self::dst_gpr(dst)?,
            Self::gpr(src_true)?,
            Self::gpr(src_false_base)?,
            Self::arm_cond_code(cond)?,
            op,
            op2,
            width,
        )
    }

    fn try_lower_fused_flagm(&mut self, ops: &[SmirOp]) -> Result<Option<usize>, LowerError> {
        if let Some(SmirOp {
            kind:
                OpKind::Xor {
                    dst,
                    src1,
                    src2,
                    width: OpWidth::W32,
                    flags,
                },
            ..
        }) = ops.first()
        {
            if Self::is_nzcv(*dst)
                && Self::is_nzcv(*src1)
                && Self::src_imm_eq(src2, NZCV_C)
                && !flags.updates_any()
            {
                self.emit_flagm(0b000);
                return Ok(Some(1));
            }
        }

        if Self::matches_axflag_ops(ops) {
            self.emit_flagm(0b010);
            return Ok(Some(8));
        }

        if Self::matches_xaflag_ops(ops) {
            self.emit_flagm(0b001);
            return Ok(Some(16));
        }

        Ok(None)
    }

    fn try_lower_fused_cls(&mut self, ops: &[SmirOp]) -> Result<Option<usize>, LowerError> {
        let [
            SmirOp {
                kind:
                    OpKind::Sar {
                        dst: sign_mask,
                        src,
                        amount,
                        width,
                        flags,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Xor {
                        dst: normalized,
                        src1: xor_src,
                        src2,
                        width: xor_width,
                        flags: xor_flags,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Clz {
                        dst: leading,
                        src: clz_src,
                        width: clz_width,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Sub {
                        dst,
                        src1: sub_src,
                        src2: sub_amount,
                        width: sub_width,
                        flags: sub_flags,
                    },
                ..
            },
            ..
        ] = ops
        else {
            return Ok(None);
        };

        if flags.updates_any()
            || xor_flags.updates_any()
            || sub_flags.updates_any()
            || xor_width != width
            || clz_width != width
            || sub_width != width
            || !Self::src_imm_eq(amount, i64::from(width.bits() - 1))
            || xor_src != src
            || !Self::src_reg_eq(src2, *sign_mask)
            || clz_src != normalized
            || sub_src != leading
            || !Self::src_imm_eq(sub_amount, 1)
        {
            return Ok(None);
        }

        self.lower_cls(*dst, *src, *width)?;
        Ok(Some(4))
    }

    fn try_lower_fused_signed_load_w(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        if let [writeback, load, extend, ..] = ops {
            if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                if let Some((rt, addr, size, opc)) =
                    Self::signed_load_w_parts(&load.kind, &extend.kind)?
                {
                    if Self::direct_addr_reg(addr) == Some(base)
                        && !Self::transfer_reg_aliases_base(rt, base)
                        && (-256..=255).contains(&offset)
                    {
                        self.lower_mem_indexed_access(rt, base, size, opc, offset, 0b11)?;
                        return Ok(Some(3));
                    }
                }
            }
        }

        if let [load, extend, writeback, ..] = ops {
            if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                if let Some((rt, addr, size, opc)) =
                    Self::signed_load_w_parts(&load.kind, &extend.kind)?
                {
                    if Self::direct_addr_reg(addr) == Some(base)
                        && !Self::transfer_reg_aliases_base(rt, base)
                        && (-256..=255).contains(&offset)
                    {
                        self.lower_mem_indexed_access(rt, base, size, opc, offset, 0b01)?;
                        return Ok(Some(3));
                    }
                }
            }
        }

        if let [load, extend, ..] = ops {
            if let Some((rt, addr, size, opc)) =
                Self::signed_load_w_parts(&load.kind, &extend.kind)?
            {
                self.lower_mem_access(rt, addr, size, opc)?;
                return Ok(Some(2));
            }
        }

        Ok(None)
    }

    fn try_lower_fused_mem_indexed(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        if let [writeback, access, ..] = ops {
            if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                if let Some((rt, addr, size, opc)) = Self::mem_access_parts(&access.kind)? {
                    if Self::direct_addr_reg(addr) == Some(base)
                        && !Self::transfer_reg_aliases_base(rt, base)
                        && (-256..=255).contains(&offset)
                    {
                        self.lower_mem_indexed_access(rt, base, size, opc, offset, 0b11)?;
                        return Ok(Some(2));
                    }
                }
            }
        }

        if let [access, writeback, ..] = ops {
            if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                if let Some((rt, addr, size, opc)) = Self::mem_access_parts(&access.kind)? {
                    if Self::direct_addr_reg(addr) == Some(base)
                        && !Self::transfer_reg_aliases_base(rt, base)
                        && (-256..=255).contains(&offset)
                    {
                        self.lower_mem_indexed_access(rt, base, size, opc, offset, 0b01)?;
                        return Ok(Some(2));
                    }
                }
            }
        }

        Ok(None)
    }

    fn try_lower_fused_pair_indexed(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        if let [writeback, access, ..] = ops {
            if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                if let Some((rt, rt2, addr, width, load)) =
                    Self::pair_access_parts(&access.kind)?
                {
                    if Self::direct_addr_reg(addr) == Some(base)
                        && !Self::transfer_reg_aliases_base(rt, base)
                        && !Self::transfer_reg_aliases_base(rt2, base)
                        && Self::pair_scaled_imm(width, offset)?.is_some()
                    {
                        self.lower_pair_indexed_access(
                            rt, rt2, base, width, load, offset, 0b11,
                        )?;
                        return Ok(Some(2));
                    }
                }
            }
        }

        if let [access, writeback, ..] = ops {
            if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                if let Some((rt, rt2, addr, width, load)) =
                    Self::pair_access_parts(&access.kind)?
                {
                    if Self::direct_addr_reg(addr) == Some(base)
                        && !Self::transfer_reg_aliases_base(rt, base)
                        && !Self::transfer_reg_aliases_base(rt2, base)
                        && Self::pair_scaled_imm(width, offset)?.is_some()
                    {
                        self.lower_pair_indexed_access(
                            rt, rt2, base, width, load, offset, 0b01,
                        )?;
                        return Ok(Some(2));
                    }
                }
            }
        }

        Ok(None)
    }

    fn try_lower_fused_ldpsw_pair(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        if let [writeback, first, second, ..] = ops {
            if writeback.guest_pc == first.guest_pc {
                if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                    if let Some((rt, rt2, addr)) =
                        Self::lifted_ldpsw_pair_parts(first, second)?
                    {
                        if Self::direct_addr_reg(addr) == Some(base)
                            && !Self::transfer_reg_aliases_base(rt, base)
                            && !Self::transfer_reg_aliases_base(rt2, base)
                            && Self::ldpsw_scaled_imm(offset).is_some()
                        {
                            self.lower_ldpsw_pair_access(rt, rt2, base, offset, 0b11)?;
                            return Ok(Some(3));
                        }
                    }
                }
            }
        }

        if let [first, second, writeback, ..] = ops {
            if writeback.guest_pc == first.guest_pc {
                if let Some((base, offset)) = Self::writeback_add_parts(&writeback.kind) {
                    if let Some((rt, rt2, addr)) =
                        Self::lifted_ldpsw_pair_parts(first, second)?
                    {
                        if Self::direct_addr_reg(addr) == Some(base)
                            && !Self::transfer_reg_aliases_base(rt, base)
                            && !Self::transfer_reg_aliases_base(rt2, base)
                            && Self::ldpsw_scaled_imm(offset).is_some()
                        {
                            self.lower_ldpsw_pair_access(rt, rt2, base, offset, 0b01)?;
                            return Ok(Some(3));
                        }
                    }
                }
            }
        }

        if let [first, second, ..] = ops {
            if let Some((rt, rt2, addr)) = Self::lifted_ldpsw_pair_parts(first, second)? {
                if let Some((base, offset)) = Self::addr_base_offset(addr) {
                    self.lower_ldpsw_pair_access(rt, rt2, base, offset, 0b10)?;
                    return Ok(Some(2));
                }
            }
        }

        Ok(None)
    }

    fn try_lower_fused_extract(&mut self, ops: &[SmirOp]) -> Result<Option<usize>, LowerError> {
        let [lo_op, hi_op, or_op, ..] = ops else {
            return Ok(None);
        };
        if lo_op.guest_pc != hi_op.guest_pc || lo_op.guest_pc != or_op.guest_pc {
            return Ok(None);
        }

        let (
            OpKind::Shr {
                dst: lo,
                src: rm,
                amount: lo_amount,
                width,
                flags: lo_flags,
            },
            OpKind::Shl {
                dst: hi,
                src: rn,
                amount: hi_amount,
                width: hi_width,
                flags: hi_flags,
            },
            OpKind::Or {
                dst,
                src1,
                src2: SrcOperand::Reg(src2),
                width: or_width,
                flags: or_flags,
            },
        ) = (&lo_op.kind, &hi_op.kind, &or_op.kind)
        else {
            return Ok(None);
        };

        if width != hi_width
            || width != or_width
            || lo_flags.updates_any()
            || hi_flags.updates_any()
            || or_flags.updates_any()
            || *src1 != *lo
            || *src2 != *hi
        {
            return Ok(None);
        }

        let bits = i64::from(width.bits());
        let (Some(lo_amount), Some(hi_amount)) =
            (Self::src_imm(lo_amount), Self::src_imm(hi_amount))
        else {
            return Ok(None);
        };
        if !(1..bits).contains(&lo_amount) || hi_amount != bits - lo_amount {
            return Ok(None);
        }

        self.emit_extract(
            Self::dst_gpr(*dst)?,
            Self::gpr(*rn)?,
            Self::gpr(*rm)?,
            lo_amount as u32,
            *width,
        )?;
        Ok(Some(3))
    }

    fn try_lower_fused_rev16(&mut self, ops: &[SmirOp]) -> Result<Option<usize>, LowerError> {
        let [lo_op, hi_op, lo_shift_op, hi_shift_op, or_op, ..] = ops else {
            return Ok(None);
        };
        if lo_op.guest_pc != hi_op.guest_pc
            || lo_op.guest_pc != lo_shift_op.guest_pc
            || lo_op.guest_pc != hi_shift_op.guest_pc
            || lo_op.guest_pc != or_op.guest_pc
        {
            return Ok(None);
        }

        let (
            OpKind::And {
                dst: lo,
                src1,
                src2: lo_mask,
                width,
                flags: lo_flags,
            },
            OpKind::And {
                dst: hi,
                src1: hi_src,
                src2: hi_mask,
                width: hi_width,
                flags: hi_flags,
            },
            OpKind::Shl {
                dst: lo_shifted,
                src: lo_shift_src,
                amount: lo_amount,
                width: lo_shift_width,
                flags: lo_shift_flags,
            },
            OpKind::Shr {
                dst: hi_shifted,
                src: hi_shift_src,
                amount: hi_amount,
                width: hi_shift_width,
                flags: hi_shift_flags,
            },
            OpKind::Or {
                dst,
                src1: or_src1,
                src2: SrcOperand::Reg(or_src2),
                width: or_width,
                flags: or_flags,
            },
        ) = (
            &lo_op.kind,
            &hi_op.kind,
            &lo_shift_op.kind,
            &hi_shift_op.kind,
            &or_op.kind,
        )
        else {
            return Ok(None);
        };

        let Some((expected_lo_mask, expected_hi_mask)) = Self::rev16_masks(*width) else {
            return Ok(None);
        };
        if width != hi_width
            || width != lo_shift_width
            || width != hi_shift_width
            || width != or_width
            || lo_flags.updates_any()
            || hi_flags.updates_any()
            || lo_shift_flags.updates_any()
            || hi_shift_flags.updates_any()
            || or_flags.updates_any()
            || hi_src != src1
            || !Self::src_imm_eq(lo_mask, expected_lo_mask)
            || !Self::src_imm_eq(hi_mask, expected_hi_mask)
            || lo_shift_src != lo
            || hi_shift_src != hi
            || !Self::src_imm_eq(lo_amount, 8)
            || !Self::src_imm_eq(hi_amount, 8)
            || or_src1 != lo_shifted
            || or_src2 != hi_shifted
        {
            return Ok(None);
        }

        self.lower_rev16(*dst, *src1, *width)?;
        Ok(Some(5))
    }

    fn try_lower_fused_rev32(&mut self, ops: &[SmirOp]) -> Result<Option<usize>, LowerError> {
        let [lo_rev_op, hi_op, hi_rev_op, hi_shift_op, or_op, ..] = ops else {
            return Ok(None);
        };
        if lo_rev_op.guest_pc != hi_op.guest_pc
            || lo_rev_op.guest_pc != hi_rev_op.guest_pc
            || lo_rev_op.guest_pc != hi_shift_op.guest_pc
            || lo_rev_op.guest_pc != or_op.guest_pc
        {
            return Ok(None);
        }

        let (
            OpKind::Bswap {
                dst: lo_rev,
                src,
                width: OpWidth::W32,
            },
            OpKind::Shr {
                dst: hi,
                src: hi_src,
                amount,
                width: OpWidth::W64,
                flags: hi_flags,
            },
            OpKind::Bswap {
                dst: hi_rev,
                src: hi_rev_src,
                width: OpWidth::W32,
            },
            OpKind::Shl {
                dst: hi_shifted,
                src: hi_shift_src,
                amount: hi_shift_amount,
                width: OpWidth::W64,
                flags: hi_shift_flags,
            },
            OpKind::Or {
                dst,
                src1,
                src2: SrcOperand::Reg(src2),
                width: OpWidth::W64,
                flags: or_flags,
            },
        ) = (
            &lo_rev_op.kind,
            &hi_op.kind,
            &hi_rev_op.kind,
            &hi_shift_op.kind,
            &or_op.kind,
        )
        else {
            return Ok(None);
        };

        if hi_flags.updates_any()
            || hi_shift_flags.updates_any()
            || or_flags.updates_any()
            || hi_src != src
            || !Self::src_imm_eq(amount, 32)
            || hi_rev_src != hi
            || hi_shift_src != hi_rev
            || !Self::src_imm_eq(hi_shift_amount, 32)
            || src1 != hi_shifted
            || src2 != lo_rev
        {
            return Ok(None);
        }

        self.lower_rev32(*dst, *src, OpWidth::W64)?;
        Ok(Some(5))
    }

    fn try_lower_fused_bitfield_insert_zero(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        let [bfx_op, shl_op, ..] = ops else {
            return Ok(None);
        };
        if bfx_op.guest_pc != shl_op.guest_pc {
            return Ok(None);
        }

        let (
            OpKind::Bfx {
                dst: extracted,
                src,
                lsb: 0,
                width_bits,
                sign_extend,
                op_width,
            },
            OpKind::Shl {
                dst,
                src: shl_src,
                amount,
                width,
                flags,
            },
        ) = (&bfx_op.kind, &shl_op.kind)
        else {
            return Ok(None);
        };

        let Some(amount) = Self::src_imm(amount) else {
            return Ok(None);
        };
        let bits = i64::from(op_width.bits());
        if flags.updates_any()
            || shl_src != extracted
            || width != op_width
            || !(1..bits).contains(&amount)
            || i64::from(*width_bits) + amount > bits
        {
            return Ok(None);
        }

        self.lower_bitfield_insert_zero(
            *dst,
            *src,
            amount as u8,
            *width_bits,
            *sign_extend,
            *op_width,
        )?;
        Ok(Some(2))
    }

    fn try_lower_fused_bitfield_insert_low(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        let [bfx_op, bfi_op, ..] = ops else {
            return Ok(None);
        };
        if bfx_op.guest_pc != bfi_op.guest_pc {
            return Ok(None);
        }

        let (
            OpKind::Bfx {
                dst: extracted,
                src,
                lsb,
                width_bits,
                sign_extend: false,
                op_width,
            },
            OpKind::Bfi {
                dst,
                dst_in,
                src: bfi_src,
                lsb: 0,
                width_bits: bfi_width_bits,
                op_width: bfi_width,
            },
        ) = (&bfx_op.kind, &bfi_op.kind)
        else {
            return Ok(None);
        };

        if bfi_src != extracted || width_bits != bfi_width_bits || op_width != bfi_width {
            return Ok(None);
        }

        self.lower_bitfield_insert_low(*dst, *dst_in, *src, *lsb, *width_bits, *op_width)?;
        Ok(Some(2))
    }

    fn try_lower_fused_mem_reg_offset(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        if let [
            extend,
            SmirOp {
                kind:
                    OpKind::Shl {
                        dst: shifted,
                        src: shift_src,
                        amount,
                        width: OpWidth::W64,
                        flags: shift_flags,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Add {
                        dst: addr_tmp,
                        src1: base,
                        src2,
                        width: OpWidth::W64,
                        flags: add_flags,
                    },
                ..
            },
            ..
        ] = ops
        {
            if !shift_flags.updates_any()
                && !add_flags.updates_any()
                && Self::src_reg_eq(src2, *shifted)
            {
                if let Some((extended, index, option)) = Self::mem_extend_parts(&extend.kind) {
                    if shift_src == &extended {
                        if let Some((rt, addr, size, opc, access_consumed)) =
                            Self::mem_access_sequence_parts(&ops[3..])?
                        {
                            if Self::direct_addr_reg(addr) == Some(*addr_tmp) {
                                if let Some(s) = Self::mem_shift_bit(amount, size) {
                                    self.lower_mem_reg_offset_access(
                                        rt, *base, index, size, opc, option, s,
                                    )?;
                                    return Ok(Some(3 + access_consumed));
                                }
                            }
                        }
                    }
                }
            }
        }

        if let [
            SmirOp {
                kind:
                    OpKind::Shl {
                        dst: shifted,
                        src: index,
                        amount,
                        width: OpWidth::W64,
                        flags: shift_flags,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Add {
                        dst: addr_tmp,
                        src1: base,
                        src2,
                        width: OpWidth::W64,
                        flags: add_flags,
                    },
                ..
            },
            ..
        ] = ops
        {
            if !shift_flags.updates_any()
                && !add_flags.updates_any()
                && Self::src_reg_eq(src2, *shifted)
            {
                if let Some((rt, addr, size, opc, access_consumed)) =
                    Self::mem_access_sequence_parts(&ops[2..])?
                {
                    if Self::direct_addr_reg(addr) == Some(*addr_tmp) {
                        if let Some(s) = Self::mem_shift_bit(amount, size) {
                            self.lower_mem_reg_offset_access(
                                rt, *base, *index, size, opc, 0b011, s,
                            )?;
                            return Ok(Some(2 + access_consumed));
                        }
                    }
                }
            }
        }

        if let [
            extend,
            SmirOp {
                kind:
                    OpKind::Add {
                        dst: addr_tmp,
                        src1: base,
                        src2,
                        width: OpWidth::W64,
                        flags,
                    },
                ..
            },
            ..
        ] = ops
        {
            if !flags.updates_any() {
                if let Some((extended, index, option)) = Self::mem_extend_parts(&extend.kind) {
                    if Self::src_reg_eq(src2, extended) {
                        if let Some((rt, addr, size, opc, access_consumed)) =
                            Self::mem_access_sequence_parts(&ops[2..])?
                        {
                            if Self::direct_addr_reg(addr) == Some(*addr_tmp) {
                                self.lower_mem_reg_offset_access(
                                    rt, *base, index, size, opc, option, 0,
                                )?;
                                return Ok(Some(2 + access_consumed));
                            }
                        }
                    }
                }
            }
        }

        if let [
            SmirOp {
                kind:
                    OpKind::Add {
                        dst: addr_tmp,
                        src1: base,
                        src2,
                        width: OpWidth::W64,
                        flags,
                    },
                ..
            },
            ..
        ] = ops
        {
            if !flags.updates_any() {
                if let SrcOperand::Reg(index) = src2 {
                    if let Some((rt, addr, size, opc, access_consumed)) =
                        Self::mem_access_sequence_parts(&ops[1..])?
                    {
                        if Self::direct_addr_reg(addr) == Some(*addr_tmp) {
                            self.lower_mem_reg_offset_access(
                                rt, *base, *index, size, opc, 0b011, 0,
                            )?;
                            return Ok(Some(1 + access_consumed));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn try_lower_fused_ldclr(&mut self, ops: &[SmirOp]) -> Result<Option<usize>, LowerError> {
        let [
            SmirOp {
                guest_pc,
                kind:
                    OpKind::Not {
                        dst: inverted,
                        src,
                        width: not_width,
                    },
                ..
            },
            SmirOp {
                guest_pc: atomic_pc,
                kind:
                    OpKind::AtomicRmw {
                        dst,
                        addr,
                        src: atomic_src,
                        op: AtomicOp::And,
                        width,
                        order,
                    },
                ..
            },
            ..
        ] = ops
        else {
            return Ok(None);
        };

        if guest_pc != atomic_pc
            || atomic_src != inverted
            || !matches!(inverted, VReg::Virtual(_))
            || *not_width != OpWidth::W64
        {
            return Ok(None);
        }

        self.lower_ldclr(*dst, addr, *src, *width, *order)?;
        Ok(Some(2))
    }

    fn try_lower_fused_sysreg_access(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        let [
            SmirOp {
                kind:
                    OpKind::And {
                        dst: masked,
                        src1,
                        src2,
                        width,
                        flags,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Mov {
                        dst,
                        src: SrcOperand::Reg(mov_src),
                        width: mov_width,
                    },
                ..
            },
            ..
        ] = ops
        else {
            return Ok(None);
        };

        if flags.updates_any() || mov_src != masked {
            return Ok(None);
        }

        if let Some(reg) = Self::sysreg_vreg(*src1) {
            let Some(info) = Self::sysreg_info(reg) else {
                return Ok(None);
            };
            if *width != info.read_width
                || *mov_width != OpWidth::W64
                || !Self::src_imm_eq(src2, info.mask)
            {
                return Ok(None);
            }
            self.emit_sysreg(Self::dst_gpr(*dst)?, reg, true)?;
            return Ok(Some(2));
        }

        let Some(reg) = Self::sysreg_vreg(*dst) else {
            return Ok(None);
        };
        let Some(info) = Self::sysreg_info(reg) else {
            return Ok(None);
        };
        if *width != OpWidth::W64
            || *mov_width != info.write_width
            || !Self::src_imm_eq(src2, info.mask)
        {
            return Ok(None);
        }
        self.emit_sysreg(Self::gpr(*src1)?, reg, false)?;
        Ok(Some(2))
    }

    fn try_lower_fused_select(&mut self, ops: &[SmirOp]) -> Result<Option<usize>, LowerError> {
        let Some(SmirOp {
            kind: OpKind::TestCondition { dst: cond_vreg, cond },
            ..
        }) = ops.first()
        else {
            return Ok(None);
        };
        let Some(next) = ops.get(1) else {
            return Ok(None);
        };

        if let OpKind::Select {
            dst,
            cond: select_cond,
            src_true,
            src_false,
            width,
        } = &next.kind
        {
            if select_cond == cond_vreg {
                self.lower_fused_select(
                    *dst,
                    *cond,
                    *src_true,
                    *src_false,
                    CondSelectFalseOp::Identity,
                    *width,
                )?;
                return Ok(Some(2));
            }
        }

        let Some(select) = ops.get(2) else {
            return Ok(None);
        };
        let OpKind::Select {
            dst,
            cond: select_cond,
            src_true,
            src_false,
            width,
        } = &select.kind
        else {
            return Ok(None);
        };
        if select_cond != cond_vreg {
            return Ok(None);
        }

        let Some((false_tmp, false_base, false_op, op_width)) =
            Self::cond_select_false_transform(&next.kind)
        else {
            return Ok(None);
        };
        if src_false != &false_tmp || width != &op_width {
            return Ok(None);
        }

        self.lower_fused_select(*dst, *cond, *src_true, false_base, false_op, *width)?;
        Ok(Some(3))
    }

    fn cond_select_false_transform(
        op: &OpKind,
    ) -> Option<(VReg, VReg, CondSelectFalseOp, OpWidth)> {
        match op {
            OpKind::Add {
                dst,
                src1,
                src2: SrcOperand::Imm(1) | SrcOperand::Imm64(1),
                width,
                flags,
            } if !flags.updates_any() => Some((
                *dst,
                *src1,
                CondSelectFalseOp::Increment,
                *width,
            )),
            OpKind::Not { dst, src, width } => {
                Some((*dst, *src, CondSelectFalseOp::Invert, *width))
            }
            OpKind::Neg {
                dst,
                src,
                width,
                flags,
            } if !flags.updates_any() => Some((
                *dst,
                *src,
                CondSelectFalseOp::Negate,
                *width,
            )),
            _ => None,
        }
    }

    fn try_lower_fused_cond_compare(
        &mut self,
        ops: &[SmirOp],
    ) -> Result<Option<usize>, LowerError> {
        let [
            SmirOp {
                kind: OpKind::TestCondition { dst: cond_vreg, cond },
                ..
            },
            cmp_op,
            SmirOp {
                kind:
                    OpKind::Mov {
                        dst: cmp_nzcv,
                        src:
                            SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::Nzcv))),
                        width: OpWidth::W32,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Select {
                        dst: final_nzcv,
                        cond: select_cond,
                        src_true,
                        src_false: VReg::Imm(fallback_nzcv),
                        width: OpWidth::W32,
                    },
                ..
            },
            SmirOp {
                kind:
                    OpKind::Mov {
                        dst: VReg::Arch(ArchReg::Arm(ArmReg::Nzcv)),
                        src: SrcOperand::Reg(writeback_nzcv),
                        width: OpWidth::W32,
                    },
                ..
            },
            ..
        ] = ops
        else {
            return Ok(None);
        };

        if select_cond != cond_vreg || src_true != cmp_nzcv || writeback_nzcv != final_nzcv {
            return Ok(None);
        }

        let Some((discarded_dst, rn, src2, subtract, width)) =
            Self::cond_compare_op_args(&cmp_op.kind)
        else {
            return Ok(None);
        };
        if !matches!(discarded_dst, VReg::Virtual(_)) {
            return Ok(None);
        }

        let (rm_imm5, immediate) = Self::cond_compare_src2(src2)?;
        let nzcv = Self::cond_compare_nzcv(*fallback_nzcv)?;
        self.emit_cond_compare(
            Self::gpr(rn)?,
            rm_imm5,
            Self::arm_cond_code(*cond)?,
            nzcv,
            subtract,
            immediate,
            width,
        )?;
        Ok(Some(5))
    }

    fn cond_compare_op_args(
        op: &OpKind,
    ) -> Option<(VReg, VReg, &SrcOperand, bool, OpWidth)> {
        match op {
            OpKind::Add {
                dst,
                src1,
                src2,
                width,
                flags,
            } if flags.updates_any() => Some((*dst, *src1, src2, false, *width)),
            OpKind::Sub {
                dst,
                src1,
                src2,
                width,
                flags,
            } if flags.updates_any() => Some((*dst, *src1, src2, true, *width)),
            _ => None,
        }
    }

    fn cond_compare_src2(src2: &SrcOperand) -> Result<(u8, bool), LowerError> {
        match src2 {
            SrcOperand::Reg(reg) => Ok((Self::gpr(*reg)?, false)),
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) if (0..=31).contains(imm) => {
                Ok((*imm as u8, true))
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native conditional compare source {other:?}"),
            }),
        }
    }

    fn cond_compare_nzcv(nzcv: i64) -> Result<u32, LowerError> {
        if nzcv >= 0 && (nzcv & !0xf000_0000) == 0 {
            Ok(((nzcv as u32) >> 28) & 0xf)
        } else {
            Err(LowerError::InvalidOperand {
                op: "AArch64 conditional compare fallback NZCV".into(),
                operand: format!("{nzcv:#x}"),
            })
        }
    }

    fn lower_op(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        match &op.kind {
            OpKind::Nop => {
                self.emit(0xd503_201f);
                Ok(())
            }
            OpKind::Breakpoint => {
                self.emit_brk(0);
                Ok(())
            }
            OpKind::Undefined { .. } => {
                self.emit_udf(0);
                Ok(())
            }
            OpKind::Swi { imm } => {
                let imm = Self::exception_imm16("SVC", *imm)?;
                self.emit_svc(imm);
                Ok(())
            }
            OpKind::MaterializeFlags => Ok(()),
            OpKind::ClearExclusive => {
                self.emit(0xd503_3f5f);
                Ok(())
            }
            OpKind::Prefetch { .. } => Ok(()),
            OpKind::Fence { kind } => {
                let insn = match kind {
                    FenceKind::ISync => 0xd503_3fdf,
                    FenceKind::DSync | FenceKind::Full => 0xd503_3f9f,
                    FenceKind::LoadLoad
                    | FenceKind::LoadStore
                    | FenceKind::StoreLoad
                    | FenceKind::StoreStore => 0xd503_3fbf,
                };
                self.emit(insn);
                Ok(())
            }
            OpKind::Mov { dst, src, width } => self.lower_mov(*dst, src, *width),
            OpKind::ReadSysReg { dst, reg } => self.lower_raw_sysreg_read(*dst, *reg),
            OpKind::WriteSysReg { reg, src } => self.lower_raw_sysreg_write(*reg, *src),
            OpKind::Add {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_addsub(*dst, *src1, src2, false, flags.updates_any(), *width),
            OpKind::Sub {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_addsub(*dst, *src1, src2, true, flags.updates_any(), *width),
            OpKind::Adc {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_addsub_carry(*dst, *src1, src2, false, flags.updates_any(), *width),
            OpKind::Sbb {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_addsub_carry(*dst, *src1, src2, true, flags.updates_any(), *width),
            OpKind::And {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let opc = if flags.updates_any() { 0b11 } else { 0b00 };
                self.lower_logic(*dst, *src1, src2, opc, false, flags.updates_any(), *width)
            }
            OpKind::AndNot {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let opc = if flags.updates_any() { 0b11 } else { 0b00 };
                self.lower_logic(*dst, *src1, src2, opc, true, flags.updates_any(), *width)
            }
            OpKind::Or {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic(*dst, *src1, src2, 0b01, false, flags.updates_any(), *width),
            OpKind::Xor {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic(*dst, *src1, src2, 0b10, false, flags.updates_any(), *width),
            OpKind::Neg {
                dst,
                src,
                width,
                flags,
            } => self.lower_neg(*dst, *src, flags.updates_any(), *width),
            OpKind::Inc {
                dst,
                src,
                width,
                flags,
            } => self.lower_inc_dec(*dst, *src, false, flags.updates_any(), *width),
            OpKind::Dec {
                dst,
                src,
                width,
                flags,
            } => self.lower_inc_dec(*dst, *src, true, flags.updates_any(), *width),
            OpKind::MulU {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                flags,
            } => self.lower_mul(
                *dst_lo,
                *dst_hi,
                *src1,
                src2,
                *width,
                flags.updates_any(),
                false,
            ),
            OpKind::MulS {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                flags,
            } => self.lower_mul(
                *dst_lo,
                *dst_hi,
                *src1,
                src2,
                *width,
                flags.updates_any(),
                true,
            ),
            OpKind::MulAdd {
                dst,
                acc,
                src1,
                src2,
                width,
            } => self.lower_mul_acc(*dst, *acc, *src1, *src2, *width, false),
            OpKind::MulSub {
                dst,
                acc,
                src1,
                src2,
                width,
            } => self.lower_mul_acc(*dst, *acc, *src1, *src2, *width, true),
            OpKind::DivU {
                quot,
                rem,
                src1,
                src2,
                width,
                flags,
            } => self.lower_div(*quot, *rem, *src1, src2, *width, flags.updates_any(), false),
            OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
                flags,
            } => self.lower_div(*quot, *rem, *src1, src2, *width, flags.updates_any(), true),
            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => self.lower_load(*dst, addr, *width, *sign),
            OpKind::Store { src, addr, width } => self.lower_store(*src, addr, *width),
            OpKind::PredLoad {
                dst,
                cond,
                addr,
                width,
                signed,
            } => self.lower_pred_load(*dst, *cond, addr, *width, *signed),
            OpKind::PredStore {
                src,
                cond,
                addr,
                width,
            } => self.lower_pred_store(src, *cond, addr, *width),
            OpKind::AtomicLoad {
                dst,
                addr,
                width,
                order,
            } => self.lower_atomic_load(*dst, addr, *width, *order),
            OpKind::AtomicStore {
                src,
                addr,
                width,
                order,
            } => self.lower_atomic_store(*src, addr, *width, *order),
            OpKind::LoadExclusive { dst, addr, width } => {
                self.lower_load_exclusive(*dst, addr, *width)
            }
            OpKind::StoreExclusive {
                status,
                src,
                addr,
                width,
            } => self.lower_store_exclusive(*status, *src, addr, *width),
            OpKind::AtomicRmw {
                dst,
                addr,
                src,
                op,
                width,
                order,
            } => self.lower_atomic_rmw(*dst, addr, *src, *op, *width, *order),
            OpKind::Cas {
                dst,
                success,
                addr,
                expected,
                new_val,
                width,
                order,
            } => self.lower_cas(*dst, *success, addr, *expected, *new_val, *width, *order),
            OpKind::LoadPair {
                dst1,
                dst2,
                addr,
                width,
            } => self.lower_load_pair(*dst1, *dst2, addr, *width),
            OpKind::StorePair {
                src1,
                src2,
                addr,
                width,
            } => self.lower_store_pair(*src1, *src2, addr, *width),
            OpKind::Not { dst, src, width } => self.lower_not(*dst, *src, *width),
            OpKind::Cmp { src1, src2, width } => self.lower_cmp(*src1, src2, *width),
            OpKind::Test { src1, src2, width } => self.lower_test(*src1, src2, *width),
            OpKind::Clz { dst, src, width } => self.lower_clz(*dst, *src, *width),
            OpKind::Ctz { dst, src, width } => self.lower_ctz(*dst, *src, *width),
            OpKind::Bsf {
                dst,
                src,
                width,
                flags,
            } => self.lower_bsf(*dst, *src, *width, *flags),
            OpKind::Bsr {
                dst,
                src,
                width,
                flags,
            } => self.lower_bsr(*dst, *src, *width, *flags),
            OpKind::Bswap { dst, src, width } => self.lower_bswap(*dst, *src, *width),
            OpKind::Rbit { dst, src, width } => self.lower_rbit(*dst, *src, *width),
            OpKind::Bfx {
                dst,
                src,
                lsb,
                width_bits,
                sign_extend,
                op_width,
            } => self.lower_bfx(*dst, *src, *lsb, *width_bits, *sign_extend, *op_width),
            OpKind::Bfi {
                dst,
                dst_in,
                src,
                lsb,
                width_bits,
                op_width,
            } => self.lower_bfi(*dst, *dst_in, *src, *lsb, *width_bits, *op_width),
            OpKind::Lea { dst, addr } => self.lower_lea(*dst, addr),
            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width,
            } => self.lower_extend(*dst, *src, *from_width, *to_width, false),
            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width,
            } => self.lower_extend(*dst, *src, *from_width, *to_width, true),
            OpKind::Truncate { dst, src, to_width, .. } => {
                self.lower_truncate(*dst, *src, *to_width)
            }
            OpKind::Cwd { dst, src, width } => self.lower_cwd(*dst, *src, *width),
            OpKind::Xchg { reg1, reg2, width } => self.lower_xchg(*reg1, *reg2, *width),
            OpKind::Shl {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift(
                *dst,
                *src,
                amount,
                ShiftOp::Lsl,
                flags.updates_any(),
                *width,
            ),
            OpKind::Shr {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift(
                *dst,
                *src,
                amount,
                ShiftOp::Lsr,
                flags.updates_any(),
                *width,
            ),
            OpKind::Sar {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift(
                *dst,
                *src,
                amount,
                ShiftOp::Asr,
                flags.updates_any(),
                *width,
            ),
            OpKind::Shld {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_double_shift(
                *dst,
                *src,
                amount,
                true,
                flags.updates_any(),
                *width,
            ),
            OpKind::Shrd {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_double_shift(
                *dst,
                *src,
                amount,
                false,
                flags.updates_any(),
                *width,
            ),
            OpKind::Ror {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_shift(
                *dst,
                *src,
                amount,
                ShiftOp::Ror,
                flags.updates_any(),
                *width,
            ),
            OpKind::Rol {
                dst,
                src,
                amount,
                width,
                flags,
            } => self.lower_rol(*dst, *src, amount, flags.updates_any(), *width),
            OpKind::Rcl { .. } | OpKind::Rcr { .. } => Err(LowerError::UnsupportedOp {
                op: "AArch64 lower RCL/RCR".to_string(),
            }),
            OpKind::Select {
                dst,
                cond,
                src_true,
                src_false,
                width,
            } => self.lower_select(*dst, *cond, *src_true, *src_false, *width),
            OpKind::CMove {
                dst,
                src,
                cond,
                width,
            } => self.lower_cmove(*dst, *src, *cond, *width),
            OpKind::CmcCF => {
                self.emit_flagm(0b000);
                Ok(())
            }
            OpKind::SetCC { dst, cond, width } => self.lower_setcc(*dst, *cond, *width),
            OpKind::TestCondition { dst, cond } => self.lower_test_condition(*dst, *cond),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native lowering for {other:?}"),
            }),
        }
    }

    fn lower_cond_branch(
        &mut self,
        cond: VReg,
        true_target: BlockId,
        false_target: BlockId,
        folded_cond: Option<Condition>,
    ) -> Result<(), LowerError> {
        if true_target == false_target {
            self.emit_branch_placeholder(true_target);
            return Ok(());
        }

        if let Some(cond) = folded_cond {
            if cond == Condition::Always {
                self.emit_branch_placeholder(true_target);
                return Ok(());
            }
            self.emit_cond_branch_placeholder(Self::arm_cond_code(cond)?, true_target);
            self.emit_branch_placeholder(false_target);
            return Ok(());
        }

        if let VReg::Imm(value) = cond {
            self.emit_branch_placeholder(if value == 0 {
                false_target
            } else {
                true_target
            });
            return Ok(());
        }

        self.emit_compare_branch_placeholder(Self::gpr(cond)?, true, true_target);
        self.emit_branch_placeholder(false_target);
        Ok(())
    }

    fn lower_switch(
        &mut self,
        index: VReg,
        targets: &[BlockId],
        default: BlockId,
    ) -> Result<(), LowerError> {
        if let VReg::Imm(value) = index {
            let target = if value >= 0 {
                targets
                    .get(value as usize)
                    .copied()
                    .unwrap_or(default)
            } else {
                default
            };
            self.emit_branch_placeholder(target);
            return Ok(());
        }

        let index = Self::gpr(index)?;
        for (case, target) in targets.iter().enumerate() {
            let case = i64::try_from(case).map_err(|_| LowerError::InvalidOperand {
                op: "AArch64 native switch case".into(),
                operand: format!("case index {case}"),
            })?;
            self.emit_addsub_imm(31, index, case, true, true, OpWidth::W64)?;
            self.emit_cond_branch_placeholder(Self::arm_cond_code(Condition::Eq)?, *target);
        }
        self.emit_branch_placeholder(default);
        Ok(())
    }

    fn lower_terminator(
        &mut self,
        block: &SmirBlock,
        folded_cond: Option<Condition>,
    ) -> Result<(), LowerError> {
        match &block.terminator {
            Terminator::Branch { target } => {
                self.emit_branch_placeholder(*target);
                Ok(())
            }
            Terminator::CondBranch {
                cond,
                true_target,
                false_target,
            } => self.lower_cond_branch(*cond, *true_target, *false_target, folded_cond),
            Terminator::Switch {
                index,
                targets,
                default,
            } => self.lower_switch(*index, targets, *default),
            Terminator::IndirectBranch { target, .. } => {
                self.emit_br_reg(Self::branch_gpr(*target)?);
                Ok(())
            }
            Terminator::Return { .. } => {
                self.emit(0xd65f_03c0);
                Ok(())
            }
            Terminator::Trap {
                kind: TrapKind::Breakpoint,
            } => {
                self.emit_brk(0);
                Ok(())
            }
            Terminator::Trap {
                kind: TrapKind::SystemCall,
            } => {
                self.emit_svc(0);
                Ok(())
            }
            Terminator::Trap {
                kind: TrapKind::Halt,
            } => {
                self.emit_hlt(0);
                Ok(())
            }
            Terminator::Trap {
                kind: TrapKind::Undefined | TrapKind::InvalidOpcode,
            }
            | Terminator::Unreachable => {
                self.emit_udf(0);
                Ok(())
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native terminator {other:?}"),
            }),
        }
    }

    fn folded_branch_condition(block: &SmirBlock) -> (usize, Option<Condition>) {
        let op_end = block.ops.len();
        let Terminator::CondBranch { cond: branch_cond, .. } = &block.terminator else {
            return (op_end, None);
        };
        let Some(SmirOp {
            kind: OpKind::TestCondition { dst, cond },
            ..
        }) = block.ops.last()
        else {
            return (op_end, None);
        };
        if dst == branch_cond {
            (op_end - 1, Some(*cond))
        } else {
            (op_end, None)
        }
    }

    fn lower_block(&mut self, block: &SmirBlock) -> Result<(), LowerError> {
        self.block_offsets.insert(block.id, self.code.position());
        let (op_end, folded_cond) = Self::folded_branch_condition(block);
        let mut idx = 0;
        while idx < op_end {
            let ops = &block.ops[idx..op_end];
            if let Some(consumed) = self.try_lower_fused_signed_load_w(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_ldpsw_pair(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_mem_indexed(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_pair_indexed(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_mem_reg_offset(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_ldclr(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_extract(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_rev16(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_rev32(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_bitfield_insert_zero(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_bitfield_insert_low(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_cls(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_flagm(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_sysreg_access(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_cond_compare(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_select(ops)? {
                idx += consumed;
                continue;
            }
            self.lower_op(&block.ops[idx])?;
            idx += 1;
        }
        self.lower_terminator(block, folded_cond)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CondSelectFalseOp {
    Identity,
    Increment,
    Invert,
    Negate,
}

#[derive(Clone, Copy)]
struct SysRegInfo {
    op1: u32,
    crn: u32,
    crm: u32,
    op2: u32,
    mask: i64,
    read_width: OpWidth,
    write_width: OpWidth,
}

impl Default for Aarch64Lowerer {
    fn default() -> Self {
        Self::new()
    }
}

impl SmirLowerer for Aarch64Lowerer {
    fn target_arch(&self) -> &'static str {
        "aarch64"
    }

    fn lower_function(&mut self, func: &SmirFunction) -> Result<LowerResult, LowerError> {
        self.code.clear();
        self.block_offsets.clear();
        self.branch_fixups.clear();
        self.relocations.clear();

        for block in &func.blocks {
            self.lower_block(block)?;
        }
        self.fixup_branches()?;

        Ok(LowerResult {
            code_size: self.code.len(),
            entry_offset: *self.block_offsets.get(&func.entry).unwrap_or(&0),
            block_offsets: self.block_offsets.clone(),
            relocations: self.relocations.clone(),
            stack_size: 0,
        })
    }

    fn code_buffer(&self) -> &CodeBuffer {
        &self.code
    }

    fn finalize(&mut self) -> Result<Vec<u8>, LowerError> {
        Ok(self.code.as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::flags::FlagUpdate;
    use crate::smir::ir::{FunctionBuilder, Terminator, TrapKind};
    use crate::smir::types::{DispSize, FunctionId, SrcOperand};

    fn x(n: u8) -> VReg {
        VReg::Arch(ArchReg::Arm(ArmReg::X(n)))
    }

    fn enc_ldst_simm(size: u32, opc: u32, mode: u32, imm9: i64) -> u32 {
        (size << 30)
            | (0b111 << 27)
            | (opc << 22)
            | (((imm9 as u32) & 0x1ff) << 12)
            | (mode << 10)
            | (1 << 5)
    }

    fn enc_ldst_uimm(size: u32, opc: u32, imm12: u32) -> u32 {
        (size << 30) | (0b111 << 27) | (0b01 << 24) | (opc << 22) | (imm12 << 10) | (1 << 5)
    }

    fn enc_ldst_reg(size: u32, opc: u32, rm: u32, option: u32, s: u32) -> u32 {
        (size << 30)
            | (0b111 << 27)
            | (opc << 22)
            | (1 << 21)
            | (rm << 16)
            | (option << 13)
            | (s << 12)
            | (0b10 << 10)
            | (1 << 5)
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

    fn enc_ldxr(size: u32) -> u32 {
        (size << 30)
            | (0b001000 << 24)
            | (1 << 22)
            | (0b11111 << 16)
            | (0b11111 << 10)
            | (1 << 5)
    }

    fn enc_stxr(size: u32) -> u32 {
        (size << 30) | (0b001000 << 24) | (2 << 16) | (0b11111 << 10) | (1 << 5) | 3
    }

    fn enc_ldar(size: u32) -> u32 {
        (size << 30)
            | (0b001000 << 24)
            | (1 << 23)
            | (1 << 22)
            | (0b11111 << 16)
            | (1 << 15)
            | (0b11111 << 10)
            | (1 << 5)
    }

    fn enc_stlr(size: u32) -> u32 {
        (size << 30)
            | (0b001000 << 24)
            | (1 << 23)
            | (0b11111 << 16)
            | (1 << 15)
            | (0b11111 << 10)
            | (1 << 5)
            | 3
    }

    fn enc_atomic_rmw(size: u32, acquire: u32, release: u32, o3: u32, opc: u32) -> u32 {
        (size << 30)
            | (0b111 << 27)
            | (acquire << 23)
            | (release << 22)
            | (1 << 21)
            | (2 << 16)
            | (o3 << 15)
            | (opc << 12)
            | (1 << 5)
    }

    fn enc_cas(size: u32, acquire: u32, release: u32) -> u32 {
        (size << 30)
            | (0b001000 << 24)
            | (1 << 23)
            | (acquire << 22)
            | (1 << 21)
            | (2 << 16)
            | (release << 15)
            | (0b11111 << 10)
            | (1 << 5)
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

    fn enc_br(rn: u32) -> u32 {
        0xd61f_0000 | ((rn & 0x1f) << 5)
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

    fn enc_addsub_imm(sf: u32, op: u32, s: u32, imm12: u32) -> u32 {
        (sf << 31) | (op << 30) | (s << 29) | (0b10001 << 24) | (imm12 << 10) | (1 << 5)
    }

    fn enc_addsub_imm_regs(
        sf: u32,
        op: u32,
        s: u32,
        shift: u32,
        imm12: u32,
        rd: u32,
        rn: u32,
    ) -> u32 {
        (sf << 31)
            | (op << 30)
            | (s << 29)
            | (0b10001 << 24)
            | (shift << 22)
            | (imm12 << 10)
            | (rn << 5)
            | rd
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

    fn enc_logical_reg_n(sf: u32, opc: u32, n: u32, rd: u32, rn: u32, rm: u32) -> u32 {
        (sf << 31) | (opc << 29) | (0b01010 << 24) | (n << 21) | (rm << 16) | (rn << 5) | rd
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

    fn enc_brk(imm16: u32) -> u32 {
        0xd420_0000 | ((imm16 & 0xffff) << 5)
    }

    fn enc_svc(imm16: u32) -> u32 {
        0xd400_0001 | ((imm16 & 0xffff) << 5)
    }

    fn enc_hlt(imm16: u32) -> u32 {
        0xd440_0000 | ((imm16 & 0xffff) << 5)
    }

    fn enc_udf(imm16: u32) -> u32 {
        (imm16 & 0xffff) << 5
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
        0xd500_0000
            | (3 << 19)
            | (op1 << 16)
            | (crn << 12)
            | (crm << 8)
            | (op2 << 5)
            | (rt & 0x1f)
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
        (b5 << 31)
            | (0b011011 << 25)
            | ((nonzero as u32) << 24)
            | (b40 << 19)
            | (imm14 << 5)
            | rt
    }

    #[test]
    fn lowers_add_register_and_ret() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        assert_eq!(code, [0x20, 0x00, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6]);
    }

    #[test]
    fn lowers_inc_x_as_add_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Inc {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_imm(1, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_dec_w_as_sub_imm_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Dec {
                dst: x(0),
                src: x(1),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_imm(0, 1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_mulu_full_width_when_low_aliases_src1_as_high_then_low() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::MulU {
                dst_lo: x(1),
                dst_hi: Some(x(0)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp3_regs(1, 0b110, 0, 0, 1, 2, 31).to_le_bytes());
        expected.extend_from_slice(&enc_dp3_regs(1, 0b000, 0, 1, 1, 2, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_muls_full_width_when_low_aliases_src2_as_high_then_low() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::MulS {
                dst_lo: x(2),
                dst_hi: Some(x(0)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp3_regs(1, 0b010, 0, 0, 1, 2, 31).to_le_bytes());
        expected.extend_from_slice(&enc_dp3_regs(1, 0b000, 0, 2, 1, 2, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_mulu_full_width_when_high_aliases_src1_as_low_then_high() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::MulU {
                dst_lo: x(0),
                dst_hi: Some(x(1)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp3_regs(1, 0b000, 0, 0, 1, 2, 31).to_le_bytes());
        expected.extend_from_slice(&enc_dp3_regs(1, 0b110, 0, 1, 1, 2, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_full_width_multiply_when_both_outputs_alias_sources() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::MulU {
                dst_lo: x(1),
                dst_hi: Some(x(2)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_divu_x_with_remainder_as_udiv_msub() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::DivU {
                quot: x(0),
                rem: Some(x(3)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp2_regs(1, 0b0010, 1, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp3_regs(1, 0b000, 1, 3, 0, 2, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_divs_w_with_remainder_as_sdiv_msub_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::DivS {
                quot: x(0),
                rem: Some(x(3)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp2_regs(0, 0b0011, 1, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp3_regs(0, 0b000, 1, 3, 0, 2, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_divu_x_with_remainder_when_quotient_aliases_dividend() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::DivU {
                quot: x(1),
                rem: Some(x(3)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp2_regs(1, 0b0010, 1, 2, 3).to_le_bytes());
        expected.extend_from_slice(&enc_dp3_regs(1, 0b000, 1, 3, 3, 2, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(1, 0b0010, 1, 2, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_divs_w_with_remainder_when_quotient_aliases_divisor() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::DivS {
                quot: x(2),
                rem: Some(x(3)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp2_regs(0, 0b0011, 1, 2, 3).to_le_bytes());
        expected.extend_from_slice(&enc_dp3_regs(0, 0b000, 1, 3, 3, 2, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(0, 0b0011, 1, 2, 2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_div_remainder_when_quotient_alias_has_no_temp() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::DivU {
                quot: x(1),
                rem: Some(x(1)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_flag_setting_div_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::DivU {
                quot: x(0),
                rem: Some(x(3)),
                src1: x(1),
                src2: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_cwd_x_as_asr63() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Cwd {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(1, 0b00, 63, 63).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cwd_w_as_asr31_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Cwd {
                dst: x(0),
                src: x(1),
                width: OpWidth::W32,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b00, 31, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cwd_w8_as_sbfm_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Cwd {
                dst: x(0),
                src: x(1),
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b00, 7, 7).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cwd_w16_as_sbfm_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Cwd {
                dst: x(0),
                src: x(1),
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b00, 15, 15).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shl_w8_imm_as_ubfiz() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(3),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b10, 29, 4).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shr_w16_imm_as_ubfx() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shr {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(5),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b10, 5, 15).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_sar_w8_imm_as_sbfm_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Sar {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(3),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b00, 3, 7).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shl_w16_imm_count_above_width_as_zero() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(17),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_wide(0, 0b10, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ror_w8_imm_as_duplicate_extract() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Ror {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(3),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b01, 24, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 3, 10, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_rol_w16_imm_as_subword_ror() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(5),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b01, 16, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 11, 26, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ror_w8_imm_masked_zero_as_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Ror {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(8),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 1, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shl_w8_reg_with_count_guards() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_test_branch(2, 3, true, 24).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 4, true, 20).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 5, true, 16).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(0, 0b1000, 1, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_b(2).to_le_bytes());
        expected.extend_from_slice(&enc_mov_wide(0, 0b10, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shr_w16_reg_with_count_guards_and_source_mask() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shr {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_test_branch(2, 4, true, 20).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 5, true, 16).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(0, 0b1001, 0, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_b(2).to_le_bytes());
        expected.extend_from_slice(&enc_mov_wide(0, 0b10, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_sar_w8_reg_with_count_guards_and_sign_fill() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Sar {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_test_branch(2, 3, true, 28).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 4, true, 24).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 5, true, 20).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 8, 7, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(0, 0b1010, 0, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 24, 31, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_b(3).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b00, 7, 7, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_subword_shr_reg_count_when_dst_is_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shr {
                dst: x(2),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_xchg_x_as_eor_swap() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xchg {
                reg1: x(0),
                reg2: x(1),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_reg(1, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(1, 0b10, 1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(1, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_xchg_w_as_eor_swap_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xchg {
                reg1: x(0),
                reg2: x(1),
                width: OpWidth::W32,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_xchg_same_w_as_self_mov_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xchg {
                reg1: x(0),
                reg2: x(0),
                width: OpWidth::W32,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_xchg_w16_as_eor_swap_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xchg {
                reg1: x(0),
                reg2: x(1),
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 1, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_xchg_same_w16_as_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xchg {
                reg1: x(0),
                reg2: x(0),
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_xchg_w8_as_eor_swap_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xchg {
                reg1: x(0),
                reg2: x(1),
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_logical_reg(0, 0b10, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 1, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_xchg_same_w8_as_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xchg {
                reg1: x(0),
                reg2: x(0),
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_lea_direct_as_add_zero() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Lea {
                dst: x(0),
                addr: Address::Direct(x(1)),
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_imm_regs(1, 0, 0, 0, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_lea_base_positive_offset_as_add_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Lea {
                dst: x(0),
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: 0x123,
                    disp_size: DispSize::Auto,
                },
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_imm_regs(1, 0, 0, 0, 0x123, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_lea_base_negative_offset_as_sub_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Lea {
                dst: x(0),
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: -0x2000,
                    disp_size: DispSize::Auto,
                },
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_imm_regs(1, 1, 0, 1, 2, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_lea_base_index_scale_disp() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Lea {
                dst: x(0),
                addr: Address::BaseIndexScale {
                    base: Some(x(1)),
                    index: x(2),
                    scale: 4,
                    disp: -0x20,
                    disp_size: DispSize::Auto,
                },
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_shift_regs(1, 0, 0, 0, 2, 0, 1, 2).to_le_bytes());
        expected.extend_from_slice(&enc_addsub_imm_regs(1, 1, 0, 0, 0x20, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_lea_index_scale_without_base() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Lea {
                dst: x(0),
                addr: Address::BaseIndexScale {
                    base: None,
                    index: x(2),
                    scale: 8,
                    disp: 0,
                    disp_size: DispSize::Auto,
                },
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_shift_regs(1, 0, 0, 0, 3, 0, 31, 2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_scalar_pre_index_load_sequence() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(1),
                src1: x(1),
                src2: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_simm(3, 0b01, 0b11, 8).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_scalar_post_index_store_sequence() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Store {
                src: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
            },
        );
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(1),
                src1: x(1),
                src2: SrcOperand::Imm(-8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_simm(3, 0b00, 0b01, -8).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_pred_load_with_tbz_guard() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::PredLoad {
                dst: x(0),
                cond: x(2),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                signed: SignExtend::Zero,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_test_branch(2, 0, false, 8).to_le_bytes());
        expected.extend_from_slice(&enc_ldst_uimm(3, 0b01, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_pred_store_with_tbz_guard() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::PredStore {
                src: SrcOperand::Reg(x(0)),
                cond: x(2),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_test_branch(2, 0, false, 8).to_le_bytes());
        expected.extend_from_slice(&enc_ldst_uimm(3, 0b00, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_signed_load_w_zero_extend_sequence() {
        let tmp = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Load {
                dst: tmp,
                addr: Address::Direct(x(1)),
                width: MemWidth::B1,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::ZeroExtend {
                dst: x(0),
                src: tmp,
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_uimm(0, 0b11, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_signed_load_w_post_index_sequence() {
        let tmp = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Load {
                dst: tmp,
                addr: Address::Direct(x(1)),
                width: MemWidth::B2,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::ZeroExtend {
                dst: x(0),
                src: tmp,
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            },
        );
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(1),
                src1: x(1),
                src2: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_simm(1, 0b11, 0b01, 8).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_signed_load_w_reg_offset_sequence() {
        let ext = VReg::virt(0);
        let addr = VReg::virt(1);
        let load_tmp = VReg::virt(2);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::SignExtend {
                dst: ext,
                src: x(2),
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            },
        );
        builder.push_op(
            0,
            OpKind::Add {
                dst: addr,
                src1: x(1),
                src2: SrcOperand::Reg(ext),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Load {
                dst: load_tmp,
                addr: Address::Direct(addr),
                width: MemWidth::B1,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::ZeroExtend {
                dst: x(0),
                src: load_tmp,
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_reg(0, 0b11, 2, 0b110, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_signed_load_w_shifted_reg_offset_sequence() {
        let ext = VReg::virt(0);
        let shifted = VReg::virt(1);
        let addr = VReg::virt(2);
        let load_tmp = VReg::virt(3);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::ZeroExtend {
                dst: ext,
                src: x(2),
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: shifted,
                src: ext,
                amount: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Add {
                dst: addr,
                src1: x(1),
                src2: SrcOperand::Reg(shifted),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Load {
                dst: load_tmp,
                addr: Address::Direct(addr),
                width: MemWidth::B2,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::ZeroExtend {
                dst: x(0),
                src: load_tmp,
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_reg(1, 0b11, 2, 0b010, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_load_base_index_scale_as_scaled_reg_offset() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(0),
                addr: Address::BaseIndexScale {
                    base: Some(x(1)),
                    index: x(2),
                    scale: 8,
                    disp: 0,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_reg(3, 0b01, 2, 0b011, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_store_base_index_scale_as_unscaled_reg_offset() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Store {
                src: x(0),
                addr: Address::BaseIndexScale {
                    base: Some(x(1)),
                    index: x(2),
                    scale: 1,
                    disp: 0,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B4,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_reg(2, 0b00, 2, 0b011, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_load_exclusive_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::LoadExclusive {
                dst: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldxr(3).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_store_exclusive_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::StoreExclusive {
                status: x(2),
                src: x(3),
                addr: Address::Direct(x(1)),
                width: MemWidth::B4,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_stxr(2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_atomic_load_acquire_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicLoad {
                dst: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                order: MemoryOrder::Acquire,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldar(3).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_atomic_load_relaxed_as_plain_load() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicLoad {
                dst: x(0),
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: 2,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B2,
                order: MemoryOrder::Relaxed,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_uimm(1, 0b01, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_atomic_load_release_order() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicLoad {
                dst: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                order: MemoryOrder::Release,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        assert!(lowerer.lower_function(&func).is_err());
    }

    #[test]
    fn lowers_atomic_store_release_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicStore {
                src: x(3),
                addr: Address::Direct(x(1)),
                width: MemWidth::B4,
                order: MemoryOrder::Release,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_stlr(2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_atomic_store_relaxed_as_plain_store() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicStore {
                src: x(0),
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: 16,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B8,
                order: MemoryOrder::Relaxed,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldst_uimm(3, 0b00, 2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_atomic_store_acquire_order() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicStore {
                src: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                order: MemoryOrder::Acquire,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        assert!(lowerer.lower_function(&func).is_err());
    }

    #[test]
    fn lowers_atomic_rmw_swap_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicRmw {
                dst: x(0),
                addr: Address::Direct(x(1)),
                src: x(2),
                op: AtomicOp::Swap,
                width: MemWidth::B8,
                order: MemoryOrder::Relaxed,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_atomic_rmw(3, 0, 0, 1, 0b000).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_atomic_rmw_add_acqrel_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicRmw {
                dst: x(0),
                addr: Address::Direct(x(1)),
                src: x(2),
                op: AtomicOp::Add,
                width: MemWidth::B4,
                order: MemoryOrder::AcqRel,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_atomic_rmw(2, 1, 1, 0, 0b000).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_ldclr_sequence() {
        let inverted = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Not {
                dst: inverted,
                src: x(2),
                width: OpWidth::W64,
            },
        );
        builder.push_op(
            0,
            OpKind::AtomicRmw {
                dst: x(0),
                addr: Address::Direct(x(1)),
                src: inverted,
                op: AtomicOp::And,
                width: MemWidth::B8,
                order: MemoryOrder::Release,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_atomic_rmw(3, 0, 1, 0, 0b001).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_unfused_atomic_rmw_and() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AtomicRmw {
                dst: x(0),
                addr: Address::Direct(x(1)),
                src: x(2),
                op: AtomicOp::And,
                width: MemWidth::B8,
                order: MemoryOrder::Relaxed,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        assert!(lowerer.lower_function(&func).is_err());
    }

    #[test]
    fn lowers_cas_lifted_shape_direct() {
        let success = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Cas {
                dst: x(2),
                success,
                addr: Address::Direct(x(1)),
                expected: x(2),
                new_val: x(0),
                width: MemWidth::B8,
                order: MemoryOrder::AcqRel,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_cas(3, 1, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_cas_with_observable_success() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Cas {
                dst: x(2),
                success: x(3),
                addr: Address::Direct(x(1)),
                expected: x(2),
                new_val: x(0),
                width: MemWidth::B8,
                order: MemoryOrder::Relaxed,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        assert!(lowerer.lower_function(&func).is_err());
    }

    #[test]
    fn rejects_cas_with_split_compare_and_destination() {
        let success = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Cas {
                dst: x(3),
                success,
                addr: Address::Direct(x(1)),
                expected: x(2),
                new_val: x(0),
                width: MemWidth::B8,
                order: MemoryOrder::Relaxed,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        assert!(lowerer.lower_function(&func).is_err());
    }

    #[test]
    fn fuses_lifted_extract_sequence() {
        let lo = VReg::virt(0);
        let hi = VReg::virt(1);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shr {
                dst: lo,
                src: x(2),
                amount: SrcOperand::Imm(13),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: hi,
                src: x(1),
                amount: SrcOperand::Imm(51),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: lo,
                src2: SrcOperand::Reg(hi),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(1, 1, 2, 13).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_ror_w_alias_sequence() {
        let lo = VReg::virt(0);
        let hi = VReg::virt(1);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shr {
                dst: lo,
                src: x(1),
                amount: SrcOperand::Imm(7),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: hi,
                src: x(1),
                amount: SrcOperand::Imm(25),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: lo,
                src2: SrcOperand::Reg(hi),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(0, 1, 1, 7).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_rol_x_imm_as_ror() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(13),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(1, 1, 1, 51).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_rol_w_imm_as_ror_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(7),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(0, 1, 1, 25).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shl_w_reg_with_x86_count_guard() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp2_regs(0, 0b1000, 1, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 5, false, 8).to_le_bytes());
        expected.extend_from_slice(&enc_mov_reg(0, 0, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shr_w_reg_with_x86_count_guard() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shr {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp2_regs(0, 0b1001, 1, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 5, false, 8).to_le_bytes());
        expected.extend_from_slice(&enc_mov_reg(0, 0, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ctz_x_as_rbit_clz() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Ctz {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1_regs(1, 0b000000, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(1, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ctz_w_as_rbit_clz_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Ctz {
                dst: x(0),
                src: x(1),
                width: OpWidth::W32,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000000, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bsf_x_as_rbit_clz_ubfx() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsf {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1_regs(1, 0b000000, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(1, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(1, 0b10, 0, 5, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bsf_w_as_rbit_clz_ubfx_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsf {
                dst: x(0),
                src: x(1),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000000, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 4, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bsr_x_as_orr_clz_eor_mask() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsr {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(1, 0b01, 1, 0, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(1, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_logical_imm(1, 0b10, 1, 0, 5, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bsr_w_as_orr_clz_eor_mask_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsr {
                dst: x(0),
                src: x(1),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b01, 0, 0, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_logical_imm(0, 0b10, 0, 0, 4, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_orr_x_low_mask_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0x3f),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(1, 0b01, 1, 0, 5, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_eor_x_high_bit_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xor {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(0x8000_0000_0000_0000_u64 as i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(1, 0b10, 1, 1, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_orr_x_wrapping_mask_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(0x8000_0000_0000_0001_u64 as i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(1, 0b01, 1, 1, 1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_and_w_shifted_byte_mask_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0xff00),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b00, 0, 24, 7, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_and_w_wrapping_mask_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0xf000_000f),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b00, 0, 4, 7, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_and_w_repeated_byte_mask_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0x00ff_00ff),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b00, 0, 0, 39, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_eor_x_repeated_alternating_bit_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xor {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(0x5555_5555_5555_5555),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(1, 0b10, 0, 0, 60, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_and_x_zero_imm_as_movz_zero() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_wide(1, 0b10, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_and_x_all_ones_imm_as_mov_reg() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(-1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_orr_x_zero_imm_as_mov_reg() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_orr_x_all_ones_imm_as_movn_zero() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(-1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_wide(1, 0b00, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_orr_w_all_ones_imm_as_movn_zero() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(-1),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_wide(0, 0b00, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_eor_x_all_ones_imm_as_mvn() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Xor {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(-1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_reg_n(1, 0b01, 1, 0, 31, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ands_x_zero_imm_as_ands_zero_regs() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_reg_n(1, 0b11, 0, 0, 31, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_test_x_zero_imm_as_ands_zero_regs() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Test {
                src1: x(1),
                src2: SrcOperand::Imm(0),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_reg_n(1, 0b11, 0, 31, 31, 31).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_andnot_x_zero_imm_as_mov_reg() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AndNot {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_andnot_x_all_ones_imm_as_movz_zero() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AndNot {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(-1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_wide(1, 0b10, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_andnot_x_high_bit_imm_as_and_inverse_mask() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AndNot {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(0x8000_0000_0000_0000_u64 as i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(1, 0b00, 1, 0, 62, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bics_w_high_bits_imm_as_ands_inverse_mask() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AndNot {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0xffff_ff00),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b11, 0, 0, 7, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ands_w_low_mask_imm_to_zero_reg_for_virtual_dst() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: VReg::virt(0),
                src1: x(1),
                src2: SrcOperand::Imm(0x1f),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b11, 0, 0, 4, 31, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_test_x_high_bit_imm_to_zero_reg() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Test {
                src1: x(1),
                src2: SrcOperand::Imm64(0x8000_0000_0000_0000_u64 as i64),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(1, 0b11, 1, 1, 0, 31, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_non_contiguous_logical_immediate() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm(0x55),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_inverted_logical_immediate_with_unencodable_inverse() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::AndNot {
                dst: x(0),
                src1: x(1),
                src2: SrcOperand::Imm64(!0x55_i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_truncate_x_to_w8_as_ubfx() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Truncate {
                dst: x(0),
                src: x(1),
                from_width: OpWidth::W64,
                to_width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(1, 0b10, 0, 7).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_truncate_x_to_w16_as_ubfx() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Truncate {
                dst: x(0),
                src: x(1),
                from_width: OpWidth::W64,
                to_width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(1, 0b10, 0, 15).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_truncate_x_to_w32_as_w_mov_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Truncate {
                dst: x(0),
                src: x(1),
                from_width: OpWidth::W64,
                to_width: OpWidth::W32,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_zero_extend_w8_to_w16_as_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::ZeroExtend {
                dst: x(0),
                src: x(1),
                from_width: OpWidth::W8,
                to_width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b10, 0, 7).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_sign_extend_w8_to_w16_as_sxtb_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::SignExtend {
                dst: x(0),
                src: x(1),
                from_width: OpWidth::W8,
                to_width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b00, 0, 7).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_constant_select_true_imm_as_mov_imm() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Select {
                dst: x(0),
                cond: VReg::Imm(1),
                src_true: VReg::Imm(0x2468),
                src_false: x(1),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_wide(1, 0b10, 0, 0x2468, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_constant_select_true_w8_imm_as_mov_imm_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Select {
                dst: x(0),
                cond: VReg::Imm(1),
                src_true: VReg::Imm(0x1234),
                src_false: x(1),
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_wide(0, 0b10, 0, 0x1234, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_register_select_with_aliased_condition() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Select {
                dst: x(0),
                cond: x(0),
                src_true: x(1),
                src_false: x(2),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_cbz(0, 3).to_le_bytes());
        expected.extend_from_slice(&enc_mov_reg(1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_b(2).to_le_bytes());
        expected.extend_from_slice(&enc_mov_reg(1, 0, 2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_register_select_w16_with_aliased_condition() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Select {
                dst: x(0),
                cond: x(0),
                src_true: x(1),
                src_false: x(2),
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_cbz(0, 4).to_le_bytes());
        expected.extend_from_slice(&enc_mov_reg(0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_b(3).to_le_bytes());
        expected.extend_from_slice(&enc_mov_reg(0, 0, 2).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ctz_in_place_as_rbit_clz() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Ctz {
                dst: x(0),
                src: x(0),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1_regs(1, 0b000000, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(1, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_setcc_w8_as_cset() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::SetCC {
                dst: x(0),
                cond: Condition::Ne,
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_csel_regs(1, 0, 1, 31, 31, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cmove_x_as_csel() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::CMove {
                dst: x(0),
                src: x(1),
                cond: Condition::Eq,
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_csel_regs(1, 0, 0, 1, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cmove_w_as_csel_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::CMove {
                dst: x(0),
                src: x(1),
                cond: Condition::Eq,
                width: OpWidth::W32,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_csel_regs(0, 0, 0, 1, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cmove_w_imm_with_false_path_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::CMove {
                dst: x(0),
                src: VReg::Imm(0x1234),
                cond: Condition::Eq,
                width: OpWidth::W32,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_b_cond(1, 2).to_le_bytes());
        expected.extend_from_slice(&enc_mov_wide(0, 0b10, 0, 0x1234, 0).to_le_bytes());
        expected.extend_from_slice(&enc_mov_reg(0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cmove_w16_as_csel_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::CMove {
                dst: x(0),
                src: x(1),
                cond: Condition::Eq,
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_csel_regs(0, 0, 0, 1, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cmove_w8_as_csel_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::CMove {
                dst: x(0),
                src: x(1),
                cond: Condition::Eq,
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_csel_regs(0, 0, 0, 1, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_cmc_cf_as_cfinv() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(0, OpKind::CmcCF);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_flagm(0b000).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_breakpoint_op_as_brk() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(0, OpKind::Breakpoint);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_brk(0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_undefined_op_as_udf() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Undefined {
                opcode: 0xffff_ffff,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_udf(0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_swi_op_as_svc() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(0, OpKind::Swi { imm: 0x1234 });
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_svc(0x1234).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_swi_imm_out_of_range() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(0, OpKind::Swi { imm: 0x1_0000 });
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::InvalidOperand { .. }));
    }

    #[test]
    fn lowers_breakpoint_trap_terminator_as_brk() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::Breakpoint,
        });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_brk(0).to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_system_call_trap_terminator_as_svc() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::SystemCall,
        });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_svc(0).to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_halt_trap_terminator_as_hlt() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::Halt,
        });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_hlt(0).to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_undefined_trap_terminator_as_udf() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.set_terminator(Terminator::Trap {
            kind: TrapKind::Undefined,
        });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_udf(0).to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_unreachable_terminator_as_udf() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.set_terminator(Terminator::Unreachable);
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_udf(0).to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_branch_terminator_as_b() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        let target = builder.create_block(4);
        builder.set_terminator(Terminator::Branch { target });
        builder.switch_to_block(target);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let result = lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_b(1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(result.block_offsets.get(&target), Some(&4));
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_test_condition_cond_branch_as_b_cond() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        let true_target = builder.create_block(4);
        let false_target = builder.create_block(8);
        let cond = VReg::virt(0);
        builder.push_op(
            0,
            OpKind::TestCondition {
                dst: cond,
                cond: Condition::Eq,
            },
        );
        builder.set_terminator(Terminator::CondBranch {
            cond,
            true_target,
            false_target,
        });
        builder.switch_to_block(true_target);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(false_target);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_b_cond(0, 2).to_le_bytes());
        expected.extend_from_slice(&enc_b(2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_register_cond_branch_as_cbnz() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        let true_target = builder.create_block(4);
        let false_target = builder.create_block(8);
        builder.set_terminator(Terminator::CondBranch {
            cond: x(1),
            true_target,
            false_target,
        });
        builder.switch_to_block(true_target);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(false_target);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_cbnz(1, 2).to_le_bytes());
        expected.extend_from_slice(&enc_b(2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_immediate_cond_branch_as_single_b() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        let true_target = builder.create_block(4);
        let false_target = builder.create_block(8);
        builder.set_terminator(Terminator::CondBranch {
            cond: VReg::Imm(0),
            true_target,
            false_target,
        });
        builder.switch_to_block(true_target);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(false_target);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_b(2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_register_switch_as_compare_branch_chain() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        let case0 = builder.create_block(4);
        let case1 = builder.create_block(8);
        let default = builder.create_block(12);
        builder.set_terminator(Terminator::Switch {
            index: x(1),
            targets: vec![case0, case1],
            default,
        });
        builder.switch_to_block(case0);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(case1);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(default);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_imm_regs(1, 1, 1, 0, 0, 31, 1).to_le_bytes());
        expected.extend_from_slice(&enc_b_cond(0, 4).to_le_bytes());
        expected.extend_from_slice(&enc_addsub_imm_regs(1, 1, 1, 0, 1, 31, 1).to_le_bytes());
        expected.extend_from_slice(&enc_b_cond(0, 3).to_le_bytes());
        expected.extend_from_slice(&enc_b(3).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_immediate_switch_as_single_b() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        let case0 = builder.create_block(4);
        let case1 = builder.create_block(8);
        let default = builder.create_block(12);
        builder.set_terminator(Terminator::Switch {
            index: VReg::Imm(1),
            targets: vec![case0, case1],
            default,
        });
        builder.switch_to_block(case0);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(case1);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(default);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_b(2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_indirect_branch_terminator_as_br() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.set_terminator(Terminator::IndirectBranch {
            target: x(3),
            possible_targets: vec![],
        });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_br(3).to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_indirect_branch_immediate_target() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.set_terminator(Terminator::IndirectBranch {
            target: VReg::Imm(0),
            possible_targets: vec![],
        });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::InvalidRegister(_)));
    }

    #[test]
    fn lowers_materialize_flags_as_noop() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(0, OpKind::MaterializeFlags);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_read_sysreg_nzcv_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::ReadSysReg {
                dst: x(0),
                reg: SYSREG_NZCV,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mrs_sysreg(0, 3, 4, 2, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_write_sysreg_nzcv_direct() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::WriteSysReg {
                reg: SYSREG_NZCV,
                src: x(1),
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_msr_sysreg(1, 3, 4, 2, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_prefetch_as_noop() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Prefetch {
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: 24,
                    disp_size: DispSize::Auto,
                },
                write: false,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_x_imm_as_extract() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(13),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(1, 1, 0, 13).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shld_x_imm_as_extract() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(13),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(1, 0, 1, 51).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w_imm_as_extract_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(7),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(0, 1, 0, 7).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shld_w_imm_as_extract_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(7),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_extract(0, 0, 1, 25).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w_masked_zero_count_as_self_mov() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(32),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_rev16_x_sequence() {
        let lo = VReg::virt(0);
        let hi = VReg::virt(1);
        let lo_shifted = VReg::virt(2);
        let hi_shifted = VReg::virt(3);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: lo,
                src1: x(1),
                src2: SrcOperand::Imm64(0x00ff_00ff_00ff_00ff),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::And {
                dst: hi,
                src1: x(1),
                src2: SrcOperand::Imm64(0xff00_ff00_ff00_ff00_u64 as i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: lo_shifted,
                src: lo,
                amount: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Shr {
                dst: hi_shifted,
                src: hi,
                amount: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: lo_shifted,
                src2: SrcOperand::Reg(hi_shifted),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1(1, 0b000001).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_rev16_w_sequence() {
        let lo = VReg::virt(0);
        let hi = VReg::virt(1);
        let lo_shifted = VReg::virt(2);
        let hi_shifted = VReg::virt(3);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::And {
                dst: lo,
                src1: x(1),
                src2: SrcOperand::Imm64(0x00ff_00ff),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::And {
                dst: hi,
                src1: x(1),
                src2: SrcOperand::Imm64(0xff00_ff00),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: lo_shifted,
                src: lo,
                amount: SrcOperand::Imm(8),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Shr {
                dst: hi_shifted,
                src: hi,
                amount: SrcOperand::Imm(8),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: lo_shifted,
                src2: SrcOperand::Reg(hi_shifted),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1(0, 0b000001).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bswap_w8_as_mov_reg() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bswap {
                dst: x(0),
                src: x(1),
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_rbit_w8_as_mov_reg() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rbit {
                dst: x(0),
                src: x(1),
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_rbit_w16_as_mov_reg() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rbit {
                dst: x(0),
                src: x(1),
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_mov_reg(1, 0, 1).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bswap_w16_as_rev16_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bswap {
                dst: x(0),
                src: x(1),
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1(0, 0b000001).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_rev32_x_sequence() {
        let lo_rev = VReg::virt(0);
        let hi = VReg::virt(1);
        let hi_rev = VReg::virt(2);
        let hi_shifted = VReg::virt(3);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bswap {
                dst: lo_rev,
                src: x(1),
                width: OpWidth::W32,
            },
        );
        builder.push_op(
            0,
            OpKind::Shr {
                dst: hi,
                src: x(1),
                amount: SrcOperand::Imm(32),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Bswap {
                dst: hi_rev,
                src: hi,
                width: OpWidth::W32,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: hi_shifted,
                src: hi_rev,
                amount: SrcOperand::Imm(32),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Or {
                dst: x(0),
                src1: hi_shifted,
                src2: SrcOperand::Reg(lo_rev),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp1(1, 0b000010).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_ubfiz_sequence() {
        let extracted = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bfx {
                dst: extracted,
                src: x(1),
                lsb: 0,
                width_bits: 8,
                sign_extend: false,
                op_width: OpWidth::W64,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(0),
                src: extracted,
                amount: SrcOperand::Imm(4),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(1, 0b10, 60, 7).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_sbfiz_w_sequence() {
        let extracted = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bfx {
                dst: extracted,
                src: x(1),
                lsb: 0,
                width_bits: 8,
                sign_extend: true,
                op_width: OpWidth::W32,
            },
        );
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(0),
                src: extracted,
                amount: SrcOperand::Imm(8),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(0, 0b00, 24, 7).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_lifted_bfxil_sequence() {
        let extracted = VReg::virt(0);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bfx {
                dst: extracted,
                src: x(1),
                lsb: 8,
                width_bits: 8,
                sign_extend: false,
                op_width: OpWidth::W64,
            },
        );
        builder.push_op(
            0,
            OpKind::Bfi {
                dst: x(0),
                dst_in: x(0),
                src: extracted,
                lsb: 0,
                width_bits: 8,
                op_width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield(1, 0b01, 8, 15).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_ldpsw_pair_sequence() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(2),
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: 8,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B8,
                sign: SignExtend::Sign,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldp(0b01, 0b10, true, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_ldpsw_pre_index_sequence() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(1),
                src1: x(1),
                src2: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(2),
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: 8,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B8,
                sign: SignExtend::Sign,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldp(0b01, 0b11, true, 2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_ldpsw_post_index_sequence() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(0),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::Load {
                dst: x(2),
                addr: Address::BaseOffset {
                    base: x(1),
                    offset: 8,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B8,
                sign: SignExtend::Sign,
            },
        );
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(1),
                src1: x(1),
                src2: SrcOperand::Imm(-8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldp(0b01, 0b01, true, -2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_pair_pre_index_load_sequence() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(1),
                src1: x(1),
                src2: SrcOperand::Imm(16),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.push_op(
            0,
            OpKind::LoadPair {
                dst1: x(0),
                dst2: x(2),
                addr: Address::Direct(x(1)),
                width: MemWidth::B8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldp(0b10, 0b11, true, 2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn fuses_pair_post_index_store_sequence() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::StorePair {
                src1: x(0),
                src2: x(2),
                addr: Address::Direct(x(1)),
                width: MemWidth::B4,
            },
        );
        builder.push_op(
            0,
            OpKind::Add {
                dst: x(1),
                src1: x(1),
                src2: SrcOperand::Imm(-8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_ldp(0b00, 0b01, false, -2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_flag_setting_shift_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_sar_w_reg_with_sign_guard() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Sar {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_dp2_regs(0, 0b1010, 1, 2, 0).to_le_bytes());
        expected.extend_from_slice(&enc_test_branch(2, 5, false, 8).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b00, 31, 31, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_sar_w_reg_count_when_dst_is_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Sar {
                dst: x(2),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shl_w_reg_count_when_dst_is_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shl {
                dst: x(2),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_flag_setting_rol_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_rol_x_reg_as_neg_count_rorv() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_shift_regs(1, 1, 0, 0, 0, 0, 31, 2).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(1, 0b1011, 1, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_rol_w_reg_as_neg_count_rorv_zero_ext() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_shift_regs(0, 1, 0, 0, 0, 0, 31, 2).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(0, 0b1011, 1, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_rol_x_reg_when_dst_is_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(2),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_addsub_shift_regs(1, 1, 0, 0, 0, 2, 31, 2).to_le_bytes());
        expected.extend_from_slice(&enc_dp2_regs(1, 0b1011, 1, 2, 2).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_rol_register_amount_when_dst_is_src() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Rol {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shld_register_amount_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Reg(x(2)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shrd_flag_setting_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_shld_w16_imm_as_shift_bfxil_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(5),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 27, 26, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b01, 11, 15, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shld_w16_masked_zero_count_as_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(32),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shld_w8_imm_as_shift_bfxil_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(3),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 29, 28, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b01, 5, 7, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shld_w8_masked_zero_count_as_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(32),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w8_imm_as_shift_bfi_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(3),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 3, 31, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b01, 27, 2, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w8_masked_zero_count_as_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(32),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w16_imm_as_shift_bfi_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(5),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 5, 31, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b01, 21, 4, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w16_masked_zero_count_as_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(32),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shld_w16_full_count_alias_as_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(16),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w16_full_count_alias_as_uxth() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(16),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shld_w8_full_count_alias_as_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(8),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_shrd_w8_full_count_alias_as_uxtb() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(8),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_shld_w16_count_greater_than_width() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(17),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shrd_w16_count_greater_than_width() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(17),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shld_w8_count_greater_than_width() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(9),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shrd_w8_count_greater_than_width() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(1),
                amount: SrcOperand::Imm(9),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shld_w16_aliased_nonzero_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(1),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shld_w8_aliased_nonzero_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shld {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(1),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shrd_w8_aliased_nonzero_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(1),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_shrd_w16_aliased_nonzero_count() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Shrd {
                dst: x(0),
                src: x(0),
                amount: SrcOperand::Imm(1),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_ctz_w8_as_sentinel_rbit_clz() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Ctz {
                dst: x(0),
                src: x(1),
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b01, 0, 24, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000000, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_ctz_w16_as_sentinel_rbit_clz() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Ctz {
                dst: x(0),
                src: x(1),
                width: OpWidth::W16,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b01, 0, 16, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000000, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_bsf_flag_setting_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsf {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_bsf_w16_as_sentinel_rbit_clz_ubfx() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsf {
                dst: x(0),
                src: x(1),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b01, 0, 16, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000000, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 3, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bsf_w8_as_sentinel_rbit_clz_ubfx() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsf {
                dst: x(0),
                src: x(1),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_logical_imm(0, 0b01, 0, 24, 0, 0, 1).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000000, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 2, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_bsr_flag_setting_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsr {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn lowers_bsr_w16_as_ubfx_orr_clz_eor_mask() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsr {
                dst: x(0),
                src: x(1),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 15, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_logical_imm(0, 0b01, 0, 0, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_logical_imm(0, 0b10, 0, 0, 4, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn lowers_bsr_w8_as_ubfx_orr_clz_eor_mask() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Bsr {
                dst: x(0),
                src: x(1),
                width: OpWidth::W8,
                flags: FlagUpdate::None,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.lower_function(&func).unwrap();
        let code = lowerer.finalize().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&enc_bitfield_regs(0, 0b10, 0, 7, 1, 0).to_le_bytes());
        expected.extend_from_slice(&enc_logical_imm(0, 0b01, 0, 0, 0, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_dp1_regs(0, 0b000100, 0, 0).to_le_bytes());
        expected.extend_from_slice(&enc_logical_imm(0, 0b10, 0, 0, 4, 0, 0).to_le_bytes());
        expected.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert_eq!(code, expected);
    }

    #[test]
    fn rejects_truncate_w128_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Truncate {
                dst: x(0),
                src: x(1),
                from_width: OpWidth::W128,
                to_width: OpWidth::W128,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_setcc_parity_condition_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::SetCC {
                dst: x(0),
                cond: Condition::Parity,
                width: OpWidth::W8,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_setcc_w128_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::SetCC {
                dst: x(0),
                cond: Condition::Ne,
                width: OpWidth::W128,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_cmove_parity_condition_lowering() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::CMove {
                dst: x(0),
                src: x(1),
                cond: Condition::Parity,
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_flag_setting_inc_dec_lowering() {
        for kind in [
            OpKind::Inc {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            OpKind::Dec {
                dst: x(0),
                src: x(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ] {
            let mut builder = FunctionBuilder::new(FunctionId(0), 0);
            builder.push_op(0, kind);
            builder.set_terminator(Terminator::Return { values: vec![] });
            let func = builder.finish();

            let mut lowerer = Aarch64Lowerer::new();
            let err = lowerer.lower_function(&func).unwrap_err();
            assert!(matches!(err, LowerError::UnsupportedOp { .. }));
        }
    }

    #[test]
    fn rejects_lea_unsupported_scale() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Lea {
                dst: x(0),
                addr: Address::BaseIndexScale {
                    base: Some(x(1)),
                    index: x(2),
                    scale: 3,
                    disp: 0,
                    disp_size: DispSize::Auto,
                },
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }

    #[test]
    fn rejects_lea_gprel_address() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        builder.push_op(
            0,
            OpKind::Lea {
                dst: x(0),
                addr: Address::GpRel { offset: 4 },
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut lowerer = Aarch64Lowerer::new();
        let err = lowerer.lower_function(&func).unwrap_err();
        assert!(matches!(err, LowerError::UnsupportedOp { .. }));
    }
}

//! Branch, call, and return lowering

use crate::smir::lower::aarch64::*;
use std::collections::HashMap;

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    ArmDpRegShiftKind, OpKind, SmirOp, X86AdxKind, X86BlsKind, X86CountKind,
};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, AtomicOp, Avx10FP16Op, BlockId, Condition, ExtendOp, FenceKind,
    FpPrecision, FpRoundMode, MemWidth, MemoryOrder, OpWidth, ShiftOp, SignExtend, SrcOperand,
    VLaneOp, VReg, VecElementType, VecPermuteKind, VecReduceOp, VecUnaryOp, VecWidth,
};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

use super::{CodeBuffer, LowerError, LowerResult, Relocation, SmirLowerer};

impl Aarch64Lowerer {
    /// Lower direct, argument-free guest calls as native frontier exits.
    ///
    /// The call block's ordinary operations execute first (including guest
    /// link-register materialization), then the exit stub records the direct
    /// target PC and returns to the runtime trampoline. This requires X28 to
    /// hold the runtime state pointer. Cross-lowered AArch32/Thumb callers must
    /// validate the function with the AArch32 native clobber gate first.
    pub fn set_guest_call_exits(&mut self, enable: bool) {
        self.guest_call_exits = enable;
    }

    /// Lower structurally validated AArch32 direct/register BLX calls as
    /// interworking dispatcher exits. This mode must be paired with the
    /// AArch32 native clobber gate.
    pub fn set_guest_interworking_call_exits(&mut self, enable: bool) {
        self.guest_interworking_call_exits = enable;
    }

    /// `blr Xn` — call through a register, setting the link register (x30).
    pub(crate) fn emit_blr_reg(&mut self, rn: u8) {
        self.emit(0xd63f_0000 | ((rn as u32) << 5));
    }

    pub(crate) fn emit_branch_placeholder(&mut self, target: BlockId) {
        let offset = self.code.position();
        self.emit(0x1400_0000);
        self.branch_fixups.push(BranchFixup {
            offset,
            target,
            kind: BranchFixupKind::Uncond,
        });
    }

    pub(crate) fn emit_cond_branch_placeholder(&mut self, cond: u32, target: BlockId) {
        let offset = self.code.position();
        self.emit(0x5400_0000 | (cond & 0xf));
        self.branch_fixups.push(BranchFixup {
            offset,
            target,
            kind: BranchFixupKind::Cond { cond: cond & 0xf },
        });
    }

    pub(crate) fn emit_compare_branch_placeholder(
        &mut self,
        rt: u8,
        nonzero: bool,
        target: BlockId,
    ) {
        let offset = self.code.position();
        self.emit(if nonzero { 0xb500_0000 } else { 0xb400_0000 } | (rt as u32));
        self.branch_fixups.push(BranchFixup {
            offset,
            target,
            kind: BranchFixupKind::CompareAndBranch { rt, nonzero },
        });
    }

    pub(crate) fn branch_scaled_imm(
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

    pub(crate) fn fixup_branches(&mut self) -> Result<(), LowerError> {
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

    pub(crate) fn patch_branch_to_current(&mut self, insn_offset: usize) -> Result<(), LowerError> {
        let target = self.code.position();
        let imm26 = Self::branch_scaled_imm(insn_offset, target, 26)?;
        self.code
            .patch_i32(insn_offset, (0x1400_0000 | imm26) as i32);
        Ok(())
    }

    pub(crate) fn patch_compare_branch_to_current(
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

    pub(crate) fn patch_cond_branch_to_current(
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

    pub(crate) fn emit_branch_to_offset(&mut self, target_offset: usize) -> Result<(), LowerError> {
        let offset = self.code.position();
        let imm26 = Self::branch_scaled_imm(offset, target_offset, 26)?;
        self.emit(0x1400_0000 | imm26);
        Ok(())
    }

    pub(crate) fn emit_compare_branch_to_offset(
        &mut self,
        rt: u8,
        nonzero: bool,
        target_offset: usize,
    ) -> Result<(), LowerError> {
        let offset = self.code.position();
        let imm19 = Self::branch_scaled_imm(offset, target_offset, 19)?;
        let base = if nonzero { 0xb500_0000 } else { 0xb400_0000 };
        self.emit(base | (imm19 << 5) | (rt as u32));
        Ok(())
    }

    pub(crate) fn emit_test_branch(
        &mut self,
        rt: u8,
        bit: u32,
        nonzero: bool,
        offset: i32,
    ) -> Result<(), LowerError> {
        self.emit(Self::test_branch_word(rt, bit, nonzero, offset)?);
        Ok(())
    }

    pub(crate) fn test_branch_word(
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
        Ok((b5 << 31)
            | (0b011011 << 25)
            | ((nonzero as u32) << 24)
            | (b40 << 19)
            | (((imm14 as u32) & 0x3fff) << 5)
            | (rt as u32))
    }

    pub(crate) fn patch_test_branch_to_current(
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

    pub(crate) fn lower_cond_branch(
        &mut self,
        source: BlockId,
        cond: VReg,
        true_target: BlockId,
        false_target: BlockId,
        folded_cond: Option<Condition>,
    ) -> Result<(), LowerError> {
        if true_target == false_target {
            return self.lower_branch_edge(source, true_target);
        }

        if let Some(cond) = folded_cond {
            if cond == Condition::Always {
                return self.lower_branch_edge(source, true_target);
            }
            let native_cond = Self::arm_cond_code(cond)?;
            if let Some(resume_pc) = self.native_exit_edges.get(&(source, true_target)).copied() {
                // If the true edge exits, invert the condition to skip the
                // inline exit stub on the false path.
                let skip_exit = self.code.position();
                self.emit(0x5400_0000 | ((native_cond ^ 1) & 0xf));
                self.emit_native_exit(resume_pc)?;
                self.patch_cond_branch_to_current(skip_exit, native_cond ^ 1)?;
            } else {
                self.emit_cond_branch_placeholder(native_cond, true_target);
            }
            return self.lower_branch_edge(source, false_target);
        }

        if let VReg::Imm(value) = cond {
            return self.lower_branch_edge(
                source,
                if value == 0 {
                    false_target
                } else {
                    true_target
                },
            );
        }

        let cond_reg = Self::gpr_arm_or_x86(cond)?;
        if let Some(resume_pc) = self.native_exit_edges.get(&(source, true_target)).copied() {
            // CBZ skips the true-edge exit stub when the materialized
            // condition is false.
            let skip_exit = self.code.position();
            self.emit(0xb400_0000 | (cond_reg as u32));
            self.emit_native_exit(resume_pc)?;
            self.patch_compare_branch_to_current(skip_exit, cond_reg, false)?;
        } else {
            self.emit_compare_branch_placeholder(cond_reg, true, true_target);
        }
        self.lower_branch_edge(source, false_target)
    }

    pub(crate) fn lower_branch_edge(
        &mut self,
        source: BlockId,
        target: BlockId,
    ) -> Result<(), LowerError> {
        if let Some(resume_pc) = self.native_exit_edges.get(&(source, target)).copied() {
            self.emit_native_exit(resume_pc)
        } else {
            self.emit_branch_placeholder(target);
            Ok(())
        }
    }

    pub(crate) fn folded_branch_condition(block: &SmirBlock) -> (Option<usize>, Option<Condition>) {
        let Terminator::CondBranch {
            cond: branch_cond, ..
        } = &block.terminator
        else {
            return (None, None);
        };
        // Retirement does not change NZCV. A framed B.cond puts its pure
        // condition immediately before Commit; retain that Commit while
        // folding the condition into the native branch instruction.
        let Some((
            index,
            SmirOp {
                kind: OpKind::TestCondition { dst, cond },
                ..
            },
        )) = block
            .ops
            .iter()
            .enumerate()
            .rev()
            .find(|(_, op)| !matches!(op.kind, OpKind::ArmInstructionCommit { .. }))
        else {
            return (None, None);
        };
        if dst == branch_cond && matches!(dst, VReg::Virtual(_)) {
            (Some(index), Some(*cond))
        } else {
            (None, None)
        }
    }
}

//! AArch64 instruction lifter.
//!
//! This module lifts AArch64 machine code to SMIR using the existing ARM decoder.

use std::collections::HashSet;

use crate::isa::arm::decoder::{
    AddressingMode, Condition as ArmCondition, DecodedInsn, ExtendType, FpRegSize, FpRegister,
    MemOffset, MemOperand, Mnemonic, Operand, Register, ShiftType,
};
use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::memory::MemoryError;
use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::*;
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
};
use crate::smir::lift::{ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader};

// ---- module tree (auto-split) ----
mod advanced_simd;
mod alu;
mod comparisons;
pub(crate) use alu::*;
mod control;
pub(crate) use control::*;
mod dispatch;
pub(crate) use dispatch::*;
mod fp;
mod memory;
mod resize;
mod saturating;
mod scalar_simd;
pub(crate) use memory::*;
mod misc;
mod pauth;
#[cfg(test)]
mod pauth_tests;
pub(crate) use misc::*;
mod simd;
pub(crate) use simd::*;
mod system;
pub(crate) use system::*;

const NZCV_N: i64 = 1_i64 << 31;
const NZCV_Z: i64 = 1_i64 << 30;
const NZCV_C: i64 = 1_i64 << 29;
const NZCV_V: i64 = 1_i64 << 28;
const NZCV_MASK: i64 = NZCV_N | NZCV_Z | NZCV_C | NZCV_V;
const FPCR_SYSREG_MASK: i64 = 0x07c8_0007;
const FPSR_SYSREG_MASK: i64 = 0xf800_009f;
const MTE_TAG_CLEAR_MASK: i64 = (!0x0f00_0000_0000_0000u64) as i64;
const SYSREG_NZCV: u16 = (3 << 14) | (3 << 11) | (4 << 7) | (2 << 3);
const SYSREG_FPCR: u16 = (3 << 14) | (3 << 11) | (4 << 7) | (4 << 3);
const SYSREG_FPSR: u16 = (3 << 14) | (3 << 11) | (4 << 7) | (4 << 3) | 1;

// ============================================================================
// AArch64 Lifter
// ============================================================================

#[derive(Clone, Copy)]
enum CondSelectFalseOp {
    Identity,
    Increment,
    Invert,
    Negate,
}

#[derive(Clone, Copy)]
enum RevKind {
    Full,
    Halfwords,
    Words,
}

#[derive(Clone, Copy)]
struct SysRegAccess {
    reg: ArmReg,
    mask: i64,
    read_width: OpWidth,
    write_width: OpWidth,
}

#[derive(Clone, Copy)]
enum BitfieldKind {
    Extract { sign_extend: bool },
    Insert,
    InsertLow,
    InsertZero { sign_extend: bool },
}

/// AArch64 instruction lifter
pub struct Aarch64Lifter {
    /// Whether to use strict mode (fail on unsupported instructions)
    strict: bool,
}

impl Default for Aarch64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SmirLifter Implementation
// ============================================================================

impl crate::smir::lift::SmirLifter for Aarch64Lifter {
    fn source_arch(&self) -> SourceArch {
        SourceArch::Aarch64
    }

    fn lift_insn(
        &mut self,
        addr: GuestAddr,
        bytes: &[u8],
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        use crate::isa::arm::decoder::aarch64::Aarch64Decoder;

        if bytes.len() < 4 {
            return Err(LiftError::Incomplete {
                addr,
                have: bytes.len(),
                need: 4,
            });
        }

        // Decode the 32-bit instruction
        let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let insn = Aarch64Decoder::decode(raw).map_err(|_| LiftError::InvalidEncoding {
            addr,
            bytes: bytes[..4].to_vec(),
        })?;

        ctx.guest_pc = addr;
        let (mut ops, control_flow) = if ctx.aarch64_features.is_some()
            && let Some(operation) = crate::smir::ir::ops::ArmPauthOp::decode(raw)
        {
            self.lift_pauth(operation, addr, ctx)
        } else {
            self.lift_insn_inner(&insn, addr, ctx)?
        };
        if let Some(features) = ctx.aarch64_features {
            self.frame_instruction(raw, addr, features.bits(), &mut ops, &control_flow, ctx);
        }

        let mut branch_targets = Vec::new();
        match &control_flow {
            ControlFlow::Branch { target } => {
                branch_targets.push(*target);
            }
            ControlFlow::CondBranch {
                target,
                fallthrough,
                ..
            } => {
                branch_targets.push(*target);
                branch_targets.push(*fallthrough);
            }
            ControlFlow::CondBranchReg {
                taken, not_taken, ..
            } => {
                branch_targets.push(*taken);
                branch_targets.push(*not_taken);
            }
            ControlFlow::Call {
                target: CallTarget::GuestAddr(target),
            } => {
                branch_targets.push(*target);
            }
            _ => {}
        }

        Ok(LiftResult {
            ops,
            bytes_consumed: 4,
            control_flow,
            branch_targets,
        })
    }

    fn lift_block(
        &mut self,
        addr: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirBlock, LiftError> {
        let block_id = ctx.get_or_create_block(addr);
        let mut all_ops = Vec::new();
        let mut current_addr = addr;

        loop {
            let bytes = mem
                .read(current_addr, 4)
                .map_err(|e| LiftError::MemoryError {
                    addr: current_addr,
                    error: e,
                })?;

            let result = self.lift_insn(current_addr, &bytes, ctx)?;
            all_ops.extend(result.ops);
            current_addr += result.bytes_consumed as u64;

            if result.control_flow.ends_block() {
                let terminator = match result.control_flow {
                    ControlFlow::Fallthrough | ControlFlow::NextInsn => unreachable!(),
                    ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
                        Terminator::Branch {
                            target: ctx.get_or_create_block(target),
                        }
                    }
                    ControlFlow::CondBranch {
                        cond,
                        target,
                        fallthrough,
                    } => {
                        let cond_vreg = ctx.alloc_vreg();
                        let operation = SmirOp::new(
                            ctx.next_op_id(),
                            current_addr - result.bytes_consumed as u64,
                            OpKind::TestCondition {
                                dst: cond_vreg,
                                cond,
                            },
                        );
                        if ctx.aarch64_features.is_some() {
                            let before_commit = all_ops.len() - 1;
                            all_ops.insert(before_commit, operation);
                        } else {
                            all_ops.push(operation);
                        }
                        Terminator::CondBranch {
                            cond: cond_vreg,
                            true_target: ctx.get_or_create_block(target),
                            false_target: ctx.get_or_create_block(fallthrough),
                        }
                    }
                    ControlFlow::CondBranchReg {
                        cond,
                        taken,
                        not_taken,
                    } => Terminator::CondBranch {
                        cond,
                        true_target: ctx.get_or_create_block(taken),
                        false_target: ctx.get_or_create_block(not_taken),
                    },
                    ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
                        target,
                        possible_targets: vec![],
                    },
                    ControlFlow::IndirectBranchMem { addr } => Terminator::IndirectBranchMem {
                        addr,
                        possible_targets: vec![],
                    },
                    ControlFlow::Call { target } => Terminator::Call {
                        target,
                        args: vec![],
                        continuation: ctx.get_or_create_block(current_addr),
                    },
                    ControlFlow::Return => Terminator::Return { values: vec![] },
                    ControlFlow::Trap { kind } => Terminator::Trap { kind },
                    ControlFlow::Syscall => Terminator::Trap {
                        kind: TrapKind::SystemCall,
                    },
                };

                return Ok(SmirBlock {
                    id: block_id,
                    guest_pc: addr,
                    phis: vec![],
                    ops: all_ops,
                    terminator,
                    exec_count: 0,
                });
            }
        }
    }

    fn lift_function(
        &mut self,
        entry: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirFunction, LiftError> {
        let func_id = FunctionId(ctx.known_functions.len() as u32);
        ctx.known_functions.insert(entry, func_id);

        let mut blocks = Vec::new();
        let mut worklist = vec![entry];
        let mut visited = HashSet::new();
        let mut min_addr = entry;
        let mut max_addr = entry;

        while let Some(addr) = worklist.pop() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);

            let block = self.lift_block(addr, mem, ctx)?;

            if block.guest_pc < min_addr {
                min_addr = block.guest_pc;
            }
            let block_end = block.guest_pc + (block.ops.len() * 4) as u64;
            if block_end > max_addr {
                max_addr = block_end;
            }

            for succ in block.successors() {
                if let Some(&succ_addr) = ctx
                    .block_cache
                    .iter()
                    .find(|(_, id)| **id == succ)
                    .map(|(addr, _)| addr)
                {
                    if !visited.contains(&succ_addr) {
                        worklist.push(succ_addr);
                    }
                }
            }

            blocks.push(block);
        }

        Ok(SmirFunction {
            id: func_id,
            entry: ctx.get_or_create_block(entry),
            blocks,
            locals: vec![],
            guest_range: (min_addr, max_addr),
            calling_convention: CallingConv::Aarch64Aapcs,
            attrs: FunctionAttrs::default(),
            x86_instruction_bytes: std::collections::HashMap::new(),
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::lift::SmirLifter;

    struct MockMemory {
        data: Vec<u8>,
        base: GuestAddr,
    }

    impl MemoryReader for MockMemory {
        fn read(&self, addr: GuestAddr, size: usize) -> Result<Vec<u8>, MemoryError> {
            let offset = (addr - self.base) as usize;
            if offset + size > self.data.len() {
                return Err(MemoryError::OutOfBounds { addr });
            }
            Ok(self.data[offset..offset + size].to_vec())
        }
    }

    #[test]
    fn test_aarch64_lifter_add() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);

        // ADD X0, X1, X2 => 0x8b020020
        let bytes = [0x20, 0x00, 0x02, 0x8b];
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert!(!result.ops.is_empty());
        match &result.ops[0].kind {
            OpKind::Add { width, .. } => {
                assert_eq!(*width, OpWidth::W64);
            }
            _ => panic!("Expected Add operation"),
        }
    }

    #[test]
    fn test_lift_long_multiply_negative_aliases() {
        for bytes in [
            0x9b22_fc20u32.to_le_bytes(), // SMNEGL X0, W1, W2
            0x9ba2_fc20u32.to_le_bytes(), // UMNEGL X0, W1, W2
        ] {
            let (ops, _) = lift_single(bytes);
            assert!(ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Sub {
                    src1: VReg::Imm(0),
                    width: OpWidth::W64,
                    ..
                }
            )));
        }
    }

    #[test]
    fn test_lift_ngc_aliases_subtract_from_zero() {
        for bytes in [
            0xda01_03e0u32.to_le_bytes(), // NGC X0, X1
            0x7a01_03e0u32.to_le_bytes(), // NGCS W0, W1
        ] {
            let (ops, _) = lift_single(bytes);
            assert!(ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Sbb {
                    src1: VReg::Imm(0),
                    ..
                }
            )));
        }
    }

    #[test]
    fn test_lift_bfxil_xzr_source_extract_low_shape() {
        let (ops, _) = lift_single(0xb341_07e0u32.to_le_bytes()); // BFXIL X0, XZR, #1, #1

        assert!(ops.iter().any(|op| matches!(
            op.kind,
            OpKind::Bfx {
                lsb: 1,
                width_bits: 1,
                sign_extend: false,
                op_width: OpWidth::W64,
                ..
            }
        )));
        assert!(ops.iter().any(|op| matches!(
            op.kind,
            OpKind::Bfi {
                lsb: 0,
                width_bits: 1,
                op_width: OpWidth::W64,
                ..
            }
        )));
    }

    #[test]
    fn test_lift_shifted_neg_aliases_as_sub_from_zero() {
        for (bytes, flags) in [
            (0xcb01_07e0u32.to_le_bytes(), FlagUpdate::None), // NEG X0, X1, LSL #1
            (0xeb81_0fe0u32.to_le_bytes(), FlagUpdate::All),  // NEGS X0, X1, ASR #3
        ] {
            let (ops, _) = lift_single(bytes);
            assert!(ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Sub {
                    src1: VReg::Imm(0),
                    src2: SrcOperand::Shifted { .. },
                    width: OpWidth::W64,
                    flags: actual_flags,
                    ..
                } if actual_flags == flags
            )));
        }
    }

    #[test]
    fn test_lift_shifted_mvn_aliases_materialize_source() {
        for (bytes, width) in [
            (0xaa21_07e0u32.to_le_bytes(), OpWidth::W64), // MVN X0, X1, LSL #1
            (0x2aa1_0fe0u32.to_le_bytes(), OpWidth::W32), // MVN W0, W1, ASR #3
        ] {
            let (ops, _) = lift_single(bytes);
            assert!(ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Mov {
                    src: SrcOperand::Shifted { .. },
                    width: actual_width,
                    ..
                } if actual_width == width
            )));
            assert!(ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Not {
                    width: actual_width,
                    ..
                } if actual_width == width
            )));
        }
    }

    #[test]
    fn test_lift_lrcpc3_pair_forms() {
        fn pair(mode: u32, l: u32) -> [u8; 4] {
            ((0b11 << 30) | (0b101 << 27) | (mode << 23) | (l << 22) | (2 << 10) | (1 << 5))
                .to_le_bytes()
        }

        let (ops, _) = lift_single(pair(0b10, 1));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::LoadPair {
                    width: MemWidth::B8,
                    ..
                }
            )),
            "LDTP must lift as a 64-bit LoadPair"
        );

        let (ops, _) = lift_single(pair(0b10, 0));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::StorePair {
                    width: MemWidth::B8,
                    ..
                }
            )),
            "STTP must lift as a 64-bit StorePair"
        );
    }

    #[test]
    fn test_lift_ordered_unscaled_forms() {
        fn ordered(size: u32, opc: u32) -> [u8; 4] {
            ((size << 30) | (0b011001 << 24) | (opc << 22) | (1 << 5)).to_le_bytes()
        }

        let (ops, _) = lift_single(ordered(0b11, 0b01));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Load {
                    width: MemWidth::B8,
                    sign: SignExtend::Zero,
                    ..
                }
            )),
            "LDAPUR X must lift as a zero-extending 64-bit Load"
        );

        let (ops, _) = lift_single(ordered(0b10, 0b10));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Load {
                    width: MemWidth::B4,
                    sign: SignExtend::Sign,
                    ..
                }
            )),
            "LDAPURSW must lift as a sign-extending 32-bit Load"
        );

        let (ops, _) = lift_single(ordered(0b00, 0b00));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Store {
                    width: MemWidth::B1,
                    ..
                }
            )),
            "STLURB must lift as a byte Store"
        );
    }

    #[test]
    fn test_lift_unprivileged_load_store_forms() {
        fn unprivileged(size: u32, opc: u32) -> [u8; 4] {
            ((size << 30) | (0b111 << 27) | (opc << 22) | (0b10 << 10) | (1 << 5)).to_le_bytes()
        }

        let (ops, _) = lift_single(unprivileged(0b11, 0b01));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Load {
                    width: MemWidth::B8,
                    sign: SignExtend::Zero,
                    ..
                }
            )),
            "LDTR X must lift as a zero-extending 64-bit Load"
        );

        let (ops, _) = lift_single(unprivileged(0b10, 0b10));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Load {
                    width: MemWidth::B4,
                    sign: SignExtend::Sign,
                    ..
                }
            )),
            "LDTRSW must lift as a sign-extending 32-bit Load"
        );

        let (ops, _) = lift_single(unprivileged(0b00, 0b00));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Store {
                    width: MemWidth::B1,
                    ..
                }
            )),
            "STTRB must lift as a byte Store"
        );
    }

    #[test]
    fn test_lift_ldapr_forms() {
        fn ldapr(size: u32) -> [u8; 4] {
            ((size << 30)
                | (0b111 << 27)
                | (1 << 23)
                | (1 << 21)
                | (31 << 16)
                | (1 << 15)
                | (0b100 << 12)
                | (1 << 5))
                .to_le_bytes()
        }

        let (ops, _) = lift_single(ldapr(0b00));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Load {
                    width: MemWidth::B1,
                    sign: SignExtend::Zero,
                    ..
                }
            )),
            "LDAPRB must lift as a byte Load"
        );

        let (ops, _) = lift_single(ldapr(0b11));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Load {
                    width: MemWidth::B8,
                    sign: SignExtend::Zero,
                    ..
                }
            )),
            "LDAPR X must lift as a 64-bit Load"
        );
    }

    #[test]
    fn test_lift_loregion_ordered_forms() {
        fn loregion(size: u32, load: bool) -> [u8; 4] {
            let l = if load { 1 } else { 0 };
            ((size << 30)
                | (0b001000 << 24)
                | (1 << 23)
                | (l << 22)
                | (31 << 16)
                | (31 << 10)
                | (1 << 5))
                .to_le_bytes()
        }

        let (ops, _) = lift_single(loregion(0b00, true));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Load {
                    width: MemWidth::B1,
                    sign: SignExtend::Zero,
                    ..
                }
            )),
            "LDLARB must lift as a byte Load"
        );

        let (ops, _) = lift_single(loregion(0b11, false));
        assert!(
            ops.iter().any(|op| matches!(
                op.kind,
                OpKind::Store {
                    width: MemWidth::B8,
                    ..
                }
            )),
            "STLLR X must lift as a 64-bit Store"
        );
    }

    // Regression for issue #28: an across-vector integer reduction with a reserved
    // arrangement (here SADDLV with Q=0, size=0b10 = 2S) must NOT lift to a native
    // across-lanes op — that would be an invalid host encoding and SIGILL if
    // executed. It must bail (Unsupported) so the interpreter treats it as
    // UNDEFINED. The valid 4S form (Q=1, size=0b10) must still lift.
    #[test]
    fn issue_28_rejects_reserved_2s_across_lanes_reduction() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);

        // SADDLV ..., V0.2S  (Q=0, size=0b10): reserved.
        let saddlv_2s = 0x0EB0_3800u32.to_le_bytes();
        assert!(
            lifter.lift_insn(0x2000, &saddlv_2s, &mut ctx).is_err(),
            "SADDLV with Q=0,size=0b10 (2S) is reserved and must not lift natively"
        );

        // SADDLV ..., V0.4S  (Q=1, size=0b10): valid — still lifts to a VReduce.
        let saddlv_4s = 0x4EB0_3800u32.to_le_bytes();
        let result = lifter
            .lift_insn(0x2000, &saddlv_4s, &mut ctx)
            .expect("SADDLV 4S must lift");
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op.kind, OpKind::VReduce { .. })),
            "SADDLV 4S must lift to a VReduce op"
        );
    }

    // Regression for issue #55: vector REV reverses elements within a container, so
    // the element size must be strictly smaller than the container. Reserved forms
    // (REV16 with >=halfword elements, REV64 with doubleword elements) must NOT lift
    // to a native two-reg-misc op (which would be an undefined host encoding =
    // SIGILL); they must bail to the interpreter. Valid forms still lift. (#55)
    #[test]
    fn issue_55_rejects_invalid_vector_rev_arrangements() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);

        // REV16 with halfword elements (size=0b01): reserved.
        assert!(
            lifter
                .lift_insn(0x3000, &0x0E60_1800u32.to_le_bytes(), &mut ctx)
                .is_err(),
            "REV16 with halfword elements is reserved and must not lift natively"
        );
        // REV64 with doubleword elements (size=0b11): reserved.
        assert!(
            lifter
                .lift_insn(0x3000, &0x0EE0_0800u32.to_le_bytes(), &mut ctx)
                .is_err(),
            "REV64 with doubleword elements is reserved and must not lift natively"
        );

        // REV16 with byte elements (size=0b00): valid — still lifts to a VUnary.
        let result = lifter
            .lift_insn(0x3000, &0x0E20_1800u32.to_le_bytes(), &mut ctx)
            .expect("REV16.8B must lift");
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op.kind, OpKind::VUnary { .. })),
            "REV16.8B must lift to a VUnary op"
        );
    }

    // Regression for issue #54: an FP-vector unary (FABS/FNEG/FSQRT) with sz=1, Q=0
    // is the reserved 1D arrangement. It must NOT lift (the lowerer would re-derive
    // Q from elem*lanes and emit a valid 2D op for the invalid encoding); it must
    // bail to the interpreter. Valid 2D and 2S forms still lift. (#54)
    #[test]
    fn issue_54_rejects_reserved_1d_fp_vector_unary() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);

        // FABS V0.1D, V0.1D (sz=1, Q=0): reserved.
        assert!(
            lifter
                .lift_insn(0x4000, &0x0EE0_F800u32.to_le_bytes(), &mut ctx)
                .is_err(),
            "FABS with 1D arrangement (sz=1,Q=0) is reserved and must not lift natively"
        );

        // FABS V0.2D (sz=1, Q=1): valid — lifts to a VUnary.
        let r2d = lifter
            .lift_insn(0x4000, &0x4EE0_F800u32.to_le_bytes(), &mut ctx)
            .expect("FABS.2D must lift");
        assert!(
            r2d.ops
                .iter()
                .any(|op| matches!(op.kind, OpKind::VUnary { .. })),
            "FABS.2D must lift to a VUnary op"
        );

        // FABS V0.2S (sz=0, Q=0): valid — Q=0 alone must not be rejected.
        let r2s = lifter
            .lift_insn(0x4000, &0x0EA0_F800u32.to_le_bytes(), &mut ctx)
            .expect("FABS.2S must lift");
        assert!(
            r2s.ops
                .iter()
                .any(|op| matches!(op.kind, OpKind::VUnary { .. })),
            "FABS.2S must lift to a VUnary op"
        );
    }

    #[test]
    fn test_aarch64_lifter_mov_imm() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);

        // MOV X0, #0x1234 => MOVZ X0, #0x1234 => 0xd2824680
        let bytes = [0x80, 0x46, 0x82, 0xd2];
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert!(!result.ops.is_empty());
    }

    #[test]
    fn test_aarch64_lifter_branch() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);

        // B #0x10 => 0x14000004
        let bytes = [0x04, 0x00, 0x00, 0x14];
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        match result.control_flow {
            ControlFlow::Branch { target } => {
                assert_eq!(target, 0x1010);
            }
            _ => panic!("Expected Branch control flow"),
        }
    }

    #[test]
    fn test_lift_block_cond_branch_defines_condition() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);

        // B.EQ #8 => 0x54000040
        let mem = MockMemory {
            data: vec![0x40, 0x00, 0x00, 0x54],
            base: 0x1000,
        };
        let block = lifter.lift_block(0x1000, &mem, &mut ctx).unwrap();

        let cond_def = block
            .ops
            .last()
            .expect("conditional branch should define a condition vreg");
        let OpKind::TestCondition {
            dst,
            cond: Condition::Eq,
        } = &cond_def.kind
        else {
            panic!("expected TestCondition Eq, got {:?}", cond_def.kind);
        };
        let Terminator::CondBranch { cond, .. } = block.terminator else {
            panic!("expected conditional branch terminator");
        };
        assert_eq!(cond, *dst);
    }

    #[test]
    fn test_lift_context_aarch64() {
        let ctx = LiftContext::new(SourceArch::Aarch64);
        assert_eq!(ctx.endian, Endian::Little);
    }

    #[test]
    fn test_lift_wfxt_as_nop() {
        for bytes in [[0x00, 0x10, 0x03, 0xd5], [0x21, 0x10, 0x03, 0xd5]] {
            let (ops, control) = lift_single(bytes);
            assert_eq!(ops.len(), 1);
            assert!(matches!(ops[0].kind, OpKind::Nop));
            assert!(matches!(control, ControlFlow::Fallthrough));
        }
    }

    #[test]
    fn test_lift_dgh_as_nop() {
        let (ops, control) = lift_single([0xdf, 0x20, 0x03, 0xd5]);
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0].kind, OpKind::Nop));
        assert!(matches!(control, ControlFlow::Fallthrough));
    }

    fn lift_single(bytes: [u8; 4]) -> (Vec<SmirOp>, ControlFlow) {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();
        (result.ops, result.control_flow)
    }

    fn assert_mnemonic_unsupported(mnemonic: Mnemonic) {
        let lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);
        let insn = DecodedInsn::new(mnemonic, crate::isa::arm::ExecutionState::Aarch64, 0, 4);
        let err = lifter.lift_insn_inner(&insn, 0x1000, &mut ctx).unwrap_err();
        assert!(
            matches!(err, LiftError::Unsupported { .. }),
            "{mnemonic:?} must not lift as a NOP or unauthenticated branch: {err:?}"
        );
    }

    #[test]
    fn issue_44_rejects_pointer_authentication_lifts() {
        for mnemonic in [
            Mnemonic::BLRAA,
            Mnemonic::BLRAB,
            Mnemonic::RETAA,
            Mnemonic::RETAB,
            Mnemonic::PACIA,
            Mnemonic::PACIB,
            Mnemonic::PACDA,
            Mnemonic::PACDB,
            Mnemonic::AUTIA,
            Mnemonic::AUTIB,
            Mnemonic::AUTDA,
            Mnemonic::AUTDB,
            Mnemonic::PACIZA,
            Mnemonic::PACIZB,
            Mnemonic::PACDZA,
            Mnemonic::PACDZB,
            Mnemonic::AUTIZA,
            Mnemonic::AUTIZB,
            Mnemonic::AUTDZA,
            Mnemonic::AUTDZB,
            Mnemonic::XPACI,
            Mnemonic::XPACD,
            Mnemonic::PACGA,
        ] {
            assert_mnemonic_unsupported(mnemonic);
        }
    }

    #[test]
    fn issue_44_rejects_tag_generation_lifts() {
        for mnemonic in [
            Mnemonic::SUBP,
            Mnemonic::SUBPS,
            Mnemonic::IRG,
            Mnemonic::GMI,
        ] {
            assert_mnemonic_unsupported(mnemonic);
        }
    }

    #[test]
    fn test_rejects_casp_pair_lifts() {
        fn casp(l: u32, o0: u32) -> [u8; 4] {
            ((0b001000 << 24)
                | (l << 22)
                | (1 << 21)
                | (2 << 16)
                | (o0 << 15)
                | (0b11111 << 10)
                | (1 << 5)
                | 4)
            .to_le_bytes()
        }

        for (l, o0) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            let (ops, control) = lift_single(casp(l, o0));
            assert!(ops.is_empty());
            assert!(matches!(
                control,
                ControlFlow::Trap {
                    kind: TrapKind::Undefined
                }
            ));
        }
    }

    #[test]
    fn test_lift_fadd_scalar() {
        let (ops, _) = lift_single([0x20, 0x28, 0x22, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FAdd { precision, .. } => assert_eq!(*precision, FpPrecision::F32),
            other => panic!("expected FAdd, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fadd_scalar_d() {
        // fadd d0, d1, d2  (0x1e622820); was previously the FDIV-double encoding,
        // which only decoded as FADD due to the scrambled 2-source opcode table.
        let (ops, _) = lift_single([0x20, 0x28, 0x62, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FAdd { precision, .. } => assert_eq!(*precision, FpPrecision::F64),
            other => panic!("expected FAdd F64, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fsub_scalar() {
        // fsub s0, s1, s2  (0x1e223820); was the FMIN encoding under the old bug.
        let (ops, _) = lift_single([0x20, 0x38, 0x22, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FSub { .. } => {}
            other => panic!("expected FSub, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fdiv_scalar() {
        // fdiv s0, s1, s2  (0x1e221820); was the FMAXNM encoding under the old bug.
        let (ops, _) = lift_single([0x20, 0x18, 0x22, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FDiv { .. } => {}
            other => panic!("expected FDiv, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fabs_scalar() {
        // fabs s0, s1 = 0x1e20c020 (opcode 000001). The earlier encoding
        // 0x1e214020 is actually FNEG (opcode 000010); it only decoded as FABS
        // under the old, buggy scalar FP 1-source table.
        let (ops, _) = lift_single([0x20, 0xc0, 0x20, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FAbs { precision, .. } => assert_eq!(*precision, FpPrecision::F32),
            other => panic!("expected FAbs, got {:?}", other),
        }
    }

    #[test]
    // fneg s0, s1 = 0x1e214020 (opcode 000010). The earlier encoding 0x1e244020
    // is actually FRINTN (opcode 001000); it only decoded as FNEG under the old,
    // buggy scalar FP 1-source table.
    fn test_lift_fneg_scalar() {
        let (ops, _) = lift_single([0x20, 0x40, 0x21, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FNeg { .. } => {}
            other => panic!("expected FNeg, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fsqrt_scalar() {
        let (ops, _) = lift_single([0x20, 0xc0, 0x21, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FSqrt { .. } => {}
            other => panic!("expected FSqrt, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_frintn_scalar() {
        let (ops, _) = lift_single([0x20, 0x40, 0x24, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FRound {
                precision, mode, ..
            } => {
                assert_eq!(*precision, FpPrecision::F32);
                assert_eq!(*mode, FpRoundMode::RoundNearest);
            }
            other => panic!("expected FRound, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fcvtas_scalar_uses_ties_away() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);
        let insn = DecodedInsn::new(
            Mnemonic::FCVTAS,
            crate::isa::arm::ExecutionState::Aarch64,
            0,
            4,
        )
        .with_operand(Operand::FpReg(FpRegister {
            num: 0,
            size: FpRegSize::S,
        }))
        .with_operand(Operand::FpReg(FpRegister {
            num: 1,
            size: FpRegSize::S,
        }));
        let ops = lifter.lift_insn_inner(&insn, 0x1000, &mut ctx).unwrap().0;
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FpToInt {
                fp_precision,
                int_width,
                signed,
                round,
                ..
            } => {
                assert_eq!(*fp_precision, FpPrecision::F32);
                assert_eq!(*int_width, OpWidth::W32);
                assert!(*signed);
                assert_eq!(*round, FpRoundMode::RoundNearestTiesAway);
            }
            other => panic!("expected FpToInt, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fcvtau_scalar_uses_ties_away() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);
        let insn = DecodedInsn::new(
            Mnemonic::FCVTAU,
            crate::isa::arm::ExecutionState::Aarch64,
            0,
            4,
        )
        .with_operand(Operand::FpReg(FpRegister {
            num: 0,
            size: FpRegSize::D,
        }))
        .with_operand(Operand::FpReg(FpRegister {
            num: 1,
            size: FpRegSize::D,
        }));
        let ops = lifter.lift_insn_inner(&insn, 0x1000, &mut ctx).unwrap().0;
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FpToInt {
                fp_precision,
                int_width,
                signed,
                round,
                ..
            } => {
                assert_eq!(*fp_precision, FpPrecision::F64);
                assert_eq!(*int_width, OpWidth::W64);
                assert!(!*signed);
                assert_eq!(*round, FpRoundMode::RoundNearestTiesAway);
            }
            other => panic!("expected FpToInt, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fmadd_scalar() {
        let (ops, _) = lift_single([0x20, 0x0c, 0x02, 0x1f]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FFma { precision, .. } => assert_eq!(*precision, FpPrecision::F32),
            other => panic!("expected FFma, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fcmp_scalar() {
        let (ops, _) = lift_single([0x20, 0x20, 0x22, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FCmp { precision, .. } => assert_eq!(*precision, FpPrecision::F32),
            other => panic!("expected FCmp, got {:?}", other),
        }
    }

    #[test]
    fn test_lift_fcsel_scalar() {
        let (ops, _) = lift_single([0x20, 0x1c, 0x22, 0x1e]);
        assert_eq!(ops.len(), 2);
        match &ops[0].kind {
            OpKind::Mov { width, .. } => assert_eq!(*width, OpWidth::W32),
            other => panic!("expected Mov, got {:?}", other),
        }
        match &ops[1].kind {
            OpKind::CMove { width, .. } => assert_eq!(*width, OpWidth::W32),
            other => panic!("expected CMove, got {:?}", other),
        }
    }

    #[test]
    fn issue_48_does_not_lift_fccmp_as_unconditional_compare() {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);
        let result = lifter
            .lift_insn(0x1000, &[0x27, 0x14, 0x22, 0x1e], &mut ctx)
            .unwrap();
        assert!(result.ops.is_empty());
        assert!(matches!(
            result.control_flow,
            ControlFlow::Trap {
                kind: TrapKind::Undefined
            }
        ));
    }

    #[test]
    fn test_lift_fcvt_s_to_d() {
        let (ops, _) = lift_single([0x20, 0xc0, 0x22, 0x1e]);
        assert_eq!(ops.len(), 1);
        match &ops[0].kind {
            OpKind::FConvert { from, to, .. } => {
                assert_eq!(*from, FpPrecision::F32);
                assert_eq!(*to, FpPrecision::F64);
            }
            other => panic!("expected FConvert S->D, got {:?}", other),
        }
    }
}

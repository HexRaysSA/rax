//! AArch64 instruction lifter.
//!
//! This module lifts AArch64 machine code to SMIR using the existing ARM decoder.

use std::collections::HashSet;

use crate::arm::decoder::{
    AddressingMode, Condition as ArmCondition, DecodedInsn, ExtendType, MemOffset, MemOperand,
    Mnemonic, Operand, Register, ShiftType,
};
use crate::smir::flags::FlagUpdate;
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
};
use crate::smir::lift::{ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader};
use crate::smir::memory::MemoryError;
use crate::smir::ops::{OpKind, SmirOp};
use crate::smir::types::*;

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

/// AArch64 instruction lifter
pub struct Aarch64Lifter {
    /// Whether to use strict mode (fail on unsupported instructions)
    strict: bool,
}

impl Aarch64Lifter {
    /// Create a new AArch64 lifter
    pub fn new() -> Self {
        Aarch64Lifter { strict: false }
    }

    /// Create a lifter in strict mode
    pub fn strict() -> Self {
        Aarch64Lifter { strict: true }
    }

    // ========================================================================
    // Register Conversion
    // ========================================================================

    /// Convert ARM register to VReg
    fn arm_reg(&self, reg: &Register) -> VReg {
        if reg.is_sp {
            VReg::Arch(ArchReg::Arm(ArmReg::Sp))
        } else if reg.num == 31 && !reg.is_sp {
            // XZR/WZR reads as zero
            VReg::Imm(0)
        } else {
            VReg::Arch(ArchReg::Arm(ArmReg::X(reg.num)))
        }
    }

    /// Get the width for an ARM register operand
    fn reg_width(&self, reg: &Register) -> OpWidth {
        if reg.is_64bit {
            OpWidth::W64
        } else {
            OpWidth::W32
        }
    }

    /// Convert ARM condition to SMIR condition
    fn arm_cond(&self, cond: ArmCondition) -> Condition {
        match cond {
            ArmCondition::EQ => Condition::Eq,
            ArmCondition::NE => Condition::Ne,
            ArmCondition::CS => Condition::Uge,
            ArmCondition::CC => Condition::Ult,
            ArmCondition::MI => Condition::Negative,
            ArmCondition::PL => Condition::Positive,
            ArmCondition::VS => Condition::Overflow,
            ArmCondition::VC => Condition::NoOverflow,
            ArmCondition::HI => Condition::Ugt,
            ArmCondition::LS => Condition::Ule,
            ArmCondition::GE => Condition::Sge,
            ArmCondition::LT => Condition::Slt,
            ArmCondition::GT => Condition::Sgt,
            ArmCondition::LE => Condition::Sle,
            ArmCondition::AL | ArmCondition::NV => Condition::Always,
        }
    }

    /// Convert shift type
    fn arm_shift(&self, shift: ShiftType) -> ShiftOp {
        match shift {
            ShiftType::LSL => ShiftOp::Lsl,
            ShiftType::LSR => ShiftOp::Lsr,
            ShiftType::ASR => ShiftOp::Asr,
            ShiftType::ROR | ShiftType::RRX => ShiftOp::Ror,
        }
    }

    // ========================================================================
    // Operand Helpers
    // ========================================================================

    /// Convert memory operand to SMIR address
    fn mem_to_addr(&self, mem: &MemOperand, ctx: &mut LiftContext) -> (Address, Vec<SmirOp>) {
        let mut pre_ops = Vec::new();
        let pc = ctx.guest_pc;

        let addr = match &mem.offset {
            MemOffset::None => Address::Direct(self.arm_reg(&mem.base)),
            MemOffset::Imm(off) => Address::BaseOffset {
                base: self.arm_reg(&mem.base),
                offset: *off,
                disp_size: DispSize::Auto,
            },
            MemOffset::Reg(idx) => {
                let tmp = ctx.alloc_vreg();
                let width = self.reg_width(&mem.base);
                pre_ops.push(SmirOp::new(
                    OpId(0),
                    pc,
                    OpKind::Add {
                        dst: tmp,
                        src1: self.arm_reg(&mem.base),
                        src2: SrcOperand::Reg(self.arm_reg(idx)),
                        width,
                        flags: FlagUpdate::None,
                    },
                ));
                Address::Direct(tmp)
            }
            MemOffset::ShiftedReg(sr) => {
                let tmp_shift = ctx.alloc_vreg();
                let tmp_addr = ctx.alloc_vreg();
                let width = self.reg_width(&mem.base);

                pre_ops.push(SmirOp::new(
                    OpId(0),
                    pc,
                    OpKind::Shl {
                        dst: tmp_shift,
                        src: self.arm_reg(&sr.reg),
                        amount: SrcOperand::Imm(sr.amount as i64),
                        width,
                        flags: FlagUpdate::None,
                    },
                ));

                pre_ops.push(SmirOp::new(
                    OpId(1),
                    pc,
                    OpKind::Add {
                        dst: tmp_addr,
                        src1: self.arm_reg(&mem.base),
                        src2: SrcOperand::Reg(tmp_shift),
                        width,
                        flags: FlagUpdate::None,
                    },
                ));

                Address::Direct(tmp_addr)
            }
            MemOffset::ExtendedReg(er) => {
                let tmp_ext = ctx.alloc_vreg();
                let tmp_addr = ctx.alloc_vreg();
                let width = self.reg_width(&mem.base);

                let (from_width, signed) = match er.extend_type {
                    ExtendType::UXTB => (OpWidth::W8, false),
                    ExtendType::UXTH => (OpWidth::W16, false),
                    ExtendType::UXTW => (OpWidth::W32, false),
                    ExtendType::UXTX => (OpWidth::W64, false),
                    ExtendType::SXTB => (OpWidth::W8, true),
                    ExtendType::SXTH => (OpWidth::W16, true),
                    ExtendType::SXTW => (OpWidth::W32, true),
                    ExtendType::SXTX => (OpWidth::W64, true),
                };

                if signed {
                    pre_ops.push(SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::SignExtend {
                            dst: tmp_ext,
                            src: self.arm_reg(&er.reg),
                            from_width,
                            to_width: width,
                        },
                    ));
                } else {
                    pre_ops.push(SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::ZeroExtend {
                            dst: tmp_ext,
                            src: self.arm_reg(&er.reg),
                            from_width,
                            to_width: width,
                        },
                    ));
                }

                if er.shift > 0 {
                    let tmp_shift = ctx.alloc_vreg();
                    pre_ops.push(SmirOp::new(
                        OpId(1),
                        pc,
                        OpKind::Shl {
                            dst: tmp_shift,
                            src: tmp_ext,
                            amount: SrcOperand::Imm(er.shift as i64),
                            width,
                            flags: FlagUpdate::None,
                        },
                    ));
                    pre_ops.push(SmirOp::new(
                        OpId(2),
                        pc,
                        OpKind::Add {
                            dst: tmp_addr,
                            src1: self.arm_reg(&mem.base),
                            src2: SrcOperand::Reg(tmp_shift),
                            width,
                            flags: FlagUpdate::None,
                        },
                    ));
                } else {
                    pre_ops.push(SmirOp::new(
                        OpId(1),
                        pc,
                        OpKind::Add {
                            dst: tmp_addr,
                            src1: self.arm_reg(&mem.base),
                            src2: SrcOperand::Reg(tmp_ext),
                            width,
                            flags: FlagUpdate::None,
                        },
                    ));
                }

                Address::Direct(tmp_addr)
            }
        };

        (addr, pre_ops)
    }

    /// Handle pre/post-index writeback for memory operand
    fn handle_writeback(
        &self,
        mem: &MemOperand,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        _ctx: &mut LiftContext,
    ) {
        let offset = match &mem.offset {
            MemOffset::Imm(off) => *off,
            _ => return,
        };

        match mem.mode {
            AddressingMode::PreIndex | AddressingMode::PostIndex => {
                let width = self.reg_width(&mem.base);
                let base_reg = self.arm_reg(&mem.base);

                if matches!(base_reg, VReg::Imm(_)) {
                    return;
                }

                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Add {
                        dst: base_reg,
                        src1: base_reg,
                        src2: SrcOperand::Imm(offset),
                        width,
                        flags: FlagUpdate::None,
                    },
                ));
            }
            AddressingMode::Offset => {}
        }
    }

    fn indexed_access_addr(&self, mem: &MemOperand, addr: Address) -> Address {
        if matches!(
            mem.mode,
            AddressingMode::PreIndex | AddressingMode::PostIndex
        ) {
            Address::Direct(self.arm_reg(&mem.base))
        } else {
            addr
        }
    }

    /// Get destination VReg from operand, handling XZR/WZR writes
    fn dst_reg(&self, reg: &Register, ctx: &mut LiftContext) -> VReg {
        if reg.num == 31 && !reg.is_sp {
            ctx.alloc_vreg()
        } else if reg.is_sp {
            VReg::Arch(ArchReg::Arm(ArmReg::Sp))
        } else {
            VReg::Arch(ArchReg::Arm(ArmReg::X(reg.num)))
        }
    }

    fn push_lifted_op(ops: &mut Vec<SmirOp>, pc: u64, kind: OpKind) {
        ops.push(SmirOp::new(OpId(ops.len() as u16), pc, kind));
    }

    fn push_mul_op(
        ops: &mut Vec<SmirOp>,
        pc: u64,
        dst_lo: VReg,
        dst_hi: Option<VReg>,
        src1: VReg,
        src2: VReg,
        width: OpWidth,
        signed: bool,
    ) {
        let src2 = SrcOperand::Reg(src2);
        let flags = FlagUpdate::None;
        if signed {
            Self::push_lifted_op(
                ops,
                pc,
                OpKind::MulS {
                    dst_lo,
                    dst_hi,
                    src1,
                    src2,
                    width,
                    flags,
                },
            );
        } else {
            Self::push_lifted_op(
                ops,
                pc,
                OpKind::MulU {
                    dst_lo,
                    dst_hi,
                    src1,
                    src2,
                    width,
                    flags,
                },
            );
        }
    }

    fn widen_w_to_x(
        &self,
        ops: &mut Vec<SmirOp>,
        pc: u64,
        ctx: &mut LiftContext,
        src: &Register,
        signed: bool,
    ) -> VReg {
        let dst = ctx.alloc_vreg();
        let kind = if signed {
            OpKind::SignExtend {
                dst,
                src: self.arm_reg(src),
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            }
        } else {
            OpKind::ZeroExtend {
                dst,
                src: self.arm_reg(src),
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            }
        };
        Self::push_lifted_op(ops, pc, kind);
        dst
    }

    // ========================================================================
    // Instruction Lifting
    // ========================================================================

    /// Lift a single instruction to SMIR ops
    fn lift_insn_inner(
        &self,
        insn: &DecodedInsn,
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let mut ops = Vec::new();
        let mut control = ControlFlow::Fallthrough;

        macro_rules! push_op {
            ($kind:expr) => {{
                ops.push(SmirOp::new(OpId(ops.len() as u16), pc, $kind));
            }};
        }

        match insn.mnemonic {
            // =================================================================
            // Arithmetic
            // =================================================================
            Mnemonic::ADD | Mnemonic::ADDS => {
                let (dst, src1, src2, width) = self.parse_arith_operands(insn, ctx)?;
                let flags = if insn.sets_flags {
                    FlagUpdate::All
                } else {
                    FlagUpdate::None
                };
                push_op!(OpKind::Add {
                    dst,
                    src1,
                    src2,
                    width,
                    flags,
                });
            }

            Mnemonic::SUB | Mnemonic::SUBS => {
                let (dst, src1, src2, width) = self.parse_arith_operands(insn, ctx)?;
                let flags = if insn.sets_flags {
                    FlagUpdate::All
                } else {
                    FlagUpdate::None
                };
                push_op!(OpKind::Sub {
                    dst,
                    src1,
                    src2,
                    width,
                    flags,
                });
            }

            Mnemonic::ADC | Mnemonic::ADCS => {
                let (dst, src1, src2, width) = self.parse_arith_operands(insn, ctx)?;
                let flags = if insn.sets_flags {
                    FlagUpdate::All
                } else {
                    FlagUpdate::None
                };
                push_op!(OpKind::Adc {
                    dst,
                    src1,
                    src2,
                    width,
                    flags,
                });
            }

            Mnemonic::SBC | Mnemonic::SBCS => {
                let (dst, src1, src2, width) = self.parse_arith_operands(insn, ctx)?;
                let flags = if insn.sets_flags {
                    FlagUpdate::All
                } else {
                    FlagUpdate::None
                };
                push_op!(OpKind::Sbb {
                    dst,
                    src1,
                    src2,
                    width,
                    flags,
                });
            }

            Mnemonic::NEG | Mnemonic::NEGS => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rm))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    let flags = if insn.sets_flags {
                        FlagUpdate::All
                    } else {
                        FlagUpdate::None
                    };
                    push_op!(OpKind::Neg {
                        dst,
                        src: self.arm_reg(rm),
                        width,
                        flags,
                    });
                }
            }

            Mnemonic::MUL | Mnemonic::MNEG => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn)), Some(Operand::Reg(rm))) = (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                ) {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    let product = if insn.mnemonic == Mnemonic::MUL {
                        dst
                    } else {
                        ctx.alloc_vreg()
                    };
                    Self::push_mul_op(
                        &mut ops,
                        pc,
                        product,
                        None,
                        self.arm_reg(rn),
                        self.arm_reg(rm),
                        width,
                        false,
                    );
                    if insn.mnemonic == Mnemonic::MNEG {
                        push_op!(OpKind::Neg {
                            dst,
                            src: product,
                            width,
                            flags: FlagUpdate::None,
                        });
                    }
                }
            }

            Mnemonic::MADD | Mnemonic::MSUB => {
                if let (
                    Some(Operand::Reg(rd)),
                    Some(Operand::Reg(rn)),
                    Some(Operand::Reg(rm)),
                    Some(Operand::Reg(ra)),
                ) = (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                    insn.operands.get(3),
                ) {
                    let dst = self.dst_reg(rd, ctx);
                    let tmp = ctx.alloc_vreg();
                    let width = self.reg_width(rd);

                    Self::push_mul_op(
                        &mut ops,
                        pc,
                        tmp,
                        None,
                        self.arm_reg(rn),
                        self.arm_reg(rm),
                        width,
                        false,
                    );

                    if insn.mnemonic == Mnemonic::MADD {
                        push_op!(OpKind::Add {
                            dst,
                            src1: self.arm_reg(ra),
                            src2: SrcOperand::Reg(tmp),
                            width,
                            flags: FlagUpdate::None,
                        });
                    } else {
                        push_op!(OpKind::Sub {
                            dst,
                            src1: self.arm_reg(ra),
                            src2: SrcOperand::Reg(tmp),
                            width,
                            flags: FlagUpdate::None,
                        });
                    }
                }
            }

            Mnemonic::SMADDL | Mnemonic::SMSUBL | Mnemonic::UMADDL | Mnemonic::UMSUBL => {
                if let (
                    Some(Operand::Reg(rd)),
                    Some(Operand::Reg(rn)),
                    Some(Operand::Reg(rm)),
                    Some(Operand::Reg(ra)),
                ) = (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                    insn.operands.get(3),
                ) {
                    let dst = self.dst_reg(rd, ctx);
                    let src1 = self.widen_w_to_x(
                        &mut ops,
                        pc,
                        ctx,
                        rn,
                        matches!(insn.mnemonic, Mnemonic::SMADDL | Mnemonic::SMSUBL),
                    );
                    let src2 = self.widen_w_to_x(
                        &mut ops,
                        pc,
                        ctx,
                        rm,
                        matches!(insn.mnemonic, Mnemonic::SMADDL | Mnemonic::SMSUBL),
                    );
                    let product = ctx.alloc_vreg();
                    let signed = matches!(insn.mnemonic, Mnemonic::SMADDL | Mnemonic::SMSUBL);
                    Self::push_mul_op(
                        &mut ops,
                        pc,
                        product,
                        None,
                        src1,
                        src2,
                        OpWidth::W64,
                        signed,
                    );
                    if matches!(insn.mnemonic, Mnemonic::SMADDL | Mnemonic::UMADDL) {
                        push_op!(OpKind::Add {
                            dst,
                            src1: self.arm_reg(ra),
                            src2: SrcOperand::Reg(product),
                            width: OpWidth::W64,
                            flags: FlagUpdate::None,
                        });
                    } else {
                        push_op!(OpKind::Sub {
                            dst,
                            src1: self.arm_reg(ra),
                            src2: SrcOperand::Reg(product),
                            width: OpWidth::W64,
                            flags: FlagUpdate::None,
                        });
                    }
                }
            }

            Mnemonic::SMULL | Mnemonic::UMULL => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn)), Some(Operand::Reg(rm))) = (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                ) {
                    let dst = self.dst_reg(rd, ctx);
                    let signed = insn.mnemonic == Mnemonic::SMULL;
                    let src1 = self.widen_w_to_x(&mut ops, pc, ctx, rn, signed);
                    let src2 = self.widen_w_to_x(&mut ops, pc, ctx, rm, signed);
                    Self::push_mul_op(
                        &mut ops,
                        pc,
                        dst,
                        None,
                        src1,
                        src2,
                        OpWidth::W64,
                        signed,
                    );
                }
            }

            Mnemonic::SMULH | Mnemonic::UMULH => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn)), Some(Operand::Reg(rm))) = (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                ) {
                    let dst = self.dst_reg(rd, ctx);
                    let lo = ctx.alloc_vreg();
                    Self::push_mul_op(
                        &mut ops,
                        pc,
                        lo,
                        Some(dst),
                        self.arm_reg(rn),
                        self.arm_reg(rm),
                        OpWidth::W64,
                        insn.mnemonic == Mnemonic::SMULH,
                    );
                }
            }

            Mnemonic::UDIV => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn)), Some(Operand::Reg(rm))) = (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                ) {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    push_op!(OpKind::DivU {
                        quot: dst,
                        rem: None,
                        src1: self.arm_reg(rn),
                        src2: SrcOperand::Reg(self.arm_reg(rm)),
                        width,
                    });
                }
            }

            Mnemonic::SDIV => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn)), Some(Operand::Reg(rm))) = (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                ) {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    push_op!(OpKind::DivS {
                        quot: dst,
                        rem: None,
                        src1: self.arm_reg(rn),
                        src2: SrcOperand::Reg(self.arm_reg(rm)),
                        width,
                    });
                }
            }

            // =================================================================
            // Logical
            // =================================================================
            Mnemonic::AND | Mnemonic::ANDS => {
                let (dst, src1, src2, width) = self.parse_arith_operands(insn, ctx)?;
                let flags = if insn.sets_flags {
                    FlagUpdate::All
                } else {
                    FlagUpdate::None
                };
                push_op!(OpKind::And {
                    dst,
                    src1,
                    src2,
                    width,
                    flags,
                });
            }

            Mnemonic::ORR | Mnemonic::ORRS => {
                let (dst, src1, src2, width) = self.parse_arith_operands(insn, ctx)?;
                let flags = if insn.sets_flags {
                    FlagUpdate::All
                } else {
                    FlagUpdate::None
                };
                push_op!(OpKind::Or {
                    dst,
                    src1,
                    src2,
                    width,
                    flags,
                });
            }

            Mnemonic::EOR | Mnemonic::EORS => {
                let (dst, src1, src2, width) = self.parse_arith_operands(insn, ctx)?;
                let flags = if insn.sets_flags {
                    FlagUpdate::All
                } else {
                    FlagUpdate::None
                };
                push_op!(OpKind::Xor {
                    dst,
                    src1,
                    src2,
                    width,
                    flags,
                });
            }

            Mnemonic::BIC | Mnemonic::BICS => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let src1 = self.arm_reg(rn);
                    let width = self.reg_width(rd);
                    let flags = if insn.sets_flags {
                        FlagUpdate::All
                    } else {
                        FlagUpdate::None
                    };

                    let src2 = self.parse_operand2(insn, 2, ctx)?;
                    let tmp = ctx.alloc_vreg();

                    push_op!(OpKind::Not {
                        dst: tmp,
                        src: match src2 {
                            SrcOperand::Reg(r) => r,
                            SrcOperand::Imm(i) | SrcOperand::Imm64(i) => VReg::Imm(i),
                            SrcOperand::Shifted { reg, .. } => reg,
                            SrcOperand::Extended { reg, .. } => reg,
                        },
                        width,
                    });

                    push_op!(OpKind::And {
                        dst,
                        src1,
                        src2: SrcOperand::Reg(tmp),
                        width,
                        flags,
                    });
                }
            }

            Mnemonic::MVN | Mnemonic::MVNS => {
                if let (Some(Operand::Reg(rd)), Some(src_op)) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);

                    let src = match src_op {
                        Operand::Reg(rm) => self.arm_reg(rm),
                        Operand::Imm(imm) => VReg::Imm(imm.effective_value()),
                        _ => return Err(LiftError::Internal("invalid MVN operand".to_string())),
                    };

                    push_op!(OpKind::Not { dst, src, width });
                }
            }

            Mnemonic::TST => {
                if let (Some(Operand::Reg(rn)), Some(op2)) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let tmp = ctx.alloc_vreg();
                    let src1 = self.arm_reg(rn);
                    let width = self.reg_width(rn);
                    let src2 = self.operand_to_src(op2, ctx)?;

                    push_op!(OpKind::And {
                        dst: tmp,
                        src1,
                        src2,
                        width,
                        flags: FlagUpdate::All,
                    });
                }
            }

            // =================================================================
            // Compare
            // =================================================================
            Mnemonic::CMP => {
                if let (Some(Operand::Reg(rn)), Some(op2)) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let tmp = ctx.alloc_vreg();
                    let src1 = self.arm_reg(rn);
                    let width = self.reg_width(rn);
                    let src2 = self.operand_to_src(op2, ctx)?;

                    push_op!(OpKind::Sub {
                        dst: tmp,
                        src1,
                        src2,
                        width,
                        flags: FlagUpdate::All,
                    });
                }
            }

            Mnemonic::CMN => {
                if let (Some(Operand::Reg(rn)), Some(op2)) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let tmp = ctx.alloc_vreg();
                    let src1 = self.arm_reg(rn);
                    let width = self.reg_width(rn);
                    let src2 = self.operand_to_src(op2, ctx)?;

                    push_op!(OpKind::Add {
                        dst: tmp,
                        src1,
                        src2,
                        width,
                        flags: FlagUpdate::All,
                    });
                }
            }

            // =================================================================
            // Move
            // =================================================================
            Mnemonic::MOV | Mnemonic::MOVS => {
                if let (Some(Operand::Reg(rd)), Some(src_op)) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    let src = self.operand_to_src(src_op, ctx)?;

                    push_op!(OpKind::Mov { dst, src, width });
                }
            }

            Mnemonic::MOVZ => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Imm(imm))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    let val = imm.effective_value();

                    push_op!(OpKind::Mov {
                        dst,
                        src: SrcOperand::Imm(val),
                        width,
                    });
                }
            }

            Mnemonic::MOVN => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Imm(imm))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    let val = !imm.effective_value();

                    push_op!(OpKind::Mov {
                        dst,
                        src: SrcOperand::Imm(val),
                        width,
                    });
                }
            }

            Mnemonic::MOVK => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Imm(imm))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    let shift = imm.shift;
                    let mask = !(0xFFFFu64 << shift);
                    let insert_val = (imm.value as u64) << shift;

                    let tmp = ctx.alloc_vreg();

                    push_op!(OpKind::And {
                        dst: tmp,
                        src1: self.arm_reg(rd),
                        src2: SrcOperand::Imm(mask as i64),
                        width,
                        flags: FlagUpdate::None,
                    });

                    push_op!(OpKind::Or {
                        dst,
                        src1: tmp,
                        src2: SrcOperand::Imm(insert_val as i64),
                        width,
                        flags: FlagUpdate::None,
                    });
                }
            }

            // =================================================================
            // Address Calculation
            // =================================================================
            Mnemonic::ADR => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Label(offset))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let target = (pc as i64).wrapping_add(*offset) as u64;

                    push_op!(OpKind::Mov {
                        dst,
                        src: SrcOperand::Imm(target as i64),
                        width: OpWidth::W64,
                    });
                }
            }

            Mnemonic::ADRP => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Label(offset))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let page = pc & !0xFFF;
                    let target = (page as i64).wrapping_add(*offset) as u64;

                    push_op!(OpKind::Mov {
                        dst,
                        src: SrcOperand::Imm(target as i64),
                        width: OpWidth::W64,
                    });
                }
            }

            // =================================================================
            // Shifts
            // =================================================================
            Mnemonic::LSL | Mnemonic::LSLS => {
                self.lift_shift(insn, ShiftOp::Lsl, pc, &mut ops, ctx)?;
            }

            Mnemonic::LSR | Mnemonic::LSRS => {
                self.lift_shift(insn, ShiftOp::Lsr, pc, &mut ops, ctx)?;
            }

            Mnemonic::ASR | Mnemonic::ASRS => {
                self.lift_shift(insn, ShiftOp::Asr, pc, &mut ops, ctx)?;
            }

            Mnemonic::ROR | Mnemonic::RORS => {
                self.lift_shift(insn, ShiftOp::Ror, pc, &mut ops, ctx)?;
            }

            Mnemonic::EXTR => {
                self.lift_extract(insn, pc, &mut ops, ctx)?;
            }

            // =================================================================
            // Extend
            // =================================================================
            Mnemonic::SXTB => {
                self.lift_extend(insn, OpWidth::W8, true, pc, &mut ops, ctx)?;
            }

            Mnemonic::SXTH => {
                self.lift_extend(insn, OpWidth::W16, true, pc, &mut ops, ctx)?;
            }

            Mnemonic::SXTW => {
                self.lift_extend(insn, OpWidth::W32, true, pc, &mut ops, ctx)?;
            }

            Mnemonic::UXTB => {
                self.lift_extend(insn, OpWidth::W8, false, pc, &mut ops, ctx)?;
            }

            Mnemonic::UXTH => {
                self.lift_extend(insn, OpWidth::W16, false, pc, &mut ops, ctx)?;
            }

            // =================================================================
            // Conditional Select
            // =================================================================
            Mnemonic::CSEL
            | Mnemonic::CSINC
            | Mnemonic::CSINV
            | Mnemonic::CSNEG
            | Mnemonic::CSET
            | Mnemonic::CSETM
            | Mnemonic::CINC
            | Mnemonic::CINV
            | Mnemonic::CNEG => {
                self.lift_cond_select(insn, pc, &mut ops, ctx)?;
            }

            // =================================================================
            // Bit manipulation
            // =================================================================
            Mnemonic::CLZ => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    push_op!(OpKind::Clz {
                        dst,
                        src: self.arm_reg(rn),
                        width,
                    });
                }
            }

            Mnemonic::RBIT => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    push_op!(OpKind::Rbit {
                        dst,
                        src: self.arm_reg(rn),
                        width,
                    });
                }
            }

            Mnemonic::REV => {
                if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let dst = self.dst_reg(rd, ctx);
                    let width = self.reg_width(rd);
                    push_op!(OpKind::Bswap {
                        dst,
                        src: self.arm_reg(rn),
                        width,
                    });
                }
            }

            // =================================================================
            // Load/Store
            // =================================================================
            Mnemonic::LDR => {
                let width = match insn.operands.first() {
                    Some(Operand::Reg(r)) if !r.is_64bit => MemWidth::B4,
                    _ => MemWidth::B8,
                };
                self.lift_load(insn, width, SignExtend::Zero, pc, &mut ops, ctx)?;
            }

            Mnemonic::LDRB => {
                self.lift_load(insn, MemWidth::B1, SignExtend::Zero, pc, &mut ops, ctx)?;
            }

            Mnemonic::LDRH => {
                self.lift_load(insn, MemWidth::B2, SignExtend::Zero, pc, &mut ops, ctx)?;
            }

            Mnemonic::LDRSB => {
                self.lift_load(insn, MemWidth::B1, SignExtend::Sign, pc, &mut ops, ctx)?;
            }

            Mnemonic::LDRSH => {
                self.lift_load(insn, MemWidth::B2, SignExtend::Sign, pc, &mut ops, ctx)?;
            }

            Mnemonic::LDRSW => {
                self.lift_load(insn, MemWidth::B4, SignExtend::Sign, pc, &mut ops, ctx)?;
            }

            Mnemonic::STR => {
                let width = match insn.operands.first() {
                    Some(Operand::Reg(r)) if !r.is_64bit => MemWidth::B4,
                    _ => MemWidth::B8,
                };
                self.lift_store(insn, width, pc, &mut ops, ctx)?;
            }

            Mnemonic::STRB => {
                self.lift_store(insn, MemWidth::B1, pc, &mut ops, ctx)?;
            }

            Mnemonic::STRH => {
                self.lift_store(insn, MemWidth::B2, pc, &mut ops, ctx)?;
            }

            Mnemonic::LDP => {
                self.lift_load_pair(insn, SignExtend::Zero, pc, &mut ops, ctx)?;
            }

            Mnemonic::LDPSW => {
                self.lift_load_pair(insn, SignExtend::Sign, pc, &mut ops, ctx)?;
            }

            Mnemonic::STP => {
                self.lift_store_pair(insn, pc, &mut ops, ctx)?;
            }

            // =================================================================
            // Branches
            // =================================================================
            Mnemonic::B => {
                if let Some(Operand::Label(offset)) = insn.operands.get(0) {
                    let target = (pc as i64).wrapping_add(*offset) as u64;
                    control = ControlFlow::Branch { target };
                }
            }

            Mnemonic::BL => {
                if let Some(Operand::Label(offset)) = insn.operands.get(0) {
                    let target = (pc as i64).wrapping_add(*offset) as u64;
                    let ret_addr = pc + 4;

                    push_op!(OpKind::Mov {
                        dst: VReg::Arch(ArchReg::Arm(ArmReg::X(30))),
                        src: SrcOperand::Imm(ret_addr as i64),
                        width: OpWidth::W64,
                    });

                    control = ControlFlow::Call {
                        target: CallTarget::GuestAddr(target),
                    };
                }
            }

            Mnemonic::BR => {
                if let Some(Operand::Reg(rn)) = insn.operands.get(0) {
                    control = ControlFlow::IndirectBranch {
                        target: self.arm_reg(rn),
                    };
                }
            }

            Mnemonic::BLR => {
                if let Some(Operand::Reg(rn)) = insn.operands.get(0) {
                    let ret_addr = pc + 4;

                    push_op!(OpKind::Mov {
                        dst: VReg::Arch(ArchReg::Arm(ArmReg::X(30))),
                        src: SrcOperand::Imm(ret_addr as i64),
                        width: OpWidth::W64,
                    });

                    control = ControlFlow::Call {
                        target: CallTarget::Indirect(self.arm_reg(rn)),
                    };
                }
            }

            Mnemonic::RET => {
                control = ControlFlow::Return;
            }

            Mnemonic::BCC => {
                if let (Some(Operand::Label(offset)), Some(cond)) =
                    (insn.operands.get(0), insn.cond)
                {
                    let target = (pc as i64).wrapping_add(*offset) as u64;
                    let fallthrough = pc + 4;
                    control = ControlFlow::CondBranch {
                        cond: self.arm_cond(cond),
                        target,
                        fallthrough,
                    };
                }
            }

            Mnemonic::CBZ => {
                if let (Some(Operand::Reg(rn)), Some(Operand::Label(offset))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let target = (pc as i64).wrapping_add(*offset) as u64;
                    let fallthrough = pc + 4;
                    let width = self.reg_width(rn);
                    let cmp = ctx.alloc_vreg();

                    // Compare with zero - sets flags
                    push_op!(OpKind::Cmp {
                        src1: self.arm_reg(rn),
                        src2: SrcOperand::Imm(0),
                        width,
                    });

                    control = ControlFlow::CondBranch {
                        cond: Condition::Eq,
                        target,
                        fallthrough,
                    };
                }
            }

            Mnemonic::CBNZ => {
                if let (Some(Operand::Reg(rn)), Some(Operand::Label(offset))) =
                    (insn.operands.get(0), insn.operands.get(1))
                {
                    let target = (pc as i64).wrapping_add(*offset) as u64;
                    let fallthrough = pc + 4;
                    let width = self.reg_width(rn);

                    // Compare with zero - sets flags
                    push_op!(OpKind::Cmp {
                        src1: self.arm_reg(rn),
                        src2: SrcOperand::Imm(0),
                        width,
                    });

                    control = ControlFlow::CondBranch {
                        cond: Condition::Ne,
                        target,
                        fallthrough,
                    };
                }
            }

            // =================================================================
            // System
            // =================================================================
            Mnemonic::NOP => {
                push_op!(OpKind::Nop);
            }

            Mnemonic::SVC => {
                control = ControlFlow::Syscall;
            }

            Mnemonic::BRK => {
                control = ControlFlow::Trap {
                    kind: TrapKind::Breakpoint,
                };
            }

            Mnemonic::HLT => {
                control = ControlFlow::Trap {
                    kind: TrapKind::Halt,
                };
            }

            Mnemonic::UDF => {
                control = ControlFlow::Trap {
                    kind: TrapKind::Undefined,
                };
            }

            Mnemonic::DMB | Mnemonic::DSB | Mnemonic::ISB => {
                push_op!(OpKind::Fence {
                    kind: FenceKind::Full,
                });
            }

            // =================================================================
            // Unhandled
            // =================================================================
            _ => {
                if self.strict {
                    return Err(LiftError::Unsupported {
                        addr: pc,
                        mnemonic: format!("{:?}", insn.mnemonic),
                    });
                }
                control = ControlFlow::Trap {
                    kind: TrapKind::Undefined,
                };
            }
        }

        Ok((ops, control))
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    fn parse_arith_operands(
        &self,
        insn: &DecodedInsn,
        ctx: &mut LiftContext,
    ) -> Result<(VReg, VReg, SrcOperand, OpWidth), LiftError> {
        let rd = match insn.operands.get(0) {
            Some(Operand::Reg(r)) => r,
            _ => return Err(LiftError::Internal("missing rd".to_string())),
        };

        let rn = match insn.operands.get(1) {
            Some(Operand::Reg(r)) => r,
            _ => return Err(LiftError::Internal("missing rn".to_string())),
        };

        let src2 = self.parse_operand2(insn, 2, ctx)?;

        Ok((
            self.dst_reg(rd, ctx),
            self.arm_reg(rn),
            src2,
            self.reg_width(rd),
        ))
    }

    fn parse_operand2(
        &self,
        insn: &DecodedInsn,
        idx: usize,
        _ctx: &mut LiftContext,
    ) -> Result<SrcOperand, LiftError> {
        match insn.operands.get(idx) {
            Some(Operand::Reg(r)) => Ok(SrcOperand::Reg(self.arm_reg(r))),
            Some(Operand::Imm(imm)) => Ok(SrcOperand::Imm(imm.effective_value())),
            Some(Operand::ShiftedReg(sr)) => Ok(SrcOperand::Reg(self.arm_reg(&sr.reg))),
            _ => Err(LiftError::Internal("invalid operand2".to_string())),
        }
    }

    fn operand_to_src(
        &self,
        op: &Operand,
        _ctx: &mut LiftContext,
    ) -> Result<SrcOperand, LiftError> {
        match op {
            Operand::Reg(r) => Ok(SrcOperand::Reg(self.arm_reg(r))),
            Operand::Imm(imm) => Ok(SrcOperand::Imm(imm.effective_value())),
            Operand::ShiftedReg(sr) => Ok(SrcOperand::Reg(self.arm_reg(&sr.reg))),
            _ => Err(LiftError::Internal("invalid operand".to_string())),
        }
    }

    fn lift_shift(
        &self,
        insn: &DecodedInsn,
        shift_op: ShiftOp,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn)), Some(amount)) = (
            insn.operands.get(0),
            insn.operands.get(1),
            insn.operands.get(2),
        ) {
            let dst = self.dst_reg(rd, ctx);
            let width = self.reg_width(rd);
            let flags = if insn.sets_flags {
                FlagUpdate::All
            } else {
                FlagUpdate::None
            };

            let amount_src = match amount {
                Operand::Imm(imm) => {
                    let value = if shift_op == ShiftOp::Lsl
                        && matches!(insn.operands.get(3), Some(Operand::Imm(_)))
                    {
                        i64::from(width.bits()) - imm.value
                    } else {
                        imm.value
                    };
                    SrcOperand::Imm(value)
                }
                Operand::Reg(r) => SrcOperand::Reg(self.arm_reg(r)),
                _ => return Err(LiftError::Internal("invalid shift amount".to_string())),
            };

            let kind = match shift_op {
                ShiftOp::Lsl => OpKind::Shl {
                    dst,
                    src: self.arm_reg(rn),
                    amount: amount_src,
                    width,
                    flags,
                },
                ShiftOp::Lsr => OpKind::Shr {
                    dst,
                    src: self.arm_reg(rn),
                    amount: amount_src,
                    width,
                    flags,
                },
                ShiftOp::Asr => OpKind::Sar {
                    dst,
                    src: self.arm_reg(rn),
                    amount: amount_src,
                    width,
                    flags,
                },
                ShiftOp::Ror | ShiftOp::Rrx => OpKind::Ror {
                    dst,
                    src: self.arm_reg(rn),
                    amount: amount_src,
                    width,
                    flags,
                },
            };

            ops.push(SmirOp::new(OpId(ops.len() as u16), pc, kind));
        }

        Ok(())
    }

    fn lift_extract(
        &self,
        insn: &DecodedInsn,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        if let (
            Some(Operand::Reg(rd)),
            Some(Operand::Reg(rn)),
            Some(Operand::Reg(rm)),
            Some(Operand::Imm(lsb)),
        ) = (
            insn.operands.get(0),
            insn.operands.get(1),
            insn.operands.get(2),
            insn.operands.get(3),
        ) {
            let dst = self.dst_reg(rd, ctx);
            let width = self.reg_width(rd);
            let amount = lsb.value;

            if amount == 0 {
                Self::push_lifted_op(
                    ops,
                    pc,
                    OpKind::Mov {
                        dst,
                        src: SrcOperand::Reg(self.arm_reg(rm)),
                        width,
                    },
                );
                return Ok(());
            }

            let lo = ctx.alloc_vreg();
            let hi = ctx.alloc_vreg();
            Self::push_lifted_op(
                ops,
                pc,
                OpKind::Shr {
                    dst: lo,
                    src: self.arm_reg(rm),
                    amount: SrcOperand::Imm(amount),
                    width,
                    flags: FlagUpdate::None,
                },
            );
            Self::push_lifted_op(
                ops,
                pc,
                OpKind::Shl {
                    dst: hi,
                    src: self.arm_reg(rn),
                    amount: SrcOperand::Imm(i64::from(width.bits()) - amount),
                    width,
                    flags: FlagUpdate::None,
                },
            );
            Self::push_lifted_op(
                ops,
                pc,
                OpKind::Or {
                    dst,
                    src1: lo,
                    src2: SrcOperand::Reg(hi),
                    width,
                    flags: FlagUpdate::None,
                },
            );
        }

        Ok(())
    }

    fn lift_cond_select(
        &self,
        insn: &DecodedInsn,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        let invalid = || LiftError::Internal("invalid conditional select operands".to_string());

        // Alias mnemonics keep the raw condition from the canonical CS* encoding.
        let (rd, src_true, src_false_base, false_op, cond) = match insn.mnemonic {
            Mnemonic::CSEL | Mnemonic::CSINC | Mnemonic::CSINV | Mnemonic::CSNEG => {
                let (rd, rn, rm, cond) = match (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                    insn.operands.get(3),
                ) {
                    (
                        Some(Operand::Reg(rd)),
                        Some(Operand::Reg(rn)),
                        Some(Operand::Reg(rm)),
                        Some(Operand::Cond(cond)),
                    ) => (*rd, *rn, *rm, *cond),
                    _ => return Err(invalid()),
                };
                let false_op = match insn.mnemonic {
                    Mnemonic::CSEL => CondSelectFalseOp::Identity,
                    Mnemonic::CSINC => CondSelectFalseOp::Increment,
                    Mnemonic::CSINV => CondSelectFalseOp::Invert,
                    Mnemonic::CSNEG => CondSelectFalseOp::Negate,
                    _ => unreachable!(),
                };
                (
                    rd,
                    self.arm_reg(&rn),
                    self.arm_reg(&rm),
                    false_op,
                    cond,
                )
            }
            Mnemonic::CINC | Mnemonic::CINV | Mnemonic::CNEG => {
                let (rd, rn, cond) = match (
                    insn.operands.get(0),
                    insn.operands.get(1),
                    insn.operands.get(2),
                ) {
                    (
                        Some(Operand::Reg(rd)),
                        Some(Operand::Reg(rn)),
                        Some(Operand::Cond(cond)),
                    ) => (*rd, *rn, *cond),
                    _ => return Err(invalid()),
                };
                let false_op = match insn.mnemonic {
                    Mnemonic::CINC => CondSelectFalseOp::Increment,
                    Mnemonic::CINV => CondSelectFalseOp::Invert,
                    Mnemonic::CNEG => CondSelectFalseOp::Negate,
                    _ => unreachable!(),
                };
                (
                    rd,
                    self.arm_reg(&rn),
                    self.arm_reg(&rn),
                    false_op,
                    cond,
                )
            }
            Mnemonic::CSET | Mnemonic::CSETM => {
                let (rd, cond) = match (insn.operands.get(0), insn.operands.get(1)) {
                    (Some(Operand::Reg(rd)), Some(Operand::Cond(cond))) => (*rd, *cond),
                    _ => return Err(invalid()),
                };
                let false_op = if insn.mnemonic == Mnemonic::CSET {
                    CondSelectFalseOp::Increment
                } else {
                    CondSelectFalseOp::Invert
                };
                (rd, VReg::Imm(0), VReg::Imm(0), false_op, cond)
            }
            _ => return Err(invalid()),
        };

        let dst = self.dst_reg(&rd, ctx);
        let width = self.reg_width(&rd);
        let cmp = ctx.alloc_vreg();

        Self::push_lifted_op(
            ops,
            pc,
            OpKind::TestCondition {
                dst: cmp,
                cond: self.arm_cond(cond),
            },
        );

        let src_false = match false_op {
            CondSelectFalseOp::Identity => src_false_base,
            CondSelectFalseOp::Increment => {
                let tmp = ctx.alloc_vreg();
                Self::push_lifted_op(
                    ops,
                    pc,
                    OpKind::Add {
                        dst: tmp,
                        src1: src_false_base,
                        src2: SrcOperand::Imm(1),
                        width,
                        flags: FlagUpdate::None,
                    },
                );
                tmp
            }
            CondSelectFalseOp::Invert => {
                let tmp = ctx.alloc_vreg();
                Self::push_lifted_op(
                    ops,
                    pc,
                    OpKind::Not {
                        dst: tmp,
                        src: src_false_base,
                        width,
                    },
                );
                tmp
            }
            CondSelectFalseOp::Negate => {
                let tmp = ctx.alloc_vreg();
                Self::push_lifted_op(
                    ops,
                    pc,
                    OpKind::Neg {
                        dst: tmp,
                        src: src_false_base,
                        width,
                        flags: FlagUpdate::None,
                    },
                );
                tmp
            }
        };

        Self::push_lifted_op(
            ops,
            pc,
            OpKind::Select {
                dst,
                cond: cmp,
                src_true,
                src_false,
                width,
            },
        );

        Ok(())
    }

    fn lift_extend(
        &self,
        insn: &DecodedInsn,
        from_width: OpWidth,
        signed: bool,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        if let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn))) =
            (insn.operands.get(0), insn.operands.get(1))
        {
            let dst = self.dst_reg(rd, ctx);
            let to_width = self.reg_width(rd);

            let kind = if signed {
                OpKind::SignExtend {
                    dst,
                    src: self.arm_reg(rn),
                    from_width,
                    to_width,
                }
            } else {
                OpKind::ZeroExtend {
                    dst,
                    src: self.arm_reg(rn),
                    from_width,
                    to_width,
                }
            };

            ops.push(SmirOp::new(OpId(ops.len() as u16), pc, kind));
        }

        Ok(())
    }

    fn lift_load(
        &self,
        insn: &DecodedInsn,
        width: MemWidth,
        extend: SignExtend,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        let (rd, mem) = match (insn.operands.get(0), insn.operands.get(1)) {
            (Some(Operand::Reg(r)), Some(Operand::Mem(m))) => (r, m),
            (Some(Operand::Reg(r)), Some(Operand::Label(off))) => {
                let dst = self.dst_reg(r, ctx);
                let load_dst = if extend == SignExtend::Sign && !r.is_64bit {
                    ctx.alloc_vreg()
                } else {
                    dst
                };

                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Load {
                        dst: load_dst,
                        addr: Address::PcRel {
                            offset: *off,
                            disp_size: DispSize::Auto,
                            base: None,
                        },
                        width,
                        sign: extend,
                    },
                ));
                if load_dst != dst {
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::ZeroExtend {
                            dst,
                            src: load_dst,
                            from_width: OpWidth::W32,
                            to_width: OpWidth::W64,
                        },
                    ));
                }
                return Ok(());
            }
            _ => return Err(LiftError::Internal("invalid load operands".to_string())),
        };

        let dst = self.dst_reg(rd, ctx);
        let load_dst = if extend == SignExtend::Sign && !rd.is_64bit {
            ctx.alloc_vreg()
        } else {
            dst
        };
        let (addr, pre_ops) = self.mem_to_addr(mem, ctx);

        for mut op in pre_ops {
            op.id = OpId(ops.len() as u16);
            ops.push(op);
        }

        if mem.mode == AddressingMode::PreIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        let load_addr = self.indexed_access_addr(mem, addr);

        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Load {
                dst: load_dst,
                addr: load_addr,
                width,
                sign: extend,
            },
        ));
        if load_dst != dst {
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::ZeroExtend {
                    dst,
                    src: load_dst,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
        }

        if mem.mode == AddressingMode::PostIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        Ok(())
    }

    fn lift_store(
        &self,
        insn: &DecodedInsn,
        width: MemWidth,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        let (rt, mem) = match (insn.operands.get(0), insn.operands.get(1)) {
            (Some(Operand::Reg(r)), Some(Operand::Mem(m))) => (r, m),
            _ => return Err(LiftError::Internal("invalid store operands".to_string())),
        };

        let src = self.arm_reg(rt);
        let (addr, pre_ops) = self.mem_to_addr(mem, ctx);

        for mut op in pre_ops {
            op.id = OpId(ops.len() as u16);
            ops.push(op);
        }

        if mem.mode == AddressingMode::PreIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        let store_addr = self.indexed_access_addr(mem, addr);

        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Store {
                src,
                addr: store_addr,
                width,
            },
        ));

        if mem.mode == AddressingMode::PostIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        Ok(())
    }

    fn lift_load_pair(
        &self,
        insn: &DecodedInsn,
        extend: SignExtend,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        let (rt1, rt2, mem) = match (
            insn.operands.get(0),
            insn.operands.get(1),
            insn.operands.get(2),
        ) {
            (Some(Operand::Reg(r1)), Some(Operand::Reg(r2)), Some(Operand::Mem(m))) => (r1, r2, m),
            _ => return Err(LiftError::Internal("invalid LDP operands".to_string())),
        };

        let dst1 = self.dst_reg(rt1, ctx);
        let dst2 = self.dst_reg(rt2, ctx);
        let width = if rt1.is_64bit {
            MemWidth::B8
        } else {
            MemWidth::B4
        };
        let offset2 = if rt1.is_64bit { 8i64 } else { 4i64 };

        let (addr, pre_ops) = self.mem_to_addr(mem, ctx);

        for mut op in pre_ops {
            op.id = OpId(ops.len() as u16);
            ops.push(op);
        }

        if mem.mode == AddressingMode::PreIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        let load_addr = self.indexed_access_addr(mem, addr);

        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Load {
                dst: dst1,
                addr: load_addr.clone(),
                width,
                sign: extend,
            },
        ));

        let addr2 = match &load_addr {
            Address::Direct(base) => Address::BaseOffset {
                base: *base,
                offset: offset2,
                disp_size: DispSize::Auto,
            },
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => Address::BaseOffset {
                base: *base,
                offset: *offset + offset2,
                disp_size: *disp_size,
            },
            _ => load_addr,
        };

        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Load {
                dst: dst2,
                addr: addr2,
                width,
                sign: extend,
            },
        ));

        if mem.mode == AddressingMode::PostIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        Ok(())
    }

    fn lift_store_pair(
        &self,
        insn: &DecodedInsn,
        pc: u64,
        ops: &mut Vec<SmirOp>,
        ctx: &mut LiftContext,
    ) -> Result<(), LiftError> {
        let (rt1, rt2, mem) = match (
            insn.operands.get(0),
            insn.operands.get(1),
            insn.operands.get(2),
        ) {
            (Some(Operand::Reg(r1)), Some(Operand::Reg(r2)), Some(Operand::Mem(m))) => (r1, r2, m),
            _ => return Err(LiftError::Internal("invalid STP operands".to_string())),
        };

        let src1 = self.arm_reg(rt1);
        let src2 = self.arm_reg(rt2);
        let width = if rt1.is_64bit {
            MemWidth::B8
        } else {
            MemWidth::B4
        };
        let offset2 = if rt1.is_64bit { 8i64 } else { 4i64 };

        let (addr, pre_ops) = self.mem_to_addr(mem, ctx);

        for mut op in pre_ops {
            op.id = OpId(ops.len() as u16);
            ops.push(op);
        }

        if mem.mode == AddressingMode::PreIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        let store_addr = self.indexed_access_addr(mem, addr);

        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Store {
                src: src1,
                addr: store_addr.clone(),
                width,
            },
        ));

        let addr2 = match &store_addr {
            Address::Direct(base) => Address::BaseOffset {
                base: *base,
                offset: offset2,
                disp_size: DispSize::Auto,
            },
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => Address::BaseOffset {
                base: *base,
                offset: *offset + offset2,
                disp_size: *disp_size,
            },
            _ => store_addr,
        };

        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Store {
                src: src2,
                addr: addr2,
                width,
            },
        ));

        if mem.mode == AddressingMode::PostIndex {
            self.handle_writeback(mem, pc, ops, ctx);
        }

        Ok(())
    }
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
        use crate::arm::decoder::aarch64::Aarch64Decoder;

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
        let (ops, control_flow) = self.lift_insn_inner(&insn, addr, ctx)?;

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
                        cond: _,
                        target,
                        fallthrough,
                    } => {
                        let cond_vreg = ctx.alloc_vreg();
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
    fn test_lift_context_aarch64() {
        let ctx = LiftContext::new(SourceArch::Aarch64);
        assert_eq!(ctx.endian, Endian::Little);
    }
}

//! Hexagon instruction lifter.
//!
//! This module lifts Hexagon machine code to SMIR. Since Hexagon's DecodedInsn
//! is already in an IR-like format, this is a relatively straightforward mapping.

use std::collections::HashSet;

use crate::smir::flags::FlagUpdate;
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
};
use crate::smir::lift::{
    ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter,
};
use crate::smir::ops::{OpKind, SmirOp};
use crate::smir::types::*;

// Re-use the existing Hexagon decoder types
use crate::backend::emulator::hexagon::decode::{
    AddrMode, CmpKind, DecodedInsn, ExtendKind, MemSign, MemWidth as HexMemWidth, ShiftKind,
};

// ============================================================================
// Hexagon Lifter
// ============================================================================

/// Hexagon instruction lifter
pub struct HexagonLifter {
    /// ISA version for feature detection
    isa: crate::config::HexagonIsa,
}

impl HexagonLifter {
    /// Create a new Hexagon lifter
    pub fn new(isa: crate::config::HexagonIsa) -> Self {
        HexagonLifter { isa }
    }

    /// Create a lifter with default ISA (V68)
    pub fn default_isa() -> Self {
        Self::new(crate::config::HexagonIsa::V68)
    }

    /// Convert Hexagon register to VReg
    fn hex_reg(&self, reg: u8) -> VReg {
        VReg::Arch(ArchReg::Hexagon(HexagonReg::R(reg)))
    }

    /// Convert Hexagon predicate register to VReg
    fn hex_pred(&self, pred: u8) -> VReg {
        VReg::Arch(ArchReg::Hexagon(HexagonReg::P(pred)))
    }

    /// Convert Hexagon memory width to SMIR memory width
    fn hex_mem_width(&self, width: HexMemWidth) -> MemWidth {
        match width {
            HexMemWidth::Byte => MemWidth::B1,
            HexMemWidth::Half => MemWidth::B2,
            HexMemWidth::Word => MemWidth::B4,
            HexMemWidth::Double => MemWidth::B8,
        }
    }

    /// Convert Hexagon sign extension mode
    fn hex_sign(&self, sign: MemSign) -> SignExtend {
        match sign {
            MemSign::Signed => SignExtend::Sign,
            MemSign::Unsigned => SignExtend::Zero,
        }
    }

    /// Convert Hexagon address mode to SMIR address
    fn hex_addr(&self, addr: &AddrMode, ctx: &mut LiftContext) -> Address {
        match addr {
            AddrMode::Offset { base, offset } => {
                let offset = ctx.extend_imm(*offset);
                Address::BaseOffset {
                    base: self.hex_reg(*base),
                    offset: offset as i64,
                    disp_size: DispSize::Auto,
                }
            }
            AddrMode::PostIncImm { base, offset: _ }
            | AddrMode::PostIncReg { base, .. }
            | AddrMode::PostIncBrev { base, .. }
            | AddrMode::PostIncCircImm { base, .. }
            | AddrMode::PostIncCircReg { base, .. } => {
                // Post-increment: use base address, increment handled separately.
                Address::Direct(self.hex_reg(*base))
            }
            AddrMode::GpOffset { offset } => {
                let offset = ctx.extend_imm(*offset);
                Address::GpRel { offset }
            }
            AddrMode::Abs { addr } => Address::Absolute(*addr as u64),
        }
    }

    /// Convert Hexagon shift kind to SMIR shift op
    fn hex_shift(&self, kind: ShiftKind) -> ShiftOp {
        match kind {
            ShiftKind::Lsl => ShiftOp::Lsl,
            ShiftKind::Lsr => ShiftOp::Lsr,
            ShiftKind::Asr => ShiftOp::Asr,
        }
    }

    /// Convert Hexagon compare kind to SMIR condition
    fn hex_cmp_to_cond(&self, kind: CmpKind) -> Condition {
        match kind {
            CmpKind::Eq => Condition::Eq,
            CmpKind::Ne => Condition::Ne,
            CmpKind::Gt => Condition::Sgt,
            CmpKind::Gtu => Condition::Ugt,
            CmpKind::Lte => Condition::Sle,
            CmpKind::Lteu => Condition::Ule,
        }
    }

    /// Lift a single Hexagon instruction to SMIR operations
    fn lift_insn_inner(
        &self,
        insn: &DecodedInsn,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let mut ops = Vec::new();
        let mut op_id = 0u16;

        macro_rules! push_op {
            ($kind:expr) => {{
                ops.push(SmirOp::new(OpId(op_id), addr, $kind));
                op_id += 1;
            }};
        }

        let control_flow = match insn {
            // ================================================================
            // Immediate Extension
            // ================================================================
            DecodedInsn::ImmExt { value } => {
                ctx.set_extended_imm(*value);
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Arithmetic
            // ================================================================
            DecodedInsn::Add { dst, src1, src2 } => {
                push_op!(OpKind::Add {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::AddImm { dst, src, imm } => {
                let imm = ctx.extend_imm(*imm);
                push_op!(OpKind::Add {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src),
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Sub { dst, src1, src2 } => {
                push_op!(OpKind::Sub {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::SubImmRev { dst, src, imm } => {
                // dst = imm - src
                let imm = ctx.extend_imm(*imm);
                let tmp = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: tmp,
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Sub {
                    dst: self.hex_reg(*dst),
                    src1: tmp,
                    src2: SrcOperand::Reg(self.hex_reg(*src)),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Mul { dst, src1, src2 } => {
                push_op!(OpKind::MulU {
                    dst_lo: self.hex_reg(*dst),
                    dst_hi: None,
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Abs { dst, src, sat: _ } => {
                // abs(src) = src >= 0 ? src : -src
                let src_val = self.hex_reg(*src);
                let neg = ctx.alloc_vreg();
                let cond = ctx.alloc_vreg();

                push_op!(OpKind::Neg {
                    dst: neg,
                    src: src_val,
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                // Check if src < 0 (sign bit set)
                push_op!(OpKind::Sar {
                    dst: cond,
                    src: src_val,
                    amount: SrcOperand::Imm(31),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                push_op!(OpKind::Select {
                    dst: self.hex_reg(*dst),
                    cond,
                    src_true: neg,
                    src_false: src_val,
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::NegSat { dst, src } => {
                push_op!(OpKind::Neg {
                    dst: self.hex_reg(*dst),
                    src: self.hex_reg(*src),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Max { dst, src1, src2 } => {
                // Signed max
                let cmp_result = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: cmp_result,
                    cond: Condition::Sgt,
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Select {
                    dst: self.hex_reg(*dst),
                    cond: cmp_result,
                    src_true: self.hex_reg(*src1),
                    src_false: self.hex_reg(*src2),
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Maxu { dst, src1, src2 } => {
                // Unsigned max
                let cmp_result = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: cmp_result,
                    cond: Condition::Ugt,
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Select {
                    dst: self.hex_reg(*dst),
                    cond: cmp_result,
                    src_true: self.hex_reg(*src1),
                    src_false: self.hex_reg(*src2),
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Min { dst, src1, src2 } => {
                let cmp_result = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: cmp_result,
                    cond: Condition::Slt,
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Select {
                    dst: self.hex_reg(*dst),
                    cond: cmp_result,
                    src_true: self.hex_reg(*src1),
                    src_false: self.hex_reg(*src2),
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Minu { dst, src1, src2 } => {
                let cmp_result = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: cmp_result,
                    cond: Condition::Ult,
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Select {
                    dst: self.hex_reg(*dst),
                    cond: cmp_result,
                    src_true: self.hex_reg(*src1),
                    src_false: self.hex_reg(*src2),
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Logical
            // ================================================================
            DecodedInsn::And { dst, src1, src2 } => {
                push_op!(OpKind::And {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::AndImm { dst, src, imm } => {
                push_op!(OpKind::And {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src),
                    src2: SrcOperand::Imm(*imm as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Or { dst, src1, src2 } => {
                push_op!(OpKind::Or {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::OrImm { dst, src, imm } => {
                push_op!(OpKind::Or {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src),
                    src2: SrcOperand::Imm(*imm as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Xor { dst, src1, src2 } => {
                push_op!(OpKind::Xor {
                    dst: self.hex_reg(*dst),
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Data Movement
            // ================================================================
            DecodedInsn::Mov { dst, src } => {
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(*dst),
                    src: SrcOperand::Reg(self.hex_reg(*src)),
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::MovImm { dst, imm } => {
                let imm = ctx.extend_imm(*imm);
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(*dst),
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::Extend { dst, src, kind } => {
                let (from_width, sign) = match kind {
                    ExtendKind::Sxt8 => (OpWidth::W8, true),
                    ExtendKind::Sxt16 => (OpWidth::W16, true),
                    ExtendKind::Zxt8 => (OpWidth::W8, false),
                    ExtendKind::Zxt16 => (OpWidth::W16, false),
                };

                if sign {
                    push_op!(OpKind::SignExtend {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        from_width,
                        to_width: OpWidth::W32,
                    });
                } else {
                    push_op!(OpKind::ZeroExtend {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        from_width,
                        to_width: OpWidth::W32,
                    });
                }
                ControlFlow::Fallthrough
            }

            DecodedInsn::Combine { dst, high, low } => {
                // Combine two 32-bit values into a 64-bit pair (stored in Rdd)
                // This maps to a pair of registers Rd:Rd+1
                use crate::backend::emulator::hexagon::decode::CombineOperand;

                let high_val = match high {
                    CombineOperand::Reg(r) => SrcOperand::Reg(self.hex_reg(*r)),
                    CombineOperand::Imm(i) => SrcOperand::Imm(*i as i64),
                };
                let low_val = match low {
                    CombineOperand::Reg(r) => SrcOperand::Reg(self.hex_reg(*r)),
                    CombineOperand::Imm(i) => SrcOperand::Imm(*i as i64),
                };

                // Store low part in Rd
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(*dst),
                    src: low_val,
                    width: OpWidth::W32,
                });
                // Store high part in Rd+1
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(*dst + 1),
                    src: high_val,
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Shifts
            // ================================================================
            DecodedInsn::ShiftImm {
                dst,
                src,
                kind,
                amount,
            } => {
                let shift_op = self.hex_shift(*kind);
                match shift_op {
                    ShiftOp::Lsl => push_op!(OpKind::Shl {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        amount: SrcOperand::Imm(*amount as i64),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }),
                    ShiftOp::Lsr => push_op!(OpKind::Shr {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        amount: SrcOperand::Imm(*amount as i64),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }),
                    ShiftOp::Asr => push_op!(OpKind::Sar {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        amount: SrcOperand::Imm(*amount as i64),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }),
                    _ => {}
                }
                ControlFlow::Fallthrough
            }

            DecodedInsn::ShiftReg {
                dst,
                src,
                amt,
                kind,
            } => {
                let shift_op = self.hex_shift(*kind);
                match shift_op {
                    ShiftOp::Lsl => push_op!(OpKind::Shl {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        amount: SrcOperand::Reg(self.hex_reg(*amt)),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }),
                    ShiftOp::Lsr => push_op!(OpKind::Shr {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        amount: SrcOperand::Reg(self.hex_reg(*amt)),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }),
                    ShiftOp::Asr => push_op!(OpKind::Sar {
                        dst: self.hex_reg(*dst),
                        src: self.hex_reg(*src),
                        amount: SrcOperand::Reg(self.hex_reg(*amt)),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }),
                    _ => {}
                }
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Memory
            // ================================================================
            DecodedInsn::Load {
                dst,
                addr,
                width,
                sign,
                pred: _,
            } => {
                let smir_addr = self.hex_addr(addr, ctx);
                let mem_width = self.hex_mem_width(*width);
                let sign_ext = self.hex_sign(*sign);

                push_op!(OpKind::Load {
                    dst: self.hex_reg(*dst),
                    addr: smir_addr,
                    width: mem_width,
                    sign: sign_ext,
                });

                // Handle post-increment
                if let AddrMode::PostIncImm { base, offset } = addr {
                    let offset = ctx.extend_imm(*offset);
                    push_op!(OpKind::Add {
                        dst: self.hex_reg(*base),
                        src1: self.hex_reg(*base),
                        src2: SrcOperand::Imm(offset as i64),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    });
                }
                ControlFlow::Fallthrough
            }

            DecodedInsn::Store {
                src,
                addr,
                width,
                pred: _,
                src_new: _,
            } => {
                let smir_addr = self.hex_addr(addr, ctx);
                let mem_width = self.hex_mem_width(*width);

                push_op!(OpKind::Store {
                    src: self.hex_reg(*src),
                    addr: smir_addr,
                    width: mem_width,
                });

                // Handle post-increment
                if let AddrMode::PostIncImm { base, offset } = addr {
                    let offset = ctx.extend_imm(*offset);
                    push_op!(OpKind::Add {
                        dst: self.hex_reg(*base),
                        src1: self.hex_reg(*base),
                        src2: SrcOperand::Imm(offset as i64),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    });
                }
                ControlFlow::Fallthrough
            }

            DecodedInsn::StoreImm {
                value,
                addr,
                width,
                pred: _,
            } => {
                let smir_addr = self.hex_addr(addr, ctx);
                let mem_width = self.hex_mem_width(*width);
                let tmp = ctx.alloc_vreg();

                push_op!(OpKind::Mov {
                    dst: tmp,
                    src: SrcOperand::Imm(*value as i64),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Store {
                    src: tmp,
                    addr: smir_addr,
                    width: mem_width,
                });
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Comparisons
            // ================================================================
            DecodedInsn::Cmp {
                pred,
                src1,
                src2,
                kind,
            } => {
                let cond = self.hex_cmp_to_cond(*kind);
                push_op!(OpKind::Cmp {
                    src1: self.hex_reg(*src1),
                    src2: SrcOperand::Reg(self.hex_reg(*src2)),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: self.hex_pred(*pred),
                    cond,
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::CmpImm {
                pred,
                src,
                imm,
                kind,
                unsigned: _,
            } => {
                let imm = ctx.extend_imm(*imm);
                let cond = self.hex_cmp_to_cond(*kind);
                push_op!(OpKind::Cmp {
                    src1: self.hex_reg(*src),
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: self.hex_pred(*pred),
                    cond,
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Control Flow
            // ================================================================
            DecodedInsn::Jump { offset } => {
                let offset = ctx.extend_imm(*offset);
                let target = addr.wrapping_add(offset as i64 as u64);
                ControlFlow::Branch { target }
            }

            DecodedInsn::JumpCond {
                offset,
                pred,
                sense,
                pred_new: _,
            } => {
                let offset = ctx.extend_imm(*offset);
                let target = addr.wrapping_add(offset as i64 as u64);
                let fallthrough = addr + 4;

                // Test predicate
                let cond_vreg = ctx.alloc_vreg();
                if *sense {
                    // Jump if predicate is true
                    push_op!(OpKind::Mov {
                        dst: cond_vreg,
                        src: SrcOperand::Reg(self.hex_pred(*pred)),
                        width: OpWidth::W32,
                    });
                } else {
                    // Jump if predicate is false (invert)
                    push_op!(OpKind::Xor {
                        dst: cond_vreg,
                        src1: self.hex_pred(*pred),
                        src2: SrcOperand::Imm(1),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    });
                }

                ControlFlow::CondBranch {
                    cond: Condition::Ne, // cond_vreg != 0
                    target,
                    fallthrough,
                }
            }

            DecodedInsn::JumpReg { src } => ControlFlow::IndirectBranch {
                target: self.hex_reg(*src),
            },

            DecodedInsn::JumpRegCond {
                src,
                pred,
                sense,
                pred_new: _,
            } => {
                // This is more complex - conditional indirect branch
                // For now, treat as unconditional (simplification)
                let _ = (pred, sense);
                ControlFlow::IndirectBranch {
                    target: self.hex_reg(*src),
                }
            }

            DecodedInsn::Call { offset } => {
                let offset = ctx.extend_imm(*offset);
                let target = addr.wrapping_add(offset as i64 as u64);
                let ret_addr = addr + 4;

                // Save return address to LR (R31)
                push_op!(OpKind::Mov {
                    dst: VReg::Arch(ArchReg::Hexagon(HexagonReg::Lr)),
                    src: SrcOperand::Imm(ret_addr as i64),
                    width: OpWidth::W32,
                });

                ControlFlow::Call {
                    target: CallTarget::GuestAddr(target),
                }
            }

            DecodedInsn::CallReg { src } => {
                let ret_addr = addr + 4;

                // Save return address to LR (R31)
                push_op!(OpKind::Mov {
                    dst: VReg::Arch(ArchReg::Hexagon(HexagonReg::Lr)),
                    src: SrcOperand::Imm(ret_addr as i64),
                    width: OpWidth::W32,
                });

                ControlFlow::Call {
                    target: CallTarget::Indirect(self.hex_reg(*src)),
                }
            }

            // ================================================================
            // Stack Frame
            // ================================================================
            DecodedInsn::AllocFrame { base, size } => {
                // allocframe(Rs):
                // SP = SP - framesize - 8
                // mem[SP+framesize] = LR:FP
                // FP = SP + framesize
                let sp = VReg::Arch(ArchReg::Hexagon(HexagonReg::Sp));
                let fp = VReg::Arch(ArchReg::Hexagon(HexagonReg::Fp));
                let lr = VReg::Arch(ArchReg::Hexagon(HexagonReg::Lr));

                let total_size = *size + 8;

                // SP = SP - total_size
                push_op!(OpKind::Sub {
                    dst: sp,
                    src1: self.hex_reg(*base),
                    src2: SrcOperand::Imm(total_size as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });

                // Store FP at [SP + size]
                push_op!(OpKind::Store {
                    src: fp,
                    addr: Address::BaseOffset {
                        base: sp,
                        offset: *size as i64,
                        disp_size: DispSize::Auto,
                    },
                    width: MemWidth::B4,
                });

                // Store LR at [SP + size + 4]
                push_op!(OpKind::Store {
                    src: lr,
                    addr: Address::BaseOffset {
                        base: sp,
                        offset: (*size + 4) as i64,
                        disp_size: DispSize::Auto,
                    },
                    width: MemWidth::B4,
                });

                // FP = SP + size
                push_op!(OpKind::Add {
                    dst: fp,
                    src1: sp,
                    src2: SrcOperand::Imm(*size as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });

                ControlFlow::Fallthrough
            }

            DecodedInsn::DeallocFrame {
                base,
                dst: _,
                update_lr_fp,
            } => {
                let sp = VReg::Arch(ArchReg::Hexagon(HexagonReg::Sp));
                let fp = VReg::Arch(ArchReg::Hexagon(HexagonReg::Fp));
                let lr = VReg::Arch(ArchReg::Hexagon(HexagonReg::Lr));

                if *update_lr_fp {
                    // Load FP from [base]
                    push_op!(OpKind::Load {
                        dst: fp,
                        addr: Address::Direct(self.hex_reg(*base)),
                        width: MemWidth::B4,
                        sign: SignExtend::Zero,
                    });

                    // Load LR from [base + 4]
                    push_op!(OpKind::Load {
                        dst: lr,
                        addr: Address::BaseOffset {
                            base: self.hex_reg(*base),
                            offset: 4,
                            disp_size: DispSize::Auto,
                        },
                        width: MemWidth::B4,
                        sign: SignExtend::Zero,
                    });
                }

                // SP = base + 8
                push_op!(OpKind::Add {
                    dst: sp,
                    src1: self.hex_reg(*base),
                    src2: SrcOperand::Imm(8),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });

                ControlFlow::Fallthrough
            }

            DecodedInsn::DeallocReturn {
                base,
                dst: _,
                pred: _,
                update_lr_fp,
            } => {
                let sp = VReg::Arch(ArchReg::Hexagon(HexagonReg::Sp));
                let fp = VReg::Arch(ArchReg::Hexagon(HexagonReg::Fp));
                let lr = VReg::Arch(ArchReg::Hexagon(HexagonReg::Lr));

                if *update_lr_fp {
                    push_op!(OpKind::Load {
                        dst: fp,
                        addr: Address::Direct(self.hex_reg(*base)),
                        width: MemWidth::B4,
                        sign: SignExtend::Zero,
                    });

                    push_op!(OpKind::Load {
                        dst: lr,
                        addr: Address::BaseOffset {
                            base: self.hex_reg(*base),
                            offset: 4,
                            disp_size: DispSize::Auto,
                        },
                        width: MemWidth::B4,
                        sign: SignExtend::Zero,
                    });
                }

                push_op!(OpKind::Add {
                    dst: sp,
                    src1: self.hex_reg(*base),
                    src2: SrcOperand::Imm(8),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });

                ControlFlow::Return
            }

            // ================================================================
            // System
            // ================================================================
            DecodedInsn::Trap0 => {
                push_op!(OpKind::Swi { imm: 0 });
                ControlFlow::Syscall
            }

            DecodedInsn::TfrCrR { dst, src } => {
                // Transfer from control register to general register
                push_op!(OpKind::ReadSysReg {
                    dst: self.hex_reg(*dst),
                    reg: *src as u32,
                });
                ControlFlow::Fallthrough
            }

            DecodedInsn::TfrRrCr { dst, src } => {
                // Transfer from general register to control register
                push_op!(OpKind::WriteSysReg {
                    reg: *dst as u32,
                    src: self.hex_reg(*src),
                });
                ControlFlow::Fallthrough
            }

            // ================================================================
            // Loop Setup
            // ================================================================
            DecodedInsn::LoopStartReg {
                loop_id,
                start_offset,
                count_reg,
            } => {
                let offset = ctx.extend_imm(*start_offset);
                let target = addr.wrapping_add(offset as i64 as u64);

                // Set SA (loop start address)
                let sa = if *loop_id == 0 {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Sa0))
                } else {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Sa1))
                };
                push_op!(OpKind::Mov {
                    dst: sa,
                    src: SrcOperand::Imm(target as i64),
                    width: OpWidth::W32,
                });

                // Set LC (loop count)
                let lc = if *loop_id == 0 {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Lc0))
                } else {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Lc1))
                };
                push_op!(OpKind::Mov {
                    dst: lc,
                    src: SrcOperand::Reg(self.hex_reg(*count_reg)),
                    width: OpWidth::W32,
                });

                ControlFlow::Fallthrough
            }

            DecodedInsn::LoopStartImm {
                loop_id,
                start_offset,
                count,
            } => {
                let offset = ctx.extend_imm(*start_offset);
                let target = addr.wrapping_add(offset as i64 as u64);

                let sa = if *loop_id == 0 {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Sa0))
                } else {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Sa1))
                };
                push_op!(OpKind::Mov {
                    dst: sa,
                    src: SrcOperand::Imm(target as i64),
                    width: OpWidth::W32,
                });

                let lc = if *loop_id == 0 {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Lc0))
                } else {
                    VReg::Arch(ArchReg::Hexagon(HexagonReg::Lc1))
                };
                push_op!(OpKind::Mov {
                    dst: lc,
                    src: SrcOperand::Imm(*count as i64),
                    width: OpWidth::W32,
                });

                ControlFlow::Fallthrough
            }

            DecodedInsn::ClearCond { dst, pred: _ } => {
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(*dst),
                    src: SrcOperand::Imm(0),
                    width: OpWidth::W32,
                });
                ControlFlow::Fallthrough
            }

            // New-value stores need packet producer context; the interpreter
            // path resolves them. Reject in the lifter so callers fall back.
            DecodedInsn::StoreNew { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "store_new".to_string(),
                });
            }

            // Read-modify-write memops are not lifted to SMIR (the interpreter
            // path in cpu.rs handles them); reject so callers fall back.
            DecodedInsn::MemOp { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "memop".to_string(),
                });
            }
            // HVX vector loads/stores are handled by the interpreter path.
            DecodedInsn::VLoad { .. } | DecodedInsn::VStore { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "vmem".to_string(),
                });
            }

            // ================================================================
            // Unknown
            // ================================================================
            DecodedInsn::Unknown(word) => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: format!("unknown: {:#010x}", word),
                });
            }
        };

        Ok((ops, control_flow))
    }
}

impl SmirLifter for HexagonLifter {
    fn source_arch(&self) -> SourceArch {
        SourceArch::Hexagon
    }

    fn lift_insn(
        &mut self,
        addr: GuestAddr,
        bytes: &[u8],
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if bytes.len() < 4 {
            return Err(LiftError::Incomplete {
                addr,
                have: bytes.len(),
                need: 4,
            });
        }

        let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());

        // Use the existing Hexagon decoder
        let decoded =
            crate::backend::emulator::hexagon::decode::decode(word, ctx.extended_imm, self.isa);

        let insn = decoded.insn;
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
            // Fetch instruction bytes
            let bytes = mem
                .read(current_addr, 4)
                .map_err(|e| LiftError::MemoryError {
                    addr: current_addr,
                    error: e,
                })?;

            // Lift the instruction
            let result = self.lift_insn(current_addr, &bytes, ctx)?;
            all_ops.extend(result.ops);
            current_addr += result.bytes_consumed as u64;

            // Check if block ends
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
                        // Need a condition vreg - use the last op if it's a SetCC
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

            // Track address range
            if block.guest_pc < min_addr {
                min_addr = block.guest_pc;
            }
            let block_end = block.guest_pc + (block.ops.len() * 4) as u64;
            if block_end > max_addr {
                max_addr = block_end;
            }

            // Add branch targets to worklist
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
            calling_convention: CallingConv::HexagonStd,
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

    struct MockMemory {
        data: Vec<u8>,
        base: GuestAddr,
    }

    impl MemoryReader for MockMemory {
        fn read(
            &self,
            addr: GuestAddr,
            size: usize,
        ) -> Result<Vec<u8>, crate::smir::memory::MemoryError> {
            let offset = (addr - self.base) as usize;
            if offset + size > self.data.len() {
                return Err(crate::smir::memory::MemoryError::OutOfBounds { addr });
            }
            Ok(self.data[offset..offset + size].to_vec())
        }
    }

    #[test]
    fn test_hexagon_lifter_add() {
        let mut lifter = HexagonLifter::default_isa();
        let mut ctx = LiftContext::new(SourceArch::Hexagon);

        // R0 = add(R1, R2) - encoded as a test
        // This is a simplified test - actual encoding would need the real opcode
        let bytes = [0x00u8, 0x00, 0x00, 0x00]; // Placeholder

        // We can't easily test without the actual decoder, but we can test the lifter structure
        assert_eq!(lifter.source_arch(), SourceArch::Hexagon);
    }

    #[test]
    fn test_lift_context_hexagon() {
        let mut ctx = LiftContext::new(SourceArch::Hexagon);

        // Test extended immediate
        ctx.set_extended_imm(0x12345);
        let extended = ctx.extend_imm(0x20);
        assert_eq!(extended, (0x12345i32 << 6) | 0x20);

        // Extension should be consumed
        let not_extended = ctx.extend_imm(0x30);
        assert_eq!(not_extended, 0x30);
    }
}

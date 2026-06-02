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
// Direct opcode-level decoding for the ~900 scalar ops that decode to
// `DecodedInsn::Unknown` (handled only by the sem layer in cpu.rs). The lifter
// re-decodes such words via `decode_word` and emits SMIR for the regular
// scalar register ops; see `lift_unknown_op`.
use crate::backend::emulator::hexagon::opcode::{DecodedOp, Opcode, decode_word};

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

    /// Convert an HVX vector register V0..V31 to an SMIR vector VReg.
    fn hex_v(&self, n: u8) -> VReg {
        VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)))
    }

    /// Convert an HVX vector predicate register Q0..Q3 to an SMIR vector VReg.
    fn hex_q(&self, n: u8) -> VReg {
        VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(n)))
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
            AddrMode::RegScaled { base, index, shift } => Address::BaseIndexScale {
                base: Some(self.hex_reg(*base)),
                index: self.hex_reg(*index),
                scale: 1u8 << *shift,
                disp: 0,
                disp_size: DispSize::Auto,
            },
            // `memX(Re=##U6)`: the absolute-set forms also write Re; the
            // interpreter handles that side effect (these reach the lifter only
            // via the rejecting `Load` arm below, which never calls `hex_addr`).
            AddrMode::AbsSet { addr, .. } => Address::Absolute(*addr as u64),
            // `memX(Ru<<#u2+##U6)`: scaled index plus an absolute displacement.
            AddrMode::IndexAbs { index, shift, addr } => Address::BaseIndexScale {
                base: None,
                index: self.hex_reg(*index),
                scale: 1u8 << *shift,
                disp: *addr as i32,
                disp_size: DispSize::Auto,
            },
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
            CmpKind::Gte => Condition::Sge,
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
            // `memX(Re=##U6)` absolute-set loads also WRITE the address
            // register Re; the simple Load op below cannot model that side
            // effect, so reject and let the interpreter handle it.
            DecodedInsn::Load {
                addr: AddrMode::AbsSet { .. },
                ..
            } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "load_abs_set".to_string(),
                });
            }

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

            // Shift-and-insert FIFO loads (`memX_fifo`, loadalign) read-modify a
            // register pair and the byte/half-unpack loads (membh/memubh) build
            // a halfword vector; both need bespoke commit semantics handled by
            // the interpreter path. Reject in the lifter so callers fall back.
            DecodedInsn::LoadAlign { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "loadalign".to_string(),
                });
            }
            DecodedInsn::LoadUnpack { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "load_unpack".to_string(),
                });
            }

            // Predicated and high-half (`storerf`) stores need conditional /
            // sub-word commit semantics that the simple Store op below does not
            // model; the interpreter path handles them. Reject so callers fall
            // back rather than silently storing unconditionally / the wrong half.
            DecodedInsn::Store { pred: Some(_), .. }
            | DecodedInsn::Store {
                high_half: true, ..
            } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "pred_or_high_half_store".to_string(),
                });
            }

            DecodedInsn::Store {
                src,
                addr,
                width,
                pred: _,
                src_new: _,
                high_half: _,
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

            // Predicated store-immediate (`if (Pv) memX(Rs+#u)=#s6`) needs the
            // conditional commit the interpreter provides; reject here.
            DecodedInsn::StoreImm { pred: Some(_), .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "pred_store_imm".to_string(),
                });
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

            // Predicated calls (`J2_callt`/`J2_callf`) are interpreter-only.
            DecodedInsn::Call { pred: Some(_), .. }
            | DecodedInsn::CallReg { pred: Some(_), .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "cond_call".to_string(),
                });
            }

            DecodedInsn::Call { offset, pred: None } => {
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

            DecodedInsn::CallReg { src, pred: None } => {
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

            // Control-register PAIR transfers and the dczeroa cache-line zero are
            // handled by the interpreter (the JIT path defers to it).
            DecodedInsn::TfrCrRPair { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "tfrcpp".to_string(),
                });
            }
            DecodedInsn::TfrRrCrPair { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "tfrpcp".to_string(),
                });
            }
            DecodedInsn::DcZero { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "dczeroa".to_string(),
                });
            }

            // ================================================================
            // Loop Setup
            // ================================================================
            // Software-pipelined loop setup (`sp*loop0`) sets USR.LPCFG and P3 in
            // addition to the loop registers; handled only by the interpreter.
            DecodedInsn::LoopStartReg { lpcfg: Some(_), .. }
            | DecodedInsn::LoopStartImm { lpcfg: Some(_), .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "sploop".to_string(),
                });
            }

            DecodedInsn::LoopStartReg {
                loop_id,
                start_offset,
                count_reg,
                lpcfg: None,
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
                lpcfg: None,
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

            // Load-locked sets an LL reservation the simple Load op does not
            // track; interpreter-only for now.
            DecodedInsn::LoadLocked { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "load_locked".to_string(),
                });
            }

            // Store-conditional / store-release sets a predicate side effect the
            // simple Store op does not model; interpreter-only for now.
            DecodedInsn::StoreCond { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "store_cond".to_string(),
                });
            }

            // Vector byte splice (`vspliceb`): register-pair op handled by the
            // interpreter path; reject in the lifter so callers fall back.
            DecodedInsn::Vsplice { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "vspliceb".to_string(),
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
            // HVX V65 scatter/gather are handled by the interpreter path.
            DecodedInsn::VScatter { .. } | DecodedInsn::VGather { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "vscatter_gather".to_string(),
                });
            }

            // J4 compound compare-and-jump, the jumpr-compare-zero family, the
            // jumpset compound, and `pause`: interpreter-only for now.
            DecodedInsn::CompoundCmpJump { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "compound_cmpjump".to_string(),
                });
            }
            DecodedInsn::JumpRegZero { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "jumpr_cmpzero".to_string(),
                });
            }
            DecodedInsn::JumpSet { .. } => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "jumpset".to_string(),
                });
            }
            DecodedInsn::Nop => {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "pause".to_string(),
                });
            }

            // ================================================================
            // Unknown to the DecodedInsn path — re-decode at the opcode level
            // and lift the regular scalar register ops the sem layer handles.
            // ================================================================
            DecodedInsn::Unknown(word) => {
                let dop = decode_word(*word).ok_or_else(|| LiftError::Unsupported {
                    addr,
                    mnemonic: format!("unknown: {:#010x}", word),
                })?;
                let extra = self.lift_unknown_op(&dop, addr, ctx, &mut op_id)?;
                ops.extend(extra);
                ControlFlow::Fallthrough
            }
        };

        Ok((ops, control_flow))
    }

    /// Lift a regular scalar register opcode that the `DecodedInsn` path leaves
    /// as `Unknown` (the ~900 ops handled only by the sem layer). Emits SMIR ops
    /// matching the sem-layer semantics bit-for-bit; returns `Unsupported` for
    /// anything not implemented (HVX, memory, control flow, saturating/USR ops,
    /// float, CABAC, predicated-cancel forms with no SMIR equivalent).
    ///
    /// All ops handled here are pure register/predicate computations with
    /// `ControlFlow::Fallthrough`, so this returns only the op list.
    fn lift_unknown_op(
        &self,
        dop: &DecodedOp,
        addr: GuestAddr,
        ctx: &mut LiftContext,
        op_id: &mut u16,
    ) -> Result<Vec<SmirOp>, LiftError> {
        let mut ops: Vec<SmirOp> = Vec::new();

        macro_rules! push_op {
            ($kind:expr) => {{
                ops.push(SmirOp::new(OpId(*op_id), addr, $kind));
                *op_id += 1;
            }};
        }

        let op = dop.opcode;
        let mnemonic = crate::backend::emulator::hexagon::opcode::opcode_name(op);
        let unsupported = || LiftError::Unsupported {
            addr,
            mnemonic: mnemonic.to_string(),
        };

        // --- field extraction (mirrors sem/mod.rs `fld`/`fimm_s`/`fimm_u`) ---
        // Consume the pending constant extender exactly once, matching the sem
        // layer's per-instruction `immext`.
        let immext = ctx.take_extended_imm();
        let fld = |letter: u8| -> u8 { dop.field(letter).map(|f| f.value as u8).unwrap_or(0) };
        // Signed immediate: extender (26:6 || imm5:0) if present, else sign-extend.
        let fimm_s = |letter: u8| -> i32 {
            match dop.field(letter) {
                Some(f) => match immext {
                    Some(ext) => (((ext & 0x03ff_ffff) << 6) | (f.value & 0x3f)) as i32,
                    None => {
                        let shift = 32u8.saturating_sub(f.bits);
                        ((f.value << shift) as i32) >> shift
                    }
                },
                None => 0,
            }
        };
        // Unsigned immediate.
        let fimm_u = |letter: u8| -> u32 {
            match dop.field(letter) {
                Some(f) => match immext {
                    Some(ext) => ((ext & 0x03ff_ffff) << 6) | (f.value & 0x3f),
                    None => f.value,
                },
                None => 0,
            }
        };

        // GPR / predicate register operands.
        let rs = self.hex_reg(fld(b's'));
        let rt = self.hex_reg(fld(b't'));
        let ru = self.hex_reg(fld(b'u'));
        let rd_n = fld(b'd');
        let rx_n = fld(b'x');
        let rd = self.hex_reg(rd_n);
        let rx = self.hex_reg(rx_n);

        // Helper: read a 64-bit register pair (even := low, odd := high) into a
        // fresh W64 temp = (R(odd) << 32) | R(even).
        macro_rules! read_pair {
            ($reg:expr) => {{
                let even = $reg & !1;
                let hi = ctx.alloc_vreg();
                let pair = ctx.alloc_vreg();
                push_op!(OpKind::Shl {
                    dst: hi,
                    src: self.hex_reg(even + 1),
                    amount: SrcOperand::Imm(32),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                push_op!(OpKind::Or {
                    dst: pair,
                    src1: hi,
                    src2: SrcOperand::Reg(self.hex_reg(even)),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                pair
            }};
        }

        // Helper: write a W64 temp `$val` into a register pair `$reg`.
        macro_rules! write_pair {
            ($reg:expr, $val:expr) => {{
                let even = $reg & !1;
                let v = $val;
                let hi = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(even),
                    src: SrcOperand::Reg(v),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Shr {
                    dst: hi,
                    src: v,
                    amount: SrcOperand::Imm(32),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(even + 1),
                    src: SrcOperand::Reg(hi),
                    width: OpWidth::W32,
                });
            }};
        }

        // Helper: a binary W64 op of two pair temps -> dst pair.
        macro_rules! pair_binop {
            ($mk:expr) => {{
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let r = ctx.alloc_vreg();
                push_op!($mk(r, a, b));
                write_pair!(rd_n, r);
            }};
        }

        // Helper: write a 32-bit value temp into Rd.
        macro_rules! set_r {
            ($val:expr) => {{
                let v = $val;
                push_op!(OpKind::Mov {
                    dst: rd,
                    src: SrcOperand::Reg(v),
                    width: OpWidth::W32,
                });
            }};
        }

        // Helper: write a 0/1 predicate truth from a condition-bearing flag set.
        // Compares `a` vs `b` (W32) and sets predicate Pd via SetCC(cond).
        macro_rules! cmp_set_pred {
            ($pred:expr, $a:expr, $b:expr, $cond:expr) => {{
                push_op!(OpKind::Cmp {
                    src1: $a,
                    src2: $b,
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: self.hex_pred($pred),
                    cond: $cond,
                    width: OpWidth::W32,
                });
            }};
        }

        // Emit a single-vector HVX elementwise op `Vd = op(Vu, Vv)` over the
        // full 1024-bit vector (`$lanes` elements of `$elem` bits, `$signed`).
        // Field layout mirrors the VV-form sem (dest `d`, sources `u`/`v`).
        macro_rules! vlane {
            ($op:expr, $elem:expr, $lanes:expr, $signed:expr) => {{
                push_op!(OpKind::VLane {
                    dst: self.hex_v(fld(b'd')),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    elem: $elem,
                    lanes: $lanes,
                    op: $op,
                    signed: $signed,
                });
            }};
        }

        // Emit a dual-vector HVX elementwise op `Vdd = op(Vuu, Vvv)` as two
        // independent elementwise ops over the even and odd registers of each
        // pair, matching the sem's `dv_*` dispatch (bases d/u/v and d+1/u+1/v+1;
        // the encoded pair base is even, so `+1` and `|1` coincide).
        macro_rules! vlane_dv {
            ($op:expr, $elem:expr, $lanes:expr, $signed:expr) => {{
                let (dd, uu, vv) = (fld(b'd'), fld(b'u'), fld(b'v'));
                push_op!(OpKind::VLane {
                    dst: self.hex_v(dd),
                    src1: self.hex_v(uu),
                    src2: self.hex_v(vv),
                    elem: $elem,
                    lanes: $lanes,
                    op: $op,
                    signed: $signed,
                });
                push_op!(OpKind::VLane {
                    dst: self.hex_v(dd + 1),
                    src1: self.hex_v(uu + 1),
                    src2: self.hex_v(vv + 1),
                    elem: $elem,
                    lanes: $lanes,
                    op: $op,
                    signed: $signed,
                });
            }};
        }

        match op {
            // ============================================================
            // A2 64-bit pair logical / arithmetic
            // ============================================================
            Opcode::A2_addp => pair_binop!(|r, a, b| OpKind::Add {
                dst: r,
                src1: a,
                src2: SrcOperand::Reg(b),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            }),
            // sub(Rtt,Rss): note operand order.
            Opcode::A2_subp => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Sub {
                    dst: r,
                    src1: b,
                    src2: SrcOperand::Reg(a),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                write_pair!(rd_n, r);
            }
            Opcode::A2_andp => pair_binop!(|r, a, b| OpKind::And {
                dst: r,
                src1: a,
                src2: SrcOperand::Reg(b),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            }),
            Opcode::A2_orp => pair_binop!(|r, a, b| OpKind::Or {
                dst: r,
                src1: a,
                src2: SrcOperand::Reg(b),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            }),
            Opcode::A2_xorp => pair_binop!(|r, a, b| OpKind::Xor {
                dst: r,
                src1: a,
                src2: SrcOperand::Reg(b),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            }),
            Opcode::A4_andnp => {
                // and(Rtt, ~Rss)
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::AndNot {
                    dst: r,
                    src1: b,
                    src2: SrcOperand::Reg(a),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                write_pair!(rd_n, r);
            }
            Opcode::A4_ornp => {
                // or(Rtt, ~Rss)
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let na = ctx.alloc_vreg();
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Not {
                    dst: na,
                    src: a,
                    width: OpWidth::W64,
                });
                push_op!(OpKind::Or {
                    dst: r,
                    src1: b,
                    src2: SrcOperand::Reg(na),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                write_pair!(rd_n, r);
            }
            Opcode::A2_negp => {
                let a = read_pair!(fld(b's'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Neg {
                    dst: r,
                    src: a,
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                write_pair!(rd_n, r);
            }
            Opcode::A2_notp => {
                let a = read_pair!(fld(b's'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Not {
                    dst: r,
                    src: a,
                    width: OpWidth::W64,
                });
                write_pair!(rd_n, r);
            }
            // sxtw: Rdd = sign-extend(Rs) to 64.
            Opcode::A2_sxtw => {
                let r = ctx.alloc_vreg();
                push_op!(OpKind::SignExtend {
                    dst: r,
                    src: rs,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                });
                write_pair!(rd_n, r);
            }

            // ============================================================
            // A2 min/max (32-bit, signed/unsigned) and pair forms
            // ============================================================
            Opcode::A2_max => {
                // max(Rs,Rt) = Rs > Rt ? Rs : Rt (signed)
                let c = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Sgt,
                    width: OpWidth::W32
                });
                push_op!(OpKind::Select {
                    dst: rd,
                    cond: c,
                    src_true: rs,
                    src_false: rt,
                    width: OpWidth::W32
                });
            }
            Opcode::A2_maxu => {
                let c = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Ugt,
                    width: OpWidth::W32
                });
                push_op!(OpKind::Select {
                    dst: rd,
                    cond: c,
                    src_true: rs,
                    src_false: rt,
                    width: OpWidth::W32
                });
            }
            // min(Rs,Rt) computed as min(Rt,Rs): Rt < Rs ? Rt : Rs (matches sem).
            Opcode::A2_min => {
                let c = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: rt,
                    src2: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Slt,
                    width: OpWidth::W32
                });
                push_op!(OpKind::Select {
                    dst: rd,
                    cond: c,
                    src_true: rt,
                    src_false: rs,
                    width: OpWidth::W32
                });
            }
            Opcode::A2_minu => {
                let c = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: rt,
                    src2: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Ult,
                    width: OpWidth::W32
                });
                push_op!(OpKind::Select {
                    dst: rd,
                    cond: c,
                    src_true: rt,
                    src_false: rs,
                    width: OpWidth::W32
                });
            }
            Opcode::A2_maxp => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let c = ctx.alloc_vreg();
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: a,
                    src2: SrcOperand::Reg(b),
                    width: OpWidth::W64
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Sgt,
                    width: OpWidth::W64
                });
                push_op!(OpKind::Select {
                    dst: r,
                    cond: c,
                    src_true: a,
                    src_false: b,
                    width: OpWidth::W64
                });
                write_pair!(rd_n, r);
            }
            Opcode::A2_maxup => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let c = ctx.alloc_vreg();
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: a,
                    src2: SrcOperand::Reg(b),
                    width: OpWidth::W64
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Ugt,
                    width: OpWidth::W64
                });
                push_op!(OpKind::Select {
                    dst: r,
                    cond: c,
                    src_true: a,
                    src_false: b,
                    width: OpWidth::W64
                });
                write_pair!(rd_n, r);
            }
            Opcode::A2_minp => {
                // min(Rtt,Rss)
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let c = ctx.alloc_vreg();
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: b,
                    src2: SrcOperand::Reg(a),
                    width: OpWidth::W64
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Slt,
                    width: OpWidth::W64
                });
                push_op!(OpKind::Select {
                    dst: r,
                    cond: c,
                    src_true: b,
                    src_false: a,
                    width: OpWidth::W64
                });
                write_pair!(rd_n, r);
            }
            Opcode::A2_minup => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let c = ctx.alloc_vreg();
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Cmp {
                    src1: b,
                    src2: SrcOperand::Reg(a),
                    width: OpWidth::W64
                });
                push_op!(OpKind::SetCC {
                    dst: c,
                    cond: Condition::Ult,
                    width: OpWidth::W64
                });
                push_op!(OpKind::Select {
                    dst: r,
                    cond: c,
                    src_true: b,
                    src_false: a,
                    width: OpWidth::W64
                });
                write_pair!(rd_n, r);
            }

            // ============================================================
            // A2 immediate logical / sub-reverse / halfword shifts / nop
            // ============================================================
            Opcode::A2_orir => {
                let imm = fimm_s(b'i');
                set_r!({
                    let r = ctx.alloc_vreg();
                    push_op!(OpKind::Or {
                        dst: r,
                        src1: rs,
                        src2: SrcOperand::Imm(imm as i64),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    });
                    r
                });
            }
            Opcode::A2_subri => {
                // Rd = #s10 - Rs
                let imm = fimm_s(b'i');
                let tmp = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: tmp,
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Sub {
                    dst: rd,
                    src1: tmp,
                    src2: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            Opcode::A2_aslh => {
                push_op!(OpKind::Shl {
                    dst: rd,
                    src: rs,
                    amount: SrcOperand::Imm(16),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            Opcode::A2_asrh => {
                push_op!(OpKind::Sar {
                    dst: rd,
                    src: rs,
                    amount: SrcOperand::Imm(16),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            Opcode::A2_nop => {
                push_op!(OpKind::Nop);
            }

            // ============================================================
            // A2 combine (pair + halfword) and A4 combine reg/imm
            // ============================================================
            // combine(Rs,Rt): word1 (high) = Rs, word0 (low) = Rt.
            Opcode::A2_combinew => {
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(rd_n & !1),
                    src: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Mov {
                    dst: self.hex_reg((rd_n & !1) + 1),
                    src: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                });
            }
            // combine(#s8,#S8): high (word1) = field i (extendable), low = field I.
            Opcode::A2_combineii => {
                let hi = fimm_s(b'i');
                let lo = {
                    // field I is not extendable here (sem passes None); replicate.
                    match dop.field(b'I') {
                        Some(f) => {
                            let shift = 32u8.saturating_sub(f.bits);
                            ((f.value << shift) as i32) >> shift
                        }
                        None => 0,
                    }
                };
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(rd_n & !1),
                    src: SrcOperand::Imm(lo as i64),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Mov {
                    dst: self.hex_reg((rd_n & !1) + 1),
                    src: SrcOperand::Imm(hi as i64),
                    width: OpWidth::W32,
                });
            }
            // A4_combineri: combine(Rs,#s8) -> word1=Rs, word0=#s8 (extendable).
            Opcode::A4_combineri => {
                let lo = fimm_s(b'i');
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(rd_n & !1),
                    src: SrcOperand::Imm(lo as i64),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Mov {
                    dst: self.hex_reg((rd_n & !1) + 1),
                    src: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                });
            }
            // A4_combineir: combine(#s8,Rs) -> word1=#s8 (extendable), word0=Rs.
            Opcode::A4_combineir => {
                let hi = fimm_s(b'i');
                push_op!(OpKind::Mov {
                    dst: self.hex_reg(rd_n & !1),
                    src: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                });
                push_op!(OpKind::Mov {
                    dst: self.hex_reg((rd_n & !1) + 1),
                    src: SrcOperand::Imm(hi as i64),
                    width: OpWidth::W32,
                });
            }
            // Halfword combine (single-word result): Rd = (Rt.X << 16) | Rs.Y.
            Opcode::A2_combine_hh
            | Opcode::A2_combine_hl
            | Opcode::A2_combine_lh
            | Opcode::A2_combine_ll => {
                let (t_hi, s_hi) = match op {
                    Opcode::A2_combine_hh => (true, true),
                    Opcode::A2_combine_hl => (true, false),
                    Opcode::A2_combine_lh => (false, true),
                    _ => (false, false),
                };
                // hi_part = (t_hi ? Rt>>16 : Rt&0xffff) << 16
                let hi_src = ctx.alloc_vreg();
                if t_hi {
                    push_op!(OpKind::Shr {
                        dst: hi_src,
                        src: rt,
                        amount: SrcOperand::Imm(16),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None
                    });
                } else {
                    push_op!(OpKind::And {
                        dst: hi_src,
                        src1: rt,
                        src2: SrcOperand::Imm(0xffff),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None
                    });
                }
                let hi_sh = ctx.alloc_vreg();
                push_op!(OpKind::Shl {
                    dst: hi_sh,
                    src: hi_src,
                    amount: SrcOperand::Imm(16),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                // lo_part = s_hi ? Rs>>16 : Rs&0xffff
                let lo = ctx.alloc_vreg();
                if s_hi {
                    push_op!(OpKind::Shr {
                        dst: lo,
                        src: rs,
                        amount: SrcOperand::Imm(16),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None
                    });
                } else {
                    push_op!(OpKind::And {
                        dst: lo,
                        src1: rs,
                        src2: SrcOperand::Imm(0xffff),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None
                    });
                }
                push_op!(OpKind::Or {
                    dst: rd,
                    src1: hi_sh,
                    src2: SrcOperand::Reg(lo),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }

            // ============================================================
            // A4 logical with negated operand (single word)
            // ============================================================
            Opcode::A4_andn => {
                // and(Rt, ~Rs)
                push_op!(OpKind::AndNot {
                    dst: rd,
                    src1: rt,
                    src2: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            Opcode::A4_orn => {
                // or(Rt, ~Rs)
                let ns = ctx.alloc_vreg();
                push_op!(OpKind::Not {
                    dst: ns,
                    src: rs,
                    width: OpWidth::W32
                });
                push_op!(OpKind::Or {
                    dst: rd,
                    src1: rt,
                    src2: SrcOperand::Reg(ns),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }

            // ============================================================
            // A4 compare-into-register (rcmp): Rd = (cond) ? 1 : 0
            // ============================================================
            Opcode::A4_rcmpeq => {
                push_op!(OpKind::Cmp {
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32
                });
                push_op!(OpKind::SetCC {
                    dst: rd,
                    cond: Condition::Eq,
                    width: OpWidth::W32
                });
            }
            Opcode::A4_rcmpneq => {
                push_op!(OpKind::Cmp {
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32
                });
                push_op!(OpKind::SetCC {
                    dst: rd,
                    cond: Condition::Ne,
                    width: OpWidth::W32
                });
            }
            Opcode::A4_rcmpeqi => {
                let imm = fimm_s(b'i');
                push_op!(OpKind::Cmp {
                    src1: rs,
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::SetCC {
                    dst: rd,
                    cond: Condition::Eq,
                    width: OpWidth::W32
                });
            }
            Opcode::A4_rcmpneqi => {
                let imm = fimm_s(b'i');
                push_op!(OpKind::Cmp {
                    src1: rs,
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::SetCC {
                    dst: rd,
                    cond: Condition::Ne,
                    width: OpWidth::W32
                });
            }

            // ============================================================
            // C2/C4 scalar register & pair compares -> predicate
            // ============================================================
            Opcode::C4_cmpneq => cmp_set_pred!(rd_n, rs, SrcOperand::Reg(rt), Condition::Ne),
            Opcode::C4_cmplte => cmp_set_pred!(rd_n, rs, SrcOperand::Reg(rt), Condition::Sle),
            Opcode::C4_cmplteu => cmp_set_pred!(rd_n, rs, SrcOperand::Reg(rt), Condition::Ule),
            Opcode::C4_cmpneqi => {
                let imm = fimm_s(b'i');
                cmp_set_pred!(rd_n, rs, SrcOperand::Imm(imm as i64), Condition::Ne);
            }
            Opcode::C4_cmpltei => {
                let imm = fimm_s(b'i');
                cmp_set_pred!(rd_n, rs, SrcOperand::Imm(imm as i64), Condition::Sle);
            }
            Opcode::C4_cmplteui => {
                let imm = fimm_u(b'i');
                cmp_set_pred!(rd_n, rs, SrcOperand::Imm(imm as i64), Condition::Ule);
            }
            Opcode::C2_cmpeqp => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                push_op!(OpKind::Cmp {
                    src1: a,
                    src2: SrcOperand::Reg(b),
                    width: OpWidth::W64
                });
                push_op!(OpKind::SetCC {
                    dst: self.hex_pred(rd_n),
                    cond: Condition::Eq,
                    width: OpWidth::W64
                });
            }
            Opcode::C2_cmpgtp => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                push_op!(OpKind::Cmp {
                    src1: a,
                    src2: SrcOperand::Reg(b),
                    width: OpWidth::W64
                });
                push_op!(OpKind::SetCC {
                    dst: self.hex_pred(rd_n),
                    cond: Condition::Sgt,
                    width: OpWidth::W64
                });
            }
            Opcode::C2_cmpgtup => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                push_op!(OpKind::Cmp {
                    src1: a,
                    src2: SrcOperand::Reg(b),
                    width: OpWidth::W64
                });
                push_op!(OpKind::SetCC {
                    dst: self.hex_pred(rd_n),
                    cond: Condition::Ugt,
                    width: OpWidth::W64
                });
            }

            // ============================================================
            // C2/C4 bit-test compares -> predicate
            // ============================================================
            Opcode::C2_bitsset => {
                // (Rs & Rt) == Rt
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Reg(rt), Condition::Eq);
            }
            Opcode::C4_nbitsset => {
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Reg(rt), Condition::Ne);
            }
            Opcode::C2_bitsclr => {
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Imm(0), Condition::Eq);
            }
            Opcode::C4_nbitsclr => {
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Imm(0), Condition::Ne);
            }
            Opcode::C2_bitsclri => {
                let imm = fimm_u(b'i');
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Imm(0), Condition::Eq);
            }
            Opcode::C4_nbitsclri => {
                let imm = fimm_u(b'i');
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Imm(0), Condition::Ne);
            }

            // ============================================================
            // C2 mux family: Rd = (Pu.lsb) ? a : b
            // ============================================================
            Opcode::C2_mux => {
                let cond = self.hex_pred(fld(b'u'));
                push_op!(OpKind::Select {
                    dst: rd,
                    cond,
                    src_true: rs,
                    src_false: rt,
                    width: OpWidth::W32
                });
            }
            Opcode::C2_muxir => {
                // Pu ? Rs : #s8
                let imm = fimm_s(b'i');
                let cond = self.hex_pred(fld(b'u'));
                let fv = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: fv,
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::Select {
                    dst: rd,
                    cond,
                    src_true: rs,
                    src_false: fv,
                    width: OpWidth::W32
                });
            }
            Opcode::C2_muxri => {
                // Pu ? #s8 : Rs
                let imm = fimm_s(b'i');
                let cond = self.hex_pred(fld(b'u'));
                let tv = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: tv,
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::Select {
                    dst: rd,
                    cond,
                    src_true: tv,
                    src_false: rs,
                    width: OpWidth::W32
                });
            }
            Opcode::C2_muxii => {
                // Pu ? #s8(i, ext) : #S8(I)
                let a = fimm_s(b'i');
                let b = match dop.field(b'I') {
                    Some(f) => {
                        let shift = 32u8.saturating_sub(f.bits);
                        ((f.value << shift) as i32) >> shift
                    }
                    None => 0,
                };
                let cond = self.hex_pred(fld(b'u'));
                let tv = ctx.alloc_vreg();
                let fv = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: tv,
                    src: SrcOperand::Imm(a as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::Mov {
                    dst: fv,
                    src: SrcOperand::Imm(b as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::Select {
                    dst: rd,
                    cond,
                    src_true: tv,
                    src_false: fv,
                    width: OpWidth::W32
                });
            }

            // ============================================================
            // C2/C4 predicate logic (operate on 0/1 predicate truth)
            // ============================================================
            Opcode::C2_and => {
                push_op!(OpKind::And {
                    dst: self.hex_pred(rd_n),
                    src1: self.hex_pred(fld(b's')),
                    src2: SrcOperand::Reg(self.hex_pred(fld(b't'))),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::C2_or => {
                push_op!(OpKind::Or {
                    dst: self.hex_pred(rd_n),
                    src1: self.hex_pred(fld(b's')),
                    src2: SrcOperand::Reg(self.hex_pred(fld(b't'))),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::C2_xor => {
                push_op!(OpKind::Xor {
                    dst: self.hex_pred(rd_n),
                    src1: self.hex_pred(fld(b's')),
                    src2: SrcOperand::Reg(self.hex_pred(fld(b't'))),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // The SMIR Hexagon context stores a predicate as a bool (truth =
            // value != 0), and the harness compares predicate LSB. AND/OR/XOR of
            // 0/1 predicates stay 0/1, but a bitwise NOT (`~Ps`) flips all 32
            // bits, so `!= 0` would read back TRUE even when the LSB is 0. Model
            // negation on the LSB only: `~Ps -> Ps ^ 1`.
            Opcode::C2_not => {
                push_op!(OpKind::Xor {
                    dst: self.hex_pred(rd_n),
                    src1: self.hex_pred(fld(b's')),
                    src2: SrcOperand::Imm(1),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::C2_andn => {
                // Pt & ~Ps  -> Pt & (Ps ^ 1)
                let nps = ctx.alloc_vreg();
                push_op!(OpKind::Xor {
                    dst: nps,
                    src1: self.hex_pred(fld(b's')),
                    src2: SrcOperand::Imm(1),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::And {
                    dst: self.hex_pred(rd_n),
                    src1: self.hex_pred(fld(b't')),
                    src2: SrcOperand::Reg(nps),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::C2_orn => {
                // Pt | ~Ps  -> Pt | (Ps ^ 1)
                let nps = ctx.alloc_vreg();
                push_op!(OpKind::Xor {
                    dst: nps,
                    src1: self.hex_pred(fld(b's')),
                    src2: SrcOperand::Imm(1),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Or {
                    dst: self.hex_pred(rd_n),
                    src1: self.hex_pred(fld(b't')),
                    src2: SrcOperand::Reg(nps),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }

            // ============================================================
            // C2 predicate <-> GPR transfers
            // ============================================================
            // Rd = zero-extend(Ps) — but the SMIR predicate holds only 0/1, so
            // the byte-splat (0xff) is NOT modelled. The harness only compares
            // predicate truth, but tfrpr WRITES A GPR; an 8-bit splat would
            // mismatch the interpreter's full byte value. Reject to stay exact.
            Opcode::C2_tfrpr => return Err(unsupported()),
            // Pd = fGETUBYTE(0,Rs) (low byte). The SMIR predicate stores only a
            // truth bit and the harness compares predicate LSB, so masking to
            // bit 0 (`Rs & 1`) is LSB-exact: Pd truth = bit0 of Rs, matching the
            // interpreter's `(Rs & 0xff) & 1`.
            Opcode::C2_tfrrp => {
                push_op!(OpKind::And {
                    dst: self.hex_pred(rd_n),
                    src1: rs,
                    src2: SrcOperand::Imm(1),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }

            // ============================================================
            // S2/S6 immediate single-word shifts & rotate
            // ============================================================
            // (S2_asl_i_r / asr_i_r / lsr_i_r are handled by the DecodedInsn path.)
            Opcode::S6_rol_i_r => {
                let n = fimm_u(b'i');
                push_op!(OpKind::Rol {
                    dst: rd,
                    src: rs,
                    amount: SrcOperand::Imm(n as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }

            // ============================================================
            // S2 immediate pair shifts
            // ============================================================
            Opcode::S2_asl_i_p => {
                let n = fimm_u(b'i');
                let a = read_pair!(fld(b's'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Shl {
                    dst: r,
                    src: a,
                    amount: SrcOperand::Imm(n as i64),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                write_pair!(rd_n, r);
            }
            Opcode::S2_asr_i_p => {
                let n = fimm_u(b'i');
                let a = read_pair!(fld(b's'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Sar {
                    dst: r,
                    src: a,
                    amount: SrcOperand::Imm(n as i64),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                write_pair!(rd_n, r);
            }
            Opcode::S2_lsr_i_p => {
                let n = fimm_u(b'i');
                let a = read_pair!(fld(b's'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Shr {
                    dst: r,
                    src: a,
                    amount: SrcOperand::Imm(n as i64),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                write_pair!(rd_n, r);
            }
            Opcode::S6_rol_i_p => {
                let n = fimm_u(b'i');
                let a = read_pair!(fld(b's'));
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Rol {
                    dst: r,
                    src: a,
                    amount: SrcOperand::Imm(n as i64),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                write_pair!(rd_n, r);
            }

            // ============================================================
            // S2/S4 bit manipulation
            // ============================================================
            Opcode::S2_setbit_i => {
                let n = fimm_u(b'i');
                push_op!(OpKind::Or {
                    dst: rd,
                    src1: rs,
                    src2: SrcOperand::Imm(1i64 << n),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::S2_clrbit_i => {
                let n = fimm_u(b'i');
                push_op!(OpKind::And {
                    dst: rd,
                    src1: rs,
                    src2: SrcOperand::Imm(!(1i64 << n) & 0xffff_ffff),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::S2_togglebit_i => {
                let n = fimm_u(b'i');
                push_op!(OpKind::Xor {
                    dst: rd,
                    src1: rs,
                    src2: SrcOperand::Imm(1i64 << n),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::S2_tstbit_i => {
                // Pd = (Rs & (1<<n)) != 0
                let n = fimm_u(b'i');
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Imm(1i64 << n),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Imm(0), Condition::Ne);
            }
            Opcode::S4_ntstbit_i => {
                let n = fimm_u(b'i');
                let m = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: m,
                    src1: rs,
                    src2: SrcOperand::Imm(1i64 << n),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                cmp_set_pred!(rd_n, m, SrcOperand::Imm(0), Condition::Eq);
            }
            // extractu: Rd = zero-extend(width, Rs >> offset). width=#u5(i),
            // offset=#U5(I); both unextended. width 0 -> 0.
            Opcode::S2_extractu => {
                let width = fimm_u(b'i');
                let offset = fimm_u(b'I');
                let v = ctx.alloc_vreg();
                push_op!(OpKind::Shr {
                    dst: v,
                    src: rs,
                    amount: SrcOperand::Imm(offset as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                let mask: i64 = if width == 0 {
                    0
                } else if width >= 32 {
                    0xffff_ffff
                } else {
                    (1i64 << width) - 1
                };
                push_op!(OpKind::And {
                    dst: rd,
                    src1: v,
                    src2: SrcOperand::Imm(mask),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // S2_insert: Rx = (Rx & ~(mask<<off)) | ((Rs & mask) << off).
            Opcode::S2_insert => {
                let width = fimm_u(b'i');
                let offset = fimm_u(b'I');
                let mask: i64 = if width >= 32 {
                    0xffff_ffff
                } else {
                    (1i64 << width) - 1
                };
                // (Rs & mask) << off
                let sm = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: sm,
                    src1: rs,
                    src2: SrcOperand::Imm(mask),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                let sml = ctx.alloc_vreg();
                push_op!(OpKind::Shl {
                    dst: sml,
                    src: sm,
                    amount: SrcOperand::Imm(offset as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                // Rx & ~(mask<<off)
                let clear: i64 = !((mask << offset) as u32 as i64) & 0xffff_ffff;
                let kept = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: kept,
                    src1: rx,
                    src2: SrcOperand::Imm(clear),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Or {
                    dst: rx,
                    src1: kept,
                    src2: SrcOperand::Reg(sml),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            Opcode::S2_tstbit_r => {
                // bit = bidir_lshiftl(1, sxt7(Rt)); Pd = (Rs & bit) != 0.
                // Modelled with a Rol-style barrel only for the in-range positive
                // case; the bidirectional negative shift has no SMIR equivalent.
                return Err(unsupported());
            }
            // clb/cl0/cl1/ct0/ct1 — bit counts. SMIR Clz/Ctz over 32-bit.
            Opcode::S2_cl0 => {
                // count leading zeros of Rs
                push_op!(OpKind::Clz {
                    dst: rd,
                    src: rs,
                    width: OpWidth::W32
                });
            }
            Opcode::S2_cl1 => {
                // count leading ones = clz(~Rs)
                let n = ctx.alloc_vreg();
                push_op!(OpKind::Not {
                    dst: n,
                    src: rs,
                    width: OpWidth::W32
                });
                push_op!(OpKind::Clz {
                    dst: rd,
                    src: n,
                    width: OpWidth::W32
                });
            }
            Opcode::S2_ct0 => {
                // count trailing zeros of Rs (Ctz returns width when 0; sem does
                // cl1(brev(~Rs)) which for Rs==0 gives 32 — matches Ctz of 0).
                push_op!(OpKind::Ctz {
                    dst: rd,
                    src: rs,
                    width: OpWidth::W32
                });
            }
            Opcode::S2_ct1 => {
                // count trailing ones = ctz(~Rs)
                let n = ctx.alloc_vreg();
                push_op!(OpKind::Not {
                    dst: n,
                    src: rs,
                    width: OpWidth::W32
                });
                push_op!(OpKind::Ctz {
                    dst: rd,
                    src: n,
                    width: OpWidth::W32
                });
            }
            Opcode::S2_brev => {
                push_op!(OpKind::Rbit {
                    dst: rd,
                    src: rs,
                    width: OpWidth::W32
                });
            }
            Opcode::S2_vsplatrb => {
                // Rd = (Rs & 0xff) replicated into 4 bytes.
                let b = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: b,
                    src1: rs,
                    src2: SrcOperand::Imm(0xff),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                // multiply by 0x01010101
                push_op!(OpKind::MulU {
                    dst_lo: rd,
                    dst_hi: None,
                    src1: b,
                    src2: SrcOperand::Imm(0x0101_0101),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            // Rdd = (Rs & 0xffff) replicated into 4 halfwords of a pair.
            Opcode::S2_vsplatrh => {
                let h = ctx.alloc_vreg();
                push_op!(OpKind::And {
                    dst: h,
                    src1: rs,
                    src2: SrcOperand::Imm(0xffff),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                let hz = ctx.alloc_vreg();
                push_op!(OpKind::ZeroExtend {
                    dst: hz,
                    src: h,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                let r = ctx.alloc_vreg();
                // 0x0001_0001_0001_0001 splats the halfword into all 4 lanes.
                push_op!(OpKind::MulU {
                    dst_lo: r,
                    dst_hi: None,
                    src1: hz,
                    src2: SrcOperand::Imm(0x0001_0001_0001_0001),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                write_pair!(rd_n, r);
            }

            // ============================================================
            // S4 add/sub-with-shift compounds, S2_addasl
            // ============================================================
            // S2_addasl_rrri: Rd = Rt + (Rs << #u3).
            Opcode::S2_addasl_rrri => {
                let n = fimm_u(b'i');
                let sh = ctx.alloc_vreg();
                push_op!(OpKind::Shl {
                    dst: sh,
                    src: rs,
                    amount: SrcOperand::Imm(n as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Add {
                    dst: rd,
                    src1: rt,
                    src2: SrcOperand::Reg(sh),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }

            // ============================================================
            // M2 scalar multiplies that map to MulS/MulU/MulAdd/MulSub
            // ============================================================
            // Rdd = (i32)Rs * (i32)Rt  (full signed 64-bit product, pair dst).
            Opcode::M2_dpmpyss_s0 => {
                let lo = self.hex_reg(rd_n & !1);
                let hi = self.hex_reg((rd_n & !1) + 1);
                push_op!(OpKind::MulS {
                    dst_lo: lo,
                    dst_hi: Some(hi),
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            Opcode::M2_dpmpyuu_s0 => {
                let lo = self.hex_reg(rd_n & !1);
                let hi = self.hex_reg((rd_n & !1) + 1);
                push_op!(OpKind::MulU {
                    dst_lo: lo,
                    dst_hi: Some(hi),
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            // Rxx +/-= (i32)Rs * (i32)Rt   (signed 64-bit product accumulate).
            // The 32x32 signed product fits in 64 bits, so a W64 MulS of the
            // sign-extended operands (dst_hi=None) gives the full product.
            Opcode::M2_dpmpyss_acc_s0 | Opcode::M2_dpmpyss_nac_s0 => {
                let se_s = ctx.alloc_vreg();
                let se_t = ctx.alloc_vreg();
                push_op!(OpKind::SignExtend {
                    dst: se_s,
                    src: rs,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                push_op!(OpKind::SignExtend {
                    dst: se_t,
                    src: rt,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                let prod = ctx.alloc_vreg();
                push_op!(OpKind::MulS {
                    dst_lo: prod,
                    dst_hi: None,
                    src1: se_s,
                    src2: SrcOperand::Reg(se_t),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                let acc = read_pair!(rx_n);
                let r = ctx.alloc_vreg();
                if matches!(op, Opcode::M2_dpmpyss_acc_s0) {
                    push_op!(OpKind::Add {
                        dst: r,
                        src1: acc,
                        src2: SrcOperand::Reg(prod),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None
                    });
                } else {
                    push_op!(OpKind::Sub {
                        dst: r,
                        src1: acc,
                        src2: SrcOperand::Reg(prod),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None
                    });
                }
                write_pair!(rx_n, r);
            }
            // Rxx +/-= (u32)Rs * (u32)Rt   (unsigned 64-bit product accumulate).
            Opcode::M2_dpmpyuu_acc_s0 | Opcode::M2_dpmpyuu_nac_s0 => {
                let ze_s = ctx.alloc_vreg();
                let ze_t = ctx.alloc_vreg();
                push_op!(OpKind::ZeroExtend {
                    dst: ze_s,
                    src: rs,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                push_op!(OpKind::ZeroExtend {
                    dst: ze_t,
                    src: rt,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                let prod = ctx.alloc_vreg();
                push_op!(OpKind::MulU {
                    dst_lo: prod,
                    dst_hi: None,
                    src1: ze_s,
                    src2: SrcOperand::Reg(ze_t),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                });
                let acc = read_pair!(rx_n);
                let r = ctx.alloc_vreg();
                if matches!(op, Opcode::M2_dpmpyuu_acc_s0) {
                    push_op!(OpKind::Add {
                        dst: r,
                        src1: acc,
                        src2: SrcOperand::Reg(prod),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None
                    });
                } else {
                    push_op!(OpKind::Sub {
                        dst: r,
                        src1: acc,
                        src2: SrcOperand::Reg(prod),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None
                    });
                }
                write_pair!(rx_n, r);
            }

            // Rd = ((i32)Rs * (i32)Rt + 0x80000000) >> 32  (rounded high half).
            Opcode::M2_dpmpyss_rnd_s0 => {
                let se_s = ctx.alloc_vreg();
                let se_t = ctx.alloc_vreg();
                push_op!(OpKind::SignExtend {
                    dst: se_s,
                    src: rs,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                push_op!(OpKind::SignExtend {
                    dst: se_t,
                    src: rt,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                let prod = ctx.alloc_vreg();
                push_op!(OpKind::MulS {
                    dst_lo: prod,
                    dst_hi: None,
                    src1: se_s,
                    src2: SrcOperand::Reg(se_t),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                let rnd = ctx.alloc_vreg();
                push_op!(OpKind::Add {
                    dst: rnd,
                    src1: prod,
                    src2: SrcOperand::Imm(0x8000_0000),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Sar {
                    dst: rd,
                    src: rnd,
                    amount: SrcOperand::Imm(32),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
            }

            // Rd = high 32 bits of signed/unsigned 32x32 product.
            Opcode::M2_mpy_up => {
                let lo = ctx.alloc_vreg();
                push_op!(OpKind::MulS {
                    dst_lo: lo,
                    dst_hi: Some(rd),
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            Opcode::M2_mpyu_up => {
                let lo = ctx.alloc_vreg();
                push_op!(OpKind::MulU {
                    dst_lo: lo,
                    dst_hi: Some(rd),
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            // Rd = ((i32)Rs * (u32)Rt) >> 32. The product fits in i64; zero-
            // extending Rt makes it non-negative as i64, so a signed W64 multiply
            // yields the correct signed*unsigned product.
            Opcode::M2_mpysu_up => {
                let se_s = ctx.alloc_vreg();
                let ze_t = ctx.alloc_vreg();
                push_op!(OpKind::SignExtend {
                    dst: se_s,
                    src: rs,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                push_op!(OpKind::ZeroExtend {
                    dst: ze_t,
                    src: rt,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                let prod = ctx.alloc_vreg();
                push_op!(OpKind::MulS {
                    dst_lo: prod,
                    dst_hi: None,
                    src1: se_s,
                    src2: SrcOperand::Reg(ze_t),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Sar {
                    dst: rd,
                    src: prod,
                    amount: SrcOperand::Imm(32),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
            }
            // Rd = ((i32)Rs * (i32)Rt) >> 31  (Q1.31 high-half, no saturation).
            Opcode::M2_mpy_up_s1 => {
                let se_s = ctx.alloc_vreg();
                let se_t = ctx.alloc_vreg();
                push_op!(OpKind::SignExtend {
                    dst: se_s,
                    src: rs,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                push_op!(OpKind::SignExtend {
                    dst: se_t,
                    src: rt,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64
                });
                let prod = ctx.alloc_vreg();
                push_op!(OpKind::MulS {
                    dst_lo: prod,
                    dst_hi: None,
                    src1: se_s,
                    src2: SrcOperand::Reg(se_t),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Sar {
                    dst: rd,
                    src: prod,
                    amount: SrcOperand::Imm(31),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
            }
            // Rd = Rs * #u8 (extendable). Low 32 bits.
            Opcode::M2_mpysip => {
                let imm = fimm_u(b'i');
                let iv = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: iv,
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::MulU {
                    dst_lo: rd,
                    dst_hi: None,
                    src1: rs,
                    src2: SrcOperand::Reg(iv),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            // Rd = Rs * (-#u8)  (not extendable).
            Opcode::M2_mpysin => {
                let imm = fimm_u(b'i').wrapping_neg();
                let iv = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: iv,
                    src: SrcOperand::Imm(imm as i32 as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::MulU {
                    dst_lo: rd,
                    dst_hi: None,
                    src1: rs,
                    src2: SrcOperand::Reg(iv),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                });
            }
            // Rx += Rs * Rt   (MulAdd: dst = acc + src1*src2; low 32).
            Opcode::M2_maci => {
                push_op!(OpKind::MulAdd {
                    dst: rx,
                    acc: rx,
                    src1: rs,
                    src2: rt,
                    width: OpWidth::W32
                });
            }
            // Rx -= Rs * Rt   (MulSub: dst = acc - src1*src2).
            Opcode::M2_mnaci => {
                push_op!(OpKind::MulSub {
                    dst: rx,
                    acc: rx,
                    src1: rs,
                    src2: rt,
                    width: OpWidth::W32
                });
            }
            // Rx += Rs * #u8 (extendable).
            Opcode::M2_macsip => {
                let imm = fimm_u(b'i');
                let iv = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: iv,
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::MulAdd {
                    dst: rx,
                    acc: rx,
                    src1: rs,
                    src2: iv,
                    width: OpWidth::W32
                });
            }
            // Rx -= Rs * #u8 (extendable).
            Opcode::M2_macsin => {
                let imm = fimm_u(b'i');
                let iv = ctx.alloc_vreg();
                push_op!(OpKind::Mov {
                    dst: iv,
                    src: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32
                });
                push_op!(OpKind::MulSub {
                    dst: rx,
                    acc: rx,
                    src1: rs,
                    src2: iv,
                    width: OpWidth::W32
                });
            }
            // Rx += Rs + Rt
            Opcode::M2_acci => {
                let s = ctx.alloc_vreg();
                push_op!(OpKind::Add {
                    dst: s,
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Add {
                    dst: rx,
                    src1: rx,
                    src2: SrcOperand::Reg(s),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // Rx += Rs + #s8 (extendable)
            Opcode::M2_accii => {
                let imm = fimm_s(b'i');
                let s = ctx.alloc_vreg();
                push_op!(OpKind::Add {
                    dst: s,
                    src1: rs,
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Add {
                    dst: rx,
                    src1: rx,
                    src2: SrcOperand::Reg(s),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // Rx -= (Rs + Rt)
            Opcode::M2_nacci => {
                let s = ctx.alloc_vreg();
                push_op!(OpKind::Add {
                    dst: s,
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Sub {
                    dst: rx,
                    src1: rx,
                    src2: SrcOperand::Reg(s),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // Rx -= (Rs + #s8) (extendable)
            Opcode::M2_naccii => {
                let imm = fimm_s(b'i');
                let s = ctx.alloc_vreg();
                push_op!(OpKind::Add {
                    dst: s,
                    src1: rs,
                    src2: SrcOperand::Imm(imm as i64),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Sub {
                    dst: rx,
                    src1: rx,
                    src2: SrcOperand::Reg(s),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // Rx += Rt - Rs
            Opcode::M2_subacc => {
                let s = ctx.alloc_vreg();
                push_op!(OpKind::Sub {
                    dst: s,
                    src1: rt,
                    src2: SrcOperand::Reg(rs),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Add {
                    dst: rx,
                    src1: rx,
                    src2: SrcOperand::Reg(s),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // Rx ^= Rs ^ Rt
            Opcode::M2_xor_xacc => {
                let s = ctx.alloc_vreg();
                push_op!(OpKind::Xor {
                    dst: s,
                    src1: rs,
                    src2: SrcOperand::Reg(rt),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Xor {
                    dst: rx,
                    src1: rx,
                    src2: SrcOperand::Reg(s),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None
                });
            }
            // Rxx ^= Rss ^ Rtt
            Opcode::M4_xor_xacc => {
                let a = read_pair!(fld(b's'));
                let b = read_pair!(fld(b't'));
                let x = read_pair!(rx_n);
                let s = ctx.alloc_vreg();
                let r = ctx.alloc_vreg();
                push_op!(OpKind::Xor {
                    dst: s,
                    src1: a,
                    src2: SrcOperand::Reg(b),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                push_op!(OpKind::Xor {
                    dst: r,
                    src1: x,
                    src2: SrcOperand::Reg(s),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None
                });
                write_pair!(rx_n, r);
            }

            // ============================================================
            // HVX (V6_*) elementwise integer vector ops
            //
            // HVX vectors are 1024-bit (V0..V31). The SMIR vector ops execute
            // over the full 1024-bit VecValue via read_vec/write_vec, which map
            // VReg::Arch(Hexagon::V(n)) to the interpreter's V state. We use
            // elem=I8/lanes=128 (byte), I16/lanes=64 (half), I32/lanes=32 (word).
            //
            // Field layout mirrors the sem layer (sem/hvx*.rs): the dest vreg is
            // `fld(b'd')`, the two vector sources are `fld(b'u')` and `fld(b'v')`,
            // the scalar shift-amount register (vasl/vlsr-by-Rt) is `fld(b't')`.
            // ============================================================

            // ---- non-saturating vector add (Vd = vadd(Vu,Vv)) ----
            // VAdd uses wrapping_add per lane: matches V6_vaddb/h/w exactly.
            Opcode::V6_vaddb => push_op!(OpKind::VAdd {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I8,
                lanes: 128,
            }),
            Opcode::V6_vaddh => push_op!(OpKind::VAdd {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                lanes: 64,
            }),
            Opcode::V6_vaddw => push_op!(OpKind::VAdd {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I32,
                lanes: 32,
            }),

            // ---- non-saturating vector sub (Vd = vsub(Vu,Vv)) ----
            // VSub uses wrapping_sub per lane: matches V6_vsubb/h/w exactly.
            // sem computes a.wrapping_sub(b) with a=Vu, b=Vv (map_*(&vu,&vv,..)).
            Opcode::V6_vsubb => push_op!(OpKind::VSub {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I8,
                lanes: 128,
            }),
            Opcode::V6_vsubh => push_op!(OpKind::VSub {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                lanes: 64,
            }),
            Opcode::V6_vsubw => push_op!(OpKind::VSub {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I32,
                lanes: 32,
            }),

            // ---- unsigned vector min/max ----
            // The SMIR VMax operates on the zero-extended lane value (get_lane
            // masks to elem_bits), so a.max(b) is an UNSIGNED compare. That
            // matches V6_vmaxub/vmaxuh (unsigned max) only. The signed forms
            // (vmaxb/h/w) and VMin (interp stub) are reported in needs_opkind.
            Opcode::V6_vmaxub => push_op!(OpKind::VMax {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I8,
                lanes: 128,
            }),
            Opcode::V6_vmaxuh => push_op!(OpKind::VMax {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                lanes: 64,
            }),

            // ---- non-widening vector integer multiply (low half) ----
            // V6_vmpyih: Vd.h = vmpyi(Vu.h, Vv.h) — per-halfword 16x16 product
            // keeping the LOW 16 bits. VMul routes through vec_binary_op with
            // wrapping_mul on zero-extended lanes, then set_lane masks to 16
            // bits. The low 16 bits of an integer product are identical for
            // signed and unsigned operands, so this is bit-exact with the sem
            // layer's `(get_h(a,i) as i32 * get_h(b,i) as i32) as u16`.
            // (The scalar-by-vector forms vmpyihb/vmpyiwb/vmpyiwh select a
            // byte/half of Rt per lane (i%4 / i%2); VMul is vector-by-vector
            // only and cannot express them — reported in needs_opkind.)
            Opcode::V6_vmpyih => push_op!(OpKind::VMul {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                lanes: 64,
            }),

            // ---- vector shifts by scalar Rt ----
            // VShift reads a single scalar amount and shifts every lane by it,
            // masking the result to elem_bits. The interp computes amt % elem_bits
            // which equals the sem layer's `rt & (elem_bits-1)`.
            //   Lsl (vasl*) and Lsr (vlsr*) match bit-exactly.
            //   Asr (vasr*) does NOT match: VShift's Asr treats the zero-extended
            //   lane as i64 (no per-lane sign extension), so negative lanes shift
            //   in zeros instead of the sign bit. Reported in needs_opkind.
            Opcode::V6_vaslh => push_op!(OpKind::VShift {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                shift: ShiftOp::Lsl,
                elem: VecElementType::I16,
                lanes: 64,
            }),
            Opcode::V6_vaslw => push_op!(OpKind::VShift {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                shift: ShiftOp::Lsl,
                elem: VecElementType::I32,
                lanes: 32,
            }),
            Opcode::V6_vlsrb => push_op!(OpKind::VShift {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                shift: ShiftOp::Lsr,
                elem: VecElementType::I8,
                lanes: 128,
            }),
            Opcode::V6_vlsrh => push_op!(OpKind::VShift {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                shift: ShiftOp::Lsr,
                elem: VecElementType::I16,
                lanes: 64,
            }),
            Opcode::V6_vlsrw => push_op!(OpKind::VShift {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                shift: ShiftOp::Lsr,
                elem: VecElementType::I32,
                lanes: 32,
            }),

            // ---- per-lane bidirectional vector-amount shifts ----
            // `Vd = vasl/vasr/vlsr(Vu, Vv)`: each lane of the value Vu (fld 'u')
            // is shifted by the signed per-lane amount in Vv (fld 'v'), where the
            // sem takes `sxtn(low log2(elem_bits)+1 bits of the amount lane)`
            // (n=5 for .h, n=6 for .w). OpKind::VShiftV reproduces this exactly,
            // bidirectional (a negative amount shifts the opposite way).
            //   VShiftVKind::AshiftL = vaslhv/vaslwv (arithmetic left)
            //   VShiftVKind::AshiftR = vasrhv/vasrwv (arithmetic right)
            //   VShiftVKind::LshiftR = vlsrhv/vlsrwv (logical right)
            Opcode::V6_vaslhv => push_op!(OpKind::VShiftV {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                lanes: 64,
                kind: VShiftVKind::AshiftL,
            }),
            Opcode::V6_vaslwv => push_op!(OpKind::VShiftV {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: self.hex_v(fld(b'v')),
                elem: VecElementType::I32,
                lanes: 32,
                kind: VShiftVKind::AshiftL,
            }),
            Opcode::V6_vasrhv => push_op!(OpKind::VShiftV {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                lanes: 64,
                kind: VShiftVKind::AshiftR,
            }),
            Opcode::V6_vasrwv => push_op!(OpKind::VShiftV {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: self.hex_v(fld(b'v')),
                elem: VecElementType::I32,
                lanes: 32,
                kind: VShiftVKind::AshiftR,
            }),
            Opcode::V6_vlsrhv => push_op!(OpKind::VShiftV {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                lanes: 64,
                kind: VShiftVKind::LshiftR,
            }),
            Opcode::V6_vlsrwv => push_op!(OpKind::VShiftV {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: self.hex_v(fld(b'v')),
                elem: VecElementType::I32,
                lanes: 32,
                kind: VShiftVKind::LshiftR,
            }),

            // ---- vassign: Vd = Vu (full-vector copy) ----
            // VMov uses read_vec/write_vec over the full 1024-bit VecValue.
            Opcode::V6_vassign => push_op!(OpKind::VMov {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                width: VecWidth::V512,
            }),

            // ============================================================
            // HVX elementwise VLane ops (Wave 2)
            //
            // `OpKind::VLane` runs `op` over `lanes` elements of `elem` bits
            // across the full 1024-bit HVX vector, signed iff `signed`. Field
            // layout is the VV form `Vd = op(Vu, Vv)`: dest `fld(b'd')`, sources
            // `fld(b'u')`/`fld(b'v')`, matching the existing VAdd/VSub arms.
            //
            // `vlane!`     — single-vector  Vd = op(Vu, Vv).
            // `vlane_dv!`  — dual-vector    Vdd = op(Vuu, Vvv): two independent
            //                elementwise ops over the even/odd register of each
            //                pair (sem dispatches via `dv_*` on bases d/u/v and
            //                d+1/u+1/v+1; the pair base from the encoding is even
            //                so `+1` and `|1` coincide).
            // ============================================================
            // ---- bitwise logical (elem/lanes irrelevant; span 1024 bits as
            // 32 x I32). sem: map_w(a&b / a|b / a^b). ----
            Opcode::V6_vand => vlane!(VLaneOp::And, VecElementType::I32, 32, false),
            Opcode::V6_vor => vlane!(VLaneOp::Or, VecElementType::I32, 32, false),
            Opcode::V6_vxor => vlane!(VLaneOp::Xor, VecElementType::I32, 32, false),

            // ---- signed min/max (sem hvx_minmax: (a as iN).min/max) ----
            Opcode::V6_vmaxb => vlane!(VLaneOp::Max, VecElementType::I8, 128, true),
            Opcode::V6_vmaxh => vlane!(VLaneOp::Max, VecElementType::I16, 64, true),
            Opcode::V6_vmaxw => vlane!(VLaneOp::Max, VecElementType::I32, 32, true),
            Opcode::V6_vminb => vlane!(VLaneOp::Min, VecElementType::I8, 128, true),
            Opcode::V6_vminh => vlane!(VLaneOp::Min, VecElementType::I16, 64, true),
            Opcode::V6_vminw => vlane!(VLaneOp::Min, VecElementType::I32, 32, true),
            // ---- unsigned min/max (sem: a.min/max on the raw lane). vmaxub/uh
            // are already lifted via VMax in Wave 1 — only add the new ones. ----
            Opcode::V6_vminub => vlane!(VLaneOp::Min, VecElementType::I8, 128, false),
            Opcode::V6_vminuh => vlane!(VLaneOp::Min, VecElementType::I16, 64, false),

            // ---- signed saturating add/sub (single vector). sem clamps the
            // widened signed sum/difference to the lane's signed range. ----
            Opcode::V6_vaddbsat => vlane!(VLaneOp::AddSat, VecElementType::I8, 128, true),
            Opcode::V6_vaddhsat => vlane!(VLaneOp::AddSat, VecElementType::I16, 64, true),
            Opcode::V6_vaddwsat => vlane!(VLaneOp::AddSat, VecElementType::I32, 32, true),
            Opcode::V6_vsubbsat => vlane!(VLaneOp::SubSat, VecElementType::I8, 128, true),
            Opcode::V6_vsubhsat => vlane!(VLaneOp::SubSat, VecElementType::I16, 64, true),
            Opcode::V6_vsubwsat => vlane!(VLaneOp::SubSat, VecElementType::I32, 32, true),
            // ---- unsigned saturating add/sub (single vector). sem clamps to the
            // lane's unsigned range (checked_add / saturating_sub). ----
            Opcode::V6_vaddubsat => vlane!(VLaneOp::AddSat, VecElementType::I8, 128, false),
            Opcode::V6_vadduhsat => vlane!(VLaneOp::AddSat, VecElementType::I16, 64, false),
            Opcode::V6_vadduwsat => vlane!(VLaneOp::AddSat, VecElementType::I32, 32, false),
            Opcode::V6_vsububsat => vlane!(VLaneOp::SubSat, VecElementType::I8, 128, false),
            Opcode::V6_vsubuhsat => vlane!(VLaneOp::SubSat, VecElementType::I16, 64, false),

            // ---- saturating add/sub, dual-vector (Vdd = op(Vuu, Vvv)) ----
            // signed
            Opcode::V6_vaddbsat_dv => vlane_dv!(VLaneOp::AddSat, VecElementType::I8, 128, true),
            Opcode::V6_vaddhsat_dv => vlane_dv!(VLaneOp::AddSat, VecElementType::I16, 64, true),
            Opcode::V6_vaddwsat_dv => vlane_dv!(VLaneOp::AddSat, VecElementType::I32, 32, true),
            Opcode::V6_vsubbsat_dv => vlane_dv!(VLaneOp::SubSat, VecElementType::I8, 128, true),
            Opcode::V6_vsubhsat_dv => vlane_dv!(VLaneOp::SubSat, VecElementType::I16, 64, true),
            Opcode::V6_vsubwsat_dv => vlane_dv!(VLaneOp::SubSat, VecElementType::I32, 32, true),
            // unsigned
            Opcode::V6_vaddubsat_dv => vlane_dv!(VLaneOp::AddSat, VecElementType::I8, 128, false),
            Opcode::V6_vadduhsat_dv => vlane_dv!(VLaneOp::AddSat, VecElementType::I16, 64, false),
            Opcode::V6_vadduwsat_dv => vlane_dv!(VLaneOp::AddSat, VecElementType::I32, 32, false),
            Opcode::V6_vsububsat_dv => vlane_dv!(VLaneOp::SubSat, VecElementType::I8, 128, false),
            Opcode::V6_vsubuhsat_dv => vlane_dv!(VLaneOp::SubSat, VecElementType::I16, 64, false),
            Opcode::V6_vsubuwsat_dv => vlane_dv!(VLaneOp::SubSat, VecElementType::I32, 32, false),

            // ---- truncating average (a+b)>>1 (sem hvx_minmax: avg(...,0)) ----
            // unsigned
            Opcode::V6_vavgub => vlane!(VLaneOp::Avg, VecElementType::I8, 128, false),
            Opcode::V6_vavguh => vlane!(VLaneOp::Avg, VecElementType::I16, 64, false),
            Opcode::V6_vavguw => vlane!(VLaneOp::Avg, VecElementType::I32, 32, false),
            // signed
            Opcode::V6_vavgb => vlane!(VLaneOp::Avg, VecElementType::I8, 128, true),
            Opcode::V6_vavgh => vlane!(VLaneOp::Avg, VecElementType::I16, 64, true),
            Opcode::V6_vavgw => vlane!(VLaneOp::Avg, VecElementType::I32, 32, true),
            // ---- rounding average (a+b+1)>>1 (sem: avg(...,1)) ----
            // unsigned
            Opcode::V6_vavgubrnd => vlane!(VLaneOp::AvgRnd, VecElementType::I8, 128, false),
            Opcode::V6_vavguhrnd => vlane!(VLaneOp::AvgRnd, VecElementType::I16, 64, false),
            Opcode::V6_vavguwrnd => vlane!(VLaneOp::AvgRnd, VecElementType::I32, 32, false),
            // signed
            Opcode::V6_vavgbrnd => vlane!(VLaneOp::AvgRnd, VecElementType::I8, 128, true),
            Opcode::V6_vavghrnd => vlane!(VLaneOp::AvgRnd, VecElementType::I16, 64, true),
            Opcode::V6_vavgwrnd => vlane!(VLaneOp::AvgRnd, VecElementType::I32, 32, true),

            // ---- absolute difference |a-b| (non-saturating) ----
            // unsigned (sem: if a>b {a-b} else {b-a} on the raw lane)
            Opcode::V6_vabsdiffub => vlane!(VLaneOp::AbsDiff, VecElementType::I8, 128, false),
            Opcode::V6_vabsdiffuh => vlane!(VLaneOp::AbsDiff, VecElementType::I16, 64, false),
            // signed (sem: (a as iN - b as iN).unsigned_abs())
            Opcode::V6_vabsdiffh => vlane!(VLaneOp::AbsDiff, VecElementType::I16, 64, true),
            Opcode::V6_vabsdiffw => vlane!(VLaneOp::AbsDiff, VecElementType::I32, 32, true),

            // ============================================================
            // HVX vector-by-vector WIDENING multiplies -> register PAIR.
            //
            // `Vdd.<2w> = vmpy(Vu.<w>, Vv.<w>)` (and the `Vxx += ...` acc form):
            // each pair of adjacent NARROW lanes is multiplied into a
            // double-width product; the EVEN narrow lanes' products go to the
            // low vector (V[base]) and the ODD lanes' to the high (V[base+1]).
            // OpKind::VWidenMul models exactly this layout (see interp.rs):
            // even/odd split, per-operand signedness, and `acc` read-modify-
            // write of the dst pair. `src_elem` is the NARROW lane type — I8
            // for byte multiplies (-> halfword pair), I16 for half (-> word
            // pair). The dst pair base is `fld(b'd')` for the plain form and
            // `fld(b'x')` for the `_acc` form (which reads+writes that pair).
            //
            // Mapping (confirmed against sem/hvx_mpyv.rs):
            //   vmpybv   Vu.b  x Vv.b  -> .h pair  signed×signed
            //   vmpybusv Vu.ub x Vv.b  -> .h pair  unsigned×signed
            //   vmpyubv  Vu.ub x Vv.ub -> .uh pair unsigned×unsigned
            //   vmpyhv   Vu.h  x Vv.h  -> .w pair  signed×signed
            //   vmpyhus  Vu.h  x Vv.uh -> .w pair  signed×unsigned
            //   vmpyuhv  Vu.uh x Vv.uh -> .uw pair unsigned×unsigned
            // The sem layer wraps the (acc + product) into the lane width via
            // `as u16`/`as u32`, identical to VWidenMul's wrapping_add + masked
            // set_lane, so signed/unsigned accumulate forms are bit-identical.
            Opcode::V6_vmpybv | Opcode::V6_vmpybv_acc => {
                let base = if matches!(op, Opcode::V6_vmpybv_acc) {
                    rx_n
                } else {
                    rd_n
                };
                push_op!(OpKind::VWidenMul {
                    dst_lo: self.hex_v(base),
                    dst_hi: self.hex_v(base + 1),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src_elem: VecElementType::I8,
                    signed1: true,
                    signed2: true,
                    acc: matches!(op, Opcode::V6_vmpybv_acc),
                });
            }
            Opcode::V6_vmpybusv | Opcode::V6_vmpybusv_acc => {
                let base = if matches!(op, Opcode::V6_vmpybusv_acc) {
                    rx_n
                } else {
                    rd_n
                };
                push_op!(OpKind::VWidenMul {
                    dst_lo: self.hex_v(base),
                    dst_hi: self.hex_v(base + 1),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src_elem: VecElementType::I8,
                    signed1: false,
                    signed2: true,
                    acc: matches!(op, Opcode::V6_vmpybusv_acc),
                });
            }
            Opcode::V6_vmpyubv | Opcode::V6_vmpyubv_acc => {
                let base = if matches!(op, Opcode::V6_vmpyubv_acc) {
                    rx_n
                } else {
                    rd_n
                };
                push_op!(OpKind::VWidenMul {
                    dst_lo: self.hex_v(base),
                    dst_hi: self.hex_v(base + 1),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src_elem: VecElementType::I8,
                    signed1: false,
                    signed2: false,
                    acc: matches!(op, Opcode::V6_vmpyubv_acc),
                });
            }
            Opcode::V6_vmpyhv | Opcode::V6_vmpyhv_acc => {
                let base = if matches!(op, Opcode::V6_vmpyhv_acc) {
                    rx_n
                } else {
                    rd_n
                };
                push_op!(OpKind::VWidenMul {
                    dst_lo: self.hex_v(base),
                    dst_hi: self.hex_v(base + 1),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src_elem: VecElementType::I16,
                    signed1: true,
                    signed2: true,
                    acc: matches!(op, Opcode::V6_vmpyhv_acc),
                });
            }
            Opcode::V6_vmpyhus | Opcode::V6_vmpyhus_acc => {
                let base = if matches!(op, Opcode::V6_vmpyhus_acc) {
                    rx_n
                } else {
                    rd_n
                };
                push_op!(OpKind::VWidenMul {
                    dst_lo: self.hex_v(base),
                    dst_hi: self.hex_v(base + 1),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src_elem: VecElementType::I16,
                    signed1: true,
                    signed2: false,
                    acc: matches!(op, Opcode::V6_vmpyhus_acc),
                });
            }
            Opcode::V6_vmpyuhv | Opcode::V6_vmpyuhv_acc => {
                let base = if matches!(op, Opcode::V6_vmpyuhv_acc) {
                    rx_n
                } else {
                    rd_n
                };
                push_op!(OpKind::VWidenMul {
                    dst_lo: self.hex_v(base),
                    dst_hi: self.hex_v(base + 1),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src_elem: VecElementType::I16,
                    signed1: false,
                    signed2: false,
                    acc: matches!(op, Opcode::V6_vmpyuhv_acc),
                });
            }

            // ============================================================
            // Wave 4: HVX horizontal reduce multiplies (OpKind::VReduceMul)
            // and scalar splats (OpKind::VBroadcast).
            // ============================================================
            //
            // `OpKind::VReduceMul` models the vrmpy/vdmpy reduce family:
            //   dst.lane[i] = (acc?dst[i]:0)
            //               + Σ_{k<taps} ext(src1[taps*i+k]) · ext(src2[taps*i+k])
            // where the OUTPUT lane is `src_elem_bits*taps` wide. `signed1`/
            // `signed2` select per-operand signedness of the sub-lane products.
            // This is bit-identical to the sem `set_w`/`set_h` wrapping stores
            // (interp wraps `s as u64` into the masked output lane), so the
            // non-saturating forms map exactly.
            //
            // VECTOR-VECTOR 4-tap byte dot product -> word (sem/hvx_rmpy.rs):
            //   vrmpyubv   ub*ub -> uw   unsigned×unsigned
            //   vrmpybv    b*b   -> w    signed×signed
            //   vrmpybusv  ub*b  -> w    unsigned×signed
            // dst base = fld('d') (plain) / fld('x') (_acc); the _acc form reads
            // and re-writes that vector (matched by VReduceMul `acc:true`).
            Opcode::V6_vrmpyubv | Opcode::V6_vrmpyubv_acc => {
                let acc = matches!(op, Opcode::V6_vrmpyubv_acc);
                let base = if acc { rx_n } else { rd_n };
                push_op!(OpKind::VReduceMul {
                    dst: self.hex_v(base),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src1_elem: VecElementType::I8,
                    src2_elem: VecElementType::I8,
                    out_elem: VecElementType::I32,
                    taps: 4,
                    signed1: false,
                    signed2: false,
                    sat: false,
                    acc,
                });
            }
            Opcode::V6_vrmpybv | Opcode::V6_vrmpybv_acc => {
                let acc = matches!(op, Opcode::V6_vrmpybv_acc);
                let base = if acc { rx_n } else { rd_n };
                push_op!(OpKind::VReduceMul {
                    dst: self.hex_v(base),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src1_elem: VecElementType::I8,
                    src2_elem: VecElementType::I8,
                    out_elem: VecElementType::I32,
                    taps: 4,
                    signed1: true,
                    signed2: true,
                    sat: false,
                    acc,
                });
            }
            Opcode::V6_vrmpybusv | Opcode::V6_vrmpybusv_acc => {
                let acc = matches!(op, Opcode::V6_vrmpybusv_acc);
                let base = if acc { rx_n } else { rd_n };
                push_op!(OpKind::VReduceMul {
                    dst: self.hex_v(base),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src1_elem: VecElementType::I8,
                    src2_elem: VecElementType::I8,
                    out_elem: VecElementType::I32,
                    taps: 4,
                    signed1: false, // Vu.ub
                    signed2: true,  // Vv.b
                    sat: false,
                    acc,
                });
            }

            // SCALAR splats: replicate the low `elem` bits of a GPR into every
            // lane (sem/hvx_perm.rs). lvsplatw -> word lanes, lvsplath -> half
            // lanes, lvsplatb -> byte lanes; dst = fld('d'), scalar = fld('t').
            Opcode::V6_lvsplatw => {
                push_op!(OpKind::VBroadcast {
                    dst: self.hex_v(fld(b'd')),
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
            }
            Opcode::V6_lvsplath => {
                push_op!(OpKind::VBroadcast {
                    dst: self.hex_v(fld(b'd')),
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I16,
                    lanes: 64,
                });
            }
            Opcode::V6_lvsplatb => {
                push_op!(OpKind::VBroadcast {
                    dst: self.hex_v(fld(b'd')),
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I8,
                    lanes: 128,
                });
            }

            // SCALAR 4-tap vrmpy (Vu.byte * Rt.byte, Rt's 4 bytes reused per
            // word lane): broadcast Rt across all 32 word lanes into an SSA temp
            // (so temp.byte[4i+k] = Rt.byte[k], the exact scalar reuse), then run
            // a 4-tap byte VReduceMul of Vu against that temp. dst base =
            // fld('d') (plain) / fld('x') (_acc).
            //   vrmpyub   ub*Rt.ub -> uw   unsigned×unsigned
            //   vrmpybus  ub*Rt.b  -> w    unsigned×signed
            Opcode::V6_vrmpyub
            | Opcode::V6_vrmpyub_acc
            | Opcode::V6_vrmpybus
            | Opcode::V6_vrmpybus_acc => {
                let acc = matches!(op, Opcode::V6_vrmpyub_acc | Opcode::V6_vrmpybus_acc);
                let signed2 = matches!(op, Opcode::V6_vrmpybus | Opcode::V6_vrmpybus_acc);
                let base = if acc { rx_n } else { rd_n };
                let t = ctx.alloc_vreg();
                push_op!(OpKind::VBroadcast {
                    dst: t,
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
                push_op!(OpKind::VReduceMul {
                    dst: self.hex_v(base),
                    src1: self.hex_v(fld(b'u')),
                    src2: t,
                    src1_elem: VecElementType::I8,
                    src2_elem: VecElementType::I8,
                    out_elem: VecElementType::I32,
                    taps: 4,
                    signed1: false, // Vu.ub
                    signed2,
                    sat: false,
                    acc,
                });
            }

            // SCALAR 2-tap vdmpybus (Vu.ub * Rt.b -> halfword). The sem reuses
            // Rt bytes by lane: halfword lane i uses Rt.byte[(2i)%4] and
            // Rt.byte[(2i+1)%4]. Broadcasting Rt as I32 word lanes makes the
            // temp's byte n equal Rt.byte[n%4], so a 2-tap byte VReduceMul of Vu
            // against the temp sums temp.byte[2i] = Rt.byte[(2i)%4] and
            // temp.byte[2i+1] = Rt.byte[(2i+1)%4] — exactly the sem reuse. Output
            // halfword lane wraps via `s as u16`, identical to VReduceMul's
            // masked 16-bit store. dst base = fld('d') / fld('x').
            Opcode::V6_vdmpybus | Opcode::V6_vdmpybus_acc => {
                let acc = matches!(op, Opcode::V6_vdmpybus_acc);
                let base = if acc { rx_n } else { rd_n };
                let t = ctx.alloc_vreg();
                push_op!(OpKind::VBroadcast {
                    dst: t,
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
                push_op!(OpKind::VReduceMul {
                    dst: self.hex_v(base),
                    src1: self.hex_v(fld(b'u')),
                    src2: t,
                    src1_elem: VecElementType::I8,
                    src2_elem: VecElementType::I8,
                    out_elem: VecElementType::I16,
                    taps: 2,
                    signed1: false, // Vu.ub
                    signed2: true,  // Rt.b
                    acc,
                    sat: false,
                });
            }

            // ============================================================
            // Wave 5: widen-extend pairs, vcombine, vector arithmetic
            // right-shift by scalar, and vector-by-scalar widening multiplies.
            // ============================================================
            //
            // ---- widen-extend a single vector into a register PAIR ----------
            // `OpKind::VWidenExt` zero/sign-extends each narrow lane to double
            // width into the pair (dst_lo = V[base], dst_hi = V[base+1]). The
            // INTERLEAVED forms (vzxt/vsxt: vzb/vsb/vzh/vsh) route even narrow
            // lanes -> dst_lo and odd -> dst_hi, exactly matching the sem's
            // `set_h(lo, i, byte 2i)` / `set_h(hi, i, byte 2i+1)` interleave.
            // The SEQUENTIAL forms (vunpack) route the low half of the narrow
            // lanes -> dst_lo and the high half -> dst_hi, matching the sem's
            // `i<64 -> lo[i]` / `i>=64 -> hi[i-64]` split. src = V[fld('u')].
            // signed = sign-extend (vsxt/vunpackb/vunpackh) vs zero (vzxt/...ub).
            Opcode::V6_vzb => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I8,
                signed: false,
                interleave: true,
            }),
            Opcode::V6_vsb => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I8,
                signed: true,
                interleave: true,
            }),
            Opcode::V6_vzh => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I16,
                signed: false,
                interleave: true,
            }),
            Opcode::V6_vsh => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I16,
                signed: true,
                interleave: true,
            }),
            Opcode::V6_vunpackub => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I8,
                signed: false,
                interleave: false,
            }),
            Opcode::V6_vunpackb => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I8,
                signed: true,
                interleave: false,
            }),
            Opcode::V6_vunpackuh => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I16,
                signed: false,
                interleave: false,
            }),
            Opcode::V6_vunpackh => push_op!(OpKind::VWidenExt {
                dst_lo: self.hex_v(rd_n),
                dst_hi: self.hex_v(rd_n + 1),
                src: self.hex_v(fld(b'u')),
                src_elem: VecElementType::I16,
                signed: true,
                interleave: false,
            }),

            // ---- vcombine: Vdd = vcombine(Vu, Vv) ---------------------------
            // sem (hvx_perm.rs): set_v(rd, Vv) [low := Vv], set_v(rd+1, Vu)
            // [high := Vu]. Emit two full-vector copies in that exact mapping.
            Opcode::V6_vcombine => {
                push_op!(OpKind::VMov {
                    dst: self.hex_v(rd_n),
                    src: self.hex_v(fld(b'v')),
                    width: VecWidth::V512,
                });
                push_op!(OpKind::VMov {
                    dst: self.hex_v(rd_n + 1),
                    src: self.hex_v(fld(b'u')),
                    width: VecWidth::V512,
                });
            }

            // ---- vector arithmetic right shift by scalar Rt -----------------
            // sem (hvx_shift.rs): vasrh = map_h(|x| ((x as i16) >> (rt & 15)));
            // vasrw = map_w(|x| ((x as i32) >> (rt & 31))). `VShift` Asr now
            // sign-extends each lane to i64 before the arithmetic shift and
            // computes `amt % elem_bits` (== rt & (elem_bits-1)), so it is
            // bit-exact with the sem per-lane signed right shift.
            Opcode::V6_vasrh => push_op!(OpKind::VShift {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                shift: ShiftOp::Asr,
                elem: VecElementType::I16,
                lanes: 64,
            }),
            Opcode::V6_vasrw => push_op!(OpKind::VShift {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                shift: ShiftOp::Asr,
                elem: VecElementType::I32,
                lanes: 32,
            }),

            // ---- vector-by-SCALAR widening multiplies -> register PAIR ------
            // sem (hvx_mpyv.rs): per output lane i, even uses Rt sub-element
            // [(2i)%4 byte | half 0], odd uses Rt sub-element [(2i+1)%4 byte |
            // half 1]. COMPOSE: broadcast Rt as I32 word lanes into a temp t
            // (so t.byte[n]=Rt.byte[n%4], t.half[n]=Rt.half[n%2]) then run a
            // VWidenMul of Vu against t. VWidenMul reads t at even=2i / odd=2i+1
            // lane indices, i.e. t.byte[2i]=Rt.byte[(2i)%4], t.byte[2i+1]=
            // Rt.byte[(2i+1)%4] (byte forms) and t.half[2i]=Rt.half[0],
            // t.half[2i+1]=Rt.half[1] (half forms) — the exact sem sub-element
            // reuse. dst base = fld('d') (plain) / fld('x') (_acc); the _acc
            // form reads+rewrites the pair (VWidenMul `acc:true`). Output lanes
            // wrap via `as u16`/`as u32`, matching VWidenMul's masked store.
            //   vmpybus  ub*Rt.b  -> h pair   signed1=false signed2=true
            //   vmpyub   ub*Rt.ub -> uh pair  signed1=false signed2=false
            //   vmpyh    h *Rt.h  -> w pair   signed1=true  signed2=true
            //   vmpyuh   uh*Rt.uh -> uw pair  signed1=false signed2=false
            Opcode::V6_vmpybus
            | Opcode::V6_vmpybus_acc
            | Opcode::V6_vmpyub
            | Opcode::V6_vmpyub_acc
            | Opcode::V6_vmpyh
            | Opcode::V6_vmpyh_acc
            | Opcode::V6_vmpyuh
            | Opcode::V6_vmpyuh_acc => {
                let acc = matches!(
                    op,
                    Opcode::V6_vmpybus_acc
                        | Opcode::V6_vmpyub_acc
                        | Opcode::V6_vmpyh_acc
                        | Opcode::V6_vmpyuh_acc
                );
                let (src_elem, signed1, signed2) = match op {
                    Opcode::V6_vmpybus | Opcode::V6_vmpybus_acc => {
                        (VecElementType::I8, false, true)
                    }
                    Opcode::V6_vmpyub | Opcode::V6_vmpyub_acc => (VecElementType::I8, false, false),
                    Opcode::V6_vmpyh | Opcode::V6_vmpyh_acc => (VecElementType::I16, true, true),
                    // vmpyuh
                    _ => (VecElementType::I16, false, false),
                };
                let base = if acc { rx_n } else { rd_n };
                let t = ctx.alloc_vreg();
                push_op!(OpKind::VBroadcast {
                    dst: t,
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
                push_op!(OpKind::VWidenMul {
                    dst_lo: self.hex_v(base),
                    dst_hi: self.hex_v(base + 1),
                    src1: self.hex_v(fld(b'u')),
                    src2: t,
                    src_elem,
                    signed1,
                    signed2,
                    acc,
                });
            }

            // ============================================================
            // HVX pack even/odd (Vd = narrow sub-element of two wide srcs)
            // sem (sem/hvx_perm.rs): out[i] (low half)  = sub-elem of Vv;
            //                        out[i+half] (high) = sub-elem of Vu.
            // VPack encodes src2->low, src1->high, so src1=Vu, src2=Vv.
            // ============================================================
            Opcode::V6_vpackeb | Opcode::V6_vpackob | Opcode::V6_vpackeh | Opcode::V6_vpackoh => {
                let (elem, odd) = match op {
                    Opcode::V6_vpackeb => (VecElementType::I8, false),
                    Opcode::V6_vpackob => (VecElementType::I8, true),
                    Opcode::V6_vpackeh => (VecElementType::I16, false),
                    // V6_vpackoh
                    _ => (VecElementType::I16, true),
                };
                push_op!(OpKind::VPack {
                    dst: self.hex_v(fld(b'd')),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    elem,
                    odd,
                });
            }

            // HVX saturating narrowing pack (signed wide src -> half-width).
            // sem: out low half = sat(Vv lane), high half = sat(Vu lane);
            // VPackSat encodes src2->low, src1->high, so src1=Vu, src2=Vv.
            Opcode::V6_vpackhub_sat
            | Opcode::V6_vpackhb_sat
            | Opcode::V6_vpackwuh_sat
            | Opcode::V6_vpackwh_sat => {
                let (src_elem, to_unsigned) = match op {
                    Opcode::V6_vpackhub_sat => (VecElementType::I16, true),
                    Opcode::V6_vpackhb_sat => (VecElementType::I16, false),
                    Opcode::V6_vpackwuh_sat => (VecElementType::I32, true),
                    // V6_vpackwh_sat
                    _ => (VecElementType::I32, false),
                };
                push_op!(OpKind::VPackSat {
                    dst: self.hex_v(fld(b'd')),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    src_elem,
                    to_unsigned,
                });
            }

            // ============================================================
            // HVX single-vector shuffle / deal (Wave 7)
            //
            // `OpKind::VShuffle2` reorders narrow lanes of one vector.
            //   shuffle (deal=false): out[2i]=src[i], out[2i+1]=src[i+half]
            //   deal    (deal=true):  out[i]=src[2i], out[i+half]=src[2i+1]
            // half = (1024/elem_bits)/2. Confirmed against sem/hvx_perm.rs:
            //   vshuffb (I8):  out[2i]=Vu[i], out[2i+1]=Vu[i+64]   (half=64)
            //   vshuffh (I16): out_h[2i]=Vu_h[i], out_h[2i+1]=Vu_h[i+32]
            //   vdealb  (I8):  out[i]=Vu[2i], out[i+64]=Vu[2i+1]
            //   vdealh  (I16): out_h[i]=Vu_h[2i], out_h[i+32]=Vu_h[2i+1]
            // Single source is Vu (fld 'u'); dest is Vd (fld 'd').
            // ============================================================
            Opcode::V6_vshuffb => push_op!(OpKind::VShuffle2 {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                elem: VecElementType::I8,
                deal: false,
            }),
            Opcode::V6_vshuffh => push_op!(OpKind::VShuffle2 {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                elem: VecElementType::I16,
                deal: false,
            }),
            Opcode::V6_vdealb => push_op!(OpKind::VShuffle2 {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                elem: VecElementType::I8,
                deal: true,
            }),
            Opcode::V6_vdealh => push_op!(OpKind::VShuffle2 {
                dst: self.hex_v(fld(b'd')),
                src: self.hex_v(fld(b'u')),
                elem: VecElementType::I16,
                deal: true,
            }),

            // ============================================================
            // HVX two-vector even/odd shuffle (Wave 7)
            //
            // `OpKind::VShuffleEO` interleaves the even (odd=false) or odd
            // (odd=true) narrow sub-elements of two vectors:
            //   out[2i] = src2[2i+odd], out[2i+1] = src1[2i+odd]
            // Confirmed against sem/hvx_perm.rs (src1=Vu, src2=Vv):
            //   vshuffeb (I8,  even): out[2i]=Vv[2i],   out[2i+1]=Vu[2i]
            //   vshuffob (I8,  odd):  out[2i]=Vv[2i+1], out[2i+1]=Vu[2i+1]
            //   vshufeh  (I16, even): out_h[2i]=Vv_h[2i],   out_h[2i+1]=Vu_h[2i]
            //   vshufoh  (I16, odd):  out_h[2i]=Vv_h[2i+1], out_h[2i+1]=Vu_h[2i+1]
            // ============================================================
            Opcode::V6_vshuffeb => push_op!(OpKind::VShuffleEO {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I8,
                odd: false,
            }),
            Opcode::V6_vshuffob => push_op!(OpKind::VShuffleEO {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I8,
                odd: true,
            }),
            Opcode::V6_vshufeh => push_op!(OpKind::VShuffleEO {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                odd: false,
            }),
            Opcode::V6_vshufoh => push_op!(OpKind::VShuffleEO {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                elem: VecElementType::I16,
                odd: true,
            }),

            // ============================================================
            // HVX byte-align / rotate (Wave 8)
            //
            // `OpKind::VAlign` byte-aligns the 256-byte concat `src1:src2`:
            // with byte shift `s` (right/left=false: s = amount&127; left=true:
            // s = 128 - (amount&127)) the result byte i = src2[i+s] when i+s<128,
            // else src1[i+s-128]. Confirmed against sem/hvx_perm.rs
            // `align(vu, vv, shift)` with src1 = Vu (fld 'u'), src2 = Vv (fld 'v').
            //
            //   vror      : align(Vu, Vu, Rt&127)        -> src1=src2=Vu, right
            //   valignb   : align(Vu, Vv, Rt&127)        -> right
            //   vlalignb  : align(Vu, Vv, 128-(Rt&127))  -> left
            //   valignbi  : align(Vu, Vv, #u3)           -> right, imm
            //   vlalignbi : align(Vu, Vv, 128-#u3)       -> left, imm
            // The interp masks `amount & 127` and applies `left` internally, so we
            // pass the raw Rt register / #u3 immediate unchanged.
            // ============================================================
            Opcode::V6_vror => push_op!(OpKind::VAlign {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'u')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                left: false,
            }),
            Opcode::V6_valignb => push_op!(OpKind::VAlign {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                left: false,
            }),
            Opcode::V6_vlalignb => push_op!(OpKind::VAlign {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                amount: SrcOperand::Reg(self.hex_reg(fld(b't'))),
                left: true,
            }),
            Opcode::V6_valignbi => push_op!(OpKind::VAlign {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                amount: SrcOperand::Imm((fimm_u(b'i') & 0x7) as i64),
                left: false,
            }),
            Opcode::V6_vlalignbi => push_op!(OpKind::VAlign {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                amount: SrcOperand::Imm((fimm_u(b'i') & 0x7) as i64),
                left: true,
            }),

            // ============================================================
            // HVX shift-round-saturate narrowing multiply (Wave 9)
            //
            // `OpKind::VMulShiftSat` models per-lane
            //   p = ext(src1)·ext(src2) (i64);  p <<= shift_left;
            //   if round   p += 1<<(out_shift-1);
            //   if sat_bits!=0  clamp p to signed sat_bits range;
            //   out lane = (p >> out_shift) masked to src_elem (output elem = src_elem).
            //
            // --- vector-by-vector forms (direct VMulShiftSat) ---
            // Confirmed against sem/hvx_mpyv.rs:
            //   V6_vmpyhvsrs  Vd.h=vmpy(Vu.h,Vv.h):<<1:rnd:sat
            //     per half lane: prod=(Vu.h·Vv.h)<<1; rnd=prod+0x8000;
            //     sat_n(rnd,32); out.h=(s32>>16)&0xffff. => signed×signed,
            //     shift_left=1, round=true, sat_bits=32, out_shift=16.
            //   V6_vmpyuhvs   Vd.uh=vmpy(Vu.uh,Vv.uh):>>16
            //     per half lane: p=Vu.uh·Vv.uh (u64); out.h=(p>>16)&0xffff.
            //     => unsigned×unsigned, shift_left=0, round=false, sat_bits=0,
            //     out_shift=16.
            Opcode::V6_vmpyhvsrs => push_op!(OpKind::VMulShiftSat {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                src_elem: VecElementType::I16,
                signed1: true,
                signed2: true,
                shift_left: 1,
                round: true,
                sat_bits: 32,
                out_shift: 16,
            }),
            Opcode::V6_vmpyuhvs => push_op!(OpKind::VMulShiftSat {
                dst: self.hex_v(fld(b'd')),
                src1: self.hex_v(fld(b'u')),
                src2: self.hex_v(fld(b'v')),
                src_elem: VecElementType::I16,
                signed1: false,
                signed2: false,
                shift_left: 0,
                round: false,
                sat_bits: 0,
                out_shift: 16,
            }),

            // --- vector-by-scalar forms (VBroadcast(Rt) then VMulShiftSat) ---
            // The sem multiplies each even halfword lane by Rt.half[0] and each
            // odd halfword lane by Rt.half[1]. Broadcasting Rt with elem=I32,
            // lanes=32 yields t.word[i]=Rt, i.e. t.half[2i]=Rt.half[0] and
            // t.half[2i+1]=Rt.half[1] — exactly the sem's rt_half(rt,0)/(rt,1)
            // per even/odd halfword. A direct I16 VMulShiftSat of Vu against t
            // then matches the per-half-lane product/shift/sat/round/high-extract.
            // Confirmed against sem/hvx_mpyv.rs:
            //   V6_vmpyhss  Vd.h=vmpy(Vu.h,Rt.h):<<1:sat
            //     p=(Vu.h·Rt.h)<<1; sat_n(p,32); out.h=(s32>>16)&0xffff.
            //     => signed×signed, shift_left=1, round=false, sat_bits=32, out_shift=16.
            //   V6_vmpyhsrs same with +0x8000 round => round=true.
            Opcode::V6_vmpyhss | Opcode::V6_vmpyhsrs => {
                let round = matches!(op, Opcode::V6_vmpyhsrs);
                let t = ctx.alloc_vreg();
                push_op!(OpKind::VBroadcast {
                    dst: t,
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
                push_op!(OpKind::VMulShiftSat {
                    dst: self.hex_v(fld(b'd')),
                    src1: self.hex_v(fld(b'u')),
                    src2: t,
                    src_elem: VecElementType::I16,
                    signed1: true,
                    signed2: true,
                    shift_left: 1,
                    round,
                    sat_bits: 32,
                    out_shift: 16,
                });
            }

            // --- HVX vector compares -> Q vector-predicate (Wave 11) ---
            // `Qd = vcmp.<cond>(Vu.<t>, Vv.<t>)`: for each elem-wide lane the
            // comparison sets all that lane's per-byte Q bits. Field letters
            // src1=u, src2=v, dst=d (confirmed against sem/hvx_cmp.rs). `eq` is
            // signedness-agnostic; `gt` is signed (Gt) vs unsigned (Gtu).
            Opcode::V6_veqb
            | Opcode::V6_vgtb
            | Opcode::V6_vgtub
            | Opcode::V6_veqh
            | Opcode::V6_vgth
            | Opcode::V6_vgtuh
            | Opcode::V6_veqw
            | Opcode::V6_vgtw
            | Opcode::V6_vgtuw => {
                let (cond, elem, lanes) = match op {
                    Opcode::V6_veqb => (VecCmpCond::Eq, VecElementType::I8, 128),
                    Opcode::V6_vgtb => (VecCmpCond::Gt, VecElementType::I8, 128),
                    Opcode::V6_vgtub => (VecCmpCond::Gtu, VecElementType::I8, 128),
                    Opcode::V6_veqh => (VecCmpCond::Eq, VecElementType::I16, 64),
                    Opcode::V6_vgth => (VecCmpCond::Gt, VecElementType::I16, 64),
                    Opcode::V6_vgtuh => (VecCmpCond::Gtu, VecElementType::I16, 64),
                    Opcode::V6_veqw => (VecCmpCond::Eq, VecElementType::I32, 32),
                    Opcode::V6_vgtw => (VecCmpCond::Gt, VecElementType::I32, 32),
                    // V6_vgtuw
                    _ => (VecCmpCond::Gtu, VecElementType::I32, 32),
                };
                push_op!(OpKind::VCmpToQ {
                    dst: self.hex_q(fld(b'd')),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    cond,
                    elem,
                    lanes,
                    accumulate: None,
                });
            }

            // --- HVX vmux: per-byte select by a Q vector-predicate (Wave 11) ---
            // `Vd.b[i] = Qt.bit[i] ? Vu.b[i] : Vv.b[i]`. The Q is read from
            // field `t` (sem uses qread_new(fld(d, b't'))), true src = Vu,
            // false src = Vv.
            Opcode::V6_vmux => push_op!(OpKind::VBlend {
                dst: self.hex_v(fld(b'd')),
                mask_q: self.hex_q(fld(b't')),
                src_true: self.hex_v(fld(b'u')),
                src_false: self.hex_v(fld(b'v')),
            }),

            // --- HVX Q-predicate logic: Qd = OP(Qs, Qt) per-bit (Wave 11) ---
            // Modeled as a VLane bitwise op over the 128-bit Q regs (two I64
            // lanes). Field letters src1=s, src2=t, dst=d (sem/hvx_cmp.rs reads
            // qread_new(fld(d,b's'))/(b't')).
            Opcode::V6_pred_and
            | Opcode::V6_pred_or
            | Opcode::V6_pred_xor
            | Opcode::V6_pred_and_n => {
                let lane_op = match op {
                    Opcode::V6_pred_and => VLaneOp::And,
                    Opcode::V6_pred_or => VLaneOp::Or,
                    Opcode::V6_pred_xor => VLaneOp::Xor,
                    // V6_pred_and_n
                    _ => VLaneOp::AndNot,
                };
                push_op!(OpKind::VLane {
                    dst: self.hex_q(fld(b'd')),
                    src1: self.hex_q(fld(b's')),
                    src2: self.hex_q(fld(b't')),
                    elem: VecElementType::I64,
                    lanes: 2,
                    op: lane_op,
                    signed: false,
                });
            }

            // --- HVX Q-predicate unary / or-not logic (Wave 12) ---
            // `Qd = not(Qs)` is the unary VLaneOp::Not (src2 unused, point it at
            // src1 so the op is well-formed). `Qd = or(Qs,!Qt)` is VLaneOp::OrNot
            // (`src1 | !src2`), matching the sem `qs[k] | !qt[k]`. Both run over
            // the 128-bit Q regs as two I64 lanes (sem/hvx_cmp.rs: src1=s, t=t).
            Opcode::V6_pred_not => {
                let s = self.hex_q(fld(b's'));
                push_op!(OpKind::VLane {
                    dst: self.hex_q(fld(b'd')),
                    src1: s,
                    src2: s,
                    elem: VecElementType::I64,
                    lanes: 2,
                    op: VLaneOp::Not,
                    signed: false,
                });
            }
            Opcode::V6_pred_or_n => {
                push_op!(OpKind::VLane {
                    dst: self.hex_q(fld(b'd')),
                    src1: self.hex_q(fld(b's')),
                    src2: self.hex_q(fld(b't')),
                    elem: VecElementType::I64,
                    lanes: 2,
                    op: VLaneOp::OrNot,
                    signed: false,
                });
            }

            // --- HVX scalar 2-tap vdmpy halfword reduces -> word (Wave 12) ---
            // `Vd.w = vdmpy(Vu.h, Rt.<t>)`: each word lane i = Σ_{k<2}
            // Vu.h[2i+k] * Rt.<t>[(2i+k)%lanes]. Broadcast Rt as I32 word lanes
            // into a temp so temp.b[n] = Rt.b[n%4] (and temp.h[n] = Rt.h[n%2]),
            // matching the sem's per-lane Rt reuse, then run a 2-tap VReduceMul of
            // Vu against the temp. dst base = fld('x') for _acc else fld('d').
            //   vdmpyhb     Vu.h(s) * Rt.b(s)  -> w,  no sat   (src2 I8)
            //   vdmpyhsat   Vu.h(s) * Rt.h(s)  -> w,  sat32    (src2 I16)
            //   vdmpyhsusat Vu.h(s) * Rt.uh(u) -> w,  sat32    (src2 I16, unsigned)
            // HVX vector saturation does not set USR (verified by prior sat ops).
            Opcode::V6_vdmpyhb
            | Opcode::V6_vdmpyhb_acc
            | Opcode::V6_vdmpyhsat
            | Opcode::V6_vdmpyhsat_acc
            | Opcode::V6_vdmpyhsusat
            | Opcode::V6_vdmpyhsusat_acc => {
                let acc = matches!(
                    op,
                    Opcode::V6_vdmpyhb_acc | Opcode::V6_vdmpyhsat_acc | Opcode::V6_vdmpyhsusat_acc
                );
                let (src2_elem, signed2, sat) = match op {
                    Opcode::V6_vdmpyhb | Opcode::V6_vdmpyhb_acc => {
                        (VecElementType::I8, true, false)
                    }
                    Opcode::V6_vdmpyhsat | Opcode::V6_vdmpyhsat_acc => {
                        (VecElementType::I16, true, true)
                    }
                    // V6_vdmpyhsusat(_acc): Rt.uh is unsigned
                    _ => (VecElementType::I16, false, true),
                };
                let base = if acc { rx_n } else { rd_n };
                let t = ctx.alloc_vreg();
                push_op!(OpKind::VBroadcast {
                    dst: t,
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
                push_op!(OpKind::VReduceMul {
                    dst: self.hex_v(base),
                    src1: self.hex_v(fld(b'u')),
                    src2: t,
                    src1_elem: VecElementType::I16, // Vu.h (signed)
                    src2_elem,
                    out_elem: VecElementType::I32,
                    taps: 2,
                    signed1: true,
                    signed2,
                    sat,
                    acc,
                });
            }

            // --- HVX accumulating vector compares -> Q vector-predicate (Wave 13) ---
            // `Qx {&=,|=,^=} vcmp.<cond>(Vu.<t>, Vv.<t>)`: recompute a per-element
            // compare into a per-byte Q mask, then combine it bit-wise into the
            // EXISTING architectural Qx via And/Or/Xor (read-modify-write). The Q is
            // both source and destination -> field letter `x` (confirmed against
            // sem/hvx_cmpacc.rs: qx = fld(d, b'x'), old = ctx.qread(qx)). src1=u,
            // src2=v. `eq` is signedness-agnostic (the assembler maps the unsigned
            // ub/uh/uw `eq` forms onto these signed b/h/w encodings); `gt` is signed
            // (Gt) vs unsigned (Gtu).
            Opcode::V6_veqb_and
            | Opcode::V6_veqb_or
            | Opcode::V6_veqb_xor
            | Opcode::V6_veqh_and
            | Opcode::V6_veqh_or
            | Opcode::V6_veqh_xor
            | Opcode::V6_veqw_and
            | Opcode::V6_veqw_or
            | Opcode::V6_veqw_xor
            | Opcode::V6_vgtb_and
            | Opcode::V6_vgtb_or
            | Opcode::V6_vgtb_xor
            | Opcode::V6_vgth_and
            | Opcode::V6_vgth_or
            | Opcode::V6_vgth_xor
            | Opcode::V6_vgtw_and
            | Opcode::V6_vgtw_or
            | Opcode::V6_vgtw_xor
            | Opcode::V6_vgtub_and
            | Opcode::V6_vgtub_or
            | Opcode::V6_vgtub_xor
            | Opcode::V6_vgtuh_and
            | Opcode::V6_vgtuh_or
            | Opcode::V6_vgtuh_xor
            | Opcode::V6_vgtuw_and
            | Opcode::V6_vgtuw_or
            | Opcode::V6_vgtuw_xor => {
                let (cond, elem, lanes) = match op {
                    Opcode::V6_veqb_and | Opcode::V6_veqb_or | Opcode::V6_veqb_xor => {
                        (VecCmpCond::Eq, VecElementType::I8, 128)
                    }
                    Opcode::V6_veqh_and | Opcode::V6_veqh_or | Opcode::V6_veqh_xor => {
                        (VecCmpCond::Eq, VecElementType::I16, 64)
                    }
                    Opcode::V6_veqw_and | Opcode::V6_veqw_or | Opcode::V6_veqw_xor => {
                        (VecCmpCond::Eq, VecElementType::I32, 32)
                    }
                    Opcode::V6_vgtb_and | Opcode::V6_vgtb_or | Opcode::V6_vgtb_xor => {
                        (VecCmpCond::Gt, VecElementType::I8, 128)
                    }
                    Opcode::V6_vgth_and | Opcode::V6_vgth_or | Opcode::V6_vgth_xor => {
                        (VecCmpCond::Gt, VecElementType::I16, 64)
                    }
                    Opcode::V6_vgtw_and | Opcode::V6_vgtw_or | Opcode::V6_vgtw_xor => {
                        (VecCmpCond::Gt, VecElementType::I32, 32)
                    }
                    Opcode::V6_vgtub_and | Opcode::V6_vgtub_or | Opcode::V6_vgtub_xor => {
                        (VecCmpCond::Gtu, VecElementType::I8, 128)
                    }
                    Opcode::V6_vgtuh_and | Opcode::V6_vgtuh_or | Opcode::V6_vgtuh_xor => {
                        (VecCmpCond::Gtu, VecElementType::I16, 64)
                    }
                    // vgtuw_{and,or,xor}
                    _ => (VecCmpCond::Gtu, VecElementType::I32, 32),
                };
                let acc = match op {
                    Opcode::V6_veqb_and
                    | Opcode::V6_veqh_and
                    | Opcode::V6_veqw_and
                    | Opcode::V6_vgtb_and
                    | Opcode::V6_vgth_and
                    | Opcode::V6_vgtw_and
                    | Opcode::V6_vgtub_and
                    | Opcode::V6_vgtuh_and
                    | Opcode::V6_vgtuw_and => VLaneOp::And,
                    Opcode::V6_veqb_or
                    | Opcode::V6_veqh_or
                    | Opcode::V6_veqw_or
                    | Opcode::V6_vgtb_or
                    | Opcode::V6_vgth_or
                    | Opcode::V6_vgtw_or
                    | Opcode::V6_vgtub_or
                    | Opcode::V6_vgtuh_or
                    | Opcode::V6_vgtuw_or => VLaneOp::Or,
                    // _xor variants
                    _ => VLaneOp::Xor,
                };
                push_op!(OpKind::VCmpToQ {
                    dst: self.hex_q(fld(b'x')),
                    src1: self.hex_v(fld(b'u')),
                    src2: self.hex_v(fld(b'v')),
                    cond,
                    elem,
                    lanes,
                    accumulate: Some(acc),
                });
            }

            // ---- Wave 14: HVX Q<->V and Q<->R bridge ops (vand* family) ----
            // vandvqv:  Vd.b[i] = Qv.bit[i]        ? Vu.b[i] : 0
            // vandvnqv: Vd.b[i] = (!Qv.bit[i])     ? Vu.b[i] : 0
            // Fields (from opcode_generated.rs): d=Vd, u=Vu, v=Qv (matches the sem
            // in hvx_cmp.rs which reads qread_new(fld(d, b'v')) / vread(fld(d, b'u'))).
            Opcode::V6_vandvqv | Opcode::V6_vandvnqv => {
                let negate = matches!(op, Opcode::V6_vandvnqv);
                push_op!(OpKind::VMaskZero {
                    dst: self.hex_v(fld(b'd')),
                    mask_q: self.hex_q(fld(b'v')),
                    src: self.hex_v(fld(b'u')),
                    negate,
                });
            }

            // vandqrt:  Vd.ub[i] = Qu.bit[i]    ? Rt.byte[i%4] : 0
            // vandnqrt: Vd.ub[i] = (!Qu.bit[i]) ? Rt.byte[i%4] : 0
            // Fields: d=Vd, t=Rt, u=Qu. Compose a per-byte Rt-replicated vector
            // (VBroadcast of Rt as 32x I32 lanes => byte[i]=Rt.byte[i%4]), then
            // gate it by the Q mask. Mirrors the sem (qread_new(fld(d, b'u')),
            // r(fld(d, b't'))).
            Opcode::V6_vandqrt | Opcode::V6_vandnqrt => {
                let negate = matches!(op, Opcode::V6_vandnqrt);
                let t = ctx.alloc_vreg();
                push_op!(OpKind::VBroadcast {
                    dst: t,
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
                push_op!(OpKind::VMaskZero {
                    dst: self.hex_v(fld(b'd')),
                    mask_q: self.hex_q(fld(b'u')),
                    src: t,
                    negate,
                });
            }

            // vandvrt:  Qd.bit[i] = (Vu.ub[i] & Rt.byte[i%4]) != 0
            // Fields: d=Qd, t=Rt, u=Vu. VBroadcast Rt to per-byte, then build the
            // Q predicate via the per-byte AND test. Mirrors the sem (vread(fld(d,
            // b'u')), r(fld(d, b't')), set_q(fld(d, b'd'))).
            Opcode::V6_vandvrt => {
                let t = ctx.alloc_vreg();
                push_op!(OpKind::VBroadcast {
                    dst: t,
                    scalar: self.hex_reg(fld(b't')),
                    elem: VecElementType::I32,
                    lanes: 32,
                });
                push_op!(OpKind::VQFromVAndR {
                    dst: self.hex_q(fld(b'd')),
                    src1: self.hex_v(fld(b'u')),
                    src2: t,
                });
            }

            // Everything else: not implemented here.
            _ => return Err(unsupported()),
        }

        Ok(ops)
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

//! Native AArch64 code generator for SMIR.
//!
//! This lowerer currently targets identity-mapped AArch64 scalar SMIR: architectural
//! AArch64 X registers in SMIR are emitted as the same native X registers. It is
//! intentionally small and strict; unsupported virtual-register and memory forms
//! fail rather than silently changing semantics.

use std::collections::HashMap;

use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
use crate::smir::ops::{OpKind, SmirOp};
use crate::smir::types::{ArchReg, ArmReg, BlockId, OpWidth, ShiftOp, SrcOperand, VReg};

use super::{CodeBuffer, LowerError, LowerResult, Relocation, SmirLowerer};

/// Native AArch64 lowerer for identity-mapped AArch64 scalar SMIR.
pub struct Aarch64Lowerer {
    code: CodeBuffer,
    block_offsets: HashMap<BlockId, usize>,
    relocations: Vec<Relocation>,
}

impl Aarch64Lowerer {
    pub fn new() -> Self {
        Self {
            code: CodeBuffer::with_capacity(1024),
            block_offsets: HashMap::new(),
            relocations: Vec::new(),
        }
    }

    fn emit(&mut self, word: u32) {
        self.code.emit_u32(word);
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

    fn emit_addsub_reg(
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
                | (0b01011 << 24)
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
        let sf = Self::sf(width)?;
        self.emit(
            (sf << 31)
                | (opc << 29)
                | (0b01010 << 24)
                | ((n as u32) << 21)
                | ((rm as u32) << 16)
                | ((rn as u32) << 5)
                | (dst as u32),
        );
        Ok(())
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

    fn lower_mov(&mut self, dst: VReg, src: &SrcOperand, width: OpWidth) -> Result<(), LowerError> {
        let dst = Self::dst_gpr(dst)?;
        match src {
            SrcOperand::Reg(reg) => self.emit_mov_reg(dst, Self::gpr(*reg)?, width),
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => self.emit_mov_imm(dst, *imm, width),
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Mov source {other:?}"),
            }),
        }
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
            SrcOperand::Reg(reg) => {
                self.emit_addsub_reg(dst, rn, Self::gpr(*reg)?, subtract, set_flags, width)
            }
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                self.emit_addsub_imm(dst, rn, *imm, subtract, set_flags, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native add/sub source {other:?}"),
            }),
        }
    }

    fn lower_logic(
        &mut self,
        dst: VReg,
        src1: VReg,
        src2: &SrcOperand,
        opc: u32,
        set_flags: bool,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        if set_flags && opc != 0b11 {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native logical flags are only supported for ANDS".into(),
            });
        }
        let SrcOperand::Reg(src2) = src2 else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native logical source {src2:?}"),
            });
        };
        self.emit_logic_reg_n(
            Self::dst_or_zero_for_flags(dst, set_flags)?,
            Self::gpr(src1)?,
            Self::gpr(*src2)?,
            opc,
            false,
            width,
        )
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
            SrcOperand::Reg(reg) => {
                self.emit_addsub_reg(31, rn, Self::gpr(*reg)?, true, true, width)
            }
            SrcOperand::Imm(imm) | SrcOperand::Imm64(imm) => {
                self.emit_addsub_imm(31, rn, *imm, true, true, width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native CMP source {other:?}"),
            }),
        }
    }

    fn lower_test(
        &mut self,
        src1: VReg,
        src2: &SrcOperand,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        let SrcOperand::Reg(src2) = src2 else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native TST source {src2:?}"),
            });
        };
        self.emit_logic_reg_n(
            31,
            Self::gpr(src1)?,
            Self::gpr(*src2)?,
            0b11,
            false,
            width,
        )
    }

    fn lower_clz(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, 0b000100, width)
    }

    fn lower_rbit(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        self.emit_dp1(Self::dst_gpr(dst)?, Self::gpr(src)?, 0b000000, width)
    }

    fn lower_bswap(&mut self, dst: VReg, src: VReg, width: OpWidth) -> Result<(), LowerError> {
        let opcode = match width {
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
        if from_bits > to_bits || !matches!(to_width, OpWidth::W32 | OpWidth::W64) {
            return Err(LowerError::UnsupportedOp {
                op: format!(
                    "AArch64 native extend from {from_width:?} to {to_width:?}"
                ),
            });
        }

        let dst = Self::dst_gpr(dst)?;
        let src = Self::gpr(src)?;
        if from_bits == to_bits {
            return self.emit_mov_reg(dst, src, to_width);
        }
        self.emit_bitfield(
            dst,
            src,
            if sign_extend { 0b00 } else { 0b10 },
            0,
            from_bits - 1,
            to_width,
        )
    }

    fn lower_shift_imm(
        &mut self,
        dst: u8,
        src: u8,
        amount: i64,
        shift: ShiftOp,
        width: OpWidth,
    ) -> Result<(), LowerError> {
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
        if width == OpWidth::W32 && !matches!(shift, ShiftOp::Ror) {
            return Err(LowerError::UnsupportedOp {
                op: format!(
                    "AArch64 native W32 variable {shift:?} count semantics differ from SMIR"
                ),
            });
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

    fn lower_op(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        match &op.kind {
            OpKind::Nop => {
                self.emit(0xd503_201f);
                Ok(())
            }
            OpKind::Mov { dst, src, width } => self.lower_mov(*dst, src, *width),
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
            OpKind::And {
                dst,
                src1,
                src2,
                width,
                flags,
            } => {
                let opc = if flags.updates_any() { 0b11 } else { 0b00 };
                self.lower_logic(*dst, *src1, src2, opc, flags.updates_any(), *width)
            }
            OpKind::Or {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic(*dst, *src1, src2, 0b01, flags.updates_any(), *width),
            OpKind::Xor {
                dst,
                src1,
                src2,
                width,
                flags,
            } => self.lower_logic(*dst, *src1, src2, 0b10, flags.updates_any(), *width),
            OpKind::Neg {
                dst,
                src,
                width,
                flags,
            } => self.lower_neg(*dst, *src, flags.updates_any(), *width),
            OpKind::Not { dst, src, width } => self.lower_not(*dst, *src, *width),
            OpKind::Cmp { src1, src2, width } => self.lower_cmp(*src1, src2, *width),
            OpKind::Test { src1, src2, width } => self.lower_test(*src1, src2, *width),
            OpKind::Clz { dst, src, width } => self.lower_clz(*dst, *src, *width),
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
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native lowering for {other:?}"),
            }),
        }
    }

    fn lower_terminator(&mut self, block: &SmirBlock) -> Result<(), LowerError> {
        match &block.terminator {
            Terminator::Return { .. } => {
                self.emit(0xd65f_03c0);
                Ok(())
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native terminator {other:?}"),
            }),
        }
    }

    fn lower_block(&mut self, block: &SmirBlock) -> Result<(), LowerError> {
        self.block_offsets.insert(block.id, self.code.position());
        for op in &block.ops {
            self.lower_op(op)?;
        }
        self.lower_terminator(block)
    }
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
        self.relocations.clear();

        for block in &func.blocks {
            self.lower_block(block)?;
        }

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
    use crate::smir::ir::{FunctionBuilder, Terminator};
    use crate::smir::types::{FunctionId, SrcOperand};

    fn x(n: u8) -> VReg {
        VReg::Arch(ArchReg::Arm(ArmReg::X(n)))
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
}

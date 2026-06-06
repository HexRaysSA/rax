//! Native AArch64 code generator for SMIR.
//!
//! This lowerer currently targets identity-mapped AArch64 scalar SMIR: architectural
//! AArch64 X registers in SMIR are emitted as the same native X registers. It is
//! intentionally small and strict; unsupported virtual-register and memory forms
//! fail rather than silently changing semantics.

use std::collections::HashMap;

use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
use crate::smir::ops::{OpKind, SmirOp};
use crate::smir::types::{
    ArchReg, ArmReg, BlockId, Condition, ExtendOp, OpWidth, ShiftOp, SrcOperand, VReg,
};

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
            if [dst_lo, dst_hi].contains(&rn) || [dst_lo, dst_hi].contains(&rm) {
                return Err(LowerError::UnsupportedOp {
                    op: "AArch64 native full-width multiply with overlapping sources".into(),
                });
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
        signed: bool,
    ) -> Result<(), LowerError> {
        if rem.is_some() {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 native divide remainder output".into(),
            });
        }
        let SrcOperand::Reg(src2) = src2 else {
            return Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native divide source {src2:?}"),
            });
        };
        self.emit_dp2(
            Self::dst_gpr(quot)?,
            Self::gpr(src1)?,
            Self::gpr(*src2)?,
            if signed { 0b0011 } else { 0b0010 },
            width,
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
                let src = if value != 0 { src_true } else { src_false };
                self.lower_mov(dst, &SrcOperand::Reg(src), width)
            }
            other => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 native Select condition {other:?}"),
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
            } => self.lower_div(*quot, *rem, *src1, src2, *width, false),
            OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
            } => self.lower_div(*quot, *rem, *src1, src2, *width, true),
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
            OpKind::Select {
                dst,
                cond,
                src_true,
                src_false,
                width,
            } => self.lower_select(*dst, *cond, *src_true, *src_false, *width),
            OpKind::TestCondition { dst, cond } => self.lower_test_condition(*dst, *cond),
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
        let mut idx = 0;
        while idx < block.ops.len() {
            if let Some(consumed) = self.try_lower_fused_cond_compare(&block.ops[idx..])? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_select(&block.ops[idx..])? {
                idx += consumed;
                continue;
            }
            self.lower_op(&block.ops[idx])?;
            idx += 1;
        }
        self.lower_terminator(block)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CondSelectFalseOp {
    Identity,
    Increment,
    Invert,
    Negate,
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

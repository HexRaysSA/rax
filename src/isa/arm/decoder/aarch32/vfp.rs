//! Floating-point (VFP) instructions and the Advanced SIMD and floating-point
//! transfers between core and extension registers: loads and stores,
//! register transfers, `VMRS`/`VMSR`, `VDUP` (core register), `VSEL`,
//! `VMAXNM`/`VMINNM`, directed conversions and rounding, and data
//! processing.

use super::*;

impl Aarch32Decoder {
    pub(crate) fn decode_vfp_pair_register_transfer(raw: u32) -> Option<DecodedInsn> {
        let coproc = (raw >> 8) & 0xF;
        if ((raw >> 4) & 1) != 1
            || !matches!(coproc, 0b1010 | 0b1011)
            || ((raw >> 21) & 0x7) != 0b010
            || (raw & 0xC0) != 0
        {
            return None;
        }

        let rt = ((raw >> 12) & 0xF) as u8;
        let rt2 = ((raw >> 16) & 0xF) as u8;
        let fp = if coproc == 0b1010 {
            FpRegister::s(((raw & 0xF) as u8) << 1)
        } else {
            FpRegister::d(((((raw >> 5) & 1) << 4) | (raw & 0xF)) as u8)
        };
        Some(
            DecodedInsn::new(Mnemonic::VMOV, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::FpReg(fp))
                .with_operand(Operand::Reg(Register::raw(rt, false, false)))
                .with_operand(Operand::Reg(Register::raw(rt2, false, false))),
        )
    }

    pub(crate) fn decode_vfp_load_store(raw: u32) -> Option<DecodedInsn> {
        let p = (raw >> 24) & 1;
        let u = (raw >> 23) & 1;
        let w = (raw >> 21) & 1;
        let size = (raw >> 8) & 0x3;
        if ((raw >> 10) & 0x3) != 0b10 || size == 0 {
            return None;
        }

        if let Some(insn) = Self::decode_vfp_block_load_store(raw, p, u, w, size) {
            return Some(insn);
        }

        if p != 1 || w != 0 {
            return None;
        }

        let l = (raw >> 20) & 1;
        let d_bit = ((raw >> 22) & 1) as u8;
        let rn = ((raw >> 16) & 0xF) as u8;
        let vd = ((raw >> 12) & 0xF) as u8;
        let imm8 = (raw & 0xFF) as i64;
        let scale = if size == 1 { 2 } else { 4 };
        let offset = if u == 1 {
            imm8 * scale
        } else {
            -(imm8 * scale)
        };
        let fp = match size {
            1 | 2 => FpRegister::s((vd << 1) | d_bit),
            3 => FpRegister::d((d_bit << 4) | vd),
            _ => return None,
        };
        let mnemonic = if l == 1 {
            Mnemonic::VLDR
        } else {
            Mnemonic::VSTR
        };

        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::FpReg(fp))
                .with_operand(Operand::Mem(MemOperand::imm_offset(
                    Register::raw(rn, false, rn == 13),
                    offset,
                ))),
        )
    }

    pub(crate) fn decode_vfp_block_load_store(
        raw: u32,
        p: u32,
        u: u32,
        w: u32,
        size: u32,
    ) -> Option<DecodedInsn> {
        if !matches!((p, u, w), (0, 1, _) | (1, 0, 1)) {
            return None;
        }

        let imm8 = raw & 0xFF;
        if imm8 == 0 {
            return None;
        }
        if size == 3 && (imm8 & 1) != 0 {
            return None;
        }

        let l = (raw >> 20) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        let mnemonic = match (l, rn, p, u, w) {
            (0, 13, 1, 0, 1) => Mnemonic::VPUSH,
            (1, 13, 0, 1, 1) => Mnemonic::VPOP,
            (0, _, _, _, _) => Mnemonic::VSTM,
            (1, _, _, _, _) => Mnemonic::VLDM,
            _ => return None,
        };

        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4).with_operand(Operand::Mem(
                MemOperand::imm_offset(Register::raw(rn, false, rn == 13), 0),
            )),
        )
    }

    pub(crate) fn decode_vfp_transfer_or_system(raw: u32) -> Option<DecodedInsn> {
        let op = (raw >> 4) & 1;
        if op != 1 {
            return None;
        }

        let coproc = (raw >> 8) & 0xF;
        if coproc == 0b1010 && ((raw >> 21) & 0x7) >= 0b110 {
            let l = (raw >> 20) & 1;
            let mnemonic = if l == 1 {
                Mnemonic::VMRS
            } else {
                Mnemonic::VMSR
            };
            let reg = ((raw >> 16) & 0xF) as i64;
            let rt = ((raw >> 12) & 0xF) as u8;
            return Some(
                DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
                    .with_operand(Operand::Imm(Immediate::new(10)))
                    .with_operand(Operand::Imm(Immediate::new(reg)))
                    .with_operand(Operand::Reg(Register::raw(rt, false, false))),
            );
        }

        let opc1 = ((raw >> 21) & 0x3) as u8;
        let opc2 = ((raw >> 5) & 0x3) as u8;
        if !matches!(coproc, 0b1010 | 0b1011) {
            return None;
        }

        let rt = ((raw >> 12) & 0xF) as u8;
        let v = ((raw >> 16) & 0xF) as u8;
        if coproc == 0b1011 {
            let transfer_to_core = ((raw >> 20) & 1) != 0;
            let u = ((raw >> 23) & 1) != 0;
            let valid = if transfer_to_core {
                (opc1 & 0b10) != 0 || (opc1 & 0b10) == 0 && (opc2 & 1) != 0 || (!u && opc2 == 0)
            } else {
                !u && ((opc1 & 0b10) != 0 || (opc2 & 1) != 0 || opc2 == 0)
            };
            if valid {
                return Some(
                    DecodedInsn::new(Mnemonic::VMOV, ExecutionState::Aarch32, raw, 4)
                        .with_operand(Operand::FpReg(FpRegister::d(
                            ((((raw >> 7) & 1) << 4) as u8) | v,
                        )))
                        .with_operand(Operand::Imm(Immediate::new((opc1 & 1) as i64)))
                        .with_operand(Operand::Reg(Register::raw(rt, false, false))),
                );
            }

            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        if coproc == 0b1010 {
            if opc2 != 0 || (opc1 & 0b10) != 0 {
                return None;
            }
            if opc1 != 0 || (raw & 0xF) != 0 {
                return None;
            }
            let sreg = (v << 1) | (((raw >> 7) & 1) as u8);
            return Some(
                DecodedInsn::new(Mnemonic::VMOV, ExecutionState::Aarch32, raw, 4)
                    .with_operand(Operand::FpReg(FpRegister::s(sreg)))
                    .with_operand(Operand::Reg(Register::raw(rt, false, false))),
            );
        }

        Some(
            DecodedInsn::new(Mnemonic::VMOV, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::FpReg(FpRegister::d(
                    ((((raw >> 7) & 1) << 4) as u8) | v,
                )))
                .with_operand(Operand::Imm(Immediate::new((opc1 & 1) as i64)))
                .with_operand(Operand::Reg(Register::raw(rt, false, false))),
        )
    }

    pub(crate) fn decode_neon_vdup_register(raw: u32) -> Option<DecodedInsn> {
        if ((raw >> 23) & 0x1F) != 0b11101
            || ((raw >> 20) & 1) != 0
            || ((raw >> 8) & 0xF) != 0b1011
            || ((raw >> 6) & 1) != 0
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let b = (raw >> 22) & 1;
        let e = (raw >> 5) & 1;
        let q = ((raw >> 21) & 1) != 0;
        let vd = (raw >> 16) & 0xF;
        let rt = (raw >> 12) & 0xF;
        if (b == 1 && e == 1) || (q && (vd & 1) != 0) || rt == 15 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            Mnemonic::VDUP,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_vfp_conditional_select(raw: u32) -> Option<DecodedInsn> {
        if (raw & 0xFF80_0C50) != 0xFE00_0800 {
            return None;
        }
        let size = (raw >> 8) & 0x3;
        if size == 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        let mnemonic = match (raw >> 20) & 0x3 {
            0 => Mnemonic::VSELEQ,
            1 => Mnemonic::VSELVS,
            2 => Mnemonic::VSELGE,
            3 => Mnemonic::VSELGT,
            _ => return None,
        };

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_vfp_minmaxnm(raw: u32) -> Option<DecodedInsn> {
        if (raw & 0xFFB0_0C10) != 0xFE80_0800 {
            return None;
        }
        let size = (raw >> 8) & 0x3;
        let op = (raw >> 6) & 1;
        let mnemonic = match (op, size) {
            (0, 1) => Mnemonic::VMAXNM_F16,
            (0, 2) => Mnemonic::VMAXNM_F32,
            (0, 3) => Mnemonic::VMAXNM_F64,
            (1, 1) => Mnemonic::VMINNM_F16,
            (1, 2) => Mnemonic::VMINNM_F32,
            (1, 3) => Mnemonic::VMINNM_F64,
            _ => return None,
        };

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_vfp_directed_convert(raw: u32) -> Option<DecodedInsn> {
        if (raw & 0xFFBC_0C50) != 0xFEBC_0840 {
            return None;
        }
        let size = (raw >> 8) & 0x3;
        if size == 0 {
            return None;
        }
        let signed = ((raw >> 7) & 1) != 0;
        let mnemonic = match (((raw >> 16) & 0x3), size, signed) {
            (0, 1, true) => Mnemonic::VCVTA_S32_F16,
            (0, 1, false) => Mnemonic::VCVTA_U32_F16,
            (0, 2, true) => Mnemonic::VCVTA_S32_F32,
            (0, 2, false) => Mnemonic::VCVTA_U32_F32,
            (0, 3, true) => Mnemonic::VCVTA_S32_F64,
            (0, 3, false) => Mnemonic::VCVTA_U32_F64,
            (1, 1, true) => Mnemonic::VCVTN_S32_F16,
            (1, 1, false) => Mnemonic::VCVTN_U32_F16,
            (1, 2, true) => Mnemonic::VCVTN_S32_F32,
            (1, 2, false) => Mnemonic::VCVTN_U32_F32,
            (1, 3, true) => Mnemonic::VCVTN_S32_F64,
            (1, 3, false) => Mnemonic::VCVTN_U32_F64,
            (2, 1, true) => Mnemonic::VCVTP_S32_F16,
            (2, 1, false) => Mnemonic::VCVTP_U32_F16,
            (2, 2, true) => Mnemonic::VCVTP_S32_F32,
            (2, 2, false) => Mnemonic::VCVTP_U32_F32,
            (2, 3, true) => Mnemonic::VCVTP_S32_F64,
            (2, 3, false) => Mnemonic::VCVTP_U32_F64,
            (3, 1, true) => Mnemonic::VCVTM_S32_F16,
            (3, 1, false) => Mnemonic::VCVTM_U32_F16,
            (3, 2, true) => Mnemonic::VCVTM_S32_F32,
            (3, 2, false) => Mnemonic::VCVTM_U32_F32,
            (3, 3, true) => Mnemonic::VCVTM_S32_F64,
            (3, 3, false) => Mnemonic::VCVTM_U32_F64,
            _ => return None,
        };

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_vfp_directed_round(raw: u32) -> Option<DecodedInsn> {
        if (raw & 0xFFBC_0CD0) != 0xFEB8_0840 {
            return None;
        }
        let size = (raw >> 8) & 0x3;
        if size == 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        let mnemonic = match (((raw >> 16) & 0x3), size) {
            (0, 1) => Mnemonic::VRINTA_F16,
            (0, 2) => Mnemonic::VRINTA_F32,
            (0, 3) => Mnemonic::VRINTA_F64,
            (1, 1) => Mnemonic::VRINTN_F16,
            (1, 2) => Mnemonic::VRINTN_F32,
            (1, 3) => Mnemonic::VRINTN_F64,
            (2, 1) => Mnemonic::VRINTP_F16,
            (2, 2) => Mnemonic::VRINTP_F32,
            (2, 3) => Mnemonic::VRINTP_F64,
            (3, 1) => Mnemonic::VRINTM_F16,
            (3, 2) => Mnemonic::VRINTM_F32,
            (3, 3) => Mnemonic::VRINTM_F64,
            _ => return None,
        };

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_vfp_data_processing(raw: u32) -> Option<DecodedInsn> {
        if (raw & 0x0000_0810) != 0x0000_0800 {
            return None;
        }
        let size = (raw >> 8) & 0x3;
        if size == 0 {
            return None;
        }

        let op23 = (raw >> 23) & 1;
        let op21 = (raw >> 21) & 1;
        let op20 = (raw >> 20) & 1;
        let op6 = (raw >> 6) & 1;
        let op7 = (raw >> 7) & 1;
        let vn = (raw >> 16) & 0xF;
        let mnemonic = match (op23, op21, op20, op7, op6, vn) {
            (0, 0, 0, _, 0, _) => Mnemonic::VMLA,
            (0, 0, 0, _, 1, _) => Mnemonic::VMLS,
            (0, 0, 1, _, 0, _) => Mnemonic::VNMLS,
            (0, 0, 1, _, 1, _) => Mnemonic::VNMLA,
            (0, 1, 0, _, 0, _) => Mnemonic::VMUL,
            (0, 1, 0, _, 1, _) => Mnemonic::VNMUL,
            (0, 1, 1, _, 0, _) => Mnemonic::VADD,
            (0, 1, 1, _, 1, _) => Mnemonic::VSUB,
            (1, 0, 0, _, 0, _) => Mnemonic::VDIV,
            (1, 1, 0, _, 0, _) => Mnemonic::VFMA,
            (1, 1, 0, _, 1, _) => Mnemonic::VFMS,
            (1, 0, 1, _, 1, _) => Mnemonic::VFNMA,
            (1, 0, 1, _, 0, _) => Mnemonic::VFNMS,
            (1, 1, 1, 0, 1, 0) => Mnemonic::VMOV,
            (1, 1, 1, 0, 0, _) => Mnemonic::VMOV,
            (1, 1, 1, 1, 1, 0) => Mnemonic::VABS,
            (1, 1, 1, 0, 1, 1) => Mnemonic::VNEG,
            (1, 1, 1, 1, 1, 1) => Mnemonic::VSQRT,
            (1, 1, 1, 0, 1, 2) if size == 2 => Mnemonic::VCVTB_F32_F16,
            (1, 1, 1, 1, 1, 2) if size == 2 => Mnemonic::VCVTT_F32_F16,
            (1, 1, 1, 0, 1, 3) if size == 2 => Mnemonic::VCVTB_F16_F32,
            (1, 1, 1, 1, 1, 3) if size == 2 => Mnemonic::VCVTT_F16_F32,
            (1, 1, 1, 0, 1, 4 | 5) => Mnemonic::VCMP,
            (1, 1, 1, 0, 1, 6) if size == 1 => Mnemonic::VRINTR_F16,
            (1, 1, 1, 0, 1, 6) if size == 2 => Mnemonic::VRINTR_F32,
            (1, 1, 1, 0, 1, 6) if size == 3 => Mnemonic::VRINTR_F64,
            (1, 1, 1, 1, 1, 6) if size == 1 => Mnemonic::VRINTZ_F16,
            (1, 1, 1, 1, 1, 6) if size == 2 => Mnemonic::VRINTZ_F32,
            (1, 1, 1, 1, 1, 6) if size == 3 => Mnemonic::VRINTZ_F64,
            (1, 1, 1, 0, 1, 7) if size == 1 => Mnemonic::VRINTX_F16,
            (1, 1, 1, 0, 1, 7) if size == 2 => Mnemonic::VRINTX_F32,
            (1, 1, 1, 0, 1, 7) if size == 3 => Mnemonic::VRINTX_F64,
            (1, 1, 1, 1, 1, 4 | 5) => Mnemonic::VCMPE,
            (1, 1, 1, 1, 1, 7) if size == 2 => Mnemonic::VCVT_F64_F32,
            (1, 1, 1, 1, 1, 7) if size == 3 => Mnemonic::VCVT_F32_F64,
            (1, 1, 1, 1, 1, 8) if size == 1 => Mnemonic::VCVT_F16_S32,
            (1, 1, 1, 0, 1, 8) if size == 1 => Mnemonic::VCVT_F16_U32,
            (1, 1, 1, 1, 1, 8) if size == 2 => Mnemonic::VCVT_F32_S32,
            (1, 1, 1, 0, 1, 8) if size == 2 => Mnemonic::VCVT_F32_U32,
            (1, 1, 1, 1, 1, 8) if size == 3 => Mnemonic::VCVT_F64_S32,
            (1, 1, 1, 0, 1, 8) if size == 3 => Mnemonic::VCVT_F64_U32,
            (1, 1, 1, 1, 1, 10) if size == 2 => Mnemonic::VCVT_F32_S32_FIXED,
            (1, 1, 1, 1, 1, 11) if size == 2 => Mnemonic::VCVT_F32_U32_FIXED,
            (1, 1, 1, 1, 1, 14) if size == 2 => Mnemonic::VCVT_S32_F32_FIXED,
            (1, 1, 1, 1, 1, 15) if size == 2 => Mnemonic::VCVT_U32_F32_FIXED,
            (1, 1, 1, 1, 1, 10) if size == 3 => Mnemonic::VCVT_F64_S32_FIXED,
            (1, 1, 1, 1, 1, 11) if size == 3 => Mnemonic::VCVT_F64_U32_FIXED,
            (1, 1, 1, 1, 1, 14) if size == 3 => Mnemonic::VCVT_S32_F64_FIXED,
            (1, 1, 1, 1, 1, 15) if size == 3 => Mnemonic::VCVT_U32_F64_FIXED,
            (1, 1, 1, 1, 1, 12) if size == 2 => Mnemonic::VCVT_U32_F32,
            (1, 1, 1, 1, 1, 13) if size == 2 => Mnemonic::VCVT_S32_F32,
            (1, 1, 1, 0, 1, 12) if size == 1 => Mnemonic::VCVTR_U32_F16,
            (1, 1, 1, 0, 1, 13) if size == 1 => Mnemonic::VCVTR_S32_F16,
            (1, 1, 1, 0, 1, 12) if size == 2 => Mnemonic::VCVTR_U32_F32,
            (1, 1, 1, 0, 1, 13) if size == 2 => Mnemonic::VCVTR_S32_F32,
            (1, 1, 1, 1, 1, 12) if size == 1 => Mnemonic::VCVT_U32_F16,
            (1, 1, 1, 1, 1, 13) if size == 1 => Mnemonic::VCVT_S32_F16,
            (1, 1, 1, 1, 1, 12) if size == 3 => Mnemonic::VCVT_U32_F64,
            (1, 1, 1, 1, 1, 13) if size == 3 => Mnemonic::VCVT_S32_F64,
            (1, 1, 1, 0, 1, 12) if size == 3 => Mnemonic::VCVTR_U32_F64,
            (1, 1, 1, 0, 1, 13) if size == 3 => Mnemonic::VCVTR_S32_F64,
            _ => return None,
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4);
        if matches!(
            mnemonic,
            Mnemonic::VCVT_F32_S32_FIXED
                | Mnemonic::VCVT_F32_U32_FIXED
                | Mnemonic::VCVT_S32_F32_FIXED
                | Mnemonic::VCVT_U32_F32_FIXED
                | Mnemonic::VCVT_F64_S32_FIXED
                | Mnemonic::VCVT_F64_U32_FIXED
                | Mnemonic::VCVT_S32_F64_FIXED
                | Mnemonic::VCVT_U32_F64_FIXED
        ) {
            if op7 == 0 {
                return None;
            }
            let imm5 = (((raw & 0xF) << 1) | ((raw >> 5) & 1)) as i64;
            insn = insn.with_operand(Operand::Imm(Immediate::new(32 - imm5)));
        }

        Some(insn)
    }
}

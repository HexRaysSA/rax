//! Floating-point (VFP) instructions and the Advanced SIMD and floating-point
//! transfers between core and extension registers: loads and stores,
//! register transfers, `VMRS`/`VMSR`, `VDUP` (core register), `VSEL`,
//! `VMAXNM`/`VMINNM`, directed conversions and rounding, and data
//! processing.

use super::*;

pub(crate) struct VmovLaneTransfer {
    pub(crate) d: u8,
    pub(crate) rt: u8,
    pub(crate) bytes: u8,
    pub(crate) lane: u8,
    pub(crate) to_core: bool,
    pub(crate) unsigned: bool,
}

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
        // VMOV_ss encodes the first S register as Vm:M, including odd starts.
        // VMOV_d encodes its D register as M:Vm. Decode constraints precede
        // permission checks; select Undefined for these unpredictable operands.
        let single = (((raw & 0xf) << 1) | ((raw >> 5) & 1)) as u8;
        let to_core = raw & (1 << 20) != 0;
        if rt == 15 || rt2 == 15 || coproc == 0b1010 && single == 31 || to_core && rt == rt2 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        let fp = if coproc == 0b1010 {
            FpRegister::s(single)
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
        // Select Undefined for the unpredictable conditional FP16 forms.
        // The Thumb wrapper supplies AL here and checks IT at execution.
        if size == 1 && raw >> 28 != 14 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
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
        if !matches!(size, 2 | 3) || !matches!((p, u, w), (0, 1, _) | (1, 0, 1)) {
            return None;
        }

        let l = (raw >> 20) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        // Decode constraints precede CheckVFPEnabled. Preserve the selected
        // Undefined outcome for invalid lists and apply it to invalid bases.
        if Self::vfp_block_registers(raw).is_none() || rn == 15 && w != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        let legacy = size == 3 && raw & 1 != 0;
        let mnemonic = match (l, rn, p, u, w, legacy) {
            (0, 13, 1, 0, 1, false) => Mnemonic::VPUSH,
            (1, 13, 0, 1, 1, false) => Mnemonic::VPOP,
            (0, _, _, _, _, _) => Mnemonic::VSTM,
            (1, _, _, _, _, _) => Mnemonic::VLDM,
            _ => return None,
        };

        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4).with_operand(Operand::Mem(
                MemOperand::imm_offset(Register::raw(rn, false, rn == 13), 0),
            )),
        )
    }

    /// Element width, first register, and register count of a scalar VFP list.
    pub(crate) fn vfp_block_registers(raw: u32) -> Option<(u32, u8, u8)> {
        let size = (raw >> 8) & 3;
        let vd = ((raw >> 12) & 15) as u8;
        let d = ((raw >> 22) & 1) as u8;
        let words = (raw & 0xff) as u8;
        let (width, first, count, limit) = match size {
            2 => (32, (vd << 1) | d, words, 32),
            // FLDMX/FSTMX use an odd word count and address only D0–D15.
            3 if words & 1 != 0 => (64, (d << 4) | vd, words / 2, 16),
            3 => (64, (d << 4) | vd, words / 2, 32),
            _ => return None,
        };
        if count == 0 || size == 3 && count > 16 || u16::from(first) + u16::from(count) > limit {
            return None;
        }
        Some((width, first, count))
    }

    pub(crate) fn vmov_lane_transfer(raw: u32) -> Option<VmovLaneTransfer> {
        if raw & 0x0f00_0f10 != 0x0e00_0b10 || raw >> 28 == 15 {
            return None;
        }
        let rt = ((raw >> 12) & 15) as u8;
        let to_core = raw & (1 << 20) != 0;
        let unsigned = raw & (1 << 23) != 0;
        if rt == 15 || unsigned && !to_core {
            return None;
        }
        let index_high = ((raw >> 21) & 1) as u8;
        let opc2 = ((raw >> 5) & 3) as u8;
        let (bytes, lane) = if raw & (1 << 22) != 0 {
            (1, (index_high << 2) | opc2)
        } else if opc2 & 1 != 0 {
            (2, (index_high << 1) | (opc2 >> 1))
        } else if opc2 == 0 && !unsigned {
            (4, index_high)
        } else {
            return None;
        };
        let d = ((((raw >> 7) & 1) << 4) | ((raw >> 16) & 15)) as u8;
        Some(VmovLaneTransfer {
            d,
            rt,
            bytes,
            lane,
            to_core,
            unsigned,
        })
    }

    pub(crate) fn decode_vfp_transfer_or_system(raw: u32) -> Option<DecodedInsn> {
        let op = (raw >> 4) & 1;
        if op != 1 {
            return None;
        }

        let coproc = (raw >> 8) & 0xF;
        let opcode = (raw >> 21) & 7;
        // The half-register decoder has already claimed the allocated CP9
        // transfer. Remaining CP8/CP9 words are unallocated in this group.
        if matches!(coproc, 8 | 9) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        if coproc == 0b1010 && opcode != 0 {
            // This space allocates only the single-register VMOV (opcode 0)
            // and the special-register transfers (opcode 7). Select Undefined
            // for VMRS/VMSR with nonzero (0) fields at [7:5] or [3:0].
            if opcode != 7 || raw & 0xef != 0 {
                return Some(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch32,
                    raw,
                    4,
                ));
            }
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

        if !matches!(coproc, 0b1010 | 0b1011) {
            return None;
        }

        let rt = ((raw >> 12) & 0xF) as u8;
        // Core/extension transfers select Undefined before FP access checks
        // for R15 and for nonzero (0) fields in the single-register form.
        if rt == 15 || (coproc == 0b1010 && raw & 0x6f != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        let core = Operand::Reg(Register::raw(rt, false, false));
        let insn = DecodedInsn::new(Mnemonic::VMOV, ExecutionState::Aarch32, raw, 4);
        if coproc == 0b1011 {
            let Some(transfer) = Self::vmov_lane_transfer(raw) else {
                return Some(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch32,
                    raw,
                    4,
                ));
            };
            let fp = Operand::FpReg(FpRegister::d(transfer.d));
            let lane = Operand::Imm(Immediate::new(i64::from(transfer.lane)));
            return Some(if transfer.to_core {
                insn.with_operands([core, fp, lane])
            } else {
                insn.with_operands([fp, lane, core])
            });
        }

        let sreg = ((((raw >> 16) & 15) << 1) | ((raw >> 7) & 1)) as u8;
        let fp = Operand::FpReg(FpRegister::s(sreg));
        Some(if raw & (1 << 20) != 0 {
            insn.with_operands([core, fp])
        } else {
            insn.with_operands([fp, core])
        })
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
        // Ordinary scalar FP uses coprocessors 8..11 in the conditional
        // 1110 major space. Unconditional FP extensions are decoded first.
        if raw & 0x0f00_0c10 != 0x0e00_0800 {
            return None;
        }
        let size = (raw >> 8) & 0x3;
        if raw >> 28 == 15 || size == 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        if let Some(fields) = Self::scalar_fixed_fields(raw) {
            let insn = DecodedInsn::new(fields.mnemonic, ExecutionState::Aarch32, raw, 4);
            return Some(if fields.mnemonic == Mnemonic::UNDEFINED {
                insn
            } else {
                insn.with_operand(Operand::Imm(Immediate::new(i64::from(
                    fields.fractional_bits,
                ))))
            });
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
            // Register VMOV uses coprocessor fields 1010/1011; 1001 is reserved.
            (1, 1, 1, 0, 1, 0) if size == 1 => Mnemonic::UNDEFINED,
            (1, 1, 1, 0, 1, 0) => Mnemonic::VMOV,
            // Scalar VMOV (immediate) A2/T2 has SBZ bits 7 and 5.
            (1, 1, 1, 0, 0, _) if raw & (1 << 5) == 0 => Mnemonic::VMOV,
            (1, 1, 1, 1, 1, 0) => Mnemonic::VABS,
            (1, 1, 1, 0, 1, 1) => Mnemonic::VNEG,
            (1, 1, 1, 1, 1, 1) => Mnemonic::VSQRT,
            (1, 1, 1, 0, 1, 2) if size == 2 => Mnemonic::VCVTB_F32_F16,
            (1, 1, 1, 0, 1, 2) if size == 3 => Mnemonic::VCVTB_F64_F16,
            (1, 1, 1, 1, 1, 2) if size == 2 => Mnemonic::VCVTT_F32_F16,
            (1, 1, 1, 1, 1, 2) if size == 3 => Mnemonic::VCVTT_F64_F16,
            (1, 1, 1, 0, 1, 3) if size == 2 => Mnemonic::VCVTB_F16_F32,
            (1, 1, 1, 0, 1, 3) if size == 3 => Mnemonic::VCVTB_F16_F64,
            (1, 1, 1, 1, 1, 3) if size == 2 => Mnemonic::VCVTT_F16_F32,
            (1, 1, 1, 1, 1, 3) if size == 3 => Mnemonic::VCVTT_F16_F64,
            // VCMP/VCMPE against zero A2/T2 require bits 5 and 3:0 to be zero.
            (1, 1, 1, _, 1, 5) if raw & 0x2f != 0 => Mnemonic::UNDEFINED,
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
            (1, 1, 1, 1, 1, 9) if size == 3 => Mnemonic::VJCVT_S32_F64,
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
            // The conditional scalar FP prefix has already been matched.
            // Unallocated opcode/size combinations cannot decode as CDP.
            _ => Mnemonic::UNDEFINED,
        };

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }
}

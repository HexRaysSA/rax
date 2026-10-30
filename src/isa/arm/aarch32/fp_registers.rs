//! MVFR0.SIMDReg admission, before access traps and operand effects.
//!
//! Arm DDI0487B.a G6.2.107 defines the D16/D32 register banks. Raw
//! transfer width does not imply double-precision arithmetic support.
use super::VfpState;
use crate::isa::arm::decoder::{
    Aarch32Decoder, DecodedInsn, FpRegSize, Mnemonic, Operand, ThumbDecoder,
};

pub(super) fn instruction_supported(insn: &DecodedInsn, advsimd: bool, state: &VfpState) -> bool {
    let registers = match state.mvfr0 & 15 {
        1 => 16,
        2 => 32,
        _ => return false,
    };
    if advsimd {
        return registers == 32;
    }
    if registers == 32 {
        return true;
    }
    if insn.operands.iter().any(|operand| {
        matches!(operand, Operand::FpReg(reg) if reg.size == FpRegSize::D && reg.num >= 16)
    }) {
        return false;
    }
    // Explicit FP operands describe core transfers and scalar loads/stores.
    // Their remaining raw bits can name core registers, lanes or offsets.
    if insn
        .operands
        .iter()
        .any(|operand| matches!(operand, Operand::FpReg(_)))
    {
        return true;
    }
    let raw = if insn.state.is_thumb() && insn.size == 4 {
        ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
    } else {
        insn.raw
    };
    if matches!(
        insn.mnemonic,
        Mnemonic::VLDM | Mnemonic::VSTM | Mnemonic::VPUSH | Mnemonic::VPOP
    ) {
        if (raw >> 8) & 3 != 3 {
            return true; // S0-S31 all alias D0-D15.
        }
        let first = ((raw >> 12) & 15) | ((raw >> 18) & 16);
        let count = (raw & 255) >> 1;
        return first + count <= 16;
    }
    if let Some(fields) = Aarch32Decoder::scalar_fixed_fields(raw) {
        // Vm:M encodes fractional bits here, not a second register.
        return fields.fp_bits != 64 || fields.d < 16;
    }
    // Scalar data processing has no explicit decoded register operands.
    // Other classes have already been checked above or access system state.
    if raw & 0x0f00_0010 != 0x0e00_0000 {
        return true;
    }
    let d = 1 << 22;
    let n = 1 << 7;
    let m = 1 << 5;
    let used = match insn.mnemonic {
        Mnemonic::VCVT_F64_F32
        | Mnemonic::VCVTB_F64_F16
        | Mnemonic::VCVTT_F64_F16
        | Mnemonic::VCVT_F64_S32
        | Mnemonic::VCVT_F64_U32 => d,
        Mnemonic::VCVT_F32_F64
        | Mnemonic::VCVTB_F16_F64
        | Mnemonic::VCVTT_F16_F64
        | Mnemonic::VCVT_S32_F64
        | Mnemonic::VCVT_U32_F64
        | Mnemonic::VCVTR_S32_F64
        | Mnemonic::VCVTR_U32_F64
        | Mnemonic::VCVTA_S32_F64
        | Mnemonic::VCVTA_U32_F64
        | Mnemonic::VCVTN_S32_F64
        | Mnemonic::VCVTN_U32_F64
        | Mnemonic::VCVTP_S32_F64
        | Mnemonic::VCVTP_U32_F64
        | Mnemonic::VCVTM_S32_F64
        | Mnemonic::VCVTM_U32_F64 => m,
        _ if (raw >> 8) & 3 != 3 => 0,
        Mnemonic::VADD
        | Mnemonic::VSUB
        | Mnemonic::VMUL
        | Mnemonic::VDIV
        | Mnemonic::VMLA
        | Mnemonic::VMLS
        | Mnemonic::VNMLA
        | Mnemonic::VNMLS
        | Mnemonic::VNMUL
        | Mnemonic::VFMA
        | Mnemonic::VFMS
        | Mnemonic::VFNMA
        | Mnemonic::VFNMS
        | Mnemonic::VSELEQ
        | Mnemonic::VSELGE
        | Mnemonic::VSELGT
        | Mnemonic::VSELVS
        | Mnemonic::VMAXNM_F64
        | Mnemonic::VMINNM_F64 => d | n | m,
        Mnemonic::VMOV if raw & (1 << 6) == 0 => d, // Immediate literal.
        Mnemonic::VCMP | Mnemonic::VCMPE if raw & (1 << 16) != 0 => d, // Compare zero.
        _ => d | m,
    };
    raw & used == 0
}

//! Scalar precision and optional-operation admission from MVFR0.
//!
//! Arm DDI0487B.a G6.2.107 distinguishes VFPv2 from VFPv3, and
//! arithmetic precision from the shared register file's storage width.
use super::{HalfKind, VfpState, kind};
use crate::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};

pub(super) fn instruction_supported(insn: &DecodedInsn, advsimd: bool, state: &VfpState) -> bool {
    // Vector operations use their Advanced SIMD capability fields; the scalar
    // FPSP/FPDP fields must not accidentally disable them.
    if advsimd || state.mvfr0 & 0x00ff_0ff0 == 0x0011_0220 {
        return true;
    }
    let single = (state.mvfr0 >> 4) & 15;
    let double = (state.mvfr0 >> 8) & 15;
    match kind(insn, false) {
        HalfKind::ScalarData => return true, // Checked by the distinct FP16 admission.
        HalfKind::ScalarConversion { double: false } => return matches!(single, 1 | 2),
        HalfKind::ScalarConversion { double: true } => return matches!(double, 1 | 2),
        _ => {}
    }
    let raw = if insn.state.is_thumb() && insn.size == 4 {
        ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
    } else {
        insn.raw
    };
    if let Some(fields) = Aarch32Decoder::scalar_fixed_fields(raw) {
        // VFPv3 adds fixed-point conversion. Its integer operand is stored in
        // the same extension register and does not imply another precision.
        return match fields.fp_bits {
            16 => true,
            32 => single == 2,
            64 => double == 2,
            _ => false,
        };
    }
    if raw & 0x0f00_0010 != 0x0e00_0000 {
        // Core transfers, scalar memory transfers and FP system-register
        // access require scalar FP, including raw 64-bit loads/stores/moves.
        // They do not require double-precision arithmetic.
        return matches!(single, 1 | 2);
    }
    if matches!(
        insn.mnemonic,
        Mnemonic::VCVT_F64_F32 | Mnemonic::VCVT_F32_F64
    ) {
        return matches!(single, 1 | 2) && matches!(double, 1 | 2);
    }
    let precision = if (raw >> 8) & 3 == 3 { double } else { single };
    if !matches!(precision, 1 | 2) {
        return false;
    }
    if insn.mnemonic == Mnemonic::VMOV && raw & (1 << 6) == 0 {
        return precision == 2; // Floating-point immediate constants require VFPv3.
    }
    match insn.mnemonic {
        Mnemonic::VDIV => (state.mvfr0 >> 16) & 15 == 1,
        Mnemonic::VSQRT => (state.mvfr0 >> 20) & 15 == 1,
        _ => true,
    }
}

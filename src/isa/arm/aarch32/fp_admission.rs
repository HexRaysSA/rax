//! Capability admission for the implemented A32/T32 floating-point families.
//!
//! MVFR1 conversion fields do not imply FEAT_FP16 data processing. See the
//! archived Arm ASL guards and feature-admission reference provenance.
use super::vfp::VfpState;
use crate::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};

#[path = "fp_modes.rs"]
mod modes;
#[path = "fp_precision.rs"]
mod precision;
#[path = "fp_registers.rs"]
mod registers;
#[path = "fp_simd_precision.rs"]
mod simd_precision;

pub(crate) use modes::execution_supported;

/// Decode-time capabilities precede access checks and architectural effects.
/// The MVFR1/MVFR2 definitions are retained in ARM DDI 0487B.a, G6.2.108-109.
pub(crate) fn instruction_supported(
    insn: &DecodedInsn,
    advsimd: bool,
    state: &VfpState,
    id_isar6: u32,
) -> bool {
    if advsimd {
        // Arm DDI0487B.a G6.2.108: SIMDLS admits structure memory
        // operations; SIMDInt admits integer/register operations and is also
        // required by SIMDSP. Only field value 1 denotes implementation.
        let shift = if matches!(
            insn.mnemonic,
            Mnemonic::VLD1
                | Mnemonic::VLD2
                | Mnemonic::VLD3
                | Mnemonic::VLD4
                | Mnemonic::VST1
                | Mnemonic::VST2
                | Mnemonic::VST3
                | Mnemonic::VST4
        ) {
            8
        } else {
            12
        };
        if (state.mvfr1 >> shift) & 15 != 1 {
            return false;
        }
    }
    if !registers::instruction_supported(insn, advsimd, state)
        || !precision::instruction_supported(insn, advsimd, state)
        || advsimd && !simd_precision::instruction_supported(insn, state)
        || !half_supported(insn, advsimd, state, id_isar6)
        || !modes::instruction_supported(insn, advsimd, state)
    {
        return false;
    }
    if matches!(
        insn.mnemonic,
        Mnemonic::VFMA | Mnemonic::VFMS | Mnemonic::VFNMA | Mnemonic::VFNMS
    ) {
        // Scalar and Advanced SIMD implementations advertise the same fused
        // support. Values other than 0 and 1 are reserved, not extra levels.
        return state.mvfr1 >> 28 == 1;
    }
    let scalar_minimum = match insn.mnemonic {
        Mnemonic::VSELEQ | Mnemonic::VSELGE | Mnemonic::VSELGT | Mnemonic::VSELVS => 1,
        Mnemonic::VCVTA_S32_F16
        | Mnemonic::VCVTA_U32_F16
        | Mnemonic::VCVTN_S32_F16
        | Mnemonic::VCVTN_U32_F16
        | Mnemonic::VCVTP_S32_F16
        | Mnemonic::VCVTP_U32_F16
        | Mnemonic::VCVTM_S32_F16
        | Mnemonic::VCVTM_U32_F16
        | Mnemonic::VCVTA_S16_F16
        | Mnemonic::VCVTA_U16_F16
        | Mnemonic::VCVTN_S16_F16
        | Mnemonic::VCVTN_U16_F16
        | Mnemonic::VCVTP_S16_F16
        | Mnemonic::VCVTP_U16_F16
        | Mnemonic::VCVTM_S16_F16
        | Mnemonic::VCVTM_U16_F16
        | Mnemonic::VCVTA_S32_F32
        | Mnemonic::VCVTA_U32_F32
        | Mnemonic::VCVTN_S32_F32
        | Mnemonic::VCVTN_U32_F32
        | Mnemonic::VCVTP_S32_F32
        | Mnemonic::VCVTP_U32_F32
        | Mnemonic::VCVTM_S32_F32
        | Mnemonic::VCVTM_U32_F32
        | Mnemonic::VCVTA_S32_F64
        | Mnemonic::VCVTA_U32_F64
        | Mnemonic::VCVTN_S32_F64
        | Mnemonic::VCVTN_U32_F64
        | Mnemonic::VCVTP_S32_F64
        | Mnemonic::VCVTP_U32_F64
        | Mnemonic::VCVTM_S32_F64
        | Mnemonic::VCVTM_U32_F64 => 2,
        Mnemonic::VRINTA_F16
        | Mnemonic::VRINTN_F16
        | Mnemonic::VRINTP_F16
        | Mnemonic::VRINTM_F16
        | Mnemonic::VRINTR_F16
        | Mnemonic::VRINTX_F16
        | Mnemonic::VRINTZ_F16
        | Mnemonic::VRINTA_F32
        | Mnemonic::VRINTN_F32
        | Mnemonic::VRINTP_F32
        | Mnemonic::VRINTM_F32
        | Mnemonic::VRINTR_F32
        | Mnemonic::VRINTX_F32
        | Mnemonic::VRINTZ_F32
        | Mnemonic::VRINTA_F64
        | Mnemonic::VRINTN_F64
        | Mnemonic::VRINTP_F64
        | Mnemonic::VRINTM_F64
        | Mnemonic::VRINTR_F64
        | Mnemonic::VRINTX_F64
        | Mnemonic::VRINTZ_F64 => 3,
        Mnemonic::VMAXNM_F16
        | Mnemonic::VMINNM_F16
        | Mnemonic::VMAXNM_F32
        | Mnemonic::VMINNM_F32
        | Mnemonic::VMAXNM_F64
        | Mnemonic::VMINNM_F64 => 4,
        _ => return true,
    };
    if advsimd {
        // SIMDMisc omits scalar selection and numbers its remaining levels
        // one lower. Reject reserved values rather than treating them as a
        // superset. Invalid SIMD selection cannot acquire an allocation here.
        let level = state.mvfr2 & 15;
        scalar_minimum > 1 && (scalar_minimum - 1..=3).contains(&level)
    } else {
        let level = (state.mvfr2 >> 4) & 15;
        (scalar_minimum..=4).contains(&level)
    }
}

#[derive(Clone, Copy)]
enum HalfKind {
    None,
    ScalarConversion { double: bool },
    SimdConversion,
    ScalarData,
    SimdData,
}

fn decoded_as(decoded: Option<DecodedInsn>, mnemonic: Mnemonic) -> bool {
    decoded.is_some_and(|decoded| decoded.mnemonic == mnemonic && mnemonic != Mnemonic::UNDEFINED)
}

fn kind(insn: &DecodedInsn, advsimd: bool) -> HalfKind {
    let raw = if insn.state.is_thumb() && insn.size == 4 {
        ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
    } else {
        insn.raw
    };
    match insn.mnemonic {
        Mnemonic::VCVTB_F32_F16
        | Mnemonic::VCVTT_F32_F16
        | Mnemonic::VCVTB_F16_F32
        | Mnemonic::VCVTT_F16_F32 => {
            return HalfKind::ScalarConversion { double: false };
        }
        Mnemonic::VCVTB_F64_F16
        | Mnemonic::VCVTT_F64_F16
        | Mnemonic::VCVTB_F16_F64
        | Mnemonic::VCVTT_F16_F64 => {
            return HalfKind::ScalarConversion { double: true };
        }
        Mnemonic::VCVT_F16_F32 | Mnemonic::VCVT_F32_F16 if advsimd => {
            return HalfKind::SimdConversion;
        }
        _ => {}
    }
    let typed_half = matches!(
        insn.mnemonic,
        Mnemonic::VMAXNM_F16
            | Mnemonic::VMINNM_F16
            | Mnemonic::VRINTA_F16
            | Mnemonic::VRINTM_F16
            | Mnemonic::VRINTN_F16
            | Mnemonic::VRINTP_F16
            | Mnemonic::VRINTR_F16
            | Mnemonic::VRINTX_F16
            | Mnemonic::VRINTZ_F16
            | Mnemonic::VCVT_F16_S32
            | Mnemonic::VCVT_F16_U32
            | Mnemonic::VCVT_S32_F16
            | Mnemonic::VCVT_U32_F16
            | Mnemonic::VCVTA_S32_F16
            | Mnemonic::VCVTA_U32_F16
            | Mnemonic::VCVTM_S32_F16
            | Mnemonic::VCVTM_U32_F16
            | Mnemonic::VCVTN_S32_F16
            | Mnemonic::VCVTN_U32_F16
            | Mnemonic::VCVTP_S32_F16
            | Mnemonic::VCVTP_U32_F16
            | Mnemonic::VCVTR_S32_F16
            | Mnemonic::VCVTR_U32_F16
            | Mnemonic::VCVT_F16_S16
            | Mnemonic::VCVT_F16_U16
            | Mnemonic::VCVT_S16_F16
            | Mnemonic::VCVT_U16_F16
            | Mnemonic::VCVT_F16_S16_FIXED
            | Mnemonic::VCVT_S16_F16_FIXED
            | Mnemonic::VCVT_F16_U16_FIXED
            | Mnemonic::VCVT_U16_F16_FIXED
            | Mnemonic::VCVT_F16_S32_FIXED
            | Mnemonic::VCVT_S32_F16_FIXED
            | Mnemonic::VCVT_F16_U32_FIXED
            | Mnemonic::VCVT_U32_F16_FIXED
            | Mnemonic::VCVTA_S16_F16
            | Mnemonic::VCVTA_U16_F16
            | Mnemonic::VCVTN_S16_F16
            | Mnemonic::VCVTN_U16_F16
            | Mnemonic::VCVTP_S16_F16
            | Mnemonic::VCVTP_U16_F16
            | Mnemonic::VCVTM_S16_F16
            | Mnemonic::VCVTM_U16_F16
            | Mnemonic::VMOV_F16_CORE
            | Mnemonic::VMOVX_F16
            | Mnemonic::VINS_F16
    );
    if !advsimd {
        // Scalar half arithmetic, conversion, register and load/store forms
        // use coprocessor field 1001. VMOVX/VINS have their own encodings.
        return if typed_half || (raw >> 8) & 15 == 9 {
            HalfKind::ScalarData
        } else {
            HalfKind::None
        };
    }
    if typed_half {
        return HalfKind::SimdData;
    }
    // Same-size floating-point vector forms use bit 20 for FP16. Decoding
    // the exact class avoids mistaking integer halfwords for floating point.
    let same_size = [
        Aarch32Decoder::decode_neon_fp_add_sub(raw),
        Aarch32Decoder::decode_neon_fp_absdiff(raw),
        Aarch32Decoder::decode_neon_fp_fma(raw),
        Aarch32Decoder::decode_neon_fp_multiply(raw),
        Aarch32Decoder::decode_neon_fp_minmax(raw),
        Aarch32Decoder::decode_neon_fp_pairwise(raw),
        Aarch32Decoder::decode_neon_fp_compare(raw),
        Aarch32Decoder::decode_neon_recip_step(raw),
    ]
    .into_iter()
    .any(|decoded| decoded_as(decoded, insn.mnemonic));
    if same_size && raw & (1 << 20) != 0 {
        return HalfKind::SimdData;
    }
    let scalar_lane = decoded_as(
        Aarch32Decoder::decode_neon_fp_multiply_scalar(raw),
        insn.mnemonic,
    ) && (raw >> 20) & 3 == 1;
    let misc_half = (raw >> 18) & 3 == 1
        && (decoded_as(Aarch32Decoder::decode_neon_abs_neg(raw), insn.mnemonic)
            && raw & (1 << 10) != 0
            || decoded_as(Aarch32Decoder::decode_neon_compare_zero(raw), insn.mnemonic)
                && (raw >> 10) & 3 == 1
            || decoded_as(
                Aarch32Decoder::decode_neon_recip_estimate(raw),
                insn.mnemonic,
            ) && raw & (1 << 8) != 0);
    if scalar_lane || misc_half {
        HalfKind::SimdData
    } else {
        HalfKind::None
    }
}

pub(crate) fn half_supported(
    insn: &DecodedInsn,
    advsimd: bool,
    state: &VfpState,
    id_isar6: u32,
) -> bool {
    let scalar = (state.mvfr1 >> 24) & 15;
    let simd = (state.mvfr1 >> 20) & 15;
    // FHM is distinct from FP16 arithmetic and requires vector half support.
    // Reserved feature encodings must not accidentally enable the extension.
    if matches!(insn.mnemonic, Mnemonic::VFMAL | Mnemonic::VFMLS) {
        return advsimd && simd == 2 && (id_isar6 >> 8) & 15 == 1;
    }
    // The default full-half profile needs no further instruction classification.
    if scalar == 3 && simd == 2 {
        return true;
    }
    match kind(insn, advsimd) {
        HalfKind::None => true,
        HalfKind::ScalarConversion { double: false } => matches!(scalar, 1..=3),
        HalfKind::ScalarConversion { double: true } => matches!(scalar, 2 | 3),
        HalfKind::SimdConversion => matches!(simd, 1 | 2),
        HalfKind::ScalarData => scalar == 3,
        HalfKind::SimdData => simd == 2,
    }
}

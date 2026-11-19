//! Capability admission for the implemented A32/T32 floating-point families.
//!
//! MVFR1 conversion fields do not imply FEAT_FP16 data processing. See the
//! archived Arm ASL guards and feature-admission reference provenance.
use super::{
    cp15::{ID_ISAR5_VCMA, ID_ISAR6_DP},
    vfp::VfpState,
};
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
    id_isar5: u32,
    id_isar6: u32,
) -> bool {
    if matches!(insn.mnemonic, Mnemonic::VCADD | Mnemonic::VCMLA) {
        return advsimd
            && effective_id_isar5_vcma(id_isar5, state.mvfr0, state.mvfr1) & ID_ISAR5_VCMA != 0
            && Aarch32Decoder::complex_simd_fields(a32_word(insn)).is_some_and(|fields| {
                fields.is_ok_and(|fields| {
                    fields.mnemonic == insn.mnemonic
                        && (fields.element_bits == 32 || (state.mvfr1 >> 20) & 15 == 2)
                })
            });
    }
    if matches!(insn.mnemonic, Mnemonic::VSDOT | Mnemonic::VUDOT) {
        return advsimd
            && effective_id_isar6(id_isar6, state.mvfr0, state.mvfr1) & ID_ISAR6_DP != 0
            && Aarch32Decoder::dot_product_fields(a32_word(insn))
                .is_some_and(|fields| fields.is_ok_and(|fields| fields.mnemonic == insn.mnemonic));
    }
    if matches!(insn.mnemonic, Mnemonic::VQRDMLAH | Mnemonic::VQRDMLSH)
        && (!advsimd || (id_isar5 >> 24) & 15 != 1)
    {
        return false;
    }
    if insn.mnemonic == Mnemonic::VJCVT_S32_F64 && id_isar6 & 15 != 1 {
        return false;
    }
    if !advsimd && super::fp_traps::is_computation(insn) && (state.mvfr0 >> 12) & 15 > 1 {
        return false;
    }
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
    if !advsimd && super::short_vectors::plan(insn, state).is_err() {
        return false;
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

/// The T32 encoding restrictions are checked after the predicate passes.
/// Arm DDI0597 ID032025 specifies these in the individual instruction decodes.
pub(crate) fn predicate_supported(insn: &DecodedInsn, advsimd: bool, in_it: bool) -> bool {
    if insn.mnemonic == Mnemonic::VJCVT_S32_F64 {
        return if insn.state.is_thumb() {
            !in_it
        } else {
            insn.raw >> 28 == 14
        };
    }
    if !in_it {
        // Scalar FP16 data processing requires AL in the conditional A32
        // space. Condition 1111 belongs to the unconditional namespace.
        return insn.state.is_thumb()
            || advsimd
            || insn.raw >> 28 >= 14
            || !matches!(kind(insn, false), HalfKind::ScalarData);
    }
    let mnemonic = insn.mnemonic;
    if matches!(
        mnemonic,
        Mnemonic::VSELEQ
            | Mnemonic::VSELGE
            | Mnemonic::VSELGT
            | Mnemonic::VSELVS
            | Mnemonic::VMAXNM_F16
            | Mnemonic::VMAXNM_F32
            | Mnemonic::VMAXNM_F64
            | Mnemonic::VMINNM_F16
            | Mnemonic::VMINNM_F32
            | Mnemonic::VMINNM_F64
            | Mnemonic::VFMAL
            | Mnemonic::VFMLS
            | Mnemonic::VQRDMLAH
            | Mnemonic::VQRDMLSH
            | Mnemonic::VCADD
            | Mnemonic::VCMLA
            | Mnemonic::VSDOT
            | Mnemonic::VUDOT
    ) {
        return false;
    }
    let raw = a32_word(insn);
    if advsimd {
        // The vector rounding group excludes IT at both widths. FP16
        // fixed-point conversion shares mnemonics with the restricted
        // integer conversion but has its own encoding and permits IT.
        !decoded_as(Aarch32Decoder::decode_neon_vrint(raw), mnemonic)
            && !decoded_as(Aarch32Decoder::decode_neon_directed_convert(raw), mnemonic)
            && (!matches!(kind_from_word(insn, true, raw), HalfKind::SimdData)
                || decoded_as(Aarch32Decoder::decode_neon_fp_fixed_convert(raw), mnemonic))
    } else {
        !decoded_as(Aarch32Decoder::decode_vfp_directed_round(raw), mnemonic)
            && !decoded_as(Aarch32Decoder::decode_vfp_directed_convert(raw), mnemonic)
            && !matches!(kind_from_word(insn, false, raw), HalfKind::ScalarData)
    }
}

fn decoded_as(decoded: Option<DecodedInsn>, mnemonic: Mnemonic) -> bool {
    decoded.is_some_and(|decoded| decoded.mnemonic == mnemonic && mnemonic != Mnemonic::UNDEFINED)
}

fn a32_word(insn: &DecodedInsn) -> u32 {
    if insn.state.is_thumb() && insn.size == 4 {
        ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
    } else {
        insn.raw
    }
}

fn kind(insn: &DecodedInsn, advsimd: bool) -> HalfKind {
    kind_from_word(insn, advsimd, a32_word(insn))
}

fn kind_from_word(insn: &DecodedInsn, advsimd: bool, raw: u32) -> HalfKind {
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

const ID_ISAR6_FHM: u32 = 15 << 8;

/// FEAT_FCMA includes FP32 Advanced SIMD. FP16 remains independently optional.
pub(crate) fn effective_id_isar5_vcma(id_isar5: u32, mvfr0: u32, mvfr1: u32) -> u32 {
    let has_vcma = id_isar5 & ID_ISAR5_VCMA == 1 << 28;
    let has_d32 = mvfr0 & 15 == 2;
    let has_simd_integer = (mvfr1 >> 12) & 15 == 1;
    let has_simd_single = (mvfr1 >> 16) & 15 == 1;
    if has_vcma && has_d32 && has_simd_integer && has_simd_single {
        id_isar5
    } else {
        id_isar5 & !ID_ISAR5_VCMA
    }
}

/// Project the DotProd and FHM fields through the active AArch32 SIMD profile.
pub(crate) fn effective_id_isar6(mut id_isar6: u32, mvfr0: u32, mvfr1: u32) -> u32 {
    let has_simd_integer = mvfr0 & 15 == 2 && (mvfr1 >> 12) & 15 == 1;
    let has_simd_single = (mvfr1 >> 16) & 15 == 1;
    let has_simd_half = (mvfr1 >> 20) & 15 == 2;
    if !has_simd_integer || id_isar6 & ID_ISAR6_DP != 1 << 4 {
        id_isar6 &= !ID_ISAR6_DP;
    }
    if !(has_simd_integer && has_simd_single && has_simd_half) || id_isar6 & ID_ISAR6_FHM != 1 << 8
    {
        id_isar6 &= !ID_ISAR6_FHM;
    }
    id_isar6
}

pub(crate) fn half_supported(
    insn: &DecodedInsn,
    advsimd: bool,
    state: &VfpState,
    id_isar6: u32,
) -> bool {
    if matches!(insn.mnemonic, Mnemonic::VFMAL | Mnemonic::VFMLS) {
        return advsimd
            && effective_id_isar6(id_isar6, state.mvfr0, state.mvfr1) & ID_ISAR6_FHM != 0;
    }
    let scalar = (state.mvfr1 >> 24) & 15;
    let simd = (state.mvfr1 >> 20) & 15;
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

/// FPRound's output flushing bypasses trapped underflow. FPConvert's half
/// output ignores FZ16; ordinary half data processing uses FZ16.
pub(crate) fn output_flushes(insn: &DecodedInsn, state: &VfpState) -> bool {
    let raw = a32_word(insn);
    let half = match kind_from_word(insn, false, raw) {
        HalfKind::ScalarConversion { .. } => return false,
        HalfKind::ScalarData => true,
        _ => Aarch32Decoder::scalar_fixed_fields(raw).is_some_and(|fields| fields.fp_bits == 16),
    };
    state.fpscr.bits() & (1 << if half { 19 } else { 24 }) != 0
}

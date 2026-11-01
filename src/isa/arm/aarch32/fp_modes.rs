//! Restricted scalar VFP operating modes and synchronous support-code entry.
//!
//! Arm DDI0406C.d A2.7 and B1.11.4 permit an implementation-defined
//! hardware/support-code split. This PE selects a synchronous Undefined bounce
//! for an unsupported scalar mode, after access checks and before data effects.
//! MVFR capability values do not change the FPSCR register's write semantics.
//! Restricted profiles identify their support-code interface through VMRS FPSID.
use super::{HalfKind, VfpState, kind};
use crate::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rounding {
    None,
    Fpscr,
    Nearest,
    ConvertZero,
    Other,
}

struct Requirements {
    rounding: Rounding,
    nan: bool,
    flush: Option<u32>,
}

fn full_controls(state: &VfpState) -> bool {
    state.mvfr0 >> 28 == 1 && state.mvfr1 & 0xff == 0x11
}

fn requirements(insn: &DecodedInsn, state: &VfpState) -> Option<Requirements> {
    // Invalid raw encodings and caller-supplied mnemonics which disagree with
    // decoding retain their existing decode/operand outcome.
    let decoded = if insn.state.is_thumb() {
        ThumbDecoder::decode_32bit(insn.raw)
    } else {
        Aarch32Decoder::decode(insn.raw)
    };
    if !decoded.is_ok_and(|decoded| decoded.mnemonic == insn.mnemonic) {
        return None;
    }
    let raw = if insn.state.is_thumb() {
        ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
    } else {
        insn.raw
    };
    if let Some(fields) = Aarch32Decoder::scalar_fixed_fields(raw)
        && fields.mnemonic == insn.mnemonic
        && fields.mnemonic != Mnemonic::UNDEFINED
    {
        return Some(Requirements {
            rounding: if fields.to_fixed {
                Rounding::ConvertZero
            } else {
                Rounding::Nearest
            },
            nan: false,
            flush: Some(1 << if fields.fp_bits == 16 { 19 } else { 24 }),
        });
    }
    if matches!(kind(insn, false), HalfKind::ScalarConversion { .. }) {
        let from_half = matches!(
            insn.mnemonic,
            Mnemonic::VCVTB_F32_F16
                | Mnemonic::VCVTT_F32_F16
                | Mnemonic::VCVTB_F64_F16
                | Mnemonic::VCVTT_F64_F16
        );
        // FPConvert ignores FZ16 and observes AHP. An alternative half has
        // no NaN encoding; conversion to it also cannot propagate a NaN.
        return Some(Requirements {
            rounding: Rounding::Fpscr,
            nan: state.fpscr.bits() & (1 << 26) == 0,
            flush: if from_half { None } else { Some(1 << 24) },
        });
    }
    let flush = Some(
        1 << if matches!(kind(insn, false), HalfKind::ScalarData) {
            19
        } else {
            24
        },
    );
    let (rounding, nan) = match insn.mnemonic {
        Mnemonic::VADD
        | Mnemonic::VSUB
        | Mnemonic::VMUL
        | Mnemonic::VDIV
        | Mnemonic::VNMUL
        | Mnemonic::VMLA
        | Mnemonic::VMLS
        | Mnemonic::VNMLA
        | Mnemonic::VNMLS
        | Mnemonic::VFMA
        | Mnemonic::VFMS
        | Mnemonic::VFNMA
        | Mnemonic::VFNMS
        | Mnemonic::VSQRT
        | Mnemonic::VCVT_F32_F64
        | Mnemonic::VCVT_F64_F32 => (Rounding::Fpscr, true),
        Mnemonic::VCMP | Mnemonic::VCMPE => (Rounding::None, false),
        Mnemonic::VMAXNM_F16
        | Mnemonic::VMAXNM_F32
        | Mnemonic::VMAXNM_F64
        | Mnemonic::VMINNM_F16
        | Mnemonic::VMINNM_F32
        | Mnemonic::VMINNM_F64 => (Rounding::None, true),
        Mnemonic::VRINTR_F16
        | Mnemonic::VRINTR_F32
        | Mnemonic::VRINTR_F64
        | Mnemonic::VRINTX_F16
        | Mnemonic::VRINTX_F32
        | Mnemonic::VRINTX_F64 => (Rounding::Fpscr, true),
        Mnemonic::VRINTN_F16 | Mnemonic::VRINTN_F32 | Mnemonic::VRINTN_F64 => {
            (Rounding::Nearest, true)
        }
        Mnemonic::VRINTA_F16
        | Mnemonic::VRINTA_F32
        | Mnemonic::VRINTA_F64
        | Mnemonic::VRINTP_F16
        | Mnemonic::VRINTP_F32
        | Mnemonic::VRINTP_F64
        | Mnemonic::VRINTM_F16
        | Mnemonic::VRINTM_F32
        | Mnemonic::VRINTM_F64
        | Mnemonic::VRINTZ_F16
        | Mnemonic::VRINTZ_F32
        | Mnemonic::VRINTZ_F64 => (Rounding::Other, true),
        Mnemonic::VCVT_F16_S32
        | Mnemonic::VCVT_F16_U32
        | Mnemonic::VCVT_F32_S32
        | Mnemonic::VCVT_F32_U32
        | Mnemonic::VCVT_F64_S32
        | Mnemonic::VCVT_F64_U32
        | Mnemonic::VCVTR_S32_F16
        | Mnemonic::VCVTR_U32_F16
        | Mnemonic::VCVTR_S32_F32
        | Mnemonic::VCVTR_U32_F32
        | Mnemonic::VCVTR_S32_F64
        | Mnemonic::VCVTR_U32_F64 => (Rounding::Fpscr, false),
        // MVFR0 explicitly retains the VCVT instructions which always round
        // toward zero, independently of the live FPSCR.RMode value.
        Mnemonic::VCVT_S32_F16
        | Mnemonic::VCVT_U32_F16
        | Mnemonic::VCVT_S32_F32
        | Mnemonic::VCVT_U32_F32
        | Mnemonic::VCVT_S32_F64
        | Mnemonic::VCVT_U32_F64 => (Rounding::ConvertZero, false),
        Mnemonic::VCVTN_S32_F16
        | Mnemonic::VCVTN_U32_F16
        | Mnemonic::VCVTN_S32_F32
        | Mnemonic::VCVTN_U32_F32
        | Mnemonic::VCVTN_S32_F64
        | Mnemonic::VCVTN_U32_F64 => (Rounding::Nearest, false),
        Mnemonic::VCVTA_S32_F16
        | Mnemonic::VCVTA_U32_F16
        | Mnemonic::VCVTA_S32_F32
        | Mnemonic::VCVTA_U32_F32
        | Mnemonic::VCVTA_S32_F64
        | Mnemonic::VCVTA_U32_F64
        | Mnemonic::VCVTP_S32_F16
        | Mnemonic::VCVTP_U32_F16
        | Mnemonic::VCVTP_S32_F32
        | Mnemonic::VCVTP_U32_F32
        | Mnemonic::VCVTP_S32_F64
        | Mnemonic::VCVTP_U32_F64
        | Mnemonic::VCVTM_S32_F16
        | Mnemonic::VCVTM_U32_F16
        | Mnemonic::VCVTM_S32_F32
        | Mnemonic::VCVTM_U32_F32
        | Mnemonic::VCVTM_S32_F64
        | Mnemonic::VCVTM_U32_F64 => (Rounding::Other, false),
        // Bit/storage transfers, selection and absolute/negate do not use
        // scalar arithmetic controls. Integer Advanced SIMD has its own IDs.
        _ => return None,
    };
    Some(Requirements {
        rounding,
        nan,
        flush,
    })
}

/// Reject reserved capability values only for instructions which use them.
/// Bounded instruction decoding and field checks take O(1) work/storage.
pub(super) fn instruction_supported(insn: &DecodedInsn, advsimd: bool, state: &VfpState) -> bool {
    // These are scalar VFP capabilities. Advanced SIMD has independent IDs
    // and StandardFPSCRValue rather than the live scalar arithmetic modes.
    if advsimd || full_controls(state) {
        return true;
    }
    let Some(required) = requirements(insn, state) else {
        return true;
    };
    (required.rounding == Rounding::None || state.mvfr0 >> 28 <= 1)
        && (!required.nan || (state.mvfr1 >> 4) & 15 <= 1)
        && (required.flush.is_none() || state.mvfr1 & 15 <= 1)
}

/// A supported encoding and permitted access may still need support code.
pub(crate) fn execution_supported(insn: &DecodedInsn, advsimd: bool, state: &VfpState) -> bool {
    if advsimd || full_controls(state) {
        return true;
    }
    let Some(required) = requirements(insn, state) else {
        return true;
    };
    let round = state.mvfr0 >> 28;
    let control = state.fpscr.bits();
    let rounding = match required.rounding {
        Rounding::None => true,
        Rounding::Nearest | Rounding::ConvertZero => round <= 1,
        Rounding::Fpscr => round == 1 || round == 0 && control & (3 << 22) == 0,
        Rounding::Other => round == 1,
    };
    let nan = (state.mvfr1 >> 4) & 15;
    let nan = !required.nan || nan == 1 || nan == 0 && control & (1 << 25) != 0;
    let flush = state.mvfr1 & 15;
    let flush = required
        .flush
        .is_none_or(|mask| flush == 1 || flush == 0 && control & mask != 0);
    rounding && nan && flush
}

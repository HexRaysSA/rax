//! MVFR1.SIMDSP admission for operations that consume or produce FP32.
//!
//! Arm DDI0487B.a G6.2.108 defines only value 1 as implemented. Integer
//! operations, raw register/immediate storage and pure FP16 data processing
//! retain their separate capabilities. FHM accumulates into FP32.
use super::{HalfKind, VfpState, decoded_as, kind};
use crate::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};

pub(super) fn instruction_supported(insn: &DecodedInsn, state: &VfpState) -> bool {
    (state.mvfr1 >> 16) & 15 == 1 || !requires_single(insn)
}

fn requires_single(insn: &DecodedInsn) -> bool {
    match kind(insn, true) {
        HalfKind::SimdData => return false,
        HalfKind::SimdConversion => return true,
        _ => (),
    }
    if matches!(insn.mnemonic, Mnemonic::VFMAL | Mnemonic::VFMLS) {
        return true;
    }
    let raw = if insn.state.is_thumb() && insn.size == 4 {
        ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
    } else {
        insn.raw
    };
    // Match the allocated encoding class as well as its mnemonic: integer
    // VADD/VMUL/VMAX/comparison forms share names with floating-point forms.
    let floating = [
        Aarch32Decoder::decode_neon_fp_add_sub(raw),
        Aarch32Decoder::decode_neon_fp_absdiff(raw),
        Aarch32Decoder::decode_neon_fp_fma(raw),
        Aarch32Decoder::decode_neon_fp_multiply(raw),
        Aarch32Decoder::decode_neon_fp_multiply_scalar(raw),
        Aarch32Decoder::decode_neon_fp_minmax(raw),
        Aarch32Decoder::decode_neon_fp_number_minmax(raw),
        Aarch32Decoder::decode_neon_fp_pairwise(raw),
        Aarch32Decoder::decode_neon_fp_compare(raw),
        Aarch32Decoder::decode_neon_recip_step(raw),
        Aarch32Decoder::decode_neon_vrint(raw),
        Aarch32Decoder::decode_neon_directed_convert(raw),
        Aarch32Decoder::decode_neon_fp_convert(raw),
        Aarch32Decoder::decode_neon_fp_fixed_convert(raw),
    ]
    .into_iter()
    .any(|decoded| decoded_as(decoded, insn.mnemonic));
    if floating {
        return true;
    }
    // Miscellaneous encodings also select integer or floating-point operands
    // without changing the mnemonic. Half forms were separated above.
    decoded_as(Aarch32Decoder::decode_neon_abs_neg(raw), insn.mnemonic) && raw & (1 << 10) != 0
        || decoded_as(Aarch32Decoder::decode_neon_compare_zero(raw), insn.mnemonic)
            && (raw >> 10) & 3 == 1
        || decoded_as(
            Aarch32Decoder::decode_neon_recip_estimate(raw),
            insn.mnemonic,
        ) && raw & (1 << 8) != 0
}

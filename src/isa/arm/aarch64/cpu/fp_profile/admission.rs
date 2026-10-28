//! Decode-time reserved fields for the represented half/FP conversion classes.
//! Sources: pinned Arm ASL scalar conversion, rounding, compare and reduction
//! decodes. FEAT_FPRCVT is not implemented by this profile.

fn matches(word: u32, mask: u32, value: u32) -> bool {
    word & mask == value
}

fn scalar_conversion_reserved(word: u32) -> bool {
    let sf = word >> 31;
    let dtype = (word >> 22) & 3;
    let rmode = (word >> 19) & 3;
    let opcode = (word >> 16) & 7;
    let group = opcode >> 1;
    if matches(word, 0x7f20_0000, 0x1e00_0000) {
        // Scalar floating-point/fixed-point conversions. W forms require
        // scale[5]=1; only FCVTZ and [US]CVTF use this encoding class.
        return dtype == 2
            || (sf == 0 && word & (1 << 15) == 0)
            || !matches!((group, rmode), (0, 3) | (1, 0));
    }
    if !matches(word, 0x7f20_fc00, 0x1e20_0000) {
        return false;
    }
    // Scalar floating-point/integer conversions and bitwise FMOV. The
    // 128-bit FMOV D[1] transport is independent of optional FP16 arithmetic.
    let legal = match (group, rmode) {
        (0, _) | (1 | 2, 0) => dtype != 2,
        (3, 0) => dtype == 3 || dtype == sf,
        (3, 1) => dtype == 2 && sf == 1,
        // FJCVTZS has a fixed double-to-W encoding, not a half variant.
        (3, 3) => dtype == 1 && sf == 0 && opcode == 6,
        _ => false,
    };
    !legal
}

fn half_encoding_space(word: u32) -> bool {
    let group = (word >> 24) & 31;
    let scalar = word & (1 << 30) == 0;
    if scalar && matches!(group, 0x1e | 0x1f) && (word >> 22) & 3 == 3 {
        return true;
    }
    // Bit 31 distinguishes these spaces from overlapping crypto encodings.
    if word >> 31 != 0 {
        return false;
    }
    let simd = group == 0x0e || (group == 0x1e && !scalar);
    if simd {
        let three_same = word & (1 << 22) != 0
            && word & (1 << 21) == 0
            && (word >> 14) & 3 == 0
            && word & (1 << 10) != 0;
        let two_misc = (word >> 19) & 7 == 7 && (word >> 10) & 3 == 2;
        let reduction = word & (1 << 29) == 0
            && (word >> 17) & 31 == 24
            && (word >> 10) & 3 == 2
            && matches!((word >> 12) & 31, 12 | 13 | 15);
        if three_same || two_misc || reduction {
            return true;
        }
    }
    let indexed = group == 0x0f || (group == 0x1f && !scalar);
    indexed
        && (word >> 22) & 3 == 0
        && word & (1 << 10) == 0
        && matches!((word >> 12) & 15, 1 | 5 | 9)
}

fn reduction_reserved(word: u32) -> bool {
    if word >> 31 != 0 || (word >> 17) & 31 != 24 || (word >> 10) & 3 != 2 {
        return false;
    }
    let group = (word >> 24) & 31;
    let opcode = (word >> 12) & 31;
    if !matches!(opcode, 12 | 13 | 15) {
        return false;
    }
    let full_precision = word & (1 << 29) != 0;
    let sz = word & (1 << 22) != 0;
    let q = word & (1 << 30) != 0;
    if group == 0x0e {
        // Across-lane FMAX[NUM]/FMIN[NUM]: half vectors accept Q=0/1;
        // full-precision vectors accept .4S only. No across-lane FADD form.
        return opcode == 13 || sz || (full_precision && !q);
    }
    if group == 0x1e && q {
        // Scalar pairwise half forms require sz=0. FADDP fixes the
        // maximum/minimum selector bit to zero for every precision.
        return (!full_precision && sz) || (opcode == 13 && word & (1 << 23) != 0);
    }
    false
}

pub(super) fn reserved(word: u32) -> bool {
    if !matches!((word >> 25) & 15, 7 | 15) {
        return false;
    }
    if scalar_conversion_reserved(word) || reduction_reserved(word) {
        return true;
    }
    let optional_half = super::fp16::required(word);
    if !optional_half {
        let legacy_precision = matches!(word & 0xffff_fc00, 0x1ee2_4000 | 0x1ee2_c000);
        return half_encoding_space(word) && !legacy_precision;
    }
    if matches(word, 0xfffc_7c00, 0x1ee4_4000) {
        return (word >> 15) & 7 == 5;
    }
    if matches(word, 0x9f7f_ec00, 0x0e79_8800) {
        let rmode = (((word >> 29) & 1) << 2) | (((word >> 12) & 1) << 1) | ((word >> 23) & 1);
        return rmode == 5;
    }
    if matches(word, 0xdf60_f400, 0x5e40_2400) || matches(word, 0x9f60_f400, 0x0e40_2400) {
        let kind = (((word >> 23) & 1) << 2) | (((word >> 29) & 1) << 1) | ((word >> 11) & 1);
        return !matches!(kind, 0 | 2 | 3 | 6 | 7);
    }
    // Half-precision complex by-element: a 64-bit vector has no upper pair.
    matches(word, 0xbfc0_9400, 0x2f40_1000) && word & (1 << 11) != 0 && word & (1 << 30) == 0
}

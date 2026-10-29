//! Structural A64 FP/SIMD allocation at CPU and native admission boundaries.
//! The pinned older ASL is supplemented by qualified BF16/I8MM diagrams and
//! the scalar conversion restrictions from the current Arm instruction reference.

include!("allocation_encodings.rs");

fn matches(word: u32, mask: u32, value: u32) -> bool {
    word & mask == value
}

/// DDI0602 ID032025, FMLALB/FMLALT by element, printed page1412.
/// Keep the existing RAX V9_4A selection policy separate from structural bits.
pub(super) fn indexed_fp8_fma(word: u32) -> bool {
    word & 0xbfc0_f400 == 0x0fc0_0000
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

/// Check structural allocation in the represented profile domains. CPU
/// admission still checks feature and version policy before execution-time access.
pub(super) fn allocated(word: u32) -> bool {
    if !matches!((word >> 25) & 15, 7 | 15) {
        return true;
    }
    if indexed_fp8_fma(word) {
        return true;
    }
    if scalar_conversion_reserved(word) {
        return false;
    }
    let bucket = (((word >> 24) as usize) << 4) | (((word >> 12) & 15) as usize);
    let start = usize::from(ALLOCATION_OFFSETS[bucket]);
    let end = usize::from(ALLOCATION_OFFSETS[bucket + 1]);
    ALLOCATION_ENCODINGS[start..end]
        .iter()
        .any(|&(mask, value)| word & mask == value)
}

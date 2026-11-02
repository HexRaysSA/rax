//! math::sve tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

/// Signed rounding shift right (SRSHR), 64-bit. Port of qemu do_srshr; the
/// element is sign-extended to 64 bits before the rounding add.
#[inline]
pub(crate) fn sve_srshr(x: i64, sh: u32) -> i64 {
    if sh < 64 {
        (x >> sh) + ((x >> (sh - 1)) & 1)
    } else {
        // Rounding the sign bit always produces 0.
        0
    }
}
/// Unsigned rounding shift right (URSHR), 64-bit. Port of qemu do_urshr.
#[inline]
pub(crate) fn sve_urshr(x: u64, sh: u32) -> u64 {
    if sh < 64 {
        (x >> sh) + ((x >> (sh - 1)) & 1)
    } else if sh == 64 {
        x >> 63
    } else {
        0
    }
}
// ---- SVE predicate helpers ----

/// Number of leading active elements selected by an SVE predicate `pattern`
/// (POW2/VL1..VL256/MUL3/MUL4/ALL) given the element count. Unallocated
/// patterns select zero elements.
pub(crate) fn sve_pattern_count(pattern: u32, elements: usize) -> usize {
    match pattern {
        0b00000 => {
            // POW2: largest power of two <= elements.
            let mut p = 1;
            while p * 2 <= elements {
                p *= 2;
            }
            p
        }
        0b00001..=0b00111 => {
            let c = pattern as usize; // VL1..VL7
            if c <= elements { c } else { 0 }
        }
        0b01000 => (8 <= elements).then_some(8).unwrap_or(0),
        0b01001 => (16 <= elements).then_some(16).unwrap_or(0),
        0b01010 => (32 <= elements).then_some(32).unwrap_or(0),
        0b01011 => (64 <= elements).then_some(64).unwrap_or(0),
        0b01100 => (128 <= elements).then_some(128).unwrap_or(0),
        0b01101 => (256 <= elements).then_some(256).unwrap_or(0),
        0b11101 => (elements / 4) * 4, // MUL4
        0b11110 => (elements / 3) * 3, // MUL3
        0b11111 => elements,           // ALL
        _ => 0,
    }
}
/// Decode the 4-bit SVE contiguous-load `dtype` field into the destination
/// element size, the memory access size (both in bytes) and whether the loaded
/// value is sign-extended. msize <= esize always; signed loads sign-extend.
pub(crate) fn sve_ld1_dtype(dtype: u32) -> (usize, usize, bool) {
    match dtype {
        0b0000 => (1, 1, false), // LD1B  -> 8
        0b0001 => (2, 1, false), // LD1B  -> 16
        0b0010 => (4, 1, false), // LD1B  -> 32
        0b0011 => (8, 1, false), // LD1B  -> 64
        0b0100 => (8, 4, true),  // LD1SW -> 64
        0b0101 => (2, 2, false), // LD1H  -> 16
        0b0110 => (4, 2, false), // LD1H  -> 32
        0b0111 => (8, 2, false), // LD1H  -> 64
        0b1000 => (8, 2, true),  // LD1SH -> 64
        0b1001 => (4, 2, true),  // LD1SH -> 32
        0b1010 => (4, 4, false), // LD1W  -> 32
        0b1011 => (8, 4, false), // LD1W  -> 64
        0b1100 => (8, 1, true),  // LD1SB -> 64
        0b1101 => (4, 1, true),  // LD1SB -> 32
        0b1110 => (2, 1, true),  // LD1SB -> 16
        _ => (8, 8, false),      // 1111: LD1D -> 64
    }
}
/// Combine two FP element bit-values with an `FpKind` op at the given esize,
/// reusing the verified binary16/32/64 helpers (for SVE FP reductions/FADDA).
pub(crate) fn sve_fp_combine(kind: FpKind, esize: usize, x: u64, y: u64) -> u64 {
    sve_fp_combine_with_fpcr(kind, esize, x, y, 0)
}
pub(crate) fn sve_fp_combine_with_fpcr(
    kind: FpKind,
    esize: usize,
    x: u64,
    y: u64,
    fpcr: u32,
) -> u64 {
    match esize {
        2 => sve_fp16_binop_with_fpcr(kind, x as u16, y as u16, fpcr) as u64,
        4 => fp_three_same_f32_with_fpcr(kind, x as u32, y as u32, 0, fpcr) as u64,
        _ => fp_three_same_f64_with_fpcr(kind, x, y, 0, fpcr),
    }
}
pub(crate) fn sve_fp_pairwise_reduce_combine_with_fpcr(
    kind: FpKind,
    esize: usize,
    x: u64,
    y: u64,
    fpcr: u32,
) -> u64 {
    if fpcr & FPCR_AH != 0
        && matches!(
            kind,
            FpKind::Max | FpKind::Maxp | FpKind::Min | FpKind::Minp
        )
        && (fp_is_nan_bits(esize, x) || fp_is_nan_bits(esize, y))
    {
        return y;
    }
    if fpcr & FPCR_AH != 0
        && matches!(
            kind,
            FpKind::Max | FpKind::Maxp | FpKind::Min | FpKind::Minp
        )
        && fp_value_eq_bits(esize, x, y)
    {
        return y;
    }
    if fpcr & FPCR_AH != 0
        && matches!(
            kind,
            FpKind::MaxNm | FpKind::MaxNmp | FpKind::MinNm | FpKind::MinNmp
        )
    {
        if let Some(r) = fp_ah_maxnm_pairwise_nan(esize, x, y) {
            return r;
        }
    }
    sve_fp_combine_with_fpcr(kind, esize, x, y, fpcr)
}
/// Recursive split-in-half binary-tree reduction (the SVE "fast" reduction
/// order): combine(reduce(low half), reduce(high half)). The low-index half is
/// ALWAYS the first operand — this exact order is required for FP bit-exactness
/// (FPAdd is non-associative; FPMax/FPMin sign-of-zero depends on position).
pub(crate) fn sve_fp_tree_reduce(buf: &[u64], kind: FpKind, esize: usize) -> u64 {
    if buf.len() == 1 {
        return buf[0];
    }
    let h = buf.len() / 2;
    let lo = sve_fp_tree_reduce(&buf[..h], kind, esize);
    let hi = sve_fp_tree_reduce(&buf[h..], kind, esize);
    sve_fp_combine(kind, esize, lo, hi)
}
pub(crate) fn sve_fp_tree_reduce_status(
    buf: &[u64],
    kind: FpKind,
    esize: usize,
    fpcr: u32,
) -> (u64, u32) {
    if buf.len() == 1 {
        return (buf[0], 0);
    }
    let h = buf.len() / 2;
    let (lo, sl) = sve_fp_tree_reduce_status(&buf[..h], kind, esize, fpcr);
    let (hi, sh) = sve_fp_tree_reduce_status(&buf[h..], kind, esize, fpcr);
    let pairwise_ah_maxmin = fpcr & FPCR_AH != 0
        && matches!(
            kind,
            FpKind::Max | FpKind::Maxp | FpKind::Min | FpKind::Minp
        );
    let r = if buf.len() == 2 || pairwise_ah_maxmin {
        sve_fp_pairwise_reduce_combine_with_fpcr(kind, esize, lo, hi, fpcr)
    } else {
        sve_fp_combine_with_fpcr(kind, esize, lo, hi, fpcr)
    };
    (
        r,
        sl | sh | fp_pairwise_reduce_status_with_fpcr(esize, kind, lo, hi, r, fpcr),
    )
}
/// Identity element used to pad inactive lanes in an SVE FP reduction.
pub(crate) fn sve_fp_identity(kind: FpKind, esize: usize) -> u64 {
    use FpKind::*;
    match kind {
        Add => 0, // +0.0
        // The max identity must never win the max -> -Inf; the min identity -> +Inf.
        Max => match esize {
            2 => 0xFC00,
            4 => 0xFF80_0000,
            _ => 0xFFF0_0000_0000_0000,
        }, // -Inf
        Min => match esize {
            2 => 0x7C00,
            4 => 0x7F80_0000,
            _ => 0x7FF0_0000_0000_0000,
        }, // +Inf
        _ => match esize {
            2 => 0x7E00,
            4 => 0x7FC0_0000,
            _ => 0x7FF8_0000_0000_0000,
        }, // default NaN (FMAXNM/FMINNM)
    }
}
/// FRECPX (reciprocal exponent) over an f32/f64 element bit-value.
pub(crate) fn sve_fp_recpx(esize: usize, lane: u64) -> u64 {
    match esize {
        2 => fp16_recpx(lane as u16) as u64,
        4 => {
            let x = lane as u32;
            if (x & 0x7F80_0000) == 0x7F80_0000 && (x & 0x7F_FFFF) != 0 {
                return (x | 0x40_0000) as u64; // NaN -> quiet
            }
            let sign = x & 0x8000_0000;
            let exp = (x >> 23) & 0xFF;
            (if exp == 0 {
                sign | (0xFE << 23)
            } else {
                sign | ((!exp & 0xFF) << 23)
            }) as u64
        }
        _ => {
            let x = lane;
            if (x & 0x7FF0_0000_0000_0000) == 0x7FF0_0000_0000_0000 && (x & 0xF_FFFF_FFFF_FFFF) != 0
            {
                return x | 0x8_0000_0000_0000; // NaN -> quiet
            }
            let sign = x & 0x8000_0000_0000_0000;
            let exp = (x >> 52) & 0x7FF;
            if exp == 0 {
                sign | (0x7FE << 52)
            } else {
                sign | ((!exp & 0x7FF) << 52)
            }
        }
    }
}
/// SVE2 FLOGB: floor(log2(|x|)) of an `esize`-byte IEEE float as a signed
/// integer of the same width. Finite non-zero values yield their unbiased
/// base-2 exponent (normal: biased_exp - bias; subnormal: normalized away
/// from the implicit-bit boundary). Infinity yields the most-positive integer
/// `2^(N-1)-1` (log2|inf| = +inf); zero and NaN yield the most-negative
/// integer `-(2^(N-1))`. The special-case results are verified vs qemu.
pub(crate) fn sve_flogb(esize: usize, bits: u64) -> i64 {
    let (expbits, fracbits): (u32, u32) = match esize {
        2 => (5, 10),
        4 => (8, 23),
        _ => (11, 52),
    };
    let bias = (1i64 << (expbits - 1)) - 1;
    let exp_mask = (1u64 << expbits) - 1;
    let exp = (bits >> fracbits) & exp_mask;
    let mant = bits & ((1u64 << fracbits) - 1);
    let int_bits = (esize as u32) * 8;
    // For 64-bit elements the saturation bounds are i64::MIN / i64::MAX;
    // computing them as `-(1 << 63)` / `(1 << 63) - 1` would overflow i64 and
    // panic in checked builds, so derive them without overflowing.
    let (most_neg, most_pos) = if int_bits >= 64 {
        (i64::MIN, i64::MAX)
    } else {
        (-(1i64 << (int_bits - 1)), (1i64 << (int_bits - 1)) - 1)
    };
    if exp == exp_mask {
        // mant==0 is +/-infinity (most-positive); otherwise NaN (most-negative).
        return if mant == 0 { most_pos } else { most_neg };
    }
    if exp == 0 {
        if mant == 0 {
            return most_neg; // zero: invalid
        }
        // Subnormal: value = mant * 2^(Emin - fracbits), Emin = 1 - bias. The
        // unbiased exponent is Emin shifted down by the leading-zero count of
        // the fraction (relative to the implicit-bit position).
        let emin = 1 - bias;
        let msb = 63 - mant.leading_zeros() as i64; // floor(log2(mant))
        return emin - fracbits as i64 + msb;
    }
    exp as i64 - bias // normal: 1 <= significand < 2, so floor(log2) == exponent
}
/// One f32 lane of SVE BFDOT (FPCR.EBF==0, the qemu-user default): a 2-way bf16
/// dot product accumulated into the f32 lane. Delegates to the canonical
/// bfdotadd_ebf0 (round-to-odd-INF / flush-to-zero / default-NaN).
pub(crate) fn sve_bfdot_lane(acc_bits: u32, n: u32, m: u32) -> u32 {
    bfdotadd_ebf0(acc_bits, n, m)
}
/// SVE FEXPA (exponential accelerator): build a float from a table significand
/// indexed by the low bits of Zn and an exponent from the next bits.
pub(crate) fn sve_fexpa(esize: usize, nn: u64) -> u64 {
    match esize {
        2 => FEXPA_H[(nn & 0x1F) as usize] as u64 | (((nn >> 5) & 0x1F) << 10),
        4 => FEXPA_S[(nn & 0x3F) as usize] as u64 | (((nn >> 6) & 0xFF) << 23),
        _ => FEXPA_D[(nn & 0x3F) as usize] | (((nn >> 6) & 0x7FF) << 52),
    }
}
/// SVE FSCALE: multiply `x` by 2^(signed Zm element).
pub(crate) fn sve_fscale(esize: usize, x: u64, n: i64, fpcr: u32) -> u64 {
    match esize {
        2 => fp16_fscale_with_fpcr(x as u16, n, fpcr) as u64,
        4 => {
            if let Some(n) = fp32_nan2(x as u32, x as u32) {
                return n as u64;
            }
            fp32_fscale_with_fpcr(x as u32, n, fpcr) as u64
        }
        _ => {
            if let Some(n) = fp64_nan2(x, x) {
                return n;
            }
            fp64_fscale_with_fpcr(x, n, fpcr)
        }
    }
}
/// Widen an `esize`-byte IEEE float to f64 (exact) for SVE compares.
pub(crate) fn sve_fp_to_f64(esize: usize, x: u64) -> f64 {
    match esize {
        2 => fp16_to_f64(x as u16),
        4 => f32::from_bits(x as u32) as f64,
        _ => f64::from_bits(x),
    }
}
/// SVE FP compare (register) condition, keyed on (bits[15:13], bit4). Rust's
/// native comparisons already give the IEEE unordered (NaN) behaviour.
pub(crate) fn sve_fp_compare(esize: usize, cc: (u32, u32), a: u64, b: u64) -> bool {
    let (av, bv) = (sve_fp_to_f64(esize, a), sve_fp_to_f64(esize, b));
    match cc {
        (0b010, 0) => av >= bv,                   // FCMGE
        (0b010, 1) => av > bv,                    // FCMGT
        (0b011, 0) => av == bv,                   // FCMEQ
        (0b011, 1) => av != bv,                   // FCMNE
        (0b110, 0) => av.is_nan() || bv.is_nan(), // FCMUO
        (0b110, 1) => av.abs() >= bv.abs(),       // FACGE
        (0b111, 1) => av.abs() > bv.abs(),        // FACGT
        _ => false,
    }
}
/// SVE FP compare with zero, keyed on (bits[17:16], bit4).
pub(crate) fn sve_fp_compare_zero(esize: usize, sub: u32, bit4: u32, a: u64) -> bool {
    let av = sve_fp_to_f64(esize, a);
    match (sub, bit4) {
        (0b00, 0) => av >= 0.0, // FCMGE
        (0b00, 1) => av > 0.0,  // FCMGT
        (0b01, 0) => av < 0.0,  // FCMLT
        (0b01, 1) => av <= 0.0, // FCMLE
        (0b10, 0) => av == 0.0, // FCMEQ
        _ => av != 0.0,         // FCMNE
    }
}
/// SVE FRECPS reciprocal step: fused (2.0 - x*y), with inf*0 -> 2.0. Matches
/// qemu recpsf (FPCR.AH=0, FZ=0).
pub(crate) fn sve_recps(esize: usize, x: u64, y: u64) -> u64 {
    match esize {
        2 => fp16_recps(x as u16, y as u16) as u64,
        4 => {
            // FPRecipStepFused negates op1 first, so the propagated NaN sign
            // flips relative to the original op1.
            if let Some(n) = fp32_nan2((x as u32) ^ 0x8000_0000, y as u32) {
                return n as u64;
            }
            let (a, b) = (f32::from_bits(x as u32), f32::from_bits(y as u32));
            let r = if (a.is_infinite() && b == 0.0) || (b.is_infinite() && a == 0.0) {
                2.0
            } else {
                (-a).mul_add(b, 2.0)
            };
            (if r.is_nan() { 0x7FC0_0000 } else { r.to_bits() }) as u64
        }
        _ => {
            if let Some(n) = fp64_nan2(x ^ 0x8000_0000_0000_0000, y) {
                return n;
            }
            let (a, b) = (f64::from_bits(x), f64::from_bits(y));
            let r = if (a.is_infinite() && b == 0.0) || (b.is_infinite() && a == 0.0) {
                2.0
            } else {
                (-a).mul_add(b, 2.0)
            };
            if r.is_nan() {
                0x7FF8_0000_0000_0000
            } else {
                r.to_bits()
            }
        }
    }
}
/// SVE FRSQRTS reciprocal-sqrt step: fused (3.0 - x*y)/2, with inf*0 -> 1.5.
pub(crate) fn sve_rsqrts(esize: usize, x: u64, y: u64) -> u64 {
    match esize {
        2 => fp16_rsqrts(x as u16, y as u16) as u64,
        4 => {
            if let Some(n) = fp32_nan2((x as u32) ^ 0x8000_0000, y as u32) {
                return n as u64;
            }
            let (a, b) = (f32::from_bits(x as u32), f32::from_bits(y as u32));
            let r = if (a.is_infinite() && b == 0.0) || (b.is_infinite() && a == 0.0) {
                1.5
            } else {
                (-a).mul_add(b, 3.0) * 0.5
            };
            (if r.is_nan() { 0x7FC0_0000 } else { r.to_bits() }) as u64
        }
        _ => {
            if let Some(n) = fp64_nan2(x ^ 0x8000_0000_0000_0000, y) {
                return n;
            }
            let (a, b) = (f64::from_bits(x), f64::from_bits(y));
            let r = if (a.is_infinite() && b == 0.0) || (b.is_infinite() && a == 0.0) {
                1.5
            } else {
                (-a).mul_add(b, 3.0) * 0.5
            };
            if r.is_nan() {
                0x7FF8_0000_0000_0000
            } else {
                r.to_bits()
            }
        }
    }
}
/// SVE FTSMUL: square `x` and set the result sign to `sgn` (bit0 of Zm),
/// unless the squared value is NaN (then the sign is left as produced).
pub(crate) fn sve_ftsmul(esize: usize, x: u64, sgn: u64, fpcr: u32) -> u64 {
    match esize {
        2 => {
            let s = sve_fp16_binop_with_fpcr(FpKind::Mul, x as u16, x as u16, fpcr);
            if (s & 0x7C00) == 0x7C00 && (s & 0x03FF) != 0 {
                s as u64 // NaN
            } else {
                ((s & 0x7FFF) | ((sgn as u16) << 15)) as u64
            }
        }
        4 => {
            let r = fp_three_same_f32_with_fpcr(FpKind::Mul, x as u32, x as u32, 0, fpcr);
            if is_nan32(r) {
                r as u64
            } else {
                ((r & 0x7FFF_FFFF) | ((sgn as u32) << 31)) as u64
            }
        }
        _ => {
            let r = fp_three_same_f64_with_fpcr(FpKind::Mul, x, x, 0, fpcr);
            if is_nan64(r) {
                r
            } else {
                (r & 0x7FFF_FFFF_FFFF_FFFF) | (sgn << 63)
            }
        }
    }
}
/// SVE FTMAD: Zdn = fused(Zdn, |Zm|, coeff[imm + 8*(Zm<0)]). The product is
/// against the absolute value of Zm; a negative Zm selects the upper coefficient
/// block (FPCR.AH=0 default — no product negation).
pub(crate) fn sve_ftmad(esize: usize, nn: u64, mm: u64, imm: usize, fpcr: u32) -> u64 {
    match esize {
        2 => {
            let neg = mm & 0x8000 != 0;
            let m = (mm & 0x7FFF) as u16;
            let coeff = FTMAD_COEFF_H[imm + if neg { 8 } else { 0 }];
            fp_muladd_bits_with_fpcr(coeff as u64, nn, m as u64, 16, fpcr)
        }
        4 => {
            let neg = mm & 0x8000_0000 != 0;
            let m = (mm & 0x7FFF_FFFF) as u32;
            let coeff = FTMAD_COEFF_S[imm + if neg { 8 } else { 0 }];
            fp_muladd_bits_with_fpcr(coeff as u64, nn, m as u64, 32, fpcr)
        }
        _ => {
            let neg = mm & 0x8000_0000_0000_0000 != 0;
            let m = mm & 0x7FFF_FFFF_FFFF_FFFF;
            let coeff = FTMAD_COEFF_D[imm + if neg { 8 } else { 0 }];
            fp_muladd_bits_with_fpcr(coeff, nn, m, 64, fpcr)
        }
    }
}
/// One element of an SVE FP -> integer conversion (FCVTZS/FCVTZU): round the
/// `fp_sz`-byte float toward zero into an `int_sz`-byte integer, saturating
/// out-of-range magnitudes and mapping NaN to 0. Rust's float-to-int `as`
/// already truncates toward zero, saturates and maps NaN to 0, matching ARM.
pub(crate) fn sve_fcvtz(fp_sz: usize, int_sz: usize, signed: bool, x: u64) -> u64 {
    let f: f64 = match fp_sz {
        2 => fp16_to_f64(x as u16),
        4 => f32::from_bits(x as u32) as f64,
        _ => f64::from_bits(x),
    };
    // A signed result is sign-extended to the (possibly wider) container; an
    // unsigned result is zero-extended. The caller's write_elem masks back down
    // to the container width, so extending to 64 bits here is always correct.
    match (int_sz, signed) {
        (2, true) => (f as i16) as i64 as u64,
        (2, false) => (f as u16) as u64,
        (4, true) => (f as i32) as i64 as u64,
        (4, false) => (f as u32) as u64,
        (8, true) => (f as i64) as u64,
        _ => f as u64,
    }
}
/// One element of an SVE integer -> FP conversion (SCVTF/UCVTF): convert the
/// `int_sz`-byte integer (signed or unsigned) to an `fp_sz`-byte float using
/// the FPCR rounding mode.
pub(crate) fn sve_cvtf(int_sz: usize, fp_sz: usize, signed: bool, x: u64, fpcr: u32) -> u64 {
    let (negative, raw) = if signed {
        match int_sz {
            2 => {
                let v = x as u16 as i16;
                (v < 0, (v as i128).unsigned_abs())
            }
            4 => {
                let v = x as u32 as i32;
                (v < 0, (v as i128).unsigned_abs())
            }
            _ => {
                let v = x as i64;
                (v < 0, (v as i128).unsigned_abs())
            }
        }
    } else {
        match int_sz {
            2 => (false, (x as u16) as u128),
            4 => (false, (x as u32) as u128),
            _ => (false, x as u128),
        }
    };
    match fp_sz {
        4 => int_to_fp32_bits_with_fpcr(raw, negative, fpcr) as u64,
        8 => int_to_fp64_bits_with_fpcr(raw, negative, fpcr),
        _ => int_to_fp16_bits_with_fpcr(raw, negative, fpcr) as u64,
    }
}
/// Dispatch an `FpKind` binary op to the verified binary16 helpers (for SVE
/// predicated FP). Only the arithmetic/min/max/abd/mulx kinds are used here.
pub(crate) fn sve_fp16_binop(kind: FpKind, x: u16, y: u16) -> u16 {
    use FpKind::*;
    match kind {
        Add | Addp => fp16_add(x, y),
        Sub => fp16_sub(x, y),
        Mul => fp16_mul(x, y),
        Mulx => fp16_mulx(x, y),
        Div => fp16_div(x, y),
        Max | Maxp => fp16_max(x, y),
        Min | Minp => fp16_min(x, y),
        MaxNm | MaxNmp => fp16_maxnm(x, y),
        MinNm | MinNmp => fp16_minnm(x, y),
        Abd => fp16_abd(x, y),
        _ => x,
    }
}

include!("half_controlled.rs");

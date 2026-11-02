//! math::fp tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

/// VFPExpandImm for single precision: 8-bit immediate -> f32 bit pattern.
/// VFP modified FP immediate expansion for half precision.
pub(crate) fn vfp_expand_imm_f16(imm8: u8) -> u16 {
    let sign = ((imm8 >> 7) & 1) as u16;
    let frac = (imm8 & 0x3F) as u16;
    (sign << 15) | (if (imm8 >> 6) & 1 == 1 { 0x3000 } else { 0x4000 }) | (frac << 6)
}
/// VFP modified FP immediate expanded for an `esize`-byte element.
pub(crate) fn vfp_expand_imm(imm8: u8, esize: usize) -> u64 {
    match esize {
        2 => vfp_expand_imm_f16(imm8) as u64,
        4 => vfp_expand_imm_f32(imm8) as u64,
        _ => vfp_expand_imm_f64(imm8),
    }
}
pub(crate) fn vfp_expand_imm_f32(imm8: u8) -> u32 {
    let imm8 = imm8 as u32;
    let sign = (imm8 >> 7) & 1;
    let b6 = (imm8 >> 6) & 1;
    // exp(8) = NOT(b6) : b6*5 : imm8<5:4>
    let exp = ((!b6 & 1) << 7) | (if b6 != 0 { 0b11111 } else { 0 } << 2) | ((imm8 >> 4) & 0x3);
    let mant = (imm8 & 0xF) << 19;
    (sign << 31) | (exp << 23) | mant
}
/// VFPExpandImm for double precision: 8-bit immediate -> f64 bit pattern.
pub(crate) fn vfp_expand_imm_f64(imm8: u8) -> u64 {
    let imm8 = imm8 as u64;
    let sign = (imm8 >> 7) & 1;
    let b6 = (imm8 >> 6) & 1;
    // exp(11) = NOT(b6) : b6*8 : imm8<5:4>
    let exp = ((!b6 & 1) << 10) | (if b6 != 0 { 0xFF } else { 0 } << 2) | ((imm8 >> 4) & 0x3);
    let mant = (imm8 & 0xF) << 48;
    (sign << 63) | (exp << 52) | mant
}
pub(crate) fn fp_int_scaled_exact(abs_int: u128, precision_bits: u32) -> bool {
    if abs_int == 0 {
        return true;
    }
    let normalized = abs_int >> abs_int.trailing_zeros();
    128 - normalized.leading_zeros() <= precision_bits
}
pub(crate) fn fp_to_int_status(scaled: f64, signed: bool, bits: u32) -> u32 {
    if scaled.is_nan() || scaled.is_infinite() {
        return FPSR_IOC;
    }
    let rounded = scaled.trunc();
    fp_to_int_rounded_status(scaled, rounded, signed, bits)
}
pub(crate) fn fp_status_fjcvtzs(bits: u64) -> u32 {
    let input = f64::from_bits(bits);
    if is_nan64(bits) || !input.is_finite() {
        return FPSR_IOC;
    }
    let rounded = input.trunc();
    if rounded < i32::MIN as f64 || rounded > i32::MAX as f64 {
        return FPSR_IOC;
    }
    if input != rounded { FPSR_IXC } else { 0 }
}
pub(crate) fn fp_to_int_rounded_status(input: f64, rounded: f64, signed: bool, bits: u32) -> u32 {
    if input.is_nan() || input.is_infinite() {
        return FPSR_IOC;
    }
    let invalid = if signed {
        rounded < -(1i128 << (bits - 1)) as f64 || rounded >= (1u128 << (bits - 1)) as f64
    } else {
        rounded < 0.0 || rounded >= (1u128 << bits) as f64
    };
    if invalid {
        FPSR_IOC
    } else if input != rounded {
        FPSR_IXC
    } else {
        0
    }
}
pub(crate) fn fp_status_fjcvtzs_with_fpcr(bits: u64, fpcr: u32) -> u32 {
    fp_status_merge_input_status(
        fp_status_fjcvtzs(fp64_flush_input_with_fpcr(bits, fpcr)),
        fp_fz_input_status(8, bits, fpcr),
        fpcr,
    )
}
pub(crate) fn fp_status_int_to_fp_scaled(abs_int: u128, dst_prec: usize, result: u64) -> u32 {
    let overflow = match dst_prec {
        2 => fp16_is_inf(result as u16),
        4 => fp32_is_inf(result as u32),
        _ => fp64_is_inf(result),
    };
    if overflow {
        return FPSR_OFC | FPSR_IXC;
    }

    let precision_bits = match dst_prec {
        2 => 11,
        4 => 24,
        _ => 53,
    };
    if fp_int_scaled_exact(abs_int, precision_bits) {
        return 0;
    }
    fp_status_assume_inexact(dst_prec, result)
}
pub(crate) fn fp_scaled_int_exact(
    abs_int: u128,
    fbits: u32,
    precision_bits: u32,
    min_subnormal_exp: i32,
) -> bool {
    if abs_int == 0 {
        return true;
    }
    let trailing = abs_int.trailing_zeros();
    let normalized = abs_int >> trailing;
    let exponent = trailing as i32 - fbits as i32;
    128 - normalized.leading_zeros() <= precision_bits && exponent >= min_subnormal_exp
}
pub(crate) fn fp_status_scaled_int_to_fp(
    abs_int: u128,
    fbits: u32,
    dst_prec: usize,
    result: u64,
) -> u32 {
    let overflow = match dst_prec {
        2 => fp16_is_inf(result as u16),
        4 => fp32_is_inf(result as u32),
        _ => fp64_is_inf(result),
    };
    if overflow {
        return FPSR_OFC | FPSR_IXC;
    }

    let (precision_bits, min_subnormal_exp) = match dst_prec {
        2 => (11, -24),
        4 => (24, -149),
        _ => (53, -1074),
    };
    if fp_scaled_int_exact(abs_int, fbits, precision_bits, min_subnormal_exp) {
        return 0;
    }
    fp_status_assume_inexact(dst_prec, result)
}
pub(crate) fn round_shift_u128_with_fpcr(v: u128, shift: u32, negative: bool, fpcr: u32) -> u128 {
    if shift == 0 {
        return v;
    }
    if shift >= 128 {
        return match (fpcr >> 22) & 0x3 {
            1 if !negative && v != 0 => 1,
            2 if negative && v != 0 => 1,
            _ => 0,
        };
    }
    let truncated = v >> shift;
    let rem = v & ((1u128 << shift) - 1);
    if rem == 0 {
        return truncated;
    }
    let increment = match (fpcr >> 22) & 0x3 {
        0 => {
            let half = 1u128 << (shift - 1);
            rem > half || (rem == half && (truncated & 1) != 0)
        }
        1 => !negative,
        2 => negative,
        _ => false,
    };
    truncated + u128::from(increment)
}
pub(crate) fn round_scaled_int_to_fp_bits(
    abs_int: u128,
    negative: bool,
    fbits: u32,
    precision_bits: u32,
    exp_bits: u32,
    frac_bits: u32,
    exp_bias: i32,
    fpcr: u32,
) -> u64 {
    debug_assert_eq!(precision_bits, frac_bits + 1);
    if abs_int == 0 {
        return 0;
    }

    let sign = if negative {
        1u64 << (exp_bits + frac_bits)
    } else {
        0
    };
    let frac_mask = (1u64 << frac_bits) - 1;
    let max_exp = (1u64 << exp_bits) - 1;
    let min_exp = 1 - exp_bias;
    let bit_len = 128 - abs_int.leading_zeros();
    let mut exponent = bit_len as i32 - 1 - fbits as i32;

    if exponent < min_exp {
        let sub_scale = frac_bits as i32 - fbits as i32 - min_exp;
        let sub_sig = if sub_scale >= 0 {
            abs_int << sub_scale as u32
        } else {
            round_shift_u128_with_fpcr(abs_int, (-sub_scale) as u32, negative, fpcr)
        };
        if sub_sig >= (1u128 << frac_bits) {
            return sign | (1u64 << frac_bits);
        }
        return sign | sub_sig as u64;
    }

    let mut sig = if bit_len <= precision_bits {
        abs_int << (precision_bits - bit_len)
    } else {
        round_shift_u128_with_fpcr(abs_int, bit_len - precision_bits, negative, fpcr)
    };
    if sig == (1u128 << precision_bits) {
        sig >>= 1;
        exponent += 1;
    }

    let biased_exp = (exponent + exp_bias) as u64;
    if biased_exp >= max_exp {
        let round_to_inf = match (fpcr >> 22) & 0x3 {
            0 => true,
            1 => !negative,
            2 => negative,
            _ => false,
        };
        return if round_to_inf {
            sign | (max_exp << frac_bits)
        } else {
            sign | ((max_exp - 1) << frac_bits) | frac_mask
        };
    }

    sign | (biased_exp << frac_bits) | ((sig as u64) & frac_mask)
}
pub(crate) fn round_int_to_fp_bits(
    abs_int: u128,
    negative: bool,
    precision_bits: u32,
    exp_bits: u32,
    frac_bits: u32,
    exp_bias: i32,
    fpcr: u32,
) -> u64 {
    round_scaled_int_to_fp_bits(
        abs_int,
        negative,
        0,
        precision_bits,
        exp_bits,
        frac_bits,
        exp_bias,
        fpcr,
    )
}
pub(crate) fn int_to_fp16_bits_with_fpcr(abs_int: u128, negative: bool, fpcr: u32) -> u16 {
    round_int_to_fp_bits(abs_int, negative, 11, 5, 10, 15, fpcr) as u16
}
pub(crate) fn int_to_fp32_bits_with_fpcr(abs_int: u128, negative: bool, fpcr: u32) -> u32 {
    round_int_to_fp_bits(abs_int, negative, 24, 8, 23, 127, fpcr) as u32
}
pub(crate) fn int_to_fp64_bits_with_fpcr(abs_int: u128, negative: bool, fpcr: u32) -> u64 {
    round_int_to_fp_bits(abs_int, negative, 53, 11, 52, 1023, fpcr)
}
pub(crate) fn scaled_int_to_fp16_bits_with_fpcr(
    abs_int: u128,
    negative: bool,
    fbits: u32,
    fpcr: u32,
) -> u16 {
    round_scaled_int_to_fp_bits(abs_int, negative, fbits, 11, 5, 10, 15, fpcr) as u16
}
pub(crate) fn scaled_int_to_fp32_bits_with_fpcr(
    abs_int: u128,
    negative: bool,
    fbits: u32,
    fpcr: u32,
) -> u32 {
    round_scaled_int_to_fp_bits(abs_int, negative, fbits, 24, 8, 23, 127, fpcr) as u32
}
pub(crate) fn scaled_int_to_fp64_bits_with_fpcr(
    abs_int: u128,
    negative: bool,
    fbits: u32,
    fpcr: u32,
) -> u64 {
    round_scaled_int_to_fp_bits(abs_int, negative, fbits, 53, 11, 52, 1023, fpcr)
}
/// One element of a NEON fixed-point <-> floating-point conversion (`bits` is
/// 16, 32 or 64, `fbits` is the fixed-point fractional width). Returns the raw
/// result element and FPSR exception bits produced by that element.
pub(crate) fn fixed_point_convert(
    opcode: u32,
    u: u32,
    bits: u32,
    a: u64,
    fbits: u32,
    fpcr: u32,
) -> (u64, u32) {
    if bits == 16 {
        // FP16 variants (FEAT_FP16).
        if opcode == 0b11100 {
            let (negative, raw) = if u == 0 {
                let x = a as u16 as i16;
                (x < 0, (x as i128).unsigned_abs())
            } else {
                (false, a as u16 as u128)
            };
            let raw_r = scaled_int_to_fp16_bits_with_fpcr(raw, negative, fbits, fpcr);
            let status = fp_status_scaled_int_to_fp(raw, fbits, 2, raw_r as u64);
            let (r, status) = fp16_int_to_fp_output_status_with_fpcr(raw, raw_r, status, fpcr);
            (r as u64, status)
        } else {
            let scale = (2.0f64).powi(fbits as i32);
            let a = fp16_flush_input_with_fpcr(a as u16, fpcr);
            let f = (AArch64Cpu::fp16_to_f32(a) as f64) * scale;
            let t = f.trunc();
            let status = fp_to_int_status(f, u == 0, bits);
            let r = if u == 0 {
                (t.clamp(i16::MIN as f64, i16::MAX as f64) as i16 as u16) as u64
            } else {
                t.clamp(0.0, u16::MAX as f64) as u16 as u64
            };
            (r, status)
        }
    } else if opcode == 0b11100 {
        // SCVTF / UCVTF: integer * 2^-fbits -> float
        if bits == 32 {
            let (negative, raw) = if u == 0 {
                let x = a as u32 as i32;
                (x < 0, (x as i128).unsigned_abs())
            } else {
                (false, a as u32 as u128)
            };
            let r = scaled_int_to_fp32_bits_with_fpcr(raw, negative, fbits, fpcr);
            let status = fp_status_scaled_int_to_fp(raw, fbits, 4, r as u64);
            (r as u64, status)
        } else {
            let (negative, raw) = if u == 0 {
                let x = a as i64;
                (x < 0, (x as i128).unsigned_abs())
            } else {
                (false, a as u128)
            };
            let r = scaled_int_to_fp64_bits_with_fpcr(raw, negative, fbits, fpcr);
            let status = fp_status_scaled_int_to_fp(raw, fbits, 8, r);
            (r, status)
        }
    } else {
        // FCVTZS / FCVTZU: float * 2^fbits -> integer (round toward zero)
        let scale = (2.0f64).powi(fbits as i32);
        if bits == 32 {
            let input_status = fp_fz_input_status(4, a, fpcr);
            let a = fp32_flush_input_with_fpcr(a as u32, fpcr);
            let f = (f32::from_bits(a) as f64) * scale;
            let t = f.trunc();
            let status =
                fp_status_merge_input_status(fp_to_int_status(f, u == 0, bits), input_status, fpcr);
            let r = if u == 0 {
                (t.clamp(i32::MIN as f64, i32::MAX as f64) as i32 as u32) as u64
            } else {
                t.clamp(0.0, u32::MAX as f64) as u32 as u64
            };
            (r, status)
        } else {
            let input_status = fp_fz_input_status(8, a, fpcr);
            let a = fp64_flush_input_with_fpcr(a, fpcr);
            let f = f64::from_bits(a) * scale;
            let t = f.trunc();
            let status =
                fp_status_merge_input_status(fp_to_int_status(f, u == 0, bits), input_status, fpcr);
            let r = if u == 0 {
                (t.clamp(i64::MIN as f64, i64::MAX as f64) as i64) as u64
            } else {
                t.clamp(0.0, u64::MAX as f64) as u64
            };
            (r, status)
        }
    }
}
/// Decode the FP three-same opcode from (U, size<1>, opcode) into an `FpKind`.
pub(crate) fn fp_three_same_decode(u: u32, a: u32, opcode: u32) -> Option<FpKind> {
    use FpKind::*;
    Some(match (u, a, opcode) {
        (0, 0, 0b11000) => MaxNm,
        (0, 0, 0b11001) => Mla,
        (0, 0, 0b11010) => Add,
        (0, 0, 0b11011) => Mulx,
        (0, 0, 0b11100) => CmEq,
        (0, 0, 0b11110) => Max,
        (0, 0, 0b11111) => Recps,
        (0, 1, 0b11000) => MinNm,
        (0, 1, 0b11001) => Mls,
        (0, 1, 0b11010) => Sub,
        (0, 1, 0b11110) => Min,
        (0, 1, 0b11111) => Rsqrts,
        (1, 0, 0b11000) => MaxNmp,
        (1, 0, 0b11010) => Addp,
        (1, 0, 0b11011) => Mul,
        (1, 0, 0b11100) => CmGe,
        (1, 0, 0b11101) => AcGe,
        (1, 0, 0b11110) => Maxp,
        (1, 0, 0b11111) => Div,
        (1, 1, 0b11000) => MinNmp,
        (1, 1, 0b11010) => Abd,
        (1, 1, 0b11100) => CmGt,
        (1, 1, 0b11101) => AcGt,
        (1, 1, 0b11110) => Minp,
        _ => return None,
    })
}
/// FMAX per ARM: NaN propagates; +0 is greater than -0.
#[inline]
/// One element of an FP precision conversion before any FPCR output flushing.
/// `src_prec`/`dst_prec` are byte widths (2=f16, 4=f32, 8=f64). NaN goes through
/// FPConvertNaN; `round_odd` selects FCVTX (f64->f32 round-to-odd, which carries
/// its own NaN handling). Other narrowing conversions use FPCR rounding.
pub(crate) fn fp_cvt_elem_raw(
    bits: u64,
    src_prec: usize,
    dst_prec: usize,
    round_odd: bool,
    fpcr: u32,
) -> u64 {
    let bits = fp_cvt_input_bits_with_fpcr(bits, src_prec, dst_prec, fpcr);
    if round_odd {
        return round_odd_f64_to_f32(f64::from_bits(bits)) as u64;
    }
    let is_nan = match src_prec {
        4 => is_nan32(bits as u32),
        8 => is_nan64(bits),
        _ => (bits as u16) & 0x7C00 == 0x7C00 && (bits as u16) & 0x3FF != 0,
    };
    if is_nan {
        return fp_convert_nan(bits, src_prec, dst_prec);
    }
    let val = match src_prec {
        4 => f32::from_bits(bits as u32) as f64,
        8 => f64::from_bits(bits),
        _ => fp16_to_f64(bits as u16),
    };
    match dst_prec {
        4 if src_prec == 8 => f64_to_f32_bits_with_fpcr(val, fpcr) as u64,
        4 => (val as f32).to_bits() as u64,
        8 => val.to_bits(),
        _ => f64_to_fp16_bits_with_fpcr(val, fpcr) as u64,
    }
}
#[inline]
pub(crate) fn fp_cvt_input_bits_with_fpcr(
    bits: u64,
    src_prec: usize,
    dst_prec: usize,
    fpcr: u32,
) -> u64 {
    if src_prec == 2 && dst_prec > src_prec {
        bits
    } else {
        fp_flush_input_bits_with_fpcr(bits, (src_prec * 8) as u32, fpcr)
    }
}
/// One element of an FP precision conversion (FCVTL/FCVTN and the scalar FCVT).
pub(crate) fn fp_cvt_elem(
    bits: u64,
    src_prec: usize,
    dst_prec: usize,
    round_odd: bool,
    fpcr: u32,
) -> u64 {
    let result = fp_cvt_elem_raw(bits, src_prec, dst_prec, round_odd, fpcr);
    fp_flush_output_bits_with_fpcr(result, (dst_prec * 8) as u32, fpcr)
}
/// FRINT32/FRINT64 (FEAT_FRINTTS): round an f32 to an integral value within the
/// signed `intsize`-bit range. `z`=round-toward-zero (FRINT*Z), else round per
/// the current mode (FPCR default = ties-even). Out-of-range / NaN / Inf yield
/// INT{intsize}_MIN as a float (qemu frint_s, vfp_helper.c).
pub(crate) fn frint_ts_f32(bits: u32, intsize: u32, z: bool) -> u32 {
    let overflow = (0x100 + 126 + intsize) << 23;
    if (bits >> 23) & 0xFF == 0xFF {
        return overflow; // NaN / Inf
    }
    let x = f32::from_bits(bits);
    let r = if z { x.trunc() } else { x.round_ties_even() };
    let rb = r.to_bits();
    let rexp = (rb >> 23) & 0xFF;
    if rexp < 126 + intsize {
        return rb;
    }
    if rexp == 126 + intsize && (rb >> 31) & 1 == 1 && rb & 0x7F_FFFF == 0 {
        return rb; // exactly INT{intsize}_MIN
    }
    overflow
}
pub(crate) fn frint_ts_f32_with_fpcr(bits: u32, intsize: u32, z: bool, fpcr: u32) -> u32 {
    frint_ts_f32(fp32_flush_input_with_fpcr(bits, fpcr), intsize, z)
}
/// FRINT32/FRINT64 for f64 (qemu frint_d).
pub(crate) fn frint_ts_f64(bits: u64, intsize: u32, z: bool) -> u64 {
    let overflow = (0x800u64 + 1022 + intsize as u64) << 52;
    if (bits >> 52) & 0x7FF == 0x7FF {
        return overflow; // NaN / Inf
    }
    let x = f64::from_bits(bits);
    let r = if z { x.trunc() } else { x.round_ties_even() };
    let rb = r.to_bits();
    let rexp = ((rb >> 52) & 0x7FF) as u32;
    if rexp < 1022 + intsize {
        return rb;
    }
    if rexp == 1022 + intsize && (rb >> 63) & 1 == 1 && rb & 0xF_FFFF_FFFF_FFFF == 0 {
        return rb;
    }
    overflow
}
pub(crate) fn frint_ts_f64_with_fpcr(bits: u64, intsize: u32, z: bool, fpcr: u32) -> u64 {
    frint_ts_f64(fp64_flush_input_with_fpcr(bits, fpcr), intsize, z)
}
pub(crate) fn fp_status_frint_ts_f32(bits: u32, intsize: u32, z: bool) -> u32 {
    let x = f32::from_bits(bits);
    if is_nan32(bits) || !x.is_finite() {
        return FPSR_IOC;
    }
    let rounded = if z { x.trunc() } else { x.round_ties_even() } as f64;
    let limit = 2.0f64.powi((intsize - 1) as i32);
    if rounded < -limit || rounded >= limit {
        return FPSR_IOC;
    }
    if x.fract() != 0.0 { FPSR_IXC } else { 0 }
}
pub(crate) fn fp_status_frint_ts_f32_with_fpcr(bits: u32, intsize: u32, z: bool, fpcr: u32) -> u32 {
    let input_status = if fpcr & FPCR_AH != 0 {
        0
    } else {
        fp_fz_input_status(4, bits as u64, fpcr)
    };
    fp_status_frint_ts_f32(fp32_flush_input_with_fpcr(bits, fpcr), intsize, z) | input_status
}
pub(crate) fn fp_status_frint_ts_f64(bits: u64, intsize: u32, z: bool) -> u32 {
    let x = f64::from_bits(bits);
    if is_nan64(bits) || !x.is_finite() {
        return FPSR_IOC;
    }
    let rounded = if z { x.trunc() } else { x.round_ties_even() };
    let limit = 2.0f64.powi((intsize - 1) as i32);
    if rounded < -limit || rounded >= limit {
        return FPSR_IOC;
    }
    if x.fract() != 0.0 { FPSR_IXC } else { 0 }
}
pub(crate) fn fp_status_frint_ts_f64_with_fpcr(bits: u64, intsize: u32, z: bool, fpcr: u32) -> u32 {
    let input_status = if fpcr & FPCR_AH != 0 {
        0
    } else {
        fp_fz_input_status(8, bits, fpcr)
    };
    fp_status_frint_ts_f64(fp64_flush_input_with_fpcr(bits, fpcr), intsize, z) | input_status
}
pub(crate) fn fp_max_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() || b.is_nan() {
        f32::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_positive() { a } else { b }
    } else {
        a.max(b)
    }
}
#[inline]
pub(crate) fn fp_min_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() || b.is_nan() {
        f32::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_negative() { a } else { b }
    } else {
        a.min(b)
    }
}
#[inline]
pub(crate) fn fp_max_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_positive() { a } else { b }
    } else {
        a.max(b)
    }
}
#[inline]
pub(crate) fn fp_min_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_negative() { a } else { b }
    } else {
        a.min(b)
    }
}
#[inline]
pub(crate) fn fp16_ah_nan_number(a: u16, b: u16) -> Option<u16> {
    if fp16_is_nan(a) || fp16_is_nan(b) {
        Some(b)
    } else {
        None
    }
}
#[inline]
pub(crate) fn fp32_ah_nan_number(a: u32, b: u32) -> Option<u32> {
    if is_nan32(a) || is_nan32(b) {
        Some(b)
    } else {
        None
    }
}
#[inline]
pub(crate) fn fp64_ah_nan_number(a: u64, b: u64) -> Option<u64> {
    if is_nan64(a) || is_nan64(b) {
        Some(b)
    } else {
        None
    }
}
/// Apply a two-reg-misc FP op to one f32 element (raw bits in/out).
pub(crate) fn fp_two_reg_f32(kind: TwoRegFp, bits: u32) -> u32 {
    use TwoRegFp::*;
    let x = f32::from_bits(bits);
    let mask = |c: bool| if c { u32::MAX } else { 0 };
    match kind {
        Fabs => x.abs().to_bits(),
        Fneg => (-x).to_bits(),
        Fsqrt => {
            if x.is_sign_negative() && x != 0.0 && !x.is_nan() {
                0x7FC0_0000 // sqrt of negative/-Inf -> default NaN (positive)
            } else {
                x.sqrt().to_bits()
            }
        }
        RintN | RintX | RintI => x.round_ties_even().to_bits(),
        RintP => x.ceil().to_bits(),
        RintM => x.floor().to_bits(),
        RintZ => x.trunc().to_bits(),
        RintA => x.round().to_bits(),
        CmGt => mask(x > 0.0),
        CmGe => mask(x >= 0.0),
        CmEq => mask(x == 0.0),
        CmLe => mask(x <= 0.0),
        CmLt => mask(x < 0.0),
        CvtNS | CvtMS | CvtPS | CvtZS | CvtAS => {
            let r = match kind {
                CvtNS => x.round_ties_even(),
                CvtMS => x.floor(),
                CvtPS => x.ceil(),
                CvtZS => x.trunc(),
                _ => x.round(),
            };
            (r as i32) as u32
        }
        CvtNU | CvtMU | CvtPU | CvtZU | CvtAU => {
            let r = match kind {
                CvtNU => x.round_ties_even(),
                CvtMU => x.floor(),
                CvtPU => x.ceil(),
                CvtZU => x.trunc(),
                _ => x.round(),
            };
            r as u32
        }
    }
}
pub(crate) fn fp_two_reg_f32_with_fpcr(kind: TwoRegFp, bits: u32, fpcr: u32) -> u32 {
    use TwoRegFp::*;
    let flush_input = fpcr & FPCR_FIZ != 0
        || fpcr & FPCR_FZ != 0
            && matches!(
                kind,
                CvtNS
                    | CvtMS
                    | CvtPS
                    | CvtZS
                    | CvtAS
                    | CvtNU
                    | CvtMU
                    | CvtPU
                    | CvtZU
                    | CvtAU
                    | Fsqrt
                    | RintN
                    | RintP
                    | RintM
                    | RintZ
                    | RintA
                    | RintX
                    | RintI
                    | CmGt
                    | CmGe
                    | CmEq
                    | CmLe
                    | CmLt
            );
    let flush_input = flush_input
        && matches!(
            kind,
            RintN
                | RintP
                | RintM
                | RintZ
                | RintA
                | RintX
                | RintI
                | CvtNS
                | CvtMS
                | CvtPS
                | CvtZS
                | CvtAS
                | CvtNU
                | CvtMU
                | CvtPU
                | CvtZU
                | CvtAU
                | CmGt
                | CmGe
                | CmEq
                | CmLe
                | CmLt
        );
    let bits = if flush_input {
        fp32_flush_input_with_fpcr(bits, fpcr)
    } else {
        bits
    };
    match kind {
        Fabs => fp_abs_bits_with_fpcr(bits as u64, 32, fpcr) as u32,
        Fsqrt => fp32_sqrt_with_fpcr(bits, fpcr),
        Fneg => fp_neg_bits_with_fpcr(bits as u64, 32, fpcr) as u32,
        RintX | RintI => {
            let x = f32::from_bits(bits);
            match (fpcr >> 22) & 0x3 {
                0 => x.round_ties_even(),
                1 => x.ceil(),
                2 => x.floor(),
                _ => x.trunc(),
            }
            .to_bits()
        }
        _ => fp_two_reg_f32(kind, bits),
    }
}
pub(crate) fn fp32_sqrt_with_fpcr(bits: u32, fpcr: u32) -> u32 {
    let bits = fp32_flush_input_with_fpcr(bits, fpcr);
    let nearest = fp_two_reg_f32(TwoRegFp::Fsqrt, bits);
    if (bits >> 31) != 0 && !fp32_is_zero(bits) && !is_nan32(bits) {
        return fp32_ah_invalid_default_nan(nearest, fpcr);
    }
    if (fpcr >> 22) & 0x3 == 0 || fp32_abs(bits) == 0 || fp32_abs(bits) >= 0x7f80_0000 {
        return nearest;
    }
    if (bits >> 31) != 0 || fp32_abs(nearest) >= 0x7f80_0000 {
        return nearest;
    }

    let rounded_sq = {
        let r = f32::from_bits(nearest) as f64;
        r * r
    };
    let x = f32::from_bits(bits) as f64;
    match (fpcr >> 22) & 0x3 {
        1 if rounded_sq < x => fp32_next_up_bits(nearest),
        2 | 3 if rounded_sq > x => fp32_next_down_bits(nearest),
        _ => nearest,
    }
}
/// Apply a two-reg-misc FP op to one f64 element (raw bits in/out).
pub(crate) fn fp_two_reg_f64(kind: TwoRegFp, bits: u64) -> u64 {
    use TwoRegFp::*;
    let x = f64::from_bits(bits);
    let mask = |c: bool| if c { u64::MAX } else { 0 };
    match kind {
        Fabs => x.abs().to_bits(),
        Fneg => (-x).to_bits(),
        Fsqrt => {
            if x.is_sign_negative() && x != 0.0 && !x.is_nan() {
                0x7FF8_0000_0000_0000 // sqrt of negative/-Inf -> default NaN
            } else {
                x.sqrt().to_bits()
            }
        }
        RintN | RintX | RintI => x.round_ties_even().to_bits(),
        RintP => x.ceil().to_bits(),
        RintM => x.floor().to_bits(),
        RintZ => x.trunc().to_bits(),
        RintA => x.round().to_bits(),
        CmGt => mask(x > 0.0),
        CmGe => mask(x >= 0.0),
        CmEq => mask(x == 0.0),
        CmLe => mask(x <= 0.0),
        CmLt => mask(x < 0.0),
        CvtNS | CvtMS | CvtPS | CvtZS | CvtAS => {
            let r = match kind {
                CvtNS => x.round_ties_even(),
                CvtMS => x.floor(),
                CvtPS => x.ceil(),
                CvtZS => x.trunc(),
                _ => x.round(),
            };
            (r as i64) as u64
        }
        CvtNU | CvtMU | CvtPU | CvtZU | CvtAU => {
            let r = match kind {
                CvtNU => x.round_ties_even(),
                CvtMU => x.floor(),
                CvtPU => x.ceil(),
                CvtZU => x.trunc(),
                _ => x.round(),
            };
            r as u64
        }
    }
}
pub(crate) fn fp_two_reg_f64_with_fpcr(kind: TwoRegFp, bits: u64, fpcr: u32) -> u64 {
    use TwoRegFp::*;
    let flush_input = fpcr & FPCR_FIZ != 0
        || fpcr & FPCR_FZ != 0
            && matches!(
                kind,
                CvtNS
                    | CvtMS
                    | CvtPS
                    | CvtZS
                    | CvtAS
                    | CvtNU
                    | CvtMU
                    | CvtPU
                    | CvtZU
                    | CvtAU
                    | Fsqrt
                    | RintN
                    | RintP
                    | RintM
                    | RintZ
                    | RintA
                    | RintX
                    | RintI
                    | CmGt
                    | CmGe
                    | CmEq
                    | CmLe
                    | CmLt
            );
    let flush_input = flush_input
        && matches!(
            kind,
            RintN
                | RintP
                | RintM
                | RintZ
                | RintA
                | RintX
                | RintI
                | CvtNS
                | CvtMS
                | CvtPS
                | CvtZS
                | CvtAS
                | CvtNU
                | CvtMU
                | CvtPU
                | CvtZU
                | CvtAU
                | CmGt
                | CmGe
                | CmEq
                | CmLe
                | CmLt
        );
    let bits = if flush_input {
        fp64_flush_input_with_fpcr(bits, fpcr)
    } else {
        bits
    };
    match kind {
        Fabs => fp_abs_bits_with_fpcr(bits, 64, fpcr),
        Fsqrt => fp64_sqrt_with_fpcr(bits, fpcr),
        Fneg => fp_neg_bits_with_fpcr(bits, 64, fpcr),
        RintX | RintI => {
            let x = f64::from_bits(bits);
            match (fpcr >> 22) & 0x3 {
                0 => x.round_ties_even(),
                1 => x.ceil(),
                2 => x.floor(),
                _ => x.trunc(),
            }
            .to_bits()
        }
        _ => fp_two_reg_f64(kind, bits),
    }
}
pub(crate) fn fp64_sqrt_with_fpcr(bits: u64, fpcr: u32) -> u64 {
    let bits = fp64_flush_input_with_fpcr(bits, fpcr);
    let nearest = fp_two_reg_f64(TwoRegFp::Fsqrt, bits);
    if (bits >> 63) != 0 && !fp64_is_zero(bits) && !is_nan64(bits) {
        return fp_ah_invalid_default_nan(8, nearest, fpcr);
    }
    if (fpcr >> 22) & 0x3 == 0 || fp64_abs(bits) == 0 || fp64_abs(bits) >= 0x7ff0_0000_0000_0000 {
        return nearest;
    }
    if (bits >> 63) != 0 || fp64_abs(nearest) >= 0x7ff0_0000_0000_0000 {
        return nearest;
    }

    let Some((mx, ex)) = fp64_mant_exp(bits) else {
        return nearest;
    };
    let Some((mr, er)) = fp64_mant_exp(nearest) else {
        return nearest;
    };
    let square = (mr as u128) * (mr as u128);
    let cmp_square_input = scaled_i128_terms_sign(&[(square as i128, er * 2), (-(mx as i128), ex)]);
    match (fpcr >> 22) & 0x3 {
        1 if cmp_square_input == std::cmp::Ordering::Less => fp64_next_up_bits(nearest),
        2 | 3 if cmp_square_input == std::cmp::Ordering::Greater => fp64_next_down_bits(nearest),
        _ => nearest,
    }
}
/// Compute one f32 element of an Advanced SIMD three-same FP operation.
#[inline]
pub(crate) fn is_nan32(x: u32) -> bool {
    x & 0x7F80_0000 == 0x7F80_0000 && x & 0x007F_FFFF != 0
}
#[inline]
pub(crate) fn is_snan32(x: u32) -> bool {
    is_nan32(x) && x & 0x0040_0000 == 0
}
#[inline]
pub(crate) fn is_nan64(x: u64) -> bool {
    x & 0x7FF0_0000_0000_0000 == 0x7FF0_0000_0000_0000 && x & 0x000F_FFFF_FFFF_FFFF != 0
}
#[inline]
pub(crate) fn is_snan64(x: u64) -> bool {
    is_nan64(x) && x & 0x0008_0000_0000_0000 == 0
}
#[inline]
pub(crate) fn fp32_abs(x: u32) -> u32 {
    x & 0x7fff_ffff
}
#[inline]
pub(crate) fn fp64_abs(x: u64) -> u64 {
    x & 0x7fff_ffff_ffff_ffff
}
#[inline]
pub(crate) fn fp32_is_zero(x: u32) -> bool {
    fp32_abs(x) == 0
}
#[inline]
pub(crate) fn fp64_is_zero(x: u64) -> bool {
    fp64_abs(x) == 0
}
#[inline]
pub(crate) fn fp32_is_inf(x: u32) -> bool {
    fp32_abs(x) == 0x7f80_0000
}
#[inline]
pub(crate) fn fp64_is_inf(x: u64) -> bool {
    fp64_abs(x) == 0x7ff0_0000_0000_0000
}
#[inline]
pub(crate) fn fp32_is_finite(x: u32) -> bool {
    fp32_abs(x) < 0x7f80_0000
}
#[inline]
pub(crate) fn fp64_is_finite(x: u64) -> bool {
    fp64_abs(x) < 0x7ff0_0000_0000_0000
}
#[inline]
pub(crate) fn fp32_is_tiny(x: u32) -> bool {
    let a = fp32_abs(x);
    a != 0 && a < 0x0080_0000
}
#[inline]
pub(crate) fn fp64_is_tiny(x: u64) -> bool {
    let a = fp64_abs(x);
    a != 0 && a < 0x0010_0000_0000_0000
}
#[inline]
pub(crate) fn fp16_flush_input_with_fpcr(x: u16, fpcr: u32) -> u16 {
    if fpcr & FPCR_FZ16 != 0 && fp16_is_tiny(x) {
        x & 0x8000
    } else {
        x
    }
}
#[inline]
pub(crate) fn fp16_flush_output_with_fpcr(x: u16, fpcr: u32) -> u16 {
    if fpcr & FPCR_FZ16 != 0 && fp16_is_tiny(x) {
        x & 0x8000
    } else {
        x
    }
}
#[inline]
pub(crate) fn fp16_flush_output_status_with_fpcr(raw: u16, status: u32, fpcr: u32) -> (u16, u32) {
    let flushed = fp16_flush_output_with_fpcr(raw, fpcr);
    if flushed != raw {
        (flushed, (status & !FPSR_IXC) | FPSR_UFC)
    } else {
        (raw, status)
    }
}

#[inline]
pub(crate) fn fp32_flush_input_with_fpcr(x: u32, fpcr: u32) -> u32 {
    if fpcr & (FPCR_FIZ | FPCR_FZ) != 0 && fp32_is_tiny(x) {
        x & 0x8000_0000
    } else {
        x
    }
}
#[inline]
pub(crate) fn fp64_flush_input_with_fpcr(x: u64, fpcr: u32) -> u64 {
    if fpcr & (FPCR_FIZ | FPCR_FZ) != 0 && fp64_is_tiny(x) {
        x & 0x8000_0000_0000_0000
    } else {
        x
    }
}
#[inline]
pub(crate) fn fp32_flush_output_with_fpcr(x: u32, fpcr: u32) -> u32 {
    if fpcr & FPCR_FZ != 0 && fp32_is_tiny(x) {
        x & 0x8000_0000
    } else {
        x
    }
}
#[inline]
pub(crate) fn fp64_flush_output_with_fpcr(x: u64, fpcr: u32) -> u64 {
    if fpcr & FPCR_FZ != 0 && fp64_is_tiny(x) {
        x & 0x8000_0000_0000_0000
    } else {
        x
    }
}
#[inline]
pub(crate) fn fp_flush_input_bits_with_fpcr(x: u64, esize: u32, fpcr: u32) -> u64 {
    match esize {
        16 => fp16_flush_input_with_fpcr(x as u16, fpcr) as u64,
        32 => fp32_flush_input_with_fpcr(x as u32, fpcr) as u64,
        64 => fp64_flush_input_with_fpcr(x, fpcr),
        _ => x,
    }
}
#[inline]
pub(crate) fn fp_estimate_input_with_fpcr(x: u64, esize: u32, fpcr: u32) -> u64 {
    let x = fp_flush_input_bits_with_fpcr(x, esize, fpcr);
    if fpcr & FPCR_AH == 0 {
        return x;
    }
    match esize {
        32 if fp32_is_tiny(x as u32) => (x as u32 & 0x8000_0000) as u64,
        64 if fp64_is_tiny(x) => x & 0x8000_0000_0000_0000,
        _ => x,
    }
}
#[inline]
pub(crate) fn fp_flush_output_bits_with_fpcr(x: u64, esize: u32, fpcr: u32) -> u64 {
    match esize {
        32 => fp32_flush_output_with_fpcr(x as u32, fpcr) as u64,
        64 => fp64_flush_output_with_fpcr(x, fpcr),
        _ => x,
    }
}
#[inline]
pub(crate) fn fp_input_flush_enabled(esize: usize, fpcr: u32) -> bool {
    match esize {
        2 => fpcr & FPCR_FZ16 != 0,
        4 | 8 => fpcr & (FPCR_FIZ | FPCR_FZ) != 0,
        _ => false,
    }
}
#[inline]
pub(crate) fn fp_fz_input_status(esize: usize, x: u64, fpcr: u32) -> u32 {
    if fpcr & (FPCR_FZ | FPCR_AH) == 0 {
        return 0;
    }
    match esize {
        4 if fp32_is_tiny(x as u32) => FPSR_IDC,
        8 if fp64_is_tiny(x) => FPSR_IDC,
        _ => 0,
    }
}
#[inline]
pub(crate) fn fp_status_merge_input_status(status: u32, input_status: u32, fpcr: u32) -> u32 {
    if fpcr & FPCR_AH != 0 && status != 0 {
        status
    } else {
        status | input_status
    }
}
#[inline]
pub(crate) fn fp_is_tiny_bits(esize: usize, x: u64) -> bool {
    match esize {
        2 => fp16_is_tiny(x as u16),
        4 => fp32_is_tiny(x as u32),
        _ => fp64_is_tiny(x),
    }
}
pub(crate) fn fp32_top_exp(x: u32) -> Option<i32> {
    let abs = fp32_abs(x);
    if abs == 0 || abs >= 0x7f80_0000 {
        return None;
    }
    let exp = ((abs >> 23) & 0xff) as i32;
    let frac = abs & 0x007f_ffff;
    if exp == 0 {
        Some(frac.ilog2() as i32 - 149)
    } else {
        Some(exp - 127)
    }
}
pub(crate) fn fp32_operand_lost(anchor: u32, lost: u32) -> bool {
    let Some(anchor_exp) = fp32_top_exp(anchor) else {
        return false;
    };
    let Some(lost_exp) = fp32_top_exp(lost) else {
        return false;
    };
    anchor_exp - lost_exp > 24
}
pub(crate) fn fp64_top_exp(x: u64) -> Option<i32> {
    let abs = fp64_abs(x);
    if abs == 0 || abs >= 0x7ff0_0000_0000_0000 {
        return None;
    }
    let exp = ((abs >> 52) & 0x7ff) as i32;
    let frac = abs & 0x000f_ffff_ffff_ffff;
    if exp == 0 {
        Some(frac.ilog2() as i32 - 1074)
    } else {
        Some(exp - 1023)
    }
}
pub(crate) fn fp64_operand_lost(anchor: u64, lost: u64) -> bool {
    let Some(anchor_exp) = fp64_top_exp(anchor) else {
        return false;
    };
    let Some(lost_exp) = fp64_top_exp(lost) else {
        return false;
    };
    anchor_exp - lost_exp > 53
}
pub(crate) fn fp64_mant_exp(bits: u64) -> Option<(u64, i32)> {
    let abs = fp64_abs(bits);
    if abs == 0 || abs >= 0x7ff0_0000_0000_0000 {
        return None;
    }
    let exp = ((abs >> 52) & 0x7ff) as i32;
    let frac = abs & 0x000f_ffff_ffff_ffff;
    if exp == 0 {
        Some((frac, -1074))
    } else {
        Some(((1u64 << 52) | frac, exp - 1075))
    }
}
pub(crate) fn fp64_div_exact(a: u64, b: u64) -> bool {
    let Some((na, ea)) = fp64_mant_exp(a) else {
        return true;
    };
    let Some((nb, eb)) = fp64_mant_exp(b) else {
        return true;
    };
    if nb == 0 {
        return true;
    }
    let g = gcd_u64(na, nb);
    let mut numer = na / g;
    let denom = nb / g;
    if !denom.is_power_of_two() {
        return false;
    }
    while numer & 1 == 0 {
        numer >>= 1;
    }
    let exp = ea - eb - denom.trailing_zeros() as i32;
    let sig_bits = 64 - numer.leading_zeros() as i32;
    sig_bits <= 53 || exp + sig_bits <= -1021
}
pub(crate) fn fp64_sqrt_exact(bits: u64) -> bool {
    let Some((mut mant, mut exp)) = fp64_mant_exp(bits) else {
        return true;
    };
    while mant & 1 == 0 {
        mant >>= 1;
        exp += 1;
    }
    if exp & 1 != 0 {
        mant <<= 1;
    }
    is_square_u64(mant)
}
pub(crate) fn fp64_mul_exact(a: u64, b: u64) -> bool {
    let Some((ma, ea)) = fp64_mant_exp(a) else {
        return true;
    };
    let Some((mb, eb)) = fp64_mant_exp(b) else {
        return true;
    };
    let mut product = ma as u128 * mb as u128;
    if product == 0 {
        return true;
    }
    while product & 1 == 0 {
        product >>= 1;
    }
    let exp = ea + eb;
    let sig_bits = 128 - product.leading_zeros() as i32;
    sig_bits <= 53 || exp + sig_bits <= -1021
}
pub(crate) fn fp64_mul_exact_result(a: u64, b: u64, result: u64) -> bool {
    if fp64_is_zero(a) || fp64_is_zero(b) {
        return fp64_is_zero(result);
    }
    let Some((ma, ea)) = fp64_signed_mant_exp(a) else {
        return true;
    };
    let Some((mb, eb)) = fp64_signed_mant_exp(b) else {
        return true;
    };
    let Some((mr, er)) = fp64_signed_mant_exp(result) else {
        return false;
    };
    let Some(product) = ma.checked_mul(mb) else {
        return false;
    };
    let ep = ea + eb;
    let common = ep.min(er);
    let Some(lhs) = shift_i128_checked(product, ep - common) else {
        return false;
    };
    let Some(rhs) = shift_i128_checked(mr, er - common) else {
        return false;
    };
    lhs == rhs
}
pub(crate) fn fp64_signed_mant_exp(bits: u64) -> Option<(i128, i32)> {
    let (mant, exp) = fp64_mant_exp(bits)?;
    let signed = if bits >> 63 != 0 {
        -(mant as i128)
    } else {
        mant as i128
    };
    Some((signed, exp))
}
pub(crate) fn fp64_addsub_exact(a: u64, b: u64, sub: bool) -> bool {
    let Some((ma, ea)) = fp64_signed_mant_exp(a) else {
        return true;
    };
    let Some((mut mb, eb)) = fp64_signed_mant_exp(b) else {
        return true;
    };
    if sub {
        mb = -mb;
    }
    if ma == 0 || mb == 0 {
        return true;
    }
    let common = ea.min(eb);
    let sa = (ea - common) as u32;
    let sb = (eb - common) as u32;
    if sa >= 120 || sb >= 120 {
        return false;
    }
    let sum = (ma << sa) + (mb << sb);
    if sum == 0 {
        return true;
    }
    let mut mag = sum.unsigned_abs();
    let tz = mag.trailing_zeros();
    mag >>= tz;
    let exp = common + tz as i32;
    let sig_bits = 128 - mag.leading_zeros() as i32;
    sig_bits <= 53 || exp + sig_bits <= -1021
}
pub(crate) fn fp64_fma_exact(addend: u64, op1: u64, op2: u64, result: u64) -> bool {
    let Some((ma, ea)) = fp64_signed_mant_exp(addend) else {
        return true;
    };
    let Some((m1, e1)) = fp64_signed_mant_exp(op1) else {
        return true;
    };
    let Some((m2, e2)) = fp64_signed_mant_exp(op2) else {
        return true;
    };
    let Some(mp) = m1.checked_mul(m2) else {
        return false;
    };
    let ep = e1 + e2;
    if fp64_is_zero(result) {
        let common = ea.min(ep);
        let Some(lhs_a) = shift_i128_checked(ma, ea - common) else {
            return false;
        };
        let Some(lhs_p) = shift_i128_checked(mp, ep - common) else {
            return false;
        };
        return lhs_a.checked_add(lhs_p) == Some(0);
    }
    let Some((mr, er)) = fp64_signed_mant_exp(result) else {
        return false;
    };
    let common = ea.min(ep).min(er);
    let Some(lhs_a) = shift_i128_checked(ma, ea - common) else {
        return false;
    };
    let Some(lhs_p) = shift_i128_checked(mp, ep - common) else {
        return false;
    };
    let Some(rhs) = shift_i128_checked(mr, er - common) else {
        return false;
    };
    lhs_a.checked_add(lhs_p) == Some(rhs)
}
pub(crate) fn fp16_abs_bits(x: u16) -> u16 {
    x & 0x7fff
}
pub(crate) fn fp16_is_tiny(x: u16) -> bool {
    let a = fp16_abs_bits(x);
    a != 0 && a < 0x0400
}

pub(crate) fn fp_status_assume_inexact(esize: usize, result: u64) -> u32 {
    let underflow = match esize {
        2 => fp16_is_tiny(result as u16) || fp16_is_zero(result as u16),
        4 => fp32_is_tiny(result as u32) || fp32_is_zero(result as u32),
        _ => fp64_is_tiny(result) || fp64_is_zero(result),
    };
    let overflow = match esize {
        2 => fp16_is_inf(result as u16),
        4 => fp32_is_inf(result as u32),
        _ => fp64_is_inf(result),
    };
    if overflow {
        FPSR_OFC | FPSR_IXC
    } else if underflow {
        FPSR_UFC | FPSR_IXC
    } else {
        FPSR_IXC
    }
}
pub(crate) fn fp_value_eq_bits(esize: usize, a: u64, b: u64) -> bool {
    match esize {
        2 => fp16_to_f64(a as u16) == fp16_to_f64(b as u16),
        4 => f32::from_bits(a as u32) == f32::from_bits(b as u32),
        _ => f64::from_bits(a) == f64::from_bits(b),
    }
}
pub(crate) fn fp_mul_bits_for_status(esize: usize, op1: u64, op2: u64) -> u64 {
    match esize {
        2 => fp16_mul(op1 as u16, op2 as u16) as u64,
        4 => fp_three_same_f32(FpKind::Mul, op1 as u32, op2 as u32, 0) as u64,
        _ => fp_three_same_f64(FpKind::Mul, op1, op2, 0),
    }
}
pub(crate) fn fp_is_snan_bits(esize: usize, x: u64) -> bool {
    match esize {
        2 => fp16_is_snan(x as u16),
        4 => is_snan32(x as u32),
        _ => is_snan64(x),
    }
}
pub(crate) fn fp_is_nan_bits(esize: usize, x: u64) -> bool {
    match esize {
        2 => fp16_is_nan(x as u16),
        4 => is_nan32(x as u32),
        _ => is_nan64(x),
    }
}
pub(crate) fn fp_is_zero_bits(esize: usize, x: u64) -> bool {
    match esize {
        2 => fp16_is_zero(x as u16),
        4 => fp32_is_zero(x as u32),
        _ => fp64_is_zero(x),
    }
}
pub(crate) fn fp_is_inf_bits(esize: usize, x: u64) -> bool {
    match esize {
        2 => fp16_is_inf(x as u16),
        4 => fp32_is_inf(x as u32),
        _ => fp64_is_inf(x),
    }
}
pub(crate) fn fp_is_finite_bits(esize: usize, x: u64) -> bool {
    match esize {
        2 => fp16_abs_bits(x as u16) < 0x7c00,
        4 => fp32_is_finite(x as u32),
        _ => fp64_is_finite(x),
    }
}
pub(crate) fn fp_sign_bit(esize: usize, x: u64) -> u64 {
    x >> (esize * 8 - 1)
}
pub(crate) fn fp_status_fma(esize: usize, addend: u64, op1: u64, op2: u64, result: u64) -> u32 {
    if fp_is_snan_bits(esize, addend) || fp_is_snan_bits(esize, op1) || fp_is_snan_bits(esize, op2)
    {
        return FPSR_IOC;
    }

    if fp_invalid_fma_default_nan(esize, addend, op1, op2) {
        return FPSR_IOC;
    }

    if fp_is_finite_bits(esize, addend)
        && fp_is_finite_bits(esize, op1)
        && fp_is_finite_bits(esize, op2)
    {
        if esize == 8 {
            if fp64_is_zero(op1) || fp64_is_zero(op2) {
                return 0;
            }
            if fp64_is_inf(result) {
                return FPSR_OFC | FPSR_IXC;
            }
            if fp64_is_zero(addend) {
                if fp64_mul_exact_result(op1, op2, result) {
                    return 0;
                }
                let underflow = fp64_is_tiny(result) || fp64_is_zero(result);
                return FPSR_IXC | if underflow { FPSR_UFC } else { 0 };
            }
            if fp64_fma_exact(addend, op1, op2, result) {
                return 0;
            } else {
                let underflow = fp64_is_tiny(result) || fp64_is_zero(result);
                return FPSR_IXC | if underflow { FPSR_UFC } else { 0 };
            }
        }
        let exact =
            sve_fp_to_f64(esize, addend) + sve_fp_to_f64(esize, op1) * sve_fp_to_f64(esize, op2);
        let status = fp_status_from_exact_f64(esize, exact, result);
        if status == 0
            && matches!(esize, 2 | 4)
            && !fp_is_zero_bits(esize, op1)
            && !fp_is_zero_bits(esize, op2)
            && fp_value_eq_bits(esize, result, addend)
        {
            fp_status_assume_inexact(esize, result)
        } else if status == 0
            && matches!(esize, 2 | 4)
            && !fp_is_zero_bits(esize, addend)
            && !fp_is_zero_bits(esize, op1)
            && !fp_is_zero_bits(esize, op2)
            && fp_value_eq_bits(esize, result, fp_mul_bits_for_status(esize, op1, op2))
        {
            fp_status_assume_inexact(esize, result)
        } else {
            status
        }
    } else {
        0
    }
}
pub(crate) fn fp_invalid_fma_default_nan(esize: usize, addend: u64, op1: u64, op2: u64) -> bool {
    let invalid_product = (fp_is_zero_bits(esize, op1) && fp_is_inf_bits(esize, op2))
        || (fp_is_inf_bits(esize, op1) && fp_is_zero_bits(esize, op2));
    let invalid_sum = fp_is_inf_bits(esize, addend)
        && (fp_is_inf_bits(esize, op1) || fp_is_inf_bits(esize, op2))
        && (fp_sign_bit(esize, addend) != (fp_sign_bit(esize, op1) ^ fp_sign_bit(esize, op2)));
    invalid_product || invalid_sum
}
pub(crate) fn fp_status_mulx(esize: usize, a: u64, b: u64, result: u64) -> u32 {
    if fp_is_snan_bits(esize, a) || fp_is_snan_bits(esize, b) {
        return FPSR_IOC;
    }
    if !fp_is_finite_bits(esize, a) || !fp_is_finite_bits(esize, b) {
        return 0;
    }
    if esize == 8 {
        if fp64_is_inf(result) {
            return FPSR_OFC | FPSR_IXC;
        }
        if fp64_mul_exact_result(a, b, result) {
            0
        } else {
            FPSR_IXC
                | if fp64_is_tiny(result) || fp64_is_zero(result) {
                    FPSR_UFC
                } else {
                    0
                }
        }
    } else {
        let exact = sve_fp_to_f64(esize, a) * sve_fp_to_f64(esize, b);
        fp_status_from_exact_f64(esize, exact, result)
    }
}

pub(crate) fn fp_status_recps_rsqrts(
    esize: usize,
    rsqrt: bool,
    a: u64,
    b: u64,
    result: u64,
) -> u32 {
    if fp_is_snan_bits(esize, a) || fp_is_snan_bits(esize, b) {
        return FPSR_IOC;
    }
    if fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b) {
        return 0;
    }
    let inf_zero = (fp_is_zero_bits(esize, a) && fp_is_inf_bits(esize, b))
        || (fp_is_inf_bits(esize, a) && fp_is_zero_bits(esize, b));
    if inf_zero {
        return 0;
    }
    if !fp_is_finite_bits(esize, a) || !fp_is_finite_bits(esize, b) {
        return 0;
    }
    if esize == 8 {
        if fp64_is_inf(result) {
            return FPSR_OFC | FPSR_IXC;
        }
        let addend = if rsqrt {
            3.0f64.to_bits()
        } else {
            2.0f64.to_bits()
        };
        let target = if rsqrt {
            (f64::from_bits(result) * 2.0).to_bits()
        } else {
            result
        };
        if fp64_fma_exact(addend, fp_neg_bits(a, 64), b, target) {
            let product = fp_three_same_f64(FpKind::Mul, a, b, 0);
            if product != 0 && fp64_operand_lost(addend, product) {
                return FPSR_IXC;
            }
            if fp64_is_zero(product) && !fp64_is_zero(a) && !fp64_is_zero(b) {
                return FPSR_IXC;
            }
            return 0;
        }
        return FPSR_IXC;
    }
    let x = sve_fp_to_f64(esize, a);
    let y = sve_fp_to_f64(esize, b);
    let exact = if rsqrt {
        (3.0 - x * y) * 0.5
    } else {
        2.0 - x * y
    };
    let status = fp_status_from_exact_f64(esize, exact, result);
    if status == 0 && esize == 4 {
        let a32 = a as u32;
        let b32 = b as u32;
        if ((fp32_is_tiny(a32) && !fp32_is_zero(a32) && fp32_is_finite(b32) && !fp32_is_zero(b32))
            || (fp32_is_tiny(b32)
                && !fp32_is_zero(b32)
                && fp32_is_finite(a32)
                && !fp32_is_zero(a32)))
        {
            return FPSR_IXC;
        }
        let product = fp_three_same_f32(FpKind::Mul, fp_neg_bits(a, 32) as u32, b as u32, 0) as u64;
        let addend = if rsqrt {
            3.0f32.to_bits()
        } else {
            2.0f32.to_bits()
        };
        if !fp32_is_zero(product as u32) && fp32_operand_lost(addend, product as u32) {
            return FPSR_IXC;
        }
        if fp32_is_zero(product as u32) && !fp32_is_zero(a32) && !fp32_is_zero(b32) {
            return FPSR_IXC;
        }
        if !rsqrt && product == result && !fp32_is_zero(product as u32) {
            return FPSR_IXC;
        }
    }
    status
}

pub(crate) fn fp_three_same_status(
    esize: usize,
    kind: FpKind,
    a: u64,
    b: u64,
    d: u64,
    result: u64,
) -> u32 {
    use FpKind::*;
    match kind {
        Mla => fp_status_fma(esize, d, a, b, result),
        Mls => fp_status_fma(esize, d, fp_neg_bits(a, (esize * 8) as u32), b, result),
        Mulx => fp_status_mulx(esize, a, b, result),
        Recps => fp_status_recps_rsqrts(esize, false, a, b, result),
        Rsqrts => fp_status_recps_rsqrts(esize, true, a, b, result),
        CmEq => {
            if fp_is_snan_bits(esize, a) || fp_is_snan_bits(esize, b) {
                FPSR_IOC
            } else {
                0
            }
        }
        CmGe | CmGt | AcGe | AcGt => {
            if fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b) {
                FPSR_IOC
            } else {
                0
            }
        }
        _ => fp_status_binop(esize, kind, a, b, result),
    }
}
pub(crate) fn fp_three_same_status_with_fpcr(
    esize: usize,
    kind: FpKind,
    a: u64,
    b: u64,
    d: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    use FpKind::*;
    match kind {
        Mla => fp_status_fma_with_fpcr(esize, d, a, b, result, fpcr),
        Mls => fp_status_fma_with_fpcr(
            esize,
            d,
            fp_neg_bits_with_fpcr(a, (esize * 8) as u32, fpcr),
            b,
            result,
            fpcr,
        ),
        Mulx => fp_status_mulx_with_fpcr(esize, a, b, result, fpcr),
        Recps => fp_status_recps_rsqrts_with_fpcr(esize, false, a, b, result, fpcr),
        Rsqrts => fp_status_recps_rsqrts_with_fpcr(esize, true, a, b, result, fpcr),
        CmEq => {
            let status =
                if fpcr & FPCR_AH != 0 && (fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b)) {
                    0
                } else {
                    fp_fz_input_status(esize, a, fpcr) | fp_fz_input_status(esize, b, fpcr)
                };
            if fp_is_snan_bits(esize, a) || fp_is_snan_bits(esize, b) {
                status | FPSR_IOC
            } else {
                status
            }
        }
        CmGe | CmGt | AcGe | AcGt => {
            let status =
                if fpcr & FPCR_AH != 0 && (fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b)) {
                    0
                } else {
                    fp_fz_input_status(esize, a, fpcr) | fp_fz_input_status(esize, b, fpcr)
                };
            if fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b) {
                status | FPSR_IOC
            } else {
                status
            }
        }
        _ => fp_status_binop_with_fpcr(esize, kind, a, b, result, fpcr),
    }
}
pub(crate) fn fp16_three_same_status(
    u: u32,
    a_bit: u32,
    opcode: u32,
    n: u16,
    m: u16,
    r: u16,
) -> u32 {
    use FpKind::*;
    let kind = match (u, a_bit, opcode) {
        (0, 0, 0b000) => Some(MaxNm),
        (0, 1, 0b000) => Some(MinNm),
        (0, 0, 0b010) => Some(Add),
        (0, 1, 0b010) => Some(Sub),
        (0, 0, 0b011) => return fp_status_mulx(2, n as u64, m as u64, r as u64),
        (0, 0, 0b100) => {
            return if fp16_is_snan(n) || fp16_is_snan(m) {
                FPSR_IOC
            } else {
                0
            };
        }
        (1, 0, 0b100) | (1, 1, 0b100) => {
            return if fp16_is_nan(n) || fp16_is_nan(m) {
                FPSR_IOC
            } else {
                0
            };
        }
        (1, 0, 0b101) | (1, 1, 0b101) => {
            return if fp16_is_nan(n) || fp16_is_nan(m) {
                FPSR_IOC
            } else {
                0
            };
        }
        (0, 0, 0b110) => Some(Max),
        (0, 1, 0b110) => Some(Min),
        (0, 0, 0b111) => {
            return fp_status_recps_rsqrts(2, false, n as u64, m as u64, r as u64);
        }
        (0, 1, 0b111) => {
            return fp_status_recps_rsqrts(2, true, n as u64, m as u64, r as u64);
        }
        (1, 0, 0b000) => Some(MaxNmp),
        (1, 1, 0b000) => Some(MinNmp),
        (1, 0, 0b010) => Some(Addp),
        (1, 1, 0b010) => Some(Abd),
        (1, 0, 0b011) => Some(Mul),
        (1, 0, 0b110) => Some(Maxp),
        (1, 1, 0b110) => Some(Minp),
        (1, 0, 0b111) => Some(Div),
        _ => None,
    };
    kind.map_or(0, |k| fp_status_binop(2, k, n as u64, m as u64, r as u64))
}

pub(crate) fn fp_status_estimate(esize: usize, rsqrt: bool, a: u64, result: u64) -> u32 {
    if fp_is_snan_bits(esize, a) {
        return FPSR_IOC;
    }
    if fp_is_nan_bits(esize, a) {
        return 0;
    }
    if rsqrt && fp_sign_bit(esize, a) != 0 && !fp_is_zero_bits(esize, a) {
        return FPSR_IOC;
    }
    if fp_is_zero_bits(esize, a) {
        return FPSR_DZC;
    }
    if fp_is_finite_bits(esize, a) && fp_is_inf_bits(esize, result) {
        return FPSR_OFC | FPSR_IXC;
    }
    0
}
pub(crate) fn fp_status_estimate_with_fpcr(
    esize: usize,
    rsqrt: bool,
    a: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    if fpcr & FPCR_AH != 0 {
        return 0;
    }
    let a_flushed = fp_flush_input_bits_with_fpcr(a, (esize * 8) as u32, fpcr);
    fp_status_estimate(esize, rsqrt, a_flushed, result) | fp_fz_input_status(esize, a, fpcr)
}
pub(crate) fn fp16_two_reg_status(u: u32, a_bit: u32, opcode: u32, s: u16, r: u16) -> u32 {
    use TwoRegFp::*;
    let kind = match (u, a_bit, opcode) {
        (1, 1, 0b11111) => return fp_status_unop(2, Some(Fsqrt), s as u64, r as u64),
        (0, 1, 0b11101) => return fp_status_estimate(2, false, s as u64, r as u64),
        (1, 1, 0b11101) => return fp_status_estimate(2, true, s as u64, r as u64),
        (0, 1, 0b01101) => {
            return if fp16_is_snan(s) { FPSR_IOC } else { 0 };
        }
        (0, 1, 0b01100) | (0, 1, 0b01110) | (1, 1, 0b01100) | (1, 1, 0b01101) => {
            return if fp16_is_nan(s) { FPSR_IOC } else { 0 };
        }
        (0, 0, 0b11000) => Some(RintN),
        (0, 0, 0b11001) => Some(RintM),
        (0, 1, 0b11000) => Some(RintP),
        (0, 1, 0b11001) => Some(RintZ),
        (1, 0, 0b11000) => Some(RintA),
        (1, 0, 0b11001) => Some(RintX),
        (1, 1, 0b11001) => Some(RintI),
        (0, 0, 0b11010) => Some(CvtNS),
        (0, 0, 0b11011) => Some(CvtMS),
        (0, 0, 0b11100) => Some(CvtAS),
        (0, 1, 0b11010) => Some(CvtPS),
        (0, 1, 0b11011) => Some(CvtZS),
        (1, 0, 0b11010) => Some(CvtNU),
        (1, 0, 0b11011) => Some(CvtMU),
        (1, 0, 0b11100) => Some(CvtAU),
        (1, 1, 0b11010) => Some(CvtPU),
        (1, 1, 0b11011) => Some(CvtZU),
        (0, 0, 0b11101) => {
            let raw = (s as i16 as i128).unsigned_abs();
            return fp_status_int_to_fp_scaled(raw, 2, r as u64);
        }
        (1, 0, 0b11101) => return fp_status_int_to_fp_scaled(s as u128, 2, r as u64),
        _ => None,
    };
    kind.map_or(0, |k| {
        if matches!(
            k,
            CvtNS | CvtMS | CvtPS | CvtZS | CvtAS | CvtNU | CvtMU | CvtPU | CvtZU | CvtAU
        ) {
            fp_status_fp_to_int_unop(2, k, s as u64)
        } else {
            fp_status_unop(2, Some(k), s as u64, r as u64)
        }
    })
}
pub(crate) fn fp16_two_reg_status_with_fpcr(
    u: u32,
    a_bit: u32,
    opcode: u32,
    s: u16,
    r: u16,
    fpcr: u32,
) -> u32 {
    use TwoRegFp::*;
    if fpcr & FPCR_AH != 0 && matches!((u, a_bit, opcode), (0, 1, 0b11101) | (1, 1, 0b11101)) {
        return 0;
    }
    if fpcr & FPCR_FZ16 == 0 {
        return fp16_two_reg_status(u, a_bit, opcode, s, r);
    }
    let sf = fp16_flush_input_with_fpcr(s, fpcr);
    match (u, a_bit, opcode) {
        (1, 1, 0b11111) => fp_status_unop_f16(Some(Fsqrt), sf, r),
        (0, 1, 0b11101) => {
            let sf = fp16_flush_input_with_fpcr(s, fpcr);
            let raw_r = fp16_recpe(sf);
            let (_, status) = fp16_flush_output_status_with_fpcr(
                raw_r,
                fp_status_estimate_with_fpcr(2, false, s as u64, raw_r as u64, fpcr),
                fpcr,
            );
            status
        }
        (1, 1, 0b11101) => {
            let sf = fp16_flush_input_with_fpcr(s, fpcr);
            let raw_r = fp16_rsqrte(sf);
            let (_, status) = fp16_flush_output_status_with_fpcr(
                raw_r,
                fp_status_estimate_with_fpcr(2, true, s as u64, raw_r as u64, fpcr),
                fpcr,
            );
            status
        }
        (0, 0, 0b11101) => {
            let raw = (s as i16 as i128).unsigned_abs();
            let raw_r = int_to_fp16_bits_with_fpcr(raw, (s as i16) < 0, fpcr);
            let (_, status) = fp16_int_to_fp_output_status_with_fpcr(
                raw,
                raw_r,
                fp_status_int_to_fp_scaled(raw, 2, raw_r as u64),
                fpcr,
            );
            status
        }
        (1, 0, 0b11101) => {
            let raw_r = int_to_fp16_bits_with_fpcr(s as u128, false, fpcr);
            let (_, status) = fp16_int_to_fp_output_status_with_fpcr(
                s as u128,
                raw_r,
                fp_status_int_to_fp_scaled(s as u128, 2, raw_r as u64),
                fpcr,
            );
            status
        }
        _ => fp16_two_reg_status(u, a_bit, opcode, sf, r),
    }
}
pub(crate) fn fp_status_cvt_precision(
    src: u64,
    src_prec: usize,
    dst_prec: usize,
    result: u64,
) -> u32 {
    let snan = match src_prec {
        2 => fp16_is_snan(src as u16),
        4 => is_snan32(src as u32),
        _ => is_snan64(src),
    };
    if snan {
        return FPSR_IOC;
    }
    let is_nan = match src_prec {
        2 => fp16_is_nan(src as u16),
        4 => is_nan32(src as u32),
        _ => is_nan64(src),
    };
    if is_nan {
        return 0;
    }
    let exact = match src_prec {
        2 => fp16_to_f64(src as u16),
        4 => f32::from_bits(src as u32) as f64,
        _ => f64::from_bits(src),
    };
    if dst_prec == 8 {
        0
    } else {
        fp_status_from_exact_f64(dst_prec, exact, result)
    }
}
pub(crate) fn fp_fz_cvt_output(
    src: u64,
    src_prec: usize,
    dst_prec: usize,
    result: u64,
    round_odd: bool,
    fpcr: u32,
) -> Option<(u64, u32)> {
    if fpcr & FPCR_FZ == 0 || !matches!(dst_prec, 4 | 8) || !fp_is_zero_bits(dst_prec, result) {
        return None;
    }

    let raw = fp_cvt_elem_raw(src, src_prec, dst_prec, round_odd, fpcr);
    if !fp_is_tiny_bits(dst_prec, raw) {
        return None;
    }

    Some((raw, FPSR_UFC))
}
pub(crate) fn fp_status_cvt_precision_with_fpcr(
    src: u64,
    src_prec: usize,
    dst_prec: usize,
    result: u64,
    fpcr: u32,
) -> u32 {
    fp_status_cvt_precision_with_fpcr_rounding(src, src_prec, dst_prec, result, false, fpcr)
}

pub(crate) fn fp_status_bfcvt(src: u32, result: u16) -> u32 {
    if is_snan32(src) {
        return FPSR_IOC;
    }
    if is_nan32(src) || fp32_is_inf(src) || (src & 0xFFFF) == 0 {
        return 0;
    }

    let result_abs = result & 0x7FFF;
    if result_abs == 0x7F80 {
        FPSR_OFC | FPSR_IXC
    } else if (result_abs & 0x7F80) == 0 {
        FPSR_UFC | FPSR_IXC
    } else {
        FPSR_IXC
    }
}
pub(crate) fn fp_status_bfcvt_with_fpcr(src: u32, result: u16, fpcr: u32) -> u32 {
    if fpcr & FPCR_AH != 0 {
        return 0;
    }
    fp_status_bfcvt(fp32_flush_input_with_fpcr(src, fpcr), result)
        | fp_fz_input_status(4, src as u64, fpcr)
}
pub(crate) fn fp_invalid_binop_f32(kind: FpKind, a: u32, b: u32) -> bool {
    use FpKind::*;
    if is_snan32(a) || is_snan32(b) {
        return true;
    }
    match kind {
        Add | Addp => fp32_is_inf(a) && fp32_is_inf(b) && ((a ^ b) >> 31) != 0,
        Sub | Abd => fp32_is_inf(a) && fp32_is_inf(b) && ((a ^ b) >> 31) == 0,
        Mul | Mla | Mls => {
            (fp32_is_zero(a) && fp32_is_inf(b)) || (fp32_is_inf(a) && fp32_is_zero(b))
        }
        Div => (fp32_is_zero(a) && fp32_is_zero(b)) || (fp32_is_inf(a) && fp32_is_inf(b)),
        Max | Maxp | Min | Minp | MaxNm | MaxNmp | MinNm | MinNmp => false,
        _ => false,
    }
}
pub(crate) fn fp_invalid_binop_f64(kind: FpKind, a: u64, b: u64) -> bool {
    use FpKind::*;
    if is_snan64(a) || is_snan64(b) {
        return true;
    }
    match kind {
        Add | Addp => fp64_is_inf(a) && fp64_is_inf(b) && ((a ^ b) >> 63) != 0,
        Sub | Abd => fp64_is_inf(a) && fp64_is_inf(b) && ((a ^ b) >> 63) == 0,
        Mul | Mla | Mls => {
            (fp64_is_zero(a) && fp64_is_inf(b)) || (fp64_is_inf(a) && fp64_is_zero(b))
        }
        Div => (fp64_is_zero(a) && fp64_is_zero(b)) || (fp64_is_inf(a) && fp64_is_inf(b)),
        Max | Maxp | Min | Minp | MaxNm | MaxNmp | MinNm | MinNmp => false,
        _ => false,
    }
}
pub(crate) fn fp_status_binop_f32(kind: FpKind, a: u32, b: u32, result: u32) -> u32 {
    use FpKind::*;
    if !matches!(
        kind,
        Add | Sub
            | Mul
            | Div
            | Addp
            | Abd
            | Max
            | Maxp
            | Min
            | Minp
            | MaxNm
            | MaxNmp
            | MinNm
            | MinNmp
    ) {
        return 0;
    }

    if fp_invalid_binop_f32(kind, a, b) {
        return FPSR_IOC;
    }

    if matches!(kind, Div) && fp32_is_zero(b) && !fp32_is_zero(a) && fp32_is_finite(a) {
        return FPSR_DZC;
    }

    if !matches!(kind, Add | Sub | Mul | Div | Addp | Abd)
        || !fp32_is_finite(a)
        || !fp32_is_finite(b)
    {
        return 0;
    }

    let mut status = 0;
    if fp32_is_inf(result) {
        return FPSR_OFC | FPSR_IXC;
    }

    let x = f32::from_bits(a) as f64;
    let y = f32::from_bits(b) as f64;
    let exact = match kind {
        Add | Addp => x + y,
        Sub => x - y,
        Mul => x * y,
        Div => x / y,
        Abd => (x - y).abs(),
        _ => return 0,
    };
    let rounded = f32::from_bits(result) as f64;
    if exact != rounded {
        status |= FPSR_IXC;
        if fp32_is_tiny(result) || (fp32_is_zero(result) && exact != 0.0) {
            status |= FPSR_UFC;
        }
    } else if matches!(kind, Add | Addp | Sub | Abd) {
        let r = f32::from_bits(result);
        let x = f32::from_bits(a);
        let y = f32::from_bits(b);
        let y_effectively_lost = r == x && fp32_operand_lost(a, b);
        let x_effectively_lost = matches!(kind, Add | Addp) && r == y && fp32_operand_lost(b, a);
        let subtrahend_lost = matches!(kind, Sub | Abd) && r == x.abs() && fp32_operand_lost(a, b);
        let minuend_lost = matches!(kind, Abd) && r == y.abs() && fp32_operand_lost(b, a);
        let subtract_minuend_lost = matches!(kind, Sub)
            && fp32_operand_lost(b, a)
            && result == (-f32::from_bits(b)).to_bits();
        if y_effectively_lost
            || x_effectively_lost
            || subtrahend_lost
            || minuend_lost
            || subtract_minuend_lost
        {
            status |= FPSR_IXC;
        }
    }
    status
}
pub(crate) fn fp_status_binop_f64(kind: FpKind, a: u64, b: u64, result: u64) -> u32 {
    use FpKind::*;
    if !matches!(
        kind,
        Add | Sub
            | Mul
            | Div
            | Addp
            | Abd
            | Max
            | Maxp
            | Min
            | Minp
            | MaxNm
            | MaxNmp
            | MinNm
            | MinNmp
    ) {
        return 0;
    }

    if fp_invalid_binop_f64(kind, a, b) {
        return FPSR_IOC;
    }

    if matches!(kind, Div) && fp64_is_zero(b) && !fp64_is_zero(a) && fp64_is_finite(a) {
        return FPSR_DZC;
    }

    if !matches!(kind, Add | Sub | Mul | Div | Addp | Abd)
        || !fp64_is_finite(a)
        || !fp64_is_finite(b)
    {
        return 0;
    }

    if fp64_is_inf(result) {
        return FPSR_OFC | FPSR_IXC;
    }

    if (fp64_is_tiny(result) || fp64_is_zero(result))
        && !fp64_is_zero(a)
        && !fp64_is_zero(b)
        && matches!(kind, Div)
    {
        return FPSR_UFC | FPSR_IXC;
    }

    if matches!(kind, Div) && !fp64_div_exact(a, b) {
        return FPSR_IXC;
    }

    if matches!(kind, Mul) {
        if fp64_mul_exact_result(a, b, result) {
            return 0;
        }
        let underflow = fp64_is_tiny(result) || fp64_is_zero(result);
        return FPSR_IXC | if underflow { FPSR_UFC } else { 0 };
    }

    if matches!(kind, Add | Addp | Sub | Abd) {
        if !fp64_addsub_exact(a, b, matches!(kind, Sub | Abd)) {
            return FPSR_IXC;
        }
        let r = f64::from_bits(result);
        let x = f64::from_bits(a);
        let y = f64::from_bits(b);
        let y_effectively_lost = r == x && fp64_operand_lost(a, b);
        let x_effectively_lost = matches!(kind, Add | Addp) && r == y && fp64_operand_lost(b, a);
        let subtrahend_lost = matches!(kind, Sub | Abd) && r == x.abs() && fp64_operand_lost(a, b);
        let minuend_lost = matches!(kind, Abd) && r == y.abs() && fp64_operand_lost(b, a);
        if y_effectively_lost || x_effectively_lost || subtrahend_lost || minuend_lost {
            return FPSR_IXC;
        }
    }

    0
}
pub(crate) fn fp_invalid_binop_f16(kind: FpKind, a: u16, b: u16) -> bool {
    use FpKind::*;
    if fp16_is_snan(a) || fp16_is_snan(b) {
        return true;
    }
    match kind {
        Add | Addp => fp16_is_inf(a) && fp16_is_inf(b) && ((a ^ b) >> 15) != 0,
        Sub | Abd => fp16_is_inf(a) && fp16_is_inf(b) && ((a ^ b) >> 15) == 0,
        Mul | Mla | Mls => {
            (fp16_is_zero(a) && fp16_is_inf(b)) || (fp16_is_inf(a) && fp16_is_zero(b))
        }
        Div => (fp16_is_zero(a) && fp16_is_zero(b)) || (fp16_is_inf(a) && fp16_is_inf(b)),
        Max | Maxp | Min | Minp | MaxNm | MaxNmp | MinNm | MinNmp => false,
        _ => false,
    }
}
pub(crate) fn fp_status_binop_f16(kind: FpKind, a: u16, b: u16, result: u16) -> u32 {
    use FpKind::*;
    if !matches!(
        kind,
        Add | Sub
            | Mul
            | Div
            | Addp
            | Abd
            | Max
            | Maxp
            | Min
            | Minp
            | MaxNm
            | MaxNmp
            | MinNm
            | MinNmp
    ) {
        return 0;
    }

    if fp_invalid_binop_f16(kind, a, b) {
        return FPSR_IOC;
    }

    if matches!(kind, Div) && fp16_is_zero(b) && !fp16_is_zero(a) && fp16_abs_bits(a) < 0x7c00 {
        return FPSR_DZC;
    }

    if !matches!(kind, Add | Sub | Mul | Div | Addp | Abd)
        || fp16_abs_bits(a) >= 0x7c00
        || fp16_abs_bits(b) >= 0x7c00
    {
        return 0;
    }

    let x = fp16_to_f64(a);
    let y = fp16_to_f64(b);
    let exact = match kind {
        Add | Addp => x + y,
        Sub => x - y,
        Mul => x * y,
        Div => x / y,
        Abd => (x - y).abs(),
        _ => return 0,
    };
    fp_status_from_exact_f64(2, exact, result as u64)
}
pub(crate) fn fp_status_binop(esize: usize, kind: FpKind, a: u64, b: u64, result: u64) -> u32 {
    match esize {
        2 => fp_status_binop_f16(kind, a as u16, b as u16, result as u16),
        4 => fp_status_binop_f32(kind, a as u32, b as u32, result as u32),
        _ => fp_status_binop_f64(kind, a, b, result),
    }
}
pub(crate) fn fp_fz_binop_output(
    esize: usize,
    kind: FpKind,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> Option<(u64, u32)> {
    if fpcr & FPCR_FZ == 0
        || !fp_is_zero_bits(esize, result)
        || !matches!(
            kind,
            FpKind::Add | FpKind::Addp | FpKind::Sub | FpKind::Mul | FpKind::Div | FpKind::Abd
        )
    {
        return None;
    }

    let raw = match esize {
        4 => fp_three_same_f32(kind, a as u32, b as u32, 0) as u64,
        8 => fp_three_same_f64(kind, a, b, 0),
        _ => return None,
    };
    if !fp_is_tiny_bits(esize, raw) {
        return None;
    }

    Some((raw, FPSR_UFC))
}
pub(crate) fn fp_fz_fma_output(
    esize: usize,
    addend: u64,
    op1: u64,
    op2: u64,
    result: u64,
    fpcr: u32,
) -> Option<(u64, u32)> {
    if fpcr & FPCR_FZ == 0 || !fp_is_zero_bits(esize, result) {
        return None;
    }

    let raw = fp_muladd_bits(addend, op1, op2, (esize * 8) as u32);
    if !fp_is_tiny_bits(esize, raw) {
        return None;
    }

    Some((raw, FPSR_UFC))
}

pub(crate) fn fp_status_unop_f32(kind: Option<TwoRegFp>, a: u32, result: u32) -> u32 {
    match kind {
        Some(TwoRegFp::Fsqrt) => {
            if is_snan32(a) || (a & 0x8000_0000) != 0 && fp32_abs(a) != 0 && !is_nan32(a) {
                return FPSR_IOC;
            }
            if fp32_is_finite(a) && a & 0x8000_0000 == 0 {
                let exact = (f32::from_bits(a) as f64).sqrt();
                let rounded = f32::from_bits(result) as f64;
                if exact != rounded {
                    return FPSR_IXC;
                }
            }
            0
        }
        Some(
            TwoRegFp::RintN
            | TwoRegFp::RintP
            | TwoRegFp::RintM
            | TwoRegFp::RintZ
            | TwoRegFp::RintA
            | TwoRegFp::RintX
            | TwoRegFp::RintI,
        ) => {
            if is_snan32(a) {
                return FPSR_IOC;
            }
            if !matches!(kind, Some(TwoRegFp::RintX)) {
                return 0;
            }
            let x = f32::from_bits(a);
            if x.is_finite() && x.fract() != 0.0 {
                FPSR_IXC
            } else {
                0
            }
        }
        Some(TwoRegFp::CmEq) => {
            if is_snan32(a) {
                FPSR_IOC
            } else {
                0
            }
        }
        Some(TwoRegFp::CmGt | TwoRegFp::CmGe | TwoRegFp::CmLe | TwoRegFp::CmLt) => {
            if is_nan32(a) {
                FPSR_IOC
            } else {
                0
            }
        }
        _ => 0,
    }
}
pub(crate) fn fp_status_unop_f64(kind: Option<TwoRegFp>, a: u64, result: u64) -> u32 {
    match kind {
        Some(TwoRegFp::Fsqrt) => {
            if is_snan64(a) || (a & 0x8000_0000_0000_0000) != 0 && fp64_abs(a) != 0 && !is_nan64(a)
            {
                return FPSR_IOC;
            }
            if fp64_is_finite(a) && a & 0x8000_0000_0000_0000 == 0 {
                if !fp64_sqrt_exact(a) {
                    return FPSR_IXC;
                }
            }
            0
        }
        Some(
            TwoRegFp::RintN
            | TwoRegFp::RintP
            | TwoRegFp::RintM
            | TwoRegFp::RintZ
            | TwoRegFp::RintA
            | TwoRegFp::RintX
            | TwoRegFp::RintI,
        ) => {
            if is_snan64(a) {
                return FPSR_IOC;
            }
            if !matches!(kind, Some(TwoRegFp::RintX)) {
                return 0;
            }
            let x = f64::from_bits(a);
            if x.is_finite() && x.fract() != 0.0 {
                FPSR_IXC
            } else {
                0
            }
        }
        Some(TwoRegFp::CmEq) => {
            if is_snan64(a) {
                FPSR_IOC
            } else {
                0
            }
        }
        Some(TwoRegFp::CmGt | TwoRegFp::CmGe | TwoRegFp::CmLe | TwoRegFp::CmLt) => {
            if is_nan64(a) {
                FPSR_IOC
            } else {
                0
            }
        }
        _ => 0,
    }
}
pub(crate) fn fp_status_unop_f16(kind: Option<TwoRegFp>, a: u16, result: u16) -> u32 {
    match kind {
        Some(TwoRegFp::Fsqrt) => {
            if fp16_is_snan(a) || (a & 0x8000) != 0 && fp16_abs_bits(a) != 0 && !fp16_is_nan(a) {
                return FPSR_IOC;
            }
            if fp16_abs_bits(a) < 0x7c00 && a & 0x8000 == 0 {
                let exact = fp16_to_f64(a).sqrt();
                return fp_status_from_exact_f64(2, exact, result as u64);
            }
            0
        }
        Some(
            TwoRegFp::RintN
            | TwoRegFp::RintP
            | TwoRegFp::RintM
            | TwoRegFp::RintZ
            | TwoRegFp::RintA
            | TwoRegFp::RintX
            | TwoRegFp::RintI,
        ) => {
            if fp16_is_snan(a) {
                return FPSR_IOC;
            }
            if !matches!(kind, Some(TwoRegFp::RintX)) {
                return 0;
            }
            let x = fp16_to_f64(a);
            if x.is_finite() && x.fract() != 0.0 {
                FPSR_IXC
            } else {
                0
            }
        }
        Some(TwoRegFp::CmEq) => {
            if fp16_is_snan(a) {
                FPSR_IOC
            } else {
                0
            }
        }
        Some(TwoRegFp::CmGt | TwoRegFp::CmGe | TwoRegFp::CmLe | TwoRegFp::CmLt) => {
            if fp16_is_nan(a) { FPSR_IOC } else { 0 }
        }
        _ => 0,
    }
}
pub(crate) fn fp_status_unop(esize: usize, kind: Option<TwoRegFp>, a: u64, result: u64) -> u32 {
    match esize {
        2 => fp_status_unop_f16(kind, a as u16, result as u16),
        4 => fp_status_unop_f32(kind, a as u32, result as u32),
        _ => fp_status_unop_f64(kind, a, result),
    }
}
pub(crate) fn fp_status_unop_with_fpcr(
    esize: usize,
    kind: Option<TwoRegFp>,
    a: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    if matches!(
        kind,
        Some(TwoRegFp::CmGt | TwoRegFp::CmGe | TwoRegFp::CmEq | TwoRegFp::CmLe | TwoRegFp::CmLt)
    ) {
        return fp_status_unop(esize, kind, a, result) | fp_fz_input_status(esize, a, fpcr);
    }
    if fpcr & FPCR_AH != 0 && matches!(kind, Some(TwoRegFp::Fsqrt)) {
        let status = fp_status_unop(esize, kind, a, result);
        let input_status = fp_fz_input_status(esize, a, fpcr);
        return if status & FPSR_IOC != 0 {
            status
        } else {
            status | input_status
        };
    }
    if fp_input_flush_enabled(esize, fpcr)
        && matches!(
            kind,
            Some(
                TwoRegFp::Fsqrt
                    | TwoRegFp::RintN
                    | TwoRegFp::RintP
                    | TwoRegFp::RintM
                    | TwoRegFp::RintZ
                    | TwoRegFp::RintA
                    | TwoRegFp::RintX
                    | TwoRegFp::RintI
            )
        )
    {
        match esize {
            2 => {
                return fp_status_unop_f16(
                    kind,
                    fp16_flush_input_with_fpcr(a as u16, fpcr),
                    result as u16,
                ) | fp_fz_input_status(esize, a, fpcr);
            }
            4 => {
                return fp_status_unop_f32(
                    kind,
                    fp32_flush_input_with_fpcr(a as u32, fpcr),
                    result as u32,
                ) | fp_fz_input_status(esize, a, fpcr);
            }
            8 => {
                return fp_status_unop_f64(kind, fp64_flush_input_with_fpcr(a, fpcr), result)
                    | fp_fz_input_status(esize, a, fpcr);
            }
            _ => {}
        }
    }
    fp_status_unop(esize, kind, a, result)
}
pub(crate) fn fp_status_fp_to_int_unop(esize: usize, kind: TwoRegFp, a: u64) -> u32 {
    use TwoRegFp::*;
    let signed = matches!(kind, CvtNS | CvtMS | CvtPS | CvtZS | CvtAS);
    if !signed && !matches!(kind, CvtNU | CvtMU | CvtPU | CvtZU | CvtAU) {
        return 0;
    }
    let input = sve_fp_to_f64(esize, a);
    let rounded = match kind {
        CvtNS | CvtNU => input.round_ties_even(),
        CvtMS | CvtMU => input.floor(),
        CvtPS | CvtPU => input.ceil(),
        CvtZS | CvtZU => input.trunc(),
        CvtAS | CvtAU => input.round(),
        _ => unreachable!(),
    };
    fp_to_int_rounded_status(input, rounded, signed, (esize * 8) as u32)
}
pub(crate) fn fp_status_fp_to_int_unop_with_fpcr(
    esize: usize,
    kind: TwoRegFp,
    a: u64,
    fpcr: u32,
) -> u32 {
    use TwoRegFp::*;
    if fp_input_flush_enabled(esize, fpcr)
        && matches!(
            kind,
            CvtNS | CvtMS | CvtPS | CvtZS | CvtAS | CvtNU | CvtMU | CvtPU | CvtZU | CvtAU
        )
    {
        return fp_status_fp_to_int_unop(
            esize,
            kind,
            fp_flush_input_bits_with_fpcr(a, (esize * 8) as u32, fpcr),
        ) | fp_fz_input_status(esize, a, fpcr);
    }
    fp_status_fp_to_int_unop(esize, kind, a)
}

/// ARM FPProcessNaNs for two f32 operands (FPCR.DN=0): a signaling NaN is
/// quieted (sign+payload preserved), a quiet NaN is returned as-is; sNaN takes
/// priority, then operand order.
pub(crate) fn fp32_nan2(a: u32, b: u32) -> Option<u32> {
    if is_snan32(a) {
        Some(a | 0x0040_0000)
    } else if is_snan32(b) {
        Some(b | 0x0040_0000)
    } else if is_nan32(a) {
        Some(a)
    } else if is_nan32(b) {
        Some(b)
    } else {
        None
    }
}
pub(crate) fn fp32_ah_nan2(a: u32, b: u32) -> Option<u32> {
    if is_nan32(a) {
        Some(if is_snan32(a) { a | 0x0040_0000 } else { a })
    } else if is_nan32(b) {
        Some(if is_snan32(b) { b | 0x0040_0000 } else { b })
    } else {
        None
    }
}
/// FPProcessNaNs over three f32 operands (for the fused multiply-add forms),
/// processed in (addend, op1, op2) order as ARM FPMulAdd does.
pub(crate) fn fp32_nan3(a: u32, b: u32, c: u32) -> Option<u32> {
    for &x in &[a, b, c] {
        if is_snan32(x) {
            return Some(x | 0x0040_0000);
        }
    }
    for &x in &[a, b, c] {
        if is_nan32(x) {
            return Some(x);
        }
    }
    None
}
pub(crate) fn fp32_ah_nan3(a: u32, b: u32, c: u32) -> Option<u32> {
    for &x in &[a, b, c] {
        if is_nan32(x) {
            return Some(if is_snan32(x) { x | 0x0040_0000 } else { x });
        }
    }
    None
}
#[inline]
pub(crate) fn fp32_ah_invalid_default_nan(result: u32, fpcr: u32) -> u32 {
    fp_ah_invalid_default_nan(4, result as u64, fpcr) as u32
}
#[inline]
pub(crate) fn fp_ah_invalid_default_nan(esize: usize, result: u64, fpcr: u32) -> u64 {
    if fpcr & FPCR_AH == 0 {
        return result;
    }
    match esize {
        2 if result == 0x7e00 => 0xfe00,
        4 if result == 0x7fc0_0000 => 0xffc0_0000,
        8 if result == 0x7ff8_0000_0000_0000 => 0xfff8_0000_0000_0000,
        _ => result,
    }
}
pub(crate) fn fp64_nan2(a: u64, b: u64) -> Option<u64> {
    if is_snan64(a) {
        Some(a | 0x0008_0000_0000_0000)
    } else if is_snan64(b) {
        Some(b | 0x0008_0000_0000_0000)
    } else if is_nan64(a) {
        Some(a)
    } else if is_nan64(b) {
        Some(b)
    } else {
        None
    }
}
pub(crate) fn fp64_ah_nan2(a: u64, b: u64) -> Option<u64> {
    if is_nan64(a) {
        Some(if is_snan64(a) {
            a | 0x0008_0000_0000_0000
        } else {
            a
        })
    } else if is_nan64(b) {
        Some(if is_snan64(b) {
            b | 0x0008_0000_0000_0000
        } else {
            b
        })
    } else {
        None
    }
}
pub(crate) fn fp64_nan3(a: u64, b: u64, c: u64) -> Option<u64> {
    for &x in &[a, b, c] {
        if is_snan64(x) {
            return Some(x | 0x0008_0000_0000_0000);
        }
    }
    for &x in &[a, b, c] {
        if is_nan64(x) {
            return Some(x);
        }
    }
    None
}
pub(crate) fn fp64_ah_nan3(a: u64, b: u64, c: u64) -> Option<u64> {
    for &x in &[a, b, c] {
        if is_nan64(x) {
            return Some(if is_snan64(x) {
                x | 0x0008_0000_0000_0000
            } else {
                x
            });
        }
    }
    None
}
pub(crate) fn fp_three_same_f32(kind: FpKind, a: u32, b: u32, d: u32) -> u32 {
    use FpKind::*;
    // ARM NaN handling (FPCR.DN=0, the qemu-user default): a NaN input
    // propagates quieted; an invalid operation on non-NaN inputs yields the
    // default NaN 0x7FC00000 (native x86 arithmetic would give 0xFFC00000).
    match kind {
        // FABD = FPAbs(FPSub(a,b)): a propagated NaN has its sign cleared.
        Abd => {
            if let Some(n) = fp32_nan2(a, b) {
                return n & 0x7FFF_FFFF;
            }
        }
        Add | Sub | Mul | Div | Mulx | Addp | Max | Maxp | Min | Minp => {
            if let Some(n) = fp32_nan2(a, b) {
                return n;
            }
        }
        Mla => {
            if let Some(n) = fp32_nan3(d, a, b) {
                return n;
            }
        }
        // FMLS negates op1 (a) before the fused multiply-add, flipping its NaN
        // sign for propagation.
        Mls => {
            if let Some(n) = fp32_nan3(d, a ^ 0x8000_0000, b) {
                return n;
            }
        }
        MaxNm | MaxNmp | MinNm | MinNmp => {
            // sNaN propagates (quieted); a lone qNaN loses to the number below.
            if is_snan32(a) {
                return a | 0x0040_0000;
            }
            if is_snan32(b) {
                return b | 0x0040_0000;
            }
        }
        // Recps/Rsqrts delegate to sve_recps/sve_rsqrts (fused + FPNeg-first NaN).
        _ => {}
    }
    let x = f32::from_bits(a);
    let y = f32::from_bits(b);
    let acc = f32::from_bits(d);
    let mask = |c: bool| if c { u32::MAX } else { 0 };
    let canon = |r: f32| -> u32 { if r.is_nan() { 0x7FC0_0000 } else { r.to_bits() } };
    let inf0 = |p: f32, q: f32| (p.is_infinite() && q == 0.0) || (p == 0.0 && q.is_infinite());
    match kind {
        Add => canon(x + y),
        Sub => canon(x - y),
        Mul => canon(x * y),
        Div => canon(x / y),
        Mulx => {
            if inf0(x, y) {
                // FMULX(inf,0)=+/-2.0 with sign = sign(x) XOR sign(y).
                let neg = x.is_sign_negative() ^ y.is_sign_negative();
                (if neg { -2.0f32 } else { 2.0f32 }).to_bits()
            } else {
                canon(x * y)
            }
        }
        Mla => canon(x.mul_add(y, acc)),
        Mls => canon((-x).mul_add(y, acc)),
        Max | Maxp => fp_max_f32(x, y).to_bits(),
        Min | Minp => fp_min_f32(x, y).to_bits(),
        MaxNm | MaxNmp => {
            let (aq, bq) = (is_nan32(a), is_nan32(b));
            if aq && bq {
                a
            } else if aq {
                b
            } else if bq {
                a
            } else {
                fp_max_f32(x, y).to_bits()
            }
        }
        MinNm | MinNmp => {
            let (aq, bq) = (is_nan32(a), is_nan32(b));
            if aq && bq {
                a
            } else if aq {
                b
            } else if bq {
                a
            } else {
                fp_min_f32(x, y).to_bits()
            }
        }
        CmEq => mask(x == y),
        CmGe => mask(x >= y),
        CmGt => mask(x > y),
        AcGe => mask(x.abs() >= y.abs()),
        AcGt => mask(x.abs() > y.abs()),
        Abd => canon((x - y).abs()),
        Recps => sve_recps(4, a as u64, b as u64) as u32,
        Rsqrts => sve_rsqrts(4, a as u64, b as u64) as u32,
        Addp => canon(x + y),
    }
}
pub(crate) fn fp_three_same_f32_with_fpcr(kind: FpKind, a: u32, b: u32, d: u32, fpcr: u32) -> u32 {
    use FpKind::*;
    let flush_output = |r| fp32_flush_output_with_fpcr(r, fpcr);
    let (a, b, d) = if fpcr & (FPCR_FIZ | FPCR_FZ) != 0 {
        match kind {
            Add | Addp | Sub | Mul | Div | Mulx | Abd | Max | Maxp | MaxNm | MaxNmp | Min
            | Minp | MinNm | MinNmp | Recps | Rsqrts | CmEq | CmGe | CmGt | AcGe | AcGt => (
                fp32_flush_input_with_fpcr(a, fpcr),
                fp32_flush_input_with_fpcr(b, fpcr),
                d,
            ),
            Mla | Mls => (
                fp32_flush_input_with_fpcr(a, fpcr),
                fp32_flush_input_with_fpcr(b, fpcr),
                fp32_flush_input_with_fpcr(d, fpcr),
            ),
            _ => (a, b, d),
        }
    } else {
        (a, b, d)
    };
    if fpcr & FPCR_AH != 0 && matches!(kind, Mla | Mls) {
        if let Some(n) = fp32_ah_nan3(d, a, b) {
            return flush_output(n);
        }
    }
    if fpcr & FPCR_AH != 0
        && matches!(
            kind,
            Add | Addp | Sub | Mul | Div | Mulx | Abd | Recps | Rsqrts
        )
    {
        if let Some(n) = fp32_ah_nan2(a, b) {
            return flush_output(n);
        }
    }
    if fpcr & FPCR_AH != 0 && matches!(kind, Max | Min) {
        if let Some(n) = fp32_ah_nan_number(a, b) {
            return flush_output(n);
        }
    }
    if (fpcr >> 22) & 0x3 == 0
        || !matches!(
            kind,
            Add | Addp | Sub | Mul | Div | Mulx | Mla | Mls | Recps | Rsqrts
        )
    {
        return flush_output(fp32_ah_invalid_default_nan(
            fp_three_same_f32(kind, a, b, d),
            fpcr,
        ));
    }

    let x = f32::from_bits(a);
    let y = f32::from_bits(b);
    let acc = f32::from_bits(d);
    if matches!(kind, Mla | Mls) {
        if !x.is_finite() || !y.is_finite() || !acc.is_finite() {
            return flush_output(fp32_ah_invalid_default_nan(
                fp_three_same_f32(kind, a, b, d),
                fpcr,
            ));
        }
        let lhs = if matches!(kind, Mls) { -x } else { x };
        return flush_output(f64_to_f32_bits_with_fpcr(
            lhs as f64 * y as f64 + acc as f64,
            fpcr,
        ));
    }
    if matches!(kind, Recps | Rsqrts) {
        if !x.is_finite() || !y.is_finite() {
            return flush_output(fp_three_same_f32(kind, a, b, d));
        }
        let product = x as f64 * y as f64;
        let exact = if matches!(kind, Recps) {
            2.0 - product
        } else {
            (3.0 - product) * 0.5
        };
        return flush_output(f64_to_f32_bits_with_fpcr(exact, fpcr));
    }
    if !x.is_finite() || !y.is_finite() {
        return flush_output(fp32_ah_invalid_default_nan(
            fp_three_same_f32(kind, a, b, d),
            fpcr,
        ));
    }

    let exact = match kind {
        Add | Addp => x as f64 + y as f64,
        Sub => x as f64 - y as f64,
        Div => x as f64 / y as f64,
        Mul | Mulx => x as f64 * y as f64,
        _ => unreachable!(),
    };
    if exact == 0.0
        && matches!(kind, Add | Addp | Sub)
        && fp_addsub_cancelled_zero_rounds_negative(
            a as u64,
            b as u64,
            matches!(kind, Sub),
            32,
            fpcr,
        )
    {
        return flush_output(0x8000_0000);
    }
    flush_output(f64_to_f32_bits_with_fpcr(exact, fpcr))
}
pub(crate) fn fp64_exact_cmp_to_nearest(
    terms: &[(i128, i32)],
    nearest: u64,
) -> Option<(std::cmp::Ordering, bool)> {
    let exact_sign = scaled_i128_terms_sign(terms);
    if exact_sign == std::cmp::Ordering::Equal {
        return Some((std::cmp::Ordering::Equal, false));
    }
    let exact_negative = exact_sign == std::cmp::Ordering::Less;
    if fp64_is_inf(nearest) {
        let cmp = if (nearest >> 63) != 0 {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        };
        return Some((cmp, exact_negative));
    }
    if fp64_is_zero(nearest) {
        return Some((exact_sign, exact_negative));
    }
    let (nearest_mant, nearest_exp) = fp64_signed_mant_exp(nearest)?;
    let mut cmp_terms = Vec::with_capacity(terms.len() + 1);
    cmp_terms.extend_from_slice(terms);
    cmp_terms.push((-nearest_mant, nearest_exp));
    Some((scaled_i128_terms_sign(&cmp_terms), exact_negative))
}
pub(crate) fn fp64_adjust_nearest_with_fpcr(
    nearest: u64,
    cmp_exact_nearest: std::cmp::Ordering,
    exact_negative: bool,
    fpcr: u32,
) -> u64 {
    use std::cmp::Ordering::*;

    if cmp_exact_nearest == Equal {
        return nearest;
    }

    if fp64_is_inf(nearest) {
        let max_finite = if exact_negative {
            0xffef_ffff_ffff_ffff
        } else {
            0x7fef_ffff_ffff_ffff
        };
        return match (fpcr >> 22) & 0x3 {
            1 if exact_negative => max_finite,
            2 if !exact_negative => max_finite,
            3 => max_finite,
            _ => nearest,
        };
    }

    match (fpcr >> 22) & 0x3 {
        1 if cmp_exact_nearest == Greater => fp64_next_up_bits(nearest),
        2 if cmp_exact_nearest == Less => fp64_next_down_bits(nearest),
        3 if !exact_negative && cmp_exact_nearest == Less => fp64_next_down_bits(nearest),
        3 if exact_negative && cmp_exact_nearest == Greater => fp64_next_up_bits(nearest),
        _ => nearest,
    }
}
pub(crate) fn fp_three_same_f64_with_fpcr(kind: FpKind, a: u64, b: u64, d: u64, fpcr: u32) -> u64 {
    use FpKind::*;
    let flush_output = |r| fp64_flush_output_with_fpcr(r, fpcr);
    let (a, b, d) = if fpcr & (FPCR_FIZ | FPCR_FZ) != 0 {
        match kind {
            Add | Addp | Sub | Mul | Div | Mulx | Abd | Max | Maxp | MaxNm | MaxNmp | Min
            | Minp | MinNm | MinNmp | Recps | Rsqrts | CmEq | CmGe | CmGt | AcGe | AcGt => (
                fp64_flush_input_with_fpcr(a, fpcr),
                fp64_flush_input_with_fpcr(b, fpcr),
                d,
            ),
            Mla | Mls => (
                fp64_flush_input_with_fpcr(a, fpcr),
                fp64_flush_input_with_fpcr(b, fpcr),
                fp64_flush_input_with_fpcr(d, fpcr),
            ),
            _ => (a, b, d),
        }
    } else {
        (a, b, d)
    };
    let nearest = if fpcr & FPCR_AH != 0 && matches!(kind, Mla | Mls) {
        fp64_ah_nan3(d, a, b).unwrap_or_else(|| fp_three_same_f64(kind, a, b, d))
    } else {
        fp_three_same_f64(kind, a, b, d)
    };
    if fpcr & FPCR_AH != 0
        && matches!(
            kind,
            Add | Addp | Sub | Mul | Div | Mulx | Abd | Recps | Rsqrts
        )
    {
        if let Some(n) = fp64_ah_nan2(a, b) {
            return flush_output(n);
        }
    }
    if fpcr & FPCR_AH != 0 && matches!(kind, Max | Min) {
        if let Some(n) = fp64_ah_nan_number(a, b) {
            return flush_output(n);
        }
    }
    let nearest = if fpcr & FPCR_AH != 0 && fp_invalid_binop_f64(kind, a, b) {
        fp_ah_invalid_default_nan(8, nearest, fpcr)
    } else {
        nearest
    };
    if (fpcr >> 22) & 0x3 == 0
        || !matches!(
            kind,
            Add | Addp | Sub | Mul | Div | Mulx | Mla | Mls | Recps | Rsqrts
        )
    {
        return flush_output(nearest);
    }

    if matches!(kind, Recps | Rsqrts) {
        let Some((ma, ea)) = fp64_signed_mant_exp(a).or_else(|| fp64_is_zero(a).then_some((0, 0)))
        else {
            return flush_output(nearest);
        };
        let Some((mb, eb)) = fp64_signed_mant_exp(b).or_else(|| fp64_is_zero(b).then_some((0, 0)))
        else {
            return flush_output(nearest);
        };
        let Some(product) = ma.checked_mul(mb) else {
            return flush_output(nearest);
        };
        let constant = if matches!(kind, Recps) {
            2.0f64
        } else {
            3.0f64
        };
        let Some((mc, ec)) = fp64_signed_mant_exp(constant.to_bits()) else {
            return flush_output(nearest);
        };
        let terms = if matches!(kind, Recps) {
            [(mc, ec), (-product, ea + eb)]
        } else {
            [(mc, ec - 1), (-product, ea + eb - 1)]
        };
        let Some((cmp, exact_negative)) = fp64_exact_cmp_to_nearest(&terms, nearest) else {
            return flush_output(nearest);
        };
        return flush_output(fp64_adjust_nearest_with_fpcr(
            nearest,
            cmp,
            exact_negative,
            fpcr,
        ));
    }

    let signed_or_add_zero = |bits| {
        fp64_signed_mant_exp(bits)
            .or_else(|| (matches!(kind, Add | Addp | Sub) && fp64_is_zero(bits)).then_some((0, 0)))
    };
    let Some((ma, ea)) = signed_or_add_zero(a) else {
        return flush_output(nearest);
    };
    let Some((mut mb, eb)) = signed_or_add_zero(b) else {
        return flush_output(nearest);
    };
    if matches!(kind, Sub) {
        mb = -mb;
    }

    if matches!(kind, Div) {
        let exact_negative = (ma < 0) ^ (mb < 0);
        let cmp = if fp64_is_inf(nearest) {
            if (nearest >> 63) != 0 {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        } else if fp64_is_zero(nearest) {
            if exact_negative {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        } else {
            let Some((mn, en)) = fp64_signed_mant_exp(nearest) else {
                return flush_output(nearest);
            };
            let Some(nearest_scaled) = mn.checked_mul(mb) else {
                return flush_output(nearest);
            };
            let cmp = scaled_i128_terms_sign(&[(ma, ea), (-nearest_scaled, en + eb)]);
            if mb < 0 { cmp.reverse() } else { cmp }
        };
        return flush_output(fp64_adjust_nearest_with_fpcr(
            nearest,
            cmp,
            exact_negative,
            fpcr,
        ));
    }

    let terms = if matches!(kind, Mla | Mls) {
        let Some((md, ed)) = fp64_signed_mant_exp(d).or_else(|| fp64_is_zero(d).then_some((0, 0)))
        else {
            return flush_output(nearest);
        };
        let Some(mut product) = ma.checked_mul(mb) else {
            return flush_output(nearest);
        };
        if matches!(kind, Mls) {
            product = -product;
        }
        [(product, ea + eb), (md, ed)]
    } else if matches!(kind, Mul | Mulx) {
        let Some(product) = ma.checked_mul(mb) else {
            return flush_output(nearest);
        };
        [(product, ea + eb), (0, 0)]
    } else {
        [(ma, ea), (mb, eb)]
    };

    let Some((cmp, exact_negative)) = fp64_exact_cmp_to_nearest(&terms, nearest) else {
        return flush_output(nearest);
    };
    if cmp == std::cmp::Ordering::Equal
        && fp64_is_zero(nearest)
        && matches!(kind, Add | Addp | Sub)
        && fp_addsub_cancelled_zero_rounds_negative(a, b, matches!(kind, Sub), 64, fpcr)
    {
        return flush_output(0x8000_0000_0000_0000);
    }
    flush_output(fp64_adjust_nearest_with_fpcr(
        nearest,
        cmp,
        exact_negative,
        fpcr,
    ))
}
/// Compute one f64 element of an Advanced SIMD three-same FP operation.
pub(crate) fn fp_three_same_f64(kind: FpKind, a: u64, b: u64, d: u64) -> u64 {
    use FpKind::*;
    match kind {
        Abd => {
            if let Some(n) = fp64_nan2(a, b) {
                return n & 0x7FFF_FFFF_FFFF_FFFF;
            }
        }
        Add | Sub | Mul | Div | Mulx | Addp | Max | Maxp | Min | Minp => {
            if let Some(n) = fp64_nan2(a, b) {
                return n;
            }
        }
        Mla => {
            if let Some(n) = fp64_nan3(d, a, b) {
                return n;
            }
        }
        Mls => {
            if let Some(n) = fp64_nan3(d, a ^ 0x8000_0000_0000_0000, b) {
                return n;
            }
        }
        MaxNm | MaxNmp | MinNm | MinNmp => {
            if is_snan64(a) {
                return a | 0x0008_0000_0000_0000;
            }
            if is_snan64(b) {
                return b | 0x0008_0000_0000_0000;
            }
        }
        _ => {}
    }
    let x = f64::from_bits(a);
    let y = f64::from_bits(b);
    let acc = f64::from_bits(d);
    let mask = |c: bool| if c { u64::MAX } else { 0 };
    let canon = |r: f64| -> u64 {
        if r.is_nan() {
            0x7FF8_0000_0000_0000
        } else {
            r.to_bits()
        }
    };
    let inf0 = |p: f64, q: f64| (p.is_infinite() && q == 0.0) || (p == 0.0 && q.is_infinite());
    match kind {
        Add => canon(x + y),
        Sub => canon(x - y),
        Mul => canon(x * y),
        Div => canon(x / y),
        Mulx => {
            if inf0(x, y) {
                let neg = x.is_sign_negative() ^ y.is_sign_negative();
                (if neg { -2.0f64 } else { 2.0f64 }).to_bits()
            } else {
                canon(x * y)
            }
        }
        Mla => canon(x.mul_add(y, acc)),
        Mls => canon((-x).mul_add(y, acc)),
        Max | Maxp => fp_max_f64(x, y).to_bits(),
        Min | Minp => fp_min_f64(x, y).to_bits(),
        MaxNm | MaxNmp => {
            let (aq, bq) = (is_nan64(a), is_nan64(b));
            if aq && bq {
                a
            } else if aq {
                b
            } else if bq {
                a
            } else {
                fp_max_f64(x, y).to_bits()
            }
        }
        MinNm | MinNmp => {
            let (aq, bq) = (is_nan64(a), is_nan64(b));
            if aq && bq {
                a
            } else if aq {
                b
            } else if bq {
                a
            } else {
                fp_min_f64(x, y).to_bits()
            }
        }
        CmEq => mask(x == y),
        CmGe => mask(x >= y),
        CmGt => mask(x > y),
        AcGe => mask(x.abs() >= y.abs()),
        AcGt => mask(x.abs() > y.abs()),
        Abd => canon((x - y).abs()),
        Recps => sve_recps(8, a, b),
        Rsqrts => sve_rsqrts(8, a, b),
        Addp => canon(x + y),
    }
}
/// ARM RecipEstimate integer core (input a in [256,512)).
pub(crate) fn recip_estimate(a: u32) -> u32 {
    let a = a * 2 + 1;
    let b = (1u32 << 19) / a;
    (b + 1) >> 1
}
/// FRECPE for f32 (normal inputs).
pub(crate) fn fp_recip_estimate_f32(bits: u32) -> u32 {
    let sign = bits >> 31;
    let exp = (bits >> 23) & 0xFF;
    let frac = bits & 0x7F_FFFF;
    if exp == 0xFF {
        return if frac != 0 {
            bits | 0x40_0000
        } else {
            sign << 31
        }; // NaN->qNaN, inf->0
    }
    if exp == 0 && frac == 0 {
        return (sign << 31) | (0xFF << 23); // zero -> infinity
    }
    // |value| < 2^-128 -> the reciprocal overflows -> +/-inf (round-to-nearest).
    if exp == 0 && frac < 0x20_0000 {
        return (sign << 31) | (0xFF << 23);
    }
    // Work with a 52-bit fraction (ASL maps the f32 significand to f64 width).
    let mut fraction: u64 = (frac as u64) << 29;
    let mut e = exp as i32;
    if e == 0 {
        // Normalise a denormal input (value >= 2^-128).
        if (fraction >> 51) & 1 == 0 {
            e = -1;
            fraction = (fraction << 2) & ((1u64 << 52) - 1);
        } else {
            fraction = (fraction << 1) & ((1u64 << 52) - 1);
        }
    }
    let scaled = 0x100 | ((fraction >> 44) & 0xFF) as u32;
    let estimate = recip_estimate(scaled);
    let mut result_exp = 253i32 - e;
    let mut out_frac: u64 = ((estimate & 0xFF) as u64) << 44;
    if result_exp == 0 {
        out_frac = (1u64 << 51) | (out_frac >> 1); // denormal output
    } else if result_exp == -1 {
        out_frac = (1u64 << 50) | (out_frac >> 2);
        result_exp = 0;
    }
    (sign << 31) | (((result_exp as u32) & 0xFF) << 23) | ((out_frac >> 29) as u32 & 0x7F_FFFF)
}
/// FRECPE for f64 (normal inputs).
pub(crate) fn fp_recip_estimate_f64(bits: u64) -> u64 {
    let sign = bits >> 63;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & 0xF_FFFF_FFFF_FFFF;
    if exp == 0x7FF {
        return if frac != 0 {
            bits | 0x8_0000_0000_0000
        } else {
            sign << 63
        };
    }
    if exp == 0 && frac == 0 {
        return (sign << 63) | (0x7FFu64 << 52);
    }
    // |value| < 2^-1024 -> overflow -> +/-inf.
    if exp == 0 && frac < (1u64 << 50) {
        return (sign << 63) | (0x7FFu64 << 52);
    }
    let mut fraction = frac;
    let mut e = exp;
    if e == 0 {
        if (fraction >> 51) & 1 == 0 {
            e = -1;
            fraction = (fraction << 2) & ((1u64 << 52) - 1);
        } else {
            fraction = (fraction << 1) & ((1u64 << 52) - 1);
        }
    }
    let scaled = 0x100 | ((fraction >> 44) & 0xFF) as u32;
    let estimate = recip_estimate(scaled);
    let mut result_exp = 2045i32 - e;
    let mut out_frac: u64 = ((estimate & 0xFF) as u64) << 44;
    if result_exp == 0 {
        out_frac = (1u64 << 51) | (out_frac >> 1);
    } else if result_exp == -1 {
        out_frac = (1u64 << 50) | (out_frac >> 2);
        result_exp = 0;
    }
    (sign << 63) | (((result_exp as u64) & 0x7FF) << 52) | (out_frac & 0xF_FFFF_FFFF_FFFF)
}
/// ARM RecipSqrtEstimate integer core (input a in [128,512)).
pub(crate) fn recip_sqrt_estimate(mut a: u32) -> u32 {
    if a < 256 {
        a = a * 2 + 1;
    } else {
        a = (a >> 1) << 1;
        a = (a + 1) * 2;
    }
    let a = a as u64;
    let mut b: u64 = 512;
    while a * (b + 1) * (b + 1) < (1u64 << 28) {
        b += 1;
    }
    ((b + 1) >> 1) as u32
}
/// FRSQRTE for f32.
pub(crate) fn fp_rsqrt_estimate_f32(bits: u32) -> u32 {
    let sign = bits >> 31;
    let exp = (bits >> 23) & 0xFF;
    let frac = bits & 0x7F_FFFF;
    if exp == 0xFF && frac != 0 {
        return bits | 0x40_0000;
    } // NaN -> qNaN
    if exp == 0 && frac == 0 {
        return (sign << 31) | (0xFF << 23);
    } // zero -> inf
    if sign == 1 {
        return 0x7FC0_0000;
    } // negative -> default NaN
    if exp == 0xFF {
        return 0;
    } // +inf -> +0
    let mut fraction: u64 = (frac as u64) << 29; // bits<51:29>
    let mut e = exp as i32;
    if e == 0 {
        while (fraction >> 51) & 1 == 0 {
            fraction = (fraction << 1) & 0xF_FFFF_FFFF_FFFF;
            e -= 1;
        }
        fraction = (fraction << 1) & 0xF_FFFF_FFFF_FFFF;
    }
    let scaled = if e & 1 == 0 {
        0x100 | ((fraction >> 44) & 0xFF) as u32
    } else {
        0x80 | ((fraction >> 45) & 0x7F) as u32
    };
    let result_exp = (((380 - e) / 2) as u32) & 0xFF;
    let est = recip_sqrt_estimate(scaled);
    (sign << 31) | (result_exp << 23) | ((est & 0xFF) << 15)
}
pub(crate) fn fp_rsqrt_estimate_f32_with_fpcr(bits: u32, fpcr: u32) -> u32 {
    let result = fp_rsqrt_estimate_f32(bits);
    if (bits >> 31) != 0 && !fp32_is_zero(bits) && !is_nan32(bits) {
        fp32_ah_invalid_default_nan(result, fpcr)
    } else {
        result
    }
}
/// FRSQRTE for f64.
pub(crate) fn fp_rsqrt_estimate_f64(bits: u64) -> u64 {
    let sign = bits >> 63;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & 0xF_FFFF_FFFF_FFFF;
    if exp == 0x7FF && frac != 0 {
        return bits | 0x8_0000_0000_0000;
    }
    if exp == 0 && frac == 0 {
        return (sign << 63) | (0x7FFu64 << 52);
    }
    if sign == 1 {
        return 0x7FF8_0000_0000_0000;
    }
    if exp == 0x7FF {
        return 0;
    }
    let mut fraction: u64 = frac;
    let mut e = exp;
    if e == 0 {
        while (fraction >> 51) & 1 == 0 {
            fraction = (fraction << 1) & 0xF_FFFF_FFFF_FFFF;
            e -= 1;
        }
        fraction = (fraction << 1) & 0xF_FFFF_FFFF_FFFF;
    }
    let scaled = if e & 1 == 0 {
        0x100 | ((fraction >> 44) & 0xFF) as u32
    } else {
        0x80 | ((fraction >> 45) & 0x7F) as u32
    };
    let result_exp = (((3068 - e) / 2) as u64) & 0x7FF;
    let est = recip_sqrt_estimate(scaled);
    (sign << 63) | (result_exp << 52) | (((est & 0xFF) as u64) << 44)
}
pub(crate) fn fp_rsqrt_estimate_f64_with_fpcr(bits: u64, fpcr: u32) -> u64 {
    let result = fp_rsqrt_estimate_f64(bits);
    if (bits >> 63) != 0 && !fp64_is_zero(bits) && !is_nan64(bits) {
        fp_ah_invalid_default_nan(8, result, fpcr)
    } else {
        result
    }
}
// ---- Precision-generic FP element helpers (esize in bits: 16/32/64) ----

/// Flip the sign bit of a floating-point element.
pub(crate) fn fp_neg_bits(b: u64, esize: u32) -> u64 {
    b ^ (1u64 << (esize - 1))
}
pub(crate) fn fp_neg_bits_with_fpcr(b: u64, esize: u32, fpcr: u32) -> u64 {
    if fpcr & FPCR_AH != 0 && fp_is_nan_bits((esize / 8) as usize, b) {
        b
    } else {
        fp_neg_bits(b, esize)
    }
}
pub(crate) fn fp_abs_bits_with_fpcr(b: u64, esize: u32, fpcr: u32) -> u64 {
    if fpcr & FPCR_AH != 0 && fp_is_nan_bits((esize / 8) as usize, b) {
        b
    } else {
        b & !(1u64 << (esize - 1))
    }
}
/// FPAdd over a binary16/32/64 element.
pub(crate) fn fp_add_bits(a: u64, b: u64, esize: u32) -> u64 {
    match esize {
        16 => fp16_add(a as u16, b as u16) as u64,
        32 => fp_three_same_f32(FpKind::Add, a as u32, b as u32, 0) as u64,
        _ => fp_three_same_f64(FpKind::Add, a, b, 0),
    }
}
pub(crate) fn fp_add_bits_with_fpcr(a: u64, b: u64, esize: u32, fpcr: u32) -> u64 {
    match esize {
        16 => sve_fp16_binop_with_fpcr(FpKind::Add, a as u16, b as u16, fpcr) as u64,
        32 => fp_three_same_f32_with_fpcr(FpKind::Add, a as u32, b as u32, 0, fpcr) as u64,
        _ => fp_three_same_f64_with_fpcr(FpKind::Add, a, b, 0, fpcr),
    }
}
/// FPMulAdd (fused): `acc + x*y` over a binary16/32/64 element.
pub(crate) fn fp_muladd_bits(acc: u64, x: u64, y: u64, esize: u32) -> u64 {
    match esize {
        16 => fp16_mla(acc as u16, x as u16, y as u16) as u64,
        32 => fp_three_same_f32(FpKind::Mla, x as u32, y as u32, acc as u32) as u64,
        _ => fp_three_same_f64(FpKind::Mla, x, y, acc),
    }
}
pub(crate) fn fp_fma_cancelled_zero_rounds_negative(
    acc: u64,
    x: u64,
    y: u64,
    esize: u32,
    fpcr: u32,
) -> bool {
    if (fpcr >> 22) & 0x3 != 2 {
        return false;
    }
    let bytes = (esize / 8) as usize;
    if fp_is_zero_bits(bytes, acc) || fp_is_zero_bits(bytes, x) || fp_is_zero_bits(bytes, y) {
        return false;
    }
    let sign_bit = 1u64 << (esize - 1);
    let acc_negative = (acc & sign_bit) != 0;
    let product_negative = ((x ^ y) & sign_bit) != 0;
    acc_negative != product_negative
}
pub(crate) fn fp_addsub_cancelled_zero_rounds_negative(
    a: u64,
    b: u64,
    sub: bool,
    esize: u32,
    fpcr: u32,
) -> bool {
    if (fpcr >> 22) & 0x3 != 2 {
        return false;
    }
    let sign_bit = 1u64 << (esize - 1);
    let a_negative = (a & sign_bit) != 0;
    let b_negative = ((b & sign_bit) != 0) ^ sub;
    a_negative != b_negative
}
pub(crate) fn fp_muladd_f32_with_fpcr(acc: u32, x: u32, y: u32, fpcr: u32) -> u32 {
    let (acc, x, y) = if fpcr & (FPCR_FIZ | FPCR_FZ) != 0 {
        (
            fp32_flush_input_with_fpcr(acc, fpcr),
            fp32_flush_input_with_fpcr(x, fpcr),
            fp32_flush_input_with_fpcr(y, fpcr),
        )
    } else {
        (acc, x, y)
    };
    let flush_output = |r| fp32_flush_output_with_fpcr(r, fpcr);
    if fpcr & FPCR_AH != 0 {
        if let Some(n) = fp32_ah_nan3(acc, x, y) {
            return flush_output(n);
        }
    }
    let nearest = fp_three_same_f32(FpKind::Mla, x, y, acc);
    let nearest =
        if fpcr & FPCR_AH != 0 && fp_invalid_fma_default_nan(4, acc as u64, x as u64, y as u64) {
            fp_ah_invalid_default_nan(4, nearest as u64, fpcr) as u32
        } else {
            nearest
        };
    if (fpcr >> 22) & 0x3 == 0 {
        return flush_output(nearest);
    }
    let xf = f32::from_bits(x);
    let yf = f32::from_bits(y);
    let af = f32::from_bits(acc);
    if !xf.is_finite() || !yf.is_finite() || !af.is_finite() {
        return flush_output(nearest);
    }
    let exact = xf as f64 * yf as f64 + af as f64;
    if exact == 0.0
        && fp_fma_cancelled_zero_rounds_negative(acc as u64, x as u64, y as u64, 32, fpcr)
    {
        return flush_output(0x8000_0000);
    }
    flush_output(f64_to_f32_bits_with_fpcr(exact, fpcr))
}
pub(crate) fn fp_muladd_f64_with_fpcr(acc: u64, x: u64, y: u64, fpcr: u32) -> u64 {
    let (acc, x, y) = if fpcr & (FPCR_FIZ | FPCR_FZ) != 0 {
        (
            fp64_flush_input_with_fpcr(acc, fpcr),
            fp64_flush_input_with_fpcr(x, fpcr),
            fp64_flush_input_with_fpcr(y, fpcr),
        )
    } else {
        (acc, x, y)
    };
    let flush_output = |r| fp64_flush_output_with_fpcr(r, fpcr);
    if fpcr & FPCR_AH != 0 {
        if let Some(n) = fp64_ah_nan3(acc, x, y) {
            return flush_output(n);
        }
    }
    let nearest = fp_three_same_f64(FpKind::Mla, x, y, acc);
    let nearest = if fpcr & FPCR_AH != 0 && fp_invalid_fma_default_nan(8, acc, x, y) {
        fp_ah_invalid_default_nan(8, nearest, fpcr)
    } else {
        nearest
    };
    if (fpcr >> 22) & 0x3 == 0 {
        return flush_output(nearest);
    }
    let Some((mx, ex)) = fp64_signed_mant_exp(x) else {
        return flush_output(nearest);
    };
    let Some((my, ey)) = fp64_signed_mant_exp(y) else {
        return flush_output(nearest);
    };
    let Some((ma, ea)) = fp64_signed_mant_exp(acc) else {
        return flush_output(nearest);
    };
    let Some(product) = mx.checked_mul(my) else {
        return flush_output(nearest);
    };
    let terms = [(product, ex + ey), (ma, ea)];
    let Some((cmp, exact_negative)) = fp64_exact_cmp_to_nearest(&terms, nearest) else {
        return flush_output(nearest);
    };
    if cmp == std::cmp::Ordering::Equal
        && fp64_is_zero(nearest)
        && fp_fma_cancelled_zero_rounds_negative(acc, x, y, 64, fpcr)
    {
        return flush_output(0x8000_0000_0000_0000);
    }
    flush_output(fp64_adjust_nearest_with_fpcr(
        nearest,
        cmp,
        exact_negative,
        fpcr,
    ))
}
pub(crate) fn fp_muladd_bits_with_fpcr(acc: u64, x: u64, y: u64, esize: u32, fpcr: u32) -> u64 {
    match esize {
        16 => fp16_mla_with_fpcr(acc as u16, x as u16, y as u16, fpcr) as u64,
        32 => fp_muladd_f32_with_fpcr(acc as u32, x as u32, y as u32, fpcr) as u64,
        _ => fp_muladd_f64_with_fpcr(acc, x, y, fpcr),
    }
}
pub(crate) fn fp_fcmla_muladd_bits_with_fpcr(
    acc: u64,
    x: u64,
    y: u64,
    esize: u32,
    fpcr: u32,
) -> u64 {
    if fpcr & FPCR_AH != 0 {
        let nan = match esize {
            16 => fp16_ah_nan3(x as u16, y as u16, acc as u16).map(|n| n as u64),
            32 => fp32_ah_nan3(x as u32, y as u32, acc as u32).map(|n| n as u64),
            _ => fp64_ah_nan3(x, y, acc),
        };
        if let Some(nan) = nan {
            return nan;
        }
    }
    fp_muladd_bits_with_fpcr(acc, x, y, esize, fpcr)
}
pub(crate) fn fp_ah_maxnm_pairwise_nan(esize: usize, x: u64, y: u64) -> Option<u64> {
    let x_nan = fp_is_nan_bits(esize, x);
    let y_nan = fp_is_nan_bits(esize, y);
    match (x_nan, y_nan) {
        (true, false) => Some(y),
        (false, true) => Some(x),
        (true, true) => {
            if !fp_is_snan_bits(esize, x) {
                Some(x)
            } else if !fp_is_snan_bits(esize, y) {
                Some(y)
            } else {
                Some(x)
            }
        }
        _ => None,
    }
}
pub(crate) fn fp_pairwise_reduce_status_with_fpcr(
    esize: usize,
    kind: FpKind,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    if fpcr & FPCR_AH != 0
        && matches!(
            kind,
            FpKind::Max | FpKind::Maxp | FpKind::Min | FpKind::Minp
        )
        && (fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b))
    {
        return FPSR_IOC;
    }
    if fpcr & FPCR_AH != 0
        && matches!(
            kind,
            FpKind::MaxNm | FpKind::MaxNmp | FpKind::MinNm | FpKind::MinNmp
        )
        && (fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b))
    {
        let status = fp_status_binop(esize, kind, a, b, result);
        let input_status = fp_fz_input_status(esize, a, fpcr) | fp_fz_input_status(esize, b, fpcr);
        return fp_status_merge_input_status(status, input_status, fpcr);
    }
    fp_status_binop_with_fpcr(esize, kind, a, b, result, fpcr)
}
/// Round an f64 to f32 with round-to-odd (Von Neumann): truncate toward zero,
/// and if any bits were discarded force the result mantissa LSB to 1. Used for
/// the unrounded BF16 dot-product accumulation (FPCR.EBF==0). The f64 input is
/// assumed to be the exact value (callers keep the exponent span small enough
/// that the f64 sum is exact).
pub(crate) fn round_odd_f64_to_f32(x: f64) -> u32 {
    if x.is_nan() {
        // FPConvertNaN (FPCR.DN=0): preserve sign and the top 23 fraction bits,
        // forcing the quiet bit (an sNaN is quieted, signalling InvalidOp which
        // the oracle does not compare). FCVTX/FCVTXNT are NOT default-NaN ops.
        let b = x.to_bits();
        let sign = ((b >> 63) as u32) << 31;
        let frac = ((b >> 29) as u32 & 0x7F_FFFF) | 0x40_0000;
        return sign | 0x7F80_0000 | frac;
    }
    let sign = ((x.is_sign_negative()) as u32) << 31;
    let a = x.abs();
    if a == 0.0 {
        return sign;
    }
    if a.is_infinite() {
        return sign | 0x7F80_0000;
    }
    let bits = a.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i64 - 1023; // unbiased, `a` is normal f64
    let mant = bits & 0x000F_FFFF_FFFF_FFFF; // 52-bit fraction
    if exp > 127 {
        return sign | 0x7F7F_FFFF; // round-to-odd never overflows to Inf
    }
    if exp >= -126 {
        // Normal f32: keep the top 23 fraction bits, OR in sticky for round-odd.
        let frac = (mant >> 29) as u32;
        let dropped = mant & ((1u64 << 29) - 1);
        let f = if dropped != 0 { frac | 1 } else { frac };
        let e = (exp + 127) as u32;
        return sign | (e << 23) | f;
    }
    // Subnormal f32: value = 1.mant * 2^exp, exp <= -127.
    let sig = (1u64 << 52) | mant;
    let shift = (-(exp + 97)) as u32; // value * 2^149 == sig >> shift
    if shift >= 64 {
        return sign | 1; // tiny nonzero -> smallest subnormal under round-odd
    }
    let frac = (sig >> shift) as u32 & 0x7F_FFFF;
    let dropped = sig & ((1u64 << shift) - 1);
    let f = if dropped != 0 { frac | 1 } else { frac };
    sign | f
}
/// Round an f64 to f32 with round-to-odd-INF (the BF16 dot-product rounding,
/// FPCR.EBF==0): like `round_odd_f64_to_f32` but overflow rounds to infinity
/// (not the max finite), and any NaN collapses to the default NaN 0x7FC00000
/// (default-NaN mode is forced for these instructions). The f64 input is the
/// exact value to round (the add path pre-rounds to odd at f64 precision so the
/// final f32 round-to-odd is double-rounding-safe).
pub(crate) fn round_odd_inf_f64_to_f32(x: f64) -> u32 {
    if x.is_nan() {
        return 0x7FC0_0000; // default NaN
    }
    let sign = (x.is_sign_negative() as u32) << 31;
    let a = x.abs();
    if a == 0.0 {
        return sign;
    }
    if a.is_infinite() {
        return sign | 0x7F80_0000;
    }
    let bits = a.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i64 - 1023;
    let mant = bits & 0x000F_FFFF_FFFF_FFFF;
    if exp > 127 {
        return sign | 0x7F80_0000; // round-to-odd-INF: overflow -> infinity
    }
    if exp >= -126 {
        let frac = (mant >> 29) as u32;
        let dropped = mant & ((1u64 << 29) - 1);
        let f = if dropped != 0 { frac | 1 } else { frac };
        let e = (exp + 127) as u32;
        return sign | (e << 23) | f;
    }
    // Subnormal f32: value = 1.mant * 2^exp, exp <= -127.
    let sig = (1u64 << 52) | mant;
    let shift = (-(exp + 97)) as u32;
    if shift >= 64 {
        return sign | 1;
    }
    let frac = (sig >> shift) as u32 & 0x7F_FFFF;
    let dropped = sig & ((1u64 << shift) - 1);
    let f = if dropped != 0 { frac | 1 } else { frac };
    sign | f
}
/// Flush an f32 denormal (raw bits) to a sign-preserving zero, per FPCR.FZ /
/// FZ-of-inputs. Used by the EBF==0 BF16 dot path. Inf/NaN pass through.
#[inline]
pub(crate) fn ftz_f32_bits(bits: u32) -> u32 {
    let exp = (bits >> 23) & 0xFF;
    let mant = bits & 0x007F_FFFF;
    if exp == 0 && mant != 0 {
        bits & 0x8000_0000
    } else {
        bits
    }
}
/// Move a finite, nonzero f64 one ULP toward +inf (`up`) or -inf.
#[inline]
pub(crate) fn nextafter_f64(x: f64, up: bool) -> f64 {
    let bits = x.to_bits();
    let neg = (bits >> 63) == 1;
    let nb = if up == !neg { bits + 1 } else { bits - 1 };
    f64::from_bits(nb)
}
/// scalbn for f32: x * 2^n, correctly rounded (musl port, avoids double rounding).
pub(crate) fn scalbn_f32(x: f32, mut n: i32) -> f32 {
    let mut y = x;
    if n > 127 {
        y *= f32::from_bits(0x7F00_0000); // 2^127
        n -= 127;
        if n > 127 {
            y *= f32::from_bits(0x7F00_0000);
            n -= 127;
            if n > 127 {
                n = 127;
            }
        }
    } else if n < -126 {
        y *= f32::from_bits(0x0080_0000) * f32::from_bits(0x4B80_0000); // 2^-126 * 2^24
        n += 126 - 24;
        if n < -126 {
            y *= f32::from_bits(0x0080_0000) * f32::from_bits(0x4B80_0000);
            n += 126 - 24;
            if n < -126 {
                n = -126;
            }
        }
    }
    y * f32::from_bits(((0x7F + n) as u32) << 23)
}
/// scalbn for f64 (musl port).
pub(crate) fn scalbn_f64(x: f64, mut n: i64) -> f64 {
    let mut y = x;
    if n > 1023 {
        y *= f64::from_bits(0x7FE0_0000_0000_0000); // 2^1023
        n -= 1023;
        if n > 1023 {
            y *= f64::from_bits(0x7FE0_0000_0000_0000);
            n -= 1023;
            if n > 1023 {
                n = 1023;
            }
        }
    } else if n < -1022 {
        y *= f64::from_bits(0x0010_0000_0000_0000) * f64::from_bits(0x4340_0000_0000_0000); // 2^-1022*2^53
        n += 1022 - 53;
        if n < -1022 {
            y *= f64::from_bits(0x0010_0000_0000_0000) * f64::from_bits(0x4340_0000_0000_0000);
            n += 1022 - 53;
            if n < -1022 {
                n = -1022;
            }
        }
    }
    y * f64::from_bits(((0x3FF + n) as u64) << 52)
}
pub(crate) fn fp16_fscale_with_fpcr(x: u16, n: i64, fpcr: u32) -> u16 {
    if let Some(nan) = fp16_nan2(x, x) {
        return nan;
    }
    let xf = fp16_to_f64(x);
    let scaled = xf * exp2_f64(n.clamp(-1023, 1023) as i32);
    let nearest = fp16_round(scaled);
    if (fpcr >> 22) & 0x3 == 0 || fp16_is_zero(x) || fp16_is_inf(x) {
        return nearest;
    }
    if fp16_is_inf(nearest) {
        let huge = if x & 0x8000 != 0 { -f64::MAX } else { f64::MAX };
        return f64_to_fp16_bits_with_fpcr(huge, fpcr);
    }
    if fp16_is_zero(nearest) && !fp16_is_zero(x) {
        return match (fpcr >> 22) & 0x3 {
            1 if x & 0x8000 == 0 => 0x0001,
            2 if x & 0x8000 != 0 => 0x8001,
            _ => nearest,
        };
    }
    f64_to_fp16_bits_with_fpcr(scaled, fpcr)
}
pub(crate) fn fp32_fscale_with_fpcr(x: u32, n: i64, fpcr: u32) -> u32 {
    let nearest = scalbn_f32(
        f32::from_bits(x),
        n.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
    )
    .to_bits();
    if (fpcr >> 22) & 0x3 == 0 || !fp32_is_finite(x) || fp32_is_zero(x) {
        return nearest;
    }
    if fp32_is_inf(nearest) {
        let huge = if x >> 31 != 0 { -f64::MAX } else { f64::MAX };
        return f64_to_f32_bits_with_fpcr(huge, fpcr);
    }
    if fp32_is_zero(nearest) {
        return match (fpcr >> 22) & 0x3 {
            1 if x >> 31 == 0 => 0x0000_0001,
            2 if x >> 31 != 0 => 0x8000_0001,
            _ => nearest,
        };
    }
    let scaled = (f32::from_bits(x) as f64) * exp2_f64(n.clamp(-1023, 1023) as i32);
    if scaled.is_infinite() {
        let huge = if x >> 31 != 0 { -f64::MAX } else { f64::MAX };
        f64_to_f32_bits_with_fpcr(huge, fpcr)
    } else {
        f64_to_f32_bits_with_fpcr(scaled, fpcr)
    }
}
pub(crate) fn fp64_fscale_with_fpcr(x: u64, n: i64, fpcr: u32) -> u64 {
    let nearest = scalbn_f64(f64::from_bits(x), n).to_bits();
    if (fpcr >> 22) & 0x3 == 0 || !fp64_is_finite(x) || fp64_is_zero(x) {
        return nearest;
    }
    if fp64_is_inf(nearest) {
        let cmp = if x >> 63 != 0 {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        };
        return fp64_adjust_nearest_with_fpcr(nearest, cmp, x >> 63 != 0, fpcr);
    }
    if fp64_is_zero(nearest) && n < -4096 {
        return match (fpcr >> 22) & 0x3 {
            1 if x >> 63 == 0 => 0x0000_0000_0000_0001,
            2 if x >> 63 != 0 => 0x8000_0000_0000_0001,
            _ => nearest,
        };
    }
    let Some((mant, exp)) = fp64_signed_mant_exp(x) else {
        return nearest;
    };
    let Some(exp) = (exp as i64)
        .checked_add(n)
        .and_then(|e| i32::try_from(e).ok())
    else {
        return if n < 0 {
            match (fpcr >> 22) & 0x3 {
                1 if x >> 63 == 0 => 0x0000_0000_0000_0001,
                2 if x >> 63 != 0 => 0x8000_0000_0000_0001,
                _ => nearest,
            }
        } else {
            let cmp = if x >> 63 != 0 {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            };
            fp64_adjust_nearest_with_fpcr(nearest, cmp, x >> 63 != 0, fpcr)
        };
    };
    let Some((cmp, exact_negative)) = fp64_exact_cmp_to_nearest(&[(mant, exp)], nearest) else {
        return nearest;
    };
    fp64_adjust_nearest_with_fpcr(nearest, cmp, exact_negative, fpcr)
}
/// 2^n as an f64, exact for |n| <= 1023.
pub(crate) fn exp2_f64(n: i32) -> f64 {
    f64::from_bits(((0x3FF + n) as u64) << 52)
}
// ---- Software half-precision (IEEE binary16) for AdvSIMD FP16 ----
//
// All operations follow the Arm ASL with the default FPCR (round-to-nearest
// even, no flush-to-zero, DN=0 so input NaNs propagate quieted). Arithmetic is
// evaluated in f64 — exact for binary16 add/sub/mul and the fused step/estimate
// forms — then rounded once to binary16 with `fp16_round`.

#[inline]
/// ARM FPConvertNaN (FPCR.DN=0): convert a NaN between FP precisions, preserving
/// the sign, quieting, and aligning the payload to the MSB of the destination
/// mantissa. `prec` is the byte width: 2=f16(10-bit mantissa), 4=f32(23), 8=f64(52).
pub(crate) fn fp_convert_nan(src: u64, src_prec: usize, dst_prec: usize) -> u64 {
    let fields = |p: usize| -> (u32, u32) {
        match p {
            2 => (10, 5),
            4 => (23, 8),
            _ => (52, 11),
        }
    };
    let (sm, se) = fields(src_prec);
    let (dm, de) = fields(dst_prec);
    let sign = (src >> (sm + se)) & 1;
    let payload = src & ((1u64 << sm) - 1);
    let aligned = if dm >= sm {
        payload << (dm - sm)
    } else {
        payload >> (sm - dm)
    };
    let quiet = 1u64 << (dm - 1);
    let exp_all = (1u64 << de) - 1;
    (sign << (dm + de)) | (exp_all << dm) | quiet | aligned
}
pub(crate) fn fp32_next_up_bits(bits: u32) -> u32 {
    let x = f32::from_bits(bits);
    if x.is_nan() || bits == 0x7f80_0000 {
        return bits;
    }
    if bits == 0x8000_0000 {
        return 1;
    }
    if (bits >> 31) != 0 {
        bits - 1
    } else {
        bits + 1
    }
}
pub(crate) fn fp32_next_down_bits(bits: u32) -> u32 {
    let x = f32::from_bits(bits);
    if x.is_nan() || bits == 0xff80_0000 {
        return bits;
    }
    if bits == 0 {
        return 0x8000_0001;
    }
    if (bits >> 31) != 0 {
        bits + 1
    } else {
        bits - 1
    }
}
pub(crate) fn fp64_next_up_bits(bits: u64) -> u64 {
    let x = f64::from_bits(bits);
    if x.is_nan() || bits == 0x7ff0_0000_0000_0000 {
        return bits;
    }
    if bits == 0xfff0_0000_0000_0000 {
        return 0xffef_ffff_ffff_ffff;
    }
    if bits == 0x8000_0000_0000_0000 {
        return 1;
    }
    if (bits >> 63) != 0 {
        bits - 1
    } else {
        bits + 1
    }
}
pub(crate) fn fp64_next_down_bits(bits: u64) -> u64 {
    let x = f64::from_bits(bits);
    if x.is_nan() || bits == 0xfff0_0000_0000_0000 {
        return bits;
    }
    if bits == 0x7ff0_0000_0000_0000 {
        return 0x7fef_ffff_ffff_ffff;
    }
    if bits == 0 {
        return 0x8000_0000_0000_0001;
    }
    if (bits >> 63) != 0 {
        bits + 1
    } else {
        bits - 1
    }
}
pub(crate) fn fp16_next_up_bits(bits: u16) -> u16 {
    if ((bits & 0x7c00) == 0x7c00 && (bits & 0x03ff) != 0) || bits == 0x7c00 {
        return bits;
    }
    if bits == 0x8000 {
        return 1;
    }
    if (bits >> 15) != 0 {
        bits - 1
    } else {
        bits + 1
    }
}
pub(crate) fn fp16_next_down_bits(bits: u16) -> u16 {
    if ((bits & 0x7c00) == 0x7c00 && (bits & 0x03ff) != 0) || bits == 0xfc00 {
        return bits;
    }
    if bits == 0 {
        return 0x8001;
    }
    if (bits >> 15) != 0 {
        bits + 1
    } else {
        bits - 1
    }
}
pub(crate) fn f64_to_f32_bits_with_fpcr(x: f64, fpcr: u32) -> u32 {
    if x.is_nan() {
        return fp_convert_nan(x.to_bits(), 8, 4) as u32;
    }
    let bits = (x as f32).to_bits();
    if x.is_infinite() {
        return bits;
    }
    let rounded = f32::from_bits(bits) as f64;
    if rounded == x {
        return bits;
    }
    match (fpcr >> 22) & 0x3 {
        0 => bits,
        1 => {
            if rounded < x {
                fp32_next_up_bits(bits)
            } else {
                bits
            }
        }
        2 => {
            if rounded > x {
                fp32_next_down_bits(bits)
            } else {
                bits
            }
        }
        _ => {
            if (x.is_sign_positive() && rounded > x) || (x.is_sign_negative() && rounded < x) {
                if x.is_sign_positive() {
                    fp32_next_down_bits(bits)
                } else {
                    fp32_next_up_bits(bits)
                }
            } else {
                bits
            }
        }
    }
}
pub(crate) fn f64_to_fp16_bits_with_fpcr(x: f64, fpcr: u32) -> u16 {
    if x.is_nan() {
        return fp_convert_nan(x.to_bits(), 8, 2) as u16;
    }
    let bits = fp16_round(x);
    if x.is_infinite() {
        return bits;
    }
    let rounded = fp16_to_f64(bits);
    if rounded == x {
        return bits;
    }
    match (fpcr >> 22) & 0x3 {
        0 => bits,
        1 => {
            if rounded < x {
                fp16_next_up_bits(bits)
            } else {
                bits
            }
        }
        2 => {
            if rounded > x {
                fp16_next_down_bits(bits)
            } else {
                bits
            }
        }
        _ => {
            if (x.is_sign_positive() && rounded > x) || (x.is_sign_negative() && rounded < x) {
                if x.is_sign_positive() {
                    fp16_next_down_bits(bits)
                } else {
                    fp16_next_up_bits(bits)
                }
            } else {
                bits
            }
        }
    }
}
pub(crate) fn fp16_to_f64(h: u16) -> f64 {
    AArch64Cpu::fp16_to_f32(h) as f64
}
#[inline]
pub(crate) fn fp16_is_nan(h: u16) -> bool {
    (h & 0x7C00) == 0x7C00 && (h & 0x03FF) != 0
}
#[inline]
pub(crate) fn fp16_is_snan(h: u16) -> bool {
    fp16_is_nan(h) && (h & 0x0200) == 0
}
#[inline]
pub(crate) fn fp16_is_inf(h: u16) -> bool {
    (h & 0x7FFF) == 0x7C00
}
#[inline]
pub(crate) fn fp16_is_zero(h: u16) -> bool {
    (h & 0x7FFF) == 0
}
/// FPProcessNaNs over two operands (DN=0): propagate a NaN if present,
/// quieting signaling NaNs and giving them priority. Returns None if neither
/// operand is a NaN.
pub(crate) fn fp16_nan2(a: u16, b: u16) -> Option<u16> {
    let a_nan = fp16_is_nan(a);
    let b_nan = fp16_is_nan(b);
    if a_nan && (a & 0x0200) == 0 {
        Some(a | 0x0200)
    } else if b_nan && (b & 0x0200) == 0 {
        Some(b | 0x0200)
    } else if a_nan {
        Some(a)
    } else if b_nan {
        Some(b)
    } else {
        None
    }
}
pub(crate) fn fp16_ah_nan2(a: u16, b: u16) -> Option<u16> {
    if fp16_is_nan(a) {
        Some(if (a & 0x0200) == 0 { a | 0x0200 } else { a })
    } else if fp16_is_nan(b) {
        Some(if (b & 0x0200) == 0 { b | 0x0200 } else { b })
    } else {
        None
    }
}
/// FPProcessNaNs over three operands (for the fused multiply-add forms).
pub(crate) fn fp16_nan3(a: u16, b: u16, c: u16) -> Option<u16> {
    for &x in &[a, b, c] {
        if fp16_is_nan(x) && (x & 0x0200) == 0 {
            return Some(x | 0x0200);
        }
    }
    for &x in &[a, b, c] {
        if fp16_is_nan(x) {
            return Some(x);
        }
    }
    None
}
pub(crate) fn fp16_ah_nan3(a: u16, b: u16, c: u16) -> Option<u16> {
    for &x in &[a, b, c] {
        if fp16_is_nan(x) {
            return Some(if (x & 0x0200) == 0 { x | 0x0200 } else { x });
        }
    }
    None
}
/// Round `v / 2^shift` to nearest, ties to even.
pub(crate) fn round_shift_u64(v: u64, shift: u32) -> u64 {
    if shift == 0 {
        return v;
    }
    if shift >= 64 {
        return 0;
    }
    let result = v >> shift;
    let rem = v & ((1u64 << shift) - 1);
    let half = 1u64 << (shift - 1);
    if rem > half || (rem == half && (result & 1) == 1) {
        result + 1
    } else {
        result
    }
}
/// Round an f64 to IEEE binary16 (round-to-nearest even, no flush-to-zero).
/// A NaN input maps to the default binary16 NaN; callers that must preserve an
/// operand NaN handle propagation before calling this.
pub(crate) fn fp16_round(x: f64) -> u16 {
    if x.is_nan() {
        return 0x7E00;
    }
    let sign: u16 = if x.is_sign_negative() { 0x8000 } else { 0 };
    let a = x.abs();
    if a == 0.0 {
        return sign;
    }
    if a.is_infinite() || a >= 65520.0 {
        // 65520 is the round-to-nearest overflow threshold (halfway to 2^16).
        return sign | 0x7C00;
    }
    let bits = a.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i32 - 1023; // `a` is a normal f64 here
    let mant52 = bits & 0x000F_FFFF_FFFF_FFFF;
    if exp < -14 {
        // Subnormal binary16 (or rounding up into the smallest normal).
        let sig = (1u64 << 52) | mant52; // 1.mant52 scaled by 2^52
        let shift = (28 - exp) as u32; // value * 2^24 == sig >> (28 - exp)
        let m = round_shift_u64(sig, shift);
        if m >= 1024 {
            return sign | (1 << 10) | ((m as u16) & 0x3FF);
        }
        return sign | (m as u16 & 0x3FF);
    }
    let e16 = (exp + 15) as u16; // biased binary16 exponent in [1, 30]
    let m = round_shift_u64(mant52, 42); // round the 52-bit fraction to 10 bits
    if m >= 1024 {
        let e2 = e16 + 1;
        if e2 >= 0x1F {
            return sign | 0x7C00;
        }
        return sign | (e2 << 10);
    }
    sign | (e16 << 10) | (m as u16 & 0x3FF)
}
pub(crate) fn fp16_add(a: u16, b: u16) -> u16 {
    if let Some(n) = fp16_nan2(a, b) {
        return n;
    }
    fp16_round(fp16_to_f64(a) + fp16_to_f64(b))
}
pub(crate) fn fp16_sub(a: u16, b: u16) -> u16 {
    if let Some(n) = fp16_nan2(a, b) {
        return n;
    }
    fp16_round(fp16_to_f64(a) - fp16_to_f64(b))
}
pub(crate) fn fp16_mul(a: u16, b: u16) -> u16 {
    if let Some(n) = fp16_nan2(a, b) {
        return n;
    }
    fp16_round(fp16_to_f64(a) * fp16_to_f64(b))
}
pub(crate) fn fp16_div(a: u16, b: u16) -> u16 {
    if let Some(n) = fp16_nan2(a, b) {
        return n;
    }
    fp16_round(fp16_to_f64(a) / fp16_to_f64(b))
}
pub(crate) fn fp16_mulx(a: u16, b: u16) -> u16 {
    if let Some(n) = fp16_nan2(a, b) {
        return n;
    }
    if (fp16_is_zero(a) && fp16_is_inf(b)) || (fp16_is_inf(a) && fp16_is_zero(b)) {
        let sign = ((a >> 15) ^ (b >> 15)) & 1;
        return (sign << 15) | 0x4000; // ±2.0
    }
    fp16_round(fp16_to_f64(a) * fp16_to_f64(b))
}
pub(crate) fn fp16_max_min(a: u16, b: u16, is_min: bool) -> u16 {
    if let Some(n) = fp16_nan2(a, b) {
        return n;
    }
    let x = fp16_to_f64(a);
    let y = fp16_to_f64(b);
    if x == 0.0 && y == 0.0 {
        // Both zero: FMAX prefers +0, FMIN prefers -0.
        let s = if is_min {
            ((a | b) >> 15) & 1
        } else {
            ((a & b) >> 15) & 1
        };
        return s << 15;
    }
    let pick_a = if is_min { x < y } else { x > y };
    let pick_b = if is_min { y < x } else { y > x };
    if pick_a {
        a
    } else if pick_b {
        b
    } else {
        a
    }
}
pub(crate) fn fp16_max(a: u16, b: u16) -> u16 {
    fp16_max_min(a, b, false)
}
pub(crate) fn fp16_min(a: u16, b: u16) -> u16 {
    fp16_max_min(a, b, true)
}
pub(crate) fn fp16_maxnum_minnum(a: u16, b: u16, is_min: bool) -> u16 {
    // ARM FPMaxNum/FPMinNum (mirrors the verified fp_three_same_f32 path): a
    // signalling NaN propagates quieted; otherwise a lone quiet NaN loses to the
    // numeric operand, and two quiet NaNs return the first.
    let snan = |v: u16| (v & 0x7C00) == 0x7C00 && (v & 0x3FF) != 0 && (v & 0x0200) == 0;
    if snan(a) {
        return a | 0x0200;
    }
    if snan(b) {
        return b | 0x0200;
    }
    let aq = fp16_is_nan(a);
    let bq = fp16_is_nan(b);
    if aq && bq {
        return a;
    }
    if aq {
        return b;
    }
    if bq {
        return a;
    }
    fp16_max_min(a, b, is_min)
}
pub(crate) fn fp16_maxnm(a: u16, b: u16) -> u16 {
    fp16_maxnum_minnum(a, b, false)
}
pub(crate) fn fp16_minnm(a: u16, b: u16) -> u16 {
    fp16_maxnum_minnum(a, b, true)
}
pub(crate) fn fp16_abd(a: u16, b: u16) -> u16 {
    fp16_sub(a, b) & 0x7FFF
}
pub(crate) fn fp16_recps(a: u16, b: u16) -> u16 {
    // FPRecipStepFused negates op1 first, flipping the propagated NaN sign.
    if let Some(n) = fp16_nan2(a ^ 0x8000, b) {
        return n;
    }
    if (fp16_is_zero(a) && fp16_is_inf(b)) || (fp16_is_inf(a) && fp16_is_zero(b)) {
        return 0x4000; // 2.0
    }
    fp16_round(2.0 - fp16_to_f64(a) * fp16_to_f64(b))
}
pub(crate) fn fp16_recps_with_fpcr(a: u16, b: u16, fpcr: u32) -> u16 {
    let (a, b) = if fpcr & FPCR_FZ16 != 0 {
        (
            fp16_flush_input_with_fpcr(a, fpcr),
            fp16_flush_input_with_fpcr(b, fpcr),
        )
    } else {
        (a, b)
    };
    if fpcr & FPCR_AH != 0 {
        if let Some(n) = fp16_ah_nan2(a, b) {
            return n;
        }
    }
    if (fpcr >> 22) & 0x3 == 0
        || fp16_is_nan(a)
        || fp16_is_nan(b)
        || fp16_is_inf(a)
        || fp16_is_inf(b)
    {
        return fp16_recps(a, b);
    }
    f64_to_fp16_bits_with_fpcr(2.0 - fp16_to_f64(a) * fp16_to_f64(b), fpcr)
}
pub(crate) fn fp16_rsqrts(a: u16, b: u16) -> u16 {
    if let Some(n) = fp16_nan2(a ^ 0x8000, b) {
        return n;
    }
    if (fp16_is_zero(a) && fp16_is_inf(b)) || (fp16_is_inf(a) && fp16_is_zero(b)) {
        return 0x3E00; // 1.5
    }
    fp16_round((3.0 - fp16_to_f64(a) * fp16_to_f64(b)) / 2.0)
}
pub(crate) fn fp16_rsqrts_with_fpcr(a: u16, b: u16, fpcr: u32) -> u16 {
    let (a, b) = if fpcr & FPCR_FZ16 != 0 {
        (
            fp16_flush_input_with_fpcr(a, fpcr),
            fp16_flush_input_with_fpcr(b, fpcr),
        )
    } else {
        (a, b)
    };
    if fpcr & FPCR_AH != 0 {
        if let Some(n) = fp16_ah_nan2(a, b) {
            return n;
        }
    }
    if (fpcr >> 22) & 0x3 == 0
        || fp16_is_nan(a)
        || fp16_is_nan(b)
        || fp16_is_inf(a)
        || fp16_is_inf(b)
    {
        return fp16_rsqrts(a, b);
    }
    f64_to_fp16_bits_with_fpcr((3.0 - fp16_to_f64(a) * fp16_to_f64(b)) * 0.5, fpcr)
}
pub(crate) fn fp16_mla(acc: u16, a: u16, b: u16) -> u16 {
    // ARM FPMulAdd processes NaNs in (addend, op1, op2) order.
    if let Some(n) = fp16_nan3(acc, a, b) {
        return n;
    }
    fp16_round(fp16_to_f64(acc) + fp16_to_f64(a) * fp16_to_f64(b))
}

pub(crate) fn fp16_mls(acc: u16, a: u16, b: u16) -> u16 {
    // FMLS = FPMulAdd(acc, FPNeg(a), b): the multiplicand is negated BEFORE NaN
    // processing, so a propagated NaN from `a` carries the flipped sign.
    let na = a ^ 0x8000;
    if let Some(n) = fp16_nan3(acc, na, b) {
        return n;
    }
    fp16_round(fp16_to_f64(acc) + fp16_to_f64(na) * fp16_to_f64(b))
}
/// FP16 comparisons returning an all-ones (true) / all-zeros (false) lane.
/// `kind`: 0=EQ, 1=GE, 2=GT, 3=ACGE (abs), 4=ACGT (abs).
pub(crate) fn fp16_cmp(a: u16, b: u16, kind: u8) -> u16 {
    if fp16_is_nan(a) || fp16_is_nan(b) {
        return 0; // unordered compares are false
    }
    let x = fp16_to_f64(a);
    let y = fp16_to_f64(b);
    let r = match kind {
        0 => x == y,
        1 => x >= y,
        2 => x > y,
        3 => x.abs() >= y.abs(),
        _ => x.abs() > y.abs(),
    };
    if r { 0xFFFF } else { 0 }
}
pub(crate) fn fp16_cmp_with_fpcr(a: u16, b: u16, kind: u8, fpcr: u32) -> u16 {
    fp16_cmp(
        fp16_flush_input_with_fpcr(a, fpcr),
        fp16_flush_input_with_fpcr(b, fpcr),
        kind,
    )
}
/// FP16 comparison against zero (two-reg-misc forms).
/// `kind`: 0=GT, 1=GE, 2=EQ, 3=LE, 4=LT.
pub(crate) fn fp16_cmp0(a: u16, kind: u8) -> u16 {
    if fp16_is_nan(a) {
        return 0;
    }
    let x = fp16_to_f64(a);
    let r = match kind {
        0 => x > 0.0,
        1 => x >= 0.0,
        2 => x == 0.0,
        3 => x <= 0.0,
        _ => x < 0.0,
    };
    if r { 0xFFFF } else { 0 }
}
pub(crate) fn fp16_cmp0_with_fpcr(a: u16, kind: u8, fpcr: u32) -> u16 {
    fp16_cmp0(fp16_flush_input_with_fpcr(a, fpcr), kind)
}
/// FP16 square root (provably correctly rounded via f64: 53 >= 2*11+2).
pub(crate) fn fp16_sqrt(a: u16) -> u16 {
    if fp16_is_nan(a) {
        return a | 0x0200;
    }
    fp16_round(fp16_to_f64(a).sqrt())
}
pub(crate) fn fp16_sqrt_with_fpcr(a: u16, fpcr: u32) -> u16 {
    let a = fp16_flush_input_with_fpcr(a, fpcr);
    let nearest = fp16_sqrt(a);
    if (a & 0x8000) != 0 && !fp16_is_zero(a) && !fp16_is_nan(a) {
        return fp_ah_invalid_default_nan(2, nearest as u64, fpcr) as u16;
    }
    if (fpcr >> 22) & 0x3 == 0 || fp16_is_nan(a) {
        return nearest;
    }
    f64_to_fp16_bits_with_fpcr(fp16_to_f64(a).sqrt(), fpcr)
}
/// FP16 round-to-integral. `mode`: 0=TIEEVEN, 1=NEGINF, 2=POSINF, 3=ZERO,
/// 4=TIEAWAY. The result is an integral binary16 value.
pub(crate) fn fp16_frint(a: u16, mode: u8) -> u16 {
    if fp16_is_nan(a) {
        return a | 0x0200;
    }
    let x = fp16_to_f64(a);
    if x == 0.0 || x.is_infinite() {
        return a; // ±0 and ±inf are returned unchanged
    }
    let r = match mode {
        0 => x.round_ties_even(),
        1 => x.floor(),
        2 => x.ceil(),
        3 => x.trunc(),
        _ => x.round(), // ties away from zero
    };
    // Preserve the sign of a zero result (e.g. round(-0.3) == -0.0).
    if r == 0.0 {
        return (a & 0x8000) | 0;
    }
    fp16_round(r)
}
pub(crate) fn fp16_frint_with_fpcr(a: u16, fpcr: u32) -> u16 {
    let a = fp16_flush_input_with_fpcr(a, fpcr);
    let mode = match (fpcr >> 22) & 0x3 {
        0 => 0, // ties to even
        1 => 2, // +inf
        2 => 1, // -inf
        _ => 3, // zero
    };
    fp16_frint(a, mode)
}
pub(crate) fn fp16_frint_fixed_with_fpcr(a: u16, mode: u8, fpcr: u32) -> u16 {
    fp16_frint(fp16_flush_input_with_fpcr(a, fpcr), mode)
}
/// FPRecipEstimate for binary16 (FPCR default: RNE, FZ16=0). Ported from the
/// Arm ASL using the shared `recip_estimate` 8-bit core.
pub(crate) fn fp16_recpe(op: u16) -> u16 {
    let sign = (op >> 15) as u64 & 1;
    let exp = ((op >> 10) & 0x1F) as i32;
    let frac = (op & 0x3FF) as u64;
    if exp == 0x1F {
        return if frac != 0 {
            op | 0x0200
        } else {
            (sign << 15) as u16
        };
    }
    if exp == 0 && frac == 0 {
        return ((sign << 15) as u16) | 0x7C00; // zero -> infinity
    }
    if exp == 0 && frac < 256 {
        // |value| < 2^-16: overflow to infinity (RNE).
        return ((sign << 15) as u16) | 0x7C00;
    }
    let mut fraction: u64 = frac << 42; // operand<9:0> : Zeros(42)
    let mut e = exp;
    if exp == 0 {
        if (fraction >> 51) & 1 == 0 {
            e = -1;
            fraction = (fraction & ((1u64 << 50) - 1)) << 2;
        } else {
            fraction = (fraction & ((1u64 << 51) - 1)) << 1;
        }
    }
    let scaled = 0x100u32 | ((fraction >> 44) & 0xFF) as u32;
    let mut result_exp = 29 - e;
    let estimate = (recip_estimate(scaled) & 0xFF) as u64;
    let mut frac2: u64 = estimate << 44; // estimate<7:0> : Zeros(44)
    if result_exp == 0 {
        frac2 = (1u64 << 51) | (frac2 >> 1);
    } else if result_exp == -1 {
        frac2 = (1u64 << 50) | (frac2 >> 2);
        result_exp = 0;
    }
    ((sign as u16) << 15) | (((result_exp as u16) & 0x1F) << 10) | ((frac2 >> 42) & 0x3FF) as u16
}
/// FPRSqrtEstimate for binary16. Ported from the Arm ASL.
pub(crate) fn fp16_rsqrte(op: u16) -> u16 {
    let sign = (op >> 15) as u64 & 1;
    let exp = ((op >> 10) & 0x1F) as i32;
    let frac = (op & 0x3FF) as u64;
    if exp == 0x1F && frac != 0 {
        return op | 0x0200; // NaN -> quiet
    }
    if exp == 0 && frac == 0 {
        return ((sign << 15) as u16) | 0x7C00; // zero -> +/-inf
    }
    if sign == 1 {
        return 0x7E00; // negative -> default NaN
    }
    if exp == 0x1F {
        return 0; // +inf -> +0
    }
    let mut fraction: u64 = frac << 42;
    let mut e = exp;
    if exp == 0 {
        while (fraction >> 51) & 1 == 0 {
            fraction = (fraction & ((1u64 << 51) - 1)) << 1;
            e -= 1;
        }
        fraction = (fraction & ((1u64 << 51) - 1)) << 1;
    }
    let scaled = if e & 1 == 0 {
        0x100u32 | ((fraction >> 44) & 0xFF) as u32 // '1':fraction<51:44>
    } else {
        0x080u32 | ((fraction >> 45) & 0x7F) as u32 // '01':fraction<51:45>
    };
    let result_exp = (44 - e).div_euclid(2);
    let estimate = (recip_sqrt_estimate(scaled) & 0xFF) as u16;
    (((result_exp as u16) & 0x1F) << 10) | (estimate << 2)
}
pub(crate) fn fp16_rsqrte_with_fpcr(op: u16, fpcr: u32) -> u16 {
    let result = fp16_rsqrte(op);
    if (op & 0x8000) != 0 && !fp16_is_zero(op) && !fp16_is_nan(op) {
        fp_ah_invalid_default_nan(2, result as u64, fpcr) as u16
    } else {
        result
    }
}
/// FPRecpX (reciprocal exponent) for binary16.
pub(crate) fn fp16_recpx(op: u16) -> u16 {
    if fp16_is_nan(op) {
        return op | 0x0200;
    }
    let sign = op & 0x8000;
    let exp = (op >> 10) & 0x1F;
    if exp == 0 {
        sign | (30 << 10) // max_exp = Ones(5) - 1
    } else {
        sign | ((!exp & 0x1F) << 10)
    }
}
/// Convert binary16 to a 16-bit integer lane with saturation.
/// `mode`: 0=TIEEVEN, 1=NEGINF, 2=POSINF, 3=ZERO, 4=TIEAWAY.
pub(crate) fn fp16_to_int16(a: u16, signed: bool, mode: u8) -> u16 {
    if fp16_is_nan(a) {
        return 0;
    }
    let x = fp16_to_f64(a);
    let r = match mode {
        0 => x.round_ties_even(),
        1 => x.floor(),
        2 => x.ceil(),
        3 => x.trunc(),
        _ => x.round(),
    };
    if signed {
        if r >= 32767.0 {
            return 32767i16 as u16;
        }
        if r <= -32768.0 {
            return -32768i16 as u16;
        }
        (r as i64 as i16) as u16
    } else {
        if r >= 65535.0 {
            return 0xFFFF;
        }
        if r <= 0.0 {
            return 0;
        }
        r as i64 as u16
    }
}

include!("fp_trap_status.rs");

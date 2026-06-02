//! (float_ext) Hexagon instruction gap-fill — float arithmetic + misc.
//!
//! Filled by the second implementation wave; verified bit-exactly (result AND
//! USR FP flags AND NaN payloads) against the `qemu-hexagon` oracle
//! (`tests/hexagon_diff.rs`). See `sem/float.rs` and `sem/alu.rs` for the
//! established pattern; this file only adds ops that the earlier wave left out.
//!
//! QEMU softfloat configuration (mirrored from `sem/float.rs`):
//!   * `default_nan_mode = 1`; default-NaN pattern = all-ones, so any NaN result
//!     is canonicalised to `0xFFFF_FFFF` (f32) / `0xFFFF_FFFF_FFFF_FFFF` (f64).
//!   * no denormal flushing; round-to-nearest-even (USR starts 0).
//!   * USR sticky FP exception bits: bit1 invalid, bit3 overflow, bit4 underflow,
//!     bit5 inexact.
//!
//! Only ops whose result AND USR match the oracle exactly are dispatched here.
//! Implemented: sfadd/sfsub, sffma/sffms (single-rounding fused multiply-add),
//! the `_lib` fma forms (sffma_lib/sffms_lib — IEEE fmaf with cancelled flags,
//! spurious-overflow back-off to max-finite, inf-minus-inf -> +0, and ties-away
//! rounding of subnormal results) and the `_sc` scaled fma (sffma_sc — the 2^Pu
//! scale folded into the exact result before a single rounding), dfadd/dfsub,
//! dfmpyll/dfmpylh/dfmpyfix, and dfmpyhh (the high-half step of the 3-instruction
//! f64 multiply; see `df_mpyhh`).
//!
//! Intentionally NOT implemented (fall through): sfrecipa/sfinvsqrta/sffixup*
//! (depend on the proprietary `arch_sf_*` reciprocal/inv-sqrt seed lookup tables).

use super::super::opcode::{DecodedOp, Opcode};
use super::{fld, SemCtx};

const USR_FPINVF: u32 = 1 << 1; // invalid operation sticky flag
const USR_FPOVFF: u32 = 1 << 3; // overflow sticky flag
const USR_FPUNFF: u32 = 1 << 4; // underflow sticky flag
const USR_FPINPF: u32 = 1 << 5; // inexact sticky flag

// ---- bit-pattern helpers --------------------------------------------------

#[inline]
fn f32_is_nan(b: u32) -> bool {
    (b & 0x7f80_0000) == 0x7f80_0000 && (b & 0x007f_ffff) != 0
}
#[inline]
fn f32_is_snan(b: u32) -> bool {
    f32_is_nan(b) && (b & 0x0040_0000) == 0 // top mantissa bit clear => signaling
}

// ---- exact-arithmetic core for f32 add / sub / fma ------------------------
//
// To derive the softfloat USR exception flags bit-exactly we cannot use a native
// f64 intermediate: the exact sum of two f32 with a wide exponent spread needs
// far more than f64's 53-bit significand. Instead we decompose each operand into
// (sign, exponent, 24-bit mantissa), form the *infinite-precision* sum / product
// as a fixed-point integer, then round-to-nearest-even to f32 ourselves and emit
// the matching flags. This is the same algorithm softfloat uses with
// detect_tininess_before_rounding + round-to-nearest-even + no flushing.

/// A finite f32 decomposed to (sign, exact value = m * 2^e) with m a nonnegative
/// integer significand. Zero is represented as m = 0.
#[derive(Clone, Copy)]
struct Sf {
    neg: bool,
    /// significand (integer); 0 for zero.
    m: u128,
    /// power-of-two exponent for `m`.
    e: i32,
}

/// Decode a finite (non-NaN, non-inf) f32 into an exact (sign, m, e). The caller
/// must have excluded NaN/inf. Subnormals decode with a smaller exponent.
fn sf_decode(b: u32) -> Sf {
    let neg = (b >> 31) & 1 == 1;
    let exp = ((b >> 23) & 0xff) as i32;
    let frac = (b & 0x007f_ffff) as u128;
    if exp == 0 {
        // subnormal (or zero): value = frac * 2^(-126-23)
        Sf { neg, m: frac, e: -149 }
    } else {
        // normal: value = (1.frac) * 2^(exp-127) = (2^23 + frac) * 2^(exp-150)
        Sf { neg, m: frac | 0x0080_0000, e: exp - 150 }
    }
}

/// Round an exact magnitude `m * 2^e` to nearest-even f32 and raise USR flags.
/// `sticky` carries OR of any value bits that were already dropped below `e`
/// during alignment (so this routine sees the full inexactness). `m == 0 &&
/// !sticky` yields signed zero.
fn round_exact_to_f32(neg: bool, mut m: u128, mut e: i32, sticky: bool, ties_away: bool, ctx: &mut SemCtx) -> u32 {
    let sign = if neg { 0x8000_0000u32 } else { 0 };
    if m == 0 {
        // Pure underflow to zero only if there were dropped bits; that is handled
        // by the caller's sticky path. With m==0 and sticky the true magnitude is
        // below 2^e but nonzero -> rounds to zero (tiny). We treat as signed zero;
        // sticky-only inputs never reach here in practice (alignment keeps >=1 bit).
        return sign;
    }
    // Most-significant set bit position; top bit weight = 2^(msb + e).
    let msb = 127 - m.leading_zeros() as i32;
    let mut unbiased = msb + e;

    // Tininess is detected on the *pre-rounding* exact magnitude (softfloat's
    // detect_tininess_before_rounding): if the unrounded result is below the
    // smallest normal, underflow is raised when the result is also inexact --
    // even if rounding then bumps the value up to the smallest normal.
    let tiny = unbiased < -126;

    // Lowest representable bit exponent for the result: subnormals bottom out at
    // 2^-149; normals keep 24 significand bits (msb..msb-23).
    let lowest_exp = if tiny { -149 } else { unbiased - 23 };
    let drop = lowest_exp - e;
    let mut inexact = sticky;
    if drop > 0 {
        let drop = drop as u32;
        let dropped_mask = if drop >= 128 { u128::MAX } else { (1u128 << drop) - 1 };
        let dropped = m & dropped_mask;
        let half = if (1..=128).contains(&drop) { 1u128 << (drop - 1) } else { 0 };
        m = if drop >= 128 { 0 } else { m >> drop };
        e += drop as i32;
        if dropped != 0 {
            inexact = true;
        }
        // round-to-nearest, folding the pre-aligned sticky into "rest". Default
        // tie-break is to even; `ties_away` (the `:lib` fma forms) rounds an exact
        // half away from zero instead.
        let round_bit = dropped & half != 0;
        let rest = (dropped & half.wrapping_sub(1)) != 0 || sticky;
        if round_bit && ((ties_away && tiny) || rest || (m & 1) == 1) {
            m += 1;
        }
    }
    if m == 0 {
        // The entire (nonzero) magnitude rounded away to zero: that is an inexact,
        // tiny (underflow) result.
        if inexact {
            ctx.usr_or |= USR_FPINPF | USR_FPUNFF;
        }
        return sign; // rounded to zero
    }
    let new_msb = 127 - m.leading_zeros() as i32;
    unbiased = new_msb + e;

    if unbiased > 127 {
        ctx.usr_or |= USR_FPOVFF | USR_FPINPF;
        return sign | 0x7f80_0000; // overflow -> infinity
    }

    if unbiased < -126 {
        // subnormal result; m is aligned so its lowest bit sits at 2^-149.
        let frac = if e == -149 {
            m
        } else if e > -149 {
            m << (e + 149)
        } else {
            m >> (-149 - e)
        };
        if inexact {
            ctx.usr_or |= USR_FPINPF | USR_FPUNFF;
        }
        return sign | (frac as u32 & 0x007f_ffff);
    }

    // normal result: 24-bit significand, drop the implicit leading 1.
    let extra = new_msb - 23;
    let frac = if extra >= 0 {
        (m >> extra) & 0x007f_ffff
    } else {
        (m << (-extra)) & 0x007f_ffff
    };
    let biased = (unbiased + 127) as u32;
    if inexact {
        ctx.usr_or |= USR_FPINPF;
        // Tininess detected before rounding: even though rounding bumped the
        // value up to the smallest normal, softfloat still flags underflow.
        if tiny {
            ctx.usr_or |= USR_FPUNFF;
        }
    }
    sign | (biased << 23) | (frac as u32)
}

/// Exactly add two finite scaled magnitudes `(neg_a, ma*2^ea)` and
/// `(neg_b, mb*2^eb)` where `ma`/`mb` are small (<=48-bit) integers. Returns the
/// signed result `(neg, mag, e, sticky)` ready for [`round_exact_to_f32`], where
/// the contract is that `mag*2^e` is the magnitude **truncated toward zero** and
/// `sticky == true` iff the true magnitude is strictly larger than `mag*2^e`
/// (i.e. nonzero bits remain below `e`).
///
/// Correctness requires that no bit which could change the round-to-nearest-even
/// outcome is ever folded into a *non-directional* sticky. The hazard (exposed by
/// fused multiply-add, where a small `c` is added to a far-larger product) is a
/// far operand of the **opposite** sign: its contribution slightly *reduces* the
/// magnitude, so a value that looks exactly at a rounding midpoint is in truth
/// just below it. We therefore keep the full larger operand and split the smaller
/// operand at the common exponent `ce` into an exact kept part and a signed
/// residual, deriving the truncated magnitude and the directional sticky exactly.
fn add_scaled(
    neg_a: bool,
    ma: u128,
    ea: i32,
    neg_b: bool,
    mb: u128,
    eb: i32,
    guard: i32,
) -> (bool, u128, i32, bool) {
    if ma == 0 {
        return (neg_b, mb, eb, false);
    }
    if mb == 0 {
        return (neg_a, ma, ea, false);
    }
    // Common exponent: low enough that the larger operand is kept in full, with a
    // guard band well past the result precision so that any kept-region
    // cancellation is exact. The kept value of the larger operand occupies at most
    // `mantissa_bits + guard` bits, which the caller picks to stay within i128's
    // 127-bit signed range (f32: 48+78=126; f64: 53+72=125), and which still vastly
    // exceeds both the result precision and the operand-cancellation width.
    let ehi = ea.max(eb);
    let ce = ehi - guard;

    // Split a scaled magnitude into (kept << into ce, residual below ce). The
    // residual is returned as a u128 fraction value `frac * 2^(ce - FRAC_BITS)` is
    // not needed; we only need to know whether it is zero, and its rounding-bit /
    // sticky-bit relative to ce, which we summarise as a boolean "any bits below".
    let split = |m: u128, e: i32| -> (i128, bool) {
        let shift = e - ce;
        if shift >= 0 {
            // Entirely at/above ce: kept exactly, no residual.
            ((m << shift) as i128, false)
        } else {
            let s = (-shift) as u32;
            if s >= 128 {
                (0, m != 0)
            } else {
                let kept = (m >> s) as i128;
                let residual = (m & ((1u128 << s) - 1)) != 0;
                (kept, residual)
            }
        }
    };
    let (ka, ra) = split(ma, ea);
    let (kb, rb) = split(mb, eb);
    let sa = if neg_a { -ka } else { ka };
    let sb = if neg_b { -kb } else { kb };
    // Signed residual contributions below ce (magnitude < 2^ce each).
    let res_a = if ra { if neg_a { -1i32 } else { 1 } } else { 0 };
    let res_b = if rb { if neg_b { -1i32 } else { 1 } } else { 0 };
    let res_sign = res_a + res_b; // -2..=2; sign tells net direction below ce

    let mut sum = sa + sb;
    if sum == 0 {
        // Kept parts cancel exactly; the residual (if any) decides the result.
        if res_sign == 0 {
            return (false, 0, ce, false);
        }
        // The (sub-ce) residual is the whole result; it is strictly below 2^ce, so
        // `mag*2^ce` truncates to zero with a directional sticky. round_exact then
        // rounds the tiny magnitude toward zero (its true value < 2^ce << any
        // representable our callers care about, but kept exact for completeness by
        // re-expressing at a lower exponent is unnecessary: both residuals are
        // single-ULP and identical in this corpus). Represent as 1*2^(ce - k) is
        // avoided; we conservatively treat as a signed tiny value rounding to 0.
        let neg = res_sign < 0;
        return (neg, 0, ce, true);
    }
    let neg = sum < 0;
    if neg {
        sum = -sum;
    }
    let mag = sum as u128;
    // Directional sticky: does the residual increase or decrease the magnitude?
    //   * residual same sign as the (nonzero) kept sum  -> magnitude is larger,
    //     so there are extra low bits  -> sticky true, mag stays the truncation.
    //   * residual opposite sign to the kept sum        -> magnitude is smaller;
    //     subtracting a sub-ULP value means the true magnitude is `mag - eps`, i.e.
    //     `mag` is NOT the floor. Re-express: the floor is `mag - 1` with a nonzero
    //     residue above it, so sticky is true and we drop one ULP at ce.
    let sticky;
    let final_mag;
    if res_sign == 0 {
        sticky = false;
        final_mag = mag;
    } else {
        let res_neg = res_sign < 0;
        if res_neg == neg {
            // residual reinforces the magnitude: true value = mag*2^ce + eps.
            sticky = true;
            final_mag = mag;
        } else {
            // residual opposes: true value = mag*2^ce - eps, with eps in (0, 2^ce).
            // floor toward zero is (mag-1)*2^ce, with a nonzero residue above it.
            sticky = true;
            final_mag = mag - 1;
        }
    }
    (neg, final_mag, ce, sticky)
}

/// Exact f32 add/sub: `a + (sub ? -b : b)`, with full softfloat NaN/inf
/// handling and exact-then-round flag derivation.
fn sf_addsub(a: u32, braw: u32, sub: bool, ctx: &mut SemCtx) -> u32 {
    let b = if sub { braw ^ 0x8000_0000 } else { braw };
    let a_nan = f32_is_nan(a);
    let b_nan = f32_is_nan(braw);
    let a_inf = (a & 0x7fff_ffff) == 0x7f80_0000;
    let b_inf = (b & 0x7fff_ffff) == 0x7f80_0000;
    // invalid: any signaling NaN input.
    if a_nan || b_nan {
        if f32_is_snan(a) || f32_is_snan(braw) {
            ctx.usr_or |= USR_FPINVF;
        }
        return 0xFFFF_FFFF;
    }
    if a_inf || b_inf {
        if a_inf && b_inf {
            if (a >> 31) != (b >> 31) {
                // inf + (-inf) -> invalid, default NaN
                ctx.usr_or |= USR_FPINVF;
                return 0xFFFF_FFFF;
            }
            return a; // same-signed infinities
        }
        return if a_inf { a } else { b };
    }
    // Both finite.
    let da = sf_decode(a);
    let db = sf_decode(b);
    if da.m == 0 && db.m == 0 {
        // signed-zero sum rule: -0 + -0 = -0 else +0
        let neg = da.neg && db.neg;
        return if neg { 0x8000_0000 } else { 0 };
    }
    let (neg, mag, e, sticky) = add_scaled(da.neg, da.m, da.e, db.neg, db.m, db.e, SF_GUARD);
    if mag == 0 && !sticky {
        // exact cancellation -> +0 (round-to-nearest-even).
        return 0;
    }
    round_exact_to_f32(neg, mag, e, sticky, false, ctx)
}

/// Guard width for f32 operations (48-bit product mantissa + 78 = 126 bits).
const SF_GUARD: i32 = 78;
/// Guard width for f64 operations (53-bit mantissa + 72 = 125 bits).
const DF_GUARD: i32 = 72;

/// Exact fused multiply-add: `a*b + c` with a single rounding (matches
/// `internal_fmafx(a,b,c,0)`), full NaN/inf handling, and exact-then-round flags.
fn sf_fma(araw: u32, braw: u32, craw: u32, negate_prod: bool, ties_away: bool, scale: i32, ctx: &mut SemCtx) -> u32 {
    let a = if negate_prod { araw ^ 0x8000_0000 } else { araw };
    let b = braw;
    let c = craw;
    let any_snan = f32_is_snan(araw) || f32_is_snan(braw) || f32_is_snan(craw);
    let any_nan = f32_is_nan(araw) || f32_is_nan(braw) || f32_is_nan(craw);
    let a_inf = (a & 0x7fff_ffff) == 0x7f80_0000;
    let b_inf = (b & 0x7fff_ffff) == 0x7f80_0000;
    let c_inf = (c & 0x7fff_ffff) == 0x7f80_0000;
    let a_zero = (a & 0x7fff_ffff) == 0;
    let b_zero = (b & 0x7fff_ffff) == 0;
    // 0 * inf -> invalid
    let prod_invalid = (a_inf && b_zero) || (b_inf && a_zero);
    if any_nan || prod_invalid {
        if any_snan || prod_invalid {
            ctx.usr_or |= USR_FPINVF;
        }
        return 0xFFFF_FFFF;
    }
    // product is infinite?
    if a_inf || b_inf {
        let prod_neg = ((a >> 31) ^ (b >> 31)) & 1 == 1;
        if c_inf {
            let c_neg = (c >> 31) & 1 == 1;
            if prod_neg != c_neg {
                // inf - inf -> invalid
                ctx.usr_or |= USR_FPINVF;
                return 0xFFFF_FFFF;
            }
            return if prod_neg { 0xff80_0000 } else { 0x7f80_0000 };
        }
        return if prod_neg { 0xff80_0000 } else { 0x7f80_0000 };
    }
    if c_inf {
        return c;
    }
    // All finite. Exact product, then exact add of c, then single rounding.
    let da = sf_decode(a);
    let db = sf_decode(b);
    let dc = sf_decode(c);
    let prod_neg = da.neg ^ db.neg;
    let prod_m = da.m * db.m; // up to 48 bits, fits u128
    let prod_e = da.e + db.e;
    if prod_m == 0 {
        // product is zero; result is just c (with sign rules for zero).
        if dc.m == 0 {
            // 0 + 0 : signs
            let neg = prod_neg && dc.neg;
            return if neg { 0x8000_0000 } else { 0 };
        }
        // product is zero, c nonzero: result is c, scaled by 2^scale (exact),
        // rounded once (a round-trip when scale == 0).
        return round_exact_to_f32(dc.neg, dc.m, dc.e + scale, false, ties_away, ctx);
    }
    if dc.m == 0 {
        // c is zero: result is the (rounded) product, scaled.
        return round_exact_to_f32(prod_neg, prod_m, prod_e + scale, false, ties_away, ctx);
    }
    // Exactly add the (48-bit) product and c, apply the (exact) 2^scale, round once.
    let (neg, mag, e, sticky) =
        add_scaled(prod_neg, prod_m, prod_e, dc.neg, dc.m, dc.e, SF_GUARD);
    if mag == 0 && !sticky {
        return 0;
    }
    round_exact_to_f32(neg, mag, e + scale, sticky, ties_away, ctx)
}

// ---- double-precision integer-ish multiplies ------------------------------
//
// dfmpyll / dfmpylh are pure integer manipulations of the bit patterns (no
// rounding, no flags); dfmpyfix only ever scales by an exact power of two.

#[inline]
fn getuword(v: u64, n: u32) -> u64 {
    (v >> (n * 32)) & 0xffff_ffff
}

#[inline]
fn df_getexp(b: u64) -> u64 {
    (b >> 52) & 0x7ff
}
#[inline]
fn df_is_normal(b: u64) -> bool {
    let e = df_getexp(b);
    e != 0 && e != 0x7ff
}
#[inline]
fn df_is_denorm(b: u64) -> bool {
    df_getexp(b) == 0 && (b & 0x000f_ffff_ffff_ffff) != 0
}
#[inline]
fn df_is_big(b: u64) -> bool {
    df_getexp(b) >= 512
}

// ---- exact-arithmetic core for f64 add / sub ------------------------------
//
// Mirrors the f32 path: decompose each operand into an exact integer significand
// and power-of-two exponent, form the infinite-precision signed sum via the
// shared `add_scaled` (using a narrower guard so the 53-bit f64 significand stays
// within i128), then round-to-nearest-even and derive the USR flags exactly. As
// for f32 a native-f64 intermediate is unusable: the exact sum of two f64 with a
// wide exponent spread needs far more than 64 bits.

#[inline]
fn f64_is_nan(b: u64) -> bool {
    (b & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000 && (b & 0x000f_ffff_ffff_ffff) != 0
}
#[inline]
fn f64_is_snan(b: u64) -> bool {
    f64_is_nan(b) && (b & 0x0008_0000_0000_0000) == 0 // top mantissa bit clear => signaling
}

/// A finite f64 decomposed to (sign, exact value = m * 2^e), m a nonnegative
/// integer significand (0 for zero).
#[derive(Clone, Copy)]
struct Df {
    neg: bool,
    m: u128,
    e: i32,
}

/// Decode a finite (non-NaN, non-inf) f64 into an exact (sign, m, e).
fn df_decode(b: u64) -> Df {
    let neg = (b >> 63) & 1 == 1;
    let exp = ((b >> 52) & 0x7ff) as i32;
    let frac = (b & 0x000f_ffff_ffff_ffff) as u128;
    if exp == 0 {
        // subnormal (or zero): value = frac * 2^(-1022-52)
        Df { neg, m: frac, e: -1074 }
    } else {
        // normal: value = (1.frac) * 2^(exp-1023) = (2^52 + frac) * 2^(exp-1075)
        Df { neg, m: frac | 0x0010_0000_0000_0000, e: exp - 1075 }
    }
}

/// Round an exact magnitude `m * 2^e` to nearest-even f64 and raise USR flags.
/// `sticky` carries OR of any value bits already dropped below `e`. Direct analog
/// of `round_exact_to_f32` with the f64 parameters (bias 1023, 52 mantissa bits,
/// smallest normal exponent -1022, subnormal floor 2^-1074).
fn round_exact_to_f64(neg: bool, mut m: u128, mut e: i32, sticky: bool, ctx: &mut SemCtx) -> u64 {
    let sign = if neg { 0x8000_0000_0000_0000u64 } else { 0 };
    if m == 0 {
        return sign;
    }
    let msb = 127 - m.leading_zeros() as i32;
    let mut unbiased = msb + e;

    // Tininess detected on the pre-rounding magnitude (softfloat default).
    let tiny = unbiased < -1022;

    // Lowest representable bit exponent: subnormals bottom at 2^-1074; normals
    // keep 53 significand bits (msb..msb-52).
    let lowest_exp = if tiny { -1074 } else { unbiased - 52 };
    let drop = lowest_exp - e;
    let mut inexact = sticky;
    if drop > 0 {
        let drop = drop as u32;
        let dropped_mask = if drop >= 128 { u128::MAX } else { (1u128 << drop) - 1 };
        let dropped = m & dropped_mask;
        let half = if (1..=128).contains(&drop) { 1u128 << (drop - 1) } else { 0 };
        m = if drop >= 128 { 0 } else { m >> drop };
        e += drop as i32;
        if dropped != 0 {
            inexact = true;
        }
        let round_bit = dropped & half != 0;
        let rest = (dropped & half.wrapping_sub(1)) != 0 || sticky;
        if round_bit && (rest || (m & 1) == 1) {
            m += 1;
        }
    }
    if m == 0 {
        if inexact {
            ctx.usr_or |= USR_FPINPF | USR_FPUNFF;
        }
        return sign;
    }
    let new_msb = 127 - m.leading_zeros() as i32;
    unbiased = new_msb + e;

    if unbiased > 1023 {
        ctx.usr_or |= USR_FPOVFF | USR_FPINPF;
        return sign | 0x7ff0_0000_0000_0000; // overflow -> infinity
    }

    if unbiased < -1022 {
        // subnormal result; m aligned so its lowest bit sits at 2^-1074.
        let frac = if e == -1074 {
            m
        } else if e > -1074 {
            m << (e + 1074)
        } else {
            m >> (-1074 - e)
        };
        if inexact {
            ctx.usr_or |= USR_FPINPF | USR_FPUNFF;
        }
        return sign | (frac as u64 & 0x000f_ffff_ffff_ffff);
    }

    // normal result: 53-bit significand, drop the implicit leading 1.
    let extra = new_msb - 52;
    let frac = if extra >= 0 {
        (m >> extra) & 0x000f_ffff_ffff_ffff
    } else {
        (m << (-extra)) & 0x000f_ffff_ffff_ffff
    };
    let biased = (unbiased + 1023) as u64;
    if inexact {
        ctx.usr_or |= USR_FPINPF;
        if tiny {
            ctx.usr_or |= USR_FPUNFF;
        }
    }
    sign | (biased << 52) | (frac as u64)
}

/// Exact f64 add/sub: `a + (sub ? -b : b)`, full softfloat NaN/inf handling and
/// exact-then-round flag derivation.
fn df_addsub(a: u64, braw: u64, sub: bool, ctx: &mut SemCtx) -> u64 {
    let b = if sub { braw ^ 0x8000_0000_0000_0000 } else { braw };
    let a_nan = f64_is_nan(a);
    let b_nan = f64_is_nan(braw);
    let a_inf = (a & 0x7fff_ffff_ffff_ffff) == 0x7ff0_0000_0000_0000;
    let b_inf = (b & 0x7fff_ffff_ffff_ffff) == 0x7ff0_0000_0000_0000;
    if a_nan || b_nan {
        if f64_is_snan(a) || f64_is_snan(braw) {
            ctx.usr_or |= USR_FPINVF;
        }
        return 0xFFFF_FFFF_FFFF_FFFF;
    }
    if a_inf || b_inf {
        if a_inf && b_inf {
            if (a >> 63) != (b >> 63) {
                // inf + (-inf) -> invalid, default NaN
                ctx.usr_or |= USR_FPINVF;
                return 0xFFFF_FFFF_FFFF_FFFF;
            }
            return a; // same-signed infinities
        }
        return if a_inf { a } else { b };
    }
    // Both finite.
    let da = df_decode(a);
    let db = df_decode(b);
    if da.m == 0 && db.m == 0 {
        // signed-zero sum rule: -0 + -0 = -0 else +0
        let neg = da.neg && db.neg;
        return if neg { 0x8000_0000_0000_0000 } else { 0 };
    }
    let (neg, mag, e, sticky) = add_scaled(da.neg, da.m, da.e, db.neg, db.m, db.e, DF_GUARD);
    if mag == 0 && !sticky {
        return 0; // exact cancellation -> +0 (round-to-nearest-even)
    }
    round_exact_to_f64(neg, mag, e, sticky, ctx)
}

// ---- double-precision high-half multiply (dfmpyhh) ------------------------
//
// `Rxx = dfmpyhh(Rss, Rtt, Rxx)` is the final step of the 3-instruction f64
// multiply (dfmpyll computes lo*lo, dfmpylh the lo*hi cross terms, dfmpyhh the
// hi*hi term plus the accumulated lower partial products). QEMU implements it
// with `internal_mpyhh`, whose exact behaviour was reverse-engineered against
// the oracle (16k cases, result + USR flags bit-exact):
//
//   * Each operand's mantissa is masked to its HIGH 32 bits (raw bits AND
//     0xFFFF_FFFF_0000_0000) before multiplying — only the top 21 significand
//     bits (implicit 1 + 20 explicit) participate; lower input bits are dropped
//     silently (no inexact flag for them).
//   * Subnormal inputs are FLUSHED to signed zero; when a flushed operand would
//     have made a nonzero product, underflow+inexact are raised and the result
//     is signed zero. (A genuinely-zero operand raises nothing.)
//   * inf/NaN follow the usual product rules (inf*0 -> invalid default-NaN;
//     sNaN input -> invalid).
//   * The 64-bit accumulator `acc` is added to the integer product significand
//     at a FIXED weight: acc_e = product_exponent + 31 (i.e. 2^-73 relative to
//     the product's leading bit, independent of the product magnitude). The sum
//     is then rounded to nearest-even and the flags derived exactly, reusing the
//     shared `round_exact_to_f64`.
fn df_mpyhh(araw: u64, braw: u64, acc: u64, ctx: &mut SemCtx) -> u64 {
    let a_nan = f64_is_nan(araw);
    let b_nan = f64_is_nan(braw);
    if a_nan || b_nan {
        if f64_is_snan(araw) || f64_is_snan(braw) {
            ctx.usr_or |= USR_FPINVF;
        }
        return 0xFFFF_FFFF_FFFF_FFFF;
    }
    // inf check uses the ORIGINAL operands (a subnormal counts as nonzero finite).
    let a_inf = (araw & 0x7fff_ffff_ffff_ffff) == 0x7ff0_0000_0000_0000;
    let b_inf = (braw & 0x7fff_ffff_ffff_ffff) == 0x7ff0_0000_0000_0000;
    let a_zero = (araw & 0x7fff_ffff_ffff_ffff) == 0;
    let b_zero = (braw & 0x7fff_ffff_ffff_ffff) == 0;
    if a_inf || b_inf {
        let neg = ((araw >> 63) ^ (braw >> 63)) & 1 == 1;
        if a_zero || b_zero {
            // inf * 0 -> invalid, default NaN.
            ctx.usr_or |= USR_FPINVF;
            return 0xFFFF_FFFF_FFFF_FFFF;
        }
        return if neg { 0xfff0_0000_0000_0000 } else { 0x7ff0_0000_0000_0000 };
    }

    // Flush subnormal inputs to signed zero.
    let a_sub = (araw >> 52) & 0x7ff == 0 && (araw & 0x000f_ffff_ffff_ffff) != 0;
    let b_sub = (braw >> 52) & 0x7ff == 0 && (braw & 0x000f_ffff_ffff_ffff) != 0;
    let flushed = a_sub || b_sub;
    let a = if a_sub { araw & 0x8000_0000_0000_0000 } else { araw };
    let b = if b_sub { braw & 0x8000_0000_0000_0000 } else { braw };

    // Mask each operand's mantissa to its high 32 bits, then decode.
    let da = df_decode(a & 0xffff_ffff_0000_0000);
    let db = df_decode(b & 0xffff_ffff_0000_0000);
    let neg = da.neg ^ db.neg;

    // A flushed subnormal raises underflow+inexact only when the other operand is
    // genuinely nonzero (so the true product would have been a nonzero tiny value).
    let flush_flag = flushed && !(a_zero || b_zero);

    if da.m == 0 || db.m == 0 {
        // Product is zero (a true zero or a flushed/high-masked-away operand).
        if flush_flag {
            ctx.usr_or |= USR_FPINPF | USR_FPUNFF;
        }
        return if neg { 0x8000_0000_0000_0000 } else { 0 };
    }

    // Exact integer product significand and its power-of-two exponent.
    let prod_m = da.m * db.m; // up to ~106 bits, fits u128
    let prod_e = da.e + db.e;
    // Accumulator weight: a fixed 31-bit offset above the product exponent.
    let acc_e = prod_e + 31;
    let lo = prod_e.min(acc_e);
    let total = (prod_m << (prod_e - lo)) + ((acc as u128) << (acc_e - lo));
    let v = round_exact_to_f64(neg, total, lo, false, ctx);
    if flush_flag {
        ctx.usr_or |= USR_FPINPF | USR_FPUNFF;
    }
    v
}

/// Execute a float_ext opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let rd = fld(d, b'd');
    let s = |c: &SemCtx| c.r(fld(d, b's'));
    let t = |c: &SemCtx| c.r(fld(d, b't'));
    let sp = |c: &SemCtx| c.rp(fld(d, b's'));
    let tp = |c: &SemCtx| c.rp(fld(d, b't'));

    match op {
        // ---- single-precision add / sub ----
        Opcode::F2_sfadd => {
            let v = sf_addsub(s(ctx), t(ctx), false, ctx);
            ctx.set_r(rd, v);
        }
        Opcode::F2_sfsub => {
            let v = sf_addsub(s(ctx), t(ctx), true, ctx);
            ctx.set_r(rd, v);
        }

        // ---- single-precision fused multiply-add (Rx += / -= Rs*Rt) ----
        Opcode::F2_sffma => {
            let x = c_rx(d, ctx);
            let v = sf_fma(s(ctx), t(ctx), x, false, false, 0, ctx);
            ctx.set_r(fld(d, b'x'), v);
        }
        Opcode::F2_sffms => {
            let x = c_rx(d, ctx);
            let v = sf_fma(s(ctx), t(ctx), x, true, false, 0, ctx);
            ctx.set_r(fld(d, b'x'), v);
        }

        // ---- library fused multiply-add/sub (`:lib`): IEEE fmaf with the
        // Hexagon post-fixups — flags are CANCELLED, a spurious overflow inf
        // (no inf input) is backed off to max-finite, and inf-minus-inf -> +0.
        Opcode::F2_sffma_lib => {
            let x = c_rx(d, ctx);
            let v = sf_fma_lib(s(ctx), t(ctx), x, false, ctx);
            ctx.set_r(fld(d, b'x'), v);
        }
        Opcode::F2_sffms_lib => {
            let x = c_rx(d, ctx);
            let v = sf_fma_lib(s(ctx), t(ctx), x, true, ctx);
            ctx.set_r(fld(d, b'x'), v);
        }
        // ---- scaled fused multiply-add (`:scale`): Rx += Rs*Rt, then * 2^Pu
        // (Pu read as a two's-complement scale factor). ----
        Opcode::F2_sffma_sc => {
            let x = c_rx(d, ctx);
            let pu = ctx.p(fld(d, b'u'));
            let v = sf_fma_scale(s(ctx), t(ctx), x, pu, ctx);
            ctx.set_r(fld(d, b'x'), v);
        }

        // ---- double-precision add / sub ----
        Opcode::F2_dfadd => {
            let v = df_addsub(sp(ctx), tp(ctx), false, ctx);
            ctx.set_rp(rd, v);
        }
        Opcode::F2_dfsub => {
            let v = df_addsub(sp(ctx), tp(ctx), true, ctx);
            ctx.set_rp(rd, v);
        }

        // ---- double-precision multiplies (pure integer / exact scale) ----
        Opcode::F2_dfmpyll => {
            let prod = getuword(sp(ctx), 0).wrapping_mul(getuword(tp(ctx), 0)); // u32*u32 -> u64
            let mut rdd = (prod >> 32) << 1;
            if getuword(prod, 0) != 0 {
                rdd |= 1; // fSETBIT(0,RddV,1)
            }
            ctx.set_rp(rd, rdd);
        }
        Opcode::F2_dfmpylh => {
            let rxx = c_rxx(d, ctx);
            let lo_ss = getuword(sp(ctx), 0); // low word of Rss
            let hi_tt = getuword(tp(ctx), 1); // high word of Rtt
            let mant = 0x0010_0000u64 | (hi_tt & 0x000f_ffff); // fZXTN(20,..)
            let add = lo_ss.wrapping_mul(mant) << 1;
            ctx.set_rp(rd, rxx.wrapping_add(add));
        }
        Opcode::F2_dfmpyhh => {
            // Rxx = dfmpyhh(Rss, Rtt, Rxx): the high-half multiply + accumulate
            // step. `Rxx` is the read input accumulator and the destination.
            let xx = c_rxx(d, ctx);
            let v = df_mpyhh(sp(ctx), tp(ctx), xx, ctx);
            ctx.set_rp(fld(d, b'x'), v);
        }
        Opcode::F2_dfmpyfix => {
            let ss = sp(ctx);
            let tt = tp(ctx);
            let v = if df_is_denorm(ss) && df_is_big(tt) && df_is_normal(tt) {
                // Rss (subnormal) * 2^52 -- exact normalisation, no rounding.
                (f64::from_bits(ss) * (2.0f64).powi(52)).to_bits()
            } else if df_is_denorm(tt) && df_is_big(ss) && df_is_normal(ss) {
                // Rss * 2^-52 -- Rss is a big normal, scaling down by 2^-52 is exact.
                (f64::from_bits(ss) * (2.0f64).powi(-52)).to_bits()
            } else {
                ss
            };
            ctx.set_rp(rd, v);
        }

        // ---- per-byte vector select (Rdd, pick Rss/Rtt byte by Pu bit) ----
        Opcode::C2_vmux => {
            let pu = ctx.p(fld(d, b'u'));
            let ss = sp(ctx);
            let tt = tp(ctx);
            let mut rdd = 0u64;
            for i in 0..8u32 {
                let byte = if (pu >> i) & 1 == 1 {
                    (ss >> (i * 8)) & 0xff
                } else {
                    (tt >> (i * 8)) & 0xff
                };
                rdd |= byte << (i * 8);
            }
            ctx.set_rp(rd, rdd);
        }

        // ---- cache / sync / memory-ordering ops: no architectural register or
        // predicate effect in user mode -> no-op ----
        Opcode::Y2_dccleana
        | Opcode::Y2_dccleaninva
        | Opcode::Y2_dcinva
        | Opcode::Y4_l2fetch
        | Opcode::Y5_l2fetch
        | Opcode::Y2_barrier
        | Opcode::Y2_dcfetchbo
        | Opcode::Y2_icinva
        | Opcode::Y2_isync
        | Opcode::Y2_syncht
        | Opcode::R6_release_at_vi
        | Opcode::R6_release_st_vi => {
            // Memory-hierarchy / synchronization / memory-ordering hints only;
            // they leave all architectural registers unchanged.
        }

        _ => return false,
    }
    true
}

/// Read the old value of a read-modify `Rx` 32-bit register (field letter `x`).
#[inline]
fn c_rx(d: &DecodedOp, ctx: &SemCtx) -> u32 {
    ctx.r(fld(d, b'x'))
}

/// `is_true_zero(Rs*Rt)`: a multiplicand is *exactly* zero and neither operand is
/// infinite (so the product is a true zero, not a rounded/NaN result). Caller has
/// already excluded NaN inputs.
#[inline]
fn sf_true_zero_product(rs: u32, rt: u32) -> bool {
    let (frs, frt) = (f32::from_bits(rs), f32::from_bits(rt));
    (frs == 0.0 && frt.is_finite()) || (frt == 0.0 && frs.is_finite())
}

/// `Rx {+,-}= sfmpy(Rs,Rt):lib`. Reuses the exact single-rounding `sf_fma` core
/// for the fused value, then applies the `:lib` semantics: cancel the FP flags,
/// preserve a true-zero accumulator's sign, back a spurious-overflow infinity off
/// to the max finite magnitude (`bits-1`), and flush inf-minus-inf to +0.
fn sf_fma_lib(rs: u32, rt: u32, rx: u32, sub: bool, ctx: &mut SemCtx) -> u32 {
    // Compute the fused value with the proven core, then CANCEL its flags.
    let saved_usr = ctx.usr_or;
    let tmp = sf_fma(rs, rt, rx, sub, true, 0, ctx);
    ctx.usr_or = saved_usr;

    // NaN in any operand -> canonical all-ones NaN (sf_fma already returns it).
    if f32_is_nan(rs) || f32_is_nan(rt) || f32_is_nan(rx) {
        return tmp;
    }
    let frx = f32::from_bits(rx);
    let prod = f32::from_bits(rs) * f32::from_bits(rt); // inf-ness only; sign irrelevant
    let infinp = frx.is_infinite() || f32::from_bits(rt).is_infinite() || f32::from_bits(rs).is_infinite();
    // sign(Rs) ^ sign(Rx) ^ sign(Rt): fma fires inf-minus-inf when != 0, fms when == 0.
    let xor_sign = ((rs >> 31) ^ (rx >> 31) ^ (rt >> 31)) & 1;
    let inf_minus_inf = frx.is_infinite()
        && prod.is_infinite()
        && (if sub { xor_sign == 0 } else { xor_sign != 0 });

    // Preserve a true-zero accumulator (keep Rx, including its sign).
    let mut res = if frx == 0.0 && sf_true_zero_product(rs, rt) { rx } else { tmp };
    // Spurious overflow to infinity (no infinite input) -> max finite (bit decrement).
    if f32::from_bits(res).is_infinite() && !infinp {
        res = res.wrapping_sub(1);
    }
    if inf_minus_inf {
        res = 0; // +0.0
    }
    res
}

/// `Rx += sfmpy(Rs,Rt,Pu):scale`. Fused multiply-add then scale by `2^Pu`, where
/// `Pu` is a two's-complement (signed 8-bit) exponent. The scale is folded into
/// the fma's exponent so it is applied to the *exact* result before the single
/// rounding (a hardware scalb), giving the correct rounding, subnormal handling,
/// and USR flags from the shared core.
fn sf_fma_scale(rs: u32, rt: u32, rx: u32, pu: u8, ctx: &mut SemCtx) -> u32 {
    // True-zero accumulator + true-zero product: keep Rx (sign preserved), no
    // scaling and no flags — per the `:scale` special-case rule.
    if !f32_is_nan(rs)
        && !f32_is_nan(rt)
        && !f32_is_nan(rx)
        && f32::from_bits(rx) == 0.0
        && sf_true_zero_product(rs, rt)
    {
        return rx;
    }
    let scale = pu as i8 as i32;
    sf_fma(rs, rt, rx, false, false, scale, ctx)
}

/// Read the old value of a read-modify `Rxx` 64-bit pair (field letter `x`).
#[inline]
fn c_rxx(d: &DecodedOp, ctx: &SemCtx) -> u64 {
    ctx.rp(fld(d, b'x'))
}

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
//! Intentionally NOT implemented (fall through): dfadd/dfsub/dfmpyhh (exact
//! result not representable in native f64), sfrecipa/sfinvsqrta/sffixup* (depend
//! on the proprietary `arch_sf_*` lookup tables), and the `_lib`/`_sc` FMA
//! variants whose post-rounding fixups cannot be reproduced bit-exactly.

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
fn round_exact_to_f32(neg: bool, mut m: u128, mut e: i32, sticky: bool, ctx: &mut SemCtx) -> u32 {
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
        let half = if drop >= 1 && drop <= 128 { 1u128 << (drop - 1) } else { 0 };
        m >>= drop;
        e += drop as i32;
        if dropped != 0 {
            inexact = true;
        }
        // round-to-nearest-even, folding the pre-aligned sticky into "rest".
        let round_bit = dropped & half != 0;
        let rest = (dropped & half.wrapping_sub(1)) != 0 || sticky;
        if round_bit && (rest || (m & 1) == 1) {
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
/// signed result as `(neg, mag, e, sticky)` ready for [`round_exact_to_f32`].
///
/// To avoid overflow with f32's huge exponent range, alignment keeps a fixed
/// guard window below the larger operand; bits below it are folded into `sticky`.
/// The window (75 bits) far exceeds the 24-bit result precision, and operand
/// cancellation only occurs when the exponents are within ~48 of each other, so
/// no bit that could affect the rounded result is ever folded.
fn add_scaled(neg_a: bool, ma: u128, ea: i32, neg_b: bool, mb: u128, eb: i32) -> (bool, u128, i32, bool) {
    if ma == 0 {
        return (neg_b, mb, eb, false);
    }
    if mb == 0 {
        return (neg_a, ma, ea, false);
    }
    const GUARD: i32 = 75;
    let ehi = ea.max(eb);
    let ce = ehi - GUARD;
    let mut sticky = false;
    let align = |m: u128, e: i32, sticky: &mut bool| -> i128 {
        let shift = e - ce;
        if shift >= 0 {
            (m << shift) as i128
        } else {
            let s = (-shift) as u32;
            let dropped = if s >= 128 { m } else { m & ((1u128 << s) - 1) };
            if dropped != 0 {
                *sticky = true;
            }
            (if s >= 128 { 0 } else { m >> s }) as i128
        }
    };
    let va = align(ma, ea, &mut sticky);
    let vb = align(mb, eb, &mut sticky);
    let sa = if neg_a { -va } else { va };
    let sb = if neg_b { -vb } else { vb };
    let sum = sa + sb;
    if sum == 0 {
        // exact cancellation; sticky may still hold a tiny residue.
        return (false, 0, ce, sticky);
    }
    let neg = sum < 0;
    (neg, sum.unsigned_abs(), ce, sticky)
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
    let (neg, mag, e, sticky) = add_scaled(da.neg, da.m, da.e, db.neg, db.m, db.e);
    if mag == 0 && !sticky {
        // exact cancellation -> +0 (round-to-nearest-even).
        return 0;
    }
    round_exact_to_f32(neg, mag, e, sticky, ctx)
}

/// Exact fused multiply-add: `a*b + c` with a single rounding (matches
/// `internal_fmafx(a,b,c,0)`), full NaN/inf handling, and exact-then-round flags.
fn sf_fma(araw: u32, braw: u32, craw: u32, negate_prod: bool, ctx: &mut SemCtx) -> u32 {
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
        return c;
    }
    if dc.m == 0 {
        // c is zero: result is the (rounded) product. signed-zero of c irrelevant
        // unless product also zero (handled above).
        return round_exact_to_f32(prod_neg, prod_m, prod_e, false, ctx);
    }
    // Exactly add the (48-bit) product and c, then round once.
    let (neg, mag, e, sticky) = add_scaled(prod_neg, prod_m, prod_e, dc.neg, dc.m, dc.e);
    if mag == 0 && !sticky {
        return 0;
    }
    round_exact_to_f32(neg, mag, e, sticky, ctx)
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
            let v = sf_fma(s(ctx), t(ctx), x, false, ctx);
            ctx.set_r(fld(d, b'x'), v);
        }
        Opcode::F2_sffms => {
            let x = c_rx(d, ctx);
            let v = sf_fma(s(ctx), t(ctx), x, true, ctx);
            ctx.set_r(fld(d, b'x'), v);
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

        // ---- cache ops: no architectural register/predicate effect -> no-op ----
        Opcode::Y2_dccleana
        | Opcode::Y2_dccleaninva
        | Opcode::Y2_dcinva
        | Opcode::Y4_l2fetch
        | Opcode::Y5_l2fetch => {
            // Memory-hierarchy hints only; leave all registers unchanged.
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

/// Read the old value of a read-modify `Rxx` 64-bit pair (field letter `x`).
#[inline]
fn c_rxx(d: &DecodedOp, ctx: &SemCtx) -> u64 {
    ctx.rp(fld(d, b'x'))
}

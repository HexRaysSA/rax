//! (mpy_ext) Hexagon halfword/word integer-multiply matrix.
//!
//! Implements the systematic `M2_mpy*` 16x16 multiply family
//! (`M2_mpy_{hh,hl,lh,ll}_s{0,1}` and the `_acc`/`_nac`/`_rnd`/`_sat`/
//! `_sat_rnd`/`_acc_sat`/`_nac_sat` variants), the 64-bit-result `M2_mpyd_*`
//! family, the unsigned `M2_mpyu_*`/`M2_mpyud_*` families, the
//! `M2_hmmpy{h,l}_{s1,rs1}` 32x16 high-half multiplies, and the
//! `M6_vabsdiff{b,ub}` byte absolute-difference ops.
//!
//! Semantics taken verbatim from the Hexagon V68 spec
//! (semantics_generated.pyinc) and the f-macros in `imported/macros.def`:
//!   fMPY16SS(a,b)   = fSE32_64(fSE16_32(a)*fSE16_32(b))    (signed 16x16 -> i32 -> i64)
//!   fMPY16UU(a,b)   = fZE32_64(fZE16_32(a)*fZE16_32(b))    (unsigned 16x16 -> u32 -> i64)
//!   fMPY3216SS(a,b) = fSE32_64(a) * fSXTN(16,64,b)         (i32 x signed-16 -> i64)
//!   fSCALE(N,A)     = ((size8s_t)A) << N
//!   fROUND(A)       = A + 0x8000
//!   fSAT(A)         = fSATN(32,A)   (signed-32 saturate, sets USR:OVF)
//!   fGETHALF(N,S)   = (size2s_t)((S>>(N*16))&0xffff)       (signed half)
//!   fGETUHALF(N,S)  = (size2u_t)((S>>(N*16))&0xffff)       (unsigned half)
//!   fGETBYTE/fGETUBYTE/fSETBYTE                            (byte lanes)
//!   fABS(A)         = (A<0)?-A:A
//!
//! Verified against the qemu-hexagon oracle (tests/hexagon_diff.rs).

use super::super::opcode::{DecodedOp, Opcode};
use super::{fld, SemCtx};

/// Accumulate mode for the 16x16 multiply matrix.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Acc {
    /// `Rd = product` (no read-modify).
    Set,
    /// `Rx += product`.
    Add,
    /// `Rx -= product`.
    Sub,
}

/// fGETHALF(n, src): signed 16-bit lane, sign-extended to i64.
#[inline]
fn get_half(src: u32, n: u32) -> i64 {
    (((src >> (n * 16)) & 0xffff) as u16 as i16) as i64
}
/// fGETUHALF(n, src): unsigned 16-bit lane, zero-extended to i64.
#[inline]
fn get_uhalf(src: u32, n: u32) -> i64 {
    ((src >> (n * 16)) & 0xffff) as i64
}
/// fGETBYTE(n, src): signed 8-bit lane, sign-extended to i64.
#[inline]
fn get_byte(src: u64, n: u32) -> i64 {
    (((src >> (n * 8)) & 0xff) as u8 as i8) as i64
}
/// fGETUBYTE(n, src): unsigned 8-bit lane, zero-extended to i64.
#[inline]
fn get_ubyte(src: u64, n: u32) -> i64 {
    ((src >> (n * 8)) & 0xff) as i64
}
/// fSETBYTE(n, dst, val): insert the low 8 bits of `val` into byte lane `n`.
#[inline]
fn set_byte(dst: u64, n: u32, val: i64) -> u64 {
    let sh = n * 8;
    (dst & !(0xffu64 << sh)) | (((val as u64) & 0xff) << sh)
}

/// Parametrised 16x16 multiply (the `M2_mpy*` matrix).
///
/// * `s_high`/`t_high`: select Rs.H/Rs.L and Rt.H/Rt.L (`1` = high half).
/// * `unsigned`: use fMPY16UU (`mpyu`/`mpyud`) instead of fMPY16SS.
/// * `s1`: fSCALE(1,..) — shift the product left by one (the `:<<1` form).
/// * `acc`: Set (`Rd=`), Add (`Rx+=`), or Sub (`Rx-=`).
/// * `rnd`: fROUND — add 0x8000 (only ever combined with `Acc::Set`).
/// * `sat`: fSAT — saturate the result to signed 32 (non-wide only).
/// * `wide`: 64-bit Rdd/Rxx result (`mpyd`/`mpyud`) vs 32-bit Rd/Rx.
#[allow(clippy::too_many_arguments)]
#[inline]
fn mpy16(
    ctx: &mut SemCtx,
    d: &DecodedOp,
    s_high: u32,
    t_high: u32,
    unsigned: bool,
    s1: bool,
    acc: Acc,
    rnd: bool,
    sat: bool,
    wide: bool,
) {
    let rs = ctx.r(fld(d, b's'));
    let rt = ctx.r(fld(d, b't'));

    // 16x16 product, sign- or zero-extended into i64 (always fits in i32/u32).
    let prod: i64 = if unsigned {
        let a = get_uhalf(rs, s_high) as u32;
        let b = get_uhalf(rt, t_high) as u32;
        (a.wrapping_mul(b) as u64) as i64
    } else {
        let a = get_half(rs, s_high) as i32;
        let b = get_half(rt, t_high) as i32;
        (a.wrapping_mul(b)) as i64
    };

    // fSCALE(1, product) when the `:<<1` form is selected.
    let scaled = if s1 { prod << 1 } else { prod };

    // Combine with the accumulator (read OLD Rx) per the acc/nac/set rule.
    // fROUND (+0x8000) only ever appears on the `Acc::Set` rnd forms.
    let val: i64 = match acc {
        Acc::Set => {
            if rnd {
                scaled + 0x8000
            } else {
                scaled
            }
        }
        Acc::Add => {
            let old = if wide {
                ctx.rp(fld(d, b'x')) as i64
            } else {
                ctx.r(fld(d, b'x')) as i32 as i64
            };
            old.wrapping_add(scaled)
        }
        Acc::Sub => {
            let old = if wide {
                ctx.rp(fld(d, b'x')) as i64
            } else {
                ctx.r(fld(d, b'x')) as i32 as i64
            };
            old.wrapping_sub(scaled)
        }
    };

    // fSAT (signed-32 saturate) is applied to the final value when present.
    let val = if sat { ctx.sat_n(val, 32) } else { val };

    let dst = match acc {
        Acc::Set => fld(d, b'd'),
        Acc::Add | Acc::Sub => fld(d, b'x'),
    };
    if wide {
        ctx.set_rp(dst, val as u64);
    } else {
        ctx.set_r(dst, val as u32);
    }
}

/// Execute a mpy_ext opcode. Returns `false` if `op` is not handled here.
pub fn exec(op: Opcode, d: &DecodedOp, ctx: &mut SemCtx) -> bool {
    let rd = fld(d, b'd');
    match op {
        // ============ 16x16 multiply matrix (M2_mpy* / mpyd / mpyu / mpyud) ============
        Opcode::M2_mpy_acc_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Add, false, false, false),
        Opcode::M2_mpy_acc_sat_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Add, false, true, false),
        Opcode::M2_mpy_acc_sat_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Add, false, true, false),
        Opcode::M2_mpy_acc_sat_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Add, false, true, false),
        Opcode::M2_mpy_acc_sat_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Add, false, true, false),
        Opcode::M2_mpy_acc_sat_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Add, false, true, false),
        Opcode::M2_mpy_acc_sat_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Add, false, true, false),
        Opcode::M2_mpy_acc_sat_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Add, false, true, false),
        Opcode::M2_mpy_acc_sat_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Add, false, true, false),
        Opcode::M2_mpyd_acc_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Add, false, false, true),
        Opcode::M2_mpyd_acc_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Add, false, false, true),
        Opcode::M2_mpyd_acc_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Add, false, false, true),
        Opcode::M2_mpyd_acc_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Add, false, false, true),
        Opcode::M2_mpyd_acc_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Add, false, false, true),
        Opcode::M2_mpyd_acc_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Add, false, false, true),
        Opcode::M2_mpyd_acc_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Add, false, false, true),
        Opcode::M2_mpyd_acc_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Add, false, false, true),
        Opcode::M2_mpyd_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Set, false, false, true),
        Opcode::M2_mpyd_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Set, false, false, true),
        Opcode::M2_mpyd_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Set, false, false, true),
        Opcode::M2_mpyd_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Set, false, false, true),
        Opcode::M2_mpyd_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Set, false, false, true),
        Opcode::M2_mpyd_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Set, false, false, true),
        Opcode::M2_mpyd_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Set, false, false, true),
        Opcode::M2_mpyd_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Set, false, false, true),
        Opcode::M2_mpyd_nac_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_nac_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_nac_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_nac_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_nac_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_nac_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_nac_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_nac_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyd_rnd_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Set, true, false, true),
        Opcode::M2_mpyd_rnd_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Set, true, false, true),
        Opcode::M2_mpyd_rnd_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Set, true, false, true),
        Opcode::M2_mpyd_rnd_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Set, true, false, true),
        Opcode::M2_mpyd_rnd_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Set, true, false, true),
        Opcode::M2_mpyd_rnd_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Set, true, false, true),
        Opcode::M2_mpyd_rnd_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Set, true, false, true),
        Opcode::M2_mpyd_rnd_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Set, true, false, true),
        Opcode::M2_mpy_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Set, false, false, false),
        Opcode::M2_mpy_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Set, false, false, false),
        Opcode::M2_mpy_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Set, false, false, false),
        Opcode::M2_mpy_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Set, false, false, false),
        Opcode::M2_mpy_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Set, false, false, false),
        Opcode::M2_mpy_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Set, false, false, false),
        Opcode::M2_mpy_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Set, false, false, false),
        Opcode::M2_mpy_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Set, false, false, false),
        Opcode::M2_mpy_nac_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Sub, false, false, false),
        Opcode::M2_mpy_nac_sat_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Sub, false, true, false),
        Opcode::M2_mpy_nac_sat_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Sub, false, true, false),
        Opcode::M2_mpy_nac_sat_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Sub, false, true, false),
        Opcode::M2_mpy_nac_sat_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Sub, false, true, false),
        Opcode::M2_mpy_nac_sat_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Sub, false, true, false),
        Opcode::M2_mpy_nac_sat_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Sub, false, true, false),
        Opcode::M2_mpy_nac_sat_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Sub, false, true, false),
        Opcode::M2_mpy_nac_sat_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Sub, false, true, false),
        Opcode::M2_mpy_rnd_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Set, true, false, false),
        Opcode::M2_mpy_rnd_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Set, true, false, false),
        Opcode::M2_mpy_rnd_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Set, true, false, false),
        Opcode::M2_mpy_rnd_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Set, true, false, false),
        Opcode::M2_mpy_rnd_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Set, true, false, false),
        Opcode::M2_mpy_rnd_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Set, true, false, false),
        Opcode::M2_mpy_rnd_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Set, true, false, false),
        Opcode::M2_mpy_rnd_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Set, true, false, false),
        Opcode::M2_mpy_sat_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Set, false, true, false),
        Opcode::M2_mpy_sat_rnd_hh_s0 => mpy16(ctx, d, 1, 1, false, false, Acc::Set, true, true, false),
        Opcode::M2_mpy_sat_rnd_hh_s1 => mpy16(ctx, d, 1, 1, false, true, Acc::Set, true, true, false),
        Opcode::M2_mpy_sat_rnd_hl_s0 => mpy16(ctx, d, 1, 0, false, false, Acc::Set, true, true, false),
        Opcode::M2_mpy_sat_rnd_hl_s1 => mpy16(ctx, d, 1, 0, false, true, Acc::Set, true, true, false),
        Opcode::M2_mpy_sat_rnd_lh_s0 => mpy16(ctx, d, 0, 1, false, false, Acc::Set, true, true, false),
        Opcode::M2_mpy_sat_rnd_lh_s1 => mpy16(ctx, d, 0, 1, false, true, Acc::Set, true, true, false),
        Opcode::M2_mpy_sat_rnd_ll_s0 => mpy16(ctx, d, 0, 0, false, false, Acc::Set, true, true, false),
        Opcode::M2_mpy_sat_rnd_ll_s1 => mpy16(ctx, d, 0, 0, false, true, Acc::Set, true, true, false),
        Opcode::M2_mpyu_acc_hh_s0 => mpy16(ctx, d, 1, 1, true, false, Acc::Add, false, false, false),
        Opcode::M2_mpyu_acc_hh_s1 => mpy16(ctx, d, 1, 1, true, true, Acc::Add, false, false, false),
        Opcode::M2_mpyu_acc_hl_s0 => mpy16(ctx, d, 1, 0, true, false, Acc::Add, false, false, false),
        Opcode::M2_mpyu_acc_hl_s1 => mpy16(ctx, d, 1, 0, true, true, Acc::Add, false, false, false),
        Opcode::M2_mpyu_acc_lh_s0 => mpy16(ctx, d, 0, 1, true, false, Acc::Add, false, false, false),
        Opcode::M2_mpyu_acc_lh_s1 => mpy16(ctx, d, 0, 1, true, true, Acc::Add, false, false, false),
        Opcode::M2_mpyu_acc_ll_s0 => mpy16(ctx, d, 0, 0, true, false, Acc::Add, false, false, false),
        Opcode::M2_mpyu_acc_ll_s1 => mpy16(ctx, d, 0, 0, true, true, Acc::Add, false, false, false),
        Opcode::M2_mpyud_acc_hh_s0 => mpy16(ctx, d, 1, 1, true, false, Acc::Add, false, false, true),
        Opcode::M2_mpyud_acc_hh_s1 => mpy16(ctx, d, 1, 1, true, true, Acc::Add, false, false, true),
        Opcode::M2_mpyud_acc_hl_s0 => mpy16(ctx, d, 1, 0, true, false, Acc::Add, false, false, true),
        Opcode::M2_mpyud_acc_hl_s1 => mpy16(ctx, d, 1, 0, true, true, Acc::Add, false, false, true),
        Opcode::M2_mpyud_acc_lh_s0 => mpy16(ctx, d, 0, 1, true, false, Acc::Add, false, false, true),
        Opcode::M2_mpyud_acc_lh_s1 => mpy16(ctx, d, 0, 1, true, true, Acc::Add, false, false, true),
        Opcode::M2_mpyud_acc_ll_s0 => mpy16(ctx, d, 0, 0, true, false, Acc::Add, false, false, true),
        Opcode::M2_mpyud_acc_ll_s1 => mpy16(ctx, d, 0, 0, true, true, Acc::Add, false, false, true),
        Opcode::M2_mpyud_hh_s0 => mpy16(ctx, d, 1, 1, true, false, Acc::Set, false, false, true),
        Opcode::M2_mpyud_hh_s1 => mpy16(ctx, d, 1, 1, true, true, Acc::Set, false, false, true),
        Opcode::M2_mpyud_hl_s0 => mpy16(ctx, d, 1, 0, true, false, Acc::Set, false, false, true),
        Opcode::M2_mpyud_hl_s1 => mpy16(ctx, d, 1, 0, true, true, Acc::Set, false, false, true),
        Opcode::M2_mpyud_lh_s0 => mpy16(ctx, d, 0, 1, true, false, Acc::Set, false, false, true),
        Opcode::M2_mpyud_lh_s1 => mpy16(ctx, d, 0, 1, true, true, Acc::Set, false, false, true),
        Opcode::M2_mpyud_ll_s0 => mpy16(ctx, d, 0, 0, true, false, Acc::Set, false, false, true),
        Opcode::M2_mpyud_ll_s1 => mpy16(ctx, d, 0, 0, true, true, Acc::Set, false, false, true),
        Opcode::M2_mpyud_nac_hh_s0 => mpy16(ctx, d, 1, 1, true, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyud_nac_hh_s1 => mpy16(ctx, d, 1, 1, true, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyud_nac_hl_s0 => mpy16(ctx, d, 1, 0, true, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyud_nac_hl_s1 => mpy16(ctx, d, 1, 0, true, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyud_nac_lh_s0 => mpy16(ctx, d, 0, 1, true, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyud_nac_lh_s1 => mpy16(ctx, d, 0, 1, true, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyud_nac_ll_s0 => mpy16(ctx, d, 0, 0, true, false, Acc::Sub, false, false, true),
        Opcode::M2_mpyud_nac_ll_s1 => mpy16(ctx, d, 0, 0, true, true, Acc::Sub, false, false, true),
        Opcode::M2_mpyu_hh_s0 => mpy16(ctx, d, 1, 1, true, false, Acc::Set, false, false, false),
        Opcode::M2_mpyu_hh_s1 => mpy16(ctx, d, 1, 1, true, true, Acc::Set, false, false, false),
        Opcode::M2_mpyu_hl_s0 => mpy16(ctx, d, 1, 0, true, false, Acc::Set, false, false, false),
        Opcode::M2_mpyu_hl_s1 => mpy16(ctx, d, 1, 0, true, true, Acc::Set, false, false, false),
        Opcode::M2_mpyu_lh_s0 => mpy16(ctx, d, 0, 1, true, false, Acc::Set, false, false, false),
        Opcode::M2_mpyu_lh_s1 => mpy16(ctx, d, 0, 1, true, true, Acc::Set, false, false, false),
        Opcode::M2_mpyu_ll_s0 => mpy16(ctx, d, 0, 0, true, false, Acc::Set, false, false, false),
        Opcode::M2_mpyu_ll_s1 => mpy16(ctx, d, 0, 0, true, true, Acc::Set, false, false, false),
        Opcode::M2_mpyu_nac_hh_s0 => mpy16(ctx, d, 1, 1, true, false, Acc::Sub, false, false, false),
        Opcode::M2_mpyu_nac_hh_s1 => mpy16(ctx, d, 1, 1, true, true, Acc::Sub, false, false, false),
        Opcode::M2_mpyu_nac_hl_s0 => mpy16(ctx, d, 1, 0, true, false, Acc::Sub, false, false, false),
        Opcode::M2_mpyu_nac_hl_s1 => mpy16(ctx, d, 1, 0, true, true, Acc::Sub, false, false, false),
        Opcode::M2_mpyu_nac_lh_s0 => mpy16(ctx, d, 0, 1, true, false, Acc::Sub, false, false, false),
        Opcode::M2_mpyu_nac_lh_s1 => mpy16(ctx, d, 0, 1, true, true, Acc::Sub, false, false, false),
        Opcode::M2_mpyu_nac_ll_s0 => mpy16(ctx, d, 0, 0, true, false, Acc::Sub, false, false, false),
        Opcode::M2_mpyu_nac_ll_s1 => mpy16(ctx, d, 0, 0, true, true, Acc::Sub, false, false, false),

        // ============ hmmpy: 32 x signed-16 high-half multiply (:<<1[:rnd]:sat) ============
        // RdV = fSAT( (fSCALE(1, fMPY3216SS(RsV, Rt.{H|L})) [+0x8000]) >> 16 )
        Opcode::M2_hmmpyh_s1 => {
            let rs = ctx.r(fld(d, b's')) as i32 as i64;
            let rt = get_half(ctx.r(fld(d, b't')), 1);
            let v = ctx.sat_n((rs.wrapping_mul(rt) << 1) >> 16, 32);
            ctx.set_r(rd, v as u32);
        }
        Opcode::M2_hmmpyl_s1 => {
            let rs = ctx.r(fld(d, b's')) as i32 as i64;
            let rt = get_half(ctx.r(fld(d, b't')), 0);
            let v = ctx.sat_n((rs.wrapping_mul(rt) << 1) >> 16, 32);
            ctx.set_r(rd, v as u32);
        }
        Opcode::M2_hmmpyh_rs1 => {
            let rs = ctx.r(fld(d, b's')) as i32 as i64;
            let rt = get_half(ctx.r(fld(d, b't')), 1);
            let v = ctx.sat_n(((rs.wrapping_mul(rt) << 1) + 0x8000) >> 16, 32);
            ctx.set_r(rd, v as u32);
        }
        Opcode::M2_hmmpyl_rs1 => {
            let rs = ctx.r(fld(d, b's')) as i32 as i64;
            let rt = get_half(ctx.r(fld(d, b't')), 0);
            let v = ctx.sat_n(((rs.wrapping_mul(rt) << 1) + 0x8000) >> 16, 32);
            ctx.set_r(rd, v as u32);
        }

        // ============ vabsdiff: per-byte |Rtt[i] - Rss[i]| (M6) ============
        // Note: operands are (Rtt, Rss) — the difference is Rtt-byte minus Rss-byte.
        Opcode::M6_vabsdiffb => {
            let rss = ctx.rp(fld(d, b's'));
            let rtt = ctx.rp(fld(d, b't'));
            let mut v: u64 = 0;
            for i in 0..8 {
                v = set_byte(v, i, (get_byte(rtt, i) - get_byte(rss, i)).abs());
            }
            ctx.set_rp(rd, v);
        }
        Opcode::M6_vabsdiffub => {
            let rss = ctx.rp(fld(d, b's'));
            let rtt = ctx.rp(fld(d, b't'));
            let mut v: u64 = 0;
            for i in 0..8 {
                v = set_byte(v, i, (get_ubyte(rtt, i) - get_ubyte(rss, i)).abs());
            }
            ctx.set_rp(rd, v);
        }

        _ => return false,
    }
    true
}

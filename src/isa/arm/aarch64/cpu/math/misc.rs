//! math::misc tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

// =============================================================================
// Helper Functions
// =============================================================================

/// Decode bitmask immediate for logical instructions.
pub(crate) fn decode_bitmask(
    n: bool,
    imms: u32,
    immr: u32,
    is_64bit: bool,
) -> Result<u64, ArmError> {
    // For 64-bit (sf=1): N must be 1
    // For 32-bit (sf=0): N must be 0, and highest set bit in ~imms[5:0] determines element size
    let len = if n {
        6 // 64-bit elements
    } else {
        // Find highest set bit position in ~imms[5:0] (6-bit value)
        let not_imms = !imms & 0x3F;
        if not_imms == 0 {
            return Err(ArmError::UndefinedInstruction(0));
        }
        // len = HighestSetBit(immN:NOT(imms)) per the A64 DecodeBitMasks
        // pseudocode. For N=0 this is the highest set bit position of
        // ~imms[5:0] (0-5); the element size is 1<<len.
        let pos = 31 - not_imms.leading_zeros();
        if pos > 5 {
            return Err(ArmError::UndefinedInstruction(0));
        }
        pos
    };

    if len < 1 || len > 6 {
        return Err(ArmError::UndefinedInstruction(0));
    }

    let levels = (1u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    let esize = 1u64 << len;

    if s == levels {
        return Err(ArmError::UndefinedInstruction(0));
    }

    // Create the pattern - a run of (s+1) ones
    let welem = if s + 1 >= 64 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };

    // Create mask for element size
    let esize_mask = if esize >= 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    };

    // Rotate right by r
    let rotated = if r == 0 {
        welem
    } else {
        ((welem >> r) | (welem << (esize as u32 - r))) & esize_mask
    };

    // Replicate to fill the register
    let mut result = 0u64;
    let replications = 64 / esize;
    for i in 0..replications {
        result |= rotated << (i * esize);
    }

    if !is_64bit {
        result &= 0xFFFF_FFFF;
    }

    Ok(result)
}
/// Decode bitmasks for bitfield instructions.
pub(crate) fn decode_bitmasks(
    n: bool,
    imms: u32,
    immr: u32,
    _immediate: bool,
    datasize: u32,
) -> Result<(u64, u64), ArmError> {
    // len = HighestSetBit(immN:NOT(imms<5:0>))
    // For N=1: the 7-bit value is 1:xxxxxx, so highest bit is at position 6 -> len=6
    // For N=0: the 7-bit value is 0:NOT(imms), we find highest bit of NOT(imms)
    let len = if n {
        6
    } else {
        let not_imms = !imms & 0x3F;
        if not_imms == 0 {
            // All bits of imms are 1, which is reserved
            return Err(ArmError::UndefinedInstruction(0));
        }
        // Find position of highest set bit in not_imms (0-5)
        // leading_zeros for u32 counts from bit 31, so position = 31 - leading_zeros
        // But not_imms is only 6 bits, so we need: 5 - (not_imms as u8).leading_zeros() after masking
        // Actually simpler: 31 - not_imms.leading_zeros() gives us the position in the u32
        let pos = 31 - not_imms.leading_zeros();
        if pos > 5 {
            return Err(ArmError::UndefinedInstruction(0));
        }
        pos // len = position of highest set bit (not pos + 1!)
    };

    if len < 1 || len > 6 || (1 << len) > datasize {
        return Err(ArmError::UndefinedInstruction(0));
    }

    let levels = (1u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    let diff = ((s as i32).wrapping_sub(r as i32)) as u32;
    let esize = 1u64 << len;

    // Create element masks, handling potential overflow
    let welem = if s + 1 >= 64 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };

    let telem_bits = (diff & levels) + 1;
    let telem = if telem_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << telem_bits) - 1
    };

    let esize_mask = if esize >= 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    };

    // Rotate welem right by R within element size
    let wmask_elem = if r == 0 {
        welem
    } else {
        ((welem >> r) | (welem << (esize as u32 - r))) & esize_mask
    };

    // Replicate
    let mut wmask = 0u64;
    let mut tmask = 0u64;
    let replications = 64 / esize;
    for i in 0..replications {
        wmask |= wmask_elem << (i * esize);
        tmask |= (telem & esize_mask) << (i * esize);
    }

    if datasize == 32 {
        wmask &= 0xFFFF_FFFF;
        tmask &= 0xFFFF_FFFF;
    }

    Ok((wmask, tmask))
}
/// CRC32 calculation (ISO 3309 polynomial).
pub(crate) fn crc32(crc: u64, data: u64, size: u32) -> u64 {
    const POLY: u32 = 0xEDB8_8320;
    let mut crc = crc as u32;
    let bytes = size / 8;

    for i in 0..bytes {
        let byte = ((data >> (i * 8)) & 0xFF) as u8;
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }

    crc as u64
}
/// CRC32C calculation (Castagnoli polynomial).
pub(crate) fn crc32c(crc: u64, data: u64, size: u32) -> u64 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = crc as u32;
    let bytes = size / 8;

    for i in 0..bytes {
        let byte = ((data >> (i * 8)) & 0xFF) as u8;
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }

    crc as u64
}
// =============================================================================
// Advanced SIMD (NEON) element helpers
//
// These operate on a single vector element whose value occupies the low
// `bits` bits of a u64 (`bits` in {8, 16, 32, 64}). They implement the exact
// per-element semantics from the ARM Architecture Reference Manual and are
// verified differentially against qemu-user
// (`tests/suites/differential/arm/aarch64.rs`).
// =============================================================================

/// Mask covering the low `bits` bits.
#[inline]
pub(crate) fn elem_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}
/// Saturating signed/unsigned add/subtract of a small non-negative `val` into
/// the low 32 bits of a 64-bit GPR (SQINCP/UQINCP/SQDECP/UQDECP, 32-bit form).
/// Matches qemu do_sat_addsub_32: the signed result is sign-extended to 64
/// bits, the unsigned result zero-extended.
pub(crate) fn sat_addsub_32(reg: u64, val: u64, u: bool, d: bool) -> u64 {
    if u {
        let r = (reg as u32) as i64; // zero-extend
        let res = if d {
            (r - val as i64).max(0)
        } else {
            (r + val as i64).min(u32::MAX as i64)
        };
        res as u64 // in [0, UINT32_MAX] -> zero-extended
    } else {
        let r = (reg as u32) as i32 as i64; // sign-extend
        let res = if d {
            (r - val as i64).max(i32::MIN as i64)
        } else {
            (r + val as i64).min(i32::MAX as i64)
        };
        res as u64 // sign-extended 64-bit pattern
    }
}
/// Saturating signed/unsigned add/subtract of a small non-negative `val` into a
/// full 64-bit GPR (SQINCP/UQINCP/SQDECP/UQDECP, 64-bit form). Matches qemu
/// do_sat_addsub_64.
pub(crate) fn sat_addsub_64(reg: u64, val: u64, u: bool, d: bool) -> u64 {
    if u {
        if d {
            reg.saturating_sub(val)
        } else {
            reg.saturating_add(val)
        }
    } else {
        let r = reg as i64;
        let v = val as i64;
        (if d {
            r.saturating_sub(v)
        } else {
            r.saturating_add(v)
        }) as u64
    }
}
/// Per-element saturating add/sub of `count` for the SINCDECP vector form.
/// `bits` ∈ {16,32,64}; increments add `count`, decrements subtract it,
/// saturating into the element's signed (`u`=false) or unsigned (`u`=true)
/// range. Matches qemu sve_{s,u}q{add,sub}i_{h,s,d}.
pub(crate) fn sat_addsub_elem(elem: u64, count: u64, bits: u32, u: bool, dec: bool) -> u64 {
    let mask = elem_mask(bits);
    if u {
        if bits >= 64 {
            return if dec {
                elem.saturating_sub(count)
            } else {
                elem.saturating_add(count)
            };
        }
        let n = (elem & mask) as i128;
        let r = if dec {
            n - count as i128
        } else {
            n + count as i128
        };
        (r.clamp(0, mask as i128) as u64) & mask
    } else {
        let n = sext_elem(elem, bits);
        if bits >= 64 {
            let r = if dec {
                (n as i64).saturating_sub(count as i64)
            } else {
                (n as i64).saturating_add(count as i64)
            };
            return r as u64;
        }
        let r = if dec {
            n - count as i128
        } else {
            n + count as i128
        };
        let smax = (1i128 << (bits - 1)) - 1;
        let smin = -(1i128 << (bits - 1));
        (r.clamp(smin, smax) as u64) & mask
    }
}
/// Sign-extend the low `bits` bits of `v` to i128.
#[inline]
pub(crate) fn sext_elem(v: u64, bits: u32) -> i128 {
    let v = v & elem_mask(bits);
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as i128
}
/// Zero-extend the low `bits` bits of `v` to u128.
#[inline]
pub(crate) fn uext_elem(v: u64, bits: u32) -> u128 {
    (v & elem_mask(bits)) as u128
}
/// Saturate a signed value to the `bits`-bit signed range, returned as raw bits.
#[inline]
/// Signed saturating/rounding shift-left by a signed amount, for bits in
/// {8,16,32}. Faithful port of qemu do_sqrshl_bhs (vec_internal.h).
pub(crate) fn sqrshl_bhs(src: i32, shift: i32, bits: u32, round: bool, sat: bool) -> i32 {
    if shift <= -(bits as i32) {
        return if round { 0 } else { src >> 31 };
    } else if shift < 0 {
        if round {
            let s = src >> (-shift - 1);
            return (s >> 1) + (s & 1);
        }
        return src >> (-shift);
    } else if shift < bits as i32 {
        let val = src.wrapping_shl(shift as u32);
        if bits == 32 {
            if !sat || (val >> shift) == src {
                return val;
            }
        } else {
            let extval = (val << (32 - bits)) >> (32 - bits); // sextract32(val,0,bits)
            if !sat || val == extval {
                return extval;
            }
        }
    } else if !sat || src == 0 {
        return 0;
    }
    // Saturate: positive sources clamp to the max, negatives to the min. For
    // bits < 32 the max/min share their low `bits` bits, so the caller's mask
    // recovers the right value either way. For bits == 32, `(1<<31)-1` would
    // overflow i32 in checked builds, so return i32::MAX / i32::MIN directly.
    if bits == 32 {
        if src >= 0 { i32::MAX } else { i32::MIN }
    } else {
        (1i32 << (bits - 1)) - i32::from(src >= 0)
    }
}
/// Unsigned saturating/rounding shift-left, bits in {8,16,32}. Port of qemu
/// do_uqrshl_bhs.
pub(crate) fn uqrshl_bhs(src: u32, shift: i32, bits: u32, round: bool, sat: bool) -> u32 {
    if shift <= -(bits as i32 + round as i32) {
        return 0;
    } else if shift < 0 {
        if round {
            let s = src >> (-shift - 1);
            return (s >> 1) + (s & 1);
        }
        return src >> (-shift);
    } else if shift < bits as i32 {
        let val = src.wrapping_shl(shift as u32);
        if bits == 32 {
            if !sat || (val >> shift) == src {
                return val;
            }
        } else {
            let extval = val & ((1u32 << bits) - 1);
            if !sat || val == extval {
                return extval;
            }
        }
    } else if !sat || src == 0 {
        return 0;
    }
    if bits == 32 {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    }
}
/// Signed saturating/rounding shift-left for 64-bit elements. Port of qemu
/// do_sqrshl_d.
pub(crate) fn sqrshl_d(src: i64, shift: i64, round: bool, sat: bool) -> i64 {
    if shift <= -64 {
        return if round { 0 } else { src >> 63 };
    } else if shift < 0 {
        if round {
            let s = src >> (-shift - 1);
            return (s >> 1) + (s & 1);
        }
        return src >> (-shift);
    } else if shift < 64 {
        let val = src.wrapping_shl(shift as u32);
        if !sat || (val >> shift) == src {
            return val;
        }
    } else if !sat || src == 0 {
        return 0;
    }
    if src < 0 { i64::MIN } else { i64::MAX }
}
/// Unsigned saturating/rounding shift-left for 64-bit elements. Port of qemu
/// do_uqrshl_d.
pub(crate) fn uqrshl_d(src: u64, shift: i64, round: bool, sat: bool) -> u64 {
    if shift <= -(64 + round as i64) {
        return 0;
    } else if shift < 0 {
        if round {
            let s = src >> (-shift - 1);
            return (s >> 1) + (s & 1);
        }
        return src >> (-shift);
    } else if shift < 64 {
        let val = src.wrapping_shl(shift as u32);
        if !sat || (val >> shift) == src {
            return val;
        }
    } else if !sat || src == 0 {
        return 0;
    }
    u64::MAX
}
pub(crate) fn sat_signed(v: i128, bits: u32) -> u64 {
    let max = (1i128 << (bits - 1)) - 1;
    let min = -(1i128 << (bits - 1));
    (v.clamp(min, max) as u64) & elem_mask(bits)
}
#[inline]
pub(crate) fn sat_signed_q(v: i128, bits: u32) -> (u64, bool) {
    let max = (1i128 << (bits - 1)) - 1;
    let min = -(1i128 << (bits - 1));
    (
        (v.clamp(min, max) as u64) & elem_mask(bits),
        v < min || v > max,
    )
}
/// Saturate a value to the `bits`-bit unsigned range, returned as raw bits.
#[inline]
pub(crate) fn sat_unsigned(v: i128, bits: u32) -> u64 {
    let max = (1i128 << bits) - 1;
    (v.clamp(0, max) as u64) & elem_mask(bits)
}
#[inline]
pub(crate) fn sat_unsigned_q(v: i128, bits: u32) -> (u64, bool) {
    let max = (1i128 << bits) - 1;
    ((v.clamp(0, max) as u64) & elem_mask(bits), v < 0 || v > max)
}
/// All-ones if `cond`, else 0, in the low `bits` bits (comparison result).
#[inline]
pub(crate) fn bool_mask(cond: bool, bits: u32) -> u64 {
    if cond { elem_mask(bits) } else { 0 }
}
/// Shift `a` (the low `bits` bits) by the signed amount `sh` per the ARM
/// register-shift family. `signed` selects SSHL vs USHL; `rounding` adds the
/// round constant on right shifts (SRSHL/URSHL); `saturating` clamps left-shift
/// overflow to the element range (SQSHL/UQSHL etc.). Returns the raw result.
pub(crate) fn adv_simd_shift_reg(
    a: u64,
    sh: i32,
    bits: u32,
    signed: bool,
    rounding: bool,
    saturating: bool,
) -> (u64, bool) {
    let m = elem_mask(bits);
    if signed {
        let sval = sext_elem(a, bits);
        if sh >= 0 {
            // Left shift.
            let s = sh as u32;
            if s >= bits || s >= 64 {
                if saturating {
                    if sval == 0 {
                        (0, false)
                    } else {
                        (
                            sat_signed(if sval > 0 { i128::MAX } else { i128::MIN }, bits),
                            true,
                        )
                    }
                } else {
                    (0, false)
                }
            } else {
                let res = sval << s;
                if saturating {
                    sat_signed_q(res, bits)
                } else {
                    ((res as u64) & m, false)
                }
            }
        } else {
            // Right shift (arithmetic), optionally rounded.
            let rsh = (-sh) as u32;
            if rsh > bits {
                // Round constant dominates: rounded -> 0, unrounded -> sign.
                if rounding {
                    (0, false)
                } else if sval < 0 {
                    (m, false)
                } else {
                    (0, false)
                }
            } else {
                let round = if rounding { 1i128 << (rsh - 1) } else { 0 };
                let res = (sval + round) >> rsh;
                ((res as u64) & m, false)
            }
        }
    } else {
        let uval = uext_elem(a, bits) as i128;
        if sh >= 0 {
            let s = sh as u32;
            if s >= bits || s >= 64 {
                if saturating {
                    if uval == 0 { (0, false) } else { (m, true) }
                } else {
                    (0, false)
                }
            } else {
                let res = uval << s;
                if saturating {
                    sat_unsigned_q(res, bits)
                } else {
                    ((res as u64) & m, false)
                }
            }
        } else {
            let rsh = (-sh) as u32;
            if rsh > bits {
                (0, false)
            } else {
                let round = if rounding { 1i128 << (rsh - 1) } else { 0 };
                let res = (uval + round) >> rsh;
                ((res as u64) & m, false)
            }
        }
    }
}
/// Polynomial (carry-less) multiply of two 8-bit values, low 8 bits of result.
#[inline]
pub(crate) fn poly_mul_8(a: u64, b: u64) -> u64 {
    let mut result: u64 = 0;
    for i in 0..8 {
        if (a >> i) & 1 != 0 {
            result ^= b << i;
        }
    }
    result & 0xFF
}
/// Widening polynomial multiply: `bits`-bit operands -> full `2*bits` product.
#[inline]
pub(crate) fn poly_mul_wide(a: u64, b: u64, bits: u32) -> u64 {
    let mut result: u64 = 0;
    for i in 0..bits {
        if (a >> i) & 1 != 0 {
            result ^= b << i;
        }
    }
    result
}
/// 64x64 -> 128-bit polynomial (carry-less) multiply (PMULL.1Q).
#[inline]
pub(crate) fn poly_mul_64(a: u64, b: u64) -> u128 {
    let mut result: u128 = 0;
    for i in 0..64 {
        if (a >> i) & 1 != 0 {
            result ^= (b as u128) << i;
        }
    }
    result
}
/// Sign-extend the low `bits` bits of a u128 (`bits` up to 64) to i128.
#[inline]
pub(crate) fn sext_elem_wide(v: u128, bits: u32) -> i128 {
    let v = v & elem_mask_u128(bits);
    let shift = 128 - bits;
    ((v << shift) as i128) >> shift
}
/// Saturate a signed value to the `bits`-bit signed range (`bits` up to 64),
/// returned as raw bits in a u128.
#[inline]
pub(crate) fn sat_signed_wide(v: i128, bits: u32) -> u128 {
    let max = (1i128 << (bits - 1)) - 1;
    let min = -(1i128 << (bits - 1));
    (v.clamp(min, max) as u128) & elem_mask_u128(bits)
}
/// Compute one element of an Advanced SIMD three-same *integer* operation.
///
/// `a`, `b` are the source elements (low `bits` bits); `d` is the current
/// destination element (used by accumulating ops MLA/MLS/SABA/UABA). `u` is the
/// U bit and `opcode` the 5-bit opcode. For pairwise opcodes (SMAXP/SMINP/ADDP)
/// the caller supplies the adjacent pair as `(a, b)`.
pub(crate) fn adv_simd_three_same_int(
    u: u32,
    opcode: u32,
    bits: u32,
    a: u64,
    b: u64,
    d: u64,
) -> (u64, bool) {
    let m = elem_mask(bits);
    let sa = sext_elem(a, bits);
    let sb = sext_elem(b, bits);
    let ua = uext_elem(a, bits) as i128;
    let ub = uext_elem(b, bits) as i128;
    let ud = uext_elem(d, bits);

    match opcode {
        0b00000 => {
            // SHADD / UHADD
            if u == 0 {
                (((sa + sb) >> 1) as u64 & m, false)
            } else {
                (((ua + ub) >> 1) as u64 & m, false)
            }
        }
        0b00010 => {
            // SRHADD / URHADD
            if u == 0 {
                (((sa + sb + 1) >> 1) as u64 & m, false)
            } else {
                (((ua + ub + 1) >> 1) as u64 & m, false)
            }
        }
        0b00100 => {
            // SHSUB / UHSUB
            if u == 0 {
                (((sa - sb) >> 1) as u64 & m, false)
            } else {
                (((ua - ub) >> 1) as u64 & m, false)
            }
        }
        0b00001 => {
            // SQADD / UQADD
            if u == 0 {
                sat_signed_q(sa + sb, bits)
            } else {
                sat_unsigned_q(ua + ub, bits)
            }
        }
        0b00101 => {
            // SQSUB / UQSUB
            if u == 0 {
                sat_signed_q(sa - sb, bits)
            } else {
                sat_unsigned_q(ua - ub, bits)
            }
        }
        0b00110 => {
            // CMGT / CMHI
            let c = if u == 0 { sa > sb } else { ua > ub };
            (bool_mask(c, bits), false)
        }
        0b00111 => {
            // CMGE / CMHS
            let c = if u == 0 { sa >= sb } else { ua >= ub };
            (bool_mask(c, bits), false)
        }
        0b01000 | 0b01001 | 0b01010 | 0b01011 => {
            // SSHL/USHL (1000), SQSHL/UQSHL (1001), SRSHL/URSHL (1010),
            // SQRSHL/UQRSHL (1011). Shift amount is the low byte of b, signed.
            let sh = (b as u8 as i8) as i32;
            let rounding = opcode == 0b01010 || opcode == 0b01011;
            let saturating = opcode == 0b01001 || opcode == 0b01011;
            adv_simd_shift_reg(a, sh, bits, u == 0, rounding, saturating)
        }
        0b01100 => {
            // SMAX / UMAX  (also SMAXP/UMAXP share this op via pairwise sourcing)
            if u == 0 {
                ((sa.max(sb) as u64) & m, false)
            } else {
                ((ua.max(ub) as u64) & m, false)
            }
        }
        0b01101 => {
            // SMIN / UMIN
            if u == 0 {
                ((sa.min(sb) as u64) & m, false)
            } else {
                ((ua.min(ub) as u64) & m, false)
            }
        }
        0b01110 => {
            // SABD / UABD
            if u == 0 {
                (((sa - sb).abs() as u64) & m, false)
            } else {
                (((ua - ub).abs() as u64) & m, false)
            }
        }
        0b01111 => {
            // SABA / UABA  (accumulate absolute difference)
            let abd = if u == 0 {
                (sa - sb).abs()
            } else {
                (ua - ub).abs()
            };
            (((ud as i128 + abd) as u64) & m, false)
        }
        0b10000 => {
            // ADD / SUB
            if u == 0 {
                (((ua + ub) as u64) & m, false)
            } else {
                (((ua - ub) as u64) & m, false)
            }
        }
        0b10001 => {
            // CMTST / CMEQ
            let c = if u == 0 { (ua & ub) != 0 } else { ua == ub };
            (bool_mask(c, bits), false)
        }
        0b10010 => {
            // MLA / MLS
            let prod = (ua * ub) as u64;
            if u == 0 {
                ((ud as u64).wrapping_add(prod) & m, false)
            } else {
                ((ud as u64).wrapping_sub(prod) & m, false)
            }
        }
        0b10011 => {
            // MUL / PMUL
            if u == 0 {
                (((ua * ub) as u64) & m, false)
            } else {
                (poly_mul_8(a, b), false)
            }
        }
        0b10100 => {
            // SMAXP / UMAXP (pairwise max -- same kernel as SMAX/UMAX)
            if u == 0 {
                ((sa.max(sb) as u64) & m, false)
            } else {
                ((ua.max(ub) as u64) & m, false)
            }
        }
        0b10101 => {
            // SMINP / UMINP
            if u == 0 {
                ((sa.min(sb) as u64) & m, false)
            } else {
                ((ua.min(ub) as u64) & m, false)
            }
        }
        0b10110 => {
            // SQDMULH / SQRDMULH (signed saturating doubling multiply high)
            let prod = sa * sb;
            let rounded = if u == 1 {
                prod * 2 + (1i128 << (bits - 1))
            } else {
                prod * 2
            };
            sat_signed_q(rounded >> bits, bits)
        }
        0b10111 => {
            // ADDP (pairwise add)
            (((ua + ub) as u64) & m, false)
        }
        _ => (a & m, false),
    }
}
/// Reverse the `unit`-byte chunks within an `esize`-byte little-endian value
/// (REVB unit=1, REVH unit=2, REVW unit=4).
pub(crate) fn reverse_chunks(val: u64, esize: usize, unit: usize) -> u64 {
    let bytes = val.to_le_bytes();
    let mut out = [0u8; 8];
    let n = esize / unit;
    for c in 0..n {
        let dst = (n - 1 - c) * unit;
        out[dst..dst + unit].copy_from_slice(&bytes[c * unit..c * unit + unit]);
    }
    u64::from_le_bytes(out)
}
/// AdvSIMDExpandImm: expand an 8-bit immediate to a 64-bit value per `cmode`/`op`
/// (ARM Architecture Reference Manual). Used by the SIMD modified-immediate group.
pub(crate) fn adv_simd_expand_imm(op: u32, cmode: u32, imm8: u8) -> u64 {
    let imm8 = imm8 as u64;
    let rep32 = |x: u64| (x & 0xFFFF_FFFF) | ((x & 0xFFFF_FFFF) << 32);
    let rep16 = |x: u64| {
        let x = x & 0xFFFF;
        x | (x << 16) | (x << 32) | (x << 48)
    };
    let rep8 = |x: u64| (x & 0xFF).wrapping_mul(0x0101_0101_0101_0101);
    match cmode {
        0b0000 | 0b0001 => rep32(imm8),
        0b0010 | 0b0011 => rep32(imm8 << 8),
        0b0100 | 0b0101 => rep32(imm8 << 16),
        0b0110 | 0b0111 => rep32(imm8 << 24),
        0b1000 | 0b1001 => rep16(imm8),
        0b1010 | 0b1011 => rep16(imm8 << 8),
        0b1100 => rep32((imm8 << 8) | 0xFF),
        0b1101 => rep32((imm8 << 16) | 0xFFFF),
        0b1110 => {
            if op == 0 {
                rep8(imm8)
            } else {
                // MOVI 64-bit: each bit of imm8 expands to a 0x00/0xFF byte.
                let mut r = 0u64;
                for i in 0..8 {
                    if (imm8 >> i) & 1 != 0 {
                        r |= 0xFFu64 << (i * 8);
                    }
                }
                r
            }
        }
        0b1111 => {
            if op == 0 {
                rep32(vfp_expand_imm_f32(imm8 as u8) as u64)
            } else {
                vfp_expand_imm_f64(imm8 as u8)
            }
        }
        _ => 0,
    }
}
/// Mask covering the low `bits` bits, as u128 (`bits` up to 128).
#[inline]
pub(crate) fn elem_mask_u128(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}
/// Like `simd_rshift` but returns the full (untruncated, signed) shifted value
/// so a narrowing op can saturate it to a smaller destination element.
pub(crate) fn simd_rshift_full(
    a: u64,
    shift: u32,
    bits: u32,
    signed: bool,
    rounding: bool,
) -> i128 {
    let round: i128 = if rounding { 1i128 << (shift - 1) } else { 0 };
    if signed {
        (sext_elem(a, bits) + round) >> shift
    } else {
        ((uext_elem(a, bits) as i128) + round) >> shift
    }
}
/// Right-shift the low `bits` bits of `a` by `shift` (1..=bits), arithmetic if
/// `signed`, with optional rounding (SRSHR/URSHR). Result in the low `bits` bits.
pub(crate) fn simd_rshift(a: u64, shift: u32, bits: u32, signed: bool, rounding: bool) -> u64 {
    let m = elem_mask(bits);
    let round: i128 = if rounding { 1i128 << (shift - 1) } else { 0 };
    if signed {
        let v = sext_elem(a, bits);
        (((v + round) >> shift) as u64) & m
    } else {
        let v = uext_elem(a, bits) as i128;
        (((v + round) >> shift) as u64) & m
    }
}
/// One element of a same-size Advanced SIMD shift-by-immediate. `a` is the
/// source element, `d` the current destination element (for the accumulating
/// and insert forms). Returns the raw result element.
pub(crate) fn adv_simd_shift_imm_elem(
    u: u32,
    opcode: u32,
    bits: u32,
    shift: u32,
    a: u64,
    d: u64,
) -> (u64, bool) {
    let m = elem_mask(bits);
    let signed = u == 0;
    match opcode {
        0b00000 => (simd_rshift(a, shift, bits, signed, false), false), // SSHR / USHR
        0b00010 => {
            // SSRA / USRA: accumulate shifted value into destination.
            (
                (d.wrapping_add(simd_rshift(a, shift, bits, signed, false))) & m,
                false,
            )
        }
        0b00100 => (simd_rshift(a, shift, bits, signed, true), false), // SRSHR / URSHR
        0b00110 => {
            // SRSRA / URSRA
            (
                (d.wrapping_add(simd_rshift(a, shift, bits, signed, true))) & m,
                false,
            )
        }
        0b01000 => {
            // SRI (u==1): shift right and insert.
            let low_mask = if shift >= bits {
                0
            } else {
                (1u64 << (bits - shift)) - 1
            };
            let shifted = (uext_elem(a, bits) >> shift) as u64 & low_mask;
            (shifted | (d & !low_mask & m), false)
        }
        0b01010 => {
            if u == 0 {
                // SHL
                (((uext_elem(a, bits) << shift) as u64) & m, false)
            } else {
                // SLI: shift left and insert.
                let low_mask = (1u64 << shift) - 1;
                let shifted = ((uext_elem(a, bits) << shift) as u64) & m & !low_mask;
                (shifted | (d & low_mask), false)
            }
        }
        0b01100 => {
            // SQSHLU: signed value, saturating left shift to unsigned range.
            sat_unsigned_q(sext_elem(a, bits) << shift, bits)
        }
        0b01110 => {
            // SQSHL / UQSHL: saturating left shift.
            if signed {
                sat_signed_q(sext_elem(a, bits) << shift, bits)
            } else {
                sat_unsigned_q((uext_elem(a, bits) as i128) << shift, bits)
            }
        }
        _ => (a & m, false),
    }
}
/// Reverse the low `bits` bits of each byte, returning a value with `bits/8`
/// bit-reversed bytes (RBIT operates per byte).
#[inline]
pub(crate) fn rbit_bytes(a: u64, bits: u32) -> u64 {
    let mut out = 0u64;
    for byte in 0..(bits / 8) {
        let b = ((a >> (byte * 8)) & 0xFF) as u8;
        out |= (b.reverse_bits() as u64) << (byte * 8);
    }
    out
}
/// Count leading sign bits (CLS): number of consecutive bits after the sign bit
/// that equal the sign bit, within an element of `bits`.
#[inline]
pub(crate) fn count_leading_sign(a: u64, bits: u32) -> u64 {
    let v = a & elem_mask(bits);
    let sign = (v >> (bits - 1)) & 1;
    let mut count = 0u64;
    let mut i = bits as i32 - 2;
    while i >= 0 {
        if (v >> i) & 1 == sign {
            count += 1;
            i -= 1;
        } else {
            break;
        }
    }
    count
}
/// Count leading zeros (CLZ) within an element of `bits`.
#[inline]
pub(crate) fn count_leading_zeros_elem(a: u64, bits: u32) -> u64 {
    let v = a & elem_mask(bits);
    if v == 0 {
        return bits as u64;
    }
    let mut count = 0u64;
    let mut i = bits as i32 - 1;
    while i >= 0 {
        if (v >> i) & 1 == 0 {
            count += 1;
            i -= 1;
        } else {
            break;
        }
    }
    count
}
/// One element of an Advanced SIMD two-register-miscellaneous *integer* op that
/// preserves element size (not REV / widening / narrowing / FP). `a` is the
/// source element and `d` the current destination (for SUQADD/USQADD). Returns
/// `Some(result)` or `None` if the opcode is handled elsewhere.
pub(crate) fn adv_simd_two_reg_int(
    u: u32,
    opcode: u32,
    bits: u32,
    a: u64,
    d: u64,
) -> Option<(u64, bool)> {
    let m = elem_mask(bits);
    let sa = sext_elem(a, bits);
    Some(match (u, opcode) {
        (0, 0b00011) => sat_signed_q(sext_elem(d, bits) + uext_elem(a, bits) as i128, bits), // SUQADD
        (1, 0b00011) => sat_unsigned_q(uext_elem(d, bits) as i128 + sext_elem(a, bits), bits), // USQADD
        (0, 0b00100) => (count_leading_sign(a, bits) & m, false), // CLS
        (1, 0b00100) => (count_leading_zeros_elem(a, bits) & m, false), // CLZ
        (0, 0b00101) => ((a & 0xFF).count_ones() as u64, false),  // CNT (per byte; bits==8)
        (0, 0b00111) => sat_signed_q(sext_elem(a, bits).abs(), bits), // SQABS
        (1, 0b00111) => sat_signed_q(-sext_elem(a, bits), bits),  // SQNEG
        (0, 0b01000) => (bool_mask(sa > 0, bits), false),         // CMGT #0
        (1, 0b01000) => (bool_mask(sa >= 0, bits), false),        // CMGE #0
        (0, 0b01001) => (bool_mask(sa == 0, bits), false),        // CMEQ #0
        (1, 0b01001) => (bool_mask(sa <= 0, bits), false),        // CMLE #0
        (0, 0b01010) => (bool_mask(sa < 0, bits), false),         // CMLT #0
        (0, 0b01011) => ((sa.unsigned_abs() as u64) & m, false),  // ABS
        (1, 0b01011) => (((-sa) as u64) & m, false),              // NEG
        _ => return None,
    })
}
/// Read an `esize`-byte little-endian element from `bytes` at `off`.
#[inline]
pub(crate) fn read_elem(bytes: &[u8], off: usize, esize: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..esize {
        v |= (bytes[off + i] as u64) << (8 * i);
    }
    v
}
/// Write the low `esize` bytes of `val` little-endian into `bytes` at `off`.
#[inline]
pub(crate) fn write_elem(bytes: &mut [u8], off: usize, esize: usize, val: u64) {
    for i in 0..esize {
        bytes[off + i] = (val >> (8 * i)) as u8;
    }
}
#[inline]
pub(crate) fn mask_fpcr(value: u32) -> u32 {
    value & FPCR_ARCH_MASK
}
#[inline]
pub(crate) fn mask_fpsr(value: u32) -> u32 {
    value & FPSR_ARCH_MASK
}
pub(crate) fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}
pub(crate) fn is_square_u64(n: u64) -> bool {
    let r = (n as f64).sqrt() as u64;
    r * r == n || r.saturating_add(1).saturating_mul(r.saturating_add(1)) == n
}
pub(crate) fn shift_i128_checked(value: i128, shift: i32) -> Option<i128> {
    if shift < 0 || shift >= 120 {
        return None;
    }
    value.checked_shl(shift as u32)
}
pub(crate) fn add_shifted_limb(dst: &mut Vec<u64>, index: usize, limb: u64) {
    if limb == 0 {
        return;
    }
    if dst.len() <= index {
        dst.resize(index + 1, 0);
    }
    let mut i = index;
    let mut carry = limb as u128;
    while carry != 0 {
        if dst.len() <= i {
            dst.push(0);
        }
        let sum = dst[i] as u128 + carry;
        dst[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }
}
pub(crate) fn add_shifted_u128(dst: &mut Vec<u64>, value: u128, shift: u32) {
    if value == 0 {
        return;
    }
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    for limb_index in 0..2 {
        let limb = (value >> (limb_index * 64)) as u64;
        if limb == 0 {
            continue;
        }
        let index = word_shift + limb_index;
        if bit_shift == 0 {
            add_shifted_limb(dst, index, limb);
        } else {
            add_shifted_limb(dst, index, limb << bit_shift);
            add_shifted_limb(dst, index + 1, limb >> (64 - bit_shift));
        }
    }
}
pub(crate) fn cmp_u64_words(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let alen = a.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    let blen = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    if alen != blen {
        return alen.cmp(&blen);
    }
    for i in (0..alen).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    std::cmp::Ordering::Equal
}
pub(crate) fn scaled_i128_terms_sign(terms: &[(i128, i32)]) -> std::cmp::Ordering {
    let Some(min_exp) = terms
        .iter()
        .filter(|(mant, _)| *mant != 0)
        .map(|(_, exp)| *exp)
        .min()
    else {
        return std::cmp::Ordering::Equal;
    };
    let mut pos = Vec::new();
    let mut neg = Vec::new();
    for &(mant, exp) in terms {
        if mant == 0 {
            continue;
        }
        let shift = (exp - min_exp) as u32;
        if mant > 0 {
            add_shifted_u128(&mut pos, mant as u128, shift);
        } else {
            add_shifted_u128(&mut neg, mant.unsigned_abs(), shift);
        }
    }
    cmp_u64_words(&pos, &neg)
}
/// UnsignedRecipEstimate (N=32): estimate of 1/x for a fixed-point value.
pub(crate) fn unsigned_recip_estimate(op: u32) -> u32 {
    if op & 0x8000_0000 == 0 {
        return 0xFFFF_FFFF;
    }
    let est = recip_estimate((op >> 23) & 0x1FF);
    (est & 0x1FF) << 23
}
/// UnsignedRSqrtEstimate (N=32).
pub(crate) fn unsigned_rsqrt_estimate(op: u32) -> u32 {
    if op & 0xC000_0000 == 0 {
        return 0xFFFF_FFFF;
    }
    let est = recip_sqrt_estimate((op >> 23) & 0x1FF);
    (est & 0x1FF) << 23
}
/// NZCV produced by an SVE predicate-setting op (PTEST convention with an
/// all-true governing predicate): N=First active, Z=None active, C=!Last
/// active, V=0. `pred` is byte-granular; element `e` is bit `e*esize`.
/// Sign-extend an MTE-tagged address from bit 55 (the address part is bits
/// [55:0]; the logical/physical tags above are ignored for SUBP/SUBPS).
pub(crate) fn sign_extend_56(v: u64) -> u64 {
    ((v << 8) as i64 >> 8) as u64
}
/// 64-bit subtract returning (result, N, Z, C, V).
pub(crate) fn sub_with_flags_64(a: u64, b: u64) -> (u64, bool, bool, bool, bool) {
    let (res, borrow) = a.overflowing_sub(b);
    let c = !borrow; // ARM carry = NOT borrow
    let v = (((a ^ b) & (a ^ res)) >> 63) & 1 == 1;
    (res, (res >> 63) & 1 == 1, res == 0, c, v)
}
pub(crate) fn pred_test_flags(
    pred: u32,
    elements: usize,
    esize: usize,
) -> (bool, bool, bool, bool) {
    let first = pred & 1 != 0;
    let none = pred == 0;
    let last = (pred >> ((elements - 1) * esize)) & 1 != 0;
    (first, none, !last, false)
}
/// General SVE PredTest(mask, result): N=is the first mask-active element set in
/// result, Z=no mask-active element is set, C=!is the last mask-active element
/// set, V=0. Both predicates are byte-granular.
pub(crate) fn pred_test(
    mask: u32,
    result: u32,
    elements: usize,
    esize: usize,
) -> (bool, bool, bool, bool) {
    let mut n = false;
    let mut first = true;
    let mut z = true;
    let mut last_r = false;
    for e in 0..elements {
        let b = e * esize;
        if (mask >> b) & 1 == 1 {
            let r = (result >> b) & 1 == 1;
            if first {
                n = r;
                first = false;
            }
            if r {
                z = false;
            }
            last_r = r;
        }
    }
    (n, z, !last_r, false)
}
/// SVE LastActive(mask, operand): true iff the highest-indexed mask-active
/// element is set in `operand`. Both predicates are byte-granular (element `e`
/// of size `esize` bytes is governed by bit `e*esize`).
pub(crate) fn last_active(mask: u32, operand: u32, elements: usize, esize: usize) -> bool {
    for e in (0..elements).rev() {
        let b = e * esize;
        if (mask >> b) & 1 == 1 {
            return (operand >> b) & 1 == 1;
        }
    }
    false
}
/// Convert a 16-bit integer lane to binary16 (round to nearest even).
pub(crate) fn int16_to_fp16(lane: u16, signed: bool) -> u16 {
    let v = if signed {
        (lane as i16) as f64
    } else {
        lane as f64
    };
    fp16_round(v)
}

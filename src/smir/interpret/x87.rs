//! x87 FPU instruction interpretation

mod data;
mod stack_metadata;
mod transcendental;

pub(crate) use data::{X87EflagsUpdate, X87Memory};

use crate::smir::interpret::*;
use std::cmp::Ordering;
use std::collections::HashMap;

use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::ir::flags::{FlagSet, FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::ops::{
    HexFpOp, HexFpRecipKind, OpKind, RvVectorState, SmirOp, X86AdxKind, X86BlsKind,
    X86CacheControlKind, X86CountKind, X86OpHint, X86ThreeDNowKind, X86X87ArithmeticDestination,
    X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind,
    X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth, X86X87TranscendentalKind, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

impl SmirInterpreter {
    pub(crate) fn execute_x86_x87_data(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        guest_pc: GuestAddr,
        kind: X86X87DataKind,
        addr: Option<&Address>,
        st: u8,
        fop: u16,
    ) -> Result<(), MemoryError> {
        let effective_addr = addr.map(|address| self.compute_address(ctx, address));
        let conditional_move_taken = if let X86X87DataKind::ConditionalMove(condition) = kind {
            Some(ctx.flags.eval_condition(condition))
        } else {
            None
        };
        let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
            return Ok(());
        };
        let mut x87 = x86.x87.clone();
        let eflags = Self::x86_x87_data_step(
            &mut x87,
            memory,
            guest_pc,
            kind,
            effective_addr,
            st,
            fop,
            conditional_move_taken,
        )?;
        x86.x87 = x87;
        if let Some(update) = eflags {
            ctx.flags.materialize_all();
            ctx.flags.materialized.of = false;
            ctx.flags.materialized.sf = false;
            ctx.flags.materialized.af = false;
            ctx.flags.lazy = None;
            if let Some(codes) = update.codes {
                ctx.flags.materialized.cf = codes & 0x0100 != 0;
                ctx.flags.materialized.pf = codes & 0x0400 != 0;
                ctx.flags.materialized.zf = codes & 0x4000 != 0;
            }
        }
        Ok(())
    }

    pub(crate) fn x86_x87_raw_info(raw: &[u8; 10]) -> X87RawInfo {
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
        let exponent = exponent_sign & 0x7FFF;
        let integer_bit = significand >> 63;
        let fraction = significand & 0x7FFF_FFFF_FFFF_FFFF;
        let unsupported = (exponent == 0x7FFF && integer_bit == 0)
            || (exponent != 0 && exponent != 0x7FFF && integer_bit == 0);
        let nan = exponent == 0x7FFF && integer_bit == 1 && fraction != 0;
        X87RawInfo {
            sign: exponent_sign & 0x8000 != 0,
            unsupported,
            nan,
            signaling_nan: nan && fraction & (1u64 << 62) == 0,
            denormal: exponent == 0 && significand != 0,
            zero: exponent == 0 && significand == 0,
        }
    }

    /// Exact total ordering for supported, non-NaN binary80 operands. Signed
    /// zeros compare equal. Pseudo-denormals use an effective biased exponent
    /// of one, as specified by Intel, so their ordering aliases the equivalent
    /// minimum-exponent normal encoding.
    pub(crate) fn x86_x87_compare_raw(lhs: &[u8; 10], rhs: &[u8; 10]) -> Ordering {
        let lhs_info = Self::x86_x87_raw_info(lhs);
        let rhs_info = Self::x86_x87_raw_info(rhs);
        if lhs_info.zero && rhs_info.zero {
            return Ordering::Equal;
        }
        if lhs_info.sign != rhs_info.sign {
            return if lhs_info.sign {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let magnitude = |raw: &[u8; 10]| {
            let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let mut exponent = u16::from_le_bytes(raw[8..].try_into().unwrap()) & 0x7FFF;
            if exponent == 0 && significand >> 63 != 0 {
                exponent = 1;
            }
            (exponent, significand)
        };
        let ordering = magnitude(lhs).cmp(&magnitude(rhs));
        if lhs_info.sign {
            ordering.reverse()
        } else {
            ordering
        }
    }

    pub(crate) fn x86_x87_from_i64(value: i64) -> [u8; 10] {
        Self::x86_x87_from_signed_magnitude(value.unsigned_abs(), value < 0)
    }

    /// Convert an exactly representable signed magnitude into binary80. The
    /// explicit sign preserves the packed-BCD distinction between +0 and -0.
    pub(crate) fn x86_x87_from_signed_magnitude(magnitude: u64, sign: bool) -> [u8; 10] {
        if magnitude == 0 {
            let mut raw = [0; 10];
            raw[9] = u8::from(sign) << 7;
            return raw;
        }
        let highest = 63 - magnitude.leading_zeros();
        let significand = magnitude << (63 - highest);
        let exponent_sign = (16383 + highest as u16) | ((sign as u16) << 15);
        let mut raw = [0u8; 10];
        raw[..8].copy_from_slice(&significand.to_le_bytes());
        raw[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        raw
    }

    pub(crate) fn x86_x87_to_integer(
        raw: &[u8; 10],
        width_bits: u32,
        rounding: u16,
    ) -> X87IntegerConversion {
        let info = Self::x86_x87_raw_info(raw);
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let mut exponent = u16::from_le_bytes(raw[8..].try_into().unwrap()) & 0x7FFF;
        if info.unsupported || info.nan || exponent == 0x7FFF {
            return X87IntegerConversion {
                value: 0,
                invalid: true,
                inexact: false,
                rounded_up: false,
            };
        }
        if info.zero {
            return X87IntegerConversion {
                value: 0,
                invalid: false,
                inexact: false,
                rounded_up: false,
            };
        }
        if exponent == 0 && significand >> 63 != 0 {
            exponent = 1; // pseudo-denormal effective exponent
        }
        let unbiased = exponent as i32 - 16383;
        let denominator_shift = 63i32 - unbiased;
        let (mut magnitude, remainder, half_cmp) = if denominator_shift <= 0 {
            let shift = (-denominator_shift) as u32;
            if shift >= 128 {
                (u128::MAX, false, Ordering::Less)
            } else {
                (
                    (significand as u128)
                        .checked_shl(shift)
                        .unwrap_or(u128::MAX),
                    false,
                    Ordering::Less,
                )
            }
        } else if denominator_shift >= 128 {
            let half_bit = denominator_shift - 1;
            let half_cmp = if half_bit >= 128 {
                Ordering::Less
            } else {
                (significand as u128).cmp(&(1u128 << half_bit))
            };
            (0, significand != 0, half_cmp)
        } else {
            let shift = denominator_shift as u32;
            let denominator_mask = (1u128 << shift) - 1;
            let remainder_bits = (significand as u128) & denominator_mask;
            (
                (significand as u128) >> shift,
                remainder_bits != 0,
                remainder_bits.cmp(&(1u128 << (shift - 1))),
            )
        };

        let increment = if remainder {
            match rounding & 3 {
                0 => {
                    half_cmp == Ordering::Greater
                        || (half_cmp == Ordering::Equal && magnitude & 1 != 0)
                }
                1 => info.sign,
                2 => !info.sign,
                3 => false,
                _ => unreachable!(),
            }
        } else {
            false
        };
        if increment {
            magnitude = magnitude.saturating_add(1);
        }

        let negative_limit = 1u128 << (width_bits - 1);
        let positive_limit = negative_limit - 1;
        let invalid = if info.sign {
            magnitude > negative_limit
        } else {
            magnitude > positive_limit
        };
        if invalid {
            return X87IntegerConversion {
                value: 0,
                invalid: true,
                inexact: false,
                rounded_up: false,
            };
        }
        let mask = if width_bits == 64 {
            u64::MAX
        } else {
            (1u64 << width_bits) - 1
        };
        let value = if info.sign {
            (0u64.wrapping_sub(magnitude as u64)) & mask
        } else {
            magnitude as u64
        };
        X87IntegerConversion {
            value,
            invalid: false,
            inexact: remainder,
            rounded_up: increment,
        }
    }

    /// Round a binary80 value to an integral binary80 value without narrowing
    /// through a host integer type. Values with unbiased exponent >= 63 are
    /// already integral because binary80 has a 64-bit significand.
    pub(crate) fn x86_x87_round_to_integral(
        raw: &[u8; 10],
        rounding: u16,
    ) -> X87IntegralConversion {
        let info = Self::x86_x87_raw_info(raw);
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
        let exponent = exponent_sign & 0x7FFF;

        if info.unsupported {
            return X87IntegralConversion {
                raw: crate::smir::X86X87State::INDEFINITE,
                invalid: true,
                denormal: false,
                inexact: false,
                rounded_up: false,
            };
        }
        if info.nan {
            let mut result = *raw;
            if info.signaling_nan {
                let quiet = significand | (1u64 << 62);
                result[..8].copy_from_slice(&quiet.to_le_bytes());
            }
            return X87IntegralConversion {
                raw: result,
                invalid: info.signaling_nan,
                denormal: false,
                inexact: false,
                rounded_up: false,
            };
        }
        if exponent == 0x7FFF || info.zero {
            return X87IntegralConversion {
                raw: *raw,
                invalid: false,
                denormal: false,
                inexact: false,
                rounded_up: false,
            };
        }

        // True denormals and pseudo-denormals both use biased exponent one for
        // their value. They still raise #D because their encoded exponent is 0.
        let effective_exponent = if exponent == 0 { 1 } else { exponent };
        let unbiased = effective_exponent as i32 - 16383;
        if unbiased >= 63 {
            return X87IntegralConversion {
                raw: *raw,
                invalid: false,
                denormal: info.denormal,
                inexact: false,
                rounded_up: false,
            };
        }

        let (magnitude, inexact, rounded_up) =
            Self::x86_x87_round_shift(significand as u128, 63 - unbiased, rounding, info.sign);
        X87IntegralConversion {
            raw: Self::x86_x87_from_signed_magnitude(magnitude as u64, info.sign),
            invalid: false,
            denormal: info.denormal,
            inexact,
            rounded_up,
        }
    }

    pub(crate) fn x86_x87_extract(raw: &[u8; 10]) -> X87ExtractResult {
        let info = Self::x86_x87_raw_info(raw);
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
        let exponent = exponent_sign & 0x7FFF;

        if info.unsupported {
            return X87ExtractResult {
                significand: crate::smir::X86X87State::INDEFINITE,
                exponent: crate::smir::X86X87State::INDEFINITE,
                invalid: true,
                denormal: false,
                zero: false,
            };
        }
        if info.nan {
            let mut quiet = *raw;
            if info.signaling_nan {
                quiet[..8].copy_from_slice(&(significand | (1u64 << 62)).to_le_bytes());
            }
            return X87ExtractResult {
                significand: quiet,
                exponent: quiet,
                invalid: info.signaling_nan,
                denormal: false,
                zero: false,
            };
        }
        if exponent == 0x7FFF {
            let positive_infinity = Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 0x7FFF);
            return X87ExtractResult {
                significand: *raw,
                exponent: positive_infinity,
                invalid: false,
                denormal: false,
                zero: false,
            };
        }
        if info.zero {
            return X87ExtractResult {
                significand: *raw,
                exponent: Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 0xFFFF),
                invalid: false,
                denormal: false,
                zero: true,
            };
        }

        let (normalized, true_exponent) = if exponent == 0 {
            let highest = 63 - significand.leading_zeros();
            (significand << (63 - highest), highest as i64 - 16_445)
        } else {
            (significand, exponent as i64 - 16_383)
        };
        X87ExtractResult {
            significand: Self::x86_x87_from_raw_parts(
                normalized,
                0x3FFF | (exponent_sign & 0x8000),
            ),
            exponent: Self::x86_x87_from_i64(true_exponent),
            invalid: false,
            denormal: info.denormal,
            zero: false,
        }
    }

    pub(crate) fn x86_x87_from_raw_parts(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut raw = [0u8; 10];
        raw[..8].copy_from_slice(&significand.to_le_bytes());
        raw[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        raw
    }

    /// Truncate a supported finite binary80 value toward zero, saturating at a
    /// bound larger than every exponent displacement relevant to FSCALE.
    pub(crate) fn x86_x87_truncate_scale(raw: &[u8; 10]) -> i64 {
        const LIMIT: u64 = 100_000;
        let info = Self::x86_x87_raw_info(raw);
        if info.zero {
            return 0;
        }
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let exponent = u16::from_le_bytes(raw[8..].try_into().unwrap()) & 0x7FFF;
        let effective_exponent = if exponent == 0 { 1 } else { exponent };
        let unbiased = effective_exponent as i32 - 16_383;
        let magnitude = if unbiased < 0 {
            0
        } else if unbiased >= 63 {
            LIMIT
        } else {
            (significand >> (63 - unbiased)).min(LIMIT)
        };
        if info.sign {
            -(magnitude as i64)
        } else {
            magnitude as i64
        }
    }

    pub(crate) fn x86_x87_quiet_nan(raw: &[u8; 10]) -> [u8; 10] {
        let mut result = *raw;
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        result[..8].copy_from_slice(&(significand | (1u64 << 62)).to_le_bytes());
        result
    }

    /// Exact FSCALE response. The operation is independent of FCW.PC; only
    /// denormalization at the binary80 exponent floor can discard bits.
    pub(crate) fn x86_x87_scale(
        st0: &[u8; 10],
        st1: &[u8; 10],
        control_word: u16,
    ) -> X87ScaleResult {
        let lhs = Self::x86_x87_raw_info(st0);
        let rhs = Self::x86_x87_raw_info(st1);
        let lhs_sig = u64::from_le_bytes(st0[..8].try_into().unwrap());
        let lhs_exp = u16::from_le_bytes(st0[8..].try_into().unwrap()) & 0x7FFF;
        let rhs_exp = u16::from_le_bytes(st1[8..].try_into().unwrap()) & 0x7FFF;
        let sign = lhs.sign;
        let finish =
            |raw, invalid, denormal, overflow, underflow, inexact, rounded_up| X87ScaleResult {
                raw,
                invalid,
                denormal,
                overflow,
                underflow,
                inexact,
                rounded_up,
            };

        if lhs.unsupported || rhs.unsupported {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
                false,
                false,
            );
        }
        if lhs.nan || rhs.nan {
            let selected = if lhs.signaling_nan {
                Self::x86_x87_quiet_nan(st0)
            } else if rhs.signaling_nan {
                Self::x86_x87_quiet_nan(st1)
            } else if lhs.nan {
                *st0
            } else {
                *st1
            };
            return finish(
                selected,
                lhs.signaling_nan || rhs.signaling_nan,
                false,
                false,
                false,
                false,
                false,
            );
        }

        let lhs_infinite = lhs_exp == 0x7FFF;
        let rhs_infinite = rhs_exp == 0x7FFF;
        if rhs_infinite {
            let invalid = (rhs.sign && lhs_infinite) || (!rhs.sign && lhs.zero);
            if invalid {
                return finish(
                    crate::smir::X86X87State::INDEFINITE,
                    true,
                    false,
                    false,
                    false,
                    false,
                    false,
                );
            }
            if rhs.sign {
                return finish(
                    Self::x86_x87_from_raw_parts(0, (sign as u16) << 15),
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                );
            }
            return finish(
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 0x7FFF | ((sign as u16) << 15)),
                false,
                false,
                false,
                false,
                false,
                false,
            );
        }
        if lhs_infinite || lhs.zero {
            return finish(*st0, false, rhs.denormal, false, false, false, false);
        }

        let denormal = lhs.denormal || rhs.denormal;
        let highest = 63 - lhs_sig.leading_zeros();
        let normalized = lhs_sig << (63 - highest);
        let base_exponent = if lhs_exp == 0 {
            highest as i64 - 16_445
        } else {
            lhs_exp as i64 - 16_383
        };
        let result_exponent = base_exponent + Self::x86_x87_truncate_scale(st1);
        if result_exponent > 16_383 {
            let overflow_masked = control_word & 0x0008 != 0;
            let raw = if !overflow_masked {
                let biased = result_exponent - 24_576;
                if biased <= 16_383 {
                    Self::x86_x87_from_raw_parts(
                        normalized,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                }
            } else {
                let infinity = match (control_word >> 10) & 3 {
                    0 => true,
                    1 => sign,
                    2 => !sign,
                    3 => false,
                    _ => unreachable!(),
                };
                if infinity {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(u64::MAX, 0x7FFE | ((sign as u16) << 15))
                }
            };
            let rounded_up = overflow_masked && matches!((control_word >> 10) & 3, 0)
                || (overflow_masked && matches!((control_word >> 10) & 3, 1) && sign)
                || (overflow_masked && matches!((control_word >> 10) & 3, 2) && !sign);
            return finish(raw, false, denormal, true, false, true, rounded_up);
        }
        if result_exponent < -16_382 {
            let shift = (-16_382 - result_exponent) as i32;
            let (rounded, inexact, rounded_up) = Self::x86_x87_round_shift(
                normalized as u128,
                shift,
                (control_word >> 10) & 3,
                sign,
            );
            if !inexact {
                return finish(
                    Self::x86_x87_from_raw_parts(rounded as u64, (sign as u16) << 15),
                    false,
                    denormal,
                    false,
                    false,
                    false,
                    false,
                );
            }
            let underflow_masked = control_word & 0x0010 != 0;
            let raw = if !underflow_masked {
                let biased = result_exponent + 24_576;
                if biased >= -16_382 {
                    Self::x86_x87_from_raw_parts(
                        normalized,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(0, (sign as u16) << 15)
                }
            } else if rounded == 1u128 << 63 {
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 1 | ((sign as u16) << 15))
            } else {
                Self::x86_x87_from_raw_parts(rounded as u64, (sign as u16) << 15)
            };
            return finish(
                raw,
                false,
                denormal,
                false,
                true,
                true,
                underflow_masked && rounded_up,
            );
        }

        finish(
            Self::x86_x87_from_raw_parts(
                normalized,
                (result_exponent + 16_383) as u16 | ((sign as u16) << 15),
            ),
            false,
            denormal,
            false,
            false,
            false,
            false,
        )
    }

    /// Floor(sqrt(value)) for the full u128 domain. The restoring algorithm
    /// consumes one base-4 digit per iteration: O(64) time and O(1) space.
    pub(crate) fn x86_x87_integer_sqrt(mut value: u128) -> u128 {
        let mut result = 0u128;
        let mut bit = 1u128 << 126;
        while bit > value {
            bit >>= 2;
        }
        while bit != 0 {
            if value >= result + bit {
                value -= result + bit;
                result = (result >> 1) + bit;
            } else {
                result >>= 1;
            }
            bit >>= 2;
        }
        result
    }

    /// Exact binary80 square root. The radicand is promoted to a u128 fixed-
    /// point integer, so both the root and its residual are available for an
    /// exact midpoint decision at 24-, 53-, or 64-bit precision.
    pub(crate) fn x86_x87_sqrt(raw: &[u8; 10], control_word: u16) -> X87SqrtResult {
        let info = Self::x86_x87_raw_info(raw);
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
        let exponent = exponent_sign & 0x7FFF;
        let finish = |raw, invalid, denormal, inexact, rounded_up| X87SqrtResult {
            raw,
            invalid,
            denormal,
            inexact,
            rounded_up,
        };

        if info.unsupported {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
            );
        }
        if info.nan {
            return finish(
                if info.signaling_nan {
                    Self::x86_x87_quiet_nan(raw)
                } else {
                    *raw
                },
                info.signaling_nan,
                false,
                false,
                false,
            );
        }
        if info.zero {
            return finish(*raw, false, false, false, false);
        }
        if info.sign {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
            );
        }
        if exponent == 0x7FFF {
            return finish(*raw, false, false, false, false);
        }

        let highest = 63 - significand.leading_zeros();
        let normalized = significand << (63 - highest);
        let true_exponent = if exponent == 0 {
            highest as i32 - 16_445
        } else {
            exponent as i32 - 16_383
        };
        let odd_exponent = true_exponent.rem_euclid(2) != 0;
        let radicand = (normalized as u128) << (63 + u32::from(odd_exponent));
        let root = Self::x86_x87_integer_sqrt(radicand);
        let remainder = radicand - root * root;
        let precision = match (control_word >> 8) & 3 {
            0 => 24u32,
            2 => 53,
            // PC=01 is reserved. Current Intel hardware treats it like the
            // architectural 64-bit setting; keeping that behavior avoids an
            // invented reduced-precision mode.
            1 | 3 => 64,
            _ => unreachable!(),
        };
        let shift = 64 - precision;
        let truncated = root >> shift;
        let discarded = if shift == 0 {
            0
        } else {
            root & ((1u128 << shift) - 1)
        };
        let inexact = discarded != 0 || remainder != 0;
        let half_cmp = if !inexact {
            Ordering::Less
        } else if shift == 0 {
            // Compare sqrt(N)-floor(sqrt(N)) with 1/2 without approximation:
            // 4*(N-q^2) ? 4*q+1.
            (4 * remainder).cmp(&(4 * root + 1))
        } else {
            let midpoint = (truncated << shift) + (1u128 << (shift - 1));
            match root.cmp(&midpoint) {
                Ordering::Equal if remainder != 0 => Ordering::Greater,
                ordering => ordering,
            }
        };
        let increment = inexact
            && match (control_word >> 10) & 3 {
                0 => {
                    half_cmp == Ordering::Greater
                        || (half_cmp == Ordering::Equal && truncated & 1 != 0)
                }
                1 | 3 => false, // positive result: down and toward-zero truncate
                2 => true,
                _ => unreachable!(),
            };
        let rounded = truncated + u128::from(increment);
        let mut result_exponent = true_exponent.div_euclid(2);
        let result_significand = if rounded == 1u128 << precision {
            result_exponent += 1;
            1u64 << 63
        } else {
            (rounded << shift) as u64
        };
        finish(
            Self::x86_x87_from_raw_parts(result_significand, (result_exponent + 16_383) as u16),
            false,
            info.denormal,
            inexact,
            increment,
        )
    }

    /// Exact binary80 multiplication. A 64x64-bit significand product fits in
    /// u128, permitting one rounding step from the exact product at FCW.PC or
    /// directly at the denormal destination quantum.
    pub(crate) fn x86_x87_multiply(
        lhs_raw: &[u8; 10],
        rhs_raw: &[u8; 10],
        rhs_signaling_nan: bool,
        rhs_source_denormal: bool,
        control_word: u16,
    ) -> X87MultiplyResult {
        let lhs = Self::x86_x87_raw_info(lhs_raw);
        let rhs = Self::x86_x87_raw_info(rhs_raw);
        let lhs_sig = u64::from_le_bytes(lhs_raw[..8].try_into().unwrap());
        let rhs_sig = u64::from_le_bytes(rhs_raw[..8].try_into().unwrap());
        let lhs_exp = u16::from_le_bytes(lhs_raw[8..].try_into().unwrap()) & 0x7FFF;
        let rhs_exp = u16::from_le_bytes(rhs_raw[8..].try_into().unwrap()) & 0x7FFF;
        let sign = lhs.sign ^ rhs.sign;
        let finish =
            |raw, invalid, denormal, overflow, underflow, inexact, rounded_up| X87MultiplyResult {
                raw,
                invalid,
                denormal,
                overflow,
                underflow,
                inexact,
                rounded_up,
            };

        if lhs.unsupported || rhs.unsupported {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
                false,
                false,
            );
        }
        let lhs_signaling = lhs.signaling_nan;
        let rhs_signaling = rhs.signaling_nan || rhs_signaling_nan;
        if lhs.nan || rhs.nan {
            let raw = if lhs_signaling {
                Self::x86_x87_quiet_nan(lhs_raw)
            } else if rhs_signaling {
                Self::x86_x87_quiet_nan(rhs_raw)
            } else if lhs.nan {
                *lhs_raw
            } else {
                *rhs_raw
            };
            return finish(
                raw,
                lhs_signaling || rhs_signaling,
                false,
                false,
                false,
                false,
                false,
            );
        }

        let lhs_infinite = lhs_exp == 0x7FFF;
        let rhs_infinite = rhs_exp == 0x7FFF;
        if (lhs.zero && rhs_infinite) || (rhs.zero && lhs_infinite) {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
                false,
                false,
            );
        }
        let denormal = lhs.denormal || rhs.denormal || rhs_source_denormal;
        if lhs_infinite || rhs_infinite {
            return finish(
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 0x7FFF | ((sign as u16) << 15)),
                false,
                denormal,
                false,
                false,
                false,
                false,
            );
        }
        if lhs.zero || rhs.zero {
            return finish(
                Self::x86_x87_from_raw_parts(0, (sign as u16) << 15),
                false,
                denormal,
                false,
                false,
                false,
                false,
            );
        }

        let lhs_highest = 63 - lhs_sig.leading_zeros();
        let rhs_highest = 63 - rhs_sig.leading_zeros();
        let lhs_normalized = lhs_sig << (63 - lhs_highest);
        let rhs_normalized = rhs_sig << (63 - rhs_highest);
        let lhs_exponent = if lhs_exp == 0 {
            lhs_highest as i32 - 16_445
        } else {
            lhs_exp as i32 - 16_383
        };
        let rhs_exponent = if rhs_exp == 0 {
            rhs_highest as i32 - 16_445
        } else {
            rhs_exp as i32 - 16_383
        };
        let product = (lhs_normalized as u128) * (rhs_normalized as u128);
        let product_highest = if product >> 127 != 0 { 127i32 } else { 126 };
        let exact_exponent = lhs_exponent + rhs_exponent + (product_highest - 126);
        let precision = match (control_word >> 8) & 3 {
            0 => 24u32,
            2 => 53,
            1 | 3 => 64,
            _ => unreachable!(),
        };
        let rc = (control_word >> 10) & 3;

        // PC-round with an unbounded exponent for normal and Intel biased
        // unmasked-range responses. Masked underflow is separately rounded
        // from `product`, avoiding a double-rounding boundary.
        let normal_shift = product_highest - (precision as i32 - 1);
        let (mut rounded, normal_inexact, normal_rounded_up) =
            Self::x86_x87_round_shift(product, normal_shift, rc, sign);
        let mut rounded_exponent = exact_exponent;
        if rounded == 1u128 << precision {
            rounded >>= 1;
            rounded_exponent += 1;
        }
        let rounded_significand = (rounded << (64 - precision)) as u64;

        if rounded_exponent > 16_383 {
            let overflow_masked = control_word & 0x0008 != 0;
            let raw = if !overflow_masked {
                let biased = rounded_exponent - 24_576;
                if biased <= 16_383 {
                    Self::x86_x87_from_raw_parts(
                        rounded_significand,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                }
            } else {
                let infinity = match rc {
                    0 => true,
                    1 => sign,
                    2 => !sign,
                    3 => false,
                    _ => unreachable!(),
                };
                if infinity {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                } else {
                    // Reduced PC controls the overflow finite significand too.
                    let maximum = u64::MAX << (64 - precision);
                    Self::x86_x87_from_raw_parts(maximum, 0x7FFE | ((sign as u16) << 15))
                }
            };
            let masked_rounded_up = overflow_masked
                && match rc {
                    0 => true,
                    1 => sign,
                    2 => !sign,
                    3 => false,
                    _ => unreachable!(),
                };
            return finish(
                raw,
                false,
                denormal,
                true,
                false,
                true,
                if overflow_masked {
                    masked_rounded_up
                } else {
                    normal_rounded_up
                },
            );
        }

        if exact_exponent < -16_382 {
            let denormal_shift =
                (product_highest - 63) + (-16_382 - exact_exponent) + (64 - precision) as i32;
            let (denormal_rounded, denormal_inexact, denormal_rounded_up) =
                Self::x86_x87_round_shift(product, denormal_shift, rc, sign);
            let denormal_significand = denormal_rounded << (64 - precision);
            if !denormal_inexact {
                return finish(
                    Self::x86_x87_from_raw_parts(denormal_significand as u64, (sign as u16) << 15),
                    false,
                    denormal,
                    false,
                    false,
                    false,
                    false,
                );
            }
            let underflow_masked = control_word & 0x0010 != 0;
            let raw = if !underflow_masked {
                let biased = rounded_exponent + 24_576;
                if biased >= -16_382 {
                    Self::x86_x87_from_raw_parts(
                        rounded_significand,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(0, (sign as u16) << 15)
                }
            } else if denormal_significand == 1u128 << 63 {
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 1 | ((sign as u16) << 15))
            } else {
                Self::x86_x87_from_raw_parts(denormal_significand as u64, (sign as u16) << 15)
            };
            return finish(
                raw,
                false,
                denormal,
                false,
                true,
                true,
                if underflow_masked {
                    denormal_rounded_up
                } else {
                    normal_rounded_up
                },
            );
        }

        finish(
            Self::x86_x87_from_raw_parts(
                rounded_significand,
                (rounded_exponent + 16_383) as u16 | ((sign as u16) << 15),
            ),
            false,
            denormal,
            false,
            false,
            normal_inexact,
            normal_rounded_up,
        )
    }

    /// Exact binary80 addition and subtraction. Finite magnitudes are held as
    /// unsigned integers in units of the minimum binary80 subnormal
    /// (`2^-16445`), so cancellation and rounding remain exact across the
    /// complete 32767-value exponent field without host floating-point use.
    pub(crate) fn x86_x87_add_subtract(
        destination_raw: &[u8; 10],
        source_raw: &[u8; 10],
        source_signaling_nan: bool,
        source_denormal: bool,
        control_word: u16,
        subtract: bool,
        reverse: bool,
    ) -> X87AddSubtractResult {
        let destination = Self::x86_x87_raw_info(destination_raw);
        let source = Self::x86_x87_raw_info(source_raw);
        let finish = |raw, invalid, denormal, overflow, underflow, inexact, rounded_up| {
            X87AddSubtractResult {
                raw,
                invalid,
                denormal,
                overflow,
                underflow,
                inexact,
                rounded_up,
            }
        };

        if destination.unsupported || source.unsupported {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
                false,
                false,
            );
        }
        let destination_signaling = destination.signaling_nan;
        let source_signaling = source.signaling_nan || source_signaling_nan;
        if destination.nan || source.nan {
            let raw = if destination_signaling {
                Self::x86_x87_quiet_nan(destination_raw)
            } else if source_signaling {
                Self::x86_x87_quiet_nan(source_raw)
            } else if destination.nan {
                *destination_raw
            } else {
                *source_raw
            };
            return finish(
                raw,
                destination_signaling || source_signaling,
                false,
                false,
                false,
                false,
                false,
            );
        }

        let destination_exp = u16::from_le_bytes(destination_raw[8..].try_into().unwrap()) & 0x7FFF;
        let source_exp = u16::from_le_bytes(source_raw[8..].try_into().unwrap()) & 0x7FFF;
        let destination_infinite = destination_exp == 0x7FFF;
        let source_infinite = source_exp == 0x7FFF;
        let lhs_sign = if reverse {
            source.sign
        } else {
            destination.sign
        };
        let mut rhs_sign = if reverse {
            destination.sign
        } else {
            source.sign
        };
        if subtract {
            rhs_sign = !rhs_sign;
        }
        let lhs_infinite = if reverse {
            source_infinite
        } else {
            destination_infinite
        };
        let rhs_infinite = if reverse {
            destination_infinite
        } else {
            source_infinite
        };
        let denormal = destination.denormal || source.denormal || source_denormal;
        if lhs_infinite && rhs_infinite && lhs_sign != rhs_sign {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
                false,
                false,
            );
        }
        if lhs_infinite || rhs_infinite {
            let sign = if lhs_infinite { lhs_sign } else { rhs_sign };
            return finish(
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 0x7FFF | ((sign as u16) << 15)),
                false,
                denormal,
                false,
                false,
                false,
                false,
            );
        }

        let destination_magnitude = Self::x86_x87_big_from_raw(destination_raw);
        let source_magnitude = Self::x86_x87_big_from_raw(source_raw);
        let (lhs_magnitude, rhs_magnitude) = if reverse {
            (&source_magnitude, &destination_magnitude)
        } else {
            (&destination_magnitude, &source_magnitude)
        };
        let rc = (control_word >> 10) & 3;
        let (magnitude, sign) = if lhs_sign == rhs_sign {
            (
                Self::x86_x87_big_add(lhs_magnitude, rhs_magnitude),
                lhs_sign,
            )
        } else {
            match Self::x86_x87_big_cmp(lhs_magnitude, rhs_magnitude) {
                Ordering::Greater => (
                    Self::x86_x87_big_sub(lhs_magnitude, rhs_magnitude),
                    lhs_sign,
                ),
                Ordering::Less => (
                    Self::x86_x87_big_sub(rhs_magnitude, lhs_magnitude),
                    rhs_sign,
                ),
                Ordering::Equal => (Vec::new(), rc == 1),
            }
        };
        if magnitude.is_empty() {
            return finish(
                Self::x86_x87_from_raw_parts(0, (sign as u16) << 15),
                false,
                denormal,
                false,
                false,
                false,
                false,
            );
        }

        let highest = Self::x86_x87_big_bit_len(&magnitude) as i32 - 1;
        let exact_exponent = highest - 16_445;
        let precision = match (control_word >> 8) & 3 {
            0 => 24u32,
            2 => 53,
            1 | 3 => 64,
            _ => unreachable!(),
        };
        let normal_shift = highest - (precision as i32 - 1);
        let (mut rounded, normal_inexact, normal_rounded_up) =
            Self::x86_x87_big_round_shift(&magnitude, normal_shift, rc, sign);
        let mut rounded_exponent = exact_exponent;
        if rounded == 1u128 << precision {
            rounded >>= 1;
            rounded_exponent += 1;
        }
        let rounded_significand = (rounded << (64 - precision)) as u64;

        if rounded_exponent > 16_383 {
            let overflow_masked = control_word & 0x0008 != 0;
            let raw = if !overflow_masked {
                let biased = rounded_exponent - 24_576;
                if biased <= 16_383 {
                    Self::x86_x87_from_raw_parts(
                        rounded_significand,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                }
            } else {
                let infinity = match rc {
                    0 => true,
                    1 => sign,
                    2 => !sign,
                    3 => false,
                    _ => unreachable!(),
                };
                if infinity {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(
                        u64::MAX << (64 - precision),
                        0x7FFE | ((sign as u16) << 15),
                    )
                }
            };
            let masked_rounded_up = overflow_masked
                && match rc {
                    0 => true,
                    1 => sign,
                    2 => !sign,
                    3 => false,
                    _ => unreachable!(),
                };
            return finish(
                raw,
                false,
                denormal,
                true,
                false,
                true,
                if overflow_masked {
                    masked_rounded_up
                } else {
                    normal_rounded_up
                },
            );
        }

        if exact_exponent < -16_382 {
            let denormal_shift = (64 - precision) as i32;
            let (denormal_rounded, denormal_inexact, denormal_rounded_up) =
                Self::x86_x87_big_round_shift(&magnitude, denormal_shift, rc, sign);
            let denormal_significand = denormal_rounded << (64 - precision);
            if !denormal_inexact {
                return finish(
                    Self::x86_x87_from_raw_parts(denormal_significand as u64, (sign as u16) << 15),
                    false,
                    denormal,
                    false,
                    false,
                    false,
                    false,
                );
            }
            let underflow_masked = control_word & 0x0010 != 0;
            let raw = if !underflow_masked {
                let biased = rounded_exponent + 24_576;
                if biased >= -16_382 {
                    Self::x86_x87_from_raw_parts(
                        rounded_significand,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(0, (sign as u16) << 15)
                }
            } else if denormal_significand == 1u128 << 63 {
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 1 | ((sign as u16) << 15))
            } else {
                Self::x86_x87_from_raw_parts(denormal_significand as u64, (sign as u16) << 15)
            };
            return finish(
                raw,
                false,
                denormal,
                false,
                true,
                true,
                if underflow_masked {
                    denormal_rounded_up
                } else {
                    normal_rounded_up
                },
            );
        }

        finish(
            Self::x86_x87_from_raw_parts(
                rounded_significand,
                (rounded_exponent + 16_383) as u16 | ((sign as u16) << 15),
            ),
            false,
            denormal,
            false,
            false,
            normal_inexact,
            normal_rounded_up,
        )
    }

    /// Exact binary80 division. The normalized 64-bit significands are scaled
    /// into a u128 numerator, and the quotient remainder supplies the exact
    /// halfway relation for a single FCW.PC/RC rounding step.
    pub(crate) fn x86_x87_divide(
        destination_raw: &[u8; 10],
        source_raw: &[u8; 10],
        source_signaling_nan: bool,
        source_denormal: bool,
        control_word: u16,
        reverse: bool,
    ) -> X87DivideResult {
        let destination = Self::x86_x87_raw_info(destination_raw);
        let source = Self::x86_x87_raw_info(source_raw);
        let finish =
            |raw, invalid, denormal, zero_divide, overflow, underflow, inexact, rounded_up| {
                X87DivideResult {
                    raw,
                    invalid,
                    denormal,
                    zero_divide,
                    overflow,
                    underflow,
                    inexact,
                    rounded_up,
                }
            };

        if destination.unsupported || source.unsupported {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
                false,
                false,
                false,
            );
        }
        let destination_signaling = destination.signaling_nan;
        let source_signaling = source.signaling_nan || source_signaling_nan;
        if destination.nan || source.nan {
            let raw = if destination_signaling {
                Self::x86_x87_quiet_nan(destination_raw)
            } else if source_signaling {
                Self::x86_x87_quiet_nan(source_raw)
            } else if destination.nan {
                *destination_raw
            } else {
                *source_raw
            };
            return finish(
                raw,
                destination_signaling || source_signaling,
                false,
                false,
                false,
                false,
                false,
                false,
            );
        }

        let destination_exp = u16::from_le_bytes(destination_raw[8..].try_into().unwrap()) & 0x7FFF;
        let source_exp = u16::from_le_bytes(source_raw[8..].try_into().unwrap()) & 0x7FFF;
        let destination_infinite = destination_exp == 0x7FFF;
        let source_infinite = source_exp == 0x7FFF;
        let (lhs_raw, rhs_raw, lhs, rhs, lhs_infinite, rhs_infinite) = if reverse {
            (
                source_raw,
                destination_raw,
                source,
                destination,
                source_infinite,
                destination_infinite,
            )
        } else {
            (
                destination_raw,
                source_raw,
                destination,
                source,
                destination_infinite,
                source_infinite,
            )
        };
        let sign = lhs.sign ^ rhs.sign;
        let denormal = destination.denormal || source.denormal || source_denormal;
        if (lhs_infinite && rhs_infinite) || (lhs.zero && rhs.zero) {
            return finish(
                crate::smir::X86X87State::INDEFINITE,
                true,
                false,
                false,
                false,
                false,
                false,
                false,
            );
        }
        if lhs_infinite {
            return finish(
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 0x7FFF | ((sign as u16) << 15)),
                false,
                denormal,
                false,
                false,
                false,
                false,
                false,
            );
        }
        if rhs_infinite {
            return finish(
                Self::x86_x87_from_raw_parts(0, (sign as u16) << 15),
                false,
                denormal,
                false,
                false,
                false,
                false,
                false,
            );
        }
        if rhs.zero {
            return finish(
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 0x7FFF | ((sign as u16) << 15)),
                false,
                false,
                true,
                false,
                false,
                false,
                false,
            );
        }
        if lhs.zero {
            return finish(
                Self::x86_x87_from_raw_parts(0, (sign as u16) << 15),
                false,
                denormal,
                false,
                false,
                false,
                false,
                false,
            );
        }

        let normalized = |raw: &[u8; 10]| {
            let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let exponent = u16::from_le_bytes(raw[8..].try_into().unwrap()) & 0x7FFF;
            let highest = 63 - significand.leading_zeros();
            let normalized = significand << (63 - highest);
            let true_exponent = if exponent == 0 {
                highest as i32 - 16_445
            } else {
                exponent as i32 - 16_383
            };
            (normalized, true_exponent)
        };
        let (lhs_significand, lhs_exponent) = normalized(lhs_raw);
        let (rhs_significand, rhs_exponent) = normalized(rhs_raw);
        let precision = match (control_word >> 8) & 3 {
            0 => 24u32,
            2 => 53,
            1 | 3 => 64,
            _ => unreachable!(),
        };
        let rc = (control_word >> 10) & 3;
        let lhs_at_least_rhs = lhs_significand >= rhs_significand;
        let exact_exponent = lhs_exponent - rhs_exponent - i32::from(!lhs_at_least_rhs);
        let normal_shift = if lhs_at_least_rhs {
            precision as i32 - 1
        } else {
            precision as i32
        };
        let (mut rounded, normal_inexact, normal_rounded_up) = Self::x86_x87_round_ratio_shift(
            lhs_significand,
            rhs_significand,
            normal_shift,
            rc,
            sign,
        );
        let mut rounded_exponent = exact_exponent;
        if rounded == 1u128 << precision {
            rounded >>= 1;
            rounded_exponent += 1;
        }
        let rounded_significand = (rounded << (64 - precision)) as u64;

        if rounded_exponent > 16_383 {
            let overflow_masked = control_word & 0x0008 != 0;
            let raw = if !overflow_masked {
                let biased = rounded_exponent - 24_576;
                if biased <= 16_383 {
                    Self::x86_x87_from_raw_parts(
                        rounded_significand,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                }
            } else {
                let infinity = match rc {
                    0 => true,
                    1 => sign,
                    2 => !sign,
                    3 => false,
                    _ => unreachable!(),
                };
                if infinity {
                    Self::x86_x87_from_raw_parts(
                        0x8000_0000_0000_0000,
                        0x7FFF | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(
                        u64::MAX << (64 - precision),
                        0x7FFE | ((sign as u16) << 15),
                    )
                }
            };
            let masked_rounded_up = overflow_masked
                && match rc {
                    0 => true,
                    1 => sign,
                    2 => !sign,
                    3 => false,
                    _ => unreachable!(),
                };
            return finish(
                raw,
                false,
                denormal,
                false,
                true,
                false,
                true,
                if overflow_masked {
                    masked_rounded_up
                } else {
                    normal_rounded_up
                },
            );
        }

        if exact_exponent < -16_382 {
            // Divide the exact result by the denormal PC quantum
            // `2^(-16445 + 64 - precision)` before rounding.
            let denormal_shift = lhs_exponent - rhs_exponent + 16_381 + precision as i32;
            let (denormal_rounded, denormal_inexact, denormal_rounded_up) =
                Self::x86_x87_round_ratio_shift(
                    lhs_significand,
                    rhs_significand,
                    denormal_shift,
                    rc,
                    sign,
                );
            let denormal_significand = denormal_rounded << (64 - precision);
            if !denormal_inexact {
                return finish(
                    Self::x86_x87_from_raw_parts(denormal_significand as u64, (sign as u16) << 15),
                    false,
                    denormal,
                    false,
                    false,
                    false,
                    false,
                    false,
                );
            }
            let underflow_masked = control_word & 0x0010 != 0;
            let raw = if !underflow_masked {
                let biased = rounded_exponent + 24_576;
                if biased >= -16_382 {
                    Self::x86_x87_from_raw_parts(
                        rounded_significand,
                        (biased + 16_383) as u16 | ((sign as u16) << 15),
                    )
                } else {
                    Self::x86_x87_from_raw_parts(0, (sign as u16) << 15)
                }
            } else if denormal_significand == 1u128 << 63 {
                Self::x86_x87_from_raw_parts(0x8000_0000_0000_0000, 1 | ((sign as u16) << 15))
            } else {
                Self::x86_x87_from_raw_parts(denormal_significand as u64, (sign as u16) << 15)
            };
            return finish(
                raw,
                false,
                denormal,
                false,
                false,
                true,
                true,
                if underflow_masked {
                    denormal_rounded_up
                } else {
                    normal_rounded_up
                },
            );
        }

        finish(
            Self::x86_x87_from_raw_parts(
                rounded_significand,
                (rounded_exponent + 16_383) as u16 | ((sign as u16) << 15),
            ),
            false,
            denormal,
            false,
            false,
            false,
            normal_inexact,
            normal_rounded_up,
        )
    }

    /// Round `numerator * 2^shift / denominator` without losing the exact
    /// remainder relation. Callers constrain positive shifts to at most 64.
    pub(crate) fn x86_x87_round_ratio_shift(
        numerator: u64,
        denominator: u64,
        shift: i32,
        rounding: u16,
        sign: bool,
    ) -> (u128, bool, bool) {
        let (truncated, remainder, scaled_denominator) = if shift >= 0 {
            debug_assert!(shift <= 64);
            let scaled_numerator = (numerator as u128) << shift;
            let denominator = denominator as u128;
            (
                scaled_numerator / denominator,
                scaled_numerator % denominator,
                denominator,
            )
        } else {
            let right = (-shift) as u32;
            if right > 64 {
                let increment = match rounding & 3 {
                    0 | 3 => false,
                    1 => sign,
                    2 => !sign,
                    _ => unreachable!(),
                };
                return (u128::from(increment), true, increment);
            }
            let denominator = (denominator as u128) << right;
            let numerator = numerator as u128;
            (
                numerator / denominator,
                numerator % denominator,
                denominator,
            )
        };
        let inexact = remainder != 0;
        let half_cmp = if inexact {
            remainder.cmp(&(scaled_denominator - remainder))
        } else {
            Ordering::Less
        };
        let increment = inexact
            && match rounding & 3 {
                0 => {
                    half_cmp == Ordering::Greater
                        || (half_cmp == Ordering::Equal && truncated & 1 != 0)
                }
                1 => sign,
                2 => !sign,
                3 => false,
                _ => unreachable!(),
            };
        (truncated + u128::from(increment), inexact, increment)
    }

    /// Exact FPREM/FPREM1 with a deterministic architecturally permitted
    /// partial-reduction width N=63. All finite operands are integer multiples
    /// of the minimum binary80 subnormal, so the remainder requires no result
    /// rounding and cannot generate #P.
    pub(crate) fn x86_x87_remainder(
        dividend_raw: &[u8; 10],
        modulus_raw: &[u8; 10],
        nearest: bool,
    ) -> X87RemainderResult {
        let dividend = Self::x86_x87_raw_info(dividend_raw);
        let modulus = Self::x86_x87_raw_info(modulus_raw);
        let finish = |raw, invalid, denormal, incomplete, quotient_bits| X87RemainderResult {
            raw,
            invalid,
            denormal,
            incomplete,
            quotient_bits,
        };

        if dividend.unsupported || modulus.unsupported {
            return finish(crate::smir::X86X87State::INDEFINITE, true, false, false, 0);
        }
        if dividend.nan || modulus.nan {
            let raw = if dividend.signaling_nan {
                Self::x86_x87_quiet_nan(dividend_raw)
            } else if modulus.signaling_nan {
                Self::x86_x87_quiet_nan(modulus_raw)
            } else if dividend.nan {
                *dividend_raw
            } else {
                *modulus_raw
            };
            return finish(
                raw,
                dividend.signaling_nan || modulus.signaling_nan,
                false,
                false,
                0,
            );
        }

        let dividend_exp = u16::from_le_bytes(dividend_raw[8..].try_into().unwrap()) & 0x7FFF;
        let modulus_exp = u16::from_le_bytes(modulus_raw[8..].try_into().unwrap()) & 0x7FFF;
        if dividend_exp == 0x7FFF || modulus.zero {
            return finish(crate::smir::X86X87State::INDEFINITE, true, false, false, 0);
        }
        let denormal = dividend.denormal || modulus.denormal;
        if modulus_exp == 0x7FFF || dividend.zero {
            return finish(*dividend_raw, false, denormal, false, 0);
        }

        let normalized = |raw: &[u8; 10]| {
            let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let exponent = u16::from_le_bytes(raw[8..].try_into().unwrap()) & 0x7FFF;
            let highest = 63 - significand.leading_zeros();
            let normalized = significand << (63 - highest);
            let true_exponent = if exponent == 0 {
                highest as i32 - 16_445
            } else {
                exponent as i32 - 16_383
            };
            (normalized, true_exponent)
        };
        let (dividend_significand, dividend_exponent) = normalized(dividend_raw);
        let (modulus_significand, modulus_exponent) = normalized(modulus_raw);
        let exponent_difference = dividend_exponent - modulus_exponent;
        let dividend_magnitude = Self::x86_x87_big_from_raw(dividend_raw);
        let modulus_magnitude = Self::x86_x87_big_from_raw(modulus_raw);

        let (quotient, product, incomplete) = if exponent_difference < 64 {
            let (truncated, remainder, denominator) = if exponent_difference >= 0 {
                let numerator = (dividend_significand as u128) << exponent_difference;
                let denominator = modulus_significand as u128;
                (
                    numerator / denominator,
                    numerator % denominator,
                    denominator,
                )
            } else if exponent_difference >= -64 {
                let numerator = dividend_significand as u128;
                let denominator = (modulus_significand as u128) << (-exponent_difference) as u32;
                (
                    numerator / denominator,
                    numerator % denominator,
                    denominator,
                )
            } else {
                (0, dividend_significand as u128, u128::MAX)
            };
            let increment = nearest
                && remainder != 0
                && (remainder > denominator - remainder
                    || (remainder == denominator - remainder && truncated & 1 != 0));
            let quotient = truncated + u128::from(increment);
            (
                quotient,
                Self::x86_x87_big_mul_u128(&modulus_magnitude, quotient),
                false,
            )
        } else {
            let quotient = Self::x86_x87_round_ratio_shift(
                dividend_significand,
                modulus_significand,
                63,
                3,
                false,
            )
            .0;
            let shifted_modulus =
                Self::x86_x87_big_shl(&modulus_magnitude, (exponent_difference - 63) as usize);
            (
                quotient,
                Self::x86_x87_big_mul_u128(&shifted_modulus, quotient),
                true,
            )
        };

        let (remainder, sign) = match Self::x86_x87_big_cmp(&dividend_magnitude, &product) {
            Ordering::Greater => (
                Self::x86_x87_big_sub(&dividend_magnitude, &product),
                dividend.sign,
            ),
            Ordering::Less => (
                Self::x86_x87_big_sub(&product, &dividend_magnitude),
                !dividend.sign,
            ),
            Ordering::Equal => (Vec::new(), dividend.sign),
        };
        finish(
            Self::x86_x87_big_to_raw(&remainder, sign),
            false,
            denormal,
            incomplete,
            (quotient & 7) as u8,
        )
    }

    pub(crate) fn x86_x87_big_from_raw(raw: &[u8; 10]) -> Vec<u64> {
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        if significand == 0 {
            return Vec::new();
        }
        let exponent = u16::from_le_bytes(raw[8..].try_into().unwrap()) & 0x7FFF;
        let shift = if exponent == 0 {
            0usize
        } else {
            exponent as usize - 1
        };
        let word = shift / 64;
        let bit = shift % 64;
        let mut result = vec![0; word + usize::from(bit != 0) + 1];
        result[word] = significand << bit;
        if bit != 0 {
            result[word + 1] = significand >> (64 - bit);
        }
        Self::x86_x87_big_trim(&mut result);
        result
    }

    pub(crate) fn x86_x87_big_shl(value: &[u64], shift: usize) -> Vec<u64> {
        if value.is_empty() {
            return Vec::new();
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut result = vec![0; value.len() + word_shift + usize::from(bit_shift != 0)];
        for (index, word) in value.iter().copied().enumerate() {
            result[index + word_shift] |= word << bit_shift;
            if bit_shift != 0 {
                result[index + word_shift + 1] |= word >> (64 - bit_shift);
            }
        }
        Self::x86_x87_big_trim(&mut result);
        result
    }

    pub(crate) fn x86_x87_big_mul_u128(value: &[u64], multiplier: u128) -> Vec<u64> {
        if value.is_empty() || multiplier == 0 {
            return Vec::new();
        }
        let multiplier_words = [multiplier as u64, (multiplier >> 64) as u64];
        let mut result = vec![0u64; value.len() + 2];
        for (multiplier_index, multiplier_word) in multiplier_words.into_iter().enumerate() {
            if multiplier_word == 0 {
                continue;
            }
            let mut carry = 0u128;
            for (value_index, value_word) in value.iter().copied().enumerate() {
                let result_index = value_index + multiplier_index;
                let product = (value_word as u128) * (multiplier_word as u128)
                    + result[result_index] as u128
                    + carry;
                result[result_index] = product as u64;
                carry = product >> 64;
            }
            let mut result_index = value.len() + multiplier_index;
            while carry != 0 {
                let sum = result[result_index] as u128 + carry;
                result[result_index] = sum as u64;
                carry = sum >> 64;
                result_index += 1;
                if result_index == result.len() && carry != 0 {
                    result.push(0);
                }
            }
        }
        Self::x86_x87_big_trim(&mut result);
        result
    }

    pub(crate) fn x86_x87_big_to_raw(value: &[u64], sign: bool) -> [u8; 10] {
        let bit_length = Self::x86_x87_big_bit_len(value);
        if bit_length == 0 {
            return Self::x86_x87_from_raw_parts(0, (sign as u16) << 15);
        }
        let highest = bit_length - 1;
        if highest < 63 {
            return Self::x86_x87_from_raw_parts(
                value.first().copied().unwrap_or(0),
                (sign as u16) << 15,
            );
        }
        let shift = highest - 63;
        debug_assert!(!Self::x86_x87_big_any_below(value, shift));
        let significand = Self::x86_x87_big_shr_u64(value, shift);
        let true_exponent = highest as i32 - 16_445;
        debug_assert!((-16_382..=16_383).contains(&true_exponent));
        Self::x86_x87_from_raw_parts(
            significand,
            (true_exponent + 16_383) as u16 | ((sign as u16) << 15),
        )
    }

    pub(crate) fn x86_x87_big_trim(value: &mut Vec<u64>) {
        while value.last() == Some(&0) {
            value.pop();
        }
    }

    pub(crate) fn x86_x87_big_cmp(lhs: &[u64], rhs: &[u64]) -> Ordering {
        lhs.len().cmp(&rhs.len()).then_with(|| {
            lhs.iter()
                .rev()
                .zip(rhs.iter().rev())
                .find_map(|(lhs, rhs)| (lhs != rhs).then(|| lhs.cmp(rhs)))
                .unwrap_or(Ordering::Equal)
        })
    }

    pub(crate) fn x86_x87_big_add(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
        let length = lhs.len().max(rhs.len());
        let mut result = Vec::with_capacity(length + 1);
        let mut carry = 0u128;
        for index in 0..length {
            let sum = lhs.get(index).copied().unwrap_or(0) as u128
                + rhs.get(index).copied().unwrap_or(0) as u128
                + carry;
            result.push(sum as u64);
            carry = sum >> 64;
        }
        if carry != 0 {
            result.push(carry as u64);
        }
        result
    }

    pub(crate) fn x86_x87_big_sub(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
        debug_assert!(Self::x86_x87_big_cmp(lhs, rhs) != Ordering::Less);
        let mut result = Vec::with_capacity(lhs.len());
        let mut borrow = false;
        for (index, lhs_word) in lhs.iter().copied().enumerate() {
            let (partial, borrow_rhs) =
                lhs_word.overflowing_sub(rhs.get(index).copied().unwrap_or(0));
            let (word, borrow_carry) = partial.overflowing_sub(u64::from(borrow));
            result.push(word);
            borrow = borrow_rhs || borrow_carry;
        }
        debug_assert!(!borrow);
        Self::x86_x87_big_trim(&mut result);
        result
    }

    pub(crate) fn x86_x87_big_bit_len(value: &[u64]) -> usize {
        value
            .last()
            .map(|word| (value.len() - 1) * 64 + (64 - word.leading_zeros() as usize))
            .unwrap_or(0)
    }

    pub(crate) fn x86_x87_big_any_below(value: &[u64], bit_count: usize) -> bool {
        if bit_count == 0 {
            return false;
        }
        let complete_words = bit_count / 64;
        if value.iter().take(complete_words).any(|word| *word != 0) {
            return true;
        }
        let remaining = bit_count % 64;
        remaining != 0
            && value
                .get(complete_words)
                .is_some_and(|word| word & ((1u64 << remaining) - 1) != 0)
    }

    pub(crate) fn x86_x87_big_bit(value: &[u64], bit: usize) -> bool {
        value
            .get(bit / 64)
            .is_some_and(|word| word & (1u64 << (bit % 64)) != 0)
    }

    pub(crate) fn x86_x87_big_shr_u64(value: &[u64], shift: usize) -> u64 {
        let word = shift / 64;
        let bit = shift % 64;
        let low = value.get(word).copied().unwrap_or(0) >> bit;
        if bit == 0 {
            low
        } else {
            low | (value.get(word + 1).copied().unwrap_or(0) << (64 - bit))
        }
    }

    pub(crate) fn x86_x87_big_round_shift(
        value: &[u64],
        shift: i32,
        rounding: u16,
        sign: bool,
    ) -> (u128, bool, bool) {
        if shift <= 0 {
            let left = (-shift) as u32;
            let unshifted = value.first().copied().unwrap_or(0) as u128;
            return (unshifted << left, false, false);
        }
        let shift = shift as usize;
        let truncated = Self::x86_x87_big_shr_u64(value, shift) as u128;
        let inexact = Self::x86_x87_big_any_below(value, shift);
        let half_cmp = if !Self::x86_x87_big_bit(value, shift - 1) {
            Ordering::Less
        } else if Self::x86_x87_big_any_below(value, shift - 1) {
            Ordering::Greater
        } else {
            Ordering::Equal
        };
        let increment = inexact
            && match rounding & 3 {
                0 => {
                    half_cmp == Ordering::Greater
                        || (half_cmp == Ordering::Equal && truncated & 1 != 0)
                }
                1 => sign,
                2 => !sign,
                3 => false,
                _ => unreachable!(),
            };
        (truncated + u128::from(increment), inexact, increment)
    }

    /// Round an unsigned integer divided by `2^shift` according to an x87 RC
    /// field. The final boolean reports an increment of the truncated
    /// magnitude, which is the x87 definition used for C1 on precision loss.
    pub(crate) fn x86_x87_round_shift(
        value: u128,
        shift: i32,
        rounding: u16,
        sign: bool,
    ) -> (u128, bool, bool) {
        if shift <= 0 {
            let left = (-shift) as u32;
            return (
                if left >= 128 {
                    u128::MAX
                } else {
                    value.checked_shl(left).unwrap_or(u128::MAX)
                },
                false,
                false,
            );
        }

        let (truncated, inexact, half_cmp) = if shift >= 128 {
            let half_bit = shift - 1;
            (
                0,
                value != 0,
                if half_bit >= 128 {
                    Ordering::Less
                } else {
                    value.cmp(&(1u128 << half_bit))
                },
            )
        } else {
            let shift = shift as u32;
            let remainder = value & ((1u128 << shift) - 1);
            (
                value >> shift,
                remainder != 0,
                remainder.cmp(&(1u128 << (shift - 1))),
            )
        };
        let increment = inexact
            && match rounding & 3 {
                0 => {
                    half_cmp == Ordering::Greater
                        || (half_cmp == Ordering::Equal && truncated & 1 != 0)
                }
                1 => sign,
                2 => !sign,
                3 => false,
                _ => unreachable!(),
            };
        (
            truncated.saturating_add(u128::from(increment)),
            inexact,
            increment,
        )
    }

    /// Narrow a supported x87 binary80 value to an IEEE interchange payload.
    /// This uses integer arithmetic exclusively, including gradual underflow,
    /// and therefore cannot inherit host floating-point rounding or exception
    /// state. `exponent_bits`/`fraction_bits` are `(8, 23)` or `(11, 52)`.
    pub(crate) fn x86_x87_to_ieee(
        raw: &[u8; 10],
        exponent_bits: u32,
        fraction_bits: u32,
        rounding: u16,
    ) -> X87FloatConversion {
        let info = Self::x86_x87_raw_info(raw);
        let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
        let exponent = exponent_sign & 0x7FFF;
        let sign_bit = (info.sign as u64) << (exponent_bits + fraction_bits);
        let exponent_mask = (1u64 << exponent_bits) - 1;
        let fraction_mask = (1u64 << fraction_bits) - 1;

        if info.unsupported {
            return X87FloatConversion {
                bits: (1u64 << (exponent_bits + fraction_bits))
                    | (exponent_mask << fraction_bits)
                    | (1u64 << (fraction_bits - 1)),
                invalid: true,
                overflow: false,
                underflow: false,
                inexact: false,
                rounded_up: false,
            };
        }
        if info.nan {
            let payload = ((significand & 0x7FFF_FFFF_FFFF_FFFF) >> (63 - fraction_bits))
                | (1u64 << (fraction_bits - 1));
            return X87FloatConversion {
                bits: sign_bit | (exponent_mask << fraction_bits) | payload,
                invalid: info.signaling_nan,
                overflow: false,
                underflow: false,
                inexact: false,
                rounded_up: false,
            };
        }
        if exponent == 0x7FFF {
            return X87FloatConversion {
                bits: sign_bit | (exponent_mask << fraction_bits),
                invalid: false,
                overflow: false,
                underflow: false,
                inexact: false,
                rounded_up: false,
            };
        }
        if info.zero {
            return X87FloatConversion {
                bits: sign_bit,
                invalid: false,
                overflow: false,
                underflow: false,
                inexact: false,
                rounded_up: false,
            };
        }

        // True and pseudo-denormals both use the minimum binary80 exponent;
        // the explicit integer bit determines their leading-value exponent.
        let effective_exponent = if exponent == 0 { 1 } else { exponent };
        let extended_unbiased = effective_exponent as i32 - 16383;
        let highest = 63 - significand.leading_zeros() as i32;
        let value_exponent = extended_unbiased - 63 + highest;
        let target_bias = (1i32 << (exponent_bits - 1)) - 1;
        let minimum_normal_exponent = 1 - target_bias;
        let maximum_normal_exponent = target_bias;
        let precision = fraction_bits + 1;

        let overflow = |rounded_up: bool| {
            let infinity = match rounding & 3 {
                0 => true,
                1 => info.sign,
                2 => !info.sign,
                3 => false,
                _ => unreachable!(),
            };
            let magnitude = if infinity {
                exponent_mask << fraction_bits
            } else {
                ((exponent_mask - 1) << fraction_bits) | fraction_mask
            };
            X87FloatConversion {
                bits: sign_bit | magnitude,
                invalid: false,
                overflow: true,
                underflow: false,
                inexact: true,
                rounded_up,
            }
        };

        if value_exponent > maximum_normal_exponent {
            return overflow(match rounding & 3 {
                0 => true,
                1 => info.sign,
                2 => !info.sign,
                3 => false,
                _ => unreachable!(),
            });
        }

        if value_exponent >= minimum_normal_exponent {
            let shift = highest + 1 - precision as i32;
            let (mut rounded, inexact, increment) =
                Self::x86_x87_round_shift(significand as u128, shift, rounding, info.sign);
            let mut result_exponent = value_exponent;
            if rounded >= 1u128 << precision {
                rounded >>= 1;
                result_exponent += 1;
            }
            if result_exponent > maximum_normal_exponent {
                let infinity = match rounding & 3 {
                    0 => true,
                    1 => info.sign,
                    2 => !info.sign,
                    3 => false,
                    _ => unreachable!(),
                };
                if infinity {
                    return overflow(increment);
                }
                return X87FloatConversion {
                    bits: sign_bit | ((exponent_mask - 1) << fraction_bits) | fraction_mask,
                    invalid: false,
                    overflow: false,
                    underflow: false,
                    inexact: true,
                    rounded_up: increment,
                };
            }
            let fraction = (rounded as u64) & fraction_mask;
            return X87FloatConversion {
                bits: sign_bit
                    | ((result_exponent + target_bias) as u64) << fraction_bits
                    | fraction,
                invalid: false,
                overflow: false,
                underflow: false,
                inexact,
                rounded_up: increment,
            };
        }

        // Subnormal payload units are 2^(emin-fraction_bits). Divide the
        // binary80 integer significand by that unit, then round once.
        let shift = 63 + minimum_normal_exponent - fraction_bits as i32 - extended_unbiased;
        let (rounded, inexact, increment) =
            Self::x86_x87_round_shift(significand as u128, shift, rounding, info.sign);
        let (encoded_exponent, fraction) = if rounded >= 1u128 << fraction_bits {
            (1u64, 0u64)
        } else {
            (0u64, rounded as u64)
        };
        X87FloatConversion {
            bits: sign_bit | (encoded_exponent << fraction_bits) | fraction,
            invalid: false,
            overflow: false,
            // Intel detects tininess before rounding for x87 narrowing stores:
            // an inexact value below the minimum normal magnitude raises UE
            // even when rounding promotes it to the minimum normal payload.
            underflow: inexact,
            inexact,
            rounded_up: increment,
        }
    }

    /// Widen an IEEE binary32/binary64 payload into x87 double-extended
    /// precision without host floating-point conversion. Returns the raw
    /// binary80 value plus source SNaN and denormal classifications. SNaNs are
    /// quieted in the returned masked-response value.
    pub(crate) fn x86_x87_widen_ieee(
        bits: u64,
        exponent_bits: u32,
        fraction_bits: u32,
    ) -> ([u8; 10], bool, bool) {
        let sign = bits >> (exponent_bits + fraction_bits) & 1;
        let exponent_mask = (1u64 << exponent_bits) - 1;
        let fraction_mask = (1u64 << fraction_bits) - 1;
        let exponent = (bits >> fraction_bits) & exponent_mask;
        let fraction = bits & fraction_mask;
        let bias = (1i32 << (exponent_bits - 1)) - 1;
        let (significand, extended_exponent, signaling_nan, denormal) = if exponent == exponent_mask
        {
            let signaling_nan = fraction != 0 && fraction & (1 << (fraction_bits - 1)) == 0;
            let mut significand = (1u64 << 63) | (fraction << (63 - fraction_bits));
            if signaling_nan {
                significand |= 1u64 << 62;
            }
            (significand, 0x7FFF, signaling_nan, false)
        } else if exponent == 0 {
            if fraction == 0 {
                (0, 0, false, false)
            } else {
                let highest = 63 - fraction.leading_zeros();
                let unbiased = 1 - bias - fraction_bits as i32 + highest as i32;
                (
                    fraction << (63 - highest),
                    (unbiased + 16383) as u16,
                    false,
                    true,
                )
            }
        } else {
            (
                ((1u64 << fraction_bits) | fraction) << (63 - fraction_bits),
                (exponent as i32 - bias + 16383) as u16,
                false,
                false,
            )
        };
        let exponent_sign = extended_exponent | ((sign as u16) << 15);
        let mut raw = [0u8; 10];
        raw[..8].copy_from_slice(&significand.to_le_bytes());
        raw[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        (raw, signaling_nan, denormal)
    }

    /// Return the architecturally rounded 80-bit encoding of an x87 load
    /// constant. Values were cross-checked byte-for-byte for all FCW.RC modes
    /// against an x86-64 execution probe. Every constant is positive, so RC=01
    /// (down) and RC=11 (truncate) select the lower neighbor, while RC=10 (up)
    /// selects the upper neighbor. FLD1 and FLDZ are exact.
    pub(crate) fn x86_x87_constant(constant: X86X87Constant, control_word: u16) -> [u8; 10] {
        let rc = (control_word >> 10) & 3;
        let (nearest, lower, upper, exponent): (u64, u64, u64, u16) = match constant {
            X86X87Constant::One => (
                0x8000_0000_0000_0000,
                0x8000_0000_0000_0000,
                0x8000_0000_0000_0000,
                0x3FFF,
            ),
            X86X87Constant::Log2Ten => (
                0xD49A_784B_CD1B_8AFE,
                0xD49A_784B_CD1B_8AFE,
                0xD49A_784B_CD1B_8AFF,
                0x4000,
            ),
            X86X87Constant::Log2E => (
                0xB8AA_3B29_5C17_F0BC,
                0xB8AA_3B29_5C17_F0BB,
                0xB8AA_3B29_5C17_F0BC,
                0x3FFF,
            ),
            X86X87Constant::Pi => (
                0xC90F_DAA2_2168_C235,
                0xC90F_DAA2_2168_C234,
                0xC90F_DAA2_2168_C235,
                0x4000,
            ),
            X86X87Constant::Log10Two => (
                0x9A20_9A84_FBCF_F799,
                0x9A20_9A84_FBCF_F798,
                0x9A20_9A84_FBCF_F799,
                0x3FFD,
            ),
            X86X87Constant::LnTwo => (
                0xB172_17F7_D1CF_79AC,
                0xB172_17F7_D1CF_79AB,
                0xB172_17F7_D1CF_79AC,
                0x3FFE,
            ),
            X86X87Constant::Zero => (0, 0, 0, 0),
        };
        let significand = match rc {
            0 => nearest,
            1 | 3 => lower,
            2 => upper,
            _ => unreachable!(),
        };
        let mut raw = [0u8; 10];
        raw[..8].copy_from_slice(&significand.to_le_bytes());
        raw[8..].copy_from_slice(&exponent.to_le_bytes());
        raw
    }

    /// The exact binary80 encoding of `value` (every binary64 value is
    /// representable).
    pub(crate) fn x86_x87_from_f64(value: f64) -> [u8; 10] {
        Self::x86_x87_widen_ieee(value.to_bits(), 11, 52).0
    }

    /// `raw` rounded to the nearest binary64 value (ties to even), as FST
    /// m64fp stores it with round-to-nearest.
    pub(crate) fn x86_x87_to_f64(raw: &[u8; 10]) -> f64 {
        f64::from_bits(Self::x86_x87_to_ieee(raw, 11, 52, 0).bits)
    }

    pub(crate) fn x86_x87_environment_len(width: X86X87EnvWidth) -> usize {
        match width {
            X86X87EnvWidth::W16 => 14,
            X86X87EnvWidth::W32 => 28,
        }
    }

    /// Construct the protected-mode legacy x87 environment image used in
    /// 64-bit mode. Legacy formats save only 16 or 32 pointer-offset bits and
    /// do not preserve the upper halves of FIP/FDP. Segment selectors are not
    /// represented by SMIR and are stored as zero (the architecturally
    /// permitted value on processors that deprecate FCS/FDS).
    pub(crate) fn x86_x87_environment_image(
        state: &crate::smir::X86X87State,
        width: X86X87EnvWidth,
    ) -> ([u8; 28], usize) {
        let mut image = [0u8; 28];
        match width {
            X86X87EnvWidth::W16 => {
                image[0..2].copy_from_slice(&state.control_word.to_le_bytes());
                image[2..4].copy_from_slice(&state.status_word.to_le_bytes());
                image[4..6].copy_from_slice(&state.tag_word.to_le_bytes());
                image[6..8].copy_from_slice(&(state.instr_ptr as u16).to_le_bytes());
                // 8:10 is FCS, which is modeled as zero.
                image[10..12].copy_from_slice(&(state.data_ptr as u16).to_le_bytes());
                // 12:14 is FDS, which is modeled as zero. The protected-mode
                // 16-bit format has no FOP field.
            }
            X86X87EnvWidth::W32 => {
                image[0..2].copy_from_slice(&state.control_word.to_le_bytes());
                image[4..6].copy_from_slice(&state.status_word.to_le_bytes());
                image[8..10].copy_from_slice(&state.tag_word.to_le_bytes());
                image[12..16].copy_from_slice(&(state.instr_ptr as u32).to_le_bytes());
                // 16:18 is FCS; FOP occupies bits 26:16 of this dword.
                image[18..20].copy_from_slice(&(state.last_opcode & 0x07FF).to_le_bytes());
                image[20..24].copy_from_slice(&(state.data_ptr as u32).to_le_bytes());
                // 24:26 is FDS and all remaining fields are reserved zero.
            }
        }
        (image, Self::x86_x87_environment_len(width))
    }

    pub(crate) fn restore_x86_x87_environment(
        state: &mut crate::smir::X86X87State,
        image: &[u8],
        width: X86X87EnvWidth,
    ) {
        match width {
            X86X87EnvWidth::W16 => {
                state.control_word = u16::from_le_bytes(image[0..2].try_into().unwrap());
                state.status_word = u16::from_le_bytes(image[2..4].try_into().unwrap());
                state.tag_word = u16::from_le_bytes(image[4..6].try_into().unwrap());
                state.instr_ptr = u16::from_le_bytes(image[6..8].try_into().unwrap()) as u64;
                state.data_ptr = u16::from_le_bytes(image[10..12].try_into().unwrap()) as u64;
                // No FOP is present in the protected-mode 16-bit image; retain
                // the current opcode register rather than inventing a source.
            }
            X86X87EnvWidth::W32 => {
                state.control_word = u16::from_le_bytes(image[0..2].try_into().unwrap());
                state.status_word = u16::from_le_bytes(image[4..6].try_into().unwrap());
                state.tag_word = u16::from_le_bytes(image[8..10].try_into().unwrap());
                state.instr_ptr = u32::from_le_bytes(image[12..16].try_into().unwrap()) as u64;
                state.last_opcode = u16::from_le_bytes(image[18..20].try_into().unwrap()) & 0x07FF;
                state.data_ptr = u32::from_le_bytes(image[20..24].try_into().unwrap()) as u64;
            }
        }
    }

    pub(crate) fn x86_x87_state_image(
        state: &crate::smir::X86X87State,
        width: X86X87EnvWidth,
    ) -> ([u8; 108], usize) {
        let (environment, environment_len) = Self::x86_x87_environment_image(state, width);
        let mut image = [0u8; 108];
        image[..environment_len].copy_from_slice(&environment[..environment_len]);
        // Unlike the full tag word, register payloads are serialized in
        // logical ST(0)..ST(7) order relative to the saved TOP.
        for logical in 0..8u8 {
            let physical = state.physical_index(logical);
            let offset = environment_len + logical as usize * 10;
            image[offset..offset + 10].copy_from_slice(&state.regs[physical]);
        }
        (image, environment_len + 80)
    }

    pub(crate) fn restore_x86_x87_state(
        state: &mut crate::smir::X86X87State,
        image: &[u8],
        width: X86X87EnvWidth,
    ) {
        let environment_len = Self::x86_x87_environment_len(width);
        Self::restore_x86_x87_environment(state, &image[..environment_len], width);
        for logical in 0..8u8 {
            let physical = state.physical_index(logical);
            let offset = environment_len + logical as usize * 10;
            state.regs[physical].copy_from_slice(&image[offset..offset + 10]);
        }
    }
}

//! Integer semantics: mathematical integers modulo 2^bits, with deferred
//! poison and immediate undefined behaviour exactly where chapter 02 puts it.
//!
//! Operands arrive already refined: an undef operand is the value zero, chosen
//! independently at each use. Widths are 1..=128 and every concrete operand is
//! below 2^bits; lowering establishes both.

use crate::ir::{Cast, IntBinary, IntFlags, IntUnary, Predicate};

/// A refined integer operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arg {
    Bits(u128),
    Poison,
}

/// A computed integer result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Computed {
    Bits(u128),
    Poison,
}

pub(crate) fn mask(bits: u32) -> u128 {
    u128::MAX >> (128 - bits)
}

pub(crate) fn signed(value: u128, bits: u32) -> i128 {
    ((value << (128 - bits)) as i128) >> (128 - bits)
}

fn signed_in_range(value: i128, bits: u32) -> bool {
    bits == 128 || (-(1_i128 << (bits - 1))..(1_i128 << (bits - 1))).contains(&value)
}

/// Evaluate a two-operand integer operation. `Err` is the code of immediate
/// undefined behaviour.
pub(crate) fn binary(
    op: IntBinary,
    bits: u32,
    flags: IntFlags,
    lhs: Arg,
    rhs: Arg,
) -> Result<Computed, &'static str> {
    let mask = mask(bits);
    if matches!(
        op,
        IntBinary::UDiv | IntBinary::SDiv | IntBinary::URem | IntBinary::SRem
    ) {
        // Division is undefined, not poison, for these divisors even when the
        // dividend is poison.
        let divisor = match rhs {
            Arg::Poison => return Err("ub_poison_divisor"),
            Arg::Bits(0) => return Err("ub_div_zero"),
            Arg::Bits(divisor) => divisor,
        };
        // A divisor of all ones is -1. Dividing the minimum value by it
        // overflows; a poison dividend may be that value.
        if matches!(op, IntBinary::SDiv | IntBinary::SRem)
            && divisor == mask
            && (lhs == Arg::Poison || lhs == Arg::Bits(1 << (bits - 1)))
        {
            return Err("ub_signed_div_overflow");
        }
    }
    let (Arg::Bits(a), Arg::Bits(b)) = (lhs, rhs) else {
        return Ok(Computed::Poison);
    };
    let (sa, sb) = (signed(a, bits), signed(b, bits));
    let (result, unsigned_overflow, signed_overflow) = match op {
        IntBinary::Add => {
            let (result, carried) = a.overflowing_add(b);
            let fits = sa
                .checked_add(sb)
                .is_some_and(|sum| signed_in_range(sum, bits));
            (result, carried || result > mask, !fits)
        }
        IntBinary::Sub => {
            let fits = sa
                .checked_sub(sb)
                .is_some_and(|difference| signed_in_range(difference, bits));
            (a.wrapping_sub(b), a < b, !fits)
        }
        IntBinary::Mul => {
            // A product that overflows 128 bits still has the right low bits,
            // because 2^bits divides 2^128.
            let (result, carried) = a.overflowing_mul(b);
            let fits = sa
                .checked_mul(sb)
                .is_some_and(|product| signed_in_range(product, bits));
            (result, carried || result > mask, !fits)
        }
        IntBinary::Shl | IntBinary::LShr | IntBinary::AShr => {
            if b >= u128::from(bits) {
                return Ok(Computed::Poison);
            }
            let shift = b as u32;
            if op == IntBinary::Shl {
                let truncated = (a << shift) & mask;
                // Shifting back arithmetically recovers the operand exactly
                // when no significant bit was lost.
                (
                    truncated,
                    a > (mask >> shift),
                    (signed(truncated, bits) >> shift) != sa,
                )
            } else {
                let discarded = a & ((1_u128 << shift) - 1);
                if flags.exact && discarded != 0 {
                    return Ok(Computed::Poison);
                }
                let result = if op == IntBinary::LShr {
                    a >> shift
                } else {
                    (sa >> shift) as u128
                };
                (result, false, false)
            }
        }
        IntBinary::UDiv | IntBinary::URem => {
            if flags.exact && a % b != 0 {
                return Ok(Computed::Poison);
            }
            (
                if op == IntBinary::UDiv { a / b } else { a % b },
                false,
                false,
            )
        }
        IntBinary::SDiv | IntBinary::SRem => {
            // Zero and MIN / -1 were rejected above, so neither host operation
            // can overflow. Both truncate toward zero.
            if flags.exact && sa % sb != 0 {
                return Ok(Computed::Poison);
            }
            (
                (if op == IntBinary::SDiv {
                    sa / sb
                } else {
                    sa % sb
                }) as u128,
                false,
                false,
            )
        }
        IntBinary::And => (a & b, false, false),
        IntBinary::Or => (a | b, false, false),
        IntBinary::Xor => (a ^ b, false, false),
        IntBinary::RotL | IntBinary::RotR => {
            let amount = (b % u128::from(bits)) as u32;
            let left = if op == IntBinary::RotL {
                amount
            } else {
                (bits - amount) % bits
            };
            let right = (bits - left) % bits;
            // `left` and `right` are both below `bits`, hence below 128.
            ((a << left) | (a >> right), false, false)
        }
    };
    if (flags.nuw && unsigned_overflow) || (flags.nsw && signed_overflow) {
        Ok(Computed::Poison)
    } else {
        Ok(Computed::Bits(result & mask))
    }
}

pub(crate) fn unary(op: IntUnary, bits: u32, zero_is_poison: bool, operand: Arg) -> Computed {
    let Arg::Bits(a) = operand else {
        return Computed::Poison;
    };
    Computed::Bits(match op {
        IntUnary::Clz | IntUnary::Ctz if a == 0 && zero_is_poison => return Computed::Poison,
        IntUnary::Clz => u128::from(a.leading_zeros() - (128 - bits)),
        IntUnary::Ctz => u128::from(if a == 0 { bits } else { a.trailing_zeros() }),
        IntUnary::Popcount => u128::from(a.count_ones()),
        // For abs the flag means "the minimum signed value is poison".
        IntUnary::Abs if a == 1 << (bits - 1) && zero_is_poison => return Computed::Poison,
        IntUnary::Abs => signed(a, bits).unsigned_abs() & mask(bits),
        IntUnary::Bswap => a.swap_bytes() >> (128 - bits),
        IntUnary::BitReverse => a.reverse_bits() >> (128 - bits),
    })
}

pub(crate) fn compare(pred: Predicate, bits: u32, lhs: Arg, rhs: Arg) -> Computed {
    let (Arg::Bits(a), Arg::Bits(b)) = (lhs, rhs) else {
        return Computed::Poison;
    };
    let (sa, sb) = (signed(a, bits), signed(b, bits));
    Computed::Bits(u128::from(match pred {
        Predicate::Eq => a == b,
        Predicate::Ne => a != b,
        Predicate::Ult => a < b,
        Predicate::Ule => a <= b,
        Predicate::Ugt => a > b,
        Predicate::Uge => a >= b,
        Predicate::Slt => sa < sb,
        Predicate::Sle => sa <= sb,
        Predicate::Sgt => sa > sb,
        Predicate::Sge => sa >= sb,
    }))
}

pub(crate) fn cast(op: Cast, from_bits: u32, to_bits: u32, operand: Arg) -> Computed {
    let Arg::Bits(a) = operand else {
        return Computed::Poison;
    };
    Computed::Bits(match op {
        Cast::Trunc => a & mask(to_bits),
        Cast::Zext => a,
        Cast::Sext => (signed(a, from_bits) as u128) & mask(to_bits),
    })
}

#[cfg(test)]
#[path = "int_tests.rs"]
mod tests;

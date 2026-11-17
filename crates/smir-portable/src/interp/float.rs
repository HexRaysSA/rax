//! Floating-point operations in the default environment.
//!
//! A float value is its interchange bit pattern. Every operation here rounds
//! to nearest, ties to even, and raises nothing: that is the default
//! environment, the only one the engine executes so far.
//!
//! binary128 values are carried, stored and passed like the others, and the
//! operations that act on the bits alone (negation, absolute value, sign
//! copy) apply to them. Their arithmetic is not implemented; lowering
//! refuses a module that needs it.
//!
//! Finite arithmetic uses the host's `f32` and `f64`, whose addition,
//! subtraction, multiplication, division, remainder, square root and fused
//! multiply-add are correctly rounded and therefore the same on every host.
//! What hosts disagree on is which NaN an operation produces, so every NaN
//! result is chosen here from the bit patterns, by the execution chapter's
//! rule: the first NaN operand with its quiet bit set, or the positive quiet
//! NaN with an empty payload when no operand is a NaN.

use crate::ir::{FloatFormat, FloatOp, FloatRelation};

use super::int::{Computed, mask};

/// The formats whose arithmetic the host performs.
#[derive(Clone, Copy)]
enum Native {
    Single,
    Double,
}

impl FloatFormat {
    /// Bits of the fraction field.
    fn fraction_bits(self) -> u32 {
        match self {
            Self::Binary32 => 23,
            Self::Binary64 => 52,
            Self::Binary128 => 112,
        }
    }

    fn native(self) -> Option<Native> {
        match self {
            Self::Binary32 => Some(Native::Single),
            Self::Binary64 => Some(Native::Double),
            Self::Binary128 => None,
        }
    }

    fn sign_bit(self) -> u128 {
        1 << (self.bits() - 1)
    }

    fn fraction_mask(self) -> u128 {
        (1 << self.fraction_bits()) - 1
    }

    /// The exponent field of infinities and NaNs, in place.
    fn exponent_mask(self) -> u128 {
        mask(self.bits()) & !self.sign_bit() & !self.fraction_mask()
    }

    fn quiet_bit(self) -> u128 {
        1 << (self.fraction_bits() - 1)
    }

    fn is_nan(self, bits: u128) -> bool {
        bits & self.exponent_mask() == self.exponent_mask() && bits & self.fraction_mask() != 0
    }

    fn is_infinite(self, bits: u128) -> bool {
        bits & !self.sign_bit() == self.exponent_mask()
    }

    fn is_zero(self, bits: u128) -> bool {
        bits & !self.sign_bit() == 0
    }

    fn is_negative(self, bits: u128) -> bool {
        bits & self.sign_bit() != 0
    }

    /// The NaN an invalid operation on numbers produces.
    fn preferred_nan(self) -> u128 {
        self.exponent_mask() | self.quiet_bit()
    }

    /// A finite value as `sign`, `significand` and `exponent`, where the
    /// magnitude is exactly `significand * 2^exponent`.
    fn decompose(self, bits: u128) -> (bool, u128, i32) {
        let fraction = bits & self.fraction_mask();
        let exponent = ((bits & self.exponent_mask()) >> self.fraction_bits()) as i32;
        let bias = (1 << (self.bits() - self.fraction_bits() - 2)) - 1;
        let offset = bias + self.fraction_bits() as i32;
        if exponent == 0 {
            // Subnormals share the smallest normal exponent.
            (self.is_negative(bits), fraction, 1 - offset)
        } else {
            (
                self.is_negative(bits),
                fraction | (1 << self.fraction_bits()),
                exponent - offset,
            )
        }
    }
}

impl Native {
    /// The value as a host `f64`, which holds every value of both formats.
    fn widen(self, bits: u128) -> f64 {
        match self {
            Self::Single => f64::from(f32::from_bits(bits as u32)),
            Self::Double => f64::from_bits(bits as u64),
        }
    }
}

/// The first NaN among `operands`, quieted.
fn first_nan(format: FloatFormat, operands: &[u128]) -> Option<u128> {
    operands
        .iter()
        .find(|bits| format.is_nan(**bits))
        .map(|bits| bits | format.quiet_bit())
}

/// Apply a host operation to non-NaN operands. A NaN it returns came from an
/// invalid operation on numbers.
fn arithmetic(
    format: FloatFormat,
    native: Native,
    operands: &[u128],
    single: impl Fn(&[f32]) -> f32,
    double: impl Fn(&[f64]) -> f64,
) -> u128 {
    if let Some(nan) = first_nan(format, operands) {
        return nan;
    }
    let result = match native {
        Native::Single => {
            let values: Vec<f32> = operands
                .iter()
                .map(|bits| f32::from_bits(*bits as u32))
                .collect();
            let result = single(&values);
            (!result.is_nan()).then(|| u128::from(result.to_bits()))
        }
        Native::Double => {
            let values: Vec<f64> = operands
                .iter()
                .map(|bits| f64::from_bits(*bits as u64))
                .collect();
            let result = double(&values);
            (!result.is_nan()).then(|| u128::from(result.to_bits()))
        }
    };
    result.unwrap_or_else(|| format.preferred_nan())
}

/// The six minimum and maximum operations. `propagate` returns a NaN when
/// either operand is one; otherwise a single NaN operand yields the other.
fn extremum(
    format: FloatFormat,
    native: Native,
    a: u128,
    b: u128,
    maximum: bool,
    propagate: bool,
) -> u128 {
    let (a_nan, b_nan) = (format.is_nan(a), format.is_nan(b));
    if a_nan || b_nan {
        if propagate || (a_nan && b_nan) {
            return (if a_nan { a } else { b }) | format.quiet_bit();
        }
        return if a_nan { b } else { a };
    }
    if format.is_zero(a) && format.is_zero(b) {
        // Negative zero orders below positive zero.
        return if maximum { a & b } else { a | b };
    }
    let (x, y) = (native.widen(a), native.widen(b));
    let take_a = if maximum { x >= y } else { x <= y };
    if take_a { a } else { b }
}

fn compare(
    format: FloatFormat,
    native: Native,
    relation: FloatRelation,
    unordered: bool,
    a: u128,
    b: u128,
) -> bool {
    let is_unordered = format.is_nan(a) || format.is_nan(b);
    let (x, y) = (native.widen(a), native.widen(b));
    let holds = match relation {
        FloatRelation::False => return false,
        FloatRelation::True => return true,
        FloatRelation::Ordered => return !is_unordered,
        FloatRelation::Unordered => return is_unordered,
        // Host comparisons are false when either side is a NaN, except `!=`.
        FloatRelation::Equal => x == y,
        FloatRelation::NotEqual => !is_unordered && x != y,
        FloatRelation::Less => x < y,
        FloatRelation::LessEqual => x <= y,
        FloatRelation::Greater => x > y,
        FloatRelation::GreaterEqual => x >= y,
    };
    holds || (unordered && is_unordered)
}

/// Truncate toward zero to an integer of `bits` bits. A NaN, and a value
/// whose truncation does not fit, is poison; a saturating conversion instead
/// maps a NaN to zero and clamps to the nearest representable integer.
fn to_integer(
    format: FloatFormat,
    value: u128,
    bits: u32,
    signed: bool,
    saturating: bool,
) -> Computed {
    // The largest magnitudes of a non-negative and of a negative result.
    let (above, below) = if signed {
        (mask(bits) >> 1, (mask(bits) >> 1) + 1)
    } else {
        (mask(bits), 0)
    };
    let negated = |magnitude: u128| Computed::Bits(magnitude.wrapping_neg() & mask(bits));
    let clamp = |negative: bool| match (saturating, negative) {
        (false, _) => Computed::Poison,
        (true, true) => negated(below),
        (true, false) => Computed::Bits(above),
    };
    if format.is_nan(value) {
        return if saturating {
            Computed::Bits(0)
        } else {
            Computed::Poison
        };
    }
    let negative = format.is_negative(value);
    if format.is_infinite(value) {
        return clamp(negative);
    }
    let (_, significand, exponent) = format.decompose(value);
    // The magnitude truncated to an integer, if it fits 128 bits.
    let magnitude = if exponent >= 0 {
        significand
            .checked_shl(exponent as u32)
            .filter(|shifted| shifted >> exponent == significand)
    } else {
        Some(
            significand
                .checked_shr(exponent.unsigned_abs())
                .unwrap_or(0),
        )
    };
    match magnitude {
        Some(magnitude) if negative && magnitude <= below => negated(magnitude),
        Some(magnitude) if !negative && magnitude <= above => Computed::Bits(magnitude),
        _ => clamp(negative),
    }
}

/// Convert between formats. A NaN keeps its sign and the leading bits of its
/// payload, and becomes quiet.
fn convert(from: FloatFormat, to: FloatFormat, value: u128) -> Option<u128> {
    // The numbers convert through the host's formats.
    let (source, target) = (from.native()?, to.native()?);
    if from.is_nan(value) {
        let payload = value & (from.quiet_bit() - 1);
        let (source, target) = (from.fraction_bits(), to.fraction_bits());
        let payload = if source >= target {
            payload >> (source - target)
        } else {
            payload << (target - source)
        };
        let sign = if from.is_negative(value) {
            to.sign_bit()
        } else {
            0
        };
        return Some(sign | to.exponent_mask() | to.quiet_bit() | payload);
    }
    Some(match (source, target) {
        (Native::Single, Native::Double) => {
            u128::from(f64::from(f32::from_bits(value as u32)).to_bits())
        }
        // Rounds to nearest, ties to even.
        (Native::Double, Native::Single) => {
            u128::from((f64::from_bits(value as u64) as f32).to_bits())
        }
        (Native::Single, Native::Single) | (Native::Double, Native::Double) => value,
    })
}

/// An integer of `bits` bits, rounded to nearest with ties to even.
fn from_integer(native: Native, value: u128, bits: u32, signed: bool) -> u128 {
    let negative = signed && (value >> (bits - 1)) & 1 == 1;
    // Sign-extend to the full width of the host integer.
    let wide = if negative { value | !mask(bits) } else { value };
    match (native, signed) {
        (Native::Single, true) => u128::from((wide as i128 as f32).to_bits()),
        (Native::Single, false) => u128::from((wide as f32).to_bits()),
        (Native::Double, true) => u128::from((wide as i128 as f64).to_bits()),
        (Native::Double, false) => u128::from((wide as f64).to_bits()),
    }
}

/// Evaluate `op` on defined operands. `format` is the format of the float
/// operands, or of the result when the operands are integers. `None` if the
/// number of operands is not the operation's, or the operation is arithmetic
/// in a format the host does not compute; lowering rules out both.
pub(super) fn evaluate(op: FloatOp, format: FloatFormat, operands: &[u128]) -> Option<Computed> {
    let bits = match (op, operands) {
        // These three act on the bits and do not quiet a NaN.
        (FloatOp::Neg, [a]) => a ^ format.sign_bit(),
        (FloatOp::Abs, [a]) => a & !format.sign_bit(),
        (FloatOp::CopySign, [a, b]) => (a & !format.sign_bit()) | (b & format.sign_bit()),
        // Truncation is exact in every format.
        (FloatOp::ToSigned { bits, saturating }, [a]) => {
            return Some(to_integer(format, *a, bits, true, saturating));
        }
        (FloatOp::ToUnsigned { bits, saturating }, [a]) => {
            return Some(to_integer(format, *a, bits, false, saturating));
        }
        (FloatOp::Convert { to }, [a]) => convert(format, to, *a)?,
        _ => {
            let native = format.native()?;
            let apply = |single: fn(&[f32]) -> f32, double: fn(&[f64]) -> f64| {
                arithmetic(format, native, operands, single, double)
            };
            let extreme = |a: &u128, b: &u128, maximum, propagate| {
                extremum(format, native, *a, *b, maximum, propagate)
            };
            match (op, operands) {
                (FloatOp::Add, [_, _]) => apply(|v| v[0] + v[1], |v| v[0] + v[1]),
                (FloatOp::Sub, [_, _]) => apply(|v| v[0] - v[1], |v| v[0] - v[1]),
                (FloatOp::Mul, [_, _]) => apply(|v| v[0] * v[1], |v| v[0] * v[1]),
                (FloatOp::Div, [_, _]) => apply(|v| v[0] / v[1], |v| v[0] / v[1]),
                // The remainder of truncating division, with the dividend's sign.
                (FloatOp::Rem, [_, _]) => apply(|v| v[0] % v[1], |v| v[0] % v[1]),
                (FloatOp::Fma, [_, _, _]) => {
                    apply(|v| v[0].mul_add(v[1], v[2]), |v| v[0].mul_add(v[1], v[2]))
                }
                (FloatOp::Sqrt, [_]) => apply(|v| v[0].sqrt(), |v| v[0].sqrt()),
                (FloatOp::Minimum, [a, b]) => extreme(a, b, false, true),
                (FloatOp::Maximum, [a, b]) => extreme(a, b, true, true),
                (FloatOp::MinNum | FloatOp::MinimumNum, [a, b]) => extreme(a, b, false, false),
                (FloatOp::MaxNum | FloatOp::MaximumNum, [a, b]) => extreme(a, b, true, false),
                (
                    FloatOp::Compare {
                        relation,
                        unordered,
                    },
                    [a, b],
                ) => u128::from(compare(format, native, relation, unordered, *a, *b)),
                (FloatOp::FromSigned { bits }, [a]) => from_integer(native, *a, bits, true),
                (FloatOp::FromUnsigned { bits }, [a]) => from_integer(native, *a, bits, false),
                _ => return None,
            }
        }
    };
    Some(Computed::Bits(bits))
}

#[cfg(test)]
#[path = "float_tests.rs"]
mod tests;

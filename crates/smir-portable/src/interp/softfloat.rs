//! Exact binary floating point in software, for the formats the host has no
//! arithmetic for.
//!
//! Every operation computes its result exactly, as an integer significand and
//! a power of two with a sticky bit for an inexact quotient or root, and
//! rounds once to nearest with ties to even. The integers are as long as
//! they need to be; speed is not a concern here, since only binary128 goes
//! this way and compiled code rarely computes in it.
//!
//! The functions take any format, so the unit tests run them in binary32 and
//! binary64 against the host's arithmetic.

use std::cmp::Ordering;

use crate::ir::{FloatFormat, FloatOp, FloatRelation};

use super::int::mask;

/// An unsigned integer of any length, least significant limb first, with no
/// zero limbs at the top.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Natural(Vec<u64>);

impl Natural {
    fn zero() -> Self {
        Self(Vec::new())
    }

    fn from_u128(value: u128) -> Self {
        Self(vec![value as u64, (value >> 64) as u64]).trimmed()
    }

    fn trimmed(mut self) -> Self {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        self
    }

    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of bits up to and including the highest set bit.
    fn bits(&self) -> u64 {
        self.0.last().map_or(0, |top| {
            64 * self.0.len() as u64 - u64::from(top.leading_zeros())
        })
    }

    fn bit(&self, index: u64) -> bool {
        self.0
            .get((index / 64) as usize)
            .is_some_and(|limb| limb >> (index % 64) & 1 == 1)
    }

    /// Whether any bit below `index` is set.
    fn any_below(&self, index: u64) -> bool {
        let whole = (index / 64) as usize;
        self.0.iter().take(whole).any(|limb| *limb != 0)
            || self
                .0
                .get(whole)
                .is_some_and(|limb| limb & ((1 << (index % 64)) - 1) != 0)
    }

    fn shl(&self, count: u64) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let (limbs, bits) = ((count / 64) as usize, count % 64);
        let mut out = vec![0; limbs];
        let mut carry = 0;
        for limb in &self.0 {
            out.push(limb << bits | carry);
            carry = if bits == 0 { 0 } else { limb >> (64 - bits) };
        }
        out.push(carry);
        Self(out).trimmed()
    }

    fn shr(&self, count: u64) -> Self {
        let (limbs, bits) = ((count / 64) as usize, count % 64);
        let mut out = Vec::new();
        for (index, limb) in self.0.iter().enumerate().skip(limbs) {
            let above = self.0.get(index + 1).copied().unwrap_or(0);
            out.push(if bits == 0 {
                *limb
            } else {
                limb >> bits | above << (64 - bits)
            });
        }
        Self(out).trimmed()
    }

    fn add(&self, other: &Self) -> Self {
        let mut out = Vec::new();
        let mut carry = false;
        for index in 0..self.0.len().max(other.0.len()) {
            let a = self.0.get(index).copied().unwrap_or(0);
            let b = other.0.get(index).copied().unwrap_or(0);
            let (sum, first) = a.overflowing_add(b);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            out.push(sum);
            carry = first || second;
        }
        out.push(u64::from(carry));
        Self(out).trimmed()
    }

    /// `self - other`, which must not be negative.
    fn sub(&self, other: &Self) -> Self {
        let mut out = Vec::new();
        let mut borrow = false;
        for (index, a) in self.0.iter().enumerate() {
            let b = other.0.get(index).copied().unwrap_or(0);
            let (difference, first) = a.overflowing_sub(b);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            out.push(difference);
            borrow = first || second;
        }
        Self(out).trimmed()
    }

    fn mul(&self, other: &Self) -> Self {
        let mut out = vec![0_u64; self.0.len() + other.0.len() + 1];
        for (i, a) in self.0.iter().enumerate() {
            let mut carry = 0_u128;
            for (j, b) in other.0.iter().enumerate() {
                let total = u128::from(*a) * u128::from(*b) + u128::from(out[i + j]) + carry;
                out[i + j] = total as u64;
                carry = total >> 64;
            }
            out[i + other.0.len()] = carry as u64;
        }
        Self(out).trimmed()
    }

    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }

    /// Quotient and remainder by a nonzero divisor, one bit at a time.
    fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        let mut quotient = vec![0_u64; self.0.len()];
        let mut remainder = Self::zero();
        for index in (0..self.bits()).rev() {
            remainder = remainder.shl(1);
            if self.bit(index) {
                remainder = remainder.add(&Self::from_u128(1));
            }
            if remainder.cmp(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                quotient[(index / 64) as usize] |= 1 << (index % 64);
            }
        }
        (Self(quotient).trimmed(), remainder)
    }

    /// The integer square root and whether it is exact.
    fn sqrt(&self) -> (Self, bool) {
        let mut root = Self::zero();
        // Decide the result's bits from the top: keep a bit if the square of
        // the candidate does not exceed the value.
        for index in (0..self.bits().div_ceil(2)).rev() {
            let candidate = root.add(&Self::from_u128(1).shl(index));
            if candidate.mul(&candidate).cmp(self) != Ordering::Greater {
                root = candidate;
            }
        }
        let exact = root.mul(&root) == *self;
        (root, exact)
    }

    /// The low 128 bits.
    fn low(&self) -> u128 {
        u128::from(self.0.first().copied().unwrap_or(0))
            | u128::from(self.0.get(1).copied().unwrap_or(0)) << 64
    }
}

/// The layout of a format: the widths of its exponent and fraction fields.
#[derive(Clone, Copy)]
struct Layout {
    exponent_bits: u32,
    fraction_bits: u32,
}

impl Layout {
    fn of(format: FloatFormat) -> Self {
        let (exponent_bits, fraction_bits) = match format {
            FloatFormat::Binary32 => (8, 23),
            FloatFormat::Binary64 => (11, 52),
            FloatFormat::Binary128 => (15, 112),
        };
        Self {
            exponent_bits,
            fraction_bits,
        }
    }

    fn bits(self) -> u32 {
        1 + self.exponent_bits + self.fraction_bits
    }

    fn bias(self) -> i64 {
        (1 << (self.exponent_bits - 1)) - 1
    }

    fn sign_bit(self) -> u128 {
        1 << (self.bits() - 1)
    }

    fn exponent_mask(self) -> u128 {
        ((1 << self.exponent_bits) - 1) << self.fraction_bits
    }

    fn fraction_mask(self) -> u128 {
        (1 << self.fraction_bits) - 1
    }

    fn quiet_bit(self) -> u128 {
        1 << (self.fraction_bits - 1)
    }

    fn infinity(self, negative: bool) -> u128 {
        self.exponent_mask() | if negative { self.sign_bit() } else { 0 }
    }

    fn zero(self, negative: bool) -> u128 {
        if negative { self.sign_bit() } else { 0 }
    }

    /// The NaN an invalid operation on numbers produces.
    fn preferred_nan(self) -> u128 {
        self.exponent_mask() | self.quiet_bit()
    }

    fn unpack(self, bits: u128) -> Unpacked {
        let negative = bits & self.sign_bit() != 0;
        let exponent = ((bits & self.exponent_mask()) >> self.fraction_bits) as i64;
        let fraction = bits & self.fraction_mask();
        let scale = self.bias() + i64::from(self.fraction_bits);
        if exponent == (1 << self.exponent_bits) - 1 {
            if fraction == 0 {
                Unpacked::Infinite { negative }
            } else {
                Unpacked::Nan
            }
        } else if exponent == 0 {
            // Zero and the subnormals share the smallest exponent.
            Unpacked::Finite(Number {
                negative,
                significand: Natural::from_u128(fraction),
                exponent: 1 - scale,
            })
        } else {
            Unpacked::Finite(Number {
                negative,
                significand: Natural::from_u128(fraction | 1 << self.fraction_bits),
                exponent: exponent - scale,
            })
        }
    }

    /// Round `significand * 2^exponent` to the format: to nearest, ties to
    /// even. `sticky` says the true value is slightly above that product.
    fn round(self, negative: bool, significand: &Natural, exponent: i64, sticky: bool) -> u128 {
        if significand.is_zero() && !sticky {
            return self.zero(negative);
        }
        let precision = i64::from(self.fraction_bits);
        let smallest = 1 - self.bias();
        // The exponent of the leading bit, and of the last bit that is kept.
        let leading = exponent + significand.bits() as i64 - 1;
        let mut quantum = leading.max(smallest) - precision;
        let shift = quantum - exponent;
        let (mut kept, round_up) = if shift <= 0 {
            (significand.shl(shift.unsigned_abs()), false)
        } else {
            let shift = shift as u64;
            let half = significand.bit(shift - 1);
            let below = sticky || significand.any_below(shift - 1);
            let kept = significand.shr(shift);
            let odd = kept.bit(0);
            (kept, half && (below || odd))
        };
        if round_up {
            kept = kept.add(&Natural::from_u128(1));
            if kept.bits() as i64 > precision + 1 {
                kept = kept.shr(1);
                quantum += 1;
            }
        }
        let fraction = kept.low();
        if fraction >> self.fraction_bits == 0 {
            // No leading bit: zero or a subnormal, whose exponent field is 0.
            return fraction | self.zero(negative);
        }
        let field = quantum + precision + self.bias();
        if field >= (1 << self.exponent_bits) - 1 {
            return self.infinity(negative);
        }
        (field as u128) << self.fraction_bits
            | fraction & self.fraction_mask()
            | self.zero(negative)
    }
}

/// A finite value: `significand * 2^exponent`, with its sign kept apart so
/// that a zero has one.
#[derive(Clone)]
struct Number {
    negative: bool,
    significand: Natural,
    exponent: i64,
}

enum Unpacked {
    Nan,
    Infinite { negative: bool },
    Finite(Number),
}

impl Number {
    fn is_zero(&self) -> bool {
        self.significand.is_zero()
    }

    /// The two significands over a common exponent, which is returned.
    fn aligned(&self, other: &Self) -> (Natural, Natural, i64) {
        let exponent = self.exponent.min(other.exponent);
        (
            self.significand.shl((self.exponent - exponent) as u64),
            other.significand.shl((other.exponent - exponent) as u64),
            exponent,
        )
    }

    /// The order of the magnitudes.
    fn compare_magnitude(&self, other: &Self) -> Ordering {
        let (a, b, _) = self.aligned(other);
        a.cmp(&b)
    }
}

/// The exact sum of two finite values, rounded.
fn add(layout: Layout, a: &Number, b: &Number) -> u128 {
    let (x, y, exponent) = a.aligned(b);
    if a.negative == b.negative {
        return layout.round(a.negative, &x.add(&y), exponent, false);
    }
    match x.cmp(&y) {
        // An exact zero from opposite signs is positive.
        Ordering::Equal => layout.zero(false),
        Ordering::Greater => layout.round(a.negative, &x.sub(&y), exponent, false),
        Ordering::Less => layout.round(b.negative, &y.sub(&x), exponent, false),
    }
}

fn negated(mut number: Number) -> Number {
    number.negative = !number.negative;
    number
}

/// The first NaN among `operands`, quieted.
fn first_nan(layout: Layout, operands: &[u128]) -> Option<u128> {
    operands
        .iter()
        .find(|bits| matches!(layout.unpack(**bits), Unpacked::Nan))
        .map(|bits| bits | layout.quiet_bit())
}

fn binary(layout: Layout, op: FloatOp, left: u128, right: u128) -> u128 {
    if let Some(nan) = first_nan(layout, &[left, right]) {
        return nan;
    }
    let invalid = layout.preferred_nan();
    match (op, layout.unpack(left), layout.unpack(right)) {
        (FloatOp::Add | FloatOp::Sub, a, b) => {
            // A difference is the sum with the second operand negated.
            let flip = op == FloatOp::Sub;
            match (a, b) {
                (Unpacked::Infinite { negative: x }, Unpacked::Infinite { negative: y }) => {
                    if x == (y != flip) {
                        layout.infinity(x)
                    } else {
                        invalid
                    }
                }
                (Unpacked::Infinite { negative }, _) => layout.infinity(negative),
                (_, Unpacked::Infinite { negative }) => layout.infinity(negative != flip),
                (Unpacked::Finite(a), Unpacked::Finite(b)) => {
                    let b = if flip { negated(b) } else { b };
                    // Two zeros keep a sign they share.
                    if a.is_zero() && b.is_zero() {
                        layout.zero(a.negative && b.negative)
                    } else {
                        add(layout, &a, &b)
                    }
                }
                _ => invalid,
            }
        }
        (FloatOp::Mul, a, b) => match (a, b) {
            (Unpacked::Finite(a), Unpacked::Finite(b)) => layout.round(
                a.negative != b.negative,
                &a.significand.mul(&b.significand),
                a.exponent + b.exponent,
                false,
            ),
            (Unpacked::Infinite { negative }, Unpacked::Finite(other))
            | (Unpacked::Finite(other), Unpacked::Infinite { negative }) => {
                if other.is_zero() {
                    invalid
                } else {
                    layout.infinity(negative != other.negative)
                }
            }
            (Unpacked::Infinite { negative: x }, Unpacked::Infinite { negative: y }) => {
                layout.infinity(x != y)
            }
            _ => invalid,
        },
        (FloatOp::Div, a, b) => match (a, b) {
            (Unpacked::Finite(a), Unpacked::Finite(b)) => {
                let negative = a.negative != b.negative;
                match (a.is_zero(), b.is_zero()) {
                    (true, true) => invalid,
                    (true, false) => layout.zero(negative),
                    (false, true) => layout.infinity(negative),
                    (false, false) => {
                        // Enough quotient bits for the format and a guard,
                        // however the significands compare.
                        let extra = u64::from(layout.fraction_bits) + 3 + b.significand.bits();
                        let (quotient, remainder) =
                            a.significand.shl(extra).div_rem(&b.significand);
                        layout.round(
                            negative,
                            &quotient,
                            a.exponent - b.exponent - extra as i64,
                            !remainder.is_zero(),
                        )
                    }
                }
            }
            (Unpacked::Infinite { negative }, Unpacked::Finite(other)) => {
                layout.infinity(negative != other.negative)
            }
            (Unpacked::Finite(other), Unpacked::Infinite { negative }) => {
                layout.zero(negative != other.negative)
            }
            _ => invalid,
        },
        // The remainder of truncating division: exact, with the sign of the
        // dividend.
        (FloatOp::Rem, a, b) => match (a, b) {
            (Unpacked::Finite(a), Unpacked::Finite(b)) => {
                if b.is_zero() {
                    invalid
                } else {
                    let (x, y, exponent) = a.aligned(&b);
                    layout.round(a.negative, &x.div_rem(&y).1, exponent, false)
                }
            }
            (Unpacked::Finite(_), Unpacked::Infinite { .. }) => left,
            _ => invalid,
        },
        _ => invalid,
    }
}

fn sqrt(layout: Layout, value: u128) -> u128 {
    if let Some(nan) = first_nan(layout, &[value]) {
        return nan;
    }
    match layout.unpack(value) {
        Unpacked::Finite(number) if number.is_zero() => value,
        Unpacked::Finite(Number {
            negative: false,
            significand,
            exponent,
        }) => {
            // An even exponent, and twice the bits the result needs.
            let extra = 2 * (u64::from(layout.fraction_bits) + 3) + exponent.rem_euclid(2) as u64;
            let scaled = significand.shl(extra);
            let (root, exact) = scaled.sqrt();
            layout.round(false, &root, (exponent - extra as i64) / 2, !exact)
        }
        Unpacked::Infinite { negative: false } => value,
        _ => layout.preferred_nan(),
    }
}

fn fused(layout: Layout, a: u128, b: u128, c: u128) -> u128 {
    if let Some(nan) = first_nan(layout, &[a, b, c]) {
        return nan;
    }
    let invalid = layout.preferred_nan();
    let product = match (layout.unpack(a), layout.unpack(b)) {
        (Unpacked::Finite(a), Unpacked::Finite(b)) => Unpacked::Finite(Number {
            negative: a.negative != b.negative,
            significand: a.significand.mul(&b.significand),
            exponent: a.exponent + b.exponent,
        }),
        (Unpacked::Infinite { negative }, Unpacked::Finite(other))
        | (Unpacked::Finite(other), Unpacked::Infinite { negative }) => {
            if other.is_zero() {
                return invalid;
            }
            Unpacked::Infinite {
                negative: negative != other.negative,
            }
        }
        (Unpacked::Infinite { negative: x }, Unpacked::Infinite { negative: y }) => {
            Unpacked::Infinite { negative: x != y }
        }
        _ => return invalid,
    };
    match (product, layout.unpack(c)) {
        (Unpacked::Infinite { negative: x }, Unpacked::Infinite { negative: y }) => {
            if x == y {
                layout.infinity(x)
            } else {
                invalid
            }
        }
        (Unpacked::Infinite { negative }, _) | (_, Unpacked::Infinite { negative }) => {
            layout.infinity(negative)
        }
        (Unpacked::Finite(product), Unpacked::Finite(addend)) => {
            if product.is_zero() && addend.is_zero() {
                layout.zero(product.negative && addend.negative)
            } else {
                add(layout, &product, &addend)
            }
        }
        _ => invalid,
    }
}

/// The order of two values that are not NaNs; the two zeros are equal.
fn order(layout: Layout, a: u128, b: u128) -> Ordering {
    let rank = |value: Unpacked| match value {
        Unpacked::Infinite { negative } => (if negative { -1 } else { 1 }, None),
        Unpacked::Finite(number) => (0, Some(number)),
        Unpacked::Nan => (0, None),
    };
    let ((x, a), (y, b)) = (rank(layout.unpack(a)), rank(layout.unpack(b)));
    x.cmp(&y).then_with(|| match (a, b) {
        (Some(a), Some(b)) => match (a.is_zero(), b.is_zero()) {
            (true, true) => Ordering::Equal,
            _ if a.negative != b.negative => {
                if a.negative {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            _ if a.negative => b.compare_magnitude(&a),
            _ => a.compare_magnitude(&b),
        },
        _ => Ordering::Equal,
    })
}

fn extremum(layout: Layout, a: u128, b: u128, maximum: bool, propagate: bool) -> u128 {
    let nan = |bits| matches!(layout.unpack(bits), Unpacked::Nan);
    if nan(a) || nan(b) {
        if propagate || (nan(a) && nan(b)) {
            return (if nan(a) { a } else { b }) | layout.quiet_bit();
        }
        return if nan(a) { b } else { a };
    }
    match order(layout, a, b) {
        // Negative zero orders below positive zero; equal numbers are one.
        Ordering::Equal => {
            if maximum {
                a & b
            } else {
                a | b
            }
        }
        Ordering::Less => {
            if maximum {
                b
            } else {
                a
            }
        }
        Ordering::Greater => {
            if maximum {
                a
            } else {
                b
            }
        }
    }
}

fn compare(layout: Layout, relation: FloatRelation, unordered: bool, a: u128, b: u128) -> bool {
    let nan = |bits| matches!(layout.unpack(bits), Unpacked::Nan);
    let is_unordered = nan(a) || nan(b);
    let holds = |test: fn(Ordering) -> bool| !is_unordered && test(order(layout, a, b));
    let holds = match relation {
        FloatRelation::False => return false,
        FloatRelation::True => return true,
        FloatRelation::Ordered => return !is_unordered,
        FloatRelation::Unordered => return is_unordered,
        FloatRelation::Equal => holds(|order| order == Ordering::Equal),
        FloatRelation::NotEqual => holds(|order| order != Ordering::Equal),
        FloatRelation::Less => holds(|order| order == Ordering::Less),
        FloatRelation::LessEqual => holds(|order| order != Ordering::Greater),
        FloatRelation::Greater => holds(|order| order == Ordering::Greater),
        FloatRelation::GreaterEqual => holds(|order| order != Ordering::Less),
    };
    holds || (unordered && is_unordered)
}

/// Convert between formats. A NaN keeps its sign and the leading bits of its
/// payload, and becomes quiet.
fn convert(from: Layout, to: Layout, value: u128) -> u128 {
    match from.unpack(value) {
        Unpacked::Nan => {
            let payload = value & (from.quiet_bit() - 1);
            let payload = if from.fraction_bits >= to.fraction_bits {
                payload >> (from.fraction_bits - to.fraction_bits)
            } else {
                payload << (to.fraction_bits - from.fraction_bits)
            };
            to.zero(value & from.sign_bit() != 0) | to.exponent_mask() | to.quiet_bit() | payload
        }
        Unpacked::Infinite { negative } => to.infinity(negative),
        Unpacked::Finite(number) => {
            to.round(number.negative, &number.significand, number.exponent, false)
        }
    }
}

/// An integer of `bits` bits as a float.
fn from_integer(layout: Layout, value: u128, bits: u32, signed: bool) -> u128 {
    let negative = signed && (value >> (bits - 1)) & 1 == 1;
    let magnitude = if negative {
        value.wrapping_neg() & mask(bits)
    } else {
        value
    };
    layout.round(negative, &Natural::from_u128(magnitude), 0, false)
}

/// Evaluate `op` in software. `format` is the format of the float operands,
/// or of the result when the operands are integers. `None` if the operation
/// is not one of these or has the wrong number of operands.
pub(super) fn evaluate(op: FloatOp, format: FloatFormat, operands: &[u128]) -> Option<u128> {
    let layout = Layout::of(format);
    Some(match (op, operands) {
        (FloatOp::Add | FloatOp::Sub | FloatOp::Mul | FloatOp::Div | FloatOp::Rem, [a, b]) => {
            binary(layout, op, *a, *b)
        }
        (FloatOp::Fma, [a, b, c]) => fused(layout, *a, *b, *c),
        (FloatOp::Sqrt, [a]) => sqrt(layout, *a),
        (FloatOp::Minimum, [a, b]) => extremum(layout, *a, *b, false, true),
        (FloatOp::Maximum, [a, b]) => extremum(layout, *a, *b, true, true),
        (FloatOp::MinNum | FloatOp::MinimumNum, [a, b]) => extremum(layout, *a, *b, false, false),
        (FloatOp::MaxNum | FloatOp::MaximumNum, [a, b]) => extremum(layout, *a, *b, true, false),
        (
            FloatOp::Compare {
                relation,
                unordered,
            },
            [a, b],
        ) => u128::from(compare(layout, relation, unordered, *a, *b)),
        (FloatOp::FromSigned { bits }, [a]) => from_integer(layout, *a, bits, true),
        (FloatOp::FromUnsigned { bits }, [a]) => from_integer(layout, *a, bits, false),
        (FloatOp::Convert { to }, [a]) => convert(layout, Layout::of(to), *a),
        _ => return None,
    })
}

#[cfg(test)]
#[path = "softfloat_tests.rs"]
mod tests;

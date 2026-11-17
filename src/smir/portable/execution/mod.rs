//! Independent integer-core draft witness, not a portable runtime interpreter.
//!
//! Only concrete scalar widths 1..=128 are evaluated here. No production module
//! admission API consumes this module. The Python reference uses arbitrary
//! precision integers and a separate implementation of the same mathematics.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Bits(u128),
    Poison,
    Undef,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Flags {
    pub nsw: bool,
    pub nuw: bool,
    pub exact: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Width,
    Operand,
    Operation,
    Flags,
    PoisonDivisor,
    DivisionByZero,
    SignedDivisionOverflow,
}

fn signed(bits: u128, width: u32) -> i128 {
    if width == 128 {
        bits as i128
    } else {
        ((bits << (128 - width)) as i128) >> (128 - width)
    }
}

/// Evaluate a verified mathematical integer operation without host flags or FP.
///
/// Out-of-range operands, widths and flags are rejected. Poison is not a trap
/// unless used where a concrete operand can cause immediate undefined behavior.
/// Undef is refined to zero on each use; freeze fixes that choice in its result.
/// Time/space are O(1), bounded by the 128-bit independent witness width limit.
pub fn evaluate(
    operation: &str,
    width: u32,
    left: Value,
    right: Value,
    flags: Flags,
) -> Result<Value, Error> {
    if !(1..=128).contains(&width) {
        return Err(Error::Width);
    }
    let mask = u128::MAX >> (128 - width);
    for value in [left, right] {
        if let Value::Bits(bits) = value
            && bits > mask
        {
            return Err(Error::Operand);
        }
    }
    let arithmetic_flags = matches!(operation, "add" | "sub" | "mul" | "shl");
    let exact_flags = matches!(operation, "lshr" | "ashr" | "udiv" | "sdiv");
    if ((flags.nsw || flags.nuw) && !arithmetic_flags) || (flags.exact && !exact_flags) {
        return Err(Error::Flags);
    }
    if !matches!(
        operation,
        "copy"
            | "freeze"
            | "add"
            | "sub"
            | "mul"
            | "shl"
            | "lshr"
            | "ashr"
            | "udiv"
            | "sdiv"
            | "urem"
            | "srem"
            | "and"
            | "or"
            | "xor"
            | "eq"
            | "ne"
            | "ult"
            | "ule"
            | "ugt"
            | "uge"
            | "slt"
            | "sle"
            | "sgt"
            | "sge"
    ) {
        return Err(Error::Operation);
    }
    if operation == "freeze" {
        return Ok(match left {
            Value::Bits(_) => left,
            Value::Poison | Value::Undef => Value::Bits(0),
        });
    }
    if operation == "copy" {
        return Ok(left);
    }
    let a = match left {
        Value::Bits(bits) => bits,
        Value::Poison | Value::Undef => 0,
    };
    let b = match right {
        Value::Bits(bits) => bits,
        Value::Poison | Value::Undef => 0,
    };
    let division = matches!(operation, "udiv" | "sdiv" | "urem" | "srem");
    if division {
        if right == Value::Poison {
            return Err(Error::PoisonDivisor);
        }
        if b == 0 {
            return Err(Error::DivisionByZero);
        }
        if matches!(operation, "sdiv" | "srem")
            && b == mask
            && (left == Value::Poison || a == (1 << (width - 1)))
        {
            return Err(Error::SignedDivisionOverflow);
        }
    }
    if left == Value::Poison || right == Value::Poison {
        return Ok(Value::Poison);
    }
    let sa = signed(a, width);
    let sb = signed(b, width);
    let signed_in_range = |value: i128| {
        width == 128 || (-(1_i128 << (width - 1))..(1_i128 << (width - 1))).contains(&value)
    };
    let (result, unsigned_overflow, signed_overflow) = match operation {
        "add" => {
            let (result, overflow) = a.overflowing_add(b);
            let signed_ok = sa.checked_add(sb).is_some_and(signed_in_range);
            (result, overflow || result > mask, !signed_ok)
        }
        "sub" => {
            let (result, overflow) = a.overflowing_sub(b);
            let signed_ok = sa.checked_sub(sb).is_some_and(signed_in_range);
            (result, overflow, !signed_ok)
        }
        "mul" => {
            let (result, overflow) = a.overflowing_mul(b);
            let signed_ok = sa.checked_mul(sb).is_some_and(signed_in_range);
            (result, overflow || result > mask, !signed_ok)
        }
        "shl" | "lshr" | "ashr" => {
            if b >= u128::from(width) {
                return Ok(Value::Poison);
            }
            let shift = b as u32;
            let discarded = if shift == 0 {
                0
            } else {
                a & ((1 << shift) - 1)
            };
            if flags.exact && discarded != 0 {
                return Ok(Value::Poison);
            }
            match operation {
                "shl" => {
                    let truncated = (a << shift) & mask;
                    // Recovering by arithmetic shift detects signed overflow
                    // even for width=128/shift=127 without an i128 factor.
                    let signed_overflow = (signed(truncated, width) >> shift) != sa;
                    (truncated, a > (mask >> shift), signed_overflow)
                }
                "lshr" => (a >> shift, false, false),
                _ => ((sa >> shift) as u128, false, false),
            }
        }
        "udiv" | "urem" => {
            if flags.exact && a % b != 0 {
                return Ok(Value::Poison);
            }
            (
                if operation == "udiv" { a / b } else { a % b },
                false,
                false,
            )
        }
        "sdiv" | "srem" => {
            // MIN/-1 and zero were rejected before evaluating signed division.
            if flags.exact && sa % sb != 0 {
                return Ok(Value::Poison);
            }
            let result = if operation == "sdiv" {
                sa / sb
            } else {
                sa % sb
            };
            (result as u128, false, false)
        }
        "and" => (a & b, false, false),
        "or" => (a | b, false, false),
        "xor" => (a ^ b, false, false),
        "eq" => (u128::from(a == b), false, false),
        "ne" => (u128::from(a != b), false, false),
        "ult" => (u128::from(a < b), false, false),
        "ule" => (u128::from(a <= b), false, false),
        "ugt" => (u128::from(a > b), false, false),
        "uge" => (u128::from(a >= b), false, false),
        "slt" => (u128::from(sa < sb), false, false),
        "sle" => (u128::from(sa <= sb), false, false),
        "sgt" => (u128::from(sa > sb), false, false),
        "sge" => (u128::from(sa >= sb), false, false),
        _ => return Err(Error::Operation),
    };
    if (flags.nuw && unsigned_overflow) || (flags.nsw && signed_overflow) {
        Ok(Value::Poison)
    } else {
        Ok(Value::Bits(result & mask))
    }
}

#[cfg(test)]
mod tests;

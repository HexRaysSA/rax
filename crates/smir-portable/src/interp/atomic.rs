//! The atomic read-modify-write operations, on one thread.
//!
//! Each checks the whole access for writing before it reads, as the
//! reference machine does, so a failed guard changes nothing.

use crate::ir::{IntBinary, IntFlags, Pointer, RmwAction, Scalar, Value};

use super::int::{self, Arg, Computed};
use super::memory::{Fault, Memory};

/// The integer an atomic action stores, from the old value and the operand.
fn combine(action: RmwAction, bits: u32, old: Arg, operand: Arg) -> Computed {
    let wrapping = |op| {
        // Without flags these operations cannot fault.
        int::binary(op, bits, IntFlags::default(), old, operand).unwrap_or(Computed::Poison)
    };
    match action {
        RmwAction::Add => return wrapping(IntBinary::Add),
        RmwAction::Sub => return wrapping(IntBinary::Sub),
        RmwAction::And => return wrapping(IntBinary::And),
        RmwAction::Or => return wrapping(IntBinary::Or),
        RmwAction::Xor => return wrapping(IntBinary::Xor),
        _ => {}
    }
    let (Arg::Bits(a), Arg::Bits(b)) = (old, operand) else {
        return Computed::Poison;
    };
    let (sa, sb) = (int::signed(a, bits), int::signed(b, bits));
    Computed::Bits(match action {
        RmwAction::Nand => !(a & b) & int::mask(bits),
        RmwAction::Min => {
            if sa < sb {
                a
            } else {
                b
            }
        }
        RmwAction::Max => {
            if sa > sb {
                a
            } else {
                b
            }
        }
        RmwAction::UMin => a.min(b),
        RmwAction::UMax => a.max(b),
        // The exchange and the wrapping actions were handled above.
        _ => b,
    })
}

/// An integer operand with undef refined to zero.
fn argument(value: Value) -> Arg {
    match value {
        Value::Int(bits) => Arg::Bits(bits),
        Value::Poison => Arg::Poison,
        _ => Arg::Bits(0),
    }
}

/// Replace the scalar at `pointer` by `action` applied to it and `operand`;
/// returns the value that was there.
pub(super) fn read_modify_write(
    memory: &mut Memory,
    pointer: Pointer,
    action: RmwAction,
    operand: Value,
    kind: Scalar,
    bytes: u32,
    alignment: u32,
) -> Result<Value, Fault> {
    memory.writable(pointer, u64::from(bytes), alignment)?;
    let old = memory.load(pointer, kind, bytes, alignment)?;
    let desired = match action {
        RmwAction::Exchange => operand,
        _ => match combine(action, kind.bits(), argument(old), argument(operand)) {
            Computed::Bits(bits) => Value::Int(bits),
            Computed::Poison => Value::Poison,
        },
    };
    memory.store(pointer, desired, kind, bytes, alignment)?;
    Ok(old)
}

/// The bits a value is compared by, with poison and undef refined to zero.
fn compared(value: Value) -> u128 {
    match value {
        Value::Int(bits) => bits,
        Value::DataPtr(pointer) => u128::from(pointer.address),
        Value::CodePtr(target) | Value::CodeAddress(target) => u128::from(target.bits()),
        Value::Poison | Value::Undef => 0,
    }
}

/// Store `replacement` at `pointer` if the scalar there equals `expected`.
/// Returns the value that was there and whether the store happened.
///
/// The comparison is of the bits, where poison and undef bits count as
/// zero on both sides; the value returned keeps whatever it held.
pub(super) fn compare_exchange(
    memory: &mut Memory,
    pointer: Pointer,
    expected: Value,
    replacement: Value,
    kind: Scalar,
    bytes: u32,
    alignment: u32,
) -> Result<(Value, bool), Fault> {
    memory.writable(pointer, u64::from(bytes), alignment)?;
    let old = memory.load(pointer, kind, bytes, alignment)?;
    let observed = memory.refined_bits(pointer, kind, bytes)?;
    let success = observed == compared(expected);
    if success {
        memory.store(pointer, replacement, kind, bytes, alignment)?;
    }
    Ok((old, success))
}

//! Pure little-endian RISC-V AMO/CAS operand transformations.
use super::{MemError, MemResult};

/// One AMO transformation, or a Zacas comparison and replacement.
/// Scalar operands use 4/8 bytes; comparisons additionally support 16 bytes.
/// This descriptor carries no callback, host pointer or serialized state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicOp {
    Exchange(u64),
    Add(u64),
    Subtract(u64),
    Negate,
    And(u64),
    Or(u64),
    Xor(u64),
    Nand(u64),
    SignedMax(u64),
    SignedMin(u64),
    UnsignedMax(u64),
    UnsignedMin(u64),
    CompareExchange { expected: u128, replacement: u128 },
}
impl AtomicOp {
    /// Admit the whole operand before any memory or device access.
    pub fn validate(self, address: u64, size: u8) -> MemResult<()> {
        if !matches!(size, 4 | 8) && !(size == 16 && matches!(self, Self::CompareExchange { .. })) {
            return Err(MemError::OutOfBounds {
                addr: address,
                size: usize::from(size),
            });
        }
        if address & (u64::from(size) - 1) != 0 {
            return Err(MemError::Misaligned {
                addr: address,
                size: usize::from(size),
            });
        }
        Ok(())
    }

    /// None denotes a failed comparison. The ISA permits omitting its store
    /// or writing back the old value; write permission is required either way.
    /// Called only after validation. Time/space are O(1), up to 16 operand bytes.
    pub(crate) fn replacement(self, old: u128, size: u8) -> Option<u128> {
        let bits = u32::from(size) * 8;
        let mask = u128::MAX >> (128 - bits);
        let old = old & mask;
        let signed = |value: u128| ((value & mask) << (128 - bits)) as i128 >> (128 - bits);
        let new = match self {
            Self::Exchange(value) => u128::from(value),
            Self::Add(value) => old.wrapping_add(u128::from(value)),
            Self::Subtract(value) => old.wrapping_sub(u128::from(value)),
            Self::Negate => old.wrapping_neg(),
            Self::And(value) => old & u128::from(value),
            Self::Or(value) => old | u128::from(value),
            Self::Xor(value) => old ^ u128::from(value),
            Self::Nand(value) => !(old & u128::from(value)),
            Self::SignedMax(value) => signed(old).max(signed(u128::from(value))) as u128,
            Self::SignedMin(value) => signed(old).min(signed(u128::from(value))) as u128,
            Self::UnsignedMax(value) => old.max(u128::from(value) & mask),
            Self::UnsignedMin(value) => old.min(u128::from(value) & mask),
            Self::CompareExchange {
                expected,
                replacement,
            } => {
                if old != expected & mask {
                    return None;
                }
                replacement
            }
        };
        Some(new & mask)
    }
}

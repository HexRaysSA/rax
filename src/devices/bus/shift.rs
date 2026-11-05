//! Bounded scalar shifts and rotations used by one device RMW transaction.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmioShift {
    RotateLeft,
    RotateRight,
    RotateCarryLeft,
    RotateCarryRight,
    Left,
    LogicalRight,
    ArithmeticRight,
}

impl MmioShift {
    /// The caller has admitted a scalar size of 1, 2, 4 or 8 bytes.
    pub(crate) fn count(self, size: u8, count: u8) -> u32 {
        let count = u32::from(count & if size == 8 { 63 } else { 31 });
        match self {
            Self::RotateLeft | Self::RotateRight => count % (u32::from(size) * 8),
            Self::RotateCarryLeft | Self::RotateCarryRight if size <= 2 => {
                count % (u32::from(size) * 8 + 1)
            }
            _ => count,
        }
    }

    /// O(1) time and space. A 65-bit intermediate retains CF for RCL/RCR64;
    /// all host shifts remain strictly below the 128-bit intermediate width.
    pub(super) fn apply(self, old: u64, size: u8, count: u8, carry: bool) -> u64 {
        let count = self.count(size, count);
        if count == 0 {
            return old;
        }
        let bits = u32::from(size) * 8;
        match self {
            Self::Left => old.checked_shl(count).unwrap_or(0),
            Self::LogicalRight => old >> count,
            Self::ArithmeticRight => {
                let signed = ((old << (64 - bits)) as i64) >> (64 - bits);
                (signed >> count) as u64
            }
            _ => {
                let through_carry = matches!(self, Self::RotateCarryLeft | Self::RotateCarryRight);
                let width = bits + u32::from(through_carry);
                let value = u128::from(old)
                    | if through_carry {
                        u128::from(carry) << bits
                    } else {
                        0
                    };
                let mask = (1u128 << width) - 1;
                let rotated = if matches!(self, Self::RotateLeft | Self::RotateCarryLeft) {
                    ((value << count) | (value >> (width - count))) & mask
                } else {
                    ((value >> count) | (value << (width - count))) & mask
                };
                rotated as u64
            }
        }
    }
}

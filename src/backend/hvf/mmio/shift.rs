//! Intel SDM086 Vol.2B 4-533/534 and 4-602/603: defined shift/rotate flags.
use crate::devices::bus::MmioShift;
use crate::isa::x86_64::flags::{self, bits};

pub(super) fn flags(
    kind: MmioShift,
    size: u8,
    count: u8,
    old: u64,
    result: u64,
    before: u64,
) -> u64 {
    let masked = u32::from(count & if size == 8 { 63 } else { 31 });
    let width = u32::from(size) * 8;
    // Carry selection reduces only byte/word RCL/RCR modulo width + 1.
    // Full-turn ROL/ROR still update CF even when their value is unchanged.
    let carry_count = if size <= 2 {
        masked % (width + 1)
    } else {
        masked
    };
    if masked == 0
        || carry_count == 0
            && matches!(
                kind,
                MmioShift::RotateCarryLeft | MmioShift::RotateCarryRight
            )
    {
        return before;
    }
    let msb = 1u64 << (width - 1);
    let carry = match kind {
        MmioShift::RotateLeft => Some(result & 1 != 0),
        MmioShift::RotateRight => Some(result & msb != 0),
        MmioShift::RotateCarryLeft => Some(old & (1 << (width - carry_count)) != 0),
        MmioShift::RotateCarryRight => Some(old & (1 << (carry_count - 1)) != 0),
        MmioShift::Left if masked < width => Some(old & (1 << (width - masked)) != 0),
        MmioShift::LogicalRight if masked < width => Some(old & (1 << (masked - 1)) != 0),
        MmioShift::ArithmeticRight => Some(old & (1 << (masked.min(width) - 1)) != 0),
        // SHL/SHR CF is undefined when the count reaches the operand width.
        _ => None,
    };
    let mut after = before;
    if matches!(
        kind,
        MmioShift::Left | MmioShift::LogicalRight | MmioShift::ArithmeticRight
    ) {
        flags::update_flags_logic(&mut after, result, size);
        // Logic's helpers also clear CF/OF. Preserve undefined flags until
        // their specified cases below; AF remains untouched and undefined.
        after = (after & !(bits::CF | bits::OF)) | (before & (bits::CF | bits::OF));
    }
    if let Some(carry) = carry {
        after = (after & !bits::CF) | u64::from(carry);
    }
    if masked == 1 {
        let overflow = match kind {
            MmioShift::Left | MmioShift::RotateLeft | MmioShift::RotateCarryLeft => {
                (result & msb != 0) ^ (after & bits::CF != 0)
            }
            MmioShift::RotateRight | MmioShift::RotateCarryRight => {
                (result & msb != 0) ^ (result & (msb >> 1) != 0)
            }
            MmioShift::LogicalRight => old & msb != 0,
            MmioShift::ArithmeticRight => false,
        };
        after = (after & !bits::OF) | if overflow { bits::OF } else { 0 };
    }
    after
}

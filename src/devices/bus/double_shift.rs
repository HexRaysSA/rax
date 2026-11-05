//! SDM086 Vol.2B4-636/637 and4-639/640: one SHLD/SHRD memory operand.

/// Caller admits a 2/4/8-byte operand. Count masking precedes every host shift.
/// O(1) time and space; no host shift reaches or exceeds64 bits.
pub(super) fn apply(old: u64, source: u64, size: u8, count: u8, right: bool) -> u64 {
    let width = u32::from(size) * 8;
    let count = u32::from(count & if size == 8 { 63 } else { 31 });
    // SDM leaves the result/flags undefined for16-bit counts17..31. Select
    // unchanged data, without rejecting a valid instruction or its bus cycle.
    if count == 0 || count > width {
        return old;
    }
    let mask = u64::MAX >> (64 - width);
    let source = source & mask;
    let result = if right {
        (old >> count) | (source << (width - count))
    } else {
        (old << count) | (source >> (width - count))
    };
    result & mask
}

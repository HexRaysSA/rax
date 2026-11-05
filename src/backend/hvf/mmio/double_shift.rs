//! Intel SDM086 SHLD/SHRD defined flags, including masked-zero counts.
use crate::isa::x86_64::flags::{self, bits};

pub(super) fn flags(right: bool, size: u8, count: u8, old: u64, result: u64, before: u64) -> u64 {
    let width = u32::from(size) * 8;
    let count = u32::from(count & if size == 8 { 63 } else { 31 });
    // Undefined16-bit outcomes use the bus transform's unchanged-data policy.
    if count == 0 || count > width {
        return before;
    }
    let carry = if right {
        old & (1 << (count - 1)) != 0
    } else {
        old & (1 << (width - count)) != 0
    };
    let mut after = before;
    flags::update_flags_logic(&mut after, result, size);
    // AF is undefined for a nonzero count; OF is undefined beyond count1.
    // Retain those inputs until a defined OF case explicitly replaces it.
    after = (after & !(bits::CF | bits::OF | bits::AF))
        | (before & (bits::OF | bits::AF))
        | u64::from(carry);
    if count == 1 {
        let overflow = (old ^ result) & (1 << (width - 1)) != 0;
        after = (after & !bits::OF) | if overflow { bits::OF } else { 0 };
    }
    after
}

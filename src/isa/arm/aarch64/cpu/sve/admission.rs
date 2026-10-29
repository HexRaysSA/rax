//! Existing represented SVE reserved fields, checked before access traps.
use crate::isa::arm::aarch64::cpu::decode_bitmask;

pub(in crate::isa::arm::aarch64::cpu) fn reserved(insn: u32) -> bool {
    let top = (insn >> 24) & 0xff;
    // SVE2 PMUL is byte-only.
    if top == 0x04
        && (insn >> 21) & 1 == 1
        && (insn >> 12) & 15 == 6
        && (insn >> 10) & 3 == 1
        && (insn >> 22) & 3 != 0
    {
        return true;
    }
    // Predicated wide shifts use a separate encoding class from the
    // unpredicated forms below; both exclude doubleword destination elements.
    if top == 0x04
        && (insn >> 13) & 7 == 4
        && (insn >> 19) & 7 == 3
        && matches!((insn >> 16) & 7, 0 | 1 | 3)
        && (insn >> 22) & 3 == 3
    {
        return true;
    }
    // Wide-element shifts have no doubleword element-size encoding.
    if top == 0x04
        && (insn >> 21) & 1 == 1
        && (insn >> 13) & 7 == 4
        && (insn >> 12) & 1 == 0
        && (insn >> 22) & 3 == 3
    {
        return true;
    }
    // Predicate ZIP/UZP/TRN and REV encode four-bit predicate registers.
    // Register-extension bits and the two unused permutation opcodes are
    // unallocated before scalable-access permission checks.
    if top == 0x05 {
        let permute = (insn >> 20) & 3 == 2 && (insn >> 13) & 7 == 2;
        let reverse = (insn >> 16) & 63 == 0b110100 && (insn >> 10) & 63 == 0b010000;
        if (permute || reverse) && insn & ((1 << 9) | (1 << 4)) != 0
            || permute && (insn >> 10) & 7 > 5
        {
            return true;
        }
    }
    // Predicate SEL has no flag-setting variant (SELS is unallocated).
    if top == 0x25
        && (insn >> 20) & 3 == 0
        && (insn >> 14) & 3 == 1
        && (insn >> 23) & 1 == 0
        && (insn >> 22) & 1 == 1
        && insn & ((1 << 9) | (1 << 4)) == (1 << 9) | (1 << 4)
    {
        return true;
    }
    // Shifted immediate arithmetic has no sh=1 byte-element encoding.
    if top == 0x25
        && (insn >> 19) & 7 == 4
        && (insn >> 14) & 3 == 3
        && (insn >> 13) & 1 == 1
        && (insn >> 22) & 3 == 0
    {
        return true;
    }
    if top == 0x05 && (insn >> 18) & 15 == 0 {
        return decode_bitmask(
            (insn >> 17) & 1 != 0,
            (insn >> 5) & 63,
            (insn >> 11) & 63,
            true,
        )
        .is_err();
    }
    false
}

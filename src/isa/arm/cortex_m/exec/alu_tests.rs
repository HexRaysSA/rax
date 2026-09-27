//! Armv7-M pseudocode helpers against values worked by hand from the
//! pseudocode (DDI 0403E.e, A2.2.1 and A5.3.2).

use super::*;

#[test]
fn thumb_expand_imm_covers_replication_and_rotation() {
    // imm12<11:10> = 00: the byte, replicated per imm12<9:8>; carry kept.
    assert_eq!(thumb_expand_imm_c(0x0AB, true), Some((0x0000_00AB, true)));
    assert_eq!(thumb_expand_imm_c(0x1AB, false), Some((0x00AB_00AB, false)));
    assert_eq!(thumb_expand_imm_c(0x2AB, false), Some((0xAB00_AB00, false)));
    assert_eq!(thumb_expand_imm_c(0x3AB, false), Some((0xABAB_ABAB, false)));
    // A zero byte in the replicated forms is UNPREDICTABLE.
    assert_eq!(thumb_expand_imm_c(0x100, false), None);
    // '1':imm12<6:0> rotated right by imm12<11:7>; the carry is bit 31.
    assert_eq!(thumb_expand_imm_c(0x400, false), Some((0x8000_0000, true)));
    assert_eq!(thumb_expand_imm_c(0x7FF, true), Some((0x01FE_0000, false)));
}

#[test]
fn shift_c_handles_amounts_of_32_and_more() {
    assert_eq!(shift_c(0x8000_0001, Shift::Lsl, 32, false), (0, true));
    assert_eq!(shift_c(0xFFFF_FFFF, Shift::Lsl, 33, true), (0, false));
    assert_eq!(shift_c(0x8000_0000, Shift::Lsr, 32, false), (0, true));
    assert_eq!(shift_c(0xFFFF_FFFF, Shift::Lsr, 255, true), (0, false));
    assert_eq!(
        shift_c(0x8000_0000, Shift::Asr, 32, false),
        (0xFFFF_FFFF, true)
    );
    assert_eq!(shift_c(0x7FFF_FFFF, Shift::Asr, 255, true), (0, false));
    assert_eq!(
        shift_c(0x8000_0000, Shift::Ror, 32, false),
        (0x8000_0000, true)
    );
    assert_eq!(
        shift_c(0x0000_0001, Shift::Ror, 33, false),
        (0x8000_0000, true)
    );
    // An amount of zero keeps the value and the carry.
    assert_eq!(shift_c(0x1234, Shift::Ror, 0, true), (0x1234, true));
    assert_eq!(
        shift_c(0x0000_0001, Shift::Rrx, 1, true),
        (0x8000_0000, true)
    );
    assert_eq!(decode_imm_shift(0b11, 0), (Shift::Rrx, 1));
    assert_eq!(decode_imm_shift(0b01, 0), (Shift::Lsr, 32));
}

#[test]
fn add_with_carry_reports_carry_and_overflow() {
    assert_eq!(
        add_with_carry(0x7FFF_FFFF, 1, false),
        (0x8000_0000, false, true)
    );
    assert_eq!(add_with_carry(0xFFFF_FFFF, 1, false), (0, true, false));
    // Subtraction as x + NOT(y) + 1: 0 - 0 sets C (no borrow).
    assert_eq!(add_with_carry(0, !0, true), (0, true, false));
    assert_eq!(
        add_with_carry(0x8000_0000, !1, true),
        (0x7FFF_FFFF, true, true)
    );
}

#[test]
fn saturation_clamps_and_reports() {
    assert_eq!(signed_sat_q(128, 8), (127, true));
    assert_eq!(signed_sat_q(-129, 8), (0xFFFF_FF80, true));
    assert_eq!(signed_sat_q(-128, 8), (0xFFFF_FF80, false));
    assert_eq!(signed_sat_q(1 << 31, 32), (0x7FFF_FFFF, true));
    assert_eq!(unsigned_sat_q(-1, 8), (0, true));
    assert_eq!(unsigned_sat_q(256, 8), (255, true));
    assert_eq!(unsigned_sat_q(5, 0), (0, true));
    assert_eq!(unsigned_sat_q(0x7FFF_FFFF, 31), (0x7FFF_FFFF, false));
}

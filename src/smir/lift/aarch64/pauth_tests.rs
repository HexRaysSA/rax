//! Raw-encoding regressions for fail-closed pointer authentication.
use super::*;
use crate::smir::lift::SmirLifter;

#[test]
fn pauth_forms_reject_explicitly_in_both_modes() {
    let mut words = vec![
        0xd71f_0801,
        0xd71f_0c01,
        0xd73f_0801,
        0xd73f_0c01,
        0xd61f_081f,
        0xd61f_0c1f,
        0xd63f_081f,
        0xd63f_0c1f,
        0xd65f_0bff,
        0xd65f_0fff,
        0xd69f_0bff,
        0xd69f_0fff,
        0xf820_17e6,
        0xf8a0_17e6,
        0x9ac1_3000,
    ];
    words.extend((0..=17u32).map(|opcode| 0xdac1_0000 | (opcode << 10) | (31 << 5)));
    words.extend(
        [7u32, 8, 10, 12, 14, 24, 25, 26, 27, 28, 29, 30, 31].map(|imm| 0xd503_201f | (imm << 5)),
    );
    assert_eq!(words.len(), 46);
    for mut lifter in [Aarch64Lifter::new(), Aarch64Lifter::strict()] {
        for &word in &words {
            let mut ctx = LiftContext::new(SourceArch::Aarch64);
            assert!(
                matches!(
                    lifter.lift_insn(0x1000, &word.to_le_bytes(), &mut ctx),
                    Err(LiftError::Unsupported { addr: 0x1000, .. })
                ),
                "{word:#010x}"
            );
        }
    }
}

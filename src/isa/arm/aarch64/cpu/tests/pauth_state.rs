//! Persistent keyed state, full PSTATE, and malformed import boundaries.

use super::*;
use crate::isa::arm::aarch64::pauth::{
    PauthAlgorithm, PauthConfig, PauthKey, PauthKeys, PauthProfile,
};

#[test]
fn pauth_state_every_configured_initial_el_has_a_valid_reset_pstate() {
    for el in 0..=3 {
        let config = AArch64Config {
            initial_el: el,
            gic_config: None,
            ..Default::default()
        };
        let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x1000)));
        let expected = 0x3c0 | (u64::from(el) << 2) | u64::from(el != 0);
        assert_eq!(cpu.pstate_bits(), expected);
        AArch64Cpu::validate_pstate_bits(cpu.pstate_bits()).unwrap();
        cpu.set_pstate_bits(0).unwrap();
        cpu.reset();
        assert_eq!(cpu.pstate_bits(), expected);
    }
}

#[test]
fn pauth_state_bincode_roundtrip_preserves_keys_controls_and_higher_el_banks() {
    let mut original = create_test_cpu();
    original.config.features |= ArmFeatures::PACA | ArmFeatures::PACG;
    original.configure_pauth(PauthConfig {
        algorithm: PauthAlgorithm::Qarma3,
        profile: PauthProfile::Fpac,
    });
    let keys = PauthKeys {
        ia: PauthKey { lo: 1, hi: 2 },
        ib: PauthKey { lo: 3, hi: 4 },
        da: PauthKey { lo: 5, hi: 6 },
        db: PauthKey { lo: 7, hi: 8 },
        ga: PauthKey { lo: 9, hi: 10 },
    };
    original.set_pauth_keys(keys);
    original.sysregs.el1.sctlr = 1 << 31;
    original.sysregs.el1.tcr = 16 | (16 << 16) | (1 << 37);
    original.sysregs.el2.sctlr = 0x100;
    original.sysregs.el2.tcr = 21;
    original.sysregs.el2.elr = 0x2340;
    original.sysregs.el2.spsr = 0x3c5;
    original.sysregs.el3.sctlr = 0x200;
    original.sysregs.el3.elr = 0x3450;
    original.sysregs.el3.spsr = 0x3c9;
    original.sysregs.hcr_el2 = (1 << 40) | (1 << 41);
    original.sysregs.scr_el3 = 1 | (1 << 16) | (1 << 17);
    original.sp_el = [0x1000, 0x2000, 0x3000, 0x4000];
    let saved = original.export_sregs();
    let bytes = crate::codec::serialize(&saved).unwrap();
    let decoded: Aarch64SystemRegisters = crate::codec::deserialize(&bytes).unwrap();
    let mut restored = create_test_cpu();
    restored.import_sregs(&decoded).unwrap();
    assert_eq!(restored.pauth_keys(), keys);
    assert_eq!(restored.pauth_controls(), original.pauth_controls());
    assert_eq!(restored.config.pauth, original.config.pauth);
    assert_eq!(restored.sp_el, original.sp_el);
    assert_eq!(restored.sysregs.el2.elr, 0x2340);
    assert_eq!(restored.sysregs.el2.spsr, 0x3c5);
    assert_eq!(restored.sysregs.el3.elr, 0x3450);
    assert_eq!(restored.sysregs.el3.spsr, 0x3c9);
    assert_eq!(crate::codec::serialize(&restored.export_sregs()).unwrap(), bytes);
    // Every truncated serialization must fail rather than default missing keys.
    for end in 0..bytes.len() {
        assert!(crate::codec::deserialize::<Aarch64SystemRegisters>(&bytes[..end]).is_err());
    }
}

#[test]
fn pauth_state_pstate_roundtrip_covers_every_modeled_flag_and_mode() {
    let mut cpu = create_test_cpu();
    let flags = 0xf000_0000 | (0x3f << 20) | (1 << 12) | (3 << 10) | (15 << 6);
    for mode in [0, 4, 5, 8, 9, 12, 13] {
        cpu.set_pstate_bits(flags | mode).unwrap();
        assert_eq!(cpu.pstate_bits(), flags | mode);
    }
    let before = cpu.pstate_bits();
    for mode in [1, 2, 3, 6, 7, 10, 11, 14, 15, 0x14, 0x16] {
        assert!(cpu.set_pstate_bits(flags | mode).is_err());
        assert_eq!(cpu.pstate_bits(), before);
    }
    for bit in [5, 13, 19, 26, 32, 63] {
        assert!(cpu.set_pstate_bits(before | (1 << bit)).is_err());
        assert_eq!(cpu.pstate_bits(), before);
    }
}

#[test]
fn pauth_state_legacy_register_overlay_preserves_complete_keyed_extension() {
    let mut cpu = create_test_cpu();
    cpu.sysregs.apiakeylo_el1 = 0x1234;
    cpu.sysregs.el2.elr = 0x9870;
    let mut saved = cpu.export_sregs();
    saved.sctlr_el1 = 1 << 31;
    saved.sp_el0 = 0x4440;
    cpu.import_sregs(&saved).unwrap();
    assert_eq!(cpu.sysregs.el1.sctlr, 1 << 31);
    assert_eq!(cpu.sysregs.apiakeylo_el1, 0x1234);
    assert_eq!(cpu.sysregs.el2.elr, 0x9870);
    assert_eq!(cpu.sp_el[0], 0x4440);
}

#[test]
fn pauth_state_omitted_keys_cannot_enable_authentication_during_import() {
    let mut cpu = create_test_cpu();
    cpu.sysregs.apiakeylo_el1 = 0x1234;
    let before = crate::codec::serialize(&cpu.export_sregs()).unwrap();
    for bit in [31, 30, 27, 13] {
        let incomplete = Aarch64SystemRegisters {
            sctlr_el1: 1 << bit,
            ..Default::default()
        };
        assert!(cpu.import_sregs(&incomplete).is_err());
        assert_eq!(crate::codec::serialize(&cpu.export_sregs()).unwrap(), before);
    }
}

#[test]
fn pauth_hint_reserved_rt_does_not_sign_or_authenticate() {
    for immediate in [7, 8, 10, 12, 14, 24, 25, 26, 27, 28, 29, 30, 31] {
        for rt in 0..31 {
            let word = 0xd503_201f | (immediate << 5);
            let reserved = (word & !31) | rt;
            let mut cpu = create_cpu_with_insn(reserved);
            cpu.config.features |= ArmFeatures::PACA;
            cpu.set_x(30, 0xabcd_0000_0000_1230);
            let before = cpu.x;
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(raw)) if raw == reserved)
            );
            assert_eq!(cpu.x, before);
            assert_eq!(cpu.get_pc(), 0);
        }
    }
}

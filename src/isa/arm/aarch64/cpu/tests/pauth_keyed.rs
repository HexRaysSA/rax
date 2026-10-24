//! Keyed PAuth execution, permission checks, and precise fault state.

use super::*;
use crate::isa::arm::aarch64::pauth::{
    PauthAlgorithm, PauthConfig, PauthKey, PauthKeys, PauthProfile,
};

pub(super) fn keyed_cpu(word: u32, algorithm: PauthAlgorithm, profile: PauthProfile) -> AArch64Cpu {
    let config = AArch64Config {
        features: ArmFeatures::armv8_3_base(),
        pauth: PauthConfig { algorithm, profile },
        gic_config: None,
        ..AArch64Config::default()
    };
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x10000)));
    cpu.write_memory(0, &word.to_le_bytes()).unwrap();
    let mut controls = cpu.pauth_controls();
    controls.scr_el3 = 1 | (1 << 10) | (1 << 16) | (1 << 17);
    controls.hcr_el2 = (1 << 31) | (1 << 40) | (1 << 41);
    controls.sctlr[1] = (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13);
    controls.tcr[1] = 16 | (16 << 16);
    cpu.set_pauth_controls(controls).unwrap();
    let key = PauthKey {
        lo: u64::MAX,
        hi: 0x0123_4567_89ab_cdef,
    };
    cpu.set_pauth_keys(PauthKeys {
        ia: key,
        ib: key,
        da: key,
        db: key,
        ga: key,
    });
    cpu
}

#[test]
fn pauth_direct_sign_and_generic_match_independent_known_values() {
    for (algorithm, signed, generic) in [
        (
            PauthAlgorithm::Qarma5,
            0xf916_0000_0000_0000,
            0xf996_e761_0000_0000,
        ),
        (
            PauthAlgorithm::Qarma3,
            0xa02d_0000_0000_0000,
            0xa02d_2cde_0000_0000,
        ),
    ] {
        // QEMU primitive inputs: pointer/data=0, modifier=1, key Lo=MAX,
        // key Hi=0x0123456789abcdef. PAC placement excludes selector bit 55.
        let mut cpu = keyed_cpu(0xdac1_0020, algorithm, PauthProfile::FpacCombine); // PACIA X0,X1
        cpu.set_x(1, 1);
        cpu.step().unwrap();
        assert_eq!(cpu.get_x(0), signed);
        assert_eq!(cpu.get_pc(), 4);
        let mut cpu = keyed_cpu(0x9ac1_3000, algorithm, PauthProfile::FpacCombine); // PACGA X0,X0,X1
        cpu.set_x(1, 1);
        cpu.step().unwrap();
        assert_eq!(cpu.get_x(0), generic);
        assert_eq!(cpu.get_x(0) as u32, 0);
    }
}

#[test]
fn pauth_direct_address_and_generic_feature_gates_are_independent() {
    let mut cases = 0;
    for address in [false, true] {
        for generic in [false, true] {
            for (raw, enabled, signed) in [
                (0xdac1_0020, address, 0xf916_0000_0000_0000),
                (0x9ac1_3000, generic, 0xf996_e761_0000_0000),
            ] {
                let mut cpu = keyed_cpu(raw, PauthAlgorithm::Qarma5, PauthProfile::FpacCombine);
                cpu.config.features.set(ArmFeatures::PACA, address);
                cpu.config.features.set(ArmFeatures::PACG, generic);
                cpu.set_x(1, 1);
                if enabled {
                    cpu.step().unwrap();
                    assert_eq!(cpu.get_x(0), signed);
                    assert_eq!(cpu.insn_count, 1);
                } else {
                    assert!(
                        matches!(cpu.step(), Err(ArmError::UndefinedInstruction(word)) if word == raw)
                    );
                    assert_eq!(cpu.get_x(0), 0);
                    assert_eq!(cpu.pc, 0);
                    assert_eq!(cpu.insn_count, 0);
                }
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 8);
}

#[test]
fn pauth_direct_all_data_keys_and_zero_modifiers_roundtrip() {
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for key in 0..4u32 {
                for zero in [false, true] {
                    let rn = if zero { 31 } else { 1 };
                    let sign_opcode = key | if zero { 8 } else { 0 };
                    let sign = 0xdac1_0000 | (sign_opcode << 10) | (rn << 5);
                    let auth = sign | (4 << 10);
                    let mut cpu = keyed_cpu(sign, algorithm, profile);
                    cpu.write_memory(4, &auth.to_le_bytes()).unwrap();
                    cpu.set_x(0, 0x1230);
                    cpu.set_x(1, 0x4567);
                    cpu.step().unwrap();
                    assert_ne!(cpu.get_x(0), 0x1230, "{algorithm:?} {profile:?} key={key}");
                    cpu.step().unwrap();
                    assert_eq!(cpu.get_x(0), 0x1230);
                    assert_eq!(cpu.nzcv, 0);
                }
            }
        }
    }
}

#[test]
fn pauth_direct_fpac_fault_preserves_registers_pc_and_btype() {
    for key in 0..4u32 {
        let auth = 0xdac1_0000 | ((key | 4) << 10) | (1 << 5);
        let mut cpu = keyed_cpu(auth, PauthAlgorithm::Qarma5, PauthProfile::FpacCombine);
        cpu.set_x(0, 0x1230); // Unsigned pointer is not a valid signature with this key/modifier.
        cpu.set_x(1, 0x4567);
        cpu.btype = 3;
        cpu.nzcv = 10;
        let before = cpu.x;
        assert!(
            matches!(cpu.step(), Err(ArmError::ArchitecturalException { ec: 0x1c, iss, target_el: Some(1) }) if iss == key)
        );
        assert_eq!(cpu.x, before);
        assert_eq!(cpu.get_pc(), 0);
        assert_eq!(cpu.btype, 3);
        assert_eq!(cpu.nzcv, 10);
        assert_eq!(cpu.instruction_count(), 0);
    }
}

#[test]
fn pauth_direct_disabled_keys_are_identity_before_use_traps() {
    let mut cpu = keyed_cpu(
        0xdac1_0020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    cpu.sysregs.el1.sctlr = 0;
    cpu.sysregs.hcr_el2 = 0;
    cpu.sysregs.scr_el3 = 1;
    cpu.set_x(0, 0x1230);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x1230);
    cpu.write_memory(4, &0x9ac1_3000_u32.to_le_bytes()).unwrap();
    assert!(matches!(
        cpu.step(),
        Err(ArmError::ArchitecturalException {
            ec: 9,
            target_el: Some(2),
            ..
        })
    ));
    assert_eq!(cpu.get_pc(), 4);
    assert_eq!(cpu.get_x(0), 0x1230);
}

#[test]
fn pauth_direct_key_access_trap_has_exact_sysreg_syndrome() {
    // MRS X5,APIAKeyLo_EL1; field placement from Arm's system-access ISS definition.
    let word = 0xd520_0000 | (3 << 19) | (2 << 12) | (1 << 8) | 5;
    let mut cpu = keyed_cpu(word, PauthAlgorithm::Qarma5, PauthProfile::FpacCombine);
    cpu.sysregs.hcr_el2 &= !(1 << 40);
    let iss = (3 << 20) | (2 << 10) | (5 << 5) | (1 << 1) | 1;
    assert!(
        matches!(cpu.step(), Err(ArmError::ArchitecturalException { ec: 0x18, iss: actual, target_el: Some(2) }) if actual == iss)
    );
    assert_eq!(cpu.get_x(5), 0);
    assert_eq!(cpu.get_pc(), 0);
}

#[test]
fn pauth_direct_auth_load_precedes_sp_alignment_and_does_not_writeback_on_fault() {
    let word = 0xf820_0fe6; // LDRAA X6,[SP,#0]!
    let mut cpu = keyed_cpu(word, PauthAlgorithm::Qarma5, PauthProfile::FpacCombine);
    cpu.sysregs.el1.sctlr |= 1 << 3;
    cpu.set_current_sp(0x108);
    cpu.set_x(6, 0xabcdef);
    assert!(matches!(
        cpu.step(),
        Err(ArmError::ArchitecturalException {
            ec: 0x1c,
            iss: 2,
            ..
        })
    ));
    assert_eq!(cpu.current_sp(), 0x108);
    assert_eq!(cpu.get_x(6), 0xabcdef);
    let signed = cpu
        .pauth_value(
            0x108,
            0,
            crate::isa::arm::aarch64::pauth::PauthKeyKind::Da,
            false,
            false,
        )
        .unwrap();
    cpu.set_current_sp(signed);
    assert!(
        matches!(cpu.step(), Err(ArmError::MemoryError(info)) if info.fault_type == MemoryFaultType::SpAlignment)
    );
    assert_eq!(cpu.current_sp(), signed);
    assert_eq!(cpu.get_x(6), 0xabcdef);
}

#[test]
fn pauth_direct_call_authenticates_aliased_link_register_before_update() {
    let mut cpu = keyed_cpu(
        0xd73f_0bdf,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    ); // BLRAA X30,SP
    cpu.set_current_sp(0x200);
    let signed = cpu
        .pauth_value(
            0x800,
            0x200,
            crate::isa::arm::aarch64::pauth::PauthKeyKind::Ia,
            false,
            false,
        )
        .unwrap();
    cpu.set_x(30, signed);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(30), 4);
    assert_eq!(cpu.get_pc(), 0x800);
    assert_eq!(cpu.btype, 2);
}

#[test]
fn pauth_direct_exception_return_authenticates_before_restoring_saved_pstate() {
    let mut cpu = keyed_cpu(
        0xd69f_0bff,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    cpu.set_current_sp(0x200);
    cpu.sp_el[0] = 0x300;
    cpu.sysregs.el1.spsr = 0x2000_03c0; // EL0t, C=1, masked interrupts.
    let signed = cpu
        .pauth_value(
            0x800,
            0x200,
            crate::isa::arm::aarch64::pauth::PauthKeyKind::Ia,
            false,
            false,
        )
        .unwrap();
    cpu.sysregs.el1.elr = signed ^ (1 << 48);
    let before = cpu.sysregs.el1.spsr;
    assert!(matches!(
        cpu.step(),
        Err(ArmError::ArchitecturalException { ec: 0x1c, .. })
    ));
    assert_eq!(cpu.current_el, 1);
    assert_eq!(cpu.sysregs.el1.spsr, before);
    cpu.sysregs.el1.elr = signed;
    cpu.step().unwrap();
    assert_eq!(cpu.current_el, 0);
    assert_eq!(cpu.get_pc(), 0x800);
    assert_eq!(cpu.current_sp(), 0x300);
    assert!(cpu.get_c());
    assert_eq!(cpu.sysregs.el1.elr, signed);
}

#[test]
fn pauth_direct_profile_id_fields_and_reset_are_consistent() {
    let mut cpu = keyed_cpu(
        0xd503_201f,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    assert_eq!((cpu.sysregs.id_aa64isar1_el1 >> 4) & 0xff, 5);
    assert_eq!((cpu.sysregs.id_aa64isar1_el1 >> 24) & 0xff, 1);
    cpu.configure_pauth(PauthConfig {
        algorithm: PauthAlgorithm::Qarma3,
        profile: PauthProfile::Base,
    });
    assert_eq!((cpu.sysregs.id_aa64isar1_el1 >> 4) & 0xff, 0);
    assert_eq!((cpu.sysregs.id_aa64isar2_el1 >> 8) & 0xff, 0x11);
    cpu.reset();
    assert_eq!(cpu.pauth_keys(), PauthKeys::default());
    assert_eq!(cpu.config.pauth.algorithm, PauthAlgorithm::Qarma3);
    assert_eq!((cpu.sysregs.id_aa64isar2_el1 >> 8) & 0xff, 0x11);
}

#[test]
fn pauth_direct_branch_removes_only_the_instruction_tag_after_authentication() {
    let mut cpu = keyed_cpu(
        0xd61f_081f,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    ); // BRAAZ X0
    let mut controls = cpu.pauth_controls();
    controls.tcr[1] |= 1 << 37;
    cpu.set_pauth_controls(controls).unwrap();
    let tagged = 0xab00_0000_0000_0800;
    let signed = cpu
        .pauth_value(
            tagged,
            0,
            crate::isa::arm::aarch64::pauth::PauthKeyKind::Ia,
            false,
            false,
        )
        .unwrap();
    cpu.set_x(0, signed);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x800);
}

#[test]
fn pauth_direct_system_fault_vectors_with_exact_saved_pc_and_syndrome() {
    let mut cpu = keyed_cpu(
        0xdac1_1020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    cpu.set_x(0, 0x1230);
    cpu.set_x(1, 0x4567);
    cpu.sysregs.el1.vbar = 0x8000;
    cpu.btype = 3;
    cpu.nzcv = 10;
    let before = cpu.x;
    assert!(matches!(cpu.step_system(), Ok(CpuExit::Continue)));
    assert_eq!(cpu.x, before);
    assert_eq!(cpu.sysregs.el1.elr, 0);
    assert_eq!(cpu.sysregs.el1.esr, (0x1c << 26) | (1 << 25));
    assert_eq!((cpu.sysregs.el1.spsr >> 10) & 3, 3);
    assert_eq!(cpu.sysregs.el1.spsr >> 28, 10);
    assert_eq!(cpu.pc, 0x8200);
    assert_eq!(cpu.btype, 0);
}

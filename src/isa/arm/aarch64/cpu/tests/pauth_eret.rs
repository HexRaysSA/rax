//! Arm IllegalExceptionReturn, SetPSTATEFromPSR, and ERET trap priority.

use super::*;
use crate::isa::arm::aarch64::exception_return::{ExceptionReturnMode, classify_exception_return};

#[test]
fn pauth_eret_mode_classifier_covers_every_spsr_m_encoding() {
    let mut cpu = create_test_cpu();
    cpu.current_el = 3;
    cpu.sysregs.scr_el3 |= 1;
    let controls = cpu.pauth_controls();
    for mode in 0..32 {
        let expected = match mode {
            0 => ExceptionReturnMode::Aarch64 {
                el: 0,
                sp_elx: false,
            },
            4 | 5 => ExceptionReturnMode::Aarch64 {
                el: 1,
                sp_elx: mode & 1 != 0,
            },
            8 | 9 => ExceptionReturnMode::Aarch64 {
                el: 2,
                sp_elx: mode & 1 != 0,
            },
            12 | 13 => ExceptionReturnMode::Aarch64 {
                el: 3,
                sp_elx: mode & 1 != 0,
            },
            16 => ExceptionReturnMode::Aarch32 { el: 0, mode: 16 },
            _ => ExceptionReturnMode::Illegal,
        };
        assert_eq!(
            classify_exception_return(controls, cpu.sysregs.id_aa64pfr0_el1, mode),
            expected,
            "M={mode:#x}"
        );
    }
    let mut restricted = controls;
    restricted.implemented_els &= !4;
    assert_eq!(
        classify_exception_return(restricted, cpu.sysregs.id_aa64pfr0_el1, 9),
        ExceptionReturnMode::Illegal
    );
    let mut secure = controls;
    secure.scr_el3 &= !1;
    assert_eq!(
        classify_exception_return(secure, cpu.sysregs.id_aa64pfr0_el1, 9),
        ExceptionReturnMode::Illegal
    );
    let mut aarch32 = controls;
    aarch32.scr_el3 &= !(1 << 10);
    assert_eq!(
        classify_exception_return(aarch32, cpu.sysregs.id_aa64pfr0_el1, 9),
        ExceptionReturnMode::Illegal
    );
    assert_eq!(
        classify_exception_return(aarch32, cpu.sysregs.id_aa64pfr0_el1, 0x1a),
        ExceptionReturnMode::Aarch32 { el: 2, mode: 0x1a }
    );
}

#[test]
fn pauth_eret_illegal_return_sets_il_and_restores_unconditional_flags() {
    let mut cpu = create_cpu_with_insn(0xd69f_03e0);
    cpu.sysregs.el1.elr = 0x100;
    cpu.sysregs.el1.spsr = (10 << 28) | (1 << 22) | (1 << 23) | (3 << 10) | (5 << 6) | 9;
    cpu.set_x(0, 0x1234);
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.current_el, 1);
    assert!(cpu.sp_sel);
    assert!(cpu.il);
    assert_eq!(cpu.nzcv, 10);
    assert_eq!(cpu.daif, 5);
    assert!(cpu.pan);
    assert!(!cpu.uao);
    assert_eq!(cpu.btype, 0);
    assert_eq!(cpu.get_pc(), 0x100);
    assert_eq!(cpu.get_x(0), 0x1234);
    assert_eq!(cpu.instruction_count(), 1);
    assert!(matches!(
        cpu.step(),
        Err(ArmError::ArchitecturalException {
            ec: 0x0e,
            iss: 0,
            ..
        })
    ));
    assert_eq!(cpu.instruction_count(), 1);
}

#[test]
fn pauth_eret_tge_and_debug_single_step_rules_are_observed() {
    let mut cpu = create_test_cpu();
    cpu.current_el = 2;
    cpu.sysregs.scr_el3 |= 1;
    cpu.sysregs.hcr_el2 |= 1 << 27;
    cpu.sysregs.el2.elr = 0x100;
    cpu.sysregs.el2.spsr = 5;
    cpu.exception_return().unwrap();
    assert_eq!(cpu.current_el, 2);
    assert!(cpu.il);
    for stepping in [false, true] {
        let mut cpu = create_test_cpu();
        cpu.sysregs.el1.elr = 0x100;
        cpu.sysregs.el1.spsr = 1 << 21; // EL0t with saved SS.
        cpu.sysregs.mdscr_el1 = u64::from(stepping);
        cpu.exception_return().unwrap();
        assert_eq!(cpu.current_el, 0);
        assert_eq!(cpu.ss, stepping);
    }
}

#[test]
fn pauth_eret_nv_trap_precedes_authentication_and_saved_state_checks() {
    for (word, iss) in [(0xd69f_03e0, 0), (0xd69f_0bff, 2), (0xd69f_0fff, 3)] {
        let mut cpu = create_cpu_with_insn(word);
        cpu.config.features |= ArmFeatures::PACA | ArmFeatures::NV;
        cpu.sysregs.scr_el3 |= 1;
        cpu.sysregs.hcr_el2 |= 1 << 42;
        cpu.sysregs.el1.sctlr = (1 << 31) | (1 << 30);
        cpu.sysregs.el1.spsr = u64::MAX;
        assert!(
            matches!(cpu.step(), Err(ArmError::ArchitecturalException { ec: 0x1a, iss: actual, target_el: Some(2) }) if actual == iss)
        );
        assert_eq!(cpu.current_el, 1);
        assert_eq!(cpu.get_pc(), 0);
        assert_eq!(cpu.instruction_count(), 0);
    }
}

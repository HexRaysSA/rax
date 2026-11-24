//! tests::system tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

#[test]
fn wfx_traps_use_the_effective_control_bank_and_preserve_the_faulting_pc() {
    for (word, hint, sctlr_bit, hcr_bit, scr_bit, iss) in [
        (0xd503_205f, CpuExit::Wfe, 18, 14, 13, 0x1e0_0001),
        (0xd503_207f, CpuExit::Wfi, 16, 13, 12, 0x1e0_0000),
    ] {
        for (el, secure, host, tge, el1_allow, el2_allow, target) in [
            (1, false, false, false, true, true, Some(2)),
            (1, true, false, false, true, true, Some(3)),
            (0, false, false, false, false, true, Some(1)),
            (0, false, false, true, false, true, Some(2)),
            (0, false, true, true, true, false, Some(2)),
            (0, false, true, true, false, true, Some(3)),
            (2, false, true, true, false, false, Some(3)),
            (3, true, false, false, false, false, None),
        ] {
            let mut cpu = create_cpu_with_insn(word);
            cpu.current_el = el;
            cpu.sp_sel = el != 0;
            cpu.config.features.insert(ArmFeatures::VHE);
            cpu.sysregs.hcr_el2 =
                (1 << 31) | (1 << hcr_bit) | (u64::from(host) << 34) | (u64::from(tge) << 27);
            cpu.sysregs.scr_el3 = (1 << 10) | (1 << scr_bit) | u64::from(!secure);
            cpu.sysregs.el1.sctlr = u64::from(el1_allow) << sctlr_bit;
            cpu.sysregs.el2.sctlr = u64::from(el2_allow) << sctlr_bit;
            match target {
                Some(target) => {
                    assert!(
                        matches!(
                            cpu.step(),
                            Err(ArmError::ArchitecturalException { ec: 1, iss: value, target_el: Some(level) })
                                if value == iss && level == target
                        ),
                        "word={word:08x}, el={el}, secure={secure}, host={host}, tge={tge}"
                    );
                    assert_eq!(
                        (cpu.pc, cpu.insn_count, cpu.wfe, cpu.wfi),
                        (0, 0, false, false)
                    );
                    cpu.sysregs.bank_mut(target).vbar = 0x800;
                    assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
                    let bank = cpu.sysregs.bank(target);
                    assert_eq!((cpu.current_el, cpu.pc, cpu.insn_count), (target, 0xc00, 0));
                    assert_eq!(bank.elr, 0);
                    assert_eq!(bank.esr, 0x0600_0000 | u64::from(iss));
                }
                None => {
                    assert_eq!(cpu.step().unwrap(), hint);
                    assert_eq!((cpu.pc, cpu.insn_count), (4, 1));
                }
            }
        }
    }
}

#[test]
fn wfx_traps_are_bypassed_for_ready_wakeups_and_process_hints() {
    for word in [0xd503_205fu32, 0xd503_207f] {
        let mut cpu = create_cpu_with_insn(word);
        cpu.current_el = 1;
        cpu.gic = None;
        cpu.daif = 0xf;
        cpu.sysregs.scr_el3 |= 1;
        cpu.sysregs.hcr_el2 |= (1 << 14) | (1 << 13);
        let expected = if word == 0xd503_205f {
            cpu.set_event();
            CpuExit::Continue
        } else {
            cpu.sysregs.cntp_ctl_el0 = 1;
            cpu.sysregs.cntp_cval_el0 = 0;
            CpuExit::Wfi
        };
        assert_eq!(cpu.step_system().unwrap(), expected);
        assert!(!cpu.event_pending());
        assert_eq!(
            (cpu.pc, cpu.insn_count, cpu.wfe, cpu.wfi),
            (4, 1, false, false)
        );

        let mut process = create_cpu_with_insn(word);
        process.enter_el0();
        let result = process.step_user_pauth(false).unwrap();
        assert!(matches!(result, CpuExit::Wfe | CpuExit::Wfi));
        assert_eq!((process.pc, process.insn_count), (4, 1));
    }
}

#[test]
fn rng_mrs_sets_z_when_value_unavailable() {
    for (op2, value) in [
        (0, 0),
        (1, 0),
        (0, 0x1122_3344_5566_7788),
        (1, 0x8877_6655_4433_2211),
    ] {
        let mut cpu = create_cpu_with_insn(encode_mrs_rng(op2, 0));
        if op2 == 0 {
            cpu.sysregs.rndr = value;
        } else {
            cpu.sysregs.rndrrs = value;
        }
        cpu.set_nzcv(true, true, true, true);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_x(0), value);
        assert!(!cpu.get_n());
        assert_eq!(cpu.get_z(), value == 0);
        assert!(!cpu.get_c());
        assert!(!cpu.get_v());
    }
}
#[test]
fn sve_brkn_rejects_reserved_bits() {
    // BRKN has fixed 0 bits at bit9 and bit4. Setting either yields an
    // unallocated encoding that must NOT execute as BRKN (which would
    // mutate predicate state); it falls through to a rejection instead.
    let setup = |insn: u32| {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16);
        cpu.set_sve_pred(0, 0xABCD); // Pdm sentinel
        cpu
    };
    for insn in [0x2518_4200u32, 0x2518_4010] {
        let mut cpu = setup(insn);
        // Not executed as BRKN (BRKN with these operands would zero Pdm).
        assert!(!matches!(cpu.step(), Ok(CpuExit::Continue)));
        assert_eq!(cpu.sve_pred(0), 0xABCD, "{insn:#x} mutated predicate state");
    }
    // The valid BRKN still executes (last-active false -> result all-false).
    let mut ok = setup(0x2518_4000);
    assert_eq!(ok.step().unwrap(), CpuExit::Continue);
}
#[test]
fn test_el0_feature_hints_and_barriers_continue() {
    for (name, insn, setup) in [
        ("dgh", 0xD50320DF, None),
        ("bti", 0xD503241F, None),
        ("bti_c", 0xD503245F, None),
        ("bti_j", 0xD503249F, None),
        ("bti_jc", 0xD50324DF, None),
        ("wfet_x0_zero_timeout", 0xD5031000, Some((0u8, 0u64))),
        ("wfit_x1_zero_timeout", 0xD5031021, Some((1u8, 0u64))),
        ("sb", 0xD50330FF, None),
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        if let Some((reg, value)) = setup {
            cpu.set_x(reg, value);
        }
        let exit = cpu.step().unwrap();
        assert_eq!(exit, CpuExit::Continue, "{name} should retire");
        assert_eq!(cpu.get_pc(), 4, "{name} should advance PC");
    }
}
#[test]
fn test_el0_privileged_op1_3_sys_traps() {
    let mut config = AArch64Config::default();
    config.initial_el = 0;

    for (name, insn) in [
        ("sys_op1_3_c0_c0_0", 0xD50B0000u32),
        ("sys_op1_3_c1_c0_0", 0xD50B1000u32),
        ("sys_op1_3_c7_c0_0", 0xD50B7000u32),
        ("sys_op1_3_c7_c4_0", 0xD50B7400u32),
        ("sys_op1_3_c7_c5_0", 0xD50B7500u32),
        ("sys_op1_3_c7_c10_0", 0xD50B7A00u32),
        ("sys_op1_3_c8_c7_0", 0xD50B8700u32),
        ("sys_op1_3_c8_c7_1", 0xD50B8720u32),
        ("sys_op1_3_c7_c8_0", 0xD50B7800u32),
        ("sys_op1_3_c15_c15_7", 0xD50BFFE0u32),
    ] {
        let memory = FlatMemory::new(0, 0x1000_0000);
        let mut cpu = AArch64Cpu::new(config.clone(), Box::new(memory));
        cpu.write_memory(0, &insn.to_le_bytes()).unwrap();
        assert!(
            matches!(cpu.step(), Err(ArmError::UndefinedInstruction(got)) if got == insn),
            "{name} should be undefined at EL0"
        );
    }
}
#[test]
fn test_el0_privileged_pstate_immediate_traps() {
    let mut config = AArch64Config::default();
    config.initial_el = 0;

    for (name, insn) in [
        ("msr_uao_0", 0xD500407Fu32),
        ("msr_uao_1", 0xD500417Fu32),
        ("msr_pan_0", 0xD500409Fu32),
        ("msr_pan_1", 0xD500419Fu32),
        ("msr_spsel_1", 0xD50041BFu32),
        ("msr_daifset_f", 0xD5034FDFu32),
        ("msr_daifclr_f", 0xD5034FFFu32),
    ] {
        let memory = FlatMemory::new(0, 0x1000_0000);
        let mut cpu = AArch64Cpu::new(config.clone(), Box::new(memory));
        cpu.write_memory(0, &insn.to_le_bytes()).unwrap();
        assert!(
            matches!(cpu.step(), Err(ArmError::UndefinedInstruction(got)) if got == insn),
            "{name} should be undefined at EL0"
        );
    }
}
#[test]
fn test_el0_clidr_el1_read_traps() {
    let mut config = AArch64Config::default();
    config.initial_el = 0;

    let insn = 0xD5390020u32; // MRS X0, CLIDR_EL1
    let memory = FlatMemory::new(0, 0x1000_0000);
    let mut cpu = AArch64Cpu::new(config, Box::new(memory));
    cpu.write_memory(0, &insn.to_le_bytes()).unwrap();

    assert!(
        matches!(cpu.step(), Err(ArmError::InvalidExceptionLevel(0))),
        "MRS CLIDR_EL1 should be privileged at EL0"
    );
}
#[test]
fn test_el0_pstate_immediate_controls_continue() {
    let mut config = AArch64Config::default();
    config.initial_el = 0;

    for (name, insn, expected_ssbs, expected_tco) in [
        ("msr_ssbs_0", 0xD503403Fu32, false, true),
        ("msr_ssbs_1", 0xD503413Fu32, true, true),
        ("msr_tco_0", 0xD503409Fu32, true, false),
        ("msr_tco_1", 0xD503419Fu32, true, true),
    ] {
        let memory = FlatMemory::new(0, 0x1000_0000);
        let mut cpu = AArch64Cpu::new(config.clone(), Box::new(memory));
        cpu.ssbs = true;
        cpu.tco = true;
        cpu.write_memory(0, &insn.to_le_bytes()).unwrap();

        assert!(
            matches!(cpu.step(), Ok(CpuExit::Continue)),
            "{name} should execute at EL0"
        );
        assert_eq!(cpu.ssbs, expected_ssbs, "{name} should update PSTATE.SSBS");
        assert_eq!(cpu.tco, expected_tco, "{name} should update PSTATE.TCO");
        assert_eq!(cpu.get_pc(), 4, "{name} should advance PC");
    }
}
#[test]
fn test_el0_pstate_register_controls_continue() {
    fn msr(crm: u32, op2: u32, rt: u32) -> u32 {
        0xd510_0000 | (1 << 19) | (3 << 16) | (4 << 12) | (crm << 8) | (op2 << 5) | rt
    }

    let mut config = AArch64Config::default();
    config.initial_el = 0;

    for (name, insn, value, expected_ssbs, expected_tco) in [
        ("msr_ssbs_x0_clear", msr(2, 6, 0), 0, false, true),
        ("msr_ssbs_x0_set", msr(2, 6, 0), 1 << 12, true, true),
        ("msr_tco_x0_clear", msr(2, 7, 0), 0, true, false),
        ("msr_tco_x0_set", msr(2, 7, 0), 1 << 25, true, true),
        ("msr_ssbs_xzr_clear", msr(2, 6, 31), 1 << 12, false, true),
        ("msr_tco_xzr_clear", msr(2, 7, 31), 1 << 25, true, false),
    ] {
        let memory = FlatMemory::new(0, 0x1000_0000);
        let mut cpu = AArch64Cpu::new(config.clone(), Box::new(memory));
        cpu.ssbs = true;
        cpu.tco = true;
        cpu.set_x(0, value);
        cpu.write_memory(0, &insn.to_le_bytes()).unwrap();

        assert!(
            matches!(cpu.step(), Ok(CpuExit::Continue)),
            "{name} should execute at EL0"
        );
        assert_eq!(cpu.ssbs, expected_ssbs, "{name} should update PSTATE.SSBS");
        assert_eq!(cpu.tco, expected_tco, "{name} should update PSTATE.TCO");
        assert_eq!(cpu.get_pc(), 4, "{name} should advance PC");
    }
}
#[test]
fn test_el0_drps_traps() {
    let mut config = AArch64Config::default();
    config.initial_el = 0;

    let insn = 0xD6BF03E0u32; // DRET/DRPS
    let memory = FlatMemory::new(0, 0x1000_0000);
    let mut cpu = AArch64Cpu::new(config, Box::new(memory));
    cpu.write_memory(0, &insn.to_le_bytes()).unwrap();

    assert!(
        matches!(cpu.step(), Err(ArmError::InvalidExceptionLevel(0))),
        "DRET/DRPS should be privileged at EL0"
    );
}
#[test]
fn test_el0_eret_traps() {
    let mut config = AArch64Config::default();
    config.initial_el = 0;

    let insn = 0xD69F03E0u32; // ERET
    let memory = FlatMemory::new(0, 0x1000_0000);
    let mut cpu = AArch64Cpu::new(config, Box::new(memory));
    cpu.write_memory(0, &insn.to_le_bytes()).unwrap();

    assert!(
        matches!(cpu.step(), Err(ArmError::InvalidExceptionLevel(0))),
        "ERET should be privileged at EL0"
    );
}
// Regression for issue #39: unprivileged load/stores must perform their
// permission checks as EL0 accesses when run at EL1, unless PSTATE.UAO
// explicitly overrides that behavior.
#[test]
fn issue_39_unprivileged_access_uses_el0_permission_checks() {
    let (mut cpu, data_va) = create_issue_39_cpu();

    // Privileged (EL1) access succeeds...
    assert_eq!(
        cpu.mem_read_u64(data_va).unwrap(),
        0xCAFE_F00D_DEAD_BEEF,
        "EL1 privileged access to an AP=00 page is allowed"
    );
    // ...unprivileged (EL0) access to the same page must fault, even at EL1.
    assert!(
        is_permission_error(cpu.mem_read_u64_unprivileged(data_va)),
        "unprivileged access to an EL0-no-access page must fault even at EL1"
    );

    cpu.uao = true;
    assert_eq!(
        cpu.mem_read_u64_unprivileged(data_va).unwrap(),
        0xCAFE_F00D_DEAD_BEEF,
        "UAO lets EL1 unprivileged accesses use privileged permissions"
    );
}
#[test]
fn issue_187_el0_cannot_forge_uao_or_pan() {
    let mut cpu = create_test_cpu();
    cpu.current_el = 0;

    let msr_uao_1 = msr_imm_pstate(0, 0b011, 1);
    assert!(matches!(
        cpu.exec_system(msr_uao_1),
        Err(ArmError::UndefinedInstruction(insn)) if insn == msr_uao_1
    ));
    assert!(!cpu.uao);

    let msr_pan_1 = msr_imm_pstate(0, 0b100, 1);
    assert!(matches!(
        cpu.exec_system(msr_pan_1),
        Err(ArmError::UndefinedInstruction(insn)) if insn == msr_pan_1
    ));
    assert!(!cpu.pan);
}
#[test]
fn issue_187_exception_entry_clears_uao_until_eret() {
    let mut cpu = create_test_cpu();
    cpu.current_el = 0;
    cpu.uao = true;
    cpu.pc = 0x4000;
    cpu.sysregs.el1.vbar = 0x1000;

    cpu.take_exception(1, ExceptionType::Synchronous, SyndromeRegister::new())
        .unwrap();

    assert_eq!(cpu.current_el, 1);
    assert!(!cpu.uao, "exception entry must clear PSTATE.UAO");
    assert_eq!(cpu.pc, 0x1400);

    let (_, _, saved_el, _, _, _, saved_uao, _, _, _, _, _) = parse_spsr(cpu.sysregs.el1.spsr);
    assert_eq!(saved_el, 0);
    assert!(saved_uao, "SPSR must still preserve the old UAO bit");

    assert_eq!(cpu.exception_return().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.current_el, 0);
    assert!(cpu.uao, "ERET restores UAO from SPSR");
    assert_eq!(cpu.pc, 0x4000);
}

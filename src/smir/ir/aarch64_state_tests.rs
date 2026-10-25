//! Full keyed state is explicit, banked, and preserved across SMIR adapters.

use super::context::{Aarch64RegState, ArchRegState, SmirContext};
use super::types::{ArchReg, ArmReg};
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use crate::isa::arm::common::{
    features::ArmFeatures, memory::FlatMemory, sysreg::Aarch64SysRegEncoding,
};
use crate::vm::vcpu::{Aarch64CpuState, Aarch64Registers};

fn state() -> Aarch64CpuState {
    let cpu = AArch64Cpu::new(
        AArch64Config {
            features: ArmFeatures::armv8_3_base(),
            gic_config: None,
            ..Default::default()
        },
        Box::new(FlatMemory::new(0, 0x1000)),
    );
    let mut sregs = cpu.export_sregs();
    sregs.sp_el0 = 0x1000;
    sregs.sp_el1 = 0x2000;
    sregs.execution.as_mut().unwrap().sp_el2 = 0x3000;
    sregs.execution.as_mut().unwrap().sp_el3 = 0x4000;
    Aarch64CpuState {
        regs: Aarch64Registers {
            sp: 0x2000,
            pstate: 0xa000_03c5,
            ..Default::default()
        },
        sregs,
    }
}

#[test]
fn pauth_smir_state_roundtrip_preserves_every_bank_and_full_pstate() {
    let original = state();
    let mut registers = Aarch64RegState::from_cpu_state(&original).unwrap();
    assert_eq!(
        crate::codec::serialize(&registers.to_cpu_state().unwrap()).unwrap(),
        crate::codec::serialize(&original).unwrap()
    );
    for (pstate, expected) in [(9, 0x3000), (13, 0x4000), (0, 0x1000), (5, 0x2000)] {
        assert!(registers.set_pstate_value(pstate));
        assert_eq!(registers.sp, expected);
        assert_eq!(registers.pstate_bits(), pstate);
    }
    registers.set_sp_value(0x2500);
    registers.set_pstate_value(9);
    assert_eq!(registers.sp_bank(1), Some(0x2500));
    let before = crate::codec::serialize(&registers.to_cpu_state().unwrap()).unwrap();
    for invalid in [1, 2, 0x14, 0x16, 1 << 63] {
        assert!(!registers.set_pstate_value(invalid));
        assert_eq!(
            crate::codec::serialize(&registers.to_cpu_state().unwrap()).unwrap(),
            before
        );
    }
}

#[test]
fn pauth_smir_state_sysreg_keys_and_legacy_control_overlay_are_authoritative() {
    let mut registers = Aarch64RegState::from_cpu_state(&state()).unwrap();
    for (index, (crm, op2)) in [
        (1, 0),
        (1, 1),
        (1, 2),
        (1, 3),
        (2, 0),
        (2, 1),
        (2, 2),
        (2, 3),
        (3, 0),
        (3, 1),
    ]
    .into_iter()
    .enumerate()
    {
        let encoded = Aarch64SysRegEncoding::new(3, 0, 2, crm, op2).encode();
        let value = 0x1234_0000_0000_0000 | index as u64;
        assert!(registers.write_system_register(encoded, value));
        assert_eq!(registers.read_system_register(encoded), Some(value));
    }
    let environment = registers.pauth_environment().unwrap();
    for (index, key) in [
        environment.keys.ia,
        environment.keys.ib,
        environment.keys.da,
        environment.keys.db,
        environment.keys.ga,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(key.lo, 0x1234_0000_0000_0000 | (2 * index) as u64);
        assert_eq!(key.hi, 0x1234_0000_0000_0000 | (2 * index + 1) as u64);
    }
    let sctlr = Aarch64SysRegEncoding::new(3, 0, 1, 0, 0).encode();
    assert!(registers.write_system_register(sctlr, 1 << 31));
    assert_eq!(
        registers.pauth_environment().unwrap().controls.sctlr[1],
        1 << 31
    );
    assert_eq!(registers.read_system_register(sctlr), Some(1 << 31));
}

#[test]
fn pauth_smir_state_missing_keys_and_unknown_fetch_metadata_do_not_default() {
    let mut incomplete = state();
    incomplete.sregs.execution = None;
    assert!(Aarch64RegState::from_cpu_state(&incomplete).is_err());
    assert!(Aarch64RegState::default().pauth_environment().is_none());
    let mut registers = Aarch64RegState::from_cpu_state(&state()).unwrap();
    assert_eq!(registers.guarded_instruction(), Some(false));
    registers.system.as_mut().unwrap().sctlr_el1 |= 1;
    assert_eq!(registers.guarded_instruction(), None);
    registers.instruction_guarded = Some(true);
    assert_eq!(registers.guarded_instruction(), Some(true));
}

#[test]
fn pauth_smir_state_architectural_views_keep_flags_and_current_sp_coherent() {
    let mut context = SmirContext::new_aarch64();
    context.arch_regs = ArchRegState::Aarch64(Aarch64RegState::from_cpu_state(&state()).unwrap());
    context.write_arch_reg(ArchReg::Arm(ArmReg::Pstate), 0xb000_0c09);
    assert_eq!(
        context.read_arch_reg(ArchReg::Arm(ArmReg::Nzcv)),
        0xb000_0000
    );
    assert_eq!(
        context.read_arch_reg(ArchReg::Arm(ArmReg::Pstate)),
        0xb000_0c09
    );
    context.write_arch_reg(ArchReg::Arm(ArmReg::SpEl(2)), 0x3500);
    assert_eq!(context.read_arch_reg(ArchReg::Arm(ArmReg::Sp)), 0x3500);
    context.write_arch_reg(ArchReg::Arm(ArmReg::Sp), 0x3600);
    assert_eq!(context.read_arch_reg(ArchReg::Arm(ArmReg::SpEl(2))), 0x3600);
}

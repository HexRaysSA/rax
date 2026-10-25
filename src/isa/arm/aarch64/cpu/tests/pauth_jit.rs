//! Actual CPU JIT admission, dynamic keys, counters and precise fault delivery.

use super::pauth_keyed::keyed_cpu;
use super::*;
use crate::isa::arm::aarch64::pauth::{PauthAlgorithm, PauthProfile};

fn forms() -> Vec<u32> {
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
    words.extend((0..=17).map(|opcode| 0xdac1_03e0 | (opcode << 10)));
    words.extend(
        [7, 8, 10, 12, 14, 24, 25, 26, 27, 28, 29, 30, 31]
            .map(|immediate| 0xd503_201f | (immediate << 5)),
    );
    assert_eq!(words.len(), 46);
    words
}

fn install(cpu: &mut AArch64Cpu) -> std::sync::Arc<JitRegion> {
    let region = std::sync::Arc::new(
        cpu.jit_compile_region()
            .expect("compile exact PAuth region"),
    );
    assert!(region.pauth_instruction.is_some());
    cpu.jit
        .cache
        .insert((cpu.pc, cpu.jit_mode_tag()), Some(region.clone()));
    region
}

fn assert_state(actual: &AArch64Cpu, expected: &AArch64Cpu) {
    assert_eq!(actual.x, expected.x);
    assert_eq!(actual.sp_el, expected.sp_el);
    assert_eq!(actual.pc, expected.pc);
    assert_eq!(actual.pstate_bits(), expected.pstate_bits());
    assert_eq!(actual.v, expected.v);
    assert_eq!(actual.fpcr, expected.fpcr);
    assert_eq!(actual.fpsr, expected.fpsr);
    assert_eq!(actual.event_register, expected.event_register);
    assert_eq!(actual.insn_count, expected.insn_count);
    assert_eq!(actual.cycle_count, expected.cycle_count);
    assert_eq!(
        crate::codec::serialize(&actual.export_sregs()).unwrap(),
        crate::codec::serialize(&expected.export_sregs()).unwrap()
    );
}

#[test]
fn pauth_jit_system_step_all_forms_algorithms_profiles_and_features_match_direct() {
    let mut cases = 0;
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for enabled in [false, true] {
                for raw in forms() {
                    let make = || {
                        let mut cpu = keyed_cpu(raw, algorithm, profile);
                        cpu.config
                            .features
                            .set(ArmFeatures::PACA | ArmFeatures::PACG, enabled);
                        cpu.configure_pauth(cpu.config.pauth);
                        cpu.set_x(1, 1);
                        cpu.nzcv = 10;
                        cpu.btype = 3;
                        cpu.event_register = true;
                        cpu
                    };
                    let mut direct = make();
                    direct.jit.disabled = true;
                    let mut native = make();
                    install(&mut native);
                    let expected = direct.step_system_with_fault_exit();
                    let actual = native.step_system_with_fault_exit();
                    assert_eq!(
                        format!("{actual:?}"),
                        format!("{expected:?}"),
                        "{raw:#x} {algorithm:?} {profile:?} enabled={enabled}"
                    );
                    assert_eq!(
                        native.jit.pauth_native_runs, 1,
                        "{raw:#x} {algorithm:?} {profile:?} enabled={enabled}"
                    );
                    assert!(native.jit.native_fault.is_none());
                    assert_state(&native, &direct);
                    assert_eq!(native.sysregs.cntpct_el0, 16);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 736);
}

#[test]
fn pauth_jit_auth_fault_is_delivered_once_with_exact_saved_pc_pstate_and_syndrome() {
    let mut direct = keyed_cpu(
        0xdac1_1020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    let mut native = keyed_cpu(
        0xdac1_1020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    for cpu in [&mut direct, &mut native] {
        cpu.set_x(0, 0x1230);
        cpu.set_x(1, 0x4567);
        cpu.sysregs.el1.vbar = 0x8000;
        cpu.nzcv = 10;
        cpu.btype = 3;
    }
    direct.jit.disabled = true;
    install(&mut native);
    direct.step_system().unwrap();
    native.step_system().unwrap();
    assert_state(&native, &direct);
    assert_eq!(native.sysregs.el1.esr, (0x1c << 26) | (1 << 25));
    assert_eq!(native.sysregs.el1.elr, 0);
    assert_eq!(native.pc, 0x8200);
    assert_eq!(native.insn_count, 0);
    assert_eq!(native.jit.pauth_native_runs, 1);
}

#[test]
fn pauth_jit_reads_dynamic_keys_and_refuses_stale_instruction_bytes() {
    let mut cpu = keyed_cpu(
        0xdac1_0020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    cpu.set_x(1, 1);
    let region = install(&mut cpu);
    assert!(cpu.jit_run_region(&region));
    assert_eq!(cpu.get_x(0), 0xf916_0000_0000_0000);
    cpu.set_pc(0);
    cpu.set_x(0, 0);
    let mut keys = cpu.pauth_keys();
    keys.ia.lo = 1;
    keys.ia.hi = 2;
    cpu.set_pauth_keys(keys);
    assert!(cpu.jit_run_region(&region));
    assert_eq!(cpu.get_x(0), 0xd733_0000_0000_0000); // Independent QEMU vector.
    assert_eq!(cpu.jit.pauth_native_runs, 2);
    cpu.set_pc(0);
    cpu.set_x(0, 0x1230);
    cpu.write_memory(0, &0xd503_201fu32.to_le_bytes()).unwrap();
    assert!(!cpu.jit_run_region(&region));
    assert_eq!(cpu.get_x(0), 0x1230);
    assert_eq!(cpu.get_pc(), 0);
    assert_eq!(cpu.jit.pauth_native_runs, 2);
}

#[test]
fn pauth_jit_promotion_preserves_one_retirement_and_16_counter_ticks_per_system_step() {
    assert!(
        std::env::var_os("RAX_NO_JIT").is_none(),
        "native promotion proof requires a JIT-enabled test environment"
    );
    let mut cpu = keyed_cpu(
        0xdac1_0020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    cpu.set_x(1, 1);
    cpu.write_memory(4, &0x17ff_ffffu32.to_le_bytes()).unwrap(); // B 0.
    cpu.set_pc(4);
    cpu.jit.hot.insert(0, A64_JIT_HOT_THRESHOLD - 1);
    cpu.step_system().unwrap();
    assert_eq!(cpu.pc, 0);
    assert_eq!(cpu.get_x(0), 0);
    assert_eq!(cpu.insn_count, 1);
    assert_eq!(cpu.sysregs.cntpct_el0, 16);
    assert_eq!(cpu.jit.pauth_native_runs, 0);
    assert!(cpu.jit_lookup(0).is_some());
    cpu.step_system().unwrap();
    assert_eq!(cpu.pc, 4);
    assert_eq!(cpu.get_x(0), 0xf916_0000_0000_0000);
    assert_eq!(cpu.insn_count, 2);
    assert_eq!(cpu.cycle_count, 2);
    assert_eq!(cpu.sysregs.cntpct_el0, 32);
    assert_eq!(cpu.jit.pauth_native_runs, 1);
    assert!(cpu.jit_lookup(0).is_some());
}

#[test]
fn pauth_jit_authenticated_call_preserves_an_aliased_guest_link_target() {
    use crate::isa::arm::aarch64::pauth::PauthKeyKind;
    let make = || {
        let mut cpu = keyed_cpu(
            0xd73f_0bdf,
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
        );
        cpu.set_current_sp(0x200);
        let signed = cpu
            .pauth_value(0x800, 0x200, PauthKeyKind::Ia, false, false)
            .unwrap();
        cpu.set_x(30, signed);
        cpu
    };
    let mut direct = make();
    direct.jit.disabled = true;
    let mut native = make();
    install(&mut native);
    direct.step_system().unwrap();
    native.step_system().unwrap();
    assert_state(&native, &direct);
    assert_eq!(native.pc, 0x800);
    assert_eq!(native.get_x(30), 4);
    assert_eq!(native.btype, 2);
    assert_eq!(native.jit.pauth_native_runs, 1);
}

#[test]
fn pauth_jit_vhe_tagged_load_fault_retains_far_stage_level_and_exception_target() {
    use crate::isa::arm::aarch64::pauth::PauthKeyKind;
    for el in [0, 2] {
        for fault_exit in [false, true] {
            for pointer in [0xab00_0000_0000_1000, 0xabff_0000_0000_1000] {
                let make = || {
                    let mut cpu = super::pauth_regime::host_cpu(el);
                    let signed = cpu
                        .pauth_value(pointer, 0, PauthKeyKind::Da, false, false)
                        .unwrap();
                    cpu.set_x(0, signed);
                    cpu
                };
                let mut direct = make();
                direct.jit.disabled = true;
                let mut native = make();
                install(&mut native);
                let expected = if fault_exit {
                    direct.step_system_with_fault_exit()
                } else {
                    direct.step_system()
                };
                let actual = if fault_exit {
                    native.step_system_with_fault_exit()
                } else {
                    native.step_system()
                };
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                if fault_exit {
                    let Err(ArmError::MemoryError(info)) = actual else {
                        panic!("missing precise fault")
                    };
                    assert_eq!(info.address, pointer);
                    assert_eq!(info.fault_type, MemoryFaultType::Translation);
                    assert!(!info.stage2);
                } else {
                    assert_eq!(native.sysregs.el2.far, pointer);
                    assert_eq!(native.sysregs.el2.elr, 0x20);
                    assert_eq!(native.sysregs.el2.esr & 0x3f, 7); // Translation fault, level 3.
                    assert_eq!(native.current_el, 2);
                }
                assert_state(&native, &direct);
                assert_eq!(native.jit.pauth_native_runs, 1);
                assert_eq!(native.insn_count, 0);
            }
        }
    }
}

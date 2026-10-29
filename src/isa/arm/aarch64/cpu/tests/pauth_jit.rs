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
    assert_eq!(actual.event_pending(), expected.event_pending());
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
                        cpu.set_event();
                        cpu
                    };
                    let mut direct = make();
                    direct.execution.disabled = true;
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
                        native.execution.pauth_native_runs, 1,
                        "{raw:#x} {algorithm:?} {profile:?} enabled={enabled}"
                    );
                    assert!(native.execution.native_fault.is_none());
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
    direct.execution.disabled = true;
    install(&mut native);
    direct.step_system().unwrap();
    native.step_system().unwrap();
    assert_state(&native, &direct);
    assert_eq!(native.sysregs.el1.esr, (0x1c << 26) | (1 << 25));
    assert_eq!(native.sysregs.el1.elr, 0);
    assert_eq!(native.pc, 0x8200);
    assert_eq!(native.insn_count, 0);
    assert_eq!(native.execution.pauth_native_runs, 1);
}

fn pending_native_authentication_fault() -> AArch64Cpu {
    let mut cpu = keyed_cpu(
        0xdac1_1020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    cpu.set_x(0, 0x1230);
    cpu.set_x(1, 0x4567);
    cpu.sysregs.el1.vbar = 0x8000;
    // Match the system entry's existing 16-tick advance before native entry.
    cpu.tick_system(16);
    let region = install(&mut cpu);
    assert!(cpu.jit_run_region(&region));
    assert!(matches!(
        cpu.execution.native_fault,
        Some(ArmError::ArchitecturalException { ec: 0x1c, .. })
    ));
    // A resumed CPU must deliver the already-produced event. Re-executing the
    // instruction bytes can no longer reproduce it after this replacement.
    cpu.write_memory(0, &0xd503_201fu32.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn pending_native_fault_survives_cache_policy_changes_and_all_interpreter_entries() {
    for clear_cache in [false, true] {
        for entry in ["system", "user", "direct"] {
            let mut cpu = pending_native_authentication_fault();
            let expected = format!("{:?}", cpu.execution.native_fault.as_ref().unwrap());
            if clear_cache {
                cpu.clear_jit_cache();
            }
            cpu.set_jit_enabled(false);
            let before = (
                cpu.pc,
                cpu.insn_count,
                cpu.cycle_count,
                cpu.sysregs.cntpct_el0,
            );
            let result = match entry {
                "system" => cpu.step_system_interpreted(true),
                "user" => cpu.step_user_pauth(false),
                "direct" => cpu.step(),
                _ => unreachable!(),
            };
            let error = result.expect_err("pending native event must precede the replacement NOP");
            assert_eq!(
                format!("{error:?}"),
                expected,
                "{entry} clear={clear_cache}"
            );
            assert_eq!(
                (
                    cpu.pc,
                    cpu.insn_count,
                    cpu.cycle_count,
                    cpu.sysregs.cntpct_el0
                ),
                before,
                "{entry} clear={clear_cache}"
            );
            assert!(cpu.execution.native_fault.is_none());
            assert_eq!(
                cpu.step_system_interpreted(true).unwrap(),
                CpuExit::Continue
            );
            assert_eq!(cpu.pc, 4);
            assert_eq!(cpu.insn_count, before.1 + 1);
            assert_eq!(cpu.sysregs.cntpct_el0, before.3 + 16);
        }
    }
}

#[test]
fn pending_native_fault_vectors_before_another_system_tick_or_instruction() {
    let mut cpu = pending_native_authentication_fault();
    let before = (cpu.insn_count, cpu.cycle_count, cpu.sysregs.cntpct_el0);
    cpu.clear_jit_cache();
    assert_eq!(
        cpu.step_system_interpreted(false).unwrap(),
        CpuExit::Continue
    );
    assert_eq!(cpu.pc, 0x8200);
    assert_eq!(cpu.sysregs.el1.elr, 0);
    assert_eq!(cpu.sysregs.el1.esr, (0x1c << 26) | (1 << 25));
    assert_eq!(
        (cpu.insn_count, cpu.cycle_count, cpu.sysregs.cntpct_el0),
        before
    );
    assert!(cpu.execution.native_fault.is_none());
}

#[test]
fn explicit_host_frontier_replacement_cancels_the_old_native_fault() {
    for replace in ["pc", "pstate", "sregs", "reset"] {
        let mut cpu = pending_native_authentication_fault();
        match replace {
            "pc" => cpu.set_pc(0),
            "pstate" => cpu.set_pstate_bits(cpu.pstate_bits()).unwrap(),
            "sregs" => cpu.import_sregs(&cpu.export_sregs()).unwrap(),
            "reset" => cpu.reset(),
            _ => unreachable!(),
        }
        assert!(cpu.execution.native_fault.is_none(), "{replace}");
    }
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
    assert_eq!(cpu.execution.pauth_native_runs, 2);
    cpu.set_pc(0);
    cpu.set_x(0, 0x1230);
    cpu.write_memory(0, &0xd503_201fu32.to_le_bytes()).unwrap();
    assert!(!cpu.jit_run_region(&region));
    assert_eq!(cpu.get_x(0), 0x1230);
    assert_eq!(cpu.get_pc(), 0);
    assert_eq!(cpu.execution.pauth_native_runs, 2);
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
    assert_eq!(cpu.execution.pauth_native_runs, 0);
    cpu.step_system().unwrap();
    assert_eq!(cpu.pc, 4);
    assert_eq!(cpu.get_x(0), 0xf916_0000_0000_0000);
    assert_eq!(cpu.insn_count, 2);
    assert_eq!(cpu.cycle_count, 2);
    assert_eq!(cpu.sysregs.cntpct_el0, 32);
    assert_eq!(cpu.execution.pauth_native_runs, 1);
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
    direct.execution.disabled = true;
    let mut native = make();
    install(&mut native);
    direct.step_system().unwrap();
    native.step_system().unwrap();
    assert_state(&native, &direct);
    assert_eq!(native.pc, 0x800);
    assert_eq!(native.get_x(30), 4);
    assert_eq!(native.btype, 2);
    assert_eq!(native.execution.pauth_native_runs, 1);
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
                direct.execution.disabled = true;
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
                assert_eq!(native.execution.pauth_native_runs, 1);
                assert_eq!(native.insn_count, 0);
            }
        }
    }
}

#[derive(Debug)]
struct EventDuringLoad {
    inner: Box<dyn ArmMemory>,
    event: std::sync::Arc<std::sync::atomic::AtomicBool>,
    loads: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ArmMemory for EventDuringLoad {
    fn mark_exclusive(&mut self, address: u64, size: u8) {
        self.inner.mark_exclusive(address, size);
    }
    fn check_exclusive(&mut self, address: u64, size: u8) -> bool {
        self.inner.check_exclusive(address, size)
    }
    fn clear_exclusive(&mut self) {
        self.inner.clear_exclusive();
    }
    fn register_mmio(&mut self, base: u64, size: u64, handler: Box<dyn MmioHandler>) {
        self.inner.register_mmio(base, size, handler);
    }
    fn unregister_mmio(&mut self, base: u64) {
        self.inner.unregister_mmio(base);
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> MemResult<()> {
        self.inner.read(address, bytes)?;
        if address == 0x200 {
            self.event.store(true, std::sync::atomic::Ordering::Release);
            self.loads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> MemResult<()> {
        self.inner.write(address, bytes)
    }

    fn fetch(&self, address: u64, bytes: &mut [u8]) -> MemResult<()> {
        self.inner.fetch(address, bytes)
    }
}

#[test]
fn pauth_native_load_preserves_a_peer_event_received_after_frame_export() {
    use crate::isa::arm::aarch64::pauth::PauthKeyKind;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    let raw = 0xf820_0fe6; // LDRAA X6,[SP,#0]!
    let mut cpu = keyed_cpu(raw, PauthAlgorithm::Qarma5, PauthProfile::FpacCombine);
    cpu.write_memory(0x200, &0x0123_4567_89ab_cdefu64.to_le_bytes())
        .unwrap();
    let signed = cpu
        .pauth_value(0x200, 0, PauthKeyKind::Da, false, false)
        .unwrap();
    cpu.set_current_sp(signed);
    let region = install(&mut cpu);
    let loads = Arc::new(AtomicU64::new(0));
    let inner = std::mem::replace(&mut cpu.memory, Box::new(FlatMemory::new(0, 0)));
    cpu.memory = Box::new(EventDuringLoad {
        inner,
        event: cpu.event_register_handle(),
        loads: loads.clone(),
    });
    assert!(!cpu.event_pending());
    assert!(cpu.jit_run_pauth_instruction(&region, raw));
    assert_eq!(loads.load(Ordering::Relaxed), 1);
    assert_eq!(cpu.execution.pauth_native_runs, 1);
    assert!(cpu.execution.native_fault.is_none());
    assert_eq!((cpu.pc, cpu.insn_count), (4, 1));
    assert_eq!(cpu.get_x(6), 0x0123_4567_89ab_cdef);
    assert_eq!(cpu.current_sp(), 0x200);
    assert!(cpu.event_pending());
}

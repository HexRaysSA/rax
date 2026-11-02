//! Actual clock-bearing file admission before and after VMM construction.
use super::*;
use crate::config::CliConfig;
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::timing::{ClockMode, TimingContext};

#[test]
fn retired_file_constructor_must_honor_the_saved_clock_before_device_construction() {
    let mut fixture = super::execution_tests::Fixture::with_memory(1, 128 << 20);
    // Reach the already-existing clock-bearing producer on the old engine.
    // No guest instruction or timer executes through this fixture-only binding.
    fixture.vm.timing_context = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    let path = std::env::temp_dir().join(format!(
        "rax-retired-constructor-{}.rxc",
        std::process::id()
    ));
    saved.save(&path).unwrap();
    let loaded = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    drop(fixture); // The new machine must not reopen the source kernel.
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert_eq!(target.timing_context.mode(), ClockMode::Retired);
    assert_eq!(
        target.timing_context.checkpoint_state(),
        *loaded.clock().unwrap()
    );
}

use crate::config::{ArchKind, BackendKind, MemorySize};
use crate::vm::timing::ClockState;
use std::path::PathBuf;
use vm_memory::{Bytes, GuestAddress};

struct RemoveFile(PathBuf);
impl Drop for RemoveFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn configuration(count: u8) -> (VmConfig, CpuState) {
    let fixture = super::execution_tests::Fixture::with_memory(count, 128 << 20);
    let config = VmConfig::from_checkpoint(
        fixture.vm.checkpoint_config.clone(),
        CliConfig::default(),
        fixture.vm.guest_mem.size(),
    )
    .unwrap();
    let state = fixture.vm.vcpus[0].get_state().unwrap();
    (config, state) // The fixture removes its kernel before the caller runs.
}
fn image(vm: &Vmm) -> Vec<u8> {
    crate::codec::serialize(
        &vm.vcpus
            .iter()
            .map(|cpu| {
                (
                    cpu.get_state().unwrap(),
                    cpu.capture_backend_context()
                        .unwrap()
                        .map(|context| (context.kind, context.data)),
                )
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
fn prepare(count: u8, phase: u8, wrap: bool) -> (Vmm, ClockState) {
    let (config, state) = configuration(count);
    let mut vm = Vmm::new_resume_with_clock(config, ClockMode::Retired).unwrap();
    let mut clock = vm.timing_context.checkpoint_state();
    clock.subnanosecond_quanta = phase;
    if wrap {
        clock.elapsed_nanos = u64::MAX - 1;
        clock.retired_units = u64::MAX - 1;
    }
    vm.timing_context.restore_checkpoint_state(&clock).unwrap();
    vm.coordinator.retired = clock.retired_units;
    let _scope = vm.timing_context.enter();
    for id in 0..usize::from(count) {
        let entry = 0x8000 + id as u64 * 0x100;
        let address = 0x7000 + id as u32 * 0x40;
        let mut code = Vec::new();
        for offset in [0u32, 8] {
            if offset != 0 {
                code.push(0x90); // NOP: second timestamp observes four retired units.
            }
            code.extend_from_slice(&[0x0f, 0x31]); // RDTSC
            code.push(0xa3); // MOV moffs32,EAX
            code.extend_from_slice(&(address + offset).to_le_bytes());
            code.extend_from_slice(&[0x89, 0x15]); // MOV [disp32],EDX
            code.extend_from_slice(&(address + offset + 4).to_le_bytes());
        }
        code.push(0xf4); // HLT is the eighth retired instruction.
        vm.guest_mem
            .memory()
            .write_slice(&code, GuestAddress(entry))
            .unwrap();
        let mut public = state.clone();
        let CpuState::X86_64(prior) = vm.vcpus[id].get_state().unwrap() else {
            panic!()
        };
        let CpuState::X86_64(cpu) = &mut public else {
            panic!()
        };
        cpu.regs.rip = entry;
        cpu.sregs.cr8 = prior.sregs.cr8;
        vm.vcpus[id].set_state(&public).unwrap();
        let mut apic = vm.local_apics[id].lock().unwrap();
        apic.write_register(0x3e0, 0xb); // Divide by one.
        apic.write_register(0x320, 1 << 16); // Mask IRQ; observe timer clock only.
        apic.write_register(0x380, 4096);
    }
    vm.coordinator.online.fill(true); // Prepared contexts, not guest AP startup.
    drop(_scope);
    (vm, clock)
}
fn turn(vm: &mut Vmm, expected: usize) {
    let result = vm.execute_turn().unwrap().unwrap();
    assert_eq!(result.cpu_index, expected);
    assert!(matches!(result.exit, VcpuExit::Hlt));
}
fn check(vm: &Vmm, initial: ClockState) {
    let count = vm.vcpus.len();
    let delta = 8 * count as u64;
    let state = vm.timing_context.checkpoint_state();
    assert_eq!(
        state.retired_units,
        initial.retired_units.wrapping_add(delta)
    );
    assert_eq!(vm.coordinator.retired, state.retired_units);
    let quanta = u64::from(initial.subnanosecond_quanta) + delta;
    assert_eq!(
        state.elapsed_nanos,
        initial.elapsed_nanos.wrapping_add(quanta / 3)
    );
    assert_eq!(state.subnanosecond_quanta, (quanta % 3) as u8);
    for id in 0..count {
        assert_eq!(vm.vcpus[id].instruction_count(), 8);
        let mut raw = [0; 16];
        vm.guest_mem
            .memory()
            .read_slice(&mut raw, GuestAddress(0x7000 + id as u64 * 0x40))
            .unwrap();
        for offset in [0usize, 8] {
            let observed = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
            let expected = initial
                .retired_units
                .wrapping_add(8 * id as u64 + if offset == 0 { 0 } else { 4 });
            assert_eq!(observed, expected, "CPU{id} offset={offset}");
        }
        let expected = 4096 - (quanta / 3) as u32;
        assert_eq!(
            vm.local_apics[id].lock().unwrap().read_register(0x390),
            expected
        );
    }
}

#[test]
fn explicit_clock_selection_preserves_supported_and_unsupported_factory_boundaries() {
    let (config, _) = configuration(1);
    for arch in [
        ArchKind::X86_64,
        ArchKind::Aarch64,
        ArchKind::Armv7a,
        ArchKind::Armv8a32,
        ArchKind::CortexM,
        ArchKind::CortexR,
        ArchKind::Riscv64,
        ArchKind::Hexagon,
    ] {
        for mode in [ClockMode::Wall, ClockMode::Retired] {
            let mut selected = config.clone();
            selected.arch = arch;
            let result = Vmm::new_resume_with_clock(selected, mode);
            if matches!(arch, ArchKind::Armv8a32 | ArchKind::CortexR) {
                // Existing audit backlog: these selectors have no CPU factory.
                // Preserve an explicit rejection; they are not extra modes of
                // the implemented ARMv7/S3C producer.
                assert!(
                    matches!(result, Err(Error::Emulator(ref message)) if message == &format!("Unsupported architecture: {arch:?}"))
                );
                continue;
            }
            let vm = result.unwrap();
            assert_eq!(vm.timing_context.mode(), mode, "{arch:?}");
            assert!(vm.vcpus.iter().all(|cpu| cpu.supports_stepping()));
            if mode == ClockMode::Retired {
                assert_eq!(
                    vm.timing_context.checkpoint_state(),
                    TimingContext::with_mode(mode).checkpoint_state()
                );
            }
        }
    }
    assert_eq!(
        Vmm::new_resume(config).unwrap().timing_context.mode(),
        ClockMode::Wall
    );
}

#[test]
fn fresh_explicit_retired_constructor_loads_and_executes_a_real_aarch64_guest() {
    let (mut config, _) = configuration(1);
    config.arch = ArchKind::Aarch64;
    let kernel = RemoveFile(config.kernel.clone());
    let code: Vec<u8> = [0xd503201fu32, 0xd503207f]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    std::fs::write(&kernel.0, code).unwrap(); // NOP; WFI raw kernel.
    let mut vm = Vmm::new_with_clock(config, ClockMode::Retired).unwrap();
    assert_eq!(vm.timing_context.checkpoint_state().retired_units, 0);
    turn(&mut vm, 0);
    let clock = vm.timing_context.checkpoint_state();
    assert_eq!(
        (
            clock.elapsed_nanos,
            clock.retired_units,
            clock.subnanosecond_quanta
        ),
        (0, 2, 2)
    );
}

#[test]
fn explicit_native_retired_modes_reject_before_host_resources_or_kernel_access() {
    let (config, _) = configuration(1);
    assert!(!config.kernel.exists());
    for backend in [BackendKind::Kvm, BackendKind::Hvf] {
        let mut selected = config.clone();
        selected.backend = backend;
        selected.memory = MemorySize(u64::MAX);
        for fresh in [false, true] {
            let result = if fresh {
                Vmm::new_with_clock(selected.clone(), ClockMode::Retired)
            } else {
                Vmm::new_resume_with_clock(selected.clone(), ClockMode::Retired)
            };
            assert!(
                matches!(result, Err(Error::InvalidConfig(ref message)) if message == "retired VM clock requires the software backend")
            );
        }
    }
}

#[test]
fn actual_retired_files_preserve_three_phases_wrap_per_cpu_tsc_and_lapic_clock_identity() {
    for (count, phase, wrap) in [(1, 0, false), (2, 1, false), (4, 2, true)] {
        let (mut source, initial) = prepare(count, phase, wrap);
        std::thread::sleep(std::time::Duration::from_millis(3));
        assert_eq!(source.timing_context.checkpoint_state(), initial);
        turn(&mut source, 0);
        let saved = source
            .take_snapshot_bundle(source.coordinator.retired)
            .unwrap();
        let path = RemoveFile(std::env::temp_dir().join(format!(
            "rax-retired-file-{}-{count}.rxc",
            std::process::id()
        )));
        saved.save(&path.0).unwrap();
        let loaded = SnapshotBundle::load(&path.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        assert!(!config.kernel.exists());
        let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(
            target.timing_context.checkpoint_state(),
            source.timing_context.checkpoint_state()
        );
        assert_eq!(target.coordinator, source.coordinator);
        assert_eq!(image(&target), image(&source));
        let unrelated = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        unrelated.advance_retired(3_000_000_000).unwrap();
        let _foreign = unrelated.enter();
        for id in 1..usize::from(count) {
            turn(&mut source, id);
            std::thread::sleep(std::time::Duration::from_millis(1));
            turn(&mut target, id);
        }
        check(&source, initial);
        check(&target, initial);
        assert_eq!(image(&target), image(&source));
        assert_eq!(target.coordinator, source.coordinator);
        let before = target.timing_context.checkpoint_state();
        turn(&mut target, 0); // Waiting CPU: no fabricated time or retirement.
        assert_eq!(target.timing_context.checkpoint_state(), before);
    }
}

#[test]
fn retired_restoration_rejects_incomplete_or_inconsistent_timelines_before_mutation() {
    let (mut target, _) = prepare(1, 2, false);
    turn(&mut target, 0);
    let saved = target
        .take_snapshot_bundle(target.coordinator.retired)
        .unwrap();
    let path = RemoveFile(
        std::env::temp_dir().join(format!("rax-retired-admission-{}.rxc", std::process::id())),
    );
    saved.save(&path.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    for backend in [BackendKind::Kvm, BackendKind::Hvf] {
        let mut native = config.clone();
        native.backend = backend;
        assert!(
            native
                .validate_resume_bundle(&saved)
                .unwrap_err()
                .to_string()
                .contains("retired VM clock requires the software backend")
        );
    }
    let before = (
        image(&target),
        target.guest_mem.try_read_all().unwrap(),
        target.timing_context.checkpoint_state(),
        target.coordinator.clone(),
    );
    assert!(
        target
            .take_snapshot(0)
            .err()
            .unwrap()
            .to_string()
            .contains("complete snapshot bundle")
    );
    assert!(
        target
            .restore_snapshot(saved.base())
            .unwrap_err()
            .to_string()
            .contains("complete snapshot bundle")
    );
    for defect in 0..5 {
        let mut bad = SnapshotBundle::load(&path.0).unwrap();
        match defect {
            0 => {
                bad.take_execution();
            }
            1 => {
                bad.take_cpus();
            }
            2 => {
                bad.take_backend_contexts();
            }
            3 => {
                bad.take_clock();
            }
            4 => {
                let mut clock = *bad.clock().unwrap();
                clock.retired_units = clock.retired_units.wrapping_add(1);
                bad = bad.with_clock(clock).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            target.restore_snapshot_bundle(&bad).is_err(),
            "defect={defect}"
        );
        assert_eq!(image(&target), before.0);
        assert_eq!(target.guest_mem.try_read_all().unwrap(), before.1);
        assert_eq!(target.timing_context.checkpoint_state(), before.2);
        assert_eq!(target.coordinator, before.3);
    }
    let wall = Vmm::new_resume(config).unwrap();
    let wall_saved = wall.take_snapshot_bundle(0).unwrap();
    assert!(
        target
            .restore_snapshot_bundle(&wall_saved)
            .unwrap_err()
            .to_string()
            .contains("clock checkpoint mode does not match target")
    );
    assert_eq!(target.timing_context.checkpoint_state(), before.2);
    assert_eq!(image(&target), before.0);
    assert_eq!(target.guest_mem.try_read_all().unwrap(), before.1);
    target.timing_context.advance_retired(1).unwrap();
    assert!(
        target
            .take_snapshot_bundle(0)
            .unwrap_err()
            .to_string()
            .contains("clock and coordinator counts disagree")
    );
}

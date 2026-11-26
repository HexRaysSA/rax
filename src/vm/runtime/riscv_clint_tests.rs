//! CLINT behavior through the public VMM and complete checkpoint pipeline.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::timing::ClockMode;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};
#[path = "../../../tests/support/riscv_startup.rs"]
mod image;
#[path = "../../../tests/support/riscv_clint.rs"]
mod program;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    kernel: PathBuf,
    vm: Vmm,
}
impl Fixture {
    fn new(count: u8, wait: bool) -> Self {
        Self::with_clock(count, wait, ClockMode::Retired)
    }
    fn with_clock(count: u8, wait: bool, mode: ClockMode) -> Self {
        Self::with_code(count, program::program(count, wait), mode)
    }
    fn with_code(count: u8, code: Vec<u8>, mode: ClockMode) -> Self {
        Self::with_memory(count, code, mode, 128 << 20)
    }
    fn with_memory(count: u8, code: Vec<u8>, mode: ClockMode, bytes: u64) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-clint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, image::elf(&code, 0x1000, 0x1000)).unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Riscv64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                memory: Some(MemorySize(bytes)),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let vm = Vmm::new_with_clock(config, mode).unwrap();
        Self { kernel, vm }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(self.kernel.with_extension("rxc"));
    }
}
fn word(vm: &Vmm, address: u64) -> u32 {
    u32::from_le(
        vm.guest_mem
            .memory()
            .read_obj(GuestAddress(address))
            .unwrap(),
    )
}
fn assert_work(vm: &Vmm, count: u8) {
    for hart in 0..count {
        assert_eq!(
            word(vm, 0x80008100 + u64::from(hart) * 4),
            3,
            "hart {hart} must execute both interrupt handlers"
        );
    }
}
#[test]
fn actual_vmm_clint_software_and_timer_handlers_execute_on_every_hart() {
    let mut results = Vec::new();
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count, false);
        let result = fixture.vm.run();
        println!("CLINT {count} harts: {result:?}");
        if result.is_ok() {
            assert_work(&fixture.vm, count);
        }
        results.push(result.is_ok());
    }
    assert!(results.iter().all(|result| *result));
}

#[test]
fn clint_checkpoint_rejects_a_fully_offline_machine() {
    let mut rejected = Vec::new();
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count, false);
        assert_eq!(
            fixture.vm.coordinator.online,
            vec![true; usize::from(count)]
        );
        fixture.vm.coordinator.online.fill(false);
        let error = fixture.vm.take_snapshot_bundle(0).err();
        println!("CLINT checkpoint with all {count} harts offline: {error:?}");
        rejected.push(error.is_some_and(|error| error.to_string().contains("an online hart")));
    }
    assert_eq!(rejected, [true; 3]);
}

fn contexts(vm: &Vmm) -> Vec<Option<crate::vm::snapshot::BackendContext>> {
    vm.vcpus
        .iter()
        .map(|cpu| cpu.capture_backend_context().unwrap())
        .collect()
}

#[test]
fn wall_checkpoint_uses_one_mtime_and_publishes_due_inputs_before_guest_entry() {
    use crate::vm::snapshot::SnapshotBundle;

    const MTIME: u64 = 0x0200_bff8;
    const MTIMECMP: u64 = 0x0200_4000;
    const TICKS: u64 = 90_000;
    const SOFTWARE_SEIP: u64 = 1 << 9;
    const MTIP: u64 = 1 << 7;
    const MSIP: u64 = 1 << 3;

    let hart_timing = |state: &CpuState| {
        let CpuState::RiscV(hart) = state else {
            panic!("expected an RV64 hart");
        };
        let csr = |address| {
            hart.regs
                .csrs
                .iter()
                .find(|&&(n, _)| n == address)
                .unwrap()
                .1
        };
        (csr(0xc01), csr(0x344))
    };

    let mut source = Fixture::with_clock(4, false, ClockMode::Wall);
    let mut clock = source.vm.timing_context.checkpoint_state();
    clock.elapsed_nanos = 12_345_600;
    source
        .vm
        .timing_context
        .prepare_stopped_checkpoint_state(&clock)
        .unwrap()
        .commit();
    let platform = platform(&source.vm);
    platform.write(MTIME, &TICKS.to_le_bytes()).unwrap();
    platform.write(MTIMECMP + 8, &TICKS.to_le_bytes()).unwrap();
    platform.write(0x0200_0008, &1u32.to_le_bytes()).unwrap();
    let CpuState::RiscV(mut cpu) = source.vm.vcpus[3].get_state().unwrap() else {
        panic!("expected an RV64 hart");
    };
    cpu.regs.csrs = vec![(0x344, SOFTWARE_SEIP)];
    source.vm.vcpus[3].set_state(&CpuState::RiscV(cpu)).unwrap();
    let source_before = contexts(&source.vm);

    let captured = source.vm.take_snapshot_bundle(0).unwrap();
    let file = source.kernel.with_extension("rxc");
    captured.save(&file).unwrap();
    assert_eq!(source_before, contexts(&source.vm));
    let loaded = SnapshotBundle::load(&file).unwrap();
    assert_eq!(loaded.clock(), Some(&clock));
    let expected = [
        (TICKS, 0),
        (TICKS, MTIP),
        (TICKS, MSIP),
        (TICKS, SOFTWARE_SEIP),
    ];
    for (record, expected) in loaded.cpus().unwrap().entries().iter().zip(expected) {
        assert_eq!(hart_timing(&record.state), expected);
    }
    std::fs::remove_file(&source.kernel).unwrap();
    drop(source);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
    for (hart, expected) in restored.vcpus.iter().zip(expected) {
        assert_eq!(hart_timing(&hart.get_state().unwrap()), expected);
        assert_eq!(hart.instruction_count(), 0);
    }
    assert_eq!(
        contexts(&restored),
        loaded.backend_contexts().unwrap().entries()
    );
}

fn platform(vm: &Vmm) -> Arc<crate::backend::emulator::riscv::platform::Platform> {
    vm.vm
        .as_any()
        .downcast_ref::<crate::backend::emulator::EmulatorVm>()
        .unwrap()
        .riscv_platform()
        .unwrap()
}

#[test]
fn riscv_checkpoint_frontier_publishes_the_unentered_peers_timer() {
    let mut fixture = Fixture::with_code(2, [0x13, 0, 0, 0].repeat(320), ClockMode::Retired);
    let vm = &mut fixture.vm;
    vm.snapshot_config = Some(SnapshotConfig {
        at_instructions: vec![300],
        ..SnapshotConfig::default()
    });
    platform(vm)
        .write(0x0200_4008, &1u64.to_le_bytes())
        .unwrap();
    let CpuState::RiscV(mut peer) = vm.vcpus[1].get_state().unwrap() else {
        panic!("expected RV64 peer");
    };
    peer.regs.csrs = vec![(0x300, 0x8), (0x304, 0x80), (0x305, 0x1800)];
    vm.vcpus[1].set_state(&CpuState::RiscV(peer)).unwrap();

    assert!(vm.execute_turn().unwrap().is_none());
    assert_eq!(vm.coordinator.retired, 300);
    assert_eq!(vm.coordinator.cursor, 1);
    assert_eq!(vm.vcpus[0].instruction_count(), 300);
    assert_eq!(vm.vcpus[1].instruction_count(), 0);
    let CpuState::RiscV(peer) = vm.vcpus[1].get_state().unwrap() else {
        panic!("expected RV64 peer");
    };
    assert!(peer.regs.csrs.contains(&(0x344, 0x80)));

    vm.last_snapshot_insn = 300;
    assert!(vm.execute_turn().unwrap().is_none());
    assert_eq!(vm.coordinator.retired, 300);
    assert_eq!(vm.vcpus[1].instruction_count(), 0);
    assert_eq!(vm.vcpus[1].current_pc(), 0x1800);
}

#[test]
fn riscv_retirement_wrap_restarts_the_checkpoint_schedule_inside_a_turn() {
    let mut fixture = Fixture::with_code(1, [0x13, 0, 0, 0].repeat(320), ClockMode::Retired);
    let vm = &mut fixture.vm;
    vm.snapshot_config = Some(SnapshotConfig {
        at_instructions: vec![3],
        ..SnapshotConfig::default()
    });
    vm.last_snapshot_insn = u64::MAX - 10;
    vm.coordinator.retired = u64::MAX - 3;

    assert!(vm.execute_turn().unwrap().is_none());
    assert_eq!(vm.coordinator.retired, 3);
    assert_eq!(vm.last_snapshot_insn, 0);
    assert_eq!(vm.vcpus[0].instruction_count(), 7);
}

#[test]
fn idle_clock_file_preserves_riscv_wait_and_timer_wake_order() {
    use crate::vm::snapshot::SnapshotBundle;
    const BASE: u64 = 0x8000_8100;
    let results = |vm: &Vmm, count| {
        (0..count)
            .map(|hart| {
                u64::from_le(
                    vm.guest_mem
                        .memory()
                        .read_obj(GuestAddress(BASE + 8 * hart))
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    // Each hart writes MTIMECMP = 8 + 2*hart, then executes WFI with MTIE
    // set and global MIE clear. After recording rdtime it masks MTIE and
    // waits again. Entering the final illegal instruction is a failure.
    let code = [
        0xf1402573u32,
        0x08000293,
        0x30429073,
        0x02004337,
        0x00351393,
        0x00730333,
        0x00800293,
        0x00151393,
        0x007282b3,
        0x00533023,
        0x10500073,
        0xc01022f3,
        0x10001337,
        0x00331313,
        0x10030313,
        0x00730333,
        0x00730333,
        0x00730333,
        0x00730333,
        0x00533023,
        0x30401073,
        0x10500073,
        0xc0001073,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect::<Vec<_>>();
    for count in [1u8, 2, 4] {
        let mut source = Fixture::with_code(count, code.clone(), ClockMode::RetiredWithIdle);
        let harts = u64::from(count);
        for _ in 0..count {
            source.vm.execute_turn().unwrap();
        }
        assert_eq!(source.vm.coordinator.retired, 11 * harts);
        assert_eq!(results(&source.vm, harts), vec![0; usize::from(count)]);
        let saved = source.vm.take_snapshot_bundle(11 * harts).unwrap();
        assert!(
            saved
                .execution()
                .unwrap()
                .online()
                .iter()
                .all(|&online| online)
        );
        for record in saved.backend_contexts().unwrap().entries() {
            assert!(record.as_ref().unwrap().data.starts_with(b"RAXRV006"));
        }
        let file = source.kernel.with_extension("rxc");
        saved.save(&file).unwrap();
        let loaded = SnapshotBundle::load(&file).unwrap();
        std::fs::remove_file(&source.kernel).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(contexts(&restored), contexts(&source.vm));
        assert_eq!(restored.coordinator, source.vm.coordinator);
        for waking in 0..harts {
            for vm in [&mut source.vm, &mut restored] {
                let expected = (0..harts)
                    .map(|hart| if hart <= waking { 8 + 2 * hart } else { 0 })
                    .collect::<Vec<_>>();
                for _ in 0..harts {
                    vm.execute_turn().unwrap();
                    if results(vm, harts) == expected {
                        break;
                    }
                }
                assert_eq!(results(vm, harts), expected);
            }
            assert_eq!(contexts(&restored), contexts(&source.vm));
            assert_eq!(restored.coordinator, source.vm.coordinator);
            assert_eq!(
                restored.timing_context.checkpoint_state(),
                source.vm.timing_context.checkpoint_state()
            );
        }
        let before = restored.timing_context.checkpoint_state();
        assert_eq!(before.retired_units, 22 * harts);
        for record in contexts(&restored).iter().flatten() {
            assert!(record.data.starts_with(b"RAXRV006"));
        }
        for _ in 0..count {
            let turn = restored.execute_turn().unwrap().unwrap();
            assert!(matches!(turn.exit, VcpuExit::Hlt));
        }
        assert_eq!(restored.timing_context.checkpoint_state(), before);
    }
}

#[test]
fn pending_clint_file_resumes_new_interrupt_work_on_one_two_and_four_harts() {
    use crate::vm::snapshot::SnapshotBundle;
    for count in [1, 2, 4] {
        let mut source = Fixture::new(count, true);
        let expected_cursor = usize::from(count > 1);
        let mut ready = false;
        for _ in 0..128 {
            source.vm.execute_turn().unwrap();
            ready = word(&source.vm, 0x80008008) == 1
                && source.vm.coordinator.cursor == expected_cursor;
            if ready {
                break;
            }
        }
        assert!(ready, "all software interrupts must be sent before capture");
        for hart in 0..count {
            assert_eq!(word(&source.vm, 0x80008100 + u64::from(hart) * 4), 0);
            let signals = platform(&source.vm)
                .signals(u32::from(hart))
                .unwrap()
                .unwrap();
            assert!(
                signals.software && signals.timer,
                "both inputs pending on hart {hart}"
            );
        }
        let before = contexts(&source.vm);
        let saved = source
            .vm
            .take_snapshot_bundle(source.vm.coordinator.retired)
            .unwrap();
        let file = source.kernel.with_extension("rxc");
        saved.save(&file).unwrap();
        let loaded = SnapshotBundle::load(&file).unwrap();
        std::fs::remove_file(&source.kernel).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(contexts(&restored), before);
        assert_eq!(restored.coordinator, source.vm.coordinator);
        assert_eq!(
            platform(&restored).checkpoint().unwrap(),
            platform(&source.vm).checkpoint().unwrap()
        );
        for vm in [&mut source.vm, &mut restored] {
            vm.guest_mem
                .memory()
                .write_obj(1u32.to_le(), GuestAddress(0x80008004))
                .unwrap();
            vm.run().unwrap();
            assert_work(vm, count);
            for hart in 0..count {
                let signals = platform(vm).signals(u32::from(hart)).unwrap().unwrap();
                assert!(!signals.software && !signals.timer);
            }
        }
        assert_eq!(contexts(&source.vm), contexts(&restored));
        assert_eq!(source.vm.coordinator, restored.coordinator);
        assert_eq!(
            source.vm.timing_context.checkpoint_state(),
            restored.timing_context.checkpoint_state()
        );
    }
}
#[test]
fn incomplete_or_mismatched_clint_graph_rejects_before_any_publication() {
    let source = Fixture::new(4, true);
    let mut target = Fixture::new(4, true);
    target
        .vm
        .guest_mem
        .memory()
        .write_obj(0xa5a5a5a5u32, GuestAddress(0x80008004))
        .unwrap();
    let before = contexts(&target.vm);
    let before_controller = platform(&target.vm).checkpoint().unwrap();
    let before_clock = target.vm.timing_context.checkpoint_state();
    let mut saved = source.vm.take_snapshot_bundle(0).unwrap();
    let original_execution = saved.execution().unwrap().clone();
    let original_contexts = saved.backend_contexts().unwrap().entries().to_vec();
    let original_clock = saved.clock().unwrap().clone();
    for mutation in 0..7 {
        match mutation {
            0 => {
                saved.take_clock();
            }
            1 => {
                saved.take_backend_contexts();
            }
            2 => {
                let mut state = saved.take_execution().unwrap();
                state.riscv_platform = None;
                saved = saved.with_execution(state).unwrap();
            }
            3 => {
                let mut records = saved.backend_contexts().unwrap().entries().to_vec();
                records.last_mut().unwrap().as_mut().unwrap().data[8] = 0;
                saved = saved.with_backend_contexts(records).unwrap();
            }
            4 | 5 => {
                let mut records = saved.backend_contexts().unwrap().entries().to_vec();
                records.last_mut().unwrap().as_mut().unwrap().data[8] =
                    if mutation == 4 { 1 } else { 2 };
                saved = saved.with_backend_contexts(records).unwrap();
            }
            6 => {
                saved.take_physical_memory();
            }
            _ => unreachable!(),
        }
        assert!(
            target.vm.restore_snapshot_bundle(&saved).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(contexts(&target.vm), before);
        assert_eq!(
            platform(&target.vm).checkpoint().unwrap(),
            before_controller
        );
        assert_eq!(target.vm.timing_context.checkpoint_state(), before_clock);
        assert_eq!(word(&target.vm, 0x80008004), 0xa5a5a5a5);
        if mutation < 6 {
            saved = saved
                .with_backend_contexts(original_contexts.clone())
                .unwrap()
                .with_execution(original_execution.clone())
                .unwrap()
                .with_clock(original_clock.clone())
                .unwrap();
        }
    }
}
#[test]
fn legacy_private_harts_restore_clint_addresses_as_ordinary_ram() {
    let source = Fixture::new(2, true);
    platform(&source.vm).restore_with(None, || Ok(())).unwrap();
    source
        .vm
        .guest_mem
        .memory()
        .write_obj(0x11223344u32.to_le(), GuestAddress(0x02000004))
        .unwrap();
    let mut saved = source.vm.take_snapshot_bundle(0).unwrap();
    let records = saved
        .backend_contexts()
        .unwrap()
        .entries()
        .iter()
        .map(|record| {
            let mut record = record.clone().unwrap();
            assert_eq!(&record.data[..10], b"RAXRV005\0\0");
            record.data.splice(..10, b"RAXRV002".iter().copied());
            Some(record)
        })
        .collect();
    saved = saved.with_backend_contexts(records).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let mut restored = Vmm::new_resume_bundle(config, &saved).unwrap();
    assert!(!platform(&restored).enabled());
    assert_eq!(word(&restored, 0x02000004), 0x11223344);
    // LW t0,0(a0); SW a1,0(a0): legacy RAM remains directly observable.
    restored
        .guest_mem
        .memory()
        .write_slice(
            &[0x83, 0x22, 0x05, 0x00, 0x23, 0x20, 0xb5, 0x00],
            GuestAddress(0x1000),
        )
        .unwrap();
    let CpuState::RiscV(mut state) = restored.vcpus[1].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = 0x1000;
    state.regs.x[10] = 0x02000004;
    state.regs.x[11] = 0x55667788;
    restored.vcpus[1]
        .set_state(&CpuState::RiscV(state))
        .unwrap();
    restored.vcpus[1].step_insn().unwrap();
    restored.vcpus[1].step_insn().unwrap();
    let CpuState::RiscV(state) = restored.vcpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(state.regs.x[5], 0x11223344);
    assert_eq!(word(&restored, 0x02000004), 0x55667788);
    let again = restored.take_snapshot_bundle(2).unwrap();
    assert!(again.execution().unwrap().riscv_platform.is_none());
    assert!(
        again
            .backend_contexts()
            .unwrap()
            .entries()
            .iter()
            .all(|r| r.as_ref().unwrap().data[8] == 0)
    );
}
#[cfg(feature = "debug")]
#[test]
fn debugger_cannot_read_or_write_clint_shadow_ram() {
    let mut fixture = Fixture::new(1, false);
    let before = word(&fixture.vm, 0x02000000);
    assert!(fixture.vm.read_debug_memory(0x02000000, 4).is_err());
    assert!(
        !fixture
            .vm
            .write_debug_memory(0x02000000, &[1, 0, 0, 0])
            .unwrap()
    );
    assert_eq!(word(&fixture.vm, 0x02000000), before);
}

#[test]
fn wall_clock_vmm_clint_handlers_execute_on_one_two_and_four_harts() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::with_clock(count, false, ClockMode::Wall);
        fixture.vm.run().unwrap();
        assert_work(&fixture.vm, count);
        assert!(
            fixture
                .vm
                .take_snapshot(0)
                .err()
                .unwrap()
                .to_string()
                .contains("complete snapshot bundle")
        );
    }
}

#[test]
fn legacy_base_restore_disables_clint_before_guest_execution() {
    let source = Fixture::with_clock(1, false, ClockMode::Wall);
    platform(&source.vm).restore_with(None, || Ok(())).unwrap();
    source
        .vm
        .guest_mem
        .memory()
        .write_obj(0x11223344u32.to_le(), GuestAddress(0x02000000))
        .unwrap();
    let saved = source.vm.take_snapshot(0).unwrap();
    let mut target = Fixture::with_clock(1, false, ClockMode::Wall);
    platform(&target.vm)
        .write(0x02000000, &1u32.to_le_bytes())
        .unwrap();
    target.vm.restore_snapshot(&saved).unwrap();
    assert!(!platform(&target.vm).enabled());
    assert_eq!(word(&target.vm, 0x02000000), 0x11223344);
    assert_eq!(contexts(&target.vm)[0].as_ref().unwrap().data[8], 0);
    assert!(target.vm.take_snapshot(0).is_ok());
}

#[test]
fn future_deadlines_advance_through_actual_vmm_retirement_on_every_hart() {
    for mode in [ClockMode::Retired, ClockMode::Wall] {
        for count in [1, 2, 4] {
            let mut fixture =
                Fixture::with_code(count, program::future_program(count, false), mode);
            fixture.vm.run().unwrap();
            assert_work(&fixture.vm, count);
            if mode == ClockMode::Retired {
                assert!(fixture.vm.timing_context.retirement_count().unwrap() >= 64 * 300);
            }
        }
    }
}

#[test]
fn page_rounded_riscv_topology_uses_the_actual_reported_extent() {
    for count in [1, 2, 4] {
        let fixture = Fixture::with_memory(
            count,
            program::program(count, false),
            ClockMode::Retired,
            (128 << 20) + 1,
        );
        assert_eq!(fixture.vm.guest_mem.size(), (128 << 20) + 4096);
        platform(&fixture.vm)
            .checkpoint()
            .unwrap()
            .unwrap()
            .validate(usize::from(count), fixture.vm.guest_mem.size())
            .unwrap();
    }
}

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

fn contexts(vm: &Vmm) -> Vec<Option<crate::vm::snapshot::BackendContext>> {
    vm.vcpus
        .iter()
        .map(|cpu| cpu.capture_backend_context().unwrap())
        .collect()
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
            assert!(signals.1 && signals.2, "both inputs pending on hart {hart}");
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
                let (_, software, timer) = platform(vm).signals(u32::from(hart)).unwrap().unwrap();
                assert!(!software && !timer);
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
    for mutation in 0..6 {
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
            4 => {
                let mut records = saved.backend_contexts().unwrap().entries().to_vec();
                records.last_mut().unwrap().as_mut().unwrap().data[8] = 2;
                saved = saved.with_backend_contexts(records).unwrap();
            }
            5 => {
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
        if mutation < 5 {
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
            assert_eq!(&record.data[..9], b"RAXRV003\0");
            record.data.splice(..9, b"RAXRV002".iter().copied());
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

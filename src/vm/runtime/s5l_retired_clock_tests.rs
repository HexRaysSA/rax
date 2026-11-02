//! Actual guest MMIO and source-free files under selected retired elapsed clocks.
use super::*;
use crate::vm::timing::ClockMode;
const LABEL: &str = "retired_clock::actual_elapsed_timer_files_preserve_owned_epochs_before_entry_and_after_guest_reads";
const SEED: u64 = 3_000_001; // Explicit fixture epoch:1000000 ns,phase1.

fn make_source(path: &Path, count: u8) -> Vmm {
    std::fs::write(path.join("kernel"), [0; 64]).unwrap();
    let mut vm = Vmm::new_resume_with_clock(config(path, count), ClockMode::Retired).unwrap();
    let mut words = vec![0xe5912004u32, 0xe5913000, 0xe320f003]; // low,high,WFI
    words.extend(std::iter::repeat_n(0xe1a00000, 253));
    words.extend([0xe5914004, 0xe5915000, 0xe320f003]); // low,high,WFI
    let bytes = words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    vm.guest_mem
        .memory()
        .write_slice(&bytes, GuestAddress(CODE as u64))
        .unwrap();
    for cpu in &mut vm.vcpus {
        let CpuState::Aarch32(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.r[1] = 0x3e20_0080; // S5L TIMER1: high at+0,low at+4.
        cpu.set_state(&CpuState::Aarch32(state)).unwrap();
    }
    vm.coordinator.online.fill(true); // Prepared contexts,not architectural AP startup.
    // Seed a representable prior VM epoch; subsequent retirements are measured.
    vm.timing_context.advance_retired(SEED).unwrap();
    vm.coordinator.retired = SEED;
    std::thread::sleep(std::time::Duration::from_millis(3));
    for id in 0..usize::from(count) {
        let turn = vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        let CpuState::Aarch32(state) = vm.vcpus[id].get_state().unwrap() else {
            panic!()
        };
        assert_eq!((state.regs.r[2], state.regs.r[3]), (1000, 0));
        assert_eq!(vm.vcpus[id].instruction_count(), 3);
    }
    assert_eq!(vm.coordinator.retired, SEED + 3 * u64::from(count));
    vm
}

#[test]
fn actual_elapsed_timer_files_preserve_owned_epochs_before_entry_and_after_guest_reads() {
    if !selected(LABEL) {
        let dir = Directory::new();
        std::fs::create_dir_all(dir.0.join("nand/bank0")).unwrap();
        child(LABEL, &dir.0, "source", true);
        std::fs::remove_dir_all(dir.0.join("nand")).unwrap();
        std::fs::remove_file(dir.0.join("kernel")).unwrap();
        child(LABEL, &dir.0, "restore", false);
        return;
    }
    let path = root();
    let source_phase = std::env::var("RAX_S5L_CONTEXT_PHASE").as_deref() == Ok("source");
    for count in [1u8, 2, 4] {
        let file = path.join(format!("retired-{count}.rxc"));
        if source_phase {
            let source = make_source(&path, count);
            let first = source
                .take_snapshot_bundle(source.coordinator.retired)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(3));
            let second = source
                .take_snapshot_bundle(source.coordinator.retired)
                .unwrap();
            assert_eq!(first.clock(), second.clock());
            assert_eq!(
                first.backend_contexts().unwrap().entries(),
                second.backend_contexts().unwrap().entries()
            );
            second.save(&file).unwrap();
            continue;
        }
        let bundle = SnapshotBundle::load(&file).unwrap();
        let mut target = Vmm::new_resume_bundle(
            VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap(),
            &bundle,
        )
        .unwrap();
        if count == 2 {
            // Exercise in-place restoration from a different old target epoch.
            target.timing_context.advance_retired(3_000_000).unwrap();
            target.coordinator.retired = target.coordinator.retired.wrapping_add(3_000_000);
            target.restore_snapshot_bundle(&bundle).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(3));
        assert_eq!(
            target.timing_context.checkpoint_state(),
            *bundle.clock().unwrap()
        );
        let again = target
            .take_snapshot_bundle(target.coordinator.retired)
            .unwrap();
        assert_eq!(
            again.backend_contexts().unwrap().entries(),
            bundle.backend_contexts().unwrap().entries()
        );
        for cpu in &mut target.vcpus {
            cpu.wake();
        }
        for id in 0..usize::from(count) {
            let turn = target.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            let CpuState::Aarch32(state) = target.vcpus[id].get_state().unwrap() else {
                panic!()
            };
            assert_eq!((state.regs.r[4], state.regs.r[5]), (1000, 0));
            assert_eq!(target.vcpus[id].instruction_count(), 259);
        }
        assert_eq!(target.coordinator.retired, SEED + 259 * u64::from(count));
        assert_eq!(
            target.timing_context.checkpoint_state().retired_units,
            target.coordinator.retired
        );
    }
}

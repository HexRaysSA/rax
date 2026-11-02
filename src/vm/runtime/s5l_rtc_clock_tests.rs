//! Guest I2C/PMU reads before and after fresh source-free selected-clock files.
use super::*;
use crate::vm::timing::ClockMode;
const LABEL: &str =
    "rtc_clock::selected_pmu_unread_calendar_files_restore_before_and_after_guest_reads";
const ADDED: u64 = 183_000_000_000; // Explicit prior epoch fixture:61 seconds.
fn prepare(path: &Path, count: u8) -> Vmm {
    std::fs::write(path.join("kernel"), [0; 64]).unwrap();
    let mut vm = Vmm::new_resume_with_clock(config(path, count), ClockMode::Retired).unwrap();
    let words = [
        0xe581000cu32,
        0xe5812004,
        0xe581300c,
        0xe320f003,
        0xe591400c,
        0xe591500c,
        0xe591600c,
        0xe320f003,
        0xe591700c,
        0xe591800c,
        0xe591900c,
        0xe591a00c,
        0xe320f003,
    ];
    let code = words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    vm.guest_mem
        .memory()
        .write_slice(&code, GuestAddress(CODE as u64))
        .unwrap();
    for cpu in &mut vm.vcpus {
        let CpuState::Aarch32(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.r[0] = 0xe6;
        state.regs.r[1] = 0x3c90_0000;
        state.regs.r[2] = 0xf0;
        state.regs.r[3] = 0x59;
        cpu.set_state(&CpuState::Aarch32(state)).unwrap();
    }
    vm.coordinator.online.fill(true);
    turn(&mut vm, count);
    assert_eq!(vm.coordinator.retired, 4 * u64::from(count));
    vm
}
fn turn(vm: &mut Vmm, count: u8) {
    for id in 0..usize::from(count) {
        let t = vm.execute_turn().unwrap().unwrap();
        assert_eq!(t.cpu_index, id);
        assert!(matches!(t.exit, VcpuExit::Hlt));
    }
}
#[test]
fn selected_pmu_unread_calendar_files_restore_before_and_after_guest_reads() {
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
        let file = path.join(format!("rtc-{count}.rxc"));
        if source_phase {
            let vm = prepare(&path, count);
            vm.take_snapshot_bundle(vm.coordinator.retired)
                .unwrap()
                .save(&file)
                .unwrap();
            continue;
        }
        let saved = SnapshotBundle::load(&file).unwrap();
        let mut target = Vmm::new_resume_bundle(
            VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap(),
            &saved,
        )
        .unwrap();
        target
            .timing_context
            .advance_retired(3_000_000_000)
            .unwrap();
        target.coordinator.retired += 3_000_000_000;
        target.restore_snapshot_bundle(&saved).unwrap();
        let before = target
            .take_snapshot_bundle(target.coordinator.retired)
            .unwrap();
        assert_eq!(
            before.backend_contexts().unwrap().entries(),
            saved.backend_contexts().unwrap().entries()
        );
        target.timing_context.advance_retired(ADDED).unwrap();
        target.coordinator.retired += ADDED;
        for cpu in &mut target.vcpus {
            cpu.wake();
        }
        turn(&mut target, count);
        for cpu in &target.vcpus {
            let CpuState::Aarch32(state) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(
                [state.regs.r[4], state.regs.r[5], state.regs.r[6]],
                [1, 1, 0]
            );
            assert_eq!(cpu.instruction_count(), 8);
        }
        let post = path.join(format!("rtc-post-{count}.rxc"));
        target
            .take_snapshot_bundle(target.coordinator.retired)
            .unwrap()
            .save(&post)
            .unwrap();
        drop(target);
        let saved = SnapshotBundle::load(&post).unwrap();
        let mut target = Vmm::new_resume_bundle(
            VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap(),
            &saved,
        )
        .unwrap();
        for cpu in &mut target.vcpus {
            cpu.wake();
        }
        turn(&mut target, count);
        for cpu in &target.vcpus {
            let CpuState::Aarch32(state) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(
                [
                    state.regs.r[7],
                    state.regs.r[8],
                    state.regs.r[9],
                    state.regs.r[10]
                ],
                [0, 1, 1, 0]
            );
            assert_eq!(cpu.instruction_count(), 13);
        }
        assert_eq!(target.coordinator.retired, ADDED + 13 * u64::from(count));
        assert_eq!(
            target.timing_context.checkpoint_state().retired_units,
            target.coordinator.retired
        );
    }
}

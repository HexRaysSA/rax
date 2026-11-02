//! Actual CMOS PIO instructions and retained-owner full-file continuation.
use super::*;
use crate::config::CliConfig;
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::timing::{ClockMode, TimingContext};
use vm_memory::{Bytes, GuestAddress};
fn bytes(vm: &Vmm, count: u8, phase: u32) {
    for id in 0..count {
        let mut observed = [0; 3];
        vm.guest_mem
            .memory()
            .read_slice(
                &mut observed,
                GuestAddress(0x7000 + u64::from(id) * 8 + u64::from(phase) * 4),
            )
            .unwrap();
        assert_eq!(observed, [phase as u8, 0, 0x20], "CPU{id} phase{phase}");
    }
}
fn turn(vm: &mut Vmm, count: u8) {
    let mut halted = vec![false; usize::from(count)];
    for _ in 0..128 * usize::from(count) {
        let t = vm.execute_turn().unwrap().unwrap();
        match t.exit {
            VcpuExit::IoOut { port, data } => vm.io_bus.write(port, &data).unwrap(),
            VcpuExit::IoIn { port, size } => {
                let mut data = vec![0; usize::from(size)];
                vm.io_bus.read(port, &mut data).unwrap();
                vm.vcpus[t.cpu_index].complete_io_in(&data);
                vm.vcpus[t.cpu_index].io_completion_result().unwrap();
            }
            VcpuExit::Hlt => halted[t.cpu_index] = true,
            exit => panic!("unexpected CMOS guest exit {exit:?}"),
        }
        if halted.iter().all(|v| *v) {
            return;
        }
    }
    panic!("CMOS guest did not halt on every CPU");
}
#[test]
fn selected_cmos_guest_reads_continue_from_source_free_one_two_four_cpu_files() {
    for count in [1u8, 2, 4] {
        let (config, initial) = super::clock_tests::configuration(count);
        let mut source = Vmm::new_resume_with_clock(config, ClockMode::Retired).unwrap();
        for id in 0..usize::from(count) {
            let mut program = Vec::new();
            for phase in 0..2u32 {
                for (off, index) in [0u8, 2, 0x32].into_iter().enumerate() {
                    program.extend([0xb0, index, 0xe6, 0x70, 0xe4, 0x71, 0xa2]);
                    program.extend_from_slice(
                        &(0x7000 + id as u32 * 8 + phase * 4 + off as u32).to_le_bytes(),
                    );
                }
                program.push(0xf4);
            }
            let entry = 0x8000 + id as u64 * 0x100;
            source
                .guest_mem
                .memory()
                .write_slice(&program, GuestAddress(entry))
                .unwrap();
            let mut state = initial.clone();
            let CpuState::X86_64(cpu) = &mut state else {
                panic!()
            };
            cpu.regs.rip = entry;
            source.vcpus[id].set_state(&state).unwrap();
        }
        source.coordinator.online.fill(true);
        turn(&mut source, count);
        bytes(&source, count, 0);
        assert_eq!(source.coordinator.retired, 13 * u64::from(count));
        let file = std::env::temp_dir().join(format!(
            "rax-selected-cmos-{}-{count}.rxc",
            std::process::id()
        ));
        source
            .take_snapshot_bundle(source.coordinator.retired)
            .unwrap()
            .save(&file)
            .unwrap();
        drop(source);
        let bundle = SnapshotBundle::load(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        foreign.advance_retired(90_000_000_000).unwrap();
        let _foreign = foreign.enter();
        let mut target = Vmm::new_resume_bundle(
            VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap(),
            &bundle,
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(3));
        assert_eq!(
            target.timing_context.checkpoint_state(),
            *bundle.clock().unwrap()
        );
        let pre = target
            .take_snapshot_bundle(target.coordinator.retired)
            .unwrap();
        assert_eq!(
            pre.execution()
                .unwrap()
                .pc
                .as_ref()
                .unwrap()
                .encoded()
                .unwrap(),
            bundle
                .execution()
                .unwrap()
                .pc
                .as_ref()
                .unwrap()
                .encoded()
                .unwrap()
        );
        target
            .timing_context
            .advance_retired(3_000_000_000)
            .unwrap();
        target.coordinator.retired += 3_000_000_000;
        for cpu in &mut target.vcpus {
            cpu.wake();
        }
        turn(&mut target, count);
        bytes(&target, count, 1);
        assert_eq!(
            target.coordinator.retired,
            3_000_000_000 + 26 * u64::from(count)
        );
        for cpu in &target.vcpus {
            assert_eq!(cpu.instruction_count(), 26);
        }
        target.restore_snapshot_bundle(&bundle).unwrap();
        target.io_bus.write(0x70, &[0]).unwrap();
        let mut second = [99];
        target.io_bus.read(0x71, &mut second).unwrap();
        assert_eq!(second, [0]);
        assert_eq!(
            target.timing_context.checkpoint_state(),
            *bundle.clock().unwrap()
        );
        // Explicit old calendar profile cannot be silently imported into this target.
        let mut execution = bundle.execution().unwrap().clone();
        let mut image = execution.pc.as_ref().unwrap().encoded().unwrap();
        image[..8].copy_from_slice(b"RAXPCD01");
        execution.pc = Some(crate::machine::pc::PcCheckpoint::decode(&image).unwrap());
        // Load a second complete bundle to preserve every unrelated section.
        bundle.save(&file).unwrap();
        let bad = SnapshotBundle::load(&file)
            .unwrap()
            .with_execution(execution)
            .unwrap();
        std::fs::remove_file(&file).unwrap();
        let before = (
            target.guest_mem.try_read_all().unwrap(),
            target.coordinator.clone(),
            target.timing_context.checkpoint_state(),
        );
        assert!(
            target
                .restore_snapshot_bundle(&bad)
                .unwrap_err()
                .to_string()
                .contains("legacy PC calendar")
        );
        assert_eq!(target.guest_mem.try_read_all().unwrap(), before.0);
        assert_eq!(target.coordinator, before.1);
        assert_eq!(target.timing_context.checkpoint_state(), before.2);
    }
}

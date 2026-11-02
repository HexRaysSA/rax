//! Guest forwarding controls across source-free, prepared 1/2/4-PE VM files.
use super::*;
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::vcpu::Aarch64CpuState;

const PPI: u32 = 1 << 30;
const WFI: u32 = 0xd503_207f;

fn image(vm: &Vmm, id: usize) -> Aarch64CpuState {
    let CpuState::Aarch64(state) = vm.vcpus[id].get_state().unwrap() else {
        panic!()
    };
    state
}

fn same(source: &Vmm, target: &Vmm) {
    assert_eq!(source.coordinator, target.coordinator);
    assert_eq!(
        source.timing_context.checkpoint_state(),
        target.timing_context.checkpoint_state()
    );
    let graph = |vm: &Vmm| {
        let cluster = vm
            .vm
            .as_any()
            .downcast_ref::<EmulatorVm>()
            .unwrap()
            .arm_cluster()
            .unwrap();
        crate::codec::serialize(&cluster.checkpoint().unwrap()).unwrap()
    };
    assert_eq!(graph(source), graph(target));
    for id in 0..source.vcpus.len() {
        assert_eq!(image(source, id), image(target, id));
        assert_eq!(
            source.vcpus[id].instruction_count(),
            target.vcpus[id].instruction_count()
        );
    }
}

fn line(vm: &Vmm, id: usize) -> bool {
    vm.vm
        .as_any()
        .downcast_ref::<EmulatorVm>()
        .unwrap()
        .arm_cluster()
        .unwrap()
        .irq_line_for_test(id)
        .load(Ordering::Acquire)
}

#[test]
fn guest_group_controls_continue_from_files_without_source_kernel_or_checkpoint() {
    for count in [1, 2, 4] {
        for mask in 0..4 {
            let mut source = Fixture::with_clock(count, ClockMode::Retired);
            for id in 1..count {
                assert_eq!(
                    source
                        .cluster()
                        .request_on(u64::from(id), CODE + u64::from(id) * 0x1000, 0, 0x3c5)
                        .unwrap(),
                    0
                );
            }
            source.vm.route_interprocessor_requests().unwrap();
            let program = [
                0xb900_0292, // STR W18,[X20]: GICR_WAKER.ProcessorSleep=0.
                0xb900_014b, // STR W11,[X10]: GICD_CTLR.
                0xb900_01ac, // STR W12,[X13]: GICR_IGROUPR0.
                0xb900_01cc, // STR W12,[X14]: GICR_ISENABLER0.
                0xb900_026c, // STR W12,[X19]: GICR_ISPENDR0.
                0xd518_460f, // MSR ICC_PMR_EL1,X15.
                0xd518_ccd0, // MSR ICC_IGRPEN0_EL1,X16.
                0xd518_ccf0, // MSR ICC_IGRPEN1_EL1,X16.
                WFI,
                0xb900_0151, // STR W17,[X10]: inverse group mask.
                0xb940_0140, // LDR W0,[X10].
                WFI,
                0xd518_ccff, // MSR ICC_IGRPEN1_EL1,XZR.
                WFI,
                0xd518_ccf0, // MSR ICC_IGRPEN1_EL1,X16.
                0xb900_014b, // STR W11,[X10]: original group mask.
                0xb940_0141, // LDR W1,[X10].
                WFI,
            ];
            let bytes = program
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            for id in 0..usize::from(count) {
                source
                    .vm
                    .guest_mem
                    .memory()
                    .write_slice(&bytes, GuestAddress(CODE + id as u64 * 0x1000))
                    .unwrap();
                let mut state = image(&source.vm, id);
                let bank = 0x080a_0000 + id as u64 * 0x20000;
                state.regs.x[10] = 0x0800_0000;
                state.regs.x[11] = mask;
                state.regs.x[12] = u64::from(PPI);
                state.regs.x[13] = bank + 0x10080;
                state.regs.x[14] = bank + 0x10100;
                state.regs.x[15] = 0xff;
                state.regs.x[16] = 1;
                state.regs.x[17] = mask ^ 3;
                state.regs.x[18] = 0;
                state.regs.x[20] = bank + 0x14;
                state.regs.x[19] = bank + 0x10200;
                source.vm.vcpus[id]
                    .set_state(&CpuState::Aarch64(state))
                    .unwrap();
            }
            for id in 0..usize::from(count) {
                let turn = source.vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                assert_eq!(source.vm.vcpus[id].instruction_count(), 9);
                assert_eq!(line(&source.vm, id), mask & 2 != 0);
            }
            let bundle = source
                .vm
                .take_snapshot_bundle(source.vm.coordinator.retired)
                .unwrap();
            let path = source.kernel.with_extension("gic-forwarding.rxc");
            bundle.save(&path).unwrap();
            let loaded = SnapshotBundle::load(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            std::fs::remove_file(&source.kernel).unwrap();
            let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
            assert!(!config.kernel.exists() && !path.exists());
            let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
            same(&source.vm, &target);
            for (phase, retired) in [(0, 12), (1, 14), (2, 18)] {
                for vm in [&mut source.vm, &mut target] {
                    for cpu in &mut vm.vcpus {
                        cpu.wake();
                    }
                    for id in 0..usize::from(count) {
                        let turn = vm.execute_turn().unwrap().unwrap();
                        assert_eq!(turn.cpu_index, id);
                        assert!(matches!(turn.exit, VcpuExit::Hlt));
                        assert_eq!(vm.vcpus[id].instruction_count(), retired);
                        let state = image(vm, id);
                        match phase {
                            0 => {
                                assert_eq!(state.regs.x[0], 0x50 | (mask ^ 3));
                                assert_eq!(line(vm, id), (mask ^ 3) & 2 != 0);
                            }
                            1 => assert!(!line(vm, id)),
                            2 => {
                                assert_eq!(state.regs.x[1], 0x50 | mask);
                                assert_eq!(line(vm, id), mask & 2 != 0);
                            }
                            _ => unreachable!(),
                        }
                    }
                    assert_eq!(vm.coordinator.retired, retired * u64::from(count));
                }
                same(&source.vm, &target);
            }
        }
    }
}

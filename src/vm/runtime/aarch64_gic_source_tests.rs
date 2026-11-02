//! Guest timer/GIC source conservation through actual source-free VM files.
use super::*;
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::vcpu::Aarch64CpuState;

const PPI: u32 = 1 << 30;
const WFI: u32 = 0xd503_207f;
const DISABLE: u32 = 0xd51b_e23f;
const ENABLE: u32 = 0xd51b_e227;
const READ0: u32 = 0xb940_0280; // LDR W0,[X20].
const READ1: u32 = 0xb940_0281;
const CLEAR: u32 = 0xb900_02ac; // STR W12,[X21].
const IAR2: u32 = 0xd538_cc02;
const EOI2: u32 = 0xd518_cc22;

fn image(vm: &Vmm, id: usize) -> Aarch64CpuState {
    let CpuState::Aarch64(state) = vm.vcpus[id].get_state().unwrap() else {
        panic!()
    };
    state
}

fn graph(vm: &Vmm) -> Vec<u8> {
    let cluster = vm
        .vm
        .as_any()
        .downcast_ref::<EmulatorVm>()
        .unwrap()
        .arm_cluster()
        .unwrap();
    crate::codec::serialize(&cluster.checkpoint().unwrap()).unwrap()
}

fn source(count: u8, software: bool, edge: bool, tail: &[u32]) -> (Fixture, u64) {
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
    source.vm.route_interprocessor_requests().unwrap(); // Prepared peers,not guest startup.
    let mut program = vec![0xb900_014b, 0xb900_01ac]; // Distributor/group1.
    if edge {
        program.push(0xb900_02d1);
    } // STR W17,[X22]: GICR_ICFGR1.
    program.extend([0xb900_01cc, 0xd518_460f, 0xd518_ccf0, 0xd51b_e246, ENABLE]);
    if edge {
        program.extend([IAR2, EOI2]);
    } else {
        program.push(0xb900_0272);
    } // STR W18,[X19]: software pending.
    program.push(WFI);
    let prefix = program.len() as u64;
    program.extend_from_slice(tail);
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
        state.regs.x[6] = 0;
        state.regs.x[7] = 1;
        state.regs.x[10] = 0x0800_0000;
        state.regs.x[11] = 2;
        state.regs.x[12] = u64::from(PPI);
        let bank = 0x080a_0000 + id as u64 * 0x20000;
        state.regs.x[13] = bank + 0x10080;
        state.regs.x[14] = bank + 0x10100;
        state.regs.x[15] = 0xff;
        state.regs.x[16] = 1;
        state.regs.x[17] = 1 << 29;
        state.regs.x[18] = if software { u64::from(PPI) } else { 0 };
        state.regs.x[19] = bank + 0x10200;
        state.regs.x[20] = bank + 0x10200;
        state.regs.x[21] = bank + 0x10280;
        state.regs.x[22] = bank + 0x10c04;
        source.vm.vcpus[id]
            .set_state(&CpuState::Aarch64(state))
            .unwrap();
    }
    for id in 0..usize::from(count) {
        let turn = source.vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        assert_eq!(source.vm.vcpus[id].instruction_count(), prefix);
        if edge {
            assert_eq!(image(&source.vm, id).regs.x[2], 30);
        }
    }
    assert_eq!(source.vm.coordinator.retired, prefix * u64::from(count));
    (source, prefix)
}

fn restored(source: &Fixture, suffix: &str) -> Vmm {
    let saved = source
        .vm
        .take_snapshot_bundle(source.vm.coordinator.retired)
        .unwrap();
    let path = source.kernel.with_extension(suffix);
    saved.save(&path).unwrap();
    let loaded = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(&source.kernel).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    assert!(!config.kernel.exists());
    let target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    same(&source.vm, &target);
    target
}

fn same(a: &Vmm, b: &Vmm) {
    assert_eq!(a.coordinator, b.coordinator);
    assert_eq!(
        a.timing_context.checkpoint_state(),
        b.timing_context.checkpoint_state()
    );
    assert_eq!(graph(a), graph(b));
    for id in 0..a.vcpus.len() {
        assert_eq!(image(a, id), image(b, id));
        assert_eq!(
            a.vcpus[id].instruction_count(),
            b.vcpus[id].instruction_count()
        );
    }
}

#[test]
fn source_free_files_keep_software_pending_after_the_same_timer_input_deasserts() {
    for count in [1, 2, 4] {
        let (mut source, prefix) = source(count, true, false, &[DISABLE, READ0, CLEAR, READ1, WFI]);
        let mut target = restored(&source, "gic-software.rxc");
        for vm in [&mut source.vm, &mut target] {
            for cpu in &mut vm.vcpus {
                cpu.wake();
            }
            for id in 0..usize::from(count) {
                let turn = vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let state = image(vm, id);
                assert_eq!(
                    (
                        state.regs.x[0] & u64::from(PPI),
                        state.regs.x[1] & u64::from(PPI)
                    ),
                    (u64::from(PPI), 0)
                );
                assert_eq!(vm.vcpus[id].instruction_count(), prefix + 5);
            }
            assert_eq!(vm.coordinator.retired, (prefix + 5) * u64::from(count));
        }
        same(&source.vm, &target);
    }
}

#[test]
fn source_free_files_keep_asserted_timer_input_after_guest_clear_pending() {
    for count in [1, 2, 4] {
        let (mut source, prefix) =
            source(count, false, false, &[CLEAR, READ0, DISABLE, READ1, WFI]);
        let mut target = restored(&source, "gic-level.rxc");
        for vm in [&mut source.vm, &mut target] {
            for cpu in &mut vm.vcpus {
                cpu.wake();
            }
            for id in 0..usize::from(count) {
                let turn = vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let state = image(vm, id);
                assert_eq!(
                    (
                        state.regs.x[0] & u64::from(PPI),
                        state.regs.x[1] & u64::from(PPI)
                    ),
                    (u64::from(PPI), 0)
                );
                assert_eq!(vm.vcpus[id].instruction_count(), prefix + 5);
            }
        }
        same(&source.vm, &target);
    }
}

#[test]
fn source_free_files_keep_consumed_edge_history_and_deliver_the_next_edge_once() {
    let tail = [
        READ0,
        ENABLE,
        READ1,
        DISABLE,
        ENABLE,
        0xb940_0283,
        0xd538_cc04,
        0xd518_cc24,
        0xb940_0285,
        WFI,
    ];
    for count in [1, 2, 4] {
        let (mut source, prefix) = source(count, false, true, &tail);
        let mut target = restored(&source, "gic-edge.rxc");
        for vm in [&mut source.vm, &mut target] {
            for cpu in &mut vm.vcpus {
                cpu.wake();
            }
            for id in 0..usize::from(count) {
                let turn = vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let state = image(vm, id);
                assert_eq!(
                    (
                        state.regs.x[0] & u64::from(PPI),
                        state.regs.x[1] & u64::from(PPI),
                        state.regs.x[3] & u64::from(PPI),
                        state.regs.x[4],
                        state.regs.x[5] & u64::from(PPI)
                    ),
                    (0, 0, u64::from(PPI), 30, 0)
                );
                assert_eq!(vm.vcpus[id].instruction_count(), prefix + 10);
            }
            assert_eq!(vm.coordinator.retired, (prefix + 10) * u64::from(count));
        }
        same(&source.vm, &target);
    }
}

#[test]
fn inconsistent_first_or_last_timer_source_rejects_without_live_vm_changes() {
    for count in [1, 2, 4] {
        let (source, _) = source(count, true, false, &[WFI]);
        let mut target = Fixture::with_clock(count, ClockMode::Retired);
        target
            .vm
            .guest_mem
            .memory()
            .write_slice(&0xfeed_beefu32.to_le_bytes(), GuestAddress(CODE + 0x7000))
            .unwrap();
        for bad_cpu in if count == 1 {
            vec![0]
        } else {
            vec![0, usize::from(count) - 1]
        } {
            let mut bundle = source
                .vm
                .take_snapshot_bundle(source.vm.coordinator.retired)
                .unwrap();
            let mut execution = bundle.take_execution().unwrap();
            let mut value = serde_json::to_value(execution.arm_cluster.as_ref().unwrap()).unwrap();
            value["gic"]["sources"]["ppis"][bad_cpu][14]["line"] = false.into();
            value["gic"]["sources"]["ppis"][bad_cpu][14]["software"] = true.into();
            execution.arm_cluster = Some(serde_json::from_value(value).unwrap());
            let bad = bundle.with_execution(execution).unwrap(); // Aggregate pending remains coherent.
            let cpus = (0..usize::from(count))
                .map(|id| image(&target.vm, id))
                .collect::<Vec<_>>();
            let gic = graph(&target.vm);
            let clock = target.vm.timing_context.checkpoint_state();
            let coordinator = target.vm.coordinator.clone();
            assert!(
                target
                    .vm
                    .restore_snapshot_bundle(&bad)
                    .unwrap_err()
                    .to_string()
                    .contains("timer inputs")
            );
            assert_eq!(
                (0..usize::from(count))
                    .map(|id| image(&target.vm, id))
                    .collect::<Vec<_>>(),
                cpus
            );
            assert_eq!(graph(&target.vm), gic);
            assert_eq!(target.vm.timing_context.checkpoint_state(), clock);
            assert_eq!(target.vm.coordinator, coordinator);
            let mut raw = [0; 4];
            target
                .vm
                .guest_mem
                .memory()
                .read_slice(&mut raw, GuestAddress(CODE + 0x7000))
                .unwrap();
            assert_eq!(u32::from_le_bytes(raw), 0xfeed_beef);
        }
    }
}

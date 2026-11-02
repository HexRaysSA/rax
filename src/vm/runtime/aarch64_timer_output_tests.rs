//! Guest timer outputs across reset, real files and PSCI restart.
use super::*;
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::vcpu::VcpuExit;

const VIRTUAL: u32 = 1 << 27;
const PHYSICAL: u32 = 1 << 30;
const BOTH: u32 = VIRTUAL | PHYSICAL;
const READ: u64 = CODE + 0x1000;
const CALL: u64 = CODE + 0x2000;
const WFI: u32 = 0xd503_207f;
const HVC: u32 = 0xd400_0002;

fn write(vm: &Vmm, address: u64, code: &[u32]) {
    vm.guest_mem
        .memory()
        .write_slice(
            &code
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
            GuestAddress(address),
        )
        .unwrap();
}

fn machine(count: u8, virtual_timer: bool, physical_timer: bool, software: u32) -> Fixture {
    let mut fixture = Fixture::with_clock(count, ClockMode::Retired);
    for id in 1..count {
        assert_eq!(
            fixture
                .cluster()
                .request_on(u64::from(id), CODE + u64::from(id) * 0x100, 0, 0x3c5)
                .unwrap(),
            0
        );
    }
    fixture.vm.route_interprocessor_requests().unwrap();
    let program = [
        0xb900_014b, // STR W11,[X10]: GICD_CTLR.
        0xb900_01ac, // STR W12,[X13]: GICR_IGROUPR0.
        0xb900_01cc, // STR W12,[X14]: GICR_ISENABLER0.
        0xd518_460f, // MSR ICC_PMR_EL1,X15.
        0xd518_ccf0, // MSR ICC_IGRPEN1_EL1,X16.
        0xd51b_e246, // MSR CNTP_CVAL_EL0,X6.
        0xd51b_e346, // MSR CNTV_CVAL_EL0,X6.
        0xd51b_e227, // MSR CNTP_CTL_EL0,X7.
        0xd51b_e328, // MSR CNTV_CTL_EL0,X8.
        0xb900_0272, // STR W18,[X19]: software-pending the other timer PPI.
        WFI,
    ];
    let target = usize::from(count) - 1;
    for id in 0..usize::from(count) {
        write(&fixture.vm, CODE + id as u64 * 0x100, &program);
        let CpuState::Aarch64(mut state) = fixture.vm.vcpus[id].get_state().unwrap() else {
            panic!()
        };
        state.regs.x[6] = 0;
        state.regs.x[7] = u64::from(id != target || physical_timer);
        state.regs.x[8] = u64::from(id != target || virtual_timer);
        state.regs.x[10] = 0x0800_0000;
        state.regs.x[11] = 2;
        state.regs.x[12] = u64::from(BOTH);
        state.regs.x[13] = 0x080a_0000 + id as u64 * 0x20000 + 0x10080;
        state.regs.x[14] = 0x080a_0000 + id as u64 * 0x20000 + 0x10100;
        state.regs.x[15] = 0xff;
        state.regs.x[16] = 1;
        state.regs.x[18] = if id == target { u64::from(software) } else { 0 };
        state.regs.x[19] = 0x080a_0000 + id as u64 * 0x20000 + 0x10200;
        fixture.vm.vcpus[id]
            .update_state(&CpuState::Aarch64(state))
            .unwrap();
        fixture.vm.coordinator.cursor = id;
        let turn = fixture.vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        assert_eq!(
            fixture.vm.vcpus[id].instruction_count(),
            program.len() as u64
        );
    }
    // The read program constructs its own addresses, including after PSCI has
    // reset every argument register other than X0.
    let mut reads = Vec::new();
    for id in 0..u32::from(count) {
        let address = 0x080a_0000 + id * 0x20000 + 0x10200;
        reads.extend([
            0xd280_0011 | ((address & 0xffff) << 5),
            0xf2a0_0011 | (((address >> 16) & 0xffff) << 5),
            0xb940_0220 | id,
        ]);
    }
    reads.push(WFI);
    write(&fixture.vm, READ, &reads);
    write(&fixture.vm, CALL, &[HVC, WFI]);
    fixture
}

fn reset_target(vm: &mut Vmm, target: usize) {
    let clock = vm.timing_context.checkpoint_state();
    let CpuState::Aarch64(mut state) = vm.vcpus[target].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = READ;
    state.sregs.cntp_ctl_el0 = 0;
    state.sregs.cntv_ctl_el0 = 0;
    let system = &mut state.sregs.execution.as_mut().unwrap().sysregs;
    system.cntp_ctl_el0 = 0;
    system.cntv_ctl_el0 = 0;
    vm.vcpus[target]
        .set_state(&CpuState::Aarch64(state))
        .unwrap();
    assert_eq!(vm.timing_context.checkpoint_state(), clock);
}

fn load_source_free(fixture: &Fixture, suffix: &str) -> SnapshotBundle {
    let saved = fixture
        .vm
        .take_snapshot_bundle(fixture.vm.coordinator.retired)
        .unwrap();
    let path = fixture.kernel.with_extension(suffix);
    saved.save(&path).unwrap();
    let loaded = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(&fixture.kernel).unwrap();
    loaded
}

fn fresh(bundle: &SnapshotBundle) -> Vmm {
    let config = VmConfig::from_checkpoint_bundle(bundle, CliConfig::default()).unwrap();
    assert!(!config.kernel.exists());
    Vmm::new_resume_bundle(config, bundle).unwrap()
}

fn public_cpu(vm: &Vmm, id: usize) -> crate::vm::vcpu::Aarch64CpuState {
    let CpuState::Aarch64(state) = vm.vcpus[id].get_state().unwrap() else {
        panic!()
    };
    state
}

fn assert_guest_pending(vm: &mut Vmm, target: usize, own: u32) {
    let peer_counts: Vec<_> = vm.vcpus.iter().map(|cpu| cpu.instruction_count()).collect();
    vm.coordinator.cursor = target;
    let turn = vm.execute_turn().unwrap().unwrap();
    assert_eq!(turn.cpu_index, target);
    assert!(matches!(turn.exit, VcpuExit::Hlt));
    let CpuState::Aarch64(state) = vm.vcpus[target].get_state().unwrap() else {
        panic!()
    };
    for (id, cpu) in vm.vcpus.iter().enumerate() {
        assert_eq!(
            state.regs.x[id] & u64::from(BOTH),
            u64::from(if id == target { own } else { BOTH })
        );
        if id != target {
            assert_eq!(cpu.instruction_count(), peer_counts[id]);
        }
    }
}

#[test]
fn reset_output_frontiers_survive_actual_source_free_one_two_four_cpu_files() {
    for count in [1, 2, 4] {
        for (virtual_timer, physical_timer, software) in [
            (true, true, 0),
            (true, false, PHYSICAL),
            (false, true, VIRTUAL),
        ] {
            let mut source = machine(count, virtual_timer, physical_timer, software);
            let target = usize::from(count) - 1;
            reset_target(&mut source.vm, target);
            // Capture before the next coordinator poll publishes the owed
            // deassertion. The shared GIC still contains the old timer level.
            let saved = load_source_free(&source, "timer-reset.rxc");
            let mut restored = fresh(&saved);
            assert_guest_pending(&mut source.vm, target, software);
            assert_guest_pending(&mut restored, target, software);
            assert_eq!(
                source.vm.timing_context.checkpoint_state(),
                restored.timing_context.checkpoint_state()
            );
            assert_eq!(source.vm.coordinator, restored.coordinator);
            assert_eq!(
                public_cpu(&source.vm, target),
                public_cpu(&restored, target)
            );
        }
    }
}

fn firmware(vm: &mut Vmm, cpu: usize, function: u64, target: usize) {
    let CpuState::Aarch64(mut state) = vm.vcpus[cpu].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CALL;
    state.regs.x[0] = function;
    state.regs.x[1] = target as u64;
    state.regs.x[2] = READ;
    state.regs.x[3] = 0;
    vm.vcpus[cpu]
        .update_state(&CpuState::Aarch64(state))
        .unwrap();
    vm.vcpus[cpu].wake();
    vm.coordinator.cursor = cpu;
    vm.execute_turn().unwrap();
}

#[test]
fn guest_psci_restart_withdraws_old_timer_outputs_after_an_off_cpu_file_frontier() {
    for count in [2, 4] {
        let mut source = machine(count, true, true, 0);
        let target = usize::from(count) - 1;
        firmware(&mut source.vm, target, 0x8400_0002, target);
        assert!(!source.vm.coordinator.online[target]);
        let saved = load_source_free(&source, "timer-psci-off.rxc");
        let mut restored = fresh(&saved);
        for vm in [&mut source.vm, &mut restored] {
            firmware(vm, 0, 0xc400_0003, target);
            assert!(vm.coordinator.online[target]);
            assert_eq!(
                vm.vcpus[0]
                    .get_state()
                    .unwrap()
                    .as_aarch64()
                    .unwrap()
                    .regs
                    .x[0],
                0
            );
            assert_guest_pending(vm, target, 0);
        }
        assert_eq!(
            source.vm.timing_context.checkpoint_state(),
            restored.timing_context.checkpoint_state()
        );
        assert_eq!(source.vm.coordinator, restored.coordinator);
    }
}

#[test]
fn final_cpu_record_rejection_keeps_the_live_reset_publication_frontier() {
    for count in [2, 4] {
        let mut fixture = machine(count, true, true, 0);
        let target = usize::from(count) - 1;
        reset_target(&mut fixture.vm, target);
        let mut saved = fixture
            .vm
            .take_snapshot_bundle(fixture.vm.coordinator.retired)
            .unwrap();
        let mut records = saved.take_backend_contexts().unwrap().entries().to_vec();
        records.last_mut().unwrap().as_mut().unwrap().data.pop();
        let bad = saved.with_backend_contexts(records).unwrap();
        let before = public_cpu(&fixture.vm, target);
        let clock = fixture.vm.timing_context.checkpoint_state();
        let graph = fixture.graph();
        assert!(fixture.vm.restore_snapshot_bundle(&bad).is_err());
        assert_eq!(public_cpu(&fixture.vm, target), before);
        assert_eq!(fixture.vm.timing_context.checkpoint_state(), clock);
        assert_eq!(fixture.graph(), graph);
        assert_guest_pending(&mut fixture.vm, target, 0);
    }
}

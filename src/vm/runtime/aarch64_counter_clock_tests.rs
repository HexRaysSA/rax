//! Architectural counter observations through the real software VMM adapters.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::{RetirementStop, VcpuExit};

const CNTPCT_X0: u32 = 0xd53b_e020;
const CNTVCT_X1: u32 = 0xd53b_e041;
const WFI: u32 = 0xd503_207f;
const NOP: u32 = 0xd503_201f;
const FREQUENCY: u128 = 62_500_000;

fn retired(count: u8, program: &[u32]) -> Vmm {
    machine(count, program, ClockMode::Retired)
}

fn machine(count: u8, program: &[u32], mode: ClockMode) -> Vmm {
    let fixture = Fixture::new(count);
    let config = VmConfig::from_checkpoint(
        fixture.vm.checkpoint_config.clone(),
        CliConfig::default(),
        fixture.vm.guest_mem.size(),
    )
    .unwrap();
    let mut vm = Vmm::new_resume_with_clock(config, mode).unwrap();
    for id in 0..usize::from(count) {
        let pc = CODE + id as u64 * 0x100;
        vm.guest_mem
            .memory()
            .write_slice(
                &program
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>(),
                GuestAddress(pc),
            )
            .unwrap();
        vm.vcpus[id]
            .set_state(&CpuState::aarch64(
                Aarch64Registers {
                    pc,
                    pstate: 0x3c5,
                    ..Default::default()
                },
                Default::default(),
            ))
            .unwrap();
    }
    let cluster = vm
        .vm
        .as_any()
        .downcast_ref::<EmulatorVm>()
        .unwrap()
        .arm_cluster()
        .unwrap();
    for id in 1..count {
        assert_eq!(
            cluster
                .request_on(u64::from(id), CODE + u64::from(id) * 0x100, 0, 0x3c5)
                .unwrap(),
            0
        );
    }
    vm.route_interprocessor_requests().unwrap(); // Platform startup request, not guest PSCI.
    vm
}

fn sample(vm: &mut Vmm, id: usize, register: usize) -> u64 {
    let result = step(vm, id);
    assert_eq!(result.retired, 1);
    let CpuState::Aarch64(state) = vm.vcpus[id].get_state().unwrap() else {
        panic!()
    };
    state.regs.x[register]
}

fn step(vm: &mut Vmm, id: usize) -> crate::vm::vcpu::RetirementRun {
    let _binding = vm.timing_context.enter();
    let result = vm.vcpus[id].run_retirement_budget(1).unwrap();
    vm.coordinator.retired = vm.coordinator.retired.wrapping_add(result.retired);
    result
}

fn expected(vm: &Vmm) -> u64 {
    let clock = vm.timing_context.checkpoint_state();
    // Independent widened integer formula, not the implementation helper.
    (((u128::from(clock.elapsed_nanos) * 3 + u128::from(clock.subnanosecond_quanta)) * FREQUENCY)
        / 3_000_000_000) as u64
}

#[test]
fn selected_counter_uses_one_vm_time_domain_for_one_two_four_prepared_pes() {
    for count in [1, 2, 4] {
        let mut vm = retired(count, &[CNTPCT_X0, CNTVCT_X1, WFI]);
        let mut clock = vm.timing_context.checkpoint_state();
        clock.elapsed_nanos = 1_000_000_000;
        clock.subnanosecond_quanta = 2;
        vm.timing_context.restore_checkpoint_state(&clock).unwrap();
        for id in 0..usize::from(count) {
            let wanted = expected(&vm);
            assert_eq!(sample(&mut vm, id, 0), wanted, "physical PE{id}");
            let wanted = expected(&vm);
            assert_eq!(sample(&mut vm, id, 1), wanted, "virtual PE{id}");
        }
    }
}

#[test]
fn waiting_attempts_and_foreign_scopes_cannot_advance_the_selected_counter() {
    let mut vm = retired(1, &[WFI, CNTPCT_X0, NOP]);
    let first = step(&mut vm, 0);
    assert_eq!(first.retired, 1);
    assert!(matches!(first.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    let clock = vm.timing_context.checkpoint_state();
    let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    foreign.advance_retired(9_000_000_000).unwrap();
    let _foreign = foreign.enter();
    for _ in 0..5 {
        let result = step(&mut vm, 0);
        assert_eq!(result.retired, 0);
        assert!(matches!(result.stop, RetirementStop::Exit(VcpuExit::Hlt)));
    }
    assert_eq!(vm.timing_context.checkpoint_state(), clock);
    vm.vcpus[0].wake();
    let wanted = expected(&vm);
    assert_eq!(sample(&mut vm, 0, 0), wanted);
}

#[test]
fn guest_virtual_offsets_and_frequency_metadata_preserve_the_platform_rate() {
    let mut vm = retired(
        4,
        &[
            0xd51c_e064,
            0xd51b_e005,
            CNTPCT_X0,
            CNTVCT_X1,
            0xd53b_e00a,
            WFI,
        ],
    );
    let mut clock = vm.timing_context.checkpoint_state();
    clock.elapsed_nanos = 1_000_000_000;
    vm.timing_context.restore_checkpoint_state(&clock).unwrap();
    for (id, offset) in [0, 13, 62_500_001, u64::MAX].into_iter().enumerate() {
        let CpuState::Aarch64(mut state) = vm.vcpus[id].get_state().unwrap() else {
            panic!()
        };
        state.regs.pstate = 0x3cd; // EL3h: frequency and virtualization controls.
        state.regs.x[4] = offset;
        state.regs.x[5] = 1 + id as u64;
        vm.vcpus[id]
            .update_state(&CpuState::Aarch64(state))
            .unwrap();
        assert_eq!(step(&mut vm, id).retired, 1);
        assert_eq!(step(&mut vm, id).retired, 1);
        let physical = expected(&vm);
        assert_eq!(sample(&mut vm, id, 0), physical);
        let physical = expected(&vm);
        assert_eq!(sample(&mut vm, id, 1), physical.wrapping_sub(offset));
        assert_eq!(sample(&mut vm, id, 10), 1 + id as u64);
    }
}

#[test]
fn another_pes_retirement_asserts_and_clears_a_waiting_pes_timer_ppi() {
    use crate::vm::snapshot::SnapshotBundle;
    for count in [2, 4] {
        let program = [
            0xb900_014b, // STR W11,[X10]: distributor control.
            0xb900_01ac, // STR W12,[X13]: private interrupt group.
            0xb900_01cc, // STR W12,[X14]: private interrupt enable.
            0xd518_460f, // MSR ICC_PMR_EL1,X15.
            0xd518_ccf0, // MSR ICC_IGRPEN1_EL1,X16.
            0xd51b_e246, // MSR CNTP_CVAL_EL0,X6.
            0xd51b_e227, // MSR CNTP_CTL_EL0,X7.
            WFI,
            CNTPCT_X0,
            0xd51b_e23f,
            WFI,
        ];
        let mut vm = retired(count, &program);
        let target = usize::from(count) - 1;
        let CpuState::Aarch64(mut state) = vm.vcpus[target].get_state().unwrap() else {
            panic!()
        };
        state.regs.x[6] = 1;
        state.regs.x[7] = 1;
        state.regs.x[10] = 0x0800_0000;
        state.regs.x[11] = 2;
        state.regs.x[12] = 1 << 30;
        state.regs.x[13] = 0x080a_0000 + target as u64 * 0x20000 + 0x10080;
        state.regs.x[14] = 0x080a_0000 + target as u64 * 0x20000 + 0x10100;
        state.regs.x[15] = 0xff;
        state.regs.x[16] = 1;
        vm.vcpus[target]
            .update_state(&CpuState::Aarch64(state))
            .unwrap();
        for _ in 0..8 {
            assert_eq!(step(&mut vm, target).retired, 1);
        }
        assert_eq!(expected(&vm), 0);
        let CpuState::Aarch64(mut state) = vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        for id in 0..usize::from(count) {
            state.regs.x[17 + id] = 0x080a_0000 + id as u64 * 0x20000 + 0x10200;
        }
        vm.vcpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
        let reads: Vec<_> = (0..u32::from(count))
            .map(|id| 0xb940_0000 | ((17 + id) << 5) | id)
            .collect();
        let code: Vec<_> = [NOP; 48]
            .into_iter()
            .chain(reads)
            .chain([WFI])
            .flat_map(u32::to_le_bytes)
            .collect();
        vm.guest_mem
            .memory()
            .write_slice(&code, GuestAddress(CODE))
            .unwrap();
        vm.coordinator.cursor = 0;
        let turn = vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, 0);
        assert_eq!(vm.vcpus[target].instruction_count(), 8);
        let CpuState::Aarch64(state) = vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        for id in 0..usize::from(count) {
            assert_eq!(
                state.regs.x[id] & (1 << 30),
                if id == target { 1 << 30 } else { 0 }
            );
        }
        let saved = vm.take_snapshot_bundle(vm.coordinator.retired).unwrap();
        let path = std::env::temp_dir().join(format!(
            "rax-counter-ppi-{}-{count}.rxc",
            std::process::id()
        ));
        saved.save(&path).unwrap();
        let loaded = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        for machine in [&mut vm, &mut restored] {
            let wanted = expected(machine);
            machine.coordinator.cursor = target;
            let turn = machine.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, target);
            assert_eq!(machine.vcpus[target].instruction_count(), 11);
            let CpuState::Aarch64(state) = machine.vcpus[target].get_state().unwrap() else {
                panic!()
            };
            assert_eq!(state.regs.x[0], wanted);
            machine.vcpus[0].set_current_pc(CODE + 48 * 4).unwrap();
            machine.vcpus[0].wake();
            machine.coordinator.cursor = 0;
            machine.execute_turn().unwrap().unwrap();
            let CpuState::Aarch64(state) = machine.vcpus[0].get_state().unwrap() else {
                panic!()
            };
            for id in 0..usize::from(count) {
                assert_eq!(state.regs.x[id] & (1 << 30), 0);
            }
        }
        assert_eq!(
            vm.timing_context.checkpoint_state(),
            restored.timing_context.checkpoint_state()
        );
    }
}

#[test]
fn source_free_counter_files_rebind_one_two_four_pes_and_keep_phase_and_wrap() {
    use crate::vm::snapshot::SnapshotBundle;
    for (count, phase, nanos) in [
        (1, 0, 1_000_000_015),
        (2, 1, 1_000_000_015),
        (4, 2, u64::MAX - 1),
    ] {
        let mut source = retired(
            count,
            &[CNTPCT_X0, CNTVCT_X1, 0xd53b_e022, 0xd53b_e043, WFI],
        );
        let mut clock = source.timing_context.checkpoint_state();
        clock.elapsed_nanos = nanos;
        clock.subnanosecond_quanta = phase;
        if count == 4 {
            clock.retired_units = u64::MAX - 1;
            source.coordinator.retired = clock.retired_units;
        }
        source
            .timing_context
            .restore_checkpoint_state(&clock)
            .unwrap();
        for id in 0..usize::from(count) {
            let wanted = expected(&source);
            assert_eq!(sample(&mut source, id, 0), wanted);
        }
        let saved = source
            .take_snapshot_bundle(source.coordinator.retired)
            .unwrap();
        assert!(
            saved
                .backend_contexts()
                .unwrap()
                .entries()
                .iter()
                .all(|entry| { entry.as_ref().unwrap().data.starts_with(b"RAXA6404") })
        );
        let path = std::env::temp_dir().join(format!(
            "rax-counter-file-{}-{count}.rxc",
            std::process::id()
        ));
        saved.save(&path).unwrap();
        let loaded = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        assert!(!config.kernel.exists());
        let mut target = if count == 4 {
            let mut target = retired(count, &[WFI]);
            let mut skew = target.timing_context.checkpoint_state();
            skew.elapsed_nanos = 7_000_000_000;
            skew.retired_units = 99;
            skew.subnanosecond_quanta = 1;
            target
                .timing_context
                .restore_checkpoint_state(&skew)
                .unwrap();
            target.coordinator.retired = 99;
            target.restore_snapshot_bundle(&loaded).unwrap();
            target
        } else {
            Vmm::new_resume_bundle(config, &loaded).unwrap()
        };
        let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        foreign.advance_retired(12_000_000_000).unwrap();
        let _foreign = foreign.enter();
        for id in 0..usize::from(count) {
            for register in [1, 2, 3] {
                let wanted = expected(&source);
                assert_eq!(sample(&mut source, id, register), wanted);
                assert_eq!(sample(&mut target, id, register), wanted);
            }
        }
        assert_eq!(
            source.timing_context.checkpoint_state(),
            target.timing_context.checkpoint_state()
        );
        assert_eq!(source.coordinator.retired, target.coordinator.retired);
    }
}

#[test]
fn final_counter_binding_rejection_preserves_cpu_clock_coordinator_gic_and_ram() {
    let mut source = retired(4, &[NOP, WFI]);
    let mut saved = source.take_snapshot_bundle(0).unwrap();
    let mut entries = saved.take_backend_contexts().unwrap().entries().to_vec();
    entries[3].as_mut().unwrap().data[9..17].copy_from_slice(&62_500_001u64.to_le_bytes());
    let bad = saved.with_backend_contexts(entries).unwrap();
    let mut target = retired(4, &[WFI]);
    let mut clock = target.timing_context.checkpoint_state();
    clock.elapsed_nanos = 17;
    clock.subnanosecond_quanta = 2;
    target
        .timing_context
        .restore_checkpoint_state(&clock)
        .unwrap();
    target
        .guest_mem
        .memory()
        .write_slice(&0x1234_abcdu32.to_le_bytes(), GuestAddress(CODE + 0x2000))
        .unwrap();
    let before = cpu_image(&target);
    let cluster = target
        .vm
        .as_any()
        .downcast_ref::<EmulatorVm>()
        .unwrap()
        .arm_cluster()
        .unwrap();
    let graph = crate::codec::serialize(&cluster.checkpoint().unwrap()).unwrap();
    let execution = target.coordinator.clone();
    assert!(
        target
            .restore_snapshot_bundle(&bad)
            .unwrap_err()
            .to_string()
            .contains("system counter")
    );
    assert_eq!(target.timing_context.checkpoint_state(), clock);
    assert_eq!(cpu_image(&target), before);
    assert_eq!(target.coordinator, execution);
    assert_eq!(
        crate::codec::serialize(&cluster.checkpoint().unwrap()).unwrap(),
        graph
    );
    let mut raw = [0; 4];
    target
        .guest_mem
        .memory()
        .read_slice(&mut raw, GuestAddress(CODE + 0x2000))
        .unwrap();
    assert_eq!(u32::from_le_bytes(raw), 0x1234_abcd);
}

fn cpu_image(vm: &Vmm) -> Vec<u8> {
    crate::codec::serialize(
        &vm.vcpus
            .iter()
            .map(|cpu| (cpu.get_state().unwrap(), cpu.instruction_count()))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn shared_counter_files_require_one_complete_domain_and_legacy_files_remain_legacy() {
    use crate::vm::snapshot::SnapshotBundle;
    let source = retired(2, &[WFI]);
    for defect in 0..5 {
        let mut bundle = source.take_snapshot_bundle(0).unwrap();
        match defect {
            0 => {
                bundle.take_clock();
            }
            1 => {
                bundle.take_execution();
            }
            2 => {
                bundle.take_cpus();
            }
            3 | 4 => {
                let mut records = bundle.take_backend_contexts().unwrap().entries().to_vec();
                if defect == 3 {
                    let entry = records[0].as_mut().unwrap();
                    let mut data = b"RAXA6403".to_vec();
                    data.extend_from_slice(&entry.data[17..]);
                    entry.data = data;
                } else {
                    records[0] = None;
                }
                bundle = bundle.with_backend_contexts(records).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default())
                .and_then(|config| config.validate_resume_bundle(&bundle))
                .is_err(),
            "defect {defect}"
        );
    }
    // V3's unchanged payload schema has no VM-counter binding. Importing an
    // entirely legacy set must preserve that domain rather than invent one.
    let mut bundle = source.take_snapshot_bundle(0).unwrap();
    let mut records = bundle.take_backend_contexts().unwrap().entries().to_vec();
    for entry in &mut records {
        let entry = entry.as_mut().unwrap();
        let mut data = b"RAXA6403".to_vec();
        data.extend_from_slice(&entry.data[17..]);
        entry.data = data;
    }
    let bundle = bundle.with_backend_contexts(records).unwrap();
    let path = std::env::temp_dir().join(format!("rax-counter-legacy-{}.rxc", std::process::id()));
    bundle.save(&path).unwrap();
    let loaded = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    let captured = target.take_snapshot_bundle(0).unwrap();
    assert!(
        captured
            .backend_contexts()
            .unwrap()
            .entries()
            .iter()
            .flatten()
            .all(|record| { record.data.starts_with(b"RAXA6403") })
    );
}

#[test]
fn hot_system_counter_loop_keeps_the_selected_clock_under_bounded_native_execution() {
    let mut vm = retired(1, &[CNTPCT_X0, 0x9100_0421, 0xf108_003f, 0x54ff_ffa1, WFI]);
    let mut clock = vm.timing_context.checkpoint_state();
    clock.elapsed_nanos = 1_000_000_015;
    clock.subnanosecond_quanta = 1;
    vm.timing_context.restore_checkpoint_state(&clock).unwrap();
    let mut finished = false;
    for _ in 0..8 {
        if let Some(turn) = vm.execute_turn().unwrap() {
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            finished = true;
            break;
        }
    }
    assert!(finished);
    let CpuState::Aarch64(state) = vm.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(state.regs.x[1], 512);
    let last_read = 4 * 511;
    let wanted = (((u128::from(clock.elapsed_nanos) * 3
        + u128::from(clock.subnanosecond_quanta)
        + last_read)
        * FREQUENCY)
        / 3_000_000_000) as u64;
    assert_eq!(state.regs.x[0], wanted);
    assert_eq!(vm.coordinator.retired, 2049);
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    assert!(vm.vcpus[0].bounded_native_test_count() > 0);
}

#[test]
fn wall_counter_reads_follow_the_owning_vm_time_across_pes() {
    let mut vm = machine(2, &[CNTPCT_X0, WFI], ClockMode::Wall);
    let mut observations = Vec::new();
    for id in 0..2 {
        let before = vm.timing_context.counter_ticks(FREQUENCY as u64);
        let value = sample(&mut vm, id, 0);
        let after = vm.timing_context.counter_ticks(FREQUENCY as u64);
        assert!(before <= value && value <= after);
        observations.push(value);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(observations[1] > observations[0]);
}

#[test]
fn el1_offset_access_vectors_without_retiring_or_mutating_the_offset_bank() {
    for instruction in [0xd51c_e064, 0xd53c_e064] {
        let mut vm = retired(1, &[instruction]);
        let before = vm.timing_context.checkpoint_state();
        let result = step(&mut vm, 0);
        assert_eq!(result.retired, 0);
        assert!(matches!(result.stop, RetirementStop::StateChange));
        assert_eq!(vm.timing_context.checkpoint_state(), before);
        let CpuState::Aarch64(state) = vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.sregs.elr_el1, CODE);
        assert_eq!(state.sregs.esr_el1 >> 26, 0);
        assert_eq!(state.sregs.execution.unwrap().sysregs.cntvoff_el2, 0);
    }
}

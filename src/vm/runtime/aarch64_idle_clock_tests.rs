use super::*;
use crate::vm::snapshot::SnapshotBundle;

const FIRST_COMPARE: u64 = 16;
const PERIOD_NANOS: u64 = 16; // 62.5 MHz platform counter.
const IDLE_CLOCK: ClockMode = ClockMode::RetiredWithIdle;

fn prepare(count: u8, mode: ClockMode, masked: bool) -> Vmm {
    let mut vm = machine(count, &[WFI], mode);
    for id in 0..usize::from(count) {
        let target = usize::from(count) - 1;
        let virtual_timer = id == target;
        let program = [
            0xb900_014b, // STR W11,[X10]: distributor control.
            0xb900_01ac, // STR W12,[X13]: private interrupt group.
            0xb900_01cc, // STR W12,[X14]: private interrupt enable.
            0xd518_460f, // MSR ICC_PMR_EL1,X15.
            0xd518_ccf0, // MSR ICC_IGRPEN1_EL1,X16.
            if virtual_timer {
                0xd51b_e346
            } else {
                0xd51b_e246
            }, // CVAL, X6.
            if virtual_timer {
                0xd51b_e327
            } else {
                0xd51b_e227
            }, // CTL, X7.
            WFI,
            CNTPCT_X0,
            if virtual_timer {
                0xd51b_e33f
            } else {
                0xd51b_e23f
            }, // CTL, XZR.
            WFI,
        ];
        let CpuState::Aarch64(mut state) = vm.vcpus[id].get_state().unwrap() else {
            panic!("expected an AArch64 state");
        };
        vm.guest_mem
            .memory()
            .write_slice(
                &program
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
                GuestAddress(state.regs.pc),
            )
            .unwrap();
        state.regs.x[6] = FIRST_COMPARE + (target - id) as u64 * 8;
        state.regs.x[7] = if masked { 3 } else { 1 };
        state.regs.x[10] = 0x0800_0000;
        state.regs.x[11] = 2;
        state.regs.x[12] = 1 << if virtual_timer { 27 } else { 30 };
        state.regs.x[13] = 0x080a_0000 + id as u64 * 0x20000 + 0x10080;
        state.regs.x[14] = 0x080a_0000 + id as u64 * 0x20000 + 0x10100;
        state.regs.x[15] = 0xff;
        state.regs.x[16] = 1;
        vm.vcpus[id]
            .update_state(&CpuState::Aarch64(state))
            .unwrap();
    }
    for id in 0..usize::from(count) {
        let turn = vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        // Timer deadlines cannot jump while any peer is still running.
        assert_eq!(vm.coordinator.retired, (id as u64 + 1) * 8);
        assert_eq!(expected(&vm), 0);
    }
    vm
}

fn resume_timer_sequence(vm: &mut Vmm, count: u8) -> Vec<(usize, u64)> {
    let mut wakes = Vec::new();
    let mut seen = vec![false; usize::from(count)];
    let first = vm.coordinator.retired;
    for _ in 0..usize::from(count).pow(2) {
        let turn = vm.execute_turn().unwrap().unwrap();
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        let id = turn.cpu_index;
        let CpuState::Aarch64(state) = vm.vcpus[id].get_state().unwrap() else {
            panic!("expected an AArch64 state");
        };
        if state.regs.x[0] != 0 && !seen[id] {
            seen[id] = true;
            wakes.push((id, state.regs.x[0]));
        }
        if wakes.len() == usize::from(count) {
            break;
        }
    }
    assert_eq!(
        wakes,
        (0..usize::from(count))
            .rev()
            .enumerate()
            .map(|(order, id)| (id, FIRST_COMPARE + order as u64 * 8))
            .collect::<Vec<_>>()
    );
    let last = FIRST_COMPARE + u64::from(count - 1) * 8;
    let clock = vm.timing_context.checkpoint_state();
    assert_eq!(clock.elapsed_nanos, last * PERIOD_NANOS + 1);
    assert_eq!(clock.subnanosecond_quanta, 0);
    assert_eq!(clock.retired_units, first + u64::from(count) * 3);
    assert_eq!(clock.retired_units, vm.coordinator.retired);
    wakes
}

#[test]
fn all_waiting_pes_wake_in_timer_order_without_fabricated_retirements() {
    for count in [1, 2, 4] {
        let mut vm = prepare(count, IDLE_CLOCK, false);
        resume_timer_sequence(&mut vm, count);
    }
}

#[test]
fn source_free_checkpoint_resumes_the_same_idle_wakes() {
    let mut vm = prepare(4, IDLE_CLOCK, false);
    let mut clock = vm.timing_context.checkpoint_state();
    clock.subnanosecond_quanta = 2;
    vm.timing_context.restore_checkpoint_state(&clock).unwrap();
    let path = std::env::temp_dir().join(format!("rax-idle-wait-{}.rxc", std::process::id()));
    vm.take_snapshot_bundle(vm.coordinator.retired)
        .unwrap()
        .save(&path)
        .unwrap();
    let bundle = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(bundle.clock(), Some(&clock));
    assert!(!vm.checkpoint_config.kernel.exists());
    let original_wakes = resume_timer_sequence(&mut vm, 4);
    let original_clock = vm.timing_context.checkpoint_state();
    let original_cpu_table: Vec<_> = vm
        .vcpus
        .iter()
        .map(|cpu| cpu.get_state().unwrap())
        .collect();
    drop(vm);

    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &bundle).unwrap();
    assert_eq!(resumed.timing_context.checkpoint_state(), clock);
    assert_eq!(resume_timer_sequence(&mut resumed, 4), original_wakes);
    assert_eq!(resumed.timing_context.checkpoint_state(), original_clock);
    for (cpu, state) in resumed.vcpus.iter().zip(original_cpu_table) {
        let (CpuState::Aarch64(actual), CpuState::Aarch64(expected)) =
            (cpu.get_state().unwrap(), state)
        else {
            panic!("expected AArch64 states");
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn masked_timers_and_legacy_retirement_keep_the_clock_frozen() {
    for (mode, masked) in [(ClockMode::Retired, false), (IDLE_CLOCK, true)] {
        let mut vm = prepare(2, mode, masked);
        let clock = vm.timing_context.checkpoint_state();
        for _ in 0..6 {
            assert!(matches!(
                vm.execute_turn().unwrap().unwrap().exit,
                VcpuExit::Hlt
            ));
        }
        assert_eq!(vm.timing_context.checkpoint_state(), clock);
    }
}

#[cfg(feature = "debug")]
#[test]
fn paused_debugger_keeps_a_waiting_cluster_at_its_current_time() {
    let mut vm = prepare(2, IDLE_CLOCK, false);
    let clock = vm.timing_context.checkpoint_state();
    vm.gdb_stopped = true;
    assert!(vm.execute_turn().unwrap().is_none());
    assert_eq!(vm.timing_context.checkpoint_state(), clock);
    vm.gdb_stopped = false;
    resume_timer_sequence(&mut vm, 2);
}

#[test]
fn idle_mode_rejects_unimplemented_architectures_and_native_backends_at_admission() {
    let vm = machine(1, &[WFI], IDLE_CLOCK);
    let config = VmConfig::from_checkpoint(
        vm.checkpoint_config.clone(),
        CliConfig::default(),
        vm.guest_mem.size(),
    )
    .unwrap();
    let mut other_arch = config.clone();
    other_arch.arch = crate::config::ArchKind::X86_64;
    assert!(
        matches!(Vmm::new_with_clock(other_arch, IDLE_CLOCK), Err(error)
        if error.to_string().contains("idle-enabled VM clock requires software AArch64"))
    );
    for backend in [
        crate::config::BackendKind::Kvm,
        crate::config::BackendKind::Hvf,
    ] {
        let mut native = config.clone();
        native.backend = backend;
        assert!(matches!(Vmm::new_with_clock(native, IDLE_CLOCK), Err(error)
            if error.to_string().contains("retired VM clock requires the software backend")));
    }
}

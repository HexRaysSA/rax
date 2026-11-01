//! Guest-driven native CPU_ON and actual scheduled file continuation.
use super::*;
const MARKERS: u64 = 0x40010000;
const RESULTS: u64 = 0x40010100;
#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_guest_cpu_on_starts_secondaries_and_continues_after_real_file_restore() {
    for count in [2, 4] {
        let fixture = Fixture::new();
        let mut vm = Vmm::new_resume(fixture.config(count)).unwrap();
        let code: &[u8] = match count {
            2 => {
                include_bytes!("../../../docs/development/native-arm64-checkpoints/psci/boot-2.bin")
            }
            4 => {
                include_bytes!("../../../docs/development/native-arm64-checkpoints/psci/boot-4.bin")
            }
            _ => unreachable!(),
        };
        vm.guest_mem
            .memory()
            .write_slice(code, GuestAddress(CODE))
            .unwrap();
        publish_native_code(&vm.guest_mem, CODE, code.len());
        for id in 1..count {
            vm.guest_mem
                .memory()
                .write_obj(u64::MAX, GuestAddress(RESULTS + u64::from(id) * 8))
                .unwrap();
        }
        let CpuState::Aarch64(mut state) = vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.pstate = 0x3c5;
        vm.vcpus[0].set_state(&CpuState::Aarch64(state)).unwrap();
        assert_eq!(
            vm.coordinator.online,
            vec![true, false]
                .into_iter()
                .chain(std::iter::repeat_n(false, usize::from(count) - 2))
                .collect::<Vec<_>>()
        );
        let mut visits = vec![0u32; usize::from(count)];
        drive_native_boot(&mut vm, &mut visits, 1);
        for id in 1..count {
            let result: u64 = vm
                .guest_mem
                .memory()
                .read_obj(GuestAddress(RESULTS + u64::from(id) * 8))
                .unwrap();
            assert_eq!(result, 0, "CPU_ON for CPU{id} did not succeed");
        }
        assert!(vm.coordinator.online.iter().all(|online| *online));
        let markers: Vec<u64> = (0..count)
            .map(|id| {
                vm.guest_mem
                    .memory()
                    .read_obj(GuestAddress(MARKERS + u64::from(id) * 8))
                    .unwrap()
            })
            .collect();
        for (id, value) in markers.iter().enumerate() {
            assert!(*value >= (id as u64 + 1) * 0x1000 + 1);
        }
        let saved = vm.take_snapshot_bundle(0).unwrap();
        saved.save(&fixture.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        let coordinator = vm.coordinator.clone();
        drop(vm);
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(restored.coordinator, coordinator);
        if let Some(path) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
            let path = std::path::PathBuf::from(path);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::copy(
                &fixture.checkpoint,
                path.join(format!("native-psci-boot-{count}.rxc")),
            )
            .unwrap();
        }
        visits.fill(0);
        drive_native_boot(&mut restored, &mut visits, 1);
        for (id, old) in markers.into_iter().enumerate() {
            let current: u64 = restored
                .guest_mem
                .memory()
                .read_obj(GuestAddress(MARKERS + id as u64 * 8))
                .unwrap();
            assert!(current > old, "CPU{id} failed to continue after restore");
        }
    }
}
fn drive_native_boot(vm: &mut Vmm, visits: &mut [u32], minimum: u32) {
    for _ in 0..1000 {
        let Some(turn) = vm.execute_turn().unwrap() else {
            continue;
        };
        match turn.exit {
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                visits[turn.cpu_index] += 1;
                vm.vcpus[turn.cpu_index].complete_io_in(&0u64.to_le_bytes());
                vm.vcpus[turn.cpu_index].io_completion_result().unwrap();
                if turn.cpu_index == 0 {
                    for id in 1..visits.len() {
                        let result: u64 = vm
                            .guest_mem
                            .memory()
                            .read_obj(GuestAddress(RESULTS + id as u64 * 8))
                            .unwrap();
                        assert_eq!(result, 0, "guest CPU_ON result for CPU{id}");
                    }
                }
            }
            VcpuExit::Hlt => (),
            exit => panic!("unexpected native PSCI boot exit: {exit:?}"),
        }
        if visits.iter().all(|value| *value >= minimum) {
            return;
        }
    }
    panic!("native CPU startup/coordinator made insufficient progress: {visits:?}");
}

// Older private-state fixtures explicitly prepare AP registers. First perform
// real firmware startup so their direct AP entry respects the native power graph.
pub(super) fn boot_native_secondaries(vm: &mut Vmm) {
    let count = vm.vcpus.len();
    if count == 1 {
        return;
    }
    let code: &[u8] = match count {
        2 => include_bytes!("../../../docs/development/native-arm64-checkpoints/psci/boot-2.bin"),
        4 => include_bytes!("../../../docs/development/native-arm64-checkpoints/psci/boot-4.bin"),
        _ => panic!("unsupported native fixture count"),
    };
    vm.guest_mem
        .memory()
        .write_slice(code, GuestAddress(CODE))
        .unwrap();
    publish_native_code(&vm.guest_mem, CODE, code.len());
    let CpuState::Aarch64(mut state) = vm.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CODE;
    state.regs.pstate = 0x3c5;
    vm.vcpus[0].set_state(&CpuState::Aarch64(state)).unwrap();
    for _ in 0..100 {
        match vm.vcpus[0].run().unwrap() {
            VcpuExit::Hlt => (),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                vm.vcpus[0].complete_io_in(&0u64.to_le_bytes());
                vm.vcpus[0].io_completion_result().unwrap();
                vm.route_interprocessor_requests().unwrap();
                assert!(vm.coordinator.online.iter().all(|online| *online));
                return;
            }
            exit => panic!("native fixture startup: {exit:?}"),
        }
    }
    panic!("native fixture startup made no progress");
}

fn call(vm: &mut Vmm, function: u32, arguments: [u64; 3], smc: bool, big_endian: bool) -> u64 {
    let pc = CODE + 0x800;
    let instructions = [if smc { 0xd4000003u32 } else { 0xd4000002u32 }, 0xf940016a]; // HVC/SMC; LDR X10,[X11]
    for (i, word) in instructions.into_iter().enumerate() {
        vm.guest_mem
            .memory()
            .write_obj(word.to_le(), GuestAddress(pc + i as u64 * 4))
            .unwrap();
    }
    publish_native_code(&vm.guest_mem, pc, 8);
    let CpuState::Aarch64(mut state) = vm.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = pc;
    state.regs.pstate = 0x3c5;
    state.regs.x[0] = u64::from(function);
    state.regs.x[1..4].copy_from_slice(&arguments);
    state.regs.x[11] = UART;
    state.sregs.sctlr_el1 = (state.sregs.sctlr_el1 & !(1 << 25)) | (u64::from(big_endian) << 25);
    vm.vcpus[0].set_state(&CpuState::Aarch64(state)).unwrap();
    for _ in 0..100 {
        match vm.vcpus[0].run().unwrap() {
            VcpuExit::Hlt => (),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => {
                vm.vcpus[0].complete_io_in(&0u64.to_le_bytes());
                vm.vcpus[0].io_completion_result().unwrap();
                let CpuState::Aarch64(state) = vm.vcpus[0].get_state().unwrap() else {
                    panic!()
                };
                return state.regs.x[0];
            }
            exit => panic!("firmware call {function:#x}: {exit:?}"),
        }
    }
    panic!("native firmware call failed to return");
}
fn load_boot(vm: &Vmm, count: u8) {
    let code: &[u8] = if count == 2 {
        include_bytes!("../../../docs/development/native-arm64-checkpoints/psci/boot-2.bin")
    } else {
        include_bytes!("../../../docs/development/native-arm64-checkpoints/psci/boot-4.bin")
    };
    vm.guest_mem
        .memory()
        .write_slice(code, GuestAddress(CODE))
        .unwrap();
    publish_native_code(&vm.guest_mem, CODE, code.len());
}
fn save_restore(vm: Vmm, fixture: &Fixture, evidence_name: &str) -> Vmm {
    let saved = vm.take_snapshot_bundle(0).unwrap();
    saved.save(&fixture.checkpoint).unwrap();
    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    let coordinator = vm.coordinator.clone();
    if let Some(path) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::copy(&fixture.checkpoint, path.join(evidence_name)).unwrap();
    }
    drop(vm);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert_eq!(restored.coordinator, coordinator);
    restored
}
#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_pending_start_failure_retains_remaining_cpus_through_real_file() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(4)).unwrap();
    load_boot(&vm, 4);
    for id in 1..4 {
        assert_eq!(
            call(
                &mut vm,
                0xc4000003,
                [id, CODE + id * 0x100, MARKERS + id * 8],
                false,
                false
            ),
            0
        );
    }
    vm.vm
        .as_any()
        .downcast_ref::<crate::backend::hvf::HvfArm64Vm>()
        .unwrap()
        .fail_next_gpr_writes(2, 0, 1);
    assert!(vm.route_interprocessor_requests().is_err());
    assert_eq!(vm.coordinator.online, [true, true, false, false]);
    for id in [2, 3] {
        assert!(
            matches!(vm.vcpus[id].run().unwrap(), VcpuExit::Hlt),
            "unacknowledged CPU{id} entered native execution"
        );
    }
    let pending = vm.vm.take_cpu_power_requests().unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(vm.vm.take_cpu_power_requests().unwrap(), pending);
    let mut restored = save_restore(vm, &fixture, "native-psci-pending-start.rxc");
    assert_eq!(restored.vm.take_cpu_power_requests().unwrap(), pending);
    restored.route_interprocessor_requests().unwrap();
    assert!(restored.coordinator.online.iter().all(|on| *on));
    for id in 1..4 {
        let cpu = &mut restored.vcpus[id];
        for _ in 0..100 {
            match cpu.run().unwrap() {
                VcpuExit::Hlt => (),
                VcpuExit::MmioRead {
                    addr: UART,
                    size: 8,
                } => {
                    cpu.complete_io_in(&0u64.to_le_bytes());
                    cpu.io_completion_result().unwrap();
                    break;
                }
                exit => panic!("pending CPU{id} failed to execute: {exit:?}"),
            }
        }
        let marker: u64 = restored
            .guest_mem
            .memory()
            .read_obj(GuestAddress(MARKERS + id as u64 * 8))
            .unwrap();
        assert_eq!(marker, (id as u64 + 1) * 0x1000 + 1);
    }
}
#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_psci_32_64_conduits_admit_arguments_and_copy_caller_endianness() {
    for (function, smc) in [
        (0x84000003, false),
        (0x84000003, true),
        (0xc4000003, false),
        (0xc4000003, true),
    ] {
        let fixture = Fixture::new();
        let mut vm = Vmm::new_resume(fixture.config(2)).unwrap();
        load_boot(&vm, 2);
        let is32 = function == 0x84000003;
        let upper = if is32 { 0xfeed000000000000 } else { 0 };
        assert_eq!(
            call(&mut vm, 0x8400000a, [u64::from(function), 0, 0], smc, false),
            0
        );
        assert_eq!(
            call(&mut vm, 0xc4000003, [1 << 32, CODE + 0x100, 0], smc, false),
            -2i64 as u64
        );
        assert_eq!(
            call(&mut vm, 0xc4000003, [1, CODE + 1, 0], smc, false),
            -9i64 as u64
        );
        assert_eq!(
            call(
                &mut vm,
                function,
                [upper | 1, upper | (CODE + 0x100), upper | (MARKERS + 8)],
                smc,
                true
            ),
            0
        );
        assert_eq!(call(&mut vm, 0xc4000004, [1, 0, 0], smc, true), 2);
        // DEN0022D 5.1.5 declares this parameter uint32 in both conventions.
        assert_eq!(call(&mut vm, 0xc4000004, [1, 1 << 32, 0], smc, true), 2);
        assert_eq!(
            call(
                &mut vm,
                function,
                [upper | 1, upper | (CODE + 0x100), 0],
                smc,
                true
            ),
            -5i64 as u64
        );
        let CpuState::Aarch64(caller) = vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        let caller_ee = caller.sregs.sctlr_el1 & (1 << 25);
        let profile =
            Context::decode(&vm.vcpus[0].capture_backend_context().unwrap().unwrap().data)
                .unwrap()
                .profile;
        let mmfr0 = profile
            .feature_values
            .iter()
            .find(|r| r.id == 0xc038)
            .unwrap()
            .value;
        let bigend = (mmfr0 >> 8) & 15;
        if bigend == 0 {
            assert_eq!(
                caller_ee, 0,
                "BigEnd=NI must retain little-endian execution"
            );
        }
        println!(
            "native PSCI convention={function:#x} smc={smc} ID_AA64MMFR0_EL1={mmfr0:#x} caller_EE={caller_ee:#x}"
        );
        vm.route_interprocessor_requests().unwrap();
        let CpuState::Aarch64(state) = vm.vcpus[1].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.pc, CODE + 0x100);
        assert_eq!(state.regs.x[0], MARKERS + 8);
        assert_eq!(state.regs.pstate, 0x3c5);
        assert_eq!(
            state.sregs.sctlr_el1 & ((1 << 25) | (1 << 12) | (1 << 2) | 1),
            caller_ee
        );
        assert_eq!(call(&mut vm, 0xc4000004, [1, 0, 0], smc, true), 0);
        assert_eq!(
            call(&mut vm, function, [1, CODE + 0x100, 0], smc, true),
            -4i64 as u64
        );
        for _ in 0..100 {
            match vm.vcpus[1].run().unwrap() {
                VcpuExit::Hlt => (),
                VcpuExit::MmioRead {
                    addr: UART,
                    size: 8,
                } => break,
                exit => panic!("endianness guest: {exit:?}"),
            }
        }
        let mut bytes = [0; 8];
        vm.guest_mem
            .memory()
            .read_slice(&mut bytes, GuestAddress(MARKERS + 8))
            .unwrap();
        let marker = if caller_ee != 0 {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        };
        assert_eq!(marker, 0x2001);
    }
}
#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_cpu_off_blocks_entry_and_pending_stop_survives_file_before_restart() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(2)).unwrap();
    boot_native_secondaries(&mut vm);
    // CPU_OFF is non-returning: the following MMIO load must never execute.
    let pc = CODE + 0x900;
    for (i, word) in [0x52800040u32, 0x72b08000, 0xd4000002, 0xf940016a]
        .into_iter()
        .enumerate()
    {
        vm.guest_mem
            .memory()
            .write_obj(word.to_le(), GuestAddress(pc + i as u64 * 4))
            .unwrap();
    }
    vm.vcpus[1].set_current_pc(pc).unwrap();
    for _ in 0..100 {
        assert!(matches!(vm.vcpus[1].run().unwrap(), VcpuExit::Hlt));
        if !vm.vm.take_cpu_power_requests().unwrap().is_empty() {
            break;
        }
    }
    assert_eq!(
        vm.vm.take_cpu_power_requests().unwrap(),
        [crate::vm::vcpu::CpuPowerRequest::Off { cpu_id: 1 }]
    );
    let mut restored = save_restore(vm, &fixture, "native-psci-pending-stop.rxc");
    assert!(matches!(restored.vcpus[1].run().unwrap(), VcpuExit::Hlt));
    restored.route_interprocessor_requests().unwrap();
    assert_eq!(restored.coordinator.online, [true, false]);
    assert!(matches!(restored.vcpus[1].run().unwrap(), VcpuExit::Hlt));
    assert_eq!(call(&mut restored, 0xc4000004, [1, 0, 0], false, false), 1);
    assert_eq!(
        call(
            &mut restored,
            0xc4000003,
            [1, CODE + 0x100, MARKERS + 8],
            false,
            false
        ),
        0
    );
    restored.route_interprocessor_requests().unwrap();
    assert_eq!(restored.coordinator.online, [true, true]);
    let CpuState::Aarch64(state) = restored.vcpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(state.regs.pc, CODE + 0x100);
    assert_eq!(state.regs.x[0], MARKERS + 8);
    for _ in 0..100 {
        match restored.vcpus[1].run().unwrap() {
            VcpuExit::Hlt => (),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => return,
            exit => panic!("restarted CPU: {exit:?}"),
        }
    }
    panic!("restarted CPU did not execute");
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn native_secondary_system_off_stops_every_cpu_through_real_file() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(2)).unwrap();
    boot_native_secondaries(&mut vm);
    let pc = CODE + 0x900;
    for (i, word) in [0x52800100u32, 0x72b08000, 0xd4000002, 0xf940016a]
        .into_iter()
        .enumerate()
    {
        vm.guest_mem
            .memory()
            .write_obj(word.to_le(), GuestAddress(pc + i as u64 * 4))
            .unwrap();
    }
    vm.vcpus[1].set_current_pc(pc).unwrap();
    let mut shutdown = false;
    for _ in 0..100 {
        match vm.vcpus[1].run().unwrap() {
            VcpuExit::Hlt => (),
            VcpuExit::Shutdown => {
                shutdown = true;
                break;
            }
            exit => panic!("secondary SYSTEM_OFF: {exit:?}"),
        }
    }
    assert!(shutdown);
    assert!(matches!(vm.vcpus[0].run().unwrap(), VcpuExit::Shutdown));
    let mut restored = save_restore(vm, &fixture, "native-psci-secondary-shutdown.rxc");
    for cpu in &mut restored.vcpus {
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
    }
    assert!(private_states(&restored).iter().all(|state| state.shutdown));
    restored.vcpus[0].wake();
    assert!(
        private_states(&restored)
            .iter()
            .all(|state| !state.shutdown)
    );
    let CpuState::Aarch64(mut restart) = restored.vcpus[1].get_state().unwrap() else {
        panic!()
    };
    restart.regs.pc = CODE + 0x100;
    restart.regs.x[0] = MARKERS + 8;
    restored.vcpus[1]
        .update_state(&CpuState::Aarch64(restart))
        .unwrap();
    for _ in 0..100 {
        match restored.vcpus[1].run().unwrap() {
            VcpuExit::Hlt => (),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            } => return,
            exit => panic!("VM-wide explicit restart retained a stale terminal latch: {exit:?}"),
        }
    }
    panic!("secondary failed to run after explicit VM restart");
}

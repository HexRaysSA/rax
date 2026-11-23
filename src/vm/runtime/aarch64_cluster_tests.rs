//! Shared platform restoration through the real VMM admission/commit path.
use super::*;
use crate::backend::emulator::EmulatorVm;
use crate::config::{CliConfig, MemorySize};
use crate::vm::timing::ClockMode;
use crate::vm::vcpu::Aarch64Registers;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::GuestAddress;

static NEXT: AtomicU64 = AtomicU64::new(0);
const CODE: u64 = 0x4008_0000;

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[path = "aarch64_bounded_native_tests.rs"]
mod bounded_native;
#[path = "aarch64_counter_clock_tests.rs"]
mod counter_clock;
#[path = "aarch64_event_tests.rs"]
mod events;
#[path = "aarch64_fpexc32_tests.rs"]
mod fpexc32;
#[path = "aarch64_gic_discovery_tests.rs"]
mod gic_discovery;
#[path = "aarch64_gic_forwarding_tests.rs"]
mod gic_forwarding;
#[path = "aarch64_gic_interface_tests.rs"]
mod gic_interface;
#[path = "aarch64_gic_source_tests.rs"]
mod gic_sources;
#[path = "aarch64_psci_start_admission_tests.rs"]
mod psci_start_admission;
#[path = "aarch64_timer_output_tests.rs"]
mod timer_outputs;
#[path = "aarch64_undefined_tests.rs"]
mod undefined;

struct Fixture {
    kernel: std::path::PathBuf,
    vm: Vmm,
}

impl Fixture {
    fn new(count: u8) -> Self {
        Self::with_clock(count, ClockMode::Wall)
    }

    fn with_clock(count: u8, mode: ClockMode) -> Self {
        Self::with_memory(count, mode, 128 * 1024 * 1024)
    }

    fn with_memory(count: u8, mode: ClockMode, memory_bytes: u64) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-arm-cluster-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Aarch64),
                backend: Some(BackendKind::Emulator),
                vcpus: Some(count),
                kernel: Some(kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(memory_bytes);
        let mut vm = Vmm::new_resume_with_clock(config, mode).unwrap();
        vm.vcpus[0]
            .set_state(&CpuState::aarch64(
                Aarch64Registers {
                    pc: CODE,
                    pstate: 0x3c5,
                    ..Default::default()
                },
                Default::default(),
            ))
            .unwrap();
        Self { kernel, vm }
    }

    fn cluster(&self) -> Arc<crate::backend::emulator::aarch64::cluster::ArmCluster> {
        self.vm
            .vm
            .as_any()
            .downcast_ref::<EmulatorVm>()
            .unwrap()
            .arm_cluster()
            .unwrap()
    }

    fn graph(&self) -> Vec<u8> {
        crate::codec::serialize_limited(&self.cluster().checkpoint().unwrap(), 16 * 1024 * 1024)
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
    }
}

#[test]
fn complete_shared_platform_restores_and_missing_smp_state_rejects_before_mutation() {
    for count in [2, 4] {
        let mut source = Fixture::new(count);
        for id in 1..count {
            assert_eq!(
                source
                    .cluster()
                    .request_on(u64::from(id), CODE, 0x40 + u64::from(id), 0x3c5)
                    .unwrap(),
                0
            );
        }
        source.vm.route_interprocessor_requests().unwrap();
        for id in 0..usize::from(count) {
            source
                .vm
                .guest_mem
                .memory()
                .write_slice(&0xd518_4600u32.to_le_bytes(), GuestAddress(CODE))
                .unwrap();
            let CpuState::Aarch64(mut state) = source.vm.vcpus[id].get_state().unwrap() else {
                panic!()
            };
            state.regs.x[0] = 0x80 + id as u64 * 16;
            source.vm.vcpus[id]
                .update_state(&CpuState::Aarch64(state))
                .unwrap();
            assert_eq!(
                source.vm.vcpus[id]
                    .run_retirement_budget(1)
                    .unwrap()
                    .retired,
                1
            );
        }
        let graph = source.graph();
        let mut saved = source.vm.take_snapshot_bundle(53).unwrap();
        let mut target = Fixture::new(count);
        target.vm.restore_snapshot_bundle(&saved).unwrap();
        assert_eq!(target.graph(), graph);
        assert_eq!(target.vm.coordinator.online, vec![true; usize::from(count)]);

        // A newer SMP producer cannot be admitted as a register-only record.
        let mut execution = saved.take_execution().unwrap();
        execution.arm_cluster = None;
        let stripped = saved.with_execution(execution).unwrap();
        let before = target.graph();
        let cpus = target.vm.capture_cpu_states().unwrap();
        assert!(target.vm.restore_snapshot_bundle(&stripped).is_err());
        assert_eq!(target.graph(), before);
        assert_eq!(
            format!("{:?}", target.vm.capture_cpu_states().unwrap()),
            format!("{cpus:?}")
        );
    }
}

#[test]
fn dma_writes_invalidate_only_reservations_in_the_written_granule() {
    use crate::backend::emulator::aarch64::Aarch64Vcpu;
    use crate::devices::virtio::Mem;
    for (address, valid, status) in [(0x80, true, 1), (0xc0, true, 0), (0x1000, false, 0)] {
        let memory = Arc::new(
            vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        memory
            .write_slice(&0x885f_7c20u32.to_le_bytes(), GuestAddress(0))
            .unwrap();
        memory
            .write_slice(&0x8802_7c20u32.to_le_bytes(), GuestAddress(4))
            .unwrap();
        let mut cpu = Aarch64Vcpu::new_micro(0, memory.clone());
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.x[1] = 0x80;
        cpu.update_state(&CpuState::Aarch64(state)).unwrap();
        assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
        let mut dma = GuestDmaMem(Arc::new(memory.as_ref().clone()));
        assert_eq!(dma.write(address, &[0]), valid);
        assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.x[2], status, "address={address:#x}");
    }
}

#[test]
fn aarch64_file_restore_retains_exclusive_frontier_and_pl011_fifo() {
    let mut source = Fixture::new(1);
    let memory = source.vm.guest_mem.memory();
    memory
        .write_slice(&0x885f_7c20u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    memory
        .write_slice(&0x8802_7c20u32.to_le_bytes(), GuestAddress(CODE + 4))
        .unwrap();
    memory
        .write_slice(&0x1234_5678u32.to_le_bytes(), GuestAddress(CODE + 0x1000))
        .unwrap();
    let CpuState::Aarch64(mut state) = source.vm.vcpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.x[1] = CODE + 0x1000;
    source.vm.vcpus[0]
        .update_state(&CpuState::Aarch64(state))
        .unwrap();
    source
        .vm
        .pl011
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(b"checkpoint FIFO");
    assert_eq!(
        source.vm.vcpus[0].run_retirement_budget(1).unwrap().retired,
        1
    );
    let saved = source.vm.take_snapshot_bundle(1).unwrap();
    assert_eq!(
        saved.backend_contexts().unwrap().entries()[0]
            .as_ref()
            .unwrap()
            .kind,
        crate::vm::snapshot::AARCH64_CONTEXT
    );
    let path = source.kernel.with_extension("rxc");
    saved.save(&path).unwrap();
    let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    let expected_uart = source
        .vm
        .pl011
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .checkpoint()
        .unwrap();
    let mut target = Fixture::new(1);
    target.vm.restore_snapshot_bundle(&loaded).unwrap();
    assert_eq!(
        target
            .vm
            .pl011
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .checkpoint()
            .unwrap(),
        expected_uart
    );
    assert_eq!(
        target.vm.vcpus[0].run_retirement_budget(1).unwrap().retired,
        1
    );
    assert_eq!(
        target.vm.vcpus[0]
            .get_state()
            .unwrap()
            .as_aarch64()
            .unwrap()
            .regs
            .x[2],
        0
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn aarch64_private_checkpoint_requires_the_pl011_endpoint() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut source = Fixture::new(1);
    let source_uart = source.vm.pl011.as_ref().unwrap();
    source_uart.lock().unwrap().queue_input(b"source");
    source.vm.coordinator.retired = 17;
    let mut incoming = source.vm.take_snapshot_bundle(17).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&incoming, CliConfig::default()).unwrap();
    let mut execution = incoming.take_execution().unwrap();
    assert!(execution.pl011.take().is_some());
    incoming = incoming.with_execution(execution).unwrap();

    let mut target = Fixture::new(1);
    let target_uart = Arc::clone(target.vm.pl011.as_ref().unwrap());
    target_uart.lock().unwrap().queue_input(b"target");
    let uart = target_uart.lock().unwrap().checkpoint().unwrap();
    target.vm.coordinator.retired = 41;

    let path = source.kernel.with_extension("rxc");
    let save = incoming.save(&path);
    if save.is_ok() {
        std::fs::remove_file(&path).unwrap();
    }
    let detached = Vmm::new_resume_bundle(config, &incoming).err();
    let warm = target.vm.restore_snapshot_bundle(&incoming);
    for (route, error) in [
        ("save", save.err()),
        ("detached", detached),
        ("warm", warm.err()),
    ] {
        assert!(
            error
                .as_ref()
                .is_some_and(|error| error.to_string().contains("PL011")),
            "{route} must reject the incomplete machine image: {error:?}"
        );
    }
    assert!(!path.exists());
    assert_eq!(target.vm.coordinator.retired, 41);
    assert_eq!(target_uart.lock().unwrap().checkpoint().unwrap(), uart);

    // A coordinator-only projection has no private CPU or endpoint records.
    // Restoring it retains the target UART under the legacy contract.
    assert!(incoming.take_backend_contexts().is_some());
    let mut execution = incoming.take_execution().unwrap();
    execution.arm_cluster = None;
    incoming = incoming.with_execution(execution).unwrap();
    incoming.save(&path).unwrap();
    let legacy = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    target.vm.restore_snapshot_bundle(&legacy).unwrap();
    assert_eq!(target.vm.coordinator.retired, 17);
    assert_eq!(target_uart.lock().unwrap().checkpoint().unwrap(), uart);
}

#[test]
fn malformed_final_aarch64_context_preserves_all_cpus_ram_uart_and_shared_controller() {
    let source = Fixture::new(2);
    let mut saved = source.vm.take_snapshot_bundle(0).unwrap();
    let mut contexts = saved.take_backend_contexts().unwrap().entries().to_vec();
    contexts.last_mut().unwrap().as_mut().unwrap().data.pop();
    let bad = saved.with_backend_contexts(contexts).unwrap();
    let mut target = Fixture::new(2);
    target
        .vm
        .guest_mem
        .memory()
        .write_slice(&[0x77; 16], GuestAddress(CODE + 0x1000))
        .unwrap();
    target
        .vm
        .pl011
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(b"target FIFO");
    let graph = target.graph();
    let cpus = target.vm.capture_cpu_states().unwrap();
    let uart = target
        .vm
        .pl011
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .checkpoint()
        .unwrap();
    assert!(target.vm.restore_snapshot_bundle(&bad).is_err());
    assert_eq!(target.graph(), graph);
    assert_eq!(
        format!("{:?}", target.vm.capture_cpu_states().unwrap()),
        format!("{cpus:?}")
    );
    assert_eq!(
        target
            .vm
            .pl011
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .checkpoint()
            .unwrap(),
        uart
    );
    let mut bytes = [0; 16];
    target
        .vm
        .guest_mem
        .memory()
        .read_slice(&mut bytes, GuestAddress(CODE + 0x1000))
        .unwrap();
    assert_eq!(bytes, [0x77; 16]);
}

#[test]
fn capture_rejects_private_cpu_power_disagreement_with_psci_graph() {
    let mut source = Fixture::new(2);
    // Simulate a broken host startup path that bypassed PSCI completion.
    source.vm.vcpus[1]
        .start_aarch64_cpu(CODE, 0, 0x3c5)
        .unwrap();
    let error = source.vm.take_snapshot_bundle(0).unwrap_err();
    assert!(error.to_string().contains("power state differs"));
}

#[test]
fn retained_psci_requests_restore_and_run_the_right_secondaries() {
    const HVC: u32 = 0xd400_0002;
    const CPU_OFF: u64 = 0x8400_0002;
    const CPU_ON: u64 = 0xc400_0003;
    const CPU1: u64 = CODE + 0x100;
    const CPU2: u64 = CODE + 0x200;

    for stop_removed_from_schedule in [false, true] {
        let mut source = Fixture::new(3);
        let cluster = source.cluster();
        assert_eq!(cluster.request_on(1, CPU1, CPU_OFF, 0x3c5).unwrap(), 0);
        source.vm.route_interprocessor_requests().unwrap();
        let memory = source.vm.guest_mem.memory();
        for (address, words) in [
            // BSP starts CPU2. If the coordinator never runs it, the BSP's
            // countdown and SYSTEM_OFF let the final register assertion fail.
            (
                CODE,
                &[
                    HVC,
                    0xd284_0008,
                    0xf100_0508,
                    0x54ff_ffe1,
                    0xd280_0100,
                    0xf2b0_8000,
                    HVC,
                ][..],
            ),
            (CPU1, &[HVC, 0xd293_3329][..]), // CPU_OFF; MOVZ X9,#0x9999.
            (CPU2, &[0xd282_4689, 0xd280_0100, 0xf2b0_8000, HVC][..]),
        ] {
            for (index, word) in words.iter().enumerate() {
                memory
                    .write_slice(
                        &word.to_le_bytes(),
                        GuestAddress(address + 4 * index as u64),
                    )
                    .unwrap();
            }
        }
        let CpuState::Aarch64(mut regs) = source.vm.vcpus[0].get_state().unwrap() else {
            panic!();
        };
        regs.regs.x[..4].copy_from_slice(&[CPU_ON, 2, CPU2, 0x5678]);
        source.vm.vcpus[0]
            .update_state(&CpuState::Aarch64(regs))
            .unwrap();
        assert_eq!(
            source.vm.vcpus[0].run_retirement_budget(1).unwrap().retired,
            1
        );
        assert_eq!(
            source.vm.vcpus[1].run_retirement_budget(1).unwrap().retired,
            1
        );
        if stop_removed_from_schedule {
            source.vm.coordinator.online[1] = false;
        }
        let pending = source.vm.vm.take_cpu_power_requests().unwrap();
        assert!(matches!(
            pending.as_slice(),
            [
                crate::vm::vcpu::CpuPowerRequest::Start { cpu_id: 2, .. },
                crate::vm::vcpu::CpuPowerRequest::Off { cpu_id: 1 }
            ]
        ));

        let source_kernel = source.kernel.clone();
        let path = source_kernel.with_extension("rxc");
        source
            .vm
            .take_snapshot_bundle(2)
            .unwrap()
            .save(&path)
            .unwrap();
        drop(source);
        assert!(!source_kernel.exists());
        let bundle = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut target = Fixture::new(3);
        target.vm.restore_snapshot_bundle(&bundle).unwrap();
        assert_eq!(target.vm.vm.take_cpu_power_requests().unwrap(), pending);
        target.vm.run().unwrap();
        assert_eq!(target.vm.coordinator.online, [true, false, true]);
        assert!(target.vm.vm.take_cpu_power_requests().unwrap().is_empty());
        let stopped = target.vm.vcpus[1].get_state().unwrap();
        assert_eq!(stopped.as_aarch64().unwrap().regs.x[9], 0);
        let started = target.vm.vcpus[2].get_state().unwrap();
        let regs = &started.as_aarch64().unwrap().regs;
        assert_eq!((regs.x[9], regs.x[0]), (0x1234, 0x8400_0008));
    }
}

#[test]
fn aarch32_cpu_on_keeps_data_endianness_through_pending_checkpoint() {
    const ENTRY: u64 = CODE + 0x100;
    const DATA: u64 = CODE + 0x200;
    const CPSR_E: u64 = 1 << 9;
    const CPSR_T: u64 = 1 << 5;
    const RAM_BYTES: u64 = 8 * 1024 * 1024;

    for caller_thumb in [false, true] {
        let entry_thumb = !caller_thumb;
        let hvc = if caller_thumb {
            [0xe0, 0xf7, 0x00, 0x80]
        } else {
            0xe140_0070u32.to_le_bytes()
        };
        for big_endian in [true, false] {
            let mut source = Fixture::with_memory(2, ClockMode::Wall, RAM_BYTES);
            let memory = source.vm.guest_mem.memory();
            memory.write_slice(&hvc, GuestAddress(CODE)).unwrap();
            // LDR R4, [R0] in the secondary's instruction set.
            let arm_load = 0xe590_4000u32.to_le_bytes();
            let thumb_load = 0x6804u16.to_le_bytes();
            memory
                .write_slice(
                    if entry_thumb { &thumb_load } else { &arm_load },
                    GuestAddress(ENTRY),
                )
                .unwrap();
            memory
                .write_slice(&[0x01, 0x23, 0x45, 0x67], GuestAddress(DATA))
                .unwrap();

            let CpuState::Aarch64(mut state) = source.vm.vcpus[0].get_state().unwrap() else {
                panic!("expected an Arm vCPU");
            };
            state.regs.pstate =
                0x1d3 | (u64::from(caller_thumb) * CPSR_T) | (u64::from(big_endian) * CPSR_E);
            state.regs.x[..4].copy_from_slice(&[
                0x8400_0003, // PSCI CPU_ON, SMC32 calling convention.
                1,
                ENTRY | u64::from(entry_thumb),
                DATA,
            ]);
            state.sregs.execution.as_mut().unwrap().sysregs.hcr_el2 &= !(1 << 31);
            source.vm.vcpus[0]
                .update_state(&CpuState::Aarch64(state))
                .unwrap();

            let result = source.vm.vcpus[0].run_retirement_budget(1).unwrap();
            assert_eq!(result.retired, 1, "{result:?}");
            let caller = source.vm.vcpus[0].get_state().unwrap();
            assert_eq!(caller.as_aarch64().unwrap().regs.x[0], 0);
            assert_eq!(source.cluster().affinity_info(1, 0).unwrap(), 2);
            assert_eq!(source.vm.coordinator.online, [true, false]);
            let pending = source.vm.vm.take_cpu_power_requests().unwrap();
            let [crate::vm::vcpu::CpuPowerRequest::Start { pstate, .. }] = pending.as_slice()
            else {
                panic!("expected one pending CPU_ON: {pending:?}");
            };
            let expected = (u64::from(big_endian) * CPSR_E) | (u64::from(entry_thumb) * CPSR_T);
            assert_eq!(
                *pstate & (CPSR_E | CPSR_T),
                expected,
                "caller_thumb={caller_thumb}, big_endian={big_endian}"
            );

            let verify_start = |vm: &mut Vmm| {
                vm.route_interprocessor_requests().unwrap();
                assert_eq!(vm.coordinator.online, [true, true]);
                let secondary = vm.vcpus[1].get_state().unwrap();
                let regs = &secondary.as_aarch64().unwrap().regs;
                assert_eq!(regs.pc, ENTRY);
                assert_eq!(regs.x[0], DATA);
                assert_eq!(
                    regs.pstate & (CPSR_E | CPSR_T),
                    expected,
                    "caller_thumb={caller_thumb}, big_endian={big_endian}"
                );
                let result = vm.vcpus[1].run_retirement_budget(1).unwrap();
                assert_eq!(result.retired, 1, "{result:?}");
                let secondary = vm.vcpus[1].get_state().unwrap();
                assert_eq!(
                    secondary.as_aarch64().unwrap().regs.x[4],
                    if big_endian { 0x0123_4567 } else { 0x6745_2301 },
                    "caller_thumb={caller_thumb}, big_endian={big_endian}"
                );
            };

            let source_kernel = source.kernel.clone();
            let path = source_kernel.with_extension("rxc");
            source
                .vm
                .take_snapshot_bundle(1)
                .unwrap()
                .save(&path)
                .unwrap();
            verify_start(&mut source.vm);
            drop(source);
            assert!(!source_kernel.exists());

            let bundle = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
            std::fs::remove_file(path).unwrap();
            let mut restored = Fixture::with_memory(2, ClockMode::Wall, RAM_BYTES);
            restored.vm.restore_snapshot_bundle(&bundle).unwrap();
            assert_eq!(restored.cluster().affinity_info(1, 0).unwrap(), 2);
            verify_start(&mut restored.vm);
        }
    }
}

#[path = "aarch64_sve_tests.rs"]
mod sve_profile;

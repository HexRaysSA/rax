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
        config.memory = MemorySize(128 * 1024 * 1024);
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

#[path = "aarch64_sve_tests.rs"]
mod sve_profile;

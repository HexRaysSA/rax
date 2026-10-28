//! Shared platform restoration through the real VMM admission/commit path.
use super::*;
use crate::backend::emulator::EmulatorVm;
use crate::config::{CliConfig, MemorySize};
use crate::vm::vcpu::Aarch64Registers;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::GuestAddress;

static NEXT: AtomicU64 = AtomicU64::new(0);
const CODE: u64 = 0x4008_0000;

struct Fixture {
    kernel: std::path::PathBuf,
    vm: Vmm,
}

impl Fixture {
    fn new(count: u8) -> Self {
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
        let mut vm = Vmm::new_resume(config).unwrap();
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

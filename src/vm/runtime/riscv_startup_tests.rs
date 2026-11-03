//! Execute the real coordinator; no direct per-hart stepping supplies progress.
use super::*;
use crate::config::{CliConfig, MemorySize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};
#[path = "../../../tests/support/riscv_startup.rs"]
mod program;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    kernel: PathBuf,
    vm: Vmm,
}

impl Fixture {
    fn new(count: u8, elf: bool) -> Self {
        Self::with_wait(count, elf, false)
    }

    fn with_wait(count: u8, elf: bool, wait: bool) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-riscv-startup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let code = program::program(count, wait);
        let image = if elf {
            program::elf(&code, 0x1000, 0x1000)
        } else {
            code
        };
        std::fs::write(&kernel, image).unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Riscv64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.clone()),
                memory: Some(MemorySize(128 << 20)),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let vm = Vmm::new(config).unwrap();
        Self { kernel, vm }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(self.kernel.with_extension("rxc"));
    }
}

#[test]
fn constructor_initializes_every_generic_hart_at_nonzero_entry() {
    for count in [1u8, 2, 4] {
        let f = Fixture::new(count, true);
        assert_eq!(f.vm.coordinator.online, vec![true; usize::from(count)]);
        let mut stacks = Vec::new();
        for (index, cpu) in f.vm.vcpus.iter().enumerate() {
            let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(state.regs.pc, 0x1000, "hart {index}");
            assert_eq!(state.regs.x[10], index as u64);
            assert_eq!(state.regs.x[2] & 15, 0);
            assert!(state.regs.x[2] != 0);
            stacks.push(state.regs.x[2]);
        }
        for pair in stacks.windows(2) {
            assert_eq!(pair[0] - pair[1], 4096);
        }
    }
}
fn run(count: u8) {
    let mut f = Fixture::new(count, false);
    f.vm.run().unwrap();
    assert_eq!(
        f.vm.guest_mem
            .memory()
            .read_obj::<u32>(GuestAddress(0x80008100))
            .map(u32::from_le)
            .unwrap(),
        u32::from(count)
    );
    for (index, cpu) in f.vm.vcpus.iter().enumerate() {
        let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(
            state.regs.x[31],
            index as u64 + 1,
            "hart {index} must execute its guest publication"
        );
        assert_eq!(state.regs.x[29], 1, "hart {index} must contribute work");
        assert!(cpu.instruction_count() > 0);
    }
}

#[test]
fn actual_vmm_run_executes_two_riscv_harts() {
    run(2);
}

#[test]
fn actual_vmm_run_executes_four_riscv_harts() {
    run(4);
}

fn contexts(vm: &Vmm) -> Vec<Option<crate::vm::snapshot::BackendContext>> {
    vm.vcpus
        .iter()
        .map(|cpu| cpu.capture_backend_context().unwrap())
        .collect()
}

#[test]
fn source_free_checkpoint_resumes_new_work_on_one_two_and_four_riscv_harts() {
    use crate::vm::snapshot::SnapshotBundle;

    for count in [1, 2, 4] {
        let mut source = Fixture::with_wait(count, true, true);
        let expected_cursor = usize::from(count > 1);
        let mut ready = false;
        for _ in 0..128 {
            source.vm.execute_turn().unwrap();
            ready = source
                .vm
                .guest_mem
                .memory()
                .read_obj::<u32>(GuestAddress(0x80008000))
                .map(u32::from_le)
                .unwrap()
                == u32::from(count)
                && source.vm.coordinator.cursor == expected_cursor;
            if ready {
                break;
            }
        }
        assert!(ready, "all {count} harts must execute before capture");
        for cpu in &source.vm.vcpus {
            let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(state.regs.x[29], 0, "post-checkpoint work has not run");
        }
        let before = contexts(&source.vm);
        let saved = source
            .vm
            .take_snapshot_bundle(source.vm.coordinator.retired)
            .unwrap();
        assert_eq!(
            saved.execution().unwrap().online(),
            vec![true; usize::from(count)]
        );
        assert_eq!(saved.execution().unwrap().cursor(), expected_cursor);
        let checkpoint = source.kernel.with_extension("rxc");
        saved.save(&checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&checkpoint).unwrap();
        std::fs::remove_file(&source.kernel).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(restored.coordinator, source.vm.coordinator);
        assert_eq!(
            contexts(&restored),
            before,
            "restore retains all private hart contexts"
        );
        for vm in [&mut source.vm, &mut restored] {
            vm.guest_mem
                .memory()
                .write_obj(1u32.to_le(), GuestAddress(0x80008200))
                .unwrap();
            vm.run().unwrap();
            assert_eq!(
                vm.guest_mem
                    .memory()
                    .read_obj::<u32>(GuestAddress(0x80008100))
                    .map(u32::from_le)
                    .unwrap(),
                u32::from(count)
            );
            for (id, cpu) in vm.vcpus.iter().enumerate() {
                let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(state.regs.x[31], id as u64 + 1);
                assert_eq!(
                    state.regs.x[29], 1,
                    "hart {id} performs new work after capture"
                );
            }
        }
        assert_eq!(source.vm.coordinator, restored.coordinator);
        assert_eq!(contexts(&source.vm), contexts(&restored));
    }
}

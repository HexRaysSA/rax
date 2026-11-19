//! The real VMM coordinator and bundle restore at a delegated interrupt boundary.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::timing::ClockMode;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

#[path = "../../../tests/support/riscv_startup.rs"]
mod image;
#[path = "../../../tests/support/riscv_supervisor_irq.rs"]
mod program;

const LOAD: u64 = 0x1000;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    kernel: PathBuf,
    vm: Vmm,
}

impl Fixture {
    fn new(count: u8, hold: bool) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-supervisor-irq-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &kernel,
            image::elf(&program::program(count, hold), LOAD, LOAD),
        )
        .unwrap();
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
        let vm = Vmm::new_with_clock(config, ClockMode::Retired).unwrap();
        Self { kernel, vm }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(self.kernel.with_extension("rxc"));
    }
}

fn stage(vm: &Vmm, hart: u8) -> u32 {
    let addr = LOAD + program::RECORDS_OFFSET + u64::from(hart) * 4;
    u32::from_le(vm.guest_mem.memory().read_obj(GuestAddress(addr)).unwrap())
}

fn contexts(vm: &Vmm) -> Vec<Option<crate::vm::snapshot::BackendContext>> {
    vm.vcpus
        .iter()
        .map(|cpu| cpu.capture_backend_context().unwrap())
        .collect()
}

#[test]
fn every_hart_handles_delegated_software_interrupt_and_returns() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count, false);
        fixture.vm.run().unwrap();
        for hart in 0..count {
            assert_eq!(stage(&fixture.vm, hart), 2, "count={count}, hart={hart}");
        }
    }
}

#[test]
fn source_free_restore_continues_inside_supervisor_handlers() {
    use crate::vm::snapshot::SnapshotBundle;
    for count in [1, 2, 4] {
        let mut source = Fixture::new(count, true);
        let mut ready = false;
        for _ in 0..32 {
            assert!(source.vm.execute_turn().unwrap().is_none());
            ready = (0..count).all(|hart| stage(&source.vm, hart) == 1)
                && source.vm.coordinator.cursor == usize::from(count > 1);
            if ready {
                break;
            }
        }
        assert!(ready, "harts must reach their active S-mode handlers");
        for (id, cpu) in source.vm.vcpus.iter().enumerate() {
            let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
                panic!("expected a RISC-V hart");
            };
            assert_eq!(state.regs.privilege, Some(1));
            let csr = |number| {
                state
                    .regs
                    .csrs
                    .iter()
                    .find(|&(n, _)| *n == number)
                    .unwrap()
                    .1
            };
            assert_eq!(csr(0x105), LOAD + 0xf4 + 1); // vectored stvec
            assert_eq!(csr(0x140), 0x65 + id as u64); // sscratch
            assert_eq!(csr(0x141), LOAD + 0x6c); // sepc
            assert_eq!(csr(0x142), (1 << 63) | 1); // SSI
            assert_eq!(csr(0x143), 0); // stval
            assert_eq!(csr(0x300) & 0x122, 0x120);
            assert_ne!(csr(0x344) & 2, 0); // SSIP remains pending
        }

        let before = contexts(&source.vm);
        let file = source.kernel.with_extension("rxc");
        source
            .vm
            .take_snapshot_bundle(source.vm.coordinator.retired)
            .unwrap()
            .save(&file)
            .unwrap();
        let bundle = SnapshotBundle::load(&file).unwrap();
        std::fs::remove_file(&source.kernel).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &bundle).unwrap();
        assert_eq!(contexts(&restored), before);
        assert_eq!(restored.coordinator, source.vm.coordinator);
        for vm in [&mut source.vm, &mut restored] {
            vm.guest_mem
                .memory()
                .write_obj(1u32.to_le(), GuestAddress(LOAD + program::RELEASE_OFFSET))
                .unwrap();
            vm.run().unwrap();
            for hart in 0..count {
                assert_eq!(stage(vm, hart), 2);
            }
        }
        assert_eq!(contexts(&source.vm), contexts(&restored));
        assert_eq!(source.vm.coordinator, restored.coordinator);
        assert_eq!(
            source.vm.timing_context.checkpoint_state(),
            restored.timing_context.checkpoint_state()
        );
    }
}

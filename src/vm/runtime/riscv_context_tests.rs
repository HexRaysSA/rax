//! Real backend objects through bundle capture, file I/O and fresh VMM restore.
//! Explicit per-hart steps here verify context transport, not secondary startup.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::{BackendContext, RISCV_CONTEXT, SnapshotBundle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    kernel: PathBuf,
    checkpoint: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "rax-riscv-context-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let kernel = base.with_extension("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        Self {
            kernel,
            checkpoint: base.with_extension("rxc"),
        }
    }
    fn config(&self, count: u8) -> VmConfig {
        VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Riscv64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.kernel.clone()),
                memory: Some(MemorySize(128 << 20)),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap()
    }
    fn source(&self, count: u8) -> Vmm {
        let mut vm = Vmm::new_resume(self.config(count)).unwrap();
        for (index, cpu) in vm.vcpus.iter_mut().enumerate() {
            let code = 0x1000 + index as u64 * 0x100;
            vm.guest_mem
                .memory()
                .write_slice(
                    &[0xaf, 0x22, 0x05, 0x10, 0xaf, 0x25, 0x55, 0x18],
                    GuestAddress(code),
                )
                .unwrap();
            let data = 0x8000 + index as u64 * 64;
            vm.guest_mem
                .memory()
                .write_slice(
                    &(0x1234_5678u32 + index as u32).to_le_bytes(),
                    GuestAddress(data),
                )
                .unwrap();
            let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = code;
            state.regs.x[10] = data;
            cpu.set_state(&CpuState::RiscV(state)).unwrap();
            assert!(cpu.step_insn().unwrap().is_none());
            assert_eq!(cpu.instruction_count(), 1);
        }
        vm
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(&self.checkpoint);
    }
}
fn contexts(vm: &Vmm) -> Vec<Option<BackendContext>> {
    vm.vcpus
        .iter()
        .map(|cpu| cpu.capture_backend_context().unwrap())
        .collect()
}

#[test]
fn riscv_reservation_files_continue_one_two_four_actual_backend_contexts() {
    for count in [1, 2, 4] {
        let f = Fixture::new();
        let mut source = f.source(count);
        let before = contexts(&source);
        assert!(
            before
                .iter()
                .all(|ctx| ctx.as_ref().unwrap().kind == RISCV_CONTEXT)
        );
        source
            .take_snapshot_bundle(u64::from(count))
            .unwrap()
            .save(&f.checkpoint)
            .unwrap();
        let loaded = SnapshotBundle::load(&f.checkpoint).unwrap();
        assert_eq!(loaded.backend_contexts().unwrap().entries(), before);
        let config = f.config(count);
        std::fs::remove_file(&f.kernel).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(contexts(&restored), before);
        for vm in [&mut source, &mut restored] {
            for (index, cpu) in vm.vcpus.iter_mut().enumerate() {
                assert!(cpu.step_insn().unwrap().is_none());
                let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(state.regs.x[11], 0, "SC status on hart {index}");
                assert_eq!(state.regs.pc, 0x1008 + index as u64 * 0x100);
                assert_eq!(cpu.instruction_count(), 2);
            }
        }
        assert_eq!(contexts(&restored), contexts(&source));
    }
}

#[test]
fn invalid_final_riscv_context_preserves_all_harts_and_ram() {
    let f = Fixture::new();
    let source = f.source(4);
    let original = contexts(&source);
    let cpus = source.capture_cpu_states().unwrap();
    let mut target = Vmm::new_resume(f.config(4)).unwrap();
    target
        .guest_mem
        .memory()
        .write_slice(&[0xa5; 4096], GuestAddress(0x1000))
        .unwrap();
    let before = contexts(&target);
    for mutation in 0..4 {
        let mut entries = original.clone();
        let last = entries.last_mut().unwrap().as_mut().unwrap();
        match mutation {
            0 => last.kind = u32::MAX,
            1 => last.data[0] ^= 0x80,
            2 => {
                last.data.pop();
            }
            3 => last.data[8..12].copy_from_slice(&0u32.to_le_bytes()),
            _ => unreachable!(),
        }
        let bundle = SnapshotBundle::new(source.take_snapshot(4).unwrap())
            .with_cpus(cpus.clone())
            .unwrap()
            .with_backend_contexts(entries)
            .unwrap();
        assert!(target.restore_snapshot_bundle(&bundle).is_err());
        assert_eq!(contexts(&target), before);
        let mut memory = [0; 4096];
        target
            .guest_mem
            .memory()
            .read_slice(&mut memory, GuestAddress(0x1000))
            .unwrap();
        assert_eq!(memory, [0xa5; 4096]);
    }
}

#[test]
fn rv32_private_record_under_riscv64_machine_rejects_before_live_changes() {
    use crate::backend::emulator::riscv::RiscVVcpu;
    use crate::isa::riscv::{Isa, RiscVConfig};
    use crate::vm::snapshot::CpuSnapshot;
    let f = Fixture::new();
    let source = Vmm::new_resume(f.config(1)).unwrap();
    let rv32 = RiscVVcpu::new_with_config(
        0,
        std::sync::Arc::new(source.guest_mem.memory().clone()),
        RiscVConfig::rv32(Isa::rv64gc()),
    );
    let state = rv32.get_state().unwrap();
    let mut base = source.take_snapshot(0).unwrap();
    base.cpu_state = state.clone();
    let bundle = SnapshotBundle::new(base)
        .with_cpus(vec![CpuSnapshot {
            state,
            emulator: Default::default(),
        }])
        .unwrap()
        .with_backend_contexts(vec![rv32.capture_backend_context().unwrap()])
        .unwrap();
    let mut target = f.source(1);
    target
        .guest_mem
        .memory()
        .write_slice(&[0xa5; 4096], GuestAddress(0x9000))
        .unwrap();
    let before = contexts(&target);
    let error = target.restore_snapshot_bundle(&bundle).unwrap_err();
    assert!(
        error.to_string().contains("RV64 backend profile"),
        "{error}"
    );
    assert_eq!(contexts(&target), before);
    let mut bytes = [0; 4096];
    target
        .guest_mem
        .memory()
        .read_slice(&mut bytes, GuestAddress(0x9000))
        .unwrap();
    assert_eq!(bytes, [0xa5; 4096]);
    let error = Vmm::new_resume_bundle(f.config(1), &bundle).err().unwrap();
    assert!(
        error.to_string().contains("RV64 backend profile"),
        "{error}"
    );
}

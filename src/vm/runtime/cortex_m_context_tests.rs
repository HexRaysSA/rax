//! Actual Cortex-M VMM files must retain execution phase beyond public registers.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

static NEXT: AtomicU64 = AtomicU64::new(0);
const CODE: u64 = 0x1000;
struct Fixture {
    kernel: PathBuf,
    checkpoint: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rax-cortex-m-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let kernel = p.with_extension("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        Self {
            kernel,
            checkpoint: p.with_extension("rxc"),
        }
    }
    fn config(&self, count: u8) -> VmConfig {
        VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::CortexM),
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
    fn source(&self, count: u8, code: &[u8]) -> Vmm {
        let mut vm = Vmm::new_resume(self.config(count)).unwrap();
        vm.guest_mem
            .memory()
            .write_slice(code, GuestAddress(CODE))
            .unwrap();
        for cpu in &mut vm.vcpus {
            cpu.set_current_pc(CODE).unwrap();
        }
        vm
    }
    fn restore(&self, vm: &Vmm, count: u8, retired: u64) -> Vmm {
        let bundle = vm.take_snapshot_bundle(retired).unwrap();
        bundle.save(&self.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&self.checkpoint).unwrap();
        Vmm::new_resume_bundle(self.config(count), &loaded).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.kernel);
        let _ = std::fs::remove_file(&self.checkpoint);
    }
}

#[test]
fn actual_cortex_m_file_retains_each_cpus_retirement_count() {
    let f = Fixture::new();
    for count in [1, 2, 4] {
        // SEV; WFI; WFE; NOP: each CPU owns both sleep and event phase.
        let mut source = f.source(count, &[0x40, 0xbf, 0x30, 0xbf, 0x20, 0xbf, 0x00, 0xbf]);
        for cpu in &mut source.vcpus {
            assert!(cpu.step_insn().unwrap().is_none());
            assert!(matches!(cpu.step_insn().unwrap(), Some(VcpuExit::Hlt)));
            assert_eq!(cpu.instruction_count(), 2);
        }
        let mut restored = f.restore(&source, count, 2 * u64::from(count));
        for (id, (a, b)) in source.vcpus.iter().zip(&restored.vcpus).enumerate() {
            assert_eq!(
                b.instruction_count(),
                a.instruction_count(),
                "CPU{id} retirement lost after actual file restoration"
            );
        }
        for vm in [&mut source, &mut restored] {
            for cpu in &mut vm.vcpus {
                assert!(matches!(cpu.step_insn().unwrap(), Some(VcpuExit::Hlt)));
                assert_eq!(cpu.instruction_count(), 2);
                cpu.wake();
                assert!(
                    cpu.step_insn().unwrap().is_none(),
                    "WFE must consume this CPU's retained event"
                );
                assert_eq!(cpu.instruction_count(), 3);
            }
        }
    }
}

#[test]
fn actual_cortex_m_file_retains_wfi_sleep_until_explicit_wake() {
    let f = Fixture::new();
    let mut source = f.source(1, &[0x30, 0xbf, 0x2a, 0x20]); // WFI; MOVS r0,#42.
    assert!(matches!(
        source.vcpus[0].step_insn().unwrap(),
        Some(VcpuExit::Hlt)
    ));
    let mut restored = f.restore(&source, 1, 1);
    assert!(matches!(
        source.vcpus[0].step_insn().unwrap(),
        Some(VcpuExit::Hlt)
    ));
    let exit = restored.vcpus[0].step_insn().unwrap();
    assert!(
        matches!(exit, Some(VcpuExit::Hlt)),
        "restored sleeping CPU executed without wake: {exit:?}"
    );
    for vm in [&mut source, &mut restored] {
        vm.vcpus[0].wake();
        assert!(vm.vcpus[0].step_insn().unwrap().is_none());
        let CpuState::CortexM(s) = vm.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(s.regs.r[0], 42);
    }
}

#[test]
fn actual_cortex_m_file_retains_a_sev_event_for_the_next_wfe() {
    let f = Fixture::new();
    let mut source = f.source(1, &[0x40, 0xbf, 0x20, 0xbf, 0x00, 0xbf]); // SEV; WFE; NOP.
    assert!(source.vcpus[0].step_insn().unwrap().is_none());
    let mut restored = f.restore(&source, 1, 1);
    assert!(source.vcpus[0].step_insn().unwrap().is_none());
    let exit = restored.vcpus[0].step_insn().unwrap();
    assert!(
        exit.is_none(),
        "restored CPU lost its pending SEV event: {exit:?}"
    );
}

#[test]
fn last_cortex_m_private_record_failure_rejects_before_any_cpu_or_ram_mutation() {
    let f = Fixture::new();
    for count in [2, 4] {
        for missing in [false, true] {
            let mut source = f.source(count, &[0x00, 0xbf, 0x30, 0xbf]);
            for cpu in &mut source.vcpus {
                cpu.step_insn().unwrap();
            }
            let mut bundle = source.take_snapshot_bundle(u64::from(count)).unwrap();
            let mut entries = bundle.take_backend_contexts().unwrap().entries().to_vec();
            let last = entries.last_mut().unwrap();
            if missing {
                *last = None;
            } else {
                last.as_mut().unwrap().data[0] ^= 1;
            }
            let bundle = bundle.with_backend_contexts(entries).unwrap();
            bundle.save(&f.checkpoint).unwrap();
            let loaded = SnapshotBundle::load(&f.checkpoint).unwrap();
            let mut target = f.source(count, &[0x2a, 0x20, 0x30, 0xbf]);
            let before: Vec<_> = target
                .vcpus
                .iter()
                .map(|c| c.capture_backend_context().unwrap())
                .collect();
            let ram = target.guest_mem.try_read_all().unwrap();
            let error = target
                .restore_snapshot_bundle(&loaded)
                .unwrap_err()
                .to_string();
            if missing {
                assert!(error.contains("missing private context"), "{error}");
            } else {
                assert!(error.contains("tag differs"), "{error}");
            }
            assert_eq!(
                target
                    .vcpus
                    .iter()
                    .map(|c| c.capture_backend_context().unwrap())
                    .collect::<Vec<_>>(),
                before
            );
            assert_eq!(target.guest_mem.try_read_all().unwrap(), ram);
            assert!(Vmm::new_resume_bundle(f.config(count), &loaded).is_err());
            std::fs::remove_file(&f.checkpoint).unwrap();
        }
    }
}

#[test]
fn absent_cortex_m_private_section_retains_legacy_projection_contract() {
    let f = Fixture::new();
    for count in [1, 2, 4] {
        let mut source = f.source(count, &[0x00, 0xbf, 0x30, 0xbf]);
        for cpu in &mut source.vcpus {
            cpu.step_insn().unwrap();
        }
        let bundle = SnapshotBundle::new(source.take_snapshot(u64::from(count)).unwrap())
            .with_cpus(source.capture_cpu_states().unwrap())
            .unwrap();
        assert!(bundle.backend_contexts().is_none());
        bundle.save(&f.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&f.checkpoint).unwrap();
        let target = Vmm::new_resume_bundle(f.config(count), &loaded).unwrap();
        for (id, cpu) in target.vcpus.iter().enumerate() {
            assert_eq!(
                crate::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
                crate::codec::serialize(&loaded.cpus().unwrap().entries()[id].state).unwrap()
            );
            assert_eq!(
                cpu.instruction_count(),
                0,
                "legacy projection does not contain retirement phase"
            );
        }
    }
}

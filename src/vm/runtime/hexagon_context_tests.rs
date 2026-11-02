//! Actual Hexagon checkpoint files must retain packet and adapter phase.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

const CODE: u64 = 0x1000;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    kernel: PathBuf,
    checkpoint: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "rax-hexagon-checkpoint-{}-{}",
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
                arch: Some(ArchKind::Hexagon),
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
    fn source(&self, count: u8, words: &[u32]) -> Vmm {
        let mut vm = Vmm::new_resume(self.config(count)).unwrap();
        let code: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        vm.guest_mem
            .memory()
            .write_slice(&code, GuestAddress(CODE))
            .unwrap();
        for cpu in &mut vm.vcpus {
            cpu.set_current_pc(CODE).unwrap();
        }
        vm
    }
    fn restore(&self, vm: &Vmm, count: u8, retired: u64) -> Vmm {
        vm.take_snapshot_bundle(retired)
            .unwrap()
            .save(&self.checkpoint)
            .unwrap();
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
fn regs(cpu: &dyn VCpu) -> crate::vm::vcpu::HexagonRegisters {
    let CpuState::Hexagon(s) = cpu.get_state().unwrap() else {
        panic!()
    };
    s.regs
}
fn configure(cpu: &mut dyn VCpu, edit: impl FnOnce(&mut crate::vm::vcpu::HexagonRegisters)) {
    let mut r = regs(cpu);
    edit(&mut r);
    cpu.set_state(&CpuState::hexagon(r)).unwrap();
}

#[test]
fn actual_hexagon_file_retains_each_cpus_committed_packet_count() {
    let f = Fixture::new();
    for count in [1, 2, 4] {
        // LLVM 23 hexagonv68: {r0=#42}.
        let mut source = f.source(count, &[0x7800_c540]);
        for cpu in &mut source.vcpus {
            assert!(cpu.step_insn().unwrap().is_none());
            assert_eq!(cpu.instruction_count(), 1);
        }
        let restored = f.restore(&source, count, u64::from(count));
        for (id, (a, b)) in source.vcpus.iter().zip(&restored.vcpus).enumerate() {
            assert_eq!(
                b.instruction_count(),
                a.instruction_count(),
                "CPU{id} committed packet count lost after actual file restore"
            );
        }
    }
}
#[test]
fn actual_hexagon_file_retains_a_pending_mmio_read_and_its_completion() {
    let f = Fixture::new();
    for count in [1, 2, 4] {
        // LLVM 23 hexagonv68: {r1=memw(r2)}; r2 names the modeled UART.
        let mut source = f.source(count, &[0x9182_c001]);
        for cpu in &mut source.vcpus {
            configure(cpu.as_mut(), |r| r.r[2] = 0xf000_0000);
            assert!(matches!(
                cpu.step_insn().unwrap(),
                Some(VcpuExit::MmioRead {
                    addr: 0xf000_0000,
                    size: 4
                })
            ));
            assert_eq!(cpu.instruction_count(), 0);
        }
        let mut restored = f.restore(&source, count, 0);
        for vm in [&mut source, &mut restored] {
            for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
                let response = 0x1122_3300u32 + id as u32;
                cpu.complete_io_in(&response.to_le_bytes());
                let exit = cpu.step_insn().unwrap();
                assert!(
                    exit.is_none(),
                    "CPU{id} lost the saved input completion and requested input again: {exit:?}"
                );
                assert_eq!(regs(cpu.as_ref()).r[1], response);
                assert_eq!(cpu.instruction_count(), 1);
                assert_eq!(cpu.current_pc(), CODE + 4);
            }
        }
    }
}
#[test]
fn actual_hexagon_file_retains_local_load_locked_state_until_store_conditional() {
    let f = Fixture::new();
    for count in [1, 2, 4] {
        // LLVM 23 hexagonv68: {r1=memw_locked(r2)}; {memw_locked(r2,p0)=r3}.
        let mut source = f.source(count, &[0x9202_c001, 0xa0a2_c300]);
        for (id, cpu) in source.vcpus.iter_mut().enumerate() {
            let address = 0x2000 + 8 * id as u64;
            source
                .guest_mem
                .memory()
                .write_slice(&0x1122_3344u32.to_le_bytes(), GuestAddress(address))
                .unwrap();
            configure(cpu.as_mut(), |r| {
                r.r[2] = address as u32;
                r.r[3] = 0x5566_7788;
            });
            assert!(cpu.step_insn().unwrap().is_none());
        }
        let mut restored = f.restore(&source, count, u64::from(count));
        for vm in [&mut source, &mut restored] {
            for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
                assert!(cpu.step_insn().unwrap().is_none());
                assert_eq!(
                    regs(cpu.as_ref()).p[0],
                    0xff,
                    "CPU{id} lost its modeled local reservation during file restore"
                );
            }
            for id in 0..count {
                let mut data = [0; 4];
                vm.guest_mem
                    .memory()
                    .read_slice(&mut data, GuestAddress(0x2000 + 8 * u64::from(id)))
                    .unwrap();
                assert_eq!(u32::from_le_bytes(data), 0x5566_7788);
            }
        }
    }
}

#[test]
fn last_hexagon_private_record_rejects_before_any_cpu_or_ram_mutation() {
    let f = Fixture::new();
    for count in [2, 4] {
        for missing in [false, true] {
            let mut source = f.source(count, &[0x7800_c540]);
            for cpu in &mut source.vcpus {
                cpu.step_insn().unwrap();
            }
            let mut bundle = source.take_snapshot_bundle(u64::from(count)).unwrap();
            let mut entries = bundle.take_backend_contexts().unwrap().entries().to_vec();
            if missing {
                *entries.last_mut().unwrap() = None;
            } else {
                entries.last_mut().unwrap().as_mut().unwrap().data[0] ^= 1;
            }
            let bundle = bundle.with_backend_contexts(entries).unwrap();
            bundle.save(&f.checkpoint).unwrap();
            let loaded = SnapshotBundle::load(&f.checkpoint).unwrap();
            let mut target = f.source(count, &[0x7800_c540]);
            target
                .guest_mem
                .memory()
                .write_slice(&[0x77], GuestAddress(0x2000))
                .unwrap();
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
            assert!(
                error.contains(if missing {
                    "missing private context"
                } else {
                    "tag differs"
                }),
                "{error}"
            );
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
fn absent_hexagon_private_section_retains_legacy_projection_semantics() {
    let f = Fixture::new();
    for count in [1, 2, 4] {
        let mut source = f.source(count, &[0x7800_c540]);
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
                "legacy files cannot supply an omitted packet count"
            );
        }
    }
}

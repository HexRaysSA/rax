//! Real software backends through file capture and fresh-machine restoration.
//! Explicit CPU steps verify transport; secondary startup is tested separately.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::{BackendContext, CheckpointResource, SnapshotBundle, X86_64_CONTEXT};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

static NEXT: AtomicU64 = AtomicU64::new(0);
const CODE: &[u8] = &[0x0f, 0x01, 0xd1, 0xe4, 0x80, 0x0f, 0x01, 0xd0, 0xf4];
struct Fixture {
    kernel: PathBuf,
    checkpoint: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let prefix = std::env::temp_dir().join(format!(
            "rax-x86-context-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let kernel = prefix.with_extension("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        Self {
            kernel,
            checkpoint: prefix.with_extension("rxc"),
        }
    }
    fn config(&self, count: u8) -> VmConfig {
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.kernel.clone()),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(128 << 20);
        config
    }
    fn source(&self, count: u8) -> Vmm {
        let mut vm = Vmm::new_resume(self.config(count)).unwrap();
        let medium = Arc::new(vec![0xa5; 2048]);
        for (index, cpu) in vm.vcpus.iter_mut().enumerate() {
            let code = 0x1000 + index as u64 * 0x100;
            vm.guest_mem
                .memory()
                .write_slice(CODE, GuestAddress(code))
                .unwrap();
            let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.rip = code;
            state.regs.rsp = 0xe000;
            state.regs.rax = 3;
            state.regs.rcx = 0;
            state.regs.rdx = 0;
            state.regs.rflags = 2;
            state.sregs.cr0 = 1;
            state.sregs.cr3 = 0;
            state.sregs.cr4 = 1 << 18;
            state.sregs.efer = 1 << 10;
            state.sregs.cs.base = 0;
            state.sregs.cs.selector = 0;
            state.sregs.cs.l = true;
            state.sregs.cs.db = false;
            cpu.set_state(&CpuState::X86_64(state)).unwrap();
            cpu.attach_x86_64_bios(Some(medium.clone()), 128 << 20);
            assert!(cpu.step_insn().unwrap().is_none());
            assert!(matches!(
                cpu.step_insn().unwrap(),
                Some(VcpuExit::IoIn {
                    port: 0x80,
                    size: 1
                })
            ));
            assert_eq!(cpu.instruction_count(), 2);
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
fn files_continue_pending_inputs_xcr0_counts_and_shared_media_for_one_two_four_cpus() {
    for count in [1, 2, 4] {
        let fixture = Fixture::new();
        let mut source = fixture.source(count);
        let before = contexts(&source);
        assert!(
            before
                .iter()
                .all(|context| context.as_ref().unwrap().kind == X86_64_CONTEXT)
        );
        source
            .take_snapshot_bundle(2 * u64::from(count))
            .unwrap()
            .save(&fixture.checkpoint)
            .unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        assert_eq!(loaded.resources().unwrap().keys().count(), 1);
        assert_eq!(loaded.backend_contexts().unwrap().entries(), before);
        let config = fixture.config(count);
        std::fs::remove_file(&fixture.kernel).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(contexts(&restored), before);
        let first = restored.vcpus[0].x86_bios_binding().unwrap().0.unwrap();
        for cpu in &restored.vcpus {
            assert!(Arc::ptr_eq(
                &first,
                &cpu.x86_bios_binding().unwrap().0.unwrap()
            ));
        }
        for vm in [&mut source, &mut restored] {
            for (index, cpu) in vm.vcpus.iter_mut().enumerate() {
                cpu.complete_io_in(&[0xa5]);
                let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(state.regs.rax, 0xa5);
                assert_eq!(cpu.instruction_count(), 2);
                cpu.complete_io_in(&[0x77]);
                assert!(cpu.step_insn().unwrap().is_none());
                let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(state.regs.rax, 3);
                assert_eq!(state.regs.rip, 0x1008 + index as u64 * 0x100);
                assert_eq!(cpu.instruction_count(), 3);
            }
        }
        assert_eq!(contexts(&restored), contexts(&source));
    }
}

#[test]
fn malformed_final_cpu_and_missing_or_unreferenced_media_preserve_all_live_state() {
    let fixture = Fixture::new();
    let source = fixture.source(4);
    let original = contexts(&source);
    let cpus = source.capture_cpu_states().unwrap();
    let mut target = Vmm::new_resume(fixture.config(4)).unwrap();
    target
        .guest_mem
        .memory()
        .write_slice(&[0x55; 4096], GuestAddress(0x8000))
        .unwrap();
    target.serial.lock().unwrap().queue_input(&[0x7a]);
    let before = contexts(&target);
    let devices = crate::codec::serialize(&target.capture_devices().unwrap()).unwrap();
    let execution = target.coordinator.clone();
    let memory = target.guest_mem.try_read_all().unwrap();
    for mutation in 0..5 {
        let mut entries = original.clone();
        let last = entries.last_mut().unwrap().as_mut().unwrap();
        match mutation {
            0 => last.kind = u32::MAX,
            1 => last.data[0] ^= 0x80,
            2 => {
                last.data.pop();
            }
            3 | 4 => (),
            _ => unreachable!(),
        }
        let mut bundle = SnapshotBundle::new(source.take_snapshot(8).unwrap())
            .with_cpus(cpus.clone())
            .unwrap()
            .with_backend_contexts(entries)
            .unwrap();
        if mutation != 3 {
            let mut resources = source.vcpus[0].capture_checkpoint_resources().unwrap();
            if mutation == 4 {
                resources.push(CheckpointResource::boot_cdrom(Arc::new(vec![0x33; 2048])).unwrap());
            }
            bundle = bundle.with_resources(resources).unwrap();
        }
        assert!(
            target.restore_snapshot_bundle(&bundle).is_err(),
            "mutation{mutation}"
        );
        assert_eq!(contexts(&target), before);
        assert_eq!(target.guest_mem.try_read_all().unwrap(), memory);
        assert_eq!(
            crate::codec::serialize(&target.capture_devices().unwrap()).unwrap(),
            devices
        );
        assert_eq!(target.coordinator, execution);
    }
}

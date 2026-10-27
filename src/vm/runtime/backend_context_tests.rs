//! Actual platform adapters must retain private controls and device phase.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::{BackendContext, SnapshotBundle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

static NEXT: AtomicU64 = AtomicU64::new(0);
const CODE: u64 = 0x5000_0100;
const CONTROLS: [u32; 4] = [0x0050_0000, 0x00f0_0000, 0x8050_0000, 0x80f0_0000];
// MCR CPACR; STR VIC enable/software-pending; STR PWM count/control/enable;
// WFI; MRC CPACR; LDR PWM counter; LDR VIC IRQSTATUS; WFI.
const GUEST: [u32; 11] = [
    0xee01_0f50,
    0xe588_9010,
    0xe588_9018,
    0xe582_403c,
    0xe582_5008,
    0xe582_6044,
    0xe320_f003,
    0xee11_1f50,
    0xe592_7040,
    0xe598_a000,
    0xe320_f003,
];

struct Fixture {
    kernel: PathBuf,
    checkpoint: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let prefix = std::env::temp_dir().join(format!(
            "rax-backend-context-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let kernel = prefix.with_extension("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        Self {
            kernel,
            checkpoint: prefix.with_extension("rax"),
        }
    }
    fn config(&self, count: u8) -> VmConfig {
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Armv7a),
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
        for index in 0..usize::from(count) {
            let code = CODE + 0x100 * index as u64;
            for (i, word) in GUEST.iter().enumerate() {
                vm.guest_mem
                    .memory()
                    .write_slice(&word.to_le_bytes(), GuestAddress(code + i as u64 * 4))
                    .unwrap();
            }
            let CpuState::Aarch32(mut state) = vm.vcpus[index].get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = code as u32;
            state.regs.r[0] = CONTROLS[index];
            state.regs.r[2] = 0x7f00_6000;
            state.regs.r[4] = 17;
            state.regs.r[5] = (1 << 21) | (1 << 20);
            state.regs.r[6] = 1 << 4;
            state.regs.r[8] = 0x7120_0000;
            state.regs.r[9] = 1 << 12;
            vm.vcpus[index]
                .set_state(&CpuState::Aarch32(state))
                .unwrap();
            assert!(matches!(vm.vcpus[index].run().unwrap(), VcpuExit::Hlt));
            assert_eq!(vm.vcpus[index].instruction_count(), 7);
        }
        let mut uart = vm.s3c_uart.as_ref().unwrap().lock().unwrap();
        uart.queue_input(&[0x39, 0xa6]);
        uart.write(0x38, 0xe);
        drop(uart);
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
fn resume(vm: &mut Vmm) {
    for (index, cpu) in vm.vcpus.iter_mut().enumerate() {
        assert_eq!(cpu.current_pc(), CODE + index as u64 * 0x100 + 28);
        cpu.wake();
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        let CpuState::Aarch32(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.r[1], CONTROLS[index], "CPACR/{index}");
        assert_eq!(state.regs.r[7], 13, "PWM phase/{index}");
        assert_eq!(state.regs.r[10], 1 << 12, "pending VIC/{index}");
        assert_eq!(cpu.instruction_count(), 11);
    }
}

#[test]
fn backend_context_files_resume_one_two_four_actual_s3c_adapters() {
    let fixture = Fixture::new();
    for count in [1, 2, 4] {
        let mut uninterrupted = fixture.source(count);
        let before = contexts(&uninterrupted);
        let bundle = uninterrupted
            .take_snapshot_bundle(7 * u64::from(count))
            .unwrap();
        assert_eq!(bundle.backend_contexts().unwrap().entries(), before);
        bundle.save(&fixture.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        assert_eq!(loaded.backend_contexts().unwrap().entries(), before);
        let mut restored = Vmm::new_resume_bundle(fixture.config(count), &loaded).unwrap();
        assert_eq!(contexts(&restored), before);
        resume(&mut uninterrupted);
        resume(&mut restored);
        for vm in [&uninterrupted, &restored] {
            let mut uart = vm.s3c_uart.as_ref().unwrap().lock().unwrap();
            assert!(uart.irq_pending());
            assert_eq!(uart.read(0x24), 0x39);
            assert_eq!(uart.read(0x24), 0xa6);
            assert!(!uart.irq_pending());
        }
        assert_eq!(contexts(&restored), contexts(&uninterrupted));
        std::fs::remove_file(&fixture.checkpoint).unwrap();
    }
}

#[test]
fn invalid_final_backend_context_rejects_before_cpu_ram_or_uart_changes() {
    let fixture = Fixture::new();
    let source = fixture.source(4);
    let cpus = source.capture_cpu_states().unwrap();
    let original = contexts(&source);
    let mut target = Vmm::new_resume(fixture.config(4)).unwrap();
    target
        .guest_mem
        .memory()
        .write_slice(&[0xa5; 4096], GuestAddress(0))
        .unwrap();
    target
        .s3c_uart
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(&[0x77]);
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
            3 => {
                last.data[8..12].copy_from_slice(&0u32.to_le_bytes());
            }
            _ => unreachable!(),
        }
        let bundle = SnapshotBundle::new(source.take_snapshot(28).unwrap())
            .with_cpus(cpus.clone())
            .unwrap()
            .with_backend_contexts(entries)
            .unwrap();
        assert!(
            target.restore_snapshot_bundle(&bundle).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(contexts(&target), before);
        let mut memory = [0; 4096];
        target
            .guest_mem
            .memory()
            .read_slice(&mut memory, GuestAddress(0))
            .unwrap();
        assert_eq!(memory, [0xa5; 4096]);
    }
}

#[test]
fn backend_contexts_cannot_be_dropped_by_base_or_cpu_set_extraction() {
    let fixture = Fixture::new();
    let source = fixture.source(1);
    let build = || {
        SnapshotBundle::new(source.take_snapshot(7).unwrap())
            .with_cpus(source.capture_cpu_states().unwrap())
            .unwrap()
            .with_backend_contexts(contexts(&source))
            .unwrap()
    };
    assert!(build().into_base().is_err());
    assert!(build().into_parts().is_err());
    let mut missing = build();
    missing.take_cpus();
    assert!(missing.save(&fixture.checkpoint).is_err());
    assert!(!fixture.checkpoint.exists());
}

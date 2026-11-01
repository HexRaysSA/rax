//! Actual platform adapters must retain private controls and device phase.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::{BackendContext, SnapshotBundle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};

#[path = "a32_restricted_fp_tests.rs"]
mod restricted_fp;

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

// The S3C02 payload begins with a fixed-width ID and the complete typed CPU.
// Preserve its remaining controller/adapter bytes exactly. Checking the decoded
// prefix against re-encoding prevents a wire-layout change from going unnoticed.
fn profile_cpu(context: &BackendContext) -> (u32, crate::isa::arm::Armv7Cpu, usize) {
    assert_eq!(context.kind, crate::vm::snapshot::S3C64XX_CONTEXT);
    assert!(context.data.starts_with(b"RAXS3C02"));
    let mut reader = std::io::Cursor::new(&context.data[8..]);
    let id: u32 = crate::codec::deserialize_from(&mut reader).unwrap();
    let cpu: crate::isa::arm::Armv7Cpu = crate::codec::deserialize_from(&mut reader).unwrap();
    let length = reader.position() as usize;
    assert_eq!(
        crate::codec::serialize(&(id, &cpu)).unwrap(),
        &context.data[8..8 + length]
    );
    (id, cpu, 8 + length)
}

fn select_profile(vm: &mut Vmm, index: usize, enabled: bool) {
    let vcpu = &mut vm.vcpus[index];
    let mut context = vcpu.capture_backend_context().unwrap().unwrap();
    let (id, mut cpu, end) = profile_cpu(&context);
    assert_eq!(id as usize, index);
    cpu.vfp.mvfr1 = 0x0211_1111 | if enabled { 1 << 28 } else { 0 };
    cpu.vfp.mvfr2 = if enabled { 0x43 } else { 0 };
    cpu.cp15.id_isar6 = 0;
    cpu.cp15.cpacr = crate::isa::arm::cp15::Cpacr::from_bits(0x00f0_0000);
    cpu.vfp.fpexc = 1 << 30;
    let mut data = b"RAXS3C02".to_vec();
    data.extend(crate::codec::serialize(&(id, cpu)).unwrap());
    data.extend_from_slice(&context.data[end..]);
    context.data = data;
    vcpu.restore_checkpoint_context(
        &vcpu.get_state().unwrap(),
        &vcpu.get_emulator_state().unwrap_or_default(),
        Some(&context),
    )
    .unwrap();
}

#[test]
fn miscellaneous_and_fused_profiles_survive_multicpu_rxc_file_continuation() {
    let mut fixture = Fixture::new();
    fixture.checkpoint.set_extension("rxc");
    for count in [2, 4] {
        for fused in [false, true] {
            for enabled_parity in [0, 1] {
                let mut source = Vmm::new_resume(fixture.config(count)).unwrap();
                for id in 0..usize::from(count) {
                    let code = CODE + 0x100 * id as u64;
                    let thumb = id & 1 != 0;
                    // VFMA.F32 S0,S1,S2 / VMAXNM.F32 Q0,Q1,Q2.
                    let raw = if fused {
                        0xeea0_0a81u32
                    } else if thumb {
                        0xff02_0f54
                    } else {
                        0xf302_0f54
                    };
                    let bytes = if thumb {
                        let high = ((raw >> 16) as u16).to_le_bytes();
                        let low = (raw as u16).to_le_bytes();
                        [high[0], high[1], low[0], low[1]]
                    } else {
                        raw.to_le_bytes()
                    };
                    source
                        .guest_mem
                        .memory()
                        .write_slice(&bytes, GuestAddress(code))
                        .unwrap();
                    let wfi = if thumb {
                        vec![0x30, 0xbf]
                    } else {
                        0xe320_f003u32.to_le_bytes().to_vec()
                    };
                    source
                        .guest_mem
                        .memory()
                        .write_slice(&wfi, GuestAddress(code + 4))
                        .unwrap();
                    let CpuState::Aarch32(mut state) = source.vcpus[id].get_state().unwrap() else {
                        panic!()
                    };
                    state.regs.pc = code as u32;
                    state.regs.cpsr = (state.regs.cpsr & !32) | if thumb { 32 } else { 0 };
                    source.vcpus[id]
                        .set_state(&CpuState::Aarch32(state))
                        .unwrap();
                    select_profile(&mut source, id, id & 1 == enabled_parity);
                }
                // These are explicitly prepared software execution contexts.
                // AP firmware/startup is a separate architectural requirement;
                // construction alone leaves all secondary CPUs offline.
                source.coordinator.online.fill(true);
                let before = contexts(&source);
                let bundle = source.take_snapshot_bundle(0).unwrap();
                bundle.save(&fixture.checkpoint).unwrap();
                let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
                assert_eq!(loaded.backend_contexts().unwrap().entries(), before);
                let mut restored = Vmm::new_resume_bundle(fixture.config(count), &loaded).unwrap();
                assert_eq!(contexts(&restored), before);
                for vm in [&mut source, &mut restored] {
                    for id in 0..usize::from(count) {
                        let enabled = id & 1 == enabled_parity;
                        assert!(vm.vcpus[id].supports_stepping());
                        let context = vm.vcpus[id].capture_backend_context().unwrap().unwrap();
                        let (_, private, _) = profile_cpu(&context);
                        assert!(
                            !private.is_halted,
                            "count={count} fused={fused} parity={enabled_parity} CPU{id} already halted"
                        );
                        assert_eq!(private.vfp.mvfr2, if enabled { 0x43 } else { 0 });
                        let turn = vm.execute_turn().unwrap();
                        if enabled {
                            let turn = turn.expect("enabled instruction followed by WFI");
                            assert_eq!(turn.cpu_index, id);
                            assert!(matches!(turn.exit, VcpuExit::Hlt));
                        } else {
                            assert!(
                                turn.is_none(),
                                "count={count} fused={fused} parity={enabled_parity} CPU{id} PC={:#x} retired={} exit={:?}",
                                vm.vcpus[id].current_pc(),
                                vm.vcpus[id].instruction_count(),
                                turn.as_ref().map(|t| &t.exit)
                            );
                        }
                        let cpu = &vm.vcpus[id];
                        assert_eq!(cpu.instruction_count(), if enabled { 2 } else { 0 });
                        assert_eq!(
                            cpu.current_pc(),
                            if enabled {
                                CODE + 0x100 * id as u64 + if id & 1 != 0 { 6 } else { 8 }
                            } else {
                                4
                            }
                        );
                        let context = cpu.capture_backend_context().unwrap().unwrap();
                        let (_, private, _) = profile_cpu(&context);
                        assert_eq!(private.vfp.mvfr2, if enabled { 0x43 } else { 0 });
                        assert_eq!(private.vfp.mvfr1 >> 28, u32::from(enabled));
                    }
                    assert_eq!(vm.coordinator.cursor, 0);
                    assert_eq!(vm.coordinator.retired, u64::from(count));
                }
                assert_eq!(contexts(&restored), contexts(&source));
                std::fs::remove_file(&fixture.checkpoint).unwrap();
            }
        }
    }
}

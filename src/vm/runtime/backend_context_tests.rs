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

// Coordinated S3C shared-owner admission and failure publication regressions.
struct S3cFinalRestoreFailure(Box<dyn VCpu>);
impl VCpu for S3cFinalRestoreFailure {
    fn id(&self) -> u32 {
        self.0.id()
    }
    fn run(&mut self) -> Result<VcpuExit> {
        self.0.run()
    }
    fn get_state(&self) -> Result<CpuState> {
        self.0.get_state()
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.0.set_state(state)
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        self.0.complete_io_in(data)
    }
    fn capture_backend_context(&self) -> Result<Option<BackendContext>> {
        self.0.capture_backend_context()
    }
    fn validate_checkpoint_context(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&BackendContext>,
    ) -> Result<()> {
        self.0.validate_checkpoint_context(state, emulator, context)
    }
    fn restore_checkpoint_context(
        &mut self,
        _: &CpuState,
        _: &crate::vm::snapshot::EmulatorState,
        _: Option<&BackendContext>,
    ) -> Result<()> {
        Err(Error::Emulator("injected final S3C restore failure".into()))
    }
}
#[test]
fn final_s3c_setter_failure_keeps_earlier_cpu_and_shared_uart_unchanged() {
    let fixture = Fixture::new();
    let source = fixture.source(2);
    let bundle = source.take_snapshot_bundle(14).unwrap();
    let mut target = Vmm::new_resume(fixture.config(2)).unwrap();
    target
        .s3c_uart
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(&[0x77]);
    let before = contexts(&target);
    let memory = target.guest_mem.try_read_all().unwrap();
    let old = target.vcpus.remove(1);
    target.vcpus.push(Box::new(S3cFinalRestoreFailure(old)));
    let error = target
        .restore_snapshot_bundle(&bundle)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("injected final S3C restore failure"),
        "{error}"
    );
    assert_eq!(
        contexts(&target),
        before,
        "rejected restore published a CPU/UART prefix"
    );
    assert_eq!(target.guest_mem.try_read_all().unwrap(), memory);
}
#[test]
fn conflicting_s3c_shared_uart_images_reject_before_target_mutation() {
    let fixture = Fixture::new();
    let source = fixture.source(2);
    let first = source.vcpus[0].capture_backend_context().unwrap();
    {
        let mut uart = source.s3c_uart.as_ref().unwrap().lock().unwrap();
        while uart.read(0x10) & 1 != 0 {
            uart.read(0x24);
        }
        uart.queue_input(&[0x5b]);
    }
    let second = source.vcpus[1].capture_backend_context().unwrap();
    let bundle = SnapshotBundle::new(source.take_snapshot(14).unwrap())
        .with_cpus(source.capture_cpu_states().unwrap())
        .unwrap()
        .with_backend_contexts(vec![first, second])
        .unwrap();
    let mut target = Vmm::new_resume(fixture.config(2)).unwrap();
    target
        .s3c_uart
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .queue_input(&[0x77]);
    for (index, entry) in bundle.cpus().unwrap().entries().iter().enumerate() {
        target.vcpus[index]
            .validate_checkpoint_context(
                &entry.state,
                &entry.emulator,
                bundle.backend_contexts().unwrap().entries()[index].as_ref(),
            )
            .unwrap();
    }
    let before = contexts(&target);
    let memory = target.guest_mem.try_read_all().unwrap();
    let error = target
        .restore_snapshot_bundle(&bundle)
        .unwrap_err()
        .to_string()
        .to_ascii_lowercase();
    assert!(
        error.contains("uart") && error.contains("conflict"),
        "{error}"
    );
    assert_eq!(contexts(&target), before);
    assert_eq!(target.guest_mem.try_read_all().unwrap(), memory);
}
struct S3cCaptureBarrier {
    inner: Box<dyn VCpu>,
    entered: std::sync::mpsc::Sender<()>,
    resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl VCpu for S3cCaptureBarrier {
    fn id(&self) -> u32 {
        self.inner.id()
    }
    fn run(&mut self) -> Result<VcpuExit> {
        self.inner.run()
    }
    fn get_state(&self) -> Result<CpuState> {
        self.inner.get_state()
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.inner.set_state(state)
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        self.inner.complete_io_in(data)
    }
    fn capture_checkpoint_record(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        scope: Option<&crate::vm::memory::checkpoint::CheckpointPublication<'_>>,
    ) -> Result<(crate::vm::snapshot::CpuSnapshot, Option<BackendContext>)> {
        self.entered
            .send(())
            .map_err(|e| Error::Emulator(e.to_string()))?;
        self.resume
            .lock()
            .map_err(|_| Error::Emulator("test barrier lock poisoned".into()))?
            .recv()
            .map_err(|e| Error::Emulator(e.to_string()))?;
        self.inner.capture_checkpoint_record(boundary, scope)
    }
}
#[test]
fn complete_s3c_capture_excludes_the_shared_uart_writer() {
    let fixture = Fixture::new();
    let mut source = fixture.source(2);
    let uart = source.s3c_uart.as_ref().unwrap().clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let first = source.vcpus.remove(0);
    source.vcpus.insert(
        0,
        Box::new(S3cCaptureBarrier {
            inner: first,
            entered: entered_tx,
            resume: std::sync::Mutex::new(resume_rx),
        }),
    );
    let worker = std::thread::spawn(move || source.take_snapshot_bundle(14));
    let entered = entered_rx.recv_timeout(std::time::Duration::from_secs(15));
    let excluded = matches!(uart.try_lock(), Err(std::sync::TryLockError::WouldBlock));
    // Release and join before assertions, including failure paths.
    let released = resume_tx.send(());
    let result = worker.join();
    assert!(
        entered.is_ok(),
        "capture did not reach the CPU boundary: {entered:?}"
    );
    assert!(released.is_ok());
    assert!(result.unwrap().is_ok());
    assert!(
        excluded,
        "complete capture admitted a shared UART writer inside its boundary"
    );
}

#[test]
fn present_private_context_set_rejects_a_missing_s3c_cpu_before_target_mutation() {
    let fixture = Fixture::new();
    for count in [2, 4] {
        let source = fixture.source(count);
        let mut bundle = source.take_snapshot_bundle(7 * u64::from(count)).unwrap();
        let mut entries = bundle.take_backend_contexts().unwrap().entries().to_vec();
        let source_cpacr = profile_cpu(entries[0].as_ref().unwrap())
            .1
            .cp15
            .cpacr
            .bits();
        assert_ne!(source_cpacr, 0x00f0_0000);
        entries[0] = None;
        let bundle = bundle.with_backend_contexts(entries).unwrap();
        assert!(bundle.execution().is_some());
        bundle.save(&fixture.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        let mut target = Vmm::new_resume(fixture.config(count)).unwrap();
        target
            .s3c_uart
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .queue_input(&[0x77]);
        let before = contexts(&target);
        let memory = target.guest_mem.try_read_all().unwrap();
        let result = target.restore_snapshot_bundle(&loaded);
        if result.is_ok() {
            let actual = contexts(&target);
            let observed = profile_cpu(actual[0].as_ref().unwrap()).1.cp15.cpacr.bits();
            panic!(
                "accepted incomplete private set: CPU0 CPACR={observed:#010x}, source={source_cpacr:#010x}"
            );
        }
        let error = result.unwrap_err().to_string().to_ascii_lowercase();
        assert!(
            error.contains("private") && error.contains("missing"),
            "{error}"
        );
        assert_eq!(contexts(&target), before);
        assert_eq!(target.guest_mem.try_read_all().unwrap(), memory);
        assert!(Vmm::new_resume_bundle(fixture.config(count), &loaded).is_err());
        std::fs::remove_file(&fixture.checkpoint).unwrap();
    }
}

#[test]
fn absent_private_context_section_retains_explicit_s3c_projection_compatibility() {
    let fixture = Fixture::new();
    for count in [2, 4] {
        let source = fixture.source(count);
        let bundle = SnapshotBundle::new(source.take_snapshot(7 * u64::from(count)).unwrap())
            .with_cpus(source.capture_cpu_states().unwrap())
            .unwrap();
        assert!(bundle.backend_contexts().is_none());
        bundle.save(&fixture.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        let mut target = Vmm::new_resume(fixture.config(count)).unwrap();
        target
            .s3c_uart
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .queue_input(&[0x77]);
        target.restore_snapshot_bundle(&loaded).unwrap();
        for (id, cpu) in target.vcpus.iter().enumerate() {
            assert_eq!(
                crate::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
                crate::codec::serialize(&loaded.cpus().unwrap().entries()[id].state).unwrap()
            );
            let private = cpu.capture_backend_context().unwrap().unwrap();
            assert_eq!(profile_cpu(&private).1.cp15.cpacr.bits(), 0x00f0_0000);
        }
        assert_eq!(
            target.s3c_uart.as_ref().unwrap().lock().unwrap().read(0x24),
            0x77
        );
        std::fs::remove_file(&fixture.checkpoint).unwrap();
    }
}

struct PrivateComparison {
    records: Vec<Option<BackendContext>>,
    heartbeat_epochs: Vec<Option<(crate::host::time::Instant, crate::host::time::Instant)>>,
}

fn private_comparison(vm: &Vmm) -> PrivateComparison {
    let begin = crate::host::time::Instant::now();
    let mut records = contexts(vm);
    let end = crate::host::time::Instant::now();
    let mut heartbeat_epochs = Vec::new();
    for record in &mut records {
        let Some(record) = record
            .as_mut()
            .filter(|r| r.kind == crate::vm::snapshot::AARCH64_CONTEXT)
        else {
            heartbeat_epochs.push(None);
            continue;
        };
        assert!(record.data.starts_with(b"RAXA6403"));
        let mut cursor = std::io::Cursor::new(&record.data[8..]);
        let prefix: (u32, crate::isa::arm::aarch64::cpu::CoreCheckpoint, u64, u64) =
            crate::codec::deserialize_from(&mut cursor).unwrap();
        let start = 8 + cursor.position() as usize;
        assert_eq!(
            crate::codec::serialize(&prefix).unwrap(),
            record.data[8..start]
        );
        let age: std::time::Duration = crate::codec::deserialize_from(&mut cursor).unwrap();
        let finish = 8 + cursor.position() as usize;
        assert_eq!(
            crate::codec::serialize(&age).unwrap(),
            record.data[start..finish]
        );
        // Age advances during pure capture. Preserve every other byte and
        // separately require that both observations imply the same epoch.
        record.data[start..finish]
            .copy_from_slice(&crate::codec::serialize(&std::time::Duration::ZERO).unwrap());
        heartbeat_epochs.push(Some((
            begin.checked_sub(age).unwrap(),
            end.checked_sub(age).unwrap(),
        )));
    }
    PrivateComparison {
        records,
        heartbeat_epochs,
    }
}

fn assert_present_private_set_admits_no_missing_required_cpu(arch: ArchKind) {
    let fixture = Fixture::new();
    let mut config = fixture.config(2);
    config.arch = arch;
    let source = Vmm::new_resume(config.clone()).unwrap();
    let mut bundle = source.take_snapshot_bundle(0).unwrap();
    let mut entries = bundle.take_backend_contexts().unwrap().entries().to_vec();
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().all(Option::is_some),
        "{arch:?} fixture lacks its producer records"
    );
    entries[0] = None;
    let incomplete = bundle.with_backend_contexts(entries).unwrap();
    let mut target = Vmm::new_resume(config).unwrap();
    let before = private_comparison(&target);
    let memory = target.guest_mem.try_read_all().unwrap();
    let error = target
        .restore_snapshot_bundle(&incomplete)
        .expect_err("accepted a missing CPU record in the present private producer set")
        .to_string()
        .to_ascii_lowercase();
    assert!(
        error.contains("private") && error.contains("missing"),
        "{arch:?}: {error}"
    );
    let after = private_comparison(&target);
    assert_eq!(after.records, before.records);
    for (id, (before, after)) in before
        .heartbeat_epochs
        .iter()
        .zip(&after.heartbeat_epochs)
        .enumerate()
    {
        match (before, after) {
            (Some((b0, b1)), Some((a0, a1))) => {
                assert!(b0 <= a1 && a0 <= b1, "heartbeat epoch changed for CPU{id}");
            }
            (None, None) => {}
            _ => panic!("heartbeat producer changed for CPU{id}"),
        }
    }
    assert_eq!(target.guest_mem.try_read_all().unwrap(), memory);
}

#[test]
fn present_private_context_set_rejects_a_missing_software_aarch64_cpu() {
    assert_present_private_set_admits_no_missing_required_cpu(ArchKind::Aarch64);
}

#[test]
fn present_private_context_set_rejects_a_missing_software_riscv_cpu() {
    assert_present_private_set_admits_no_missing_required_cpu(ArchKind::Riscv64);
}

#[test]
fn present_private_context_set_rejects_a_missing_software_x86_cpu() {
    assert_present_private_set_admits_no_missing_required_cpu(ArchKind::X86_64);
}

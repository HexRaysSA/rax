//! Actual file/factory/coordinator and source-media lock-order witnesses.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress};
const CODE: u32 = 0x1000;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rax-s5l-context-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn selected(label: &str) -> bool {
    std::env::var("RAX_S5L_CONTEXT_CASE").as_deref() == Ok(label)
}
fn root() -> PathBuf {
    std::env::var_os("RAX_S5L_CONTEXT_ROOT").unwrap().into()
}
fn child(label: &str, path: &Path, phase: &str, s5l: bool) {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("RAX_S5L_") || name == "RAX_TRACE_PC" {
            cmd.env_remove(name);
        }
    }
    cmd.args([
        &format!("vm::runtime::s5l_context_tests::{label}"),
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("RAX_S5L_CONTEXT_CASE", label)
    .env("RAX_S5L_CONTEXT_ROOT", path)
    .env("RAX_S5L_CONTEXT_PHASE", phase)
    .env("RAX_MACHINE", if s5l { "s5l8900" } else { "gsc" })
    .env(
        "RAX_S5L_NAND",
        if s5l {
            path.join("nand")
        } else {
            path.join("nonexistent-target-nand")
        },
    );
    if !s5l {
        cmd.env("RAX_S5L_NO_SECURITY_SEED", "1")
            .env("RAX_S5L_GID_KEY", "0é0");
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "S5L child {phase}: {:?}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed; 0 failed"));
}
fn config(path: &Path, count: u8) -> VmConfig {
    VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::Armv7a),
            backend: Some(BackendKind::Emulator),
            kernel: Some(path.join("kernel")),
            memory: Some(MemorySize(128 << 20)),
            vcpus: Some(count),
            ..Default::default()
        },
        None,
    )
    .unwrap()
}
fn source(path: &Path, count: u8) -> Vmm {
    std::fs::write(path.join("kernel"), [0; 64]).unwrap();
    let mut vm = Vmm::new_resume(config(path, count)).unwrap();
    // Two register writes and WFI establish an interrupted device transaction.
    // The unread page is consumed only after restore, following explicit wake.
    let words = [
        0xe5810000u32,
        0xe5812030,
        0xe320f003,
        0xe581300c,
        0xe5914080,
        0xe320f003,
    ];
    let bytes = words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    vm.guest_mem
        .memory()
        .write_slice(&bytes, GuestAddress(CODE as u64))
        .unwrap();
    vm.guest_mem
        .memory()
        .write_slice(&0xe1a00000u32.to_le_bytes(), GuestAddress(0x18005064))
        .unwrap();
    for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
        let CpuState::Aarch32(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.r[0] = 2;
        state.regs.r[1] = 0x38a00000;
        state.regs.r[2] = 2047;
        state.regs.r[3] = 2 << 16;
        state.regs.fpscr = 0x0040001f;
        state.regs.d_high[15] = 0x0123456789abcdef ^ id as u64;
        cpu.set_state(&CpuState::Aarch32(state)).unwrap();
    }
    // These are prepared logical contexts. Architectural S5L AP startup remains
    // unsupported and the separate cold-policy tests still require CPU0 only.
    vm.coordinator.online.fill(true);
    for id in 0..usize::from(count) {
        let turn = vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
        assert_eq!(vm.vcpus[id].instruction_count(), 3);
    }
    assert_eq!(vm.coordinator.retired, 3 * u64::from(count));
    vm
}
#[test]
fn actual_s5l_files_restore_unread_nand_fp_uart_and_prepared_scheduler_without_source_files() {
    const LABEL: &str =
        "actual_s5l_files_restore_unread_nand_fp_uart_and_prepared_scheduler_without_source_files";
    if !selected(LABEL) {
        let dir = Directory::new();
        std::fs::create_dir_all(dir.0.join("nand/bank0")).unwrap();
        std::fs::write(dir.0.join("nand/bank0/2.page"), 0xaabbccddu32.to_le_bytes()).unwrap();
        child(LABEL, &dir.0, "source", true);
        std::fs::remove_dir_all(dir.0.join("nand")).unwrap();
        std::fs::remove_file(dir.0.join("kernel")).unwrap();
        child(LABEL, &dir.0, "restore", false);
        return;
    }
    let path = root();
    let phase = std::env::var("RAX_S5L_CONTEXT_PHASE").unwrap();
    for count in [1u8, 2, 4] {
        let file = path.join(format!("{count}.raxcp"));
        if phase == "source" {
            let vm = source(&path, count);
            let uart = vm.vcpus[0].checkpoint_owned_s3c_uarts()[0].clone();
            uart.lock().unwrap().queue_input(b"saved-uart");
            vm.take_snapshot_bundle(3 * u64::from(count))
                .unwrap()
                .save(&file)
                .unwrap();
        } else {
            let bundle = SnapshotBundle::load(&file).unwrap();
            let mut vm = Vmm::new_resume_bundle(
                VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap(),
                &bundle,
            )
            .unwrap();
            assert_eq!(vm.coordinator.retired, 3 * u64::from(count));
            assert_eq!(vm.coordinator.online, vec![true; usize::from(count)]);
            let first = vm.vcpus[0].checkpoint_owned_s3c_uarts()[0].clone();
            let uart_image = crate::codec::serialize(&*first.lock().unwrap()).unwrap();
            assert!(uart_image.windows(10).any(|b| b == b"saved-uart"));
            for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
                assert_eq!(
                    cpu.required_private_checkpoint_kind(),
                    Some(crate::vm::snapshot::S5L8900_CONTEXT)
                );
                let CpuState::Aarch32(state) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(state.regs.fpscr, 0x0040001f);
                assert_eq!(state.regs.d_high[15], 0x0123456789abcdef ^ id as u64);
                assert_eq!(state.regs.pc, CODE + 12);
                assert!(Arc::ptr_eq(&first, &cpu.checkpoint_owned_s3c_uarts()[0]));
                cpu.wake();
            }
            for id in 0..usize::from(count) {
                let turn = vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let CpuState::Aarch32(state) = vm.vcpus[id].get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(state.regs.r[4], 0xaabbccdd);
                assert_eq!(vm.vcpus[id].instruction_count(), 6);
            }
            assert_eq!(vm.coordinator.retired, 6 * u64::from(count));
            // Snapshot policy wins over the destination's NO_SECURITY_SEED switch.
            let CpuState::Aarch32(mut state) = vm.vcpus[0].get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = 0x18005064;
            state.regs.r[0] = 1;
            vm.vcpus[0].set_state(&CpuState::Aarch32(state)).unwrap();
            vm.vcpus[0].wake();
            assert!(vm.vcpus[0].step_insn().unwrap().is_none());
            let flags = vm
                .guest_mem
                .memory()
                .read_obj::<u32>(GuestAddress(0x18022fa0))
                .unwrap();
            assert_ne!(flags & 16, 0);
        }
    }
}
#[test]
fn final_s5l_record_failure_preserves_all_targets_uart_and_ram() {
    const LABEL: &str = "final_s5l_record_failure_preserves_all_targets_uart_and_ram";
    if !selected(LABEL) {
        let dir = Directory::new();
        std::fs::create_dir(dir.0.join("nand")).unwrap();
        child(LABEL, &dir.0, "once", true);
        return;
    }
    let path = root();
    let vm = source(&path, 4);
    let bundle = vm.take_snapshot_bundle(12).unwrap();
    let mut target = Vmm::new_resume_bundle(
        VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap(),
        &bundle,
    )
    .unwrap();
    let mut rows = bundle.backend_contexts().unwrap().entries().to_vec();
    let last = rows.last_mut().unwrap().as_mut().unwrap();
    // Keep descriptor identity/reference admission valid. Corrupt only the
    // final state resource, so preceding detached candidates can be prepared.
    let (id, old_state, nand): (
        u32,
        crate::vm::snapshot::ResourceKey,
        crate::vm::snapshot::ResourceKey,
    ) = crate::codec::deserialize_strict(&last.data[8..]).unwrap();
    let bad = crate::vm::snapshot::CheckpointResource::s5l_state(b"RAXSLI01?".to_vec()).unwrap();
    let header = last.data[..8].to_vec();
    last.data = header;
    last.data
        .extend_from_slice(&crate::codec::serialize(&(id, bad.key(), nand)).unwrap());
    let resources = bundle.resources().unwrap().prepare().unwrap();
    let mut bindings = Vec::new();
    for key in resources.keys().filter(|key| *key != old_state) {
        let bytes = resources.resolve(key).unwrap();
        bindings.push(match key.kind() {
            crate::vm::snapshot::S5L_STATE_RESOURCE => {
                crate::vm::snapshot::CheckpointResource::s5l_state(bytes.as_ref().clone()).unwrap()
            }
            crate::vm::snapshot::S5L_NAND_RESOURCE => {
                crate::vm::snapshot::CheckpointResource::s5l_nand(bytes.as_ref().clone()).unwrap()
            }
            kind => panic!("unexpected S5L resource {kind}"),
        });
    }
    bindings.push(bad);
    let malformed = bundle
        .with_backend_contexts(rows)
        .unwrap()
        .with_resources(bindings)
        .unwrap();
    let mut before = Vec::new();
    for (id, cpu) in target.vcpus.iter_mut().enumerate() {
        let CpuState::Aarch32(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.r[7] = id as u32 + 99;
        cpu.set_state(&CpuState::Aarch32(state)).unwrap();
        before.push(crate::codec::serialize(&cpu.get_state().unwrap()).unwrap());
    }
    let owner = target.vcpus[0].checkpoint_owned_s3c_uarts()[0].clone();
    owner.lock().unwrap().queue_input(b"target-only");
    let uart_before = crate::codec::serialize(&*owner.lock().unwrap()).unwrap();
    target
        .guest_mem
        .memory()
        .write_obj(0x12345678u32, GuestAddress(0x4000))
        .unwrap();
    let error = target
        .restore_snapshot_bundle(&malformed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("S5L checkpoint"), "{error}");
    for (cpu, state) in target.vcpus.iter().zip(before) {
        assert_eq!(
            crate::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
            state
        );
    }
    assert_eq!(
        target
            .guest_mem
            .memory()
            .read_obj::<u32>(GuestAddress(0x4000))
            .unwrap(),
        0x12345678
    );
    assert_eq!(
        crate::codec::serialize(&*owner.lock().unwrap()).unwrap(),
        uart_before
    );
}

struct CaptureOrder {
    cpu: Box<dyn VCpu>,
    prepared: Arc<AtomicU64>,
    captured: Arc<AtomicU64>,
}
impl VCpu for CaptureOrder {
    fn run(&mut self) -> Result<VcpuExit> {
        self.cpu.run()
    }
    fn get_state(&self) -> Result<CpuState> {
        self.cpu.get_state()
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.cpu.set_state(state)
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        self.cpu.complete_io_in(data)
    }
    fn id(&self) -> u32 {
        self.cpu.id()
    }
    fn instruction_count(&self) -> u64 {
        self.cpu.instruction_count()
    }
    fn checkpoint_owned_s3c_uarts(
        &self,
    ) -> Vec<Arc<std::sync::Mutex<crate::devices::s3c64xx::S3cUart>>> {
        self.cpu.checkpoint_owned_s3c_uarts()
    }
    fn prepare_checkpoint_capture(
        &self,
    ) -> Result<Option<crate::vm::vcpu::PreparedCheckpointCapture>> {
        for uart in self.cpu.checkpoint_owned_s3c_uarts() {
            assert!(
                uart.try_lock().is_ok(),
                "source media preparation held shared UART"
            );
        }
        let prepared = self.cpu.prepare_checkpoint_capture()?;
        assert!(prepared.is_some());
        self.prepared.fetch_add(1, Ordering::Relaxed);
        Ok(prepared)
    }
    fn capture_prepared_checkpoint_record(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        scope: Option<&crate::vm::memory::checkpoint::CheckpointPublication<'_>>,
        prepared: Option<&crate::vm::vcpu::PreparedCheckpointCapture>,
    ) -> Result<(
        crate::vm::snapshot::CpuSnapshot,
        Option<crate::vm::snapshot::BackendContext>,
        Vec<crate::vm::snapshot::CheckpointResource>,
    )> {
        assert!(scope.is_some());
        for uart in self.cpu.checkpoint_owned_s3c_uarts() {
            assert!(matches!(
                uart.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
        }
        self.captured.fetch_add(1, Ordering::Relaxed);
        self.cpu
            .capture_prepared_checkpoint_record(boundary, scope, prepared)
    }
}
#[test]
fn actual_vmm_prepares_all_source_media_before_shared_uart_scope() {
    const LABEL: &str = "actual_vmm_prepares_all_source_media_before_shared_uart_scope";
    if !selected(LABEL) {
        let dir = Directory::new();
        std::fs::create_dir(dir.0.join("nand")).unwrap();
        child(LABEL, &dir.0, "once", true);
        return;
    }
    let mut vm = source(&root(), 4);
    let prepared = Arc::new(AtomicU64::new(0));
    let captured = Arc::new(AtomicU64::new(0));
    vm.vcpus = std::mem::take(&mut vm.vcpus)
        .into_iter()
        .map(|cpu| {
            Box::new(CaptureOrder {
                cpu,
                prepared: prepared.clone(),
                captured: captured.clone(),
            }) as Box<dyn VCpu>
        })
        .collect();
    vm.take_snapshot_bundle(12).unwrap();
    assert_eq!(prepared.load(Ordering::Relaxed), 4);
    assert_eq!(captured.load(Ordering::Relaxed), 4);
}

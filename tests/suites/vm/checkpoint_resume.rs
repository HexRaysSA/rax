//! Typed file resume, missing sources, allocated geometry and actual CLI execution.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::devices::{lapic::LocalApic, pic::DualPic, pit::Pit, serial::Serial16550};
use rax::vm::memory::vm::{Bytes, GuestAddress};
use rax::vm::runtime::Vmm;
use rax::vm::snapshot::{DeviceState, EmulatorState, Snapshot, SnapshotBundle};
use rax::vm::vcpu::state::CpuState;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
const RAM: u64 = 128 * 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    kernel: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temporary = option_env!("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        std::fs::create_dir_all(&temporary).unwrap();
        let dir = temporary.join(format!(
            "rax-file-resume-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let kernel = dir.join("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        Self { dir, kernel }
    }
    fn config(&self, arch: ArchKind, bytes: u64) -> VmConfig {
        VmConfig::from_sources(
            CliConfig {
                arch: Some(arch),
                backend: Some(BackendKind::Emulator),
                memory: Some(MemorySize(bytes)),
                kernel: Some(self.kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap()
    }
    fn base(&self) -> Snapshot {
        Snapshot::new(
            self.config(ArchKind::X86_64, RAM).to_checkpoint(),
            53,
            97,
            CpuState::x86_64(Default::default(), Default::default()),
            EmulatorState::default(),
            DeviceState {
                pic: DualPic::new(),
                pit: Pit::new(),
                serial: Serial16550::new(0x3f8),
                lapic: LocalApic::new(0),
            },
            &vec![0; RAM as usize],
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "retaining owned failed resume fixture:{}",
                self.dir.display()
            );
        } else {
            std::fs::remove_dir_all(&self.dir).unwrap();
        }
    }
}
#[test]
fn typed_base_config_keeps_original_resolution_and_missing_path_support() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base());
    std::fs::remove_file(&f.kernel).unwrap();
    let old =
        VmConfig::from_checkpoint(b.base().config.clone(), CliConfig::default(), RAM).unwrap();
    let new = VmConfig::from_checkpoint_bundle(&b, CliConfig::default()).unwrap();
    assert_eq!(
        rax::codec::serialize(&old.to_checkpoint()).unwrap(),
        rax::codec::serialize(&new.to_checkpoint()).unwrap()
    );
}
#[test]
fn typed_config_applies_existing_cli_precedence() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base());
    let c = VmConfig::from_checkpoint_bundle(
        &b,
        CliConfig {
            memory: Some(MemorySize(RAM + 4096)),
            vcpus: Some(2),
            cmdline: Some("override".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(c.memory.bytes(), RAM + 4096);
    assert_eq!(c.vcpus, 2);
    assert_eq!(c.cmdline, "override");
    assert!(c.validate_resume_bundle(&b).is_err());
}
#[test]
fn unsupported_version_rejects_before_trace_creation() {
    let f = Fixture::new();
    let mut base = f.base();
    base.version = 7;
    let b = SnapshotBundle::new(base);
    let mut c = f.config(ArchKind::X86_64, RAM);
    let trace = f.dir.join("unexpected.trace");
    c.trace = Some(trace.clone());
    let error = Vmm::new_resume_bundle(c, &b).err().unwrap();
    assert!(error.to_string().contains("Unsupported checkpoint version"));
    assert!(!trace.exists());
}
#[test]
fn incompatible_extent_rejects_before_runtime_trace_side_effects() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base());
    let mut c = f.config(ArchKind::X86_64, RAM + 4096);
    let trace = f.dir.join("unexpected.trace");
    c.trace = Some(trace.clone());
    let error = Vmm::new_resume_bundle(c, &b).err().unwrap();
    assert!(error.to_string().contains("RAM extent"));
    assert!(!trace.exists());
}
#[test]
fn incompatible_cpu_count_rejects_before_runtime_trace_side_effects() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base());
    let mut c = f.config(ArchKind::X86_64, RAM);
    c.vcpus = 2;
    let trace = f.dir.join("unexpected.trace");
    c.trace = Some(trace.clone());
    assert!(
        Vmm::new_resume_bundle(c, &b)
            .err()
            .unwrap()
            .to_string()
            .contains("CPU count")
    );
    assert!(!trace.exists());
}
#[test]
fn incompatible_architecture_rejects_before_runtime_creation() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base());
    let c = f.config(ArchKind::Riscv64, RAM);
    assert!(
        Vmm::new_resume_bundle(c, &b)
            .err()
            .unwrap()
            .to_string()
            .contains("architecture")
    );
}
#[test]
fn incompatible_pci_topology_rejects_before_runtime_creation() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base());
    let mut c = f.config(ArchKind::X86_64, RAM);
    c.pci_devices = true;
    assert!(
        Vmm::new_resume_bundle(c, &b)
            .err()
            .unwrap()
            .to_string()
            .contains("PCI topology")
    );
}
#[test]
fn page_rounded_request_captures_consistent_base_geometry_and_last_byte() {
    let f = Fixture::new();
    let vm = Vmm::new_resume(f.config(ArchKind::X86_64, RAM + 1)).unwrap();
    let actual = vm.guest_mem().size();
    assert_eq!(actual, RAM + 4096);
    vm.guest_mem()
        .memory()
        .write_slice(&[0xab], GuestAddress(actual - 1))
        .unwrap();
    let b = vm.take_snapshot(53).unwrap();
    assert_eq!(b.config.memory_bytes, actual);
    assert_eq!(b.memory_size, actual);
    assert_eq!(b.decompress_memory().unwrap().last(), Some(&0xab));
}
#[test]
fn typed_base_constructor_restores_without_kernel_file() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base());
    std::fs::remove_file(&f.kernel).unwrap();
    let c = VmConfig::from_checkpoint_bundle(&b, CliConfig::default()).unwrap();
    let vm = Vmm::new_resume_bundle(c, &b).unwrap();
    assert_eq!(vm.guest_mem().size(), RAM);
    assert_eq!(
        vm.guest_mem().try_read_all().unwrap(),
        vec![0; RAM as usize]
    );
}
/// Capture before guest execution. The CLI consumer must supply execution proof.
pub fn emit_reference(out: &Path) {
    let f = Fixture::new();
    std::fs::write(
        &f.kernel,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/checkpoint/resume-riscv.elf"
        )),
    )
    .unwrap();
    let mut c = f.config(ArchKind::Riscv64, RAM + 1);
    c.snapshot_out = Some(out.join("console.rxc"));
    let vm = Vmm::new(c).unwrap();
    let actual = vm.guest_mem().size();
    vm.console_checkpoint();
    let bundle = SnapshotBundle::load(out.join("console.rxc")).unwrap();
    assert_eq!(bundle.base().config.memory_bytes, actual);
    assert_eq!(bundle.base().memory_size, actual);
    assert_eq!(
        bundle.physical_memory().unwrap().total_bytes(),
        actual + 4 * 1024 * 1024 * 1024
    );
    std::fs::write(
        out.join("kernel-path.txt"),
        f.kernel.to_string_lossy().as_bytes(),
    )
    .unwrap();
    drop(vm);
    std::fs::remove_file(&f.kernel).unwrap();
    assert!(!bundle.base().config.kernel.exists());
    println!(
        "{}\t{}\t{}",
        RAM + 1,
        actual,
        bundle.physical_memory().unwrap().total_bytes()
    );
}
#[cfg(test)]
fn run_cli(file: &Path, out: &Path) {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let stdout = out.join("cli.stdout");
    let stderr = out.join("cli.stderr");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rax"))
        .args(["--checkpoint"])
        .arg(file)
        .args(["--backend", "emulator"])
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= end {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!(
                "owned resume CLI exceeded120s;stdout/stderr retained at{}",
                out.display()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut bytes = std::fs::read(stdout).unwrap();
    bytes.extend_from_slice(&std::fs::read(stderr).unwrap());
    let text = String::from_utf8_lossy(&bytes);
    assert!(status.success(), "{status}: {text}");
    assert!(
        text.matches("RAX\n").count() == 1,
        "missing or duplicated actual guest UART marker:{text}"
    );
    assert!(
        text.contains("vCPU shutdown"),
        "missing actual guest shutdown event:{text}"
    );
}
#[test]
fn console_file_resumes_missing_high_elf_kernel_and_executes_uart_shutdown() {
    let f = Fixture::new();
    emit_reference(&f.dir);
    run_cli(&f.dir.join("console.rxc"), &f.dir);
}

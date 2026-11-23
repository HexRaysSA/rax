//! Exercise the public config capture/serialization/resume boundary.
use rax::config::{ArchKind, BackendKind, CliConfig, VmConfig};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
struct Kernel(std::path::PathBuf);
impl Kernel {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rax-checkpoint-config-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, [0u8; 64]).unwrap();
        Self(path)
    }
}
impl Drop for Kernel {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[test]
fn optional_pci_topology_survives_capture_binary_metadata_and_default_resume() {
    let kernel = Kernel::new();
    for enabled in [false, true] {
        let initial = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel.0.clone()),
                pci_devices: enabled,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let bytes = rax::codec::serialize(&initial.to_checkpoint()).unwrap();
        let metadata = rax::codec::deserialize(&bytes).unwrap();
        let restored =
            VmConfig::from_checkpoint(metadata, CliConfig::default(), initial.memory.bytes())
                .unwrap();
        assert_eq!(restored.pci_devices, enabled);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn intel_hvf_parallel_scheduling_is_selected_locally_on_boot_and_resume() {
    use rax::config::FileConfig;

    let kernel = Kernel::new();
    let cli = CliConfig {
        arch: Some(ArchKind::X86_64),
        backend: Some(BackendKind::Hvf),
        kernel: Some(kernel.0.clone()),
        vcpus: Some(4),
        ..Default::default()
    };
    let file = FileConfig {
        hvf_parallel_vcpus: Some(true),
        ..Default::default()
    };
    let serial = VmConfig::from_sources(cli.clone(), None).unwrap();
    let parallel = VmConfig::from_sources(cli.clone(), Some(file.clone())).unwrap();
    assert!(!serial.hvf_parallel_vcpus);
    assert!(parallel.hvf_parallel_vcpus);
    let overridden = VmConfig::from_sources(
        CliConfig {
            hvf_parallel_vcpus: Some(false),
            ..cli
        },
        Some(file),
    )
    .unwrap();
    assert!(!overridden.hvf_parallel_vcpus);
    let stopped = parallel.to_checkpoint();
    assert_eq!(
        rax::codec::serialize(&stopped).unwrap(),
        rax::codec::serialize(&serial.to_checkpoint()).unwrap()
    );
    for enabled in [None, Some(true)] {
        let resumed = VmConfig::from_checkpoint(
            stopped.clone(),
            CliConfig {
                hvf_parallel_vcpus: enabled,
                ..Default::default()
            },
            parallel.memory.bytes(),
        )
        .unwrap();
        assert_eq!(resumed.hvf_parallel_vcpus, enabled.unwrap_or(false));
    }
}

#[test]
fn intel_hvf_parallel_scheduling_rejects_other_backends_and_architectures() {
    let kernel = Kernel::new();
    for (arch, backend) in [
        (ArchKind::X86_64, BackendKind::Emulator),
        (ArchKind::X86_64, BackendKind::Kvm),
        (ArchKind::Aarch64, BackendKind::Hvf),
    ] {
        let error = VmConfig::from_sources(
            CliConfig {
                arch: Some(arch),
                backend: Some(backend),
                kernel: Some(kernel.0.clone()),
                hvf_parallel_vcpus: Some(true),
                ..Default::default()
            },
            None,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("parallel HVF vCPUs require the Intel HVF backend")
        );
    }
}

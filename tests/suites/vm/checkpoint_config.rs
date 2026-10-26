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
        let bytes = bincode::serialize(&initial.to_checkpoint()).unwrap();
        let metadata = bincode::deserialize(&bytes).unwrap();
        let restored =
            VmConfig::from_checkpoint(metadata, CliConfig::default(), initial.memory.bytes())
                .unwrap();
        assert_eq!(restored.pci_devices, enabled);
    }
}

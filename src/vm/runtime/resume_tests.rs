//! Source-independent constructor must restore actual typed media for all modes.
use super::*;
use crate::config::{CliConfig, ImageAccess, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Files(PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "retaining failed detached constructor fixture:{}",
                self.0.display()
            );
        } else {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
#[test]
fn detached_constructor_preserves_all_image_modes_and_never_reopens_original_paths() {
    for mode in [
        ImageAccess::ReadOnly,
        ImageAccess::ReadWrite,
        ImageAccess::CopyOnWrite,
    ] {
        let dir = std::env::temp_dir().join(format!(
            "rax-detached-resume-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let files = Files(dir);
        let kernel = files.0.join("kernel");
        let n = files.0.join("n.raw");
        let a = files.0.join("a.raw");
        std::fs::write(&kernel, [0; 64]).unwrap();
        std::fs::write(&n, vec![0xa3; 16384]).unwrap();
        std::fs::write(&a, vec![0xb9; 16384]).unwrap();
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                memory: Some(MemorySize(128 * 1024 * 1024)),
                kernel: Some(kernel.clone()),
                pci_devices: true,
                nvme_image: Some(n.clone()),
                nvme_image_mode: Some(mode),
                ahci_image: Some(a.clone()),
                ahci_image_mode: Some(ImageAccess::ReadOnly),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let source = Vmm::new_resume(config).unwrap();
        let mut cp = source.pci_devices.as_ref().unwrap().checkpoint().unwrap();
        cp.bridge.state[8..12].copy_from_slice(&0x80000010u32.to_le_bytes());
        if mode != ImageAccess::ReadOnly {
            for (i, b) in cp
                .endpoints
                .as_mut()
                .unwrap()
                .nvme
                .media
                .bytes
                .iter_mut()
                .enumerate()
            {
                *b = (i as u8).wrapping_mul(17) ^ 0x5a;
            }
        }
        let base = Snapshot::new(
            source.checkpoint_config.clone(),
            53,
            97,
            source.vcpus[0].get_state().unwrap(),
            source.vcpus[0].get_emulator_state().unwrap(),
            source.capture_devices().unwrap(),
            &vec![0x33; 128 * 1024 * 1024],
        )
        .unwrap();
        let bundle = SnapshotBundle::new(base).with_pci(cp.clone()).unwrap();
        drop(source);
        std::fs::remove_file(kernel).unwrap();
        std::fs::rename(&n, files.0.join("n.moved")).unwrap();
        std::fs::rename(&a, files.0.join("a.moved")).unwrap();
        assert!(
            VmConfig::from_checkpoint(
                bundle.base().config.clone(),
                CliConfig::default(),
                bundle.base().memory_size
            )
            .is_err()
        );
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        config.validate_resume_bundle(&bundle).unwrap();
        assert!(config.validate_resume().is_err());
        let target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        assert_eq!(
            target.pci_devices.as_ref().unwrap().checkpoint().unwrap(),
            cp
        );
        assert_eq!(
            target.guest_mem.try_read_all().unwrap(),
            vec![0x33; 128 * 1024 * 1024]
        );
        assert_eq!(
            std::fs::read(files.0.join("n.moved")).unwrap(),
            vec![0xa3; 16384]
        );
        assert_eq!(
            std::fs::read(files.0.join("a.moved")).unwrap(),
            vec![0xb9; 16384]
        );
        assert!(!n.exists() && !a.exists());
    }
}

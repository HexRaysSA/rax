//! Configuration source precedence, strong image identity and v8 migration.
use rax::config::storage::{DEFAULT_IMAGE_BYTES, FileImageConfig, FileStorageConfig};
use rax::config::{
    ArchKind, BackendKind, CliConfig, FileConfig, ImageAccess, ImageAttachment, MemorySize,
    StorageConfig, VmConfig,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    kernel: PathBuf,
    image: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-image-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let kernel = directory.join("kernel");
        let image = directory.join("image.raw");
        std::fs::write(&kernel, [0; 64]).unwrap();
        std::fs::write(
            &image,
            (0..16384)
                .map(|i| ((i * 37) ^ (i >> 9)) as u8)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        Self {
            directory,
            kernel,
            image,
        }
    }
    fn cli(&self) -> CliConfig {
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            kernel: Some(self.kernel.clone()),
            ..Default::default()
        }
    }
    fn file(&self, mode: Option<ImageAccess>, limit: Option<MemorySize>) -> FileConfig {
        FileConfig {
            storage: Some(FileStorageConfig {
                nvme: Some(FileImageConfig {
                    path: self.image.clone(),
                    mode,
                    max_bytes: limit,
                }),
                ahci: None,
            }),
            ..Default::default()
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
#[test]
fn absent_images_preserve_default_machine_and_checkpoint_config() {
    let f = Fixture::new();
    let cfg = VmConfig::from_sources(f.cli(), None).unwrap();
    assert!(!cfg.pci_devices && !cfg.storage.has_images());
    let cp = cfg.to_checkpoint();
    assert_eq!(cp.storage, StorageConfig::default());
    VmConfig::from_checkpoint(cp, CliConfig::default(), cfg.memory.bytes()).unwrap();
}
#[test]
fn image_path_enables_pci_and_defaults_to_cow_with_bounded_identity() {
    let f = Fixture::new();
    let mut cli = f.cli();
    cli.nvme_image = Some(f.image.clone());
    let cfg = VmConfig::from_sources(cli, None).unwrap();
    assert!(cfg.pci_devices);
    let image = cfg.storage.nvme.unwrap();
    assert_eq!(image.path, f.image.canonicalize().unwrap());
    assert_eq!(image.mode, ImageAccess::CopyOnWrite);
    assert_eq!(image.max_bytes, DEFAULT_IMAGE_BYTES);
    assert_eq!(image.identity.bytes, 16384);
    assert_eq!(
        image.identity.sha256,
        [
            0x8d, 0xb8, 0xf2, 0x74, 0x94, 0x5b, 0x69, 0x59, 0xa1, 0xc7, 0xef, 0x87, 0x35, 0xf8,
            0x89, 0xdd, 0xec, 0xfc, 0xac, 0x55, 0x02, 0x5a, 0xe9, 0xc8, 0x12, 0x8f, 0x3f, 0xb8,
            0xa4, 0xc0, 0x83, 0xc5
        ]
    );
}
#[test]
fn cli_modes_budgets_and_paths_override_file_fields_independently() {
    let f = Fixture::new();
    let alternate = f.directory.join("alternate.raw");
    std::fs::write(&alternate, vec![0x93; 512]).unwrap();
    let mut cli = f.cli();
    cli.nvme_image = Some(alternate.clone());
    cli.nvme_image_mode = Some(ImageAccess::ReadOnly);
    cli.nvme_image_limit = Some(MemorySize(1024));
    let cfg = VmConfig::from_sources(
        cli,
        Some(f.file(Some(ImageAccess::ReadWrite), Some(MemorySize(32768)))),
    )
    .unwrap();
    let image = cfg.storage.nvme.unwrap();
    assert_eq!(image.path, alternate.canonicalize().unwrap());
    assert_eq!(image.mode, ImageAccess::ReadOnly);
    assert_eq!(image.max_bytes, 1024);
    assert_eq!(image.identity.bytes, 512);
}
#[test]
fn cli_mode_override_preserves_file_path_and_budget() {
    let f = Fixture::new();
    let mut cli = f.cli();
    cli.nvme_image_mode = Some(ImageAccess::ReadWrite);
    let cfg = VmConfig::from_sources(
        cli,
        Some(f.file(Some(ImageAccess::ReadOnly), Some(MemorySize(32768)))),
    )
    .unwrap();
    let image = cfg.storage.nvme.unwrap();
    assert_eq!(image.path, f.image.canonicalize().unwrap());
    assert_eq!(image.mode, ImageAccess::ReadWrite);
    assert_eq!(image.max_bytes, 32768);
}
#[test]
fn file_modes_and_budgets_override_defaults() {
    let f = Fixture::new();
    let cfg = VmConfig::from_sources(
        f.cli(),
        Some(f.file(Some(ImageAccess::ReadOnly), Some(MemorySize(65536)))),
    )
    .unwrap();
    let image = cfg.storage.nvme.unwrap();
    assert_eq!(image.mode, ImageAccess::ReadOnly);
    assert_eq!(image.max_bytes, 65536);
}
#[test]
fn explicit_disabled_pci_conflicts_with_images_but_cli_enable_wins() {
    let f = Fixture::new();
    let mut file = f.file(None, None);
    file.pci_devices = Some(false);
    assert!(VmConfig::from_sources(f.cli(), Some(file.clone())).is_err());
    let mut cli = f.cli();
    cli.pci_devices = true;
    VmConfig::from_sources(cli, Some(file)).unwrap();
}
#[test]
fn both_controller_images_resolve_and_capture_distinct_metadata() {
    let f = Fixture::new();
    let second = f.directory.join("second.raw");
    std::fs::write(&second, vec![0x87; 512]).unwrap();
    let mut cli = f.cli();
    cli.nvme_image = Some(f.image.clone());
    cli.ahci_image = Some(second);
    cli.ahci_image_mode = Some(ImageAccess::ReadWrite);
    let cfg = VmConfig::from_sources(cli, None).unwrap();
    assert_eq!(cfg.storage.nvme.unwrap().identity.bytes, 16384);
    let image = cfg.storage.ahci.unwrap();
    assert_eq!(image.mode, ImageAccess::ReadWrite);
    assert_eq!(image.identity.bytes, 512);
}
#[test]
fn mode_or_budget_without_path_is_rejected() {
    let f = Fixture::new();
    let mut cli = f.cli();
    cli.nvme_image_mode = Some(ImageAccess::ReadOnly);
    assert!(VmConfig::from_sources(cli, None).is_err());
    let mut cli = f.cli();
    cli.ahci_image_limit = Some(MemorySize(16384));
    assert!(VmConfig::from_sources(cli, None).is_err());
}
#[test]
fn non_x86_images_are_rejected_before_machine_execution() {
    let f = Fixture::new();
    for arch in [ArchKind::Aarch64, ArchKind::Armv7a, ArchKind::Riscv64] {
        let mut cli = f.cli();
        cli.arch = Some(arch);
        cli.nvme_image = Some(f.image.clone());
        assert!(VmConfig::from_sources(cli, None).is_err());
    }
}
#[test]
fn malformed_image_and_budget_are_rejected_without_source_effects() {
    let f = Fixture::new();
    for bytes in [0, 511, 513] {
        std::fs::write(&f.image, vec![0x27; bytes]).unwrap();
        let mut cli = f.cli();
        cli.nvme_image = Some(f.image.clone());
        assert!(VmConfig::from_sources(cli, None).is_err());
        assert_eq!(std::fs::read(&f.image).unwrap(), vec![0x27; bytes]);
    }
    assert!(ImageAttachment::capture(&f.image, ImageAccess::CopyOnWrite, 0).is_err());
}
#[test]
fn same_size_content_replacement_is_detected_before_writable_attachment() {
    let f = Fixture::new();
    let image = ImageAttachment::capture(&f.image, ImageAccess::ReadWrite, 16384).unwrap();
    let replacement = vec![0x81; 16384];
    std::fs::write(&f.image, &replacement).unwrap();
    assert!(image.open().is_err());
    assert_eq!(std::fs::read(&f.image).unwrap(), replacement);
}
#[test]
fn image_capacity_change_and_metadata_budget_corruption_are_rejected() {
    let f = Fixture::new();
    let mut image = ImageAttachment::capture(&f.image, ImageAccess::CopyOnWrite, 16384).unwrap();
    image.max_bytes = 512;
    assert!(image.validate_metadata().is_err());
    image.max_bytes = 16384;
    std::fs::write(&f.image, vec![0x12; 512]).unwrap();
    assert!(image.open().is_err());
}
#[test]
fn unchanged_identity_opens_the_selected_media_mode() {
    let f = Fixture::new();
    for mode in [
        ImageAccess::ReadOnly,
        ImageAccess::ReadWrite,
        ImageAccess::CopyOnWrite,
    ] {
        let image = ImageAttachment::capture(&f.image, mode, 16384).unwrap();
        let medium = image.open().unwrap();
        assert_eq!(medium.mode(), mode.into());
        assert_eq!(medium.len(), 16384);
    }
}
#[test]
fn config_file_resolves_image_paths_relative_to_its_directory() {
    let f = Fixture::new();
    let config = f.directory.join("machine.toml");
    std::fs::write(
        &config,
        "[storage.nvme]\npath='image.raw'\nmode='read_only'\nmax_bytes='32KiB'\n",
    )
    .unwrap();
    let file = FileConfig::load(&config).unwrap();
    let cfg = VmConfig::from_sources(f.cli(), Some(file)).unwrap();
    let image = cfg.storage.nvme.unwrap();
    assert_eq!(image.path, f.image.canonicalize().unwrap());
    assert_eq!(image.mode, ImageAccess::ReadOnly);
    assert_eq!(image.max_bytes, 32768);
}
#[test]
fn unknown_storage_fields_do_not_silently_fall_back_to_defaults() {
    let f = Fixture::new();
    let config = f.directory.join("bad.toml");
    for text in [
        "[storage.nvme]\npath='image.raw'\nmod='read_write'\n",
        "[storage]\nunrecognized={}\n",
    ] {
        std::fs::write(&config, text).unwrap();
        assert!(FileConfig::load(&config).is_err());
    }
}
#[test]
fn image_metadata_survives_binary_config_capture_without_reopening_source() {
    let f = Fixture::new();
    let mut cli = f.cli();
    cli.nvme_image = Some(f.image.clone());
    let config = VmConfig::from_sources(cli, None).unwrap();
    let cp = config.to_checkpoint();
    let raw = rax::codec::serialize(&cp).unwrap();
    let decoded: rax::config::CheckpointConfig = rax::codec::deserialize(&raw).unwrap();
    assert_eq!(decoded.storage, cp.storage);
    std::fs::remove_file(&f.image).unwrap();
    assert_eq!(decoded.storage.nvme.unwrap().identity.bytes, 16384);
}
#[test]
fn image_backed_resume_is_rejected_until_media_state_is_captured() {
    let f = Fixture::new();
    let mut cli = f.cli();
    cli.nvme_image = Some(f.image.clone());
    let config = VmConfig::from_sources(cli, None).unwrap();
    let result = VmConfig::from_checkpoint(
        config.to_checkpoint(),
        CliConfig::default(),
        config.memory.bytes(),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("complete device/media state")
    );
}
#[test]
fn old_tagged_schema_one_fixture_retains_pci_and_defaults_to_no_images() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/checkpoint/tagged-v8-schema1.rxc");
    let snapshot = rax::vm::snapshot::Snapshot::load(path).unwrap();
    assert_eq!(snapshot.version, 8);
    assert!(snapshot.config.pci_devices);
    assert_eq!(snapshot.config.storage, StorageConfig::default());
    assert_eq!(snapshot.memory_size, 4096);
    assert_eq!(snapshot.decompress_memory().unwrap(), vec![0x31; 4096]);
}
#[test]
fn old_json_metadata_without_storage_defaults_to_empty_attachments() {
    let f = Fixture::new();
    let cp = VmConfig::from_sources(f.cli(), None)
        .unwrap()
        .to_checkpoint();
    let mut json = serde_json::to_value(cp).unwrap();
    json.as_object_mut().unwrap().remove("storage");
    let restored: rax::config::CheckpointConfig = serde_json::from_value(json).unwrap();
    assert_eq!(restored.storage, StorageConfig::default());
}

#[test]
fn checkpoint_cli_image_override_is_resolved_and_cannot_be_silently_ignored() {
    let f = Fixture::new();
    let cfg = VmConfig::from_sources(f.cli(), None).unwrap();
    let mut cli = CliConfig::default();
    cli.nvme_image = Some(f.image.clone());
    let result = VmConfig::from_checkpoint(cfg.to_checkpoint(), cli, cfg.memory.bytes());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("complete device/media state")
    );
}

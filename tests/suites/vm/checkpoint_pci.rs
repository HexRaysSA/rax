//! Public additive checkpoint bundle framing, bounds and source-independent media.
use rax::config::{
    ArchKind, BackendKind, CliConfig, ImageAccess, ImageAttachment, StorageConfig, VmConfig,
};
use rax::devices::{lapic::LocalApic, pic::DualPic, pit::Pit, serial::Serial16550};
use rax::vm::memory::vm::{GuestAddress, GuestMemoryMmap};
use rax::vm::runtime::pci_state::{PciDeviceCheckpoint, PciDevices};
use rax::vm::snapshot::{DeviceState, EmulatorState, Snapshot, SnapshotBundle};
use rax::vm::vcpu::state::CpuState;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
const RAM: usize = 0x20000;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Files {
    dir: PathBuf,
    kernel: PathBuf,
    n: PathBuf,
    a: PathBuf,
}
impl Files {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rax-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let kernel = dir.join("kernel");
        let n = dir.join("n.raw");
        let a = dir.join("a.raw");
        std::fs::write(&kernel, [0; 64]).unwrap();
        std::fs::write(&n, vec![0xa3; 16384]).unwrap();
        std::fs::write(&a, vec![0xb9; 16384]).unwrap();
        Self { dir, kernel, n, a }
    }
    fn config(&self, enabled: bool, mode: Option<ImageAccess>) -> rax::config::CheckpointConfig {
        let mut c = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.kernel.clone()),
                pci_devices: enabled,
                cmdline: Some("checkpoint-bundle-oracle".to_string()),
                ..Default::default()
            },
            None,
        )
        .unwrap()
        .to_checkpoint();
        c.memory_bytes = RAM as u64;
        if let Some(mode) = mode {
            c.storage = StorageConfig {
                nvme: Some(ImageAttachment::capture(&self.n, mode, 16384).unwrap()),
                ahci: Some(ImageAttachment::capture(&self.a, mode, 16384).unwrap()),
            };
        }
        c
    }
    fn base(&self, enabled: bool, mode: Option<ImageAccess>) -> Snapshot {
        Snapshot::new(
            self.config(enabled, mode),
            123456789,
            987654321,
            CpuState::x86_64(Default::default(), Default::default()),
            EmulatorState::default(),
            DeviceState {
                pic: DualPic::new(),
                pit: Pit::new(),
                serial: Serial16550::new(0x3f8),
                lapic: LocalApic::new(0),
            },
            &vec![0x6b; RAM],
        )
        .unwrap()
    }
    fn state(&self, enabled: bool, mode: Option<ImageAccess>) -> PciDeviceCheckpoint {
        let config = self.config(enabled, mode);
        let m = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap());
        let d = PciDevices::new(m, &config.storage, enabled).unwrap();
        let mut cp = d.checkpoint().unwrap();
        if mode.is_some_and(|mode| mode != ImageAccess::ReadOnly) {
            let e = cp.endpoints.as_mut().unwrap();
            for (i, b) in e.nvme.media.bytes.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(17) ^ 0x5a;
            }
            for (i, b) in e.ahci.media.bytes.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31) ^ 0xc3;
            }
        }
        cp
    }
    fn bundle(&self, enabled: bool, mode: Option<ImageAccess>) -> SnapshotBundle {
        SnapshotBundle::new(self.base(enabled, mode))
            .with_pci(self.state(enabled, mode))
            .unwrap()
    }
    fn raw(&self, b: &SnapshotBundle) -> Vec<u8> {
        let p = self.dir.join("input.rxc");
        b.save(&p).unwrap();
        std::fs::read(p).unwrap()
    }
    fn read(&self, raw: &[u8]) -> rax::Result<SnapshotBundle> {
        let p = self.dir.join("mutated.rxc");
        std::fs::write(&p, raw).unwrap();
        SnapshotBundle::load(p)
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}
#[derive(Clone)]
struct Section {
    kind: u32,
    schema: u32,
    data: Vec<u8>,
}
fn sections(raw: &[u8]) -> Vec<Section> {
    assert_eq!(&raw[..8], b"RAXCKPT\0");
    let count = u32::from_le_bytes(raw[16..20].try_into().unwrap());
    let mut at = 20;
    let mut result = Vec::new();
    for _ in 0..count {
        let kind = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let schema = u32::from_le_bytes(raw[at + 4..at + 8].try_into().unwrap());
        let length = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap()) as usize;
        result.push(Section {
            kind,
            schema,
            data: raw[at + 16..at + 16 + length].to_vec(),
        });
        at += 16 + length;
    }
    assert_eq!(at, raw.len());
    result
}
fn assemble(parts: &[Section]) -> Vec<u8> {
    let mut raw = b"RAXCKPT\0".to_vec();
    raw.extend_from_slice(&8u32.to_le_bytes());
    raw.extend_from_slice(b"RXS8");
    raw.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for p in parts {
        raw.extend_from_slice(&p.kind.to_le_bytes());
        raw.extend_from_slice(&p.schema.to_le_bytes());
        raw.extend_from_slice(&(p.data.len() as u64).to_le_bytes());
        raw.extend_from_slice(&p.data);
    }
    raw
}
fn control(parts: &mut [Section]) -> &mut Vec<u8> {
    &mut parts.iter_mut().find(|s| s.kind == 7).unwrap().data
}
fn media_header_offset(data: &[u8]) -> usize {
    let mut at = 9;
    for _ in 0..6 {
        let len = u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + len;
    }
    at
}
#[test]
fn base_public_structure_and_wire_remain_unchanged() {
    let f = Files::new();
    let b = f.base(false, None);
    let path = f.dir.join("base.rxc");
    b.save(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let b = SnapshotBundle::load(&path).unwrap();
    assert!(b.pci().is_none());
    b.save(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        sections(&before).iter().map(|s| s.kind).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        b.into_base().unwrap().decompress_memory().unwrap(),
        vec![0x6b; RAM]
    );
}
#[test]
fn bridge_only_bundle_has_one_extra_required_section() {
    let f = Files::new();
    let b = f.bundle(false, None);
    let raw = f.raw(&b);
    assert_eq!(
        sections(&raw).iter().map(|s| s.kind).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 7, 6]
    );
    let loaded = f.read(&raw).unwrap();
    assert!(!loaded.pci().unwrap().has_endpoints());
    assert_eq!(
        loaded.pci().unwrap().clone().into_devices().unwrap(),
        f.state(false, None)
    );
}
#[test]
fn empty_endpoints_require_two_explicit_empty_media_frames() {
    let f = Files::new();
    let raw = f.raw(&f.bundle(true, None));
    assert_eq!(
        sections(&raw).iter().map(|s| s.kind).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 7, 8, 9, 6]
    );
    let b = f.read(&raw).unwrap();
    assert_eq!(
        b.pci()
            .unwrap()
            .nvme_media()
            .unwrap()
            .decompress()
            .unwrap()
            .bytes,
        Vec::<u8>::new()
    );
    assert_eq!(
        b.pci()
            .unwrap()
            .ahci_media()
            .unwrap()
            .decompress()
            .unwrap()
            .bytes,
        Vec::<u8>::new()
    );
}
#[test]
fn writable_and_readonly_media_bytes_and_protection_roundtrip() {
    let f = Files::new();
    for mode in [
        ImageAccess::CopyOnWrite,
        ImageAccess::ReadWrite,
        ImageAccess::ReadOnly,
    ] {
        let state = f.state(true, Some(mode));
        let b = SnapshotBundle::new(f.base(true, Some(mode)))
            .with_pci(state.clone())
            .unwrap();
        let loaded = f.read(&f.raw(&b)).unwrap();
        assert_eq!(loaded.pci().unwrap().clone().into_devices().unwrap(), state);
    }
}
#[test]
fn bundle_remains_self_contained_after_all_input_files_disappear() {
    let f = Files::new();
    let state = f.state(true, Some(ImageAccess::CopyOnWrite));
    let b = SnapshotBundle::new(f.base(true, Some(ImageAccess::CopyOnWrite)))
        .with_pci(state.clone())
        .unwrap();
    let raw = f.raw(&b);
    for p in [&f.kernel, &f.n, &f.a] {
        std::fs::remove_file(p).unwrap();
    }
    let loaded = f.read(&raw).unwrap();
    assert_eq!(loaded.base().decompress_memory().unwrap(), vec![0x6b; RAM]);
    let cp = loaded.pci().unwrap().clone().into_devices().unwrap();
    assert_eq!(cp, state);
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap());
    let runtime = PciDevices::new(mem, &StorageConfig::default(), true).unwrap();
    runtime.restore_checkpoint(cp.clone()).unwrap();
    assert_eq!(runtime.checkpoint().unwrap(), cp);
}
#[test]
fn base_only_reader_never_discards_required_pci_state() {
    let f = Files::new();
    let path = f.dir.join("bundle.rxc");
    f.bundle(true, None).save(&path).unwrap();
    assert!(
        Snapshot::load(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("SnapshotBundle")
    );
    assert!(SnapshotBundle::load(path).unwrap().into_base().is_err());
}
#[test]
fn missing_and_duplicate_conditional_sections_are_rejected() {
    let f = Files::new();
    let parts = sections(&f.raw(&f.bundle(true, None)));
    for kind in [7, 8, 9] {
        let mut p = parts.clone();
        p.retain(|s| s.kind != kind);
        assert!(f.read(&assemble(&p)).is_err());
        let mut p = parts.clone();
        p.insert(6, p.iter().find(|s| s.kind == kind).unwrap().clone());
        assert!(f.read(&assemble(&p)).is_err());
    }
}
#[test]
fn media_before_control_and_control_after_ram_are_rejected() {
    let f = Files::new();
    let parts = sections(&f.raw(&f.bundle(true, None)));
    let mut p = parts.clone();
    p.swap(5, 6);
    assert!(f.read(&assemble(&p)).is_err());
    let mut p = parts;
    p.swap(5, 8);
    assert!(f.read(&assemble(&p)).is_err());
}
#[test]
fn extension_schemas_and_optional_aliases_are_rejected() {
    let f = Files::new();
    let parts = sections(&f.raw(&f.bundle(true, None)));
    for kind in [7, 8, 9] {
        for optional in [false, true] {
            let mut p = parts.clone();
            let s = p.iter_mut().find(|s| s.kind == kind).unwrap();
            if optional {
                s.kind |= 0x80000000;
            } else {
                s.schema = 2;
            }
            assert!(f.read(&assemble(&p)).is_err());
        }
    }
}
#[test]
fn every_control_prefix_and_trailing_byte_is_rejected() {
    let f = Files::new();
    let parts = sections(&f.raw(&f.bundle(true, None)));
    let length = parts.iter().find(|s| s.kind == 7).unwrap().data.len();
    for end in 0..length {
        let mut p = parts.clone();
        control(&mut p).truncate(end);
        assert!(f.read(&assemble(&p)).is_err(), "prefix {end}");
    }
    let mut p = parts;
    control(&mut p).push(0);
    assert!(f.read(&assemble(&p)).is_err());
}
#[test]
fn control_booleans_lengths_tags_and_runtime_profile_are_checked() {
    let f = Files::new();
    let parts = sections(&f.raw(&f.bundle(true, None)));
    let header = media_header_offset(&parts.iter().find(|s| s.kind == 7).unwrap().data);
    for (off, value) in [(7, b'2'), (8, 2), (13, b'X'), (13 + 12, 7), (header + 8, 2)] {
        let mut p = parts.clone();
        control(&mut p)[off] = value;
        assert!(f.read(&assemble(&p)).is_err());
    }
    let mut p = parts;
    control(&mut p)[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(f.read(&assemble(&p)).is_err());
}
#[test]
fn controller_media_headers_and_config_geometry_must_agree() {
    let f = Files::new();
    let mut cp = f.state(true, Some(ImageAccess::CopyOnWrite));
    cp.endpoints.as_mut().unwrap().nvme.media.bytes.pop();
    assert!(
        SnapshotBundle::new(f.base(true, Some(ImageAccess::CopyOnWrite)))
            .with_pci(cp)
            .is_err()
    );
    let mut cp = f.state(true, Some(ImageAccess::ReadOnly));
    let n = &mut cp.endpoints.as_mut().unwrap().nvme;
    n.media.read_only = false;
    n.state[24] = 0;
    assert!(
        SnapshotBundle::new(f.base(true, Some(ImageAccess::ReadOnly)))
            .with_pci(cp)
            .is_err()
    );
}
#[test]
fn aggregate_budget_boundary_is_checked_without_allocating_declared_ram() {
    let f = Files::new();
    let mut base = f.base(true, None);
    base.memory_size = 64 * 1024 * 1024 * 1024;
    base.config.memory_bytes = base.memory_size;
    assert!(
        SnapshotBundle::new(base)
            .with_pci(f.state(true, None))
            .is_ok()
    );
    let mut base = f.base(true, Some(ImageAccess::CopyOnWrite));
    base.memory_size = 64 * 1024 * 1024 * 1024;
    base.config.memory_bytes = base.memory_size;
    assert!(
        SnapshotBundle::new(base)
            .with_pci(f.state(true, Some(ImageAccess::CopyOnWrite)))
            .is_err()
    );
}
#[test]
fn compressed_media_corruption_short_long_and_digest_mismatch_fail_on_decode() {
    let f = Files::new();
    let parts = sections(&f.raw(&f.bundle(true, Some(ImageAccess::CopyOnWrite))));
    for replacement in [
        vec![0; 16],
        zstd::encode_all(&[0; 10][..], 3).unwrap(),
        zstd::encode_all(&vec![0; 16385][..], 3).unwrap(),
        zstd::encode_all(&vec![0; 16384][..], 3).unwrap(),
    ] {
        let mut p = parts.clone();
        p.iter_mut().find(|s| s.kind == 8).unwrap().data = replacement;
        let b = f.read(&assemble(&p)).unwrap();
        assert!(b.pci().unwrap().nvme_media().unwrap().decompress().is_err());
    }
    let mut p = parts;
    let c = control(&mut p);
    let header = media_header_offset(c);
    c[header + 9] ^= 1;
    let b = f.read(&assemble(&p)).unwrap();
    assert!(b.pci().unwrap().nvme_media().unwrap().decompress().is_err());
}
#[test]
fn truncated_media_and_huge_section_lengths_reject_before_allocation() {
    let f = Files::new();
    let raw = f.raw(&f.bundle(true, None));
    assert!(f.read(&raw[..raw.len() - 1]).is_err());
    let mut at = 20;
    for _ in 0..9 {
        let kind = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let length = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap()) as usize;
        if matches!(kind, 7 | 8 | 9) {
            let mut bad = raw.clone();
            bad[at + 8..at + 16].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(f.read(&bad).is_err());
        }
        at += 16 + length;
    }
}
#[test]
fn failed_bundle_save_preserves_existing_target_and_cleans_temporary() {
    let f = Files::new();
    let path = f.dir.join("published.rxc");
    std::fs::write(&path, b"preserve-existing").unwrap();
    let mut base = f.base(true, None);
    base.version = 7;
    let b = SnapshotBundle::new(base)
        .with_pci(f.state(true, None))
        .unwrap();
    assert!(b.save(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"preserve-existing");
    assert!(std::fs::read_dir(&f.dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}
#[test]
fn actual_prior_schema_one_fixture_loads_with_explicit_absent_pci() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/checkpoint/tagged-v8-schema1.rxc");
    let b = SnapshotBundle::load(&fixture).unwrap();
    assert!(b.pci().is_none());
    assert!(b.base().config.pci_devices);
    assert_eq!(b.base().decompress_memory().unwrap(), vec![0x31; 4096]);
}
#[test]
fn hostile_aggregate_media_headers_reject_before_payload_allocation() {
    let f = Files::new();
    let original = sections(&f.raw(&f.bundle(true, None)));
    for size in [64 * 1024 * 1024 * 1024, u64::MAX] {
        let mut parts = original.clone();
        let raw = control(&mut parts);
        let header = media_header_offset(raw);
        let mut at = 9;
        for _ in 0..3 {
            let length = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
            at += 4 + length;
        }
        // The next length-prefixed record is NVMe; update both independently
        // checked size headers so the aggregate bound is the failing rule.
        let nvme = at + 4;
        raw[nvme + 16..nvme + 24].copy_from_slice(&size.to_le_bytes());
        raw[header..header + 8].copy_from_slice(&size.to_le_bytes());
        let error = f.read(&assemble(&parts)).err().unwrap().to_string();
        assert!(
            error.contains("budget") || error.contains("aggregate"),
            "{error}"
        );
    }
}
#[test]
fn truncated_valid_zstd_media_frame_returns_decode_error() {
    let f = Files::new();
    let mut parts = sections(&f.raw(&f.bundle(true, Some(ImageAccess::CopyOnWrite))));
    let data = &mut parts.iter_mut().find(|s| s.kind == 8).unwrap().data;
    data.pop();
    let bundle = f.read(&assemble(&parts)).unwrap();
    assert!(
        bundle
            .pci()
            .unwrap()
            .nvme_media()
            .unwrap()
            .decompress()
            .is_err()
    );
}
/// Publish fixed base/bridge/endpoint/media fixtures through public APIs.
pub fn emit_reference(directory: &std::path::Path) {
    std::fs::create_dir_all(directory).unwrap();
    for index in 0..6 {
        let f = Files::new();
        let mode = match index {
            3 => Some(ImageAccess::CopyOnWrite),
            4 => Some(ImageAccess::ReadOnly),
            5 => Some(ImageAccess::ReadWrite),
            _ => None,
        };
        let enabled = index >= 2;
        let base = f.base(enabled, mode);
        let bundle = if index == 0 {
            SnapshotBundle::new(base)
        } else {
            SnapshotBundle::new(base)
                .with_pci(f.state(enabled, mode))
                .unwrap()
        };
        let path = directory.join(format!("case-{index}.rxc"));
        bundle.save(&path).unwrap();
        let loaded = SnapshotBundle::load(&path).unwrap();
        assert_eq!(loaded.base().decompress_memory().unwrap(), vec![0x6b; RAM]);
        if let Some(pci) = loaded.pci() {
            assert_eq!(pci.clone().into_devices().unwrap(), f.state(enabled, mode));
        }
    }
}
#[test]
fn base_reader_rejects_pci_header_before_any_extension_payload() {
    let f = Files::new();
    let raw = f.raw(&f.bundle(true, None));
    let mut at = 20;
    loop {
        let kind = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let size = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap()) as usize;
        if kind == 7 {
            break;
        }
        at += 16 + size;
    }
    let path = f.dir.join("header-only.rxc");
    std::fs::write(&path, &raw[..at + 16]).unwrap();
    assert!(
        Snapshot::load(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("SnapshotBundle")
    );
    assert!(
        SnapshotBundle::load(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("truncated")
    );
}

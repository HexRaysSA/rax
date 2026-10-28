//! Wire-format, compatibility and failure-preservation checks.
use super::*;
#[test]
fn pci_setting_survives_binary_config_roundtrip_and_default_resume() {
    for enabled in [false, true] {
        let snapshot = super::tests::snapshot_with_memory_metadata(128 << 20, 128 << 20);
        let mut initial = crate::config::VmConfig::from_checkpoint(
            snapshot.config,
            crate::config::CliConfig::default(),
            128 << 20,
        )
        .unwrap();
        initial.pci_devices = enabled;
        let raw = crate::codec::serialize(&initial.to_checkpoint()).unwrap();
        let cp: CheckpointConfig = crate::codec::deserialize(&raw).unwrap();
        let restored = crate::config::VmConfig::from_checkpoint(
            cp,
            crate::config::CliConfig::default(),
            128 << 20,
        )
        .unwrap();
        assert_eq!(restored.pci_devices, enabled);
    }
}

use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
struct TestPath(std::path::PathBuf);
impl TestPath {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "rax-checkpoint-codec-{}-{}.rxc",
                std::process::id(),
                NEXT_PATH.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
            {
                Ok(_) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("{e}"),
            }
        }
    }
}
impl Drop for TestPath {
    fn drop(&mut self) {
        if self.0.is_dir() {
            let _ = std::fs::remove_dir(&self.0);
        } else {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
fn sample() -> Snapshot {
    let mut snapshot = super::tests::snapshot_with_memory_metadata(4096, 4096);
    snapshot.config.pci_devices = true;
    snapshot.instruction_count = 123456789;
    snapshot.elapsed_nanos = 987654321;
    snapshot.memory_data = zstd::encode_all(&[0xa5u8; 4096][..], 3).unwrap();
    snapshot
}

#[test]
fn backend_context_section_is_required_ordered_bounded_and_cannot_alias_optional() {
    let base = sample();
    let cpu = CpuSnapshot {
        state: base.cpu_state.clone(),
        emulator: base.emulator_state.clone(),
    };
    let bundle = SnapshotBundle::new(base)
        .with_cpus(vec![cpu])
        .unwrap()
        .with_backend_contexts(vec![Some(BackendContext {
            kind: AARCH32_CONTEXT,
            data: vec![0x12, 0x34],
        })])
        .unwrap();
    let path = TestPath::new();
    bundle.save(&path.0).unwrap();
    let raw = std::fs::read(&path.0).unwrap();
    assert_eq!(
        SnapshotBundle::load(&path.0)
            .unwrap()
            .backend_contexts()
            .unwrap()
            .entries(),
        bundle.backend_contexts().unwrap().entries()
    );
    let original = sections(&raw);
    let index = original
        .iter()
        .position(|p| u32::from_le_bytes(p[..4].try_into().unwrap()) == 14)
        .unwrap();
    let cpu_index = original
        .iter()
        .position(|p| u32::from_le_bytes(p[..4].try_into().unwrap()) == 11)
        .unwrap();
    for mutation in 0..7 {
        let mut parts = original.clone();
        match mutation {
            0 => parts[index][..4].copy_from_slice(&(14u32 | (1 << 31)).to_le_bytes()),
            1 => parts[index][4..8].copy_from_slice(&2u32.to_le_bytes()),
            2 => parts.swap(index, cpu_index),
            3 => parts.push(parts[index].clone()),
            4 => {
                let late = parts.remove(index);
                parts.push(late);
            }
            5 => {
                parts.remove(cpu_index);
            }
            6 => parts[index][24..28].copy_from_slice(&0u32.to_le_bytes()),
            _ => unreachable!(),
        }
        std::fs::write(&path.0, assemble(&parts)).unwrap();
        assert!(
            SnapshotBundle::load(&path.0).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn complete_resources_are_required_verified_ordered_and_cannot_be_discarded() {
    let base = sample();
    let cpu = CpuSnapshot {
        state: base.cpu_state.clone(),
        emulator: base.emulator_state.clone(),
    };
    let bytes = std::sync::Arc::new(vec![0x5a; 1024 * 1024]);
    let resource = CheckpointResource::boot_cdrom(bytes.clone()).unwrap();
    let key = resource.key();
    let bundle = SnapshotBundle::new(base)
        .with_cpus(vec![cpu])
        .unwrap()
        .with_backend_contexts(vec![Some(BackendContext {
            kind: X86_64_CONTEXT,
            data: vec![1], // Transport test: backend owns inner decoding.
        })])
        .unwrap()
        .with_resources(vec![resource.clone(), resource])
        .unwrap();
    let path = TestPath::new();
    bundle.save(&path.0).unwrap();
    let raw = std::fs::read(&path.0).unwrap();
    let loaded = SnapshotBundle::load(&path.0).unwrap();
    let resources = loaded.resources().unwrap();
    assert_eq!(resources.keys().collect::<Vec<_>>(), [key]);
    assert_eq!(resources.prepare().unwrap().resolve(key).unwrap(), bytes);
    assert!(Snapshot::load(&path.0).is_err());
    for pair in [false, true] {
        let mut loaded = SnapshotBundle::load(&path.0).unwrap();
        loaded.take_backend_contexts();
        loaded.take_cpus();
        if pair {
            assert!(loaded.into_parts().is_err());
        } else {
            assert!(loaded.into_base().is_err());
        }
    }
    let original = sections(&raw);
    let index = original
        .iter()
        .position(|p| u32::from_le_bytes(p[..4].try_into().unwrap()) == 15)
        .unwrap();
    let context_index = original
        .iter()
        .position(|p| u32::from_le_bytes(p[..4].try_into().unwrap()) == 14)
        .unwrap();
    for mutation in 0..8 {
        let mut parts = original.clone();
        match mutation {
            0 => parts[index][..4].copy_from_slice(&(15u32 | (1 << 31)).to_le_bytes()),
            1 => parts[index][4..8].copy_from_slice(&2u32.to_le_bytes()),
            2 => parts.push(parts[index].clone()),
            3 => {
                parts.remove(context_index);
            }
            4 => parts.swap(index, context_index),
            5 => {
                let late = parts.remove(index);
                parts.push(late);
            }
            6 => parts[index][40] ^= 1, // Inner full-content SHA-256.
            7 => parts[index][32..40].copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => unreachable!(),
        }
        std::fs::write(&path.0, assemble(&parts)).unwrap();
        assert!(
            SnapshotBundle::load(&path.0).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn projection_only_resource_bundles_enforce_ram_media_budget_before_payloads() {
    fn bundle(memory: u64) -> Result<SnapshotBundle> {
        let mut base = sample();
        // Metadata admission must run before decompressing a large RAM image.
        base.config.memory_bytes = memory;
        base.memory_size = memory;
        let cpu = CpuSnapshot {
            state: base.cpu_state.clone(),
            emulator: base.emulator_state.clone(),
        };
        SnapshotBundle::new(base)
            .with_cpus(vec![cpu])?
            .with_backend_contexts(vec![Some(BackendContext {
                kind: X86_64_CONTEXT,
                data: vec![1],
            })])?
            .with_resources(vec![CheckpointResource::boot_cdrom(std::sync::Arc::new(
                vec![0x5a; 4096],
            ))?])
    }
    let limit = crate::vm::memory::MAX_GUEST_MEMORY_BYTES;
    assert!(bundle(limit - 4096).is_ok());
    let error = bundle(limit).unwrap_err();
    assert!(error.to_string().contains("budget"), "{error}");
    // Start from a valid small file, then forge only the declared RAM geometry.
    let path = TestPath::new();
    bundle(4096).unwrap().save(&path.0).unwrap();
    let mut parts = sections(&std::fs::read(&path.0).unwrap());
    for part in &mut parts {
        match u32::from_le_bytes(part[..4].try_into().unwrap()) {
            1 => {
                let mut config: CheckpointConfig = crate::codec::deserialize(&part[16..]).unwrap();
                config.memory_bytes = limit;
                let raw = crate::codec::serialize(&config).unwrap();
                assert_eq!(raw.len(), part.len() - 16);
                part[16..].copy_from_slice(&raw);
            }
            2 => part[32..40].copy_from_slice(&limit.to_le_bytes()),
            _ => (),
        }
    }
    std::fs::write(&path.0, assemble(&parts)).unwrap();
    let error = SnapshotBundle::load(&path.0).unwrap_err();
    assert!(error.to_string().contains("budget"), "{error}");
}

#[test]
fn pci_resource_aggregate_rejects_before_later_storage_payloads() {
    use crate::config::{ImageAccess, ImageAttachment, StorageConfig};
    use crate::vm::runtime::pci_state::PciDevices;
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    let base = sample();
    let cpu = CpuSnapshot {
        state: base.cpu_state.clone(),
        emulator: base.emulator_state.clone(),
    };
    let memory = std::sync::Arc::new(
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap(),
    );
    let image = TestPath::new();
    std::fs::write(&image.0, [0x33; 8192]).unwrap();
    let storage = StorageConfig {
        nvme: Some(ImageAttachment::capture(&image.0, ImageAccess::CopyOnWrite, 8192).unwrap()),
        ..Default::default()
    };
    let devices = PciDevices::new(memory, &storage, true).unwrap();
    let bundle = SnapshotBundle::new(base)
        .with_cpus(vec![cpu])
        .unwrap()
        .with_backend_contexts(vec![Some(BackendContext {
            kind: X86_64_CONTEXT,
            data: vec![1],
        })])
        .unwrap()
        .with_pci(devices.checkpoint().unwrap())
        .unwrap()
        .with_resources(vec![
            CheckpointResource::boot_cdrom(std::sync::Arc::new(vec![0x5a; 4096])).unwrap(),
        ])
        .unwrap();
    let pci = bundle.pci().unwrap();
    let media = pci.nvme_media().unwrap().size() + pci.ahci_media().unwrap().size();
    assert!(media >= 4096);
    let declared = crate::vm::memory::MAX_GUEST_MEMORY_BYTES - media;
    let path = TestPath::new();
    bundle.save(&path.0).unwrap();
    let mut parts = sections(&std::fs::read(&path.0).unwrap());
    for part in &mut parts {
        match u32::from_le_bytes(part[..4].try_into().unwrap()) {
            1 => {
                let mut config: CheckpointConfig = crate::codec::deserialize(&part[16..]).unwrap();
                config.memory_bytes = declared;
                part[16..].copy_from_slice(&crate::codec::serialize(&config).unwrap());
            }
            2 => part[32..40].copy_from_slice(&declared.to_le_bytes()),
            _ => (),
        }
    }
    // Keep only through PCI control. The budget must reject before requesting
    // either storage frame or the missing RAM payload.
    let last = parts
        .iter()
        .position(|part| u32::from_le_bytes(part[..4].try_into().unwrap()) == 7)
        .unwrap();
    std::fs::write(&path.0, assemble(&parts[..=last])).unwrap();
    let error = SnapshotBundle::load(&path.0).unwrap_err();
    assert!(error.to_string().contains("budget"), "{error}");
}

#[test]
fn resource_capture_requires_complete_cpu_and_backend_context_sets() {
    let resource = CheckpointResource::boot_cdrom(std::sync::Arc::new(Vec::new())).unwrap();
    assert!(
        SnapshotBundle::new(sample())
            .with_resources(vec![resource.clone()])
            .is_err()
    );
    let base = sample();
    let cpu = CpuSnapshot {
        state: base.cpu_state.clone(),
        emulator: base.emulator_state.clone(),
    };
    assert!(
        SnapshotBundle::new(base)
            .with_cpus(vec![cpu])
            .unwrap()
            .with_resources(vec![resource])
            .is_err()
    );
}
fn encoded(snapshot: &Snapshot) -> Vec<u8> {
    let mut raw = vec![];
    codec::write_to(snapshot, &mut raw).unwrap();
    raw
}
fn read(raw: &[u8]) -> Result<Snapshot> {
    let file = TestPath::new();
    std::fs::write(&file.0, raw).unwrap();
    Snapshot::load(&file.0)
}
fn error(raw: &[u8]) -> String {
    read(raw)
        .err()
        .expect("invalid checkpoint accepted")
        .to_string()
}
fn sections(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut offset = 20;
    let mut result = vec![];
    while offset < raw.len() {
        let length = u64::from_le_bytes(raw[offset + 8..offset + 16].try_into().unwrap()) as usize;
        let end = offset + 16 + length;
        result.push(raw[offset..end].to_vec());
        offset = end;
    }
    result
}
fn assemble(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = CHECKPOINT_MAGIC.to_vec();
    raw.extend(8u32.to_le_bytes());
    raw.extend(codec::TAG.to_le_bytes());
    raw.extend((parts.len() as u32).to_le_bytes());
    for p in parts {
        raw.extend(p);
    }
    raw
}
fn extra(kind: u32, schema: u32, bytes: &[u8]) -> Vec<u8> {
    let mut raw = kind.to_le_bytes().to_vec();
    raw.extend(schema.to_le_bytes());
    raw.extend((bytes.len() as u64).to_le_bytes());
    raw.extend(bytes);
    raw
}
fn legacy(snapshot: &Snapshot) -> Vec<u8> {
    let c = &snapshot.config;
    let old = super::legacy::LegacyConfig {
        arch: c.arch,
        backend: c.backend,
        memory_bytes: c.memory_bytes,
        vcpus: c.vcpus,
        kernel: c.kernel.clone(),
        initrd: c.initrd.clone(),
        cmdline: c.cmdline.clone(),
        hexagon_isa: c.hexagon_isa,
        hexagon_endian: c.hexagon_endian,
        hexagon_entry: c.hexagon_entry,
        hexagon_load_addr: c.hexagon_load_addr,
        aarch64_isa: c.aarch64_isa,
        aarch32_isa: c.aarch32_isa,
        cortexm_isa: c.cortexm_isa,
        cortexr_isa: c.cortexr_isa,
        arm_entry: c.arm_entry,
        arm_load_addr: c.arm_load_addr,
        arm_dtb: c.arm_dtb.clone(),
    };
    let mut raw = CHECKPOINT_MAGIC.to_vec();
    // A bincode tuple has the original struct's field sequence, with no tuple
    // header. This layout predates tagged sections and the PCI config field.
    raw.extend(
        crate::codec::serialize(&(
            8u32,
            old,
            snapshot.instruction_count,
            snapshot.elapsed_nanos,
            &snapshot.cpu_state,
            &snapshot.emulator_state,
            &snapshot.devices,
            snapshot.memory_size,
            &snapshot.memory_data,
        ))
        .unwrap(),
    );
    raw
}
#[test]
fn tagged_checkpoint_roundtrip_preserves_config_registers_devices_and_memory() {
    let s = sample();
    let raw = encoded(&s);
    assert_eq!(&raw[..8], b"RAXCKPT\0");
    assert_eq!(&raw[8..12], &8u32.to_le_bytes());
    assert_eq!(&raw[12..16], b"RXS8");
    let back = read(&raw).unwrap();
    assert!(back.config.pci_devices);
    assert_eq!(
        crate::codec::serialize(&back).unwrap(),
        crate::codec::serialize(&s).unwrap()
    );
    assert_eq!(back.decompress_memory().unwrap(), [0xa5; 4096]);
}
#[test]
fn original_v8_wire_still_loads_with_absent_pci_defaulting_false() {
    let s = sample();
    let back = read(&legacy(&s)).unwrap();
    assert!(!back.config.pci_devices);
    assert_eq!(back.instruction_count, s.instruction_count);
    assert_eq!(back.elapsed_nanos, s.elapsed_nanos);
    assert_eq!(back.decompress_memory().unwrap(), [0xa5; 4096]);
    assert_eq!(
        crate::codec::serialize(&back.cpu_state).unwrap(),
        crate::codec::serialize(&s.cpu_state).unwrap()
    );
}
#[test]
fn duplicate_required_and_optional_sections_are_rejected() {
    let mut parts = sections(&encoded(&sample()));
    parts.push(parts[0].clone());
    assert!(error(&assemble(&parts)).contains("duplicate"));
    parts.pop();
    parts.push(extra(0x80000055, 1, &[]));
    parts.push(extra(0x80000055, 1, &[]));
    assert!(error(&assemble(&parts)).contains("duplicate"));
}
#[test]
fn unknown_required_section_is_not_silently_ignored() {
    let mut parts = sections(&encoded(&sample()));
    parts.push(extra(55, 1, &[]));
    assert!(error(&assemble(&parts)).contains("unknown required"));
}
#[test]
fn unknown_optional_section_is_bounded_and_skipped() {
    let s = sample();
    let mut parts = sections(&encoded(&s));
    parts.insert(1, extra(0x80000055, 99, &[1, 2, 3]));
    let back = read(&assemble(&parts)).unwrap();
    assert_eq!(
        crate::codec::serialize(&back).unwrap(),
        crate::codec::serialize(&s).unwrap()
    );
}
#[test]
fn missing_required_sections_and_excessive_section_count_fail() {
    let mut parts = sections(&encoded(&sample()));
    parts.pop();
    assert!(error(&assemble(&parts)).contains("missing required"));
    let mut raw = encoded(&sample());
    raw[16..20].copy_from_slice(&65u32.to_le_bytes());
    assert!(error(&raw[..20]).contains("section count"));
}
#[test]
fn unsupported_section_schema_is_rejected_before_payload() {
    let mut raw = encoded(&sample());
    raw[24..28].copy_from_slice(&3u32.to_le_bytes());
    assert!(error(&raw[..36]).contains("section schema"));
}
#[test]
fn oversized_section_and_optional_lengths_never_require_a_matching_allocation() {
    let mut raw = encoded(&sample());
    raw[28..36].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(error(&raw[..36]).contains("size limit"));
    let mut parts = sections(&encoded(&sample()));
    let mut unknown = extra(0x80000055, 1, &[]);
    unknown[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    parts.push(unknown);
    assert!(error(&assemble(&parts)).contains("truncated optional"));
}
#[test]
fn trailing_bytes_are_rejected_in_both_v8_encodings() {
    for mut raw in [encoded(&sample()), legacy(&sample())] {
        raw.push(0x42);
        assert!(error(&raw).contains("trailing"));
    }
}
#[test]
fn every_section_header_and_seeded_truncated_prefix_is_rejected() {
    let raw = encoded(&sample());
    let mut cuts = (0..20).collect::<std::collections::BTreeSet<_>>();
    let mut offset = 20;
    for part in sections(&raw) {
        for n in 0..16 {
            cuts.insert(offset + n);
        }
        cuts.insert(offset + part.len() - 1);
        offset += part.len();
    }
    let mut seed = 0x726178u64;
    for _ in 0..256 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        cuts.insert(seed as usize % raw.len());
    }
    for end in cuts {
        assert!(read(&raw[..end]).is_err(), "truncated prefix{end}");
    }
}
#[test]
fn oversized_memory_metadata_is_rejected_before_compressed_data() {
    let mut parts = sections(&encoded(&sample()));
    let size = crate::vm::memory::MAX_GUEST_MEMORY_BYTES + 4096;
    parts[0][24..32].copy_from_slice(&size.to_le_bytes());
    parts[1][32..40].copy_from_slice(&size.to_le_bytes());
    assert!(error(&assemble(&parts)).contains("guest memory must not exceed"));
}
#[test]
fn compressed_ram_length_is_bounded_by_declared_memory() {
    let mut parts = sections(&encoded(&sample()));
    parts[5][8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(error(&assemble(&parts)).contains("size limit"));
}
#[test]
fn decompression_stops_one_byte_past_declared_output() {
    let mut s = sample();
    s.memory_data = zstd::encode_all(&[0u8; 65536][..], 3).unwrap();
    let e = s.decompress_memory().unwrap_err().to_string();
    assert!(e.contains("expected4096") || e.contains("expected 4096"));
    assert!(e.contains("got 4097"));
}
#[test]
fn short_decompression_is_reported() {
    let mut s = sample();
    s.memory_data = zstd::encode_all(&[0u8; 4095][..], 3).unwrap();
    assert!(
        s.decompress_memory()
            .unwrap_err()
            .to_string()
            .contains("got 4095")
    );
}
#[test]
fn legacy_malicious_string_length_is_rejected_by_metadata_budget() {
    let mut raw = legacy(&sample());
    raw[29..37].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(error(&raw).contains("deserialize legacy"));
}
#[test]
fn known_sections_can_reorder_before_memory_but_memory_requires_metadata() {
    let parts = sections(&encoded(&sample()));
    let reordered = [
        parts[4].clone(),
        parts[3].clone(),
        parts[2].clone(),
        parts[1].clone(),
        parts[0].clone(),
        parts[5].clone(),
    ];
    assert!(read(&assemble(&reordered)).is_ok());
    let reordered = [
        parts[5].clone(),
        parts[0].clone(),
        parts[1].clone(),
        parts[2].clone(),
        parts[3].clone(),
        parts[4].clone(),
    ];
    assert!(error(&assemble(&reordered)).contains("precedes checkpoint metadata"));
}
#[test]
fn failed_serialization_preserves_existing_checkpoint_and_cleans_temporary() {
    let path = TestPath::new();
    let mut s = sample();
    s.save(&path.0).unwrap();
    let before = std::fs::read(&path.0).unwrap();
    s.config.cmdline = "x".repeat(1024 * 1024 + 1);
    assert!(s.save(&path.0).is_err());
    assert_eq!(std::fs::read(&path.0).unwrap(), before);
    let prefix = format!(".{}.rax-", path.0.file_name().unwrap().to_string_lossy());
    assert!(
        !std::fs::read_dir(path.0.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with(&prefix))
    );
}
#[test]
fn atomic_save_replaces_existing_file_and_keeps_directory_target() {
    let path = TestPath::new();
    let mut s = sample();
    s.save(&path.0).unwrap();
    s.instruction_count += 1;
    s.save(&path.0).unwrap();
    assert_eq!(
        Snapshot::load(&path.0).unwrap().instruction_count,
        s.instruction_count
    );
    std::fs::remove_file(&path.0).unwrap();
    std::fs::create_dir(&path.0).unwrap();
    assert!(s.save(&path.0).is_err());
    assert!(path.0.is_dir());
}

#[test]
fn required_section_cannot_be_hidden_behind_optional_flag() {
    let mut parts = sections(&encoded(&sample()));
    parts[0][..4].copy_from_slice(&0x80000001u32.to_le_bytes());
    assert!(error(&assemble(&parts)).contains("marked optional"));
}

#[test]
fn actual_original_writer_fixture_loads_without_original_kernel() {
    let raw = include_bytes!("../../../tests/fixtures/checkpoint/original-v8.rxc");
    let snapshot = read(raw).unwrap();
    assert!(!snapshot.config.pci_devices);
    assert_eq!(snapshot.instruction_count, 123456789);
    assert_eq!(snapshot.elapsed_nanos, 987654321);
    assert_eq!(snapshot.memory_size, 4096);
    assert_eq!(snapshot.decompress_memory().unwrap(), [0xa5; 4096]);
    assert!(matches!(snapshot.cpu_state, CpuState::X86_64(_)));
}
#[test]
fn all_current_cpu_payload_variants_roundtrip_through_both_v8_encodings() {
    use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
    use crate::isa::arm::common::memory::FlatMemory;
    let arm = AArch64Cpu::new(AArch64Config::default(), Box::new(FlatMemory::new(0, 4096)));
    let variants = [
        CpuState::x86_64(Default::default(), Default::default()),
        CpuState::hexagon(Default::default()),
        CpuState::aarch64(Default::default(), arm.export_sregs()),
        CpuState::aarch32(Default::default(), Default::default()),
        CpuState::cortex_m(Default::default(), Default::default()),
        CpuState::riscv(Default::default()),
        CpuState::ebpf(Default::default()),
    ];
    for cpu in variants {
        let mut snapshot = sample();
        snapshot.cpu_state = cpu;
        let expected = crate::codec::serialize(&snapshot.cpu_state).unwrap();
        for raw in [encoded(&snapshot), legacy(&snapshot)] {
            let back = read(&raw).unwrap();
            assert_eq!(crate::codec::serialize(&back.cpu_state).unwrap(), expected);
        }
    }
}

#[cfg(unix)]
#[test]
fn atomic_replacement_preserves_existing_permissions_and_new_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let path = TestPath::new();
    std::fs::set_permissions(&path.0, std::fs::Permissions::from_mode(0o640)).unwrap();
    sample().save(&path.0).unwrap();
    assert_eq!(
        std::fs::metadata(&path.0).unwrap().permissions().mode() & 0o777,
        0o640
    );
    std::fs::remove_file(&path.0).unwrap();
    sample().save(&path.0).unwrap();
    assert_eq!(
        std::fs::metadata(&path.0).unwrap().permissions().mode() & 0o077,
        0
    );
}

#[test]
fn prior_human_readable_config_metadata_defaults_absent_pci_to_false() {
    let mut value = serde_json::to_value(&sample().config).unwrap();
    value.as_object_mut().unwrap().remove("pci_devices");
    let config: CheckpointConfig = serde_json::from_value(value).unwrap();
    assert!(!config.pci_devices);
}

#[test]
fn tagged_config_schema_two_checks_recorded_image_metadata_before_ram() {
    let mut snapshot = sample();
    snapshot.config.storage.nvme = Some(crate::config::ImageAttachment {
        path: std::path::PathBuf::from("/recorded/raw"),
        mode: crate::config::ImageAccess::CopyOnWrite,
        max_bytes: 512,
        identity: crate::config::ImageIdentity {
            bytes: 1024,
            sha256: [0; 32],
        },
    });
    let mut parts = sections(&encoded(&sample()));
    parts[0] = extra(1, 2, &crate::codec::serialize(&snapshot.config).unwrap());
    assert!(error(&assemble(&parts)).contains("recorded storage image metadata"));
}

//! Physical RAM windows and additional writable backing are explicit state.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::memory::vm::{Bytes, GuestAddress};
use rax::vm::runtime::Vmm;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
const RAM: usize = 4096;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Kernel(PathBuf);
impl Kernel {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rax-physical-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, [0; 64]).unwrap();
        Self(path)
    }
    fn high_riscv_vm(&self) -> Vmm {
        std::fs::write(
            &self.0,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/checkpoint/high-riscv.elf"
            )),
        )
        .unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Riscv64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.0.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(RAM as u64);
        Vmm::new(config).unwrap()
    }
    fn vm(&self, arch: ArchKind) -> Vmm {
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(arch),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.0.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(RAM as u64);
        Vmm::new_resume(config).unwrap()
    }
}
impl Drop for Kernel {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}
/// Public base-API baseline: no guest instruction or boot is executed.
pub fn emit_base_reference() {
    for (index, arch, padding) in [
        (0, ArchKind::X86_64, false),
        (1, ArchKind::X86_64, true),
        (2, ArchKind::Aarch64, false),
        (3, ArchKind::Riscv64, false),
        (4, ArchKind::Riscv64, false),
    ] {
        let kernel = Kernel::new();
        let source = if index == 4 {
            kernel.high_riscv_vm()
        } else {
            kernel.vm(arch)
        };
        let address = if index == 4 {
            0x80000004
        } else if padding {
            RAM as u64 + 3
        } else {
            source.machine().ram_base() + 3
        };
        if index != 4 {
            source
                .guest_mem()
                .memory()
                .write_slice(&[0xab], GuestAddress(address))
                .unwrap();
        }
        let mut original = [0];
        source
            .guest_mem()
            .memory()
            .read_slice(&mut original, GuestAddress(address))
            .unwrap();
        assert_eq!(original, [0xab]);
        let snapshot = source.take_snapshot(53).unwrap();
        let mut target = kernel.vm(arch);
        let accepted = target.restore_snapshot(&snapshot).is_ok();
        let mut actual = [0];
        target
            .guest_mem()
            .memory()
            .read_slice(&mut actual, GuestAddress(address))
            .unwrap();
        println!("{index}\t{address}\t{}\t{}", u8::from(accepted), actual[0]);
    }
}

use rax::devices::{lapic::LocalApic, pic::DualPic, pit::Pit, serial::Serial16550};
use rax::vm::memory::vm::GuestMemoryMmap;
use rax::vm::snapshot::{
    DeviceState, EmulatorState, PhysicalMemorySnapshot, Snapshot, SnapshotBundle,
};
use rax::vm::vcpu::state::CpuState;
fn map(layout: &[(u64, usize)]) -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(
        &layout
            .iter()
            .map(|&(a, n)| (GuestAddress(a), n))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
fn bytes(memory: &GuestMemoryMmap, layout: &[(u64, usize)]) -> Vec<u8> {
    let mut result = Vec::new();
    for &(address, size) in layout {
        let mut b = vec![0; size];
        memory.read_slice(&mut b, GuestAddress(address)).unwrap();
        result.extend_from_slice(&b);
    }
    result
}
fn fill(memory: &GuestMemoryMmap, layout: &[(u64, usize)], index: usize) {
    for (region, &(address, size)) in layout.iter().enumerate() {
        let b: Vec<_> = (0..size)
            .map(|i| {
                (i as u8)
                    .wrapping_mul(17)
                    .wrapping_add((region * 31 + index * 7) as u8)
                    ^ 0x5a
            })
            .collect();
        memory.write_slice(&b, GuestAddress(address)).unwrap();
    }
}
fn base(k: &Kernel, data: &[u8]) -> Snapshot {
    let mut c = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            kernel: Some(k.0.clone()),
            ..Default::default()
        },
        None,
    )
    .unwrap()
    .to_checkpoint();
    c.memory_bytes = data.len() as u64;
    Snapshot::new(
        c,
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
        data,
    )
    .unwrap()
}
fn bundle(k: &Kernel, memory: &GuestMemoryMmap) -> SnapshotBundle {
    let mut data = vec![0; RAM];
    memory.read_slice(&mut data, GuestAddress(0)).unwrap();
    SnapshotBundle::new(base(k, &data))
        .with_physical_memory(PhysicalMemorySnapshot::capture(memory).unwrap())
        .unwrap()
}
#[derive(Clone)]
struct Section {
    kind: u32,
    schema: u32,
    data: Vec<u8>,
}
fn sections(raw: &[u8]) -> Vec<Section> {
    let mut at = 20;
    let mut result = Vec::new();
    for _ in 0..u32::from_le_bytes(raw[16..20].try_into().unwrap()) {
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
    let mut r = b"RAXCKPT\0".to_vec();
    r.extend_from_slice(&8u32.to_le_bytes());
    r.extend_from_slice(b"RXS8");
    r.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for p in parts {
        r.extend_from_slice(&p.kind.to_le_bytes());
        r.extend_from_slice(&p.schema.to_le_bytes());
        r.extend_from_slice(&(p.data.len() as u64).to_le_bytes());
        r.extend_from_slice(&p.data);
    }
    r
}
fn saved(k: &Kernel, b: &SnapshotBundle) -> Vec<u8> {
    b.save(&k.0).unwrap();
    std::fs::read(&k.0).unwrap()
}
fn loaded(k: &Kernel, parts: &[Section]) -> rax::Result<SnapshotBundle> {
    std::fs::write(&k.0, assemble(parts)).unwrap();
    SnapshotBundle::load(&k.0)
}
fn physical(parts: &mut [Section]) -> &mut Vec<u8> {
    &mut parts.iter_mut().find(|p| p.kind == 10).unwrap().data
}
fn sample() -> (Kernel, Vec<Section>, Vec<(u64, usize)>) {
    let k = Kernel::new();
    let layout = vec![(0, RAM), (0x40000000, 2 * RAM), (0x80000000, RAM)];
    let m = map(&layout);
    fill(&m, &layout, 3);
    let raw = saved(&k, &bundle(&k, &m));
    (k, sections(&raw), layout)
}
#[test]
fn discontiguous_physical_regions_restore_every_byte() {
    let layout = [(0, RAM), (0x40000000, 2 * RAM), (0x80000000, RAM)];
    let m = map(&layout);
    fill(&m, &layout, 1);
    let s = PhysicalMemorySnapshot::capture(&m).unwrap();
    assert_eq!(s.total_bytes(), 4 * RAM as u64);
    assert_eq!(
        s.layout().collect::<Vec<_>>(),
        layout.map(|(a, n)| (a, n as u64))
    );
    let target = map(&layout);
    s.restore(&target).unwrap();
    assert_eq!(bytes(&target, &layout), bytes(&m, &layout));
}
#[test]
fn maximum_region_count_is_inclusive() {
    let layout: Vec<_> = (0..128).map(|i| (i * 8192, RAM)).collect();
    let m = map(&layout);
    fill(&m, &layout, 2);
    let s = PhysicalMemorySnapshot::capture(&m).unwrap();
    s.verify().unwrap();
    assert_eq!(s.layout().len(), 128);
}
#[test]
fn excess_region_count_is_rejected_before_capture() {
    let layout: Vec<_> = (0..129).map(|i| (i * 8192, RAM)).collect();
    assert!(PhysicalMemorySnapshot::capture(&map(&layout)).is_err());
}
#[test]
fn empty_memory_map_is_rejected() {
    assert!(PhysicalMemorySnapshot::capture(&GuestMemoryMmap::new()).is_err());
}
#[test]
fn wrong_target_layout_leaves_all_bytes_unchanged() {
    let source = map(&[(0, RAM), (0x40000000, RAM)]);
    let s = PhysicalMemorySnapshot::capture(&source).unwrap();
    for layout in [
        vec![(0, RAM)],
        vec![(0, RAM), (0x40001000, RAM)],
        vec![(0, 2 * RAM), (0x40000000, RAM)],
    ] {
        let target = map(&layout);
        fill(&target, &layout, 9);
        let before = bytes(&target, &layout);
        assert!(s.restore(&target).is_err());
        assert_eq!(bytes(&target, &layout), before);
    }
}
#[test]
fn physical_bundle_roundtrips_and_preserves_base_projection() {
    let (k, p, layout) = sample();
    assert_eq!(
        p.iter().map(|s| s.kind).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 10, 6]
    );
    let b = loaded(&k, &p).unwrap();
    b.verify_physical_memory().unwrap();
    let target = map(&layout);
    b.physical_memory().unwrap().restore(&target).unwrap();
    let mut logical = vec![0; RAM];
    target.read_slice(&mut logical, GuestAddress(0)).unwrap();
    assert_eq!(logical, b.base().decompress_memory().unwrap());
}
#[test]
fn required_components_cannot_be_dropped_by_extraction() {
    let (k, p, _) = sample();
    assert!(loaded(&k, &p).unwrap().into_base().is_err());
    assert!(loaded(&k, &p).unwrap().into_parts().is_err());
    let mut b = loaded(&k, &p).unwrap();
    assert!(b.take_physical_memory().is_some());
    assert!(b.take_physical_memory().is_none());
    assert!(b.take_pci().is_none());
    assert!(b.into_base().is_ok());
}
#[test]
fn base_reader_refuses_physical_state_at_header_before_payload() {
    let (k, p, _) = sample();
    let mut raw = assemble(&p);
    let mut at = 20;
    while u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) != 10 {
        at += 16 + u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap()) as usize;
    }
    raw.truncate(at + 16);
    std::fs::write(&k.0, raw).unwrap();
    assert!(
        Snapshot::load(&k.0)
            .err()
            .unwrap()
            .to_string()
            .contains("required physical memory")
    );
}
#[test]
fn attaching_disagreeing_reported_projection_is_rejected() {
    let k = Kernel::new();
    let m = map(&[(0, RAM)]);
    fill(&m, &[(0, RAM)], 1);
    assert!(
        SnapshotBundle::new(base(&k, &vec![0; RAM]))
            .with_physical_memory(PhysicalMemorySnapshot::capture(&m).unwrap())
            .is_err()
    );
}
#[test]
fn loaded_projection_disagreement_is_detected_without_guest_writes() {
    let (k, mut p, layout) = sample();
    p.iter_mut().find(|p| p.kind == 6).unwrap().data =
        zstd::encode_all(&vec![0; RAM][..], 3).unwrap();
    let b = loaded(&k, &p).unwrap();
    let target = map(&layout);
    fill(&target, &layout, 8);
    let before = bytes(&target, &layout);
    assert!(b.verify_physical_memory().is_err());
    assert_eq!(bytes(&target, &layout), before);
}
fn rejected_payload(mut change: impl FnMut(&mut Vec<u8>)) {
    let (k, mut p, layout) = sample();
    change(physical(&mut p));
    let b = loaded(&k, &p).unwrap();
    let target = map(&layout);
    fill(&target, &layout, 6);
    let before = bytes(&target, &layout);
    assert!(b.physical_memory().unwrap().restore(&target).is_err());
    assert_eq!(bytes(&target, &layout), before);
}
#[test]
fn late_region_digest_failure_precedes_every_guest_write() {
    rejected_payload(|r| r[12 + 2 * 56 + 16] ^= 1);
}
#[test]
fn late_region_bad_frame_precedes_every_guest_write() {
    rejected_payload(|r| {
        let n = r.len();
        r[n - 1] ^= 0xff;
    });
}
#[test]
fn expanded_region_length_is_exact_in_both_directions() {
    for change in [-1i64, 1] {
        rejected_payload(|r| {
            let at = 12 + 2 * 56 + 8;
            r[at..at + 8].copy_from_slice(&((RAM as i64 + change) as u64).to_le_bytes());
        });
    }
}
#[test]
fn malformed_region_tables_reject_before_payload_allocation() {
    let (k, p, _) = sample();
    for case in 0..10 {
        let mut p = p.clone();
        let r = physical(&mut p);
        match case {
            0 => r[8..12].copy_from_slice(&0u32.to_le_bytes()),
            1 => r[8..12].copy_from_slice(&129u32.to_le_bytes()),
            2 => r[20..28].copy_from_slice(&0u64.to_le_bytes()),
            3 => r[68..76].copy_from_slice(&0u64.to_le_bytes()),
            4 => r[68..76].copy_from_slice(&1u64.to_le_bytes()),
            5 => r[12..20].copy_from_slice(&(u64::MAX - 1).to_le_bytes()),
            6 => r[20..28].copy_from_slice(&(69u64 * 1024 * 1024 * 1024).to_le_bytes()),
            7 => r[60..68].copy_from_slice(&u64::MAX.to_le_bytes()),
            8 => r[0] ^= 1,
            9 => r[60..68].copy_from_slice(&0u64.to_le_bytes()),
            _ => unreachable!(),
        };
        assert!(loaded(&k, &p).is_err(), "{case}");
    }
}
#[test]
fn section_schema_optional_alias_and_duplicates_are_rejected() {
    let (k, p, _) = sample();
    for case in 0..3 {
        let mut p = p.clone();
        let index = p.iter().position(|p| p.kind == 10).unwrap();
        match case {
            0 => p[index].schema = 2,
            1 => p[index].kind |= 1 << 31,
            2 => p.insert(index, p[index].clone()),
            _ => unreachable!(),
        };
        assert!(loaded(&k, &p).is_err());
    }
}
#[test]
fn physical_section_order_is_admitted_before_payload() {
    let (k, p, _) = sample();
    for case in 0..2 {
        let mut p = p.clone();
        let at = p.iter().position(|p| p.kind == 10).unwrap();
        let row = p.remove(at);
        if case == 0 {
            p.push(row);
        } else {
            p.insert(0, row);
        }
        assert!(loaded(&k, &p).is_err());
    }
}
#[test]
fn physical_section_truncation_and_trailing_bytes_are_rejected() {
    let (k, p, _) = sample();
    for case in 0..3 {
        let mut p = p.clone();
        let r = physical(&mut p);
        match case {
            0 => {
                r.pop();
            }
            1 => r.push(0),
            2 => r.truncate(50),
            _ => unreachable!(),
        };
        assert!(loaded(&k, &p).is_err());
    }
}
#[test]
fn old_base_fixture_loads_without_inventing_physical_state() {
    let b = SnapshotBundle::load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/checkpoint/tagged-v8-schema1.rxc"
    ))
    .unwrap();
    assert!(b.physical_memory().is_none());
    assert!(b.into_parts().is_ok());
}
fn vm_cookie(arch: ArchKind, address: u64, high_elf: bool) {
    let k = Kernel::new();
    let source = if high_elf {
        k.high_riscv_vm()
    } else {
        k.vm(arch)
    };
    if !high_elf {
        source
            .guest_mem()
            .memory()
            .write_slice(&[0xab], GuestAddress(address))
            .unwrap();
    }
    let b = source.take_snapshot_bundle(53).unwrap();
    let target = k.vm(arch);
    b.physical_memory()
        .unwrap()
        .restore(target.guest_mem().memory())
        .unwrap();
    let mut byte = [0];
    target
        .guest_mem()
        .memory()
        .read_slice(&mut byte, GuestAddress(address))
        .unwrap();
    assert_eq!(byte, [0xab]);
}
#[test]
fn actual_aarch64_ram_base_is_preserved() {
    vm_cookie(ArchKind::Aarch64, 0x40000003, false);
}
#[test]
fn actual_high_riscv_elf_load_segment_is_preserved() {
    vm_cookie(ArchKind::Riscv64, 0x80000004, true);
}
#[test]
fn actual_x86_writable_padding_is_preserved() {
    vm_cookie(ArchKind::X86_64, RAM as u64 + 3, false);
}
#[test]
fn zero_based_riscv_control_remains_preserved() {
    vm_cookie(ArchKind::Riscv64, 3, false);
}
#[test]
fn zero_based_x86_control_remains_preserved() {
    vm_cookie(ArchKind::X86_64, 3, false);
}
/// Actual bundle writer and physical restore; independently checked by Python.
/// These are synthetic mapped-region patterns, not guest execution.
pub fn emit_reference(directory: &std::path::Path) {
    let layouts = [
        vec![(0, RAM)],
        vec![(0, RAM), (0x40000000, 2 * RAM), (0x80000000, RAM)],
        vec![(0, 2 * RAM), (0x1_0000_0000, 3 * RAM)],
        (0..128).map(|i| (i * 8192, RAM)).collect(),
    ];
    for (index, layout) in layouts.iter().enumerate() {
        let k = Kernel::new();
        let memory = map(layout);
        fill(&memory, layout, index);
        let b = bundle(&k, &memory);
        let file = directory.join(format!("case-{index}.rxc"));
        b.save(&file).unwrap();
        let b = SnapshotBundle::load(&file).unwrap();
        b.verify_physical_memory().unwrap();
        let target = map(layout);
        b.physical_memory().unwrap().restore(&target).unwrap();
        std::fs::write(
            directory.join(format!("case-{index}.restored")),
            bytes(&target, layout),
        )
        .unwrap();
        println!(
            "{index}\t{}\t{}",
            layout.len(),
            b.physical_memory().unwrap().total_bytes()
        );
    }
}
#[test]
fn aggregate_limit_is_inclusive_and_checked_from_metadata() {
    let k = Kernel::new();
    let m = map(&[(0, RAM)]);
    let raw = saved(&k, &bundle(&k, &m));
    let parts = sections(&raw);
    for (size, accepted) in [
        (68u64 * 1024 * 1024 * 1024, true),
        (68u64 * 1024 * 1024 * 1024 + 1, false),
    ] {
        let mut p = parts.clone();
        physical(&mut p)[20..28].copy_from_slice(&size.to_le_bytes());
        let result = loaded(&k, &p);
        assert_eq!(result.is_ok(), accepted);
        if let Ok(b) = result {
            assert!(b.physical_memory().unwrap().verify().is_err());
        }
    }
}
#[test]
fn configured_media_counts_before_physical_payload_admission() {
    use rax::config::{ImageAccess, ImageAttachment, ImageIdentity};
    let k = Kernel::new();
    let m = map(&[(0, RAM)]);
    let mut base = base(&k, &vec![0; RAM]);
    base.config.pci_devices = true;
    base.config.storage.nvme = Some(ImageAttachment {
        path: std::env::temp_dir().join("rax-physical-no-source-is-opened.raw"),
        mode: ImageAccess::CopyOnWrite,
        max_bytes: 512,
        identity: ImageIdentity {
            bytes: 512,
            sha256: [0; 32],
        },
    });
    let b = SnapshotBundle::new(base)
        .with_physical_memory(PhysicalMemorySnapshot::capture(&m).unwrap())
        .unwrap();
    let raw = saved(&k, &b);
    let mut p = sections(&raw);
    physical(&mut p)[20..28].copy_from_slice(&(68u64 * 1024 * 1024 * 1024).to_le_bytes());
    assert!(
        loaded(&k, &p)
            .unwrap_err()
            .to_string()
            .contains("aggregate")
    );
}
#[test]
fn exact_upper_physical_address_endpoint_is_valid_metadata() {
    let k = Kernel::new();
    let m = map(&[(0, RAM)]);
    let raw = saved(&k, &bundle(&k, &m));
    let mut p = sections(&raw);
    physical(&mut p)[12..20].copy_from_slice(&(u64::MAX - RAM as u64 + 1).to_le_bytes());
    let b = loaded(&k, &p).unwrap();
    b.physical_memory().unwrap().verify().unwrap();
    assert!(b.verify_physical_memory().is_err());
}
#[test]
fn physical_and_pci_extensions_keep_required_order_and_component_state() {
    use rax::vm::runtime::pci_state::PciDevices;
    use std::sync::Arc;
    for enabled in [false, true] {
        let k = Kernel::new();
        let m = Arc::new(map(&[(0, RAM)]));
        let d = PciDevices::new(m.clone(), &Default::default(), enabled).unwrap();
        let checkpoint = d.checkpoint().unwrap();
        let mut base = base(&k, &vec![0; RAM]);
        base.config.pci_devices = enabled;
        let b = SnapshotBundle::new(base)
            .with_pci(checkpoint.clone())
            .unwrap()
            .with_physical_memory(PhysicalMemorySnapshot::capture(&m).unwrap())
            .unwrap();
        let raw = saved(&k, &b);
        let p = sections(&raw);
        let kinds: Vec<_> = p.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            if enabled {
                vec![1, 2, 3, 4, 5, 7, 10, 8, 9, 6]
            } else {
                vec![1, 2, 3, 4, 5, 7, 10, 6]
            }
        );
        let b = loaded(&k, &p).unwrap();
        b.verify_physical_memory().unwrap();
        assert_eq!(b.pci().unwrap().clone().into_devices().unwrap(), checkpoint);
        let mut bad = p;
        let row = bad.remove(5);
        bad.insert(6, row);
        assert!(loaded(&k, &bad).is_err());
    }
}
#[cfg(all(test, unix))]
fn protected(layout: &[(u64, usize, i32)]) -> GuestMemoryMmap {
    use rax::vm::memory::vm::{GuestRegionMmap, MmapRegion};
    GuestMemoryMmap::from_regions(
        layout
            .iter()
            .map(|&(address, size, prot)| {
                GuestRegionMmap::new(
                    MmapRegion::build(None, size, prot, libc::MAP_PRIVATE | libc::MAP_ANON)
                        .unwrap(),
                    GuestAddress(address),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
#[cfg(unix)]
#[test]
fn unreadable_source_mapping_is_rejected_before_dereference() {
    let m = protected(&[
        (0, RAM, libc::PROT_READ | libc::PROT_WRITE),
        (0x40000000, RAM, libc::PROT_NONE),
    ]);
    assert!(PhysicalMemorySnapshot::capture(&m).is_err());
}
#[cfg(unix)]
#[test]
fn late_readonly_destination_is_rejected_before_earlier_region_write() {
    let layout = [(0, RAM), (0x40000000, RAM)];
    let source = map(&layout);
    fill(&source, &layout, 4);
    let s = PhysicalMemorySnapshot::capture(&source).unwrap();
    let target = protected(&[
        (0, RAM, libc::PROT_READ | libc::PROT_WRITE),
        (0x40000000, RAM, libc::PROT_READ),
    ]);
    target
        .write_slice(&vec![0x6d; RAM], GuestAddress(0))
        .unwrap();
    let before = bytes(&target, &layout);
    assert!(s.restore(&target).is_err());
    assert_eq!(bytes(&target, &layout), before);
    PhysicalMemorySnapshot::capture(&target)
        .unwrap()
        .verify()
        .unwrap();
}
#[test]
fn zero_source_clears_dirty_target_instead_of_assuming_sparse_zeroes() {
    let layout = [(0, 3 * RAM), (0x80000000, 2 * RAM)];
    let source = map(&layout);
    let state = PhysicalMemorySnapshot::capture(&source).unwrap();
    let target = map(&layout);
    fill(&target, &layout, 15);
    state.restore(&target).unwrap();
    assert_eq!(bytes(&target, &layout), vec![0; 5 * RAM]);
}

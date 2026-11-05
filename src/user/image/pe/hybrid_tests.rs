//! Independent CHPE field offsets and range boundary partitions.
use super::super::hybrid::{CodeKind, HybridError, HybridMetadata};
use super::*;

const BASE: u64 = 0x1_8000_0000;
const HEADER: usize = 0x100;

fn fixture(version: u32) -> Mem {
    let mut memory = Mem::new(0x2000);
    memory.u32(HEADER, version);
    memory.u32(HEADER + 4, 0x200);
    memory.u32(HEADER + 8, 3);
    memory.u32(HEADER + 12, 0x240);
    memory.u32(HEADER + 16, 0x280);
    memory.u32(HEADER + 48, 1);
    memory.u32(HEADER + 52, 1);
    for (at, start_and_type, length) in
        [(0x200, 0x1000, 8), (0x208, 0x1011, 12), (0x210, 0x1022, 16)]
    {
        memory.u32(at, start_and_type);
        memory.u32(at + 4, length);
    }
    memory.u32(0x240, 0x1020);
    memory.u32(0x244, 0x1030);
    memory.u32(0x248, 0x1010);
    memory.u32(0x280, 0x1020);
    memory.u32(0x284, 0x1010);
    memory
}

fn read(memory: &Mem) -> Result<HybridMetadata, HybridError> {
    HybridMetadata::read(&memory.0, BASE + HEADER as u64, BASE, 0x2000)
}

#[test]
fn versioned_code_maps_keep_isa_tags_gaps_and_exclusive_ends() {
    for version in [1, 2] {
        let metadata = read(&fixture(version)).unwrap();
        assert_eq!(metadata.version, version);
        assert_eq!(metadata.code.len(), 3);
        for (rva, expected) in [
            (0, None),
            (0xFFF, None),
            (0x1000, Some(CodeKind::Arm64)),
            (0x1007, Some(CodeKind::Arm64)),
            (0x1008, None),
            (0x100F, None),
            (0x1010, Some(CodeKind::Arm64Ec)),
            (0x101B, Some(CodeKind::Arm64Ec)),
            (0x101C, None),
            (0x1020, Some(CodeKind::Amd64)),
            (0x102F, Some(CodeKind::Amd64)),
            (0x1030, None),
            (u32::MAX, None),
        ] {
            assert_eq!(metadata.code_kind(rva), expected, "v{version} RVA {rva:#x}");
        }
        assert_eq!(metadata.entries[0].entry, 0x1010);
        assert_eq!(metadata.redirections[0].destination, 0x1010);
    }
}

#[test]
fn unknown_versions_and_metadata_addresses_are_rejected_without_aliasing() {
    for version in [0, 3, u32::MAX] {
        assert!(read(&fixture(version)).is_err());
    }
    let memory = fixture(2);
    for address in [0, BASE - 1, BASE + 0x2000 - 3, u64::MAX] {
        assert!(HybridMetadata::read(&memory.0, address, BASE, 0x2000).is_err());
    }
    assert!(HybridMetadata::read(&memory.0, BASE + 0x100, BASE, 0x15B).is_err());
}

#[test]
fn malformed_code_tables_reject_reserved_tags_lengths_order_and_counts() {
    for (at, value) in [
        (HEADER + 4, 0),
        (HEADER + 4, u32::MAX),
        (HEADER + 8, 65_537),
        (HEADER + 8, u32::MAX),
        (0x200, 0x1003),
        (0x204, 0),
        (0x204, u32::MAX),
        (0x208, 0x1001),
        (0x208, 0x1005),
    ] {
        let mut memory = fixture(2);
        memory.u32(at, value);
        assert!(read(&memory).is_err(), "field {at:#x} value {value:#x}");
    }
}

#[test]
fn table_contents_must_be_readable_even_when_the_declared_extent_fits() {
    let memory = fixture(2);
    let truncated = &memory.0[..0x210];
    assert!(matches!(
        HybridMetadata::read(truncated, BASE + 0x100, BASE, 0x2000),
        Err(HybridError::Read(_))
    ));
}

#[test]
fn entry_redirection_and_helper_pointer_extents_are_checked() {
    for (at, value) in [
        (HEADER + 20, 0x1FF9),
        (HEADER + 40, 0x2000),
        (0x240, 0x1030),
        (0x244, 0x2001),
        (0x248, 0x2000),
        (0x280, 0x2000),
        (0x284, u32::MAX),
        (HEADER + 48, u32::MAX),
        (HEADER + 52, u32::MAX),
    ] {
        let mut memory = fixture(2);
        memory.u32(at, value);
        assert!(read(&memory).is_err(), "field {at:#x} value {value:#x}");
    }
    let mut memory = fixture(2);
    memory.u32(HEADER + 20, 0x1FF8);
    assert_eq!(read(&memory).unwrap().dispatch_slots[0], 0x1FF8);
}

#[test]
fn empty_tables_are_valid_and_do_not_classify_an_address() {
    let mut memory = fixture(1);
    for at in [4, 8, 12, 16, 48, 52] {
        memory.u32(HEADER + at, 0);
    }
    let metadata = read(&memory).unwrap();
    assert!(metadata.code.is_empty());
    assert!(metadata.entries.is_empty());
    assert!(metadata.redirections.is_empty());
    assert_eq!(metadata.code_kind(0), None);
}

#[test]
fn load_config_chpe_pointer_obeys_both_declared_extents_and_pointer_widths() {
    for (kind, offset, width) in [(PeKind::Pe32, 124, 4), (PeKind::Pe32Plus, 200, 8)] {
        for (declared, directory, present) in [
            (offset + width - 1, offset + width, false),
            (offset + width, offset + width - 1, false),
            (offset + width, offset + width, true),
        ] {
            let mut memory = Mem::new(0x1000);
            memory.u32(HEADER, declared);
            if width == 8 {
                memory.u64(HEADER + offset as usize, BASE + 0x300);
            } else {
                memory.u32(HEADER + offset as usize, 0x40_0300);
            }
            let config = LoadConfig::read(
                &memory.0,
                kind,
                DataDirectory {
                    rva: HEADER as u32,
                    size: directory,
                },
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                config.chpe_metadata_pointer,
                present.then_some(if width == 8 { BASE + 0x300 } else { 0x40_0300 })
            );
        }
    }
}

#[test]
fn all_eight_helper_slots_use_their_declared_noncontiguous_header_fields() {
    for version in [1, 2] {
        let mut memory = fixture(version);
        for (index, offset) in [20, 24, 28, 32, 36, 56, 60, 72].into_iter().enumerate() {
            memory.u32(HEADER + offset, 0x1800 + index as u32 * 8);
        }
        memory.u32(HEADER + 40, 0x1100);
        let metadata = read(&memory).unwrap();
        assert_eq!(
            metadata.dispatch_slots,
            [
                0x1800, 0x1808, 0x1810, 0x1818, 0x1820, 0x1828, 0x1830, 0x1838
            ]
        );
        assert_eq!(metadata.alternate_entry, 0x1100);
        for offset in [20, 24, 28, 32, 36, 56, 60, 72] {
            let mut malformed = fixture(version);
            malformed.u32(HEADER + offset, 0x1ff9);
            assert!(read(&malformed).is_err(), "helper field {offset}");
        }
    }
}

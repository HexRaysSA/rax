//! Address-space and VMA semantics. Expected behavior follows Linux
//! `mmap(2)`, `munmap(2)`, `mprotect(2)`, and `mremap(2)`.

use super::*;

const P: u64 = PAGE_SIZE;
const RW: Perms = Perms::READ.union(Perms::WRITE);
const RX: Perms = Perms::READ.union(Perms::EXEC);

fn space() -> AddressSpace {
    AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 64 * P,
        reserved_phys: vec![],
    })
    .unwrap()
}

fn anon_vma(start: u64, end: u64, perms: Perms) -> Vma {
    Vma {
        start,
        end,
        perms,
        backing: Backing::Anonymous,
        shared: false,
        name: None,
        flags: 0,
    }
}

fn ranges(m: &VmaMap) -> Vec<(u64, u64, Perms)> {
    m.iter().map(|v| (v.start, v.end, v.perms)).collect()
}

// ---------------------------------------------------------------- VmaMap

#[test]
fn vma_insert_replaces_and_splits_overlaps() {
    let mut m = VmaMap::new();
    m.insert(anon_vma(0x1000, 0x5000, Perms::READ));
    let replaced = m.insert(anon_vma(0x2000, 0x3000, RW));
    assert_eq!(replaced.len(), 1);
    assert_eq!((replaced[0].start, replaced[0].end), (0x2000, 0x3000));
    assert_eq!(
        ranges(&m),
        vec![
            (0x1000, 0x2000, Perms::READ),
            (0x2000, 0x3000, RW),
            (0x3000, 0x5000, Perms::READ)
        ]
    );
}

#[test]
fn vma_remove_splits_and_reports_pieces() {
    let mut m = VmaMap::new();
    m.insert(anon_vma(0x1000, 0x3000, Perms::READ));
    m.insert(anon_vma(0x4000, 0x6000, RW));
    let removed = m.remove(0x2000, 0x5000);
    assert_eq!(
        removed.iter().map(|v| (v.start, v.end)).collect::<Vec<_>>(),
        vec![(0x2000, 0x3000), (0x4000, 0x5000)]
    );
    assert_eq!(
        ranges(&m),
        vec![(0x1000, 0x2000, Perms::READ), (0x5000, 0x6000, RW)]
    );
    assert!(m.remove(0x8000, 0x9000).is_empty());
}

#[test]
fn vma_source_offsets_follow_splits() {
    let src: Arc<dyn PageSource> = Arc::new(BytesSource::new(vec![0u8; 0x10000].into()));
    let mut m = VmaMap::new();
    m.insert(Vma {
        backing: Backing::Source {
            source: src,
            offset: 0x3000,
        },
        ..anon_vma(0x10000, 0x14000, Perms::READ)
    });
    m.update(0x11000, 0x12000, |v| v.perms = RW);
    let offs: Vec<u64> = m.iter().map(|v| v.backing.offset()).collect();
    assert_eq!(offs, vec![0x3000, 0x4000, 0x5000]);
    // Restoring the permission lets the pieces coalesce again.
    m.update(0x11000, 0x12000, |v| v.perms = Perms::READ);
    m.coalesce(0x10000, 0x14000);
    assert_eq!(ranges(&m), vec![(0x10000, 0x14000, Perms::READ)]);
}

#[test]
fn vma_coalesce_requires_matching_attributes() {
    let mut m = VmaMap::new();
    m.insert(anon_vma(0x1000, 0x2000, RW));
    m.insert(anon_vma(0x2000, 0x3000, RW));
    m.insert(anon_vma(0x3000, 0x4000, Perms::READ));
    m.insert(anon_vma(0x5000, 0x6000, Perms::READ));
    m.coalesce(0, 0x10000);
    assert_eq!(
        ranges(&m),
        vec![
            (0x1000, 0x3000, RW),
            (0x3000, 0x4000, Perms::READ),
            (0x5000, 0x6000, Perms::READ)
        ]
    );
}

#[test]
fn vma_coverage_and_lookup() {
    let mut m = VmaMap::new();
    m.insert(anon_vma(0x1000, 0x3000, RW));
    m.insert(anon_vma(0x3000, 0x4000, RW));
    m.insert(anon_vma(0x6000, 0x7000, RW));
    assert!(m.covers(0x1000, 0x4000));
    assert!(m.covers(0x1800, 0x3800));
    assert!(!m.covers(0x1000, 0x5000));
    assert!(!m.covers(0x4000, 0x7000));
    assert!(m.is_free(0x4000, 0x6000));
    assert!(!m.is_free(0x4000, 0x6001));
    assert_eq!(m.find(0x2fff).map(|v| v.start), Some(0x1000));
    assert!(m.find(0x4000).is_none());
    assert!(m.find(0x7000).is_none());
}

#[test]
fn vma_find_free_top_down_prefers_highest_gap() {
    let mut m = VmaMap::new();
    m.insert(anon_vma(0x10000, 0x20000, RW));
    m.insert(anon_vma(0x30000, 0x40000, RW));
    // Whole window free above the highest VMA.
    assert_eq!(m.find_free_top_down(0x1000, P, 0, 0x50000), Some(0x4f000));
    // Highest gap that fits under a lower limit.
    assert_eq!(m.find_free_top_down(0x1000, P, 0, 0x30000), Some(0x2f000));
    // An exact fit in the middle gap wins over the lower gap.
    assert_eq!(m.find_free_top_down(0x10000, P, 0, 0x40000), Some(0x20000));
    // Under a limit that shrinks the middle gap, only the lowest gap fits.
    assert_eq!(m.find_free_top_down(0x10000, P, 0, 0x2f000), Some(0x0));
    // Alignment is honored within the gap.
    assert_eq!(
        m.find_free_top_down(0x1000, 0x8000, 0x20000, 0x2c000),
        Some(0x28000)
    );
    // No gap is large enough.
    assert_eq!(m.find_free_top_down(0x10001, P, 0x10000, 0x40000), None);
    // A VMA straddling the upper limit bounds the gap below it.
    assert_eq!(m.find_free_top_down(0x1000, P, 0, 0x38000), Some(0x2f000));
    assert_eq!(m.find_free_top_down(0, P, 0, 0x1000), None);
}

#[test]
fn vma_find_free_bottom_up_prefers_lowest_gap() {
    let mut m = VmaMap::new();
    m.insert(anon_vma(0x10000, 0x20000, RW));
    m.insert(anon_vma(0x30000, 0x40000, RW));
    assert_eq!(m.find_free_bottom_up(0x1000, P, 0, 0x50000), Some(0));
    assert_eq!(
        m.find_free_bottom_up(0x10000, P, 0x1000, 0x50000),
        Some(0x20000)
    );
    // Every gap below 0x50000 is exactly 0x10000 bytes or smaller.
    assert_eq!(m.find_free_bottom_up(0x10001, P, 0x1000, 0x50000), None);
    assert_eq!(
        m.find_free_bottom_up(0x10001, P, 0x1000, 0x60000),
        Some(0x40000)
    );
    assert_eq!(
        m.find_free_bottom_up(0x1000, 0x10000, 0x21000, 0x50000),
        Some(0x40000)
    );
    assert_eq!(m.find_free_bottom_up(0x20000, P, 0x40000, 0x50000), None);
}

// ---------------------------------------------------------- AddressSpace

#[test]
fn rejects_invalid_configuration_and_ranges() {
    assert!(matches!(
        AddressSpace::new(SpaceConfig {
            va_limit: (1 << 48) + P,
            arena_bytes: P,
            reserved_phys: vec![],
        }),
        Err(MmError::InvalidArgument(_))
    ));
    let s = space();
    let m = || Mapping::anonymous(RW);
    assert!(matches!(
        s.map(0x1001, P, m()),
        Err(MmError::InvalidArgument(_))
    ));
    assert!(matches!(
        s.map(0x1000, 0, m()),
        Err(MmError::InvalidArgument(_))
    ));
    assert_eq!(s.map((1 << 47) - P, 2 * P, m()), Err(MmError::OutOfRange));
    assert_eq!(s.map(u64::MAX & !0xFFF, P, m()), Err(MmError::OutOfRange));
}

#[test]
fn anonymous_pages_are_zero_and_populated_on_first_touch() {
    let s = space();
    s.map(0x10000, 4 * P, Mapping::anonymous(RW)).unwrap();
    assert_eq!(s.resident_pages(), 0, "mapping alone populates nothing");
    let mut b = [0xAAu8; 16];
    s.read(0x10ff8, &mut b).unwrap();
    assert_eq!(b, [0; 16]);
    assert_eq!(s.resident_pages(), 2, "a page-crossing read populates both");
    s.write(0x13000, b"hello").unwrap();
    let mut out = [0u8; 5];
    s.read(0x13000, &mut out).unwrap();
    assert_eq!(&out, b"hello");
    assert_eq!(s.resident_pages(), 3);
}

#[test]
fn faults_distinguish_unmapped_from_protection() {
    let s = space();
    s.map(0x10000, P, Mapping::anonymous(Perms::READ)).unwrap();
    s.map(0x11000, P, Mapping::anonymous(Perms::empty()))
        .unwrap();
    let w = s.translate(0x10010, MemoryAccessKind::Write).unwrap_err();
    assert_eq!(
        (w.address, w.kind, w.access),
        (
            0x10010,
            MemoryFaultKind::Permission,
            MemoryAccessKind::Write
        )
    );
    // The same classification after the page was populated by a read.
    s.translate(0x10000, MemoryAccessKind::Read).unwrap();
    assert_eq!(
        s.translate(0x10010, MemoryAccessKind::Write)
            .unwrap_err()
            .kind,
        MemoryFaultKind::Permission
    );
    assert_eq!(
        s.translate(0x10000, MemoryAccessKind::Fetch)
            .unwrap_err()
            .kind,
        MemoryFaultKind::Permission
    );
    // PROT_NONE pages are mapped but inaccessible.
    assert_eq!(
        s.translate(0x11000, MemoryAccessKind::Read)
            .unwrap_err()
            .kind,
        MemoryFaultKind::Permission
    );
    assert_eq!(
        s.classify_fault(0x11000, MemoryAccessKind::Read),
        FaultClass::Protection
    );
    let u = s.translate(0x12000, MemoryAccessKind::Read).unwrap_err();
    assert_eq!(u.kind, MemoryFaultKind::Unmapped);
    assert_eq!(
        s.classify_fault(0x12000, MemoryAccessKind::Read),
        FaultClass::Unmapped
    );
    assert_eq!(
        s.translate(1 << 47, MemoryAccessKind::Read)
            .unwrap_err()
            .kind,
        MemoryFaultKind::Unmapped
    );
}

#[test]
fn unmap_releases_frames_and_tolerates_holes() {
    let s = space();
    s.map(0x10000, 4 * P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10000, &[1u8; 4 * P as usize]).unwrap();
    assert_eq!(s.resident_pages(), 4);
    // Linux munmap succeeds across unmapped holes.
    s.unmap(0x11000, 8 * P).unwrap();
    assert_eq!(s.resident_pages(), 1);
    assert!(s.is_free(0x11000, 3 * P));
    assert_eq!(
        s.translate(0x11000, MemoryAccessKind::Read)
            .unwrap_err()
            .kind,
        MemoryFaultKind::Unmapped
    );
    let mut b = [0u8; 1];
    s.read(0x10000, &mut b).unwrap();
    assert_eq!(b[0], 1, "the surviving page keeps its contents");
}

#[test]
fn remapping_over_populated_pages_discards_contents() {
    let s = space();
    s.map(0x10000, 2 * P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10000, &[7u8; 2 * P as usize]).unwrap();
    s.map(0x10000, P, Mapping::anonymous(RW)).unwrap();
    let mut b = [0xFFu8; 2];
    s.read(0x10fff, &mut b).unwrap();
    assert_eq!(b, [0, 7], "MAP_FIXED replacement yields fresh zero pages");
    assert_eq!(s.resident_pages(), 2);
}

#[test]
fn freed_frames_are_zeroed_before_reuse() {
    let s = space();
    s.map(0x10000, P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10000, &[0x5Au8; P as usize]).unwrap();
    s.unmap(0x10000, P).unwrap();
    s.map(0x20000, P, Mapping::anonymous(RW)).unwrap();
    let mut b = vec![0xFFu8; P as usize];
    s.read(0x20000, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 0));
}

#[test]
fn protect_updates_populated_pages_and_requires_full_coverage() {
    let s = space();
    s.map(0x10000, 2 * P, Mapping::anonymous(RW)).unwrap();
    s.map(0x13000, P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10000, b"x").unwrap();
    s.protect(0x10000, 2 * P, Perms::READ).unwrap();
    assert_eq!(
        s.translate(0x10000, MemoryAccessKind::Write)
            .unwrap_err()
            .kind,
        MemoryFaultKind::Permission
    );
    // A range with a hole fails as a whole and changes nothing.
    assert_eq!(
        s.protect(0x10000, 4 * P, RW),
        Err(MmError::NotMapped { addr: 0x12000 })
    );
    assert_eq!(s.vma_at(0x10000).unwrap().perms, Perms::READ);
    assert_eq!(s.vma_at(0x13000).unwrap().perms, RW);
    s.protect(0x11000, P, RW).unwrap();
    assert_eq!(
        s.vma_snapshot()
            .iter()
            .map(|v| (v.start, v.end, v.perms))
            .collect::<Vec<_>>(),
        vec![
            (0x10000, 0x11000, Perms::READ),
            (0x11000, 0x12000, RW),
            (0x13000, 0x14000, RW)
        ]
    );
}

#[test]
fn remap_moves_pages_without_copying() {
    let s = space();
    s.map(0x10000, 2 * P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10ffe, b"abcd").unwrap();
    let resident = s.resident_pages();
    s.remap(0x10000, 2 * P, 0x40000).unwrap();
    assert_eq!(s.resident_pages(), resident);
    let mut b = [0u8; 4];
    s.read(0x40ffe, &mut b).unwrap();
    assert_eq!(&b, b"abcd");
    assert!(s.is_free(0x10000, 2 * P));
    assert!(matches!(
        s.remap(0x40000, 2 * P, 0x41000),
        Err(MmError::InvalidArgument(_))
    ));
    assert_eq!(
        s.remap(0x10000, P, 0x50000),
        Err(MmError::NotMapped { addr: 0x10000 })
    );
}

#[test]
fn source_backed_pages_follow_file_semantics() {
    let data: Vec<u8> = (0..(P + 100)).map(|i| (i % 251) as u8).collect();
    let src: Arc<dyn PageSource> = Arc::new(BytesSource::new(data.clone().into()));
    let s = space();
    s.map(
        0x20000,
        4 * P,
        Mapping {
            perms: Perms::READ,
            backing: Backing::Source {
                source: src,
                offset: 0,
            },
            shared: false,
            name: None,
            flags: 0,
        },
    )
    .unwrap();
    let mut page = vec![0u8; 2 * P as usize];
    s.read(0x20000, &mut page).unwrap();
    assert_eq!(&page[..data.len()], &data[..]);
    assert!(
        page[data.len()..].iter().all(|&b| b == 0),
        "the tail of the last partial page reads as zero"
    );
    // Pages wholly past end of file are inaccessible (SIGBUS).
    let f = s.translate(0x22000, MemoryAccessKind::Read).unwrap_err();
    assert_eq!(f.kind, MemoryFaultKind::Other);
    assert_eq!(
        s.classify_fault(0x22000, MemoryAccessKind::Read),
        FaultClass::BeyondSource
    );
}

#[test]
fn discard_refetches_pages_from_their_backing() {
    let data: Vec<u8> = (0..(2 * P)).map(|i| (i % 253) as u8).collect();
    let src: Arc<dyn PageSource> = Arc::new(BytesSource::new(data.clone().into()));
    let s = space();
    s.map(0x10000, 2 * P, Mapping::anonymous(RW)).unwrap();
    s.map(
        0x12000,
        2 * P,
        Mapping {
            perms: RW,
            backing: Backing::Source {
                source: src,
                offset: 0,
            },
            shared: false,
            name: None,
            flags: 0,
        },
    )
    .unwrap();
    s.write(0x10000, &[9u8; 4 * P as usize]).unwrap();
    assert!(s.is_resident(0x10000) && s.is_resident(0x13fff));
    let resident = s.resident_pages();
    // One call spanning an anonymous and a source-backed VMA.
    s.discard(0x11000, 2 * P).unwrap();
    assert_eq!(s.resident_pages(), resident - 2);
    assert!(!s.is_resident(0x11000) && !s.is_resident(0x12000));
    let mut b = vec![0u8; 4 * P as usize];
    s.read(0x10000, &mut b).unwrap();
    assert!(b[..P as usize].iter().all(|&x| x == 9), "outside the range");
    assert!(
        b[P as usize..2 * P as usize].iter().all(|&x| x == 0),
        "anonymous"
    );
    assert_eq!(
        &b[2 * P as usize..3 * P as usize],
        &data[..P as usize],
        "source"
    );
    assert!(
        b[3 * P as usize..].iter().all(|&x| x == 9),
        "outside the range"
    );
    // The VMAs are unchanged.
    assert_eq!(s.vma_snapshot().len(), 2);
}

#[test]
fn discard_requires_a_fully_mapped_aligned_range() {
    let s = space();
    s.map(0x10000, P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10000, b"x").unwrap();
    assert_eq!(
        s.discard(0x10000, 2 * P),
        Err(MmError::NotMapped { addr: 0x11000 })
    );
    assert!(matches!(
        s.discard(0x10001, P),
        Err(MmError::InvalidArgument(_))
    ));
    assert!(s.is_resident(0x10000), "a failed discard changes nothing");
    assert!(!s.is_resident(1 << 47), "beyond the address space");
}

#[test]
fn discarding_executable_pages_logs_a_code_change() {
    let s = space();
    s.map(0x10000, P, Mapping::anonymous(RX)).unwrap();
    s.map(0x20000, P, Mapping::anonymous(RW)).unwrap();
    let e0 = s.code_epoch();
    s.discard(0x20000, P).unwrap();
    assert_eq!(s.code_changes_since(e0).0, CodeChanges::None);
    s.discard(0x10000, P).unwrap();
    assert_eq!(
        s.code_changes_since(e0).0,
        CodeChanges::Ranges(vec![(0x10000, P)])
    );
}

#[test]
fn raw_access_ignores_permissions_but_not_mapping() {
    let s = space();
    s.map(0x10000, P, Mapping::anonymous(Perms::READ)).unwrap();
    assert!(s.write(0x10000, b"no").is_err());
    s.write_raw(0x10000, b"ok").unwrap();
    let mut b = [0u8; 2];
    s.read(0x10000, &mut b).unwrap();
    assert_eq!(&b, b"ok");
    assert_eq!(
        s.write_raw(0x20000, b"x").unwrap_err().kind,
        MemoryFaultKind::Unmapped
    );
}

#[test]
fn failed_host_write_changes_nothing() {
    let s = space();
    s.map(0x10000, P, Mapping::anonymous(RW)).unwrap();
    s.map(0x11000, P, Mapping::anonymous(Perms::READ)).unwrap();
    let err = s.write(0x10ffe, b"abcd").unwrap_err();
    assert_eq!(
        (err.address, err.kind),
        (0x11000, MemoryFaultKind::Permission)
    );
    let mut b = [0xFFu8; 2];
    s.read(0x10ffe, &mut b).unwrap();
    assert_eq!(b, [0, 0]);
}

#[test]
fn read_cstr_crosses_pages_and_bounds_length() {
    let s = space();
    s.map(0x10000, 2 * P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10ffd, b"path\0").unwrap();
    assert_eq!(s.read_cstr(0x10ffd, 16).unwrap(), Some(b"path".to_vec()));
    assert_eq!(s.read_cstr(0x10ffd, 4).unwrap(), Some(b"path".to_vec()));
    assert_eq!(s.read_cstr(0x10ffd, 3).unwrap(), None);
    // An unterminated string running into unmapped memory faults.
    s.write(0x11000, &[b'a'; P as usize]).unwrap();
    assert_eq!(s.read_cstr(0x11000, 1 << 20).unwrap_err().address, 0x12000);
}

#[test]
fn code_log_tracks_changes_that_invalidate_translations() {
    let s = space();
    let e0 = s.code_epoch();
    s.map(0x10000, 2 * P, Mapping::anonymous(RX)).unwrap();
    assert_eq!(s.code_epoch(), e0, "a fresh mapping invalidates nothing");
    // Populating and writing an RWX page logs the page.
    s.protect(0x10000, P, Perms::all()).unwrap();
    assert_eq!(
        s.code_epoch(),
        e0,
        "gaining permissions invalidates nothing"
    );
    s.translate(0x10004, MemoryAccessKind::Write).unwrap();
    let (changes, e1) = s.code_changes_since(e0);
    assert_eq!(changes, CodeChanges::Ranges(vec![(0x10000, P)]));
    // Dropping execute permission logs the range.
    s.protect(0x11000, P, Perms::READ).unwrap();
    let (changes, e2) = s.code_changes_since(e1);
    assert_eq!(changes, CodeChanges::Ranges(vec![(0x11000, P)]));
    // Unmapping executable memory logs the range; non-exec does not.
    s.map(0x30000, P, Mapping::anonymous(RW)).unwrap();
    s.unmap(0x30000, P).unwrap();
    assert_eq!(s.code_changes_since(e2).0, CodeChanges::None);
    s.unmap(0x10000, P).unwrap();
    assert_eq!(
        s.code_changes_since(e2).0,
        CodeChanges::Ranges(vec![(0x10000, P)])
    );
    // Host (raw) writes into executable pages are logged too.
    s.map(0x50000, P, Mapping::anonymous(RX)).unwrap();
    let e3 = s.code_epoch();
    s.write_raw(0x50000, &[0x90]).unwrap();
    assert_eq!(
        s.code_changes_since(e3).0,
        CodeChanges::Ranges(vec![(0x50000, P)])
    );
}

#[test]
fn code_log_overflow_forces_full_invalidation() {
    let s = space();
    s.map(0x10000, P, Mapping::anonymous(Perms::all())).unwrap();
    let e0 = s.code_epoch();
    for _ in 0..(CODE_LOG_CAPACITY + 1) {
        s.translate(0x10000, MemoryAccessKind::Write).unwrap();
    }
    assert_eq!(s.code_changes_since(e0).0, CodeChanges::All);
    let (_, now) = s.code_changes_since(e0);
    assert_eq!(s.code_changes_since(now).0, CodeChanges::None);
}

#[test]
fn arena_exhaustion_is_reported_and_classified() {
    let s = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 2 * P,
        reserved_phys: vec![],
    })
    .unwrap();
    s.map(0x10000, 4 * P, Mapping::anonymous(RW)).unwrap();
    s.write(0x10000, &[1; 2 * P as usize]).unwrap();
    let f = s.translate(0x12000, MemoryAccessKind::Read).unwrap_err();
    assert_eq!(f.kind, MemoryFaultKind::Other);
    assert_eq!(
        s.classify_fault(0x12000, MemoryAccessKind::Read),
        FaultClass::OutOfMemory
    );
    // Freeing a frame makes room again.
    s.unmap(0x10000, P).unwrap();
    s.translate(0x12000, MemoryAccessKind::Read).unwrap();
}

#[test]
fn reserved_physical_frames_are_never_allocated() {
    let s = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 4 * P,
        reserved_phys: vec![(P, 2 * P)],
    })
    .unwrap();
    s.map(0x10000, 2 * P, Mapping::anonymous(RW)).unwrap();
    let a = s.translate(0x10000, MemoryAccessKind::Read).unwrap();
    let b = s.translate(0x11000, MemoryAccessKind::Read).unwrap();
    assert_eq!((a, b), (0, 3 * P));
    s.map(0x20000, P, Mapping::anonymous(RW)).unwrap();
    assert_eq!(
        s.translate(0x20000, MemoryAccessKind::Read)
            .unwrap_err()
            .kind,
        MemoryFaultKind::Other
    );
}

#[test]
fn page_table_walk_skips_absent_subtrees() {
    let t = pagetable::PageTable::new();
    let vpns = [0u64, 1, 4095, 4096, 1 << 24, (1 << 36) - 1];
    for &v in &vpns {
        t.slot(v).store(make_pte(v << 12, RW), Ordering::Release);
    }
    let mut seen = Vec::new();
    t.for_each_populated(0, 1 << 36, |v, _| seen.push(v));
    assert_eq!(seen, vpns);
    let mut seen = Vec::new();
    t.for_each_populated(2, 1 << 24, |v, _| seen.push(v));
    assert_eq!(seen, vec![4095, 4096]);
    assert_eq!(t.get(5), 0);
    assert_eq!(pagetable::pte_perms(t.get(1)), RW);
}

#[test]
fn clones_share_one_space() {
    let a = space();
    let b = a.clone();
    a.map(0x10000, P, Mapping::anonymous(RW)).unwrap();
    b.write(0x10000, b"shared").unwrap();
    let mut out = [0u8; 6];
    a.read(0x10000, &mut out).unwrap();
    assert_eq!(&out, b"shared");
    assert!(a.same_space(&b));
    assert!(!a.same_space(&space()));
}

/// Naive reference: one entry per page of a small window.
#[derive(Clone)]
struct ModelPage {
    perms: Perms,
    bytes: Vec<u8>,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn randomized_operations_match_a_reference_model() {
    const BASE: u64 = 0x100_0000;
    const PAGES: u64 = 48;
    let perms_of = |r: u64| Perms::from_bits_truncate((r & 7) as u8);
    for seed in 1..=8u64 {
        let s = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 4 * PAGES * P,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut model: Vec<Option<ModelPage>> = vec![None; PAGES as usize];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
        for step in 0..3000 {
            let first = rng.below(PAGES);
            let count = 1 + rng.below((PAGES - first).min(6));
            let addr = BASE + first * P;
            let len = count * P;
            let ctx = format!("seed {seed} step {step}");
            match rng.below(6) {
                0 => {
                    let perms = perms_of(rng.next());
                    s.map(addr, len, Mapping::anonymous(perms)).unwrap();
                    for p in first..first + count {
                        model[p as usize] = Some(ModelPage {
                            perms,
                            bytes: vec![0; P as usize],
                        });
                    }
                }
                1 => {
                    s.unmap(addr, len).unwrap();
                    for p in first..first + count {
                        model[p as usize] = None;
                    }
                }
                2 => {
                    let perms = perms_of(rng.next());
                    let hole = (first..first + count).find(|&p| model[p as usize].is_none());
                    let res = s.protect(addr, len, perms);
                    match hole {
                        Some(h) => {
                            assert_eq!(res, Err(MmError::NotMapped { addr: BASE + h * P }), "{ctx}")
                        }
                        None => {
                            res.unwrap();
                            for p in first..first + count {
                                model[p as usize].as_mut().unwrap().perms = perms;
                            }
                        }
                    }
                }
                3 => {
                    // Write a random span; expect a fault at the first page
                    // that is unmapped or not writable, and no change at all.
                    let off = rng.below(P);
                    let n = 1 + rng.below(len - off) as usize;
                    let data: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                    let a = addr + off;
                    let bad = (a / P..=(a + n as u64 - 1) / P).find(|&pg| {
                        let i = (pg - BASE / P) as usize;
                        !model[i]
                            .as_ref()
                            .is_some_and(|m| m.perms.contains(Perms::WRITE))
                    });
                    match (s.write(a, &data), bad) {
                        (Ok(()), None) => {
                            for (k, &b) in data.iter().enumerate() {
                                let va = a + k as u64;
                                let i = ((va - BASE) / P) as usize;
                                model[i].as_mut().unwrap().bytes[(va % P) as usize] = b;
                            }
                        }
                        (Err(f), Some(pg)) => {
                            assert_eq!(f.address, (pg * P).max(a), "{ctx}");
                            let i = (pg - BASE / P) as usize;
                            let expect = if model[i].is_some() {
                                MemoryFaultKind::Permission
                            } else {
                                MemoryFaultKind::Unmapped
                            };
                            assert_eq!(f.kind, expect, "{ctx}");
                        }
                        (r, b) => panic!("{ctx}: write {r:?} but model expected {b:?}"),
                    }
                }
                4 => {
                    let off = rng.below(P);
                    let n = 1 + rng.below(len - off) as usize;
                    let a = addr + off;
                    let mut buf = vec![0u8; n];
                    let bad = (a / P..=(a + n as u64 - 1) / P).find(|&pg| {
                        let i = (pg - BASE / P) as usize;
                        !model[i]
                            .as_ref()
                            .is_some_and(|m| m.perms.contains(Perms::READ))
                    });
                    match (s.read(a, &mut buf), bad) {
                        (Ok(()), None) => {
                            for (k, &b) in buf.iter().enumerate() {
                                let va = a + k as u64;
                                let i = ((va - BASE) / P) as usize;
                                assert_eq!(
                                    b,
                                    model[i].as_ref().unwrap().bytes[(va % P) as usize],
                                    "{ctx} at {va:#x}"
                                );
                            }
                        }
                        (Err(f), Some(pg)) => assert_eq!(f.address, (pg * P).max(a), "{ctx}"),
                        (r, b) => panic!("{ctx}: read {r:?} but model expected {b:?}"),
                    }
                }
                _ => {
                    // Move a fully mapped range to a disjoint destination.
                    let dst = rng.below(PAGES - count + 1);
                    let disjoint = dst + count <= first || first + count <= dst;
                    let mapped = (first..first + count).all(|p| model[p as usize].is_some());
                    if disjoint && mapped {
                        s.remap(addr, len, BASE + dst * P).unwrap();
                        let moved: Vec<_> = (first..first + count)
                            .map(|p| model[p as usize].take())
                            .collect();
                        for (k, page) in moved.into_iter().enumerate() {
                            model[(dst + k as u64) as usize] = page;
                        }
                    }
                }
            }
            // The VMA view agrees with the model page by page.
            if step % 97 == 0 {
                for p in 0..PAGES {
                    let v = s.vma_at(BASE + p * P).map(|v| v.perms);
                    assert_eq!(
                        v,
                        model[p as usize].as_ref().map(|m| m.perms),
                        "{ctx} page {p}"
                    );
                }
            }
        }
        // Every frame is accounted for: resident pages never exceed mapped pages.
        let mapped = model.iter().filter(|m| m.is_some()).count() as u64;
        assert!(s.resident_pages() <= mapped);
    }
}

// ------------------------------------------------------- Shared objects

#[cfg(unix)]
mod shared_objects {
    use super::*;
    use std::os::unix::fs::FileExt;

    fn space() -> AddressSpace {
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 16 << 20,
            reserved_phys: vec![],
        })
        .unwrap()
    }

    /// A temporary host file holding `bytes`, open for reading and writing.
    fn file(tag: &str, bytes: &[u8]) -> (std::path::PathBuf, std::fs::File) {
        let path = std::env::temp_dir().join(format!("rax-mm-{}-{tag}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (path, f)
    }

    fn shared(object: &Arc<SharedObject>, offset: u64, perms: Perms) -> Mapping {
        Mapping {
            perms,
            backing: Backing::Shared {
                object: object.clone(),
                offset,
            },
            shared: true,
            name: None,
            flags: 0,
        }
    }

    fn byte(s: &AddressSpace, addr: u64) -> u8 {
        let mut b = [0u8];
        s.read(addr, &mut b).unwrap();
        b[0]
    }

    #[test]
    fn shared_file_pages_are_the_files_own() {
        let (path, f) = file("own", &[0x11; 3 * P as usize]);
        let s = space();
        let obj = Arc::new(SharedObject::file(f.try_clone().unwrap(), true).unwrap());
        // Pages at file offsets P, 2P, and 3P (past the end).
        s.map(0x10000, 3 * P, shared(&obj, P, RW)).unwrap();
        assert_eq!(byte(&s, 0x10000), 0x11);
        // Stores reach the file; the file's changes reach the mapping.
        s.write(0x10000, &[0xaa]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap()[P as usize], 0xaa);
        f.write_all_at(&[0xbb], P + 1).unwrap();
        assert_eq!(byte(&s, 0x10001), 0xbb);
        // A second mapping of the object shares the pages and the extent.
        s.map(0x40000, P, shared(&obj, P, Perms::READ)).unwrap();
        assert_eq!(byte(&s, 0x40000), 0xaa);
        assert_eq!(s.attached_extents(), 1);
        assert_eq!(s.resident_pages(), 2);
        s.sync(0x10000, 3 * P).unwrap();
        // A page wholly past the end is a bus error.
        let mut b = [0u8];
        assert!(s.read(0x10000 + 2 * P, &mut b).is_err());
        assert_eq!(
            s.classify_fault(0x10000 + 2 * P, MemoryAccessKind::Read),
            FaultClass::BeyondSource
        );
        // Once no page points into it, the extent is detached; the file
        // keeps the stores.
        s.unmap(0x10000, 3 * P).unwrap();
        assert_eq!(s.attached_extents(), 1);
        s.unmap(0x40000, P).unwrap();
        assert_eq!((s.attached_extents(), s.resident_pages()), (0, 0));
        assert_eq!(std::fs::read(&path).unwrap()[P as usize], 0xaa);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_only_objects_refuse_every_store() {
        let (path, _) = file("ro", &[0x22; P as usize]);
        let ro = std::fs::File::open(&path).unwrap();
        let s = space();
        let obj = Arc::new(SharedObject::file(ro, false).unwrap());
        s.map(0x10000, P, shared(&obj, 0, Perms::READ)).unwrap();
        assert_eq!(byte(&s, 0x10000), 0x22);
        // A forced write cannot store into a file not open for writing.
        let err = s.write_raw(0x10000, &[1]).unwrap_err();
        assert_eq!(err.kind, MemoryFaultKind::Permission);
        assert!(s.write(0x10000, &[1]).is_err());
        // Nor before the page is populated.
        let s2 = space();
        s2.map(0x10000, P, shared(&obj, 0, Perms::READ)).unwrap();
        assert!(s2.write_raw(0x10000, &[1]).is_err());
        assert_eq!(std::fs::read(&path).unwrap()[0], 0x22);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_read_only_extent_is_reattached_for_writing() {
        let (path, f) = file("upgrade", &[0x33; P as usize]);
        let ro = std::fs::File::open(&path).unwrap();
        let s = space();
        let r = Arc::new(SharedObject::file(ro, false).unwrap());
        let w = Arc::new(SharedObject::file(f, true).unwrap());
        s.map(0x10000, P, shared(&r, 0, Perms::READ)).unwrap();
        assert_eq!(byte(&s, 0x10000), 0x33);
        s.map(0x20000, P, shared(&w, 0, RW)).unwrap();
        s.write(0x20000, &[0x44]).unwrap();
        // One extent, now writable, seen through both mappings.
        assert_eq!(s.attached_extents(), 1);
        assert_eq!(byte(&s, 0x10000), 0x44);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn anonymous_objects_are_zero_and_shared_between_mappings() {
        let s = space();
        let obj = Arc::new(SharedObject::anonymous(2 * P).unwrap());
        s.map(0x10000, 2 * P, shared(&obj, 0, RW)).unwrap();
        s.map(0x30000, 2 * P, shared(&obj, 0, RW)).unwrap();
        assert_eq!(byte(&s, 0x10000 + P), 0);
        s.write(0x10000 + P, &[7]).unwrap();
        assert_eq!(byte(&s, 0x30000 + P), 7);
        // A moved range keeps its pages.
        s.remap(0x10000, 2 * P, 0x50000).unwrap();
        assert_eq!(byte(&s, 0x50000 + P), 7);
        s.write(0x50000, &[9]).unwrap();
        assert_eq!(byte(&s, 0x30000), 9);
        // Discarding re-reads the object: shared contents stay.
        s.discard(0x50000, 2 * P).unwrap();
        assert_eq!(byte(&s, 0x50000), 9);
        assert_eq!(s.attached_extents(), 1);
    }

    #[test]
    fn extents_and_frames_share_the_arena_without_overlap() {
        let arena = FrameArena::new(2 * EXTENT, &[]).unwrap();
        let e = arena.alloc_extent().unwrap();
        assert_eq!(e, EXTENT);
        assert!(arena.is_extent(e) && !arena.is_extent(e - P));
        // The frames below fill up to the extent, not into it.
        let frames: Vec<u64> = (0..EXTENT / P)
            .map(|_| arena.alloc_zeroed().unwrap())
            .collect();
        assert!(frames.iter().all(|&f| f < e));
        assert!(arena.alloc_zeroed().is_err());
        assert!(arena.alloc_extent().is_err());
        // A freed extent is reused.
        arena.free_extent(e);
        assert_eq!(arena.alloc_extent().unwrap(), e);
        // An arena smaller than an extent still hands out frames.
        let small = FrameArena::new(4 * P, &[]).unwrap();
        assert!(small.alloc_zeroed().is_ok());
        assert!(small.alloc_extent().is_err());
    }
}

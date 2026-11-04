use super::super::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    file: Option<File>,
    path: PathBuf,
}
impl Fixture {
    fn new(bytes: u64) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rax-file-cow-{}-{}.dat",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(bytes).unwrap();
        file.write_all(&[0x11]).unwrap();
        Self {
            file: Some(file),
            path,
        }
    }
    fn object(&self, writable: bool) -> Arc<SharedObject> {
        let file = OpenOptions::new()
            .read(true)
            .write(writable)
            .open(&self.path)
            .unwrap();
        Arc::new(SharedObject::file(file, writable).unwrap())
    }
    fn write(&mut self, offset: u64, value: u8) {
        let file = self.file.as_mut().unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[value]).unwrap();
    }
    fn read(&mut self, offset: u64) -> u8 {
        let file = self.file.as_mut().unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        byte[0]
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.file.take());
        std::fs::remove_file(&self.path).unwrap();
    }
}
fn memory() -> AddressSpace {
    AddressSpace::new(SpaceConfig {
        va_limit: 1 << 32,
        arena_bytes: 8 << 20,
        reserved_phys: vec![],
    })
    .unwrap()
}
fn view(object: Arc<SharedObject>, shared: bool) -> Mapping {
    Mapping {
        perms: Perms::READ | Perms::WRITE,
        backing: Backing::Shared { object, offset: 0 },
        shared,
        name: None,
        flags: 0,
    }
}
fn private_map(space: &AddressSpace, at: u64, len: u64, mapping: Mapping) {
    space.map_copy_on_write(at, len, mapping).unwrap();
}
fn byte(space: &AddressSpace, at: u64) -> u8 {
    let mut value = [0];
    space.read(at, &mut value).unwrap();
    value[0]
}

#[test]
fn copied_page_query_splits_sparse_and_adjacent_runs_without_populating_frames() {
    let file = Fixture::new(8 * PAGE_SIZE);
    let space = memory();
    let base = 0x10000;
    private_map(&space, base, 8 * PAGE_SIZE, view(file.object(false), false));
    assert_eq!(
        space.private_copy_run(base, 8 * PAGE_SIZE),
        (false, 8 * PAGE_SIZE)
    );
    space.write(base + 3 * PAGE_SIZE, &[0x33]).unwrap();
    space.write(base + 4 * PAGE_SIZE, &[0x44]).unwrap();
    space.write(base + 7 * PAGE_SIZE, &[0x77]).unwrap();
    assert_eq!(
        space.private_copy_run(base, 8 * PAGE_SIZE),
        (false, 3 * PAGE_SIZE)
    );
    assert_eq!(
        space.private_copy_run(base + 3 * PAGE_SIZE, 5 * PAGE_SIZE),
        (true, 2 * PAGE_SIZE)
    );
    assert_eq!(
        space.private_copy_run(base + 5 * PAGE_SIZE, 3 * PAGE_SIZE),
        (false, 2 * PAGE_SIZE)
    );
    assert_eq!(
        space.private_copy_run(base + 7 * PAGE_SIZE, PAGE_SIZE),
        (true, PAGE_SIZE)
    );
    assert_eq!(
        space.acquired_private_bytes(base, 8 * PAGE_SIZE),
        3 * PAGE_SIZE
    );
}

#[test]
fn file_private_views_observe_live_updates_until_individual_first_writes() {
    // Native coherence phases: all views 11 -> external22; private A33,
    // untouched B22; later external55 leaves A33 and advances B55.
    let mut file = Fixture::new(8192);
    let object = file.object(true);
    let space = memory();
    space
        .map(0x10000, 4096, view(object.clone(), true))
        .unwrap();
    private_map(&space, 0x20000, 4096, view(object.clone(), false));
    private_map(&space, 0x30000, 4096, view(object, false));
    for at in [0x10000, 0x20000, 0x30000] {
        assert_eq!(byte(&space, at), 0x11);
    }
    file.write(0, 0x22);
    for at in [0x10000, 0x20000, 0x30000] {
        assert_eq!(byte(&space, at), 0x22);
    }
    space.write(0x20000, &[0x33]).unwrap();
    assert_eq!(byte(&space, 0x20000), 0x33);
    assert_eq!(
        byte(&space, 0x10000),
        0x22,
        "private write changed a shared alias"
    );
    assert_eq!(
        byte(&space, 0x30000),
        0x22,
        "private write changed another private view"
    );
    assert_eq!(file.read(0), 0x22, "private write reached the host file");
    file.write(0, 0x55);
    assert_eq!(byte(&space, 0x20000), 0x33);
    assert_eq!(byte(&space, 0x30000), 0x55);
    space.write(0x30000, &[0x55]).unwrap();
    file.write(0, 0x66);
    assert_eq!(
        byte(&space, 0x30000),
        0x55,
        "an identical-value store must still acquire a private page"
    );
    assert_eq!(byte(&space, 0x10000), 0x66);
}

#[test]
fn file_private_readonly_backing_copies_and_keeps_ordinary_shared_raw_write_denied() {
    let mut file = Fixture::new(8192);
    let object = file.object(false);
    let space = memory();
    private_map(&space, 0x10000, 4096, view(object.clone(), false));
    let mut ordinary = view(object, true);
    ordinary.perms = Perms::READ;
    space.map(0x20000, 4096, ordinary).unwrap();
    assert_eq!(byte(&space, 0x10000), 0x11);
    assert_eq!(space.acquired_private_bytes(0x10000, 4096), 0);
    space.write(0x10000, &[0x33]).unwrap();
    assert_eq!(space.acquired_private_bytes(0x10000, 4096), 4096);
    assert!(space.write_raw(0x20000, &[0x44]).is_err());
    assert_eq!(file.read(0), 0x11);
    file.write(0, 0x55);
    assert_eq!(byte(&space, 0x10000), 0x33);
    assert_eq!(byte(&space, 0x20000), 0x55);
}

#[test]
fn file_private_initial_store_zero_fills_partial_tail_without_extending_file() {
    let mut file = Fixture::new(1);
    let space = memory();
    private_map(&space, 0x10000, 4096, view(file.object(false), false));
    space.write(0x10fff, &[0x77]).unwrap();
    assert_eq!(byte(&space, 0x10000), 0x11);
    assert_eq!(byte(&space, 0x10001), 0);
    assert_eq!(byte(&space, 0x10ffe), 0);
    assert_eq!(byte(&space, 0x10fff), 0x77);
    assert_eq!(file.file.as_ref().unwrap().metadata().unwrap().len(), 1);
    assert_eq!(file.read(0), 0x11);
    assert_eq!(space.resident_pages(), 1);
    assert_eq!(space.attached_extents(), 0);
}

#[test]
fn file_private_policy_and_charges_survive_protect_remap_and_discard() {
    let mut file = Fixture::new(8192);
    let space = memory();
    private_map(&space, 0x10000, 8192, view(file.object(false), false));
    assert_eq!(byte(&space, 0x10000), 0x11);
    space.protect(0x10000, 4096, Perms::READ).unwrap();
    assert!(space.write(0x10000, &[0x33]).is_err());
    assert_eq!(space.acquired_private_bytes(0x10000, 8192), 0);
    space.write_raw(0x10000, &[0x33]).unwrap();
    space
        .protect(0x10000, 4096, Perms::READ | Perms::WRITE)
        .unwrap();
    file.write(0, 0x22);
    assert_eq!(byte(&space, 0x10000), 0x33);
    space.remap(0x10000, 8192, 0x50000).unwrap();
    assert!(space.read(0x10000, &mut [0]).is_err());
    assert_eq!(space.private_copy_capacity(0x50000, 8192), 8192);
    assert_eq!(space.acquired_private_bytes(0x50000, 8192), 4096);
    file.write(4096, 0x66);
    assert_eq!(byte(&space, 0x51000), 0x66);
    space.write(0x51000, &[0x77]).unwrap();
    assert_eq!(file.read(4096), 0x66);
    space.discard(0x50000, 8192).unwrap();
    assert_eq!(space.acquired_private_bytes(0x50000, 8192), 0);
    assert_eq!(byte(&space, 0x50000), 0x22);
    assert_eq!(byte(&space, 0x51000), 0x66);
    space.write(0x51000, &[0x88]).unwrap();
    assert_eq!(file.read(4096), 0x66);
    space.unmap(0x50000, 8192).unwrap();
    assert_eq!(space.resident_pages(), 0);
    assert_eq!(space.attached_extents(), 0);
    assert_eq!(space.private_copy_capacity(0x50000, 8192), 0);
}

#[test]
fn file_private_replacement_removes_only_replaced_copy_policy() {
    let mut file = Fixture::new(8192);
    let space = memory();
    private_map(&space, 0x10000, 8192, view(file.object(true), false));
    space
        .map(
            0x10000,
            4096,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    assert_eq!(space.private_copy_capacity(0x10000, 8192), 4096);
    space.write(0x10000, &[0xaa]).unwrap();
    assert_eq!(file.read(0), 0x11);
    file.write(4096, 0x44);
    assert_eq!(byte(&space, 0x11000), 0x44);
    space.write(0x11000, &[0x55]).unwrap();
    assert_eq!(file.read(4096), 0x44);
    assert_eq!(space.acquired_private_bytes(0x10000, 8192), 4096);
}

#[test]
fn file_private_invalid_mapping_and_allocation_failure_preserve_old_state() {
    let mut file = Fixture::new(4096);
    let space = memory();
    space
        .map(
            0x10000,
            4096,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    space.write(0x10000, &[0xaa]).unwrap();
    assert!(
        space
            .map_copy_on_write(0x10000, 4096, Mapping::anonymous(Perms::READ))
            .is_err()
    );
    assert!(
        space
            .map_copy_on_write(0x10000, 4096, view(file.object(true), true))
            .is_err()
    );
    assert_eq!(byte(&space, 0x10000), 0xaa);
    assert_eq!(space.private_copy_capacity(0x10000, 4096), 0);
    private_map(&space, 0x20000, 4096, view(file.object(true), false));
    assert_eq!(byte(&space, 0x20000), 0x11);
    space
        .map(
            0x100000,
            8 << 20,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    let mut exhausted = false;
    for at in (0x100000..0x900000).step_by(4096) {
        if space.write(at, &[1]).is_err() {
            exhausted = true;
            break;
        }
    }
    assert!(exhausted, "fixture must actually exhaust the frame arena");
    let resident = space.resident_pages();
    assert!(space.write(0x20000, &[0x33]).is_err());
    assert_eq!(space.resident_pages(), resident);
    assert_eq!(space.acquired_private_bytes(0x20000, 4096), 0);
    assert_eq!(byte(&space, 0x20000), 0x11);
    assert_eq!(file.read(0), 0x11);
    space.unmap(0x100000, 4096).unwrap();
    space.write(0x20000, &[0x33]).unwrap();
    assert_eq!(byte(&space, 0x20000), 0x33);
    assert_eq!(file.read(0), 0x11);
}

#[test]
fn file_private_beyond_eof_failure_has_no_frame_or_charge_and_can_retry_after_growth() {
    let mut file = Fixture::new(1);
    file.file.as_ref().unwrap().set_len(0).unwrap();
    let space = memory();
    private_map(&space, 0x10000, 4096, view(file.object(false), false));
    assert!(space.write(0x10000, &[0x33]).is_err());
    assert_eq!(space.resident_pages(), 0);
    assert_eq!(space.acquired_private_bytes(0x10000, 4096), 0);
    file.write(0, 0x11);
    space.write(0x10000, &[0x33]).unwrap();
    assert_eq!(byte(&space, 0x10000), 0x33);
    assert_eq!(file.read(0), 0x11);
}

#[test]
fn file_private_executable_first_write_invalidates_code_without_writing_source() {
    let mut file = Fixture::new(4096);
    let space = memory();
    let mut mapping = view(file.object(false), false);
    mapping.perms |= Perms::EXEC;
    private_map(&space, 0x10000, 4096, mapping);
    let mut instruction = [0];
    space.fetch(0x10000, &mut instruction).unwrap();
    let epoch = space.code_epoch();
    space.write(0x10000, &[0x33]).unwrap();
    assert!(space.code_epoch() > epoch);
    assert_eq!(
        space.code_changes_since(epoch).0,
        CodeChanges::Ranges(vec![(0x10000, 4096)])
    );
    space.fetch(0x10000, &mut instruction).unwrap();
    assert_eq!(instruction, [0x33]);
    assert_eq!(file.read(0), 0x11);
}

#[test]
fn file_private_independent_objects_share_reads_and_writable_upgrade_keeps_copy_isolation() {
    let mut file = Fixture::new(4096);
    let space = memory();
    private_map(&space, 0x10000, 4096, view(file.object(false), false));
    assert_eq!(byte(&space, 0x10000), 0x11);
    space
        .map(0x20000, 4096, view(file.object(true), true))
        .unwrap();
    space.write(0x20000, &[0x22]).unwrap();
    assert_eq!(byte(&space, 0x10000), 0x22);
    space.write(0x10000, &[0x33]).unwrap();
    space.write(0x20000, &[0x44]).unwrap();
    assert_eq!(byte(&space, 0x10000), 0x33);
    assert_eq!(file.read(0), 0x44);
}

#[test]
fn file_private_untouched_pages_follow_file_growth_in_an_already_attached_extent() {
    for writable in [false, true] {
        let mut file = Fixture::new(1);
        let space = memory();
        let object = file.object(writable);
        private_map(&space, 0x10000, 69632, view(object.clone(), false));
        assert_eq!(byte(&space, 0x10000), 0x11);
        space.write(0x10000, &[0x33]).unwrap();
        // Retain another populated extent reference while growing the file.
        let mut shared = view(object, true);
        shared.perms = if writable {
            Perms::READ | Perms::WRITE
        } else {
            Perms::READ
        };
        space.map(0x30000, 69632, shared).unwrap();
        assert_eq!(byte(&space, 0x30000), 0x11);
        file.write(65536, 0x66);
        assert_eq!(byte(&space, 0x20000), 0x66);
        assert_eq!(byte(&space, 0x40000), 0x66);
        assert_eq!(byte(&space, 0x20001), 0);
        space.write(0x20000, &[0x77]).unwrap();
        assert_eq!(byte(&space, 0x40000), 0x66);
        assert_eq!(file.read(65536), 0x66);
        assert_eq!(byte(&space, 0x10000), 0x33);
        space.unmap(0x10000, 69632).unwrap();
        space.unmap(0x30000, 69632).unwrap();
        assert_eq!(space.resident_pages(), 0);
        assert_eq!(space.attached_extents(), 0);
    }
}

#[test]
fn file_private_readonly_growth_keeps_an_existing_shared_writable_extent_writable() {
    let mut file = Fixture::new(1);
    let space = memory();
    space
        .map(0x10000, 69632, view(file.object(true), true))
        .unwrap();
    assert_eq!(byte(&space, 0x10000), 0x11);
    private_map(&space, 0x30000, 69632, view(file.object(false), false));
    file.write(65536, 0x66);
    assert_eq!(byte(&space, 0x40000), 0x66);
    space.write_raw(0x10000, &[0x22]).unwrap();
    assert_eq!(file.read(0), 0x22);
    assert_eq!(byte(&space, 0x30000), 0x22);
    space.write(0x40000, &[0x77]).unwrap();
    assert_eq!(file.read(65536), 0x66);
}

#[test]
fn file_private_write_probe_acquires_a_copy_even_when_a_later_page_faults() {
    let mut file = Fixture::new(4096);
    let space = memory();
    private_map(&space, 0x10000, 4096, view(file.object(false), false));
    assert!(space.probe(0x10000, 4097, MemoryAccessKind::Write).is_err());
    assert_eq!(space.acquired_private_bytes(0x10000, 4096), 4096);
    file.write(0, 0x22);
    assert_eq!(byte(&space, 0x10000), 0x11);
    assert_eq!(file.read(0), 0x22);
}

#[test]
fn file_private_policy_changes_preserve_private_pages_and_rejoin_only_untouched_pages() {
    let mut file = Fixture::new(8192);
    let space = memory();
    space
        .map(0x10000, 8192, view(file.object(true), true))
        .unwrap();
    assert_eq!(byte(&space, 0x10000), 0x11);
    assert_eq!(byte(&space, 0x11000), 0);
    space.set_file_copy_on_write(0x10000, 8192, true).unwrap();
    space.write(0x10000, &[0x33]).unwrap();
    space.set_file_copy_on_write(0x10000, 8192, false).unwrap();
    assert_eq!(space.private_copy_capacity(0x10000, 8192), 0);
    assert_eq!(space.acquired_private_bytes(0x10000, 8192), 4096);
    space.write(0x10000, &[0x44]).unwrap();
    assert_eq!(file.read(0), 0x11);
    space.write(0x11000, &[0x55]).unwrap();
    assert_eq!(file.read(4096), 0x55);
    space.set_file_copy_on_write(0x11000, 4096, true).unwrap();
    space.write(0x11000, &[0x66]).unwrap();
    assert_eq!(file.read(4096), 0x55);
    assert_eq!(byte(&space, 0x10000), 0x44);
    assert_eq!(space.acquired_private_bytes(0x10000, 8192), 8192);
}

#[test]
fn file_private_policy_rejects_mixed_backing_and_holes_before_changing_any_page() {
    let mut file = Fixture::new(4096);
    let space = memory();
    space
        .map(0x10000, 4096, view(file.object(true), true))
        .unwrap();
    space
        .map(
            0x11000,
            4096,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    assert!(space.set_file_copy_on_write(0x10000, 8192, true).is_err());
    assert!(space.set_file_copy_on_write(0x10000, 12288, true).is_err());
    space.write(0x10000, &[0x22]).unwrap();
    assert_eq!(file.read(0), 0x22);
    assert_eq!(space.private_copy_capacity(0x10000, 4096), 0);
}

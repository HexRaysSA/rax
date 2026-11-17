use std::sync::Arc;

use crate::error::MemoryAccessKind;
use crate::user::mm::{
    AddressSpace, Backing, BytesSource, EXTENT, Mapping, PAGE_SIZE, Perms, SharedObject,
    SpaceConfig,
};

const BASE: u64 = 0x1_0000;
const RW: Perms = Perms::READ.union(Perms::WRITE);

fn space() -> AddressSpace {
    AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap()
}

fn byte(space: &AddressSpace, at: u64) -> u8 {
    let mut bytes = [0];
    space.read(at, &mut bytes).unwrap();
    bytes[0]
}

fn shared(object: &Arc<SharedObject>, perms: Perms) -> Mapping {
    Mapping {
        perms,
        backing: Backing::Shared {
            object: object.clone(),
            offset: 0,
        },
        shared: true,
        name: Some("snapshot-shared-object".into()),
        flags: 0x55,
    }
}

#[test]
fn sparse_private_pages_and_mapping_metadata_are_independent() {
    let parent = space();
    parent
        .map(
            BASE,
            4 * PAGE_SIZE,
            Mapping::anonymous(RW | Perms::EXEC).named("snapshot-private"),
        )
        .unwrap();
    parent.write(BASE, &[5]).unwrap();
    parent.write(BASE + 3 * PAGE_SIZE, &[9]).unwrap();
    parent
        .set_flags(BASE, 4 * PAGE_SIZE, u32::MAX, 0x1234)
        .unwrap();
    let epoch = parent.code_epoch();
    let child = parent.process_snapshot().unwrap();
    assert!(!parent.same_space(&child));
    assert!(!Arc::ptr_eq(
        parent.physical_memory(),
        child.physical_memory()
    ));
    assert_eq!(parent.resident_pages(), 2);
    assert_eq!(child.resident_pages(), 2);
    assert_eq!(child.code_epoch(), epoch);
    assert!(!child.is_resident(BASE + PAGE_SIZE));
    assert_eq!(byte(&child, BASE + PAGE_SIZE), 0);
    assert!(!parent.is_resident(BASE + PAGE_SIZE));
    child.write(BASE, &[77]).unwrap();
    assert_eq!(byte(&parent, BASE), 5);
    assert_eq!(byte(&child, BASE), 77);
    assert_eq!(byte(&child, BASE + 3 * PAGE_SIZE), 9);
    child.protect(BASE, PAGE_SIZE, Perms::READ).unwrap();
    child.set_flags(BASE, PAGE_SIZE, u32::MAX, 7).unwrap();
    assert!(child.write(BASE, &[88]).is_err());
    let original = parent.vma_at(BASE).unwrap();
    assert_eq!(original.perms, RW | Perms::EXEC);
    assert_eq!(original.flags, 0x1234);
    assert_eq!(original.name.as_deref(), Some("snapshot-private"));
    assert_eq!(child.vma_at(BASE).unwrap().flags, 7);
    assert_eq!(parent.code_epoch(), epoch);
    assert!(child.code_epoch() > epoch);
}

#[test]
fn true_shared_extents_and_readonly_aliases_keep_the_same_object() {
    let object = Arc::new(SharedObject::anonymous(EXTENT).unwrap());
    let parent = space();
    let alias = BASE + 4 * PAGE_SIZE;
    parent.map(BASE, PAGE_SIZE, shared(&object, RW)).unwrap();
    parent
        .map(alias, PAGE_SIZE, shared(&object, Perms::READ))
        .unwrap();
    parent.write(BASE, &[5]).unwrap();
    assert_eq!(byte(&parent, alias), 5);
    let child = parent.process_snapshot().unwrap();
    assert_eq!(parent.attached_extents(), 1);
    assert_eq!(child.attached_extents(), 1);
    child.write(BASE, &[77]).unwrap();
    assert_eq!(byte(&parent, BASE), 77);
    assert_eq!(byte(&parent, alias), 77);
    assert_eq!(byte(&child, alias), 77);
    assert!(child.write(alias, &[88]).is_err());
    let mut file_byte = [0];
    assert_eq!(object.read_at(0, &mut file_byte).unwrap(), 1);
    assert_eq!(file_byte, [77]);
    child.unmap(BASE, PAGE_SIZE).unwrap();
    assert_eq!(child.attached_extents(), 1);
    child.unmap(alias, PAGE_SIZE).unwrap();
    assert_eq!(child.attached_extents(), 0);
    assert_eq!(parent.attached_extents(), 1);
    assert_eq!(byte(&parent, alias), 77);
}

#[test]
fn explicit_file_copies_preserve_warm_private_and_untouched_cow_pages() {
    let object = Arc::new(SharedObject::anonymous(EXTENT).unwrap());
    object
        .write_all_at(0, &vec![5; 2 * PAGE_SIZE as usize])
        .unwrap();
    let parent = space();
    let mut mapping = shared(&object, RW);
    mapping.shared = false;
    parent
        .map_copy_on_write(BASE, 2 * PAGE_SIZE, mapping)
        .unwrap();
    parent.track_private_copies(BASE, 2 * PAGE_SIZE).unwrap();
    parent.write(BASE, &[19]).unwrap();
    assert_eq!(byte(&parent, BASE + PAGE_SIZE), 5);
    assert_eq!(
        parent.acquired_private_bytes(BASE, 2 * PAGE_SIZE),
        PAGE_SIZE
    );
    let child = parent.process_snapshot().unwrap();
    assert_eq!(child.acquired_private_bytes(BASE, 2 * PAGE_SIZE), PAGE_SIZE);
    assert_eq!(
        child.private_copy_capacity(BASE, 2 * PAGE_SIZE),
        2 * PAGE_SIZE
    );
    child.write(BASE, &[77]).unwrap();
    child.write(BASE + PAGE_SIZE, &[88]).unwrap();
    assert_eq!(byte(&parent, BASE), 19);
    assert_eq!(byte(&parent, BASE + PAGE_SIZE), 5);
    assert_eq!(byte(&child, BASE), 77);
    assert_eq!(byte(&child, BASE + PAGE_SIZE), 88);
    assert_eq!(
        child.acquired_private_bytes(BASE, 2 * PAGE_SIZE),
        2 * PAGE_SIZE
    );
    assert_eq!(
        parent.acquired_private_bytes(BASE, 2 * PAGE_SIZE),
        PAGE_SIZE
    );
    let mut file_byte = [0];
    object.read_at(0, &mut file_byte).unwrap();
    assert_eq!(file_byte, [5]);
    object.read_at(PAGE_SIZE, &mut file_byte).unwrap();
    assert_eq!(file_byte, [5]);
}

#[test]
fn nested_snapshots_keep_allocator_reuse_reservations_and_lifetime() {
    let parent = space();
    parent
        .map(BASE, 2 * PAGE_SIZE, Mapping::anonymous(RW))
        .unwrap();
    parent.write(BASE, &[5]).unwrap();
    parent.write(BASE + PAGE_SIZE, &[9]).unwrap();
    assert_eq!(parent.translate(BASE, MemoryAccessKind::Read).unwrap(), 0);
    assert_eq!(
        parent
            .translate(BASE + PAGE_SIZE, MemoryAccessKind::Read)
            .unwrap(),
        2 * PAGE_SIZE
    );
    parent.unmap(BASE, PAGE_SIZE).unwrap();
    let child = parent.process_snapshot().unwrap();
    let added = BASE + 4 * PAGE_SIZE;
    child.map(added, PAGE_SIZE, Mapping::anonymous(RW)).unwrap();
    child.write(added, &[77]).unwrap();
    assert_eq!(child.translate(added, MemoryAccessKind::Read).unwrap(), 0);
    let nested = child.process_snapshot().unwrap();
    child.write(added, &[11]).unwrap();
    assert_eq!(byte(&nested, added), 77);
    assert_eq!(byte(&nested, BASE + PAGE_SIZE), 9);
    drop(parent);
    drop(child);
    nested.unmap(BASE + PAGE_SIZE, PAGE_SIZE).unwrap();
    nested.map(BASE, PAGE_SIZE, Mapping::anonymous(RW)).unwrap();
    assert_eq!(byte(&nested, BASE), 0);
    assert_eq!(
        nested.translate(BASE, MemoryAccessKind::Read).unwrap(),
        2 * PAGE_SIZE
    );
    assert_eq!(byte(&nested, added), 77);
}

#[test]
fn unpopulated_backings_remain_lazy_and_preserve_source_offsets() {
    let parent = space();
    let bytes: Arc<[u8]> = [vec![3; PAGE_SIZE as usize], vec![91; PAGE_SIZE as usize]]
        .concat()
        .into();
    parent
        .map(
            BASE,
            PAGE_SIZE,
            Mapping {
                perms: Perms::READ,
                backing: Backing::Source {
                    source: Arc::new(BytesSource::new(bytes)),
                    offset: PAGE_SIZE,
                },
                shared: false,
                name: Some("snapshot-offset-source".into()),
                flags: 0x55,
            },
        )
        .unwrap();
    let child = parent.process_snapshot().unwrap();
    assert_eq!(parent.resident_pages(), 0);
    assert_eq!(child.resident_pages(), 0);
    assert_eq!(child.vma_at(BASE).unwrap().backing.offset(), PAGE_SIZE);
    assert_eq!(byte(&child, BASE), 91);
    assert_eq!(parent.resident_pages(), 0);
    assert!(child.write(BASE, &[77]).is_err());
    child.write_raw(BASE, &[77]).unwrap();
    assert_eq!(byte(&child, BASE), 77);
    assert_eq!(byte(&parent, BASE), 91);
}

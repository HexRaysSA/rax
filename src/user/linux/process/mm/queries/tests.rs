use super::*;
use crate::user::mm::{Backing, EXTENT, Mapping, Perms, SharedObject, SpaceConfig, anonymous_file};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

const BASE: u64 = 0x2_0000;
const VECTOR: u64 = BASE + 8 * PAGE_SIZE;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];
const RW: Perms = Perms::READ.union(Perms::WRITE);

fn initial(abi: LinuxAbi) -> (AddressSpace, MmState) {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    (space, crate::user::linux::process::mm::initial_state(abi))
}

fn anonymous(space: &AddressSpace, address: u64, length: u64, perms: Perms) {
    space
        .map(address, length, Mapping::anonymous(perms))
        .unwrap();
}

fn read(space: &AddressSpace, address: u64, length: usize) -> Vec<u8> {
    let mut data = vec![0; length];
    space.read(address, &mut data).unwrap();
    data
}

#[test]
fn residency_keeps_lazy_and_protected_pages_unpopulated_and_snapshots_before_output() {
    for abi in ABIS {
        let (space, mm) = initial(abi);
        anonymous(&space, BASE, 4 * PAGE_SIZE, RW);
        anonymous(&space, VECTOR, PAGE_SIZE, RW);
        space.write(BASE + PAGE_SIZE, &[17]).unwrap();
        space.write(BASE + 2 * PAGE_SIZE, &[23]).unwrap();
        space
            .protect(BASE + 2 * PAGE_SIZE, PAGE_SIZE, Perms::empty())
            .unwrap();
        assert_eq!(
            mm.residency_into(&space, abi, BASE, 4 * PAGE_SIZE, VECTOR),
            Ok(0)
        );
        assert_eq!(read(&space, VECTOR, 4), [0, 1, 1, 0]);
        assert!(!space.is_resident(BASE));
        assert!(!space.is_resident(BASE + 3 * PAGE_SIZE));
        assert!(space.is_resident(VECTOR));
        assert_eq!(mm.residency_into(&space, abi, BASE, PAGE_SIZE, BASE), Ok(0));
        assert_eq!(
            read(&space, BASE, 1),
            [0],
            "vector aliases the queried lazy page; collect before write"
        );
        assert_eq!(mm.residency_into(&space, abi, BASE, 1, BASE), Ok(0));
        assert_eq!(read(&space, BASE, 1), [1]);
    }
}

#[test]
fn residency_validation_holes_and_output_faults_preserve_existing_precedence() {
    for abi in ABIS {
        let (space, mm) = initial(abi);
        anonymous(&space, BASE, 2 * PAGE_SIZE, RW);
        anonymous(&space, VECTOR, PAGE_SIZE, RW);
        space.write(VECTOR, &[71, 73]).unwrap();
        for (address, length, output, errno) in [
            (BASE + 1, 0, 0, EINVAL),
            (BASE, u64::MAX, 0, ENOMEM),
            (abi.task_size(), PAGE_SIZE, 0, ENOMEM),
            (BASE, 3 * PAGE_SIZE, 0, ENOMEM),
            (BASE, PAGE_SIZE, 0, EFAULT),
        ] {
            assert_eq!(
                mm.residency_into(&space, abi, address, length, output),
                Err(Errno(errno))
            );
            assert_eq!(read(&space, VECTOR, 2), [71, 73]);
        }
        assert_eq!(
            mm.residency_into(&space, abi, abi.task_size(), 0, u64::MAX),
            Ok(0)
        );
        space.protect(VECTOR, PAGE_SIZE, Perms::READ).unwrap();
        assert_eq!(
            mm.residency_into(&space, abi, BASE, 2 * PAGE_SIZE, VECTOR),
            Err(Errno(EFAULT))
        );
        assert_eq!(read(&space, VECTOR, 2), [71, 73]);
        space.protect(VECTOR, PAGE_SIZE, RW).unwrap();
        space.write(VECTOR + PAGE_SIZE - 1, &[79]).unwrap();
        assert_eq!(
            mm.residency_into(&space, abi, BASE, 2 * PAGE_SIZE, VECTOR + PAGE_SIZE - 1),
            Err(Errno(EFAULT))
        );
        assert_eq!(
            read(&space, VECTOR + PAGE_SIZE - 1, 1),
            [79],
            "AddressSpace::write validates all chunks before copying any bytes"
        );
        assert!(!space.is_resident(BASE));
        assert!(!space.is_resident(BASE + PAGE_SIZE));
    }
}

#[test]
fn sync_preserves_flag_rounding_hole_order_and_uses_actual_retained_file_storage() {
    for abi in ABIS {
        let (space, mm) = initial(abi);
        let mut file = anonymous_file().unwrap();
        file.write_all(&vec![5; 2 * PAGE_SIZE as usize]).unwrap();
        let mut observer = file.try_clone().unwrap();
        let keep = Arc::new(());
        let retained = Arc::downgrade(&keep);
        let object = Arc::new(SharedObject::file_keeping(file, true, Some(keep)).unwrap());
        space
            .map(
                BASE,
                2 * PAGE_SIZE,
                Mapping {
                    perms: RW,
                    backing: Backing::Shared {
                        object: object.clone(),
                        offset: 0,
                    },
                    shared: true,
                    name: Some("actual-sync-file".into()),
                    flags: 0,
                },
            )
            .unwrap();
        drop(object);
        for (address, length, flags, errno) in [
            (BASE + 1, 0, 0, EINVAL),
            (BASE, 0, 8, EINVAL),
            (BASE, 0, 5, EINVAL),
            (BASE, u64::MAX, 0, ENOMEM),
            (BASE, 3 * PAGE_SIZE, 4, ENOMEM),
        ] {
            assert_eq!(
                mm.sync_range(&space, address, length, flags),
                Err(Errno(errno))
            );
            assert!(!space.is_resident(BASE));
        }
        assert_eq!(mm.sync_range(&space, abi.task_size(), 0, 4), Ok(0));
        for flags in [0, 1, 2, 3, 4, 6] {
            assert_eq!(mm.sync_range(&space, BASE, 1, flags), Ok(0));
            assert!(
                !space.is_resident(BASE),
                "sync does not demand-page an untouched mapping"
            );
        }
        space.write(BASE + 7, &[31, 37]).unwrap();
        assert_eq!(mm.sync_range(&space, BASE, 1, 4), Ok(0));
        observer.seek(SeekFrom::Start(7)).unwrap();
        let mut bytes = [0; 2];
        observer.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [31, 37]);
        assert!(retained.upgrade().is_some());
        space.unmap(BASE, 2 * PAGE_SIZE).unwrap();
        assert!(retained.upgrade().is_none());
    }
}

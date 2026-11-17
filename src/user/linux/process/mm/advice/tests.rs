use super::*;
use crate::user::linux::abi::{LinuxAbi, open::O_RDWR};
use crate::user::linux::fs::fd::{FileObject, FileType, OpenFile};
use crate::user::linux::fs::memfd::{Memfd, seal};
use crate::user::mm::{EXTENT, Mapping, SharedObject, SpaceConfig, anonymous_file};
use std::io::Write;
use std::sync::Arc;

const BASE: u64 = 0x2_0000;
const RW: Perms = Perms::READ.union(Perms::WRITE);
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn initial(abi: LinuxAbi) -> (AddressSpace, MmState) {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    (space, crate::user::linux::process::mm::initial_state(abi))
}

fn byte(space: &AddressSpace, address: u64) -> u8 {
    let mut value = [0];
    space.read(address, &mut value).unwrap();
    value[0]
}

#[test]
fn advice_validation_and_partial_walk_preserve_existing_order_for_all_abis() {
    for abi in ABIS {
        let (space, mm) = initial(abi);
        for address in [BASE, BASE + 2 * PAGE_SIZE] {
            space
                .map(address, PAGE_SIZE, Mapping::anonymous(RW))
                .unwrap();
            space.write(address, &[17]).unwrap();
        }
        for (address, length, advice, expected) in [
            (BASE, 0, 102, Err(Errno(EINVAL))),
            (BASE + 1, 0, 4, Err(Errno(EINVAL))),
            (BASE, u64::MAX, 4, Err(Errno(EINVAL))),
            (u64::MAX & !PAGE_MASK, PAGE_SIZE, 4, Err(Errno(EINVAL))),
            (BASE, 0, 100, Ok(0)),
            (BASE, PAGE_SIZE, 100, Err(Errno(EPERM))),
        ] {
            assert_eq!(mm.advise_range(&space, address, length, advice), expected);
            assert_eq!(byte(&space, BASE), 17);
            assert_eq!(byte(&space, BASE + 2 * PAGE_SIZE), 17);
        }
        assert_eq!(
            mm.advise_range(&space, BASE, 3 * PAGE_SIZE, 4),
            Err(Errno(ENOMEM))
        );
        assert_eq!(byte(&space, BASE), 0);
        assert_eq!(byte(&space, BASE + 2 * PAGE_SIZE), 0);
        space.write(BASE, &[23]).unwrap();
        space.write(BASE + 2 * PAGE_SIZE, &[29]).unwrap();
        space
            .set_flags(
                BASE + 2 * PAGE_SIZE,
                PAGE_SIZE,
                vma_flags::LOCKED,
                vma_flags::LOCKED,
            )
            .unwrap();
        assert_ne!(
            space.vma_at(BASE + 2 * PAGE_SIZE).unwrap().flags & vma_flags::LOCKED,
            0
        );
        assert_eq!(
            mm.advise_range(&space, BASE, 3 * PAGE_SIZE, 4),
            Err(Errno(EINVAL))
        );
        assert_eq!(
            byte(&space, BASE),
            0,
            "earlier effects precede the locked VMA error"
        );
        assert_eq!(byte(&space, BASE + 2 * PAGE_SIZE), 29);
        assert_eq!(mm.advise_range(&space, BASE + 2 * PAGE_SIZE, 1, 24), Ok(0));
        assert_eq!(byte(&space, BASE + 2 * PAGE_SIZE), 0);
        space.protect(BASE, PAGE_SIZE, Perms::READ).unwrap();
        space
            .set_flags(BASE, PAGE_SIZE, vma_flags::SEALED, vma_flags::SEALED)
            .unwrap();
        assert_ne!(space.vma_at(BASE).unwrap().flags & vma_flags::SEALED, 0);
        assert_eq!(
            mm.advise_range(&space, BASE, PAGE_SIZE, 4),
            Err(Errno(EPERM))
        );
    }
}

#[test]
fn advice_uses_actual_mapping_inode_after_last_close_and_private_snapshot() {
    for abi in ABIS {
        for sealed in [false, true] {
            let (space, mm) = initial(abi);
            let mut file = anonymous_file().unwrap();
            file.write_all(&vec![87; 2 * PAGE_SIZE as usize]).unwrap();
            let identity_owner = SharedObject::file(file.try_clone().unwrap(), true).unwrap();
            let identity = identity_owner.identity();
            let inode = Memfd::new(0, false, identity).unwrap();
            let retained = Arc::downgrade(&inode);
            let description = OpenFile::with_memfd(
                FileObject::Host(file),
                FileType::Regular,
                "/memfd:advice",
                None,
                O_RDWR,
                Some(inode.clone()),
            );
            let closed = Arc::downgrade(&description);
            let object = Arc::new(
                SharedObject::file_keeping(
                    description.host_file().unwrap().try_clone().unwrap(),
                    true,
                    description.mapping_keep(),
                )
                .unwrap(),
            );
            assert_eq!(object.identity(), identity);
            drop(identity_owner);
            space
                .map(
                    BASE,
                    2 * PAGE_SIZE,
                    Mapping {
                        perms: RW,
                        backing: Backing::Shared { object, offset: 0 },
                        shared: true,
                        name: None,
                        flags: 0,
                    },
                )
                .unwrap();
            space.write(BASE + PAGE_SIZE, &[104]).unwrap();
            if sealed {
                inode.add(seal::FUTURE_WRITE);
            }
            drop(inode);
            drop(description);
            assert!(closed.upgrade().is_none());
            let snapshot = space.process_snapshot().unwrap();
            assert!(retained.upgrade().is_some());
            assert_eq!(
                mm.advise_range(&snapshot, BASE, PAGE_SIZE, 9),
                if sealed { Err(Errno(EPERM)) } else { Ok(0) }
            );
            assert_eq!(byte(&space, BASE), if sealed { 87 } else { 0 });
            assert_eq!(byte(&snapshot, BASE + PAGE_SIZE), 104);
            // FUTURE_WRITE does not revoke an already writable mapping.
            snapshot.write(BASE, &[113]).unwrap();
            assert_eq!(byte(&space, BASE), 113);
            space.unmap(BASE, 2 * PAGE_SIZE).unwrap();
            drop(space);
            assert!(retained.upgrade().is_some());
            snapshot.unmap(BASE, 2 * PAGE_SIZE).unwrap();
            assert!(retained.upgrade().is_none());
            assert!(Memfd::find(identity).is_none());
        }
    }
}

#[test]
fn advice_population_preserves_no_read_holes_and_file_eof_failures() {
    for abi in ABIS {
        let (space, mm) = initial(abi);
        space.map(BASE, PAGE_SIZE, Mapping::anonymous(RW)).unwrap();
        assert!(!space.is_resident(BASE));
        assert_eq!(
            mm.advise_range(&space, BASE, 2 * PAGE_SIZE, 23),
            Err(Errno(ENOMEM))
        );
        assert!(
            space.is_resident(BASE),
            "population before a hole remains visible"
        );
        assert_eq!(byte(&space, BASE), 0);
        space
            .set_flags(BASE, PAGE_SIZE, vma_flags::NO_READ, vma_flags::NO_READ)
            .unwrap();
        assert_ne!(space.vma_at(BASE).unwrap().flags & vma_flags::NO_READ, 0);
        assert_eq!(mm.advise_range(&space, BASE, 1, 22), Err(Errno(EINVAL)));
        assert_eq!(mm.advise_range(&space, BASE, 1, 23), Ok(0));
        space.protect(BASE, PAGE_SIZE, Perms::READ).unwrap();
        assert_eq!(mm.advise_range(&space, BASE, 1, 23), Err(Errno(EINVAL)));
        let file = anonymous_file().unwrap();
        file.set_len(PAGE_SIZE).unwrap();
        let source = Arc::new(crate::user::mm::HostFileSource::new(file).unwrap());
        space
            .map(
                BASE + 2 * PAGE_SIZE,
                2 * PAGE_SIZE,
                Mapping {
                    perms: RW,
                    backing: Backing::Source { source, offset: 0 },
                    shared: false,
                    name: None,
                    flags: 0,
                },
            )
            .unwrap();
        assert_eq!(
            mm.advise_range(&space, BASE + 2 * PAGE_SIZE, 2 * PAGE_SIZE, 22),
            Err(Errno(EFAULT))
        );
        assert!(space.is_resident(BASE + 2 * PAGE_SIZE));
        assert!(!space.is_resident(BASE + 3 * PAGE_SIZE));
    }
}

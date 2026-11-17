use super::*;
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::{EINVAL, ENOMEM, EPERM};
use crate::user::linux::aio::Table;
use crate::user::mm::{
    Backing, BytesSource, EXTENT, Mapping, PAGE_SIZE, Perms, SharedObject, SpaceConfig,
};
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

fn initial(abi: LinuxAbi) -> (AddressSpace, MmResources) {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    (
        space,
        MmResources::new(initial_state(abi), Table::default()),
    )
}

fn byte(space: &AddressSpace, address: u64) -> u8 {
    let mut value = [0];
    space.read(address, &mut value).unwrap();
    value[0]
}

#[test]
fn dontfork_excludes_only_selected_pages_and_dofork_restores_private_inheritance() {
    for abi in ABIS {
        let (space, state) = initial(abi);
        space
            .map(BASE, 2 * PAGE_SIZE, Mapping::anonymous(RW))
            .unwrap();
        space.write(BASE, &[17]).unwrap();
        space.write(BASE + PAGE_SIZE, &[23]).unwrap();
        assert_eq!(state.mm.advise_range(&space, BASE, PAGE_SIZE, 10), Ok(0));
        let child = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&child).unwrap();
        assert!(
            child.vma_at(BASE).is_none(),
            "MADV_DONTFORK must omit the child range"
        );
        assert_eq!(byte(&child, BASE + PAGE_SIZE), 23);
        assert_eq!(
            (byte(&space, BASE), byte(&space, BASE + PAGE_SIZE)),
            (17, 23)
        );
        assert_eq!(state.mm.advise_range(&space, BASE, PAGE_SIZE, 11), Ok(0));
        let ordinary = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&ordinary).unwrap();
        assert_eq!(
            (byte(&ordinary, BASE), byte(&ordinary, BASE + PAGE_SIZE)),
            (17, 23)
        );
    }
}

#[test]
fn wipeonfork_zeros_private_and_nested_children_and_keeponfork_preserves_bytes() {
    for abi in ABIS {
        let (space, state) = initial(abi);
        space.map(BASE, PAGE_SIZE, Mapping::anonymous(RW)).unwrap();
        space.write(BASE, &[17]).unwrap();
        assert_eq!(state.mm.advise_range(&space, BASE, PAGE_SIZE, 18), Ok(0));
        let child = space.process_snapshot().unwrap();
        let child_state = state.fork_private(&child).unwrap();
        assert!(
            !child.is_resident(BASE),
            "WIPE child starts without copied pages"
        );
        assert_eq!(byte(&child, BASE), 0);
        assert_eq!(byte(&space, BASE), 17);
        child.write(BASE, &[29]).unwrap();
        let nested = child.process_snapshot().unwrap();
        let _resources = child_state.fork_private(&nested).unwrap();
        assert_eq!(byte(&nested, BASE), 0, "WIPE flag survives to nested fork");
        assert_eq!(byte(&child, BASE), 29);
        assert_eq!(state.mm.advise_range(&space, BASE, PAGE_SIZE, 19), Ok(0));
        let ordinary = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&ordinary).unwrap();
        assert_eq!(byte(&ordinary, BASE), 17);
    }
}

#[test]
fn wipeonfork_rejects_actual_shared_and_private_file_backings() {
    for abi in ABIS {
        let (space, state) = initial(abi);
        let object = Arc::new(SharedObject::anonymous(PAGE_SIZE).unwrap());
        space
            .map(
                BASE,
                PAGE_SIZE,
                Mapping {
                    perms: RW,
                    backing: Backing::Shared { object, offset: 0 },
                    shared: true,
                    name: None,
                    flags: 0,
                },
            )
            .unwrap();
        let file = Arc::new(BytesSource::new(vec![37; PAGE_SIZE as usize].into()));
        space
            .map(
                BASE + 2 * PAGE_SIZE,
                PAGE_SIZE,
                Mapping {
                    perms: RW,
                    backing: Backing::Source {
                        source: file,
                        offset: 0,
                    },
                    shared: false,
                    name: None,
                    flags: 0,
                },
            )
            .unwrap();
        for address in [BASE, BASE + 2 * PAGE_SIZE] {
            assert_eq!(
                state.mm.advise_range(&space, address, PAGE_SIZE, 18),
                Err(Errno(EINVAL))
            );
        }
        let child = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&child).unwrap();
        assert_eq!(byte(&child, BASE + 2 * PAGE_SIZE), 37);
    }
}

#[test]
fn inheritance_advice_keeps_effects_before_and_after_holes_without_changing_parent_bytes() {
    for abi in ABIS {
        let (space, state) = initial(abi);
        for address in [BASE, BASE + 2 * PAGE_SIZE] {
            space
                .map(address, PAGE_SIZE, Mapping::anonymous(RW))
                .unwrap();
            space.write(address, &[41]).unwrap();
        }
        assert_eq!(
            state.mm.advise_range(&space, BASE, 3 * PAGE_SIZE, 10),
            Err(Errno(ENOMEM))
        );
        let child = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&child).unwrap();
        assert!(child.vma_at(BASE).is_none());
        assert!(child.vma_at(BASE + 2 * PAGE_SIZE).is_none());
        assert_eq!(
            (byte(&space, BASE), byte(&space, BASE + 2 * PAGE_SIZE)),
            (41, 41)
        );
    }
}

#[test]
fn sealed_advice_rejects_before_flag_changes_but_existing_inheritance_still_applies() {
    for abi in ABIS {
        for advice in [10, 18] {
            let (space, mut state) = initial(abi);
            space
                .map(BASE, 2 * PAGE_SIZE, Mapping::anonymous(RW))
                .unwrap();
            space.write(BASE, &[43]).unwrap();
            space.write(BASE + PAGE_SIZE, &[47]).unwrap();
            assert_eq!(
                state.mm.advise_range(&space, BASE, PAGE_SIZE, advice),
                Ok(0)
            );
            space.protect(BASE, 2 * PAGE_SIZE, Perms::READ).unwrap();
            assert_eq!(state.mm.seal_range(&space, BASE, 2 * PAGE_SIZE, 0), Ok(0));
            let before = space.vma_at(BASE + PAGE_SIZE).unwrap().flags;
            assert_eq!(
                state
                    .mm
                    .advise_range(&space, BASE + PAGE_SIZE, PAGE_SIZE, advice),
                Err(Errno(EPERM))
            );
            assert_eq!(space.vma_at(BASE + PAGE_SIZE).unwrap().flags, before);
            let child = space.process_snapshot().unwrap();
            let _resources = state.fork_private(&child).unwrap();
            if advice == 10 {
                assert!(child.vma_at(BASE).is_none());
            } else {
                assert_eq!(byte(&child, BASE), 0);
                assert_eq!(child.vma_at(BASE).unwrap().perms, Perms::READ);
                assert_ne!(child.vma_at(BASE).unwrap().flags & vma_flags::SEALED, 0);
            }
            assert_eq!(byte(&child, BASE + PAGE_SIZE), 47);
            assert_eq!(
                (byte(&space, BASE), byte(&space, BASE + PAGE_SIZE)),
                (43, 47)
            );
        }
    }
}

#[test]
fn wipe_validation_stops_at_private_shmem_and_preserves_only_earlier_effects() {
    for abi in ABIS {
        let (space, state) = initial(abi);
        space.map(BASE, PAGE_SIZE, Mapping::anonymous(RW)).unwrap();
        let object = Arc::new(SharedObject::anonymous(PAGE_SIZE).unwrap());
        space
            .map(
                BASE + PAGE_SIZE,
                PAGE_SIZE,
                Mapping {
                    perms: RW,
                    backing: Backing::Shared { object, offset: 0 },
                    shared: false,
                    name: None,
                    flags: 0,
                },
            )
            .unwrap();
        space
            .map(BASE + 2 * PAGE_SIZE, PAGE_SIZE, Mapping::anonymous(RW))
            .unwrap();
        for (index, value) in [53, 59, 61].into_iter().enumerate() {
            space
                .write(BASE + index as u64 * PAGE_SIZE, &[value])
                .unwrap();
        }
        assert_eq!(
            state.mm.advise_range(&space, BASE, 3 * PAGE_SIZE, 18),
            Err(Errno(EINVAL))
        );
        let child = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&child).unwrap();
        assert_eq!(
            (
                byte(&child, BASE),
                byte(&child, BASE + PAGE_SIZE),
                byte(&child, BASE + 2 * PAGE_SIZE)
            ),
            (0, 59, 61)
        );
        assert_eq!(byte(&space, BASE), 53);
    }
}

#[test]
fn omitted_backing_is_released_and_dontcopy_precedes_wipe_invariant_validation() {
    for abi in ABIS {
        let (space, state) = initial(abi);
        let file = Arc::new(BytesSource::new(vec![67; PAGE_SIZE as usize].into()));
        let weak = Arc::downgrade(&file);
        space
            .map(
                BASE,
                PAGE_SIZE,
                Mapping {
                    perms: RW,
                    backing: Backing::Source {
                        source: file,
                        offset: 0,
                    },
                    shared: false,
                    name: None,
                    flags: 0,
                },
            )
            .unwrap();
        assert_eq!(byte(&space, BASE), 67);
        // An invalid WIPE backing must fail closed unless DONTCOPY omits it.
        space
            .set_flags(
                BASE,
                PAGE_SIZE,
                vma_flags::WIPEONFORK,
                vma_flags::WIPEONFORK,
            )
            .unwrap();
        let invalid = space.process_snapshot().unwrap();
        assert!(matches!(
            state.fork_private(&invalid),
            Err(MmError::InvalidArgument(_))
        ));
        assert_eq!(byte(&space, BASE), 67);
        drop(invalid);
        assert_eq!(state.mm.advise_range(&space, BASE, PAGE_SIZE, 10), Ok(0));
        let child = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&child).unwrap();
        assert!(child.vma_at(BASE).is_none());
        assert!(weak.upgrade().is_some(), "parent retains the source");
        drop(space);
        assert!(
            weak.upgrade().is_none(),
            "omitted child retained no backing"
        );
    }
}

#[test]
fn inheritance_flags_survive_protection_and_remap_but_not_mapping_replacement() {
    for abi in ABIS {
        let (space, mut state) = initial(abi);
        let moved = BASE + 8 * PAGE_SIZE;
        space
            .map(BASE, 2 * PAGE_SIZE, Mapping::anonymous(RW))
            .unwrap();
        space.write(BASE, &[71]).unwrap();
        space.write(BASE + PAGE_SIZE, &[73]).unwrap();
        assert_eq!(state.mm.advise_range(&space, BASE, PAGE_SIZE, 10), Ok(0));
        assert_eq!(
            state
                .mm
                .advise_range(&space, BASE + PAGE_SIZE, PAGE_SIZE, 18),
            Ok(0)
        );
        assert_eq!(
            state.mm.protect_range(
                &space,
                ProtectPolicy { abi, persona: 0 },
                BASE,
                2 * PAGE_SIZE,
                1
            ),
            Ok(0)
        );
        for (source, dest) in [(BASE, moved), (BASE + PAGE_SIZE, moved + PAGE_SIZE)] {
            assert_eq!(
                state.mm.remap_range(
                    &space,
                    &mut state.aio,
                    LockPolicy {
                        abi,
                        privileged: false,
                        memlock_limit: 0
                    },
                    RemapArgs {
                        old_address: source,
                        old_length: PAGE_SIZE,
                        new_length: PAGE_SIZE,
                        flags: 3,
                        new_address: dest,
                    }
                ),
                Ok(dest)
            );
        }
        let child = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&child).unwrap();
        assert!(child.vma_at(moved).is_none());
        assert_eq!(byte(&child, moved + PAGE_SIZE), 0);
        assert_eq!(child.vma_at(moved + PAGE_SIZE).unwrap().perms, Perms::READ);
        assert_eq!(
            (byte(&space, moved), byte(&space, moved + PAGE_SIZE)),
            (71, 73)
        );
        space
            .map(moved, 2 * PAGE_SIZE, Mapping::anonymous(RW))
            .unwrap();
        space.write(moved, &[79]).unwrap();
        space.write(moved + PAGE_SIZE, &[83]).unwrap();
        let replacement = space.process_snapshot().unwrap();
        let _resources = state.fork_private(&replacement).unwrap();
        assert_eq!(
            (
                byte(&replacement, moved),
                byte(&replacement, moved + PAGE_SIZE)
            ),
            (79, 83)
        );
    }
}

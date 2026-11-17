use super::*;
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::process::mm::{MmResources, initial_state, pending_fixture};
use crate::user::mm::{EXTENT, Perms, SharedObject, SpaceConfig};
use std::sync::Arc;

const BASE: u64 = 0x2_0000;
const DEST: u64 = BASE + 8 * PAGE_SIZE;
const RW: Perms = Perms::READ.union(Perms::WRITE);
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn policy(abi: LinuxAbi, pages: u64) -> LockPolicy {
    LockPolicy {
        abi,
        privileged: false,
        memlock_limit: pages * PAGE_SIZE,
    }
}

fn arguments(old_length: u64, new_length: u64, flags: u32) -> RemapArgs {
    RemapArgs {
        old_address: BASE,
        old_length,
        new_length,
        flags,
        new_address: DEST,
    }
}

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
fn actual_aio_ring_moves_without_replacing_pending_requests_for_all_abis() {
    for abi in ABIS {
        let (space, mut state, witness) = pending_fixture(abi, BASE);
        let mut locked = Mapping::anonymous(RW);
        locked.flags = vma_flags::LOCKED;
        space.map(DEST, PAGE_SIZE, locked).unwrap();
        state.mm.locked_vm = 1;
        for (old, new, flags, error) in [
            (PAGE_SIZE, 2 * PAGE_SIZE, 3, EFAULT),
            (0, PAGE_SIZE, 3, EFAULT),
            (PAGE_SIZE, PAGE_SIZE, 7, EINVAL),
        ] {
            assert_eq!(
                state.mm.remap_range(
                    &space,
                    &mut state.aio,
                    policy(abi, 1),
                    arguments(old, new, flags)
                ),
                Err(Errno(error))
            );
            assert_eq!(state.mm.locked_vm, 1);
            assert!(space.vma_at(BASE).is_some());
            assert_ne!(space.vma_at(DEST).unwrap().flags & vma_flags::LOCKED, 0);
        }
        assert_eq!(
            state.mm.remap_range(
                &space,
                &mut state.aio,
                policy(abi, 1),
                arguments(PAGE_SIZE, PAGE_SIZE, 3)
            ),
            Ok(DEST)
        );
        assert!(space.vma_at(BASE).is_none());
        assert_eq!(
            state.mm.locked_vm, 0,
            "fixed destination uncharged before movement"
        );
        assert!(state.aio.lookup(BASE, 0).is_none());
        let context = state.aio.get(witness.handle).unwrap();
        assert_eq!(context.id, DEST);
        assert_eq!(context.polls.len(), 1);
        assert!(Arc::ptr_eq(&context.ring, &witness.ring.upgrade().unwrap()));
        assert!(Arc::ptr_eq(
            &context.polls[0].file,
            &witness.file.upgrade().unwrap()
        ));
        assert!(Arc::ptr_eq(
            context.polls[0].resfd.as_ref().unwrap(),
            &witness.resfd.upgrade().unwrap()
        ));
        assert_eq!(context.peek_events(2).0[0].res, 23);
        assert_eq!(state.aio.aio_nr, 8);
    }
}

#[test]
fn inherited_ring_without_child_context_rejects_after_fixed_destination_unmap() {
    for abi in ABIS {
        let (parent_space, mut parent, witness) = pending_fixture(abi, BASE);
        let space = parent_space.process_snapshot().unwrap();
        let mut child = parent.fork_private(&space).unwrap();
        let mut locked = Mapping::anonymous(RW);
        locked.flags = vma_flags::LOCKED;
        space.map(DEST, PAGE_SIZE, locked).unwrap();
        child.mm.locked_vm = 1;
        assert_eq!(
            child.mm.remap_range(
                &space,
                &mut child.aio,
                policy(abi, 1),
                arguments(PAGE_SIZE, PAGE_SIZE, 3)
            ),
            Err(Errno(EINVAL))
        );
        assert!(
            space.vma_at(DEST).is_none(),
            "destination effect precedes missing-context error"
        );
        assert!(space.vma_at(BASE).is_some());
        assert_eq!(child.mm.locked_vm, 0);
        assert!(child.aio.contexts.is_empty());
        assert_eq!(parent.aio.get(witness.handle).unwrap().id, BASE);
        assert!(witness.file.upgrade().is_some());
    }
}

#[test]
fn private_locked_growth_move_shrink_and_dontunmap_preserve_accounts_and_bytes() {
    for abi in ABIS {
        let (space, mut state) = initial(abi);
        let mut locked = Mapping::anonymous(RW);
        locked.flags = vma_flags::LOCKED;
        space.map(BASE, PAGE_SIZE, locked).unwrap();
        space.write(BASE, &[17]).unwrap();
        state.mm.locked_vm = 1;
        assert_eq!(
            state.mm.remap_range(
                &space,
                &mut state.aio,
                policy(abi, 1),
                arguments(PAGE_SIZE, 2 * PAGE_SIZE, 0)
            ),
            Err(Errno(EAGAIN))
        );
        assert!(space.vma_at(BASE + PAGE_SIZE).is_none());
        assert_eq!(
            state.mm.remap_range(
                &space,
                &mut state.aio,
                policy(abi, 3),
                arguments(PAGE_SIZE, 2 * PAGE_SIZE, 0)
            ),
            Ok(BASE)
        );
        assert_eq!(state.mm.locked_vm, 2);
        assert!(space.is_resident(BASE + PAGE_SIZE));
        space.write(BASE + PAGE_SIZE, &[29]).unwrap();
        assert_eq!(
            state.mm.remap_range(
                &space,
                &mut state.aio,
                policy(abi, 3),
                arguments(2 * PAGE_SIZE, 3 * PAGE_SIZE, 3)
            ),
            Ok(DEST)
        );
        assert!(space.vma_at(BASE).is_none());
        assert_eq!(state.mm.locked_vm, 3);
        assert_eq!(
            (
                byte(&space, DEST),
                byte(&space, DEST + PAGE_SIZE),
                byte(&space, DEST + 2 * PAGE_SIZE)
            ),
            (17, 29, 0)
        );
        let shrink = RemapArgs {
            old_address: DEST,
            old_length: 3 * PAGE_SIZE,
            new_length: PAGE_SIZE,
            flags: 0,
            new_address: 0,
        };
        assert_eq!(
            state
                .mm
                .remap_range(&space, &mut state.aio, policy(abi, 3), shrink),
            Ok(DEST)
        );
        assert_eq!(state.mm.locked_vm, 1);
        assert!(space.vma_at(DEST + PAGE_SIZE).is_none());
        let keep = RemapArgs {
            old_address: DEST,
            old_length: PAGE_SIZE,
            new_length: PAGE_SIZE,
            flags: 7,
            new_address: BASE,
        };
        assert_eq!(
            state
                .mm
                .remap_range(&space, &mut state.aio, policy(abi, 3), keep),
            Ok(BASE)
        );
        assert_eq!((byte(&space, BASE), byte(&space, DEST)), (17, 0));
        assert_ne!(space.vma_at(BASE).unwrap().flags & vma_flags::LOCKED, 0);
        assert_eq!(
            space.vma_at(DEST).unwrap().flags & vma_flags::LOCKED_MASK,
            0
        );
        assert_eq!(
            state.mm.locked_vm, 2,
            "existing DONTUNMAP vrm_stat_account contract"
        );
    }
}

#[test]
fn shared_zero_length_duplication_keeps_actual_object_and_validation_precedence() {
    for abi in ABIS {
        let (space, mut state) = initial(abi);
        let object = Arc::new(SharedObject::anonymous(PAGE_SIZE).unwrap());
        space
            .map(
                BASE,
                PAGE_SIZE,
                Mapping {
                    perms: RW,
                    backing: Backing::Shared {
                        object: object.clone(),
                        offset: 0,
                    },
                    shared: true,
                    name: None,
                    flags: 0,
                },
            )
            .unwrap();
        space.write(BASE, &[37]).unwrap();
        for (args, error) in [
            (arguments(PAGE_SIZE, PAGE_SIZE, 8), EINVAL),
            (arguments(PAGE_SIZE, PAGE_SIZE, 2), EINVAL),
            (
                RemapArgs {
                    old_address: BASE + 1,
                    ..arguments(PAGE_SIZE, PAGE_SIZE, 3)
                },
                EINVAL,
            ),
            (arguments(PAGE_SIZE, u64::MAX, 3), EINVAL),
            (arguments(PAGE_SIZE, 0, 3), EINVAL),
            (
                RemapArgs {
                    new_address: BASE,
                    ..arguments(PAGE_SIZE, PAGE_SIZE, 3)
                },
                EINVAL,
            ),
            (
                RemapArgs {
                    new_address: 0,
                    ..arguments(PAGE_SIZE, PAGE_SIZE, 3)
                },
                EPERM,
            ),
            (arguments(0, PAGE_SIZE, 0), ENOMEM),
        ] {
            assert_eq!(
                state
                    .mm
                    .remap_range(&space, &mut state.aio, policy(abi, 0), args),
                Err(Errno(error))
            );
            assert_eq!(byte(&space, BASE), 37);
            assert!(space.vma_at(DEST).is_none());
        }
        assert_eq!(
            state.mm.remap_range(
                &space,
                &mut state.aio,
                policy(abi, 0),
                arguments(0, PAGE_SIZE, 3)
            ),
            Ok(DEST)
        );
        let Backing::Shared {
            object: alias,
            offset,
        } = space.vma_at(DEST).unwrap().backing
        else {
            panic!("shared object replaced")
        };
        assert!(Arc::ptr_eq(&object, &alias));
        assert_eq!(offset, 0);
        space.write(DEST, &[41]).unwrap();
        assert_eq!(byte(&space, BASE), 41);
        space
            .set_flags(BASE, PAGE_SIZE, vma_flags::SEALED, vma_flags::SEALED)
            .unwrap();
        assert_eq!(
            state.mm.remap_range(
                &space,
                &mut state.aio,
                policy(abi, 0),
                arguments(0, PAGE_SIZE, 3)
            ),
            Err(Errno(EPERM))
        );
        assert_eq!(byte(&space, DEST), 41);
    }
}

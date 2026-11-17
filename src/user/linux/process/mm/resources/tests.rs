use super::*;
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE, open, vma_flags};
use crate::user::linux::aio::{Context, Event, Handle, PendingPoll};
use crate::user::linux::fs::anon::{Anon, EventFd};
use crate::user::linux::fs::fd::{FileObject, FileType, OpenFile};
use crate::user::mm::{Backing, EXTENT, Mapping, Perms, SharedObject, SpaceConfig};
use std::sync::{Arc, Weak};

pub(crate) struct ResourceWitness {
    pub(crate) ring: Weak<SharedObject>,
    pub(crate) file: Weak<OpenFile>,
    pub(crate) resfd: Weak<OpenFile>,
    pub(crate) handle: Handle,
    pub(crate) _writer: std::io::PipeWriter,
}

/// A real mapped ring with a completion and a pending pipe poll/eventfd.
/// The witness holds only weak refs to resources owned by the AIO table.
pub(crate) fn pending_fixture(
    abi: LinuxAbi,
    address: u64,
) -> (AddressSpace, MmResources, ResourceWitness) {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    let (slots, size) = Context::ring_geometry(8).unwrap();
    assert_eq!(size, PAGE_SIZE);
    let ring = Arc::new(SharedObject::anonymous(size).unwrap());
    let weak_ring = Arc::downgrade(&ring);
    space
        .map(
            address,
            size,
            Mapping {
                perms: Perms::READ | Perms::WRITE,
                backing: Backing::Shared {
                    object: ring.clone(),
                    offset: 0,
                },
                shared: true,
                name: Some("/[aio] (deleted)".into()),
                flags: vma_flags::SPECIAL | vma_flags::AIO_RING,
            },
        )
        .unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    let file = OpenFile::new(
        FileObject::PipeRead(reader),
        FileType::Fifo,
        "pipe:[owner-poll]",
        None,
        open::O_RDONLY,
    );
    let resfd = OpenFile::new(
        FileObject::Anon(Anon::Event(EventFd::new(0, false).unwrap())),
        FileType::Anon,
        "anon_inode:[eventfd]",
        None,
        open::O_RDWR,
    );
    let mut witness = ResourceWitness {
        ring: weak_ring,
        file: Arc::downgrade(&file),
        resfd: Arc::downgrade(&resfd),
        handle: Handle { slot: 0, serial: 0 },
        _writer: writer,
    };
    let mut context = Context::new(address, 0, ring, size, slots, 8);
    assert!(context.get_req());
    context.complete(Event {
        data: 17,
        obj: address + 0x80,
        res: 23,
        res2: 0,
    });
    assert!(context.get_req());
    context.polls.push(PendingPoll {
        obj: address + 0x100,
        data: 29,
        file,
        events: 1,
        resfd: Some(resfd),
    });
    let mut table = Table::default();
    witness.handle = table.insert(context);
    table.aio_nr = 8;
    let mm = crate::user::linux::process::mm::initial_state(abi);
    (space, MmResources::new(mm, table), witness)
}

#[test]
fn private_fork_resets_only_child_aio_and_keeps_actual_parent_requests_until_owner_drop() {
    for abi in [
        LinuxAbi::X86_64,
        LinuxAbi::I386,
        LinuxAbi::Aarch64,
        LinuxAbi::Arm,
        LinuxAbi::Riscv64,
    ] {
        let base = 0x2_0000;
        let (space, mut parent, witness) = pending_fixture(abi, base);
        let context = parent.aio.get(witness.handle).unwrap();
        assert_eq!(context.id, base);
        assert_eq!(context.polls.len(), 1);
        assert!(Arc::ptr_eq(
            &context.polls[0].file,
            &witness.file.upgrade().unwrap()
        ));
        assert!(Arc::ptr_eq(
            context.polls[0].resfd.as_ref().unwrap(),
            &witness.resfd.upgrade().unwrap()
        ));
        let (events, _) = context.peek_events(2);
        assert_eq!(
            events,
            [Event {
                data: 17,
                obj: base + 0x80,
                res: 23,
                res2: 0
            }]
        );
        let snapshot = space.process_snapshot().unwrap();
        let child = parent.fork_private(&snapshot).unwrap();
        assert!(child.aio.contexts.is_empty());
        assert_eq!(child.aio.aio_nr, 0);
        assert!(
            snapshot.vma_at(base).is_some(),
            "inherited ring VMA remains"
        );
        assert_eq!(parent.aio.aio_nr, 8);
        assert!(witness.file.upgrade().is_some());
        assert!(witness.resfd.upgrade().is_some());
        drop(parent);
        assert!(
            witness.file.upgrade().is_none(),
            "only parent table owned pending poll"
        );
        assert!(witness.resfd.upgrade().is_none());
        assert!(
            witness.ring.upgrade().is_some(),
            "ring VMAs do not retain poll requests"
        );
        drop(child);
        drop(space);
        drop(snapshot);
        assert!(witness.ring.upgrade().is_none());
    }
}

#[test]
fn nested_private_fork_drops_each_childs_live_aio_table_without_retaining_omitted_rings() {
    for abi in [
        LinuxAbi::X86_64,
        LinuxAbi::I386,
        LinuxAbi::Aarch64,
        LinuxAbi::Arm,
        LinuxAbi::Riscv64,
    ] {
        let base = 0x2_0000;
        let (space, parent, parent_refs) = pending_fixture(abi, base);
        assert_eq!(parent.mm.advise_range(&space, base, PAGE_SIZE, 10), Ok(0));
        let child_space = space.process_snapshot().unwrap();
        let mut child = parent.fork_private(&child_space).unwrap();
        assert!(child_space.vma_at(base).is_none());
        assert!(child.aio.contexts.is_empty());

        // Adopt a second actual table with a completion, poll and eventfd into
        // the child. Its real ring object is mapped at the context's address;
        // the donor MM and table retain no references after the move.
        let address = base + 4 * PAGE_SIZE;
        let (donor_space, donor, child_refs) = pending_fixture(abi, address);
        let ring = child_refs.ring.upgrade().unwrap();
        child_space
            .map(
                address,
                PAGE_SIZE,
                Mapping {
                    perms: Perms::READ | Perms::WRITE,
                    backing: Backing::Shared {
                        object: ring,
                        offset: 0,
                    },
                    shared: true,
                    name: Some("/[aio] (deleted)".into()),
                    flags: vma_flags::SPECIAL | vma_flags::AIO_RING,
                },
            )
            .unwrap();
        child.aio = donor.aio;
        drop(donor_space);
        assert_eq!(
            child.mm.advise_range(&child_space, address, PAGE_SIZE, 10),
            Ok(0)
        );
        let nested_space = child_space.process_snapshot().unwrap();
        let nested = child.fork_private(&nested_space).unwrap();
        assert!(nested_space.vma_at(address).is_none());
        assert!(nested.aio.contexts.is_empty());
        assert_eq!(nested.aio.aio_nr, 0);
        assert_eq!(child.aio.get(child_refs.handle).unwrap().polls.len(), 1);
        assert!(child_refs.file.upgrade().is_some());
        assert!(parent_refs.file.upgrade().is_some());
        drop(child);
        assert!(child_refs.file.upgrade().is_none());
        assert!(child_refs.resfd.upgrade().is_none());
        drop(child_space);
        assert!(
            child_refs.ring.upgrade().is_none(),
            "nested child retained no omitted ring"
        );
        assert!(
            parent_refs.file.upgrade().is_some(),
            "original parent requests remain live"
        );
        drop(parent);
        assert!(parent_refs.file.upgrade().is_none());
        assert!(parent_refs.resfd.upgrade().is_none());
        drop(space);
        assert!(parent_refs.ring.upgrade().is_none());
    }
}

#[cfg(unix)]
#[test]
fn native_mm_owner_preserves_nonempty_aio_across_shared_private_exec_and_last_release() {
    use crate::user::linux::abi::errno::Errno;
    use crate::user::linux::abi::errno_table::EINVAL;
    use crate::user::linux::process::mm::{LockPolicy, RemapArgs};
    use crate::user::mm::process_lease::ProcessLease;
    use crate::user::mm::process_lease::test_worker::{LeaseWorker, serve_if_requested};
    use crate::user::mm::process_owner::{ForkMetadata, MemoryOwner};
    const NAME: &str = "user::linux::process::mm::resources::tests::native_mm_owner_preserves_nonempty_aio_across_shared_private_exec_and_last_release";
    serve_if_requested(NAME);
    let abi = LinuxAbi::Aarch64;
    let base = 0x2_0000;
    let dest = base + 4 * PAGE_SIZE;
    let (initial, resources, witness) = pending_fixture(abi, base);
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut owner, root) = MemoryOwner::new(lease.clone(), &initial, resources).unwrap();
    drop(initial);
    let mut root_worker = LeaseWorker::spawn(&lease, NAME);
    root_worker.acquire();
    let turn = owner.begin(root.worker, root_worker.pid()).unwrap();
    owner
        .with(turn.turn, |space, state| {
            assert_eq!(
                state.mm.remap_range(
                    space,
                    &mut state.aio,
                    LockPolicy {
                        abi,
                        privileged: false,
                        memlock_limit: 0
                    },
                    RemapArgs {
                        old_address: base,
                        old_length: PAGE_SIZE,
                        new_length: PAGE_SIZE,
                        flags: 3,
                        new_address: dest
                    }
                ),
                Ok(dest)
            );
            let context = state.aio.lookup(dest, 0).unwrap();
            assert_eq!(context.serial, witness.handle.serial);
            assert!(Arc::ptr_eq(&context.ring, &witness.ring.upgrade().unwrap()));
            assert!(Arc::ptr_eq(
                &context.polls[0].file,
                &witness.file.upgrade().unwrap()
            ));
            assert_eq!(context.peek_events(2).0[0].res, 23);
        })
        .unwrap();
    let shared = owner.fork_shared(turn.turn).unwrap();
    let private = owner
        .fork_private(turn.turn, |space, state| {
            ForkMetadata::fork_private(state, space)
        })
        .unwrap();
    owner.end(turn.turn).unwrap();
    root_worker.release();
    let mut private_worker = LeaseWorker::spawn(&lease, NAME);
    private_worker.acquire();
    let turn = owner.begin(private.worker, private_worker.pid()).unwrap();
    owner
        .with(turn.turn, |space, state| {
            assert!(state.aio.contexts.is_empty());
            assert_eq!(state.aio.aio_nr, 0);
            assert_eq!(
                state.mm.remap_range(
                    space,
                    &mut state.aio,
                    LockPolicy {
                        abi,
                        privileged: false,
                        memlock_limit: 0
                    },
                    RemapArgs {
                        old_address: dest,
                        old_length: PAGE_SIZE,
                        new_length: PAGE_SIZE,
                        flags: 3,
                        new_address: base
                    }
                ),
                Err(Errno(EINVAL))
            );
            assert!(space.vma_at(dest).is_some());
        })
        .unwrap();
    owner.end(turn.turn).unwrap();
    private_worker.release();
    let mut shared_worker = LeaseWorker::spawn(&lease, NAME);
    shared_worker.acquire();
    let turn = owner.begin(shared.worker, shared_worker.pid()).unwrap();
    owner
        .with(turn.turn, |_, state| {
            assert_eq!(state.aio.aio_nr, 8);
            let context = state.aio.get(witness.handle).unwrap();
            assert_eq!(context.id, dest);
            assert_eq!(context.polls.len(), 1);
            assert!(Arc::ptr_eq(
                context.polls[0].resfd.as_ref().unwrap(),
                &witness.resfd.upgrade().unwrap()
            ));
        })
        .unwrap();
    let empty = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    let replacement = MmResources::new(
        crate::user::linux::process::mm::initial_state(abi),
        Table::default(),
    );
    let next = owner.exec(turn.turn, &empty, replacement).unwrap();
    assert!(owner.with(turn.turn, |_, _| ()).is_err());
    owner
        .with(next.turn, |_, state| assert!(state.aio.contexts.is_empty()))
        .unwrap();
    owner.end(next.turn).unwrap();
    shared_worker.release();
    assert!(
        witness.file.upgrade().is_some(),
        "old shared MM still has the real requests"
    );
    root_worker.stop();
    owner.retire(root.worker).unwrap();
    assert!(witness.file.upgrade().is_none());
    assert!(witness.resfd.upgrade().is_none());
    assert!(
        witness.ring.upgrade().is_some(),
        "private child still maps inherited ring"
    );
    private_worker.stop();
    owner.retire(private.worker).unwrap();
    assert!(witness.ring.upgrade().is_none());
    shared_worker.stop();
    owner.retire(shared.worker).unwrap();
}

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::{Grant, MemoryOwner, OwnerError};
use crate::user::mm::process_lease::ProcessLease;
use crate::user::mm::process_lease::test_worker::{LeaseWorker, serve_if_requested};
use crate::user::mm::{
    AddressSpace, Backing, EXTENT, Mapping, MmError, PAGE_SIZE, Perms, SharedObject, SpaceConfig,
};

const BASE: u64 = 0x1_0000;
const SHARED: u64 = BASE + 4 * PAGE_SIZE;
const RW: Perms = Perms::READ.union(Perms::WRITE);

struct Metadata {
    brk: u64,
    pinned: Arc<AtomicU64>,
    drops: Arc<AtomicUsize>,
}

impl Metadata {
    fn new(brk: u64, drops: &Arc<AtomicUsize>) -> Self {
        Self {
            brk,
            pinned: Arc::new(AtomicU64::new(12)),
            drops: drops.clone(),
        }
    }
}

impl Drop for Metadata {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn space(value: u8) -> AddressSpace {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    space.map(BASE, PAGE_SIZE, Mapping::anonymous(RW)).unwrap();
    space.write(BASE, &[value]).unwrap();
    space
}

fn byte(space: &AddressSpace) -> u8 {
    let mut bytes = [0];
    space.read(BASE, &mut bytes).unwrap();
    bytes[0]
}

fn begin(
    owner: &mut MemoryOwner<Metadata>,
    registration: super::Registration,
    worker: &mut LeaseWorker,
) -> Grant {
    worker.acquire();
    owner.begin(registration.worker, worker.pid()).unwrap()
}

fn end(owner: &mut MemoryOwner<Metadata>, grant: Grant, worker: &mut LeaseWorker) {
    owner.end(grant.turn).unwrap();
    worker.release();
}

#[test]
fn shared_workers_retain_one_mm_and_one_metadata_record_until_last_retirement() {
    const NAME: &str = "user::mm::process_owner::memory::tests::shared_workers_retain_one_mm_and_one_metadata_record_until_last_retirement";
    serve_if_requested(NAME);
    let lease = Arc::new(ProcessLease::new().unwrap());
    let drops = Arc::new(AtomicUsize::new(0));
    let initial = space(5);
    let (mut owner, root) =
        MemoryOwner::new(lease.clone(), &initial, Metadata::new(1, &drops)).unwrap();
    let physical = Arc::downgrade(owner.spaces[&root.space].space.physical_memory());
    let mut a = LeaseWorker::spawn(&lease, NAME);
    let first = begin(&mut owner, root, &mut a);
    let child = owner.fork_shared(first.turn).unwrap();
    assert_eq!(root.space, child.space);
    assert_eq!(owner.spaces.len(), 1);
    owner
        .with(first.turn, |space, metadata| {
            space.write(BASE, &[77]).unwrap();
            metadata.brk = 88;
            metadata.pinned.store(99, Ordering::SeqCst);
        })
        .unwrap();
    end(&mut owner, first, &mut a);
    assert_eq!(
        byte(&initial),
        5,
        "adoption binds independent owner storage"
    );
    let mut b = LeaseWorker::spawn(&lease, NAME);
    let second = begin(&mut owner, child, &mut b);
    owner
        .with(second.turn, |space, metadata| {
            assert_eq!(byte(space), 77);
            assert_eq!(metadata.brk, 88);
            assert_eq!(metadata.pinned.load(Ordering::SeqCst), 99);
            space.protect(BASE, PAGE_SIZE, Perms::READ).unwrap();
        })
        .unwrap();
    end(&mut owner, second, &mut b);
    a.stop();
    assert!(owner.retire(root.worker).unwrap());
    assert!(!owner.retire(root.worker).unwrap());
    assert!(physical.upgrade().is_some());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let third = begin(&mut owner, child, &mut b);
    owner
        .with(third.turn, |space, metadata| {
            assert!(space.write(BASE, &[3]).is_err());
            assert_eq!(metadata.brk, 88);
        })
        .unwrap();
    end(&mut owner, third, &mut b);
    b.stop();
    assert!(owner.retire(child.worker).unwrap());
    assert!(owner.spaces.is_empty() && owner.workers.is_empty());
    assert!(physical.upgrade().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn private_and_nested_forks_copy_private_pages_but_retain_true_shared_objects() {
    const NAME: &str = "user::mm::process_owner::memory::tests::private_and_nested_forks_copy_private_pages_but_retain_true_shared_objects";
    serve_if_requested(NAME);
    let lease = Arc::new(ProcessLease::new().unwrap());
    let drops = Arc::new(AtomicUsize::new(0));
    let initial = space(5);
    let object = Arc::new(SharedObject::anonymous(EXTENT).unwrap());
    initial
        .map(
            SHARED,
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
    initial.write(SHARED, &[9]).unwrap();
    let (mut owner, root) =
        MemoryOwner::new(lease.clone(), &initial, Metadata::new(41, &drops)).unwrap();
    let mut a = LeaseWorker::spawn(&lease, NAME);
    let first = begin(&mut owner, root, &mut a);
    let child = owner
        .fork_private(first.turn, |_, metadata| {
            let child = Metadata::new(metadata.brk, &metadata.drops);
            child.pinned.store(0, Ordering::SeqCst);
            Ok(child)
        })
        .unwrap();
    assert_ne!(child.space, root.space);
    end(&mut owner, first, &mut a);
    let mut b = LeaseWorker::spawn(&lease, NAME);
    let second = begin(&mut owner, child, &mut b);
    owner
        .with(second.turn, |space, metadata| {
            assert_eq!(byte(space), 5);
            assert_eq!(metadata.brk, 41);
            assert_eq!(metadata.pinned.load(Ordering::SeqCst), 0);
            metadata.brk = 42;
            space.write(BASE, &[77]).unwrap();
            space.write(SHARED, &[88]).unwrap();
        })
        .unwrap();
    let nested = owner
        .fork_private(second.turn, |_, metadata| {
            Ok(Metadata::new(metadata.brk, &metadata.drops))
        })
        .unwrap();
    assert_ne!(nested.space, child.space);
    owner
        .with(second.turn, |space, _| space.write(BASE, &[33]).unwrap())
        .unwrap();
    end(&mut owner, second, &mut b);
    let third = begin(&mut owner, root, &mut a);
    owner
        .with(third.turn, |space, metadata| {
            assert_eq!(byte(space), 5);
            assert_eq!(metadata.brk, 41);
            assert_eq!(metadata.pinned.load(Ordering::SeqCst), 12);
            let mut shared = [0];
            space.read(SHARED, &mut shared).unwrap();
            assert_eq!(shared, [88]);
        })
        .unwrap();
    end(&mut owner, third, &mut a);
    a.stop();
    b.stop();
    owner.retire(root.worker).unwrap();
    owner.retire(child.worker).unwrap();
    assert_eq!(owner.spaces.len(), 1);
    let mut c = LeaseWorker::spawn(&lease, NAME);
    let fourth = begin(&mut owner, nested, &mut c);
    owner
        .with(fourth.turn, |space, metadata| {
            assert_eq!(byte(space), 77);
            assert_eq!(metadata.brk, 42);
        })
        .unwrap();
    end(&mut owner, fourth, &mut c);
    c.stop();
    owner.retire(nested.worker).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 3);
}

#[test]
fn exec_rotates_turn_and_detaches_only_its_worker_from_the_prior_mm() {
    const NAME: &str = "user::mm::process_owner::memory::tests::exec_rotates_turn_and_detaches_only_its_worker_from_the_prior_mm";
    serve_if_requested(NAME);
    let lease = Arc::new(ProcessLease::new().unwrap());
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut owner, root) =
        MemoryOwner::new(lease.clone(), &space(5), Metadata::new(1, &drops)).unwrap();
    let old_physical = Arc::downgrade(owner.spaces[&root.space].space.physical_memory());
    let mut a = LeaseWorker::spawn(&lease, NAME);
    let first = begin(&mut owner, root, &mut a);
    let child = owner.fork_shared(first.turn).unwrap();
    end(&mut owner, first, &mut a);
    let mut b = LeaseWorker::spawn(&lease, NAME);
    let second = begin(&mut owner, child, &mut b);
    let replacement = owner
        .exec(second.turn, &space(9), Metadata::new(7, &drops))
        .unwrap();
    assert_ne!(replacement.space, root.space);
    assert_ne!(replacement.turn, second.turn);
    assert!(owner.with(second.turn, |_, _| ()).is_err());
    owner
        .with(replacement.turn, |space, metadata| {
            assert_eq!(byte(space), 9);
            assert_eq!(metadata.brk, 7);
        })
        .unwrap();
    assert!(old_physical.upgrade().is_some());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    end(&mut owner, replacement, &mut b);
    let third = begin(&mut owner, root, &mut a);
    owner
        .with(third.turn, |space, metadata| {
            assert_eq!(byte(space), 5);
            assert_eq!(metadata.brk, 1);
        })
        .unwrap();
    end(&mut owner, third, &mut a);
    a.stop();
    owner.retire(root.worker).unwrap();
    assert!(old_physical.upgrade().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    b.stop();
    owner.retire(child.worker).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[test]
fn failed_private_preparation_and_identity_exhaustion_preserve_parent_state() {
    const NAME: &str = "user::mm::process_owner::memory::tests::failed_private_preparation_and_identity_exhaustion_preserve_parent_state";
    serve_if_requested(NAME);
    let lease = Arc::new(ProcessLease::new().unwrap());
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut owner, root) =
        MemoryOwner::new(lease.clone(), &space(5), Metadata::new(1, &drops)).unwrap();
    let mut a = LeaseWorker::spawn(&lease, NAME);
    let first = begin(&mut owner, root, &mut a);
    let result = owner.fork_private(first.turn, |snapshot, _| {
        snapshot.write(BASE, &[77]).unwrap();
        Err(MmError::InvalidArgument(
            "injected fork preparation failure",
        ))
    });
    assert!(matches!(
        result,
        Err(OwnerError::Memory(MmError::InvalidArgument(_)))
    ));
    assert_eq!(owner.last_space, 1);
    assert_eq!(owner.workers.len(), 1);
    assert_eq!(owner.spaces.len(), 1);
    owner
        .with(first.turn, |space, metadata| {
            assert_eq!(byte(space), 5);
            assert_eq!(metadata.brk, 1);
        })
        .unwrap();
    owner.last_space = u64::MAX;
    let called = std::sync::atomic::AtomicBool::new(false);
    assert!(
        owner
            .fork_private(first.turn, |_, _| {
                called.store(true, Ordering::SeqCst);
                Ok(Metadata::new(9, &drops))
            })
            .is_err()
    );
    assert!(!called.load(Ordering::SeqCst));
    assert!(
        owner
            .exec(first.turn, &space(9), Metadata::new(7, &drops))
            .is_err()
    );
    assert_eq!(owner.last_space, u64::MAX);
    assert_eq!(owner.workers.len(), 1);
    assert_eq!(owner.spaces.len(), 1);
    owner
        .with(first.turn, |space, _| assert_eq!(byte(space), 5))
        .unwrap();
    end(&mut owner, first, &mut a);
    a.stop();
    owner.retire(root.worker).unwrap();
}

#[test]
fn requests_require_current_native_holder_and_reentered_turn() {
    const NAME: &str = "user::mm::process_owner::memory::tests::requests_require_current_native_holder_and_reentered_turn";
    serve_if_requested(NAME);
    let lease = Arc::new(ProcessLease::new().unwrap());
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut owner, root) =
        MemoryOwner::new(lease.clone(), &space(5), Metadata::new(1, &drops)).unwrap();
    let mut a = LeaseWorker::spawn(&lease, NAME);
    assert!(owner.begin(root.worker, a.pid()).is_err());
    let first = begin(&mut owner, root, &mut a);
    a.release();
    assert!(
        owner
            .with(first.turn, |_, _| panic!("unleased mutation ran"))
            .is_err()
    );
    assert!(owner.fork_shared(first.turn).is_err());
    assert_eq!(owner.workers.len(), 1);
    let second = begin(&mut owner, root, &mut a);
    assert_ne!(first.turn, second.turn);
    assert!(
        owner
            .with(first.turn, |_, _| panic!("stale mutation ran"))
            .is_err()
    );
    owner
        .with(second.turn, |space, _| assert_eq!(byte(space), 5))
        .unwrap();
    end(&mut owner, second, &mut a);
    assert!(owner.with(second.turn, |_, _| ()).is_err());
    a.stop();
    owner.retire(root.worker).unwrap();
}

#[test]
fn caught_owner_mutation_panic_revokes_every_further_transaction() {
    const NAME: &str = "user::mm::process_owner::memory::tests::caught_owner_mutation_panic_revokes_every_further_transaction";
    serve_if_requested(NAME);
    let lease = Arc::new(ProcessLease::new().unwrap());
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut owner, root) =
        MemoryOwner::new(lease.clone(), &space(5), Metadata::new(1, &drops)).unwrap();
    let mut a = LeaseWorker::spawn(&lease, NAME);
    let first = begin(&mut owner, root, &mut a);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = owner.with(first.turn, |space, metadata| {
            space.write(BASE, &[77]).unwrap();
            metadata.brk = 88;
            panic!("injected owner mutation unwind");
        });
    }));
    assert!(result.is_err());
    assert!(!owner.available);
    assert!(
        owner
            .with(first.turn, |_, _| panic!("poisoned owner resumed"))
            .is_err()
    );
    assert!(owner.fork_shared(first.turn).is_err());
    assert!(owner.begin(root.worker, a.pid()).is_err());
    assert!(owner.end(first.turn).is_err());
    assert!(owner.retire(root.worker).is_err());
    a.release();
    a.stop();
    assert_eq!(lease.holder().unwrap(), None);
}

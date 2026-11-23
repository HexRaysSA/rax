use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::super::MmState;
use crate::user::linux::abi::{LinuxAbi, vma_flags};
use crate::user::linux::tests::harness::Harness;
#[cfg(unix)]
use crate::user::linux::uring::rsrc::{Account, Imu};
use crate::user::mm::{AddressSpace, EXTENT, Mapping, PAGE_SIZE, Perms, SpaceConfig};

const BASE: u64 = 0x1_0000;
const RW: Perms = Perms::READ.union(Perms::WRITE);
const FLAGS: u32 = vma_flags::LOCKED_MASK | vma_flags::GROWSDOWN | vma_flags::NO_READ;

fn space() -> AddressSpace {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    let mut mapping = Mapping::anonymous(RW);
    mapping.flags = FLAGS;
    space.map(BASE, 8 * PAGE_SIZE, mapping).unwrap();
    space
}

pub(crate) fn initial_state(abi: LinuxAbi) -> MmState {
    // Use the actual ELF/stack initialization, including both compat ABIs.
    let harness = Harness::embedded(abi);
    harness.proc.state.mm().clone()
}

fn metadata(abi: LinuxAbi) -> MmState {
    let mut mm = initial_state(abi);
    mm.def_lock = vma_flags::LOCKED_MASK;
    mm.locked_vm = 8;
    mm.pinned_vm.store(3, Ordering::Relaxed);
    mm
}

fn assert_layout(child: &MmState, parent: &MmState) {
    assert_eq!(child.start_brk, parent.start_brk);
    assert_eq!(child.brk, parent.brk);
    assert_eq!(child.mmap_base, parent.mmap_base);
    assert_eq!(child.program, parent.program);
    assert_eq!(child.stack, parent.stack);
}

#[test]
fn private_fork_preserves_layout_and_resets_only_child_locks_and_pins() {
    for abi in [
        LinuxAbi::X86_64,
        LinuxAbi::I386,
        LinuxAbi::Aarch64,
        LinuxAbi::Arm,
        LinuxAbi::Riscv64,
    ] {
        let parent = metadata(abi);
        let parent_space = space();
        let snapshot = space();
        let child = parent.fork_private(&snapshot).unwrap();
        assert_layout(&child, &parent);
        assert_eq!(child.def_lock, 0, "{abi:?}");
        assert_eq!(child.locked_vm, 0, "{abi:?}");
        assert_eq!(child.pinned_vm.load(Ordering::Relaxed), 0);
        assert!(!Arc::ptr_eq(&child.pinned_vm, &parent.pinned_vm));
        assert_eq!(parent.def_lock, vma_flags::LOCKED_MASK);
        assert_eq!(parent.locked_vm, 8);
        assert_eq!(parent.pinned_vm.load(Ordering::Relaxed), 3);
        assert_eq!(parent_space.vma_at(BASE).unwrap().flags, FLAGS);
        let vma = snapshot.vma_at(BASE).unwrap();
        assert_eq!(vma.flags, FLAGS & !vma_flags::LOCKED_MASK);
        assert_eq!(vma.perms, RW);
        assert!(
            !snapshot.is_resident(BASE),
            "lock removal must not populate"
        );
        child.pinned_vm.store(7, Ordering::Relaxed);
        assert_eq!(parent.pinned_vm.load(Ordering::Relaxed), 3);
    }
}

#[test]
fn lock_reset_preserves_existing_ring_accounts_and_handles_empty_mms() {
    let mut mm = metadata(LinuxAbi::Aarch64);
    let retained = mm.pinned_vm.clone();
    let mapped = space();
    mm.reset_fork_locks(&mapped).unwrap();
    assert!(Arc::ptr_eq(&retained, &mm.pinned_vm));
    assert_eq!(retained.load(Ordering::Relaxed), 3);
    assert_eq!(mm.def_lock, 0);
    assert_eq!(mm.locked_vm, 0);
    mapped.unmap(BASE, 8 * PAGE_SIZE).unwrap();
    let child = mm.fork_private(&mapped).unwrap();
    assert_eq!(child.pinned_vm.load(Ordering::Relaxed), 0);
    assert!(!Arc::ptr_eq(&child.pinned_vm, &retained));
    assert!(mapped.vma_snapshot().is_empty());
}

#[cfg(unix)]
#[test]
fn native_owner_shares_linux_mm_and_preserves_old_ring_accounts_across_exec() {
    use crate::user::mm::process_lease::ProcessLease;
    use crate::user::mm::process_lease::test_worker::{LeaseWorker, serve_if_requested};
    use crate::user::mm::process_owner::MemoryOwner;

    const NAME: &str = "user::linux::process::mm::tests::native_owner_shares_linux_mm_and_preserves_old_ring_accounts_across_exec";
    serve_if_requested(NAME);

    let lease = Arc::new(ProcessLease::new().unwrap());
    let initial = space();
    initial.write(BASE, &[53]).unwrap();
    let mm = metadata(LinuxAbi::Aarch64);
    let layout = (mm.program.clone(), mm.stack.clone());
    let old_counter = Arc::downgrade(&mm.pinned_vm);
    let old_buffer = Imu {
        addr: BASE,
        len: 3 * PAGE_SIZE as u32,
        acct_pages: 3,
        account: Account {
            user: None,
            mm: mm.pinned_vm.clone(),
        },
    };
    let (mut owner, root) = MemoryOwner::new(lease.clone(), &initial, mm).unwrap();
    let mut root_worker = LeaseWorker::spawn(&lease, NAME);
    root_worker.acquire();
    let root_turn = owner.begin(root.worker, root_worker.pid()).unwrap();
    let shared = owner.fork_shared(root_turn.turn).unwrap();
    let private = owner
        .fork_private(root_turn.turn, |snapshot, mm| {
            MmState::fork_private(mm, snapshot)
        })
        .unwrap();
    assert_eq!(root.space, shared.space);
    assert_ne!(root.space, private.space);
    let old_physical = owner
        .with(root_turn.turn, |space, mm| {
            mm.brk += PAGE_SIZE;
            assert_eq!(space.vma_at(BASE).unwrap().flags, FLAGS);
            Arc::downgrade(space.physical_memory())
        })
        .unwrap();
    owner.end(root_turn.turn).unwrap();
    root_worker.release();

    let mut private_worker = LeaseWorker::spawn(&lease, NAME);
    private_worker.acquire();
    let private_turn = owner.begin(private.worker, private_worker.pid()).unwrap();
    let private_buffer = owner
        .with(private_turn.turn, |space, mm| {
            assert_eq!(mm.program, layout.0);
            assert_eq!(mm.stack, layout.1);
            assert_eq!(mm.brk, mm.start_brk);
            assert_eq!(mm.def_lock, 0);
            assert_eq!(mm.locked_vm, 0);
            assert_eq!(mm.pinned_vm.load(Ordering::Relaxed), 0);
            assert!(!Arc::ptr_eq(&mm.pinned_vm, &old_buffer.account.mm));
            assert_eq!(
                space.vma_at(BASE).unwrap().flags,
                FLAGS & !vma_flags::LOCKED_MASK
            );
            space.write(BASE, &[99]).unwrap();
            mm.pinned_vm.store(5, Ordering::Relaxed);
            Imu {
                addr: BASE,
                len: 5 * PAGE_SIZE as u32,
                acct_pages: 5,
                account: Account {
                    user: None,
                    mm: mm.pinned_vm.clone(),
                },
            }
        })
        .unwrap();
    let nested = owner
        .fork_private(private_turn.turn, |snapshot, mm| {
            MmState::fork_private(mm, snapshot)
        })
        .unwrap();
    assert_ne!(nested.space, private.space);
    owner.end(private_turn.turn).unwrap();
    private_worker.release();

    let mut shared_worker = LeaseWorker::spawn(&lease, NAME);
    shared_worker.acquire();
    let shared_turn = owner.begin(shared.worker, shared_worker.pid()).unwrap();
    owner
        .with(shared_turn.turn, |space, mm| {
            assert_eq!(mm.brk, mm.start_brk + PAGE_SIZE);
            assert_eq!(mm.def_lock, vma_flags::LOCKED_MASK);
            assert_eq!(mm.locked_vm, 8);
            assert!(Arc::ptr_eq(&mm.pinned_vm, &old_buffer.account.mm));
            assert_eq!(mm.pinned_vm.load(Ordering::Relaxed), 3);
            let mut value = [0];
            space.read(BASE, &mut value).unwrap();
            assert_eq!(value, [53]);
        })
        .unwrap();
    let mut replacement = metadata(LinuxAbi::X86_64);
    replacement.def_lock = 0;
    replacement.locked_vm = 0;
    replacement.pinned_vm.store(0, Ordering::Relaxed);
    let new_counter = Arc::downgrade(&replacement.pinned_vm);
    let prepared = space();
    let next = owner
        .exec(shared_turn.turn, &prepared, replacement)
        .unwrap();
    assert_ne!(next.turn, shared_turn.turn);
    assert_ne!(next.space, root.space);
    assert!(owner.with(shared_turn.turn, |_, _| ()).is_err());
    owner
        .with(next.turn, |_, mm| {
            assert_eq!(mm.def_lock, 0);
            assert_eq!(mm.locked_vm, 0);
            assert_eq!(mm.pinned_vm.load(Ordering::Relaxed), 0);
            assert!(!Arc::ptr_eq(&mm.pinned_vm, &old_buffer.account.mm));
        })
        .unwrap();
    owner.end(next.turn).unwrap();
    shared_worker.release();

    root_worker.stop();
    assert!(owner.retire(root.worker).unwrap());
    assert!(old_physical.upgrade().is_none());
    assert!(
        old_counter.upgrade().is_some(),
        "the ring retains its old MM account"
    );
    let retained = old_counter.upgrade().unwrap();
    drop(old_buffer);
    assert_eq!(retained.load(Ordering::Relaxed), 0);
    drop(retained);
    assert!(old_counter.upgrade().is_none());

    // The nested private child begins with a fresh counter even though its
    // immediate parent has charged a live registered buffer.
    let mut nested_worker = LeaseWorker::spawn(&lease, NAME);
    nested_worker.acquire();
    let nested_turn = owner.begin(nested.worker, nested_worker.pid()).unwrap();
    owner
        .with(nested_turn.turn, |space, mm| {
            assert_eq!(mm.pinned_vm.load(Ordering::Relaxed), 0);
            assert!(!Arc::ptr_eq(&mm.pinned_vm, &private_buffer.account.mm));
            let mut value = [0];
            space.read(BASE, &mut value).unwrap();
            assert_eq!(value, [99]);
        })
        .unwrap();
    owner.end(nested_turn.turn).unwrap();
    nested_worker.release();
    nested_worker.stop();
    assert!(owner.retire(nested.worker).unwrap());
    private_worker.stop();
    assert!(owner.retire(private.worker).unwrap());
    let private_counter = private_buffer.account.mm.clone();
    drop(private_buffer);
    assert_eq!(private_counter.load(Ordering::Relaxed), 0);
    shared_worker.stop();
    assert!(owner.retire(shared.worker).unwrap());
    assert!(new_counter.upgrade().is_none());
}

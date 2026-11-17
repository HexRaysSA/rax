use super::{LockPolicy, MmResources, initial_state};
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::{EAGAIN, EFAULT, EINVAL, ENOMEM};
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE, vma_flags};
use crate::user::linux::aio::{AIO_MAX_NR, RING_MAGIC, Table};
use crate::user::mm::{AddressSpace, EXTENT, Mapping, Perms, SpaceConfig};
use std::sync::Arc;

const CONTEXT: u64 = 0x1_0000;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn fixture(abi: LinuxAbi) -> (AddressSpace, MmResources, LockPolicy) {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    space
        .map(
            CONTEXT,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    let resources = MmResources::new(initial_state(abi), Table::default());
    let policy = LockPolicy {
        abi,
        privileged: false,
        memlock_limit: 8 * PAGE_SIZE,
    };
    (space, resources, policy)
}

fn context_pointer(space: &AddressSpace, abi: LinuxAbi) -> u64 {
    let mut bytes = [0; 8];
    let width = if abi.is_compat() { 4 } else { 8 };
    space.read(CONTEXT, &mut bytes[..width]).unwrap();
    u64::from_le_bytes(bytes)
}

fn assert_ring(space: &AddressSpace, resources: &MmResources, abi: LinuxAbi) {
    let address = context_pointer(space, abi);
    let context = resources.aio.contexts[0].as_ref().unwrap();
    assert_eq!(context.id, address);
    assert_eq!(context.max_reqs, 8);
    assert_eq!(resources.aio.aio_nr, 8);
    assert!(context.polls.is_empty());
    let mapping = space.vma_at(address).unwrap();
    assert_eq!(mapping.flags, vma_flags::SPECIAL | vma_flags::AIO_RING);
    assert!(mapping.shared);
    let mut header = [0; 32];
    space.read(address, &mut header).unwrap();
    assert_eq!(&header[16..20], &RING_MAGIC.to_le_bytes());
    assert_eq!(&header[28..32], &32_u32.to_le_bytes());
    assert_eq!(&header[4..8], &context.nr_events.to_le_bytes());
    assert_eq!(resources.mm.locked_vm, 0);
}

#[test]
fn local_setup_writes_only_the_abi_width_and_publishes_one_real_shared_ring() {
    for abi in ABIS {
        let (space, mut resources, policy) = fixture(abi);
        let width = policy.abi.word_size();
        space.write(CONTEXT + width, &[0xa5; 8]).unwrap();
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 8, CONTEXT),
            Ok(0)
        );
        assert_ring(&space, &resources, abi);
        let mut guard = [0; 8];
        space.read(CONTEXT + width, &mut guard).unwrap();
        assert_eq!(guard, [0xa5; 8]);
        let address = context_pointer(&space, abi);
        let context = resources.aio.contexts[0].as_ref().unwrap();
        let ring = Arc::downgrade(&context.ring);
        let snapshot = space.process_snapshot().unwrap();
        let child = resources.fork_private(&snapshot).unwrap();
        assert!(child.aio.contexts.is_empty());
        assert_eq!(child.aio.aio_nr, 0);
        assert_eq!(context_pointer(&snapshot, abi), address);
        drop(resources);
        assert!(ring.upgrade().is_some(), "VMAs retain the actual ring");
        drop(space);
        assert!(ring.upgrade().is_some(), "the inherited VMA remains shared");
        drop(child);
        drop(snapshot);
        assert!(ring.upgrade().is_none());
    }
}

#[test]
fn setup_faults_and_count_limits_preserve_kernel_check_order_without_live_contexts() {
    for abi in ABIS {
        let (space, mut resources, policy) = fixture(abi);
        for count in [0, 1, u32::MAX] {
            assert_eq!(
                resources
                    .mm
                    .setup_aio(&space, &mut resources.aio, policy, count, 0),
                Err(Errno(EFAULT)),
                "the context is read before the count is checked: {abi:?}"
            );
        }
        for (count, expected) in [
            (0, EINVAL),
            (AIO_MAX_NR as u32 + 1, EAGAIN),
            (0x40_0001, EINVAL),
            (0x8000_0000, EAGAIN),
            (u32::MAX, EINVAL),
        ] {
            assert_eq!(
                resources
                    .mm
                    .setup_aio(&space, &mut resources.aio, policy, count, CONTEXT),
                Err(Errno(expected)),
                "{abi:?}, count={count}"
            );
        }
        space.write(CONTEXT, &1_u32.to_le_bytes()).unwrap();
        assert_eq!(
            resources.mm.setup_aio(
                &space,
                &mut resources.aio,
                policy,
                AIO_MAX_NR as u32 + 1,
                CONTEXT
            ),
            Err(Errno(EINVAL)),
            "a nonzero handle precedes geometry and quota checks"
        );
        assert!(resources.aio.contexts.is_empty());
        assert_eq!(resources.aio.aio_nr, 0);
        assert_eq!(space.vma_snapshot().len(), 1);
    }
}

#[test]
fn future_lock_limit_is_checked_but_successful_special_rings_are_not_charged() {
    for abi in ABIS {
        let (space, mut resources, mut policy) = fixture(abi);
        resources.mm.def_lock = vma_flags::LOCKED_MASK;
        policy.memlock_limit = PAGE_SIZE - 1;
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 8, CONTEXT),
            Err(Errno(ENOMEM))
        );
        assert!(resources.aio.contexts.is_empty());
        assert_eq!(space.vma_snapshot().len(), 1);
        policy.memlock_limit = PAGE_SIZE;
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 8, CONTEXT),
            Ok(0)
        );
        assert_ring(&space, &resources, abi);

        // Existing locked pages consume the same calling-process limit.
        let (space, mut resources, mut policy) = fixture(abi);
        resources.mm.def_lock = vma_flags::LOCKED;
        space
            .set_flags(
                CONTEXT,
                PAGE_SIZE,
                vma_flags::LOCKED_MASK,
                vma_flags::LOCKED,
            )
            .unwrap();
        resources.mm.locked_vm = 1;
        policy.memlock_limit = PAGE_SIZE;
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 8, CONTEXT),
            Err(Errno(ENOMEM))
        );
        policy.privileged = true;
        policy.memlock_limit = 0;
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 8, CONTEXT),
            Ok(0)
        );
        assert_eq!(resources.mm.locked_vm, 1);
    }
}

#[test]
fn failed_handle_store_releases_only_the_new_ring_and_preserves_real_pending_requests() {
    for abi in ABIS {
        let (space, mut resources, witness) = super::pending_fixture(abi, 0x2_0000);
        space
            .map(CONTEXT, PAGE_SIZE, Mapping::anonymous(Perms::READ))
            .unwrap();
        let policy = LockPolicy {
            abi,
            privileged: false,
            memlock_limit: 0,
        };
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 8, CONTEXT),
            Err(Errno(EFAULT))
        );
        assert_eq!(resources.aio.aio_nr, 8);
        assert_eq!(space.vma_snapshot().len(), 2, "new ring was unmapped");
        assert_eq!(resources.aio.contexts.len(), 2);
        assert!(resources.aio.contexts[1].is_none());
        let context = resources.aio.get(witness.handle).unwrap();
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
        assert_eq!(context.peek_events(1).0[0].res, 23);
        space
            .protect(CONTEXT, PAGE_SIZE, Perms::READ | Perms::WRITE)
            .unwrap();
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 8, CONTEXT),
            Ok(0)
        );
        assert_eq!(resources.aio.aio_nr, 16);
        let added = resources.aio.contexts[1].as_ref().unwrap();
        assert_eq!(added.index, 1, "failed setup's slot can be reused");
        assert!(added.serial > witness.handle.serial);
    }
}

#[test]
fn shared_table_quota_failure_unmaps_the_candidate_without_removing_the_live_ring() {
    for abi in ABIS {
        let (space, mut resources, policy) = fixture(abi);
        assert_eq!(
            resources.mm.setup_aio(
                &space,
                &mut resources.aio,
                policy,
                AIO_MAX_NR as u32,
                CONTEXT
            ),
            Ok(0)
        );
        let ring = context_pointer(&space, abi);
        let live = Arc::downgrade(&resources.aio.contexts[0].as_ref().unwrap().ring);
        let before = space.vma_snapshot().len();
        assert_eq!(
            resources
                .mm
                .setup_aio(&space, &mut resources.aio, policy, 1, CONTEXT + 16),
            Err(Errno(EAGAIN))
        );
        assert_eq!(space.vma_snapshot().len(), before);
        assert_eq!(resources.aio.aio_nr, AIO_MAX_NR);
        assert_eq!(resources.aio.contexts.len(), 1);
        assert_eq!(resources.aio.contexts[0].as_ref().unwrap().id, ring);
        assert!(live.upgrade().is_some());
        let mut untouched = [1; 8];
        space.read(CONTEXT + 16, &mut untouched).unwrap();
        assert_eq!(untouched, [0; 8]);
    }
}

#[cfg(unix)]
#[test]
fn owner_aio_setup_publishes_the_actual_ring_and_table_for_each_guest_abi() {
    for abi in ABIS {
        let (space, mut resources, policy) = fixture(abi);
        // A raw request also exercises decoding of the new private operation;
        // the pre-change owner rejects it before allocating a context.
        let request = serde_json::to_vec(&serde_json::json!({
            "operation": "AioSetup",
            "policy": policy,
            "nr_events": 8,
            "context": CONTEXT,
        }))
        .unwrap();
        let reply = super::remote::execute(&mut resources, &space, &request, &Default::default())
            .expect("owner must execute the complete setup operation");
        let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(
            reply,
            serde_json::json!({"reply":"AioSetup","result":{"Ok":0}})
        );
        assert_ring(&space, &resources, abi);
    }
}

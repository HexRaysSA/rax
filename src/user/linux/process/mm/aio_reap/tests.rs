use super::*;
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE, vma_flags};
use crate::user::linux::process::mm::{MmResources, pending_fixture};
use crate::user::mm::{Backing, Mapping, Perms, SharedObject};
use std::sync::Arc;

const RING: u64 = 0x2_0000;
const OUTPUT: u64 = 0x4_0000;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn output(space: &AddressSpace) {
    space
        .map(
            OUTPUT,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
}

fn arguments(handle: Handle) -> AioRead {
    AioRead {
        handle,
        min_nr: 1,
        nr: 2,
        events: OUTPUT,
        got: 0,
    }
}

fn head(space: &AddressSpace) -> u32 {
    let mut bytes = [0; 4];
    space.read(RING + 8, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

fn complete(resources: &mut MmResources, handle: Handle, data: u64) {
    let context = resources.aio.get(handle).unwrap();
    assert!(context.get_req());
    context.complete(Event {
        data,
        obj: RING + 0x180,
        res: -7,
        res2: 0,
    });
}

#[test]
fn lookup_requires_the_readable_live_ring_address_and_its_actual_table_index() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        assert_eq!(
            resources.aio.lookup_in_space(&space, RING),
            Ok(witness.handle)
        );
        assert_eq!(resources.aio.lookup_in_space(&space, 0), Err(Errno(EINVAL)));
        output(&space);
        space.write(OUTPUT, &0_u32.to_le_bytes()).unwrap();
        assert_eq!(
            resources.aio.lookup_in_space(&space, OUTPUT),
            Err(Errno(EINVAL)),
            "a readable forged header is not the context's address"
        );
        space.write(RING, &u32::MAX.to_le_bytes()).unwrap();
        assert_eq!(
            resources.aio.lookup_in_space(&space, RING),
            Err(Errno(EINVAL))
        );
        space.write(RING, &0_u32.to_le_bytes()).unwrap();
        space.protect(RING, PAGE_SIZE, Perms::empty()).unwrap();
        assert_eq!(
            resources.aio.lookup_in_space(&space, RING),
            Err(Errno(EINVAL))
        );
        space
            .protect(RING, PAGE_SIZE, Perms::READ | Perms::WRITE)
            .unwrap();
        let snapshot = space.process_snapshot().unwrap();
        let mut child = resources.fork_private(&snapshot).unwrap();
        assert_eq!(
            child.aio.lookup_in_space(&snapshot, RING),
            Err(Errno(EINVAL)),
            "the inherited shared ring does not populate a private table"
        );
        assert!(witness.file.upgrade().is_some());
        assert!(witness.resfd.upgrade().is_some());
    }
}

#[test]
fn successive_passes_copy_after_the_prior_count_and_preserve_actual_pending_resources() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        output(&space);
        let mut request = arguments(witness.handle);
        request.min_nr = 2;
        request.nr = 3;
        let first = resources.aio.read_events(&space, request).unwrap();
        assert_eq!(
            first,
            AioReadResult {
                got: 1,
                done: false
            }
        );
        assert_eq!(head(&space), 1);
        complete(&mut resources, witness.handle, 41);
        request.got = first.got;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 2, done: true })
        );
        let mut bytes = [0; 64];
        space.read(OUTPUT, &mut bytes).unwrap();
        assert_eq!(
            &bytes[..32],
            &Event {
                data: 17,
                obj: RING + 0x80,
                res: 23,
                res2: 0,
            }
            .encode()
        );
        assert_eq!(&bytes[32..40], &41_u64.to_le_bytes());
        assert_eq!(&bytes[48..56], &(-7_i64).to_le_bytes());
        assert_eq!(head(&space), 2);
        assert_eq!(resources.aio.aio_nr, 8);
        let context = resources.aio.get(witness.handle).unwrap();
        assert_eq!(context.polls.len(), 1);
        assert!(Arc::ptr_eq(
            &context.polls[0].file,
            &witness.file.upgrade().unwrap()
        ));
        assert!(Arc::ptr_eq(
            context.polls[0].resfd.as_ref().unwrap(),
            &witness.resfd.upgrade().unwrap()
        ));
    }
}

#[test]
fn faults_leave_the_batch_in_the_ring_and_return_only_a_real_prior_count() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        output(&space);
        let mut request = arguments(witness.handle);
        request.events = 0;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EFAULT))
        );
        assert_eq!(head(&space), 0);
        request.events = OUTPUT + PAGE_SIZE - 64;
        request.min_nr = 3;
        request.nr = 3;
        let first = resources.aio.read_events(&space, request).unwrap();
        assert_eq!(
            first,
            AioReadResult {
                got: 1,
                done: false
            }
        );
        complete(&mut resources, witness.handle, 41);
        complete(&mut resources, witness.handle, 43);
        request.got = first.got;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 1, done: true }),
            "the second event of this batch crosses into an unmapped page"
        );
        assert_eq!(head(&space), 1);
        request.events = OUTPUT;
        request.got = 0;
        request.min_nr = 2;
        request.nr = 2;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 2, done: true })
        );
        let mut bytes = [0; 64];
        space.read(OUTPUT, &mut bytes).unwrap();
        assert_eq!(&bytes[..8], &41_u64.to_le_bytes());
        assert_eq!(&bytes[32..40], &43_u64.to_le_bytes());
        assert_eq!(head(&space), 3);
        assert!(witness.file.upgrade().is_some());
        assert!(witness.resfd.upgrade().is_some());
    }
}

#[test]
fn killed_handle_never_reaps_a_replacement_in_the_same_slot_and_virtual_address() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        output(&space);
        let retired = resources.aio.contexts[witness.handle.slot].take().unwrap();
        let ring = Arc::new(SharedObject::anonymous(PAGE_SIZE).unwrap());
        space.unmap(RING, PAGE_SIZE).unwrap();
        space
            .map(
                RING,
                PAGE_SIZE,
                Mapping {
                    backing: Backing::Shared {
                        object: ring.clone(),
                        offset: 0,
                    },
                    shared: true,
                    flags: vma_flags::SPECIAL | vma_flags::AIO_RING,
                    ..Mapping::anonymous(Perms::READ | Perms::WRITE)
                },
            )
            .unwrap();
        let replacement = resources.aio.insert(Context::new(
            RING,
            retired.index,
            ring,
            PAGE_SIZE,
            retired.nr_events,
            retired.max_reqs,
        ));
        assert_ne!(replacement, witness.handle);
        assert_eq!(replacement.slot, witness.handle.slot);
        complete(&mut resources, replacement, 0x99);
        let mut request = arguments(witness.handle);
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EINVAL))
        );
        request.got = 1;
        request.min_nr = 2;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 1, done: true })
        );
        assert_eq!(head(&space), 0);
        request = arguments(replacement);
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 1, done: true })
        );
        let mut bytes = [0; 8];
        space.read(OUTPUT, &mut bytes).unwrap();
        assert_eq!(bytes, 0x99_u64.to_le_bytes());
    }
}

#[test]
fn ring_read_protection_or_unmapping_does_not_revoke_an_already_held_context() {
    for abi in ABIS {
        for unmap in [false, true] {
            let (space, mut resources, witness) = pending_fixture(abi, RING);
            output(&space);
            if unmap {
                space.unmap(RING, PAGE_SIZE).unwrap();
            } else {
                space.protect(RING, PAGE_SIZE, Perms::READ).unwrap();
            }
            assert_eq!(
                resources.aio.read_events(&space, arguments(witness.handle)),
                Ok(AioReadResult { got: 1, done: true })
            );
            assert!(witness.ring.upgrade().is_some());
            if !unmap {
                assert_eq!(
                    head(&space),
                    1,
                    "kernel backing writes bypass guest protection"
                );
            }
        }
    }
}

#[test]
fn invalid_progress_is_rejected_and_zero_limit_does_not_touch_the_output() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        let base = arguments(witness.handle);
        for request in [
            AioRead { min_nr: -1, ..base },
            AioRead { nr: -1, ..base },
            AioRead { min_nr: 3, ..base },
            AioRead { got: 3, ..base },
            AioRead {
                got: u64::MAX,
                ..base
            },
        ] {
            assert_eq!(
                resources.aio.read_events(&space, request),
                Err(Errno(EINVAL))
            );
            assert_eq!(head(&space), 0);
        }
        assert_eq!(
            resources.aio.read_events(
                &space,
                AioRead {
                    min_nr: 0,
                    nr: 0,
                    events: u64::MAX,
                    ..base
                }
            ),
            Ok(AioReadResult { got: 0, done: true })
        );
        assert_eq!(head(&space), 0);
        output(&space);
        assert_eq!(
            resources.aio.read_events(
                &space,
                AioRead {
                    nr: i64::MAX,
                    ..base
                }
            ),
            Ok(AioReadResult { got: 1, done: true }),
            "allocation follows the available ring contents, not the requested maximum"
        );
    }
}

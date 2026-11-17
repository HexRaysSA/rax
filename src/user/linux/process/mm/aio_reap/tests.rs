use super::*;
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE, vma_flags};
use crate::user::linux::aio::Event;
use crate::user::linux::process::mm::{MmResources, pending_fixture};
use crate::user::mm::{Backing, BytesSource, Mapping, Perms, SharedObject};
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

fn arguments(abi: LinuxAbi, handle: Handle) -> AioRead {
    AioRead {
        abi,
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

fn empty_at_last_slot(
    space: &AddressSpace,
    resources: &mut MmResources,
    abi: LinuxAbi,
    handle: Handle,
) -> u32 {
    let slots = resources.aio.get(handle).unwrap().nr_events;
    let request = AioRead {
        nr: 1,
        ..arguments(abi, handle)
    };
    assert_eq!(
        resources.aio.read_events(space, request),
        Ok(AioReadResult { got: 1, done: true })
    );
    for data in 1..u64::from(slots - 1) {
        complete(resources, handle, data);
        assert_eq!(
            resources.aio.read_events(space, request),
            Ok(AioReadResult { got: 1, done: true })
        );
    }
    assert_eq!(head(space), slots - 1);
    slots - 1
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
        let mut request = arguments(abi, witness.handle);
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
        let mut request = arguments(abi, witness.handle);
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
        let mut partial = [0; 32];
        space.read(OUTPUT + PAGE_SIZE - 32, &mut partial).unwrap();
        assert_eq!(
            partial,
            Event {
                data: 41,
                obj: RING + 0x180,
                res: -7,
                res2: 0,
            }
            .encode(),
            "the failed batch retains its successfully copied output prefix"
        );
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
fn short_output_copy_preserves_the_accessible_prefix_without_consuming_completions() {
    for abi in ABIS {
        for guard in [None, Some(Perms::READ), Some(Perms::empty())] {
            for prefix in 0..=64 {
                let (space, mut resources, witness) = pending_fixture(abi, RING);
                output(&space);
                space.write(OUTPUT, &[0xa5; PAGE_SIZE as usize]).unwrap();
                if let Some(perms) = guard {
                    space
                        .map(
                            OUTPUT + PAGE_SIZE,
                            PAGE_SIZE,
                            Mapping::anonymous(Perms::READ | Perms::WRITE),
                        )
                        .unwrap();
                    space
                        .write(OUTPUT + PAGE_SIZE, &[0xa5; PAGE_SIZE as usize])
                        .unwrap();
                    space.protect(OUTPUT + PAGE_SIZE, PAGE_SIZE, perms).unwrap();
                }
                complete(&mut resources, witness.handle, 41);
                let expected: Vec<u8> = [
                    Event {
                        data: 17,
                        obj: RING + 0x80,
                        res: 23,
                        res2: 0,
                    },
                    Event {
                        data: 41,
                        obj: RING + 0x180,
                        res: -7,
                        res2: 0,
                    },
                ]
                .iter()
                .flat_map(Event::encode)
                .collect();
                let mut request = arguments(abi, witness.handle);
                request.events = OUTPUT + PAGE_SIZE - prefix as u64;
                request.min_nr = 2;
                let result = resources.aio.read_events(&space, request);
                assert_eq!(
                    result,
                    if prefix == 64 {
                        Ok(AioReadResult { got: 2, done: true })
                    } else {
                        Err(Errno(EFAULT))
                    },
                    "abi={abi:?}, prefix={prefix}, guard={guard:?}"
                );
                let mut page = [0; PAGE_SIZE as usize];
                space.read(OUTPUT, &mut page).unwrap();
                let split = page.len() - prefix;
                assert_eq!(&page[..split], &vec![0xa5; split]);
                assert_eq!(
                    &page[split..],
                    &expected[..prefix],
                    "abi={abi:?}, prefix={prefix}, guard={guard:?}"
                );
                if guard.is_some() {
                    space.read_raw(OUTPUT + PAGE_SIZE, &mut page).unwrap();
                    assert_eq!(page, [0xa5; PAGE_SIZE as usize]);
                }
                assert_eq!(head(&space), if prefix == 64 { 2 } else { 0 });
                if prefix < 64 {
                    request.events = OUTPUT;
                    assert_eq!(
                        resources.aio.read_events(&space, request),
                        Ok(AioReadResult { got: 2, done: true })
                    );
                    let mut reaped = [0; 64];
                    space.read(OUTPUT, &mut reaped).unwrap();
                    assert_eq!(&reaped, expected.as_slice());
                    assert_eq!(head(&space), 2);
                }
                assert!(witness.file.upgrade().is_some());
                assert!(witness.resfd.upgrade().is_some());
            }
        }
    }
}

#[test]
fn user_pointer_range_is_checked_before_copy_but_compat_va_holes_keep_the_prefix() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        let top = abi.task_size();
        space
            .map(
                top - PAGE_SIZE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        space.write(top - 16, &[0xa5; 16]).unwrap();
        let mut request = arguments(abi, witness.handle);
        request.events = top - 16;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EFAULT))
        );
        let mut bytes = [0; 16];
        space.read(top - 16, &mut bytes).unwrap();
        if abi.user_ptr_max() > top {
            assert_eq!(&bytes[..8], &17_u64.to_le_bytes());
            assert_eq!(&bytes[8..], &(RING + 0x80).to_le_bytes());
        } else {
            assert_eq!(bytes, [0xa5; 16], "access_ok rejects the whole range");
        }
        assert_eq!(head(&space), 0);
        request.events = u64::MAX - 15;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EFAULT))
        );
        let mut after = [0; 16];
        space.read(top - 16, &mut after).unwrap();
        assert_eq!(after, bytes, "an overflowing range has no copy effects");
        assert_eq!(head(&space), 0);
    }
}

#[test]
fn lazy_output_population_preserves_the_prefix_when_the_next_source_page_is_missing() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        output(&space);
        space
            .map(
                OUTPUT + PAGE_SIZE,
                PAGE_SIZE,
                Mapping {
                    backing: Backing::Source {
                        source: Arc::new(BytesSource::new(Arc::from([]))),
                        offset: 0,
                    },
                    ..Mapping::anonymous(Perms::READ | Perms::WRITE)
                },
            )
            .unwrap();
        assert!(!space.is_resident(OUTPUT));
        assert!(!space.is_resident(OUTPUT + PAGE_SIZE));
        let mut request = arguments(abi, witness.handle);
        request.events = OUTPUT + PAGE_SIZE - 16;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EFAULT))
        );
        let mut bytes = [0; 16];
        space.read(OUTPUT + PAGE_SIZE - 16, &mut bytes).unwrap();
        assert_eq!(&bytes[..8], &17_u64.to_le_bytes());
        assert_eq!(&bytes[8..], &(RING + 0x80).to_le_bytes());
        assert!(space.is_resident(OUTPUT));
        assert!(!space.is_resident(OUTPUT + PAGE_SIZE));
        assert_eq!(head(&space), 0);
        request.events = OUTPUT;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 1, done: true })
        );
        assert_eq!(head(&space), 1);
    }
}

#[test]
fn a_short_copy_across_ring_wrap_keeps_both_events_and_the_original_head() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        output(&space);
        let original = empty_at_last_slot(&space, &mut resources, abi, witness.handle);
        complete(&mut resources, witness.handle, 41);
        complete(&mut resources, witness.handle, 43);
        let mut request = arguments(abi, witness.handle);
        request.events = OUTPUT + PAGE_SIZE - 32;
        request.min_nr = 2;
        request.nr = 2;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EFAULT))
        );
        assert_eq!(head(&space), original);
        let mut first = [0; 32];
        space.read(OUTPUT + PAGE_SIZE - 32, &mut first).unwrap();
        assert_eq!(
            first,
            Event {
                data: 41,
                obj: RING + 0x180,
                res: -7,
                res2: 0,
            }
            .encode()
        );
        request.events = OUTPUT;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 2, done: true })
        );
        let mut bytes = [0; 64];
        space.read(OUTPUT, &mut bytes).unwrap();
        assert_eq!(&bytes[..8], &41_u64.to_le_bytes());
        assert_eq!(&bytes[32..40], &43_u64.to_le_bytes());
        assert_eq!(head(&space), 1);
    }
}

#[test]
fn wrapped_copy_validates_each_source_batch_before_committing_the_ring_head() {
    for abi in LinuxAbi::ALL {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        output(&space);
        let original = empty_at_last_slot(&space, &mut resources, abi, witness.handle);
        complete(&mut resources, witness.handle, 41);
        complete(&mut resources, witness.handle, 43);
        let top = abi.user_ptr_max();
        space
            .map(
                top - PAGE_SIZE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        let request = AioRead {
            events: top - 32,
            min_nr: 2,
            ..arguments(abi, witness.handle)
        };
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EFAULT))
        );
        let mut first = [0; 32];
        space.read(top - 32, &mut first).unwrap();
        assert_eq!(
            first,
            Event {
                data: 41,
                obj: RING + 0x180,
                res: -7,
                res2: 0,
            }
            .encode()
        );
        assert_eq!(head(&space), original);
    }
}

#[test]
fn output_alias_into_a_later_source_batch_is_observed_after_ring_wrap() {
    for abi in ABIS {
        let (space, mut resources, witness) = pending_fixture(abi, RING);
        output(&space);
        empty_at_last_slot(&space, &mut resources, abi, witness.handle);
        complete(&mut resources, witness.handle, 41);
        complete(&mut resources, witness.handle, 43);
        // The last slot copies 41 over slot zero. After the wrap, the next
        // kernel source batch therefore reads 41 from slot zero too.
        let request = AioRead {
            events: RING + 32,
            min_nr: 2,
            ..arguments(abi, witness.handle)
        };
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 2, done: true })
        );
        let mut bytes = [0; 64];
        space.read(RING + 32, &mut bytes).unwrap();
        assert_eq!(&bytes[..8], &41_u64.to_le_bytes());
        assert_eq!(&bytes[32..40], &41_u64.to_le_bytes());
        assert_eq!(head(&space), 1);
    }
}

#[test]
fn source_page_boundary_keeps_earlier_copies_but_not_a_failed_pass_count() {
    const LARGE_RING: u64 = RING + 4 * PAGE_SIZE;
    for abi in LinuxAbi::ALL {
        let (space, mut resources, _witness) = pending_fixture(abi, RING);
        output(&space);
        let (slots, size) = Context::ring_geometry(64).unwrap();
        assert_eq!(size, 2 * PAGE_SIZE);
        let ring = Arc::new(SharedObject::anonymous(size).unwrap());
        space
            .map(
                LARGE_RING,
                size,
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
        let handle = resources
            .aio
            .insert(Context::new(LARGE_RING, 1, ring, size, slots, 64));
        resources.aio.aio_nr += 64;
        let mut request = AioRead {
            nr: 1,
            ..arguments(abi, handle)
        };
        for data in 0..126 {
            complete(&mut resources, handle, data);
            assert_eq!(
                resources.aio.read_events(&space, request),
                Ok(AioReadResult { got: 1, done: true })
            );
        }
        complete(&mut resources, handle, 41);
        complete(&mut resources, handle, 43);
        request.events = abi.user_ptr_max() - 32;
        space
            .map(
                abi.user_ptr_max() - PAGE_SIZE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        request.nr = 2;
        request.min_nr = 2;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Err(Errno(EFAULT))
        );
        let mut first = [0; 32];
        space.read(request.events, &mut first).unwrap();
        assert_eq!(&first[..8], &41_u64.to_le_bytes());
        let mut index = [0; 4];
        space.read(LARGE_RING + 8, &mut index).unwrap();
        assert_eq!(u32::from_le_bytes(index), 126);
        request.events = OUTPUT;
        assert_eq!(
            resources.aio.read_events(&space, request),
            Ok(AioReadResult { got: 2, done: true })
        );
        let mut both = [0; 64];
        space.read(OUTPUT, &mut both).unwrap();
        assert_eq!(&both[..8], &41_u64.to_le_bytes());
        assert_eq!(&both[32..40], &43_u64.to_le_bytes());
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
        let mut request = arguments(abi, witness.handle);
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
        request = arguments(abi, replacement);
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
                resources
                    .aio
                    .read_events(&space, arguments(abi, witness.handle)),
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
        let base = arguments(abi, witness.handle);
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

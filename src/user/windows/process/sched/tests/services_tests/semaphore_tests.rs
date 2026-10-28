//! Native semaphore state, names, access grants and parked-wait integration.
use super::event_tests::{attrs, handle, setup, status};
use super::*;
use crate::host::time::Instant;
use crate::user::windows::hle::dispatch;
use crate::user::windows::object_namespace::reparse_tests;
use crate::user::windows::sync;

fn named(p: &mut Proc, at: u64, root: u64, name: &str, flags: u32) {
    let width = p.arch.ptr_size();
    let text: Vec<_> = name.encode_utf16().collect();
    attrs(p, at, if p.arch.is64() { 48 } else { 24 }, flags, root);
    p.space.wptr(at + 2 * width, width, at + 64).unwrap();
    p.space.wr(at + 64, &[0; 16]).unwrap();
    p.space.w16(at + 64, (text.len() * 2) as u16).unwrap();
    // Counted NT names ignore this smaller MaximumLength.
    p.space.wptr(at + 64 + width, width, at + 128).unwrap();
    p.space.put_wstr(at + 128, &text).unwrap();
}

#[test]
fn native_semaphore_signed_counts_grants_inherit_and_last_close_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, out) = setup(arch);
        let p = process.state_mut();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let oa = out + 256;
        attrs(p, oa, if arch.is64() { 48 } else { 24 }, 2, 0);
        for (initial, maximum) in [(0i32, 1i32), (1, 2), (0, i32::MAX), (i32::MAX, i32::MAX)] {
            for (access, grant) in [
                (0, 0),
                (1, 1),
                (2, 2),
                (3, 3),
                (4, 0),
                (0x0010_0000, 0x0010_0000),
                (0x001F_0003, 0x001F_0003),
                (0x8000_0000, 0x0002_0001),
                (0x4000_0000, 0x0002_0002),
                (0x2000_0000, 0x0012_0000),
                (0x1000_0000, 0x001F_0003),
                (0x0200_0000, 0x001F_0003),
                (0x0080_0000, 0),
                (0x000F_0000, 0x000F_0000),
            ] {
                assert_eq!(
                    status(
                        p,
                        &mut t,
                        "NtCreateSemaphore",
                        &[
                            out + 1,
                            access,
                            oa,
                            initial as u32 as u64,
                            maximum as u32 as u64
                        ]
                    ),
                    0
                );
                let h = handle(p, out + 1);
                assert_eq!(p.objects.access(h), Some(grant as u32));
                assert_eq!(p.objects.flags(h), Some(1));
                assert!(
                    matches!(p.objects.get(h), Some(Object::Semaphore { count, max }) if *count == initial && *max == maximum)
                );
                p.objects.close(h).unwrap();
                assert_eq!(
                    (p.objects.handle_count(), p.objects.iter().count()),
                    baseline
                );
            }
        }
    }
}

#[test]
fn native_semaphore_names_openif_counts_types_and_root_aliases_all_abis() {
    for arch in WinArch::ALL {
        for session in [0, 42] {
            let (mut process, mut t, out) = setup(arch);
            let p = process.state_mut();
            p.object_namespace = reparse_tests::sample(session);
            let base = if session == 0 {
                "\\BaseNamedObjects".to_owned()
            } else {
                format!("\\Sessions\\{session}\\BaseNamedObjects")
            };
            let directory = p
                .object_namespace
                .lookup(None, &base.encode_utf16().collect::<Vec<_>>(), 0)
                .unwrap();
            let root = p.objects.open_directory(directory, false, 0).unwrap() as u64;
            let oa = out + 256;
            named(p, oa, root, "MeasuredSemaphore", 0);
            assert_eq!(
                status(p, &mut t, "NtCreateSemaphore", &[out, 0x1F0003, oa, 1, 2]),
                0
            );
            let first = handle(p, out);
            let id = p.objects.id(first).unwrap();
            for path in [
                "MeasuredSemaphore".to_owned(),
                "Local\\MeasuredSemaphore".to_owned(),
                format!("{base}\\MeasuredSemaphore"),
            ] {
                named(
                    p,
                    oa,
                    if path.starts_with('\\') { 0 } else { root },
                    &path,
                    0x80,
                );
                assert_eq!(
                    status(p, &mut t, "NtCreateSemaphore", &[out, 1, oa, 0, 9]),
                    0x4000_0000
                );
                let alias = handle(p, out);
                assert_eq!(p.objects.id(alias), Some(id));
                assert!(matches!(
                    p.objects.get(alias),
                    Some(Object::Semaphore { count: 1, max: 2 })
                ));
                p.objects.close(alias).unwrap();
                for (count, maximum) in [(u32::MAX as u64, 2), (3, 2), (0, 0)] {
                    assert_eq!(
                        status(
                            p,
                            &mut t,
                            "NtCreateSemaphore",
                            &[out, 1, oa, count, maximum]
                        ),
                        STATUS_INVALID_PARAMETER
                    );
                }
                assert_eq!(status(p, &mut t, "NtOpenSemaphore", &[out, 2, oa]), 0);
                let alias = handle(p, out);
                assert_eq!(p.objects.id(alias), Some(id));
                assert_eq!(p.objects.access(alias), Some(2));
                p.objects.close(alias).unwrap();
            }
            named(p, oa, root, "MeasuredSemaphore", 0);
            assert_eq!(
                status(p, &mut t, "NtCreateSemaphore", &[out, 1, oa, 0, 2]),
                STATUS_OBJECT_NAME_COLLISION
            );
            named(p, oa, root, "mEASUREDsEMAPHORE", 0x40);
            assert_eq!(status(p, &mut t, "NtOpenSemaphore", &[out, 1, oa]), 0);
            p.objects.close(handle(p, out)).unwrap();
            named(p, oa, root, "Global\\MeasuredSemaphore", 0x80);
            assert_eq!(
                status(p, &mut t, "NtCreateSemaphore", &[out, 1, oa, 0, 3]),
                if session == 0 { 0x4000_0000 } else { 0 }
            );
            let global = handle(p, out);
            assert_eq!(p.objects.id(global) == Some(id), session == 0);
            p.objects.close(global).unwrap();
            p.objects.close(first).unwrap();
            named(p, oa, root, "MeasuredSemaphore", 0);
            assert_eq!(
                status(p, &mut t, "NtOpenSemaphore", &[out, 1, oa]),
                STATUS_OBJECT_NAME_NOT_FOUND
            );
            let event = p.objects.insert(Object::Event {
                manual: false,
                signaled: 0,
            }) as u64;
            named(p, oa, event, "Other", 0);
            assert_eq!(
                status(p, &mut t, "NtOpenSemaphore", &[out, 1, oa]),
                STATUS_OBJECT_TYPE_MISMATCH
            );
            p.objects.close(event).unwrap();
            p.objects.close(root).unwrap();
        }
    }
}

#[test]
fn native_semaphore_release_wakes_parked_native_wait_and_retires_last_pin_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, out) = setup(arch);
        let p = process.state_mut();
        let objects = p.objects.iter().count();
        assert_eq!(
            status(p, &mut t, "NtCreateSemaphore", &[out, 0x1F0003, 0, 0, 2]),
            0
        );
        let h = handle(p, out);
        let id = p.objects.id(h).unwrap();
        let sp = t.cpu.sp();
        assert_eq!(
            super::native_wait_tests::invoke(p, &mut t, h, 0, 0),
            Outcome::Park
        );
        let wait = match &t.state {
            ThreadState::Waiting(wait) => wait.clone(),
            state => panic!("unexpected {state:?}"),
        };
        assert_eq!(
            sync::poll(p, t.tid, &wait, Instant::now(), false).unwrap(),
            None
        );
        let peer_handle = p.objects.open_access(id, false, 2).unwrap() as u64;
        let (_peer_process, mut peer, _) = setup(arch);
        // The service uses this shared process's objects and a separate thread
        // context; no synthetic callback changes the semaphore count.
        peer.tid = t.tid + 4;
        peer.cpu.set_sp(sp - 0x400);
        assert_eq!(
            status(
                p,
                &mut peer,
                "NtReleaseSemaphore",
                &[peer_handle, 1, out + 64]
            ),
            0
        );
        assert_eq!(p.space.u32(out + 64).unwrap(), 0);
        p.objects.close(h).unwrap();
        p.objects.close(peer_handle).unwrap();
        assert!(p.objects.obj(id).is_some());
        let result = sync::poll(p, t.tid, &wait, Instant::now(), false)
            .unwrap()
            .unwrap();
        assert_eq!(result, 0);
        assert!(matches!(
            p.objects.obj(id),
            Some(Object::Semaphore { count: 0, max: 2 })
        ));
        sync::on_cancel(p, t.tid, &wait).unwrap();
        t.state = ThreadState::Ready;
        assert_eq!(
            dispatch::wait_complete(p, &mut t, result),
            Outcome::Continue
        );
        assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert!(t.frames.is_empty());
        assert_eq!(p.objects.iter().count(), objects);
    }
}

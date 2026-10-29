//! Pending registration, thread exit, native waits and three-argument APCs.
use super::replay::*;
use super::*;
use crate::user::windows::process::registry_notify;

fn callback_arguments(p: &Proc, t: &Thread, length: usize) -> Vec<u64> {
    (0..length)
        .map(|i| match p.arch {
            WinArch::Arm64 => t.cpu.gpr(i),
            WinArch::X64 => t.cpu.gpr([1, 2, 8][i]),
            WinArch::X86 => p.space.ptr(t.cpu.sp() + 4 + i as u64 * 4, 4).unwrap(),
        })
        .collect()
}

fn begin_sync(p: &mut Proc, t: &mut Thread, args: &[u64]) -> crate::user::windows::sync::Wait {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, "NtNotifyChangeKey", 0x12)));
    arguments(p, t, args);
    assert_eq!(dispatch(p, t), Outcome::Park);
    let ThreadState::Waiting(wait) = t.state.clone() else {
        panic!("synchronous notification did not park")
    };
    assert!(matches!(
        wait,
        crate::user::windows::sync::Wait::NativeObjects {
            alertable: false,
            deadline: None,
            ..
        }
    ));
    assert_eq!(
        sync::poll(p, t.tid, &wait, Instant::now(), false).unwrap(),
        None
    );
    wait
}

fn finish_sync(p: &mut Proc, t: &mut Thread, wait: crate::user::windows::sync::Wait) {
    let result = sync::poll(p, t.tid, &wait, Instant::now(), false)
        .unwrap()
        .unwrap();
    assert_eq!(result, 0);
    sync::on_cancel(p, t.tid, &wait).unwrap();
    t.state = ThreadState::Ready;
    assert_eq!(dispatch::wait_complete(p, t, result), Outcome::Continue);
    assert!(t.frames.is_empty());
}

#[test]
fn native_notify_key_replays_thread_exit_sync_cleanup_and_io_apc_arguments_all_abis() {
    let data = corpus();
    let mut count = 0;
    for report in data["reports"].as_array().unwrap() {
        let arch = architecture(report);
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        for row in rows(&data, report, "thread") {
            let key = body(p);
            let event = event(p);
            let mode = number(row, "mode");
            let filter = number(row, "filter");
            let apc = if number(row, "apc") == 0 { 0 } else { 0x50000 };
            p.space
                .wr(base, &vec![0xcc; arch.ptr_size() as usize * 2])
                .unwrap();
            let args = [
                key,
                if number(row, "event_supplied") == 0 {
                    0
                } else {
                    event
                },
                apc,
                0x11223344,
                base,
                filter,
                0,
                0,
                0,
                u64::from(mode != 2),
            ];
            let sp = t.cpu.sp();
            let wait = if mode == 2 && filter & 0x10000000 == 0 {
                Some(begin_sync(p, &mut t, &args))
            } else {
                assert_eq!(
                    u64::from(call(p, &mut t, "NtNotifyChangeKey", &args)),
                    number(row, "status")
                );
                None
            };
            if mode == 0 {
                registry_notify::retire_thread(p, &mut t).unwrap();
            }
            assert_eq!(
                p.space.bytes(base, arch.ptr_size() as usize * 2).unwrap(),
                bytes(row["iosb_before_close"].as_str().unwrap()),
                "{arch:?} {row}"
            );
            assert_eq!(signal(p, event), number(row, "event_before"), "{row}");
            if let Some(wait) = wait {
                // A separate caller closes the process-shared handle while
                // this thread remains parked on its private completion event.
                p.objects.close(key).unwrap();
                registry_notify::finish(p, &mut t).unwrap();
                finish_sync(p, &mut t, wait);
                assert_eq!(t.cpu.gpr(0), number(row, "status"));
                t.cpu.set_sp(sp);
            } else {
                assert_eq!(call(p, &mut t, "NtClose", &[key]), 0);
            }
            let callbacks = u64::from(mode == 1 && apc != 0 && filter & 0x10000000 == 0);
            assert_eq!(callbacks, number(row, "callbacks"));
            if callbacks != 0 {
                assert_eq!(begin_apcs(p, &mut t, None), Outcome::Continue);
                assert_eq!(t.cpu.pc(), apc);
                assert_eq!(callback_arguments(p, &t, 3), [0x11223344, base, 0]);
                assert_eq!(
                    p.space.u32(base).unwrap() as u64,
                    number(row, "callback_status")
                );
                assert_eq!(
                    p.space
                        .ptr(base + arch.ptr_size(), arch.ptr_size())
                        .unwrap(),
                    number(row, "callback_information")
                );
                assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
            }
            assert_eq!(signal(p, event), number(row, "event_final"));
            assert_eq!(
                p.space.bytes(base, arch.ptr_size() as usize * 2).unwrap(),
                bytes(row["iosb_final"].as_str().unwrap()),
                "{arch:?} {row}"
            );
            assert_eq!(call(p, &mut t, "NtClose", &[event]), 0);
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.objects.iter().count(), objects);
            count += 1;
        }
    }
    assert_eq!(count, data["reports"].as_array().unwrap().len() * 24);
}

#[test]
fn native_notify_key_synchronous_wait_retains_private_event_until_last_alias_closes_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let key = body(p);
        let duplicate = u64::from(p.objects.duplicate(key, false).unwrap());
        let event = event(p);
        let sp = t.cpu.sp();
        let wait = begin_sync(
            p,
            &mut t,
            &[key, event, 0x50000, 123, base, 1, 255, 0, 0, 0],
        );
        assert_eq!(
            p.objects.handle_count(),
            before.0 + 3,
            "internal wait has no caller handle"
        );
        p.objects.close(key).unwrap();
        registry_notify::finish(p, &mut t).unwrap();
        assert_eq!(
            sync::poll(p, t.tid, &wait, Instant::now(), false).unwrap(),
            None
        );
        assert_eq!(p.space.u32(base).unwrap(), STATUS_PENDING);
        p.objects.close(duplicate).unwrap();
        registry_notify::finish(p, &mut t).unwrap();
        finish_sync(p, &mut t, wait);
        assert_eq!(t.cpu.gpr(0), u64::from(registry_notify::NOTIFY_CLEANUP));
        assert_eq!(
            signal(p, event),
            0,
            "synchronous call ignores the supplied event"
        );
        assert!(
            t.apcs.is_empty(),
            "synchronous call ignores the APC routine"
        );
        t.cpu.set_sp(sp);
        assert_eq!(call(p, &mut t, "NtClose", &[event]), 0);
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

#[test]
fn native_notify_key_io_apc_preserves_regular_fifo_and_pins_event_until_delivery_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let key = body(p);
        let event = event(p);
        let alias = u64::from(p.objects.duplicate(event, false).unwrap());
        t.apcs.push_back((0x50000, 11).into());
        assert_eq!(
            call(
                p,
                &mut t,
                "NtNotifyChangeKey",
                &[key, event, 0x50100, 22, base, 1, 0, 0, 0, 1]
            ),
            STATUS_PENDING
        );
        assert_eq!(call(p, &mut t, "NtClose", &[key]), 0);
        assert_eq!(call(p, &mut t, "NtClose", &[event]), 0);
        t.apcs.push_back((0x50200, 33).into());
        assert_eq!(begin_apcs(p, &mut t, None), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50000);
        assert_eq!(callback_arguments(p, &t, 1), [11]);
        assert_eq!(p.space.u32(base).unwrap(), STATUS_PENDING);
        assert_eq!(signal(p, alias), 258);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50100);
        assert_eq!(callback_arguments(p, &t, 3), [22, base, 0]);
        assert_eq!(p.space.u32(base).unwrap(), registry_notify::NOTIFY_CLEANUP);
        assert_eq!(signal(p, alias), 0);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.pc(), 0x50200);
        assert_eq!(callback_arguments(p, &t, 1), [33]);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert!(t.apcs.is_empty());
        assert!(t.frames.is_empty());
        assert_eq!(call(p, &mut t, "NtClose", &[alias]), 0);
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

#[test]
fn native_notify_key_actual_thread_teardown_retires_pending_and_queued_but_keeps_agnostic_all_abis()
{
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let observer_tid = thread::create(p, 0, 0, 0, false).unwrap();
        let mut observer = p.threads.remove(&observer_tid).unwrap();
        let mut keys = Vec::new();
        let mut events = Vec::new();
        for index in 0..3 {
            let key = body(p);
            let event = event(p);
            let io = base + index * 32;
            p.space
                .wr(io, &vec![0xcc; arch.ptr_size() as usize * 2])
                .unwrap();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtNotifyChangeKey",
                    &[
                        key,
                        event,
                        if index == 1 { 0x50000 } else { 0 },
                        0,
                        io,
                        if index == 2 { 0x10000001 } else { 1 },
                        0,
                        0,
                        0,
                        1
                    ]
                ),
                STATUS_PENDING
            );
            keys.push(key);
            events.push(event);
        }
        assert_eq!(call(p, &mut t, "NtClose", &[keys[1]]), 0);
        assert_eq!(t.apcs.len(), 1);
        assert_eq!(p.space.u32(base + 32).unwrap(), STATUS_PENDING);
        thread::destroy(p, t, 77);
        assert!(p.failure.is_none(), "{:?}", p.failure);
        assert_eq!(signal(p, events[0]), 0);
        assert_eq!(signal(p, events[1]), 0);
        assert_eq!(signal(p, events[2]), 258);
        for io in [base, base + 32] {
            assert_eq!(p.space.u32(io).unwrap(), registry_notify::NOTIFY_CLEANUP);
        }
        assert_eq!(p.space.u32(base + 64).unwrap(), 0xcccccccc);
        for key in [keys[0], keys[2]] {
            assert_eq!(call(p, &mut observer, "NtClose", &[key]), 0);
        }
        assert_eq!(signal(p, events[2]), 0);
        for event in events {
            assert_eq!(call(p, &mut observer, "NtClose", &[event]), 0);
        }
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        thread::destroy(p, observer, 0);
        assert!(p.failure.is_none());
    }
}

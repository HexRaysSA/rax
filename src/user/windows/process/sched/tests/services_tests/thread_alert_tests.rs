//! Independent installed-kernel corpora and scheduler lifetime/return regressions.
use super::event_tests::{call, setup, status};
use super::*;
use crate::host::time::Instant;
use crate::user::windows::hle::dispatch;
use crate::user::windows::layout::offsets;
use crate::user::windows::sync;

fn corpus(arch: WinArch, timing: bool) -> &'static str {
    match (arch, timing) {
        (WinArch::Arm64, false) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/arm64-native-v1.txt"
        )),
        (WinArch::X64, false) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x64-native-v1.txt"
        )),
        (WinArch::X86, false) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x86-native-v1.txt"
        )),
        (WinArch::Arm64, true) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/arm64-native-timing-v1.txt"
        )),
        (WinArch::X64, true) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x64-native-timing-v1.txt"
        )),
        (WinArch::X86, true) => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-alert/x86-native-timing-v1.txt"
        )),
    }
}

fn fields(line: &str) -> Vec<u64> {
    line.split_whitespace()
        .skip(1)
        .map(|v| u64::from_str_radix(v, 16).unwrap())
        .collect()
}

fn alert(p: &mut Proc, t: &mut Thread, tid: u64) -> u32 {
    status(p, t, "NtAlertThreadByThreadId", &[tid])
}

fn poll(p: &mut Proc, t: &mut Thread, zero: u64) -> u32 {
    p.space.w64(zero, 0).unwrap();
    status(p, t, "NtWaitForAlertByThreadId", &[0, zero])
}

#[test]
fn thread_alert_replays_3456_timeout_probes_latch_consumption_and_address_cases() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        let worker = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
        let zero = data + 12288;
        let last_error = t.teb + offsets(arch).teb_last_error;
        let current_tid = u64::from(t.tid);
        let mut index = 0;
        for line in corpus(arch, false)
            .lines()
            .filter(|l| l.starts_with("case "))
        {
            let row = fields(line);
            assert_eq!(row.len(), 15);
            assert_eq!(row[0], index);
            let label = format!("{arch}/{index}");
            for _ in 0..3 {
                assert_eq!(poll(p, &mut t, zero), 0x102, "{label}/clean");
            }
            p.vm.protect(data, 12288, prot::READWRITE).unwrap();
            p.space.wr(data, &[0; 12288]).unwrap();
            let (mode, delta, pending) = (row[2], row[3], row[4]);
            let timeout = if mode == 1 {
                1
            } else {
                data + 4096 - if mode >= 6 { 1 } else { 16 } + delta
            };
            if (2..=5).contains(&mode) {
                p.vm.protect(
                    data,
                    4096,
                    [
                        prot::READONLY,
                        prot::NOACCESS,
                        prot::READWRITE | prot::GUARD,
                        prot::READONLY | prot::GUARD,
                    ][(mode - 2) as usize],
                )
                .unwrap();
            }
            if mode == 7 {
                p.vm.protect(data + 4096, 4096, prot::NOACCESS).unwrap();
            }
            let address = match row[1] {
                0 => 0,
                1 => 1,
                2 => data + 256,
                3 => current_tid,
                4 => arch.ptr(u64::MAX),
                5 => u64::from(worker),
                _ => unreachable!(),
            };
            for i in 0..pending {
                assert_eq!(
                    u64::from(alert(p, &mut t, current_tid)),
                    row[5 + i as usize],
                    "{label}/alert{i}"
                );
            }
            p.space.w32(last_error, 0x7654_3210).unwrap();
            assert_eq!(
                u64::from(status(
                    p,
                    &mut t,
                    "NtWaitForAlertByThreadId",
                    &[address, timeout]
                )),
                row[7],
                "{label}/wait"
            );
            assert_eq!(row[8], 0, "native escaped exception");
            assert_eq!(
                u64::from(p.space.u32(last_error).unwrap()),
                row[9],
                "{label}/LastError"
            );
            for page in 0..2 {
                assert_eq!(
                    u64::from(p.vm.query(data + page * 4096).unwrap().protect),
                    row[10 + page as usize],
                    "{label}/guard{page}"
                );
            }
            p.vm.protect(data, 12288, prot::READWRITE).unwrap();
            for i in 0..3 {
                assert_eq!(
                    u64::from(poll(p, &mut t, zero)),
                    row[12 + i],
                    "{label}/drain{i}"
                );
            }
            index += 1;
            seen += 1;
        }
        assert_eq!(index, 1152);
        let worker = p.threads.remove(&worker).unwrap();
        thread::destroy(p, worker, 0x37);
    }
    assert_eq!(seen, 3456);
}

#[test]
fn thread_alert_replays_64_native_id_status_and_retained_lifetime_rows() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        let worker = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
        let object = p.threads[&worker].obj;
        let handle = u64::from(p.objects.open_access(object, false, 0x1fffff).unwrap());
        let last_error = t.teb + offsets(arch).teb_last_error;
        for line in corpus(arch, false).lines() {
            if line.starts_with("worker ") {
                let row = fields(line);
                let mut other = p.threads.remove(&worker).unwrap();
                for i in 0..8 {
                    assert_eq!(u64::from(poll(p, &mut other, data)), row[2 + i]);
                }
                thread::destroy(p, other, row[1] as u32);
            } else if line.starts_with("target ") {
                let row = fields(line);
                let target = match row[0] {
                    0 => 0,
                    1 => u64::from(t.tid),
                    2..=5 => u64::from(worker) | (row[0] - 2),
                    6 => u64::from(p.pid),
                    7..=9 => u64::from(t.tid) | (row[0] - 6),
                    10 => u64::from(t.tid) | (1 << 32),
                    _ => unreachable!(),
                };
                p.space.w32(last_error, 0x7654_3210).unwrap();
                assert_eq!(u64::from(alert(p, &mut t, target)), row[3], "{arch}/{line}");
                assert_eq!(row[4], 0);
                assert_eq!(u64::from(p.space.u32(last_error).unwrap()), row[5]);
                for i in 0..3 {
                    assert_eq!(
                        u64::from(poll(p, &mut t, data)),
                        row[6 + i],
                        "{arch}/{line}/drain{i}"
                    );
                }
                seen += 1;
            }
        }
        p.objects.close(handle).unwrap();
        assert!(p.objects.obj(object).is_none());
    }
    assert_eq!(seen, 64);
}

#[test]
fn thread_alert_replays_54_prequeued_null_and_signed_deadline_rows() {
    let values = [0i64, -1, -10000, 1, i64::MAX, i64::MIN];
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        let tid = u64::from(t.tid);
        let last_error = t.teb + offsets(arch).teb_last_error;
        for line in corpus(arch, true)
            .lines()
            .filter(|l| l.starts_with("deadline "))
        {
            let row = fields(line);
            for _ in 0..row[0] {
                assert_eq!(alert(p, &mut t, tid), 0);
            }
            p.space
                .w64(data, values[row[1].min(5) as usize] as u64)
                .unwrap();
            p.space.w32(last_error, 0x7654_3210).unwrap();
            let timeout = if row[1] == 6 { 0 } else { data };
            let outcome = call(p, &mut t, "NtWaitForAlertByThreadId", &[1, timeout]);
            if outcome == Outcome::Park {
                // Short relative waits may expire inside native entry or at
                // the scheduler poll. Preserve the captured final status.
                assert_eq!(row[0], 0);
                assert!(matches!(row[1], 1 | 2));
                let wait = waiting(&t);
                let result = loop {
                    if let Some(result) =
                        sync::poll(p, t.tid, &wait, Instant::now(), false).unwrap()
                    {
                        break result;
                    }
                    std::thread::yield_now();
                };
                complete(p, &mut t, &wait, result);
            } else {
                assert_eq!(outcome, Outcome::Continue);
            }
            assert_eq!(t.cpu.gpr(0), row[2], "{arch}/{line}");
            assert_eq!(row[3], 0);
            assert_eq!(u64::from(p.space.u32(last_error).unwrap()), row[4]);
            assert_eq!(u64::from(poll(p, &mut t, data)), row[5]);
            seen += 1;
        }
    }
    assert_eq!(seen, 54);
}

fn waiting(t: &Thread) -> sync::Wait {
    let ThreadState::Waiting(wait) = &t.state else {
        panic!("not parked: {:?}", t.state);
    };
    wait.clone()
}

fn complete(p: &mut Proc, t: &mut Thread, wait: &sync::Wait, result: u64) {
    sync::on_cancel(p, t.tid, wait).unwrap();
    t.state = ThreadState::Ready;
    assert_eq!(dispatch::wait_complete(p, t, result), Outcome::Continue);
}

#[test]
fn thread_alert_park_wake_coalesces_ignores_apcs_and_preserves_raw_return_all_abis() {
    for arch in WinArch::ALL {
        for ticks in [None, Some(i64::MIN), Some(i64::MAX)] {
            let (mut process, mut t, data) = setup(arch);
            let p = process.state_mut();
            let worker = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
            let mut sender = p.threads.remove(&worker).unwrap();
            t.user_alerted = true;
            t.apcs.push_back((0x50000, 0x1111).into());
            if let Some(ticks) = ticks {
                p.space.w64(data, ticks as u64).unwrap();
            }
            let sp = t.cpu.sp();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtWaitForAlertByThreadId",
                    &[arch.ptr(u64::MAX), if ticks.is_some() { data } else { 0 }]
                ),
                Outcome::Park
            );
            let wait = waiting(&t);
            assert_eq!(wait.deadline().is_none(), ticks.is_none());
            assert_eq!(
                sync::poll(p, t.tid, &wait, Instant::now(), true).unwrap(),
                None
            );
            let tid = u64::from(t.tid);
            p.threads.insert(t.tid, t);
            assert_eq!(alert(p, &mut sender, tid), 0);
            assert_eq!(alert(p, &mut sender, tid), 0);
            t = p.threads.remove(&(tid as u32)).unwrap();
            assert_eq!(
                sync::poll(p, t.tid, &wait, Instant::now(), true).unwrap(),
                Some(0x101)
            );
            complete(p, &mut t, &wait, 0x101);
            // event_tests::call restores the raw-entry SP, so only WoW64's
            // delayed kernel return still needs its actual four-byte pop.
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            assert_eq!(t.cpu.pc(), 0x1234_0004);
            assert_eq!(t.cpu.gpr(0), 0x101);
            assert!(t.frames.is_empty());
            assert!(t.user_alerted);
            assert_eq!(t.apcs.len(), 1);
            t.cpu.set_sp(sp);
            assert_eq!(poll(p, &mut t, data), 0x102, "coalesced");
            thread::destroy(p, sender, 0x37);
        }
    }
}

#[test]
fn thread_alert_channels_and_retirement_do_not_leak_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        let row = fields(
            corpus(arch, false)
                .lines()
                .find(|l| l.starts_with("independent "))
                .unwrap(),
        );
        assert_eq!(row[0], 0);
        t.user_alerted = true;
        assert_eq!(u64::from(poll(p, &mut t, data)), row[1]);
        assert_eq!(u64::from(status(p, &mut t, "NtTestAlert", &[])), row[2]);
        assert_eq!(u64::from(status(p, &mut t, "NtTestAlert", &[])), row[3]);
        let tid = u64::from(t.tid);
        assert_eq!(u64::from(alert(p, &mut t, tid)), row[4]);
        assert_eq!(u64::from(status(p, &mut t, "NtTestAlert", &[])), row[5]);
        assert_eq!(u64::from(poll(p, &mut t, data)), row[6]);
        assert_eq!(u64::from(poll(p, &mut t, data)), row[7]);
        for process_exit in [false, true] {
            let other = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
            let object = p.threads[&other].obj;
            assert_eq!(alert(p, &mut t, u64::from(other)), 0);
            if process_exit {
                sync::on_process_exit(p);
            } else {
                let other = p.threads.remove(&other).unwrap();
                thread::destroy(p, other, 0x37);
            }
            assert!(!p.sync.take_thread_alert(object));
        }
    }
}

#[test]
fn thread_alert_replays_96_blocked_worker_rows_with_native_tag_and_clock_semantics() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        for line in corpus(arch, true)
            .lines()
            .filter(|l| l.starts_with("blocked "))
        {
            let row = fields(line);
            let (mut process, mut sender, data) = setup(arch);
            let p = process.state_mut();
            let worker = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
            let mut target = p.threads.remove(&worker).unwrap();
            let address = match row[0] {
                0 => 0,
                1 => 1,
                2 => arch.ptr(u64::MAX),
                3 => data,
                _ => unreachable!(),
            };
            let ticks = if row[1] == 0 {
                -5_000_000i64
            } else {
                // Same native UTC domain as the oracle's future FILETIME.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap();
                (now.as_secs() as i64 + 11_644_473_600) * 10_000_000
                    + i64::from(now.subsec_nanos()) / 100
                    + 5_000_000
            };
            p.space.w64(data + 32, ticks as u64).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut target,
                    "NtWaitForAlertByThreadId",
                    &[address, data + 32]
                ),
                Outcome::Park
            );
            let wait = waiting(&target);
            p.threads.insert(worker, target);
            assert_eq!(
                u64::from(alert(p, &mut sender, u64::from(worker) | row[2])),
                row[3]
            );
            target = p.threads.remove(&worker).unwrap();
            let result = loop {
                if let Some(value) = sync::poll(p, worker, &wait, Instant::now(), true).unwrap() {
                    break value;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            };
            assert_eq!(result, row[4], "{arch}/{line}");
            assert_eq!(row[5], 0);
            complete(p, &mut target, &wait, result);
            thread::destroy(p, target, row[6] as u32);
            seen += 1;
        }
    }
    assert_eq!(seen, 96);
}

#[test]
fn thread_alert_rejects_foreign_identity_and_cannot_transfer_latch_to_reused_tid() {
    for arch in WinArch::ALL {
        let (mut process, mut t, data) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
        let mut target = p.threads.remove(&tid).unwrap();
        let original = target.obj;
        let foreign = p.objects.create(Object::Thread {
            tid,
            exit_code: None,
        });
        let foreign_handle = u64::from(p.objects.open_access(foreign, false, 0x1fffff).unwrap());
        assert!(
            matches!(call(p, &mut t, "NtAlertThreadByThreadId", &[u64::from(tid)]), Outcome::Fail(message) if message.contains("external process"))
        );
        assert!(!p.sync.take_thread_alert(foreign));
        p.threads.insert(tid, target);
        assert_eq!(alert(p, &mut t, u64::from(tid)), 0);
        target = p.threads.remove(&tid).unwrap();
        thread::destroy(p, target, 0x37);
        assert!(!p.sync.take_thread_alert(original));
        // A stale/external object with this numeric CID cannot acquire or
        // receive a live successor's latch.
        p.objects.close(foreign_handle).unwrap();
        p.objects.release(foreign);
        p.next_tid = tid;
        let new_tid = thread::create(p, 0x1234_5000, 0, 0x10000, true).unwrap();
        assert_eq!(new_tid, tid);
        let mut successor = p.threads.remove(&new_tid).unwrap();
        assert_ne!(successor.obj, original);
        assert_eq!(poll(p, &mut successor, data), 0x102);
        thread::destroy(p, successor, 0x37);
    }
}

#[cfg(windows)]
#[test]
fn thread_alert_installed_ntdll_leaves_park_and_return_with_exact_stack_cleanup() {
    use crate::user::windows::loader::{self, SymRef};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in arches {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
        };
        let mut cfg =
            WindowsConfig::embedded("C:\\native-thread-alert.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let data =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.w64(data, 0).unwrap();
        let original_sp = t.cpu.sp();
        let resume = p.traps.callback_return();
        for (name, args, must_park, expected) in [
            ("NtAlertThreadByThreadId", vec![u64::from(tid)], false, 0),
            ("NtWaitForAlertByThreadId", vec![1, data], false, 0x101),
            (
                "NtWaitForAlertByThreadId",
                vec![arch.ptr(u64::MAX), data],
                false,
                0x102,
            ),
            ("NtWaitForAlertByThreadId", vec![1, 0], true, 0x101),
        ] {
            let entry = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                .unwrap()
                .unwrap();
            let sp = original_sp - 128;
            t.cpu.set_sp(sp);
            t.cpu.set_pc(entry);
            for (i, value) in args.iter().copied().enumerate() {
                match arch {
                    WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
                    WinArch::X64 => t.cpu.set_gpr([1, 2][i], value),
                    WinArch::Arm64 => t.cpu.set_gpr(i, value),
                }
            }
            match arch {
                WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
                WinArch::X64 => p.space.w64(sp, resume).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            let mut parked = false;
            let mut returned = false;
            for _ in 0..64 {
                let boundary = t.cpu.run(64);
                if t.cpu.pc() == resume {
                    returned = true;
                    break;
                }
                match handle_stop(p, &mut t, boundary) {
                    Outcome::Park => {
                        assert!(must_park && !parked);
                        parked = true;
                        let wait = waiting(&t);
                        assert_eq!(t.frames.len(), 1);
                        p.sync.alert_thread(t.obj);
                        let result = sync::poll(p, tid, &wait, Instant::now(), false)
                            .unwrap()
                            .unwrap();
                        assert_eq!(result, 0x101);
                        complete(p, &mut t, &wait, result);
                    }
                    Outcome::Continue | Outcome::Yield => {}
                    other => panic!("{arch}/{name}: {other:?}"),
                }
            }
            assert!(returned);
            assert_eq!(parked, must_park);
            assert_eq!(t.cpu.gpr(0), expected);
            assert!(t.frames.is_empty());
            assert_eq!(
                t.cpu.sp(),
                sp + match arch {
                    WinArch::X86 => (args.len() as u64 + 1) * 4,
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
        }
        t.cpu.set_sp(original_sp);
        p.threads.insert(tid, t);
    }
}

//! Native wait entry, retained lifetime and kernel-return context regressions.
use super::event_tests::setup;
use super::*;
use crate::host::time::Instant;
use crate::user::windows::hle::dispatch;
use crate::user::windows::sync;

const RESUME: u64 = 0x1234_0004;

pub(super) fn invoke(
    p: &mut Proc,
    t: &mut Thread,
    handle: u64,
    alertable: u32,
    timeout: u64,
) -> Outcome {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, "NtWaitForSingleObject", 0x48)));
    let args = [handle, u64::from(alertable), timeout];
    let sp = t.cpu.sp();
    t.cpu.set_pc(RESUME);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, RESUME as u32).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (i, value) in args.into_iter().enumerate() {
                p.space.w32(sp + 8 + i as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, 0x48);
            super::super::super::super::services::wow64(p, t, 0x1234_0000)
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x48);
            t.cpu.set_gpr(1, RESUME);
            for (i, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr([10, 2, 8][i], value);
            }
            handle_stop(p, t, stop(p.arch, 0x48))
        }
        WinArch::Arm64 => {
            for (i, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(i, value);
            }
            handle_stop(p, t, stop(p.arch, 0x48))
        }
    }
}

fn event(p: &mut Proc, signaled: i32) -> (u64, u32) {
    let id = p.objects.create(Object::Event {
        manual: false,
        signaled,
    });
    let handle = p.objects.open_access(id, false, 0x0010_0000).unwrap();
    (u64::from(handle), id)
}

fn waiting(t: &Thread) -> sync::Wait {
    match &t.state {
        ThreadState::Waiting(wait) => wait.clone(),
        state => panic!("expected a native parked wait, got {state:?}"),
    }
}

fn returned(t: &Thread, arch: WinArch, sp: u64, status: u64) {
    assert_eq!(t.cpu.pc(), RESUME);
    assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
    assert_eq!(t.cpu.gpr(0), status);
    assert!(t.frames.is_empty());
    if arch == WinArch::X64 {
        assert_eq!(t.cpu.gpr(1), RESUME, "native SYSCALL RCX must survive");
    }
}

#[test]
fn native_single_wait_immediate_poll_and_native_return_all_abis() {
    for arch in WinArch::ALL {
        for (signal, expected) in [(0, sync::WAIT_TIMEOUT), (1, 0)] {
            let (mut process, mut t, data) = setup(arch);
            let p = process.state_mut();
            let sp = t.cpu.sp();
            let (handle, id) = event(p, signal);
            p.space.w64(data, 0).unwrap();
            assert_eq!(invoke(p, &mut t, handle, 0, data), Outcome::Continue);
            returned(&t, arch, sp, expected);
            assert!(matches!(
                p.objects.obj(id),
                Some(Object::Event { signaled: 0, .. })
            ));
            p.objects.close(handle).unwrap();
        }
    }
}

#[test]
fn native_single_wait_park_pins_last_handle_and_wakes_without_hle_cleanup_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, _) = setup(arch);
        let p = process.state_mut();
        let objects = p.objects.iter().count();
        let sp = t.cpu.sp();
        let (handle, id) = event(p, 0);
        assert_eq!(invoke(p, &mut t, handle, 0, 0), Outcome::Park);
        assert_eq!(t.frames.len(), 1);
        let wait = waiting(&t);
        assert!(wait.deadline().is_none(), "NULL is an infinite wait");
        p.objects.close(handle).unwrap();
        let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(id) else {
            panic!("parked native wait lost its private reference");
        };
        *signaled = 1;
        let status = sync::poll(p, t.tid, &wait, Instant::now(), false)
            .unwrap()
            .unwrap();
        assert_eq!(status, 0);
        sync::on_cancel(p, t.tid, &wait).unwrap();
        t.state = ThreadState::Ready;
        assert_eq!(
            dispatch::wait_complete(p, &mut t, status),
            Outcome::Continue
        );
        returned(&t, arch, sp, 0);
        assert_eq!(p.objects.iter().count(), objects);
    }
}

#[test]
fn native_single_wait_cancel_releases_pin_and_continuation_once_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, _) = setup(arch);
        let p = process.state_mut();
        let objects = p.objects.iter().count();
        let (handle, id) = event(p, 0);
        assert_eq!(invoke(p, &mut t, handle, 0, 0), Outcome::Park);
        let wait = waiting(&t);
        p.objects.close(handle).unwrap();
        assert!(p.objects.obj(id).is_some());
        sync::on_cancel(p, t.tid, &wait).unwrap();
        sync::on_cancel(p, t.tid, &wait).unwrap();
        t.frames.clear();
        t.state = ThreadState::Ready;
        assert!(p.objects.obj(id).is_none());
        assert_eq!(p.objects.iter().count(), objects);
    }
}

#[test]
fn native_single_wait_apc_precedes_signal_and_preserves_kernel_frame_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, _) = setup(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        let (handle, id) = event(p, 1);
        t.cpu.set_gpr(3, 0xCC55);
        t.apcs.push_back((0x50000, 0x1111));
        assert_eq!(invoke(p, &mut t, handle, 1, 0), Outcome::Park);
        let wait = waiting(&t);
        let status = sync::poll(p, t.tid, &wait, Instant::now(), true)
            .unwrap()
            .unwrap();
        assert_eq!(status, sync::WAIT_IO_COMPLETION);
        assert!(matches!(
            p.objects.obj(id),
            Some(Object::Event { signaled: 1, .. })
        ));
        sync::on_cancel(p, t.tid, &wait).unwrap();
        t.state = ThreadState::Ready;
        assert_eq!(begin_apcs(p, &mut t, Some(status)), Outcome::Continue);
        assert_eq!(t.frames.len(), 2);
        assert_eq!(dispatch::callback_return(p, &mut t), Outcome::Continue);
        assert_eq!(
            t.frames.len(),
            1,
            "APC must retain the interrupted native wait"
        );
        assert_eq!(t.wait_status.take(), Some(status));
        assert_eq!(
            dispatch::wait_complete(p, &mut t, status),
            Outcome::Continue
        );
        returned(&t, arch, sp, status);
        assert_eq!(t.cpu.gpr(3), 0xCC55);
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_single_wait_signed_timeout_boundaries_remain_finite_all_abis() {
    for arch in WinArch::ALL {
        for ticks in [0i64, 1, -1, -10_000, i64::MIN, i64::MAX] {
            let (mut process, mut t, data) = setup(arch);
            let p = process.state_mut();
            let sp = t.cpu.sp();
            let (handle, id) = event(p, 0);
            p.space.w64(data, ticks as u64).unwrap();
            let result = invoke(p, &mut t, handle, 0, data);
            if ticks == 0
                || ticks == 1
                || (ticks < 0 && ticks >= -10_000 && result == Outcome::Continue)
            {
                assert_eq!(result, Outcome::Continue);
                returned(&t, arch, sp, sync::WAIT_TIMEOUT);
            } else {
                assert_eq!(result, Outcome::Park);
                let wait = waiting(&t);
                assert!(
                    wait.deadline().is_some(),
                    "finite timeout {ticks} became infinite"
                );
                let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(id) else {
                    unreachable!()
                };
                *signaled = 1;
                let status = sync::poll(p, t.tid, &wait, Instant::now(), false)
                    .unwrap()
                    .unwrap();
                assert_eq!(status, 0, "ready object precedes expiration");
                sync::on_cancel(p, t.tid, &wait).unwrap();
                t.state = ThreadState::Ready;
                assert_eq!(
                    dispatch::wait_complete(p, &mut t, status),
                    Outcome::Continue
                );
                returned(&t, arch, sp, 0);
            }
            p.objects.close(handle).unwrap();
        }
    }
}

#[test]
fn native_single_wait_alertable_low_byte_with_pending_apc_all_abis() {
    for arch in WinArch::ALL {
        for alertable in [0u32, 1, 2, 255, 256, 257, u32::MAX] {
            for signaled in [0, 1] {
                let (mut process, mut t, data) = setup(arch);
                let p = process.state_mut();
                let sp = t.cpu.sp();
                let (handle, id) = event(p, signaled);
                p.space.w64(data, 0).unwrap();
                t.apcs.push_back((0x50000, 0x1111));
                let result = invoke(p, &mut t, handle, alertable, data);
                if alertable as u8 == 0 {
                    assert_eq!(result, Outcome::Continue);
                    returned(
                        &t,
                        arch,
                        sp,
                        if signaled == 0 { sync::WAIT_TIMEOUT } else { 0 },
                    );
                    assert!(matches!(
                        p.objects.obj(id),
                        Some(Object::Event { signaled: 0, .. })
                    ));
                } else {
                    assert_eq!(result, Outcome::Park);
                    let wait = waiting(&t);
                    assert_eq!(
                        sync::poll(p, t.tid, &wait, Instant::now(), true).unwrap(),
                        Some(sync::WAIT_IO_COMPLETION)
                    );
                    assert!(
                        matches!(p.objects.obj(id), Some(Object::Event { signaled: value, .. }) if *value == signaled)
                    );
                    sync::on_cancel(p, t.tid, &wait).unwrap();
                    t.frames.clear();
                    t.state = ThreadState::Ready;
                }
                assert_eq!(t.apcs.len(), 1, "APC delivery belongs to the scheduler");
                p.objects.close(handle).unwrap();
            }
        }
    }
}

#[test]
fn native_single_wait_process_exit_retires_native_object_pins_all_abis() {
    for arch in WinArch::ALL {
        for normal in [false, true] {
            let (mut process, mut t, _) = setup(arch);
            let p = process.state_mut();
            let objects = p.objects.iter().count();
            let (handle, id) = event(p, 0);
            assert_eq!(invoke(p, &mut t, handle, 0, 0), Outcome::Park);
            p.objects.close(handle).unwrap();
            assert!(p.objects.obj(id).is_some());
            if normal {
                sync::on_normal_process_exit(p, t.tid + 1).unwrap();
            } else {
                sync::on_process_exit(p);
            }
            assert!(p.objects.obj(id).is_none());
            assert_eq!(p.objects.iter().count(), objects);
            t.frames.clear();
        }
    }
}

#[test]
fn native_single_wait_abandoned_mutant_returns_ownership_and_native_status_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, _) = setup(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        let id = p.objects.create(Object::Mutex {
            owner: Some(t.tid + 1),
            count: 1,
            abandoned: false,
        });
        let handle = u64::from(p.objects.open_access(id, false, 0x0010_0000).unwrap());
        assert_eq!(invoke(p, &mut t, handle, 0, 0), Outcome::Park);
        let wait = waiting(&t);
        let Some(Object::Mutex {
            owner,
            count,
            abandoned,
        }) = p.objects.obj_mut(id)
        else {
            unreachable!()
        };
        *owner = None;
        *count = 0;
        *abandoned = true;
        let status = sync::poll(p, t.tid, &wait, Instant::now(), false)
            .unwrap()
            .unwrap();
        assert_eq!(status, 0x80);
        assert!(
            matches!(p.objects.obj(id), Some(Object::Mutex { owner: Some(owner), count: 1, abandoned: false }) if *owner == t.tid)
        );
        sync::on_cancel(p, t.tid, &wait).unwrap();
        t.state = ThreadState::Ready;
        assert_eq!(
            dispatch::wait_complete(p, &mut t, status),
            Outcome::Continue
        );
        returned(&t, arch, sp, status);
        p.objects.close(handle).unwrap();
    }
}

#[cfg(windows)]
#[test]
fn native_single_wait_installed_leaves_park_resume_and_keep_true_ret12() {
    use crate::user::windows::loader::{self, SymRef};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    for arch in if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    } {
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
        let mut config =
            WindowsConfig::embedded("C:\\native-wait.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtWaitForSingleObject".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let (handle, id) = event(p, 0);
        let sp = t.cpu.sp() - 128;
        let resume = p.traps.callback_return();
        t.cpu.set_sp(sp);
        t.cpu.set_pc(entry);
        for (index, value) in [handle, 0, 0].into_iter().enumerate() {
            match arch {
                WinArch::X86 => p
                    .space
                    .w32(sp + 4 + index as u64 * 4, value as u32)
                    .unwrap(),
                WinArch::X64 => t.cpu.set_gpr([1, 2, 8][index], value),
                WinArch::Arm64 => t.cpu.set_gpr(index, value),
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
                    assert!(!parked, "one native service must park once");
                    parked = true;
                    let wait = waiting(&t);
                    assert_eq!(t.frames.len(), 1);
                    let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(id) else {
                        unreachable!()
                    };
                    *signaled = 1;
                    let status = sync::poll(p, t.tid, &wait, Instant::now(), false)
                        .unwrap()
                        .unwrap();
                    assert_eq!(status, 0);
                    sync::on_cancel(p, t.tid, &wait).unwrap();
                    t.state = ThreadState::Ready;
                    assert_eq!(
                        dispatch::wait_complete(p, &mut t, status),
                        Outcome::Continue
                    );
                }
                Outcome::Continue | Outcome::Yield => {}
                other => panic!("{arch}: installed native wait failed: {other:?}"),
            }
        }
        assert!(parked && returned);
        assert_eq!(t.cpu.gpr(0), 0);
        assert!(t.frames.is_empty());
        assert_eq!(
            t.cpu.sp(),
            sp + match arch {
                WinArch::X86 => 16,
                WinArch::X64 => 8,
                WinArch::Arm64 => 0,
            }
        );
        p.objects.close(handle).unwrap();
        t.cpu.set_sp(sp + 128);
        p.threads.insert(tid, t);
    }
}

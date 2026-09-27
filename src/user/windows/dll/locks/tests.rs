use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow, Item, Value};
use crate::user::windows::memory::{Mem, MemFault, mem, prot};
use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_TIMEOUT};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};
use crate::user::windows::sync::{self, SyncError, Wait};
use std::time::Instant;

fn with_context(arch: WinArch, test: impl FnOnce(&mut Ctx, u64)) {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut cfg = WindowsConfig::new("locks-test.exe", vec![]);
    cfg.seed = Some(1);
    cfg.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (base, _) =
        p.vm.allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let cursor = t.cpu.sp();
    let Item::Func(api) = &EXPORTS[0].item else {
        panic!()
    };
    test(
        &mut Ctx {
            p,
            t: &mut t,
            api,
            entry_pc: 0,
            entry_sp: cursor,
            ret_addr: 0,
            cursor,
        },
        base,
    );
}

fn invoke(c: &mut Ctx, name: &str, args: &[u64]) -> ApiResult {
    let export = EXPORTS.iter().find(|e| e.name == name).unwrap();
    let Item::Func(api) = &export.item else {
        panic!()
    };
    let cursor = c.t.stack_base - 0x1000;
    crate::user::windows::hle::dispatch::call_guest(c.p, &mut c.t.cpu, cursor, 0x1234, args, 0)
        .unwrap();
    c.api = api;
    c.entry_sp = c.t.cpu.sp();
    c.cursor = c.entry_sp - 0x100;
    (api.imp)(c)
}

fn int(result: ApiResult) -> u64 {
    match result.unwrap() {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("integer result required"),
    }
}

fn parked(result: ApiResult) -> (Wait, crate::user::windows::hle::Cont) {
    match result.unwrap() {
        Flow::Block { wait, then } => (wait, then),
        _ => panic!("blocked result required"),
    }
}

#[test]
fn critical_section_exports_follow_all_scalar_abis_and_recursive_ownership() {
    for arch in WinArch::ALL {
        with_context(arch, |c, addr| {
            assert_eq!(
                int(invoke(
                    c,
                    "InitializeCriticalSectionAndSpinCount",
                    &[addr, 4000]
                )),
                1
            );
            assert_eq!(int(invoke(c, "TryEnterCriticalSection", &[addr])), 1);
            assert_eq!(int(invoke(c, "TryEnterCriticalSection", &[addr])), 1);
            assert_eq!(sync::cs_recursion(c.p, addr, c.t.tid).unwrap(), 2);
            assert!(!sync::cs_try_enter(c.p, addr, c.t.tid + 1).unwrap());
            assert!(!sync::cs_leave(c.p, addr, c.t.tid + 1).unwrap());
            assert_eq!(
                int(invoke(c, "SetCriticalSectionSpinCount", &[addr, 123])),
                0
            );
            invoke(c, "LeaveCriticalSection", &[addr]).unwrap();
            assert_eq!(sync::cs_recursion(c.p, addr, c.t.tid).unwrap(), 1);
            assert!(sync::cs_delete(c.p, addr).is_err());
            invoke(c, "LeaveCriticalSection", &[addr]).unwrap();
            invoke(c, "DeleteCriticalSection", &[addr]).unwrap();
            assert!(matches!(
                sync::cs_try_enter(c.p, addr, c.t.tid),
                Err(SyncError::Invalid(_))
            ));
        });
    }
}

#[test]
fn critical_section_cross_page_init_and_late_write_faults_are_transactional() {
    for arch in WinArch::ALL {
        with_context(arch, |c, base| {
            let size = if arch.is64() { 0x28 } else { 0x18 };
            let addr = base + 0x1000 - arch.ptr_size();
            c.p.space.wr(addr, &vec![0xA5; size]).unwrap();
            c.p.vm
                .protect(base + 0x1000, 0x1000, prot::READONLY)
                .unwrap();
            assert!(matches!(
                sync::cs_init(c.p, addr, 0),
                Err(SyncError::Fault(MemFault { write: true, .. }))
            ));
            assert_eq!(c.p.space.bytes(addr, size).unwrap(), vec![0xA5; size]);
            c.p.vm
                .protect(base + 0x1000, 0x1000, prot::READWRITE)
                .unwrap();
            sync::cs_init(c.p, addr, 0).unwrap();
            let before = c.p.space.bytes(addr, size).unwrap();
            c.p.vm
                .protect(base + 0x1000, 0x1000, prot::READONLY)
                .unwrap();
            assert!(matches!(
                sync::cs_try_enter(c.p, addr, c.t.tid),
                Err(SyncError::Fault(MemFault { write: true, .. }))
            ));
            assert_eq!(c.p.space.bytes(addr, size).unwrap(), before);
            c.p.vm
                .protect(base + 0x1000, 0x1000, prot::READWRITE)
                .unwrap();
            assert!(sync::cs_try_enter(c.p, addr, c.t.tid).unwrap());
            let before = c.p.space.bytes(addr, size).unwrap();
            c.p.vm
                .protect(base + 0x1000, 0x1000, prot::READONLY)
                .unwrap();
            assert!(sync::cs_leave(c.p, addr, c.t.tid).is_err());
            assert_eq!(c.p.space.bytes(addr, size).unwrap(), before);
            assert_eq!(sync::cs_recursion(c.p, addr, c.t.tid).unwrap(), 1);
        });
    }
}

#[test]
fn critical_section_registered_waiter_poll_and_cancel_are_single_transitions() {
    for arch in WinArch::ALL {
        with_context(arch, |c, addr| {
            sync::cs_init(c.p, addr, 0).unwrap();
            assert!(sync::cs_try_enter(c.p, addr, 1).unwrap());
            let wait = Wait::CritSec { addr };
            sync::on_block(c.p, 2, &wait).unwrap();
            assert!(
                sync::poll(c.p, 2, &wait, Instant::now(), false)
                    .unwrap()
                    .is_none()
            );
            sync::cs_leave(c.p, addr, 1).unwrap();
            assert_eq!(
                sync::poll(c.p, 2, &wait, Instant::now(), false).unwrap(),
                Some(0)
            );
            sync::on_cancel(c.p, 2, &wait).unwrap();
            assert_eq!(sync::cs_recursion(c.p, addr, 2).unwrap(), 1);
            sync::cs_leave(c.p, addr, 2).unwrap();
            sync::cs_delete(c.p, addr).unwrap();
        });
    }
}

#[test]
fn srw_exports_track_reader_owners_and_writer_waiters_without_false_success() {
    for arch in WinArch::ALL {
        with_context(arch, |c, addr| {
            invoke(c, "InitializeSRWLock", &[addr]).unwrap();
            assert_eq!(int(invoke(c, "TryAcquireSRWLockShared", &[addr])), 1);
            assert!(sync::srw_try(c.p, addr, c.t.tid + 1, false).unwrap());
            assert!(!sync::srw_try(c.p, addr, c.t.tid, true).unwrap());
            assert_eq!(int(invoke(c, "TryAcquireSRWLockShared", &[addr])), 0);
            assert!(sync::srw_release(c.p, addr, c.t.tid + 2, false).is_err());
            let writer = c.t.tid + 3;
            let wait = Wait::Srw {
                addr,
                exclusive: true,
            };
            sync::on_block(c.p, writer, &wait).unwrap();
            assert!(!sync::srw_try(c.p, addr, c.t.tid + 4, false).unwrap());
            invoke(c, "ReleaseSRWLockShared", &[addr]).unwrap();
            sync::srw_release(c.p, addr, c.t.tid + 1, false).unwrap();
            assert_eq!(
                sync::poll(c.p, writer, &wait, Instant::now(), false).unwrap(),
                Some(0)
            );
            sync::on_cancel(c.p, writer, &wait).unwrap();
            assert_eq!(sync::srw_held(c.p, addr, writer).unwrap(), Some(true));
            assert!(!sync::srw_try(c.p, addr, writer, true).unwrap());
            assert!(sync::srw_release(c.p, addr, writer + 1, true).is_err());
            sync::srw_release(c.p, addr, writer, true).unwrap();
            assert_eq!(c.p.space.ptr(addr, arch.ptr_size()).unwrap(), 0);
        });
    }
}

#[test]
fn srw_acquire_release_and_wait_registration_roll_back_on_write_fault() {
    for arch in WinArch::ALL {
        with_context(arch, |c, addr| {
            sync::srw_init(c.p, addr).unwrap();
            c.p.vm.protect(addr, 0x1000, prot::READONLY).unwrap();
            assert!(sync::srw_try(c.p, addr, 1, true).is_err());
            assert_eq!(sync::srw_held(c.p, addr, 1).unwrap(), None);
            assert_eq!(c.p.space.ptr(addr, arch.ptr_size()).unwrap(), 0);
            c.p.vm.protect(addr, 0x1000, prot::READWRITE).unwrap();
            sync::srw_try(c.p, addr, 1, true).unwrap();
            c.p.vm.protect(addr, 0x1000, prot::READONLY).unwrap();
            assert!(sync::srw_release(c.p, addr, 1, true).is_err());
            assert_eq!(sync::srw_held(c.p, addr, 1).unwrap(), Some(true));
            let wait = Wait::Srw {
                addr,
                exclusive: true,
            };
            assert!(sync::on_block(c.p, 2, &wait).is_err());
            c.p.vm.protect(addr, 0x1000, prot::READWRITE).unwrap();
            sync::on_block(c.p, 2, &wait).unwrap();
            sync::on_cancel(c.p, 2, &wait).unwrap();
            sync::srw_release(c.p, addr, 1, true).unwrap();
            assert!(sync::srw_try(c.p, addr, 3, false).unwrap());
        });
    }
}

#[test]
fn condition_cs_wake_and_timeout_reacquire_before_return_even_when_stolen() {
    for arch in WinArch::ALL {
        for timeout in [false, true] {
            with_context(arch, |c, lock| {
                let cv = lock + 0x80;
                sync::cs_init(c.p, lock, 0).unwrap();
                sync::cv_init(c.p, cv).unwrap();
                sync::cs_try_enter(c.p, lock, c.t.tid).unwrap();
                let (wait, then) = parked(invoke(
                    c,
                    "SleepConditionVariableCS",
                    &[cv, lock, u32::MAX.into()],
                ));
                sync::on_block(c.p, c.t.tid, &wait).unwrap();
                sync::cs_try_enter(c.p, lock, c.t.tid + 1).unwrap();
                if !timeout {
                    c.p.sync.wake(u128::from(cv) | sync::CONDVAR_KEY, 1);
                }
                let status = if timeout {
                    STATUS_TIMEOUT.into()
                } else {
                    sync::poll(c.p, c.t.tid, &wait, Instant::now(), false)
                        .unwrap()
                        .unwrap()
                };
                // Inject timeout deterministically rather than sleeping on host.
                sync::on_cancel(c.p, c.t.tid, &wait).unwrap();
                let (lock_wait, finish) = parked(then(c, status));
                sync::on_block(c.p, c.t.tid, &lock_wait).unwrap();
                sync::cs_leave(c.p, lock, c.t.tid + 1).unwrap();
                assert_eq!(
                    sync::poll(c.p, c.t.tid, &lock_wait, Instant::now(), false).unwrap(),
                    Some(0)
                );
                sync::on_cancel(c.p, c.t.tid, &lock_wait).unwrap();
                assert_eq!(int(finish(c, 0)), u64::from(!timeout));
                assert_eq!(sync::cs_recursion(c.p, lock, c.t.tid).unwrap(), 1);
                if timeout {
                    assert_eq!(c.last_error().unwrap(), ERROR_TIMEOUT);
                }
            });
        }
    }
}

#[test]
fn condition_srw_modes_and_invalid_cv_fault_do_not_release_lock() {
    for arch in WinArch::ALL {
        for shared in [false, true] {
            with_context(arch, |c, lock| {
                let cv = lock + 0x1000;
                sync::srw_init(c.p, lock).unwrap();
                sync::cv_init(c.p, cv).unwrap();
                sync::srw_try(c.p, lock, c.t.tid, !shared).unwrap();
                c.p.vm.protect(cv, 0x1000, prot::READONLY).unwrap();
                assert!(matches!(
                    invoke(
                        c,
                        "SleepConditionVariableSRW",
                        &[cv, lock, 100, shared.into()]
                    ),
                    Err(ApiErr::Fault(MemFault { write: true, .. }))
                ));
                assert_eq!(sync::srw_held(c.p, lock, c.t.tid).unwrap(), Some(!shared));
                c.p.vm.protect(cv, 0x1000, prot::READWRITE).unwrap();
                let (wait, then) = parked(invoke(
                    c,
                    "SleepConditionVariableSRW",
                    &[cv, lock, u32::MAX.into(), shared.into()],
                ));
                sync::on_block(c.p, c.t.tid, &wait).unwrap();
                assert_eq!(sync::srw_held(c.p, lock, c.t.tid).unwrap(), None);
                c.p.sync.wake(u128::from(cv) | sync::CONDVAR_KEY, 1);
                let status = sync::poll(c.p, c.t.tid, &wait, Instant::now(), false)
                    .unwrap()
                    .unwrap();
                sync::on_cancel(c.p, c.t.tid, &wait).unwrap();
                assert_eq!(int(then(c, status)), 1);
                assert_eq!(sync::srw_held(c.p, lock, c.t.tid).unwrap(), Some(!shared));
            });
        }
    }
}

#[test]
fn wait_on_address_widths_fifo_namespace_timeout_and_checked_reads() {
    for arch in WinArch::ALL {
        with_context(arch, |c, base| {
            let address = base + 3;
            let compare = base + 0x80;
            for size in [1, 2, 4, 8] {
                c.p.space.w64(address, 0x1234).unwrap();
                c.p.space.w64(compare, 0x1234).unwrap();
                let (wait, then) = parked(invoke(
                    c,
                    "WaitOnAddress",
                    &[address, compare, size, u32::MAX.into()],
                ));
                sync::on_block(c.p, 1, &wait).unwrap();
                sync::on_block(c.p, 2, &wait).unwrap();
                c.p.sync
                    .wake(u128::from(address) | sync::CONDVAR_KEY, usize::MAX);
                assert_eq!(
                    sync::poll(c.p, 1, &wait, Instant::now(), false).unwrap(),
                    None
                );
                invoke(c, "WakeByAddressSingle", &[address]).unwrap();
                assert_eq!(
                    sync::poll(c.p, 2, &wait, Instant::now(), false).unwrap(),
                    None
                );
                assert_eq!(
                    sync::poll(c.p, 1, &wait, Instant::now(), false).unwrap(),
                    Some(0)
                );
                sync::on_cancel(c.p, 1, &wait).unwrap();
                assert_eq!(int(then(c, 0)), 1);
                invoke(c, "WakeByAddressAll", &[address]).unwrap();
                assert_eq!(
                    sync::poll(c.p, 2, &wait, Instant::now(), false).unwrap(),
                    Some(0)
                );
                sync::on_cancel(c.p, 2, &wait).unwrap();
                assert_eq!(
                    int(invoke(c, "WaitOnAddress", &[address, compare, size, 0])),
                    0
                );
                assert_eq!(c.last_error().unwrap(), ERROR_TIMEOUT);
                c.p.space.w64(compare, 0x4321).unwrap();
                assert_eq!(
                    int(invoke(c, "WaitOnAddress", &[address, compare, size, 0])),
                    1
                );
            }
            assert_eq!(
                int(invoke(c, "WaitOnAddress", &[address, compare, 3, 0])),
                0
            );
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
            assert!(matches!(
                invoke(c, "WaitOnAddress", &[address, base + 0x20000, 8, 0]),
                Err(ApiErr::Fault(MemFault { write: false, .. }))
            ));
        });
    }
}

#[test]
fn synchronization_storage_alignment_bounds_and_recursion_overflow_fail_closed() {
    for arch in WinArch::ALL {
        with_context(arch, |c, addr| {
            for bad in [0, addr + 1, u64::MAX - 7] {
                assert!(sync::cs_init(c.p, bad, 0).is_err());
                assert!(sync::srw_init(c.p, bad).is_err());
                assert!(sync::cv_init(c.p, bad).is_err());
            }
            sync::cs_init(c.p, addr, 0).unwrap();
            sync::cs_try_enter(c.p, addr, c.t.tid).unwrap();
            let rec = if arch.is64() { 0xC } else { 8 };
            c.p.space.w32(addr + rec, i32::MAX as u32).unwrap();
            let before =
                c.p.space
                    .bytes(addr, if arch.is64() { 0x28 } else { 0x18 })
                    .unwrap();
            assert!(matches!(
                sync::cs_try_enter(c.p, addr, c.t.tid),
                Err(SyncError::Invalid(_))
            ));
            assert_eq!(c.p.space.bytes(addr, before.len()).unwrap(), before);
        });
    }
}

#[test]
fn object_wait_all_recursion_overflow_is_rejected_before_any_consumption() {
    for arch in WinArch::ALL {
        with_context(arch, |c, _| {
            let event = c.p.objects.create(Object::Event {
                manual: false,
                signaled: true,
            });
            let mutex = c.p.objects.create(Object::Mutex {
                owner: Some(c.t.tid),
                count: u32::MAX,
                abandoned: false,
            });
            assert!(matches!(
                sync::try_objects(c.p, c.t.tid, &[event, mutex], true),
                Err(SyncError::Invalid(_))
            ));
            assert!(matches!(
                c.p.objects.obj(event),
                Some(Object::Event { signaled: true, .. })
            ));
            assert!(matches!(
                c.p.objects.obj(mutex),
                Some(Object::Mutex {
                    count: u32::MAX,
                    ..
                })
            ));
            if let Some(Object::Mutex { count, .. }) = c.p.objects.obj_mut(mutex) {
                *count = 1;
            }
            assert_eq!(
                sync::try_objects(c.p, c.t.tid, &[event, mutex], true).unwrap(),
                Some(0)
            );
            assert!(matches!(
                c.p.objects.obj(event),
                Some(Object::Event {
                    signaled: false,
                    ..
                })
            ));
            assert!(matches!(
                c.p.objects.obj(mutex),
                Some(Object::Mutex { count: 2, .. })
            ));
            if let Some(Object::Event { signaled, .. }) = c.p.objects.obj_mut(event) {
                *signaled = true;
            }
            assert!(sync::try_objects(c.p, c.t.tid, &[event, event], true).is_err());
            assert!(sync::try_objects(c.p, c.t.tid, &[event, u32::MAX], true).is_err());
            assert!(matches!(
                c.p.objects.obj(event),
                Some(Object::Event { signaled: true, .. })
            ));
            if let Some(Object::Mutex {
                owner,
                count,
                abandoned,
            }) = c.p.objects.obj_mut(mutex)
            {
                *owner = None;
                *count = 0;
                *abandoned = true;
            }
            assert_eq!(
                sync::try_objects(c.p, c.t.tid, &[event, mutex], true).unwrap(),
                Some(sync::WAIT_ABANDONED_0)
            );
            if let Some(Object::Mutex {
                owner,
                count,
                abandoned,
            }) = c.p.objects.obj_mut(mutex)
            {
                *owner = None;
                *count = 0;
                *abandoned = true;
            }
            assert_eq!(
                sync::try_objects(c.p, c.t.tid, &[event, mutex], false).unwrap(),
                Some(sync::WAIT_ABANDONED_0 + 1)
            );
        });
    }
}

#[test]
fn completed_wait_cannot_consume_twice_and_forged_address_cannot_wake_cv() {
    for arch in WinArch::ALL {
        with_context(arch, |c, cv| {
            sync::cv_init(c.p, cv).unwrap();
            let now = Instant::now();
            let condition = Wait::Address {
                key: u128::from(cv) | sync::CONDVAR_KEY,
                deadline: None,
            };
            sync::on_block(c.p, c.t.tid, &condition).unwrap();
            invoke(c, "WakeByAddressAll", &[cv | (1 << 63)]).unwrap();
            assert_eq!(
                sync::poll(c.p, c.t.tid, &condition, now, false).unwrap(),
                None
            );
            invoke(c, "WakeConditionVariable", &[cv]).unwrap();
            assert_eq!(
                sync::poll(c.p, c.t.tid, &condition, now, false).unwrap(),
                Some(0)
            );
            assert!(sync::poll(c.p, c.t.tid, &condition, now, false).is_err());
            let different = Wait::Address {
                key: cv.into(),
                deadline: None,
            };
            assert!(sync::on_cancel(c.p, c.t.tid, &different).is_err());
            sync::on_cancel(c.p, c.t.tid, &condition).unwrap();
            sync::on_cancel(c.p, c.t.tid, &condition).unwrap();
            let timeout = Wait::Address {
                key: cv.into(),
                deadline: Some(now),
            };
            sync::on_block(c.p, c.t.tid, &timeout).unwrap();
            assert_eq!(
                sync::poll(c.p, c.t.tid, &timeout, now, false).unwrap(),
                Some(sync::WAIT_TIMEOUT)
            );
            sync::on_cancel(c.p, c.t.tid, &timeout).unwrap();
            invoke(c, "WakeByAddressAll", &[cv]).unwrap();
            let forever = Wait::Address {
                key: cv.into(),
                deadline: None,
            };
            sync::on_block(c.p, c.t.tid, &forever).unwrap();
            assert_eq!(
                sync::poll(c.p, c.t.tid, &forever, now, false).unwrap(),
                None
            );
            sync::on_cancel(c.p, c.t.tid, &forever).unwrap();
        });
    }
}

#[test]
fn zero_timeout_condition_waits_release_and_reacquire_with_checked_writes() {
    for arch in WinArch::ALL {
        for mode in [None, Some(false), Some(true)] {
            with_context(arch, |c, lock| {
                let cv = lock + 0x1000;
                sync::cv_init(c.p, cv).unwrap();
                let (api, args) = match mode {
                    None => {
                        sync::cs_init(c.p, lock, 0).unwrap();
                        sync::cs_try_enter(c.p, lock, c.t.tid).unwrap();
                        ("SleepConditionVariableCS", vec![cv, lock, 0])
                    }
                    Some(exclusive) => {
                        sync::srw_init(c.p, lock).unwrap();
                        sync::srw_try(c.p, lock, c.t.tid, exclusive).unwrap();
                        (
                            "SleepConditionVariableSRW",
                            vec![cv, lock, 0, u64::from(!exclusive)],
                        )
                    }
                };
                let size = if mode.is_none() {
                    if arch.is64() { 0x28 } else { 0x18 }
                } else {
                    arch.ptr_size() as usize
                };
                let before = c.p.space.bytes(lock, size).unwrap();
                c.p.vm.protect(lock, 0x1000, prot::READONLY).unwrap();
                assert!(matches!(
                    invoke(c, api, &args),
                    Err(ApiErr::Fault(MemFault { write: true, .. }))
                ));
                assert_eq!(c.p.space.bytes(lock, size).unwrap(), before);
                c.p.vm.protect(lock, 0x1000, prot::READWRITE).unwrap();
                let (wait, then) = parked(invoke(c, api, &args));
                match mode {
                    None => assert!(sync::cs_recursion(c.p, lock, c.t.tid).is_err()),
                    Some(_) => assert_eq!(sync::srw_held(c.p, lock, c.t.tid).unwrap(), None),
                }
                sync::on_block(c.p, c.t.tid, &wait).unwrap();
                let status = sync::poll(c.p, c.t.tid, &wait, wait.deadline().unwrap(), false)
                    .unwrap()
                    .unwrap();
                assert_eq!(status, sync::WAIT_TIMEOUT);
                sync::on_cancel(c.p, c.t.tid, &wait).unwrap();
                assert_eq!(int(then(c, status)), 0);
                assert_eq!(c.last_error().unwrap(), ERROR_TIMEOUT);
                match mode {
                    None => assert_eq!(sync::cs_recursion(c.p, lock, c.t.tid).unwrap(), 1),
                    Some(exclusive) => {
                        assert_eq!(sync::srw_held(c.p, lock, c.t.tid).unwrap(), Some(exclusive))
                    }
                }
            });
        }
    }
}

#[test]
fn process_exit_releases_final_wait_pins_without_accessing_unreadable_lockwords() {
    for arch in WinArch::ALL {
        with_context(arch, |c, addr| {
            let event = c.p.objects.create(Object::Event {
                manual: false,
                signaled: false,
            });
            let handle = c.p.objects.open(event, false);
            let objects = Wait::Objects {
                objs: vec![event],
                all: false,
                deadline: None,
                alertable: false,
            };
            sync::on_block(c.p, 10, &objects).unwrap();
            c.p.objects.close(handle.into()).unwrap();
            assert!(c.p.objects.obj(event).is_some());
            sync::cs_init(c.p, addr, 0).unwrap();
            sync::cs_try_enter(c.p, addr, 20).unwrap();
            let critical = Wait::CritSec { addr };
            sync::on_block(c.p, 30, &critical).unwrap();
            let srw = addr + 0x80;
            sync::srw_init(c.p, srw).unwrap();
            sync::srw_try(c.p, srw, 40, true).unwrap();
            let writer = Wait::Srw {
                addr: srw,
                exclusive: true,
            };
            sync::on_block(c.p, 50, &writer).unwrap();
            c.p.vm.protect(addr, 0x1000, prot::NOACCESS).unwrap();
            sync::on_process_exit(c.p);
            assert!(c.p.objects.obj(event).is_none());
            sync::on_cancel(c.p, 30, &critical).unwrap();
            sync::on_cancel(c.p, 50, &writer).unwrap();
            sync::on_process_exit(c.p);
        });
    }
}

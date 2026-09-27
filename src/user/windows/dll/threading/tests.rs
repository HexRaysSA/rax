//! Cross-ABI API tests use the same descriptor-driven argument reader as HLE.

use super::super::super::hle::{Api, ApiErr, Item, Value};
use super::super::super::memory::{mem, prot};
use super::super::super::process::{WindowsConfig, WindowsProcess};
use super::super::super::sync::{self, Wait};
use super::*;
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
    let mut config = WindowsConfig::new("thread-api-test.exe", Vec::new());
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let data =
        p.vm.allocate(None, 0x2000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let sp = t.cpu.sp();
    let mut c = Ctx {
        p,
        t: &mut t,
        api: api("CreateThread"),
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    };
    test(&mut c, data);
}

fn api(name: &str) -> &'static Api {
    EXPORTS
        .iter()
        .chain(super::super::kernel::EXPORTS.iter())
        .find_map(|export| match &export.item {
            Item::Func(api) if api.name == name => Some(api),
            _ => None,
        })
        .unwrap()
}

fn invoke(c: &mut Ctx, name: &str, arguments: &[u64]) -> ApiResult {
    c.api = api(name);
    assert_eq!(arguments.len(), c.api.args.len());
    for (index, &value) in arguments.iter().enumerate() {
        match c.arch() {
            WinArch::X86 => c
                .mem()
                .w32(c.entry_sp + 4 + index as u64 * 4, value as u32)
                .unwrap(),
            WinArch::X64 if index < 4 => c.t.cpu.set_gpr([1, 2, 8, 9][index], value),
            WinArch::X64 => c
                .mem()
                .w64(c.entry_sp + 8 + index as u64 * 8, value)
                .unwrap(),
            WinArch::Arm64 => c.t.cpu.set_gpr(index, value),
        }
    }
    (c.api.imp)(c)
}

fn integer(c: &mut Ctx, name: &str, arguments: &[u64]) -> u64 {
    match invoke(c, name, arguments).unwrap() {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("{name}: expected integer return"),
    }
}

fn put_name(c: &Ctx, addr: u64, name: &str) {
    c.mem()
        .put_wstr(addr, &name.encode_utf16().collect::<Vec<_>>())
        .unwrap();
}

#[test]
fn create_thread_suspended_reservation_and_handle_grant_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let handle = integer(c, "CreateThread", &[0, 0x10000, 0, 0x1234, 0x10004, data]);
            assert_ne!(handle, 0);
            let tid = c.mem().u32(data).unwrap();
            let child = &c.p.threads[&tid];
            assert_eq!(child.suspend, 1);
            assert_eq!(child.param, 0x1234);
            assert_eq!(child.start, 0); // Invalid entry addresses fail asynchronously.
            assert_eq!(child.stack_base - child.stack_alloc, 0x10000);
            assert!(!child.runnable());
            assert_eq!(c.p.objects.access(handle), Some(THREAD_ALL_ACCESS));
            assert_eq!(c.p.objects.flags(handle), Some(0));
            assert_eq!(integer(c, "GetExitCodeThread", &[handle, data + 4]), 1);
            assert_eq!(c.mem().u32(data + 4).unwrap(), STILL_ACTIVE);
        });
    }
}

#[test]
fn creation_rejects_hostile_flags_security_and_outputs_without_publication() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let before = (
                c.p.threads.len(),
                c.p.objects.handle_count(),
                c.p.vm.committed_bytes(),
            );
            assert_eq!(integer(c, "CreateThread", &[0, 0, 0, 0, 8, data]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
            c.mem()
                .w32(data, if arch.is64() { 24 } else { 12 })
                .unwrap();
            c.write_ptr(data + if arch.is64() { 8 } else { 4 }, 1)
                .unwrap();
            assert_eq!(integer(c, "CreateThread", &[data, 0, 0, 0, 0, 0]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_NOT_SUPPORTED);
            c.p.vm.protect(data, 4, prot::READONLY).unwrap();
            assert!(matches!(invoke(c, "CreateThread", &[0, 0, 0, 0, 0, data]),
            Err(ApiErr::Fault(MemFault { addr, write: true })) if addr == data));
            assert_eq!(
                (
                    c.p.threads.len(),
                    c.p.objects.handle_count(),
                    c.p.vm.committed_bytes()
                ),
                before
            );
        });
    }
}

#[test]
fn thread_stack_reserve_arithmetic_is_checked_and_commit_requests_fit() {
    assert_eq!(stack_reserve(0x100000, 1, 0), Some(0x100000));
    assert_eq!(stack_reserve(0x100000, 0x10000, 0x10000), Some(0x10000));
    assert_eq!(stack_reserve(0x100000, 0x100000, 0), Some(0x200000));
    assert_eq!(stack_reserve(0x100000, 0xFF000, 0), Some(0x200000));
    assert_eq!(stack_reserve(0x100000, u64::MAX, 0), None);
    for arch in [WinArch::X64, WinArch::Arm64] {
        with_context(arch, |c, _| {
            let before = (
                c.p.threads.len(),
                c.p.objects.handle_count(),
                c.p.vm.committed_bytes(),
            );
            assert_eq!(integer(c, "CreateThread", &[0, u64::MAX, 0, 0, 0, 0]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
            assert_eq!(
                (
                    c.p.threads.len(),
                    c.p.objects.handle_count(),
                    c.p.vm.committed_bytes()
                ),
                before
            );
        });
    }
}

#[test]
fn suspend_resume_boundaries_and_current_real_handle_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c, _| {
            let handle = u64::from(
                c.p.objects
                    .open_access(c.t.obj, false, THREAD_ALL_ACCESS)
                    .unwrap(),
            );
            for previous in 0..MAXIMUM_SUSPEND_COUNT {
                assert_eq!(integer(c, "SuspendThread", &[handle]), u64::from(previous));
            }
            assert_eq!(integer(c, "SuspendThread", &[handle]), u64::from(u32::MAX));
            assert_eq!(c.last_error().unwrap(), ERROR_SIGNAL_REFUSED);
            assert_eq!(c.t.suspend, MAXIMUM_SUSPEND_COUNT);
            for previous in (1..=MAXIMUM_SUSPEND_COUNT).rev() {
                assert_eq!(
                    integer(c, "ResumeThread", &[arch.ptr(u64::MAX - 1)]),
                    u64::from(previous)
                );
            }
            assert_eq!(integer(c, "ResumeThread", &[handle]), 0);
            let limited = u64::from(
                c.p.objects
                    .open_access(c.t.obj, false, THREAD_QUERY_INFORMATION)
                    .unwrap(),
            );
            assert_eq!(integer(c, "SuspendThread", &[limited]), u64::from(u32::MAX));
            assert_eq!(c.last_error().unwrap(), ERROR_ACCESS_DENIED);
        });
    }
}

#[test]
fn termination_signals_thread_object_and_apcs_fail_while_terminating() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let handle = integer(c, "CreateThread", &[0, 0x10000, 0, 0, 0x10004, data]);
            let tid = c.mem().u32(data).unwrap();
            assert_eq!(integer(c, "QueueUserAPC", &[0, handle, 7]), 1);
            assert_eq!(integer(c, "TerminateThread", &[handle, 259]), 1);
            assert_eq!(integer(c, "QueueUserAPC", &[0, handle, 8]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_GEN_FAILURE);
            assert_eq!(integer(c, "GetExitCodeThread", &[handle, data + 4]), 1);
            assert_eq!(c.mem().u32(data + 4).unwrap(), STILL_ACTIVE);
            let child = c.p.threads.remove(&tid).unwrap();
            thread::destroy(c.p, child, 259);
            assert_eq!(integer(c, "WaitForSingleObject", &[handle, 0]), 0);
            assert_eq!(integer(c, "GetExitCodeThread", &[handle, data + 4]), 1);
            assert_eq!(c.mem().u32(data + 4).unwrap(), 259);
            assert_eq!(integer(c, "QueueUserAPC", &[0, handle, 9]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_GEN_FAILURE);
            assert!(matches!(
                invoke(c, "TerminateThread", &[arch.ptr(u64::MAX - 1), 42]),
                Ok(Flow::TerminateThread(42))
            ));
        });
    }
}

#[test]
fn queued_apcs_fifo_and_alertable_sleep_flow_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c, _| {
            let current = arch.ptr(u64::MAX - 1);
            assert_eq!(integer(c, "QueueUserAPC", &[0x1111, current, 1]), 1);
            assert_eq!(integer(c, "QueueUserAPC", &[0x2222, current, 2]), 1);
            assert_eq!(
                c.t.apcs.iter().copied().collect::<Vec<_>>(),
                [(0x1111, 1), (0x2222, 2)]
            );
            assert!(matches!(
                invoke(c, "SleepEx", &[0, 0]),
                Ok(Flow::Yield(Value::Int(0)))
            ));
            let Flow::Block { wait, then } = invoke(c, "SleepEx", &[0, 1]).unwrap() else {
                panic!("expected alertable wait")
            };
            assert_eq!(
                sync::poll(c.p, c.t.tid, &wait, Instant::now(), true).unwrap(),
                Some(sync::WAIT_IO_COMPLETION)
            );
            assert!(matches!(
                then(c, sync::WAIT_IO_COMPLETION).unwrap(),
                Flow::Ret(Value::Int(0xC0))
            ));
            assert!(matches!(
                invoke(c, "Sleep", &[0]),
                Ok(Flow::Yield(Value::None))
            ));
            assert!(matches!(
                invoke(c, "SleepEx", &[u64::from(u32::MAX), 1]),
                Ok(Flow::Block {
                    wait: Wait::Sleep {
                        deadline: None,
                        alertable: true
                    },
                    ..
                })
            ));
        });
    }
}

#[test]
fn named_event_case_namespace_collision_and_existing_properties_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            put_name(c, data, "Event");
            let first = integer(c, "CreateEventW", &[0, 1, 0, data]);
            let second = integer(c, "CreateEventW", &[0, 0, 1, data]);
            assert_eq!(c.last_error().unwrap(), ERROR_ALREADY_EXISTS);
            assert_eq!(c.p.objects.id(first), c.p.objects.id(second));
            assert!(matches!(
                c.p.objects.get(first),
                Some(Object::Event {
                    manual: true,
                    signaled: false
                })
            ));
            assert_eq!(integer(c, "CreateMutexW", &[0, 1, data]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_HANDLE);
            put_name(c, data, "event");
            let lower = integer(c, "CreateEventW", &[0, 0, 0, data]);
            assert_ne!(c.p.objects.id(first), c.p.objects.id(lower));
            put_name(c, data, "Local\\Event");
            let local = integer(c, "OpenEventW", &[u64::from(objects::SYNCHRONIZE), 1, data]);
            assert_eq!(c.p.objects.id(first), c.p.objects.id(local));
            assert_eq!(c.p.objects.flags(local), Some(1));
            put_name(c, data, "Global\\Event");
            let global = integer(c, "CreateEventW", &[0, 0, 0, data]);
            assert_ne!(c.p.objects.id(first), c.p.objects.id(global));
        });
    }
}

#[test]
fn named_open_access_checks_and_last_error_success_preservation() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            put_name(c, data, "E");
            let full = integer(c, "CreateEventW", &[0, 0, 0, data]);
            c.set_last_error(0x12345678).unwrap();
            let wait = integer(c, "OpenEventW", &[u64::from(objects::SYNCHRONIZE), 0, data]);
            assert_eq!(c.last_error().unwrap(), 0x12345678);
            assert_eq!(integer(c, "SetEvent", &[wait]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_ACCESS_DENIED);
            let modify = integer(c, "OpenEventW", &[2, 0, data]);
            assert_eq!(integer(c, "SetEvent", &[modify]), 1);
            assert_eq!(
                integer(c, "WaitForSingleObject", &[modify, 0]),
                u64::from(u32::MAX)
            );
            assert_eq!(c.last_error().unwrap(), ERROR_ACCESS_DENIED);
            assert_eq!(integer(c, "WaitForSingleObject", &[wait, 0]), 0);
            assert_eq!(
                integer(c, "WaitForSingleObject", &[full, 0]),
                sync::WAIT_TIMEOUT
            );
            for unsupported in [0x80000000, 0x02000000, 0x01000000] {
                assert_eq!(integer(c, "OpenEventW", &[unsupported, 0, data]), 0);
                assert_eq!(c.last_error().unwrap(), ERROR_NOT_SUPPORTED);
            }
        });
    }
}

#[test]
fn object_names_security_and_string_faults_do_not_publish_handles() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let handles = c.p.objects.handle_count();
            for name in ["", "Local\\", "Local\\A\\B", "Session\\E"] {
                put_name(c, data, name);
                assert_eq!(integer(c, "CreateEventW", &[0, 0, 0, data]), 0);
                assert_eq!(c.p.objects.handle_count(), handles);
            }
            c.mem().put_wstr(data, &[0xD800]).unwrap();
            assert_eq!(integer(c, "CreateEventW", &[0, 0, 0, data]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_NOT_SUPPORTED);
            c.mem().put_cstr(data, &[0x80]).unwrap();
            assert_eq!(integer(c, "CreateEventA", &[0, 0, 0, data]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_NOT_SUPPORTED);
            assert!(matches!(
                invoke(c, "CreateEventW", &[0, 0, 0, 0x1000]),
                Err(ApiErr::Fault(_))
            ));
            assert_eq!(c.p.objects.handle_count(), handles);
            put_name(c, data, "E");
            let full = integer(c, "CreateEventW", &[0, 0, 0, data]);
            let attrs = data + 0x800;
            c.mem()
                .w32(attrs, if arch.is64() { 24 } else { 12 })
                .unwrap();
            c.write_ptr(attrs + if arch.is64() { 8 } else { 4 }, arch.ptr(u64::MAX))
                .unwrap();
            c.mem()
                .w32(attrs + if arch.is64() { 16 } else { 8 }, 1)
                .unwrap();
            let existing = integer(c, "CreateEventW", &[attrs, 0, 0, data]);
            assert_eq!(c.p.objects.id(full), c.p.objects.id(existing));
            assert_eq!(c.p.objects.flags(existing), Some(1));
            put_name(c, data, "New");
            assert_eq!(integer(c, "CreateEventW", &[attrs, 0, 0, data]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_NOT_SUPPORTED);
        });
    }
}

#[test]
fn recursive_mutex_release_owner_and_abandonment_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let mutex = integer(c, "CreateMutexW", &[0, 1, 0]);
            assert_eq!(integer(c, "WaitForSingleObject", &[mutex, 0]), 0);
            assert!(matches!(
                c.p.objects.get(mutex),
                Some(Object::Mutex { count: 2, .. })
            ));
            assert_eq!(integer(c, "ReleaseMutex", &[mutex]), 1);
            assert_eq!(integer(c, "ReleaseMutex", &[mutex]), 1);
            assert_eq!(integer(c, "ReleaseMutex", &[mutex]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_NOT_OWNER);
            let handle = integer(c, "CreateThread", &[0, 0x10000, 0, 0, 0x10004, data]);
            let tid = c.mem().u32(data).unwrap();
            let Some(Object::Mutex { owner, count, .. }) = c.p.objects.get_mut(mutex) else {
                panic!()
            };
            *owner = Some(tid);
            *count = 1;
            let child = c.p.threads.remove(&tid).unwrap();
            thread::destroy(c.p, child, 0);
            assert_eq!(
                integer(c, "WaitForSingleObject", &[mutex, 0]),
                sync::WAIT_ABANDONED_0
            );
            assert_eq!(integer(c, "WaitForSingleObject", &[handle, 0]), 0);
            assert_eq!(integer(c, "ReleaseMutex", &[mutex]), 1);
        });
    }
}

#[test]
fn semaphore_release_limits_output_fault_and_existing_counts_all_abis() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            put_name(c, data, "S");
            let handle = integer(c, "CreateSemaphoreW", &[0, 1, 2, data]);
            assert_ne!(handle, 0);
            assert_ne!(integer(c, "CreateSemaphoreW", &[0, u64::MAX, 0, data]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_ALREADY_EXISTS);
            assert_eq!(integer(c, "ReleaseSemaphore", &[handle, 2, 0]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_TOO_MANY_POSTS);
            assert_eq!(integer(c, "ReleaseSemaphore", &[handle, 0, 0]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
            c.p.vm.protect(data + 0x1000, 4, prot::READONLY).unwrap();
            assert!(matches!(
                invoke(c, "ReleaseSemaphore", &[handle, 1, data + 0x1000]),
                Err(ApiErr::Fault(MemFault { write: true, .. }))
            ));
            assert!(matches!(
                c.p.objects.get(handle),
                Some(Object::Semaphore { count: 1, max: 2 })
            ));
            assert_eq!(
                integer(c, "ReleaseSemaphore", &[handle, 1, data + 0x800]),
                1
            );
            assert_eq!(c.mem().u32(data + 0x800).unwrap(), 1);
            assert_eq!(integer(c, "WaitForSingleObject", &[handle, 0]), 0);
            assert_eq!(integer(c, "WaitForSingleObject", &[handle, 0]), 0);
            assert_eq!(
                integer(c, "WaitForSingleObject", &[handle, 0]),
                sync::WAIT_TIMEOUT
            );
        });
    }
}

#[test]
fn multiple_waits_lowest_index_wait_all_atomicity_and_duplicate_rejection() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let event = integer(c, "CreateEventW", &[0, 0, 1, 0]);
            let semaphore = integer(c, "CreateSemaphoreW", &[0, 0, 2, 0]);
            c.write_ptr(data, event).unwrap();
            c.write_ptr(data + c.psize(), semaphore).unwrap();
            assert_eq!(
                integer(c, "WaitForMultipleObjects", &[2, data, 1, 0]),
                sync::WAIT_TIMEOUT
            );
            assert!(matches!(
                c.p.objects.get(event),
                Some(Object::Event { signaled: true, .. })
            ));
            assert_eq!(integer(c, "ReleaseSemaphore", &[semaphore, 1, 0]), 1);
            assert_eq!(integer(c, "WaitForMultipleObjects", &[2, data, 1, 0]), 0);
            assert!(matches!(
                c.p.objects.get(event),
                Some(Object::Event {
                    signaled: false,
                    ..
                })
            ));
            assert!(matches!(
                c.p.objects.get(semaphore),
                Some(Object::Semaphore { count: 0, .. })
            ));
            assert_eq!(integer(c, "ReleaseSemaphore", &[semaphore, 1, 0]), 1);
            assert_eq!(integer(c, "WaitForMultipleObjects", &[2, data, 0, 0]), 1);
            integer(c, "SetEvent", &[event]);
            let alias = u64::from(c.p.objects.duplicate(event, false).unwrap());
            c.write_ptr(data + c.psize(), alias).unwrap();
            assert_eq!(
                integer(c, "WaitForMultipleObjects", &[2, data, 1, 0]),
                u64::from(u32::MAX)
            );
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
            assert!(matches!(
                c.p.objects.get(event),
                Some(Object::Event { signaled: true, .. })
            ));
            for count in [0, 65, u64::from(u32::MAX)] {
                assert_eq!(
                    integer(c, "WaitForMultipleObjects", &[count, 0, 0, 0]),
                    u64::from(u32::MAX)
                );
            }
        });
    }
}

#[test]
fn parked_wait_refs_survive_handle_close_and_release_on_cancel() {
    for arch in WinArch::ALL {
        with_context(arch, |c, _| {
            let handle = integer(c, "CreateEventW", &[0, 0, 0, 0]);
            let id = c.p.objects.id(handle).unwrap();
            let Flow::Block { wait, .. } =
                invoke(c, "WaitForSingleObject", &[handle, u64::from(u32::MAX)]).unwrap()
            else {
                panic!()
            };
            sync::on_block(c.p, c.t.tid, &wait).unwrap();
            assert!(c.p.objects.close(handle).unwrap().is_none());
            assert!(c.p.objects.obj(id).is_some());
            assert_eq!(
                sync::poll(c.p, c.t.tid, &wait, Instant::now(), false).unwrap(),
                None
            );
            sync::on_cancel(c.p, c.t.tid, &wait).unwrap();
            assert!(c.p.objects.obj(id).is_none());
            sync::on_cancel(c.p, c.t.tid, &wait).unwrap();
        });
    }
}

#[test]
fn wait_array_fault_and_later_invalid_handle_do_not_consume_first_object() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let event = integer(c, "CreateEventW", &[0, 0, 1, 0]);
            c.write_ptr(data, event).unwrap();
            c.write_ptr(data + c.psize(), 0).unwrap();
            assert_eq!(
                integer(c, "WaitForMultipleObjectsEx", &[2, data, 0, 0, 1]),
                u64::from(u32::MAX)
            );
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_HANDLE);
            assert!(matches!(
                c.p.objects.get(event),
                Some(Object::Event { signaled: true, .. })
            ));
            assert!(matches!(
                invoke(c, "WaitForMultipleObjects", &[2, 0x1000, 0, 0]),
                Err(ApiErr::Fault(_))
            ));
            assert!(matches!(
                c.p.objects.get(event),
                Some(Object::Event { signaled: true, .. })
            ));
        });
    }
}

#[test]
fn switch_to_thread_accounts_for_suspension_and_loader_serialization() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let handle = integer(c, "CreateThread", &[0, 0x10000, 0, 0, 0x10004, data]);
            assert!(matches!(
                invoke(c, "SwitchToThread", &[]),
                Ok(Flow::Yield(Value::Int(0)))
            ));
            integer(c, "ResumeThread", &[handle]);
            // The main thread is still in process initialization.
            assert!(matches!(
                invoke(c, "SwitchToThread", &[]),
                Ok(Flow::Yield(Value::Int(0)))
            ));
            c.t.attached = true;
            assert!(matches!(
                invoke(c, "SwitchToThread", &[]),
                Ok(Flow::Yield(Value::Int(1)))
            ));
            integer(c, "SuspendThread", &[handle]);
            assert!(matches!(
                invoke(c, "SwitchToThread", &[]),
                Ok(Flow::Yield(Value::Int(0)))
            ));
        });
    }
}

#[test]
fn manual_event_stays_signaled_until_reset_and_name_boundaries_are_checked() {
    for arch in WinArch::ALL {
        with_context(arch, |c, data| {
            let handle = integer(c, "CreateEventW", &[0, 1, 1, 0]);
            assert_eq!(integer(c, "WaitForSingleObject", &[handle, 0]), 0);
            assert_eq!(integer(c, "WaitForSingleObject", &[handle, 0]), 0);
            assert_eq!(integer(c, "ResetEvent", &[handle]), 1);
            assert_eq!(
                integer(c, "WaitForSingleObject", &[handle, 0]),
                sync::WAIT_TIMEOUT
            );
            let name = "N".repeat(260);
            put_name(c, data, &name);
            assert_ne!(integer(c, "CreateEventW", &[0, 0, 0, data]), 0);
            put_name(c, data, &(name + "N"));
            assert_eq!(integer(c, "CreateEventW", &[0, 0, 0, data]), 0);
            assert_eq!(c.last_error().unwrap(), ERROR_FILENAME_EXCED_RANGE);
            c.mem().put_cstr(data, b"ANSI").unwrap();
            let event = integer(c, "CreateEventA", &[0, 0, 0, data]);
            let opened = integer(c, "OpenEventA", &[u64::from(objects::SYNCHRONIZE), 0, data]);
            assert_eq!(c.p.objects.id(event), c.p.objects.id(opened));
        });
    }
}

#[test]
fn exhausted_or_colliding_thread_ids_fail_before_resource_mutation() {
    for arch in WinArch::ALL {
        with_context(arch, |c, _| {
            let before = (
                c.p.threads.len(),
                c.p.objects.handle_count(),
                c.p.vm.committed_bytes(),
            );
            for id in [u32::MAX - 3, 0, 3, c.t.tid] {
                c.p.next_tid = id;
                assert_eq!(
                    integer(c, "CreateThread", &[0, 0x10000, 0, 0, 0x10004, 0]),
                    0
                );
                assert_eq!(c.last_error().unwrap(), ERROR_NOT_ENOUGH_MEMORY);
                assert_eq!(c.p.next_tid, id);
                assert_eq!(
                    (
                        c.p.threads.len(),
                        c.p.objects.handle_count(),
                        c.p.vm.committed_bytes()
                    ),
                    before
                );
            }
        });
    }
}

#[test]
fn exit_thread_frees_owned_tls_expansion_without_trusting_forged_teb_pointer() {
    for arch in WinArch::ALL {
        with_context(arch, |c, _| {
            for expected in 0..=64 {
                assert_eq!(integer(c, "TlsAlloc", &[]), expected);
            }
            let heap = c.p.process_heap;
            let before = c.p.heaps.blocks(heap);
            let tid = thread::create(c.p, 0, 0, 0x10000, false).unwrap();
            let child = c.p.threads.remove(&tid).unwrap();
            let main = std::mem::replace(c.t, child);
            assert_eq!(integer(c, "TlsSetValue", &[64, 0x1234]), 1);
            let pointer = c.t.teb + offsets(arch).teb_tls_expansion_slots;
            let array = c.read_ptr(pointer).unwrap();
            assert_ne!(array, 0);
            assert!(c.t.tls_blocks.contains(&array));
            let victim =
                c.p.heaps
                    .alloc_checked(&mut c.p.vm, heap, 32, true)
                    .unwrap();
            c.write_ptr(pointer, victim).unwrap();
            assert!(matches!(
                invoke(c, "ExitThread", &[42]),
                Ok(Flow::ExitThread(42))
            ));
            let ended = std::mem::replace(c.t, main);
            thread::destroy(c.p, ended, 42);
            assert!(c.p.heaps.size(heap, array).is_err());
            // A 32-byte request is already a multiple of both guest heap
            // alignments (x86 8 bytes; x64/ARM64 16 bytes).
            assert_eq!(c.p.heaps.size(heap, victim), Ok(32));
            assert_eq!(c.p.heaps.blocks(heap).len(), before.len() + 1);
            c.p.heaps.free(heap, victim).unwrap();
            assert_eq!(c.p.heaps.blocks(heap), before);
        });
    }
}

//! Native results precede implementation; guest calls use the raw NT service.
use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::objects::{CURRENT_PROCESS, Object};

fn corpus(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-termination/arm64-native-v1.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-termination/x64-native-v1.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-termination/x86-native-v1.txt"
        )),
    }
}

#[test]
fn native_termination_replays_1134_owned_handle_lifetime_and_type_cases() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut current) = fixture(arch, "NtTerminateThread", SERVICE);
        let p = process.state_mut();
        let process_object = p
            .objects
            .iter()
            .find_map(|(id, o)| {
                matches!(o, Object::Process { pid, .. } if *pid == p.pid).then_some(id)
            })
            .unwrap();
        let last_error = current.teb + offsets(arch).teb_last_error;
        let mut index = 0;
        for line in corpus(arch).lines().filter(|v| v.starts_with("case ")) {
            let row: Vec<_> = line
                .split_whitespace()
                .skip(1)
                .map(|v| u64::from_str_radix(v, 16).unwrap())
                .collect();
            assert_eq!(row.len(), 18);
            assert_eq!(row[0], index);
            let (kind, access, tag, retired, code) =
                (row[1], row[2] as u32, row[3], row[4] != 0, row[5] as u32);
            let tid = thread::create(p, 0x1234_5000, 0, 0x10000, false).unwrap();
            p.threads.get_mut(&tid).unwrap().suspend = 1;
            let object = p.threads[&tid].obj;
            let full = u64::from(p.objects.open_access(object, false, 0x1fffff).unwrap());
            let mut handles = vec![full];
            let candidate = match kind {
                0 => {
                    let h = u64::from(p.objects.open_access(object, false, access).unwrap());
                    handles.push(h);
                    h | tag
                }
                1 => {
                    let h = u64::from(p.objects.open_access(object, false, 0x1fffff).unwrap());
                    p.objects.close(h).unwrap();
                    h
                }
                2 => 0x1234_5678,
                3 => arch.ptr(CURRENT_PROCESS),
                4 => {
                    let e = p.objects.create(Object::Event {
                        manual: false,
                        signaled: 0,
                    });
                    let h = u64::from(p.objects.open_access(e, false, access).unwrap());
                    handles.push(h);
                    h
                }
                5 => {
                    let h = u64::from(
                        p.objects
                            .open_access(process_object, false, access)
                            .unwrap(),
                    );
                    handles.push(h);
                    h
                }
                _ => unreachable!(),
            };
            if retired {
                let t = p.threads.remove(&tid).unwrap();
                thread::destroy(p, t, 0x37);
            }
            p.space.w32(last_error, 0x7654_3210).unwrap();
            let label = format!("{arch}/case{index}/kind{kind}/access{access:#x}/retired{retired}");
            let status = call(
                p,
                &mut current,
                "NtTerminateThread",
                candidate,
                u64::from(code),
            );
            assert_eq!(status, row[6] as u32, "{label}");
            assert_eq!(
                p.space.u32(last_error).unwrap(),
                row[7] as u32,
                "{label}/LastError"
            );
            // Capture the API boundary before any scheduler retirement.
            let Some(Object::Thread { exit_code, .. }) = p.objects.obj(object) else {
                panic!("retained guest thread object")
            };
            assert_eq!(
                *exit_code,
                retired.then_some(0x37),
                "{label}/retirement is separate"
            );
            if !retired {
                assert_eq!(
                    p.threads[&tid].terminate,
                    if status == 0 { Some(code) } else { None },
                    "{label}/request"
                );
            }
            assert_eq!(
                call(p, &mut current, "NtTerminateThread", candidate, 0x5566_7788),
                row[9] as u32,
                "{label}/repeat"
            );
            if !retired {
                if status != 0 {
                    assert_eq!(
                        call(p, &mut current, "NtTerminateThread", full, 0x37),
                        row[10] as u32,
                        "{label}/cleanup"
                    );
                }
                let mut t = p.threads.remove(&tid).unwrap();
                let pending = t.terminate.take().expect("forced request is pending");
                assert_eq!(pending, row[13] as u32, "{label}/first exit code wins");
                // The separate scheduler tests exercise processing/wakeup. Here
                // commit that pending forced retirement before retained queries.
                thread::destroy(p, t, pending);
            }
            assert!(
                matches!(p.objects.obj(object),Some(Object::Thread {exit_code:Some(value),..})if *value==row[13] as u32),
                "{label}/retained exit status"
            );
            assert_eq!(row[13], row[16]);
            assert_eq!(row[11], 0);
            assert_eq!(row[12], 1);
            assert_eq!(row[14], 0);
            assert_eq!(row[15], if arch == WinArch::X86 { 28 } else { 48 });
            for h in handles {
                p.objects.close(h).unwrap();
            }
            assert!(p.objects.obj(object).is_none());
            index += 1;
            seen += 1;
        }
        assert_eq!(index, 378);
    }
    assert_eq!(seen, 1134);
}

#[test]
fn native_termination_replays_54_self_handle_and_permission_cases() {
    use crate::user::windows::hle::{Ctx, Flow, Value};
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut current) = fixture(arch, "NtTerminateThread", SERVICE);
        let p = process.state_mut();
        let api = crate::user::windows::dll::nt_service("NtTerminateThread", arch).unwrap();
        for line in corpus(arch).lines().filter(|v| v.starts_with("self ")) {
            let row: Vec<_> = line
                .split_whitespace()
                .skip(1)
                .map(|v| u64::from_str_radix(v, 16).unwrap())
                .collect();
            assert_eq!(row.len(), 8);
            let real = if row[0] == 2 {
                Some(u64::from(
                    p.objects
                        .open_access(current.obj, false, row[1] as u32)
                        .unwrap(),
                ))
            } else {
                None
            };
            let handle = match row[0] {
                0 => 0,
                1 => arch.ptr(u64::MAX - 1),
                2 => real.unwrap(),
                3 => arch.ptr(CURRENT_PROCESS),
                4 => 0x1234_5678,
                _ => unreachable!(),
            };
            let sp = current.cpu.sp();
            match arch {
                WinArch::X86 => {
                    p.space.w32(sp + 4, handle as u32).unwrap();
                    p.space.w32(sp + 8, 0x1122_3344).unwrap();
                }
                WinArch::X64 => {
                    current.cpu.set_gpr(1, handle);
                    current.cpu.set_gpr(2, 0x1122_3344);
                }
                WinArch::Arm64 => {
                    current.cpu.set_gpr(0, handle);
                    current.cpu.set_gpr(1, 0x1122_3344);
                }
            }
            let mut c = Ctx {
                p,
                t: &mut current,
                api,
                entry_pc: 0,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp,
            };
            c.set_last_error(0x7654_3210).unwrap();
            let flow = (api.imp)(&mut c).unwrap();
            if row[3] == 0 {
                assert!(
                    matches!(flow,Flow::TerminateThread(code)if u64::from(code)==row[7]),
                    "{arch}/{row:?}"
                );
            } else {
                assert!(
                    matches!(flow,Flow::Ret(Value::Int(status))if status==row[4]),
                    "{arch}/{row:?}"
                );
            }
            assert_eq!(c.last_error().unwrap(), 0x7654_3210);
            if let Some(h) = real {
                c.p.objects.close(h).unwrap();
            }
            assert_eq!(row[2], 1);
            assert_eq!(row[5], 0);
            assert_eq!(row[6], 1);
            seen += 1;
        }
    }
    assert_eq!(seen, 54);
}

#[test]
fn real_handle_termination_drains_ready_suspended_and_native_waiting_threads_all_abis() {
    use crate::error::MemoryAccessKind;
    use crate::user::windows::process::sched::RunStatus;
    use crate::user::windows::sync;
    use std::sync::atomic::AtomicBool;

    for arch in WinArch::ALL {
        for mode in 0..3 {
            let (mut process, mut current) = fixture(arch, "NtTerminateThread", SERVICE);
            let p = process.state_mut();
            let tid = thread::create(p, 0x1234_5000, 0, 0x10000, false).unwrap();
            let mut target = p.threads.remove(&tid).unwrap();
            target.attached = true;
            target.suspend = u32::from(mode == 1);
            let (object, stack, teb) = (target.obj, target.stack_alloc, target.teb);
            let handle = u64::from(p.objects.open_access(object, false, 1).unwrap());
            let pinned = if mode == 2 {
                let event = p.objects.create(Object::Event {
                    manual: false,
                    signaled: 0,
                });
                let event_handle =
                    u64::from(p.objects.open_access(event, false, 0x100000).unwrap());
                assert_eq!(
                    super::super::native_wait_tests::invoke(p, &mut target, event_handle, 0, 0),
                    Outcome::Park
                );
                assert_eq!(target.frames.len(), 1);
                p.objects.close(event_handle).unwrap();
                assert!(p.objects.obj(event).is_some());
                Some(event)
            } else {
                None
            };
            p.threads.insert(tid, target);
            assert_eq!(
                call(p, &mut current, "NtTerminateThread", handle, 0x1122_3344),
                0
            );
            assert_eq!(
                call(p, &mut current, "NtTerminateThread", handle, 0x5566_7788),
                0
            );
            assert!(matches!(
                p.objects.obj(object),
                Some(Object::Thread {
                    exit_code: None,
                    ..
                })
            ));
            let wait = sync::Wait::Objects {
                objs: vec![object],
                all: false,
                deadline: None,
                alertable: false,
            };
            assert_eq!(
                sync::poll(
                    p,
                    current.tid,
                    &wait,
                    crate::host::time::Instant::now(),
                    false
                )
                .unwrap(),
                None
            );
            current.suspend = 1;
            p.threads.insert(current.tid, current);
            assert_eq!(
                process.run_slice(1, &AtomicBool::new(false)),
                RunStatus::Blocked
            );
            let p = process.state_mut();
            assert!(p.failure.is_none());
            assert!(p.exit_code.is_none());
            assert!(!p.threads.contains_key(&tid));
            assert!(matches!(
                p.objects.obj(object),
                Some(Object::Thread {
                    exit_code: Some(0x1122_3344),
                    ..
                })
            ));
            assert_eq!(
                sync::poll(p, 0, &wait, crate::host::time::Instant::now(), false).unwrap(),
                Some(0)
            );
            assert_eq!(p.vm.query(stack).unwrap().state, mem::FREE);
            assert!(p.space.probe(teb, 1, MemoryAccessKind::Read).is_err());
            if let Some(event) = pinned {
                assert!(
                    p.objects.obj(event).is_none(),
                    "native wait pin released exactly once"
                );
            }
            p.objects.close(handle).unwrap();
            assert!(p.objects.obj(object).is_none());
        }
    }
}

#[test]
fn real_handle_termination_rejects_foreign_objects_and_recycled_thread_ids_all_abis() {
    use crate::user::windows::hle::{ApiErr, Ctx};
    for arch in WinArch::ALL {
        for retired in [false, true] {
            let (mut process, mut current) = fixture(arch, "NtTerminateThread", SERVICE);
            let p = process.state_mut();
            let tid = thread::create(p, 0x1234_5000, 0, 0x10000, false).unwrap();
            let owned = p.threads[&tid].obj;
            let foreign = p.objects.create(Object::Thread {
                tid,
                exit_code: retired.then_some(0x37),
            });
            let handle = u64::from(p.objects.open_access(foreign, false, 1).unwrap());
            let api = crate::user::windows::dll::nt_service("NtTerminateThread", arch).unwrap();
            let sp = current.cpu.sp();
            match arch {
                WinArch::X86 => {
                    p.space.w32(sp + 4, handle as u32).unwrap();
                    p.space.w32(sp + 8, 0x1122_3344).unwrap();
                }
                WinArch::X64 => {
                    current.cpu.set_gpr(1, handle);
                    current.cpu.set_gpr(2, 0x1122_3344);
                }
                WinArch::Arm64 => {
                    current.cpu.set_gpr(0, handle);
                    current.cpu.set_gpr(1, 0x1122_3344);
                }
            }
            let mut c = Ctx {
                p,
                t: &mut current,
                api,
                entry_pc: 0,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp,
            };
            assert!(
                matches!((api.imp)(&mut c), Err(ApiErr::Unimplemented(_))),
                "unowned thread cannot be admitted by its numeric TID"
            );
            assert_eq!(c.p.threads[&tid].obj, owned);
            assert_eq!(c.p.threads[&tid].terminate, None);
            assert!(matches!(
                c.p.objects.obj(owned),
                Some(Object::Thread {
                    exit_code: None,
                    ..
                })
            ));
            c.p.objects.close(handle).unwrap();
        }
    }
}

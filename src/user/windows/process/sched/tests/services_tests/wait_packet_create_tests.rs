//! Independently measured packet constructor and handle/wait lifecycle.
use super::*;
use crate::user::windows::{
    dll,
    hle::{Ctx, Flow, Item, Value},
    layout,
};

#[path = "wait_packet_create_replay_tests.rs"]
mod replay_tests;

#[cfg(windows)]
#[path = "wait_packet_create_leaf_tests.rs"]
mod leaf_tests;
const SERVICE: u32 = 0x76;

fn arguments(p: &mut Proc, t: &mut Thread, args: [u64; 3]) {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (index, value) in [0x1234_0004, 0x1234_0000]
                .into_iter()
                .chain(args)
                .enumerate()
            {
                p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (register, value) in [10, 2, 8].into_iter().zip(args) {
                t.cpu.set_gpr(register, value);
            }
        }
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
    }
}
fn call(p: &mut Proc, t: &mut Thread, args: [u64; 3]) -> Outcome {
    let sp = t.cpu.sp();
    arguments(p, t, args);
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    if outcome == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    outcome
}
fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtCreateWaitCompletionPacket", SERVICE);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(
            None,
            4 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.space
        .wr(scratch, &vec![0xA5; (4 * PAGE_SIZE) as usize])
        .unwrap();
    (process, t, scratch)
}

fn attrs(p: &Proc, address: u64, length: u32, flags: u32, root: u64) {
    let bytes = if p.arch.is64() { 48 } else { 24 };
    p.space.wr(address, &vec![0; bytes]).unwrap();
    p.space.w32(address, length).unwrap();
    let offset = if p.arch.is64() { 8 } else { 4 };
    p.space
        .wptr(address + offset, p.arch.ptr_size(), root)
        .unwrap();
    p.space
        .w32(address + offset + 2 * p.arch.ptr_size(), flags)
        .unwrap();
}

#[test]
fn native_wait_packet_create_constructs_and_closes_without_resource_leak_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, out) = setup(arch);
        let p = process.state_mut();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        assert_eq!(call(p, &mut t, [out, 1, 0]), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        let handle = p.space.ptr(out, arch.ptr_size()).unwrap();
        assert_eq!(
            p.objects.get(handle).unwrap().type_name(),
            "WaitCompletionPacket"
        );
        assert_eq!(p.objects.access(handle), Some(1));
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            (before.0 + 1, before.1 + 1)
        );
        assert_eq!(
            p.space
                .bytes(out + arch.ptr_size(), 16 - arch.ptr_size() as usize)
                .unwrap(),
            vec![0xA5; 16 - arch.ptr_size() as usize]
        );
        p.objects.close(handle).unwrap();
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}
#[test]
fn native_wait_packet_create_measured_grants_inheritance_and_repeated_wait_all_abis() {
    let grants = [
        (0, 0),
        (1, 1),
        (2, 0),
        (3, 1),
        (4, 0),
        (8, 0),
        (0xF0000, 0xF0000),
        (0x100000, 0x100000),
        (0x100002, 0x100000),
        (0x1F0001, 0x1F0001),
        (0x1F0003, 0x1F0001),
        (0x2000000, 0xF0001),
        (0x80000000, 0x20001),
        (0x40000000, 0x20001),
        (0x20000000, 0x20001),
        (0x10000000, 0xF0001),
    ];
    for arch in WinArch::ALL {
        let (mut process, mut t, out) = setup(arch);
        let p = process.state_mut();
        let oa = out + PAGE_SIZE;
        for (access, grant) in grants {
            for flags in [0, 2] {
                attrs(p, oa, if arch.is64() { 48 } else { 24 }, flags, 0);
                assert_eq!(call(p, &mut t, [out, access, oa]), Outcome::Continue);
                assert_eq!(t.cpu.gpr(0), 0);
                let h = p.space.ptr(out, arch.ptr_size()).unwrap();
                let id = p.objects.id(h).unwrap();
                assert_eq!(p.objects.access(h), Some(grant as u32));
                assert_eq!(p.objects.flags(h), Some(u32::from(flags != 0)));
                for _ in 0..3 {
                    assert_eq!(
                        crate::user::windows::sync::try_objects(p, t.tid, &[id], false),
                        Ok(Some(0))
                    );
                }
                let duplicate = u64::from(p.objects.duplicate(h, false).unwrap());
                assert_eq!(p.objects.id(duplicate), Some(id));
                assert!(p.objects.close(h).unwrap().is_none());
                assert_eq!(
                    crate::user::windows::sync::try_objects(p, t.tid, &[id], false),
                    Ok(Some(0))
                );
                assert!(p.objects.close(duplicate).unwrap().is_some());
            }
        }
    }
}

fn win32(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u64 {
    let api = dll::find("kernel32.dll")
        .unwrap()
        .exports
        .iter()
        .flat_map(|exports| exports.iter())
        .find_map(|e| match &e.item {
            Item::Func(api) if api.name == name => Some(api),
            _ => None,
        })
        .unwrap();
    let sp = t.cpu.sp();
    for (index, value) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p
                .space
                .w32(sp + 4 + index as u64 * 4, *value as u32)
                .unwrap(),
            WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], *value),
            WinArch::X64 => p.space.w64(sp + 8 + index as u64 * 8, *value).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(index, *value),
        }
    }
    match (api.imp)(&mut Ctx {
        p,
        t,
        api,
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    })
    .unwrap()
    {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("unexpected Win32 wait continuation"),
    }
}

#[test]
fn native_wait_packet_create_public_waits_access_aliases_and_final_close_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, out) = setup(arch);
        let p = process.state_mut();
        t.teb = out + 3 * PAGE_SIZE;
        let last_error = t.teb + layout::offsets(arch).teb_last_error;
        for access in [0, 1, 0x100000, 0x1F0001, 0xF0001, 0x2000000, 0x80000000] {
            let before = (p.objects.handle_count(), p.objects.iter().count());
            assert_eq!(call(p, &mut t, [out, access, 0]), Outcome::Continue);
            let h = p.space.ptr(out, arch.ptr_size()).unwrap();
            let alias = u64::from(p.objects.duplicate(h, false).unwrap());
            let granted = p.objects.access(h).unwrap() & 0x100000 != 0;
            for handle in [h, h, alias] {
                p.space.w32(last_error, 0).unwrap();
                assert_eq!(
                    win32(p, &mut t, "WaitForSingleObject", &[handle, 0]),
                    if granted { 0 } else { u32::MAX as u64 }
                );
                assert_eq!(
                    p.space.u32(last_error).unwrap(),
                    if granted { 0 } else { 5 }
                );
            }
            let array = out + PAGE_SIZE;
            p.space.wptr(array, arch.ptr_size(), h).unwrap();
            p.space
                .wptr(array + arch.ptr_size(), arch.ptr_size(), alias)
                .unwrap();
            for all in [false, true] {
                p.space.w32(last_error, 0).unwrap();
                assert_eq!(
                    win32(
                        p,
                        &mut t,
                        "WaitForMultipleObjects",
                        &[2, array, u64::from(all), 0]
                    ),
                    if granted && !all { 0 } else { u32::MAX as u64 }
                );
                assert_eq!(
                    p.space.u32(last_error).unwrap(),
                    if !granted {
                        5
                    } else if all {
                        87
                    } else {
                        0
                    }
                );
            }
            assert_eq!(win32(p, &mut t, "CloseHandle", &[h]), 1);
            assert_eq!(
                win32(p, &mut t, "WaitForSingleObject", &[alias, 0]),
                if granted { 0 } else { u32::MAX as u64 }
            );
            assert_eq!(win32(p, &mut t, "CloseHandle", &[alias]), 1);
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        }
    }
}

#[test]
fn native_wait_packet_create_public_timer_and_event_wait_parity_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, out) = setup(arch);
        let p = process.state_mut();
        t.teb = out + 3 * PAGE_SIZE;
        for object in [
            Object::Timer {
                manual: false,
                signaled: false,
                due: None,
                period_ms: 0,
            },
            Object::Timer {
                manual: true,
                signaled: false,
                due: None,
                period_ms: 0,
            },
            Object::IrTimer {
                attributes: 0,
                timer_id: None,
                signaled: false,
                schedule: None,
            },
            Object::IrTimer {
                attributes: 8,
                timer_id: None,
                signaled: false,
                schedule: None,
            },
            Object::IrTimer {
                attributes: 0x80000008,
                timer_id: None,
                signaled: false,
                schedule: None,
            },
        ] {
            let id = p.objects.create(object);
            let h = u64::from(p.objects.open_access(id, false, 0x1F0003).unwrap());
            for _ in 0..2 {
                assert_eq!(win32(p, &mut t, "WaitForSingleObject", &[h, 0]), 258);
            }
            assert_eq!(win32(p, &mut t, "CloseHandle", &[h]), 1);
        }
        for manual in [false, true] {
            let id = p.objects.create(Object::Event {
                manual,
                signaled: 1,
            });
            let h = u64::from(p.objects.open(id, false));
            let alias = u64::from(p.objects.duplicate(h, false).unwrap());
            let array = out + PAGE_SIZE;
            p.space.wptr(array, arch.ptr_size(), h).unwrap();
            p.space
                .wptr(array + arch.ptr_size(), arch.ptr_size(), alias)
                .unwrap();
            assert_eq!(
                win32(p, &mut t, "WaitForMultipleObjects", &[2, array, 1, 0]),
                u32::MAX as u64
            );
            assert_eq!(
                win32(p, &mut t, "WaitForMultipleObjects", &[2, array, 0, 0]),
                0
            );
            assert_eq!(
                win32(p, &mut t, "WaitForSingleObject", &[alias, 0]),
                if manual { 0 } else { 258 }
            );
            p.objects.close(h).unwrap();
            p.objects.close(alias).unwrap();
        }
    }
}

#[test]
fn native_wait_packet_create_wait_any_pins_aliases_until_exactly_once_cleanup_all_abis() {
    use crate::user::windows::sync::{self, Wait};
    for arch in WinArch::ALL {
        let (mut process, t, _) = setup(arch);
        let p = process.state_mut();
        let before = p.objects.iter().count();
        let id = p.objects.create(Object::Event {
            manual: false,
            signaled: 0,
        });
        let h = u64::from(p.objects.open(id, false));
        let alias = u64::from(p.objects.duplicate(h, false).unwrap());
        let wait = Wait::Objects {
            objs: vec![id, id],
            all: false,
            deadline: None,
            alertable: false,
        };
        sync::on_block(p, t.tid, &wait).unwrap();
        assert!(sync::on_block(p, t.tid, &wait).is_err());
        p.objects.close(h).unwrap();
        p.objects.close(alias).unwrap();
        assert!(p.objects.obj(id).is_some());
        if let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(id) {
            *signaled = 1;
        } else {
            panic!("pinned event missing");
        }
        assert_eq!(
            sync::poll(p, t.tid, &wait, crate::host::time::Instant::now(), false),
            Ok(Some(0))
        );
        assert!(matches!(
            p.objects.obj(id),
            Some(Object::Event { signaled: 0, .. })
        ));
        sync::on_cancel(p, t.tid, &wait).unwrap();
        sync::on_cancel(p, t.tid, &wait).unwrap();
        assert!(p.objects.obj(id).is_none());
        assert_eq!(p.objects.iter().count(), before);
    }
}
#[test]
fn native_wait_packet_create_preserves_explicit_namespace_security_privilege_boundaries_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..4 {
            let (mut process, mut t, out) = setup(arch);
            let p = process.state_mut();
            let oa = out + PAGE_SIZE;
            attrs(p, oa, if arch.is64() { 48 } else { 24 }, 0, 0);
            if role < 3 {
                let offset = match role {
                    0 => 2 * arch.ptr_size(),
                    1 => {
                        if arch.is64() {
                            32
                        } else {
                            16
                        }
                    }
                    _ => {
                        if arch.is64() {
                            40
                        } else {
                            20
                        }
                    }
                };
                p.space
                    .wptr(oa + offset, arch.ptr_size(), out + 2 * PAGE_SIZE)
                    .unwrap();
            }
            let before = (p.objects.handle_count(), p.objects.iter().count());
            assert!(
                matches!(call(p,&mut t,[out,if role==3{0x1000000}else{0x1F0001},oa]),Outcome::Fail(ref reason) if reason.contains("wait completion packet"))
            );
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
            assert_eq!(p.space.bytes(out, 16).unwrap(), [0xA5; 16]);
        }
    }
}

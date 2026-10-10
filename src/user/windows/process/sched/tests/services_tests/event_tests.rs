//! Native NT events share the Win32 object and scheduler contract.
use super::*;

fn arguments(p: &mut Proc, t: &mut Thread, args: &[u64]) {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (index, value) in args.iter().enumerate() {
                p.space
                    .w32(sp + 8 + index as u64 * 4, *value as u32)
                    .unwrap();
            }
            t.cpu.set_gpr(0, 0x48);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x48);
            t.cpu.set_gpr(1, 0x1234_0004);
            for (index, value) in args.iter().enumerate() {
                if index < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][index], *value);
                } else {
                    p.space.w64(sp + 8 + index as u64 * 8, *value).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (index, value) in args.iter().enumerate() {
                t.cpu.set_gpr(index, *value);
            }
        }
    }
}
fn dispatch(p: &mut Proc, t: &mut Thread) -> Outcome {
    if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x48))
    }
}

#[test]
fn native_event_creates_real_objects_and_closes_without_leaking_all_abis() {
    for arch in WinArch::ALL {
        for (kind, initial) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
            let (mut process, mut t) = fixture(arch, "NtCreateEvent", 0x48);
            let p = process.state_mut();
            let out =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.wr(out, &[0xA5; 16]).unwrap();
            let before = p.objects.handle_count();
            let objects = p.objects.iter().count();
            arguments(p, &mut t, &[out, 0x001F_0003, 0, kind, initial]);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            let handle = if arch.is64() {
                p.space.u64(out).unwrap()
            } else {
                u64::from(p.space.u32(out).unwrap())
            };
            assert!(matches!(p.objects.get(handle), Some(Object::Event { .. })));
            assert_eq!(p.objects.access(handle), Some(0x001F_0003));
            assert_eq!(p.objects.flags(handle), Some(0));
            assert_eq!(p.objects.handle_count(), before + 1);
            assert_eq!(
                p.space
                    .bytes(out + arch.ptr_size(), 16 - arch.ptr_size() as usize)
                    .unwrap(),
                vec![0xA5; 16 - arch.ptr_size() as usize]
            );
            assert!(p.objects.close(handle).is_ok());
            assert_eq!(p.objects.handle_count(), before);
            assert_eq!(p.objects.iter().count(), objects);
            assert!(t.frames.is_empty());
        }
    }
}

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtCreateEvent", 0x48);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(
            None,
            PAGE_SIZE * 4,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.space
        .wr(scratch, &vec![0xA5; PAGE_SIZE as usize * 4])
        .unwrap();
    (process, t, scratch)
}
fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> Outcome {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, 0x48)));
    let sp = t.cpu.sp();
    arguments(p, t, args);
    let result = dispatch(p, t);
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}
fn status(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    assert_eq!(call(p, t, name, args), Outcome::Continue);
    t.cpu.gpr(0) as u32
}
fn handle(p: &Proc, address: u64) -> u64 {
    p.space.ptr(address, p.arch.ptr_size()).unwrap()
}
fn attrs(p: &mut Proc, address: u64, length: u32, flags: u32, root: u64) {
    let width = p.arch.ptr_size();
    let size = if p.arch.is64() { 48 } else { 24 };
    p.space.wr(address, &vec![0; size]).unwrap();
    p.space.w32(address, length).unwrap();
    p.space.wptr(address + width, width, root).unwrap();
    p.space.w32(address + width * 3, flags).unwrap();
}

#[test]
fn native_event_retains_boolean_byte_and_reuses_manual_auto_wait_semantics_all_abis() {
    use crate::user::windows::sync;
    for arch in WinArch::ALL {
        for kind in [0, 1] {
            for initial in [0, 1, 2, 255, 256, 257, u64::MAX] {
                let (mut process, mut t, out) = setup(arch);
                let p = process.state_mut();
                assert_eq!(
                    status(
                        p,
                        &mut t,
                        "NtCreateEvent",
                        &[out, 0x001F_0003, 0, kind, initial]
                    ),
                    0
                );
                let h = handle(p, out);
                let id = p.objects.id(h).unwrap();
                assert!(
                    matches!(p.objects.obj(id), Some(Object::Event { manual, signaled }) if *manual == (kind == 0) && *signaled == i32::from(initial as u8))
                );
                let expected = (initial as u8 != 0).then_some(0);
                assert_eq!(sync::try_objects(p, t.tid, &[id], false).unwrap(), expected);
                assert_eq!(
                    sync::try_objects(p, t.tid, &[id], false).unwrap(),
                    if kind == 0 { expected } else { None }
                );
                assert_eq!(status(p, &mut t, "NtSetEvent", &[h, out + 17]), 0);
                assert_eq!(
                    p.space.u32(out + 17).unwrap(),
                    if kind == 0 {
                        u32::from(initial as u8)
                    } else {
                        0
                    }
                );
                assert_eq!(status(p, &mut t, "NtResetEvent", &[h, out + 17]), 0);
                assert_eq!(p.space.u32(out + 17).unwrap(), 1);
                assert_eq!(sync::try_objects(p, t.tid, &[id], false).unwrap(), None);
                p.objects.close(h).unwrap();
            }
        }
    }
}

#[test]
fn native_event_maps_created_handle_access_and_inherit_all_abis() {
    for arch in WinArch::ALL {
        for (access, grant) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 0),
            (0x100000, 0x100000),
            (0xF0000, 0xF0000),
            (0x1F0003, 0x1F0003),
            (0x1F0007, 0x1F0003),
            (0x80000000, 0x20001),
            (0x40000000, 0x20002),
            (0x20000000, 0x120000),
            (0x10000000, 0x1F0003),
            (0x02000000, 0x1F0003),
        ] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let oa = scratch + PAGE_SIZE;
            attrs(p, oa, if arch.is64() { 48 } else { 24 }, 2, 0);
            assert_eq!(
                status(p, &mut t, "NtCreateEvent", &[scratch + 1, access, oa, 0, 0]),
                0
            );
            let h = handle(p, scratch + 1);
            assert_eq!(p.objects.access(h), Some(grant));
            assert_eq!(p.objects.flags(h), Some(1));
            assert_eq!(
                status(p, &mut t, "NtSetEvent", &[h | 3, scratch + 32]),
                if grant & 2 != 0 {
                    0
                } else {
                    crate::user::windows::nt::status::STATUS_ACCESS_DENIED
                }
            );
            p.objects.close(h).unwrap();
        }
        for flags in [0, 2, 0x10, 0x20, 0x40, 0x80, 0x200, 0x400, 0x800, 0x1000] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let oa = scratch + PAGE_SIZE;
            attrs(p, oa, if arch.is64() { 48 } else { 24 }, flags, 0);
            // Output aliases attributes: flags must be captured before HANDLE publication.
            assert_eq!(
                status(p, &mut t, "NtCreateEvent", &[oa, 0x1F0003, oa, 0, 0]),
                0
            );
            let h = handle(p, oa);
            assert_eq!(p.objects.flags(h), Some(u32::from(flags & 2 != 0)));
            p.objects.close(h).unwrap();
        }
    }
}

#[test]
fn native_event_output_and_attribute_fault_order_preserves_objects_all_abis() {
    use crate::user::windows::nt::status::*;
    for arch in WinArch::ALL {
        for role in 0..16 {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let oa = scratch + PAGE_SIZE;
            attrs(p, oa, if arch.is64() { 48 } else { 24 }, 0, 0);
            let (mut out, mut attributes, mut kind) = (scratch, 0, 0);
            let mut expected = STATUS_SUCCESS;
            match role {
                0 => {
                    out = 0;
                    kind = 99;
                    expected = STATUS_ACCESS_VIOLATION;
                }
                1 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READONLY).unwrap();
                    kind = 99;
                    expected = STATUS_ACCESS_VIOLATION;
                }
                2 => {
                    p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    kind = 99;
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                }
                3 => {
                    attributes = 1;
                    expected = if arch.is64() {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                }
                4 => {
                    attributes = 1;
                    kind = 99;
                    expected = if arch.is64() {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                }
                5 => {
                    attributes = oa;
                    p.space.w32(oa, 0).unwrap();
                    expected = STATUS_INVALID_PARAMETER;
                }
                6 => {
                    attributes = oa;
                    p.space.w32(oa, 0).unwrap();
                    p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = if arch.is64() {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        STATUS_INVALID_PARAMETER
                    };
                }
                7 => {
                    attributes = oa;
                    p.vm.protect(oa, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    kind = 99;
                    expected = if arch.is64() {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_GUARD_PAGE_VIOLATION
                    };
                }
                8 => {
                    attributes = oa;
                    attrs(p, oa, if arch.is64() { 48 } else { 24 }, 1, 0);
                    expected = STATUS_INVALID_PARAMETER;
                }
                9 => {
                    attributes = oa;
                    attrs(p, oa, if arch.is64() { 48 } else { 24 }, 0, 0x1234);
                    expected = STATUS_OBJECT_NAME_INVALID;
                }
                10 => {
                    kind = 99;
                    expected = STATUS_INVALID_PARAMETER;
                }
                11 => {
                    out = scratch + PAGE_SIZE - 4;
                    p.vm.protect(oa, PAGE_SIZE, prot::NOACCESS).unwrap();
                    expected = if arch.is64() {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        0
                    };
                }
                12 => {
                    attributes = oa + 1;
                    attrs(p, oa + 1, if arch.is64() { 48 } else { 24 }, 0, 0);
                    expected = if arch.is64() {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else {
                        0
                    };
                }
                13 => {
                    attributes = oa;
                    p.vm.protect(oa, PAGE_SIZE, prot::READONLY).unwrap();
                }
                14 => {
                    out = scratch + 1;
                    kind = u32::MAX;
                    expected = STATUS_INVALID_PARAMETER;
                }
                15 => {
                    attributes = oa;
                    attrs(p, oa, if arch.is64() { 52 } else { 28 }, 0, 0);
                    expected = STATUS_INVALID_PARAMETER;
                }
                _ => unreachable!(),
            }
            let before = p.objects.handle_count();
            let objects = p.objects.iter().count();
            assert_eq!(
                status(
                    p,
                    &mut t,
                    "NtCreateEvent",
                    &[out, 0x1F0003, attributes, u64::from(kind), 0]
                ),
                expected,
                "{arch}/role{role}"
            );
            if role == 6 {
                assert_eq!(
                    (p.vm.query(scratch).unwrap().protect & prot::GUARD != 0),
                    arch == WinArch::X86
                );
            }
            if role == 7 {
                assert_eq!(
                    (p.vm.query(oa).unwrap().protect & prot::GUARD != 0),
                    arch.is64()
                );
            }
            if expected == 0 {
                let h = handle(p, out);
                assert_eq!(p.objects.handle_count(), before + 1);
                p.objects.close(h).unwrap();
            }
            assert_eq!(p.objects.handle_count(), before);
            assert_eq!(p.objects.iter().count(), objects);
            if matches!(role, 8 | 9 | 10 | 14) {
                assert_eq!(
                    handle(p, out),
                    if arch == WinArch::X86 {
                        0
                    } else {
                        0xA5A5_A5A5_A5A5_A5A5
                    }
                );
            }
        }
    }
}

#[test]
fn native_event_state_probes_before_type_and_access_without_mutation_all_abis() {
    use crate::user::windows::nt::status::*;
    for arch in WinArch::ALL {
        for name in ["NtSetEvent", "NtResetEvent"] {
            for role in 0..11 {
                let (mut process, mut t, scratch) = setup(arch);
                let p = process.state_mut();
                let id = p.objects.create(Object::Event {
                    manual: true,
                    signaled: 255,
                });
                let h = u64::from(
                    p.objects
                        .open_access(id, false, if role == 8 { 0 } else { 0x1F0003 })
                        .unwrap(),
                );
                let (mut target, mut previous) = (h, scratch);
                let mut expected = 0;
                match role {
                    0 => previous = 0,
                    1 => previous = scratch + 1,
                    2 => {
                        previous = 1;
                        expected = STATUS_ACCESS_VIOLATION;
                    }
                    3 => {
                        p.vm.protect(scratch, PAGE_SIZE, prot::READONLY).unwrap();
                        expected = STATUS_ACCESS_VIOLATION;
                    }
                    4 => {
                        p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                        expected = STATUS_GUARD_PAGE_VIOLATION;
                    }
                    5 => {
                        target = 0;
                        expected = STATUS_INVALID_HANDLE;
                    }
                    6 => {
                        target = arch.ptr(u64::MAX);
                        expected = STATUS_OBJECT_TYPE_MISMATCH;
                    }
                    7 => {
                        target = 0;
                        previous = 1;
                        expected = STATUS_ACCESS_VIOLATION;
                    }
                    8 => expected = STATUS_ACCESS_DENIED,
                    9 => {
                        let other = p.objects.create(Object::Mutex {
                            owner: None,
                            count: 0,
                            abandoned: false,
                        });
                        target = u64::from(p.objects.open_access(other, false, 0).unwrap());
                        expected = STATUS_OBJECT_TYPE_MISMATCH;
                    }
                    10 => {
                        target = arch.ptr(u64::MAX - 1);
                        p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                        expected = STATUS_GUARD_PAGE_VIOLATION;
                    }
                    _ => unreachable!(),
                }
                assert_eq!(
                    status(p, &mut t, name, &[target, previous]),
                    expected,
                    "{arch}/{name}/role{role}"
                );
                let after = if expected == 0 {
                    i32::from(name == "NtSetEvent")
                } else {
                    255
                };
                assert!(
                    matches!(p.objects.obj(id),Some(Object::Event{signaled,..}) if *signaled==after)
                );
                if expected == 0 && previous != 0 {
                    assert_eq!(p.space.u32(previous).unwrap(), 255);
                }
                if matches!(role, 4 | 10) {
                    assert!(!(p.vm.query(scratch).unwrap().protect & prot::GUARD != 0));
                }
            }
        }
    }
}

#[test]
fn native_event_rejects_unimplemented_security_and_names_without_publication_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..4 {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let oa = scratch + PAGE_SIZE;
            attrs(p, oa, if arch.is64() { 48 } else { 24 }, 0, 0);
            let access = if role == 3 { 0x01000000 } else { 0x1F0003 };
            if role < 3 {
                let offset = match role {
                    0 => arch.ptr_size() * 2,
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
                    .wptr(oa + offset, arch.ptr_size(), scratch + PAGE_SIZE * 2)
                    .unwrap();
            }
            let before = p.objects.handle_count();
            let objects = p.objects.iter().count();
            assert!(
                matches!(call(p,&mut t,"NtCreateEvent",&[scratch,access,oa,0,0]),Outcome::Fail(reason) if reason.contains("event"))
            );
            assert_eq!(p.objects.handle_count(), before);
            assert_eq!(p.objects.iter().count(), objects);
            assert_eq!(p.space.bytes(scratch, 16).unwrap(), [0xA5; 16]);
        }
    }
}

#[test]
#[cfg(windows)]
fn installed_ntdll_event_leaves_create_modify_and_close_shared_objects() {
    use crate::user::windows::loader::{self, SymRef};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    let host_arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let architectures = if host_arch == WinArch::X86 {
        vec![host_arch]
    } else {
        vec![host_arch, WinArch::X86]
    };
    for arch in architectures {
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
            WindowsConfig::embedded("C:\\native-events.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let sp = t.cpu.sp();
        let out = sp - 128;
        let previous = out + 17;
        let resume = p.traps.callback_return();
        let before = p.objects.handle_count();
        let mut h = 0;
        for (name, args) in [
            ("NtCreateEvent", vec![out, 0x1F0003, 0, 1, 255]),
            ("NtSetEvent", vec![0, previous]),
            ("NtResetEvent", vec![0, previous]),
            ("NtClose", vec![0]),
        ] {
            let mut args = args;
            if name != "NtCreateEvent" {
                args[0] = h;
            }
            let entry = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                .unwrap()
                .unwrap();
            t.cpu.set_sp(sp);
            t.cpu.set_pc(entry);
            for (index, value) in args.iter().enumerate() {
                match arch {
                    WinArch::X86 => p
                        .space
                        .w32(sp + 4 + index as u64 * 4, *value as u32)
                        .unwrap(),
                    WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], *value),
                    WinArch::X64 => p.space.w64(sp + 8 + index as u64 * 8, *value).unwrap(),
                    WinArch::Arm64 => t.cpu.set_gpr(index, *value),
                }
            }
            match arch {
                WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
                WinArch::X64 => p.space.w64(sp, resume).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            let mut returned = false;
            for _ in 0..32 {
                let boundary = t.cpu.run(64);
                if t.cpu.pc() == resume {
                    returned = true;
                    break;
                }
                let description = format!("{arch}/{name} PC={:#x} {boundary:?}", t.cpu.pc());
                assert!(
                    matches!(
                        handle_stop(p, &mut t, boundary),
                        Outcome::Continue | Outcome::Yield
                    ),
                    "{description}"
                );
            }
            assert!(
                returned,
                "{arch}/{name} did not return in 2048 instructions"
            );
            assert_eq!(t.cpu.gpr(0), 0);
            assert!(t.frames.is_empty());
            assert_eq!(
                t.cpu.sp(),
                sp + match arch {
                    WinArch::X86 => 4 + args.len() as u64 * 4,
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
            match name {
                "NtCreateEvent" => {
                    h = handle(p, out);
                    assert_eq!(p.objects.handle_count(), before + 1);
                    assert!(matches!(
                        p.objects.get(h),
                        Some(Object::Event {
                            manual: false,
                            signaled: 255
                        })
                    ));
                }
                "NtSetEvent" => assert_eq!(p.space.u32(previous).unwrap(), 255),
                "NtResetEvent" => assert_eq!(p.space.u32(previous).unwrap(), 1),
                _ => {
                    assert_eq!(p.objects.handle_count(), before);
                    assert!(p.objects.get(h).is_none());
                }
            }
        }
    }
}

#[test]
fn native_event_interoperates_with_win32_waits_state_and_close_all_abis() {
    use crate::user::windows::{
        dll,
        hle::{Ctx, Flow, Item, Value},
        layout,
        nt::error::WAIT_TIMEOUT,
    };
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
            _ => panic!("unexpected Win32 event continuation"),
        }
    }
    for arch in WinArch::ALL {
        for kind in [0, 1] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            t.teb = scratch + PAGE_SIZE * 3;
            let last_error = t.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(last_error, 0xBAD0_CAFE).unwrap();
            let before = p.objects.handle_count();
            assert_eq!(
                status(
                    p,
                    &mut t,
                    "NtCreateEvent",
                    &[scratch, 0x1F0003, 0, kind, 255]
                ),
                0
            );
            let h = handle(p, scratch);
            assert_eq!(win32(p, &mut t, "WaitForSingleObject", &[h, 0]), 0);
            assert_eq!(
                win32(p, &mut t, "WaitForSingleObject", &[h, 0]),
                if kind == 0 {
                    0
                } else {
                    u64::from(WAIT_TIMEOUT)
                }
            );
            assert_eq!(win32(p, &mut t, "ResetEvent", &[h]), 1);
            assert_eq!(status(p, &mut t, "NtSetEvent", &[h, scratch + 17]), 0);
            assert_eq!(p.space.u32(scratch + 17).unwrap(), 0);
            assert_eq!(win32(p, &mut t, "SetEvent", &[h]), 1);
            assert_eq!(status(p, &mut t, "NtResetEvent", &[h, scratch + 17]), 0);
            assert_eq!(p.space.u32(scratch + 17).unwrap(), 1);
            assert_eq!(
                p.space.u32(last_error).unwrap(),
                0xBAD0_CAFE,
                "NT calls/successful Win32 calls leave LastError untouched"
            );
            assert_eq!(win32(p, &mut t, "CloseHandle", &[h]), 1);
            assert_eq!(p.objects.handle_count(), before);
            assert!(p.objects.get(h).is_none());
        }
    }
}

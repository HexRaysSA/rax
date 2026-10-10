//! Native NT registry status and snapshot-backed read behavior.
use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::registry::{NLS_KEY, Registry, Value};

#[test]
fn native_registry_selected_namespace_query_and_handle_lifetime_all_abis() {
    use crate::user::windows::registry::{SESSION_MANAGER_KEY, SelectedKey};
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let upcase = (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect();
        let entries = [
            (
                NLS_KEY,
                "ACP",
                1,
                "1252\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            ),
            (
                SESSION_MANAGER_KEY,
                "CriticalSectionTimeout",
                4,
                2_592_000u32.to_le_bytes().to_vec(),
            ),
        ];
        p.registry = Registry::selected(
            upcase,
            entries
                .iter()
                .map(|(path, name, kind, data)| SelectedKey {
                    path,
                    children: 3,
                    values: vec![Value {
                        name: name.encode_utf16().collect(),
                        kind: *kind,
                        data: data.clone(),
                    }],
                })
                .collect(),
        )
        .unwrap();
        let attrs = base + PAGE_SIZE * 2;
        let mut handles = Vec::new();
        for (path, name, kind, data) in entries {
            for view in [0, 0x100, 0x200] {
                unicode(p, attrs + 64, attrs + 128, &path.to_lowercase());
                attributes(p, attrs, attrs + 64, 0, 0x240);
                assert_eq!(
                    call(p, &mut t, "NtOpenKey", &[base, 1 | view, attrs]),
                    STATUS_SUCCESS
                );
                let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
                handles.push((handle, name, kind, data.clone()));
            }
        }
        // A key object owns immutable data after the selection namespace drops.
        p.registry = Registry::default();
        for (handle, name, kind, data) in handles {
            unicode(p, attrs + 64, attrs + 128, &name.to_lowercase());
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtQueryValueKey",
                    &[handle, attrs + 64, 2, base + 128, 64, base + PAGE_SIZE]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(base + 132).unwrap(), kind);
            assert_eq!(p.space.u32(base + 136).unwrap(), data.len() as u32);
            assert_eq!(p.space.bytes(base + 140, data.len()).unwrap(), data);
            assert_eq!(
                p.space.u32(base + PAGE_SIZE).unwrap(),
                12 + data.len() as u32
            );
            assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtQueryValueKey",
                    &[handle, attrs + 64, 2, base + 128, 64, base + PAGE_SIZE]
                ),
                STATUS_INVALID_HANDLE
            );
        }
    }
}

#[cfg(windows)]
#[path = "registry_leaf_tests.rs"]
mod installed;

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
            t.cpu.set_gpr(0, 0x12);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x12);
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
        handle_stop(p, t, stop(p.arch, 0x12))
    }
}

#[test]
fn native_registry_open_null_output_returns_nt_status_all_abis() {
    use crate::user::windows::nt::status::STATUS_ACCESS_VIOLATION;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtOpenKey", 0x12);
        let p = process.state_mut();
        arguments(p, &mut t, &[0, 0x80000000, 0]);
        assert_eq!(dispatch(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
        assert!(t.frames.is_empty());
    }
}
#[test]
fn native_registry_invalid_key_precedes_unreadable_value_name_all_abis() {
    use crate::user::windows::nt::status::STATUS_INVALID_HANDLE;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQueryValueKey", 0x12);
        let p = process.state_mut();
        arguments(p, &mut t, &[0, 0, 2, 0, 64, 0]);
        assert_eq!(dispatch(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_HANDLE));
        assert!(t.frames.is_empty());
    }
}

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtOpenKey", 0x12);
    let p = process.state_mut();
    let base =
        p.vm.allocate(
            None,
            PAGE_SIZE * 4,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.space
        .wr(base, &vec![0xA5; PAGE_SIZE as usize * 4])
        .unwrap();
    // Controlled oracle-profile fixture, not a default or installed locale.
    let upcase = (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect();
    p.registry = Registry::nls(
        upcase,
        vec![Value {
            name: "ACP".encode_utf16().collect(),
            kind: 1,
            data: "1252\0".encode_utf16().flat_map(u16::to_le_bytes).collect(),
        }],
        0,
    )
    .unwrap();
    (process, t, base)
}
fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, 0x12)));
    let sp = t.cpu.sp();
    arguments(p, t, args);
    assert_eq!(dispatch(p, t), Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}
fn unicode(p: &Proc, address: u64, buffer: u64, text: &str) {
    let units: Vec<_> = text.encode_utf16().collect();
    p.space.w16(address, (units.len() * 2) as u16).unwrap();
    p.space.w16(address + 2, 0).unwrap(); // MaximumLength is ignored.
    p.space
        .wptr(
            address + if p.arch.is64() { 8 } else { 4 },
            p.arch.ptr_size(),
            buffer,
        )
        .unwrap();
    p.space.put_wunits(buffer, &units).unwrap();
}
fn attributes(p: &Proc, address: u64, name: u64, root: u64, flags: u32) {
    let width = p.arch.ptr_size();
    let size = if p.arch.is64() { 48 } else { 24 };
    p.space.wr(address, &vec![0; size]).unwrap();
    p.space.w32(address, size as u32).unwrap();
    p.space.wptr(address + width, width, root).unwrap();
    p.space.wptr(address + width * 2, width, name).unwrap();
    p.space.w32(address + width * 3, flags).unwrap();
}
fn opened(p: &mut Proc, t: &mut Thread, base: u64, access: u32) -> u64 {
    let attrs = base + PAGE_SIZE * 2;
    unicode(p, attrs + 64, attrs + 128, NLS_KEY);
    attributes(p, attrs, attrs + 64, 0, 0x242);
    assert_eq!(
        call(p, t, "NtOpenKey", &[base, access as u64, attrs]),
        STATUS_SUCCESS
    );
    p.space.ptr(base, p.arch.ptr_size()).unwrap()
}

#[test]
fn native_registry_read_grants_typed_handles_close_and_nonwaitable_lifetime_all_abis() {
    for arch in WinArch::ALL {
        for (access, grant) in [
            (1, 1),
            (8, 8),
            (0x20019, 0x20019),
            (0x80000000, 0x20019),
            (0x20000000, 0x20019),
            (0x02000000, 0x20019),
            (0x20119, 0x20019),
            (0x20219, 0x20019),
        ] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let before = (p.objects.handle_count(), p.objects.iter().count());
            let handle = opened(p, &mut t, base, access);
            assert!(matches!(p.objects.get(handle | 3), Some(Object::Key(_))));
            assert_eq!(p.objects.access(handle), Some(grant));
            assert_eq!(p.objects.flags(handle), Some(1));
            let id = p.objects.id(handle).unwrap();
            assert_eq!(
                crate::user::windows::sync::try_objects(p, t.tid, &[id], false).unwrap(),
                None
            );
            assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
            assert_eq!(
                call(p, &mut t, "NtQueryValueKey", &[handle, 0, 2, 0, 64, 0]),
                STATUS_INVALID_HANDLE
            );
        }
    }
}
#[test]
fn native_registry_value_layout_lengths_case_and_defined_prefix_all_abis() {
    // Independent build29683 ACP value layouts, including 8-byte data offset
    // in ordinary FullInformation on every ABI. Raw REG_SZ includes its NUL.
    let data: Vec<_> = "1252\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let h = opened(p, &mut t, base, 0x20019);
        let vn = base + PAGE_SIZE * 2 + 64;
        unicode(p, vn, vn + 64, "aCp");
        for class in 0..=4u32 {
            let words: &[u32] = match class {
                0 => &[0, 1, 6],
                1 | 3 => &[0, 1, 32, 10, 6],
                2 => &[0, 1, 10],
                4 => &[1, 10],
                _ => unreachable!(),
            };
            let mut expected: Vec<_> = words.iter().flat_map(|u| u.to_le_bytes()).collect();
            if matches!(class, 0 | 1 | 3) {
                expected.extend([65, 0, 67, 0, 80, 0]);
            }
            if matches!(class, 1 | 3) {
                expected.extend([0; 6]);
            }
            if class != 0 {
                expected.extend(&data);
            }
            let header = match class {
                0 | 2 => 12,
                1 | 3 => 20,
                4 => 8,
                _ => unreachable!(),
            };
            for length in [
                0, 1, 4, 7, 8, 11, 12, 13, 16, 19, 20, 21, 22, 23, 24, 32, 64, 128,
            ] {
                p.space.wr(base, &[0xA5; 128]).unwrap();
                p.space.w32(base + PAGE_SIZE, 0xA5A5A5A5).unwrap();
                let result = call(
                    p,
                    &mut t,
                    "NtQueryValueKey",
                    &[h | 3, vn, class as u64, base, length, base + PAGE_SIZE],
                );
                let written = if length < header {
                    0
                } else {
                    expected.len().min(length as usize)
                };
                assert_eq!(
                    result,
                    if length < header {
                        STATUS_BUFFER_TOO_SMALL
                    } else if written < expected.len() {
                        STATUS_BUFFER_OVERFLOW
                    } else {
                        STATUS_SUCCESS
                    },
                    "{arch}/{class}/{length}"
                );
                assert_eq!(
                    p.space.u32(base + PAGE_SIZE).unwrap(),
                    expected.len() as u32
                );
                let mut prefix = expected[..written].to_vec();
                if matches!(class, 0 | 1 | 3)
                    && written > header as usize
                    && written < header as usize + 6
                    && written % 2 != 0
                {
                    prefix[written - 1] = 0;
                }
                assert_eq!(p.space.bytes(base, written).unwrap(), prefix);
                assert_eq!(
                    p.space.bytes(base + written as u64, 128 - written).unwrap(),
                    vec![0xA5; 128 - written]
                );
            }
        }
        unicode(p, vn, vn + 64, "missing-rax-value");
        p.space.w32(base + PAGE_SIZE, 0xA5A5A5A5).unwrap();
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[h, vn, 2, base, 64, base + PAGE_SIZE]
            ),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(p.space.u32(base + PAGE_SIZE).unwrap(), 0xA5A5A5A5);
        p.objects.close(h).unwrap();
    }
}

#[test]
fn native_registry_query_fault_order_guards_alias_and_cross_page_prefix_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..28 {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let h = opened(p, &mut t, base, 0x20019);
            p.space
                .wr(base, &vec![0xA5; PAGE_SIZE as usize * 2])
                .unwrap();
            let vn = base + PAGE_SIZE * 2 + 64;
            unicode(p, vn, vn + 64, "ACP");
            let mut args = [h, vn, 2, base, 64, base + PAGE_SIZE];
            let expected = match role {
                0 => {
                    args[5] = 0;
                    STATUS_ACCESS_VIOLATION
                }
                1 => {
                    args[5] = 1;
                    STATUS_ACCESS_VIOLATION
                }
                2 => {
                    args[5] += 1;
                    STATUS_SUCCESS
                }
                3 => {
                    args[3] = 0;
                    STATUS_ACCESS_VIOLATION
                }
                4 => {
                    args[3] += 1;
                    if arch == WinArch::X86 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_DATATYPE_MISALIGNMENT
                    }
                }
                5 => {
                    p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                6 => {
                    p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                7 => {
                    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                8 => {
                    args[0] = 0;
                    args[1] = 0;
                    STATUS_INVALID_HANDLE
                }
                9 => {
                    args[0] = 0;
                    STATUS_INVALID_HANDLE
                }
                10 => {
                    args[1] = 0;
                    STATUS_ACCESS_VIOLATION
                }
                11 => {
                    args[2] = 5;
                    args[5] = 0;
                    STATUS_INVALID_PARAMETER
                }
                12 => {
                    args[3] = 0;
                    args[4] = 0;
                    STATUS_BUFFER_TOO_SMALL
                }
                13 => {
                    args[3] = base + PAGE_SIZE - 16;
                    args[5] = base + PAGE_SIZE * 2 + 512;
                    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                14 => {
                    args[5] = base;
                    STATUS_SUCCESS
                }
                15 => {
                    args[0] = arch.ptr(u64::MAX);
                    STATUS_OBJECT_TYPE_MISMATCH
                }
                16 => {
                    args[3] = base + PAGE_SIZE - 24;
                    args[5] = base + PAGE_SIZE * 2 + 512;
                    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                    STATUS_SUCCESS
                }
                17 => {
                    p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
                    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                18 => {
                    p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                19 | 20 => {
                    args[0] = 0;
                    if role == 20 {
                        args[3] += 1;
                    }
                    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_INVALID_HANDLE
                }
                21 => {
                    args[2] = 5;
                    p.vm.protect(base, PAGE_SIZE * 2, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_INVALID_PARAMETER
                }
                22 => {
                    args[3] += 1;
                    args[4] = 0;
                    STATUS_BUFFER_TOO_SMALL
                }
                23 => {
                    args[0] = 0;
                    p.vm.protect(
                        base + PAGE_SIZE * 2,
                        PAGE_SIZE,
                        prot::READWRITE | prot::GUARD,
                    )
                    .unwrap();
                    if arch == WinArch::X86 {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        STATUS_INVALID_HANDLE
                    }
                }
                24 => {
                    args[0] = 0;
                    args[2] = 5;
                    STATUS_INVALID_PARAMETER
                }
                25 => {
                    args[1] = 0;
                    args[2] = 5;
                    STATUS_INVALID_PARAMETER
                }
                26 => {
                    args[3] += 1;
                    args[5] = 0;
                    if arch == WinArch::X86 {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_DATATYPE_MISALIGNMENT
                    }
                }
                27 => {
                    args[4] = 12;
                    p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                _ => unreachable!(),
            };
            assert_eq!(
                call(p, &mut t, "NtQueryValueKey", &args),
                expected,
                "{arch}/role{role}"
            );
            if matches!(role, 6 | 7 | 17 | 27) {
                let consumed = if matches!(role, 7 | 17) {
                    base + PAGE_SIZE
                } else {
                    base
                };
                assert_eq!(p.vm.query(consumed).unwrap().protect, prot::READWRITE);
            }
            if matches!(role, 18 | 21) {
                assert_ne!(p.vm.query(base).unwrap().protect & prot::GUARD, 0);
            }
            if matches!(role, 19 | 20 | 21) {
                assert_ne!(
                    p.vm.query(base + PAGE_SIZE).unwrap().protect & prot::GUARD,
                    0
                );
            }
            if role == 23 {
                assert_eq!(
                    p.vm.query(vn).unwrap().protect & prot::GUARD != 0,
                    arch != WinArch::X86
                );
            }
            p.vm.protect(base, PAGE_SIZE * 4, prot::READWRITE).unwrap();
            if matches!(role, 2 | 3 | 5 | 6 | 12 | 13 | 16 | 22 | 27)
                || role == 4 && arch == WinArch::X86
            {
                assert_eq!(p.space.u32(args[5]).unwrap(), 22, "{arch}/role{role}");
            }
            if role == 14 {
                assert_eq!(p.space.u32(base).unwrap(), 0);
            }
            if role == 13 {
                assert_eq!(
                    p.space.bytes(args[3], 16).unwrap(),
                    [0, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 49, 0, 50, 0]
                );
            }
            if role == 16 {
                assert_eq!(
                    p.space.bytes(args[3], 22).unwrap(),
                    [
                        0, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 49, 0, 50, 0, 53, 0, 50, 0, 0, 0
                    ]
                );
            }
            p.objects.close(h).unwrap();
        }
    }
}

#[test]
fn native_registry_open_capture_order_output_zeroing_and_read_only_policy_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..19 {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let attrs = base + PAGE_SIZE * 2;
            let vn = attrs + 64;
            unicode(p, vn, vn + 64, NLS_KEY);
            attributes(p, attrs, vn, 0, 0x240);
            let mut args = [base, 0x80000000, attrs];
            let expected = match role {
                0 => {
                    args[0] = 0;
                    STATUS_ACCESS_VIOLATION
                }
                1 => {
                    args[0] = 1;
                    STATUS_ACCESS_VIOLATION
                }
                2 => {
                    args[0] += 1;
                    STATUS_SUCCESS
                }
                3 => {
                    args[2] = 0;
                    STATUS_ACCESS_VIOLATION
                }
                4 => {
                    p.space.w32(attrs, 0).unwrap();
                    STATUS_INVALID_PARAMETER
                }
                5 => {
                    p.space
                        .wptr(attrs + p.arch.ptr_size() * 2, p.arch.ptr_size(), 0)
                        .unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                6 => {
                    p.space.w32(attrs + p.arch.ptr_size() * 3, 0).unwrap();
                    STATUS_SUCCESS
                }
                7 => {
                    p.space
                        .w32(attrs + p.arch.ptr_size() * 3, u32::MAX)
                        .unwrap();
                    STATUS_INVALID_PARAMETER
                }
                8 => {
                    p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                9 => {
                    p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                10 => {
                    p.space
                        .wptr(vn + if arch.is64() { 8 } else { 4 }, p.arch.ptr_size(), 0)
                        .unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                11 => {
                    args[1] = 0;
                    STATUS_ACCESS_DENIED
                }
                12 => {
                    args[1] = 2;
                    STATUS_ACCESS_DENIED
                }
                13 => {
                    args[1] = u32::MAX as u64;
                    if arch == WinArch::X86 {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_ACCESS_DENIED
                    }
                }
                14 | 15 => {
                    let offset = if role == 14 {
                        if arch.is64() { 32 } else { 16 }
                    } else if arch.is64() {
                        40
                    } else {
                        20
                    };
                    p.space.wptr(attrs + offset, p.arch.ptr_size(), 1).unwrap();
                    if arch == WinArch::X86 {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_DATATYPE_MISALIGNMENT
                    }
                }
                16 => {
                    p.space
                        .wptr(attrs + p.arch.ptr_size(), p.arch.ptr_size(), 1)
                        .unwrap();
                    if arch == WinArch::X86 {
                        STATUS_OBJECT_PATH_SYNTAX_BAD
                    } else {
                        STATUS_INVALID_HANDLE
                    }
                }
                17 => {
                    p.space.w16(vn, 1).unwrap();
                    STATUS_INVALID_PARAMETER
                }
                18 => {
                    p.vm.protect(attrs, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    STATUS_GUARD_PAGE_VIOLATION
                }
                _ => unreachable!(),
            };
            let before = p.objects.handle_count();
            assert_eq!(
                call(p, &mut t, "NtOpenKey", &args),
                expected,
                "{arch}/role{role}"
            );
            p.vm.protect(base, PAGE_SIZE * 4, prot::READWRITE).unwrap();
            if expected == STATUS_SUCCESS {
                let h = p.space.ptr(args[0], p.arch.ptr_size()).unwrap();
                assert!(matches!(p.objects.get(h), Some(Object::Key(_))));
                p.objects.close(h).unwrap();
            } else if !matches!(role, 0 | 1 | 8 | 9) {
                let zeroed = arch != WinArch::X86 || !matches!(role, 3 | 4 | 5 | 10 | 14 | 15 | 18);
                assert_eq!(
                    p.space.ptr(base, p.arch.ptr_size()).unwrap(),
                    if zeroed {
                        0
                    } else {
                        arch.ptr(0xA5A5A5A5A5A5A5A5)
                    },
                    "{arch}/role{role}"
                );
            }
            assert_eq!(p.objects.handle_count(), before);
        }
    }
}

#[test]
fn native_registry_query_alignment_conversion_and_short_buffer_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let h = opened(p, &mut t, base, 0x20019);
        let vn = base + PAGE_SIZE * 2 + 65; // Native UNICODE_STRING accepts byte alignment.
        unicode(p, vn, vn + 64, "ACP");
        for class in 0..=4 {
            for length in [0, 8, 64] {
                for offset in [1, 4] {
                    p.space.wr(base, &[0xA5; 128]).unwrap();
                    p.space.w32(base + PAGE_SIZE, 0xA5A5A5A5).unwrap();
                    let required = [18, 42, 22, 42, 18][class as usize];
                    let header = [12, 20, 12, 20, 8][class as usize];
                    let aligned = length == 0 || offset == 4 || arch == WinArch::X86;
                    let expected = if !aligned {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else if length < header {
                        STATUS_BUFFER_TOO_SMALL
                    } else if length < required {
                        STATUS_BUFFER_OVERFLOW
                    } else {
                        STATUS_SUCCESS
                    };
                    assert_eq!(
                        call(
                            p,
                            &mut t,
                            "NtQueryValueKey",
                            &[h, vn, class, base + offset, length, base + PAGE_SIZE]
                        ),
                        expected,
                        "{arch}/{class}/{length}/{offset}"
                    );
                    assert_eq!(
                        p.space.u32(base + PAGE_SIZE).unwrap(),
                        if aligned { required as u32 } else { 0xA5A5A5A5 }
                    );
                    if arch == WinArch::X86
                        && length != 0
                        && (offset == 1 || matches!(class, 3 | 4))
                    {
                        let defined = if length < header {
                            0
                        } else {
                            required.min(length)
                        };
                        assert_eq!(
                            p.space
                                .bytes(base + offset + defined, (length - defined) as usize)
                                .unwrap(),
                            vec![0; (length - defined) as usize]
                        );
                    }
                }
            }
        }
        p.objects.close(h).unwrap();
    }
}

#[test]
fn builtin_registry_probe_faults_return_nt_status_without_guest_seh_all_abis() {
    use crate::user::windows::{dll, hle::dispatch};
    for arch in WinArch::ALL {
        for service in ["NtOpenKey", "NtQueryValueKey"] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let h = opened(p, &mut t, base, 0x20019);
            let vn = base + PAGE_SIZE * 2 + 64;
            unicode(p, vn, vn + 64, "ACP");
            let args: Vec<u64> = if service == "NtOpenKey" {
                vec![0, 0x80000000, 0]
            } else {
                vec![h, vn, 2, base, 64, 0]
            };
            let sp = t.cpu.sp();
            let resume = 0x1234_5000;
            for (index, &value) in args.iter().enumerate() {
                match arch {
                    WinArch::X86 => p
                        .space
                        .w32(sp + 4 + index as u64 * 4, value as u32)
                        .unwrap(),
                    WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], value),
                    WinArch::X64 => p.space.w64(sp + 8 + index as u64 * 8, value).unwrap(),
                    WinArch::Arm64 => t.cpu.set_gpr(index, value),
                }
            }
            match arch {
                WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
                WinArch::X64 => p.space.w64(sp, resume).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            let api = dll::nt_service(service, arch).unwrap();
            assert_eq!(
                dispatch::enter(p, &mut t, api, 0x1234_1000),
                Outcome::Continue
            );
            assert_eq!(t.cpu.pc(), resume);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
            assert!(t.frames.is_empty());
            assert_eq!(
                t.cpu.sp(),
                sp + match arch {
                    WinArch::X86 => 4 * (1 + args.len() as u64),
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
            p.objects.close(h).unwrap();
        }
    }
}

#[test]
fn native_registry_snapshot_scope_relative_roots_type_and_access_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let h = opened(p, &mut t, base, 8);
        let attrs = base + PAGE_SIZE * 2;
        let vn = attrs + 64;
        unicode(p, vn, vn + 64, "ACP");
        assert_eq!(
            call(p, &mut t, "NtQueryValueKey", &[h, vn, 2, 0, 64, 0]),
            STATUS_ACCESS_DENIED
        );
        let event = p.objects.insert(Object::Event {
            manual: false,
            signaled: 0,
        });
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[u64::from(event), 0, 2, 0, 64, 0]
            ),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[h, 0, u32::MAX as u64, 0, 0, 0]
            ),
            STATUS_INVALID_PARAMETER
        );
        unicode(p, vn, vn + 64, "");
        attributes(p, attrs, vn, h, 0x40);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_SUCCESS
        );
        let second = p.space.ptr(base, arch.ptr_size()).unwrap();
        p.objects.close(h).unwrap();
        // A newly selected/replaced process snapshot cannot change records
        // already owned by open handles.
        p.registry = Registry::default();
        unicode(p, vn, vn + 64, "aCp");
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[second, vn, 2, base, 64, base + PAGE_SIZE]
            ),
            STATUS_SUCCESS
        );
        attributes(p, attrs, vn, second, 0x40);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        p.objects.close(second).unwrap();
        p.objects.close(u64::from(event)).unwrap();
        unicode(p, vn, vn + 64, NLS_KEY);
        attributes(p, attrs, vn, 0, 0x40);
        arguments(p, &mut t, &[base, 1, attrs]);
        assert!(
            matches!(dispatch(p, &mut t), Outcome::Fail(reason) if reason.contains("outside selected runtime snapshot"))
        );
        assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
    }
}

#[test]
fn native_registry_truncated_name_zeroes_incomplete_code_unit_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let h = opened(p, &mut t, base, 0x20019);
        let vn = base + PAGE_SIZE * 2 + 64;
        unicode(p, vn, vn + 64, "ACP");
        for (class, length) in [(0, 13), (1, 21), (1, 23), (3, 21), (3, 23)] {
            p.space.wr(base, &[0xA5; 64]).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtQueryValueKey",
                    &[h, vn, class, base, length, base + PAGE_SIZE]
                ),
                STATUS_BUFFER_OVERFLOW
            );
            assert_eq!(
                p.space.u8(base + length - 1).unwrap(),
                0,
                "{arch}/{class}/{length}"
            );
            assert_eq!(p.space.u8(base + length).unwrap(), 0xA5);
        }
        p.objects.close(h).unwrap();
    }
}

#[test]
fn native_registry_query_captures_descriptor_before_handle_but_text_after_validation_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..6 {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let h = opened(p, &mut t, base, 1);
            let vn = base + PAGE_SIZE * 2 + 64;
            unicode(p, vn, vn + 64, "ACP");
            let mut args = [h, vn, 2, base, 64, base + PAGE_SIZE];
            let buffer = if role >= 4 {
                base + PAGE_SIZE * 3
            } else if role == 1 {
                0
            } else {
                1
            };
            p.space
                .wptr(
                    vn + if arch.is64() { 8 } else { 4 },
                    arch.ptr_size(),
                    buffer,
                )
                .unwrap();
            if matches!(role, 0 | 1 | 5) {
                p.space.w16(vn, 1).unwrap();
            }
            if matches!(role, 2 | 4) {
                args[0] = 0;
            }
            if role == 3 {
                args[2] = 5;
            }
            if role >= 4 {
                p.vm.protect(buffer, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            assert_eq!(
                call(p, &mut t, "NtQueryValueKey", &args),
                if matches!(role, 2 | 4) {
                    STATUS_INVALID_HANDLE
                } else {
                    STATUS_INVALID_PARAMETER
                },
                "{arch}/role{role}"
            );
            if role >= 4 {
                assert_ne!(p.vm.query(buffer).unwrap().protect & prot::GUARD, 0);
            }
            p.objects.close(h).unwrap();
        }
    }
}

#[test]
fn native_registry_open_odd_name_is_rejected_before_native_text_probe_all_abis() {
    for arch in WinArch::ALL {
        for buffer in [0, 1] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let attrs = base + PAGE_SIZE * 2;
            let vn = attrs + 64;
            unicode(p, vn, vn + 64, NLS_KEY);
            attributes(p, attrs, vn, 0, 0x240);
            p.space.w16(vn, 1).unwrap();
            p.space
                .wptr(
                    vn + if arch.is64() { 8 } else { 4 },
                    arch.ptr_size(),
                    buffer,
                )
                .unwrap();
            assert_eq!(
                call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
                if arch == WinArch::X86 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_INVALID_PARAMETER
                },
                "{arch}/{buffer}"
            );
            assert_eq!(
                p.space.ptr(base, arch.ptr_size()).unwrap(),
                if arch == WinArch::X86 { 0xA5A5A5A5 } else { 0 }
            );
        }
    }
}

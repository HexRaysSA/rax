//! Snapshot-backed native NLS mappings and measured probe priorities.
use super::*;
use crate::user::windows::nt::status::*;

#[cfg(windows)]
#[path = "nls_leaf_tests.rs"]
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
fn native_nls_null_section_output_is_invalid_parameter_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtGetNlsSectionPtr", 0x12);
        let p = process.state_mut();
        arguments(p, &mut t, &[11, 1252, 0, 0, 0]);
        assert_eq!(dispatch(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_PARAMETER));
        assert!(t.frames.is_empty());
    }
}
#[test]
fn native_nls_bad_output_precedes_unknown_section_type_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtGetNlsSectionPtr", 0x12);
        let p = process.state_mut();
        arguments(p, &mut t, &[0, 1252, 0, 1, 0]);
        assert_eq!(dispatch(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
        assert!(t.frames.is_empty());
    }
}

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtGetNlsSectionPtr", 0x12);
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
    p.nls = Some(
        crate::user::windows::nls::Nls::new(vec![
            ((11, 1252), vec![0x53; 4097]),
            ((12, 1), vec![0x6e; 100]),
            ((14, 0), vec![0x74; 100]),
        ])
        .unwrap(),
    );
    (process, t, base)
}
fn ptr(p: &Proc, at: u64) -> u64 {
    if p.arch == WinArch::X86 {
        u64::from(p.space.u32(at).unwrap())
    } else {
        p.space.u64(at).unwrap()
    }
}
#[test]
fn native_nls_readonly_distinct_mapped_views_optional_size_and_aliases_all_abis() {
    for arch in WinArch::ALL {
        for kind in [11, 12, 14] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let data = match kind {
                11 => 1252,
                12 => 1,
                _ => u32::MAX,
            };
            let out = base + 65;
            let size = base + 129;
            arguments(p, &mut t, &[kind, u64::from(data), 0, out, size]);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_SUCCESS));
            let first = ptr(p, out);
            let region = p.vm.query(first).unwrap();
            let len = if kind == 11 { 8192 } else { 4096 };
            assert_eq!(p.space.u32(size).unwrap(), len);
            assert_eq!(region.kind, mem::MAPPED);
            assert_eq!(region.protect, prot::READONLY);
            assert_eq!(region.allocation_protect, prot::READONLY);
            assert_eq!(
                p.space.u8(first).unwrap(),
                if kind == 11 {
                    0x53
                } else if kind == 12 {
                    0x6e
                } else {
                    0x74
                }
            );
            assert!(p.space.w8(first, 1).is_err());
            if kind == 11 {
                assert_eq!(p.space.u8(first + 4096).unwrap(), 0x53);
                assert_eq!(p.space.u8(first + 4097).unwrap(), 0);
            }
            arguments(p, &mut t, &[kind, u64::from(data), 0, out, 0]);
            dispatch(p, &mut t);
            assert_eq!(t.cpu.gpr(0), 0);
            let second = ptr(p, out);
            assert_ne!(first, second);
            arguments(p, &mut t, &[kind, u64::from(data), 0, out, out]);
            dispatch(p, &mut t);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(out).unwrap(), len);
            assert_eq!(p.vm.nls_view_count(), 3);
            assert!(t.frames.is_empty());
        }
    }
}
#[test]
fn native_nls_probe_order_context_optional_size_and_guard_priority_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..22 {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let (mut kind, mut data, mut context, mut out, mut size) =
                (11, 1252, 0, base + 64, base + 128);
            let g1 = base + PAGE_SIZE;
            let g2 = base + PAGE_SIZE * 2;
            let mut expected = STATUS_SUCCESS;
            match role {
                0 => size = 0,
                1 => {
                    size = 1;
                    expected = if arch == WinArch::X86 {
                        0
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                }
                2 => {
                    context = 1;
                    expected = STATUS_ACCESS_VIOLATION;
                }
                3 => {
                    context = base + 256;
                    expected = STATUS_INVALID_PARAMETER_3;
                }
                4 => {
                    out = 0;
                    context = base + 256;
                    expected = STATUS_INVALID_PARAMETER_3;
                }
                5 => {
                    kind = 0;
                    expected = STATUS_INVALID_PARAMETER_1;
                }
                6 => {
                    kind = 0;
                    size = 1;
                    expected = if arch == WinArch::X86 {
                        STATUS_INVALID_PARAMETER_1
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                }
                7 => {
                    data = 0;
                    expected = STATUS_OBJECT_NAME_NOT_FOUND;
                }
                8 => {
                    out = 1;
                    expected = STATUS_ACCESS_VIOLATION;
                }
                9 => {
                    out = g1;
                    p.vm.protect(g1, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                }
                10 => {
                    size = g1;
                    p.vm.protect(g1, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = if arch == WinArch::X86 {
                        0
                    } else {
                        STATUS_GUARD_PAGE_VIOLATION
                    };
                }
                11 => {
                    context = g1;
                    p.vm.protect(g1, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                }
                12 => {
                    out = g1;
                    size = g2;
                    p.vm.protect(g1, PAGE_SIZE * 2, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                }
                13 => {
                    out = g1;
                    context = g2;
                    p.vm.protect(g1, PAGE_SIZE * 2, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                }
                14 => {
                    context = g1;
                    size = g2;
                    p.vm.protect(g1, PAGE_SIZE * 2, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = STATUS_GUARD_PAGE_VIOLATION;
                }
                15 => {
                    kind = 0;
                    size = g1;
                    p.vm.protect(g1, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                    expected = if arch == WinArch::X86 {
                        STATUS_INVALID_PARAMETER_1
                    } else {
                        STATUS_GUARD_PAGE_VIOLATION
                    };
                }
                16 => {
                    size = g1 - 2;
                    p.vm.protect(g1, PAGE_SIZE, prot::NOACCESS).unwrap();
                    expected = if arch == WinArch::X86 {
                        0
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                }
                17 => {
                    out = g1 - 3;
                    p.vm.protect(g1, PAGE_SIZE, prot::NOACCESS).unwrap();
                    expected = STATUS_ACCESS_VIOLATION;
                }
                18 => {
                    context = g1 - 4;
                    p.vm.protect(g1, PAGE_SIZE, prot::NOACCESS).unwrap();
                    expected = if arch == WinArch::X86 {
                        STATUS_INVALID_PARAMETER_3
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                }
                19 => {
                    kind = 0;
                    context = 1;
                    out = 0;
                    expected = STATUS_ACCESS_VIOLATION;
                }
                20 => {
                    kind = 0;
                    out = 0;
                    expected = STATUS_INVALID_PARAMETER;
                }
                21 => {
                    kind = 12;
                    data = 3;
                    expected = STATUS_OBJECT_NAME_NOT_FOUND;
                }
                _ => unreachable!(),
            }
            arguments(p, &mut t, &[kind, data, context, out, size]);
            assert_eq!(
                dispatch(p, &mut t),
                Outcome::Continue,
                "{arch:?} role{role}"
            );
            assert_eq!(t.cpu.gpr(0), u64::from(expected), "{arch:?} role{role}");
            if matches!(role, 9 | 10 | 11 | 12 | 15) {
                assert_eq!(
                    p.vm.query(g1).unwrap().protect & prot::GUARD,
                    0,
                    "{arch:?} role{role}"
                );
            }
            if role == 12 {
                assert_ne!(p.vm.query(g2).unwrap().protect & prot::GUARD, 0);
            }
            if role == 13 {
                assert_eq!(
                    p.vm.query(g1).unwrap().protect & prot::GUARD != 0,
                    arch == WinArch::X86
                );
                assert_eq!(
                    p.vm.query(g2).unwrap().protect & prot::GUARD != 0,
                    arch != WinArch::X86
                );
            }
            if role == 14 {
                assert_eq!(
                    p.vm.query(g1).unwrap().protect & prot::GUARD != 0,
                    arch != WinArch::X86
                );
                assert_eq!(
                    p.vm.query(g2).unwrap().protect & prot::GUARD != 0,
                    arch == WinArch::X86
                );
            }
            if expected != 0 {
                assert_eq!(p.vm.nls_view_count(), 0, "{arch:?} role{role}");
            }
            assert!(t.frames.is_empty());
        }
    }
}
#[test]
fn native_nls_unmap_interior_owned_views_close_and_type_access_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..10 {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            arguments(p, &mut t, &[11, 1252, 0, base + 64, 0]);
            dispatch(p, &mut t);
            let view = ptr(p, base + 64);
            let mut handle = arch.ptr(u64::MAX);
            let mut address = view;
            let mut expected = STATUS_SUCCESS;
            match role {
                1 => address += 1,
                2 => address += 8191,
                3 => {
                    address = 0;
                    expected = STATUS_NOT_MAPPED_VIEW;
                }
                4 => {
                    handle = 0;
                    expected = STATUS_INVALID_HANDLE;
                }
                5 => {
                    handle = arch.ptr(u64::MAX - 1);
                    expected = STATUS_OBJECT_TYPE_MISMATCH;
                }
                6 => {
                    address = base;
                    expected = STATUS_NOT_MAPPED_VIEW;
                }
                7 | 8 => {
                    let id = p.objects.create(Object::Process {
                        pid: p.pid,
                        exit_code: None,
                    });
                    handle = u64::from(
                        p.objects
                            .open_access(id, false, if role == 7 { 8 } else { 0 })
                            .unwrap(),
                    );
                    if role == 8 {
                        expected = STATUS_ACCESS_DENIED;
                    }
                }
                9 => {
                    let id = p.objects.create(Object::Event {
                        manual: false,
                        signaled: 0,
                    });
                    handle = u64::from(p.objects.open(id, false));
                    expected = STATUS_OBJECT_TYPE_MISMATCH;
                }
                _ => {}
            }
            p.modules.nt_services = Some((0, table(arch, "NtUnmapViewOfSection", 0x12)));
            arguments(p, &mut t, &[handle, address]);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(expected), "{arch:?} role{role}");
            if expected == 0 {
                assert!(!p.vm.is_nls_view(view));
                assert!(p.space.u8(view).is_err());
                arguments(p, &mut t, &[arch.ptr(u64::MAX), view]);
                dispatch(p, &mut t);
                assert_eq!(t.cpu.gpr(0), u64::from(STATUS_NOT_MAPPED_VIEW));
            } else {
                assert!(p.vm.is_nls_view(view));
            }
        }
    }
}

#[test]
fn native_nls_views_cannot_gain_write_or_execute_protection_or_be_freed_as_private_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        arguments(p, &mut t, &[11, 1252, 0, base + 64, 0]);
        dispatch(p, &mut t);
        let view = ptr(p, base + 64);
        for protect in [
            prot::NOACCESS,
            prot::READWRITE,
            prot::WRITECOPY,
            prot::EXECUTE,
            prot::EXECUTE_READ,
            prot::EXECUTE_READWRITE,
            prot::EXECUTE_WRITECOPY,
            prot::READONLY | prot::GUARD,
        ] {
            assert_eq!(
                p.vm.protect(view, 8192, protect).unwrap_err().status(),
                STATUS_INVALID_PAGE_PROTECTION
            );
            assert_eq!(p.vm.query(view).unwrap().protect, prot::READONLY);
            if arch == WinArch::X86 {
                p.space.w32(base + 256, view as u32).unwrap();
                p.space.w32(base + 272, 8192).unwrap();
            } else {
                p.space.w64(base + 256, view).unwrap();
                p.space.w64(base + 272, 8192).unwrap();
            }
            p.space.w32(base + 288, 0xA5A5A5A5).unwrap();
            let module = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((module, table(arch, "NtProtectVirtualMemory", 0x12)));
            arguments(
                p,
                &mut t,
                &[
                    arch.ptr(u64::MAX),
                    base + 256,
                    base + 272,
                    u64::from(protect),
                    base + 288,
                ],
            );
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_PAGE_PROTECTION));
            assert_eq!(p.space.u32(base + 288).unwrap(), prot::NOACCESS);
        }
        assert_eq!(
            p.vm.protect(view, 8192, prot::READONLY).unwrap(),
            prot::READONLY
        );
        assert_eq!(
            p.vm.free(view, 0, mem::RELEASE).unwrap_err().status(),
            0xC000001B
        );
        assert_eq!(p.vm.decommit(view, 8192).unwrap_err().status(), 0xC000001B);
        assert_eq!(
            p.vm.commit(view, 8192, prot::READONLY)
                .unwrap_err()
                .status(),
            STATUS_ALREADY_COMMITTED
        );
        assert_eq!(
            p.vm.commit(view, 8192, prot::READWRITE)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PAGE_PROTECTION
        );
        assert!(p.space.w8(view, 1).is_err());
    }
}

#[test]
fn native_nls_ntstatus_to_win32_errors_matches_installed_rtl_oracle() {
    for (status, error) in [
        (STATUS_NOT_MAPPED_VIEW, 487),
        (STATUS_UNABLE_TO_DELETE_SECTION, 87),
        (STATUS_ALREADY_COMMITTED, 5),
        (STATUS_INVALID_PAGE_PROTECTION, 87),
    ] {
        assert_eq!(
            crate::user::windows::nt::status_to_error(status),
            error,
            "{status:#010x}"
        );
    }
}

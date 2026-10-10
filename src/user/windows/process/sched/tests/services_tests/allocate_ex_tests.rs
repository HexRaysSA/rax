//! Extended private allocations: native constraints, capture and publication.
use super::*;
use crate::user::windows::memory::AllocKind;
use crate::user::windows::nt::status::*;

#[cfg(windows)]
#[path = "allocate_ex_leaf_tests.rs"]
mod installed;

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtAllocateVirtualMemoryEx", 0x78);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(
            None,
            PAGE_SIZE * 2,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    (process, t, scratch)
}
fn ptr(p: &Proc, at: u64, value: u64) {
    p.space.wptr(at, p.arch.ptr_size(), value).unwrap();
}
fn get(p: &Proc, at: u64) -> u64 {
    p.space.ptr(at, p.arch.ptr_size()).unwrap()
}
fn requirements(p: &Proc, scratch: u64, low: u64, high: u64, align: u64) {
    p.space.w64(scratch + 64, 1).unwrap();
    p.space.w64(scratch + 72, scratch + 128).unwrap();
    for (i, value) in [low, high, align].into_iter().enumerate() {
        ptr(p, scratch + 128 + i as u64 * p.arch.ptr_size(), value);
    }
}
fn arguments(p: &mut Proc, t: &mut Thread, args: &[u64]) {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (i, &value) in args.iter().enumerate() {
                p.space.w32(sp + 8 + i as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, 0x78);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x78);
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, &value) in args.iter().enumerate() {
                if i < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][i], value);
                } else {
                    p.space.w64(sp + 8 + i as u64 * 8, value).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (i, &value) in args.iter().enumerate() {
                t.cpu.set_gpr(i, value);
            }
        }
    }
}
fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    arguments(p, t, args);
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x78))
    };
    assert_eq!(result, Outcome::Continue);
    assert!(t.frames.is_empty());
    t.cpu.gpr(0) as u32
}
fn alloc(
    p: &mut Proc,
    t: &mut Thread,
    base: u64,
    size: u64,
    flags: u32,
    protection: u32,
    params: u64,
    count: u32,
) -> u32 {
    invoke(
        p,
        t,
        &[
            p.arch.ptr(u64::MAX),
            base,
            size,
            flags.into(),
            protection.into(),
            params,
            count.into(),
        ],
    )
}

#[test]
fn native_allocate_ex_default_loader_reservation_and_commit_all_abis() {
    for arch in WinArch::ALL {
        for (size, flags, params) in [
            (0x0200_1000, mem::RESERVE | mem::TOP_DOWN, true),
            (1, mem::COMMIT, false),
            (0x1001, mem::RESERVE | mem::COMMIT, true),
        ] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, size);
            requirements(p, scratch, 0, 0, 0);
            assert_eq!(
                alloc(
                    p,
                    &mut t,
                    scratch,
                    scratch + 16,
                    flags,
                    prot::READWRITE,
                    if params { scratch + 64 } else { 0 },
                    u32::from(params)
                ),
                STATUS_SUCCESS
            );
            let base = get(p, scratch);
            let rounded = (size + 4095) & !4095;
            assert_eq!(base % 65536, 0);
            assert_eq!(get(p, scratch + 16), rounded);
            let a = p.vm.allocation(base).unwrap();
            assert_eq!(a.size, rounded);
            assert_eq!(a.kind, AllocKind::Private);
            assert_eq!(
                p.vm.query(base).unwrap().state,
                if flags & mem::COMMIT != 0 {
                    mem::COMMIT
                } else {
                    mem::RESERVE
                }
            );
            assert_eq!(
                p.vm.query(base + rounded - 1).unwrap().state,
                p.vm.query(base).unwrap().state
            );
            if flags & mem::COMMIT != 0 {
                assert_eq!(p.space.u8(base).unwrap(), 0);
                p.space.w8(base, 0x5a).unwrap();
            } else {
                assert!(p.space.u8(base).is_err());
            }
            p.vm.release(base).unwrap();
            assert_eq!(p.vm.query(base).unwrap().state, mem::FREE);
        }
    }
}

#[test]
fn native_allocate_ex_constrained_holes_alignment_top_down_and_commit_all_abis() {
    for arch in WinArch::ALL {
        for (flags, alignment, expected) in [
            (mem::RESERVE, 0, 0x3000_0000),
            (mem::RESERVE | mem::TOP_DOWN, 0, 0x30ef_0000),
            (mem::COMMIT, 0x20_0000, 0x3020_0000),
        ] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            p.vm.reserve(
                Some(0x30f0_0000),
                0x10_0000,
                prot::READWRITE,
                AllocKind::Private,
                false,
                None,
            )
            .unwrap();
            if alignment != 0 {
                p.vm.reserve(
                    Some(0x3000_0000),
                    0x10_0000,
                    prot::READWRITE,
                    AllocKind::Private,
                    false,
                    None,
                )
                .unwrap();
            }
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, 0x1001);
            requirements(p, scratch, 0x3000_0000, 0x30ff_ffff, alignment);
            assert_eq!(
                alloc(
                    p,
                    &mut t,
                    scratch,
                    scratch + 16,
                    flags,
                    prot::READWRITE,
                    scratch + 64,
                    1
                ),
                STATUS_SUCCESS
            );
            assert_eq!(get(p, scratch), expected);
            assert_eq!(get(p, scratch + 16), 0x2000);
            assert_eq!(
                p.vm.query(expected).unwrap().state,
                if flags & mem::COMMIT != 0 {
                    mem::COMMIT
                } else {
                    mem::RESERVE
                }
            );
            assert_eq!(p.vm.query(0x30f0_0000).unwrap().state, mem::RESERVE);
        }
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        p.vm.reserve(
            Some(0x3000_0000),
            65536,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
        ptr(p, scratch, 0);
        ptr(p, scratch + 16, 4096);
        requirements(p, scratch, 0x3000_0000, 0x3000_ffff, 0);
        let before = p.vm.allocations().count();
        assert_eq!(
            alloc(
                p,
                &mut t,
                scratch,
                scratch + 16,
                mem::RESERVE,
                prot::READWRITE,
                scratch + 64,
                1
            ),
            STATUS_NO_MEMORY
        );
        assert_eq!(get(p, scratch), 0);
        assert_eq!(get(p, scratch + 16), 4096);
        assert_eq!(p.vm.allocations().count(), before);
    }
}

#[test]
fn native_allocate_ex_rejects_invalid_requirements_without_mutation_all_abis() {
    for arch in WinArch::ALL {
        for (low, high, alignment, size, base) in [
            (0, 0, 4096, 4096, 0),
            (0, 0, 0x18000, 4096, 0),
            (0x10001, 0, 0, 4096, 0),
            (0, 0x1fff0000, 0, 4096, 0),
            (0, arch.ptr(u64::MAX), 0, 4096, 0),
            (0x2000000, 0x1ffffff, 0, 4096, 0),
            (0x1000000, 0x100ffff, 0, 0x11000, 0),
            (0x10000, 0x1ffff, 0x20000, 4096, 0),
            (0, 0, 65536, 4096, 0x30000000),
            (0, 0, 0, 0, 0),
            (0, 0, 0, arch.ptr(u64::MAX), 0),
        ] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            ptr(p, scratch, base);
            ptr(p, scratch + 16, size);
            requirements(p, scratch, low, high, alignment);
            let before = p.vm.allocations().count();
            assert_eq!(
                alloc(
                    p,
                    &mut t,
                    scratch,
                    scratch + 16,
                    mem::RESERVE,
                    prot::READWRITE,
                    scratch + 64,
                    1
                ),
                STATUS_INVALID_PARAMETER,
                "{arch:?} low={low:x} high={high:x} alignment={alignment:x}"
            );
            assert_eq!(get(p, scratch), base);
            assert_eq!(get(p, scratch + 16), size);
            assert_eq!(p.vm.allocations().count(), before);
        }
    }
}

#[test]
fn native_allocate_ex_parameter_capture_validation_and_alignment_all_abis() {
    for arch in WinArch::ALL {
        for (parameters, count, expected) in [
            (0, 1, STATUS_INVALID_PARAMETER),
            (1, 0, STATUS_INVALID_PARAMETER),
            (
                1,
                1,
                if arch == WinArch::X86 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                },
            ),
            (
                0xdead0000,
                7,
                if arch == WinArch::X86 {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_ACCESS_VIOLATION
                },
            ),
        ] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, 4096);
            let before = p.vm.allocations().count();
            assert_eq!(
                alloc(
                    p,
                    &mut t,
                    scratch,
                    scratch + 16,
                    mem::RESERVE,
                    prot::READWRITE,
                    parameters,
                    count
                ),
                expected
            );
            assert_eq!(p.vm.allocations().count(), before);
        }
        for mode in 0..10 {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, 4096);
            requirements(p, scratch, 0, 0, 0);
            let mut parameters = scratch + 64;
            let mut count = 1;
            let expected = match mode {
                0 => {
                    p.space.w64(parameters, 255).unwrap();
                    STATUS_INVALID_PARAMETER
                }
                1 => {
                    p.space.w64(parameters, 0x101).unwrap();
                    STATUS_INVALID_PARAMETER
                }
                2 => {
                    p.space.w64(parameters + 8, 0).unwrap();
                    STATUS_ACCESS_VIOLATION
                }
                3 => {
                    p.space.w64(parameters + 8, 1).unwrap();
                    if arch == WinArch::X86 {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_DATATYPE_MISALIGNMENT
                    }
                }
                4 => {
                    p.space
                        .wr(parameters + 16, &p.space.bytes(parameters, 16).unwrap())
                        .unwrap();
                    count = 2;
                    STATUS_INVALID_PARAMETER
                }
                5 => {
                    p.space.w64(parameters, 2).unwrap();
                    p.space.w64(parameters + 8, 0).unwrap();
                    STATUS_SUCCESS
                }
                6 => {
                    p.space.w64(parameters, 2).unwrap();
                    p.space.w64(parameters + 8, 255).unwrap();
                    STATUS_INVALID_PARAMETER
                }
                7 => {
                    p.space.w64(parameters, 5).unwrap();
                    p.space.w64(parameters + 8, 0).unwrap();
                    STATUS_SUCCESS
                }
                8 => {
                    let bytes = p.space.bytes(parameters, 16).unwrap();
                    parameters += 1;
                    p.space.wr(parameters, &bytes).unwrap();
                    if arch == WinArch::X86 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_DATATYPE_MISALIGNMENT
                    }
                }
                _ => {
                    let bytes = p
                        .space
                        .bytes(scratch + 128, (arch.ptr_size() * 3) as usize)
                        .unwrap();
                    p.space.wr(scratch + 129, &bytes).unwrap();
                    p.space.w64(parameters + 8, scratch + 129).unwrap();
                    if arch == WinArch::X86 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_DATATYPE_MISALIGNMENT
                    }
                }
            };
            assert_eq!(
                alloc(
                    p,
                    &mut t,
                    scratch,
                    scratch + 16,
                    mem::RESERVE,
                    prot::READWRITE,
                    parameters,
                    count
                ),
                expected,
                "{arch:?} mode={mode}"
            );
        }
    }
}

#[test]
fn native_allocate_ex_parameter_alignment_depends_on_wow_capture_all_abis() {
    for arch in WinArch::ALL {
        for kind in 1..=6 {
            for shift in [0, 1, 4, 8] {
                let (mut process, mut t, scratch) = setup(arch);
                let p = process.state_mut();
                ptr(p, scratch, 0);
                ptr(p, scratch + 16, 4096);
                requirements(p, scratch, 0, 0, 0);
                if kind != 1 {
                    p.space.w64(scratch + 64, kind).unwrap();
                    p.space.w64(scratch + 72, 0).unwrap();
                }
                let bytes = p.space.bytes(scratch + 64, 16).unwrap();
                let parameters = scratch + 64 + shift;
                p.space.wr(parameters, &bytes).unwrap();
                let before = p.vm.allocations().count();
                let expected =
                    if parameters % 8 != 0 && (arch != WinArch::X86 || !matches!(kind, 1 | 3)) {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else if matches!(kind, 3 | 4 | 6) {
                        STATUS_INVALID_PARAMETER
                    } else {
                        STATUS_SUCCESS
                    };
                assert_eq!(
                    alloc(
                        p,
                        &mut t,
                        scratch,
                        scratch + 16,
                        mem::RESERVE,
                        prot::READWRITE,
                        parameters,
                        1
                    ),
                    expected,
                    "{arch:?} kind={kind} shift={shift}"
                );
                if expected == STATUS_SUCCESS {
                    p.vm.release(get(p, scratch)).unwrap();
                } else {
                    assert_eq!(get(p, scratch), 0);
                    assert_eq!(get(p, scratch + 16), 4096);
                }
                assert_eq!(p.vm.allocations().count(), before);
            }
        }
    }
}

#[test]
fn native_allocate_ex_wow_capture_precedes_type_validation_all_abis() {
    for arch in WinArch::ALL {
        for mode in 0..7 {
            for shift in [0, 1] {
                let (mut process, mut t, scratch) = setup(arch);
                let p = process.state_mut();
                ptr(p, scratch, 0);
                ptr(p, scratch + 16, 4096);
                requirements(p, scratch, 0, 0, 0);
                let mut count = 2;
                let expected = match mode {
                    0 | 1 => {
                        let record = p.space.bytes(scratch + 64, 16).unwrap();
                        p.space.wr(scratch + 80, &record).unwrap();
                        p.space
                            .w64(scratch + 64, if mode == 0 { 2 } else { 5 })
                            .unwrap();
                        p.space.w64(scratch + 72, 0).unwrap();
                        STATUS_SUCCESS
                    }
                    2 => {
                        p.space.w64(scratch + 80, 1).unwrap();
                        p.space.w64(scratch + 88, 0).unwrap();
                        p.space.w64(scratch + 64, 255).unwrap();
                        if arch == WinArch::X86 {
                            STATUS_ACCESS_VIOLATION
                        } else {
                            STATUS_INVALID_PARAMETER
                        }
                    }
                    3 => {
                        count = 1;
                        p.space.w64(scratch + 64, 0x101).unwrap();
                        p.space.w64(scratch + 72, 0).unwrap();
                        if arch == WinArch::X86 {
                            STATUS_ACCESS_VIOLATION
                        } else {
                            STATUS_INVALID_PARAMETER
                        }
                    }
                    4 => {
                        p.space.w64(scratch + 80, 1).unwrap();
                        p.space.w64(scratch + 88, 0).unwrap();
                        if arch == WinArch::X86 {
                            STATUS_ACCESS_VIOLATION
                        } else {
                            STATUS_INVALID_PARAMETER
                        }
                    }
                    5 => {
                        p.space.w64(scratch + 72, 0).unwrap();
                        p.space.w64(scratch + 80, 255).unwrap();
                        STATUS_ACCESS_VIOLATION
                    }
                    _ => {
                        count = 1;
                        p.space.w64(scratch + 64, 3).unwrap();
                        p.space.w64(scratch + 72, 0).unwrap();
                        STATUS_INVALID_PARAMETER
                    }
                };
                let bytes = p.space.bytes(scratch + 64, count as usize * 16).unwrap();
                let parameters = scratch + 64 + shift;
                p.space.wr(parameters, &bytes).unwrap();
                let before = p.vm.allocations().count();
                assert_eq!(
                    alloc(
                        p,
                        &mut t,
                        scratch,
                        scratch + 16,
                        mem::RESERVE,
                        prot::READWRITE,
                        parameters,
                        count
                    ),
                    if shift != 0 && arch != WinArch::X86 {
                        STATUS_DATATYPE_MISALIGNMENT
                    } else {
                        expected
                    },
                    "{arch:?} mode={mode} shift={shift}"
                );
                if expected == STATUS_SUCCESS && (shift == 0 || arch == WinArch::X86) {
                    p.vm.release(get(p, scratch)).unwrap();
                } else {
                    assert_eq!(get(p, scratch), 0);
                    assert_eq!(get(p, scratch + 16), 4096);
                }
                assert_eq!(p.vm.allocations().count(), before);
            }
        }
    }
}

#[test]
fn native_allocate_ex_numa_validation_follows_capture_and_process_access_all_abis() {
    for arch in WinArch::ALL {
        for kind in [2, 5] {
            for handle_kind in 0..4 {
                for fault in 0..4 {
                    let (mut process, mut t, scratch) = setup(arch);
                    let p = process.state_mut();
                    ptr(p, scratch, 0);
                    ptr(p, scratch + 16, 4096);
                    requirements(p, scratch, 0, 0, if fault == 2 { 4096 } else { 0 });
                    let record = p.space.bytes(scratch + 64, 16).unwrap();
                    p.space.wr(scratch + 80, &record).unwrap();
                    if fault == 1 {
                        p.space.w64(scratch + 88, 0).unwrap();
                    }
                    p.space.w64(scratch + 64, kind).unwrap();
                    p.space
                        .w64(scratch + 72, if kind == 2 { 255 } else { 1 })
                        .unwrap();
                    let handle = match handle_kind {
                        0 => arch.ptr(u64::MAX),
                        1 => 0,
                        2 => arch.ptr(u64::MAX - 1),
                        _ => {
                            let object =
                                p.objects
                                    .create(crate::user::windows::objects::Object::Process {
                                        pid: p.pid,
                                        exit_code: None,
                                    });
                            u64::from(p.objects.open_access(object, false, 0x400).unwrap())
                        }
                    };
                    let expected = if fault == 1 && (kind == 2 || arch == WinArch::X86) {
                        STATUS_ACCESS_VIOLATION
                    } else if kind == 5 {
                        STATUS_INVALID_PARAMETER
                    } else {
                        match handle_kind {
                            0 => STATUS_INVALID_PARAMETER,
                            1 => STATUS_INVALID_HANDLE,
                            2 => STATUS_OBJECT_TYPE_MISMATCH,
                            _ => STATUS_ACCESS_DENIED,
                        }
                    };
                    let before = p.vm.allocations().count();
                    assert_eq!(
                        invoke(
                            p,
                            &mut t,
                            &[
                                handle,
                                scratch,
                                scratch + 16,
                                mem::RESERVE.into(),
                                u64::from(if fault == 3 { 0 } else { prot::READWRITE }),
                                scratch + 64,
                                2
                            ]
                        ),
                        expected,
                        "{arch:?} kind={kind} handle={handle_kind} fault={fault}"
                    );
                    assert_eq!(get(p, scratch), 0);
                    assert_eq!(get(p, scratch + 16), 4096);
                    assert_eq!(p.vm.allocations().count(), before);
                }
            }
        }
    }
}

#[test]
fn native_allocate_ex_fault_copy_order_and_guards_all_abis() {
    for arch in WinArch::ALL {
        for field in 0..4 {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, 4096);
            requirements(p, scratch, 0, 0, 0);
            let guarded = scratch + PAGE_SIZE;
            let mut base = scratch;
            let mut size = scratch + 16;
            let mut parameters = scratch + 64;
            match field {
                0 => {
                    ptr(p, guarded, 0);
                    base = guarded;
                }
                1 => {
                    ptr(p, guarded, 4096);
                    size = guarded;
                }
                2 => {
                    p.space
                        .wr(guarded, &p.space.bytes(parameters, 16).unwrap())
                        .unwrap();
                    parameters = guarded;
                }
                _ => {
                    p.space
                        .wr(
                            guarded,
                            &p.space
                                .bytes(scratch + 128, (arch.ptr_size() * 3) as usize)
                                .unwrap(),
                        )
                        .unwrap();
                    p.space.w64(parameters + 8, guarded).unwrap();
                }
            }
            p.vm.protect(guarded, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let before = p.vm.allocations().count();
            let expected = if arch == WinArch::X64 && field < 2 {
                STATUS_SUCCESS
            } else if arch == WinArch::X86 && field == 1 {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            };
            assert_eq!(
                alloc(
                    p,
                    &mut t,
                    base,
                    size,
                    mem::RESERVE,
                    prot::READWRITE,
                    parameters,
                    1
                ),
                expected,
                "{arch:?} field={field}"
            );
            assert_eq!(p.vm.query(guarded).unwrap().protect & prot::GUARD, 0);
            assert_eq!(
                p.vm.allocations().count(),
                before + usize::from(expected == STATUS_SUCCESS)
            );
        }
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        ptr(p, scratch, 0);
        let size = scratch + PAGE_SIZE;
        ptr(p, size, 4096);
        requirements(p, scratch, 0, 0, 0);
        p.vm.protect(size, PAGE_SIZE, prot::READONLY).unwrap();
        let before = p.vm.allocations().count();
        assert_eq!(
            alloc(
                p,
                &mut t,
                scratch,
                size,
                mem::RESERVE,
                prot::READWRITE,
                scratch + 64,
                1
            ),
            STATUS_ACCESS_VIOLATION
        );
        if arch == WinArch::X86 {
            assert_ne!(get(p, scratch), 0);
            assert_eq!(p.vm.query(get(p, scratch)).unwrap().state, mem::RESERVE);
            assert_eq!(p.vm.allocations().count(), before + 1);
        } else {
            assert_eq!(get(p, scratch), 0);
            assert_eq!(p.vm.allocations().count(), before);
        }
    }
}

#[test]
fn native_allocate_ex_full_array_capture_precedes_type_and_requirements_all_abis() {
    for arch in WinArch::ALL {
        for bad in [false, true] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, 4096);
            let parameters = scratch + PAGE_SIZE - 16;
            p.space.w64(parameters, if bad { 255 } else { 1 }).unwrap();
            p.space.w64(parameters + 8, 1).unwrap();
            p.vm.protect(scratch + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let before = p.vm.allocations().count();
            assert_eq!(
                alloc(
                    p,
                    &mut t,
                    scratch,
                    scratch + 16,
                    mem::RESERVE,
                    prot::READWRITE,
                    parameters,
                    2
                ),
                STATUS_ACCESS_VIOLATION
            );
            assert_eq!(p.vm.allocations().count(), before);
        }
    }
}

#[test]
fn native_allocate_ex_fixed_rounding_unaligned_outputs_and_rollback_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let base = scratch + 1;
        let size = scratch + 17;
        ptr(p, base, 0x30000001);
        ptr(p, size, 4096);
        requirements(p, scratch, 0, 0, 0);
        assert_eq!(
            alloc(
                p,
                &mut t,
                base,
                size,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
                scratch + 64,
                1
            ),
            STATUS_SUCCESS
        );
        assert_eq!(get(p, base), 0x30000000);
        assert_eq!(get(p, size), 8192);
        assert_eq!(p.space.bytes(0x30000000, 8192).unwrap(), vec![0; 8192]);
        p.vm.release(0x30000000).unwrap();
        ptr(p, base, 0);
        ptr(p, size, 128 << 20);
        requirements(p, scratch, 0x30000000, 0x3fffffff, 0x100000);
        let before = p.vm.allocations().count();
        assert_eq!(
            alloc(
                p,
                &mut t,
                base,
                size,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
                scratch + 64,
                1
            ),
            STATUS_COMMITMENT_LIMIT
        );
        assert_eq!(p.vm.allocations().count(), before);
        assert_eq!(get(p, base), 0);
        assert_eq!(get(p, size), 128 << 20);
        assert_eq!(p.vm.query(0x30000000).unwrap().state, mem::FREE);
    }
}

#[test]
fn native_allocate_ex_respects_untracked_mappings_and_fault_priority_all_abis() {
    use crate::user::mm::{Mapping, Perms};
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        p.space
            .map(
                0x30000000,
                4096,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        p.space.w32(0x30000000, 0x12345678).unwrap();
        ptr(p, scratch, 0);
        ptr(p, scratch + 16, 4096);
        requirements(p, scratch, 0x30000000, 0x3001ffff, 0);
        assert_eq!(
            alloc(
                p,
                &mut t,
                scratch,
                scratch + 16,
                mem::RESERVE,
                prot::READWRITE,
                scratch + 64,
                1
            ),
            STATUS_SUCCESS
        );
        assert_eq!(get(p, scratch), 0x30010000);
        assert_eq!(p.space.u32(0x30000000).unwrap(), 0x12345678);
        ptr(p, scratch, 0);
        requirements(p, scratch, 0x2000000, 0x1ffffff, 0);
        assert_eq!(
            alloc(
                p,
                &mut t,
                scratch,
                scratch + 16,
                mem::RESERVE,
                0,
                scratch + 64,
                1
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            invoke(
                p,
                &mut t,
                &[
                    0,
                    scratch,
                    scratch + 16,
                    mem::RESERVE.into(),
                    prot::READWRITE.into(),
                    scratch + 64,
                    1
                ]
            ),
            STATUS_INVALID_HANDLE
        );
        let guard = scratch + PAGE_SIZE;
        ptr(p, guard, 4096);
        p.vm.protect(guard, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        assert_eq!(
            alloc(p, &mut t, 0, guard, 0, 0, scratch + 64, 1),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            p.vm.query(guard).unwrap().protect & prot::GUARD,
            if arch == WinArch::X86 { 0 } else { prot::GUARD }
        );
    }
}

#[test]
fn wow64_allocate_ex_large_address_aware_alignment_uses_guest_image_policy() {
    use crate::user::image::pe::IMAGE_FILE_LARGE_ADDRESS_AWARE;
    for large in [false, true] {
        let mut image =
            include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
                .to_vec();
        let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
        let mut flags = u16::from_le_bytes(image[pe + 22..pe + 24].try_into().unwrap());
        if large {
            flags |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
        } else {
            flags &= !IMAGE_FILE_LARGE_ADDRESS_AWARE;
        }
        image[pe + 22..pe + 24].copy_from_slice(&flags.to_le_bytes());
        let config =
            WindowsConfig::embedded("C:\\app\\allocation-range.exe", vec![], vec![], 0).unwrap();
        let mut process =
            crate::user::windows::process::WindowsProcess::spawn_image(config, image).unwrap();
        let p = process.state_mut();
        let module = p.modules.by_name("ntdll.dll").unwrap();
        p.modules.nt_services = Some((
            module,
            table(WinArch::X86, "NtAllocateVirtualMemoryEx", 0x78),
        ));
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let scratch =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        ptr(p, scratch, 0);
        ptr(p, scratch + 16, 4096);
        requirements(p, scratch, 0, 0, 0x80000000);
        assert_eq!(
            alloc(
                p,
                &mut t,
                scratch,
                scratch + 16,
                mem::RESERVE,
                prot::READWRITE,
                scratch + 64,
                1
            ),
            if large {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_PARAMETER
            }
        );
        if large {
            assert_eq!(get(p, scratch), 0x80000000);
            assert_eq!(p.vm.query(0x80000000).unwrap().state, mem::RESERVE);
        } else {
            assert_eq!(get(p, scratch), 0);
        }
    }
}

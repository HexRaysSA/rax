//! Class4 input/output behavior and guest residency, independently observed.
use super::*;

fn entries(p: &Proc, out: u64, addresses: &[u64]) {
    let width = p.arch.ptr_size();
    for (index, &address) in addresses.iter().enumerate() {
        let at = out + index as u64 * width * 2;
        p.space.wptr(at, width, address).unwrap();
        p.space.wptr(at + width, width, u64::MAX).unwrap();
    }
}

#[test]
fn native_working_set_query_observes_lazy_residency_without_faulting_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let target =
            p.vm.allocate(
                None,
                PAGE_SIZE * 2,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let out = base + 128;
        let width = arch.ptr_size();
        entries(p, out, &[target, target + PAGE_SIZE]);
        assert!(!p.space.is_resident(target));
        assert_eq!(
            query(p, &mut t, 0, 4, out, width * 4, base + 256),
            STATUS_SUCCESS
        );
        assert_eq!(read_ptr(p, out), target);
        assert_eq!(read_ptr(p, out + width), 0);
        assert!(!p.space.is_resident(target));
        p.space.w8(target, 1).unwrap();
        entries(p, out, &[target + 1, target + PAGE_SIZE]);
        assert_eq!(
            query(p, &mut t, 0, 4, out, width * 4, base + 256),
            STATUS_SUCCESS
        );
        assert_eq!(read_ptr(p, out + width), 0x0500_0041);
        assert_eq!(read_ptr(p, out + width * 3), 0);
        assert_eq!(read_ptr(p, base + 256), width * 4);
        assert!(!p.space.is_resident(target + PAGE_SIZE));
    }
}

#[test]
fn native_working_set_protection_guards_and_decommit_observe_current_guest_state() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let target =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.w8(target, 1).unwrap();
        let width = arch.ptr_size();
        for protect in [
            prot::READONLY,
            prot::READWRITE,
            prot::EXECUTE,
            prot::EXECUTE_READ,
            prot::EXECUTE_READWRITE,
            prot::READWRITE | prot::NOCACHE,
            prot::READWRITE | prot::GUARD,
            prot::NOACCESS,
        ] {
            p.vm.protect(target, PAGE_SIZE, protect).unwrap();
            entries(p, base + 128, &[target + 1]);
            assert_eq!(
                query(p, &mut t, 0, 4, base + 128, width * 2, 0),
                STATUS_SUCCESS
            );
            let expected = if protect & (prot::GUARD | prot::NOACCESS) != 0 {
                0x0540_0000
            } else {
                0x0500_0001 | (u64::from(protect) << 4)
            };
            assert_eq!(
                read_ptr(p, base + 128 + width),
                expected,
                "{arch}/{protect:#x}"
            );
            assert!(p.space.is_resident(target));
            assert_eq!(p.vm.query(target).unwrap().protect, protect);
        }
        p.vm.free(target, PAGE_SIZE, mem::DECOMMIT).unwrap();
        entries(p, base + 128, &[target]);
        assert_eq!(
            query(p, &mut t, 0, 4, base + 128, width * 2, 0),
            STATUS_SUCCESS
        );
        assert_eq!(read_ptr(p, base + 128 + width), 0);
        assert!(!p.space.is_resident(target));
    }
}

#[test]
fn native_working_set_unmapped_reserved_and_private_image_frames_all_abis() {
    use crate::user::windows::memory::AllocKind;
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let reserved =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE, prot::READWRITE)
                .unwrap()
                .0;
        let width = arch.ptr_size();
        entries(p, base + 128, &[0, 1, arch.ptr(u64::MAX), reserved]);
        assert_eq!(
            query(p, &mut t, 0, 4, base + 128, width * 8, 0),
            STATUS_SUCCESS
        );
        for index in 0..4 {
            assert_eq!(read_ptr(p, base + 128 + (index * 2 + 1) * width), 0);
        }
        for kind in [AllocKind::Image, AllocKind::Mapped] {
            let target =
                p.vm.reserve(None, PAGE_SIZE, prot::EXECUTE_WRITECOPY, kind, false, None)
                    .unwrap();
            p.vm.commit(target, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
            p.vm.poke(target, &[1]).unwrap();
            entries(p, base + 128, &[target]);
            assert_eq!(
                query(p, &mut t, 0, 4, base + 128, width * 2, 0),
                STATUS_SUCCESS
            );
            assert_eq!(read_ptr(p, base + 128 + width), 0x0500_0201);
        }
    }
}

#[test]
fn native_working_set_record_lengths_floor_only_wow_and_preserve_tail_bytes() {
    for arch in WinArch::ALL {
        for extra in [0, 1, 7] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let width = arch.ptr_size();
            let record = width * 2;
            let length = record * 2 + extra;
            entries(p, base + 128, &[0, base]);
            assert_eq!(
                query(p, &mut t, 0, 4, base + 128, length, base + 256),
                STATUS_SUCCESS
            );
            assert_eq!(read_ptr(p, base + 128 + width), 0);
            assert_eq!(read_ptr(p, base + 128 + width * 3), 0x0500_0041);
            assert_eq!(
                read_ptr(p, base + 256),
                if arch == WinArch::X86 {
                    record * 2
                } else {
                    length
                }
            );
            assert_eq!(p.space.u8(base + 128 + record * 2).unwrap(), 0xA5);
        }
        for length in [0, 1, arch.ptr_size() * 2 - 1] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            assert_eq!(
                query(p, &mut t, 0, 4, 1, length, base + 256),
                STATUS_INFO_LENGTH_MISMATCH
            );
            assert_eq!(p.space.u32(base + 256).unwrap(), 0xA5A5_A5A5);
        }
    }
}

#[test]
fn native_working_set_incomplete_last_record_crosses_noaccess_or_guard_only_native() {
    for arch in WinArch::ALL {
        for guard in [false, true] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let record = arch.ptr_size() * 2;
            let out = base + PAGE_SIZE - record;
            entries(p, out, &[base]);
            p.vm.protect(
                base + PAGE_SIZE,
                PAGE_SIZE,
                if guard {
                    prot::READWRITE | prot::GUARD
                } else {
                    prot::NOACCESS
                },
            )
            .unwrap();
            assert_eq!(
                query(p, &mut t, 0, 4, out, record + 1, base + 128),
                if arch == WinArch::X86 {
                    STATUS_SUCCESS
                } else if guard {
                    STATUS_GUARD_PAGE_VIOLATION
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            );
            assert_eq!(
                p.vm.query(base + PAGE_SIZE).unwrap().protect & prot::GUARD != 0,
                guard && arch == WinArch::X86
            );
            if arch == WinArch::X86 {
                assert_eq!(read_ptr(p, base + 128), record);
            }
        }
    }
}

fn with_handle(
    p: &mut Proc,
    t: &mut Thread,
    handle: u64,
    out: u64,
    length: u64,
    returned: u64,
) -> u32 {
    arguments(p, t, &[handle, 0, 4, out, length, returned]);
    assert_eq!(dispatch(p, t), Outcome::Continue);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_working_set_input_capture_precedes_wow_handle_check_and_output_copy() {
    for arch in WinArch::ALL {
        let record = arch.ptr_size() * 2;
        for protect in [
            prot::READONLY,
            prot::NOACCESS,
            prot::READWRITE | prot::GUARD,
        ] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let out = base + PAGE_SIZE;
            entries(p, out, &[base]);
            p.vm.protect(out, PAGE_SIZE, protect).unwrap();
            let expected = if protect & prot::GUARD != 0 {
                STATUS_GUARD_PAGE_VIOLATION
            } else if protect == prot::READONLY && arch == WinArch::X86 {
                STATUS_INVALID_HANDLE
            } else {
                STATUS_ACCESS_VIOLATION
            };
            assert_eq!(with_handle(p, &mut t, 0, out, record, base + 256), expected);
            assert_eq!(p.space.u32(base + 256).unwrap(), 0xA5A5_A5A5);
        }
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        assert_eq!(
            with_handle(p, &mut t, 0, 0, record, 0),
            STATUS_ACCESS_VIOLATION
        );
        entries(p, base + 128, &[base]);
        assert_eq!(
            with_handle(p, &mut t, arch.ptr(u64::MAX - 1), base + 128, record, 0),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            query(p, &mut t, 0, 4, base + 129, record, 0),
            if arch == WinArch::X86 {
                STATUS_SUCCESS
            } else {
                STATUS_DATATYPE_MISALIGNMENT
            }
        );
    }
}

#[test]
fn native_working_set_query_rights_closed_handle_and_failure_length_all_abis() {
    for arch in WinArch::ALL {
        for access in [0, 0x10, 0x400, 0x1000, 0x1010] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let object = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            let handle = p.objects.open_access(object, false, access).unwrap();
            let record = arch.ptr_size() * 2;
            entries(p, base + 128, &[base]);
            let status = with_handle(p, &mut t, handle.into(), base + 128, record, base + 256);
            assert_eq!(
                status,
                if access & 0x1400 != 0 {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_DENIED
                }
            );
            assert_eq!(
                p.space.u32(base + 256).unwrap(),
                if status == STATUS_SUCCESS {
                    record as u32
                } else {
                    0xA5A5_A5A5
                }
            );
            p.objects.close(handle.into()).unwrap();
            assert_eq!(
                with_handle(p, &mut t, handle.into(), base + 128, record, 0),
                STATUS_INVALID_HANDLE
            );
        }
    }
}

#[test]
fn native_working_set_return_length_probe_guard_order_and_shared_alias_all_abis() {
    for arch in WinArch::ALL {
        for mode in 0..5 {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let out = base + PAGE_SIZE;
            let ret = if mode >= 3 {
                out + if mode == 3 { 64 } else { 0 }
            } else {
                base + PAGE_SIZE * 2
            };
            let width = arch.ptr_size();
            entries(p, out, &[base]);
            if mode != 0 {
                p.vm.protect(out, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            if mode < 3 {
                p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            let success = arch == WinArch::X86 && (mode == 0 || mode >= 3);
            assert_eq!(
                query(p, &mut t, 0, 4, out, width * 2, ret),
                if success {
                    STATUS_SUCCESS
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                }
            );
            assert_eq!(p.vm.query(out).unwrap().protect & prot::GUARD, 0);
            if mode < 3 {
                assert_eq!(
                    p.vm.query(ret).unwrap().protect & prot::GUARD != 0,
                    arch != WinArch::X86 && mode != 0
                );
            }
            if success {
                assert_eq!(read_ptr(p, out), base);
                assert_eq!(read_ptr(p, out + width), 0x0500_0041);
                if mode != 4 {
                    assert_eq!(p.space.u32(ret).unwrap(), 0xA5A5_A5A5);
                }
            }
        }
        for bad_return in [0, 1] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            entries(p, base + 128, &[base]);
            assert_eq!(
                query(p, &mut t, 0, 4, base + 128, arch.ptr_size() * 2, bad_return),
                if bad_return == 0 || arch == WinArch::X86 {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            );
        }
    }
}

#[test]
fn native_working_set_successful_return_alias_overwrites_record_last_all_abis() {
    for arch in WinArch::ALL {
        for offset in [0, arch.ptr_size(), arch.ptr_size() * 3] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let out = base + 128;
            let width = arch.ptr_size();
            entries(p, out, &[base, base + PAGE_SIZE]);
            assert_eq!(
                query(p, &mut t, 0, 4, out, width * 4, out + offset),
                STATUS_SUCCESS
            );
            assert_eq!(read_ptr(p, out + offset), width * 4);
            if offset != 0 {
                assert_eq!(read_ptr(p, out), base);
            }
        }
    }
}

#[test]
fn native_working_set_early_bounds_and_guest_conversion_budget_all_abis() {
    for arch in WinArch::ALL {
        for length_failure in [false, true] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let out = base + PAGE_SIZE;
            let ret = base + PAGE_SIZE * 2;
            p.vm.protect(out, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            let record = arch.ptr_size() * 2;
            let high = p.vm.high();
            assert_eq!(
                query(
                    p,
                    &mut t,
                    high,
                    4,
                    out,
                    if length_failure { record - 1 } else { record },
                    ret
                ),
                if length_failure {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_INVALID_PARAMETER
                }
            );
            assert_ne!(p.vm.query(out).unwrap().protect & prot::GUARD, 0);
            assert_eq!(
                p.vm.query(ret).unwrap().protect & prot::GUARD != 0,
                arch != WinArch::X86
            );
        }
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        for length in [
            arch.ptr(u64::MAX),
            if arch.is64() { 1 << 32 } else { 1 << 31 },
        ] {
            assert_eq!(
                query(p, &mut t, 0, 4, 1, length, 0),
                if arch == WinArch::X86 {
                    STATUS_NO_MEMORY
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                }
            );
        }
        if arch == WinArch::X86 {
            let count = p.vm.commit_limit() / 16;
            let length = count * 8;
            assert_eq!(
                query(p, &mut t, 0, 4, 0, length, 0),
                STATUS_ACCESS_VIOLATION
            );
            assert_eq!(query(p, &mut t, 0, 4, 0, length + 8, 0), STATUS_NO_MEMORY);
        }
        assert_eq!(p.space.u8(base).unwrap(), 0xA5);
    }
}

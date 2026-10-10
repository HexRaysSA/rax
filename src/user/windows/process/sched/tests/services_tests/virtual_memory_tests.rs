//! Native virtual-memory query ABI and fault priority, from retained oracles.
use super::*;
use crate::user::windows::nt::status::*;

#[cfg(windows)]
#[path = "virtual_memory_leaf_tests.rs"]
mod installed;

#[path = "working_set_tests.rs"]
mod working_set;

fn arguments(p: &mut Proc, t: &mut Thread, args: &[u64]) {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (index, &value) in args.iter().enumerate() {
                p.space
                    .w32(sp + 8 + index as u64 * 4, value as u32)
                    .unwrap();
            }
            t.cpu.set_gpr(0, 0x23);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x23);
            t.cpu.set_gpr(1, 0x1234_0004);
            for (index, &value) in args.iter().enumerate() {
                if index < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][index], value);
                } else {
                    p.space.w64(sp + 8 + index as u64 * 8, value).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (index, &value) in args.iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
    }
}
fn dispatch(p: &mut Proc, t: &mut Thread) -> Outcome {
    if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x23))
    }
}
fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtQueryVirtualMemory", 0x23);
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
    (process, t, base)
}
fn query(
    p: &mut Proc,
    t: &mut Thread,
    address: u64,
    class: u32,
    out: u64,
    length: u64,
    returned: u64,
) -> u32 {
    arguments(
        p,
        t,
        &[
            p.arch.ptr(u64::MAX),
            address,
            class.into(),
            out,
            length,
            returned,
        ],
    );
    assert_eq!(dispatch(p, t), Outcome::Continue);
    assert!(t.frames.is_empty());
    t.cpu.gpr(0) as u32
}
#[test]
fn native_virtual_memory_image_query_private_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        assert_eq!(
            query(p, &mut t, base, 6, base + 128, 64, base + 256),
            STATUS_SUCCESS
        );
        let size = if arch == WinArch::X86 { 12 } else { 24 };
        assert_eq!(p.space.bytes(base + 128, size).unwrap(), vec![0; size]);
        assert_eq!(p.space.u32(base + 256).unwrap(), size as u32);
        assert_eq!(p.space.u8(base + 128 + size as u64).unwrap(), 0xA5);
    }
}

#[test]
fn native_virtual_memory_shared_guard_disables_wow_length_copy_before_output() {
    for arch in WinArch::ALL {
        for class in [0, 6] {
            for alias in [0, 64] {
                let (mut process, mut t, base) = setup(arch);
                let p = process.state_mut();
                let out = base + PAGE_SIZE;
                p.vm.protect(out, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                assert_eq!(
                    query(p, &mut t, base, class, out, 64, out + alias),
                    if arch == WinArch::X86 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_GUARD_PAGE_VIOLATION
                    }
                );
                assert_eq!(p.vm.query(out).unwrap().protect & prot::GUARD, 0);
                if arch == WinArch::X86 {
                    assert_eq!(read_ptr(p, out), if class == 0 { base } else { 0 });
                    if alias != 0 {
                        assert_eq!(p.space.u32(out + alias).unwrap(), 0xA5A5_A5A5);
                    }
                } else {
                    assert_eq!(p.space.u8(out).unwrap(), 0xA5);
                }
            }
        }
    }
}

fn read_ptr(p: &Proc, at: u64) -> u64 {
    if p.arch == WinArch::X86 {
        p.space.u32(at).unwrap().into()
    } else {
        p.space.u64(at).unwrap()
    }
}
fn required(arch: WinArch, class: u32) -> u64 {
    match (arch, class) {
        (WinArch::X86, 0) => 28,
        (_, 0) => 48,
        (WinArch::X86, 6) => 12,
        _ => 24,
    }
}

#[test]
fn native_virtual_memory_basic_regions_image_metadata_and_padding_all_abis() {
    use crate::user::windows::memory::AllocKind;
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let image =
            p.vm.reserve(
                None,
                PAGE_SIZE * 3,
                prot::EXECUTE_WRITECOPY,
                AllocKind::Image,
                false,
                None,
            )
            .unwrap();
        p.vm.commit(image, PAGE_SIZE * 3, prot::EXECUTE_READ)
            .unwrap();
        let width = if arch.is64() { 8 } else { 4 };
        let out = base + 128;
        assert_eq!(
            query(p, &mut t, image + PAGE_SIZE + 1, 6, out, 64, base + 256),
            STATUS_SUCCESS
        );
        assert_eq!(read_ptr(p, out), image);
        assert_eq!(read_ptr(p, out + width), PAGE_SIZE * 3);
        assert_eq!(p.space.u32(out + width * 2).unwrap(), 0); // guest integrity unchecked; no extension
        assert_eq!(read_ptr(p, base + 256), required(arch, 6));
        assert_eq!(
            query(p, &mut t, image + PAGE_SIZE + 1, 0, out, 64, base + 256),
            STATUS_SUCCESS
        );
        assert_eq!(read_ptr(p, out), image + PAGE_SIZE);
        assert_eq!(read_ptr(p, out + width), image);
        assert_eq!(
            p.space.u32(out + width * 2).unwrap(),
            prot::EXECUTE_WRITECOPY
        );
        let size_at = if arch.is64() { 24 } else { 12 };
        assert_eq!(read_ptr(p, out + size_at), PAGE_SIZE * 2);
        assert_eq!(p.space.u32(out + size_at + width).unwrap(), mem::COMMIT);
        assert_eq!(
            p.space.u32(out + size_at + width + 4).unwrap(),
            prot::EXECUTE_READ
        );
        assert_eq!(p.space.u32(out + size_at + width + 8).unwrap(), mem::IMAGE);
        if arch.is64() {
            assert_eq!(p.space.u32(out + 20).unwrap(), 0); // PartitionId/padding
            assert_eq!(p.space.u32(out + 44).unwrap(), 0);
        }
        assert_eq!(read_ptr(p, base + 256), required(arch, 0));
        p.vm.protect(image + PAGE_SIZE * 2, PAGE_SIZE, prot::READONLY)
            .unwrap();
        assert_eq!(
            query(p, &mut t, image + PAGE_SIZE, 0, out, 64, 0),
            STATUS_SUCCESS
        );
        assert_eq!(read_ptr(p, out + size_at), PAGE_SIZE);
        p.vm.release(image).unwrap();
        assert_eq!(
            query(p, &mut t, image, 6, out, 64, 0),
            STATUS_INVALID_ADDRESS
        );
    }
}

#[test]
fn native_virtual_memory_free_reserved_mapped_and_no_target_read_all_abis() {
    use crate::user::windows::memory::AllocKind;
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let out = base + 128;
        assert_eq!(query(p, &mut t, 0, 0, out, 64, 0), STATUS_SUCCESS);
        assert_eq!(read_ptr(p, out), 0);
        assert_eq!(read_ptr(p, out + if arch.is64() { 8 } else { 4 }), 0);
        let state_at = if arch.is64() { 32 } else { 16 };
        assert_eq!(p.space.u32(out + state_at).unwrap(), mem::FREE);
        assert_eq!(p.space.u32(out + state_at + 4).unwrap(), prot::NOACCESS);
        assert_eq!(p.space.u32(out + state_at + 8).unwrap(), 0);
        assert_eq!(query(p, &mut t, 1, 6, out, 64, 0), STATUS_INVALID_ADDRESS);
        for kind in [AllocKind::Private, AllocKind::Mapped] {
            let address =
                p.vm.reserve(None, PAGE_SIZE, prot::READWRITE, kind, false, None)
                    .unwrap();
            assert_eq!(query(p, &mut t, address + 1, 6, out, 64, 0), STATUS_SUCCESS);
            assert_eq!(
                p.space.bytes(out, required(arch, 6) as usize).unwrap(),
                vec![0; required(arch, 6) as usize]
            );
            p.vm.commit(address, PAGE_SIZE, prot::NOACCESS).unwrap();
            assert_eq!(query(p, &mut t, address, 6, out, 64, 0), STATUS_SUCCESS);
            p.vm.protect(address, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            for class in [0, 6] {
                assert_eq!(query(p, &mut t, address, class, out, 64, 0), STATUS_SUCCESS);
            }
            assert_ne!(p.vm.query(address).unwrap().protect & prot::GUARD, 0);
        }
    }
}

#[test]
fn native_virtual_memory_class_length_bound_priority_and_wow_optional_guards() {
    for arch in WinArch::ALL {
        for (class, length, address, status) in [
            (u32::MAX, 0, arch.ptr(u64::MAX), STATUS_INVALID_INFO_CLASS),
            (6, 0, arch.ptr(u64::MAX), STATUS_INFO_LENGTH_MISMATCH),
            (0, 1, arch.ptr(u64::MAX), STATUS_INFO_LENGTH_MISMATCH),
            (6, 64, arch.ptr(u64::MAX), STATUS_INVALID_PARAMETER),
        ] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let ret = base + PAGE_SIZE;
            p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            assert_eq!(query(p, &mut t, address, class, 1, length, ret), status);
            assert_eq!(
                p.vm.query(ret).unwrap().protect & prot::GUARD != 0,
                arch != WinArch::X86
            );
            assert_eq!(p.space.u8(base + 128).unwrap(), 0xA5);
        }
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        arguments(p, &mut t, &[arch.ptr(u64::MAX), base, 2, base + 128, 64, 0]);
        assert!(
            matches!(dispatch(p, &mut t), Outcome::Fail(message) if message.contains("NtQueryVirtualMemory class 2"))
        );
    }
}

#[test]
fn native_virtual_memory_null_unaligned_outputs_and_return_length_all_abis() {
    for arch in WinArch::ALL {
        for class in [0, 6] {
            for offset in [0, 1, 2, 4] {
                let (mut process, mut t, base) = setup(arch);
                let p = process.state_mut();
                let out = if offset == 0 { 0 } else { base + 128 + offset };
                let expected = if arch == WinArch::X86 {
                    STATUS_SUCCESS
                } else if offset == 0 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                };
                assert_eq!(query(p, &mut t, base, class, out, 64, base + 257), expected);
                if expected == STATUS_SUCCESS {
                    assert_eq!(read_ptr(p, base + 257), required(arch, class));
                }
            }
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            assert_eq!(
                query(p, &mut t, base, class, base + 128, 64, base + 257),
                STATUS_SUCCESS
            );
            assert_eq!(read_ptr(p, base + 257), required(arch, class));
        }
    }
}

#[test]
fn native_virtual_memory_native_extent_wow_prefix_and_pointer_sized_lengths() {
    for arch in WinArch::ALL {
        for class in [0, 6] {
            for guard in [false, true] {
                let (mut process, mut t, base) = setup(arch);
                let p = process.state_mut();
                let out = base + PAGE_SIZE - required(arch, class);
                let protection = if guard {
                    prot::READWRITE | prot::GUARD
                } else {
                    prot::NOACCESS
                };
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, protection)
                    .unwrap();
                let expected = if arch == WinArch::X86 {
                    STATUS_SUCCESS
                } else if guard {
                    STATUS_GUARD_PAGE_VIOLATION
                } else {
                    STATUS_ACCESS_VIOLATION
                };
                assert_eq!(
                    query(p, &mut t, base, class, out, required(arch, class) + 8, 0),
                    expected
                );
                if guard {
                    assert_eq!(
                        p.vm.query(base + PAGE_SIZE).unwrap().protect & prot::GUARD != 0,
                        arch == WinArch::X86
                    );
                }
            }
            for length in [
                arch.ptr(u64::MAX),
                if arch.is64() { 1 << 32 } else { 1 << 31 },
            ] {
                let (mut process, mut t, base) = setup(arch);
                let p = process.state_mut();
                assert_eq!(
                    query(p, &mut t, base, class, base + 128, length, 0),
                    if arch == WinArch::X86 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }
                );
            }
        }
    }
}

#[test]
fn native_virtual_memory_return_length_faults_and_two_guard_order_all_abis() {
    for arch in WinArch::ALL {
        for class in [0, 6] {
            for output_guard in [false, true] {
                let (mut process, mut t, base) = setup(arch);
                let p = process.state_mut();
                let ret = base + PAGE_SIZE * 2;
                let out = if output_guard {
                    base + PAGE_SIZE
                } else {
                    base + 128
                };
                p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                if output_guard {
                    p.vm.protect(out, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                        .unwrap();
                }
                let expected = if arch == WinArch::X86 && !output_guard {
                    STATUS_SUCCESS
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                };
                assert_eq!(query(p, &mut t, base, class, out, 64, ret), expected);
                assert_eq!(
                    p.vm.query(ret).unwrap().protect & prot::GUARD != 0,
                    arch != WinArch::X86 && output_guard
                );
                if output_guard {
                    assert_eq!(p.vm.query(out).unwrap().protect & prot::GUARD, 0);
                }
            }
        }
    }
}

#[test]
fn native_virtual_memory_return_length_alias_is_published_last_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        for class in [0, 6] {
            assert_eq!(
                query(p, &mut t, base, class, base + 128, 64, base + 128),
                STATUS_SUCCESS
            );
            assert_eq!(read_ptr(p, base + 128), required(arch, class));
        }
    }
}

#[test]
fn native_virtual_memory_typed_process_rights_lifetime_and_remote_frontier() {
    for arch in WinArch::ALL {
        for access in [0, 0x10, 0x400, 0x1000, 0x1010] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let object = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            let handle = p.objects.open_access(object, false, access).unwrap();
            for class in [0, 6] {
                arguments(
                    p,
                    &mut t,
                    &[handle.into(), base, class, base + 128, 64, base + 256],
                );
                assert_eq!(dispatch(p, &mut t), Outcome::Continue);
                assert_eq!(
                    t.cpu.gpr(0) as u32,
                    if access & 0x1400 != 0 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_ACCESS_DENIED
                    }
                );
                if access & 0x1400 == 0 && arch == WinArch::X86 {
                    assert_eq!(read_ptr(p, base + 256), required(arch, class as u32));
                }
            }
            p.objects.close(handle.into()).unwrap();
            arguments(p, &mut t, &[handle.into(), base, 6, base + 128, 64, 0]);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0) as u32, STATUS_INVALID_HANDLE);
        }
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let event = p.objects.create(Object::Event {
            manual: true,
            signaled: 0,
        });
        let event = p.objects.open(event, false);
        for handle in [0, event.into(), arch.ptr(u64::MAX - 1)] {
            arguments(p, &mut t, &[handle, base, 6, base + 128, 64, 0]);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(
                t.cpu.gpr(0) as u32,
                if handle == 0 {
                    STATUS_INVALID_HANDLE
                } else {
                    STATUS_OBJECT_TYPE_MISMATCH
                }
            );
        }
        let remote = p.objects.create(Object::Process {
            pid: p.pid + 1,
            exit_code: None,
        });
        let remote = p.objects.open_access(remote, false, 0x1400).unwrap();
        arguments(p, &mut t, &[remote.into(), base, 6, base + 128, 64, 0]);
        assert!(
            matches!(dispatch(p, &mut t), Outcome::Fail(message) if message.contains("another process"))
        );
    }
}

//! ProcessImageFileNameWin32 writes a caller-width record and a counted path.

use super::super::registry_tests::call;
use super::{WinArch, setup};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

const QUERY: &str = "NtQueryInformationProcess";
const CLASS: u64 = 43;
const SENTINEL: u32 = 0xa5a5_a5a5;

#[test]
fn native_process_image_name_uses_loader_path_and_caller_width() {
    let evidence = r"C:\Win Tools\λ-🪟.exe";
    let units: Vec<_> = evidence.encode_utf16().collect();
    let bytes = (2 * units.len()) as u16;
    for arch in WinArch::ALL {
        let (mut process, mut thread, output) = setup(arch);
        let p = process.state_mut();
        let width = arch.ptr_size();
        let header = 2 * width;
        let required = header + u64::from(bytes) + 2;
        let returned = output + 0x120;
        p.modules.list[0].path = evidence.into();
        // Corrupt the guest-writable descriptor; the selected image is independent of it.
        let parameters = p.current_parameters().unwrap();
        p.space
            .w16(parameters + offsets(arch).pp_image_path_name, 1)
            .unwrap();
        let current = arch.ptr(CURRENT_PROCESS);
        for length in [0, header, required - 1] {
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    QUERY,
                    &[current, CLASS, output, length, returned]
                ),
                STATUS_INFO_LENGTH_MISMATCH
            );
            assert_eq!(p.space.u32(returned).unwrap(), required as u32);
            assert_eq!(p.space.bytes(output, 128).unwrap(), [0xa5; 128]);
        }
        let object = p.objects.create(Object::Process {
            pid: p.pid,
            exit_code: None,
        });
        for right in [0x1000, 0x0400] {
            let handle = u64::from(p.objects.open_access(object, false, right).unwrap());
            p.space.wr(output, &[0xa5; 128]).unwrap();
            let offset = if width == 4 { 1 } else { 4 };
            let address = output + offset;
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    QUERY,
                    &[handle, CLASS, address, required + 1, returned + 1]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u16(address).unwrap(), bytes);
            assert_eq!(p.space.u16(address + 2).unwrap(), bytes + 2);
            if width == 8 {
                assert_eq!(p.space.u32(address + 4).unwrap(), SENTINEL);
            }
            assert_eq!(
                p.space.ptr(address + width, width).unwrap(),
                address + header
            );
            assert_eq!(
                p.space.wunits(address + header, units.len()).unwrap(),
                units
            );
            assert_eq!(p.space.u16(address + required - 2).unwrap(), 0);
            assert_eq!(p.space.u8(address + required).unwrap(), 0xa5);
            assert_eq!(p.space.u32(returned + 1).unwrap(), required as u32);
        }
        let denied = u64::from(p.objects.open_access(object, false, 0x10).unwrap());
        for (handle, expected) in [
            (0, STATUS_INVALID_HANDLE),
            (arch.ptr(CURRENT_THREAD), STATUS_OBJECT_TYPE_MISMATCH),
            (denied, STATUS_ACCESS_DENIED),
        ] {
            p.space.w32(returned, SENTINEL).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    QUERY,
                    &[handle, CLASS, output, required, returned]
                ),
                expected
            );
            assert_eq!(
                p.space.u32(returned).unwrap(),
                SENTINEL - u32::from(width == 4) * 8
            );
        }
        assert_eq!(
            call(
                p,
                &mut thread,
                QUERY,
                &[current, CLASS, output, required, output]
            ),
            STATUS_SUCCESS
        );
        let alias = if width == 4 {
            u32::from(bytes) | (u32::from(bytes + 2) << 16)
        } else {
            required as u32
        };
        assert_eq!(p.space.u32(output).unwrap(), alias);
    }
}

#[test]
fn native_process_image_name_preserves_abi_specific_buffer_fault_order() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, output) = setup(arch);
        let p = process.state_mut();
        let wow64 = arch == WinArch::X86;
        let current = arch.ptr(CURRENT_PROCESS);
        let returned =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        assert_eq!(
            call(p, &mut thread, QUERY, &[current, CLASS, 0, 0, returned]),
            STATUS_INFO_LENGTH_MISMATCH
        );
        let required = u64::from(p.space.u32(returned).unwrap());
        p.space.w32(returned, SENTINEL).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                QUERY,
                &[current, CLASS, 0, required, returned]
            ),
            if wow64 {
                STATUS_INVALID_PARAMETER
            } else {
                STATUS_ACCESS_VIOLATION
            }
        );
        assert_eq!(
            p.space.u32(returned).unwrap(),
            if wow64 { required as u32 } else { SENTINEL }
        );

        p.space.w32(returned, SENTINEL).unwrap();
        p.vm.protect(output, PAGE_SIZE, prot::READONLY | prot::GUARD)
            .unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                QUERY,
                &[current, CLASS, output, required - 1, returned]
            ),
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            p.vm.query(output).unwrap().protect,
            prot::READONLY | prot::GUARD
        );
        p.space.w32(returned, SENTINEL).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                QUERY,
                &[current, CLASS, output, required, returned]
            ),
            if wow64 {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            }
        );
        assert_eq!(
            p.space.u32(returned).unwrap(),
            if wow64 { required as u32 } else { SENTINEL }
        );
        assert_eq!(
            p.vm.query(output).unwrap().protect,
            if wow64 {
                prot::READONLY | prot::GUARD
            } else {
                prot::READONLY
            }
        );
        p.vm.protect(output, PAGE_SIZE, prot::READWRITE).unwrap();

        for mode in [prot::READWRITE, prot::READONLY] {
            p.space.w32(returned, SENTINEL).unwrap();
            p.vm.protect(returned, PAGE_SIZE, mode | prot::GUARD)
                .unwrap();
            let expect = if wow64 && mode == prot::READONLY {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            };
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    QUERY,
                    &[0, CLASS, output, required, returned]
                ),
                expect
            );
            assert_eq!(p.vm.query(returned).unwrap().protect, mode);
            p.vm.protect(returned, PAGE_SIZE, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.u32(returned).unwrap(),
                if wow64 && mode == prot::READWRITE {
                    SENTINEL - 8
                } else {
                    SENTINEL
                }
            );
        }
    }
}

#[test]
fn native_process_image_name_keeps_native_partial_copy_and_guard_order() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, returned) = setup(arch);
        let p = process.state_mut();
        let wow64 = arch == WinArch::X86;
        let name = "x".repeat(39);
        p.modules.list[0].path.clone_from(&name);
        let header = arch.ptr_size() * 2;
        let required = header + 80;
        let current = arch.ptr(CURRENT_PROCESS);
        let (allocation, _) =
            p.vm.allocate(
                None,
                2 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap();
        let second = allocation + PAGE_SIZE;
        let (raw_prefix, path_prefix) = if wow64 { (24, 16) } else { (64, 32) };
        let output = second - raw_prefix;
        p.space.wr(output, &[0xa5; 96]).unwrap();
        p.space.w32(returned, SENTINEL).unwrap();
        p.vm.protect(second, PAGE_SIZE, prot::READONLY | prot::GUARD)
            .unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                QUERY,
                &[current, CLASS, output, required, returned]
            ),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            p.vm.query(second).unwrap().protect,
            prot::READONLY | prot::GUARD
        );
        assert_eq!(
            p.space.u32(returned).unwrap(),
            if wow64 { required as u32 } else { SENTINEL }
        );
        p.vm.protect(second, PAGE_SIZE, prot::READWRITE).unwrap();
        let expected_header = if wow64 { 0x0050_004e } else { SENTINEL };
        assert_eq!(p.space.u32(output).unwrap(), expected_header);
        let copied = p.space.wunits(output + header, path_prefix / 2).unwrap();
        assert_eq!(copied, vec![b'x' as u16; path_prefix / 2]);
        let unwritten = raw_prefix as usize - header as usize - path_prefix;
        assert_eq!(
            p.space
                .bytes(output + header + path_prefix as u64, unwritten + 1)
                .unwrap(),
            vec![0xa5; unwritten + 1]
        );
    }
}

//! EC attribute admission is process-scoped; capture retains its native order.
use super::*;
use crate::user::windows::object_namespace::CodeBitmapPlan;

#[cfg(windows)]
#[path = "allocate_ec_leaf_tests.rs"]
mod installed;

const BITMAP: u64 = 0x7df4_51a1_0000;

fn enable(p: &mut Proc) {
    p.vm.publish_ec_image(
        &CodeBitmapPlan {
            base: Some(BITMAP),
            ranges: vec![],
        },
        0,
        0,
    )
    .unwrap();
}

#[test]
fn ec_attribute_checks_process_handle_before_process_view_and_protection() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, scratch) = setup(arch);
        let p = process.state_mut();
        ptr(p, scratch, 0);
        ptr(p, scratch + 16, 4096);
        p.space.w64(scratch + 64, 5).unwrap();
        p.space.w64(scratch + 72, 0x40).unwrap();
        for (handle, expected) in [
            (arch.ptr(u64::MAX - 41), STATUS_INVALID_HANDLE),
            (arch.ptr(u64::MAX - 1), STATUS_OBJECT_TYPE_MISMATCH),
            (arch.ptr(u64::MAX), STATUS_INVALID_PARAMETER),
        ] {
            let sp = thread.cpu.sp();
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    &[
                        handle,
                        scratch,
                        scratch + 16,
                        mem::RESERVE.into(),
                        prot::READWRITE.into(),
                        scratch + 64,
                        1
                    ]
                ),
                expected
            );
            thread.cpu.set_sp(sp);
            assert_eq!(get(p, scratch), 0);
            assert_eq!(get(p, scratch + 16), 4096);
        }
    }
}

#[test]
fn unsupported_attribute_capture_precedes_invalid_process_handle_all_abis() {
    for arch in WinArch::ALL {
        for value in [0x80u64, 0xc0, 0x100, 1u64 << 63, (1u64 << 63) | 0x40] {
            let (mut process, mut thread, scratch) = setup(arch);
            let p = process.state_mut();
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, 4096);
            p.space.w64(scratch + 64, 5).unwrap();
            p.space.w64(scratch + 72, value).unwrap();
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    &[
                        0,
                        scratch,
                        scratch + 16,
                        mem::RESERVE.into(),
                        prot::EXECUTE_READWRITE.into(),
                        scratch + 64,
                        1
                    ]
                ),
                if matches!(value, 0x80 | 0xc0) {
                    STATUS_NOT_SUPPORTED
                } else {
                    STATUS_INVALID_PARAMETER
                }
            );
        }
    }
}

#[test]
fn ec_attribute_native_x64_success_and_protection_failures_publish_exact_outputs() {
    for flags in [mem::RESERVE, mem::COMMIT, mem::RESERVE | mem::COMMIT] {
        for protection in [
            0,
            prot::NOACCESS,
            prot::READWRITE,
            prot::EXECUTE,
            prot::EXECUTE_READ,
            prot::EXECUTE_READWRITE,
            prot::EXECUTE_WRITECOPY,
            0x50,
        ] {
            let (mut process, mut thread, scratch) = setup(WinArch::X64);
            let p = process.state_mut();
            enable(p);
            ptr(p, scratch, 0);
            ptr(p, scratch + 16, 0x1001);
            p.space.w64(scratch + 64, 5).unwrap();
            p.space.w64(scratch + 72, 0x40).unwrap();
            let expected = match protection {
                0 | prot::NOACCESS | prot::READWRITE => STATUS_INVALID_PARAMETER,
                prot::EXECUTE_WRITECOPY | 0x50 => STATUS_INVALID_PAGE_PROTECTION,
                _ => STATUS_SUCCESS,
            };
            let before = p.vm.allocations().count();
            assert_eq!(
                alloc(
                    p,
                    &mut thread,
                    scratch,
                    scratch + 16,
                    flags,
                    protection,
                    scratch + 64,
                    1
                ),
                expected,
                "flags={flags:x} protection={protection:x}"
            );
            if expected == STATUS_SUCCESS {
                let base = get(p, scratch);
                assert_ne!(base, 0);
                assert_eq!(get(p, scratch + 16), 8192);
                assert_eq!(p.space.u8(BITMAP + (base >> 15)).unwrap() & 3, 3);
            } else {
                assert_eq!(get(p, scratch), 0);
                assert_eq!(get(p, scratch + 16), 0x1001);
                assert_eq!(p.vm.allocations().count(), before);
            }
        }
    }
}

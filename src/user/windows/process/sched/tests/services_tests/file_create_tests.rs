//! NtCreateFile uses the process service ABI, real host files and native oracles.
use super::file_open_tests::{Harness, selection};
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;

#[path = "file_create_tests/metadata_share.rs"]
mod metadata_share;
#[path = "file_create_tests/null_device.rs"]
mod null_device;
#[path = "file_create_tests/pointers.rs"]
mod pointers;
#[path = "file_create_tests/scalars.rs"]
mod scalars;

fn create(h: &mut Harness, access: u32, disposition: u32) -> u32 {
    h.invoke_api(
        "NtCreateFile",
        &[
            h.base,
            u64::from(access),
            h.attrs(),
            h.base + 4096,
            0,
            0,
            7,
            u64::from(disposition),
            0x60,
            0,
            0,
        ],
    )
}

#[test]
fn native_file_create_dispositions_change_real_contents_and_preserve_read_only_grants() {
    for arch in WinArch::ALL {
        for existing in [false, true] {
            for disposition in 0..6 {
                let mut h = Harness::new(arch);
                h.name("\\??\\C:\\created.dat");
                let path = h.directory.0.join("created.dat");
                if existing {
                    std::fs::write(&path, b"original").unwrap();
                }
                let code = create(&mut h, 0x80100080, disposition);
                let expected = if existing && disposition == 2 {
                    STATUS_OBJECT_NAME_COLLISION
                } else if !existing && matches!(disposition, 1 | 4) {
                    STATUS_OBJECT_NAME_NOT_FOUND
                } else {
                    STATUS_SUCCESS
                };
                assert_eq!(code, expected, "{arch}/{existing}/{disposition}");
                if code == STATUS_SUCCESS {
                    let p = h.process.state_mut();
                    let width = arch.ptr_size();
                    let handle = p.space.ptr(h.base, width).unwrap();
                    assert_eq!(p.objects.access(handle), Some(0x120089));
                    assert_eq!(p.space.ptr(h.base + 4096, width).unwrap(), 0);
                    let information = if !existing {
                        2
                    } else if disposition == 0 {
                        0
                    } else if matches!(disposition, 4 | 5) {
                        3
                    } else {
                        1
                    };
                    assert_eq!(
                        p.space.ptr(h.base + 4096 + width, width).unwrap(),
                        information
                    );
                    p.objects.close(handle).unwrap();
                }
                let actual = std::fs::read(&path).ok();
                let expected = if existing && matches!(disposition, 1..=3) {
                    Some(b"original".to_vec())
                } else if code == STATUS_SUCCESS {
                    Some(Vec::new())
                } else {
                    None
                };
                assert_eq!(actual, expected, "{arch}/{existing}/{disposition}");
            }
        }
    }
}

#[test]
fn native_file_create_selected_library_disposition_cannot_destroy_read_only_authority() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let dir = selection(&mut h);
        h.name("\\??\\C:\\Windows\\System32\\fixture.dll");
        for disposition in [0, 2, 4, 5] {
            assert_eq!(
                create(&mut h, 0x80100080, disposition),
                STATUS_ACCESS_DENIED,
                "{arch}/{disposition}"
            );
            assert_eq!(std::fs::read(dir.join("fixture.dll")).unwrap(), b"native");
        }
        for disposition in [1, 3] {
            assert_eq!(
                create(&mut h, 0x80100080, disposition),
                STATUS_SUCCESS,
                "{arch}/{disposition}"
            );
            let p = h.process.state_mut();
            let handle = p.space.ptr(h.base, arch.ptr_size()).unwrap();
            assert!(p.objects.runtime_library(handle));
            p.objects.close(handle).unwrap();
        }
    }
}

#[test]
fn native_file_create_empty_directory_delete_on_close_retires_owned_directory() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        h.name("\\??\\C:\\temporary-directory");
        assert_eq!(
            h.invoke_api(
                "NtCreateFile",
                &[
                    h.base,
                    0xC0110080,
                    h.attrs(),
                    h.base + 4096,
                    0,
                    0,
                    7,
                    2,
                    0x1021,
                    0,
                    0,
                ]
            ),
            STATUS_SUCCESS,
            "{arch}"
        );
        let path = h.directory.0.join("temporary-directory");
        assert!(path.is_dir());
        let p = h.process.state_mut();
        let handle = p.space.ptr(h.base, arch.ptr_size()).unwrap();
        drop(p.objects.close(handle).unwrap());
        assert!(!path.exists(), "{arch}/final directory close");
    }
}

//! Independent live NT enumeration brackets the installed snapshot acquisition.
use super::*;
use crate::user::windows::registry::{COMMAND_PROCESSOR_KEY, Lookup};
use std::ffi::c_void;
use std::ptr::null_mut;

#[repr(C)]
struct Name {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: *mut c_void,
    name: *mut Name,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenKeyEx(
        out: *mut *mut c_void,
        access: u32,
        attributes: *mut Attributes,
        options: u32,
    ) -> i32;
    fn NtQueryKey(
        key: *mut c_void,
        class: u32,
        out: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtEnumerateKey(
        key: *mut c_void,
        index: u32,
        class: u32,
        out: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(
        key: *mut c_void,
        name: *const u16,
        options: u32,
        access: u32,
        out: *mut *mut c_void,
    ) -> i32;
    fn RegCloseKey(key: *mut c_void) -> i32;
}
struct Owned(*mut c_void);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this real owned key was returned by the successful fixed-path open.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn native(path: &str, view: u32) -> Result<(Vec<u16>, Vec<BasicChild>), u32> {
    let mut text: Vec<_> = path.encode_utf16().collect();
    let length = (text.len() * 2) as u16;
    let mut name = Name {
        length,
        maximum: length,
        buffer: text.as_mut_ptr(),
    };
    let mut attributes = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: null_mut(),
        name: &mut name,
        flags: 0x40,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut key = null_mut();
    // SAFETY: fixed counted UTF-16 path and initialized native attributes live
    // for the call; read/enumerate-only access and exclusive handle output.
    let status = if path == MACHINE_HIVE_KEY {
        // SAFETY: fixed counted path and initialized native attributes; an
        // ordinary owned MACHINE handle avoids the Win32 predefined pseudo-key.
        (unsafe { NtOpenKeyEx(&mut key, 0x20019 | view, &mut attributes, 0) }) as u32
    } else {
        let suffix = path.strip_prefix("\\Registry\\Machine\\").unwrap();
        let suffix: Vec<_> = suffix.encode_utf16().chain(Some(0)).collect();
        // SAFETY: fixed terminated HKLM suffix, fixed read/enumerate access,
        // explicit Win32 view and exclusive output. NT logical opens do not
        // perform the same Win32 redirection; preserve the observed subject.
        let status = unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as *mut c_void,
                suffix.as_ptr(),
                0,
                0x20019 | view,
                &mut key,
            )
        } as u32;
        match status {
            0 => 0,
            2 => STATUS_OBJECT_NAME_NOT_FOUND,
            3 => STATUS_OBJECT_PATH_NOT_FOUND,
            other => panic!("native Win32 view open failed: {path}/{view}/error {other}"),
        }
    };
    if status != 0 {
        assert!(key.is_null());
        return Err(status);
    }
    assert!(!key.is_null());
    let key = Owned(key);
    let mut named = [0u64; 512];
    let mut named_length = 0;
    // SAFETY: live owned key and aligned initialized 4096-byte output.
    assert_eq!(
        unsafe { NtQueryKey(key.0, 3, named.as_mut_ptr().cast(), 4096, &mut named_length) } as u32,
        STATUS_SUCCESS
    );
    assert!((4..=4096).contains(&named_length));
    let named: Vec<_> = named.into_iter().flat_map(u64::to_le_bytes).collect();
    let name_bytes = u32::from_le_bytes(named[..4].try_into().unwrap()) as usize;
    assert_eq!(name_bytes % 2, 0);
    assert_eq!(name_bytes + 4, named_length as usize);
    let canonical = named[4..4 + name_bytes]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let mut result = Vec::new();
    for index in 0..=1024 {
        let mut buffer = [0u64; 66];
        let mut returned = 0;
        // SAFETY: live owned HKEY, aligned initialized 528-byte output and
        // exclusive ULONG. Decode only a successful, bounded native record.
        let status = unsafe {
            NtEnumerateKey(
                key.0,
                index,
                0,
                buffer.as_mut_ptr().cast(),
                528,
                &mut returned,
            )
        } as u32;
        if status == STATUS_NO_MORE_ENTRIES {
            return Ok((canonical, result));
        }
        assert_eq!(status, STATUS_SUCCESS, "{path}/view{view}/index{index}");
        assert!((16..=526).contains(&returned));
        let bytes: Vec<_> = buffer.into_iter().flat_map(u64::to_le_bytes).collect();
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0);
        let length = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        assert_eq!(length % 2, 0);
        assert_eq!(returned as usize, 16 + length);
        result.push(BasicChild {
            last_write: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            name: bytes[16..16 + length]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect(),
        });
    }
    panic!("native enumeration exceeded bounded child count")
}
#[test]
fn native_enumerate_key_installed_acquisition_preserves_real_order_case_and_filetimes() {
    let package = format!("{COMMAND_PROCESSOR_KEY}\\KnownPackageManagers");
    let paths = [MACHINE_HIVE_KEY, COMMAND_PROCESSOR_KEY, package.as_str()];
    for _ in 0..3 {
        let observations = || {
            paths
                .iter()
                .flat_map(|path| {
                    [0x100, 0x200]
                        .into_iter()
                        .map(move |view| ((*path, view), native(path, view)))
                })
                .collect::<Vec<_>>()
        };
        let before = observations();
        let registry = crate::user::windows::registry::snapshot().unwrap();
        let after = observations();
        if before != after {
            continue;
        }
        for ((path, view), expected) in before {
            let view = if view == 0x100 {
                crate::user::windows::registry::RegistryView::Native64
            } else {
                crate::user::windows::registry::RegistryView::Wow32
            };
            let actual = registry.lookup_view(&path.encode_utf16().collect::<Vec<_>>(), view);
            match expected {
                Ok((canonical, expected)) => {
                    let Lookup::Present(key) = actual else {
                        panic!("installed key missing: {path}/{view:?}")
                    };
                    assert_eq!(key.path, canonical, "{path}/{view:?}");
                    assert_eq!(
                        key.child_metadata(),
                        Some(expected.as_slice()),
                        "{path}/{view:?}"
                    );
                }
                Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => assert!(
                    matches!(actual, Lookup::Missing | Lookup::MissingPath),
                    "{path}/{view:?}"
                ),
                Err(status) => {
                    panic!("native fixed-key open failed: {path}/{view:?}/0x{status:08x}")
                }
            }
        }
        return;
    }
    panic!("native registry input changed across all three acquisition brackets")
}

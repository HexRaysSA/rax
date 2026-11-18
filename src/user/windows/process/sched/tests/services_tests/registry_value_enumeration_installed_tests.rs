//! Direct Windows comparison over fixed MUI keys in both installed views.
use super::*;
use std::ffi::c_void;
use std::ptr::null_mut;

type Hkey = *mut c_void;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(
        root: Hkey,
        name: *const u16,
        options: u32,
        access: u32,
        key: *mut Hkey,
    ) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtEnumerateValueKey(
        key: Hkey,
        index: u32,
        class: u32,
        output: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

struct NativeKey(Hkey);

impl NativeKey {
    fn open(path: &str, view: u32) -> Option<Self> {
        let name: Vec<u16> = path
            .strip_prefix("\\Registry\\Machine\\")
            .unwrap()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut handle = null_mut();
        // SAFETY: fixed, terminated MUI key and exclusive handle output.
        let status = unsafe {
            RegOpenKeyExW(
                -2_147_483_646isize as Hkey,
                name.as_ptr(),
                0,
                1 | view,
                &mut handle,
            )
        };
        if status == 2 {
            return None;
        }
        assert_eq!(status, 0, "{path}/{view:#x}");
        Some(Self(handle))
    }

    fn sample(&self, index: u32, class: u32, length: u32) -> (u32, u32, Vec<u8>) {
        let mut output = [0xa5a5_a5a5_a5a5_a5a5u64; 8];
        let mut returned = 0xcccccccc;
        assert!(length <= 64);
        // SAFETY: live query-only handle and disjoint aligned output buffers.
        let status = unsafe {
            NtEnumerateValueKey(
                self.0,
                index,
                class,
                output.as_mut_ptr().cast(),
                length,
                &mut returned,
            )
        };
        (
            status as u32,
            returned,
            output.into_iter().flat_map(u64::to_le_bytes).collect(),
        )
    }
}

impl Drop for NativeKey {
    fn drop(&mut self) {
        // SAFETY: this guard owns the returned HKEY exactly once.
        assert_eq!(unsafe { RegCloseKey(self.0) }, 0);
    }
}

#[test]
fn native_enumerate_values_installed_windows_matches_mui_views() {
    use crate::user::windows::registry::{Lookup, RegistryView};
    let root = TreeRoot::MuiSystem.path();
    let paths = [
        format!("{root}\\Settings\\LanguageConfiguration"),
        format!("{root}\\UILanguages\\en-US"),
    ];
    let registry = crate::user::windows::registry::snapshot().unwrap();
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = registry.clone();
        for path in &paths {
            for (view, selection) in [
                (0x100, RegistryView::Native64),
                (0x200, RegistryView::Wow32),
            ] {
                let Some(host) = NativeKey::open(path, view) else {
                    let name: Vec<u16> = path.encode_utf16().collect();
                    assert!(matches!(
                        registry.lookup_view(&name, selection),
                        Lookup::Missing | Lookup::MissingPath
                    ));
                    continue;
                };
                let handle = open(p, &mut t, base, path, u64::from(1 | view));
                for index in [0, 1, 2, u32::MAX] {
                    for class in 0..=4 {
                        for length in [0, 11, 12, 13, 19, 20, 21, 32, 64] {
                            let expected = host.sample(index, class, length);
                            let (out, ret) = (base + 128, base + 64);
                            p.space.wr(out, &[0xa5; 64]).unwrap();
                            p.space.w32(ret, 0xcccccccc).unwrap();
                            let status = call(
                                p,
                                &mut t,
                                SERVICE,
                                &[handle, index.into(), class.into(), out, length.into(), ret],
                            );
                            let actual = (
                                status,
                                p.space.u32(ret).unwrap(),
                                p.space.bytes(out, 64).unwrap(),
                            );
                            assert_eq!(
                                actual, expected,
                                "{arch}/{path}/{view:#x}/{index}/{class}/{length}"
                            );
                        }
                    }
                }
                assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
            }
        }
    }
}

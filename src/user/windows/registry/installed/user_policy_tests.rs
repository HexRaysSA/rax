use super::*;
use crate::user::windows::arch::WinArch;

fn native_sid_text(sid: &[u8]) -> Vec<u16> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertSidToStringSidW(sid: *const u8, output: *mut *mut u16) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(value: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }
    struct Owned(*mut u16);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: exclusive SDK-allocated string; never exposed to a guest.
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
    assert_eq!(crate::user::windows::security::sid(sid), Some(sid));
    let mut raw = std::ptr::null_mut();
    // SAFETY: bounded valid immutable SID and exclusive initialized output.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid.as_ptr(), &mut raw) }, 0);
    assert!(!raw.is_null());
    let text = Owned(raw);
    let mut units = Vec::new();
    for index in 0..256 {
        // SAFETY: successful SDK string is terminated; maximum valid SID text
        // is bounded below256 WCHARs. Only this owned allocation is read.
        let unit = unsafe { *text.0.add(index) };
        if unit == 0 {
            return units;
        }
        units.push(unit);
    }
    panic!("native SID text exceeds its bounded representation")
}

#[test]
fn installed_user_policy_snapshot_matches_primary_sid_and_native_views() {
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let runtime = crate::user::windows::native::NativeRuntime::select(arch).unwrap();
    let subject = runtime.wnf_catalog.primary_subject().unwrap();
    for suffix in [
        "\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
        "\\Software\\Policies\\Microsoft\\Windows\\System",
    ] {
        let mut relative = native_sid_text(&subject.user);
        relative.extend(suffix.encode_utf16());
        let guest: Vec<_> = "\\Registry\\User\\"
            .encode_utf16()
            .chain(relative.iter().copied())
            .collect();
        relative.push(0);
        for view in [0, 0x100, 0x200] {
            let mut handle = null_mut();
            // SAFETY: fixed policy suffix below independently queried primary SID;
            // query/enumerate only, terminated UTF16 and exclusive native output.
            let status = unsafe {
                RegOpenKeyExW(
                    (-2_147_483_645isize) as Hkey,
                    relative.as_ptr(),
                    0,
                    9 | view,
                    &mut handle,
                )
            };
            if status == 2 {
                assert!(matches!(
                    runtime.registry.lookup(&guest),
                    super::super::Lookup::Missing
                ));
            } else {
                assert_eq!(status, 0);
                let native = OwnedKey(handle);
                assert!(runtime.registry.key(&guest).is_some());
                super::tests::check_ifeo(&runtime.registry, &native, &guest, 0);
            }
        }
    }
}

#[test]
fn installed_user_policy_capture_distinguishes_root_absence_and_other_errors() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let path = super::super::user_policy_path(&sid).unwrap();
    let mut opens = 0;
    assert!(
        tree::capture_path_with(&registry, path.clone(), |requested| {
            opens += 1;
            assert_eq!(requested, path);
            Err(io::Error::from_raw_os_error(2))
        })
        .unwrap()
        .is_none()
    );
    assert_eq!(opens, 1);
    for status in [3, 5, 234, 259] {
        let error = tree::capture_path_with(&registry, path.clone(), |_| {
            Err(io::Error::from_raw_os_error(status))
        })
        .err()
        .expect("only root ERROR_FILE_NOT_FOUND establishes absence");
        assert_eq!(error.raw_os_error(), Some(status));
    }
}

#[test]
fn installed_user_policy_present_capture_reads_controlled_primary_user_environment() {
    let catalog = crate::user::windows::wnf::snapshot().unwrap();
    let subject = catalog.primary_subject().unwrap();
    let sid_text = native_sid_text(&subject.user);
    let fixture: Vec<_> = "\\Registry\\User\\"
        .encode_utf16()
        .chain(sid_text)
        .chain("\\Environment".encode_utf16())
        .collect();
    for selection in super::super::UserPolicyRoot::ALL {
        let policy = selection.path(&subject.user).unwrap();
        // SAFETY: pure native one-WCHAR ordinal lookup, with no pointers retained.
        let upcase = (0..=u16::MAX)
            .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
            .collect();
        let registry = Registry::selected(upcase, vec![]).unwrap();
        let captured = tree::capture_path_with(&registry, policy.clone(), |requested| {
            assert!(requested.starts_with(&policy));
            let path: Vec<_> = fixture
                .iter()
                .copied()
                .chain(requested[policy.len()..].iter().copied())
                .collect();
            user_policy::open(&fixture, &path)
        })
        .unwrap()
        .expect("native read-only per-user Environment fixture is present");
        let selected = registry
            .with_user_policy_root(selection, &subject.user, Some(captured))
            .unwrap();
        let native = user_policy::open(&fixture, &fixture).unwrap();
        let (keys, values, bytes) = super::tests::check_ifeo(&selected, &native, &policy, 0);
        assert!(
            keys >= 1 && values > 0,
            "controlled fixture must retain actual native values"
        );
        eprintln!(
            "native controlled user policy capture: {keys} keys, {values} values, {bytes} bytes"
        );
    }
    for outside in [
        "\\Registry\\Machine\\Software",
        "\\Registry\\User\\S-1-5-19\\Environment",
    ] {
        assert!(user_policy::open(&fixture, &outside.encode_utf16().collect::<Vec<_>>()).is_err());
    }
    let sibling: Vec<_> = fixture
        .iter()
        .copied()
        .chain("Suffix".encode_utf16())
        .collect();
    assert!(user_policy::open(&fixture, &sibling).is_err());
    let nul: Vec<_> = fixture.iter().copied().chain([92, 0]).collect();
    assert!(user_policy::open(&fixture, &nul).is_err());
}

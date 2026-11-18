use super::*;

#[test]
fn installed_mui_system_snapshot_matches_independent_native_presence_and_views() {
    let registry = snapshot().unwrap();
    let root = super::super::TreeRoot::MuiSystem;
    let path = root.path();
    let guest: Vec<_> = path.encode_utf16().collect();
    let native: Vec<_> = path
        .strip_prefix("\\Registry\\Machine\\")
        .unwrap()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    for view in [0, 0x100, 0x200] {
        let mut handle = null_mut();
        // SAFETY: fixed terminated HKLM runtime path, query/enumerate-only
        // access, exclusive output; no guest names or host mutation.
        let status = unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                native.as_ptr(),
                0,
                9 | view,
                &mut handle,
            )
        };
        if status == 2 {
            assert!(matches!(
                registry.lookup(&guest),
                super::super::Lookup::Missing
            ));
        } else {
            assert_eq!(status, 0);
            let host = OwnedKey(handle);
            assert!(matches!(
                registry.lookup(&guest),
                super::super::Lookup::Present(_)
            ));
            super::tests::check_ifeo(&registry, &host, &guest, 0);
        }
    }
}

#[test]
fn installed_mui_system_capture_distinguishes_absence_from_other_errors() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let root = super::super::TreeRoot::MuiSystem;
    let mut opens = 0;
    assert!(
        tree::capture_enumerated_root_with(&registry, root, |path| {
            opens += 1;
            assert_eq!(path, root.path().encode_utf16().collect::<Vec<_>>());
            Err(io::Error::from_raw_os_error(2))
        })
        .unwrap()
        .is_none()
    );
    assert_eq!(opens, 1);
    for status in [3, 5, 234, 259] {
        let error = tree::capture_enumerated_root_with(&registry, root, |_| {
            Err(io::Error::from_raw_os_error(status))
        })
        .err()
        .unwrap();
        assert_eq!(error.raw_os_error(), Some(status));
    }
}

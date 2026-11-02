use super::*;

#[test]
fn installed_key_information_absence_and_errors_do_not_expand_selection() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let expected: Vec<_> = TreeRoot::NlsCustomLocale.path().encode_utf16().collect();
    let mut calls = 0;
    assert!(
        capture_with(&registry, |path| {
            calls += 1;
            assert_eq!(path, expected);
            Err(io::Error::from_raw_os_error(2))
        })
        .unwrap()
        .is_none()
    );
    assert_eq!(calls, 1);
    for status in [3, 5, 234, 259] {
        assert_eq!(
            capture_with(&registry, |_| Err(io::Error::from_raw_os_error(status)))
                .err()
                .unwrap()
                .raw_os_error(),
            Some(status)
        );
    }
}

#[test]
fn installed_key_information_matches_independent_native_records_in_all_system_views() {
    let registry = crate::user::windows::registry::nls_custom_locale_subject().unwrap();
    let path: Vec<_> = TreeRoot::NlsCustomLocale.path().encode_utf16().collect();
    let name: Vec<_> = TreeRoot::NlsCustomLocale
        .path()
        .strip_prefix("\\Registry\\Machine\\")
        .unwrap()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    for view in [0, 0x100, 0x200] {
        let mut handle = null_mut();
        // SAFETY: compile-time fixed terminated HKLM path, query/enumerate-only
        // access and exclusive HKEY output. No guest input or host mutation.
        let status = unsafe {
            RegOpenKeyExW(
                (-2_147_483_646isize) as Hkey,
                name.as_ptr(),
                0,
                9 | view,
                &mut handle,
            )
        };
        if status == 2 {
            assert!(matches!(
                registry.lookup(&path),
                super::super::super::Lookup::Missing
            ));
            continue;
        }
        assert_eq!(status, 0);
        let host = OwnedKey(handle);
        let key = registry.key(&path).unwrap();
        let information = key.information().unwrap();
        for class in [0, 1, 2, 3, 4, 5, 6, 8] {
            let mut output = vec![0xA5A5_A5A5_A5A5_A5A5u64; MAX_RECORD_BYTES / 8];
            let mut returned = 0xA5A5_A5A5;
            // SAFETY: live owned query-only key, initialized aligned bounded
            // output and separate exclusive ULONG. Nothing is retained.
            let status = unsafe {
                NtQueryKey(
                    host.0,
                    class,
                    output.as_mut_ptr().cast(),
                    MAX_RECORD_BYTES as u32,
                    &mut returned,
                )
            };
            assert_eq!(status, 0, "view{view:x}/class{class}");
            assert!(returned as usize <= MAX_RECORD_BYTES);
            let bytes: Vec<_> = output
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .take(returned as usize)
                .collect();
            assert_eq!(
                information.record(class).unwrap(),
                bytes,
                "view{view:x}/class{class}"
            );
        }
        assert_eq!(information.canonical(), key.path);
        assert!(std::sync::Arc::ptr_eq(
            &key,
            &registry.key(&key.path).unwrap()
        ));
    }
}

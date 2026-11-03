use super::*;

#[test]
fn installed_key_information_absence_and_errors_do_not_expand_selection() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let expected: Vec<_> = TreeRoot::NlsCustomLocale.path().encode_utf16().collect();
    let mut calls = 0;
    assert!(
        capture_with(&registry, TreeRoot::NlsCustomLocale, |path| {
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
            capture_with(&registry, TreeRoot::NlsCustomLocale, |_| {
                Err(io::Error::from_raw_os_error(status))
            })
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

#[test]
fn installed_complete_nls_matches_independent_values_order_and_records_in_all_views() {
    use crate::user::windows::registry::Key;
    use std::sync::Arc;
    let registry = crate::user::windows::registry::nls_subject().unwrap();
    let root: Vec<_> = TreeRoot::Nls.path().encode_utf16().collect();
    fn collect(key: Arc<Key>, nodes: &mut Vec<Arc<Key>>) {
        if let Some(children) = &key.subkeys {
            for child in children.values() {
                collect(child.clone(), nodes);
            }
        }
        nodes.push(key);
    }
    let mut nodes = vec![];
    collect(registry.key(&root).unwrap(), &mut nodes);
    for view in [0, 0x100, 0x200] {
        for key in &nodes {
            let logical = key.logical_path.as_deref().unwrap();
            let prefix: Vec<_> = "\\Registry\\Machine\\".encode_utf16().collect();
            let native_name: Vec<_> = logical
                .strip_prefix(prefix.as_slice())
                .unwrap()
                .iter()
                .copied()
                .chain(Some(0))
                .collect();
            let mut handle = null_mut();
            // SAFETY: previously captured fixed-NLS path, terminated owned
            // WCHARs, read-only access and exclusive HKEY output.
            assert_eq!(
                unsafe {
                    RegOpenKeyExW(
                        (-2_147_483_646isize) as Hkey,
                        native_name.as_ptr(),
                        0,
                        9 | view,
                        &mut handle,
                    )
                },
                0
            );
            let host = OwnedKey(handle);
            for class in [0, 1, 2, 3, 4, 5, 6, 8] {
                for poison in [0xA5, 0x5A] {
                    let mut output = vec![u64::from_le_bytes([poison; 8]); MAX_RECORD_BYTES / 8];
                    let mut returned = 0x7F7F_7F7F;
                    // SAFETY: live owned HKEY, aligned initialized bounded
                    // storage and independent exclusive ULONG output.
                    assert_eq!(
                        unsafe {
                            NtQueryKey(
                                host.0,
                                class,
                                output.as_mut_ptr().cast(),
                                MAX_RECORD_BYTES as u32,
                                &mut returned,
                            )
                        },
                        0
                    );
                    assert!(returned as usize <= MAX_RECORD_BYTES);
                    let raw: Vec<_> = output
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .take(returned as usize)
                        .collect();
                    assert_eq!(
                        key.information().unwrap().record(class).unwrap(),
                        raw,
                        "view{view:x}/class{class}/{}",
                        String::from_utf16_lossy(logical)
                    );
                }
            }
            for (index, expected) in key.child_metadata().unwrap().iter().enumerate() {
                let mut name = vec![0u16; 16_384];
                let mut length = name.len() as u32;
                let mut time = [0u32; 2];
                // SAFETY: owned key and exclusive initialized WCHAR, DWORD,
                // FILETIME outputs; unused optional outputs are NULL.
                assert_eq!(
                    unsafe {
                        RegEnumKeyExW(
                            host.0,
                            index as u32,
                            name.as_mut_ptr(),
                            &mut length,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                            &mut time,
                        )
                    },
                    0
                );
                assert!((length as usize) < name.len());
                assert_eq!(expected.name, name[..length as usize]);
                assert_eq!(
                    expected.last_write,
                    u64::from(time[0]) | u64::from(time[1]) << 32
                );
            }
            let mut seen = std::collections::BTreeSet::new();
            for index in 0..key.values.len() {
                let mut name = vec![0u16; 16_384];
                let mut length = name.len() as u32;
                let mut data = vec![0xA5u8; 1 << 20];
                let mut bytes = data.len() as u32;
                let mut kind = 0;
                // SAFETY: initialized independently bounded native outputs,
                // live read-only HKEY, no borrowed result survives the call.
                assert_eq!(
                    unsafe {
                        RegEnumValueW(
                            host.0,
                            index as u32,
                            name.as_mut_ptr(),
                            &mut length,
                            null_mut(),
                            &mut kind,
                            data.as_mut_ptr(),
                            &mut bytes,
                        )
                    },
                    0
                );
                assert!((length as usize) < name.len() && bytes as usize <= data.len());
                let name = &name[..length as usize];
                assert!(seen.insert(key.fold(name)));
                let expected = key.value(name).unwrap();
                assert_eq!(expected.name, name);
                assert_eq!(expected.kind, kind);
                assert_eq!(expected.data, data[..bytes as usize]);
            }
            assert_eq!(seen.len(), key.values.len());
            assert!(Arc::ptr_eq(key, &registry.key(&key.path).unwrap()));
        }
    }
}

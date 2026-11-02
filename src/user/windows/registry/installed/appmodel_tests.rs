use super::*;

#[test]
fn installed_appmodel_views_match_independent_read_only_native_queries() {
    let registry = super::super::snapshot().unwrap();
    for selected in AppModelRoot::ALL {
        let path: Vec<_> = selected.path().encode_utf16().collect();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let native = open(selected, view, &path);
            match native {
                Ok(host) => {
                    let super::super::super::Lookup::Present(key) =
                        registry.lookup_view(&path, view)
                    else {
                        panic!("present native view lost")
                    };
                    let metadata = info(&host).unwrap();
                    assert_eq!(key.children, metadata.children);
                    let native_values =
                        values(&host, &metadata, super::super::super::MAX_TOTAL_BYTES).unwrap();
                    assert_eq!(key.values.len(), native_values.len());
                    for value in native_values {
                        assert_eq!(key.value(&value.name), Some(&value));
                    }
                }
                Err(error) if error.raw_os_error() == Some(2) => assert!(matches!(
                    registry.lookup_view(&path, view),
                    super::super::super::Lookup::Missing
                )),
                Err(error) => panic!("native acquisition failed: {error}"),
            }
        }
    }
}

#[test]
fn installed_appmodel_absence_is_independent_and_other_errors_abort() {
    let registry = Registry::selected(vec![0; 65_536], vec![]).unwrap();
    let mut calls = Vec::new();
    let absent = capture_with(registry.clone(), |selected, view, path| {
        calls.push((selected, view));
        assert_eq!(path, selected.path().encode_utf16().collect::<Vec<_>>());
        Err(io::Error::from_raw_os_error(2))
    })
    .unwrap();
    assert_eq!(
        calls,
        AppModelRoot::ALL
            .into_iter()
            .flat_map(|selected| [RegistryView::Native64, RegistryView::Wow32]
                .map(|view| (selected, view)))
            .collect::<Vec<_>>()
    );
    for (selected, view) in calls {
        assert!(matches!(
            absent.lookup_view(&selected.path().encode_utf16().collect::<Vec<_>>(), view),
            super::super::super::Lookup::Missing
        ));
    }
    for status in [3, 5, 234, 259] {
        for failed_call in 1..=4 {
            let mut calls = 0;
            let error = capture_with(registry.clone(), |_, _, _| {
                calls += 1;
                Err(io::Error::from_raw_os_error(if calls == failed_call {
                    status
                } else {
                    2
                }))
            })
            .unwrap_err();
            assert_eq!(calls, failed_call);
            assert_eq!(error.raw_os_error(), Some(status));
        }
    }
    for selected in AppModelRoot::ALL {
        let fixed = selected.path();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            for path in [
                "\\Registry\\Machine\\Software",
                &format!("{fixed}Other"),
                &format!("{fixed}\\bad\0"),
                AppModelRoot::ALL
                    .into_iter()
                    .find(|root| *root != selected)
                    .unwrap()
                    .path(),
            ] {
                assert_eq!(
                    open(selected, view, &path.encode_utf16().collect::<Vec<_>>())
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
    }
}

#[test]
fn installed_appmodel_present_pair_uses_bounded_native_enumeration() {
    for selected in AppModelRoot::ALL {
        // Controlled mapping to existing IFEO data exercises complete present
        // capture without writing AppModel keys or changing host registry views.
        let upcase = (0..=u16::MAX)
            .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
            .collect();
        let registry = Registry::selected(upcase, vec![]).unwrap();
        let prefix: Vec<_> = selected.path().encode_utf16().collect();
        let mut opens = [0; 2];
        let captured = capture_with(registry, |root, view, path| {
            if root != selected {
                return Err(io::Error::from_raw_os_error(2));
            }
            let slot = if view == RegistryView::Native64 { 0 } else { 1 };
            opens[slot] += 1;
            assert!(path.starts_with(&prefix));
            let name: Vec<_> = super::super::super::IFEO_KEY
                .strip_prefix("\\Registry\\Machine\\")
                .unwrap()
                .encode_utf16()
                .chain(path[prefix.len()..].iter().copied())
                .chain(Some(0))
                .collect();
            let mut handle = null_mut();
            // SAFETY: controlled fixed read-only source plus bounded enumerated
            // components; terminated WCHAR buffer and exclusive owned HKEY output.
            let status = unsafe {
                RegOpenKeyExW(
                    (-2_147_483_646isize) as Hkey,
                    name.as_ptr(),
                    0,
                    9 | view.flag(),
                    &mut handle,
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status));
            }
            Ok(OwnedKey(handle))
        })
        .unwrap();
        for (index, view) in [RegistryView::Native64, RegistryView::Wow32]
            .into_iter()
            .enumerate()
        {
            let super::super::super::Lookup::Present(key) = captured.lookup_view(&prefix, view)
            else {
                panic!()
            };
            assert!(key.children > 0 && opens[index] > 1);
            fn count(key: &super::super::super::Key) -> usize {
                1 + key
                    .subkeys
                    .as_ref()
                    .unwrap()
                    .values()
                    .map(|child| count(child))
                    .sum::<usize>()
            }
            assert_eq!(count(&key), opens[index]);
        }
        assert!(captured.value_budget().unwrap().count > 0);
    }
}

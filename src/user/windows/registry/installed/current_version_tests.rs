use super::*;

fn registry() -> Registry {
    // SAFETY: pure one-WCHAR native case mapping; no pointers or retained state.
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| unsafe { RtlUpcaseUnicodeChar(u) })
            .collect(),
        vec![],
    )
    .unwrap()
}

#[test]
fn current_version_installed_absence_preserves_native_error_classes() {
    for (code, missing_path) in [(2, false), (3, true)] {
        let selected =
            capture_with(registry(), |_| Err(io::Error::from_raw_os_error(code))).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let result = selected.lookup_view(
                &super::super::super::CURRENT_VERSION_KEY
                    .encode_utf16()
                    .collect::<Vec<_>>(),
                view,
            );
            assert!(if missing_path {
                matches!(result, super::super::super::Lookup::MissingPath)
            } else {
                matches!(result, super::super::super::Lookup::Missing)
            });
        }
    }
    for code in [5, 87] {
        assert!(capture_with(registry(), |_| Err(io::Error::from_raw_os_error(code))).is_err());
    }
}

#[test]
fn current_version_installed_capture_preserves_every_value_and_native_record() {
    let selected = capture(registry()).unwrap();
    for parent in [false, true] {
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let native = open_subject(parent, view).unwrap();
            let direct = header(&registry(), &native).unwrap();
            let super::super::super::Lookup::Present(key) = selected.lookup_view(
                &(if parent {
                    super::super::super::WINDOWS_NT_KEY
                } else {
                    super::super::super::CURRENT_VERSION_KEY
                })
                .encode_utf16()
                .collect::<Vec<_>>(),
                view,
            ) else {
                panic!("installed CurrentVersion root")
            };
            assert_eq!(key.path, direct.key.canonical);
            assert_eq!(key.children, direct.key.children);
            assert_eq!(key.command_access(), Some(direct.key.access));
            assert_eq!(key.values.len(), direct.key.values.len());
            for value in &direct.key.values {
                assert_eq!(key.value(&value.name), Some(value));
            }
            assert_eq!(
                key.enumeration.as_deref(),
                direct.key.enumeration.as_deref()
            );
            for class in [0, 1, 2, 3, 4, 5, 6, 8] {
                assert_eq!(
                    key.information().unwrap().record(class),
                    direct.information.record(class)
                );
            }
        }
    }
}

#[test]
fn current_version_installed_rejects_duplicate_selection_before_native_open() {
    let selected = registry()
        .with_current_version(
            RegistryView::Native64,
            Ok(
                crate::user::windows::registry::current_version_header_fixture(
                    CURRENT_VERSION_KEY.encode_utf16().collect(),
                    0,
                    0,
                ),
            ),
        )
        .unwrap();
    assert!(
        capture_with(selected, |_| panic!(
            "duplicate capture must not open a native key"
        ))
        .is_err()
    );
}

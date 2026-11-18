use super::*;

fn units(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}

fn header(path: &str, values: Vec<Value>) -> CommandHeader {
    CommandHeader {
        canonical: units(path),
        children: 1,
        enumeration: Some(vec![BasicChild {
            name: units("Configuration"),
            last_write: 17,
        }]),
        values,
        access: KeyAccess {
            maximum_access: 0x20019,
            system_security_status: 0xc000_0061,
        },
    }
}

fn empty_registry() -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
}

#[test]
fn side_by_side_headers_retain_distinct_views_and_limit_descendant_scope() {
    let root = SnapshotRoot::SideBySide;
    let native = RegistryView::Native64;
    let wow = RegistryView::Wow32;
    let name = units("PreferExternalManifest");
    let value = Value {
        name: name.clone(),
        kind: 4,
        data: 1u32.to_le_bytes().to_vec(),
    };
    let native_header = header(SIDE_BY_SIDE_KEY, vec![value.clone()]);
    let wow_header = header(SIDE_BY_SIDE_WOW_KEY, vec![]);
    assert!(
        empty_registry()
            .with_snapshot_selection(root, &[], wow, Ok((native_header.clone(), None)))
            .is_err()
    );
    let base = empty_registry()
        .with_snapshot_selection(root, &[], native, Ok((native_header, None)))
        .unwrap();
    let registry = base
        .clone()
        .with_snapshot_selection(root, &[], wow, Ok((wow_header, None)))
        .unwrap();
    let logical = units(SIDE_BY_SIDE_KEY);
    let physical = units(&SIDE_BY_SIDE_WOW_KEY.to_ascii_lowercase());
    let Lookup::Present(native_key) = registry.lookup_view(&logical, native) else {
        panic!("native SideBySide header");
    };
    assert_eq!(native_key.value(&name), Some(&value));
    assert_eq!(
        native_key.captured_access().unwrap().maximum_access,
        0x20019
    );
    let Lookup::Present(wow_key) = registry.lookup_view(&logical, wow) else {
        panic!("x86 SideBySide header");
    };
    assert!(wow_key.value(&name).is_none());
    assert_eq!(wow_key.child_metadata().unwrap()[0].last_write, 17);
    assert!(matches!(
        wow_key.relative(&units("Configuration")),
        Lookup::Unselected
    ));
    for view in [native, wow] {
        let Lookup::Present(key) = registry.lookup_view(&physical, view) else {
            panic!("explicit x86 SideBySide header");
        };
        assert!(Arc::ptr_eq(&key, &wow_key));
        assert!(matches!(
            registry.lookup_view(&units(&format!("{SIDE_BY_SIDE_KEY}Other")), view),
            Lookup::Unselected
        ));
    }
    let missing = base
        .with_snapshot_selection(root, &[], wow, Err(STATUS_OBJECT_PATH_NOT_FOUND))
        .unwrap();
    assert!(matches!(
        missing.lookup_view(&logical, wow),
        Lookup::MissingPath
    ));
    assert!(matches!(
        missing.lookup_view(&physical, native),
        Lookup::MissingPath
    ));
    assert!(matches!(
        missing.lookup_view(&logical, native),
        Lookup::Present(_)
    ));
}

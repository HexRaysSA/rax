use super::*;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

pub(crate) fn registry() -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
}

/// Synthetic shape fixture; this does not stand in for native value contents.
pub(crate) fn header(canonical: Vec<u16>, children: u32, values: u32) -> CurrentVersionHeader {
    let mut entries: Vec<_> = (0..children)
        .map(|i| BasicChild {
            name: units(&format!("Opaque{i:04}")),
            last_write: u64::from(i),
        })
        .collect();
    if children >= 2 {
        entries[children as usize - 2].name = units("Image File Execution Options");
        entries[children as usize - 1].name = units("GRE_Initialize");
    }
    header_with_entries(canonical, entries, values)
}

pub(crate) fn parent_header(canonical: Vec<u16>) -> CurrentVersionHeader {
    header_with_entries(
        canonical,
        vec![BasicChild {
            name: units("CurrentVersion"),
            last_write: 0,
        }],
        0,
    )
}

fn header_with_entries(
    canonical: Vec<u16>,
    entries: Vec<BasicChild>,
    values: u32,
) -> CurrentVersionHeader {
    let children = entries.len() as u32;
    let name = canonical.rsplit(|u| *u == 92).next().unwrap();
    let lengths = [
        16 + name.len() * 2,
        24 + name.len() * 2,
        44,
        4 + canonical.len() * 2,
        40,
        12,
        4,
        0,
        4,
    ];
    let mut records: [Vec<u8>; 9] = std::array::from_fn(|i| vec![0; lengths[i]]);
    for class in [0, 1, 2, 4] {
        records[class][..8].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
    }
    for (class, offset, length_at) in [(0, 16, 12), (1, 24, 20)] {
        records[class][length_at..length_at + 4]
            .copy_from_slice(&(name.len() as u32 * 2).to_le_bytes());
        for (at, unit) in name.iter().enumerate() {
            records[class][offset + at * 2..offset + at * 2 + 2]
                .copy_from_slice(&unit.to_le_bytes());
        }
    }
    records[3][..4].copy_from_slice(&(canonical.len() as u32 * 2).to_le_bytes());
    for (at, unit) in canonical.iter().enumerate() {
        records[3][4 + at * 2..6 + at * 2].copy_from_slice(&unit.to_le_bytes());
    }
    for (class, child_at, value_at) in [(2, 20, 32), (4, 12, 20)] {
        records[class][child_at..child_at + 4].copy_from_slice(&children.to_le_bytes());
        records[class][value_at..value_at + 4].copy_from_slice(&values.to_le_bytes());
    }
    let max_child = entries
        .iter()
        .map(|entry| entry.name.len() as u32 * 2)
        .max()
        .unwrap_or(0);
    let max_value_name = if values == 0 {
        0
    } else {
        format!("Value{:04}", values - 1).encode_utf16().count() as u32 * 2
    };
    for (class, child_at, name_at, data_at) in [(2, 24, 36, 40), (4, 16, 24, 28)] {
        records[class][child_at..child_at + 4].copy_from_slice(&max_child.to_le_bytes());
        records[class][name_at..name_at + 4].copy_from_slice(&max_value_name.to_le_bytes());
        records[class][data_at..data_at + 4]
            .copy_from_slice(&(if values == 0 { 0u32 } else { 4 }).to_le_bytes());
    }
    records[4][32..36].copy_from_slice(&(name.len() as u32 * 2).to_le_bytes());
    CurrentVersionHeader {
        key: CommandHeader {
            canonical,
            children,
            enumeration: Some(entries),
            values: (0..values)
                .map(|i| Value {
                    name: units(&format!("Value{i:04}")),
                    kind: 3,
                    data: i.to_le_bytes().to_vec(),
                })
                .collect(),
            access: KeyAccess {
                maximum_access: 0x20019,
                system_security_status: 0xC0000061,
            },
        },
        information: KeyInformation::new(records, [NameTail::Raw; 2]).unwrap(),
    }
}

fn paired() -> Registry {
    registry()
        .with_tree(TreeRoot::Ifeo, Some(KeyTree::default()))
        .unwrap()
        .with_tree(TreeRoot::GreInitialize, Some(KeyTree::default()))
        .unwrap()
        .with_current_version(
            RegistryView::Native64,
            Ok(header(units(CURRENT_VERSION_KEY), 96, 32)),
        )
        .unwrap()
        .with_current_version(
            RegistryView::Wow32,
            Ok(header(units(CURRENT_VERSION_WOW_KEY), 59, 23)),
        )
        .unwrap()
}

#[test]
fn current_version_views_keep_distinct_values_records_aliases_and_shared_routes() {
    let registry = paired();
    for (view, path, children, values) in [
        (RegistryView::Native64, CURRENT_VERSION_KEY, 96, 32),
        (RegistryView::Wow32, CURRENT_VERSION_WOW_KEY, 59, 23),
    ] {
        let Lookup::Present(key) = registry.lookup_view(&units(CURRENT_VERSION_KEY), view) else {
            panic!("selected root")
        };
        assert_eq!(key.path, units(path));
        assert_eq!(key.children, children);
        assert_eq!(key.values.len(), values);
        assert_eq!(key.enumeration.as_ref().unwrap().len(), children as usize);
        assert_eq!(
            key.value(&units("value0000")).unwrap().data,
            0u32.to_le_bytes()
        );
        assert!(matches!(
            key.relative(&units("OPAQUE0000")),
            Lookup::Unselected
        ));
        assert!(matches!(
            key.relative(&units("OpaqueMissing")),
            Lookup::Missing
        ));
        for class in [0, 1, 2, 3, 4, 5, 6, 8] {
            assert!(key.information().unwrap().record(class).is_some());
        }
        assert!(key.information().unwrap().record(7).is_none());
        for root in [TreeRoot::Ifeo, TreeRoot::GreInitialize] {
            let suffix = root.path().strip_prefix(CURRENT_VERSION_KEY).unwrap();
            let Lookup::Present(child) = key.relative(&units(suffix)) else {
                panic!("selected shared child")
            };
            assert_eq!(child.path, units(root.path()));
            assert_eq!(
                key.current_version_shared_alias(&child),
                view == RegistryView::Wow32
            );
        }
    }
    let Lookup::Present(physical) =
        registry.lookup_view(&units(CURRENT_VERSION_WOW_KEY), RegistryView::Native64)
    else {
        panic!("physical alias")
    };
    assert_eq!(physical.path, units(CURRENT_VERSION_WOW_KEY));
    assert!(physical.physical_wow_name(&units(CURRENT_VERSION_WOW_KEY)));
    assert!(!physical.physical_wow_name(&units(CURRENT_VERSION_KEY)));
}

#[test]
fn current_version_retained_roots_own_shared_routes_without_cycles() {
    let registry = paired();
    let Lookup::Present(key) =
        registry.lookup_view(&units(CURRENT_VERSION_KEY), RegistryView::Wow32)
    else {
        panic!()
    };
    let weak = Arc::downgrade(&key);
    let Lookup::Present(child) = key.relative(&units("Image File Execution Options")) else {
        panic!()
    };
    let child_weak = Arc::downgrade(&child);
    drop(child);
    drop(registry);
    assert!(child_weak.upgrade().is_some());
    assert!(matches!(
        key.relative(&units("GRE_Initialize")),
        Lookup::Present(_)
    ));
    drop(key);
    assert!(weak.upgrade().is_none());
    assert!(child_weak.upgrade().is_none());
}

#[test]
fn current_version_parent_metadata_resolves_real_absence_and_retains_the_selected_child() {
    let registry = paired()
        .with_current_version_parent(
            RegistryView::Native64,
            Ok(parent_header(units(WINDOWS_NT_KEY))),
        )
        .unwrap()
        .with_current_version_parent(
            RegistryView::Wow32,
            Ok(parent_header(units(WINDOWS_NT_WOW_KEY))),
        )
        .unwrap();
    let Lookup::Present(parent) = registry.lookup_view(&units(WINDOWS_NT_KEY), RegistryView::Wow32)
    else {
        panic!("selected parent")
    };
    assert!(matches!(
        parent.relative(&units("CurrentVersionPrefix")),
        Lookup::Missing
    ));
    let Lookup::Present(child) = parent.relative(&units("CurrentVersion")) else {
        panic!("selected child")
    };
    assert_eq!(child.path, units(CURRENT_VERSION_WOW_KEY));
    drop(registry);
    assert!(matches!(
        parent.relative(&units("CurrentVersion\\GRE_Initialize")),
        Lookup::Present(_)
    ));
    let weak = Arc::downgrade(&child);
    drop(child);
    assert!(weak.upgrade().is_some());
    drop(parent);
    assert!(weak.upgrade().is_none());
}

#[test]
fn current_version_bindings_reject_wrong_subjects_incomplete_metadata_and_false_absence() {
    let native = RegistryView::Native64;
    assert!(
        registry()
            .with_current_version(native, Err(0xC0000022))
            .is_err()
    );
    assert!(matches!(
        registry()
            .with_current_version(native, Err(0xC0000034))
            .unwrap()
            .lookup_view(&units(CURRENT_VERSION_KEY), native),
        Lookup::Missing
    ));
    assert!(matches!(
        registry()
            .with_current_version(native, Err(0xC000003A))
            .unwrap()
            .lookup_view(&units(CURRENT_VERSION_KEY), native),
        Lookup::MissingPath
    ));
    assert!(
        registry()
            .with_current_version(native, Ok(header(units(CURRENT_VERSION_WOW_KEY), 0, 0)))
            .is_err()
    );
    assert!(
        registry()
            .with_current_version(
                native,
                Ok(header(units("\\Registry\\Machine\\Other"), 0, 0))
            )
            .is_err()
    );
    let mut absent_order = header(units(CURRENT_VERSION_KEY), 1, 0);
    absent_order.key.enumeration = None;
    assert!(
        registry()
            .with_current_version(native, Ok(absent_order))
            .is_err()
    );
    let mut changed = header(units(CURRENT_VERSION_KEY), 0, 1);
    changed.key.values.clear();
    assert!(
        registry()
            .with_current_version(native, Ok(changed))
            .is_err()
    );
    let one = registry()
        .with_current_version(native, Ok(header(units(CURRENT_VERSION_KEY), 0, 0)))
        .unwrap();
    assert!(
        one.with_current_version(native, Ok(header(units(CURRENT_VERSION_KEY), 0, 0)))
            .is_err()
    );
    let one = registry()
        .with_current_version(native, Ok(header(units(CURRENT_VERSION_KEY), 0, 0)))
        .unwrap();
    assert!(
        one.with_current_version(
            RegistryView::Wow32,
            Ok(header(units(CURRENT_VERSION_KEY), 0, 1))
        )
        .is_err()
    );
}

#[test]
fn current_version_metadata_and_selected_child_presence_must_agree() {
    let native = RegistryView::Native64;
    for missing in [STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND] {
        assert!(
            registry()
                .with_tree(TreeRoot::Ifeo, Some(KeyTree::default()))
                .unwrap()
                .with_current_version(native, Err(missing))
                .is_err()
        );
        assert!(
            paired()
                .with_current_version_parent(native, Err(missing))
                .is_err()
        );
    }
    assert!(
        registry()
            .with_tree(TreeRoot::Ifeo, Some(KeyTree::default()))
            .unwrap()
            .with_current_version(native, Ok(header(units(CURRENT_VERSION_KEY), 0, 0)))
            .is_err()
    );
    assert!(
        registry()
            .with_tree(TreeRoot::Ifeo, None)
            .unwrap()
            .with_current_version(native, Ok(header(units(CURRENT_VERSION_KEY), 2, 0)))
            .is_err()
    );
    assert!(
        paired()
            .with_current_version_parent(native, Ok(header(units(WINDOWS_NT_KEY), 0, 0)))
            .is_err()
    );
    assert!(
        registry()
            .with_current_version(native, Err(STATUS_OBJECT_NAME_NOT_FOUND))
            .unwrap()
            .with_current_version_parent(native, Ok(parent_header(units(WINDOWS_NT_KEY))))
            .is_err()
    );
    let selected = registry()
        .with_current_version(native, Err(STATUS_OBJECT_NAME_NOT_FOUND))
        .unwrap()
        .with_current_version_parent(native, Ok(header(units(WINDOWS_NT_KEY), 0, 0)))
        .unwrap();
    let Lookup::Present(parent) = selected.lookup_view(&units(WINDOWS_NT_KEY), native) else {
        panic!("selected parent with an observed absent child")
    };
    assert!(matches!(
        parent.relative(&units("CurrentVersion")),
        Lookup::Missing
    ));
}

use super::*;
use crate::user::windows::nt::status::*;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn sid(account: u32) -> Vec<u8> {
    let mut sid = vec![1, 2, 0, 0, 0, 0, 0, 5];
    sid.extend_from_slice(&21u32.to_le_bytes());
    sid.extend_from_slice(&account.to_le_bytes());
    sid
}

fn registry(subject: &[u8], canonical_hive: &str) -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|unit| {
                if (97..=122).contains(&unit) {
                    unit - 32
                } else {
                    unit
                }
            })
            .collect(),
        vec![],
    )
    .unwrap()
    .with_primary_hive(
        subject,
        Some(primary_hive::HiveHeader {
            canonical: wide(canonical_hive),
            children: 1,
            values: vec![],
        }),
    )
    .unwrap()
}

fn leaf(canonical: &str, values: usize) -> CommandTree {
    CommandTree {
        header: CommandHeader {
            enumeration: Some(vec![]),
            canonical: wide(canonical),
            children: 0,
            values: (0..values)
                .map(|index| Value {
                    name: wide(&format!("Value{index}")),
                    kind: 3,
                    data: vec![(index & 0xff) as u8],
                })
                .collect(),
            access: KeyAccess {
                maximum_access: 0xF003F,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        },
        children: vec![],
    }
}

fn profile(canonical: &str, keys: usize, values: usize) -> CommandTree {
    assert!(keys > 0 && values >= keys);
    let mut root = leaf(canonical, values / keys + usize::from(values % keys > 0));
    root.header.children = (keys - 1) as u32;
    root.header.enumeration = Some(
        (1..keys)
            .map(|index| BasicChild {
                name: wide(&format!("Key{index}")),
                last_write: index as u64,
            })
            .collect(),
    );
    root.children = (1..keys)
        .map(|index| {
            let name = format!("Key{index}");
            let count = values / keys + usize::from(index < values % keys);
            (wide(&name), leaf(&format!("{canonical}\\{name}"), count))
        })
        .collect();
    root
}

#[test]
fn local_settings_ordinary_profile_has_a_separate_two_view_aggregate_domain() {
    let subject = sid(7);
    let hive = "\\Registry\\User\\S-1-5-21-7";
    let canonical = "\\Registry\\User\\S-1-5-21-7_Classes\\Local Settings";
    let mut selected = registry(&subject, hive);
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        selected = selected
            .with_local_settings_tree(&subject, view, Ok(profile(canonical, 4315, 11668)))
            .unwrap();
    }
    let (values, metadata) = selected
        .snapshot_budgets(SnapshotRoot::LocalSettings)
        .unwrap();
    assert_eq!(values.count, 23_336);
    assert_eq!(metadata.key_count(), 8630);
    assert_eq!(values.enumeration_count, 8628);
    assert_eq!(selected.value_budget().unwrap().count, 0);
    assert_eq!(selected.view_budget().unwrap().key_count(), 0);

    let selected = selected
        .with_ole_tree(RegistryView::Native64, Ok(leaf(OLE_KEY, 1)))
        .unwrap();
    assert_eq!(selected.value_budget().unwrap().count, 1);
    assert_eq!(selected.view_budget().unwrap().key_count(), 1);
    assert!(
        selected
            .with_ole_tree(RegistryView::Wow32, Ok(leaf(OLE_KEY, 4097)))
            .is_err()
    );
}

#[test]
fn local_settings_logical_classes_alias_and_retained_primary_routes_share_the_capture() {
    let subject = sid(7);
    let hive = "\\Registry\\User\\S-1-5-21-7";
    let canonical = "\\Registry\\User\\S-1-5-21-7_Classes\\Local Settings";
    let mut selected = registry(&subject, hive);
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        selected = selected
            .with_local_settings_tree(&subject, view, Ok(profile(canonical, 2, 3)))
            .unwrap();
    }
    let primary = selected.key(&wide(hive)).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        for path in [path(&subject).unwrap(), wide(canonical)] {
            let Lookup::Present(key) = selected.lookup_view(&path, view) else {
                panic!("captured Local Settings alias");
            };
            assert_eq!(key.path, wide(canonical));
            assert_eq!(key.command_access().unwrap().grant(0x20119), Ok(0x20019));
            assert!(matches!(key.relative(&wide("Unknown")), Lookup::Missing));
        }
        let Lookup::Present(child) =
            primary.relative_in_view(&wide("Software\\Classes\\Local Settings\\Key1"), view)
        else {
            panic!("retained complete child");
        };
        assert_eq!(child.value(&wide("Value0")).unwrap().data, [0]);
        assert!(matches!(
            primary.relative_in_view(&wide("Software\\Classes\\Local SettingsOther"), view),
            Lookup::Unselected
        ));
    }
    drop(selected);
    assert!(matches!(
        primary.relative_in_view(
            &wide("Software\\Classes\\Local Settings\\Key1"),
            RegistryView::Wow32
        ),
        Lookup::Present(_)
    ));
}

#[test]
fn local_settings_tags_do_not_cross_fixed_subject_boundaries() {
    fn branch(canonical: &str, names: &[&str]) -> CommandTree {
        let mut tree = leaf(canonical, 1);
        if let Some((name, rest)) = names.split_first() {
            tree.header.children = 1;
            tree.header.enumeration = Some(vec![BasicChild {
                name: wide(name),
                last_write: 0,
            }]);
            tree.children = vec![(wide(name), branch(&format!("{canonical}\\{name}"), rest))];
        }
        tree
    }

    let subject = sid(7);
    for root in [
        SnapshotRoot::Command(CommandRoot::Machine),
        SnapshotRoot::Command(CommandRoot::System),
        SnapshotRoot::Command(CommandRoot::User),
        SnapshotRoot::Ole,
    ] {
        let base = String::from_utf16(&root.path(&subject).unwrap()).unwrap();
        let tree = branch(&base, &["Software", "Classes", "Local Settings"]);
        let selected = registry(&subject, "\\Registry\\User\\S-1-5-21-7")
            .with_snapshot_selection(
                root,
                &subject,
                RegistryView::Native64,
                Ok((tree.header, Some(tree.children))),
            )
            .unwrap();
        let name = wide(&format!("{base}{SUFFIX}"));
        let Lookup::Present(key) = selected.lookup_view(&name, RegistryView::Native64) else {
            panic!("selected adjacent subtree");
        };
        assert_eq!(
            key.initial_local_settings_tags(&name, 0, true, None, 0),
            None,
            "{root:?} descendant must retain its own tag policy"
        );
        assert!(!key.local_settings_classes_hive());
    }
}

#[test]
fn local_settings_system_alias_is_bound_to_the_captured_primary_hive() {
    let subject = vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let canonical = "\\REGISTRY\\USER\\.DEFAULT\\Software\\Classes\\Local Settings";
    let selected = registry(&subject, "\\Registry\\User\\.DEFAULT")
        .with_local_settings_tree(&subject, RegistryView::Native64, Ok(leaf(canonical, 1)))
        .unwrap();
    assert!(matches!(
        selected.lookup(&path(&subject).unwrap()),
        Lookup::Present(_)
    ));
    assert!(matches!(
        selected.lookup(&wide(canonical)),
        Lookup::Present(_)
    ));
    assert!(selected.clone().with_primary_hive(&sid(8), None).is_err());
    assert!(
        registry(&subject, "\\Registry\\User\\.DEFAULT")
            .with_local_settings_tree(
                &subject,
                RegistryView::Native64,
                Ok(leaf(
                    "\\Registry\\User\\S-1-5-21-8_Classes\\Local Settings",
                    1
                ))
            )
            .is_err()
    );
    assert!(
        selected
            .with_local_settings_tree(
                &sid(8),
                RegistryView::Wow32,
                Err(STATUS_OBJECT_NAME_NOT_FOUND)
            )
            .is_err()
    );
}

#[test]
fn local_settings_shared_views_reject_physical_name_data_grant_and_enumeration_races() {
    let subject = sid(7);
    let hive = "\\Registry\\User\\S-1-5-21-7";
    let canonical = "\\Registry\\User\\S-1-5-21-7_Classes\\Local Settings";
    let selected = registry(&subject, hive)
        .with_local_settings_tree(
            &subject,
            RegistryView::Native64,
            Ok(profile(canonical, 2, 3)),
        )
        .unwrap();
    for variant in 0..5 {
        let mut changed = profile(canonical, 2, 3);
        match variant {
            0 => changed = profile(&String::from_utf16(&path(&subject).unwrap()).unwrap(), 2, 3),
            1 => changed.children[0].1.header.values[0].data[0] ^= 1,
            2 => changed.children[0].1.header.access.maximum_access = 0x20019,
            3 => changed.header.enumeration.as_mut().unwrap()[0].last_write += 1,
            4 => changed.children[0].1.header.access.system_security_status = 0,
            _ => unreachable!(),
        }
        assert!(
            selected
                .clone()
                .with_local_settings_tree(&subject, RegistryView::Wow32, Ok(changed))
                .is_err(),
            "race variant {variant}"
        );
    }
    assert!(
        selected
            .with_local_settings_tree(
                &subject,
                RegistryView::Wow32,
                Err(STATUS_OBJECT_PATH_NOT_FOUND)
            )
            .is_err()
    );
}

#[test]
fn local_settings_absence_classes_are_exact_and_cannot_hide_permission_failures() {
    let subject = sid(7);
    for status in [STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND] {
        let selected = registry(&subject, "\\Registry\\User\\S-1-5-21-7")
            .with_local_settings_tree(&subject, RegistryView::Native64, Err(status))
            .unwrap();
        let other = if status == STATUS_OBJECT_NAME_NOT_FOUND {
            STATUS_OBJECT_PATH_NOT_FOUND
        } else {
            STATUS_OBJECT_NAME_NOT_FOUND
        };
        assert!(
            selected
                .clone()
                .with_local_settings_tree(&subject, RegistryView::Wow32, Err(other))
                .is_err()
        );
        let selected = selected
            .with_local_settings_tree(&subject, RegistryView::Wow32, Err(status))
            .unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            assert!(matches!(
                (status, selected.lookup_view(&path(&subject).unwrap(), view)),
                (STATUS_OBJECT_NAME_NOT_FOUND, Lookup::Missing)
                    | (STATUS_OBJECT_PATH_NOT_FOUND, Lookup::MissingPath)
            ));
        }
    }
    assert!(
        registry(&subject, "\\Registry\\User\\S-1-5-21-7")
            .with_local_settings_tree(&subject, RegistryView::Native64, Err(STATUS_ACCESS_DENIED))
            .is_err()
    );
}

#[test]
fn local_settings_rejects_partial_metadata_escaped_children_and_duplicate_views() {
    let subject = sid(7);
    let canonical = "\\Registry\\User\\S-1-5-21-7_Classes\\Local Settings";
    for variant in 0..5 {
        let mut tree = profile(canonical, 2, 3);
        match variant {
            0 => tree.header.enumeration = None,
            1 => tree.children[0].1.header.enumeration = None,
            2 => tree.children[0].1.header.canonical = wide("\\Registry\\User\\Other\\Escaped"),
            3 => tree.header.children = 2,
            4 => tree.header.enumeration.as_mut().unwrap()[0].name = wide("Other"),
            _ => unreachable!(),
        }
        assert!(
            registry(&subject, "\\Registry\\User\\S-1-5-21-7")
                .with_local_settings_tree(&subject, RegistryView::Native64, Ok(tree))
                .is_err()
        );
    }
    let selected = registry(&subject, "\\Registry\\User\\S-1-5-21-7")
        .with_local_settings_tree(&subject, RegistryView::Native64, Ok(leaf(canonical, 1)))
        .unwrap();
    assert!(
        selected
            .with_local_settings_tree(&subject, RegistryView::Native64, Ok(leaf(canonical, 1)))
            .is_err()
    );
    let header = leaf(canonical, 1).header;
    assert!(
        registry(&subject, "\\Registry\\User\\S-1-5-21-7")
            .with_snapshot_selection(
                SnapshotRoot::LocalSettings,
                &subject,
                RegistryView::Native64,
                Ok((header, None))
            )
            .is_err()
    );
}

#[test]
fn local_settings_value_domain_enforces_exact_count_bytes_and_single_value_bounds() {
    let value = Value {
        name: vec![],
        kind: 3,
        data: vec![],
    };
    let mut count = ValueBudget::with_limits(budget::LOCAL_SETTINGS);
    for _ in 0..65_536 {
        count.charge(&value).unwrap();
    }
    assert!(count.charge(&value).is_err());
    let mut startup = ValueBudget::default();
    for _ in 0..4096 {
        startup.charge(&value).unwrap();
    }
    assert!(startup.charge(&value).is_err());

    let mut bytes = ValueBudget::with_limits(budget::LOCAL_SETTINGS);
    let mut large = Value {
        name: vec![],
        kind: 3,
        data: vec![0; 1 << 20],
    };
    for _ in 0..32 {
        bytes.charge(&large).unwrap();
    }
    large.data.truncate(1);
    assert!(bytes.charge(&large).is_err());
    large.data.resize((1 << 20) + 1, 0);
    assert!(
        ValueBudget::with_limits(budget::LOCAL_SETTINGS)
            .charge(&large)
            .is_err()
    );
    large.data.clear();
    large.name.resize(MAX_NAME_UNITS, 65);
    ValueBudget::with_limits(budget::LOCAL_SETTINGS)
        .charge(&large)
        .unwrap();
    large.name.push(65);
    assert!(
        ValueBudget::with_limits(budget::LOCAL_SETTINGS)
            .charge(&large)
            .is_err()
    );
}

#[test]
fn local_settings_metadata_domain_enforces_key_path_depth_and_enumeration_bounds() {
    let mut keys = tree::TreeBudget::with_limits(budget::LOCAL_SETTINGS);
    for _ in 0..16_384 {
        keys.charge(&[65], 0).unwrap();
    }
    assert!(keys.charge(&[65], 0).is_err());
    let mut paths = tree::TreeBudget::with_limits(budget::LOCAL_SETTINGS);
    let path = vec![65; 16_383];
    for _ in 0..256 {
        paths.charge(&path, 0).unwrap();
    }
    paths.charge(&vec![65; 256], 0).unwrap();
    assert!(paths.charge(&[65], 0).is_err());
    let mut depth = tree::TreeBudget::with_limits(budget::LOCAL_SETTINGS);
    depth.charge(&[65], 32).unwrap();
    assert!(depth.charge(&[65], 33).is_err());

    let child = BasicChild {
        name: wide("A"),
        last_write: 0,
    };
    let children = vec![child.clone(); 16_384];
    let mut entries = ValueBudget::with_limits(budget::LOCAL_SETTINGS);
    entries.charge_enumeration(&children).unwrap();
    entries.charge_enumeration(&children).unwrap();
    assert!(entries.charge_enumeration(&[child]).is_err());
    let long = BasicChild {
        name: vec![65; 255],
        last_write: 0,
    };
    let mut names = ValueBudget::with_limits(budget::LOCAL_SETTINGS);
    for _ in 0..4048 {
        names
            .charge_enumeration(std::slice::from_ref(&long))
            .unwrap();
    }
    names
        .charge_enumeration(&[BasicChild {
            name: vec![65; 140],
            last_write: 0,
        }])
        .unwrap();
    assert!(
        names
            .charge_enumeration(&[BasicChild {
                name: wide("A"),
                last_write: 0
            }])
            .is_err()
    );
}

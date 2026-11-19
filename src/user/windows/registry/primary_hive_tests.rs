use super::*;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn sid() -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}
fn registry() -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
}
fn value(name: &str) -> Value {
    Value {
        name: units(name),
        kind: 3,
        data: vec![0, 255, 17],
    }
}
fn header(children: u32) -> HiveHeader {
    HiveHeader {
        canonical: units("\\REGISTRY\\USER\\.DEFAULT"),
        children,
        values: vec![value("Root")],
    }
}
fn tree() -> KeyTree {
    KeyTree {
        values: vec![value("Policy")],
        children: vec![(
            units("option"),
            KeyTree {
                values: vec![value("raw")],
                children: vec![],
            },
        )],
    }
}

#[test]
fn primary_hive_aliases_share_one_owned_key_and_unknown_children_stay_unknown() {
    let selected = registry()
        .with_primary_hive(&sid(), Some(header(9)))
        .unwrap();
    let primary = selected.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
    let alias = selected.key(&units("\\registry\\user\\.default")).unwrap();
    assert!(Arc::ptr_eq(&primary, &alias));
    assert_eq!(primary.path, units("\\REGISTRY\\USER\\.DEFAULT"));
    assert_eq!(primary.children, 9);
    assert_eq!(selected.value_budget().unwrap().count, 1);
    for outside in [
        "\\Registry\\User",
        "\\Registry\\User\\S-1-5-19",
        "\\Registry\\User\\S-1-5-18Suffix",
        "\\Registry\\User\\.DEFAULTSuffix",
        "\\Registry\\User\\S-1-5-18\\Software",
        "\\Registry\\User\\.DEFAULT\\Software",
    ] {
        assert!(
            matches!(selected.lookup(&units(outside)), Lookup::Unselected),
            "{outside}"
        );
    }
    drop(selected);
    assert_eq!(primary.value(&units("root")).unwrap().data, [0, 255, 17]);
    assert!(matches!(
        alias.relative(&units("unknown")),
        Lookup::Unselected
    ));
}

#[test]
fn primary_hive_policy_routes_survive_the_catalog_and_both_capture_orders() {
    for hive_first in [false, true] {
        let selected = if hive_first {
            registry()
                .with_primary_hive(&sid(), Some(header(9)))
                .unwrap()
                .with_user_policy(&sid(), Some(tree()))
                .unwrap()
        } else {
            registry()
                .with_user_policy(&sid(), Some(tree()))
                .unwrap()
                .with_primary_hive(&sid(), Some(header(9)))
                .unwrap()
        };
        let root = selected.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
        for prefix in ["\\Registry\\User\\S-1-5-18", "\\Registry\\User\\.DEFAULT"] {
            let path = format!("{prefix}{}\\OPTION", user_policy::POLICY_SUFFIX);
            let Lookup::Present(child) = selected.lookup(&units(&path)) else {
                panic!("{path}")
            };
            assert_eq!(child.value(&units("RAW")).unwrap().data, [0, 255, 17]);
        }
        assert_eq!(selected.value_budget().unwrap().count, 3);
        drop(selected);
        for suffix in [
            "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\option",
            "software\\\\policies\\microsoft\\windows\\safer\\codeidentifiers\\OPTION\\",
        ] {
            let Lookup::Present(child) = root.relative(&units(suffix)) else {
                panic!("{suffix}")
            };
            assert_eq!(child.value(&units("raw")).unwrap().data, [0, 255, 17]);
        }
        assert!(matches!(
            root.relative(&units("Software")),
            Lookup::Unselected
        ));
        assert!(matches!(
            root.relative(&units(&format!("{}Suffix", user_policy::POLICY_SUFFIX))),
            Lookup::Unselected
        ));
    }
}

#[test]
fn primary_hive_known_absent_policy_is_distinct_from_unselected_descendants() {
    let selected = registry()
        .with_primary_hive(&sid(), Some(header(9)))
        .unwrap()
        .with_user_policy(&sid(), None)
        .unwrap();
    let root = selected.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
    for tail in ["", "\\", "\\missing\\nested"] {
        let suffix = format!("{}{tail}", user_policy::POLICY_SUFFIX);
        assert!(matches!(root.relative(&units(&suffix)), Lookup::Missing));
        assert!(matches!(
            selected.lookup(&units(&format!("\\Registry\\User\\.DEFAULT{suffix}"))),
            Lookup::Missing
        ));
    }
    assert!(matches!(
        root.relative(&units("Software\\other")),
        Lookup::Unselected
    ));
    let absent = registry().with_primary_hive(&sid(), None).unwrap();
    assert!(matches!(
        absent.lookup(&units("\\Registry\\User\\S-1-5-18")),
        Lookup::Missing
    ));
    for tail in ["", "\\", "\\unknown", "\\unknown\\nested"] {
        assert!(matches!(
            absent.lookup(&units(&format!("\\Registry\\User\\S-1-5-18{tail}"))),
            Lookup::Missing
        ));
    }
    for unknown in [
        "\\Registry\\User\\.DEFAULT",
        "\\Registry\\User\\S-1-5-18Suffix",
    ] {
        assert!(matches!(absent.lookup(&units(unknown)), Lookup::Unselected));
    }
}

#[test]
fn primary_hive_rejects_invalid_aliases_duplicate_subjects_and_contradictory_capture() {
    for canonical in [
        "",
        "\\Registry\\User\\",
        "\\Registry\\Machine\\Software",
        "\\Registry\\User\\name\\child",
        "\\Registry\\User\\name\0suffix",
    ] {
        let mut h = header(9);
        h.canonical = units(canonical);
        assert!(
            registry().with_primary_hive(&sid(), Some(h)).is_err(),
            "{canonical:?}"
        );
    }
    assert!(registry().with_primary_hive(&[], Some(header(9))).is_err());
    assert!(Registry::default().with_primary_hive(&sid(), None).is_err());
    let selected = registry()
        .with_primary_hive(&sid(), Some(header(9)))
        .unwrap();
    assert!(selected.clone().with_primary_hive(&sid(), None).is_err());
    let mut other = sid();
    other[8] = 19;
    assert!(selected.with_user_policy(&other, None).is_err());
    assert!(
        registry()
            .with_user_policy(&other, None)
            .unwrap()
            .with_primary_hive(&sid(), Some(header(9)))
            .is_err()
    );
    for h in [None, Some(header(0))] {
        assert!(
            registry()
                .with_primary_hive(&sid(), h)
                .unwrap()
                .with_user_policy(&sid(), Some(tree()))
                .is_err()
        );
    }
}

#[test]
fn primary_hive_aliases_and_policy_routes_charge_shared_values_exactly_once() {
    let mut h = header(9);
    h.values = (0..MAX_VALUES - 1)
        .map(|i| value(&format!("v{i}")))
        .collect();
    let selected = registry()
        .with_primary_hive(&sid(), Some(h))
        .unwrap()
        .with_user_policy(
            &sid(),
            Some(KeyTree {
                values: vec![value("last")],
                children: vec![],
            }),
        )
        .unwrap();
    assert_eq!(selected.value_budget().unwrap().count, MAX_VALUES);
    assert!(
        selected
            .with_tree(
                TreeRoot::Ifeo,
                Some(KeyTree {
                    values: vec![value("extra")],
                    children: vec![]
                })
            )
            .is_err()
    );
}

#[test]
fn primary_hive_route_matches_fold_once_and_retains_immutable_earlier_handles() {
    let mut table: Vec<_> = (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect();
    table[b'O' as usize] = b'X' as u16;
    let before = Registry::selected(table, vec![])
        .unwrap()
        .with_primary_hive(&sid(), Some(header(9)))
        .unwrap();
    let old = before.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
    let after = before.with_user_policy(&sid(), Some(tree())).unwrap();
    let root = after.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
    let suffix = format!("{}\\option", user_policy::POLICY_SUFFIX);
    assert!(matches!(old.relative(&units(&suffix)), Lookup::Unselected));
    let Lookup::Present(child) = root.relative(&units(&suffix)) else {
        panic!("folded twice")
    };
    assert_eq!(child.value(&units("raw")).unwrap().data, [0, 255, 17]);
}

#[test]
fn primary_hive_two_fixed_policies_preserve_aliases_absence_and_all_capture_orders() {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        for presence in [[false, false], [false, true], [true, false], [true, true]] {
            let mut selected = registry();
            for operation in order {
                selected = if operation == 0 {
                    selected.with_primary_hive(&sid(), Some(header(9)))
                } else {
                    let root = UserPolicyRoot::ALL[operation - 1];
                    selected.with_user_policy_root(root, &sid(), presence[operation - 1].then(tree))
                }
                .unwrap();
            }
            let root = selected.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
            let alias = selected.key(&units("\\Registry\\User\\.DEFAULT")).unwrap();
            assert!(Arc::ptr_eq(&root, &alias));
            assert_eq!(
                selected.value_budget().unwrap().count,
                1 + presence.into_iter().filter(|&present| present).count() * 2
            );
            for (index, policy) in UserPolicyRoot::ALL.into_iter().enumerate() {
                let suffix = format!("{}\\OPTION", policy.suffix());
                for prefix in ["\\Registry\\User\\S-1-5-18", "\\Registry\\User\\.DEFAULT"] {
                    let actual = selected.lookup(&units(&format!("{prefix}{suffix}")));
                    if presence[index] {
                        let Lookup::Present(child) = actual else {
                            panic!("{prefix}{suffix}")
                        };
                        assert_eq!(child.value(&units("raw")).unwrap().data, [0, 255, 17]);
                    } else {
                        assert!(matches!(actual, Lookup::Missing));
                    }
                }
                let lookalike = format!("{}Suffix", policy.suffix());
                assert!(matches!(
                    root.relative(&units(&lookalike)),
                    Lookup::Unselected
                ));
            }
            drop(selected);
            for (index, policy) in UserPolicyRoot::ALL.into_iter().enumerate() {
                let suffix = format!("{}\\\\OPTION\\", policy.suffix());
                let actual = alias.relative(&units(&suffix));
                assert_eq!(matches!(actual, Lookup::Present(_)), presence[index]);
                assert_eq!(matches!(actual, Lookup::Missing), !presence[index]);
            }
        }
    }
}

#[test]
fn primary_hive_two_policy_routes_charge_values_once_and_reject_other_subjects() {
    let mut h = header(9);
    h.values = (0..MAX_VALUES - 2)
        .map(|i| value(&format!("v{i}")))
        .collect();
    let mut selected = registry().with_primary_hive(&sid(), Some(h)).unwrap();
    for root in UserPolicyRoot::ALL {
        selected = selected
            .with_user_policy_root(
                root,
                &sid(),
                Some(KeyTree {
                    values: vec![value("last")],
                    children: vec![],
                }),
            )
            .unwrap();
    }
    assert_eq!(selected.value_budget().unwrap().count, MAX_VALUES);
    assert!(selected.with_tree(TreeRoot::Ifeo, Some(tree())).is_err());
    let mut other = sid();
    other[8] = 19;
    for first in UserPolicyRoot::ALL {
        let base = registry()
            .with_user_policy_root(first, &sid(), None)
            .unwrap();
        assert!(
            base.clone()
                .with_user_policy_root(first, &sid(), None)
                .is_err()
        );
        let second = if first == UserPolicyRoot::Safer {
            UserPolicyRoot::System
        } else {
            UserPolicyRoot::Safer
        };
        assert!(base.with_user_policy_root(second, &other, None).is_err());
    }
}

fn user_nt_current_version_header(canonical: Vec<u16>) -> CommandHeader {
    CommandHeader {
        canonical,
        children: 2,
        enumeration: Some(vec![
            BasicChild {
                name: units("Zeta"),
                last_write: 57,
            },
            BasicChild {
                name: units("Alpha"),
                last_write: 41,
            },
        ]),
        values: Vec::new(),
        access: KeyAccess {
            maximum_access: 0x20019,
            system_security_status: 0xC0000061,
        },
    }
}

#[test]
fn user_registry_policy_preserves_presence_absence_and_denial_for_one_sid() {
    use super::super::snapshot_root::USER_REGISTRY_POLICY_SUFFIX;
    use crate::user::windows::nt::status::{
        STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    };
    let user = sid();
    let root = SnapshotRoot::UserRegistryPolicy;
    let path = root.path(&user).unwrap();
    let relative = units(&USER_REGISTRY_POLICY_SUFFIX[1..]);
    let policy = Value {
        name: units("DisableRegistryTools"),
        kind: 4,
        data: 1u32.to_le_bytes().to_vec(),
    };
    let header = CommandHeader {
        canonical: path.clone(),
        children: 0,
        enumeration: Some(vec![]),
        values: vec![policy.clone()],
        access: KeyAccess {
            maximum_access: 0x20019,
            system_security_status: 0xC0000061,
        },
    };
    let base = registry()
        .with_primary_hive(&user, Some(self::header(9)))
        .unwrap();
    for result in [
        Ok((header, None)),
        Err(STATUS_OBJECT_NAME_NOT_FOUND),
        Err(STATUS_OBJECT_PATH_NOT_FOUND),
        Err(STATUS_ACCESS_DENIED),
    ] {
        let mut selected = base.clone();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            selected = selected
                .with_snapshot_selection(root, &user, view, result.clone())
                .unwrap();
        }
        let hive = selected.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let absolute = selected.lookup_view(&path, view);
            let relative = hive.relative_in_view(&relative, view);
            match (result.as_ref().err().copied(), absolute, relative) {
                (None, Lookup::Present(a), Lookup::Present(b)) => {
                    assert!(Arc::ptr_eq(&a, &b));
                    assert_eq!(a.value(&policy.name), Some(&policy));
                    assert_eq!(a.captured_access().unwrap().grant(0x0200_0000), Ok(0x20019));
                    assert_eq!(
                        a.captured_access().unwrap().grant(2),
                        Err(STATUS_ACCESS_DENIED)
                    );
                }
                (Some(STATUS_ACCESS_DENIED), Lookup::Present(a), Lookup::Present(b)) => {
                    assert!(Arc::ptr_eq(&a, &b));
                    assert_eq!(a.open_denial(), Some(STATUS_ACCESS_DENIED));
                    assert!(a.value(&policy.name).is_none());
                }
                (Some(STATUS_OBJECT_NAME_NOT_FOUND), Lookup::Missing, Lookup::Missing)
                | (Some(STATUS_OBJECT_PATH_NOT_FOUND), Lookup::MissingPath, Lookup::MissingPath) => {
                }
                _ => panic!("registry-tools policy route disagrees with capture"),
            }
            let sibling = units(&format!(
                "\\Registry\\User\\S-1-5-19{USER_REGISTRY_POLICY_SUFFIX}"
            ));
            assert!(matches!(
                selected.lookup_view(&sibling, view),
                Lookup::Unselected
            ));
        }
    }
}

pub(crate) fn creator_compat_layer_fixture(override_path: Option<&str>) -> Registry {
    let user = sid();
    let path = SnapshotRoot::UserNtCurrentVersion.path(&user).unwrap();
    let mut parent = user_nt_current_version_header(path.clone());
    parent.children += 1;
    parent.enumeration.as_mut().unwrap().push(BasicChild {
        name: units("AppCompatFlags"),
        last_write: 101,
    });
    let mut layers = user_nt_current_version_header(path);
    layers.canonical.extend(units("\\AppCompatFlags\\Layers"));
    layers.children = 0;
    layers.enumeration = Some(Vec::new());
    layers.values = override_path.into_iter().map(value).collect();
    let mut selected = registry();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        selected = selected
            .with_creator_current_version(&user, view, Ok(parent.clone()), Some(Ok(layers.clone())))
            .unwrap();
    }
    selected
}

#[test]
fn user_nt_current_version_shared_header_keeps_native_order_and_creator_aliases() {
    use super::super::snapshot_root::USER_NT_CURRENT_VERSION_SUFFIX;
    let user = sid();
    let subject = SnapshotRoot::UserNtCurrentVersion;
    let path = subject.path(&user).unwrap();
    let alias = units(&format!(
        "\\Registry\\User\\.DEFAULT{USER_NT_CURRENT_VERSION_SUFFIX}"
    ));
    let header = user_nt_current_version_header(alias.clone());
    let selected = registry()
        .with_primary_hive(&user, Some(self::header(9)))
        .unwrap()
        .with_snapshot_selection(
            subject,
            &user,
            RegistryView::Native64,
            Ok((header.clone(), None)),
        )
        .unwrap()
        .with_snapshot_selection(
            subject,
            &user,
            RegistryView::Wow32,
            Ok((header.clone(), None)),
        )
        .unwrap();
    let hive = selected.key(&units("\\Registry\\User\\S-1-5-18")).unwrap();
    let relative = units(USER_NT_CURRENT_VERSION_SUFFIX);
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let Lookup::Present(direct) = selected.lookup_view(&path, view) else {
            panic!("creator's fixed key");
        };
        let Lookup::Present(relative) = hive.relative_in_view(&relative, view) else {
            panic!("creator's relative open");
        };
        let Lookup::Present(alias) = selected.lookup_view(&alias, view) else {
            panic!("creator's captured canonical spelling");
        };
        assert!(Arc::ptr_eq(&direct, &relative));
        assert!(Arc::ptr_eq(&direct, &alias));
        assert_eq!(direct.child_metadata(), header.enumeration.as_deref());
        assert_eq!(direct.captured_access().unwrap().grant(8), Ok(8));
        assert_eq!(direct.captured_access().unwrap().grant(2), Err(0xC0000022));
        assert!(matches!(
            direct.relative(&units("Zeta")),
            Lookup::Unselected
        ));
    }
    let outside = units(&format!(
        "\\Registry\\User\\S-1-5-19{USER_NT_CURRENT_VERSION_SUFFIX}"
    ));
    assert!(matches!(
        selected.lookup_view(&outside, RegistryView::Native64),
        Lookup::Unselected
    ));
}

#[test]
fn user_nt_current_version_keeps_missing_paths_and_rejects_conflicting_views() {
    let user = sid();
    let subject = SnapshotRoot::UserNtCurrentVersion;
    let path = subject.path(&user).unwrap();
    let primary = registry()
        .with_primary_hive(&user, Some(header(9)))
        .unwrap();
    let native = RegistryView::Native64;
    let wow = RegistryView::Wow32;

    let missing = primary
        .clone()
        .with_snapshot_selection(subject, &user, native, Err(0xC000003A))
        .unwrap();
    assert!(matches!(
        missing.lookup_view(&path, native),
        Lookup::MissingPath
    ));
    let observed = user_nt_current_version_header(path.clone());
    assert!(
        missing
            .with_snapshot_selection(subject, &user, wow, Ok((observed.clone(), None)))
            .is_err()
    );
    let selected = primary
        .with_snapshot_selection(subject, &user, native, Ok((observed.clone(), None)))
        .unwrap();
    let mut changed = observed;
    changed.enumeration.as_mut().unwrap().reverse();
    assert!(
        selected
            .with_snapshot_selection(subject, &user, wow, Ok((changed, None)))
            .is_err()
    );
}

#[test]
fn creator_compat_layers_retains_a_fixed_relative_route_in_each_view() {
    let user = sid();
    let root = SnapshotRoot::UserNtCurrentVersion.path(&user).unwrap();
    let route = units("AppCompatFlags\\Layers");
    let path: Vec<_> = root
        .iter()
        .copied()
        .chain(Some(92))
        .chain(route.iter().copied())
        .collect();
    let mut parent = user_nt_current_version_header(root.clone());
    parent.children += 1;
    parent.enumeration.as_mut().unwrap().push(BasicChild {
        name: units("AppCompatFlags"),
        last_write: 101,
    });
    let layer = CommandHeader {
        canonical: path.clone(),
        children: 0,
        enumeration: Some(Vec::new()),
        values: vec![value("fixture.exe")],
        access: parent.access,
    };
    let mut selected = registry()
        .with_primary_hive(&user, Some(header(9)))
        .unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        selected = selected
            .with_creator_current_version(&user, view, Ok(parent.clone()), Some(Ok(layer.clone())))
            .unwrap();
    }
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let Lookup::Present(current_version) = selected.lookup_view(&root, view) else {
            panic!("creator CurrentVersion");
        };
        let Lookup::Present(relative) = current_version.relative(&route) else {
            panic!("creator Layers via handle");
        };
        let Lookup::Present(absolute) = selected.lookup_view(&path, view) else {
            panic!("creator Layers via absolute path");
        };
        assert!(Arc::ptr_eq(&relative, &absolute));
        assert_eq!(
            relative.value(&units("FIXTURE.EXE")).unwrap().data,
            [0, 255, 17]
        );
        assert_eq!(relative.captured_access().unwrap().grant(0x101), Ok(1));
        assert!(matches!(
            current_version.relative(&units("AppCompatFlags\\LayersSibling")),
            Lookup::Unselected
        ));
    }
}

#[test]
fn creator_compat_layers_keeps_distinct_native_absences() {
    let user = sid();
    let path = SnapshotRoot::UserNtCurrentVersion.path(&user).unwrap();
    let route = units("AppCompatFlags\\Layers");
    let parent = user_nt_current_version_header(path.clone());
    let base = registry()
        .with_primary_hive(&user, Some(header(9)))
        .unwrap();
    let selected = base
        .with_creator_current_version(
            &user,
            RegistryView::Native64,
            Ok(parent.clone()),
            Some(Err(0xC000003A)),
        )
        .unwrap();
    let current_version = selected.key(&path).unwrap();
    assert!(matches!(
        current_version.relative(&route),
        Lookup::MissingPath
    ));
    assert!(
        selected
            .clone()
            .with_creator_current_version(
                &user,
                RegistryView::Wow32,
                Ok(parent.clone()),
                Some(Err(0xC0000034)),
            )
            .is_err()
    );
    let matching = selected
        .with_creator_current_version(
            &user,
            RegistryView::Wow32,
            Ok(parent),
            Some(Err(0xC000003A)),
        )
        .unwrap();
    let mut absolute = path;
    absolute.push(92);
    absolute.extend(route);
    assert!(matches!(
        matching.lookup_view(&absolute, RegistryView::Wow32),
        Lookup::MissingPath
    ));
}

#[test]
fn creator_theme_headers_bind_the_original_hive_and_preserve_access_outcomes() {
    use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;

    let sid = sid();
    let mut registry = registry().with_primary_hive(&sid, Some(header(9))).unwrap();
    let manager = SnapshotRoot::ThemeManager;
    let personalize = SnapshotRoot::ThemePersonalize;
    let preference = Value {
        name: units("AppsUseLightTheme"),
        kind: 4,
        data: 1u32.to_le_bytes().to_vec(),
    };
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        registry = registry
            .with_snapshot_selection(manager, &sid, view, Err(STATUS_ACCESS_DENIED))
            .unwrap()
            .with_snapshot_selection(
                personalize,
                &sid,
                view,
                Ok((
                    CommandHeader {
                        canonical: personalize.path(&sid).unwrap(),
                        children: 0,
                        enumeration: Some(Vec::new()),
                        values: vec![preference.clone()],
                        access: KeyAccess {
                            maximum_access: 0x20019,
                            system_security_status: 0xc000_0061,
                        },
                    },
                    None,
                )),
            )
            .unwrap();
    }
    let root = registry
        .key(&user_policy::user_hive_path(&sid).unwrap())
        .unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let specify = |suffix: &str| units(suffix.trim_start_matches('\\'));
        let manager_relative = specify(super::snapshot_root::THEME_MANAGER_SUFFIX);
        let personalize_relative = specify(super::snapshot_root::THEME_PERSONALIZE_SUFFIX);
        let Lookup::Present(blocked) = root.relative_in_view(&manager_relative, view) else {
            panic!("creator theme denied key");
        };
        assert_eq!(blocked.open_denial, Some(STATUS_ACCESS_DENIED));
        let Lookup::Present(key) = root.relative_in_view(&personalize_relative, view) else {
            panic!("creator theme preference");
        };
        assert_eq!(key.value(&units("appsuselighttheme")), Some(&preference));
        assert!(key.value(&units("ThemeDebuggees")).is_none());
        assert!(matches!(
            root.relative_in_view(
                &units("Software\\Microsoft\\Windows\\CurrentVersion\\Themes"),
                view
            ),
            Lookup::Unselected
        ));
        assert!(matches!(
            registry.lookup_view(&units("\\Registry\\User\\S-1-5-19\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"), view),
            Lookup::Unselected
        ));
    }
}

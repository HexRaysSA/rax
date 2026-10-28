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

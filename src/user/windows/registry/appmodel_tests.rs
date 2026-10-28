use super::*;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
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
fn leaf(byte: u8) -> KeyTree {
    KeyTree {
        values: vec![Value {
            name: units("View"),
            kind: 3,
            data: vec![byte],
        }],
        children: vec![],
    }
}
fn present(registry: &Registry, name: &str, view: RegistryView) -> Arc<Key> {
    match registry.lookup_view(&units(name), view) {
        Lookup::Present(key) => key,
        _ => panic!("expected captured {name}/{view:?}"),
    }
}

#[test]
fn appmodel_independent_views_absence_and_handle_owned_pair() {
    let registry = registry()
        .with_appmodel_view(
            AppModelRoot::Machine,
            RegistryView::Native64,
            Some(KeyTree {
                values: vec![],
                children: vec![(units("Child"), leaf(64))],
            }),
        )
        .unwrap()
        .with_appmodel_view(
            AppModelRoot::Machine,
            RegistryView::Wow32,
            Some(KeyTree {
                values: vec![],
                children: vec![(units("Child"), leaf(32))],
            }),
        )
        .unwrap();
    let root = present(&registry, MACHINE_KEY, RegistryView::Native64);
    let pair = registry.appmodel.clone();
    let weak = Arc::downgrade(&root);
    drop(registry);
    let Lookup::Present(child) = pair.relative(&root, &units("Child"), RegistryView::Wow32) else {
        panic!()
    };
    assert_eq!(child.value(&units("view")).unwrap().data, [32]);
    assert_eq!(child.appmodel_view, Some(RegistryView::Wow32));
    drop(root);
    assert!(weak.upgrade().is_some());
    drop(pair);
    assert!(weak.upgrade().is_none());
    assert_eq!(child.value(&units("VIEW")).unwrap().data, [32]);
    let missing = self::registry()
        .with_appmodel_view(AppModelRoot::Machine, RegistryView::Wow32, None)
        .unwrap();
    assert!(matches!(
        missing.lookup_view(&units(MACHINE_KEY), RegistryView::Wow32),
        Lookup::Missing
    ));
    assert!(matches!(
        missing.lookup(&units(MACHINE_KEY)),
        Lookup::Unselected
    ));
    assert!(
        missing
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Wow32, Some(leaf(1)))
            .is_err()
    );
    assert!(
        Registry::default()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, None)
            .is_err()
    );
}

#[test]
fn appmodel_normalizes_registry_separators_without_widening_selection() {
    let registry = registry()
        .with_appmodel_view(
            AppModelRoot::Machine,
            RegistryView::Native64,
            Some(KeyTree {
                values: vec![],
                children: vec![(units("Child"), leaf(64))],
            }),
        )
        .unwrap();
    for path in [
        format!("{MACHINE_KEY}\\Child"),
        format!("{MACHINE_KEY}\\\\child\\\\"),
        format!(
            "\\{}\\child",
            MACHINE_KEY
                .trim_start_matches('\\')
                .replace('\\', "\\\\")
                .to_lowercase()
        ),
    ] {
        assert_eq!(
            present(&registry, &path, RegistryView::Native64)
                .value(&units("view"))
                .unwrap()
                .data,
            [64]
        );
    }
    for suffix in [
        "\\missing",
        "\\Child\\missing",
        "\\.",
        "\\..",
        "\\/",
        "\\\0",
    ] {
        assert!(matches!(
            registry.lookup(&units(&format!("{MACHINE_KEY}{suffix}"))),
            Lookup::Missing
        ));
    }
    for path in [
        format!("{MACHINE_KEY}Suffix"),
        format!("{MACHINE_KEY}/Child"),
        MACHINE_KEY.trim_start_matches('\\').to_owned(),
        "\\Registry\\Machine\\Software\\Microsoft\\AppModel\\Lookaside".into(),
    ] {
        assert!(matches!(registry.lookup(&units(&path)), Lookup::Unselected));
    }
}

#[test]
fn appmodel_views_share_value_count_and_byte_budgets_with_existing_roots() {
    fn many(count: usize) -> KeyTree {
        KeyTree {
            values: (0..count)
                .map(|n| Value {
                    name: units(&n.to_string()),
                    kind: 3,
                    data: vec![],
                })
                .collect(),
            children: vec![],
        }
    }
    let registry = registry()
        .with_appmodel_view(
            AppModelRoot::Machine,
            RegistryView::Native64,
            Some(many(MAX_VALUES - 1)),
        )
        .unwrap();
    assert!(
        registry
            .clone()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Wow32, Some(leaf(32)))
            .is_ok()
    );
    assert!(
        registry
            .clone()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Wow32, Some(many(2)))
            .is_err()
    );
    assert!(registry.with_tree(TreeRoot::Ifeo, Some(many(2))).is_err());
    let full = KeyTree {
        values: (0..16)
            .map(|n| Value {
                name: units(&n.to_string()),
                kind: 3,
                data: vec![0; MAX_VALUE_BYTES - 16],
            })
            .collect(),
        children: vec![],
    };
    let registry = self::registry()
        .with_appmodel_view(AppModelRoot::Machine, RegistryView::Wow32, Some(full))
        .unwrap();
    assert!(
        registry
            .with_appmodel_view(
                AppModelRoot::Machine,
                RegistryView::Native64,
                Some(KeyTree {
                    values: vec![Value {
                        name: vec![],
                        kind: 3,
                        data: vec![0; 1024]
                    }],
                    children: vec![]
                })
            )
            .is_err()
    );
}

#[test]
fn appmodel_views_share_key_and_path_budgets_and_validate_children() {
    let root = KeyTree {
        values: vec![],
        children: (0..1023)
            .map(|n| (units(&n.to_string()), KeyTree::default()))
            .collect(),
    };
    let registry = registry()
        .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, Some(root))
        .unwrap();
    assert!(
        registry
            .clone()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Wow32, None)
            .is_ok()
    );
    assert!(
        registry
            .with_appmodel_view(
                AppModelRoot::Machine,
                RegistryView::Wow32,
                Some(KeyTree::default())
            )
            .is_err()
    );
    for name in [vec![], vec![0], units("a\\b"), vec![65; 256]] {
        assert!(
            self::registry()
                .with_appmodel_view(
                    AppModelRoot::Machine,
                    RegistryView::Native64,
                    Some(KeyTree {
                        values: vec![],
                        children: vec![(name, leaf(1))]
                    })
                )
                .is_err()
        );
    }
    let long = (0..32).fold(KeyTree::default(), |child, _| KeyTree {
        values: vec![],
        children: vec![(vec![65; 255], child)],
    });
    let root = KeyTree {
        values: vec![],
        children: (0..8)
            .map(|n| {
                (
                    units(&n.to_string()),
                    (0..31).fold(KeyTree::default(), |child, _| KeyTree {
                        values: vec![],
                        children: vec![(vec![65; 255], child)],
                    }),
                )
            })
            .collect(),
    };
    assert!(
        self::registry()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, Some(root))
            .is_err()
    );
    let root = KeyTree {
        values: vec![],
        children: vec![(units("extra"), long)],
    };
    assert!(
        self::registry()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, Some(root))
            .is_err()
    );
}

#[test]
fn appmodel_malformed_object_prefix_stays_outside_fixed_selection() {
    for tree in [None, Some(leaf(64))] {
        let registry = registry()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, tree)
            .unwrap();
        for leading in 2..=4 {
            let name = format!(
                "{}{}",
                "\\".repeat(leading),
                MACHINE_KEY.trim_start_matches('\\')
            );
            assert!(matches!(registry.lookup(&units(&name)), Lookup::Unselected));
        }
    }
}

#[test]
fn appmodel_sibling_roots_keep_independent_views_and_retained_catalogs() {
    let mut registry = registry();
    for selected in AppModelRoot::ALL {
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let byte = match (selected, view) {
                (AppModelRoot::Machine, RegistryView::Native64) => 64,
                (AppModelRoot::Machine, RegistryView::Wow32) => 32,
                (AppModelRoot::User, RegistryView::Native64) => 164,
                (AppModelRoot::User, RegistryView::Wow32) => 132,
            };
            registry = registry
                .with_appmodel_view(
                    selected,
                    view,
                    Some(KeyTree {
                        values: vec![],
                        children: vec![(units("Child"), leaf(byte))],
                    }),
                )
                .unwrap();
        }
    }
    let machine = present(&registry, MACHINE_KEY, RegistryView::Native64);
    let user = present(&registry, &USER_KEY.to_lowercase(), RegistryView::Native64);
    let catalog = registry.appmodel.clone();
    drop(registry);
    for (root, expected) in [(&machine, 32), (&user, 132)] {
        let Lookup::Present(child) = catalog.relative(root, &units("child"), RegistryView::Wow32)
        else {
            panic!("sibling snapshot lost")
        };
        assert_eq!(child.value(&units("View")).unwrap().data, [expected]);
        assert!(matches!(
            catalog.relative(root, &units("..\\machine"), RegistryView::Wow32),
            Lookup::Missing
        ));
    }
    let registry = self::registry()
        .with_appmodel_view(AppModelRoot::User, RegistryView::Native64, None)
        .unwrap();
    assert!(matches!(registry.lookup(&units(USER_KEY)), Lookup::Missing));
    assert!(matches!(
        registry.lookup(&units(MACHINE_KEY)),
        Lookup::Unselected
    ));
    for name in [
        format!("{USER_KEY}Suffix"),
        USER_KEY.replace("\\Machine\\", "\\User\\"),
        format!("\\{USER_KEY}"),
    ] {
        assert!(matches!(registry.lookup(&units(&name)), Lookup::Unselected));
    }
}

#[test]
fn appmodel_sibling_roots_share_value_and_tree_budgets() {
    let full = KeyTree {
        values: (0..MAX_VALUES)
            .map(|n| Value {
                name: units(&n.to_string()),
                kind: 3,
                data: vec![],
            })
            .collect(),
        children: vec![],
    };
    let registry = registry()
        .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, Some(full))
        .unwrap();
    assert!(
        registry
            .clone()
            .with_appmodel_view(AppModelRoot::User, RegistryView::Wow32, None)
            .is_ok()
    );
    assert!(
        registry
            .with_appmodel_view(AppModelRoot::User, RegistryView::Wow32, Some(leaf(132)))
            .is_err()
    );
    let full = KeyTree {
        values: vec![],
        children: (0..1023)
            .map(|n| (units(&n.to_string()), KeyTree::default()))
            .collect(),
    };
    assert!(
        self::registry()
            .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, Some(full))
            .unwrap()
            .with_appmodel_view(
                AppModelRoot::User,
                RegistryView::Native64,
                Some(KeyTree::default())
            )
            .is_err()
    );
}

use super::*;

fn registry() -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
}
fn units(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}
fn value(name: Vec<u16>, data: Vec<u8>) -> Value {
    Value {
        name,
        kind: 4,
        data,
    }
}
fn nested(depth: usize, leaf: IfeoTree) -> IfeoTree {
    (0..depth).fold(leaf, |child, _| IfeoTree {
        values: vec![],
        children: vec![(units("child"), child)],
    })
}
#[test]
fn ifeo_closed_tree_preserves_raw_values_and_descendant_handle_lifetime() {
    let raw = value(vec![0xD800, 97], vec![0xFF, 0, 1]);
    let tree = IfeoTree {
        values: vec![],
        children: vec![(
            units("Image.EXE"),
            IfeoTree {
                values: vec![raw.clone()],
                children: vec![(units("Filter"), IfeoTree::default())],
            },
        )],
    };
    let registry = registry().with_ifeo(tree).unwrap();
    let budget = registry.value_budget().unwrap();
    assert_eq!((budget.count, budget.bytes), (1, 7));
    let root = registry.key(&units(IFEO_KEY)).unwrap();
    let child = registry
        .key(&units(&format!("{IFEO_KEY}\\image.exe")))
        .unwrap();
    assert!(Arc::ptr_eq(&root.upcase, &child.upcase));
    assert_eq!(child.value(&[0xD800, 65]), Some(&raw));
    assert_eq!(child.children, 1);
    let weak = Arc::downgrade(&child);
    drop(child);
    drop(registry);
    assert!(weak.upgrade().is_some());
    let Lookup::Present(child) = root.relative(&units("image.exe\\FILTER")) else {
        panic!("ancestor handle lost captured descendant");
    };
    assert!(child.subkeys.as_ref().unwrap().is_empty());
    drop(root);
    assert!(weak.upgrade().is_none());
    assert!(matches!(child.relative(&units("missing")), Lookup::Missing));
}
#[test]
fn ifeo_lookup_obeys_native_separator_absence_and_closed_scope() {
    let registry = registry()
        .with_ifeo(nested(1, IfeoTree::default()))
        .unwrap();
    let root = registry.key(&units(IFEO_KEY)).unwrap();
    for name in ["", "child", "child\\", "child\\\\", "\\\\child\\"] {
        assert!(
            matches!(root.relative(&units(name)), Lookup::Present(_)),
            "{name}"
        );
    }
    for name in [
        "missing",
        "missing\\nested",
        "child\\missing\\nested",
        ".",
        "..",
        "/",
    ] {
        assert!(
            matches!(root.relative(&units(name)), Lookup::Missing),
            "{name}"
        );
    }
    for suffix in ["\\missing", "\\child\\missing", "\\missing\\nested"] {
        assert!(matches!(
            registry.lookup(&units(&format!("{IFEO_KEY}{suffix}"))),
            Lookup::Missing
        ));
    }
    for name in [
        "\\Registry\\Machine\\unknown",
        &format!("{IFEO_KEY}Suffix\\child"),
    ] {
        assert!(matches!(registry.lookup(&units(name)), Lookup::Unselected));
    }
    assert!(matches!(
        Registry::default().lookup(&[]),
        Lookup::Unselected
    ));
    let absent = self::registry().with_absent_ifeo().unwrap();
    for suffix in ["", "\\child", "\\missing\\nested"] {
        assert!(matches!(
            absent.lookup(&units(&format!("{IFEO_KEY}{suffix}"))),
            Lookup::Missing
        ));
    }
    assert!(absent.with_ifeo(IfeoTree::default()).is_err());
    // Fold each component once, including for a supplied non-idempotent table.
    let mut table = registry.upcase.to_vec();
    table[97] = 65;
    table[65] = 66;
    let custom = Registry::selected(table, vec![])
        .unwrap()
        .with_ifeo(IfeoTree {
            values: vec![],
            children: vec![(units("a"), IfeoTree::default())],
        })
        .unwrap();
    assert!(matches!(
        custom.lookup(&units(&format!("{IFEO_KEY}\\a"))),
        Lookup::Present(_)
    ));
}
#[test]
fn ifeo_tree_rejects_colliding_names_grammar_depth_and_key_path_exhaustion() {
    for name in [
        vec![],
        vec![0],
        units("a\\b"),
        vec![65; MAX_COMPONENT_UNITS + 1],
    ] {
        assert!(
            registry()
                .with_ifeo(IfeoTree {
                    values: vec![],
                    children: vec![(name, IfeoTree::default())],
                })
                .is_err()
        );
    }
    assert!(
        registry()
            .with_ifeo(IfeoTree {
                values: vec![],
                children: vec![
                    (units("image"), IfeoTree::default()),
                    (units("IMAGE"), IfeoTree::default())
                ],
            })
            .is_err()
    );
    assert!(
        registry()
            .with_ifeo(nested(MAX_TREE_DEPTH, IfeoTree::default()))
            .is_ok()
    );
    assert!(
        registry()
            .with_ifeo(nested(MAX_TREE_DEPTH + 1, IfeoTree::default()))
            .is_err()
    );
    let star = |count| IfeoTree {
        values: vec![],
        children: (0..count)
            .map(|i| (vec![0x8000 + i as u16], IfeoTree::default()))
            .collect(),
    };
    assert!(registry().with_ifeo(star(MAX_TREE_KEYS - 1)).is_ok());
    assert!(registry().with_ifeo(star(MAX_TREE_KEYS)).is_err());
    let mut wide = IfeoTree {
        values: vec![],
        children: (0..200)
            .map(|i| (vec![0x8000 + i; MAX_COMPONENT_UNITS], IfeoTree::default()))
            .collect(),
    };
    for _ in 0..15 {
        wide = IfeoTree {
            values: vec![],
            children: vec![(vec![0x9000; MAX_COMPONENT_UNITS], wide)],
        };
    }
    let error = registry().with_ifeo(wide).unwrap_err();
    assert!(error.to_string().contains("key/path budget"));
    assert!(Registry::default().with_ifeo(IfeoTree::default()).is_err());
    assert!(
        registry()
            .with_ifeo(IfeoTree::default())
            .unwrap()
            .with_ifeo(IfeoTree::default())
            .is_err()
    );
}
#[test]
fn ifeo_values_share_existing_namespace_count_byte_and_collision_budgets() {
    let mut registry = registry();
    registry = Registry::selected(
        registry.upcase.to_vec(),
        vec![SelectedKey {
            path: NLS_KEY,
            children: 0,
            values: (0..MAX_VALUES)
                .map(|i| value(vec![0x8000 + i as u16], vec![]))
                .collect(),
        }],
    )
    .unwrap();
    assert!(
        registry
            .with_ifeo(IfeoTree {
                values: vec![value(units("extra"), vec![])],
                children: vec![],
            })
            .is_err()
    );
    for values in [
        vec![value(units("a"), vec![]), value(units("A"), vec![])],
        vec![value(units("large"), vec![0; MAX_VALUE_BYTES + 1])],
        (0..17)
            .map(|i| value(vec![0x8000 + i], vec![0; MAX_VALUE_BYTES]))
            .collect(),
    ] {
        assert!(
            self::registry()
                .with_ifeo(IfeoTree {
                    values,
                    children: vec![]
                })
                .is_err()
        );
    }
}

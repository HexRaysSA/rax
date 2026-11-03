use super::*;

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn registry() -> Registry {
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
}

fn captured(children: u32) -> CapturedTree {
    let root = units(IFEO_KEY);
    let denied = tree::child_path(&root, &units("Zulu.exe")).unwrap();
    let readable = tree::child_path(&root, &units("Alpha.exe")).unwrap();
    CapturedTree {
        tree: KeyTree {
            values: vec![],
            children: vec![
                (units("Zulu.exe"), KeyTree::default()),
                (
                    units("Alpha.exe"),
                    KeyTree {
                        values: vec![Value {
                            name: units("Flag"),
                            kind: 4,
                            data: 42u32.to_le_bytes().to_vec(),
                        }],
                        children: vec![],
                    },
                ),
            ],
        },
        nodes: BTreeMap::from([
            (
                root,
                CapturedTreeNode::Readable(vec![
                    BasicChild {
                        name: units("Zulu.exe"),
                        last_write: 0x1122_3344_5566_7788,
                    },
                    BasicChild {
                        name: units("Alpha.exe"),
                        last_write: 0x8877_6655_4433_2211,
                    },
                ]),
            ),
            (denied, CapturedTreeNode::Denied { children }),
            (readable, CapturedTreeNode::Readable(vec![])),
        ]),
    }
}

#[test]
fn captured_tree_retains_denial_parent_order_and_accessible_sibling_after_drop() {
    let registry = registry()
        .with_captured_tree(TreeRoot::Ifeo, Some(captured(0)))
        .unwrap();
    let parent = registry.key(&units(IFEO_KEY)).unwrap();
    let entries = parent.child_metadata().unwrap();
    assert_eq!(entries[0].name, units("Zulu.exe"));
    assert_eq!(entries[0].last_write, 0x1122_3344_5566_7788);
    assert_eq!(entries[1].name, units("Alpha.exe"));
    assert!(parent.open_denial().is_none());
    drop(registry);
    let Lookup::Present(denied) = parent.relative(&units("zULU.exe\\\\")) else {
        panic!("denied node disappeared");
    };
    assert_eq!(denied.open_denial(), Some(STATUS_ACCESS_DENIED));
    assert!(matches!(
        parent.relative(&units("Zulu.exe\\missing")),
        Lookup::Missing
    ));
    assert!(matches!(
        parent.relative(&units("absent.exe")),
        Lookup::Missing
    ));
    let Lookup::Present(readable) = parent.relative(&units("alpha.exe")) else {
        panic!("accessible sibling disappeared");
    };
    assert!(readable.open_denial().is_none());
    assert_eq!(
        readable.value(&units("FLAG")).unwrap().data,
        42u32.to_le_bytes()
    );
}

#[test]
fn captured_tree_does_not_invent_descendant_absence_below_an_unreadable_nonleaf() {
    for count in [1, 17, u32::MAX] {
        let registry = registry()
            .with_captured_tree(TreeRoot::Ifeo, Some(captured(count)))
            .unwrap();
        let denied = registry
            .key(&units(&format!("{IFEO_KEY}\\Zulu.exe")))
            .unwrap();
        assert_eq!(denied.children, count);
        assert_eq!(denied.open_denial(), Some(STATUS_ACCESS_DENIED));
        assert!(matches!(
            denied.relative(&units("uncaptured")),
            Lookup::Unselected
        ));
        assert!(matches!(
            registry.lookup(&units(&format!("{IFEO_KEY}Suffix\\Zulu.exe"))),
            Lookup::Unselected
        ));
    }
}

#[test]
fn captured_tree_rejects_missing_extra_or_invented_metadata() {
    for mutation in 0..6 {
        let mut capture = captured(0);
        match mutation {
            0 => {
                capture.nodes.remove(&units(IFEO_KEY));
            }
            1 => {
                capture
                    .nodes
                    .insert(units("\\outside"), CapturedTreeNode::Denied { children: 0 });
            }
            2 => {
                capture
                    .nodes
                    .insert(units(IFEO_KEY), CapturedTreeNode::Denied { children: 0 });
            }
            3 => {
                capture.tree.children[0].1.values.push(Value {
                    name: vec![],
                    kind: 4,
                    data: vec![1],
                });
            }
            4 => {
                capture.tree.children[0]
                    .1
                    .children
                    .push((units("invented"), KeyTree::default()));
            }
            5 => {
                capture.nodes.insert(
                    units(IFEO_KEY),
                    CapturedTreeNode::Readable(vec![BasicChild {
                        name: units("different.exe"),
                        last_write: 0,
                    }]),
                );
            }
            _ => unreachable!(),
        }
        assert!(
            registry()
                .with_captured_tree(TreeRoot::Ifeo, Some(capture))
                .is_err(),
            "mutation{mutation}"
        );
    }
}

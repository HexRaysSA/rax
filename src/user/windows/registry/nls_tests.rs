//! Fixed, populated NLS snapshot replay from independently acquired native data.
use super::*;

pub(crate) fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}
pub(crate) fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn native_units(text: &str) -> Vec<u16> {
    bytes(text)
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect()
}
pub(crate) fn observations() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-key/nls-tree/records-v1.json"
    )))
    .unwrap()
}
pub(crate) fn empty() -> Registry {
    // Every key and numeric codepage name in this corpus is ASCII. Unicode
    // folding and non-ASCII metadata are covered by the independent fixtures.
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
}
pub(crate) fn fixture(label: &str, view: u32) -> InformationTree {
    let data = observations();
    let nodes = data["observations"][label][view.to_string()]
        .as_array()
        .unwrap();
    let by_path: BTreeMap<_, _> = nodes
        .iter()
        .map(|node| (native_units(node["path_utf16"].as_str().unwrap()), node))
        .collect();
    fn contents(path: &[u16], nodes: &BTreeMap<Vec<u16>, &serde_json::Value>) -> KeyTree {
        let node = nodes[path];
        KeyTree {
            values: node["values"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| Value {
                    name: native_units(value["name_utf16"].as_str().unwrap()),
                    kind: value["type"].as_u64().unwrap() as u32,
                    data: bytes(value["data"].as_str().unwrap()),
                })
                .collect(),
            children: node["children"]
                .as_array()
                .unwrap()
                .iter()
                .map(|child| {
                    let name = native_units(child["name_utf16"].as_str().unwrap());
                    let next = tree::child_path(path, &name).unwrap();
                    (name, contents(&next, nodes))
                })
                .collect(),
        }
    }
    InformationTree {
        tree: contents(&units(NLS_ROOT_KEY), &by_path),
        information: by_path
            .into_iter()
            .map(|(path, node)| {
                let records = std::array::from_fn(|class| {
                    if class == 7 {
                        vec![]
                    } else {
                        bytes(node["records"][class.to_string()].as_str().unwrap())
                    }
                });
                let tails =
                    std::array::from_fn(|class| match node["tails"][class].as_str().unwrap() {
                        "raw" => NameTail::Raw,
                        "zero_odd" => NameTail::ZeroOdd,
                        _ => panic!("uncaptured native name-copy plan"),
                    });
                let children = node["children"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|child| BasicChild {
                        name: native_units(child["name_utf16"].as_str().unwrap()),
                        last_write: child["last_write"].as_u64().unwrap(),
                    })
                    .collect();
                (
                    path,
                    KeyInformation::new(records, tails)
                        .unwrap()
                        .with_enumeration(children),
                )
            })
            .collect(),
    }
}

#[test]
fn complete_nls_keeps_populated_descendants_and_native_order_in_all_system_views() {
    for label in ["arm64", "x64", "x86"] {
        for view in [0, 0x100, 0x200] {
            let fixture = fixture(label, view);
            let expected_codepages: BTreeSet<_> = fixture
                .tree
                .children
                .iter()
                .find(|(name, _)| *name == units("CodePage"))
                .unwrap()
                .1
                .values
                .iter()
                .filter_map(|v| String::from_utf16(&v.name).unwrap().parse::<u32>().ok())
                .collect();
            let paths: Vec<_> = fixture.information.keys().cloned().collect();
            let selected = empty().with_nls_information_tree(fixture).unwrap();
            assert_eq!(paths.len(), 16);
            assert_eq!(selected.value_budget().unwrap().count, 584);
            assert_eq!(selected.codepages(), expected_codepages);
            assert!(selected.codepages().contains(&1252));
            for path in paths {
                let key = selected.key(&path).unwrap();
                assert!(Arc::ptr_eq(&key, &selected.key(&key.path).unwrap()));
                let order = key.child_metadata().unwrap();
                assert_eq!(order.len(), key.children as usize);
                for child in order {
                    let Lookup::Present(retained) = key.relative(&child.name) else {
                        panic!("native child missing")
                    };
                    assert_eq!(
                        &retained.information().unwrap().record(0).unwrap()[..8],
                        child.last_write.to_le_bytes()
                    );
                }
            }
        }
    }
}

#[test]
fn complete_nls_prevents_partial_shadowing_and_requires_codepage() {
    for root in [TreeRoot::NlsCustomLocale, TreeRoot::NlsSortingVersions] {
        assert!(
            empty()
                .with_tree(root, None)
                .unwrap()
                .with_nls_information_tree(fixture("arm64", 0))
                .is_err()
        );
        assert!(
            empty()
                .with_nls_information_tree(fixture("arm64", 0))
                .unwrap()
                .with_tree(root, None)
                .is_err()
        );
    }
    let partial = Registry::selected(
        empty().upcase.to_vec(),
        vec![SelectedKey {
            path: NLS_KEY,
            children: 0,
            values: vec![],
        }],
    )
    .unwrap();
    assert!(
        partial
            .with_nls_information_tree(fixture("arm64", 0))
            .is_err()
    );
    assert!(
        Registry::default()
            .with_nls_information_tree(fixture("arm64", 0))
            .is_err()
    );
    let mut missing = fixture("arm64", 0);
    missing
        .tree
        .children
        .retain(|(name, _)| *name != units("CodePage"));
    // Required selection is checked before binding inconsistent metadata.
    assert_eq!(
        empty()
            .with_nls_information_tree(missing)
            .err()
            .unwrap()
            .to_string(),
        "complete NLS selection lacks required CodePage key"
    );
    assert!(
        empty()
            .with_nls_information_tree(fixture("arm64", 0))
            .unwrap()
            .with_nls_information_tree(fixture("arm64", 0))
            .is_err()
    );
}

#[test]
fn complete_nls_machine_routes_and_retained_descendants_share_one_snapshot() {
    let selected = empty()
        .with_nls_information_tree(fixture("arm64", 0))
        .unwrap()
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: units(MACHINE_HIVE_KEY),
            children: 1,
            values: vec![],
            access: KeyAccess {
                maximum_access: 0x20019,
                system_security_status: 0xC0000022,
            },
        })
        .unwrap();
    let logical = units(&format!("{NLS_ROOT_KEY}\\CodePage\\EUDCCodeRange"));
    let key = selected.key(&logical).unwrap();
    let machine = selected.key(&units(MACHINE_HIVE_KEY)).unwrap();
    let prefix = MACHINE_HIVE_KEY.encode_utf16().count() + 1;
    for path in [&logical, &key.path] {
        let Lookup::Present(relative) = machine.relative(&path[prefix..]) else {
            panic!("MACHINE descendant alias missing")
        };
        assert!(Arc::ptr_eq(&key, &relative));
    }
    assert!(matches!(
        selected.lookup(&units(&format!("{NLS_ROOT_KEY}Suffix"))),
        Lookup::Unselected
    ));
    assert!(matches!(
        selected.lookup(&units(&format!("{NLS_ROOT_KEY}\\absent\\nested"))),
        Lookup::Missing
    ));
    let extended = selected
        .key(&units(&format!("{NLS_ROOT_KEY}\\ExtendedLocale")))
        .unwrap();
    assert_eq!(extended.children, 0);
    assert!(extended.values.is_empty());
    drop(selected);
    assert!(key.information().is_some());
    assert!(matches!(
        machine.relative(&logical[prefix..]),
        Lookup::Present(_)
    ));
}

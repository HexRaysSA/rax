use super::*;
use std::io::Read;

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
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
fn native_records() -> [Vec<u8>; 9] {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-key/metadata/records-v1.json"
    )))
    .unwrap();
    std::array::from_fn(|class| {
        if class == 7 {
            vec![]
        } else {
            bytes(
                data["observations"]["arm64"]["records"][class.to_string()]
                    .as_str()
                    .unwrap(),
            )
        }
    })
}

pub(crate) fn nls_tree_fixture() -> InformationTree {
    InformationTree {
        tree: KeyTree::default(),
        information: BTreeMap::from([(
            units(NLS_CUSTOM_LOCALE_KEY),
            KeyInformation::new(native_records(), [NameTail::ZeroOdd; 2]).unwrap(),
        )]),
    }
}

#[test]
fn native_key_information_rejects_incomplete_layouts_tags_and_races() {
    let good = native_records();
    assert!(KeyInformation::new(good.clone(), [NameTail::ZeroOdd; 2]).is_ok());
    for class in [0, 1, 2, 3, 4, 5, 6, 8] {
        let mut records = good.clone();
        records[class].truncate(HEADERS[class] - 1);
        assert!(
            KeyInformation::new(records, [NameTail::Raw; 2]).is_err(),
            "class{class}"
        );
    }
    let mut records = good.clone();
    records[7] = vec![0; 4];
    assert!(KeyInformation::new(records, [NameTail::Raw; 2]).is_err());
    for class in [1, 2, 4] {
        let mut records = good.clone();
        records[class][0] ^= 1;
        assert!(KeyInformation::new(records, [NameTail::Raw; 2]).is_err());
    }
    let mut records = good.clone();
    records[3][0] ^= 1;
    assert!(KeyInformation::new(records, [NameTail::Raw; 2]).is_err());
    let mut records = good;
    records[1][12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    records[1][16..20].copy_from_slice(&2u32.to_le_bytes());
    assert!(KeyInformation::new(records, [NameTail::Raw; 2]).is_err());
}

#[test]
fn native_key_information_bindings_require_complete_contents_and_fixed_subjects() {
    let root = TreeRoot::NlsCustomLocale;
    let mut tree = nls_tree_fixture();
    tree.information.clear();
    assert!(registry().with_information_tree(root, Some(tree)).is_err());
    let mut tree = nls_tree_fixture();
    tree.tree.values.push(Value {
        name: units("unexpected"),
        kind: 3,
        data: vec![1],
    });
    assert!(registry().with_information_tree(root, Some(tree)).is_err());
    let mut tree = nls_tree_fixture();
    tree.information.insert(
        units("extra"),
        KeyInformation::new(native_records(), [NameTail::Raw; 2]).unwrap(),
    );
    assert!(registry().with_information_tree(root, Some(tree)).is_err());
    let mut raw = native_records();
    let at = raw[3].windows(2).position(|b| b == [b'M', 0]).unwrap();
    raw[3][at] = b'X';
    let mut tree = nls_tree_fixture();
    tree.information.insert(
        units(NLS_CUSTOM_LOCALE_KEY),
        KeyInformation::new(raw, [NameTail::Raw; 2]).unwrap(),
    );
    assert!(registry().with_information_tree(root, Some(tree)).is_err());
}

#[test]
fn native_key_information_logical_canonical_and_machine_routes_survive_snapshot_drop() {
    let original = registry();
    let selected = original
        .with_information_tree(TreeRoot::NlsCustomLocale, Some(nls_tree_fixture()))
        .unwrap();
    let logical = units(NLS_CUSTOM_LOCALE_KEY);
    let key = selected.key(&logical).unwrap();
    let canonical = key.path.clone();
    assert_ne!(key.fold(&canonical), key.fold(&logical));
    assert!(Arc::ptr_eq(&key, &selected.key(&canonical).unwrap()));
    assert!(matches!(
        selected.lookup(&units(&format!(
            "{}Suffix",
            String::from_utf16_lossy(&canonical)
        ))),
        Lookup::Unselected
    ));
    let selected = selected
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
    let machine = selected.key(&units(MACHINE_HIVE_KEY)).unwrap();
    let prefix = MACHINE_HIVE_KEY.encode_utf16().count() + 1;
    for path in [&logical, &canonical] {
        let Lookup::Present(relative) = machine.relative(&path[prefix..]) else {
            panic!("MACHINE alias route lost")
        };
        assert!(Arc::ptr_eq(&key, &relative));
    }
    drop(selected);
    assert_eq!(
        key.information().unwrap().record(3).unwrap()[4..],
        canonical
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>()
    );
    assert!(matches!(key.relative(&units("missing")), Lookup::Missing));
    assert!(matches!(
        machine.relative(&logical[prefix..]),
        Lookup::Present(_)
    ));
}

#[test]
fn native_key_information_records_and_aliases_charge_exact_aggregate_limits() {
    let record = KeyInformation::new(native_records(), [NameTail::Raw; 2]).unwrap();
    let mut limits = super::super::budget::STARTUP;
    limits.value_bytes = record.bytes();
    let mut budget = ValueBudget::with_limits(limits);
    budget.charge_information(&record).unwrap();
    assert!(budget.charge_information(&record).is_err());
    limits.value_bytes -= 1;
    assert!(
        ValueBudget::with_limits(limits)
            .charge_information(&record)
            .is_err()
    );
    let path = record.canonical();
    limits.path_bytes = path.len() * 2;
    let mut paths = tree::TreeBudget::with_limits(limits);
    paths.charge_alias(&path).unwrap();
    assert!(paths.charge_alias(&[1]).is_err());
}

fn fixture_corpus(encoded: &[u8]) {
    let mut text = String::new();
    let mut decoder = zstd::stream::read::Decoder::new(encoded)
        .unwrap()
        .take(128 << 20);
    decoder.read_to_string(&mut text).unwrap();
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut raw: BTreeMap<u64, [Vec<u8>; 9]> = BTreeMap::new();
    for row in &rows {
        if row["kind"] == "record" && row["class"] != 7 {
            let subject = row["subject"].as_u64().unwrap();
            let class = row["class"].as_u64().unwrap() as usize;
            let data = bytes(row["bytes"].as_str().unwrap());
            assert_eq!(data, bytes(row["opposite"].as_str().unwrap()));
            raw.entry(subject)
                .or_insert_with(|| std::array::from_fn(|_| vec![]))[class] = data;
        }
    }
    assert_eq!(raw.len(), 4);
    let information: BTreeMap<_, _> = raw
        .into_iter()
        .map(|(subject, records)| {
            let mut tails = [NameTail::Raw; 2];
            for class in 0..2 {
                let offset = HEADERS[class];
                let length = word(&records[class], if class == 0 { 12 } else { 20 });
                if let Some(index) = (offset..offset + length)
                    .step_by(2)
                    .find(|&i| records[class][i] != 0)
                {
                    let sample: Vec<_> = rows
                        .iter()
                        .filter(|r| {
                            r["kind"] == "case"
                                && r["subject"] == subject
                                && r["class"] == class as u64
                                && r["length"] == index as u64 + 1
                                && r["alias"] == -1
                        })
                        .collect();
                    assert_eq!(sample.len(), 2);
                    let a = bytes(sample[0]["bytes"].as_str().unwrap());
                    let b = bytes(sample[1]["bytes"].as_str().unwrap());
                    assert_eq!(a[..index + 1], b[..index + 1]);
                    if a[..index + 1] != records[class][..index + 1] {
                        assert_eq!(a[..index], records[class][..index]);
                        assert_eq!(a[index], 0);
                        tails[class] = NameTail::ZeroOdd;
                    }
                }
            }
            (subject, KeyInformation::new(records, tails).unwrap())
        })
        .collect();
    let mut count = 0;
    for row in rows
        .iter()
        .filter(|r| r["kind"] == "case" && r["class"] != 7)
    {
        let class = row["class"].as_u64().unwrap() as u32;
        if class > 8 {
            let poison = row["poison"].as_u64().unwrap() as u8;
            assert_eq!(row["status"], 0xC000000Du64);
            assert_eq!(
                bytes(row["bytes"].as_str().unwrap()),
                vec![poison; bytes(row["bytes"].as_str().unwrap()).len()]
            );
            let returned = if row["alias"] == -1 {
                0x7F7F7F7F
            } else {
                u32::from_le_bytes([poison; 4])
            };
            assert_eq!(row["returned"], returned);
            count += 1;
            continue;
        }
        let record = information[&row["subject"].as_u64().unwrap()]
            .record(class)
            .unwrap();
        let actual = bytes(row["bytes"].as_str().unwrap());
        let mut expected = vec![row["poison"].as_u64().unwrap() as u8; actual.len()];
        let alias = row["alias"].as_i64().unwrap();
        if alias >= 0 {
            expected[alias as usize..alias as usize + 4]
                .copy_from_slice(&(record.len() as u32).to_le_bytes());
        }
        let length = row["length"].as_u64().unwrap() as usize;
        let status = if length < HEADERS[class as usize] {
            0xC0000023u64
        } else {
            let copied = length.min(record.len());
            expected[..copied].copy_from_slice(&record[..copied]);
            if information[&row["subject"].as_u64().unwrap()].zero_partial_name_tail(class, length)
            {
                expected[copied - 1] = 0;
            }
            if length < record.len() { 0x80000005 } else { 0 }
        };
        assert_eq!(
            row["status"], status,
            "subject{}/class{class}/len{length}",
            row["subject"]
        );
        assert_eq!(
            actual, expected,
            "subject{}/class{class}/len{length}/alias{alias}",
            row["subject"]
        );
        let returned = if alias < 0 {
            record.len() as u32
        } else {
            u32::from_le_bytes(
                expected[alias as usize..alias as usize + 4]
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(row["returned"], returned);
        count += 1;
    }
    assert_eq!(count, 40_712, "native fixture cases were omitted");
}

#[test]
fn native_key_information_replays_unicode_nonempty_classes_partial_copies_and_aliases() {
    for encoded in [
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-query-key/metadata/arm64-fixture-v2.jsonl.zst"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-query-key/metadata/x64-fixture-v2.jsonl.zst"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-query-key/metadata/x86-fixture-v2.jsonl.zst"
        ))
        .as_slice(),
    ] {
        fixture_corpus(encoded);
    }
}

fn synthetic_information(canonical: &str, children: u32, timestamp: u64) -> KeyInformation {
    let mut records = native_records();
    let name = canonical
        .rsplit('\\')
        .next()
        .unwrap()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    for class in [0, 1] {
        let offset = HEADERS[class];
        records[class].truncate(offset);
        let at = if class == 0 { 12 } else { 20 };
        records[class][at..at + 4].copy_from_slice(&(name.len() as u32).to_le_bytes());
        records[class].extend_from_slice(&name);
    }
    let path = canonical
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    records[3] = (path.len() as u32)
        .to_le_bytes()
        .into_iter()
        .chain(path)
        .collect();
    for class in [0, 1, 2, 4] {
        records[class][..8].copy_from_slice(&timestamp.to_le_bytes());
    }
    records[2][20..24].copy_from_slice(&children.to_le_bytes());
    records[4][12..16].copy_from_slice(&children.to_le_bytes());
    records[4][32..36].copy_from_slice(&(name.len() as u32).to_le_bytes());
    KeyInformation::new(records, [NameTail::Raw; 2]).unwrap()
}

fn nonempty_tree(stale_child: bool) -> InformationTree {
    let root = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Control\\Nls\\CustomLocale";
    let entries = vec![
        BasicChild {
            name: units("Ω"),
            last_write: 41,
        },
        BasicChild {
            name: units("Alpha"),
            last_write: 42,
        },
    ];
    let information = BTreeMap::from([
        (
            units(NLS_CUSTOM_LOCALE_KEY),
            synthetic_information(root, 2, 40).with_enumeration(entries),
        ),
        (
            units(&format!("{NLS_CUSTOM_LOCALE_KEY}\\Ω")),
            synthetic_information(&format!("{root}\\Ω"), 0, if stale_child { 43 } else { 41 })
                .with_enumeration(vec![]),
        ),
        (
            units(&format!("{NLS_CUSTOM_LOCALE_KEY}\\Alpha")),
            synthetic_information(&format!("{root}\\Alpha"), 0, 42).with_enumeration(vec![]),
        ),
    ]);
    InformationTree {
        tree: KeyTree {
            values: vec![],
            children: vec![
                (units("Ω"), KeyTree::default()),
                (units("Alpha"), KeyTree::default()),
            ],
        },
        information,
    }
}

#[test]
fn native_key_information_keeps_native_child_order_and_canonical_descendant_identity() {
    let selected = registry()
        .with_information_tree(TreeRoot::NlsCustomLocale, Some(nonempty_tree(false)))
        .unwrap();
    let root = selected.key(&units(NLS_CUSTOM_LOCALE_KEY)).unwrap();
    assert_eq!(
        root.child_metadata()
            .unwrap()
            .iter()
            .map(|child| child.name.clone())
            .collect::<Vec<_>>(),
        vec![units("Ω"), units("Alpha")]
    );
    let Lookup::Present(child) = root.relative(&units("\\\\ALPHA\\")) else {
        panic!("captured child missing")
    };
    assert!(Arc::ptr_eq(&child, &selected.key(&child.path).unwrap()));
    assert!(Arc::ptr_eq(
        &child,
        &selected
            .key(&units(&format!("{NLS_CUSTOM_LOCALE_KEY}\\Alpha")))
            .unwrap()
    ));
    drop(selected);
    assert_eq!(
        child.information().unwrap().record(0).unwrap()[..8],
        42u64.to_le_bytes()
    );
}

#[test]
fn native_key_information_rejects_child_changes_after_ordered_enumeration() {
    assert!(
        registry()
            .with_information_tree(TreeRoot::NlsCustomLocale, Some(nonempty_tree(true)))
            .is_err()
    );
    let mut tree = nonempty_tree(false);
    tree.information
        .get_mut(&units(NLS_CUSTOM_LOCALE_KEY))
        .unwrap()
        .enumeration = None;
    assert!(
        registry()
            .with_information_tree(TreeRoot::NlsCustomLocale, Some(tree))
            .is_err()
    );
}

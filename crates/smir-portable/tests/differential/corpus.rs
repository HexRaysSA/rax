//! Independent inventory from schema edges, without importing Python's traversal.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;

pub(crate) fn expected_wire_ids(root: &Path) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut records = BTreeMap::<String, Value>::new();
    let mut queue = VecDeque::new();
    for owner in ["execution", "runtime", "abi"] {
        let path = root.join(format!("docs/specifications/smir/portable/schema/{owner}/candidate.json"));
        let schema: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        for (name, definition) in schema["records"].as_object().unwrap() {
            if let Some(previous) = records.insert(name.clone(), definition.clone()) {
                assert_eq!(previous, *definition, "conflicting shared schema record {name}");
            }
        }
        if let Some(roots) = schema["roots"].as_object() {
            for name in roots.values() {
                queue.push_back(name.as_str().unwrap().to_owned());
            }
        } else {
            assert_eq!(owner, "abi");
            assert_eq!(schema["section_reserved_by_integrator"], 10);
            queue.push_back(schema["root"].as_str().unwrap().to_owned());
        }
    }
    let mut reachable = BTreeSet::new();
    let mut expected = BTreeSet::new();
    while let Some(name) = queue.pop_front() {
        if !reachable.insert(name.clone()) {
            continue;
        }
        let definition = &records[&name];
        let layouts: Vec<(&str, &Value)> = if let Some(variants) = definition["variants"].as_object() {
            assert!(definition["discriminator"].is_string());
            variants.iter().map(|(tag, fields)| (tag.as_str(), fields)).collect()
        } else {
            vec![("record", &definition["fields"])]
        };
        for (variant, fields) in layouts {
            assert!(expected.insert(format!("wire/{name}/{variant}")));
            for field in fields.as_array().unwrap() {
                let kind = field[1].as_str().unwrap();
                let child = kind.rsplit(':').next().unwrap();
                if records.contains_key(child) {
                    queue.push_back(child.to_owned());
                }
            }
        }
    }
    let outside = records.keys().filter(|name| !reachable.contains(*name)).cloned().collect();
    (expected, outside)
}

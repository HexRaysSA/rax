//! Independent native mutations: immutable record bytes and mutable key bodies.
use super::*;
use crate::user::windows::registry::{InformationTree, KeyInformation, KeyTree, NameTail};
use std::collections::BTreeMap;

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn native_key_information_metadata_stays_immutable_when_duplicate_body_tags_change() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-key/metadata/tags-v4/observations-v4.json"
    )))
    .unwrap();
    assert_eq!(corpus["native_queries"], 243);
    assert_eq!(corpus["native_tag_mutations"], 24);
    let mut queries = 0;
    let mut mutations = 0;
    for observed in corpus["observations"].as_array().unwrap() {
        let arch = match observed["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("uncaptured ABI"),
        };
        let before = observed["before"].as_array().unwrap();
        assert_eq!(before.len(), 9);
        let records = std::array::from_fn(|class| {
            if class == 7 {
                vec![]
            } else {
                bytes(before[class]["bytes"].as_str().unwrap())
            }
        });
        let path: Vec<_> = NLS_CUSTOM_LOCALE_KEY.encode_utf16().collect();
        let tree = InformationTree {
            tree: KeyTree::default(),
            information: BTreeMap::from([(
                path.clone(),
                KeyInformation::new(records, [NameTail::Raw; 2]).unwrap(),
            )]),
        };
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = p
            .registry
            .clone()
            .with_information_tree(TreeRoot::NlsCustomLocale, Some(tree))
            .unwrap();
        let key = p.registry.key(&path).unwrap();
        let initial = u32::from_le_bytes(
            bytes(before[7]["bytes"].as_str().unwrap())
                .try_into()
                .unwrap(),
        );
        let body = p.objects.create_registry_key(key.clone(), initial).unwrap();
        let handle = p.objects.open_access(body, false, 9).unwrap() as u64;
        let duplicate = p.objects.duplicate(handle, false).unwrap() as u64;
        let other = p.objects.create_registry_key(key, initial).unwrap();
        let independent = p.objects.open_access(other, false, 9).unwrap() as u64;
        p.registry = Registry::default();
        let after = observed["after"].as_array().unwrap();
        assert_eq!(after.len(), 72);
        let mut current_input = None;
        for (index, row) in before.iter().chain(after).enumerate() {
            assert_eq!(row["class"], (index % 9) as u64);
            if let Some(input) = row["input"]
                .as_u64()
                .filter(|input| current_input != Some(*input))
            {
                assert_eq!(row["class"], 0);
                current_input = Some(input);
                mutations += 1;
                p.space.w32(base + 1024, input as u32).unwrap();
                assert_eq!(
                    call(
                        p,
                        &mut t,
                        "NtSetInformationKey",
                        &[handle, 5, base + 1024, 4]
                    ) as u64,
                    row["set_status"].as_u64().unwrap()
                );
            }
            p.space.wr(base + 128, &[0xA5; 256]).unwrap();
            p.space.w32(base + 64, 0xA5A5A5A5).unwrap();
            let class = row["class"].as_u64().unwrap();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtQueryKey",
                    &[duplicate, class, base + 128, 256, base + 64]
                ) as u64,
                row["status"].as_u64().unwrap()
            );
            let record = bytes(row["bytes"].as_str().unwrap());
            let mut expected = vec![0xA5; 256];
            expected[..record.len()].copy_from_slice(&record);
            assert_eq!(
                p.space.bytes(base + 128, 256).unwrap(),
                expected,
                "{arch}/class{class}/input{}",
                row["input"]
            );
            assert_eq!(
                p.space.u32(base + 64).unwrap() as u64,
                row["required"].as_u64().unwrap()
            );
            queries += 1;
        }
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryKey",
                &[independent, 7, base + 128, 4, base + 64]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(base + 128).unwrap(), initial);
        for h in [handle, duplicate, independent] {
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        }
    }
    assert_eq!(queries, 243);
    assert_eq!(mutations, 24);
}

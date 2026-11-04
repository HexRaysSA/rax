//! Independent native open/view/tag observations reach the owning NT handlers.
use super::machine_hive::open;
use super::*;
use crate::user::windows::registry::{
    CURRENT_VERSION_KEY, CURRENT_VERSION_WOW_KEY, InformationTree, KeyAccess, KeyTree,
    MACHINE_HIVE_KEY, MachineHeader, RegistryView, TreeRoot, current_version_header_fixture,
    current_version_parent_fixture, current_version_registry_fixture,
};
use serde_json::Value as Json;
use std::collections::BTreeMap;

fn number(row: &Json, field: &str) -> u32 {
    row[field].as_u64().unwrap().try_into().unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn units(text: &str) -> Vec<u16> {
    bytes(text)
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect()
}
fn selected(p: &mut Proc, corpus: &Json) {
    let mut registry = current_version_registry_fixture();
    let native = &corpus["profiles"][0];
    for (index, root) in [(1, TreeRoot::Ifeo), (2, TreeRoot::GreInitialize)] {
        let row = native["profile"][1]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                number(r, "parent_view") == 0
                    && number(r, "view") == 0
                    && number(r, "child") == index
            })
            .unwrap();
        let path = units(row["name_hex"].as_str().unwrap());
        registry = registry
            .with_information_tree(
                root,
                Some(InformationTree {
                    tree: KeyTree::default(),
                    information: BTreeMap::from([(
                        root.path().encode_utf16().collect(),
                        current_version_header_fixture(path, 0, 0).information,
                    )]),
                }),
            )
            .unwrap();
    }
    for (profile, flag, view) in [
        (native, 0, RegistryView::Native64),
        (&corpus["profiles"][2], 0, RegistryView::Wow32),
    ] {
        let row = profile["profile"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                number(r, "extended") == 1
                    && number(r, "request") == 0x02000000
                    && number(r, "view") == flag
            })
            .unwrap();
        let mut header = current_version_header_fixture(
            units(row["name_hex"].as_str().unwrap()),
            number(row, "children"),
            number(row, "values"),
        );
        header.key.access.maximum_access = number(row, "granted_access");
        header.key.access.system_security_status = number(
            profile["profile"][0]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| {
                    number(r, "extended") == 1
                        && number(r, "request") == 0x01000000
                        && number(r, "view") == flag
                })
                .unwrap(),
            "status",
        );
        let end = header.key.canonical.iter().rposition(|u| *u == 92).unwrap();
        let parent = current_version_parent_fixture(header.key.canonical[..end].to_vec());
        registry = registry.with_current_version(view, Ok(header)).unwrap();
        registry = registry
            .with_current_version_parent(view, Ok(parent))
            .unwrap();
    }
    p.registry = registry
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: "\\REGISTRY\\MACHINE".encode_utf16().collect(),
            children: 6,
            values: vec![],
            access: KeyAccess {
                maximum_access: 0x20019,
                system_security_status: 0xC0000061,
            },
        })
        .unwrap();
}
fn observed(p: &mut Proc, t: &mut Thread, base: u64, h: u64, row: &Json) {
    for (class, field) in [(7, "tags_status"), (3, "name_status"), (2, "full_status")] {
        if row.get(field).is_none() {
            continue;
        }
        let out = base + 512;
        let returned = base + 256;
        let status = call(p, t, "NtQueryKey", &[h, class, out, 4096, returned]);
        assert_eq!(status, number(row, field), "class{class}/handle{h:x}");
        if status != STATUS_SUCCESS {
            continue;
        }
        if class == 7 {
            assert_eq!(p.space.u32(out).unwrap(), number(row, "tags"));
        }
        if class == 3 {
            let size = p.space.u32(out).unwrap() as usize;
            assert_eq!(
                p.space.bytes(out + 4, size).unwrap(),
                bytes(row["name_hex"].as_str().unwrap())
            );
        }
        if class == 2 {
            assert_eq!(p.space.u32(out + 20).unwrap(), number(row, "children"));
            assert_eq!(p.space.u32(out + 32).unwrap(), number(row, "values"));
        }
    }
}

#[test]
fn current_version_replays_all_1248_independent_native_open_view_and_retained_parent_cases() {
    let corpus: Json = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-current-version/controls-v1.json"
    ))
    .unwrap();
    assert_eq!(corpus["native_cases"], 1248);
    let mut count = 0;
    for profile in corpus["profiles"].as_array().unwrap() {
        let arch = match profile["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("native ABI"),
        };
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        selected(p, &corpus);
        for (kind, path) in [
            ("profile", CURRENT_VERSION_KEY),
            ("physical", CURRENT_VERSION_WOW_KEY),
        ] {
            let rows = profile[kind][0]["rows"].as_array().unwrap();
            assert_eq!(rows.len(), 136);
            for row in rows {
                let service = if number(row, "extended") == 0 {
                    "NtOpenKey"
                } else {
                    "NtOpenKeyEx"
                };
                let request = number(row, "request") | number(row, "view");
                let (status, h) = open(p, &mut t, base, service, path, 0, request);
                assert_eq!(
                    status,
                    number(row, "status"),
                    "{arch}/{kind}/{service}/{request:x}"
                );
                assert_eq!(u32::from(h != 0), number(row, "handle_nonzero"));
                if status == STATUS_SUCCESS {
                    assert_eq!(p.objects.access(h), Some(number(row, "granted_access")));
                    observed(p, &mut t, base, h, row);
                    assert_eq!(
                        call(p, &mut t, "NtClose", &[h]),
                        number(row, "close_status")
                    );
                }
                count += 1;
            }
        }
        for family in 0..3 {
            let (report, parent, paths): (&Json, &str, [&str; 4]) = match family {
                0 => (
                    &profile["profile"][1],
                    MACHINE_HIVE_KEY,
                    [
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize",
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersionPrefix",
                    ],
                ),
                1 => (
                    &profile["parents"][0],
                    CURRENT_VERSION_KEY,
                    [
                        "",
                        "Image File Execution Options",
                        "GRE_Initialize",
                        "GRE_InitializePrefix",
                    ],
                ),
                _ => (
                    &profile["parents"][1],
                    CURRENT_VERSION_WOW_KEY,
                    [
                        "",
                        "Image File Execution Options",
                        "GRE_Initialize",
                        "GRE_InitializePrefix",
                    ],
                ),
            };
            let rows = report["rows"].as_array().unwrap();
            assert_eq!(rows.len(), 48);
            for row in rows {
                let (status, parent) = open(
                    p,
                    &mut t,
                    base,
                    "NtOpenKeyEx",
                    parent,
                    0,
                    0x20019 | number(row, "parent_view"),
                );
                assert_eq!(status, STATUS_SUCCESS);
                let (status, h) = open(
                    p,
                    &mut t,
                    base,
                    "NtOpenKeyEx",
                    paths[number(row, "child") as usize],
                    parent,
                    0x20019 | number(row, "view"),
                );
                assert_eq!(
                    status,
                    number(row, "status"),
                    "{arch}/family{family}/row{row}"
                );
                if status == STATUS_SUCCESS {
                    observed(p, &mut t, base, h, row);
                    assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                }
                assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
                count += 1;
            }
        }
    }
    assert_eq!(count, 1248);
}

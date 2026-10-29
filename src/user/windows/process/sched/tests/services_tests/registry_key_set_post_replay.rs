//! Independent native observations of opens after key-body tag replacement.
use super::*;
use crate::user::windows::registry::{
    AppModelRoot, COMMAND_PROCESSOR_KEY, CommandHeader, CommandRoot, CommandTree, HiveHeader,
    KeyAccess, KeyTree, MACHINE_HIVE_KEY, MachineHeader, OLE_KEY, RegistryView, SelectedKey,
};
use serde_json::{Value as Json, json};

const SUBJECTS: [&str; 8] = [
    MACHINE_HIVE_KEY,
    MACHINE_HIVE_KEY,
    COMMAND_PROCESSOR_KEY,
    NLS_KEY,
    "\\Registry\\Machine\\Software\\Microsoft\\AppModel\\Lookaside\\machine",
    OLE_KEY,
    MACHINE_HIVE_KEY,
    MACHINE_HIVE_KEY,
];

fn n(row: &Json, name: &str) -> u32 {
    row[name].as_u64().unwrap().try_into().unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn name(row: &Json, field: &str) -> Vec<u16> {
    bytes(row[field].as_str().unwrap())[4..]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect()
}
fn expand(data: &Json) -> Vec<Json> {
    assert_eq!(
        data["row_fields"],
        json!(["subject", "parent_view", "tag", "requested", "output"])
    );
    data["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|dense| {
            let mut row = data["outputs"][dense[4].as_u64().unwrap() as usize]
                .as_object()
                .unwrap()
                .clone();
            for (i, key) in ["subject", "parent_view", "tag", "requested"]
                .iter()
                .enumerate()
            {
                row.insert((*key).to_owned(), dense[i].clone());
            }
            for field in ["root_name_hex", "child_name_hex"] {
                if let Some(index) = row.get(field) {
                    row.insert(
                        field.to_owned(),
                        data["names"][index.as_u64().unwrap() as usize].clone(),
                    );
                }
            }
            Json::Object(row)
        })
        .collect()
}
fn selection(rows: &[Json]) -> Registry {
    let captured = |subject, view| {
        rows.iter()
            .find(|r| n(r, "subject") == subject && n(r, "parent_view") == view)
            .unwrap()
    };
    let mut registry = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![SelectedKey {
            path: NLS_KEY,
            children: 0,
            values: vec![],
        }],
    )
    .unwrap();
    let access = KeyAccess {
        maximum_access: 0xF003F,
        system_security_status: STATUS_ACCESS_DENIED,
    };
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let command = captured(2, view.flag());
        assert_eq!(n(command, "root_status"), STATUS_SUCCESS);
        registry = registry
            .with_command_view(
                CommandRoot::Machine,
                &[],
                view,
                Ok(CommandHeader {
                    enumeration: None,
                    canonical: name(command, "root_name_hex"),
                    children: 0,
                    values: vec![],
                    access,
                }),
            )
            .unwrap();
        let ole = captured(5, view.flag());
        assert_eq!(n(ole, "root_status"), STATUS_SUCCESS);
        registry = registry
            .with_ole_tree(
                view,
                Ok(CommandTree {
                    header: CommandHeader {
                        enumeration: None,
                        canonical: name(ole, "root_name_hex"),
                        children: 0,
                        values: vec![],
                        access,
                    },
                    children: vec![],
                }),
            )
            .unwrap();
        let appmodel = captured(4, view.flag());
        assert!(matches!(
            n(appmodel, "root_status"),
            STATUS_SUCCESS | STATUS_OBJECT_NAME_NOT_FOUND
        ));
        registry = registry
            .with_appmodel_view(
                AppModelRoot::Machine,
                view,
                (n(appmodel, "root_status") == STATUS_SUCCESS).then(|| KeyTree {
                    values: vec![],
                    children: vec![],
                }),
            )
            .unwrap();
    }
    registry
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: name(captured(1, 0x100), "root_name_hex"),
            children: 6,
            values: vec![],
            access,
        })
        .unwrap()
}
fn open(p: &mut Proc, t: &mut Thread, base: u64, path: &str, root: u64, view: u32) -> (u32, u64) {
    let attrs = base + 2 * PAGE_SIZE;
    unicode(p, attrs + 64, attrs + 128, path);
    attributes(p, attrs, attrs + 64, root, 0x40);
    let status = call(
        p,
        t,
        "NtOpenKeyEx",
        &[base, u64::from(0x20019 | view), attrs, 0],
    );
    (status, p.space.ptr(base, p.arch.ptr_size()).unwrap())
}
fn identity(p: &Proc, handle: u64, row: &Json, field: &str) {
    // KeyNameInformation remains a separate uncaptured service class. Compare
    // the actual selected identity with the independent native record. The
    // value-only NLS fixture projects the physical ControlSet alias onto its
    // fixed logical selection; it does not claim native alias-name capture.
    let expected = bytes(row[field].as_str().unwrap());
    assert_eq!(
        u32::from_le_bytes(expected[..4].try_into().unwrap()) as usize,
        expected.len() - 4
    );
    let Some(Object::Key(key)) = p.objects.get(handle) else {
        panic!("key body")
    };
    let units = if n(row, "subject") == 3 || n(row, "subject") == 6 && field == "child_name_hex" {
        NLS_KEY.encode_utf16().collect()
    } else {
        expected[4..]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>()
    };
    assert_eq!(key.path, units);
}
fn set(p: &mut Proc, t: &mut Thread, base: u64, handle: u64, value: u32) -> u32 {
    p.space.w32(base + 64, value).unwrap();
    let status = call(p, t, "NtSetInformationKey", &[handle, 5, base + 64, 4]);
    assert_eq!(p.space.u32(base + 64).unwrap(), value);
    status
}
fn tags(p: &mut Proc, t: &mut Thread, base: u64, handle: u64) -> u32 {
    assert_eq!(
        call(p, t, "NtQueryKey", &[handle, 7, base + 64, 4, base + 128]),
        0
    );
    assert_eq!(p.space.u32(base + 128).unwrap(), 4);
    p.space.u32(base + 64).unwrap()
}
fn replay(corpus: &Json) -> usize {
    assert_eq!(corpus["schema"], "rax-native-key-set-post-v1");
    assert_eq!(corpus["state"], "complete");
    let mut count = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown native ABI {other}"),
        };
        let rows = expand(&corpus["datasets"][report["dataset"].as_str().unwrap()]);
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = selection(&rows);
        let before = p.objects.handle_count();
        for row in &rows {
            let context = format!(
                "{arch}/subject{}/view{:x}/tag{:x}/requested{:x}",
                n(row, "subject"),
                n(row, "parent_view"),
                n(row, "tag"),
                n(row, "requested")
            );
            let (status, root) = open(
                p,
                &mut t,
                base,
                SUBJECTS[n(row, "subject") as usize],
                0,
                n(row, "parent_view"),
            );
            assert_eq!(status, n(row, "root_status"), "{context}");
            if status != 0 {
                assert_eq!(root, 0);
                count += 1;
                continue;
            }
            assert_eq!(
                p.objects.access(root),
                Some(n(row, "root_access")),
                "{context}"
            );
            identity(p, root, row, "root_name_hex");
            assert_eq!(
                set(p, &mut t, base, root, n(row, "tag")),
                n(row, "set_status"),
                "{context}"
            );
            assert_eq!(
                tags(p, &mut t, base, root),
                n(row, "root_after_set"),
                "{context}"
            );
            let suffix = match n(row, "subject") {
                0 => "SOFTWARE\\Microsoft\\Command Processor",
                6 => "SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage",
                7 => "SOFTWARE\\Microsoft\\OLE",
                _ => "",
            };
            let (status, child) = open(p, &mut t, base, suffix, root, n(row, "requested"));
            assert_eq!(status, n(row, "open_status"), "{context}");
            assert_eq!(
                tags(p, &mut t, base, root),
                n(row, "root_after_open"),
                "{context}"
            );
            if status == 0 {
                assert_eq!(
                    p.objects.access(child),
                    Some(n(row, "child_access")),
                    "{context}"
                );
                identity(p, child, row, "child_name_hex");
                assert_eq!(
                    tags(p, &mut t, base, child),
                    n(row, "child_tags"),
                    "{context}"
                );
                assert_eq!(
                    set(p, &mut t, base, child, n(row, "child_write_value")),
                    n(row, "child_write_status"),
                    "{context}"
                );
                assert_eq!(
                    tags(p, &mut t, base, child),
                    n(row, "child_after_write"),
                    "{context}"
                );
                assert_eq!(
                    tags(p, &mut t, base, root),
                    n(row, "root_after_write"),
                    "{context}"
                );
                assert_eq!(call(p, &mut t, "NtClose", &[child]), 0);
            } else {
                assert_eq!(child, 0);
            }
            assert_eq!(
                tags(p, &mut t, base, root),
                n(row, "root_after_close"),
                "{context}"
            );
            identity(p, root, row, "root_name_hex");
            assert_eq!(
                p.objects.access(root),
                Some(n(row, "root_access")),
                "{context}"
            );
            assert_eq!(call(p, &mut t, "NtClose", &[root]), 0);
            assert_eq!(p.objects.handle_count(), before, "{context}");
            count += 1;
        }
    }
    count
}
#[test]
fn native_set_key_replays_relative_routing_names_grants_and_independent_empty_reopens() {
    let retained: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-key-set-information/post-controls-v1.json"
    )))
    .unwrap();
    assert_eq!(replay(&retained), 34944);
    if let Some(path) = std::env::var_os("RAX_KEY_SET_POST_CORPUS") {
        let fresh = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(replay(&fresh) > 0);
    }
}

fn replay_hives(corpus: &Json) -> usize {
    let mut count = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("native hive ABI {other}"),
        };
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = selection(&expand(
            &corpus["datasets"][report["dataset"].as_str().unwrap()],
        ));
        p.registry = p
            .registry
            .clone()
            .with_primary_hive(
                &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                Some(HiveHeader {
                    canonical: "\\REGISTRY\\USER\\.DEFAULT".encode_utf16().collect(),
                    children: 6,
                    values: vec![],
                }),
            )
            .unwrap();
        let before = p.objects.handle_count();
        for row in report["hives"].as_array().unwrap() {
            let path = match n(row, "subject") {
                0 => MACHINE_HIVE_KEY,
                1 => "\\Registry\\User\\.Default",
                2 => "\\Registry\\User\\S-1-5-18",
                other => panic!("native hive subject {other}"),
            };
            let (status, handle) = open(p, &mut t, base, path, 0, n(row, "view"));
            assert_eq!(
                status,
                n(row, "status"),
                "{arch}/{path}/{:x}",
                n(row, "view")
            );
            if status == 0 {
                assert_eq!(n(row, "query"), 0);
                assert_eq!(
                    tags(p, &mut t, base, handle),
                    n(row, "tags"),
                    "{arch}/{path}/{:x}",
                    n(row, "view")
                );
                assert_eq!(call(p, &mut t, "NtClose", &[handle]), 0);
            } else {
                assert_eq!(handle, 0);
            }
            assert_eq!(p.objects.handle_count(), before);
            count += 1;
        }
    }
    count
}

#[test]
fn native_set_key_replays_absolute_hive_spelling_before_relative_tag_inheritance() {
    let retained: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-key-set-information/post-controls-v1.json"
    )))
    .unwrap();
    assert_eq!(replay_hives(&retained), 36);
    if let Some(path) = std::env::var_os("RAX_KEY_SET_POST_CORPUS") {
        let fresh = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(replay_hives(&fresh) > 0);
    }
}

//! Independent NT PROCESSOR0 observations replayed through the actual guest dispatcher.
use super::*;
use crate::user::windows::registry::PROCESSOR0_KEY;

fn retained() -> Json {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-processor0-registry/controls-v1.json"
    )))
    .unwrap()
}

fn tree_node(report: &Json, id: usize) -> crate::user::windows::registry::CommandTree {
    let raw = &report["nodes"][id];
    let mut tree = subtree::tree_node(report, id);
    tree.header.enumeration = Some(
        raw["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| {
                let name = name.as_str().unwrap();
                let child = report["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|child| {
                        child["parent"].as_i64() == Some(id as i64)
                            && child["component_hex"].as_str() == Some(name)
                    })
                    .expect("native ordered child has a captured node");
                crate::user::windows::registry::BasicChild {
                    name: units(name),
                    last_write: u64::from_le_bytes(
                        bytes(child["last_write_hex"].as_str().unwrap())
                            .try_into()
                            .unwrap(),
                    ),
                }
            })
            .collect(),
    );
    tree.children = report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|child| child["parent"].as_i64() == Some(id as i64))
        .map(|child| {
            (
                units(child["component_hex"].as_str().unwrap()),
                tree_node(report, n(child, "id") as usize),
            )
        })
        .collect();
    tree
}

fn selection(report: &Json, installed: bool) -> Registry {
    if installed {
        return crate::user::windows::registry::snapshot().unwrap();
    }
    let mut r = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap();
    for root in report["roots"].as_array().unwrap() {
        assert_eq!(n(root, "hive"), 0);
        let view = match n(root, "view") {
            1 => RegistryView::Native64,
            2 => RegistryView::Wow32,
            _ => panic!("native PROCESSOR0 view"),
        };
        let tree = match n(root, "status") {
            0 => Ok(tree_node(report, n(root, "node") as usize)),
            2 => Err(STATUS_OBJECT_NAME_NOT_FOUND),
            3 => Err(STATUS_OBJECT_PATH_NOT_FOUND),
            other => panic!("native PROCESSOR0 capture status {other:x}"),
        };
        r = r.with_processor0_tree(view, tree).unwrap();
    }
    // This synthetic MACHINE header owns the selected route. The PROCESSOR0 oracle
    // supplies every expected leaf/descendant result, grant, name and value.
    r.with_machine_hive(MachineHeader {
        enumeration: None,
        canonical: wide(MACHINE_HIVE_KEY),
        children: 1,
        values: vec![],
        access: KeyAccess {
            maximum_access: 0xF003F,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    })
    .unwrap()
}

fn replay(corpus: &Json, installed: bool) -> (usize, usize) {
    assert_eq!(corpus["state"], "complete");
    let mut absolute_and_relative = 0;
    let mut trees = vec![];
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("native ABI"),
        };
        let mut tree = report["tree"].clone();
        tree["architecture"] = report["architecture"].clone();
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = selection(&tree, installed);
        for (kind, path) in [
            ("absolute", PROCESSOR0_KEY.to_owned()),
            (
                "missing",
                format!("{PROCESSOR0_KEY}\\__RAX_ABSENT_CHILD_20261029"),
            ),
        ] {
            for row in report[kind]["rows"].as_array().unwrap() {
                let access = n(row, "request") | n(row, "view");
                let (status, h) = open(
                    p,
                    &mut t,
                    base,
                    n(row, "extended") != 0,
                    &wide(&path),
                    0,
                    access,
                );
                assert_eq!(status, n(row, "status"), "{arch}/{kind}/{access:x}");
                assert_eq!(u32::from(h != 0), n(row, "handle_nonzero"));
                if status == 0 {
                    assert_eq!(p.objects.access(h), Some(n(row, "granted_access")));
                    assert_eq!(tags(p, &mut t, base, h), n(row, "tags"));
                    let Object::Key(key) = p.objects.get(h).unwrap() else {
                        panic!("PROCESSOR0 handle")
                    };
                    assert_eq!(key.path, units(row["name_hex"].as_str().unwrap()));
                    assert_eq!(call(p, &mut t, "NtClose", &[h]), n(row, "close_status"));
                }
                absolute_and_relative += 1;
            }
        }
        for row in report["relative"]["rows"].as_array().unwrap() {
            let (status, parent) = open(
                p,
                &mut t,
                base,
                true,
                &wide(MACHINE_HIVE_KEY),
                0,
                0x02000000 | n(row, "parent_view"),
            );
            assert_eq!(status, 0);
            let (status, h) = open(
                p,
                &mut t,
                base,
                true,
                &wide("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
                parent,
                0x02000000 | n(row, "view"),
            );
            assert_eq!(
                status,
                n(row, "status"),
                "{arch}/relative/{:x}/{:x}",
                n(row, "parent_view"),
                n(row, "view")
            );
            if status == 0 {
                assert_eq!(tags(p, &mut t, base, h), n(row, "tags"));
                let Object::Key(key) = p.objects.get(h).unwrap() else {
                    panic!("PROCESSOR0")
                };
                assert_eq!(key.path, units(row["name_hex"].as_str().unwrap()));
                assert_eq!(call(p, &mut t, "NtClose", &[h]), 0);
            } else {
                assert_eq!(h, 0);
            }
            assert_eq!(call(p, &mut t, "NtClose", &[parent]), 0);
            absolute_and_relative += 1;
        }
        trees.push(tree);
    }
    let descendants = subtree::replay_trees_with(
        &serde_json::json!({"state":"complete","reports":trees}),
        installed,
        selection,
    );
    (absolute_and_relative, descendants)
}

#[test]
fn processor0_registry_replays_native_open_profiles_and_retained_complete_trees_all_abis() {
    assert_eq!(replay(&retained(), false), (852, 1280));
    if let Some(path) = std::env::var_os("RAX_PROCESSOR0_REGISTRY_CORPUS") {
        let fresh = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let (opens, descendants) = replay(&fresh, true);
        assert!(opens > 0);
        assert!(
            descendants > 0
                || fresh["reports"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|report| report["tree"]["nodes"].as_array().unwrap().is_empty())
        );
    }
}

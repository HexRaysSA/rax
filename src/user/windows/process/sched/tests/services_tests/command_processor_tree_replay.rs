//! Complete native CMD trees and every recorded descendant/self-open result.
use super::*;
use crate::user::windows::registry::CommandTree;

fn tree_corpus() -> Json {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-command-processor-tree/controls-v1.json"
    )))
    .unwrap()
}

pub(super) fn tree_node(report: &Json, id: usize) -> CommandTree {
    let raw = &report["nodes"][id];
    let state = &report["states"][n(raw, "state") as usize];
    let children = report["nodes"]
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
        .collect::<Vec<_>>();
    assert_eq!(children.len(), raw["children"].as_array().unwrap().len());
    CommandTree {
        header: CommandHeader {
            enumeration: None,
            canonical: units(state["name_hex"].as_str().unwrap()),
            children: children.len() as u32,
            values: raw["values"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| Value {
                    name: units(value["name_hex"].as_str().unwrap()),
                    kind: n(value, "kind"),
                    data: bytes(value["data_hex"].as_str().unwrap()),
                })
                .collect(),
            access: KeyAccess {
                maximum_access: n(state, "granted_access"),
                system_security_status: n(raw, "security_status"),
            },
        },
        children,
    }
}

fn tree_selection(report: &Json, installed: bool) -> Registry {
    if installed {
        let identity = crate::user::windows::wnf::snapshot().unwrap();
        let sid = &identity.primary_subject().unwrap().user;
        return crate::user::windows::registry::capture_primary_user(
            crate::user::windows::registry::snapshot().unwrap(),
            sid,
        )
        .unwrap();
    }
    let sid = vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut registry = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap();
    for root in report["roots"].as_array().unwrap() {
        let kind = if n(root, "hive") == 0 {
            CommandRoot::Machine
        } else {
            CommandRoot::User
        };
        let view = match n(root, "view") {
            1 => RegistryView::Native64,
            2 => RegistryView::Wow32,
            other => panic!("native root view {other}"),
        };
        let tree = match n(root, "status") {
            0 => {
                assert_eq!(
                    kind,
                    CommandRoot::Machine,
                    "retained creator data needs a reviewed projection"
                );
                Ok(tree_node(report, root["node"].as_u64().unwrap() as usize))
            }
            2 => Err(STATUS_OBJECT_NAME_NOT_FOUND),
            3 => Err(STATUS_OBJECT_PATH_NOT_FOUND),
            status => panic!("unexpected native root selection {status:x}"),
        };
        registry = registry.with_command_tree(kind, &sid, view, tree).unwrap();
    }
    registry
}

fn tree_key(
    registry: &Registry,
    state: &Json,
) -> std::sync::Arc<crate::user::windows::registry::Key> {
    let name = units(state["name_hex"].as_str().unwrap());
    let physical = String::from_utf16(&name).unwrap().to_ascii_uppercase();
    let view = if physical.contains("\\WOW6432NODE\\") || n(state, "tags") & 0x400 != 0 {
        RegistryView::Wow32
    } else {
        RegistryView::Native64
    };
    let Lookup::Present(key) = registry.lookup_view(&name, view) else {
        panic!("captured source key: {physical}");
    };
    assert_eq!(key.path, name);
    key
}

fn check_tree_handle(p: &mut Proc, t: &mut Thread, base: u64, handle: u64, expected: &Json) {
    assert_eq!(
        p.objects.access(handle),
        Some(n(expected, "granted_access"))
    );
    assert_eq!(tags(p, t, base, handle), n(expected, "tags"));
    let Object::Key(key) = p.objects.get(handle).unwrap() else {
        panic!("registry key");
    };
    assert_eq!(key.path, units(expected["name_hex"].as_str().unwrap()));
}

fn replay_trees(corpus: &Json, installed: bool) -> usize {
    replay_trees_with(corpus, installed, tree_selection)
}

pub(super) fn replay_trees_with(
    corpus: &Json,
    installed: bool,
    selection: fn(&Json, bool) -> Registry,
) -> usize {
    assert_eq!(corpus["state"], "complete");
    let mut checked = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("native architecture {other}"),
        };
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        p.registry = selection(report, installed);
        let states = report["states"].as_array().unwrap();
        for node in report["nodes"].as_array().unwrap() {
            let captured = &states[n(node, "state") as usize];
            for source in node["opens"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|source| n(source, "seed") == 1)
            {
                let (status, handle) = open(
                    p,
                    &mut thread,
                    base,
                    true,
                    &units(captured["name_hex"].as_str().unwrap()),
                    0,
                    0x02000000 | n(source, "view"),
                );
                assert_eq!(
                    status,
                    n(source, "status"),
                    "{arch}/absolute/{:?}",
                    node["id"]
                );
                if status == 0 {
                    check_tree_handle(
                        p,
                        &mut thread,
                        base,
                        handle,
                        &states[source["source"].as_u64().unwrap() as usize],
                    );
                    assert_eq!(call(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
                } else {
                    assert_eq!(handle, 0);
                }
            }
        }
        let mut handles = vec![];
        for state in states {
            let key = tree_key(&p.registry, state);
            let original = seed(p, key, n(state, "tags"), n(state, "granted_access"));
            let duplicate = u64::from(p.objects.duplicate(original, false).unwrap());
            assert_eq!(call(p, &mut thread, "NtClose", &[original]), STATUS_SUCCESS);
            handles.push(duplicate);
        }
        p.registry = Registry::default();
        for node in report["nodes"].as_array().unwrap() {
            for source in node["opens"].as_array().unwrap() {
                for row in source["rows"].as_array().unwrap() {
                    let index = n(row, "name") as usize;
                    let children = node["children"].as_array().unwrap();
                    let name = if index == 0 {
                        vec![]
                    } else if index <= children.len() {
                        units(children[index - 1].as_str().unwrap())
                    } else {
                        assert_eq!(index, children.len() + 1);
                        wide("__RAX_ABSENT_CHILD_20261029")
                    };
                    let (status, handle) = open(
                        p,
                        &mut thread,
                        base,
                        n(row, "extended") != 0,
                        &name,
                        handles[n(row, "source") as usize],
                        n(row, "request") | n(row, "view"),
                    );
                    checked += 1;
                    assert_eq!(
                        status,
                        n(row, "status"),
                        "{arch}/node{:?}/seed{:?}/name{index}/view{:x}",
                        node["id"],
                        source["seed"],
                        n(row, "view")
                    );
                    if status == 0 {
                        let expected = &states[row["target"].as_u64().unwrap() as usize];
                        check_tree_handle(p, &mut thread, base, handle, expected);
                        if let Some(raw) = report["nodes"].as_array().unwrap().iter().find(|raw| {
                            report["states"][n(raw, "state") as usize]["name_hex"]
                                == expected["name_hex"]
                        }) {
                            values(p, &mut thread, base, handle, raw);
                        }
                        assert_eq!(call(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
                    } else {
                        assert_eq!(handle, 0);
                    }
                }
            }
        }
        for handle in handles {
            assert_eq!(call(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
        }
    }
    checked
}

#[test]
fn command_tree_replays_native_descendant_opens_and_metadata_after_namespace_replacement() {
    assert_eq!(replay_trees(&tree_corpus(), false), 7040);
    if let Some(path) = std::env::var_os("RAX_COMMAND_TREE_CORPUS") {
        let fresh: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(
            replay_trees(&fresh, true) > 0,
            "fresh native tree corpus is empty"
        );
    }
}

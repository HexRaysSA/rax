//! Native CMD leaf controls replayed through the actual guest NT dispatcher.
#[path = "ole_registry_replay.rs"]
mod ole;
#[path = "command_processor_tree_replay.rs"]
mod subtree;
#[path = "system_command_processor_replay.rs"]
mod system;

use super::*;
use crate::user::windows::objects::Object;
use crate::user::windows::registry::{
    CommandHeader, CommandRoot, HiveHeader, KeyAccess, Lookup, MACHINE_HIVE_KEY, MachineHeader,
    RegistryView,
};
use serde_json::Value as Json;

fn n(row: &Json, field: &str) -> u32 {
    row[field].as_u64().unwrap().try_into().unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
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
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}
fn corpus() -> Json {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-command-processor/controls-v1.json"
    )))
    .unwrap()
}

fn amd64_corpus() -> Json {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-command-processor/controls-amd64-v1.json"
    )))
    .unwrap()
}

fn physical_view(name: &[u16], tags: u32) -> RegistryView {
    if tags & 0x400 != 0
        || String::from_utf16(name)
            .unwrap()
            .to_ascii_uppercase()
            .contains("\\WOW6432NODE\\")
    {
        RegistryView::Wow32
    } else {
        RegistryView::Native64
    }
}
fn capture(report: &Json, view: RegistryView) -> &Json {
    &report["family"]["hives"][0]["captures"][if view == RegistryView::Native64 { 1 } else { 2 }]
}

fn selected(report: &Json, installed: bool) -> (Registry, Vec<u8>) {
    if installed {
        let context = crate::user::windows::wnf::snapshot().unwrap();
        let sid = context.primary_subject().unwrap().user.clone();
        let r = crate::user::windows::registry::capture_primary_user(
            crate::user::windows::registry::snapshot().unwrap(),
            &sid,
        )
        .unwrap();
        return (r, sid);
    }
    let sid = vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut r = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap();
    // These parent headers are partial synthetic fixtures. The leaf data,
    // access ceilings, names and transitions below come from native reports.
    r = r
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: wide(MACHINE_HIVE_KEY),
            children: 6,
            values: vec![],
            access: KeyAccess {
                maximum_access: 0xF003F,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        })
        .unwrap();
    r = r
        .with_primary_hive(
            &sid,
            Some(HiveHeader {
                canonical: wide("\\REGISTRY\\USER\\S-1-5-18"),
                children: 6,
                values: vec![],
            }),
        )
        .unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let raw = capture(report, view);
        let rows = report[if view == RegistryView::Native64 {
            "absolute"
        } else {
            "physical"
        }]["rows"]
            .as_array()
            .unwrap();
        let security = rows
            .iter()
            .find(|row| {
                n(row, "extended") == 1
                    && n(row, "request") == 0x01000000
                    && n(row, "view") == 0x100
            })
            .unwrap();
        r = r
            .with_command_view(
                CommandRoot::Machine,
                &[],
                view,
                Ok(CommandHeader {
                    enumeration: None,
                    canonical: units(raw["name_hex"].as_str().unwrap()),
                    children: n(raw, "children"),
                    values: raw["values"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| Value {
                            name: units(v["name_hex"].as_str().unwrap()),
                            kind: n(v, "kind"),
                            data: bytes(v["data_hex"].as_str().unwrap()),
                        })
                        .collect(),
                    access: KeyAccess {
                        maximum_access: n(raw, "granted_access"),
                        system_security_status: n(security, "status"),
                    },
                }),
            )
            .unwrap();
        let user = &report["family"]["hives"][1]["captures"]
            [if view == RegistryView::Native64 { 1 } else { 2 }];
        let status = match n(user, "open_status") {
            2 => STATUS_OBJECT_NAME_NOT_FOUND,
            3 => STATUS_OBJECT_PATH_NOT_FOUND,
            other => panic!("retained fixture expects recorded user absence, got {other}"),
        };
        r = r
            .with_command_view(CommandRoot::User, &sid, view, Err(status))
            .unwrap();
    }
    (r, sid)
}

fn open(
    p: &mut Proc,
    t: &mut Thread,
    base: u64,
    extended: bool,
    name: &[u16],
    root: u64,
    access: u32,
) -> (u32, u64) {
    let attrs = base + 2 * PAGE_SIZE;
    let string = attrs + 64;
    let buffer = attrs + 128;
    p.space
        .w16(string, (name.len() * 2).try_into().unwrap())
        .unwrap();
    p.space.w16(string + 2, 0).unwrap();
    p.space
        .wptr(
            string + if p.arch.is64() { 8 } else { 4 },
            p.arch.ptr_size(),
            buffer,
        )
        .unwrap();
    p.space.put_wunits(buffer, name).unwrap();
    attributes(p, attrs, string, root, 0x40);
    let args = [base, u64::from(access), attrs, 0];
    let status = call(
        p,
        t,
        if extended { "NtOpenKeyEx" } else { "NtOpenKey" },
        &args[..if extended { 4 } else { 3 }],
    );
    (status, p.space.ptr(base, p.arch.ptr_size()).unwrap())
}
fn tags(p: &mut Proc, t: &mut Thread, base: u64, h: u64) -> u32 {
    assert_eq!(
        call(p, t, "NtQueryKey", &[h, 7, base + 128, 4, base + 64]),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(base + 64).unwrap(), 4);
    p.space.u32(base + 128).unwrap()
}
fn seed(
    p: &mut Proc,
    key: std::sync::Arc<crate::user::windows::registry::Key>,
    tag: u32,
    access: u32,
) -> u64 {
    let id = p
        .objects
        .create_registry_key_metadata(key, Some(tag))
        .unwrap();
    p.objects.set_registry_views(id, p.registry.views.clone());
    u64::from(p.objects.open_access(id, false, access).unwrap())
}
fn values(p: &mut Proc, t: &mut Thread, base: u64, h: u64, raw: &Json) {
    for value in raw["values"].as_array().unwrap() {
        let name = units(value["name_hex"].as_str().unwrap());
        let at = base + 64;
        p.space
            .w16(at, (name.len() * 2).try_into().unwrap())
            .unwrap();
        p.space.w16(at + 2, 0).unwrap();
        p.space
            .wptr(
                at + if p.arch.is64() { 8 } else { 4 },
                p.arch.ptr_size(),
                base + 256,
            )
            .unwrap();
        p.space.put_wunits(base + 256, &name).unwrap();
        assert_eq!(
            call(
                p,
                t,
                "NtQueryValueKey",
                &[h, at, 2, base + PAGE_SIZE, PAGE_SIZE, base + 128]
            ),
            STATUS_SUCCESS
        );
        let data = bytes(value["data_hex"].as_str().unwrap());
        assert_eq!(p.space.u32(base + PAGE_SIZE + 4).unwrap(), n(value, "kind"));
        assert_eq!(
            p.space.u32(base + PAGE_SIZE + 8).unwrap() as usize,
            data.len()
        );
        for (i, byte) in data.iter().enumerate() {
            assert_eq!(p.space.u8(base + PAGE_SIZE + 12 + i as u64).unwrap(), *byte);
        }
    }
}

fn replay(corpus: &Json, installed: bool) {
    assert_eq!(corpus["state"], "complete");
    let mut total = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("native architecture {other}"),
        };
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let (r, sid) = selected(report, installed);
        p.registry = r;
        for (kind, path) in [
            (
                "absolute",
                "\\Registry\\Machine\\Software\\Microsoft\\Command Processor",
            ),
            (
                "physical",
                "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Command Processor",
            ),
        ] {
            let rows = report[kind]["rows"].as_array().unwrap();
            assert_eq!(rows.len(), 136);
            for row in rows {
                let access = n(row, "request") | n(row, "view");
                let (status, h) = open(
                    p,
                    &mut t,
                    base,
                    n(row, "extended") != 0,
                    &wide(path),
                    0,
                    access,
                );
                total += 1;
                assert_eq!(status, n(row, "status"), "{arch}/{kind}/{access:x}");
                assert_eq!(u32::from(h != 0), n(row, "handle_nonzero"));
                if status == STATUS_SUCCESS {
                    assert_eq!(p.objects.access(h), Some(n(row, "granted_access")));
                    assert_eq!(tags(p, &mut t, base, h), n(row, "tags"));
                    assert_eq!(call(p, &mut t, "NtClose", &[h]), n(row, "close_status"));
                }
            }
        }
        for (kind, suffix) in [
            ("relative", "Software\\Microsoft\\Command Processor"),
            (
                "physical-relative",
                "Software\\WOW6432Node\\Microsoft\\Command Processor",
            ),
        ] {
            for row in report[kind]["rows"].as_array().unwrap() {
                let (status, parent) = open(
                    p,
                    &mut t,
                    base,
                    true,
                    &wide(MACHINE_HIVE_KEY),
                    0,
                    0x02000000 | n(row, "parent_view"),
                );
                assert_eq!(status, STATUS_SUCCESS);
                let (status, h) = open(
                    p,
                    &mut t,
                    base,
                    true,
                    &wide(suffix),
                    parent,
                    0x02000000 | n(row, "view"),
                );
                total += 1;
                assert_eq!(
                    status,
                    n(row, "status"),
                    "{arch}/{kind}/{:x}/{:x}",
                    n(row, "parent_view"),
                    n(row, "view")
                );
                if status == STATUS_SUCCESS {
                    assert_eq!(tags(p, &mut t, base, h), n(row, "tags"));
                    assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                } else {
                    assert_eq!(h, 0);
                }
                assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
            }
        }
        for hive in report["family"]["hives"].as_array().unwrap() {
            let path = if n(hive, "hive") == 0 {
                wide(MACHINE_HIVE_KEY)
            } else {
                let mut path = CommandRoot::User.path(&sid).unwrap();
                path.truncate(path.len() - wide("\\Software\\Microsoft\\Command Processor").len());
                path
            };
            let key = p.registry.key(&path).unwrap();
            let parent = seed(
                p,
                key,
                n(&hive["root"], "tags"),
                n(&hive["root"], "granted_access"),
            );
            for row in hive["native_relative"].as_array().unwrap() {
                let (status, h) = open(
                    p,
                    &mut t,
                    base,
                    n(row, "extended") != 0,
                    &wide("Software\\Microsoft\\Command Processor"),
                    parent,
                    0x02000000 | n(row, "view"),
                );
                total += 1;
                assert_eq!(
                    status,
                    n(row, "status"),
                    "{arch}/hive{:?}/relative",
                    hive["hive"]
                );
                if status == STATUS_SUCCESS {
                    assert_eq!(tags(p, &mut t, base, h), n(row, "tags"));
                    assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                } else {
                    assert_eq!(h, 0);
                }
            }
            assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
            for raw in hive["captures"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| n(row, "open_status") == 0)
            {
                let name = units(raw["name_hex"].as_str().unwrap());
                let view = physical_view(&name, n(raw, "tags"));
                let root = if n(hive, "hive") == 0 {
                    CommandRoot::Machine
                } else {
                    CommandRoot::User
                };
                let Lookup::Present(key) = p.registry.lookup_view(&root.path(&sid).unwrap(), view)
                else {
                    panic!("captured CMD key");
                };
                let parent = seed(p, key, n(raw, "tags"), n(raw, "granted_access"));
                values(p, &mut t, base, parent, raw);
                for row in raw["self_opens"].as_array().unwrap() {
                    let (status, h) = open(
                        p,
                        &mut t,
                        base,
                        n(row, "extended") != 0,
                        &[],
                        parent,
                        0x02000000 | n(row, "view"),
                    );
                    total += 1;
                    assert_eq!(status, n(row, "status"));
                    if status == STATUS_SUCCESS {
                        assert_eq!(tags(p, &mut t, base, h), n(row, "tags"));
                        assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                    } else {
                        assert_eq!(h, 0);
                    }
                }
                assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
            }
        }
    }
    assert!(total >= 688, "native corpus must cover both process ABIs");
}

#[test]
fn command_processor_replays_retained_and_fresh_native_open_controls() {
    replay(&corpus(), false);
    replay(&amd64_corpus(), false);
    if let Some(path) = std::env::var_os("RAX_COMMAND_PROCESSOR_CORPUS") {
        let fresh: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        replay(&fresh, true);
    }
}

fn replay_graph(corpus: &Json, installed: bool) -> usize {
    let mut checked = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        for graph in report["graph"]["hives"].as_array().unwrap() {
            if graph["states"].as_array().unwrap().is_empty() {
                assert_eq!(n(graph, "hive"), 1);
                continue;
            }
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let (r, sid) = selected(report, installed);
            p.registry = r;
            let mut parents = vec![];
            let root = if n(graph, "hive") == 0 {
                CommandRoot::Machine
            } else {
                CommandRoot::User
            };
            for state in graph["states"].as_array().unwrap() {
                let name = units(state["name_hex"].as_str().unwrap());
                let view = physical_view(&name, n(state, "tags"));
                let Lookup::Present(key) = p.registry.lookup_view(&root.path(&sid).unwrap(), view)
                else {
                    panic!("state identity");
                };
                assert_eq!(key.path, name);
                let h = seed(p, key, n(state, "tags"), n(state, "granted_access"));
                let duplicate = u64::from(p.objects.duplicate(h, false).unwrap());
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                parents.push(duplicate);
            }
            p.registry = Registry::default();
            for edge in graph["edges"].as_array().unwrap() {
                let parent = parents[n(edge, "source") as usize];
                let (status, h) = open(
                    p,
                    &mut t,
                    base,
                    n(edge, "extended") != 0,
                    &[],
                    parent,
                    0x02000000 | n(edge, "view"),
                );
                checked += 1;
                assert_eq!(
                    status,
                    n(edge, "status"),
                    "{arch}/state{}/view{:x}",
                    edge["source"],
                    n(edge, "view")
                );
                if status == STATUS_SUCCESS {
                    let target = &graph["states"][edge["target"].as_u64().unwrap() as usize];
                    assert_eq!(tags(p, &mut t, base, h), n(target, "tags"));
                    assert_eq!(p.objects.access(h), Some(n(target, "granted_access")));
                    let Object::Key(key) = p.objects.get(h).unwrap() else {
                        panic!("key");
                    };
                    assert_eq!(key.path, units(target["name_hex"].as_str().unwrap()));
                    assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                } else {
                    assert_eq!(h, 0);
                }
            }
            for h in parents {
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
            }
        }
    }
    checked
}

#[test]
fn command_processor_closed_self_graph_survives_duplicates_and_namespace_replacement() {
    assert_eq!(replay_graph(&corpus(), false), 112);
    assert_eq!(replay_graph(&amd64_corpus(), false), 80);
    if let Some(path) = std::env::var_os("RAX_COMMAND_PROCESSOR_CORPUS") {
        let fresh: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(
            replay_graph(&fresh, true) > 0,
            "fresh native graph has no present-key fixture"
        );
    }
}

#[test]
fn command_processor_distinct_view_values_survive_nt_handles_and_namespace_replacement_all_abis() {
    let sid = vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let mut r = Registry::selected(
            (0..=u16::MAX)
                .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
                .collect(),
            vec![],
        )
        .unwrap();
        r = r
            .with_machine_hive(MachineHeader {
                enumeration: None,
                canonical: wide(MACHINE_HIVE_KEY),
                children: 6,
                values: vec![],
                access: KeyAccess {
                    maximum_access: 0xF003F,
                    system_security_status: STATUS_ACCESS_DENIED,
                },
            })
            .unwrap();
        r = r
            .with_primary_hive(
                &sid,
                Some(HiveHeader {
                    // Native SYSTEM SID opens traverse this captured alias.
                    canonical: wide("\\REGISTRY\\USER\\.DEFAULT"),
                    children: 6,
                    values: vec![],
                }),
            )
            .unwrap();
        for root in [CommandRoot::Machine, CommandRoot::User] {
            for (view, byte) in [(RegistryView::Native64, 64), (RegistryView::Wow32, 32)] {
                let mut canonical = String::from_utf16(&root.path(&sid).unwrap()).unwrap();
                if view == RegistryView::Wow32 {
                    canonical = canonical.replace(
                        "\\Software\\Microsoft",
                        "\\Software\\WOW6432Node\\Microsoft",
                    );
                }
                r = r
                    .with_command_view(
                        root,
                        &sid,
                        view,
                        Ok(CommandHeader {
                            enumeration: None,
                            canonical: wide(&canonical),
                            children: 1,
                            values: vec![Value {
                                name: wide("CompletionChar"),
                                kind: 4,
                                data: vec![byte, 0, 0, 0],
                            }],
                            access: KeyAccess {
                                maximum_access: 0xF003F,
                                system_security_status: STATUS_ACCESS_DENIED,
                            },
                        }),
                    )
                    .unwrap();
            }
        }
        p.registry = r;
        let mut handles = vec![];
        let mut roots = vec![];
        for root in [CommandRoot::Machine, CommandRoot::User] {
            let mut parent_path = root.path(&sid).unwrap();
            parent_path.truncate(
                parent_path.len() - wide("\\Software\\Microsoft\\Command Processor").len(),
            );
            let (status, parent) = open(p, &mut t, base, true, &parent_path, 0, 0x20019);
            assert_eq!(status, STATUS_SUCCESS);
            roots.push(parent);
            for view in [0, 0x100, 0x200] {
                let (status, h) = open(
                    p,
                    &mut t,
                    base,
                    true,
                    &root.path(&sid).unwrap(),
                    0,
                    0x02000000 | view,
                );
                assert_eq!(status, STATUS_SUCCESS);
                let duplicate = u64::from(p.objects.duplicate(h, false).unwrap());
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                handles.push((
                    duplicate,
                    if arch == WinArch::X86 && view != 0x100 {
                        32
                    } else {
                        64
                    },
                ));
            }
        }
        p.registry = Registry::default();
        for parent in roots {
            let (status, h) = open(
                p,
                &mut t,
                base,
                true,
                &wide("Software\\Microsoft\\Command Processor"),
                parent,
                0x02000200,
            );
            assert_eq!(status, STATUS_SUCCESS);
            handles.push((h, if arch == WinArch::X86 { 32 } else { 64 }));
            assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
        }
        for (h, byte) in handles {
            let raw = serde_json::json!({"values":[{"kind":4,"name_hex":"43006f006d0070006c006500740069006f006e004300680061007200","data_hex":format!("{byte:02x}000000")}]});
            values(p, &mut t, base, h, &raw);
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        }
    }
}

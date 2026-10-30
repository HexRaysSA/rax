//! Independent fixed-subject opens replayed through the real NT dispatcher.
use super::*;
use crate::user::windows::registry::{BasicChild, CommandTree};

const SUFFIX: &str = "\\Software\\Classes\\Local Settings";
const ABSENT: &str = "__RAX_ABSENT_LOCAL_SETTINGS_20261029";

fn logical_hive(sid: &[u8]) -> Vec<u16> {
    let mut path = CommandRoot::User.path(sid).unwrap();
    path.truncate(path.len() - wide("\\Software\\Microsoft\\Command Processor").len());
    path
}

fn selected(report: &Json, installed: bool) -> Registry {
    let raw = &report["snapshot"];
    let sid = bytes(raw["subject_sid_hex"].as_str().unwrap());
    if installed {
        let identity = crate::user::windows::wnf::snapshot().unwrap();
        assert_eq!(identity.primary_subject().unwrap().user, sid);
        return crate::user::windows::registry::capture_primary_user(
            crate::user::windows::registry::snapshot().unwrap(),
            &sid,
        )
        .unwrap();
    }
    let canonical = raw["canonical_hex"].as_str().map(units).unwrap_or_default();
    let hive = logical_hive(&sid);
    let mut primary = hive;
    if canonical.ends_with(&wide(SUFFIX)) {
        primary = canonical[..canonical.len() - wide(SUFFIX).len()].to_vec();
    }
    let mut registry = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
    .with_primary_hive(
        &sid,
        Some(HiveHeader {
            canonical: primary,
            children: 1,
            values: vec![],
        }),
    )
    .unwrap();
    if raw["roots"][0] != 0 {
        for (index, view) in [RegistryView::Native64, RegistryView::Wow32]
            .into_iter()
            .enumerate()
        {
            registry = registry
                .with_local_settings_tree(
                    &sid,
                    view,
                    Err(raw["roots"][index].as_u64().unwrap().try_into().unwrap()),
                )
                .unwrap();
        }
        return registry;
    }
    let access = raw["opens"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| n(row, "route") == 0 && n(row, "request") == 0x02000000)
        .unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        // Minimal synthetic body: these native controls observe root identity,
        // grants, tags and missing paths, independently of its native values.
        registry = registry
            .with_local_settings_tree(
                &sid,
                view,
                Ok(CommandTree {
                    header: CommandHeader {
                        canonical: canonical.clone(),
                        enumeration: Some(Vec::<BasicChild>::new()),
                        children: 0,
                        values: vec![],
                        access: KeyAccess {
                            maximum_access: n(access, "granted_access"),
                            system_security_status: STATUS_ACCESS_DENIED,
                        },
                    },
                    children: vec![],
                }),
            )
            .unwrap();
    }
    registry
}

fn replay(corpus: &Json, installed: bool) {
    assert_eq!(corpus["schema"], "rax-native-local-settings-v1");
    assert_eq!(corpus["state"], "complete");
    let mut checked = 0;
    let mut expected = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("native process ABI {other}"),
        };
        let raw = &report["snapshot"];
        let sid = bytes(raw["subject_sid_hex"].as_str().unwrap());
        let hive_path = logical_hive(&sid);
        let logical: Vec<_> = hive_path.iter().copied().chain(wide(SUFFIX)).collect();
        if raw["roots"][0] != 0 {
            let (mut process, mut thread, base) = setup(arch);
            let p = process.state_mut();
            p.registry = selected(report, installed);
            for (index, view) in [0x100, 0x200].into_iter().enumerate() {
                let (status, handle) =
                    open(p, &mut thread, base, true, &logical, 0, 0x02000000 | view);
                assert_eq!(u64::from(status), raw["roots"][index].as_u64().unwrap());
                assert_eq!(handle, 0);
                checked += 1;
            }
            expected += 2;
            continue;
        }
        let canonical = units(raw["canonical_hex"].as_str().unwrap());
        let rows = raw["opens"].as_array().unwrap();
        assert_eq!(rows.len(), 288);
        expected += rows.len() + rows.iter().filter(|row| n(row, "route") >= 2).count();
        for retired in [false, true] {
            let (mut process, mut thread, base) = setup(arch);
            let p = process.state_mut();
            p.registry = selected(report, installed);
            let before = (p.objects.handle_count(), p.objects.iter().count());
            let mut parents = std::collections::BTreeMap::new();
            for view in [0, 0x100, 0x200] {
                for (route, path) in [(2, &hive_path), (3, &logical)] {
                    let (status, handle) =
                        open(p, &mut thread, base, true, path, 0, 0x20019 | view);
                    assert_eq!(status, STATUS_SUCCESS);
                    let duplicate = u64::from(p.objects.duplicate(handle, false).unwrap());
                    assert_eq!(call(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
                    parents.insert((route, view), duplicate);
                }
            }
            if retired {
                p.registry = Registry::default();
            }
            for row in rows {
                let route = n(row, "route");
                if retired && route < 2 {
                    continue;
                }
                let (mut name, root) = match route {
                    0 => (logical.clone(), 0),
                    1 => (canonical.clone(), 0),
                    2 => (wide(&SUFFIX[1..]), parents[&(2, n(row, "parent_view"))]),
                    3 => (vec![], parents[&(3, n(row, "parent_view"))]),
                    other => panic!("native open route {other}"),
                };
                if root != 0 {
                    assert_eq!(
                        tags(p, &mut thread, base, root),
                        n(row, "parent_tags"),
                        "{arch}/{row}"
                    );
                }
                if n(row, "name") != 0 {
                    if !name.is_empty() {
                        name.push(92);
                    }
                    name.extend(wide(ABSENT));
                    if n(row, "name") == 2 {
                        name.extend(wide("\\Child"));
                    }
                }
                let (status, handle) = open(
                    p,
                    &mut thread,
                    base,
                    n(row, "extended") != 0,
                    &name,
                    root,
                    n(row, "request") | n(row, "view"),
                );
                checked += 1;
                assert_eq!(status, n(row, "status"), "{arch}/retired{retired}/{row}");
                assert_eq!(u32::from(handle != 0), n(row, "handle_nonzero"));
                if status == STATUS_SUCCESS {
                    assert_eq!(p.objects.access(handle), Some(n(row, "granted_access")));
                    assert_eq!(
                        tags(p, &mut thread, base, handle),
                        n(row, "tags"),
                        "{arch}/{row}"
                    );
                    let Object::Key(key) = p.objects.get(handle).unwrap() else {
                        panic!("native registry body");
                    };
                    assert_eq!(key.path, canonical);
                    assert_eq!(call(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
                }
            }
            for handle in parents.into_values() {
                assert_eq!(call(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
            }
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        }
    }
    assert!(checked > 0);
    assert_eq!(checked, expected);
}

#[test]
fn local_settings_retained_and_fresh_native_opens_keep_creator_routes_and_handle_lifetime() {
    replay(
        &serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-local-settings/controls-v1.json"
        )))
        .unwrap(),
        false,
    );
    if let Some(path) = std::env::var_os("RAX_LOCAL_SETTINGS_CORPUS") {
        let fresh = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        replay(&fresh, cfg!(windows));
    }
}

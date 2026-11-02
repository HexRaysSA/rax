use super::*;
const USER_POLICY_KEY: &str =
    "\\Registry\\User\\S-1-5-18\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";

#[test]
fn native_primary_hive_replays_retained_and_fresh_read_opens_and_measured_absence_all_abis() {
    use crate::user::windows::registry::HiveHeader;
    let mut corpora = vec![
        (
            "arm64-v3".to_owned(),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-primary-user-hive/arm64-29695-v3.json"
            ))
            .to_owned(),
        ),
        (
            "arm64-v4".to_owned(),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-primary-user-hive/arm64-29695-v4.json"
            ))
            .to_owned(),
        ),
    ];
    if let Some(path) = std::env::var_os("RAX_NATIVE_PRIMARY_USER_HIVE_CORPUS") {
        corpora.push((
            "fresh-native".to_owned(),
            std::fs::read_to_string(path).unwrap(),
        ));
    }
    let missing = "\\REGISTRY\\USER\\S-1-0-4275878552";
    for (label, text) in corpora {
        let corpus: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(corpus["state"], "finished");
        assert_eq!(corpus["exit_code"], 0);
        let native_sid =
            crate::user::windows::wnf::tests::hex(corpus["primary_sid_hex"].as_str().unwrap());
        let primary = format!(
            "\\REGISTRY\\USER\\{}",
            corpus["primary_sid"].as_str().unwrap()
        );
        let rows = corpus["rows"].as_array().unwrap();
        let sample = rows
            .iter()
            .find(|row| row["path"] == primary && row["access"] == 1)
            .unwrap();
        assert_eq!(
            sample["status"], 0,
            "{label}: native primary hive must be queryable"
        );
        let canonical = sample["canonical_name"].as_str().unwrap();
        let full = crate::user::windows::wnf::tests::hex(
            sample["key_full"]["bytes_hex"].as_str().unwrap(),
        );
        let children = u32::from_le_bytes(full[20..24].try_into().unwrap());
        let mut selected_count = 0;
        for arch in WinArch::ALL {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let template = p.registry.clone();
            // This fixture replays opens and read grants only. Native acquisition
            // separately checks all actual values; no query-value oracle is inferred here.
            let attrs = base + PAGE_SIZE * 2;
            for row in rows {
                let name = row["path"].as_str().unwrap();
                let access = row["access"].as_u64().unwrap();
                let is_missing = name == missing
                    || name
                        .strip_prefix(missing)
                        .is_some_and(|tail| tail.starts_with('\\'));
                if is_missing {
                    let observation = corpus["win32_absence"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|entry| entry["path"] == name)
                        .unwrap();
                    assert_eq!(observation["status"], 2);
                    let absent_sid = [1, 1, 0, 0, 0, 0, 0, 0, 0x98, 0xBA, 0xDC, 0xFE];
                    p.registry = template
                        .clone()
                        .with_primary_hive(&absent_sid, None)
                        .unwrap();
                } else if (name != primary && name != canonical)
                    || ![0, 1, 0x20019].contains(&access)
                {
                    continue;
                } else {
                    p.registry = template
                        .clone()
                        .with_primary_hive(
                            &native_sid,
                            Some(HiveHeader {
                                canonical: canonical.encode_utf16().collect(),
                                children,
                                values: vec![],
                            }),
                        )
                        .unwrap();
                }
                unicode(p, attrs + 64, attrs + 128, name);
                attributes(
                    p,
                    attrs,
                    attrs + 64,
                    0,
                    row["attributes"].as_u64().unwrap() as u32,
                );
                assert_eq!(
                    call(p, &mut t, "NtOpenKey", &[base, access, attrs]),
                    row["status"].as_u64().unwrap() as u32,
                    "{label}/{arch}/{name}/{access:X}"
                );
                let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
                if row["status"] == 0 {
                    assert_ne!(handle, 0);
                    assert_eq!(
                        p.objects.access(handle).unwrap() as u64,
                        row["granted_access"].as_u64().unwrap()
                    );
                    assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
                } else {
                    assert_eq!(handle, 0);
                }
                if arch == WinArch::ALL[0] {
                    selected_count += 1;
                }
            }
        }
        assert!(selected_count >= 12);
        eprintln!(
            "primary hive native replay: {label}: {selected_count} observations across {} ABIs",
            WinArch::ALL.len()
        );
    }
}

#[test]
fn native_primary_hive_aliases_query_snapshot_values_and_retain_policy_all_abis() {
    use crate::user::windows::registry::HiveHeader;
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = p
            .registry
            .clone()
            .with_primary_hive(
                &sid(),
                Some(HiveHeader {
                    canonical: "\\REGISTRY\\USER\\.DEFAULT".encode_utf16().collect(),
                    children: 9,
                    values: vec![Value {
                        name: "RootValue".encode_utf16().collect(),
                        kind: 3,
                        data: vec![0, 255, 17],
                    }],
                }),
            )
            .unwrap()
            .with_user_policy(&sid(), Some(tree()))
            .unwrap();
        let attrs = base + PAGE_SIZE * 2;
        let mut handles = Vec::new();
        let mut objects = Vec::new();
        for name in ["\\Registry\\User\\S-1-5-18", "\\registry\\user\\.default"] {
            for access in [1, 0x20019, 0x2000000] {
                unicode(p, attrs + 64, attrs + 128, name);
                attributes(p, attrs, attrs + 64, 0, 0x640);
                assert_eq!(
                    call(p, &mut t, "NtOpenKey", &[base, access, attrs]),
                    STATUS_SUCCESS
                );
                let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
                assert_eq!(
                    p.objects.access(handle),
                    Some(if access == 0x2000000 {
                        0x20019
                    } else {
                        access as u32
                    })
                );
                let Object::Key(key) = p.objects.get(handle).unwrap() else {
                    panic!("key handle")
                };
                objects.push(key.clone());
                handles.push(handle);
            }
        }
        assert!(
            objects
                .iter()
                .all(|key| std::sync::Arc::ptr_eq(&objects[0], key))
        );
        p.registry = Registry::default();
        unicode(p, attrs + 64, attrs + 128, "rootvalue");
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[handles[0], attrs + 64, 2, base + 128, 64, base + PAGE_SIZE]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(base + 132).unwrap(), 3);
        assert_eq!(p.space.u32(base + 136).unwrap(), 3);
        assert_eq!(p.space.bytes(base + 140, 3).unwrap(), [0, 255, 17]);
        unicode(
            p,
            attrs + 64,
            attrs + 128,
            "software\\\\policies\\microsoft\\windows\\safer\\codeidentifiers\\PROFILE",
        );
        attributes(p, attrs, attrs + 64, handles[0], 0x640);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_SUCCESS
        );
        let child = p.space.ptr(base, arch.ptr_size()).unwrap();
        for handle in handles {
            assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
        }
        drop(objects);
        unicode(p, attrs + 64, attrs + 128, "optionvalue");
        assert_eq!(
            call(
                p,
                &mut t,
                "NtQueryValueKey",
                &[child, attrs + 64, 2, base + 128, 64, base + PAGE_SIZE]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(base + 140).unwrap(), 0xA1B2_C3D4);
        assert_eq!(call(p, &mut t, "NtClose", &[child]), STATUS_SUCCESS);
    }
}
fn sid() -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}
use crate::user::windows::registry::KeyTree;

#[test]
fn native_user_policy_known_absent_root_and_children_return_name_not_found_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = p.registry.clone().with_user_policy(&sid(), None).unwrap();
        let attrs = base + PAGE_SIZE * 2;
        let before = (p.objects.handle_count(), p.objects.iter().count());
        for suffix in ["", "\\", "\\profile", "\\missing\\nested"] {
            for access in [1, 3, 0x20019, 0x20119, 0x20219] {
                unicode(
                    p,
                    attrs + 64,
                    attrs + 128,
                    &format!("{USER_POLICY_KEY}{suffix}"),
                );
                attributes(p, attrs, attrs + 64, 0, 0x240);
                assert_eq!(
                    call(p, &mut t, "NtOpenKey", &[base, access, attrs]),
                    STATUS_OBJECT_NAME_NOT_FOUND,
                    "{arch}/{suffix}"
                );
                assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
                assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
            }
        }
    }
}

fn tree() -> KeyTree {
    KeyTree {
        values: vec![],
        children: vec![(
            "profile".encode_utf16().collect(),
            KeyTree {
                values: vec![Value {
                    name: "OptionValue".encode_utf16().collect(),
                    kind: 4,
                    data: 0xA1B2_C3D4u32.to_le_bytes().to_vec(),
                }],
                children: vec![("filter".encode_utf16().collect(), KeyTree::default())],
            },
        )],
    }
}
#[test]
fn native_user_policy_opens_relative_paths_with_observed_absence_and_root_lifetime_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = p
            .registry
            .clone()
            .with_user_policy(&sid(), Some(tree()))
            .unwrap();
        let attrs = base + PAGE_SIZE * 2;
        unicode(p, attrs + 64, attrs + 128, USER_POLICY_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x240);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 0x20019, attrs]),
            STATUS_SUCCESS
        );
        let root = p.space.ptr(base, arch.ptr_size()).unwrap();
        p.registry = Registry::default();
        for (name, expected) in [
            ("", STATUS_SUCCESS),
            ("PROFILE", STATUS_SUCCESS),
            ("profile\\", STATUS_SUCCESS),
            ("profile\\\\FILTER\\", STATUS_SUCCESS),
            ("missing", STATUS_OBJECT_NAME_NOT_FOUND),
            ("missing\\nested", STATUS_OBJECT_NAME_NOT_FOUND),
            ("profile\\missing\\nested", STATUS_OBJECT_NAME_NOT_FOUND),
            (".", STATUS_OBJECT_NAME_NOT_FOUND),
            ("..", STATUS_OBJECT_NAME_NOT_FOUND),
            ("/", STATUS_OBJECT_NAME_NOT_FOUND),
            ("\\profile", STATUS_OBJECT_PATH_SYNTAX_BAD),
        ] {
            unicode(p, attrs + 64, attrs + 128, name);
            attributes(p, attrs, attrs + 64, root, 0x240);
            assert_eq!(
                call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
                expected,
                "{arch}/{name}"
            );
            let h = p.space.ptr(base, arch.ptr_size()).unwrap();
            if expected == STATUS_SUCCESS {
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
            } else {
                assert_eq!(h, 0);
            }
        }
        unicode(p, attrs + 64, attrs + 128, "profile");
        attributes(p, attrs, attrs + 64, root, 0x240);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 2, attrs]),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(call(p, &mut t, "NtClose", &[root]), STATUS_SUCCESS);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_INVALID_HANDLE
        );
    }
}
#[test]
fn native_user_policy_absolute_children_serialize_raw_values_and_preserve_outside_frontier_all_abis()
 {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = p
            .registry
            .clone()
            .with_user_policy(&sid(), Some(tree()))
            .unwrap();
        let attrs = base + PAGE_SIZE * 2;
        for view in [0, 0x100, 0x200] {
            unicode(
                p,
                attrs + 64,
                attrs + 128,
                &format!("{USER_POLICY_KEY}\\profile\\"),
            );
            attributes(p, attrs, attrs + 64, 0, 0x240);
            assert_eq!(
                call(p, &mut t, "NtOpenKey", &[base, 1 | view, attrs]),
                STATUS_SUCCESS
            );
            let h = p.space.ptr(base, arch.ptr_size()).unwrap();
            unicode(p, attrs + 64, attrs + 128, "optionvalue");
            assert_eq!(
                call(
                    p,
                    &mut t,
                    "NtQueryValueKey",
                    &[h, attrs + 64, 2, base + 128, 64, base + PAGE_SIZE]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(base + 132).unwrap(), 4);
            assert_eq!(p.space.u32(base + 136).unwrap(), 4);
            assert_eq!(p.space.u32(base + 140).unwrap(), 0xA1B2_C3D4);
            assert_eq!(p.space.u32(base + PAGE_SIZE).unwrap(), 16);
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        }
        unicode(
            p,
            attrs + 64,
            attrs + 128,
            &format!("{USER_POLICY_KEY}\\missing\\nested"),
        );
        attributes(p, attrs, attrs + 64, 0, 0x240);
        assert_eq!(
            call(p, &mut t, "NtOpenKey", &[base, 1, attrs]),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        unicode(
            p,
            attrs + 64,
            attrs + 128,
            &format!("{USER_POLICY_KEY}Suffix\\profile"),
        );
        arguments(p, &mut t, &[base, 1, attrs]);
        assert!(
            matches!(dispatch(p, &mut t), Outcome::Fail(reason) if reason.contains("outside selected runtime snapshot"))
        );
    }
}

use super::*;
use crate::user::windows::nt::status::*;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn sid(account: u32) -> Vec<u8> {
    let mut bytes = vec![1, 2, 0, 0, 0, 0, 0, 5];
    bytes.extend_from_slice(&21u32.to_le_bytes());
    bytes.extend_from_slice(&account.to_le_bytes());
    bytes
}

fn registry(subject: &[u8], canonical: &str, children: u32) -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|unit| {
                if (97..=122).contains(&unit) {
                    unit - 32
                } else {
                    unit
                }
            })
            .collect(),
        vec![],
    )
    .unwrap()
    .with_primary_hive(
        subject,
        Some(HiveHeader {
            canonical: wide(canonical),
            children,
            values: vec![],
        }),
    )
    .unwrap()
}

fn tree(canonical: Vec<u16>) -> CommandTree {
    CommandTree {
        header: CommandHeader {
            canonical,
            enumeration: Some(vec![]),
            children: 0,
            values: vec![Value {
                name: wide("Local AppData"),
                kind: 1,
                data: "Z:\\Profile\\AppData\\Local\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }],
            access: KeyAccess {
                maximum_access: 0xF003F,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        },
        children: vec![],
    }
}

#[test]
fn shell_folders_values_views_and_retained_hive_aliases_survive_owner_drop() {
    let subject = sid(7);
    for hive in ["\\Registry\\User\\S-1-5-21-7", "\\Registry\\User\\.DEFAULT"] {
        let mut selected = registry(&subject, hive, 1);
        let canonical: Vec<_> = wide(hive)
            .into_iter()
            .chain(SUFFIX.encode_utf16())
            .collect();
        let captured = tree(canonical.clone());
        let expected = captured.header.values[0].clone();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            selected = selected
                .with_shell_folders_tree(&subject, view, Ok(captured.clone()))
                .unwrap();
        }
        let primary = selected.key(&wide(hive)).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            for name in [path(&subject).unwrap(), canonical.clone()] {
                let Lookup::Present(key) = selected.lookup_view(&name, view) else {
                    panic!("captured Shell Folders alias");
                };
                assert_eq!(key.path, canonical);
                assert_eq!(key.value(&wide("local appdata")), Some(&expected));
                assert_eq!(key.captured_access().unwrap().grant(1), Ok(1));
                assert!(matches!(key.relative(&wide("Unknown")), Lookup::Missing));
            }
        }
        drop(selected);
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let Lookup::Present(key) = primary.relative_in_view(&wide(&SUFFIX[1..]), view) else {
                panic!("retained creator-hive Shell Folders route");
            };
            assert_eq!(key.value(&wide("Local AppData")), Some(&expected));
            assert!(matches!(
                primary.relative_in_view(&wide(&format!("{}Other", &SUFFIX[1..])), view),
                Lookup::Unselected
            ));
        }
    }
}

#[test]
fn shell_folders_rejects_foreign_subjects_incomplete_metadata_and_orphan_roots() {
    let subject = sid(7);
    for case in 0..6 {
        let selected = registry(
            &subject,
            "\\Registry\\User\\S-1-5-21-7",
            u32::from(case != 5),
        );
        let mut captured = tree(path(&subject).unwrap());
        let supplied = if case == 0 { sid(8) } else { subject.clone() };
        match case {
            1 => captured.header.canonical.push(92),
            2 => captured.header.canonical = path(&sid(8)).unwrap(),
            3 => captured.header.enumeration = None,
            4 => captured.header.children = 1,
            _ => {}
        }
        assert!(
            selected
                .with_shell_folders_tree(&supplied, RegistryView::Native64, Ok(captured))
                .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn shell_folders_preserves_absence_classes_and_rejects_disagreeing_shared_views() {
    let subject = sid(7);
    let hive = "\\Registry\\User\\S-1-5-21-7";
    for status in [STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND] {
        let mut selected = registry(&subject, hive, 1);
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            selected = selected
                .with_shell_folders_tree(&subject, view, Err(status))
                .unwrap();
            match (status, selected.lookup_view(&path(&subject).unwrap(), view)) {
                (STATUS_OBJECT_NAME_NOT_FOUND, Lookup::Missing)
                | (STATUS_OBJECT_PATH_NOT_FOUND, Lookup::MissingPath) => {}
                _ => panic!("exact native absence class"),
            }
        }
        let other = if status == STATUS_OBJECT_NAME_NOT_FOUND {
            STATUS_OBJECT_PATH_NOT_FOUND
        } else {
            STATUS_OBJECT_NAME_NOT_FOUND
        };
        let selected = registry(&subject, hive, 1)
            .with_shell_folders_tree(&subject, RegistryView::Native64, Err(status))
            .unwrap();
        assert!(
            selected
                .with_shell_folders_tree(&subject, RegistryView::Wow32, Err(other))
                .is_err()
        );
    }
    for status in [STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE] {
        assert!(
            registry(&subject, hive, 1)
                .with_shell_folders_tree(&subject, RegistryView::Native64, Err(status))
                .is_err()
        );
    }
    for case in 0..4 {
        let captured = tree(path(&subject).unwrap());
        let selected = registry(&subject, hive, 1)
            .with_shell_folders_tree(&subject, RegistryView::Native64, Ok(captured.clone()))
            .unwrap();
        let mut changed = captured;
        match case {
            0 => changed.header.values[0].data.push(0),
            1 => changed.header.access.maximum_access = 1,
            2 => changed.header.access.system_security_status = STATUS_PRIVILEGE_NOT_HELD,
            _ => {
                changed.header.canonical = wide("\\Registry\\User\\.DEFAULT")
                    .into_iter()
                    .chain(SUFFIX.encode_utf16())
                    .collect()
            }
        }
        assert!(
            selected
                .with_shell_folders_tree(&subject, RegistryView::Wow32, Ok(changed))
                .is_err()
        );
    }
}

#[test]
fn shell_folders_uses_the_existing_aggregate_startup_budget() {
    let subject = sid(7);
    let mut captured = tree(path(&subject).unwrap());
    captured.header.values = (0..MAX_VALUES / 2)
        .map(|index| Value {
            name: wide(&format!("Value{index}")),
            kind: 3,
            data: vec![0],
        })
        .collect();
    let mut selected = registry(&subject, "\\Registry\\User\\S-1-5-21-7", 1);
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        selected = selected
            .with_shell_folders_tree(&subject, view, Ok(captured.clone()))
            .unwrap();
    }
    assert_eq!(selected.value_budget().unwrap().count, MAX_VALUES);
    let mut another = tree(wide(OLE_KEY));
    another.header.values[0].data = vec![1];
    assert!(
        selected
            .with_ole_tree(RegistryView::Native64, Ok(another))
            .is_err()
    );
}

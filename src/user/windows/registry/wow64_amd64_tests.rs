use super::*;
use crate::user::windows::nt::status::*;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn registry() -> Registry {
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
}

fn tree(path: &str, byte: u8) -> CommandTree {
    CommandTree {
        header: CommandHeader {
            canonical: wide(path),
            enumeration: Some(vec![]),
            children: 0,
            values: vec![Value {
                name: wide("FixtureRawValue"),
                kind: 3,
                data: vec![0, byte, 0xff],
            }],
            access: KeyAccess {
                maximum_access: 0xf003f,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        },
        children: vec![],
    }
}

fn branch(path: &str, byte: u8) -> CommandTree {
    let mut root = tree(path, byte);
    root.header.children = 1;
    root.header.enumeration = Some(vec![BasicChild {
        name: wide("Child"),
        last_write: 123,
    }]);
    let mut child = tree(&(path.to_owned() + "\\Child"), byte + 1);
    child.header.access.maximum_access = 1;
    child.header.access.system_security_status = STATUS_PRIVILEGE_NOT_HELD;
    root.children = vec![(wide("Child"), child)];
    root
}

#[test]
fn wow64_amd64_complete_views_preserve_values_grants_metadata_and_retained_machine_routes() {
    let selected = registry()
        .with_wow64_amd64_tree(RegistryView::Native64, Ok(branch(WOW64_AMD64_KEY, 1)))
        .unwrap()
        .with_wow64_amd64_tree(RegistryView::Wow32, Ok(branch(WOW32_CANONICAL, 3)))
        .unwrap()
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: wide(MACHINE_HIVE_KEY),
            children: 1,
            values: vec![],
            access: KeyAccess {
                maximum_access: 0xf003f,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        })
        .unwrap();
    for (view, physical, byte) in [
        (RegistryView::Native64, WOW64_AMD64_KEY, 1),
        (RegistryView::Wow32, WOW32_CANONICAL, 3),
    ] {
        for path in [WOW64_AMD64_KEY, physical] {
            let Lookup::Present(key) = selected.lookup_view(&wide(path), view) else {
                panic!("selected fixed view")
            };
            assert_eq!(key.path, wide(physical));
            assert_eq!(key.redirected_view, Some(view));
            assert_eq!(
                key.value(&wide("fixturerawvalue")).unwrap().data,
                [0, byte, 0xff]
            );
            assert_eq!(key.child_metadata().unwrap()[0].last_write, 123);
            assert_eq!(key.captured_access().unwrap().grant(2), Ok(2));
            let Lookup::Present(child) = key.relative(&wide("Child")) else {
                panic!("complete descendant")
            };
            assert_eq!(
                child.value(&wide("FixtureRawValue")).unwrap().data,
                [0, byte + 1, 0xff]
            );
            assert_eq!(
                child.captured_access().unwrap().grant(2),
                Err(STATUS_ACCESS_DENIED)
            );
            assert_eq!(
                child.captured_access().unwrap().system_security_status,
                STATUS_PRIVILEGE_NOT_HELD
            );
            assert!(matches!(child.relative(&wide("Absent")), Lookup::Missing));
        }
    }
    let machine = selected.key(&wide(MACHINE_HIVE_KEY)).unwrap();
    drop(selected);
    for (view, byte) in [(RegistryView::Native64, 2), (RegistryView::Wow32, 4)] {
        let Lookup::Present(child) =
            machine.relative_in_view(&wide("Software\\Microsoft\\Wow64\\amd64\\Child"), view)
        else {
            panic!("retained machine view")
        };
        assert_eq!(
            child.value(&wide("FixtureRawValue")).unwrap().data,
            [0, byte, 0xff]
        );
        assert!(matches!(
            machine.relative_in_view(&wide("Software\\Microsoft\\Wow64\\amd64Other"), view),
            Lookup::Unselected
        ));
    }
}

#[test]
fn wow64_amd64_absence_preserves_each_view_and_exact_native_not_found_classes() {
    let capture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/windows/native-wow64-amd64/observations-v3.json"
    ))
    .unwrap();
    let mut selected = registry();
    let rows = capture["observation"]["views"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for (row, flag) in rows.iter().zip([0x100, 0x200]) {
        assert_eq!(row["view"], flag);
        assert_eq!(row["native_open"]["handle_published"], false);
        assert_eq!(row["native_open_trailing"]["handle_published"], false);
        let view = if flag == 0x100 {
            RegistryView::Native64
        } else {
            RegistryView::Wow32
        };
        assert_eq!(row["native_open"]["status"], STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(
            row["native_open_trailing"]["status"],
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        selected = selected
            .with_wow64_amd64_tree(view, Err(STATUS_OBJECT_NAME_NOT_FOUND))
            .unwrap();
        for path in [
            WOW64_AMD64_KEY.to_owned(),
            WOW64_AMD64_KEY.to_lowercase() + "\\",
            WOW64_AMD64_KEY.to_owned() + "\\Child",
        ] {
            assert!(matches!(
                selected.lookup_view(&wide(&path), view),
                Lookup::Missing
            ));
        }
        assert!(matches!(
            selected.lookup_view(&wide(&(WOW64_AMD64_KEY.to_owned() + "Other")), view),
            Lookup::Unselected
        ));
    }
    let selected = registry()
        .with_wow64_amd64_tree(RegistryView::Native64, Err(STATUS_OBJECT_NAME_NOT_FOUND))
        .unwrap()
        .with_wow64_amd64_tree(RegistryView::Wow32, Err(STATUS_OBJECT_PATH_NOT_FOUND))
        .unwrap();
    assert!(matches!(
        selected.lookup_view(&wide(WOW64_AMD64_KEY), RegistryView::Native64),
        Lookup::Missing
    ));
    assert!(matches!(
        selected.lookup_view(&wide(WOW64_AMD64_KEY), RegistryView::Wow32),
        Lookup::MissingPath
    ));
    for status in [STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE] {
        assert!(
            registry()
                .with_wow64_amd64_tree(RegistryView::Native64, Err(status))
                .is_err()
        );
    }
    let selected = registry()
        .with_wow64_amd64_tree(RegistryView::Native64, Ok(tree(WOW64_AMD64_KEY, 1)))
        .unwrap()
        .with_wow64_amd64_tree(RegistryView::Wow32, Err(STATUS_OBJECT_NAME_NOT_FOUND))
        .unwrap();
    assert!(matches!(
        selected.lookup_view(&wide(WOW64_AMD64_KEY), RegistryView::Native64),
        Lookup::Present(_)
    ));
    assert!(matches!(
        selected.lookup_view(&wide(WOW64_AMD64_KEY), RegistryView::Wow32),
        Lookup::Missing
    ));
}

#[test]
fn wow64_amd64_rejects_foreign_canonical_roots_incomplete_trees_and_same_key_races() {
    for (view, name) in [
        (RegistryView::Native64, WOW32_CANONICAL),
        (RegistryView::Wow32, COMMAND_PROCESSOR_KEY),
        (
            RegistryView::Native64,
            "\\Registry\\User\\S-1-5-18\\Software\\Microsoft\\Wow64\\amd64",
        ),
    ] {
        assert!(
            registry()
                .with_wow64_amd64_tree(view, Ok(tree(name, 1)))
                .is_err()
        );
    }
    for case in 0..5 {
        let mut captured = branch(WOW64_AMD64_KEY, 1);
        match case {
            0 => captured.header.enumeration = None,
            1 => captured.children.clear(),
            2 => captured.children[0].1.header.canonical.push(0),
            3 => captured.header.enumeration.as_mut().unwrap()[0].name = wide("Other"),
            _ => captured.header.canonical.push(92),
        }
        assert!(
            registry()
                .with_wow64_amd64_tree(RegistryView::Native64, Ok(captured))
                .is_err(),
            "case{case}"
        );
    }
    let initial = branch(WOW64_AMD64_KEY, 1);
    let selected = registry()
        .with_wow64_amd64_tree(RegistryView::Native64, Ok(initial.clone()))
        .unwrap();
    for case in 0..4 {
        let mut changed = initial.clone();
        match case {
            0 => changed.children[0].1.header.values[0].data.push(1),
            1 => changed.header.access.maximum_access = 1,
            2 => changed.header.access.system_security_status = STATUS_PRIVILEGE_NOT_HELD,
            _ => changed.header.enumeration.as_mut().unwrap()[0].last_write += 1,
        }
        assert!(
            selected
                .clone()
                .with_wow64_amd64_tree(RegistryView::Wow32, Ok(changed))
                .is_err(),
            "case{case}"
        );
    }
}

#[test]
fn wow64_amd64_uses_the_existing_aggregate_startup_budget() {
    let mut first = tree(WOW64_AMD64_KEY, 1);
    first.header.values = (0..MAX_VALUES / 2)
        .map(|index| Value {
            name: wide(&format!("Fixture{index}")),
            kind: 3,
            data: vec![1],
        })
        .collect();
    let mut second = first.clone();
    second.header.canonical = wide(WOW32_CANONICAL);
    let selected = registry()
        .with_wow64_amd64_tree(RegistryView::Native64, Ok(first))
        .unwrap()
        .with_wow64_amd64_tree(RegistryView::Wow32, Ok(second))
        .unwrap();
    assert_eq!(selected.value_budget().unwrap().count, MAX_VALUES);
    assert!(
        selected
            .with_ole_tree(RegistryView::Native64, Ok(tree(OLE_KEY, 2)))
            .is_err()
    );
}

use super::*;
use crate::user::windows::nt::status::*;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn registry() -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
}
fn tree(path: &str, marker: u8) -> CommandTree {
    CommandTree {
        header: CommandHeader {
            canonical: wide(path),
            children: 0,
            enumeration: Some(vec![]),
            values: vec![Value {
                name: wide("RawFixture"),
                kind: 3,
                data: vec![0, marker, 255],
            }],
            access: KeyAccess {
                maximum_access: 0x20019,
                system_security_status: STATUS_PRIVILEGE_NOT_HELD,
            },
        },
        children: vec![],
    }
}

fn branch(path: &str) -> CommandTree {
    let mut root = tree(path, 7);
    root.header.children = 1;
    root.header.enumeration = Some(vec![BasicChild {
        name: wide("Child"),
        last_write: 123,
    }]);
    let mut child = tree(&(path.to_owned() + "\\Child"), 8);
    child.header.access.maximum_access = 1;
    root.children = vec![(wide("Child"), child)];
    root
}

#[test]
fn processor0_shared_views_preserve_raw_values_grants_and_retained_machine_routes() {
    let selected = registry()
        .with_processor0_tree(RegistryView::Native64, Ok(branch(PROCESSOR0_KEY)))
        .unwrap()
        .with_processor0_tree(
            RegistryView::Wow32,
            Ok(branch(&PROCESSOR0_KEY.to_lowercase())),
        )
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
    let machine = selected.key(&wide(MACHINE_HIVE_KEY)).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let Lookup::Present(key) =
            selected.lookup_view(&wide(&PROCESSOR0_KEY.to_lowercase()), view)
        else {
            panic!("shared processor subject")
        };
        assert_eq!(key.value(&wide("RAWfixture")).unwrap().data, [0, 7, 255]);
        assert_eq!(key.captured_access().unwrap().grant(1), Ok(1));
        assert_eq!(
            key.captured_access().unwrap().grant(2),
            Err(STATUS_ACCESS_DENIED)
        );
        assert!(matches!(key.relative(&wide("Unknown")), Lookup::Missing));
        assert_eq!(key.child_metadata().unwrap()[0].last_write, 123);
        let Lookup::Present(child) = key.relative(&wide("Child")) else {
            panic!("retained child")
        };
        assert_eq!(child.value(&wide("RawFixture")).unwrap().data, [0, 8, 255]);
        assert_eq!(
            child.captured_access().unwrap().grant(2),
            Err(STATUS_ACCESS_DENIED)
        );
    }
    drop(selected);
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        assert!(matches!(
            machine.relative_in_view(
                &wide("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
                view
            ),
            Lookup::Present(_)
        ));
        assert!(matches!(
            machine.relative_in_view(
                &wide("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\1"),
                view
            ),
            Lookup::Unselected
        ));
    }
}

#[test]
fn processor0_shared_subject_rejects_view_presence_identity_and_content_races() {
    for missing in [STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND] {
        assert!(
            registry()
                .with_processor0_tree(RegistryView::Native64, Ok(tree(PROCESSOR0_KEY, 1)))
                .unwrap()
                .with_processor0_tree(RegistryView::Wow32, Err(missing))
                .is_err()
        );
    }
    assert!(
        registry()
            .with_processor0_tree(RegistryView::Native64, Ok(tree(PROCESSOR0_KEY, 1)))
            .unwrap()
            .with_processor0_tree(RegistryView::Wow32, Ok(tree(PROCESSOR0_KEY, 2)))
            .is_err()
    );
    assert!(
        registry()
            .with_processor0_tree(
                RegistryView::Native64,
                Ok(tree(&(PROCESSOR0_KEY.to_owned() + "Other"), 1))
            )
            .is_err()
    );
    let mut changed = tree(PROCESSOR0_KEY, 1);
    changed.header.access.maximum_access = 1;
    assert!(
        registry()
            .with_processor0_tree(RegistryView::Native64, Ok(tree(PROCESSOR0_KEY, 1)))
            .unwrap()
            .with_processor0_tree(RegistryView::Wow32, Ok(changed))
            .is_err()
    );
}

#[test]
fn processor0_absence_classes_do_not_select_neighbor_processors_or_prefixes() {
    for (status, path_missing) in [
        (STATUS_OBJECT_NAME_NOT_FOUND, false),
        (STATUS_OBJECT_PATH_NOT_FOUND, true),
    ] {
        let selected = registry()
            .with_processor0_tree(RegistryView::Native64, Err(status))
            .unwrap()
            .with_processor0_tree(RegistryView::Wow32, Err(status))
            .unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            for suffix in ["", "\\", "\\Unknown"] {
                let result =
                    selected.lookup_view(&wide(&(PROCESSOR0_KEY.to_owned() + suffix)), view);
                assert!(if path_missing {
                    matches!(result, Lookup::MissingPath)
                } else {
                    matches!(result, Lookup::Missing)
                });
            }
            for path in [
                PROCESSOR0_KEY.to_owned() + "Other",
                PROCESSOR0_KEY.trim_end_matches('0').to_owned() + "1",
            ] {
                assert!(matches!(
                    selected.lookup_view(&wide(&path), view),
                    Lookup::Unselected
                ));
            }
        }
    }
    assert!(
        registry()
            .with_processor0_tree(RegistryView::Native64, Err(STATUS_ACCESS_DENIED))
            .is_err()
    );
}

#[test]
fn processor0_complete_metadata_and_duplicate_selection_are_validated() {
    let mut incomplete = tree(PROCESSOR0_KEY, 1);
    incomplete.header.enumeration = None;
    assert!(
        registry()
            .with_processor0_tree(RegistryView::Native64, Ok(incomplete))
            .is_err()
    );
    let selected = registry()
        .with_processor0_tree(RegistryView::Native64, Ok(tree(PROCESSOR0_KEY, 1)))
        .unwrap();
    assert!(
        selected
            .with_processor0_tree(RegistryView::Native64, Ok(tree(PROCESSOR0_KEY, 1)))
            .is_err()
    );
    let selected = registry()
        .with_processor0_tree(RegistryView::Native64, Err(STATUS_OBJECT_NAME_NOT_FOUND))
        .unwrap();
    assert!(
        selected
            .with_processor0_tree(RegistryView::Wow32, Err(STATUS_OBJECT_PATH_NOT_FOUND))
            .is_err()
    );
}

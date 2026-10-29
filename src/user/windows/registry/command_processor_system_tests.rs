//! Fixed System selection: captured absence and synthetic positive contents.
use super::*;
use crate::user::windows::nt::status::*;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
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
fn header(root: CommandRoot, byte: u8) -> CommandHeader {
    CommandHeader {
        enumeration: Some(vec![]),
        canonical: root.path(&[]).unwrap(),
        children: 0,
        values: vec![Value {
            name: wide("CompletionChar"),
            kind: 4,
            data: vec![byte, 0, 0, 0],
        }],
        access: KeyAccess {
            maximum_access: 0xF003F,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    }
}
fn hive(children: u32) -> super::super::MachineHeader {
    super::super::MachineHeader {
        enumeration: None,
        canonical: wide(super::super::MACHINE_HIVE_KEY),
        children,
        values: vec![],
        access: KeyAccess {
            maximum_access: 0xF003F,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    }
}
fn present(r: Registry, root: CommandRoot, view: RegistryView, byte: u8) -> io::Result<Registry> {
    r.with_command_tree(
        root,
        &[],
        view,
        Ok(CommandTree {
            header: header(root, byte),
            children: vec![],
        }),
    )
}

#[test]
fn system_command_absence_and_unselected_neighbors_survive_retained_machine_handles() {
    for missing_path in [false, true] {
        for first in [false, true] {
            let mut r = if first {
                registry().with_machine_hive(hive(2)).unwrap()
            } else {
                registry()
            };
            for view in [RegistryView::Native64, RegistryView::Wow32] {
                r = r
                    .with_command_view(
                        CommandRoot::System,
                        &[],
                        view,
                        Err(if missing_path {
                            STATUS_OBJECT_PATH_NOT_FOUND
                        } else {
                            STATUS_OBJECT_NAME_NOT_FOUND
                        }),
                    )
                    .unwrap();
            }
            if !first {
                r = r.with_machine_hive(hive(2)).unwrap();
            }
            let machine = r.key(&wide(super::super::MACHINE_HIVE_KEY)).unwrap();
            for view in [RegistryView::Native64, RegistryView::Wow32] {
                let absolute = r.lookup_view(&CommandRoot::System.path(&[]).unwrap(), view);
                let relative = machine.relative_in_view(
                    &wide("sYsTeM\\Software\\Microsoft\\Command Processor"),
                    view,
                );
                for result in [absolute, relative] {
                    assert!(matches!(
                        (missing_path, result),
                        (true, Lookup::MissingPath) | (false, Lookup::Missing)
                    ));
                }
                assert!(matches!(
                    machine.relative_in_view(
                        &wide("System\\Software\\Microsoft\\Command ProcessorOther"),
                        view
                    ),
                    Lookup::Unselected
                ));
            }
            drop(r);
            assert!(matches!(
                machine.relative_in_view(
                    &wide("System\\Software\\Microsoft\\Command Processor"),
                    RegistryView::Native64
                ),
                Lookup::Missing | Lookup::MissingPath
            ));
        }
    }
}

#[test]
fn system_command_positive_shared_views_require_identical_contents_and_fixed_names() {
    let r = present(registry(), CommandRoot::System, RegistryView::Native64, 9).unwrap();
    assert!(present(r.clone(), CommandRoot::System, RegistryView::Wow32, 10).is_err());
    let r = present(r, CommandRoot::System, RegistryView::Wow32, 9).unwrap();
    assert_eq!(
        r.value_budget().unwrap().count,
        2,
        "both retained view records charge the existing storage budget"
    );
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let Lookup::Present(key) = r.lookup_view(&wide(SYSTEM_COMMAND_PROCESSOR_KEY), view) else {
            panic!("selected System leaf")
        };
        assert_eq!(key.path, wide(SYSTEM_COMMAND_PROCESSOR_KEY));
        assert_eq!(
            key.value(&wide("completionchar")).unwrap().data,
            [9, 0, 0, 0]
        );
        assert!(matches!(key.relative(&wide("unknown")), Lookup::Missing));
    }
    for escaped in [
        "\\Registry\\Machine\\System\\Software\\WOW6432Node\\Microsoft\\Command Processor",
        COMMAND_PROCESSOR_KEY,
        "\\Registry\\User\\S-1-5-18\\Software\\Microsoft\\Command Processor",
    ] {
        let mut h = header(CommandRoot::System, 9);
        h.canonical = wide(escaped);
        assert!(
            registry()
                .with_command_view(CommandRoot::System, &[], RegistryView::Wow32, Ok(h))
                .is_err()
        );
    }
}

#[test]
fn system_command_shared_views_reject_presence_and_absence_class_races() {
    for present_first in [false, true] {
        let r = if present_first {
            present(registry(), CommandRoot::System, RegistryView::Native64, 9).unwrap()
        } else {
            registry()
                .with_command_view(
                    CommandRoot::System,
                    &[],
                    RegistryView::Native64,
                    Err(STATUS_OBJECT_NAME_NOT_FOUND),
                )
                .unwrap()
        };
        let result = if present_first {
            r.with_command_view(
                CommandRoot::System,
                &[],
                RegistryView::Wow32,
                Err(STATUS_OBJECT_NAME_NOT_FOUND),
            )
        } else {
            present(r, CommandRoot::System, RegistryView::Wow32, 9)
        };
        assert!(result.is_err(), "System views share one physical subject");
    }
    let r = registry()
        .with_command_view(
            CommandRoot::System,
            &[],
            RegistryView::Native64,
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
        )
        .unwrap();
    assert!(
        r.with_command_view(
            CommandRoot::System,
            &[],
            RegistryView::Wow32,
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        )
        .is_err()
    );
}

#[test]
fn system_command_machine_accounting_counts_system_and_software_independently() {
    for first in [false, true] {
        let mut r = if first {
            registry().with_machine_hive(hive(1)).unwrap()
        } else {
            registry()
        };
        r = present(r, CommandRoot::Machine, RegistryView::Native64, 1).unwrap();
        if first {
            assert!(present(r, CommandRoot::System, RegistryView::Native64, 1).is_err());
        } else {
            r = present(r, CommandRoot::System, RegistryView::Native64, 1).unwrap();
            assert!(r.clone().with_machine_hive(hive(1)).is_err());
            let r = r.with_machine_hive(hive(2)).unwrap();
            let root = r.key(&wide(super::super::MACHINE_HIVE_KEY)).unwrap();
            assert!(matches!(
                root.relative_in_view(
                    &wide("System\\Software\\Microsoft\\Command Processor"),
                    RegistryView::Native64
                ),
                Lookup::Present(_)
            ));
        }
    }
}

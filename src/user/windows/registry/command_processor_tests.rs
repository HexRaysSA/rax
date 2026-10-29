use super::*;
use crate::user::windows::nt::status::*;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn sid() -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]
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
fn header(root: CommandRoot, view: RegistryView, byte: u8) -> CommandHeader {
    let mut canonical = root.path(&sid()).unwrap();
    if view == RegistryView::Wow32 {
        let text = String::from_utf16(&canonical).unwrap().replace(
            "\\Software\\Microsoft",
            "\\Software\\WOW6432Node\\Microsoft",
        );
        canonical = units(&text);
    }
    CommandHeader {
        canonical,
        children: 1,
        values: vec![Value {
            name: units("CompletionChar"),
            kind: 4,
            data: vec![byte, 0, 0, 0],
        }],
        access: KeyAccess {
            maximum_access: 0xF003F,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    }
}
fn hives(r: Registry) -> Registry {
    r.with_machine_hive(MachineHeader {
        canonical: units("\\REGISTRY\\MACHINE"),
        children: 6,
        values: vec![],
        access: KeyAccess {
            maximum_access: 0xF003F,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    })
    .unwrap()
    .with_primary_hive(
        &sid(),
        Some(HiveHeader {
            canonical: units("\\REGISTRY\\USER\\.DEFAULT"),
            children: 4,
            values: vec![],
        }),
    )
    .unwrap()
}

#[test]
fn command_views_keep_physical_identity_and_retained_hive_routes_in_both_capture_orders() {
    for first in [false, true] {
        let mut r = if first { hives(registry()) } else { registry() };
        for root in [CommandRoot::Machine, CommandRoot::User] {
            for (view, byte) in [(RegistryView::Native64, 64), (RegistryView::Wow32, 32)] {
                r = r
                    .with_command_view(root, &sid(), view, Ok(header(root, view, byte)))
                    .unwrap();
            }
        }
        if !first {
            r = hives(r);
        }
        let machine = r.key(&units(MACHINE_HIVE_KEY)).unwrap();
        let user = r
            .key(&user_policy::user_hive_path(&sid()).unwrap())
            .unwrap();
        for (root, parent) in [(CommandRoot::Machine, machine), (CommandRoot::User, user)] {
            for (view, byte) in [(RegistryView::Native64, 64), (RegistryView::Wow32, 32)] {
                let logical = root.path(&sid()).unwrap();
                let Lookup::Present(absolute) = r.lookup_view(&logical, view) else {
                    panic!("absolute");
                };
                let Lookup::Present(relative) =
                    parent.relative_in_view(&units(COMMAND_SUFFIX), view)
                else {
                    panic!("relative");
                };
                assert!(Arc::ptr_eq(&absolute, &relative));
                assert_eq!(
                    relative.value(&units("completionchar")).unwrap().data,
                    [byte, 0, 0, 0]
                );
                assert_eq!(relative.children, 1);
                assert_eq!(
                    relative.captured_access().unwrap().grant(0x02000000),
                    Ok(0xF003F)
                );
                assert!(matches!(
                    relative.relative(&units("KnownPackageManagers")),
                    Lookup::Unselected
                ));
                let catalog = parent.hive_views().unwrap();
                let Lookup::Present(other) = catalog.relative(
                    &relative,
                    &[],
                    if view == RegistryView::Native64 {
                        RegistryView::Wow32
                    } else {
                        RegistryView::Native64
                    },
                ) else {
                    panic!("paired view");
                };
                assert_eq!(
                    other.value(&units("CompletionChar")).unwrap().data,
                    [if byte == 64 { 32 } else { 64 }, 0, 0, 0]
                );
                drop(catalog);
            }
            let kept = parent.clone();
            let Lookup::Present(relative) =
                kept.relative_in_view(&units(COMMAND_SUFFIX), RegistryView::Wow32)
            else {
                panic!("retained");
            };
            assert_eq!(
                relative.value(&units("CompletionChar")).unwrap().data,
                [32, 0, 0, 0]
            );
            assert_eq!(
                root.path(&sid()).unwrap(),
                r.views.paths[&root.selection()].as_ref()
            );
        }
        assert_eq!(r.value_budget().unwrap().count, 4);
        let retained = r.key(&units(MACHINE_HIVE_KEY)).unwrap();
        drop(r);
        assert!(matches!(
            retained.relative_in_view(&units(COMMAND_SUFFIX), RegistryView::Native64),
            Lookup::Present(_)
        ));
    }
}

#[test]
fn command_selected_absence_preserves_name_vs_path_and_unselected_boundaries() {
    for root in [CommandRoot::Machine, CommandRoot::User] {
        let r = hives(registry())
            .with_command_view(
                root,
                &sid(),
                RegistryView::Native64,
                Err(STATUS_OBJECT_NAME_NOT_FOUND),
            )
            .unwrap()
            .with_command_view(
                root,
                &sid(),
                RegistryView::Wow32,
                Err(STATUS_OBJECT_PATH_NOT_FOUND),
            )
            .unwrap();
        let logical = root.path(&sid()).unwrap();
        assert!(matches!(
            r.lookup_view(&logical, RegistryView::Native64),
            Lookup::Missing
        ));
        assert!(matches!(
            r.lookup_view(&logical, RegistryView::Wow32),
            Lookup::MissingPath
        ));
        let mut descendant = logical.clone();
        descendant.extend(units("\\child"));
        assert!(matches!(
            r.lookup_view(&descendant, RegistryView::Wow32),
            Lookup::MissingPath
        ));
        let mut outside = logical;
        outside.extend(units("Suffix"));
        assert!(matches!(
            r.lookup_view(&outside, RegistryView::Native64),
            Lookup::Unselected
        ));
        assert!(
            registry()
                .with_command_view(
                    root,
                    &sid(),
                    RegistryView::Native64,
                    Err(STATUS_ACCESS_DENIED)
                )
                .is_err()
        );
    }
}

#[test]
fn command_views_reject_changed_shared_key_and_mixed_creator_subjects() {
    let first = header(CommandRoot::User, RegistryView::Native64, 1);
    let canonical = first.canonical.clone();
    let r = registry()
        .with_command_view(CommandRoot::User, &sid(), RegistryView::Native64, Ok(first))
        .unwrap();
    let mut different = header(CommandRoot::User, RegistryView::Wow32, 2);
    different.canonical = canonical.clone();
    assert!(
        r.clone()
            .with_command_view(
                CommandRoot::User,
                &sid(),
                RegistryView::Wow32,
                Ok(different)
            )
            .is_err()
    );
    let mut same = header(CommandRoot::User, RegistryView::Wow32, 1);
    same.canonical = canonical;
    assert!(
        r.clone()
            .with_command_view(CommandRoot::User, &sid(), RegistryView::Wow32, Ok(same))
            .is_ok()
    );
    let mut other = sid();
    other[8] = 22;
    assert!(r.clone().with_primary_hive(&other, None).is_err());
    assert!(
        r.with_command_view(
            CommandRoot::User,
            &other,
            RegistryView::Wow32,
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        )
        .is_err()
    );
    let absent = registry().with_primary_hive(&sid(), None).unwrap();
    assert!(
        absent
            .with_command_view(
                CommandRoot::User,
                &sid(),
                RegistryView::Native64,
                Ok(header(CommandRoot::User, RegistryView::Native64, 1))
            )
            .is_err()
    );
}

#[test]
fn command_headers_validate_scope_access_and_shared_aggregate_budgets() {
    for name in [
        "\\Registry\\Machine\\Software\\Microsoft\\Other",
        "\\Registry\\Machine\\Software\\Microsoft\\Command Processor\\child",
        "\\Registry\\User\\S-1-5-21\\Software\\Microsoft\\Command Processor",
        "\\Registry\\Machine\\Software\\Microsoft\\Command Processor\0",
    ] {
        let mut h = header(CommandRoot::Machine, RegistryView::Native64, 1);
        h.canonical = units(name);
        assert!(
            registry()
                .with_command_view(CommandRoot::Machine, &[], RegistryView::Native64, Ok(h))
                .is_err()
        );
    }
    for access in [0x02000000, 0x00100000, 0xFFFFFFFF] {
        let mut h = header(CommandRoot::Machine, RegistryView::Native64, 1);
        h.access.maximum_access = access;
        assert!(
            registry()
                .with_command_view(CommandRoot::Machine, &[], RegistryView::Native64, Ok(h))
                .is_err()
        );
    }
    let mut h = header(CommandRoot::Machine, RegistryView::Native64, 1);
    h.access.system_security_status = 1;
    assert!(
        registry()
            .with_command_view(CommandRoot::Machine, &[], RegistryView::Native64, Ok(h))
            .is_err()
    );
    let r = hives(registry())
        .with_command_view(
            CommandRoot::Machine,
            &[],
            RegistryView::Native64,
            Ok(header(CommandRoot::Machine, RegistryView::Native64, 1)),
        )
        .unwrap();
    assert!(
        r.clone()
            .with_command_view(
                CommandRoot::Machine,
                &[],
                RegistryView::Native64,
                Err(STATUS_OBJECT_NAME_NOT_FOUND)
            )
            .is_err()
    );
    let mut h = header(CommandRoot::Machine, RegistryView::Wow32, 2);
    h.values = (0..MAX_VALUES)
        .map(|n| Value {
            name: units(&n.to_string()),
            kind: 0,
            data: vec![],
        })
        .collect();
    assert!(
        r.with_command_view(CommandRoot::Machine, &[], RegistryView::Wow32, Ok(h))
            .is_err()
    );
    assert!(
        registry()
            .with_command_view(
                CommandRoot::User,
                &[0],
                RegistryView::Native64,
                Err(STATUS_OBJECT_NAME_NOT_FOUND)
            )
            .is_err()
    );
}

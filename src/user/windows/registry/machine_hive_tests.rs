use super::*;
use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
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
fn value(data: u8) -> Value {
    Value {
        name: units("Data"),
        kind: 3,
        data: vec![data],
    }
}
fn tree(data: u8) -> KeyTree {
    KeyTree {
        values: vec![value(data)],
        children: vec![],
    }
}
fn header(children: u32) -> MachineHeader {
    MachineHeader {
        enumeration: None,
        canonical: units("\\REGISTRY\\MACHINE"),
        children,
        values: vec![Value {
            name: units("ServiceLastKnownStatus"),
            kind: 4,
            data: 2u32.to_le_bytes().to_vec(),
        }],
        access: KeyAccess {
            maximum_access: 0xF003F,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    }
}
fn root(r: &Registry) -> Arc<Key> {
    r.key(&units(MACHINE_HIVE_KEY)).expect("selected MACHINE")
}

#[test]
fn machine_header_keeps_captured_values_and_partial_namespace() {
    let selected = registry().with_machine_hive(header(6)).unwrap();
    let key = root(&selected);
    assert_eq!(key.path, units("\\REGISTRY\\MACHINE"));
    assert_eq!(key.children, 6);
    let value = key.value(&units("servicelastknownstatus")).unwrap();
    assert_eq!((value.kind, value.data.as_slice()), (4, &[2, 0, 0, 0][..]));
    assert_eq!(selected.value_budget().unwrap().count, 1);
    for outside in [
        "\\Registry",
        "\\Registry\\MachineSuffix",
        "\\Registry\\User",
        "\\Registry\\Machine\\unknown",
    ] {
        assert!(
            matches!(selected.lookup(&units(outside)), Lookup::Unselected),
            "{outside}"
        );
    }
    drop(selected);
    assert!(matches!(
        key.relative(&units("unknown")),
        Lookup::Unselected
    ));
    let Lookup::Present(same) = key.relative(&units("\\\\")) else {
        panic!("empty suffix");
    };
    assert!(Arc::ptr_eq(&same, &key));
}

#[test]
fn machine_ordinary_access_matches_the_native_root_controls() {
    let profile = header(6).access;
    let allowed = [
        (1, 1),
        (2, 2),
        (8, 8),
        (0x20, 0x20),
        (0x20019, 0x20019),
        (0xF003F, 0xF003F),
        (0x02000000, 0xF003F),
        (0x80000000, 0x20019),
        (0x40000000, 0x20006),
        (0x20000000, 0x20039),
        (0x10000000, 0xF003F),
        (0x82000000, 0xF003F),
    ];
    for view in [0, 0x100, 0x200, 0x300] {
        for (request, grant) in allowed {
            assert_eq!(profile.grant(request | view), Ok(grant));
        }
        for denied in [0, 0x100000, 0x1000000, 0x3000000, 0x4000000] {
            assert_eq!(profile.grant(denied | view), Err(STATUS_ACCESS_DENIED));
        }
    }
    let limited = KeyAccess {
        maximum_access: 1,
        system_security_status: 0xC0000061,
    };
    assert_eq!(limited.grant(0x02000000), Ok(1));
    assert_eq!(limited.grant(2), Err(STATUS_ACCESS_DENIED));
    assert_eq!(limited.grant(0x01000000), Err(0xC0000061));
}

fn add_routes(r: Registry) -> Registry {
    r.with_tree(TreeRoot::FileSystem, Some(tree(3)))
        .unwrap()
        .with_tree(TreeRoot::Ifeo, None)
        .unwrap()
        .with_appmodel_view(AppModelRoot::Machine, RegistryView::Native64, Some(tree(4)))
        .unwrap()
        .with_appmodel_view(AppModelRoot::Machine, RegistryView::Wow32, Some(tree(5)))
        .unwrap()
        .with_appmodel_view(AppModelRoot::User, RegistryView::Native64, None)
        .unwrap()
        .with_appmodel_view(AppModelRoot::User, RegistryView::Wow32, None)
        .unwrap()
}

#[test]
fn machine_routes_keep_both_views_and_survive_selection_replacement() {
    for first in [false, true] {
        let initial = registry().with_machine_hive(header(6)).unwrap();
        let old = root(&initial);
        let selected = if first {
            add_routes(initial)
        } else {
            add_routes(registry()).with_machine_hive(header(6)).unwrap()
        };
        let key = root(&selected);
        assert!(matches!(
            old.relative(&units("System\\CurrentControlSet\\Control\\FileSystem")),
            Lookup::Unselected
        ));
        let Lookup::Present(files) =
            key.relative(&units("system\\\\currentcontrolset\\control\\filesystem\\"))
        else {
            panic!("fixed subtree");
        };
        assert_eq!(files.value(&units("DATA")).unwrap().data, [3]);
        for (view, data) in [(RegistryView::Native64, 4), (RegistryView::Wow32, 5)] {
            let suffix = "Software\\Microsoft\\AppModel\\Lookaside\\machine";
            let Lookup::Present(child) = key.relative_in_view(&units(suffix), view) else {
                panic!("view");
            };
            assert_eq!(child.value(&units("Data")).unwrap().data, [data]);
            let catalog = key.hive_views().unwrap();
            let Lookup::Present(paired) = catalog.relative(
                &child,
                &[],
                if view == RegistryView::Native64 {
                    RegistryView::Wow32
                } else {
                    RegistryView::Native64
                },
            ) else {
                panic!("paired retained view");
            };
            assert_eq!(
                paired.value(&units("Data")).unwrap().data,
                [if data == 4 { 5 } else { 4 }]
            );
            assert!(matches!(
                key.relative_in_view(
                    &units("Software\\Microsoft\\AppModel\\Lookaside\\user\\nested"),
                    view
                ),
                Lookup::Missing
            ));
        }
        assert!(matches!(
            key.relative(&units("Software")),
            Lookup::Unselected
        ));
        assert!(matches!(key.relative(&units("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\unknown")), Lookup::Missing));
        assert_eq!(selected.value_budget().unwrap().count, 4);
        drop(selected);
        let Lookup::Present(files_again) =
            key.relative(&units("System\\CurrentControlSet\\Control\\FileSystem"))
        else {
            panic!("retained fixed tree");
        };
        assert!(Arc::ptr_eq(&files, &files_again));
    }
}

#[test]
fn machine_header_rejects_contradictions_and_unauthorized_names() {
    for name in [
        "\\Registry\\User",
        "\\Registry\\MachineSuffix",
        "\\Registry\\Machin\0",
    ] {
        let mut h = header(6);
        h.canonical = units(name);
        assert!(registry().with_machine_hive(h).is_err());
    }
    assert!(add_routes(registry()).with_machine_hive(header(1)).is_err());
    assert!(
        registry()
            .with_machine_hive(header(0))
            .unwrap()
            .with_tree(TreeRoot::FileSystem, Some(tree(3)))
            .is_err()
    );
    assert!(
        registry()
            .with_machine_hive(header(6))
            .unwrap()
            .with_machine_hive(header(6))
            .is_err()
    );
    let mut h = header(6);
    h.access.maximum_access |= 0x02000000;
    assert!(registry().with_machine_hive(h).is_err());
    let empty = registry().with_machine_hive(header(0)).unwrap();
    assert!(matches!(
        root(&empty).relative(&units("unknown")),
        Lookup::Missing
    ));
}

#[test]
fn machine_values_share_the_existing_aggregate_budget() {
    let h = header(6);
    let values = (0..MAX_VALUES)
        .map(|n| Value {
            name: units(&n.to_string()),
            kind: 0,
            data: vec![],
        })
        .collect();
    assert!(
        registry()
            .with_machine_hive(h)
            .unwrap()
            .with_tree(
                TreeRoot::FileSystem,
                Some(KeyTree {
                    values,
                    children: vec![]
                })
            )
            .is_err()
    );
}

#[test]
fn machine_route_does_not_fold_descendant_units_twice() {
    let mut map: Vec<_> = (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect();
    map[0x4000] = 0x4001;
    map[0x4001] = 0x4002;
    let selected = Registry::selected(map, vec![])
        .unwrap()
        .with_tree(
            TreeRoot::FileSystem,
            Some(KeyTree {
                values: vec![],
                children: vec![(vec![0x4000], tree(7))],
            }),
        )
        .unwrap()
        .with_machine_hive(header(6))
        .unwrap();
    let mut name = units("System\\CurrentControlSet\\Control\\FileSystem\\");
    name.push(0x4000);
    let Lookup::Present(child) = root(&selected).relative(&name) else {
        panic!("single fold");
    };
    assert_eq!(child.value(&units("Data")).unwrap().data, [7]);
}

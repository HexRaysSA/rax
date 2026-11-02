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
fn tree(path: &str, byte: u8) -> CommandTree {
    CommandTree {
        header: CommandHeader {
            enumeration: Some(vec![]),
            canonical: wide(path),
            children: 0,
            values: vec![Value {
                name: wide("Captured"),
                kind: 3,
                data: vec![byte],
            }],
            access: KeyAccess {
                maximum_access: 0xF003F,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        },
        children: vec![],
    }
}
fn present(r: Registry, view: RegistryView, byte: u8) -> io::Result<Registry> {
    r.with_ole_tree(view, Ok(tree(OLE_KEY, byte)))
}

#[test]
fn ole_shared_views_require_identical_physical_contents_and_fixed_names() {
    let r = present(registry(), RegistryView::Native64, 1).unwrap();
    assert!(present(r.clone(), RegistryView::Wow32, 2).is_err());
    let r = present(r, RegistryView::Wow32, 1).unwrap();
    assert_eq!(r.value_budget().unwrap().count, 2);
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let Lookup::Present(k) =
            r.lookup_view(&wide("\\REGISTRY\\MACHINE\\software\\microsoft\\ole"), view)
        else {
            panic!("captured OLE")
        };
        assert_eq!(k.value(&wide("captured")).unwrap().data, [1]);
        assert!(matches!(k.relative(&wide("absent")), Lookup::Missing));
        assert!(matches!(
            r.lookup_view(&wide(&(OLE_KEY.to_owned() + "Other")), view),
            Lookup::Unselected
        ));
    }
    for path in [
        "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\OLE",
        COMMAND_PROCESSOR_KEY,
        "\\Registry\\User\\S-1-5-18\\Software\\Microsoft\\OLE",
    ] {
        assert!(
            registry()
                .with_ole_tree(RegistryView::Wow32, Ok(tree(path, 1)))
                .is_err()
        );
    }
}

#[test]
fn ole_shared_views_reject_presence_and_absence_class_races() {
    for absent in [STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND] {
        let r = registry()
            .with_ole_tree(RegistryView::Native64, Err(absent))
            .unwrap();
        assert!(present(r.clone(), RegistryView::Wow32, 1).is_err());
        let other = if absent == STATUS_OBJECT_NAME_NOT_FOUND {
            STATUS_OBJECT_PATH_NOT_FOUND
        } else {
            STATUS_OBJECT_NAME_NOT_FOUND
        };
        assert!(
            r.clone()
                .with_ole_tree(RegistryView::Wow32, Err(other))
                .is_err()
        );
        let r = r.with_ole_tree(RegistryView::Wow32, Err(absent)).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            assert!(matches!(
                (absent, r.lookup_view(&wide(OLE_KEY), view)),
                (STATUS_OBJECT_NAME_NOT_FOUND, Lookup::Missing)
                    | (STATUS_OBJECT_PATH_NOT_FOUND, Lookup::MissingPath)
            ));
        }
        let r = present(registry(), RegistryView::Native64, 1).unwrap();
        assert!(r.with_ole_tree(RegistryView::Wow32, Err(absent)).is_err());
    }
    assert!(
        registry()
            .with_ole_tree(RegistryView::Native64, Err(STATUS_ACCESS_DENIED))
            .is_err()
    );
}

#[test]
fn ole_complete_tree_preserves_descendants_and_machine_routes_after_catalog_drop() {
    let mut t = tree(OLE_KEY, 1);
    t.header.children = 1;
    t.header.enumeration = None;
    t.children
        .push((wide("Child"), tree(&(OLE_KEY.to_owned() + "\\Child"), 2)));
    let r = registry()
        .with_ole_tree(RegistryView::Native64, Ok(t))
        .unwrap()
        .with_machine_hive(MachineHeader {
            enumeration: None,
            canonical: wide(MACHINE_HIVE_KEY),
            children: 1,
            values: vec![],
            access: KeyAccess {
                maximum_access: 0xF003F,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        })
        .unwrap();
    let machine = r.key(&wide(MACHINE_HIVE_KEY)).unwrap();
    drop(r);
    let Lookup::Present(child) = machine.relative_in_view(
        &wide("Software\\Microsoft\\OLE\\Child"),
        RegistryView::Native64,
    ) else {
        panic!("retained OLE child")
    };
    assert_eq!(child.value(&wide("Captured")).unwrap().data, [2]);
    assert!(matches!(
        machine.relative_in_view(
            &wide("Software\\Microsoft\\OLEOther"),
            RegistryView::Native64
        ),
        Lookup::Unselected
    ));
    assert!(matches!(child.relative(&wide("unknown")), Lookup::Missing));
}

#[test]
fn ole_shared_view_checks_include_descendants_and_access_profiles() {
    let mut first = tree(OLE_KEY, 1);
    first.header.children = 1;
    first.header.enumeration = None;
    first
        .children
        .push((wide("Child"), tree(&(OLE_KEY.to_owned() + "\\Child"), 2)));
    let r = registry()
        .with_ole_tree(RegistryView::Native64, Ok(first))
        .unwrap();
    let mut second = tree(OLE_KEY, 1);
    second.header.children = 1;
    second.header.enumeration = None;
    second
        .children
        .push((wide("Child"), tree(&(OLE_KEY.to_owned() + "\\Child"), 3)));
    assert!(
        r.clone()
            .with_ole_tree(RegistryView::Wow32, Ok(second))
            .is_err()
    );
    let mut second = tree(OLE_KEY, 1);
    second.header.children = 1;
    second.header.enumeration = None;
    second
        .children
        .push((wide("Child"), tree(&(OLE_KEY.to_owned() + "\\Child"), 2)));
    second.header.access.maximum_access = 0x20019;
    assert!(r.with_ole_tree(RegistryView::Wow32, Ok(second)).is_err());
}

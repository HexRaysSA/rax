use super::*;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

fn units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn upcase() -> Vec<u16> {
    (0..=u16::MAX)
        .map(|unit| {
            if (97..=122).contains(&unit) {
                unit - 32
            } else {
                unit
            }
        })
        .collect()
}

fn header(path: &str, values: Vec<Value>) -> CommandHeader {
    CommandHeader {
        canonical: units(path),
        children: 2,
        enumeration: None,
        values,
        access: KeyAccess {
            maximum_access: 0x20019,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    }
}

#[test]
fn process_config_projects_only_fixed_named_values_in_the_requested_view() {
    let root = ProcessConfigKey::Rpc;
    let physical = r"\Registry\Machine\Software\WOW6432Node\Microsoft\Rpc";
    let name = "MaxRpcSize";
    let value = |data: u32| Value {
        name: units(name),
        kind: 4,
        data: data.to_le_bytes().to_vec(),
    };
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(root),
            &[],
            RegistryView::Native64,
            Ok((header(root.path(), vec![value(64)]), None)),
        )
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(root),
            &[],
            RegistryView::Wow32,
            Ok((header(physical, vec![value(32)]), None)),
        )
        .unwrap();
    for (path, view, data) in [
        (root.path(), RegistryView::Native64, 64),
        (root.path(), RegistryView::Wow32, 32),
        (physical, RegistryView::Native64, 32),
    ] {
        let Lookup::Present(key) = registry.lookup_view(&units(path), view) else {
            panic!("process configuration key not routed");
        };
        assert!(key.covers_value(&units("maxrpcsize")));
        assert_eq!(key.value(&units("maxrpcsize")), Some(&value(data)));
        assert!(key.covers_value(&units("IDLETIMERWINDOW")));
        assert!(key.value(&units("IDLETIMERWINDOW")).is_none());
        assert!(!key.covers_value(&units("OtherValue")));
        assert!(key.ordered_values().is_none());
        assert!(key.child_metadata().is_none());
        let grant = key.captured_access().unwrap();
        assert_eq!(grant.grant(1), Ok(1));
        assert_eq!(grant.grant(2), Err(STATUS_ACCESS_DENIED));
        assert!(matches!(
            registry.lookup_view(&units(&format!(r"{path}\OtherKey")), view),
            Lookup::Unselected
        ));
    }
}

#[test]
fn process_config_preserves_absent_keys_and_control_set_aliases() {
    let ccg = SnapshotRoot::ProcessConfig(ProcessConfigKey::Ccg);
    let rpc = SnapshotRoot::ProcessConfig(ProcessConfigKey::Rpc);
    let computer = SnapshotRoot::ProcessConfig(ProcessConfigKey::ActiveComputerName);
    let alias = r"\REGISTRY\MACHINE\SYSTEM\ControlSet009\Control\ComputerName\ActiveComputerName";
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_snapshot_selection(
            ccg,
            &[],
            RegistryView::Native64,
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
        )
        .unwrap()
        .with_snapshot_selection(
            rpc,
            &[],
            RegistryView::Wow32,
            Err(STATUS_OBJECT_PATH_NOT_FOUND),
        )
        .unwrap()
        .with_snapshot_selection(
            computer,
            &[],
            RegistryView::Native64,
            Ok((header(alias, vec![]), None)),
        )
        .unwrap();
    assert!(matches!(
        registry.lookup(&ccg.path(&[]).unwrap()),
        Lookup::Missing
    ));
    assert!(matches!(
        registry.lookup_view(&rpc.path(&[]).unwrap(), RegistryView::Wow32),
        Lookup::MissingPath
    ));
    assert!(matches!(
        registry.lookup(&rpc.path(&[]).unwrap()),
        Lookup::Unselected
    ));
    for path in [computer.path(&[]).unwrap(), units(alias)] {
        let Lookup::Present(key) = registry.lookup(&path) else {
            panic!("active computer name key not routed");
        };
        assert!(key.covers_value(&units("computername")));
        assert!(!key.covers_value(&units("OtherValue")));
    }
    assert!(
        ProcessConfigKey::ActiveComputerName
            .check_name(
                &registry,
                RegistryView::Native64,
                &units(&alias.replace("009", "00A"))
            )
            .is_err()
    );
}

#[test]
fn winsock_parameters_exposes_only_selected_values_in_both_views() {
    let subject = ProcessConfigKey::WinsockParameters;
    let root = SnapshotRoot::ProcessConfig(subject);
    let native_path = subject.path().replace("CurrentControlSet", "ControlSet001");
    let registry = Registry::selected(upcase(), vec![]).unwrap();
    let string_value = |name: &str, kind: u32, data: &str| Value {
        name: units(name),
        kind,
        data: data
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    let values = vec![
        string_value("Current_NameSpace_Catalog", 1, "NameSpace_Catalog5"),
        string_value("Current_Protocol_Catalog", 1, "Protocol_Catalog9"),
        string_value("NameSpace_Callout", 2, r"%SystemRoot%\System32\example.dll"),
        string_value("WinSock_Registry_Version", 1, "2.0"),
    ];
    let mut captured = registry.clone();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        captured = captured
            .with_snapshot_selection(
                root,
                &[],
                view,
                Ok((header(&native_path, values.clone()), None)),
            )
            .unwrap();
        for path in [subject.path(), &native_path] {
            let Lookup::Present(key) = captured.lookup_view(&units(path), view) else {
                panic!("Winsock catalog selection did not resolve");
            };
            for expected in &values {
                assert!(key.covers_value(&expected.name));
                assert_eq!(key.value(&expected.name), Some(expected));
            }
            let optional_buckets = units("ws2_32numhandlebuckets");
            assert!(key.covers_value(&optional_buckets));
            assert!(key.value(&optional_buckets).is_none());
            assert!(!key.covers_value(&units("AutodialDLL")));
            assert!(matches!(
                key.relative(&units("Protocol_Catalog9")),
                Lookup::Unselected
            ));
            assert_eq!(
                key.captured_access().unwrap().grant(2),
                Err(STATUS_ACCESS_DENIED)
            );
        }
    }

    let unrelated = string_value("AutodialDLL", 1, "unselected.dll");
    assert!(
        registry
            .with_snapshot_selection(
                root,
                &[],
                RegistryView::Native64,
                Ok((header(&native_path, vec![unrelated]), None)),
            )
            .is_err()
    );
}

#[test]
fn winsock_app_id_catalog_uses_the_selected_child_in_both_views() {
    let parent = ProcessConfigKey::WinsockParameters;
    let child = ProcessConfigKey::WinsockAppIdCatalog;
    let physical_parent = parent.path().replace("CurrentControlSet", "ControlSet001");
    let physical_child = child.path().replace("CurrentControlSet", "ControlSet001");
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        registry = registry
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(child),
                &[],
                view,
                Ok((header(&physical_child, vec![]), None)),
            )
            .unwrap()
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(parent),
                &[],
                view,
                Ok((header(&physical_parent, vec![]), None)),
            )
            .unwrap();
        for absolute in [child.path(), &physical_child] {
            let Lookup::Present(key) = registry.lookup_view(&units(absolute), view) else {
                panic!("Winsock application-ID catalog did not resolve");
            };
            let Lookup::Present(parent_key) = registry.lookup_view(&units(parent.path()), view)
            else {
                panic!("Winsock Parameters did not resolve");
            };
            let Lookup::Present(relative) = parent_key.relative(&units(r"appID_catalog\")) else {
                panic!("Winsock Parameters could not open its selected child");
            };
            assert!(Arc::ptr_eq(&relative, &key));
            assert_eq!(key.redirected_view, Some(view));
            assert_eq!(
                key.captured_access().unwrap().grant(2),
                Err(STATUS_ACCESS_DENIED)
            );
            assert!(!key.covers_value(&units("Unselected")));
            for unselected in [
                format!(r"{absolute}\Unselected"),
                format!(r"{absolute}-Unselected"),
            ] {
                assert!(matches!(
                    registry.lookup_view(&units(&unselected), view),
                    Lookup::Unselected
                ));
            }
        }
    }
}

fn catalog_node(
    path: &str,
    values: Vec<Value>,
    children: Vec<(Vec<u16>, CommandTree)>,
) -> CommandTree {
    let mut header = header(path, values);
    header.children = children.len() as u32;
    header.enumeration = Some(
        children
            .iter()
            .map(|(name, _)| BasicChild {
                name: name.clone(),
                last_write: 42,
            })
            .collect(),
    );
    CommandTree { header, children }
}

fn catalog_tree(path: &str, entry_values: impl Fn(u8) -> Vec<Value>) -> CommandTree {
    let entry_list = |name: &str, marker: u8| {
        let path = format!(r"{path}\{name}");
        let entry = "000000000001";
        let entry_node = catalog_node(&format!(r"{path}\{entry}"), entry_values(marker), vec![]);
        (
            units(name),
            catalog_node(&path, vec![], vec![(units(entry), entry_node)]),
        )
    };
    catalog_node(
        path,
        vec![Value {
            name: units("Num_Catalog_Entries"),
            kind: 4,
            data: 1u32.to_le_bytes().to_vec(),
        }],
        vec![
            entry_list("Catalog_Entries64", 64),
            entry_list("Catalog_Entries", 32),
        ],
    )
}

fn protocol_values(marker: u8) -> Vec<Value> {
    vec![
        Value {
            name: units("ProtocolName"),
            kind: 1,
            data: vec![b'X', 0, 0, 0],
        },
        Value {
            name: units("PackedCatalogItem"),
            kind: 3,
            data: vec![marker; 888],
        },
    ]
}

fn namespace_values(marker: u8) -> Vec<Value> {
    [
        ("LibraryPath", 1, vec![b'X', 0, 0, 0]),
        ("ProviderId", 3, vec![marker; 16]),
        (
            "ProviderInfo",
            3,
            if marker == 32 { vec![] } else { vec![marker] },
        ),
        ("DisplayString", 1, vec![b'Y', 0, 0, 0]),
        ("Enabled", 4, 1u32.to_le_bytes().to_vec()),
        ("StoresServiceClassInfo", 4, 0u32.to_le_bytes().to_vec()),
        ("SupportedNameSpace", 4, 12u32.to_le_bytes().to_vec()),
        ("Version", 4, 2u32.to_le_bytes().to_vec()),
    ]
    .into_iter()
    .map(|(name, kind, data)| Value {
        name: units(name),
        kind,
        data,
    })
    .collect()
}

fn check_winsock_catalog_routes(
    subject: ProcessConfigKey,
    catalog_name: &str,
    entry_values: fn(u8) -> Vec<Value>,
) {
    let parent = ProcessConfigKey::WinsockParameters;
    let physical = subject.path().replace("CurrentControlSet", "ControlSet001");
    let physical_parent = parent.path().replace("CurrentControlSet", "ControlSet001");
    let catalog = catalog_tree(&physical, entry_values);
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        registry = registry
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(subject),
                &[],
                view,
                Ok((catalog.header.clone(), Some(catalog.children.clone()))),
            )
            .unwrap()
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(parent),
                &[],
                view,
                Ok((header(&physical_parent, vec![]), None)),
            )
            .unwrap();
        let Lookup::Present(parent) = registry.lookup_view(&units(&physical_parent), view) else {
            panic!("Winsock Parameters did not resolve");
        };
        let Lookup::Present(catalog) = parent.relative(&units(catalog_name)) else {
            panic!("Winsock catalog did not resolve");
        };
        let metadata = catalog.child_metadata().unwrap();
        assert_eq!(metadata[0].name, units("Catalog_Entries64"));
        assert_eq!(metadata[0].last_write, 42);
        assert_eq!(metadata[1].name, units("Catalog_Entries"));
        let count = catalog.value(&units("Num_Catalog_Entries")).unwrap();
        assert_eq!(count.kind, 4);
        assert_eq!(count.data, 1u32.to_le_bytes());
        for (name, marker) in [("Catalog_Entries", 32), ("Catalog_Entries64", 64)] {
            let relative = format!(r"{name}\000000000001");
            let Lookup::Present(entry) = catalog.relative(&units(&relative)) else {
                panic!("Winsock catalog entry did not resolve");
            };
            assert_eq!(entry.redirected_view, Some(view));
            let Lookup::Present(from_parameters) =
                parent.relative(&units(&format!(r"{catalog_name}\{relative}")))
            else {
                panic!("Winsock Parameters could not open the selected entry");
            };
            assert!(Arc::ptr_eq(&entry, &from_parameters));
            for path in [subject.path(), &physical] {
                let Lookup::Present(absolute) =
                    registry.lookup_view(&units(&format!(r"{path}\{relative}")), view)
                else {
                    panic!("Winsock catalog entry did not resolve by absolute path");
                };
                assert!(Arc::ptr_eq(&entry, &absolute));
            }
            let expected = entry_values(marker);
            let ordered = entry.ordered_values().unwrap();
            assert_eq!(ordered.len(), expected.len());
            for (actual, expected) in ordered.iter().zip(expected) {
                assert_eq!(actual.name, expected.name);
                let folded: Vec<u16> = expected
                    .name
                    .iter()
                    .map(|&u| entry.upcase[u as usize])
                    .collect();
                let lookup = entry.value(&folded).unwrap();
                assert_eq!(lookup.kind, expected.kind);
                assert_eq!(lookup.data, expected.data);
            }
            assert!(entry.covers_value(&units("Absent")));
            assert!(entry.value(&units("Absent")).is_none());
        }
        assert!(matches!(
            catalog.relative(&units(r"Catalog_Entries\000000000002")),
            Lookup::Missing
        ));
        assert!(matches!(
            parent.relative(&units("UnselectedSibling")),
            Lookup::Unselected
        ));
    }
}

#[test]
fn winsock_protocol_catalog_preserves_entries_and_native_order_in_both_views() {
    check_winsock_catalog_routes(
        ProcessConfigKey::WinsockProtocolCatalog,
        "protocol_catalog9",
        protocol_values,
    );
}

#[test]
fn winsock_namespace_catalog_preserves_entries_and_native_order_in_both_views() {
    check_winsock_catalog_routes(
        ProcessConfigKey::WinsockNamespaceCatalog,
        "namespace_catalog5",
        namespace_values,
    );
}

#[test]
fn winsock_protocol_catalog_rejects_partial_or_unselected_subtrees() {
    let subject = ProcessConfigKey::WinsockProtocolCatalog;
    let root = SnapshotRoot::ProcessConfig(subject);
    let view = RegistryView::Native64;
    let registry = Registry::selected(upcase(), vec![]).unwrap();
    let catalog = catalog_tree(subject.path(), protocol_values);
    assert!(
        registry
            .clone()
            .with_snapshot_selection(root, &[], view, Ok((catalog.header.clone(), None)),)
            .is_err()
    );
    let mut unexpected_list = catalog.clone();
    unexpected_list.children[0].0 = units("Unselected");
    let mut unexpected_entry = catalog.clone();
    let list = &mut unexpected_entry.children[0].1;
    list.children[0].0 = units("NotAnIndex");
    list.header.enumeration.as_mut().unwrap()[0].name = units("NotAnIndex");
    list.children[0].1.header.canonical =
        units(&format!(r"{}\Catalog_Entries64\NotAnIndex", subject.path()));
    let mut unexpected_value = catalog.clone();
    unexpected_value.children[0].1.children[0].1.header.values[1].kind = 1;
    let mut bad_count = catalog;
    bad_count.header.values[0].data.pop();
    for invalid in [
        unexpected_list,
        unexpected_entry,
        unexpected_value,
        bad_count,
    ] {
        let error = registry
            .clone()
            .with_snapshot_selection(
                root,
                &[],
                view,
                Ok((invalid.header, Some(invalid.children))),
            )
            .err()
            .expect("unexpected catalog data was accepted");
        assert_eq!(
            error.to_string(),
            "Winsock protocol catalog contains an unexpected key or value"
        );
    }
}

#[test]
fn winsock_namespace_catalog_rejects_unselected_or_malformed_provider_values() {
    let subject = ProcessConfigKey::WinsockNamespaceCatalog;
    let registry = Registry::selected(upcase(), vec![]).unwrap();
    for (index, name, kind, data) in [
        (1, "ProviderId", 3, vec![0; 15]),
        (2, "ProviderInfo", 1, vec![]),
        (3, "PackedCatalogItem", 3, vec![42]),
        (4, "Enabled", 4, vec![1, 0, 0]),
    ] {
        let mut catalog = catalog_tree(subject.path(), namespace_values);
        catalog.children[0].1.children[0].1.header.values[index] = Value {
            name: units(name),
            kind,
            data,
        };
        let error = registry
            .clone()
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(subject),
                &[],
                RegistryView::Wow32,
                Ok((catalog.header, Some(catalog.children))),
            )
            .err()
            .expect("invalid namespace provider value was accepted");
        assert_eq!(
            error.to_string(),
            "Winsock namespace catalog contains an unexpected key or value"
        );
    }
}

#[test]
fn winsock_app_id_catalog_preserves_absence_and_rejects_a_different_physical_parent() {
    let parent = ProcessConfigKey::WinsockParameters;
    let child = ProcessConfigKey::WinsockAppIdCatalog;
    let view = RegistryView::Native64;
    let base = Registry::selected(upcase(), vec![]).unwrap();
    let registry = base
        .clone()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(child),
            &[],
            view,
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
        )
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(parent),
            &[],
            view,
            Ok((header(parent.path(), vec![]), None)),
        )
        .unwrap();
    let Lookup::Present(key) = registry.lookup_view(&units(parent.path()), view) else {
        panic!("Winsock Parameters did not resolve");
    };
    assert!(matches!(
        registry.lookup_view(&units(child.path()), view),
        Lookup::Missing
    ));
    assert!(matches!(
        key.relative(&units("AppId_Catalog")),
        Lookup::Missing
    ));
    assert!(matches!(
        key.relative(&units("Protocol_Catalog9")),
        Lookup::Unselected
    ));

    let second_control_set = child.path().replace("CurrentControlSet", "ControlSet002");
    let contradictory = base
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(child),
            &[],
            view,
            Ok((header(&second_control_set, vec![]), None)),
        )
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(parent),
            &[],
            view,
            Ok((header(parent.path(), vec![]), None)),
        );
    assert!(contradictory.is_err());
}

#[test]
fn winsock_app_id_catalog_resolves_only_proven_missing_children() {
    let subject = ProcessConfigKey::WinsockAppIdCatalog;
    let root = SnapshotRoot::ProcessConfig(subject);
    let logical = subject.path();
    let physical = logical.replace("CurrentControlSet", "ControlSet001");
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let mut header = header(&physical, vec![]);
        header.children = 1;
        header.enumeration = Some(vec![BasicChild {
            name: units("1234ABCD"),
            last_write: 1,
        }]);
        registry = registry
            .with_snapshot_selection(root, &[], view, Ok((header, None)))
            .unwrap();
        let Lookup::Present(key) = registry.lookup_view(&units(logical), view) else {
            panic!("Winsock application-ID catalog did not resolve");
        };
        assert!(key.child_metadata().is_none());
        for name in ["1234abcd", r"1234ABCD\Child"] {
            assert!(matches!(key.relative(&units(name)), Lookup::Unselected));
            for path in [logical, &physical] {
                assert!(matches!(
                    registry.lookup_view(&units(&format!(r"{path}\{name}")), view),
                    Lookup::Unselected
                ));
            }
        }
        for name in ["8765FEDC", r"8765FEDC\Child"] {
            assert!(matches!(key.relative(&units(name)), Lookup::Missing));
            for path in [logical, &physical] {
                assert!(matches!(
                    registry.lookup_view(&units(&format!(r"{path}\{name}")), view),
                    Lookup::Missing
                ));
            }
        }
    }
}

#[test]
fn process_config_machine_appcompat_flags_projects_only_native_log_flags() {
    let subject = ProcessConfigKey::MachineAppCompatFlags;
    let root = SnapshotRoot::ProcessConfig(subject);
    let path = root.path(&[]).unwrap();
    let registry = Registry::selected(upcase(), vec![]).unwrap();
    let log_flags = Value {
        name: units("LogFlags"),
        kind: 4,
        data: 0x18_u32.to_le_bytes().to_vec(),
    };
    for captured in [None, Some(log_flags.clone())] {
        let header = header(subject.path(), captured.clone().into_iter().collect());
        let selected = registry
            .clone()
            .with_snapshot_selection(root, &[], RegistryView::Native64, Ok((header, None)))
            .unwrap();
        let Lookup::Present(key) = selected.lookup(&path) else {
            panic!("machine AppCompatFlags key");
        };
        assert_eq!(key.children, 2);
        assert_eq!(key.captured_access().unwrap().grant(1), Ok(1));
        assert!(key.covers_value(&units("logflags")));
        assert_eq!(key.value(&units("LOGFLAGS")), captured.as_ref());
        assert!(!key.covers_value(&units("DisableEngine")));
        assert!(matches!(key.relative(&units("Layers")), Lookup::Unselected));
        assert!(matches!(
            selected.lookup_view(&path, RegistryView::Wow32),
            Lookup::Unselected
        ));
    }
    for (view, name) in [
        (RegistryView::Wow32, "LogFlags"),
        (RegistryView::Native64, "DisableEngine"),
    ] {
        let unselected = Value {
            name: units(name),
            ..log_flags.clone()
        };
        let header = header(subject.path(), vec![unselected]);
        assert!(
            registry
                .clone()
                .with_snapshot_selection(root, &[], view, Ok((header, None)))
                .is_err()
        );
    }
    let missing = registry
        .with_snapshot_selection(
            root,
            &[],
            RegistryView::Native64,
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
        )
        .unwrap();
    assert!(matches!(missing.lookup(&path), Lookup::Missing));
}

#[test]
fn process_config_osdata_appcompat_flags_preserves_its_own_native_open_result() {
    let subject = ProcessConfigKey::OsDataAppCompatFlags;
    let root = SnapshotRoot::ProcessConfig(subject);
    let path = root.path(&[]).unwrap();
    let registry = Registry::selected(upcase(), vec![]).unwrap();
    let software = ProcessConfigKey::MachineAppCompatFlags;
    let software_root = SnapshotRoot::ProcessConfig(software);
    let registry = registry
        .with_snapshot_selection(
            software_root,
            &[],
            RegistryView::Native64,
            Ok((header(software.path(), vec![]), None)),
        )
        .unwrap();
    let present = registry
        .clone()
        .with_snapshot_selection(
            root,
            &[],
            RegistryView::Native64,
            Ok((header(subject.path(), vec![]), None)),
        )
        .unwrap();
    let Lookup::Present(key) = present.lookup(&units(&subject.path().to_ascii_lowercase())) else {
        panic!("OSDATA AppCompatFlags header");
    };
    assert_eq!(key.children, 2);
    assert_eq!(key.captured_access().unwrap().grant(1), Ok(1));
    assert!(!key.covers_value(&units("LogFlags")));
    assert!(matches!(key.relative(&units("Layers")), Lookup::Unselected));
    assert!(matches!(
        present.lookup_view(&path, RegistryView::Wow32),
        Lookup::Unselected
    ));
    assert!(matches!(
        present.lookup(&units(&format!(r"{}Sibling", subject.path()))),
        Lookup::Unselected
    ));
    assert!(
        registry
            .clone()
            .with_snapshot_selection(
                root,
                &[],
                RegistryView::Native64,
                Ok((header(software.path(), vec![]), None)),
            )
            .is_err()
    );
    for status in [STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND] {
        let absent = registry
            .clone()
            .with_snapshot_selection(root, &[], RegistryView::Native64, Err(status))
            .unwrap();
        assert!(matches!(
            (status, absent.lookup(&path)),
            (STATUS_OBJECT_NAME_NOT_FOUND, Lookup::Missing)
                | (STATUS_OBJECT_PATH_NOT_FOUND, Lookup::MissingPath)
        ));
        assert!(matches!(
            absent.lookup(&units(software.path())),
            Lookup::Present(_)
        ));
    }
}

#[test]
fn system_setup_covers_both_startup_dwords_and_leaves_other_values_unselected() {
    let registry = Registry::selected(
        upcase(),
        vec![SelectedKey {
            path: SYSTEM_SETUP_KEY,
            children: 1,
            values: vec![Value {
                name: units("OOBEInProgress"),
                kind: 4,
                data: vec![0; 4],
            }],
        }],
    )
    .unwrap();
    let key = registry.key(&units(SYSTEM_SETUP_KEY)).unwrap();
    assert!(key.covers_value(&units("oobeinprogress")));
    assert_eq!(key.value(&units("oobeinprogress")).unwrap().kind, 4);
    assert!(key.covers_value(&units("systemsetupinprogress")));
    assert!(key.value(&units("systemsetupinprogress")).is_none());
    assert!(!key.covers_value(&units("SetupType")));
}

#[test]
fn process_config_rejects_data_outside_the_fixed_projection() {
    let root = ProcessConfigKey::Ccg;
    let value = Value {
        name: units("UnselectedValue"),
        kind: 4,
        data: vec![0; 4],
    };
    let registry = Registry::selected(upcase(), vec![]).unwrap();
    assert!(
        registry
            .clone()
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(root),
                &[],
                RegistryView::Native64,
                Ok((header(root.path(), vec![value]), None)),
            )
            .is_err()
    );
    assert!(
        registry
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(root),
                &[],
                RegistryView::Native64,
                Ok((header(root.path(), vec![]), Some(vec![]))),
            )
            .is_err()
    );
}

#[test]
fn tcpip_parameters_shares_selected_dns_identity_in_both_views() {
    let subject = ProcessConfigKey::TcpipParameters;
    let root = SnapshotRoot::ProcessConfig(subject);
    let canonical = subject.path().replace("CurrentControlSet", "ControlSet001");
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        registry = registry
            .with_snapshot_selection(root, &[], view, Ok((header(&canonical, vec![]), None)))
            .unwrap();
    }
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        for path in [root.path(&[]).unwrap(), units(&canonical)] {
            let Lookup::Present(key) = registry.lookup_view(&path, view) else {
                panic!("TCP/IP parameters not shared into {view:?}");
            };
            assert!(key.covers_value(&units("hostname")));
            assert!(key.covers_value(&units("nv hostname")));
            assert!(key.covers_value(&units("domain")));
            assert!(key.covers_value(&units("nv domain")));
            assert!(!key.covers_value(&units("UnselectedValue")));
        }
    }
}

#[test]
fn dns_client_startup_keys_preserve_open_metadata() {
    for subject in [
        ProcessConfigKey::DnsClientParameters,
        ProcessConfigKey::DnsClientPolicy,
        ProcessConfigKey::DnsClientSystemPolicy,
    ] {
        let root = SnapshotRoot::ProcessConfig(subject);
        let canonical = subject.path().replace("CurrentControlSet", "ControlSet001");
        let mut registry = Registry::selected(upcase(), vec![]).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            registry = registry
                .with_snapshot_selection(root, &[], view, Ok((header(&canonical, vec![]), None)))
                .unwrap();
        }
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            for path in [root.path(&[]).unwrap(), units(&canonical)] {
                let Lookup::Present(key) = registry.lookup_view(&path, view) else {
                    panic!("{subject:?} missing in {view:?}");
                };
                let grant = key.captured_access().unwrap();
                assert_eq!(grant.grant(0x20019), Ok(0x20019));
                assert_eq!(grant.grant(2), Err(STATUS_ACCESS_DENIED));
                assert!(!key.covers_value(&units("UnselectedValue")));
                assert!(key.ordered_values().is_none());
                assert!(key.child_metadata().is_none());
            }
        }
    }
}

#[test]
fn dns_client_policy_captures_primary_domain_name_and_preserves_absence() {
    let subject = ProcessConfigKey::DnsClientPolicy;
    let root = SnapshotRoot::ProcessConfig(subject);
    let value = Value {
        name: units("PrimaryDomainName"),
        kind: 1,
        data: "example.test\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    for values in [vec![], vec![value.clone()]] {
        let mut registry = Registry::selected(upcase(), vec![]).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            registry = registry
                .with_snapshot_selection(
                    root,
                    &[],
                    view,
                    Ok((header(subject.path(), values.clone()), None)),
                )
                .unwrap();
        }
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let Lookup::Present(key) = registry.lookup_view(&units(subject.path()), view) else {
                panic!("DNS Client policy missing in {view:?}");
            };
            let name = units("primarydomainname");
            assert!(key.covers_value(&name));
            assert_eq!(key.value(&name), values.first());
            assert!(!key.covers_value(&units("UnselectedValue")));
        }
    }
}

#[test]
fn dns_client_system_policy_preserves_native_absence_class() {
    let root = SnapshotRoot::ProcessConfig(ProcessConfigKey::DnsClientSystemPolicy);
    let path = root.path(&[]).unwrap();
    for status in [STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND] {
        let mut registry = Registry::selected(upcase(), vec![]).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            registry = registry
                .with_snapshot_selection(root, &[], view, Err(status))
                .unwrap();
        }
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            match (status, registry.lookup_view(&path, view)) {
                (STATUS_OBJECT_NAME_NOT_FOUND, Lookup::Missing)
                | (STATUS_OBJECT_PATH_NOT_FOUND, Lookup::MissingPath) => {}
                _ => panic!("wrong DNS Client system policy lookup for {status:#x} in {view:?}"),
            }
        }
    }
}

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
fn winsock_parameters_exposes_only_the_two_catalog_selectors_in_both_views() {
    let subject = ProcessConfigKey::WinsockParameters;
    let root = SnapshotRoot::ProcessConfig(subject);
    let native_path = subject.path().replace("CurrentControlSet", "ControlSet001");
    let registry = Registry::selected(upcase(), vec![]).unwrap();
    let catalog_value = |name: &str, catalog: &str| Value {
        name: units(name),
        kind: 1,
        data: catalog
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    let selectors = vec![
        catalog_value("Current_NameSpace_Catalog", "NameSpace_Catalog5"),
        catalog_value("Current_Protocol_Catalog", "Protocol_Catalog9"),
    ];
    let mut captured = registry.clone();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        captured = captured
            .with_snapshot_selection(
                root,
                &[],
                view,
                Ok((header(&native_path, selectors.clone()), None)),
            )
            .unwrap();
        for path in [subject.path(), &native_path] {
            let Lookup::Present(key) = captured.lookup_view(&units(path), view) else {
                panic!("Winsock catalog selection did not resolve");
            };
            for expected in &selectors {
                assert!(key.covers_value(&expected.name));
                assert_eq!(key.value(&expected.name), Some(expected));
            }
            assert!(!key.covers_value(&units("AutodialDllName")));
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

    let unrelated = catalog_value("AutodialDllName", "unselected.dll");
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

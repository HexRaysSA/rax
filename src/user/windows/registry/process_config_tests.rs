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
fn fusion_key_preserves_the_machine_view_and_admits_only_selected_absent_values() {
    let subject = ProcessConfigKey::DotNetFusion;
    let snapshot = SnapshotRoot::ProcessConfig(subject);
    let native = header(subject.path(), vec![]);
    let mut wow = header(DOT_NET_FUSION_WOW_KEY, vec![]);
    wow.children = 1;
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_snapshot_selection(snapshot, &[], RegistryView::Native64, Ok((native, None)))
        .unwrap()
        .with_snapshot_selection(snapshot, &[], RegistryView::Wow32, Ok((wow, None)))
        .unwrap()
        .with_machine_hive(MachineHeader {
            canonical: units(MACHINE_HIVE_KEY),
            enumeration: None,
            children: 6,
            values: vec![],
            access: header(MACHINE_HIVE_KEY, vec![]).access,
        })
        .unwrap();
    let machine = registry.key(&units(MACHINE_HIVE_KEY)).unwrap();
    for (view, canonical, children) in [
        (RegistryView::Native64, subject.path(), 2),
        (RegistryView::Wow32, DOT_NET_FUSION_WOW_KEY, 1),
    ] {
        let Lookup::Present(key) =
            machine.relative_in_view(&units(r"SOFTWARE\Microsoft\Fusion"), view)
        else {
            panic!("machine-relative Fusion key must resolve in {view:?}");
        };
        let Lookup::Present(absolute) = registry.lookup_view(&units(subject.path()), view) else {
            panic!("absolute Fusion key must resolve in {view:?}");
        };
        assert!(Arc::ptr_eq(&key, &absolute));
        assert_eq!(key.path, units(canonical));
        assert_eq!(key.children, children);
        for name in [
            DOT_NET_FUSION_OPTIONAL_POLICY,
            DOT_NET_FUSION_CACHE_LOCATION,
            DOT_NET_FUSION_CACHE_QUOTA,
            DOT_NET_FUSION_ENABLE_LOG,
            DOT_NET_FUSION_LOGGING_LEVEL,
            DOT_NET_FUSION_FORCE_LOG,
        ] {
            let name = units(name);
            assert!(key.covers_value(&name));
            assert!(key.value(&name).is_none());
        }
        assert!(!key.covers_value(&units("Unselected")));
        assert!(matches!(
            key.relative(&units("Unselected")),
            Lookup::Unselected
        ));
    }
    let Lookup::Present(physical) =
        registry.lookup_view(&units(DOT_NET_FUSION_WOW_KEY), RegistryView::Native64)
    else {
        panic!("physical Fusion name must select the WoW view");
    };
    assert_eq!(physical.children, 1);
}

#[test]
fn fusion_snapshot_rejects_installed_setting_payloads() {
    let subject = ProcessConfigKey::DotNetFusion;
    for (path, view) in [
        (subject.path(), RegistryView::Native64),
        (DOT_NET_FUSION_WOW_KEY, RegistryView::Wow32),
    ] {
        for (name, kind, data) in [
            (DOT_NET_FUSION_OPTIONAL_POLICY, 4, vec![0; 4]),
            (DOT_NET_FUSION_CACHE_LOCATION, 1, vec![67, 0, 58, 0, 0, 0]),
            (
                DOT_NET_FUSION_CACHE_QUOTA,
                4,
                8192u32.to_le_bytes().to_vec(),
            ),
            (DOT_NET_FUSION_ENABLE_LOG, 4, vec![0; 4]),
            (DOT_NET_FUSION_LOGGING_LEVEL, 4, 2u32.to_le_bytes().to_vec()),
            (DOT_NET_FUSION_FORCE_LOG, 4, 1u32.to_le_bytes().to_vec()),
        ] {
            let configured = Value {
                name: units(name),
                kind,
                data,
            };
            let result = Registry::selected(upcase(), vec![])
                .unwrap()
                .with_snapshot_selection(
                    SnapshotRoot::ProcessConfig(subject),
                    &[],
                    view,
                    Ok((header(path, vec![configured]), None)),
                );
            assert!(result.is_err(), "{name}/{view:?}");
        }
    }
}

#[test]
fn dot_net_v4_full_projects_install_release_and_version_in_each_machine_view() {
    let subject = ProcessConfigKey::DotNetV4Full;
    let snapshot = SnapshotRoot::ProcessConfig(subject);
    let values = |release: u32| {
        vec![
            Value {
                name: units("Release"),
                kind: 4,
                data: release.to_le_bytes().to_vec(),
            },
            Value {
                name: units("Version"),
                kind: 1,
                data: units("4.8.10004\0")
                    .into_iter()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            },
        ]
    };
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_snapshot_selection(
            snapshot,
            &[],
            RegistryView::Native64,
            Ok((header(subject.path(), values(534292)), None)),
        )
        .unwrap()
        .with_snapshot_selection(
            snapshot,
            &[],
            RegistryView::Wow32,
            Ok((header(DOT_NET_V4_FULL_WOW_KEY, values(533325)), None)),
        )
        .unwrap()
        .with_machine_hive(MachineHeader {
            canonical: units(MACHINE_HIVE_KEY),
            enumeration: None,
            children: 6,
            values: vec![],
            access: header(MACHINE_HIVE_KEY, vec![]).access,
        })
        .unwrap();
    let machine = registry.key(&units(MACHINE_HIVE_KEY)).unwrap();
    for (relative, view, release) in [
        (
            r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
            RegistryView::Native64,
            534292,
        ),
        (
            r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
            RegistryView::Wow32,
            533325,
        ),
        (
            r"SOFTWARE\WOW6432Node\Microsoft\NET Framework Setup\NDP\v4\Full",
            RegistryView::Native64,
            533325,
        ),
    ] {
        let Lookup::Present(key) = machine.relative_in_view(&units(relative), view) else {
            panic!("machine-relative .NET v4 Full key must resolve in {view:?}");
        };
        let records = values(release);
        assert_eq!(key.value(&units("release")), Some(&records[0]));
        assert_eq!(key.value(&units("VERSION")), Some(&records[1]));
        assert!(key.covers_value(&units("Install")));
        assert!(key.value(&units("Install")).is_none());
        assert!(!key.covers_value(&units("Unselected")));
        assert!(matches!(key.relative(&units("1033")), Lookup::Unselected));
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
fn minint_startup_lookup_preserves_open_result_in_both_views() {
    let subject = ProcessConfigKey::MiniNt;
    let root = SnapshotRoot::ProcessConfig(subject);
    let active_path = r"\Registry\Machine\System\ControlSet001\Control\MiniNT";
    assert!(ProcessConfigKey::ALL.contains(&subject));
    let views = [RegistryView::Native64, RegistryView::Wow32];
    let mut missing = Registry::selected(upcase(), vec![]).unwrap();
    let mut present = Registry::selected(upcase(), vec![]).unwrap();
    for view in views {
        missing = missing
            .with_snapshot_selection(root, &[], view, Err(STATUS_OBJECT_NAME_NOT_FOUND))
            .unwrap();
        present = present
            .with_snapshot_selection(root, &[], view, Ok((header(active_path, vec![]), None)))
            .unwrap();
    }
    for view in views {
        assert!(matches!(
            missing.lookup_view(&units(subject.path()), view),
            Lookup::Missing
        ));
        for path in [subject.path(), active_path] {
            let Lookup::Present(key) = present.lookup_view(&units(path), view) else {
                panic!("captured MiniNT key not routed");
            };
            assert_eq!(key.path, units(active_path));
            assert_eq!(key.captured_access().unwrap().grant(0x20019), Ok(0x20019));
            assert!(!key.covers_value(&units("UnselectedValue")));
        }
        let neighbor = r"\Registry\Machine\System\CurrentControlSet\Control\OtherKey";
        assert!(matches!(
            missing.lookup_view(&units(neighbor), view),
            Lookup::Unselected
        ));
        let child = format!(r"{active_path}\UnselectedChild");
        assert!(matches!(
            present.lookup_view(&units(&child), view),
            Lookup::Unselected
        ));
    }
}

#[test]
fn dot_net_policy_lookup_preserves_canonical_identity_in_both_views() {
    let subject = ProcessConfigKey::DotNetPolicy;
    assert!(ProcessConfigKey::ALL.contains(&subject));
    let root = SnapshotRoot::ProcessConfig(subject);
    let native_name = r"\Registry\Machine\Software\Microsoft\.NETFramework\policy";
    let names = [
        (RegistryView::Native64, native_name),
        (RegistryView::Wow32, DOT_NET_POLICY_WOW_KEY),
    ];
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for (view, canonical) in names {
        registry = registry
            .with_snapshot_selection(root, &[], view, Ok((header(canonical, vec![]), None)))
            .unwrap();
    }
    registry = registry
        .with_machine_hive(MachineHeader {
            canonical: units(MACHINE_HIVE_KEY),
            enumeration: None,
            children: 6,
            values: vec![],
            access: header(MACHINE_HIVE_KEY, vec![]).access,
        })
        .unwrap();
    let machine = registry.key(&units(MACHINE_HIVE_KEY)).unwrap();
    for (view, canonical) in names {
        for tail in ["", "\\"] {
            let absolute = units(&format!("{}{tail}", subject.path()));
            let relative = units(&format!(r"Software\Microsoft\.NETFramework\Policy{tail}"));
            let Lookup::Present(opened) = machine.relative_in_view(&relative, view) else {
                panic!("machine-relative .NET Framework policy key not routed");
            };
            let Lookup::Present(absolute) = registry.lookup_view(&absolute, view) else {
                panic!("absolute .NET Framework policy key not routed");
            };
            assert!(Arc::ptr_eq(&opened, &absolute));
            assert_eq!(opened.path, units(canonical));
            assert_eq!(
                opened.captured_access().unwrap().grant(0x20019),
                Ok(0x20019)
            );
            assert!(!opened.covers_value(&units("UnselectedValue")));
        }
        let child = format!(r"{}\UnselectedChild", subject.path());
        assert!(matches!(
            registry.lookup_view(&units(&child), view),
            Lookup::Unselected
        ));
    }
    assert!(
        subject
            .check_name(
                &registry,
                RegistryView::Native64,
                &units(DOT_NET_POLICY_WOW_KEY)
            )
            .is_err()
    );
}

#[test]
fn dot_net_install_root_preserves_complete_native_order_per_view() {
    let subject = ProcessConfigKey::DotNetFramework;
    let values = |names: &[&str]| {
        names
            .iter()
            .map(|name| Value {
                name: units(name),
                kind: 4,
                data: 1_u32.to_le_bytes().to_vec(),
            })
            .collect::<Vec<_>>()
    };
    let native = values(&["UseRyuJIT", "Enable64Bit", "Fod"]);
    let wow = values(&["Fod", "InstallRoot"]);
    let selected = || Registry::selected(upcase(), vec![]).unwrap();
    for (view, name, ordered) in [
        (RegistryView::Native64, subject.path(), native),
        (RegistryView::Wow32, DOT_NET_FRAMEWORK_WOW_KEY, wow),
    ] {
        let header = header(name, ordered.clone());
        let mut cached = [0u8; 40];
        cached[12..16].copy_from_slice(&header.children.to_le_bytes());
        cached[20..24].copy_from_slice(&(ordered.len() as u32).to_le_bytes());
        cached[32..36].copy_from_slice(&(units(".NETFramework").len() as u32 * 2).to_le_bytes());
        let complete = selected()
            .with_cached_process_config(subject, view, header.clone(), cached)
            .unwrap();
        let lookup = |registry: &Registry| {
            let Lookup::Present(key) = registry.lookup_view(&units(subject.path()), view) else {
                panic!("fixed CLR root did not resolve");
            };
            key
        };
        let key = lookup(&complete);
        assert_eq!(key.ordered_values(), Some(ordered.as_slice()));
        for setting in ["USEryuJit", "enable64BIT"] {
            assert!(key.covers_value(&units(setting)));
        }

        cached[20..24].copy_from_slice(&(ordered.len() as u32 + 1).to_le_bytes());
        let incomplete = selected()
            .with_cached_process_config(subject, view, header, cached)
            .unwrap();
        let key = lookup(&incomplete);
        assert!(key.ordered_values().is_none());
        for setting in &ordered {
            assert_eq!(key.value(&setting.name), Some(setting));
        }
    }
}

#[test]
fn dot_net_policy_preserves_ordered_metadata_without_opening_children() {
    let subject = ProcessConfigKey::DotNetPolicy;
    assert!(subject.captures_child_membership());
    let selection = units(subject.path());
    let mut header = header(subject.path(), vec![]);
    let native_children = vec![
        BasicChild {
            name: units("v4.0"),
            last_write: 42,
        },
        BasicChild {
            name: units("AppPatch"),
            last_write: 91,
        },
    ];
    header.enumeration = Some(native_children.clone());
    let mut native = [0u8; 40];
    native[..8].copy_from_slice(&0x01dd71d91fbe51ac_u64.to_le_bytes());
    native[12..16].copy_from_slice(&header.children.to_le_bytes());
    native[16..20].copy_from_slice(&18u32.to_le_bytes());
    native[32..36].copy_from_slice(&12u32.to_le_bytes());
    let selected = || Registry::selected(upcase(), vec![]).unwrap();
    let registry = selected()
        .with_cached_process_config(subject, RegistryView::Native64, header.clone(), native)
        .unwrap();
    let mut different = native;
    different[0] ^= 1;
    assert!(
        registry
            .clone()
            .with_cached_process_config(subject, RegistryView::Wow32, header.clone(), different)
            .is_err()
    );
    let shared = registry
        .clone()
        .with_cached_process_config(subject, RegistryView::Wow32, header.clone(), native)
        .unwrap();
    let mut wow_header = header.clone();
    wow_header.canonical = units(DOT_NET_POLICY_WOW_KEY);
    let wow_children = vec![native_children[1].clone()];
    wow_header.children = wow_children.len() as u32;
    wow_header.enumeration = Some(wow_children.clone());
    different[12..16].copy_from_slice(&wow_header.children.to_le_bytes());
    let registry = registry
        .with_cached_process_config(subject, RegistryView::Wow32, wow_header, different)
        .unwrap();
    for (view, expected, canonical, children) in [
        (
            RegistryView::Native64,
            native,
            subject.path(),
            native_children,
        ),
        (
            RegistryView::Wow32,
            different,
            DOT_NET_POLICY_WOW_KEY,
            wow_children,
        ),
    ] {
        let Lookup::Present(shared_key) = shared.lookup_view(&selection, view) else {
            panic!("shared .NET Framework policy record did not resolve");
        };
        assert_eq!(
            shared_key.information().unwrap().record(4),
            Some(native.as_slice())
        );
        let Lookup::Present(key) = registry.lookup_view(&selection, view) else {
            panic!("cached .NET Framework policy record did not resolve");
        };
        let info = key.information().expect("captured key information");
        assert_eq!(info.record(4), Some(expected.as_slice()));
        assert_eq!(info.canonical(), units(canonical));
        for class in [0, 1, 2, 5, 6, 7, 8] {
            assert!(info.record(class).is_none());
        }
        assert_eq!(key.child_metadata(), Some(children.as_slice()));
        for child in &children {
            assert!(matches!(key.relative(&child.name), Lookup::Unselected));
            let absolute = format!(
                r"{}\{}",
                subject.path(),
                String::from_utf16_lossy(&child.name)
            );
            assert!(matches!(
                registry.lookup_view(&units(&absolute), view),
                Lookup::Unselected
            ));
        }
        assert!(matches!(
            key.relative(&units("UnselectedChild")),
            Lookup::Unselected
        ));
    }

    let mut wrong_count = native;
    wrong_count[12] ^= 1;
    assert!(
        selected()
            .with_cached_process_config(
                subject,
                RegistryView::Native64,
                header.clone(),
                wrong_count
            )
            .is_err()
    );
    let mut wrong_name = native;
    wrong_name[32] ^= 2;
    assert!(
        selected()
            .with_cached_process_config(subject, RegistryView::Native64, header, wrong_name)
            .is_err()
    );
}

#[test]
fn dot_net_v4_policy_child_has_the_same_record_in_relative_and_absolute_opens() {
    let parent = ProcessConfigKey::DotNetPolicy;
    let child = ProcessConfigKey::DotNetPolicyV4;
    let build = units("30319");
    let captured = |range: &str| Value {
        name: build.clone(),
        kind: 1,
        data: range
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    let cached = |stamp: u64| {
        let mut record = [0_u8; 40];
        record[..8].copy_from_slice(&stamp.to_le_bytes());
        record[20..24].copy_from_slice(&1_u32.to_le_bytes());
        record[24..28].copy_from_slice(&10_u32.to_le_bytes());
        record[28..32].copy_from_slice(&24_u32.to_le_bytes());
        record[32..36].copy_from_slice(&8_u32.to_le_bytes());
        record
    };
    let views = [
        (
            RegistryView::Native64,
            parent.path(),
            child.path(),
            "30319-30319",
            cached(42),
        ),
        (
            RegistryView::Wow32,
            DOT_NET_POLICY_WOW_KEY,
            DOT_NET_POLICY_V4_WOW_KEY,
            "30319-42000",
            cached(91),
        ),
    ];
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for (view, parent_path, child_path, range, record) in views {
        let mut leaf = header(child_path, vec![captured(range)]);
        leaf.children = 0;
        let mut incomplete = record;
        incomplete[20..24].copy_from_slice(&2_u32.to_le_bytes());
        let partial_snapshot = registry
            .clone()
            .with_cached_process_config(child, view, leaf.clone(), incomplete)
            .unwrap();
        let Lookup::Present(partial) = partial_snapshot.lookup_view(&units(child.path()), view)
        else {
            panic!("partial build policy projection did not resolve");
        };
        assert_eq!(partial.value(&build), Some(&captured(range)));
        assert!(partial.ordered_values().is_none());
        registry = registry
            .with_cached_process_config(child, view, leaf, record)
            .unwrap();
        let mut parent_header = header(parent_path, vec![]);
        parent_header.enumeration = Some(vec![
            BasicChild {
                name: units("AppPatch"),
                last_write: 91,
            },
            BasicChild {
                name: units("v4.0"),
                last_write: 42,
            },
        ]);
        registry = registry
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(parent),
                &[],
                view,
                Ok((parent_header, None)),
            )
            .unwrap();
    }

    for (view, _, child_path, range, record) in views {
        let Lookup::Present(parent) = registry.lookup_view(&units(parent.path()), view) else {
            panic!("policy parent not captured");
        };
        let Lookup::Present(relative) = parent.relative(&units("V4.0")) else {
            panic!("fixed version child did not resolve relative to its policy handle");
        };
        let Lookup::Present(absolute) = registry.lookup_view(&units(child.path()), view) else {
            panic!("fixed version child did not resolve by logical path");
        };
        let Lookup::Present(physical) =
            registry.lookup_view(&units(child_path), RegistryView::Native64)
        else {
            panic!("fixed version child did not resolve by physical path");
        };
        assert!(Arc::ptr_eq(&relative, &absolute));
        assert!(Arc::ptr_eq(&relative, &physical));
        assert_eq!(relative.value(&build), Some(&captured(range)));
        assert_eq!(
            relative.ordered_values(),
            Some([captured(range)].as_slice())
        );
        assert_eq!(
            relative.information().unwrap().record(4),
            Some(record.as_slice())
        );
        assert!(!relative.covers_value(&units("UnselectedValue")));
        assert!(matches!(
            parent.relative(&units("AppPatch")),
            Lookup::Unselected
        ));
        assert!(matches!(
            relative.relative(&units("UnselectedChild")),
            Lookup::Missing
        ));
    }
}

#[test]
fn dot_net_standards_links_fixed_children_and_their_value_ordinals() {
    let policy = ProcessConfigKey::DotNetPolicy;
    let standards = ProcessConfigKey::DotNetPolicyStandards;
    let children = [
        (ProcessConfigKey::DotNetStandardCli2002, "Standard CLI 2002"),
        (ProcessConfigKey::DotNetStandardCli2005, "Standard CLI 2005"),
        (ProcessConfigKey::DotNetStandardV1, "v1.0.0"),
    ];
    let value_name = units("v4.0.30319");
    let canonical = |subject: ProcessConfigKey, view| {
        if view == RegistryView::Wow32 {
            subject.path().replacen(
                ProcessConfigKey::DotNetFramework.path(),
                DOT_NET_FRAMEWORK_WOW_KEY,
                1,
            )
        } else {
            subject.path().into()
        }
    };
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for (view, view_data) in [(RegistryView::Native64, 64_u32), (RegistryView::Wow32, 32)] {
        for (subject, name) in children {
            let value = Value {
                name: value_name.clone(),
                kind: 4,
                data: view_data.to_le_bytes().to_vec(),
            };
            let mut selected = header(&canonical(subject, view), vec![value]);
            selected.children = 0;
            let mut cached = [0_u8; 40];
            cached[20..24].copy_from_slice(&1_u32.to_le_bytes());
            cached[24..28].copy_from_slice(&(value_name.len() as u32 * 2).to_le_bytes());
            cached[28..32].copy_from_slice(&4_u32.to_le_bytes());
            cached[32..36].copy_from_slice(&(units(name).len() as u32 * 2).to_le_bytes());
            registry = registry
                .with_cached_process_config(subject, view, selected, cached)
                .unwrap();
        }
        let entries: Vec<_> = children
            .iter()
            .enumerate()
            .map(|(index, (_, name))| BasicChild {
                name: units(name),
                last_write: index as u64,
            })
            .collect();
        let mut selected = header(&canonical(standards, view), vec![]);
        selected.children = entries.len() as u32;
        selected.enumeration = Some(entries.clone());
        let mut cached = [0_u8; 40];
        cached[12..16].copy_from_slice(&selected.children.to_le_bytes());
        cached[32..36].copy_from_slice(&18_u32.to_le_bytes());
        registry = registry
            .with_cached_process_config(standards, view, selected, cached)
            .unwrap()
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(policy),
                &[],
                view,
                Ok((header(&canonical(policy, view), vec![]), None)),
            )
            .unwrap();
        let Lookup::Present(policy_key) = registry.lookup_view(&units(policy.path()), view) else {
            panic!("fixed CLR policy key did not resolve");
        };
        let Lookup::Present(standards_key) = policy_key.relative(&units("STANDARDS")) else {
            panic!("fixed CLR standards parent did not resolve");
        };
        assert_eq!(standards_key.child_metadata(), Some(entries.as_slice()));
        assert_eq!(standards_key.ordered_values(), Some([].as_slice()));
        for (subject, name) in children {
            let nested_name = units(&format!(r"standards\{name}"));
            let Lookup::Present(relative) = policy_key.relative(&nested_name) else {
                panic!("fixed CLR standard did not resolve through its policy handle");
            };
            let Lookup::Present(absolute) = registry.lookup_view(&units(subject.path()), view)
            else {
                panic!("fixed CLR standard did not resolve through its absolute name");
            };
            assert!(Arc::ptr_eq(&relative, &absolute));
            let value = relative.value(&value_name).expect("selected CLR version");
            assert_eq!(value.data, view_data.to_le_bytes());
            assert_eq!(relative.ordered_values(), Some(std::slice::from_ref(value)));
            assert!(!relative.covers_value(&units("private")));
        }
        assert!(matches!(
            standards_key.relative(&units("Unselected")),
            Lookup::Unselected
        ));
    }
}

#[test]
fn dot_net_upgrades_retains_the_selected_build_range() {
    let policy = ProcessConfigKey::DotNetPolicy;
    let upgrades = ProcessConfigKey::DotNetPolicyUpgrades;
    let range = Value {
        name: units("4.0.30319"),
        kind: 1,
        data: "4.0.0-4.0.30319"
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    let mut child = header(upgrades.path(), vec![range.clone()]);
    child.children = 0;
    let mut cached = [0_u8; 40];
    cached[20..24].copy_from_slice(&1_u32.to_le_bytes());
    cached[24..28].copy_from_slice(&(range.name.len() as u32 * 2).to_le_bytes());
    cached[28..32].copy_from_slice(&(range.data.len() as u32).to_le_bytes());
    cached[32..36].copy_from_slice(&16_u32.to_le_bytes());

    let view = RegistryView::Native64;
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_cached_process_config(upgrades, view, child, cached)
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(policy),
            &[],
            view,
            Ok((header(policy.path(), vec![]), None)),
        )
        .unwrap();
    let Lookup::Present(parent) = registry.lookup_view(&units(policy.path()), view) else {
        panic!("fixed CLR policy key did not resolve");
    };
    let Lookup::Present(key) = parent.relative(&units("UPGRADES")) else {
        panic!("fixed CLR upgrade policy did not resolve");
    };
    assert_eq!(
        key.information().unwrap().record(4),
        Some(cached.as_slice())
    );
    assert_eq!(key.value(&range.name), Some(&range));
    assert_eq!(key.ordered_values(), Some([range].as_slice()));
    assert!(!key.covers_value(&units("30319")));
}

#[test]
fn dot_net_servicing_keeps_installed_membership_and_missing_view() {
    let policy = ProcessConfigKey::DotNetPolicy;
    let servicing = ProcessConfigKey::DotNetPolicyServicing;
    let assembly = BasicChild {
        name: units("Example.Assembly, Culture=neutral"),
        last_write: 83,
    };
    let mut native = header(servicing.path(), vec![]);
    native.children = 1;
    native.enumeration = Some(vec![assembly.clone()]);
    let mut cached = [0_u8; 40];
    cached[12..16].copy_from_slice(&native.children.to_le_bytes());
    cached[16..20].copy_from_slice(&(assembly.name.len() as u32 * 2).to_le_bytes());
    cached[32..36].copy_from_slice(&18_u32.to_le_bytes());
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_cached_process_config(servicing, RegistryView::Native64, native, cached)
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(servicing),
            &[],
            RegistryView::Wow32,
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
        )
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(policy),
            &[],
            RegistryView::Native64,
            Ok((header(policy.path(), vec![]), None)),
        )
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(policy),
            &[],
            RegistryView::Wow32,
            Ok((header(DOT_NET_POLICY_WOW_KEY, vec![]), None)),
        )
        .unwrap();
    let name = units("Servicing");
    let path = units(servicing.path());
    let Lookup::Present(parent) =
        registry.lookup_view(&units(policy.path()), RegistryView::Native64)
    else {
        panic!("native CLR policy key did not resolve");
    };
    let Lookup::Present(relative) = parent.relative(&name) else {
        panic!("fixed CLR servicing key did not resolve");
    };
    let Lookup::Present(absolute) = registry.lookup_view(&path, RegistryView::Native64) else {
        panic!("servicing key did not resolve through its absolute name");
    };
    assert!(Arc::ptr_eq(&relative, &absolute));
    assert_eq!(
        relative.child_metadata(),
        Some([assembly.clone()].as_slice())
    );
    assert_eq!(relative.ordered_values(), Some([].as_slice()));
    assert!(matches!(
        relative.relative(&assembly.name),
        Lookup::Unselected
    ));
    let Lookup::Present(parent) = registry.lookup_view(&units(policy.path()), RegistryView::Wow32)
    else {
        panic!("WoW64 CLR policy key did not resolve");
    };
    assert!(matches!(parent.relative(&name), Lookup::Missing));
    assert!(matches!(
        registry.lookup_view(&path, RegistryView::Wow32),
        Lookup::Missing
    ));
}

#[test]
fn dot_net_app_patch_keeps_complete_version_routes_and_value_order() {
    let policy = ProcessConfigKey::DotNetPolicy;
    let app_patch = ProcessConfigKey::DotNetPolicyAppPatch;
    let version = "v4.0.30319.00000";
    let version_path = format!(r"{}\{version}", app_patch.path());
    let values = vec![
        Value {
            name: units("Target Version"),
            kind: 1,
            data: units("v4.0\0")
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect(),
        },
        Value {
            name: units("Other Rule"),
            kind: 4,
            data: 1_u32.to_le_bytes().to_vec(),
        },
    ];
    let mut leaf = header(&version_path, values.clone());
    leaf.children = 0;
    leaf.enumeration = Some(vec![]);
    let mut root = header(app_patch.path(), vec![]);
    root.children = 1;
    root.enumeration = Some(vec![BasicChild {
        name: units(version),
        last_write: 19,
    }]);
    let version_tree = CommandTree {
        header: leaf,
        children: vec![],
    };
    let view = RegistryView::Native64;
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(app_patch),
            &[],
            view,
            Ok((root, Some(vec![(units(version), version_tree)]))),
        )
        .unwrap()
        .with_snapshot_selection(
            SnapshotRoot::ProcessConfig(policy),
            &[],
            view,
            Ok((header(policy.path(), vec![]), None)),
        )
        .unwrap();
    let Lookup::Present(parent) = registry.lookup_view(&units(policy.path()), view) else {
        panic!("CLR policy key did not resolve");
    };
    let Lookup::Present(relative) = parent.relative(&units(&format!(r"AppPatch\{version}"))) else {
        panic!("captured compatibility policy version did not resolve from its policy handle");
    };
    let Lookup::Present(absolute) = registry.lookup_view(&units(&version_path), view) else {
        panic!("captured compatibility policy version did not resolve by its absolute name");
    };
    assert!(Arc::ptr_eq(&relative, &absolute));
    assert_eq!(relative.ordered_values(), Some(values.as_slice()));
    assert!(relative.covers_value(&units("Missing Rule")));
    assert!(matches!(
        parent.relative(&units(r"AppPatch\UnknownVersion")),
        Lookup::Missing
    ));
    assert!(matches!(
        parent.relative(&units("OutsideSelection")),
        Lookup::Unselected
    ));
}

#[test]
fn dot_net_install_root_and_policy_link_follow_the_machine_view() {
    let framework = ProcessConfigKey::DotNetFramework;
    let policy = ProcessConfigKey::DotNetPolicy;
    let views = [
        (
            RegistryView::Native64,
            framework.path(),
            policy.path(),
            r"C:\Windows\Microsoft.NET\Framework64\",
        ),
        (
            RegistryView::Wow32,
            DOT_NET_FRAMEWORK_WOW_KEY,
            DOT_NET_POLICY_WOW_KEY,
            r"C:\Windows\Microsoft.NET\Framework\",
        ),
    ];
    let installation_value = |name: &str, path: &str| Value {
        name: units(name),
        kind: 1,
        data: path
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    let arm64_value = installation_value(
        "InstallRootARM64",
        r"C:\Windows\Microsoft.NET\FrameworkArm64\",
    );
    let load_log = installation_value("CLRLoadLogDir", r"C:\Logs\CLR");
    let prefer_latest = Value {
        name: units("OnlyUseLatestCLR"),
        kind: 4,
        data: 1u32.to_le_bytes().into(),
    };
    let legacy_activation = Value {
        name: units("UseLegacyV2RuntimeActivationPolicyDefaultValue"),
        kind: 4,
        data: 1u32.to_le_bytes().into(),
    };
    let error_dialog = Value {
        name: units("ErrorDialog"),
        kind: 4,
        data: 0u32.to_le_bytes().into(),
    };
    let fod = |bits: u32| Value {
        name: units("Fod"),
        kind: 4,
        data: bits.to_le_bytes().into(),
    };
    let fod_conservative = Value {
        name: units("FodConservativeMode"),
        kind: 4,
        data: 1u32.to_le_bytes().into(),
    };
    let disable_config_cache = Value {
        name: units("DisableConfigCache"),
        kind: 4,
        data: 1u32.to_le_bytes().into(),
    };
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for (view, framework_name, policy_name, path) in views {
        let mut values = vec![
            installation_value("InstallRoot", path),
            fod(u32::from(view == RegistryView::Wow32)),
        ];
        if view == RegistryView::Native64 {
            values.push(arm64_value.clone());
            values.push(prefer_latest.clone());
            values.push(legacy_activation.clone());
            values.push(fod_conservative.clone());
            values.push(disable_config_cache.clone());
        } else {
            values.push(load_log.clone());
            values.push(error_dialog.clone());
        }
        registry = registry
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(policy),
                &[],
                view,
                Ok((header(policy_name, vec![]), None)),
            )
            .unwrap()
            .with_snapshot_selection(
                SnapshotRoot::ProcessConfig(framework),
                &[],
                view,
                Ok((header(framework_name, values), None)),
            )
            .unwrap();
    }
    let registry = registry
        .with_machine_hive(MachineHeader {
            canonical: units(MACHINE_HIVE_KEY),
            enumeration: None,
            children: 6,
            values: vec![],
            access: header(MACHINE_HIVE_KEY, vec![]).access,
        })
        .unwrap();
    let machine = registry.key(&units(MACHINE_HIVE_KEY)).unwrap();
    for (view, framework_name, policy_name, expected) in views {
        let relative_path = units(r"Software\Microsoft\.NETFramework");
        let Lookup::Present(opened) = machine.relative_in_view(&relative_path, view) else {
            panic!("machine-relative installation key did not resolve");
        };
        let Lookup::Present(absolute) = registry.lookup_view(&units(framework.path()), view) else {
            panic!("absolute installation key did not resolve");
        };
        let Lookup::Present(child) = opened.relative(&units("Policy")) else {
            panic!("fixed policy key did not resolve from the installation handle");
        };
        assert!(Arc::ptr_eq(&opened, &absolute));
        assert_eq!(opened.path, units(framework_name));
        assert_eq!(child.path, units(policy_name));
        assert_eq!(
            opened.value(&units("InstallRoot")),
            Some(&installation_value("InstallRoot", expected)),
        );
        assert!(opened.covers_value(&arm64_value.name));
        assert_eq!(
            opened.value(&arm64_value.name),
            (view == RegistryView::Native64).then_some(&arm64_value),
        );
        let load_log_name = units("clrloadlogdir");
        assert!(opened.covers_value(&load_log_name));
        assert_eq!(
            opened.value(&load_log_name),
            (view == RegistryView::Wow32).then_some(&load_log),
        );
        let prefer_latest_name = units("onlyuselatestclr");
        assert!(opened.covers_value(&prefer_latest_name));
        assert_eq!(
            opened.value(&prefer_latest_name),
            (view == RegistryView::Native64).then_some(&prefer_latest),
        );
        let legacy_activation_name = units("UseLegacyV2RuntimeActivationPolicyDefaultVALUE");
        assert!(opened.covers_value(&legacy_activation_name));
        assert_eq!(
            opened.value(&legacy_activation_name),
            (view == RegistryView::Native64).then_some(&legacy_activation),
        );
        let error_dialog_name = units("errordialog");
        assert!(opened.covers_value(&error_dialog_name));
        assert_eq!(
            opened.value(&error_dialog_name),
            (view == RegistryView::Wow32).then_some(&error_dialog),
        );
        let fod_name = units("fod");
        assert!(opened.covers_value(&fod_name));
        assert_eq!(
            opened.value(&fod_name),
            Some(&fod(u32::from(view == RegistryView::Wow32))),
        );
        let conservative_name = units("fodconservativemode");
        assert!(opened.covers_value(&conservative_name));
        assert_eq!(
            opened.value(&conservative_name),
            (view == RegistryView::Native64).then_some(&fod_conservative),
        );
        let cache_setting = units("disableconfigcache");
        assert!(opened.covers_value(&cache_setting));
        assert_eq!(
            opened.value(&cache_setting),
            (view == RegistryView::Native64).then_some(&disable_config_cache),
        );
        assert!(!opened.covers_value(&units("UnselectedValue")));
        assert!(matches!(
            opened.relative(&units("UnselectedChild")),
            Lookup::Unselected
        ));
    }
}

#[test]
fn powershell_registry_preserves_ordered_metadata_and_independent_views() {
    let root = ProcessConfigKey::PowerShell;
    let engine = ProcessConfigKey::PowerShellEngineV3;
    let absent_engine = ProcessConfigKey::PowerShellEngineV1;
    let mut registry = Registry::selected(upcase(), vec![]).unwrap();
    for (view, prefix, version, stamp, first_engine_status) in [
        (
            RegistryView::Native64,
            root.path(),
            "5.1.64",
            64,
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            RegistryView::Wow32,
            POWERSHELL_WOW_KEY,
            "5.1.32",
            32,
            STATUS_OBJECT_PATH_NOT_FOUND,
        ),
    ] {
        let physical = |key: ProcessConfigKey| key.path().replacen(root.path(), prefix, 1);
        let mut version_value = Value {
            name: units("PowerShellVersion"),
            kind: 1,
            data: version
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        let mut engine_values = vec![version_value.clone()];
        if view == RegistryView::Native64 {
            engine_values.push(Value {
                name: units("NetFrameworkV4IsInstalled"),
                kind: 1,
                data: b"Y\0e\0s\0\0\0".to_vec(),
            });
        }
        let mut root_header = header(prefix, vec![]);
        root_header.enumeration = Some(vec![
            BasicChild {
                name: units("3"),
                last_write: stamp,
            },
            BasicChild {
                name: units("1"),
                last_write: stamp + 1,
            },
        ]);
        for (key, sample) in [
            (absent_engine, Err(first_engine_status)),
            (engine, Ok(header(&physical(engine), engine_values))),
            (
                ProcessConfigKey::PowerShellV1,
                Ok(header(&physical(ProcessConfigKey::PowerShellV1), vec![])),
            ),
            (
                ProcessConfigKey::PowerShellV3,
                Ok(header(&physical(ProcessConfigKey::PowerShellV3), vec![])),
            ),
            (root, Ok(root_header)),
        ] {
            registry = registry
                .with_snapshot_selection(
                    SnapshotRoot::ProcessConfig(key),
                    &[],
                    view,
                    sample.map(|header| (header, None)),
                )
                .unwrap();
        }
        version_value.name = units("OtherValue");
        assert!(
            Registry::selected(upcase(), vec![])
                .unwrap()
                .with_snapshot_selection(
                    SnapshotRoot::ProcessConfig(engine),
                    &[],
                    view,
                    Ok((header(&physical(engine), vec![version_value]), None)),
                )
                .is_err()
        );
    }

    registry = registry
        .with_machine_hive(MachineHeader {
            canonical: units(MACHINE_HIVE_KEY),
            enumeration: None,
            children: 6,
            values: vec![],
            access: header(MACHINE_HIVE_KEY, vec![]).access,
        })
        .unwrap();
    let machine = registry.key(&units(MACHINE_HIVE_KEY)).unwrap();
    for (view, prefix, version, stamp) in [
        (RegistryView::Native64, root.path(), "5.1.64", 64),
        (RegistryView::Wow32, POWERSHELL_WOW_KEY, "5.1.32", 32),
    ] {
        let Lookup::Present(opened) =
            machine.relative_in_view(&units(r"SOFTWARE\Microsoft\PowerShell"), view)
        else {
            panic!("rooted PowerShell installation key not resolved");
        };
        assert_eq!(opened.path, units(prefix));
        assert_eq!(
            opened.child_metadata().unwrap(),
            &[
                BasicChild {
                    name: units("3"),
                    last_write: stamp
                },
                BasicChild {
                    name: units("1"),
                    last_write: stamp + 1
                },
            ],
        );
        let Lookup::Present(child) = opened.relative(&units(r"3\powershellengine")) else {
            panic!("relative PowerShell engine not resolved");
        };
        assert_eq!(child.redirected_view, Some(view));
        let expected: Vec<_> = version
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            child.value(&units("powershellversion")).unwrap().data,
            expected
        );
        assert!(child.covers_value(&units("RuntimeVersion")));
        assert!(child.value(&units("RuntimeVersion")).is_none());
        let framework = units("netframeworkv4isinstalled");
        assert!(child.covers_value(&framework));
        match view {
            RegistryView::Native64 => {
                let value = child.value(&framework).unwrap();
                assert_eq!(value.kind, 1);
                assert_eq!(value.data, b"Y\0e\0s\0\0\0");
            }
            RegistryView::Wow32 => assert!(child.value(&framework).is_none()),
        }
        assert!(!child.covers_value(&units("OtherValue")));
        for (path, requested_view) in [
            (engine.path().to_owned(), view),
            (
                format!(r"{prefix}\3\PowerShellEngine"),
                RegistryView::Native64,
            ),
        ] {
            let Lookup::Present(absolute) = registry.lookup_view(&units(&path), requested_view)
            else {
                panic!("absolute PowerShell engine not resolved");
            };
            assert!(Arc::ptr_eq(&absolute, &child));
        }
        let first_engine = opened.relative(&units(r"1\PowerShellEngine"));
        assert!(matches!(
            (view, first_engine),
            (RegistryView::Native64, Lookup::Missing) | (RegistryView::Wow32, Lookup::MissingPath)
        ));
        assert!(matches!(
            opened.relative(&units(r"3\0409")),
            Lookup::Unselected
        ));
        assert!(matches!(
            opened.relative(&units("Unselected")),
            Lookup::Unselected
        ));
    }
}

#[test]
fn physical_wow_powershell_key_preserves_captured_missing_path() {
    let root = SnapshotRoot::ProcessConfig(ProcessConfigKey::PowerShell);
    let registry = Registry::selected(upcase(), vec![])
        .unwrap()
        .with_snapshot_selection(
            root,
            &[],
            RegistryView::Wow32,
            Err(STATUS_OBJECT_PATH_NOT_FOUND),
        )
        .unwrap();
    let physical = units(POWERSHELL_WOW_KEY);
    assert!(matches!(registry.lookup(&physical), Lookup::MissingPath));
    assert!(matches!(
        registry.lookup(&root.path(&[]).unwrap()),
        Lookup::Unselected,
    ));
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

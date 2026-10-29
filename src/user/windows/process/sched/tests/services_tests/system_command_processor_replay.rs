//! Actual NT dispatch of the independently captured fixed System requests.
use super::*;

fn corpus() -> Json {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-command-processor/controls-system-v1.json"
    )))
    .unwrap()
}

fn registry(installed: bool) -> Registry {
    if installed {
        return crate::user::windows::registry::snapshot().unwrap();
    }
    let mut r = Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        r = r
            .with_command_view(
                CommandRoot::System,
                &[],
                view,
                Err(STATUS_OBJECT_NAME_NOT_FOUND),
            )
            .unwrap();
    }
    r.with_machine_hive(MachineHeader {
        enumeration: None,
        canonical: wide(MACHINE_HIVE_KEY),
        children: 6,
        values: vec![],
        access: KeyAccess {
            maximum_access: 0xF003F,
            system_security_status: STATUS_ACCESS_DENIED,
        },
    })
    .unwrap()
}

fn check(p: &mut Proc, t: &mut Thread, base: u64, row: &Json, status: u32, handle: u64) {
    assert_eq!(status, n(row, "status"), "native System row {row}");
    if status == STATUS_SUCCESS {
        assert_eq!(tags(p, t, base, handle), n(row, "tags"));
        if let Some(grant) = row.get("granted_access") {
            assert_eq!(
                p.objects.access(handle),
                Some(grant.as_u64().unwrap() as u32)
            );
        }
        let Object::Key(key) = p.objects.get(handle).unwrap() else {
            panic!("System key")
        };
        assert_eq!(key.path, units(row["name_hex"].as_str().unwrap()));
        assert_eq!(call(p, t, "NtClose", &[handle]), STATUS_SUCCESS);
    } else {
        assert_eq!(handle, 0, "failed open preserves zero output");
    }
}

fn replay(corpus: &Json, installed: bool) -> usize {
    let mut checked = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("unrecognized native ABI"),
        };
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.registry = registry(installed);
        let logical = CommandRoot::System.path(&[]).unwrap();
        for row in report["system"]["rows"].as_array().unwrap() {
            let (status, handle) = open(
                p,
                &mut t,
                base,
                n(row, "extended") != 0,
                &logical,
                0,
                n(row, "request") | n(row, "view"),
            );
            check(p, &mut t, base, row, status, handle);
            checked += 1;
        }
        let key = p.registry.key(&wide(MACHINE_HIVE_KEY)).unwrap();
        let mut parents = std::collections::BTreeMap::new();
        for view in [0, 0x100, 0x200] {
            let h = seed(
                p,
                key.clone(),
                if arch == WinArch::X86 { view } else { 0 },
                0xF003F,
            );
            let duplicate = u64::from(p.objects.duplicate(h, false).unwrap());
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
            parents.insert(view, duplicate);
        }
        p.registry = Registry::default();
        for row in report["system-relative"]["rows"].as_array().unwrap() {
            let (status, handle) = open(
                p,
                &mut t,
                base,
                true,
                &wide("System\\Software\\Microsoft\\Command Processor"),
                parents[&n(row, "parent_view")],
                0x02000000 | n(row, "view"),
            );
            check(p, &mut t, base, row, status, handle);
            checked += 1;
        }
        for handle in parents.values() {
            assert_eq!(call(p, &mut t, "NtClose", &[*handle]), STATUS_SUCCESS);
        }
    }
    checked
}

#[test]
fn system_command_processor_replays_native_absence_and_retained_machine_routes() {
    assert_eq!(replay(&corpus(), false), 444);
    if let Some(path) = std::env::var_os("RAX_SYSTEM_COMMAND_PROCESSOR_CORPUS") {
        let fresh = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(replay(&fresh, true) >= 296);
    }
}

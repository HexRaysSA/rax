//! Replay native observations, including fresh controls from the native CI host.
use super::*;
use serde_json::Value as Json;

fn number(row: &Json, field: &str) -> u32 {
    row[field].as_u64().unwrap().try_into().unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn units(text: &str) -> Vec<u16> {
    let raw = bytes(text);
    assert_eq!(raw.len() % 2, 0);
    raw.chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect()
}

fn selected(p: &mut Proc, report: &Json) {
    // Only the fixed root metadata is transferred. No native handle, callback,
    // descendant walk or arbitrary path becomes a runtime service.
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        p.registry = p
            .registry
            .clone()
            .with_appmodel_view(AppModelRoot::Machine, view, None)
            .unwrap();
    }
    let rows = report["rows"].as_array().unwrap();
    let ordinary = |request| {
        rows.iter()
            .find(|row| {
                number(row, "extended") == 0
                    && number(row, "request") == request
                    && number(row, "view") == 0
            })
            .unwrap()
    };
    let root = ordinary(1);
    assert_eq!(number(root, "status"), STATUS_SUCCESS);
    assert_eq!(number(root, "value_status"), STATUS_SUCCESS);
    p.registry = p
        .registry
        .clone()
        .with_machine_hive(MachineHeader {
            canonical: units(root["name_hex"].as_str().unwrap()),
            children: number(root, "children"),
            values: vec![Value {
                name: units(root["value_name_hex"].as_str().unwrap()),
                kind: number(root, "value_type"),
                data: bytes(root["value_data_hex"].as_str().unwrap()),
            }],
            access: MachineAccess {
                maximum_access: number(ordinary(0x02000000), "granted_access"),
                system_security_status: number(ordinary(0x01000000), "status"),
            },
        })
        .unwrap();
    // The retained producer enumerates exactly one value, rather than claiming
    // that a first-value sample represents a larger unseen value namespace.
    assert_eq!(number(root, "values"), 1);
}

fn replay(corpus: &Json, installed: bool) {
    assert_eq!(corpus["state"], "complete");
    let reports = corpus["reports"].as_array().unwrap();
    assert!(!reports.is_empty());
    for report in reports {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown native control architecture {other}"),
        };
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        if installed {
            p.registry = crate::user::windows::registry::snapshot().unwrap();
        } else {
            selected(p, &report["absolute"]);
        }
        let rows = report["absolute"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 136);
        for row in rows {
            let service = if number(row, "extended") == 0 {
                "NtOpenKey"
            } else {
                "NtOpenKeyEx"
            };
            let request = number(row, "request") | number(row, "view");
            let (status, h) = open(p, &mut t, base, service, MACHINE_HIVE_KEY, 0, request);
            assert_eq!(
                status,
                number(row, "status"),
                "{arch}/{service}/{request:x}"
            );
            assert_eq!(u32::from(h != 0), number(row, "handle_nonzero"));
            if status != STATUS_SUCCESS {
                continue;
            }
            assert_eq!(p.objects.access(h), Some(number(row, "granted_access")));
            assert_eq!(tags(p, &mut t, base, h), number(row, "tags"));
            assert_eq!(
                call(p, &mut t, "NtClose", &[h]),
                number(row, "close_status")
            );
        }
        let relative = report["relative"]["rows"].as_array().unwrap();
        assert_eq!(relative.len(), 36);
        for row in relative {
            let parent_view = number(row, "parent_view");
            let (status, parent) = open(
                p,
                &mut t,
                base,
                "NtOpenKeyEx",
                MACHINE_HIVE_KEY,
                0,
                0x20019 | parent_view,
            );
            assert_eq!(status, STATUS_SUCCESS);
            let child = number(row, "child");
            let suffix = match child {
                0 => "",
                1 => NLS_KEY
                    .strip_prefix(MACHINE_HIVE_KEY)
                    .unwrap()
                    .trim_start_matches('\\'),
                2 => AppModelRoot::Machine
                    .path()
                    .strip_prefix(MACHINE_HIVE_KEY)
                    .unwrap()
                    .trim_start_matches('\\'),
                _ => panic!("unknown control path {child}"),
            };
            let request = 0x20019 | number(row, "view");
            let (status, h) = open(p, &mut t, base, "NtOpenKeyEx", suffix, parent, request);
            assert_eq!(
                status,
                number(row, "status"),
                "{arch}/{parent_view:x}/{child}/{request:x}"
            );
            if status == STATUS_SUCCESS {
                assert_eq!(tags(p, &mut t, base, h), number(row, "tags"));
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
            } else {
                assert_eq!(h, 0);
            }
            assert_eq!(call(p, &mut t, "NtClose", &[parent]), STATUS_SUCCESS);
        }
    }
}

#[test]
fn machine_root_replays_retained_and_fresh_native_controls() {
    let retained: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-machine-hive/controls-v1.json"
    )))
    .unwrap();
    replay(&retained, false);
    if let Some(path) = std::env::var_os("RAX_MACHINE_HIVE_CORPUS") {
        let fresh: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        replay(&fresh, true);
    }
}

//! Native input probes and key-body lifetime replay through the NT dispatcher.
use super::*;
use serde_json::{Map, Value as Json};
use std::collections::BTreeMap;

fn number(row: &Json, field: &str) -> u64 {
    row[field].as_u64().unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn body(p: &mut Proc, initial: u32, access: u32) -> u64 {
    let key = p
        .registry
        .key(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    let id = p.objects.create_registry_key(key, initial).unwrap();
    p.objects.open_access(id, false, access).unwrap() as u64
}
fn matrices(arch: WinArch, data: &Json) -> usize {
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    assert_eq!(number(data, "page_size"), PAGE_SIZE);
    let mut handles = BTreeMap::new();
    for view in [0x100, 0x200] {
        for (kind, access) in [0x20019, 1, 8, 0x10].into_iter().enumerate() {
            handles.insert((view, kind as u64), body(p, 0, access));
        }
        let id = p.objects.id(handles[&(view, 0)]).unwrap();
        handles.insert(
            (view, 4),
            p.objects.open_access(id, false, 0).unwrap() as u64,
        );
    }
    let event = p.objects.insert(Object::Event {
        manual: true,
        signaled: 0,
    }) as u64;
    let fields = data["row_fields"].as_array().unwrap();
    let mut count = 0;
    for dense in data["rows"].as_array().unwrap() {
        let values = dense.as_array().unwrap();
        assert_eq!(values.len(), fields.len());
        let mut row = Map::new();
        for (field, value) in fields.iter().zip(values) {
            if field == "output" {
                row.extend(
                    data["outputs"][value.as_u64().unwrap() as usize]
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            } else {
                row.insert(field.as_str().unwrap().to_owned(), value.clone());
            }
        }
        let row = Json::Object(row);
        let view = number(&row, "view");
        let kind = number(&row, "handle_kind");
        let handle = match kind {
            0..=4 => handles[&(view, kind)],
            5 => 0,
            6 => event,
            7 => arch.ptr(u64::MAX),
            8 => arch.ptr(u64::MAX - 1),
            _ => panic!("unknown native handle kind"),
        };
        let observer = if kind < 4 {
            handle
        } else {
            handles[&(view, 0)]
        };
        assert!(
            p.objects
                .set_registry_tags(observer, number(&row, "before_tags") as u16)
        );
        p.vm.protect(base, PAGE_SIZE * 2, prot::READWRITE).unwrap();
        p.space
            .wr(base, &vec![0xa5; PAGE_SIZE as usize * 2])
            .unwrap();
        let scenario = number(&row, "scenario");
        let mut protection = prot::READWRITE;
        let input = match scenario {
            0..=7 => base + 64 + scenario,
            8 => 0,
            9 => 1,
            10 | 20 => {
                protection = prot::NOACCESS;
                base + PAGE_SIZE + u64::from(scenario == 20)
            }
            11 => {
                protection = prot::READONLY;
                base + PAGE_SIZE
            }
            12 | 19 => {
                protection = prot::READWRITE | prot::GUARD;
                base + PAGE_SIZE + u64::from(scenario == 19)
            }
            13..=16 => {
                protection = prot::NOACCESS;
                base + PAGE_SIZE - (scenario - 12)
            }
            17 => {
                protection = prot::READWRITE | prot::GUARD;
                base + PAGE_SIZE - 1
            }
            18 => {
                protection = prot::READWRITE | prot::GUARD;
                base + PAGE_SIZE - 4
            }
            21 => {
                protection = prot::READONLY;
                base + PAGE_SIZE - 2
            }
            _ => panic!("unknown native input scenario"),
        };
        assert_eq!(input % 8, number(&row, "input_alignment"));
        if !matches!(scenario, 8 | 9) {
            p.space.w32(input, number(&row, "value") as u32).unwrap();
        }
        let watch = base + if scenario >= 10 { PAGE_SIZE - 16 } else { 48 };
        assert_eq!(
            p.space.bytes(watch, 32).unwrap(),
            bytes(row["before_hex"].as_str().unwrap())
        );
        p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, protection)
            .unwrap();
        let context = format!(
            "{arch}/view{view:x}/kind{kind}/class{}/scenario{scenario}/length{}/value{:x}",
            number(&row, "class"),
            number(&row, "length"),
            number(&row, "value")
        );
        let actual = call(
            p,
            &mut t,
            "NtSetInformationKey",
            &[handle, number(&row, "class"), input, number(&row, "length")],
        );
        assert_eq!(u64::from(actual), number(&row, "status"), "{context}");
        assert_eq!(number(&row, "exception"), 0, "{context}");
        assert_eq!(
            p.objects.registry_tags(observer),
            Some(number(&row, "after_tags") as u32),
            "{context}"
        );
        assert_eq!(
            u64::from(p.vm.query(base + PAGE_SIZE).unwrap().protect),
            number(&row, "input_protection"),
            "{context}"
        );
        p.vm.protect(base, PAGE_SIZE * 2, prot::READWRITE).unwrap();
        assert_eq!(
            p.space.bytes(watch, 32).unwrap(),
            bytes(row["after_hex"].as_str().unwrap()),
            "{context}"
        );
        count += 1;
    }
    count
}

fn lifetime(arch: WinArch, rows: &[Json]) -> usize {
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    let catalog = p.registry.clone();
    let mut count = 0;
    for view in [0x100, 0x200] {
        p.registry = catalog.clone();
        let records: Vec<_> = rows.iter().filter(|r| number(r, "view") == view).collect();
        assert_eq!(records.len(), 14);
        // The open profiles are independently measured; setting tags never
        // changes immutable snapshot identity or another open's key body.
        let initial = number(&records[0]["queries"][0], "tags") as u32;
        let original = body(p, initial, 0x20019);
        let duplicate = p.objects.duplicate(original, false).unwrap() as u64;
        let independent = body(p, initial, 0x20019);
        let id = p.objects.id(original).unwrap();
        let zero = p.objects.open_access(id, false, 0).unwrap() as u64;
        p.registry = Registry::default();
        let mut handles = [original, duplicate, independent, zero];
        let mut set_index = 0;
        for row in records {
            let action = row["action"].as_str().unwrap();
            let mut status = STATUS_SUCCESS;
            let mut observed = handles;
            if let Some(value) = action
                .strip_prefix("set-")
                .and_then(|s| s.parse::<u32>().ok())
            {
                p.space.w32(base, value).unwrap();
                let setter = if set_index % 2 == 0 {
                    original
                } else {
                    duplicate
                };
                set_index += 1;
                status = call(p, &mut t, "NtSetInformationKey", &[setter, 5, base, 4]);
            } else if let Some(low) = action.strip_prefix("low-bits-") {
                let low: u64 = low.parse().unwrap();
                p.space.w32(base, 0x100 * low as u32).unwrap();
                status = call(
                    p,
                    &mut t,
                    "NtSetInformationKey",
                    &[original | low, 5, base, 4],
                );
                observed[0] = original | low;
            } else if action == "set-zero-grant" {
                p.space.w32(base, 0x100).unwrap();
                status = call(p, &mut t, "NtSetInformationKey", &[zero, 5, base, 4]);
            } else if action == "set-after-original-close" {
                assert_eq!(call(p, &mut t, "NtClose", &[original]), STATUS_SUCCESS);
                handles[0] = 0;
                observed = handles;
                p.space.w32(base, 0x200).unwrap();
                status = call(p, &mut t, "NtSetInformationKey", &[duplicate, 5, base, 4]);
            } else if action == "fresh-after-last-close" {
                for handle in [duplicate, independent, zero] {
                    assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
                }
                p.registry = catalog.clone();
                handles = [body(p, initial, 0x20019), 0, 0, 0];
                observed = handles;
                p.registry = Registry::default();
            } else {
                assert_eq!(action, "fresh");
            }
            assert_eq!(u64::from(status), number(row, "status"), "{arch}/{action}");
            for (i, handle) in observed.into_iter().enumerate() {
                p.space.w32(base + 64, 0xcccccccc).unwrap();
                let actual = call(
                    p,
                    &mut t,
                    "NtQueryKey",
                    &[handle, 7, base + 64, 4, base + 128],
                );
                assert_eq!(
                    u64::from(actual),
                    number(&row["queries"][i], "status"),
                    "{arch}/{action}/{i}"
                );
                if actual == STATUS_SUCCESS {
                    assert_eq!(
                        u64::from(p.space.u32(base + 64).unwrap()),
                        number(&row["queries"][i], "tags"),
                        "{arch}/{action}/{i}"
                    );
                }
                // Failed WoW64 query scratch bytes are undefined. The setter's
                // stored state is still checked through its readable duplicate.
            }
            count += 1;
        }
        assert_eq!(call(p, &mut t, "NtClose", &[handles[0]]), STATUS_SUCCESS);
    }
    count
}

fn replay(corpus: &Json, matrix: bool) {
    assert_eq!(corpus["schema"], "rax-native-key-set-information-v1");
    assert_eq!(corpus["state"], "complete");
    let reports = corpus["reports"].as_array().unwrap();
    assert!(!reports.is_empty());
    for report in reports {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("unknown native ABI"),
        };
        let count = if matrix {
            matrices(
                arch,
                &corpus["datasets"][report["dataset"].as_str().unwrap()],
            )
        } else {
            lifetime(arch, report["lifetime"].as_array().unwrap())
        };
        assert_eq!(count, if matrix { 5372 } else { 28 });
        eprintln!(
            "native key set {arch}: {count} {} cases",
            if matrix { "matrix" } else { "lifetime" }
        );
    }
}
fn corpora(matrix: bool) {
    let retained: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-key-set-information/controls-v1.json"
    )))
    .unwrap();
    assert_eq!(retained["reports"].as_array().unwrap().len(), 3);
    replay(&retained, matrix);
    if let Some(path) = std::env::var_os("RAX_KEY_SET_INFORMATION_CORPUS") {
        let fresh: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        replay(&fresh, matrix);
    }
}
#[test]
fn native_set_key_replays_all_input_fault_priority_and_tag_replacement_controls() {
    corpora(true);
}
#[test]
fn native_set_key_replays_duplicate_independent_open_zero_access_and_last_close_lifetimes() {
    corpora(false);
}

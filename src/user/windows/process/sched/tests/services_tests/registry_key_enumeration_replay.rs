//! Lossless native buffer/status replay. Real path acquisition is a separate gate.
use super::*;
use serde_json::{Map, Value as Json};
use std::collections::BTreeMap;

fn n(v: &Json, key: &str) -> u64 {
    v[key].as_u64().unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn monitor(v: &Json, key: &str, size: usize, fill: u8) -> Vec<u8> {
    let mut b = bytes(v[key].as_str().unwrap());
    assert!(b.len() <= size);
    b.resize(size, fill);
    b
}
fn memory_matches(actual: Vec<u8>, expected: Vec<u8>, context: &str) {
    assert_eq!(actual.len(), expected.len(), "{context}: monitor size");
    if let Some(i) = actual.iter().zip(&expected).position(|(a, b)| a != b) {
        panic!(
            "{context}: monitor byte {i}: actual {:02x}, expected {:02x}",
            actual[i], expected[i]
        );
    }
}

fn child(raw: &Json) -> BasicChild {
    let raw_name = bytes(raw["name_hex"].as_str().unwrap());
    let name = raw_name
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let last_write = u64::from_le_bytes(
        bytes(raw["last_write_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    BasicChild { name, last_write }
}
fn fixture_key(root: &Json) -> Arc<crate::user::windows::registry::Key> {
    let entries = root["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(child)
        .collect::<Vec<_>>();
    let count = root
        .get("children")
        .map_or(entries.len() as u32, |v| v.as_u64().unwrap() as u32);
    // Enumeration does not consume the parent's path. Project each measured
    // ordered record into a fixture key; native acquisition separately checks
    // the actual MACHINE/CMD paths without inventing unmeasured child bodies.
    let r = machine(Some(entries), count);
    r.key(&MACHINE_HIVE_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap()
}
fn expand(data: &Json, dense: &Json) -> Json {
    let values = dense.as_array().unwrap();
    let fields = data["row_fields"].as_array().unwrap();
    assert_eq!(values.len(), fields.len());
    let mut row = Map::new();
    for (key, value) in fields.iter().zip(values) {
        let key = key.as_str().unwrap();
        if key == "output" {
            for (k, v) in data["outputs"][value.as_u64().unwrap() as usize]
                .as_object()
                .unwrap()
            {
                assert!(row.insert(k.clone(), v.clone()).is_none());
            }
        } else {
            assert!(row.insert(key.to_owned(), value.clone()).is_none());
        }
    }
    Json::Object(row)
}
fn profile(p: &mut Proc, corpus: &Json) {
    super::super::super::native_profile::kernel_profile(
        p,
        corpus["kernel"][2].as_u64().unwrap() as u32,
        n(corpus, "native_machine") as u16,
    );
}
fn body(p: &mut Proc, key: Arc<crate::user::windows::registry::Key>, access: u32) -> u64 {
    let id = p.objects.create_registry_key(key, 0).unwrap();
    p.objects.open_access(id, false, access).unwrap() as u64
}
fn basic(arch: WinArch, corpus: &Json, data: &Json) -> usize {
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    profile(p, corpus);
    let mut handles = BTreeMap::new();
    for root in data["roots"].as_array().unwrap() {
        if n(root, "status") != 0 {
            continue;
        }
        handles.insert(
            (n(root, "root"), n(root, "view")),
            body(p, fixture_key(root), 0x20019),
        );
    }
    p.registry = Registry::default();
    let mut count = 0;
    for dense in data["rows"].as_array().unwrap() {
        let row = expand(data, dense);
        let class = n(&row, "class");
        // Node/full payloads are valid but remain explicit unsupported. The
        // class-0 and invalid-selector rows are all executed, including EOF.
        if matches!(class, 1 | 2) {
            continue;
        }
        let out = base + 128 + n(&row, "offset");
        let returned = base + 64 + n(&row, "result_alignment");
        assert_eq!(out % 8, n(&row, "output_alignment"));
        p.space.wr(base + 128, &[0xa5; 384]).unwrap();
        p.space.w32(returned, 0xcccccccc).unwrap();
        let h = handles[&(n(&row, "root"), n(&row, "view"))];
        let actual = call(
            p,
            &mut t,
            "NtEnumerateKey",
            &[h, n(&row, "index"), class, out, n(&row, "length"), returned],
        );
        let context = format!(
            "{arch}/basic/root{}/view{}/index{}/class{class}/offset{}/length{}",
            n(&row, "root"),
            n(&row, "view"),
            n(&row, "index"),
            n(&row, "offset"),
            n(&row, "length")
        );
        assert_eq!(n(&row, "exception"), 0, "{context}");
        assert_eq!(u64::from(actual), n(&row, "status"), "{context}");
        assert_eq!(
            u64::from(p.space.u32(returned).unwrap()),
            n(&row, "returned"),
            "{context}"
        );
        memory_matches(
            p.space.bytes(base + 128, 384).unwrap(),
            monitor(&row, "buffer_prefix_hex", 384, 0xa5),
            &context,
        );
        count += 1;
    }
    count
}
fn fault(arch: WinArch, corpus: &Json, data: &Json) -> usize {
    assert_eq!(n(data, "page_size"), PAGE_SIZE);
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    profile(p, corpus);
    let mut handles = BTreeMap::new();
    for root in data["roots"].as_array().unwrap() {
        let view = n(root, "view");
        let key = fixture_key(root);
        for (kind, access) in [0x20019, 1, 8, 0x10, 0].into_iter().enumerate() {
            handles.insert((view, kind as u64), body(p, key.clone(), access));
        }
    }
    let event = p.objects.insert(Object::Event {
        manual: true,
        signaled: 0,
    }) as u64;
    p.registry = Registry::default();
    let mut count = 0;
    for dense in data["rows"].as_array().unwrap() {
        let row = expand(data, dense);
        let scenario = n(&row, "scenario");
        p.vm.protect(base, PAGE_SIZE * 4, prot::READWRITE).unwrap();
        let rb = base + PAGE_SIZE * 2;
        p.space
            .wr(base, &vec![0xa5; PAGE_SIZE as usize * 2])
            .unwrap();
        p.space.wr(rb, &vec![0xcc; PAGE_SIZE as usize * 2]).unwrap();
        let (mut out, mut returned) = (base + 64, rb + 64);
        let (mut op, mut rp) = (prot::READWRITE, prot::READWRITE);
        match scenario {
            0 => {}
            1 => out = base + 65,
            2 => out = base + 68,
            3 => out = 0,
            4 => out = 1,
            5 | 6 | 7 => {
                out = base + PAGE_SIZE;
                op = match scenario {
                    5 => prot::NOACCESS,
                    6 => prot::READONLY,
                    _ => prot::READWRITE | prot::GUARD,
                };
            }
            8 | 9 | 10 => {
                out = base + PAGE_SIZE - 16;
                op = match scenario {
                    8 => prot::NOACCESS,
                    9 => prot::READONLY,
                    _ => prot::READWRITE | prot::GUARD,
                };
            }
            11 => returned = rb + 65,
            12 => returned = rb + 67,
            13 => returned = 0,
            14 => returned = 1,
            15 | 16 | 17 => {
                returned = rb + PAGE_SIZE;
                rp = match scenario {
                    15 => prot::NOACCESS,
                    16 => prot::READONLY,
                    _ => prot::READWRITE | prot::GUARD,
                };
            }
            18 | 19 | 20 => {
                returned = rb + PAGE_SIZE - 2;
                rp = match scenario {
                    18 => prot::NOACCESS,
                    19 => prot::READONLY,
                    _ => prot::READWRITE | prot::GUARD,
                };
            }
            21 => returned = out,
            22 => returned = out + 8,
            23 => returned = out + 14,
            24 => out = base + 71,
            25 => {
                out = 0;
                returned = 0;
            }
            26 | 27 | 28 => {
                out = base + PAGE_SIZE + 1;
                op = match scenario {
                    26 => prot::NOACCESS,
                    27 => prot::READONLY,
                    _ => prot::READWRITE | prot::GUARD,
                };
            }
            29 | 30 | 31 => {
                out = base + PAGE_SIZE - 1;
                op = match scenario {
                    29 => prot::NOACCESS,
                    30 => prot::READONLY,
                    _ => prot::READWRITE | prot::GUARD,
                };
            }
            32 | 33 | 34 => {
                out = base + PAGE_SIZE - 4;
                op = match scenario {
                    32 => prot::NOACCESS,
                    33 => prot::READONLY,
                    _ => prot::READWRITE | prot::GUARD,
                };
            }
            35 => {
                out = base + 65;
                returned = rb + PAGE_SIZE;
                rp = prot::READWRITE | prot::GUARD;
            }
            36 => {
                out = base + 65;
                returned = 0;
            }
            37 => {
                out = base + 65;
                returned = rb + PAGE_SIZE;
                rp = prot::NOACCESS;
            }
            38 => {
                out = base + 65;
                returned = rb + PAGE_SIZE - 2;
                rp = prot::NOACCESS;
            }
            39 => {
                out = base + 65;
                returned = out;
            }
            40 => {
                out = base + 65;
                returned = out + 14;
            }
            _ => panic!("unknown native scenario {scenario}"),
        }
        p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, op).unwrap();
        p.vm.protect(rb + PAGE_SIZE, PAGE_SIZE, rp).unwrap();
        let kind = n(&row, "handle_kind");
        let h = match kind {
            0..=4 => handles[&(n(&row, "view"), kind)],
            5 => 0,
            6 => event,
            7 => arch.ptr(u64::MAX),
            8 => arch.ptr(u64::MAX - 1),
            _ => panic!("handle kind {kind}"),
        };
        let actual = call(
            p,
            &mut t,
            "NtEnumerateKey",
            &[
                h,
                n(&row, "index"),
                n(&row, "class"),
                out,
                n(&row, "length"),
                returned,
            ],
        );
        let context = format!(
            "{arch}/fault/view{}/handle{kind}/index{}/class{}/scenario{scenario}/length{}",
            n(&row, "view"),
            n(&row, "index"),
            n(&row, "class"),
            n(&row, "length")
        );
        assert_eq!(n(&row, "exception"), 0, "{context}");
        assert_eq!(u64::from(actual), n(&row, "status"), "{context}");
        assert_eq!(
            u64::from(p.vm.query(base + PAGE_SIZE).unwrap().protect),
            n(&row, "output_protection"),
            "{context}"
        );
        assert_eq!(
            u64::from(p.vm.query(rb + PAGE_SIZE).unwrap().protect),
            n(&row, "result_protection"),
            "{context}"
        );
        p.vm.protect(base, PAGE_SIZE * 4, prot::READWRITE).unwrap();
        memory_matches(
            p.space.bytes(base + n(&row, "out_watch"), 384).unwrap(),
            monitor(&row, "buffer_prefix_hex", 384, 0xa5),
            &context,
        );
        memory_matches(
            p.space.bytes(rb + n(&row, "result_watch"), 32).unwrap(),
            monitor(&row, "result_prefix_hex", 32, 0xcc),
            &context,
        );
        count += 1;
    }
    count
}
fn replay(corpus: &Json) -> (usize, usize) {
    assert_eq!(corpus["schema"], "rax-native-key-enumeration-v1");
    assert_eq!(corpus["state"], "complete");
    let (mut basic_rows, mut fault_rows) = (0, 0);
    for (kind, campaign) in corpus["campaigns"].as_object().unwrap() {
        for report in campaign["reports"].as_array().unwrap() {
            let arch = match report["architecture"].as_str().unwrap() {
                "arm64" => WinArch::Arm64,
                "x64" => WinArch::X64,
                "x86" => WinArch::X86,
                other => panic!("architecture {other}"),
            };
            assert_eq!(n(report, "pointer_bytes"), arch.ptr_size());
            assert_eq!(n(report, "handles_before"), n(report, "handles_after"));
            let data = &campaign["datasets"][report["dataset"].as_str().unwrap()];
            match kind.as_str() {
                "basic" => {
                    let rows = basic(arch, corpus, data);
                    eprintln!("key enumeration basic/{arch}: {rows} rows");
                    basic_rows += rows;
                }
                "fault" => {
                    let rows = fault(arch, corpus, data);
                    eprintln!("key enumeration fault/{arch}: {rows} rows");
                    fault_rows += rows;
                }
                other => panic!("campaign {other}"),
            }
        }
    }
    (basic_rows, fault_rows)
}
#[test]
fn native_enumerate_key_replays_all_14580_class_zero_selector_and_17028_fault_rows() {
    let corpus: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-key-enumeration/controls-v1.json"
    )))
    .unwrap();
    assert_eq!(replay(&corpus), (14580, 17028));
}
#[test]
fn native_enumerate_key_replays_explicitly_requested_fresh_controls() {
    let Some(path) = std::env::var_os("RAX_KEY_ENUMERATION_CORPUS") else {
        eprintln!("fresh key-enumeration controls not requested; zero fresh rows");
        return;
    };
    let corpus: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let count = corpus["campaigns"]["fault"]["reports"]
        .as_array()
        .unwrap()
        .len();
    assert!((2..=3).contains(&count));
    let (basic, fault) = replay(&corpus);
    assert!(basic > 0);
    assert_eq!(fault, count * 5676);
    eprintln!(
        "fresh key enumeration: {count} process ABIs; {basic} class-zero/invalid-selector rows and {fault} fault/rights rows"
    );
}

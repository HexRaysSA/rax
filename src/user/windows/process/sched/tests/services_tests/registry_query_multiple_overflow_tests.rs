//! Independently measured ULONG aggregate-size wrap with a small output buffer.
use super::*;
use crate::user::windows::registry::SelectedKey;

#[test]
fn native_query_multiple_value_key_wraps_required_size_without_losing_overflow() {
    let retained: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-multiple-values/overflow/controls-v1.json"
    )))
    .unwrap();
    assert_eq!(replay(&retained), 15);
    let copied: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-multiple-values/overflow/controls-v2.json"
    )))
    .unwrap();
    assert_eq!(replay(&copied), 108);
    if let Some(path) = std::env::var_os("RAX_NATIVE_QUERY_MULTIPLE_VALUE_KEY_OVERFLOW_CORPUS") {
        let fresh: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(replay(&fresh) > 0);
    }
}

fn replay(corpus: &Json) -> usize {
    assert_eq!(
        corpus["schema"],
        "rax-native-query-multiple-values-overflow-runs-v1"
    );
    let mut checked = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown native ABI {other}"),
        };
        let (mut process, mut t, _) = setup(arch);
        let p = process.state_mut();
        super::super::super::native_profile::kernel_profile(
            p,
            report["prefix"][0]["kernel"][2].as_u64().unwrap() as u32,
            corpus["native_machine"].as_u64().unwrap() as u16,
        );
        p.registry = Registry::selected(
            (0..=u16::MAX)
                .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
                .collect(),
            vec![SelectedKey {
                path: NLS_KEY,
                children: 0,
                values: vec![Value {
                    name: "Large".encode_utf16().collect(),
                    kind: 3,
                    data: vec![0; 1 << 20],
                }],
            }],
        )
        .unwrap();
        let key = p
            .registry
            .key(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let id = p.objects.create_registry_key(key, 0).unwrap();
        let handle = u64::from(p.objects.open_access(id, false, 1).unwrap());
        p.registry = Registry::default();
        let base =
            p.vm.allocate(None, 0x240000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let descriptor = base + 0x19000;
        let length = base + 0x1F000;
        let required = length + 4;
        let output = base + 0x30000;
        let width = arch.ptr_size();
        let stride = if arch.is64() { 24 } else { 16 };
        for case in report["cases"].as_array().unwrap() {
            let count = case["count"].as_u64().unwrap();
            assert_eq!(case["value_bytes"], 1 << 20);
            p.space.wr(base, &vec![0xA5; 0x230000]).unwrap();
            p.vm.protect(output + (2 << 20), PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            unicode(p, descriptor, descriptor + 64, "Large");
            p.space.w16(descriptor + 2, 12).unwrap();
            for index in 0..4098 {
                p.space
                    .wptr(base + index * stride, width, descriptor)
                    .unwrap();
            }
            p.space
                .w32(length, case["capacity"].as_u64().unwrap_or(0) as u32)
                .unwrap();
            assert_eq!(
                u64::from(call(
                    p,
                    &mut t,
                    "NtQueryMultipleValueKey",
                    &[handle, base, count, output, length, required]
                )),
                case["status"].as_u64().unwrap(),
                "{arch}/{count}/status"
            );
            assert_eq!(
                u64::from(p.space.u32(length).unwrap()),
                case["length"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(p.space.u32(required).unwrap()),
                case["required"].as_u64().unwrap()
            );
            assert_eq!(case["pointers_unchanged"], true);
            assert_eq!(case["padding_unchanged"], true);
            let mut index = 0;
            for run in case["fields_runs"].as_array().unwrap() {
                for _ in 0..run[1].as_u64().unwrap() {
                    let address = base + index * stride;
                    for field in 0..3 {
                        assert_eq!(
                            u64::from(p.space.u32(address + width + field * 4).unwrap()),
                            run[0][field as usize].as_u64().unwrap(),
                            "{arch}/{count}/{index}/{field}"
                        );
                    }
                    assert_eq!(p.space.ptr(address, width).unwrap(), descriptor);
                    if arch.is64() {
                        assert_eq!(p.space.u32(address + 20).unwrap(), 0xA5A5_A5A5);
                    }
                    index += 1;
                }
            }
            assert_eq!(index, 4098);
            if let Some(runs) = case["data_runs"].as_array() {
                let mut expected = Vec::new();
                for run in runs {
                    expected.extend(std::iter::repeat_n(
                        run[0].as_u64().unwrap() as u8,
                        run[1].as_u64().unwrap() as usize,
                    ));
                }
                assert_eq!(expected.len(), 2 << 20);
                assert_eq!(
                    p.space.bytes(output, expected.len()).unwrap(),
                    expected,
                    "{arch}/{count}/data"
                );
            } else {
                assert_eq!(case["data_unchanged"], true);
                assert_eq!(p.space.bytes(output, 16).unwrap(), [0xA5; 16]);
            }
            assert_eq!(
                p.vm.query(output + (2 << 20)).unwrap().protect,
                prot::NOACCESS
            );
            checked += 1;
        }
    }
    assert_eq!(checked as u64, corpus["native_calls"].as_u64().unwrap());
    checked
}

//! Independent native invalid-selector bytes and destination-fault priority.
use super::*;

#[test]
fn native_query_key_invalid_classes_replay_observed_fault_priority() {
    let observations: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-key/invalid-class/observations-v1.json"
    )))
    .unwrap();
    assert_eq!(observations["schema"], "rax-nt-query-key-invalid-class-v1");
    assert_eq!(observations["kernel"], serde_json::json!([10, 0, 29698]));
    let rows = observations["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 30);
    for (label, arch) in [
        ("arm64", WinArch::Arm64),
        ("x64", WinArch::X64),
        ("x86", WinArch::X86),
    ] {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let arena = base + 128;
        let mut modes = std::collections::BTreeSet::new();
        for row in rows.iter().filter(|r| r["architecture"] == label) {
            let mode = row["mode"].as_u64().unwrap();
            assert!(modes.insert(mode));
            let (output, length, returned) = match mode {
                0 => (arena + 4, 32, arena + 4),
                1 => (arena + 4, 32, 0),
                2 => (0, 32, arena + 32),
                3 => (0, 0, 0),
                4 => (arena + 1, 32, arena + 32),
                5 => (arena + 1, 0, arena + 32),
                6 => (arena, 32, 0),
                7 => (arena, 0, 0),
                8 => (1, 32, arena + 32),
                9 => (4096, 32, 4096),
                _ => panic!("unknown native invalid-class mode"),
            };
            let raw = row["stdout_hex"].as_str().unwrap();
            let expected: Vec<_> = (0..raw.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(expected.len(), 72);
            assert_eq!(
                u32::from_le_bytes(expected[..4].try_into().unwrap()) as u64,
                mode
            );
            let status = u32::from_le_bytes(expected[4..8].try_into().unwrap());
            p.space.wr(arena, &[0xA5; 64]).unwrap();
            let actual = call(p, &mut t, "NtQueryKey", &[0, 9, output, length, returned]);
            assert_eq!(actual, status, "{arch}/mode{mode}");
            assert_eq!(
                p.space.bytes(arena, 64).unwrap(),
                expected[8..],
                "{arch}/mode{mode}"
            );
        }
        assert_eq!(modes, (0..10).collect());
    }
}

#[test]
fn native_query_key_invalid_classes_do_not_allocate_convert_or_consume_guards() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let page = base + PAGE_SIZE;
        for class in [9, 10, u32::MAX] {
            for length in [0, 1, 16 << 20, (16 << 20) + 1, u32::MAX] {
                p.vm.protect(page, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                assert_eq!(
                    call(
                        p,
                        &mut t,
                        "NtQueryKey",
                        &[
                            u64::MAX,
                            u64::from(class),
                            page + 4,
                            u64::from(length),
                            page + 64
                        ]
                    ),
                    STATUS_INVALID_PARAMETER,
                    "{arch}/class{class}/length{length}"
                );
                assert_eq!(
                    p.vm.query(page).unwrap().protect,
                    prot::READWRITE | prot::GUARD,
                    "{arch}/class{class}/length{length}"
                );
            }
        }
    }
}

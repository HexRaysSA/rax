//! Replay captured native statuses, defined bytes, and one-shot guard effects.
use super::*;
use serde_json::Value as Json;
use std::collections::BTreeMap;

#[path = "registry_key_query_copy_tests.rs"]
mod copy_boundaries;

fn number(row: &Json, field: &str) -> u64 {
    row[field].as_u64().unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn corpus(arch: WinArch, text: &str, build: u32, machine: u16) {
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    super::super::super::native_profile::kernel_profile(p, build, machine);
    let crate::user::windows::registry::Lookup::Present(key) = p
        .registry
        .lookup(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
    else {
        panic!("selected key absent")
    };
    let mut handles = BTreeMap::new();
    for access in [0x20019, 0, 1, 8, 0x10, 0x20000] {
        let id = p
            .objects
            .create_registry_key(key.clone(), if arch == WinArch::X86 { 0x400 } else { 0 })
            .unwrap();
        let h = p.objects.open_access(id, false, access).unwrap() as u64;
        handles.insert(format!("access-{access:x}"), h);
    }
    let event = p.objects.insert(Object::Event {
        manual: true,
        signaled: 0,
    }) as u64;
    handles.extend([
        ("special-6".into(), 0),
        ("special-7".into(), 0xdeadbee0),
        ("special-8".into(), arch.ptr(u64::MAX)),
        ("special-9".into(), arch.ptr(u64::MAX - 1)),
        ("special-10".into(), event),
        ("special-11".into(), handles["access-20019"] | 3),
    ]);
    let mut count = 0;
    for line in text.lines() {
        let row: Json = serde_json::from_str(line).unwrap();
        if row["kind"] != "query" {
            continue;
        }
        let class = number(&row, "class");
        // Other admitted classes need captured native metadata, separately from
        // this key-body state group. Invalid classes retain native validation.
        if class < 9 && class != 7 {
            continue;
        }
        let role = number(&row, "role");
        let length = number(&row, "length");
        let label = row["handle"].as_str().unwrap();
        let h = handles[label];
        p.vm.protect(base, PAGE_SIZE * 3, prot::READWRITE).unwrap();
        p.space
            .wr(base, &vec![0xA5; PAGE_SIZE as usize * 3])
            .unwrap();
        let mut output = base + 128;
        let mut returned = base + 64;
        match role {
            1 => output += 1,
            2 => output = 0,
            3 => output = 1,
            4 => returned = 0,
            5 => returned = 1,
            6 => returned += 1,
            7 | 9 => {
                output = base + PAGE_SIZE;
                p.vm.protect(
                    output,
                    PAGE_SIZE,
                    if role == 7 {
                        prot::READONLY
                    } else {
                        prot::READWRITE | prot::GUARD
                    },
                )
                .unwrap();
            }
            8 | 10 => {
                returned = base + PAGE_SIZE;
                p.vm.protect(
                    returned,
                    PAGE_SIZE,
                    if role == 8 {
                        prot::READONLY
                    } else {
                        prot::READWRITE | prot::GUARD
                    },
                )
                .unwrap();
            }
            11 | 13 | 16 => {
                output = base + PAGE_SIZE - if role == 11 { 1 } else { 4 };
                p.vm.protect(
                    base + PAGE_SIZE,
                    PAGE_SIZE,
                    if role == 16 {
                        prot::READWRITE | prot::GUARD
                    } else {
                        prot::NOACCESS
                    },
                )
                .unwrap();
            }
            12 => {
                returned = base + PAGE_SIZE - 1;
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
            }
            14 => returned = output,
            15 => returned = output + 1,
            _ => assert_eq!(role, 0),
        }
        let last_error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x12345678).unwrap();
        let actual = call(
            p,
            &mut t,
            "NtQueryKey",
            &[h, class, output, length, returned],
        );
        let context = format!("{arch}/{label}/class{class}/length{length}/role{role}");
        assert_eq!(actual as u64, number(&row, "status"), "{context}");
        assert_eq!(
            p.space.u32(last_error).unwrap() as u64,
            number(&row, "last_error"),
            "{context}"
        );
        assert_eq!(
            p.vm.query(base + PAGE_SIZE).unwrap().protect as u64,
            number(&row, "page1_protect"),
            "{context}"
        );
        p.vm.protect(base, PAGE_SIZE * 3, prot::READWRITE).unwrap();
        for (field, at, size) in [
            ("output", base + 128, 32),
            ("result", base + 64, 16),
            ("boundary", base + PAGE_SIZE - 8, 16),
        ] {
            let expected = bytes(row[field].as_str().unwrap());
            let actual = p.space.bytes(at, size).unwrap();
            for index in 0..size {
                let address = at + index as u64;
                let converted = arch == WinArch::X86 && output % 8 != 0;
                let copied =
                    converted && (output..output.saturating_add(length)).contains(&address);
                // The thunk unconditionally copies uninitialized native scratch
                // after failures and beyond defined output. Those bytes vary by
                // host allocator state; retain raw captures but never assert them.
                let key_valid =
                    label.starts_with("access-") && label != "access-0" || label == "special-11";
                let defined_tag = key_valid
                    && class == 7
                    && length >= 4
                    && (output..output.saturating_add(4)).contains(&address);
                if copied && !defined_tag {
                    continue;
                }
                assert_eq!(actual[index], expected[index], "{context}/{field}+{index}");
            }
        }
        count += 1;
    }
    assert_eq!(count, 1920);
}

#[test]
fn native_query_key_replays_status_output_alias_guard_and_wow64_copy_order() {
    for (arch, text) in [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/arm64-29695-v2.jsonl"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/x64-29695-v2.jsonl"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/x86-29695-v2.jsonl"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/x86-laa-29695-v2.jsonl"
            )),
        ),
    ] {
        corpus(arch, text, 29695, 0xAA64);
    }
    for (build, text) in [
        (
            20348,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-20348-x86-v2.jsonl"
            )),
        ),
        (
            20348,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-20348-x86-laa-v2.jsonl"
            )),
        ),
        (
            26100,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-26100-x86-v2.jsonl"
            )),
        ),
        (
            26100,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-26100-x86-laa-v2.jsonl"
            )),
        ),
    ] {
        corpus(WinArch::X86, text, build, 0x8664);
    }
    if let Some(path) = std::env::var_os("RAX_NATIVE_QUERY_KEY_CORPUS") {
        let data: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(data["state"], "finished");
        assert_eq!(data["exit_code"], 0);
        for row in data["rows"].as_array().unwrap() {
            let arch = match row["label"].as_str().unwrap() {
                "arm64" => WinArch::Arm64,
                "x64" => WinArch::X64,
                "x86" | "x86-laa" => WinArch::X86,
                _ => panic!("unmeasured query-key ABI"),
            };
            let probe = &row["probes"]["v2"];
            assert_eq!(probe["build_returncode"], 0);
            assert_eq!(probe["run_returncode"], 0);
            assert_eq!(probe["exe_before_sha256"], probe["exe_after_sha256"]);
            corpus(
                arch,
                probe["text"].as_str().unwrap(),
                data["kernel"][2].as_u64().unwrap() as u32,
                data["native_machine"].as_u64().unwrap() as u16,
            );
        }
    }
}

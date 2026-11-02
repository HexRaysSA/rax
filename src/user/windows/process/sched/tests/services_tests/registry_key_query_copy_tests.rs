//! Independent native later-page copy controls; undefined scratch stays excluded.
use super::*;

fn boundaries(arch: WinArch, text: &str, build: u32, machine: u16) {
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    super::super::super::super::native_profile::kernel_profile(p, build, machine);
    let crate::user::windows::registry::Lookup::Present(key) = p
        .registry
        .lookup(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
    else {
        panic!("missing selected key")
    };
    let id = p
        .objects
        .create_registry_key(key, if arch == WinArch::X86 { 0x400 } else { 0 })
        .unwrap();
    let handle = p.objects.open_access(id, false, 0x20019).unwrap() as u64;
    let mut count = 0;
    for line in text.lines() {
        let row: Json = serde_json::from_str(line).unwrap();
        if row["kind"] != "copy_boundary" {
            continue;
        }
        assert_eq!(number(&row, "exception"), 0);
        let prefix = number(&row, "prefix");
        let length = number(&row, "length");
        let valid = number(&row, "valid") != 0;
        let guarded = number(&row, "guard") != 0;
        assert!(prefix < PAGE_SIZE && length <= PAGE_SIZE * 2);
        p.vm.protect(base, PAGE_SIZE * 3, prot::READWRITE).unwrap();
        p.space
            .wr(base, &vec![0xA5; PAGE_SIZE as usize * 3])
            .unwrap();
        p.vm.protect(
            base + PAGE_SIZE,
            PAGE_SIZE,
            if guarded {
                prot::READWRITE | prot::GUARD
            } else {
                prot::NOACCESS
            },
        )
        .unwrap();
        let output = base + PAGE_SIZE - prefix;
        let returned = base + PAGE_SIZE * 3;
        p.space.w32(returned, 0xA5A5_A5A5).unwrap();
        let last_error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x12345678).unwrap();
        let actual = call(
            p,
            &mut t,
            "NtQueryKey",
            &[if valid { handle } else { 0 }, 7, output, length, returned],
        );
        let label = format!(
            "{arch}/{machine:x}/{build}/prefix{prefix}/length{length}/valid{valid}/guard{guarded}"
        );
        assert_eq!(actual as u64, number(&row, "status"), "{label}");
        assert_eq!(
            p.space.u32(returned).unwrap() as u64,
            number(&row, "returned"),
            "{label}"
        );
        assert_eq!(
            p.space.u32(last_error).unwrap() as u64,
            number(&row, "last_error"),
            "{label}"
        );
        assert_eq!(
            p.vm.query(base + PAGE_SIZE).unwrap().protect as u64,
            number(&row, "page1_protect"),
            "{label}"
        );
        p.vm.protect(base, PAGE_SIZE * 3, prot::READWRITE).unwrap();
        if valid && length >= 4 {
            // Only the four-byte tag record has defined native scratch data.
            // An earlier fault can leave some or all of it at the sentinel.
            assert_eq!(
                p.space.bytes(output, 4).unwrap(),
                bytes(row["head"].as_str().unwrap())[..4],
                "{label}/tag stores"
            );
        }
        count += 1;
    }
    assert_eq!(count, 3312);
}

#[test]
fn native_query_key_replays_later_page_copies_across_captured_kernels() {
    for (build, machine, text) in [
        (
            29695,
            0xAA64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/arm64-29695-x86-v5.jsonl"
            )),
        ),
        (
            29695,
            0xAA64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/arm64-29695-x86-laa-v5.jsonl"
            )),
        ),
        (
            20348,
            0x8664,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-20348-x86-v5.jsonl"
            )),
        ),
        (
            20348,
            0x8664,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-20348-x86-laa-v5.jsonl"
            )),
        ),
        (
            26100,
            0x8664,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-26100-x86-v5.jsonl"
            )),
        ),
        (
            26100,
            0x8664,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/amd64-26100-x86-laa-v5.jsonl"
            )),
        ),
    ] {
        boundaries(WinArch::X86, text, build, machine);
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
                _ => panic!("unknown boundary ABI"),
            };
            let probe = &row["probes"]["v5"];
            assert_eq!(probe["build_returncode"], 0);
            assert_eq!(probe["run_returncode"], 0);
            boundaries(
                arch,
                probe["text"].as_str().unwrap(),
                data["kernel"][2].as_u64().unwrap() as u32,
                data["native_machine"].as_u64().unwrap() as u16,
            );
        }
    }
}

//! Replay every captured first/retry transition, independently of host OS.
use super::*;

#[test]
fn wow64_csr_replays_26_native_cases_and_32_returns_with_resources_and_publication() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-wow64-csr-connect/initial-29695-v8.json"
    )).unwrap();
    assert_eq!(corpus["case_count"], 26);
    assert_eq!(corpus["return_count"], 32);
    assert_eq!(replay(&corpus), 32);
}

#[test]
fn wow64_csr_replays_native_root_syntax_case_and_null_buffer_retry() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-wow64-csr-connect/initial-29695-v9.json"
    )).unwrap();
    assert_eq!(corpus["case_count"], 5);
    assert_eq!(corpus["return_count"], 6);
    assert_eq!(replay(&corpus), 6);
}

fn replay(corpus: &serde_json::Value) -> usize {
    let mut returns = 0;
    for row in corpus["samples"].as_array().unwrap() {
        let label = row["mode"].as_str().unwrap();
        let mode = label.strip_prefix("retry-").unwrap_or(label);
        let (mut process, mut thread, b) = setup();
        let p = process.state_mut();
        let mut request = args(b);
        configure(p, b, mode, &mut request);
        let mut native_published = false;
        let mut wow_published = false;
        for step in row["steps"].as_array().unwrap() {
            if mode == "guard-inside-null-buffer" && step["ordinal"] == 1 {
                request[2] = 0;
            }
            let before = p.objects.handle_count();
            let committed = p.vm.committed_bytes();
            let expected = u32::from_str_radix(step["status"].as_str().unwrap(), 16).unwrap();
            assert_eq!(invoke(p, &mut thread, &request), expected, "{label}");
            let delta =
                step["handles_after"].as_u64().unwrap() - step["handles_before"].as_u64().unwrap();
            assert_eq!(
                p.objects.handle_count() as u64,
                before as u64 + delta,
                "{label}"
            );
            let mapped_bytes: u64 = step["new_mappings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|region| region["state"].as_u64() == Some(0x1000))
                .map(|region| region["bytes"].as_u64().unwrap())
                .sum();
            assert_eq!(p.vm.committed_bytes(), committed + mapped_bytes, "{label}");
            native_published |= step["changed64"].as_u64().unwrap() != 0;
            wow_published |= step["changed32"].as_u64().unwrap() != 0;
            let state = p.wow64.as_ref().unwrap();
            assert_eq!(state.csr.is_some(), native_published, "{label}");
            assert_eq!(
                p.space.u64(state.native_peb + 0x88).unwrap() != 0,
                native_published,
                "{label}"
            );
            assert_eq!(
                p.space.u32(p.peb + 0x4c).unwrap() != 0,
                wow_published,
                "{label}"
            );
            assert_eq!(
                p.space.u32(p.peb + 0x54).unwrap() != 0,
                wow_published,
                "{label}"
            );
            assert_eq!(
                p.space.u64(p.peb + 0x248).unwrap() != 0,
                wow_published,
                "{label}"
            );
            returns += 1;
        }
    }
    returns
}

// The same caller-memory cases drive the ARM64 and AMD64 native corpora.
pub(super) fn configure(p: &mut Proc, b: u64, mode: &str, request: &mut [u64; 5]) {
    match mode {
        "valid" => {}
        "zero" => request[3] = 0,
        "short" => request[3] = 7,
        "length-16" => request[3] = 16,
        "length-64" => request[3] = 64,
        "null-buffer" => request[2] = 0,
        "noaccess-buffer" => {
            p.vm.protect(b + 4096, 4096, prot::NOACCESS).unwrap();
        }
        "readonly-buffer" => {
            p.vm.protect(b + 4096, 4096, prot::READONLY).unwrap();
        }
        "guard-buffer" => {
            p.vm.protect(b + 4096, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        "bad-inside" => request[4] = 1,
        "guard-inside" | "guard-inside-null-buffer" => {
            p.vm.protect(b + 8192, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        "readonly-inside" => {
            p.vm.protect(b + 8192, 4096, prot::READONLY).unwrap();
        }
        "readonly-guard-inside" => {
            p.vm.protect(b + 8192, 4096, prot::READONLY | prot::GUARD)
                .unwrap();
        }
        "null-inside" => request[4] = 0,
        "null-root" => request[0] = 0,
        "bad-root" => request[0] = 1,
        "guard-root" => {
            p.vm.protect(b, 4096, prot::READONLY | prot::GUARD).unwrap();
        }
        "missing-root" => p
            .space
            .put_wstr(
                b,
                &"\\AssistMissingCsrDirectory"
                    .encode_utf16()
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        "null-buffer-null-root" => {
            request[0] = 0;
            request[2] = 0;
        }
        "zero-bad-root" => {
            request[0] = 1;
            request[3] = 0;
        }
        "lower-root" | "upper-root" | "trailing-root" | "root-only" => {
            let root = match mode {
                "lower-root" => "\\windows",
                "upper-root" => "\\WINDOWS",
                "trailing-root" => "\\Windows\\",
                "root-only" => "\\",
                _ => unreachable!(),
            };
            p.space
                .put_wstr(b, &root.encode_utf16().collect::<Vec<_>>())
                .unwrap();
        }
        _ => panic!("unknown native case {mode}"),
    }
}

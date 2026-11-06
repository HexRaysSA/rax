//! Source-bound independent NT results, including caller-buffer aliases.
use super::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn fields(line: &str) -> BTreeMap<&str, &str> {
    line.split_whitespace()
        .filter_map(|part| part.split_once('='))
        .collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn replay_cases(text: &str, expected_reports: usize, expected_cases: usize, source_sha256: &str) {
    let corpus: Value = serde_json::from_str(text).unwrap();
    assert_eq!(corpus["state"], "complete");
    assert_eq!(corpus["schema"], "rax-native-cfg-target-records-v1");
    assert_eq!(corpus["source_sha256"], source_sha256);
    let reports = corpus["reports"].as_array().unwrap();
    assert_eq!(reports.len(), expected_reports);
    let mut comparisons = 0;
    for report in reports {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown native CFG ABI {other}"),
        };
        let mut cases = BTreeSet::new();
        let stdout = report["stdout"].as_str().unwrap();
        for block in stdout.split("BEGIN_CASE case=").skip(1) {
            let case = block.lines().next().unwrap().trim();
            assert!(cases.insert(case));
            let label = format!("{}/{arch}/{case}", corpus["kernel"][2]);
            let entry = fields(
                block
                    .lines()
                    .find(|line| line.starts_with("ENTER "))
                    .unwrap(),
            );
            let result = fields(
                block
                    .lines()
                    .find(|line| line.starts_with("RESULT "))
                    .unwrap(),
            );
            let ending = fields(
                block
                    .lines()
                    .find(|line| line.starts_with("END_CASE "))
                    .unwrap(),
            );
            assert_eq!(ending["exit"], "00000000", "{label}");
            let native_buffers: Vec<_> = block
                .lines()
                .filter(|line| line.starts_with("BUFFER "))
                .map(fields)
                .collect();
            assert_eq!(native_buffers.len(), 4, "{label}");
            assert_eq!(result["last_error"], "abababab", "{label}");
            let (mut process, mut thread) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
            let p = process.state_mut();
            super::super::system_processor_tests::kernel_profile(
                p,
                corpus["native_machine"].as_u64().unwrap() as u16,
            );
            let version = &mut p.native.as_mut().unwrap().version;
            version.major = corpus["kernel"][0].as_u64().unwrap() as u32;
            version.minor = corpus["kernel"][1].as_u64().unwrap() as u32;
            version.build = corpus["kernel"][2].as_u64().unwrap() as u32;
            std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
            let setup = inputs::prepare(p, case);
            assert_eq!(
                setup.args[2],
                entry["range_count"].parse::<u64>().unwrap(),
                "{label}"
            );
            assert_eq!(
                setup.args[5],
                entry["information_bytes"].parse::<u64>().unwrap(),
                "{label}"
            );
            let mut expected = setup.before.clone();
            let native_info = hex(native_buffers[1]["before"]);
            let width = arch.ptr_size() as usize;
            let mut pointer = [0u8; 8];
            pointer[..width].copy_from_slice(&native_info[8..8 + width]);
            let native_output = u64::from_le_bytes(pointer);
            for (index, buffer) in native_buffers.iter().enumerate() {
                let before = hex(buffer["before"]);
                let after = hex(buffer["after"]);
                assert_eq!(before.len(), 64);
                assert_eq!(after.len(), 64);
                if before != after {
                    let address = u64::from_str_radix(buffer["address"], 16).unwrap();
                    assert!(
                        (address..=address + 60).contains(&native_output),
                        "{label}: unexpected native store"
                    );
                    let at = (native_output - address) as usize;
                    assert_eq!(before[..at], after[..at], "{label}");
                    assert_eq!(before[at + 4..], after[at + 4..], "{label}");
                    // Apply the complete observed DWORD store, including zero
                    // bytes that happened to equal part of a native pointer.
                    expected[index][at..at + 4].copy_from_slice(&after[at..at + 4]);
                }
            }
            let committed = p.vm.committed_bytes();
            let handles = p.objects.handle_count();
            assert_eq!(
                enter(p, &mut thread, setup.args),
                Outcome::Continue,
                "{label}"
            );
            assert_eq!(
                thread.cpu.gpr(0),
                u64::from_str_radix(result["status"], 16).unwrap(),
                "{label}"
            );
            assert_eq!(
                p.space
                    .u32(thread.teb + layout::offsets(arch).teb_last_error)
                    .unwrap(),
                LAST_ERROR,
                "{label}"
            );
            assert_eq!(p.vm.committed_bytes(), committed, "{label}");
            assert_eq!(p.objects.handle_count(), handles, "{label}");
            for restore in block.lines().filter(|line| line.starts_with("RESTORE ")) {
                let restore = fields(restore);
                let index = restore["index"].parse::<usize>().unwrap();
                assert_eq!(
                    p.vm.query(setup.buffers[index].0).unwrap().protect,
                    u32::from_str_radix(restore["previous"], 16).unwrap(),
                    "{label}/protection/{index}"
                );
            }
            for (index, &(base, at)) in setup.buffers.iter().enumerate() {
                p.vm.protect(base, 8192, prot::READWRITE).unwrap();
                assert_eq!(
                    p.space.bytes(at, 64).unwrap(),
                    expected[index],
                    "{label}/{}",
                    native_buffers[index]["name"]
                );
            }
            comparisons += 1;
        }
        assert_eq!(cases.len(), expected_cases);
    }
    assert_eq!(comparisons, expected_cases * expected_reports);
}

fn replay(text: &str, expected_reports: usize) {
    replay_cases(
        text,
        expected_reports,
        102,
        "903aead253483748cdf4d2eca5b94ead9e972d6d16257077aa71bdb8a5f7117a",
    );
}

#[test]
fn cfg_target_native_capture_alignment_rights_and_output_guards() {
    replay_cases(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-cfg-target-records/capture-shapes-arm64-29698-v1.json"
        )),
        3,
        13,
        "5bc3652ffbeea1ed9e132199467d0ebfbe3ae43eeea576311fb7dff3a7c486ef",
    );
}

#[test]
fn cfg_target_native_arm64_kernel_replays_all_306_abi_cases() {
    replay(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-cfg-target-records/controls-arm64-29698-v1.json"
        )),
        3,
    );
}

#[test]
fn cfg_target_native_amd64_20348_replays_all_204_abi_cases() {
    replay(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-cfg-target-records/controls-amd64-20348-v1.json"
        )),
        2,
    );
}

#[test]
fn cfg_target_native_amd64_26100_replays_all_204_abi_cases() {
    replay(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-cfg-target-records/controls-amd64-26100-v1.json"
        )),
        2,
    );
}

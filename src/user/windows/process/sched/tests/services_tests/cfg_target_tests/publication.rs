//! Independent child admission distinguishes prevalidation from partial stores.
use super::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn fields(line: &str) -> BTreeMap<&str, &str> {
    line.split_whitespace()
        .filter_map(|part| part.split_once('='))
        .collect()
}

#[test]
fn cfg_target_native_publication_order_matches_owned_leaf_admission() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-cfg-target-records/target-mutation-arm64-29698-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus["state"], "complete");
    assert_eq!(corpus["schema"], "rax-native-cfg-target-mutation-v1");
    assert_eq!(
        corpus["source_sha256"],
        "22172c26a688993c6fe2265245ef134776d187a9193077d4bd1599931a5efdd6"
    );
    let reports = corpus["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 3);
    let mut comparisons = 0;
    for report in reports {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown publication ABI {other}"),
        };
        let mut cases = BTreeSet::new();
        for block in report["stdout"]
            .as_str()
            .unwrap()
            .split("BEGIN_CASE case=")
            .skip(1)
        {
            let case = block
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap();
            assert!(cases.insert(case));
            let observed = fields(block.lines().find(|line| line.starts_with("NT ")).unwrap());
            let terminal = fields(
                block
                    .lines()
                    .find(|line| line.starts_with("END_CASE "))
                    .unwrap(),
            );
            assert_eq!(observed["cfg_policy"], "00000001");
            let native_exit = u32::from_str_radix(terminal["exit"], 16).unwrap();
            assert!(matches!(native_exit, 0 | 0xc0000409));
            assert_eq!(block.contains("RETURN case="), native_exit == 0);
            let (mut process, mut thread) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
            let p = process.state_mut();
            super::super::system_processor_tests::kernel_profile(p, 0xaa64);
            let version = &mut p.native.as_mut().unwrap().version;
            version.major = 10;
            version.minor = 0;
            version.build = 29698;
            let setup = inputs::prepare(p, case);
            let committed = p.vm.committed_bytes();
            assert_eq!(enter(p, &mut thread, setup.args), Outcome::Continue);
            assert_eq!(
                thread.cpu.gpr(0),
                u64::from_str_radix(observed["status"], 16).unwrap(),
                "{arch}/{case}/status"
            );
            assert_eq!(
                p.space.u32(setup.buffers[3].1).unwrap(),
                u32::from_str_radix(observed["processed"], 16).unwrap(),
                "{arch}/{case}/processed"
            );
            assert_eq!(
                p.vm.valid_call_target(setup.target),
                native_exit == 0,
                "{arch}/{case}/target admission"
            );
            assert_eq!(p.vm.committed_bytes(), committed, "{arch}/{case}");
            comparisons += 1;
        }
        assert_eq!(cases.len(), 10);
    }
    assert_eq!(comparisons, 30);
}

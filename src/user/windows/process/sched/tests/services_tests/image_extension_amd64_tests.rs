//! Independent AMD64 native and WoW64 query bytes, guards, aliases and rights.
use super::*;
use crate::user::windows::object_namespace::ExtensionQuery;
use std::io::Read;
use std::sync::OnceLock;

fn corpus() -> &'static serde_json::Value {
    static DATA: OnceLock<serde_json::Value> = OnceLock::new();
    DATA.get_or_init(|| {
        let encoded = include_bytes!(
            "../../../../../../../docs/specifications/windows/native-image-extension-amd64/query-corpus-v1.json.zst"
        );
        let mut decoder = zstd::stream::read::Decoder::new(&encoded[..]).unwrap().take(96 << 20);
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes).unwrap();
        assert!(bytes.len() < (96 << 20), "native corpus exceeds its retained bound");
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["schema"], "native-image-extension-amd64-query-corpus-v1");
        assert_eq!(result["profiles"].as_array().unwrap().len(), 2);
        result
    })
}

fn profiles() -> impl Iterator<Item = (ExtensionQuery, &'static serde_json::Value)> {
    corpus()["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|profile| {
            let capture = &profile["capture"];
            assert_eq!(capture["state"], "finished");
            assert_eq!(capture["exit_code"], 0);
            assert_eq!(capture["samples"].as_array().unwrap().len(), 6);
            let availability = match capture["kernel"][2].as_u64().unwrap() {
                20348 => ExtensionQuery::Unavailable,
                26100 => ExtensionQuery::NativeOnly,
                _ => panic!("uncaptured independent kernel"),
            };
            (availability, capture)
        })
}

fn reports<'a>(capture: &'a serde_json::Value, kind: &str) -> Vec<(WinArch, &'a str)> {
    let mut result = Vec::new();
    for sample in capture["samples"].as_array().unwrap() {
        if sample["kind"] != kind {
            continue;
        }
        assert_eq!(sample["compile"]["exit_code"], 0);
        assert_eq!(sample["observation"]["exit_code"], 0);
        assert_eq!(sample["inputs_unchanged"], true);
        let arch = match sample["arch"].as_str().unwrap() {
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("uncaptured native process architecture"),
        };
        result.push((arch, sample["observation"]["stdout"].as_str().unwrap()));
    }
    assert_eq!(
        result.iter().map(|v| v.0).collect::<Vec<_>>(),
        [WinArch::X64, WinArch::X86]
    );
    result
}

#[test]
fn native_image_extension_amd64_query_matrix_replays_captured_availability() {
    let mut counts = (0, 0);
    for (availability, capture) in profiles() {
        let (replayed, present) =
            replay_query_profiles(&reports(capture, "query"), Some(availability));
        assert_eq!((replayed, present), (7140, 1260));
        counts.0 += replayed;
        counts.1 += present;
    }
    assert_eq!(counts, (14280, 2520));
}

#[test]
fn native_image_extension_amd64_type1_boundaries_replay_all_fault_and_copy_order() {
    let mut count = 0;
    for (availability, capture) in profiles() {
        let actual = replay_boundary_profiles(
            &reports(capture, "boundaries"),
            15480,
            Some(availability),
            1,
        );
        assert_eq!(actual, 30960);
        count += actual;
    }
    assert_eq!(count, 61920);
}

#[test]
fn native_image_extension_amd64_type1_limits_replay_without_extra_guard_consumption() {
    let mut count = 0;
    for (availability, capture) in profiles() {
        let actual =
            replay_boundary_profiles(&reports(capture, "limits"), 1092, Some(availability), 1);
        assert_eq!(actual, 2184);
        count += actual;
    }
    assert_eq!(count, 4368);
}

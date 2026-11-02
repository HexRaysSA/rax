//! Shared-key handle mechanics observed on the present System Software parent.
use super::*;

fn replay(corpus: &serde_json::Value) -> usize {
    let mut checked = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let wow = report["architecture"] == "x86";
        for hive in report["system-parent-graph"]["hives"].as_array().unwrap() {
            let states = hive["states"].as_array().unwrap();
            for edge in hive["edges"].as_array().unwrap() {
                let source = edge["source"].as_u64().unwrap() as usize;
                let parent = states[source]["tags"].as_u64().unwrap() as u32;
                let view = if parent == 0x100 {
                    RegistryView::Native64
                } else {
                    RegistryView::Wow32
                };
                let result =
                    command_reopen_tags(wow, parent, view, edge["view"].as_u64().unwrap() as u32);
                if edge["status"] == 0 {
                    let target = edge["target"].as_u64().unwrap() as usize;
                    assert_eq!(
                        result,
                        Some(states[target]["tags"].as_u64().unwrap() as u32)
                    );
                } else {
                    assert_eq!(edge["status"], STATUS_INVALID_PARAMETER);
                    assert_eq!(result, None);
                }
                checked += 1;
            }
        }
    }
    checked
}

#[test]
fn system_command_shared_key_reopen_profile_matches_all_native_parent_edges() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-command-processor/controls-system-v1.json"
    )))
    .unwrap();
    assert_eq!(replay(&corpus), 80);
    if let Some(path) = std::env::var_os("RAX_SYSTEM_COMMAND_PROCESSOR_CORPUS") {
        let fresh = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(replay(&fresh) >= 16);
    }
}

use super::*;
use std::collections::BTreeMap;

fn observations() -> BTreeMap<String, Vec<u8>> {
    let captured: BTreeMap<String, Vec<u32>> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-apphelp-cache/installed-executable-policy-29708-arm64.json"
    )))
    .unwrap();
    captured
        .into_iter()
        .map(|(file, words)| (file, words.into_iter().flat_map(u32::to_le_bytes).collect()))
        .collect()
}

fn returned(record: &[u8]) -> [u8; EXECUTABLE_REPLY_CAPACITY] {
    let mut storage = [0xa5; EXECUTABLE_REPLY_CAPACITY];
    storage[..record.len()].copy_from_slice(record);
    storage
}

#[test]
fn installed_apphelp_policy_accepts_stock_and_builtin_native_replies() {
    let captured = observations();
    assert_eq!(captured.len(), 8);
    let mut counts = [0, 0];
    for (name, record) in captured {
        let storage = returned(&record);
        let reply = ExecutableReply::capture(&storage, record.len())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(reply.as_bytes(), record, "{name}");
        counts[usize::from(record.len() == FULL_REPLY_BYTES)] += 1;
    }
    assert_eq!(counts, [2, 6]);
}

#[test]
fn installed_apphelp_policy_rejects_uncaptured_fields_and_writes() {
    let captured = observations();
    let policy = &captured["msiexec.exe"];
    let cases = [
        ("unexpected metadata", 16, 1),
        ("incorrect policy length", GROUP_BYTES + 4, 455),
        ("outside database size", HEADER_BYTES, 64 << 20),
        ("unaligned tag", HEADER_BYTES, 13),
        ("unexpected executable flags", HEADER_BYTES + EXE_FLAGS, 2),
        ("unused match slot", HEADER_BYTES + 8, 14),
        ("unmodeled layer", HEADER_BYTES + LAYERS, 1),
        ("too many matches", HEADER_BYTES + EXE_COUNT, 17),
        ("unexpected query flag", HEADER_BYTES + QUERY_FLAGS, 4),
        ("custom database", HEADER_BYTES + QUERY_FLAGS + 4, 3),
        ("unknown database ID", HEADER_BYTES + DATABASES, 0),
        ("additional database ID", HEADER_BYTES + DATABASES + 16, 1),
        ("write after end", FULL_REPLY_BYTES, 0),
    ];
    for (label, offset, value) in cases {
        let mut storage = returned(policy);
        storage[offset..offset + 4].copy_from_slice(&u32::to_le_bytes(value));
        assert!(
            ExecutableReply::capture(&storage, policy.len()).is_err(),
            "{label}"
        );
    }
    for size in [0, 63, 65, 519, 521, EXECUTABLE_REPLY_CAPACITY + 1] {
        assert!(ExecutableReply::capture(&returned(policy), size).is_err());
    }
}

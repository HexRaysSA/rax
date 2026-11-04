//! Replay kernel-produced records; fixture inputs come from a separate native
//! full-directory query, never from the encoder or enumerator under test.
use super::*;
use crate::user::windows::objects::DirectoryEntry;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

fn raw(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect()
}

fn inputs(rows: &[Value], snapshot: &str) -> Vec<DirectoryEntry> {
    let mut ids = HashMap::new();
    let mut short_names = HashMap::new();
    let bytes = raw(
        rows.iter().find(|row| row["id"] == "class-37").unwrap()["data"]
            .as_str()
            .unwrap(),
    );
    let mut at = 0;
    loop {
        let length = u32_at(&bytes, at + 60) as usize;
        ids.insert(
            units(&bytes[at + 104..at + 104 + length]),
            u64_at(&bytes, at + 96),
        );
        short_names.insert(
            units(&bytes[at + 104..at + 104 + length]),
            units(&bytes[at + 70..at + 70 + usize::from(bytes[at + 68])]),
        );
        let next = u32_at(&bytes, at) as usize;
        if next == 0 {
            break;
        }
        at += next;
    }
    let bytes = raw(
        rows.iter().find(|row| row["id"] == snapshot).unwrap()["data"]
            .as_str()
            .unwrap(),
    );
    let mut entries = Vec::new();
    let mut at = 0;
    loop {
        let length = u32_at(&bytes, at + 60) as usize;
        let name_offset = if snapshot == "class-1" { 64 } else { 68 };
        let name = units(&bytes[at + name_offset..at + name_offset + length]);
        entries.push(DirectoryEntry {
            file_id: ids[&name],
            short_name: short_names[&name].clone(),
            name,
            times: [
                u64_at(&bytes, at + 8),
                u64_at(&bytes, at + 16),
                u64_at(&bytes, at + 24),
                u64_at(&bytes, at + 32),
            ],
            size: u64_at(&bytes, at + 40),
            allocation: u64_at(&bytes, at + 48),
            attributes: u32_at(&bytes, at + 56),
            ea: None,
        });
        let next = u32_at(&bytes, at) as usize;
        if next == 0 {
            break;
        }
        at += next;
    }
    assert_eq!(entries.len(), 7);
    entries
}

fn group(id: &str) -> Option<String> {
    if id.starts_with("ea-directory-")
        || id.starts_with("rename-")
        || matches!(id, "metadata-only" | "regular-file")
    {
        return None;
    }
    if let Some(rest) = id.strip_prefix("after-length-") {
        return Some(format!("length-{rest}"));
    }
    if let Some(rest) = id.strip_prefix("overflow-next-") {
        return Some(format!("overflow-{rest}"));
    }
    if let Some(rest) = id.strip_prefix("restart-pattern-") {
        return Some(format!("pattern-{rest}"));
    }
    let pieces = id.split('-').collect::<Vec<_>>();
    Some(match pieces[0] {
        "class" | "length" | "minimum" | "overflow" => id.into(),
        "pattern" => pieces[..3].join("-"),
        "flags" | "nocursor" => pieces[..2].join("-"),
        "cursor" => format!(
            "cursor-{}-{}",
            pieces[1],
            if pieces[2] == "independent" {
                "independent"
            } else {
                "shared"
            }
        ),
        "restart" => format!("restart-{}-{}", pieces[2], pieces[3]),
        other => panic!("unclassified independent native control {other}/{id}"),
    })
}

#[test]
fn nt_directory_frozen_native_records_cursor_flags_and_partial_records_replay() {
    for text in [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-directory-enumeration/native-arm64-v5.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-directory-enumeration/native-x64-v5.json"
        )),
    ] {
        replay(text);
    }
}

fn replay(text: &str) {
    let corpus: Value = serde_json::from_str(text).unwrap();
    let rows = corpus["rows"].as_array().unwrap();
    let initial = inputs(rows, "class-1");
    // The first native scan changes the new directory's access timestamp.
    // Independently opened later scans capture the subsequent class-2 snapshot.
    // Only input metadata changes; every result byte remains an exact assertion.
    let subsequent = inputs(rows, "class-2");
    let mut scans = BTreeMap::new();
    let mut count = 0;
    let mut length_gates = 0;
    let mut other_gates = 0;
    for row in rows {
        let Some(id) = row["id"].as_str() else {
            continue;
        };
        let Some(key) = group(id) else {
            other_gates += 1;
            continue;
        };
        let class = row["class"].as_u64().unwrap() as u32;
        let length = row["length"].as_u64().unwrap() as usize;
        let layout = Layout::of(class).unwrap();
        if length < layout.minimum {
            assert_eq!(
                row["returned"].as_u64().unwrap(),
                u64::from(STATUS_INFO_LENGTH_MISMATCH)
            );
            length_gates += 1;
            continue;
        }
        let scan = scans.entry(key).or_insert_with(|| DirectoryScan {
            entries: if id == "class-1" {
                initial.clone()
            } else {
                subsequent.clone()
            },
            pattern: vec![42],
            cursor: 0,
            started: false,
        });
        let pattern = row["pattern_present"]
            .as_bool()
            .unwrap()
            .then(|| units(&raw(row["pattern_hex"].as_str().unwrap())));
        let request = Request {
            handle: 0,
            class,
            flags: row["flags"].as_u64().unwrap() as u32,
            pattern,
            bytes: vec![0xa5; length],
        };
        let completion = enumerate(scan, request).unwrap();
        assert_eq!(
            u64::from(completion.code),
            row["returned"].as_u64().unwrap(),
            "return/{id}"
        );
        let sentinel = 0xa5a5_a5a5_a5a5_a5a5u64;
        let io_status = row["io_status"].as_u64().unwrap();
        let information = row["information"].as_u64().unwrap();
        assert_eq!(
            completion.status,
            (io_status != sentinel).then_some(io_status as u32),
            "IOSB.Status/{id}"
        );
        assert_eq!(
            completion.information,
            (information != sentinel).then_some(information),
            "IOSB.Information/{id}"
        );
        assert_eq!(
            completion.bytes,
            raw(row["data"].as_str().unwrap()),
            "completed data and untouched tail/{id}"
        );
        count += 1;
    }
    // All337 queries are accounted for: minimum-length cases run through the
    // actual guest service test; metadata/EA/rename cases have dedicated tests.
    assert_eq!((count, length_gates, other_gates), (302, 28, 7));
}

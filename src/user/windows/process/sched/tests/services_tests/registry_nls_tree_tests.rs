//! Installed multi-key NLS records replayed through actual guest services.
use super::*;
use crate::user::windows::registry::{NLS_ROOT_KEY, nls_tests};
use std::collections::BTreeMap;
use std::io::Read;

fn replay(arch: WinArch, label: &str, encoded: &[u8]) {
    let mut text = String::new();
    zstd::stream::read::Decoder::new(encoded)
        .unwrap()
        .take(128 << 20)
        .read_to_string(&mut text)
        .unwrap();
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let finished = rows.last().unwrap();
    assert_eq!(finished["kind"], "finished");
    assert_eq!(finished["keys"], 48);
    let mut replayed = 0;
    for view in [0, 0x100, 0x200] {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        p.registry = nls_tests::empty()
            .with_nls_information_tree(nls_tests::fixture(label, view))
            .unwrap();
        let attrs = base + 2 * PAGE_SIZE;
        let mut handles = BTreeMap::new();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        for row in rows
            .iter()
            .filter(|row| row["kind"] == "key" && row["view"] == view)
        {
            let raw = nls_tests::bytes(row["path_utf16"].as_str().unwrap());
            let name = String::from_utf16(
                &raw.chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert!(name.starts_with(NLS_ROOT_KEY));
            unicode(p, attrs + 64, attrs + 256, &name);
            attributes(p, attrs, attrs + 64, 0, 0x40);
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    "NtOpenKey",
                    &[base, 0x20019 | u64::from(view), attrs]
                ),
                STATUS_SUCCESS,
                "{arch}/view{view:x}/{name}"
            );
            let original = p.space.ptr(base, arch.ptr_size()).unwrap();
            let duplicate = p.objects.duplicate(original, false).unwrap() as u64;
            assert_eq!(call(p, &mut thread, "NtClose", &[original]), STATUS_SUCCESS);
            assert!(
                handles
                    .insert(row["subject"].as_u64().unwrap(), duplicate)
                    .is_none()
            );
        }
        assert_eq!(handles.len(), 16);
        // Every query below must succeed solely from retained key objects.
        p.registry = Registry::default();
        for row in rows
            .iter()
            .filter(|row| row["kind"] == "case" && row["view"] == view)
        {
            let output = base + 128;
            let alias = row["alias"].as_i64().unwrap();
            let returned = if alias < 0 {
                base + 64
            } else {
                output + alias as u64
            };
            let actual = nls_tests::bytes(row["bytes"].as_str().unwrap());
            let poison = row["poison"].as_u64().unwrap() as u8;
            p.space.wr(output, &vec![poison; actual.len()]).unwrap();
            if alias < 0 {
                p.space.w32(returned, 0x7F7F_7F7F).unwrap();
            }
            let handle = handles[&row["subject"].as_u64().unwrap()];
            let status = call(
                p,
                &mut thread,
                "NtQueryKey",
                &[
                    handle,
                    row["class"].as_u64().unwrap(),
                    output,
                    row["length"].as_u64().unwrap(),
                    returned,
                ],
            );
            assert_eq!(
                u64::from(status),
                row["status"].as_u64().unwrap(),
                "{arch}/case{}",
                row["index"]
            );
            assert_eq!(
                p.space.bytes(output, actual.len()).unwrap(),
                actual,
                "{arch}/case{}",
                row["index"]
            );
            assert_eq!(
                u64::from(p.space.u32(returned).unwrap()),
                row["returned"].as_u64().unwrap(),
                "{arch}/case{}",
                row["index"]
            );
            replayed += 1;
        }
        for handle in handles.into_values() {
            assert_eq!(call(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
        }
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
    assert_eq!(replayed, finished["cases"].as_u64().unwrap());
}

#[test]
fn complete_nls_native_boundaries_and_result_aliases_survive_snapshot_drop_all_abis() {
    for (arch, label, corpus) in [
        (
            WinArch::Arm64,
            "arm64",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/nls-tree/arm64-v1.jsonl.zst"
            ))
            .as_slice(),
        ),
        (
            WinArch::X64,
            "x64",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/nls-tree/x64-v1.jsonl.zst"
            ))
            .as_slice(),
        ),
        (
            WinArch::X86,
            "x86",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/nls-tree/x86-v1.jsonl.zst"
            ))
            .as_slice(),
        ),
    ] {
        replay(arch, label, corpus);
    }
}

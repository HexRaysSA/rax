//! Complete standard protection matrix and allocation-wide private commitment.
use super::query::{bytes, hex};
use super::*;
macro_rules! corpus {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-file-data-section/validation/",
            $name
        ))
    };
}
fn region(p: &mut Proc, t: &mut Thread, b: u64, address: u64) -> Vec<u8> {
    p.space.wr(b + 1024, &[0xA5; 48]).unwrap();
    ptr(p, b + 1080, 0);
    assert_eq!(
        service(
            p,
            t,
            "NtQueryVirtualMemory",
            &[p.arch.ptr(u64::MAX), address, 3, b + 1024, 48, b + 1080]
        ),
        0
    );
    let mut bytes = p.space.bytes(b + 1024, 48).unwrap();
    bytes[..p.arch.ptr_size() as usize].fill(0);
    bytes
}

#[test]
fn native_file_data_transitions_replay_1560_native_view_rights_and_private_commit_cases() {
    let mut total = 0;
    for (arch, text, expected_count) in [
        (
            WinArch::Arm64,
            corpus!("native-transitions-arm64-v1.json"),
            448,
        ),
        (WinArch::X64, corpus!("native-transitions-x64-v1.json"), 448),
        (WinArch::X86, corpus!("native-transitions-x86-v1.json"), 448),
        (WinArch::Arm64, corpus!("native-details-arm64-v1.json"), 72),
        (WinArch::X64, corpus!("native-details-x64-v1.json"), 72),
        (WinArch::X86, corpus!("native-details-x86-v1.json"), 72),
    ] {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        let rows = data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["kind"] == "protect")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), expected_count);
        for row in rows {
            let file = FileCase::new(65537);
            let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let handle = file.insert(p, 0x001F01FF);
            let section = create(p, &mut thread, b, handle, hex(row, "section_protection"));
            let mapped = map(
                p,
                &mut thread,
                b,
                section,
                0x50000000,
                hex(row, "initial_protection"),
            );
            assert_eq!(mapped, hex(row, "map_status"), "{arch} row={row:?}");
            if mapped == 0 {
                if let Some(before) = row["before_region_hex"].as_str() {
                    assert_eq!(
                        region(p, &mut thread, b, 0x50000000),
                        bytes(before),
                        "{arch} row={row:?}"
                    );
                }
                ptr(p, b, 0x50000000);
                ptr(p, b + 16, 4096);
                p.space.w32(b + 32, 0xA5A5A5A5).unwrap();
                let changed = service(
                    p,
                    &mut thread,
                    "NtProtectVirtualMemory",
                    &[
                        arch.ptr(u64::MAX),
                        b,
                        b + 16,
                        hex(row, "protection").into(),
                        b + 32,
                    ],
                );
                assert_eq!(
                    changed == 0,
                    row["changed"].as_u64().unwrap() != 0,
                    "{arch} row={row:?}"
                );
                let error = if changed == 0 {
                    0
                } else {
                    crate::user::windows::nt::status_to_error(changed)
                };
                assert_eq!(
                    u64::from(error),
                    row["error"].as_u64().unwrap(),
                    "{arch} row={row:?}"
                );
                assert_eq!(p.space.u32(b + 32).unwrap(), hex(row, "old"));
                if changed == 0 {
                    let exception = if p.space.w8(0x50000000, 0x77).is_ok() {
                        0
                    } else {
                        STATUS_ACCESS_VIOLATION
                    };
                    assert_eq!(exception, hex(row, "write_exception"), "{arch} row={row:?}");
                }
                assert_eq!(
                    p.vm.query(0x50000000).unwrap().protect,
                    hex(row, "reported_protection")
                );
                if let Some(after) = row["after_region_hex"].as_str() {
                    assert_eq!(
                        region(p, &mut thread, b, 0x50000000),
                        bytes(after),
                        "{arch} row={row:?}"
                    );
                }
                assert_eq!(
                    service(
                        p,
                        &mut thread,
                        "NtUnmapViewOfSection",
                        &[arch.ptr(u64::MAX), 0x50000000]
                    ),
                    0
                );
            }
            total += 1;
        }
    }
    assert_eq!(total, 1560);
}

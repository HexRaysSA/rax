//! Replay independent query outputs, returned lengths, guards and handle grants.
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
pub(super) fn bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
pub(super) fn hex(row: &serde_json::Value, key: &str) -> u32 {
    u32::from_str_radix(row[key].as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

#[test]
fn native_file_data_queries_replay_5445_independent_outputs_and_fault_priorities() {
    let mut total = 0;
    for (arch, text, expected_count) in [
        (WinArch::Arm64, corpus!("native-query-arm64-v1.json"), 1584),
        (WinArch::X64, corpus!("native-query-x64-v1.json"), 1584),
        (WinArch::X86, corpus!("native-query-x86-v1.json"), 1584),
        (WinArch::Arm64, corpus!("native-details-arm64-v1.json"), 231),
        (WinArch::X64, corpus!("native-details-x64-v1.json"), 231),
        (WinArch::X86, corpus!("native-details-x86-v1.json"), 231),
    ] {
        let observations: serde_json::Value = serde_json::from_str(text).unwrap();
        let rows = observations["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["kind"] == "query")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), expected_count);
        let file = FileCase::new(65537);
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let b = scratch(p);
        let handle = file.insert(p, 0x001F01FF);
        let section = create(p, &mut thread, b, handle, 2);
        let id = p.objects.id(section).unwrap();
        let no_query = u64::from(p.objects.open_access(id, false, 4).unwrap());
        let event = u64::from(p.objects.insert(Object::Event {
            manual: false,
            signaled: 0,
        }));
        let handles = [section, no_query, 0, arch.ptr(u64::MAX), event];
        let mut differences = Vec::new();
        for row in rows {
            p.vm.protect(b, 4 * 4096, prot::READWRITE).unwrap();
            p.space.wr(b, &[0xA5; 4 * 4096]).unwrap();
            let mode = row["mode"].as_u64().unwrap();
            let mut output = b;
            let mut returned = b + 4096;
            match mode {
                0 => {}
                1 => output = 0,
                2 => output = 1,
                3 => {
                    p.vm.protect(b, 4096, prot::NOACCESS).unwrap();
                }
                4 => {
                    p.vm.protect(b, 4096, prot::READONLY).unwrap();
                }
                5 => {
                    p.vm.protect(b, 4096, prot::READWRITE | prot::GUARD)
                        .unwrap();
                }
                6 => output = b + 1,
                7 => returned = 0,
                8 => returned = 1,
                9 => {
                    p.vm.protect(b + 4096, 4096, prot::READONLY).unwrap();
                }
                10 => {
                    p.vm.protect(b + 4096, 4096, prot::READWRITE | prot::GUARD)
                        .unwrap();
                }
                11 => output = b + 4,
                12 => returned = b + 4097,
                13 => returned = b + 4100,
                _ => panic!("unrecorded query recipe"),
            }
            let role = row["handle_role"].as_u64().unwrap_or(0) as usize;
            let status = service(
                p,
                &mut thread,
                "NtQuerySection",
                &[
                    handles[role],
                    row["class"].as_u64().unwrap(),
                    output,
                    row["bytes"].as_u64().unwrap(),
                    returned,
                ],
            );
            let actual_pages = (
                p.vm.query(b).unwrap().protect,
                p.vm.query(b + 4096).unwrap().protect,
            );
            p.vm.protect(b, 4 * 4096, prot::READWRITE).unwrap();
            let actual_data = p.space.bytes(b, 40).unwrap();
            let actual_return = p.space.bytes(b + 4096, arch.ptr_size() as usize).unwrap();
            let expected = (
                hex(row, "status"),
                (hex(row, "data_page"), hex(row, "return_page")),
                bytes(row["data_hex"].as_str().unwrap()),
                bytes(row["return_hex"].as_str().unwrap()),
            );
            if (status, actual_pages, &actual_data, &actual_return)
                != (expected.0, expected.1, &expected.2, &expected.3)
            {
                differences.push(format!("{arch} row={} role={role} class={} mode={mode} bytes={}: status={status:X}/{:X}, pages={actual_pages:X?}/{:X?}, data={actual_data:02X?}/{:02X?}, returned={actual_return:02X?}/{:02X?}",row["index"],row["class"],row["bytes"],expected.0,expected.1,expected.2,expected.3));
            }
            assert_eq!(hex(row, "exception"), 0);
            total += 1;
        }
        assert!(
            differences.is_empty(),
            "{} query differences: {:#?}",
            differences.len(),
            &differences[..differences.len().min(20)]
        );
    }
    assert_eq!(total, 5445);
}

#[test]
fn native_file_data_status_conversion_matches_all_18_native_rtl_observations() {
    let mut count = 0;
    for text in [
        corpus!("native-status-arm64-v1.json"),
        corpus!("native-status-x64-v1.json"),
        corpus!("native-status-x86-v1.json"),
    ] {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        for row in data["cases"].as_array().unwrap() {
            assert_eq!(
                crate::user::windows::nt::status_to_error(hex(row, "status")),
                row["error"].as_u64().unwrap() as u32
            );
            count += 1;
        }
    }
    assert_eq!(count, 18);
}

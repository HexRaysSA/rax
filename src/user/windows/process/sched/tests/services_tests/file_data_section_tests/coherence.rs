//! Replay independent live-byte, file-growth and post-close deletion phases.
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
fn value(text: &serde_json::Value) -> u32 {
    u32::from_str_radix(text.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}
fn phase(p: &Proc, views: &[Option<u64>; 4], row: &serde_json::Value, ordinal: usize) {
    let actual = views.map(|at| at.map_or(u32::MAX, |at| u32::from(p.space.u8(at).unwrap())));
    let expected = row["phases"][ordinal]
        .as_array()
        .unwrap()
        .iter()
        .map(value)
        .collect::<Vec<_>>();
    assert_eq!(actual.as_slice(), expected, "phase={ordinal} row={row:?}");
}
fn file_value(file: &mut FileCase, row: &serde_json::Value, ordinal: usize) {
    assert_eq!(
        u32::from(file.read(0)),
        value(&row["file_values"][ordinal]),
        "row={row:?}"
    );
}

#[test]
fn native_file_data_coherence_replays_all_135_independent_growth_and_lifetime_cases() {
    let mut total = 0;
    for (arch, text) in [
        (WinArch::Arm64, corpus!("native-coherence-arm64-v1.json")),
        (WinArch::X64, corpus!("native-coherence-x64-v1.json")),
        (WinArch::X86, corpus!("native-coherence-x86-v1.json")),
    ] {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(data["cases"].as_array().unwrap().len(), 45);
        for row in data["cases"].as_array().unwrap() {
            let mut file = FileCase::new(row["file_size"].as_u64().unwrap());
            let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let baseline = p.objects.handle_count();
            let handle = file.insert(p, 0x001F01FF);
            let a = create(p, &mut thread, b, handle, hex(row, "section_protection"));
            let other = create(p, &mut thread, b, handle, hex(row, "section_protection"));
            assert_eq!(hex(row, "create_a"), 0);
            assert_eq!(hex(row, "create_b"), 0);
            let mut views = [None; 4];
            for (i, view) in views.iter_mut().enumerate() {
                let at = 0x50000000 + i as u64 * 0x20000;
                let status = map(
                    p,
                    &mut thread,
                    b,
                    if i == 2 { other } else { a },
                    at,
                    if i == 3 {
                        8
                    } else {
                        hex(row, "view_protection")
                    },
                );
                assert_eq!(status, value(&row["map_statuses"][i]), "{arch} row={row:?}");
                if status == 0 {
                    assert_eq!(get(p, b + 16), row["view_sizes"][i].as_u64().unwrap());
                    *view = Some(at);
                }
            }
            phase(p, &views, row, 0);
            file_value(&mut file, row, 0);
            file.write(0, 0x22);
            phase(p, &views, row, 1);
            file_value(&mut file, row, 1);
            let exception = views[0].map_or(u32::MAX, |at| {
                if p.space.w8(at, 0x33).is_ok() {
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            });
            assert_eq!(exception, hex(row, "write_exception"));
            phase(p, &views, row, 2);
            file_value(&mut file, row, 2);
            p.space.w8(views[3].unwrap(), 0x44).unwrap();
            assert_eq!(hex(row, "cow_exception"), 0);
            phase(p, &views, row, 3);
            file_value(&mut file, row, 3);
            file.write(0, 0x55);
            phase(p, &views, row, 4);
            file_value(&mut file, row, 4);
            let growth = if row["grow"] == 1 {
                file.write(65536, 0x66);
                let section = create(p, &mut thread, b, handle, 2);
                assert_eq!(hex(row, "growth_create"), 0);
                p.space.wr(b + 256, &[0xA5; 24]).unwrap();
                assert_eq!(
                    service(
                        p,
                        &mut thread,
                        "NtQuerySection",
                        &[section, 0, b + 256, 24, b + 320]
                    ),
                    hex(row, "growth_query")
                );
                assert_eq!(
                    p.space.bytes(b + 256, 24).unwrap(),
                    bytes(row["growth_basic_hex"].as_str().unwrap())
                );
                let address = 0x50100000;
                assert_eq!(
                    map(p, &mut thread, b, section, address, 2),
                    hex(row, "growth_map")
                );
                assert_eq!(get(p, b + 16), row["growth_size"].as_u64().unwrap());
                assert_eq!(
                    u32::from(p.space.u8(address).unwrap()),
                    hex(row, "growth_first")
                );
                assert_eq!(
                    u32::from(p.space.u8(address + 65536).unwrap()),
                    hex(row, "growth_last")
                );
                p.objects.close(section).unwrap();
                Some(address)
            } else {
                None
            };
            assert_eq!(
                file.writer.as_ref().unwrap().metadata().unwrap().len(),
                row["file_size_after"].as_u64().unwrap()
            );
            p.objects.close(handle).unwrap();
            p.objects.close(a).unwrap();
            p.objects.close(other).unwrap();
            drop(file.writer.take());
            phase(p, &views, row, 5);
            std::fs::remove_file(&file.path).unwrap();
            file.deleted = true;
            assert_eq!(row["delete_with_live_views"], 1);
            assert_eq!(row["delete_error"], 0);
            phase(p, &views, row, 6);
            for (i, at) in views.into_iter().enumerate() {
                let status = at.map_or(0xDEADBEEF, |at| {
                    service(
                        p,
                        &mut thread,
                        "NtUnmapViewOfSection",
                        &[arch.ptr(u64::MAX), at],
                    )
                });
                assert_eq!(status, value(&row["unmap_statuses"][i]));
            }
            if let Some(at) = growth {
                assert_eq!(
                    service(
                        p,
                        &mut thread,
                        "NtUnmapViewOfSection",
                        &[arch.ptr(u64::MAX), at]
                    ),
                    0
                );
            }
            assert_eq!(file.path.exists(), row["exists_after_unmap"] == 1);
            assert_eq!(p.objects.handle_count(), baseline);
            assert_eq!(p.space.attached_extents(), 0);
            // The native x86 process-wide +5 handle observation remains
            // unattributed. Product-owned guest handles are checked directly.
            total += 1;
        }
    }
    assert_eq!(total, 135);
}

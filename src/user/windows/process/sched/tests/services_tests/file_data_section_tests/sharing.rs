//! A closed file open no longer reserves its share mask through mapped views.
use super::query::hex;
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

#[test]
fn native_file_data_sharing_replays_all_405_closed_file_section_and_view_lifetimes() {
    let mut total = 0;
    for (arch, text) in [
        (WinArch::Arm64, corpus!("native-share-arm64-v1.json")),
        (WinArch::X64, corpus!("native-share-x64-v1.json")),
        (WinArch::X86, corpus!("native-share-x86-v1.json")),
    ] {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(data["cases"].as_array().unwrap().len(), 135);
        for row in data["cases"].as_array().unwrap() {
            let mut file = FileCase::with_share(4096, hex(row, "original_share"));
            let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let handle = file.insert(p, 0x001F01FF);
            let section = create(p, &mut thread, b, handle, hex(row, "section_protection"));
            assert_eq!(hex(row, "create_status"), 0);
            let stage = row["stage"].as_u64().unwrap();
            if stage != 0 {
                assert_eq!(
                    map(p, &mut thread, b, section, 0x50000000, 2),
                    hex(row, "map_status")
                );
            }
            p.objects.close(handle).unwrap();
            drop(file.writer.take());
            if stage == 2 {
                p.objects.close(section).unwrap();
            }
            let access = hex(row, "next_access");
            let mut options = OpenOptions::new();
            options
                .read(access & 0x80000000 != 0)
                .write(access & 0x40000000 != 0);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.access_mode(access).share_mode(7);
            }
            let reopened = options.open(&file.path);
            assert_eq!(
                reopened.is_ok(),
                row["reopened"] == 1,
                "{arch} row={row:?}: {reopened:?}"
            );
            if let Err(error) = &reopened {
                assert_eq!(
                    error.raw_os_error().map(|v| v as u32),
                    Some(row["error"].as_u64().unwrap() as u32)
                );
            }
            drop(reopened);
            if stage != 0 {
                assert_eq!(
                    u32::from(p.space.u8(0x50000000).unwrap()),
                    hex(row, "view_byte")
                );
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
            if stage != 2 {
                p.objects.close(section).unwrap();
            }
            assert_eq!(p.space.attached_extents(), 0);
            total += 1;
        }
    }
    assert_eq!(total, 405);
}

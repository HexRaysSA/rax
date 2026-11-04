//! Old protection and persistent private bytes after an actual first store.
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

fn protect(p: &mut Proc, t: &mut Thread, b: u64, page: u32) -> (u32, u32) {
    ptr(p, b, 0x50000000);
    ptr(p, b + 16, 4096);
    p.space.w32(b + 32, 0xA5A5A5A5).unwrap();
    let status = service(
        p,
        t,
        "NtProtectVirtualMemory",
        &[p.arch.ptr(u64::MAX), b, b + 16, page.into(), b + 32],
    );
    (status, p.space.u32(b + 32).unwrap())
}

#[test]
fn native_file_data_post_copy_replays_all_216_native_old_protections_and_bytes() {
    let mut total = 0;
    for (arch, text) in [
        (WinArch::Arm64, corpus!("native-post-copy-arm64-v1.json")),
        (WinArch::X64, corpus!("native-post-copy-x64-v1.json")),
        (WinArch::X86, corpus!("native-post-copy-x86-v1.json")),
    ] {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(data["cases"].as_array().unwrap().len(), 72);
        for row in data["cases"].as_array().unwrap() {
            let mut file = FileCase::new(4096);
            let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let handle = file.insert(p, 0x001F01FF);
            let section = create(p, &mut thread, b, handle, hex(row, "section_protection"));
            assert_eq!(hex(row, "create_status"), 0);
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
                assert_eq!(
                    protect(p, &mut thread, b, 8),
                    (hex(row, "copy_status"), hex(row, "copy_old"))
                );
                p.space.w8(0x50000000, 0x33).unwrap();
                assert_eq!(
                    p.vm.query(0x50000000).unwrap().protect,
                    hex(row, "before_protection")
                );
                assert_eq!(
                    protect(p, &mut thread, b, hex(row, "protection")),
                    (hex(row, "protect_status"), hex(row, "old")),
                    "{arch} row={row:?}"
                );
                assert_eq!(
                    p.vm.query(0x50000000).unwrap().protect,
                    hex(row, "after_protection")
                );
                let status = service(
                    p,
                    &mut thread,
                    "NtReadVirtualMemory",
                    &[arch.ptr(u64::MAX), 0x50000000, b + 512, 1, b + 528],
                );
                let value = if status == 0 {
                    u32::from(p.space.u8(b + 512).unwrap())
                } else {
                    0xFFFFFFFE
                };
                assert_eq!(value, hex(row, "view_byte"));
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
            assert_eq!(u32::from(file.read(0)), hex(row, "file_byte"));
            total += 1;
        }
    }
    assert_eq!(total, 216);
}

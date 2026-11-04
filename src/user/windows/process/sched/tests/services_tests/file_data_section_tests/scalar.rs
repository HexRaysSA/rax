//! Native constructor, query, view and file-effect vectors over identical files.
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

fn kernel_read(p: &mut Proc, t: &mut Thread, b: u64, address: u64) -> Vec<u8> {
    p.space.wr(b + 512, &[0xA5; 8]).unwrap();
    ptr(p, b + 528, 0);
    assert_eq!(
        service(
            p,
            t,
            "NtReadVirtualMemory",
            &[p.arch.ptr(u64::MAX), address, b + 512, 8, b + 528]
        ),
        0
    );
    assert_eq!(get(p, b + 528), 8);
    p.space.bytes(b + 512, 8).unwrap()
}

#[test]
fn native_file_data_scalar_replays_3402_native_creation_query_view_and_file_effect_cases() {
    let mut counts = (0, 0);
    for (arch, text) in [
        (WinArch::Arm64, corpus!("native-scalar-arm64-v1.json")),
        (WinArch::X64, corpus!("native-scalar-x64-v1.json")),
        (WinArch::X86, corpus!("native-scalar-x86-v1.json")),
    ] {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        let rows = data["cases"].as_array().unwrap();
        assert_eq!(rows.len(), 1134);
        for row in rows {
            let size = row["file_size"].as_u64().unwrap();
            let mut file = FileCase::new(size);
            let pattern: Vec<u8> = (0..size)
                .map(|i| 0x11u8.wrapping_add((i as u8).wrapping_mul(13)))
                .collect();
            file.writer
                .as_mut()
                .unwrap()
                .seek(SeekFrom::Start(0))
                .unwrap();
            file.writer.as_mut().unwrap().write_all(&pattern).unwrap();
            let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let grants = [
                0x80000000, 0xC0000000, 0, 0x20000000, 0xA0000000, 0x10000000,
            ];
            let handle = file.insert(p, grants[row["file_mode"].as_u64().unwrap() as usize]);
            let maximum_mode = row["maximum_mode"].as_u64().unwrap() as usize;
            let maxima = [0, 0, 1, 4095, 4096, 65536, u64::MAX];
            p.space.w64(b + 64, maxima[maximum_mode]).unwrap();
            ptr(p, b, 0xA5A5A5A5);
            let protection = hex(row, "protection");
            let attributes = hex(row, "attributes");
            let outcome = invoke(
                p,
                &mut thread,
                &[
                    b,
                    0xF001F,
                    0,
                    if maximum_mode == 0 { 0 } else { b + 64 },
                    protection.into(),
                    attributes.into(),
                    handle,
                ],
            );
            if let Outcome::Fail(reason) = outcome {
                assert!(
                    attributes & 0x00680000 != 0 && reason.contains("based, 64K-page or no-change"),
                    "{arch} row={row:?}: {reason}"
                );
                assert_eq!(
                    file.writer.as_ref().unwrap().metadata().unwrap().len(),
                    size
                );
                counts.1 += 1;
                continue;
            }
            assert_eq!(outcome, Outcome::Continue, "{arch} row={row:?}");
            assert_eq!(
                thread.cpu.gpr(0) as u32,
                hex(row, "status"),
                "{arch} row={row:?}"
            );
            assert_eq!(
                file.writer.as_ref().unwrap().metadata().unwrap().len(),
                row["size_after_create"].as_u64().unwrap()
            );
            let section = get(p, b);
            let valid = p.objects.get(section).is_some();
            assert_eq!(valid, row["handle_valid"].as_u64().unwrap() != 0);
            if valid {
                p.space.wr(b + 128, &[0xA5; 24]).unwrap();
                ptr(p, b + 160, 0xA5A5A5A5);
                assert_eq!(
                    service(
                        p,
                        &mut thread,
                        "NtQuerySection",
                        &[section, 0, b + 128, 24, b + 160]
                    ),
                    hex(row, "section_basic_status")
                );
                assert_eq!(
                    p.space.bytes(b + 128, 24).unwrap(),
                    bytes(row["section_basic_hex"].as_str().unwrap())
                );
                assert_eq!(
                    get(p, b + 160),
                    row["section_basic_return_bytes"].as_u64().unwrap()
                );
                let native_object = bytes(row["object_basic_hex"].as_str().unwrap());
                assert_eq!(
                    p.objects.access(section).unwrap(),
                    u32::from_le_bytes(native_object[4..8].try_into().unwrap())
                );
                p.space.wr(b + 256, &[0xA5; 64]).unwrap();
                ptr(p, b + 320, 0xA5A5A5A5);
                assert_eq!(
                    service(
                        p,
                        &mut thread,
                        "NtQuerySection",
                        &[section, 1, b + 256, 64, b + 320]
                    ),
                    hex(row, "image_status")
                );
                assert_eq!(get(p, b + 320), row["image_return_bytes"].as_u64().unwrap());
                assert_eq!(
                    map(p, &mut thread, b, section, 0, protection),
                    hex(row, "map_status")
                );
                if row["mapped"].as_u64().unwrap() != 0 {
                    let address = get(p, b);
                    let mapped_size = get(p, b + 16);
                    assert_eq!(mapped_size, row["view_size"].as_u64().unwrap());
                    let region = p.vm.query(address).unwrap();
                    assert_eq!(
                        (
                            region.protect,
                            region.allocation_protect,
                            region.state,
                            region.kind,
                            region.size
                        ),
                        (
                            hex(row, "region_protection"),
                            hex(row, "region_allocation_protection"),
                            hex(row, "region_state"),
                            hex(row, "region_type"),
                            row["region_size"].as_u64().unwrap()
                        )
                    );
                    if row["read_bytes"].as_u64().unwrap() == 8 {
                        assert_eq!(
                            kernel_read(p, &mut thread, b, address),
                            bytes(row["first_hex"].as_str().unwrap())
                        );
                    }
                    if row["tail_bytes"].as_u64().unwrap() == 8 {
                        assert_eq!(
                            kernel_read(p, &mut thread, b, address + mapped_size - 8),
                            bytes(row["tail_hex"].as_str().unwrap())
                        );
                    }
                    assert_eq!(
                        service(
                            p,
                            &mut thread,
                            "NtUnmapViewOfSection",
                            &[arch.ptr(u64::MAX), address]
                        ),
                        hex(row, "unmap_status")
                    );
                }
                p.objects.close(section).unwrap();
            }
            assert_eq!(
                file.writer.as_ref().unwrap().metadata().unwrap().len(),
                row["size_after_map"].as_u64().unwrap()
            );
            counts.0 += 1;
        }
    }
    assert_eq!(counts.0 + counts.1, 3402);
    println!(
        "Native data scalar replay: {} matched, {} explicit based/no-change policy boundaries",
        counts.0, counts.1
    );
}

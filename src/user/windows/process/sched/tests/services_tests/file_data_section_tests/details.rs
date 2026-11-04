//! Native pointer capture and file-view geometry, including failed copy-back.
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
fn observations() -> [(WinArch, &'static str); 3] {
    [
        (WinArch::Arm64, corpus!("native-details-arm64-v1.json")),
        (WinArch::X64, corpus!("native-details-x64-v1.json")),
        (WinArch::X86, corpus!("native-details-x86-v1.json")),
    ]
}
fn word(text: &str) -> u64 {
    let data = bytes(text);
    let mut value = [0; 8];
    value[..data.len()].copy_from_slice(&data);
    u64::from_le_bytes(value)
}
fn reset(p: &mut Proc, b: u64) {
    p.vm.protect(b, 4 * 4096, prot::READWRITE).unwrap();
    p.space.wr(b, &[0xA5; 4 * 4096]).unwrap();
}
fn permission(p: &mut Proc, b: u64, page: u64, protection: u32) {
    p.vm.protect(b + page * 4096, 4096, protection).unwrap();
}

#[test]
fn native_file_data_constructor_replays_4032_independent_pointer_and_guard_cases() {
    let mut count = 0;
    for (arch, text) in observations() {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        let file = FileCase::new(65537);
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let b = scratch(p);
        let handles = [file.insert(p, 0x80000000), file.insert(p, 0xC0000000)];
        let baseline = p.objects.handle_count();
        let mut differences = Vec::new();
        for row in data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "create_pointer")
        {
            reset(p, b);
            let out_mode = row["out_mode"].as_u64().unwrap();
            let max_mode = row["maximum_mode"].as_u64().unwrap();
            let oa_mode = row["oa_mode"].as_u64().unwrap();
            let (mut output, mut maximum, mut object) = (b, b + 4096, b + 8192);
            p.space
                .w64(
                    maximum,
                    if max_mode == 2 {
                        1
                    } else if max_mode == 3 {
                        u64::MAX
                    } else {
                        0
                    },
                )
                .unwrap();
            p.space.wr(object, &[0; 48]).unwrap();
            p.space
                .w32(object, if arch == WinArch::X86 { 24 } else { 48 })
                .unwrap();
            match out_mode {
                0 => {}
                1 => output = 0,
                2 => output = 1,
                3 => permission(p, b, 0, prot::NOACCESS),
                4 => permission(p, b, 0, prot::READONLY),
                5 => permission(p, b, 0, prot::READWRITE | prot::GUARD),
                6 => output = b + 1,
                _ => unreachable!(),
            }
            match max_mode {
                0 => maximum = 0,
                1..=3 => {}
                4 => maximum = 1,
                5 => maximum = b + 4097,
                6 => permission(p, b, 1, prot::NOACCESS),
                7 => permission(p, b, 1, prot::READWRITE | prot::GUARD),
                _ => unreachable!(),
            }
            match oa_mode {
                0 => object = 0,
                1 => {}
                2 => p.space.w32(object, 0).unwrap(),
                3 => object = 1,
                4 => permission(p, b, 2, prot::READWRITE | prot::GUARD),
                5 => permission(p, b, 2, prot::READONLY),
                _ => unreachable!(),
            }
            let status = service(
                p,
                &mut thread,
                "NtCreateSection",
                &[
                    output,
                    0xF001F,
                    object,
                    maximum,
                    hex(row, "protection").into(),
                    0x08000000,
                    handles[row["file_mode"].as_u64().unwrap() as usize],
                ],
            );
            let pages = [0, 1, 2].map(|page| p.vm.query(b + page * 4096).unwrap().protect);
            p.vm.protect(b, 4 * 4096, prot::READWRITE).unwrap();
            let handle = if matches!(out_mode, 1 | 2) {
                0
            } else {
                get(p, output)
            };
            let valid = p.objects.get(handle).is_some();
            if valid {
                p.objects.close(handle).unwrap();
            }
            let expected_pages = [
                hex(row, "out_page"),
                hex(row, "maximum_page"),
                hex(row, "oa_page"),
            ];
            let maximum_after = p.space.bytes(b + 4096, 8).unwrap();
            if status != hex(row, "status")
                || pages != expected_pages
                || valid != (row["handle_valid"].as_u64().unwrap() != 0)
                || maximum_after != bytes(row["maximum_after_hex"].as_str().unwrap())
                || p.objects.handle_count() != baseline
            {
                differences.push(format!("{arch} row={} out={out_mode} max={max_mode} oa={oa_mode}: status={status:X}/{:X}, pages={pages:X?}/{expected_pages:X?}, valid={valid}, handles={}/{baseline}",row["index"],hex(row,"status"),p.objects.handle_count()));
            }
            count += 1;
        }
        assert!(
            differences.is_empty(),
            "{} constructor differences: {:#?}",
            differences.len(),
            &differences[..differences.len().min(20)]
        );
    }
    assert_eq!(count, 4032);
}

#[test]
fn native_file_data_maps_replay_909_independent_geometry_and_copyback_cases() {
    let mut count = 0;
    let mut differences = Vec::new();
    for (arch, text) in observations() {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        for row in data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "map")
        {
            let file = FileCase::new(65537);
            let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
            let p = process.state_mut();
            // Keep the native probe's explicitly requested low address free.
            let b =
                p.vm.allocate(
                    Some(0x30000000),
                    4 * 4096,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
            let handle = file.insert(p, 0x001F01FF);
            let section = create(p, &mut thread, b, handle, hex(row, "section_protection"));
            reset(p, b);
            let (mut bp, mut sp, mut op) = (b, b + 4096, b + 8192);
            ptr(p, b, 0);
            ptr(p, b + 4096, 0);
            p.space.w64(b + 8192, 0).unwrap();
            let value = word(row["value_hex"].as_str().unwrap());
            let category = row["category"].as_u64().unwrap();
            let (mut zero, mut commit, mut inherit, mut flags) = (0, 0, 2, 0);
            match category {
                0 => {}
                1 => ptr(p, sp, value),
                2 => p.space.w64(op, value).unwrap(),
                3 => zero = value,
                4 => commit = value,
                5 => inherit = value,
                6 => flags = value,
                7 => {
                    // Native's free minimum slot is occupied by this process
                    // fixture's bootstrap. Keep this successful-placement case
                    // free and aligned; the minimum is exercised on an empty VM.
                    let base = if value == 0x10000 && !p.vm.is_free(value, 69632) {
                        p.vm.find_free(69632, 65536, p.vm.low(), p.vm.high(), false)
                            .unwrap()
                    } else {
                        value
                    };
                    ptr(p, bp, base);
                }
                8 => match value {
                    0 => {}
                    1 => bp = 0,
                    2 => bp = 1,
                    3 => permission(p, b, 0, prot::NOACCESS),
                    4 => permission(p, b, 0, prot::READONLY),
                    5 => permission(p, b, 0, prot::READWRITE | prot::GUARD),
                    6 => sp = 0,
                    7 => sp = 1,
                    8 => permission(p, b, 1, prot::NOACCESS),
                    9 => permission(p, b, 1, prot::READONLY),
                    10 => permission(p, b, 1, prot::READWRITE | prot::GUARD),
                    11 => op = 1,
                    12 => op = b + 8193,
                    13 => permission(p, b, 2, prot::NOACCESS),
                    14 => permission(p, b, 2, prot::READONLY),
                    15 => permission(p, b, 2, prot::READWRITE | prot::GUARD),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            }
            let status = service(
                p,
                &mut thread,
                "NtMapViewOfSection",
                &[
                    section,
                    arch.ptr(u64::MAX),
                    bp,
                    zero,
                    commit,
                    op,
                    sp,
                    inherit,
                    flags,
                    hex(row, "protection").into(),
                ],
            );
            let pages = [0, 1, 2].map(|page| p.vm.query(b + page * 4096).unwrap().protect);
            p.vm.protect(b, 4 * 4096, prot::READWRITE).unwrap();
            let actual_size = if matches!(sp, 0 | 1) { 0 } else { get(p, sp) };
            let actual_offset = if op == 1 { 0 } else { p.space.u64(op).unwrap() };
            let address = if matches!(bp, 0 | 1) { 0 } else { get(p, bp) };
            let expected_pages = [
                hex(row, "base_page"),
                hex(row, "size_page"),
                hex(row, "offset_page"),
            ];
            if status != hex(row, "status")
                || pages != expected_pages
                || actual_size != word(row["size_hex"].as_str().unwrap())
                || actual_offset != word(row["offset_hex"].as_str().unwrap())
                || (address == 0) != (row["base_null"].as_u64().unwrap() != 0)
            {
                differences.push(format!("{arch} row={} category={category} value={value:X}: status={status:X}/{:X}, pages={pages:X?}/{expected_pages:X?}, size={actual_size:X}, offset={actual_offset:X}, base_null={}",row["index"],hex(row,"status"),address==0));
            }
            if status == 0 && address != 0 {
                let region = p.vm.query(address).unwrap();
                assert_eq!(
                    (
                        region.protect,
                        region.allocation_protect,
                        region.kind,
                        region.state,
                        region.size
                    ),
                    (
                        hex(row, "region_protection"),
                        hex(row, "region_allocation_protection"),
                        hex(row, "region_type"),
                        hex(row, "region_state"),
                        row["region_size"].as_u64().unwrap()
                    ),
                    "{arch} row={row:?}"
                );
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
            count += 1;
        }
    }
    assert!(
        differences.is_empty(),
        "{} map differences: {:#?}",
        differences.len(),
        &differences[..differences.len().min(30)]
    );
    assert_eq!(count, 909);
}

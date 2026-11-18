//! Native file-backed image metadata controls and immutable guest copy-back.
use super::*;
use crate::user::windows::object_namespace::file_image::SectionImageInformation;
use crate::user::windows::object_namespace::{ImageTemplate, image_tests};

#[derive(serde::Deserialize)]
struct NativeControls {
    rows: Vec<NativeImage>,
}

#[derive(serde::Deserialize)]
struct NativeImage {
    entry_rva: u32,
    image_extent: usize,
    observations: Vec<NativeObservation>,
}

#[derive(serde::Deserialize)]
struct NativeObservation {
    flags: u32,
    access: u32,
    size: u64,
    status: u32,
    returned: u64,
    unchanged: bool,
    layout: Option<NativeLayout>,
}

#[derive(serde::Deserialize)]
struct NativeLayout {
    no_write_after_record: bool,
    normalized_record: String,
}

fn controls() -> NativeControls {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-file-section/image-information-29708-arm64.json"
    )))
    .unwrap()
}

#[test]
fn section_image_query_rebases_both_native_records_to_the_guest_entry() {
    let native = controls();
    assert_eq!(native.rows.len(), 2);
    for row in native.rows {
        let image = image_tests::template_sized(0x7000_0000, row.image_extent);
        let mut bytes = image.bytes.to_vec();
        bytes[168..172].copy_from_slice(&row.entry_rva.to_le_bytes());
        let image = ImageTemplate::selected(bytes, image.regions.clone()).unwrap();
        assert_eq!(image.entry_rva(), u64::from(row.entry_rva));
        for layout in row
            .observations
            .iter()
            .filter_map(|row| row.layout.as_ref())
        {
            assert!(layout.no_write_after_record);
            let mut record = [0; 64];
            let demonstrative_host_address = 0x7ffe_1234_0000_u64 + image.entry_rva();
            record[..8].copy_from_slice(&demonstrative_host_address.to_le_bytes());
            for (byte, pair) in record[8..]
                .iter_mut()
                .zip(layout.normalized_record.as_bytes().chunks_exact(2))
            {
                *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
            assert_eq!(layout.normalized_record.len(), 112);
            let info = SectionImageInformation::capture(&image, record).unwrap();
            let entry = image.preferred + image.entry_rva();
            assert_eq!(&info.bytes()[..8], &entry.to_le_bytes());
            assert_eq!(&info.bytes()[8..], &record[8..]);
        }
    }
}

#[test]
fn section_image_query_copies_selected_metadata_and_native_access_results() {
    let controls = controls();
    for arch in [WinArch::Arm64, WinArch::X64] {
        let directory = Directory::new();
        let path = directory.0.join("fixture.exe");
        let data = image(arch);
        let parsed = PeImage::parse(data).unwrap();
        let headers = parsed.headers();
        std::fs::write(&path, data).unwrap();
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let file = insert_file(p, &path, 0x1000A1);
        let output = scratch(p);
        let handles = [0x01000000, 0x11000000].map(|flags| {
            assert_eq!(
                call(p, &mut thread, &[output, 5, 0, 0, 2, flags.into(), file]),
                STATUS_SUCCESS
            );
            let full = get(p, output);
            let id = p.objects.id(full).unwrap();
            let denied = u64::from(p.objects.open_access(id, false, 4).unwrap());
            (flags, full, denied)
        });
        p.objects.close(file).unwrap();
        p.modules.nt_services = Some((
            p.modules.nt_services.as_ref().unwrap().0,
            table(arch, "NtQuerySection", SERVICE),
        ));
        let returned = output + 96;
        for row in controls.rows.iter().flat_map(|image| &image.observations) {
            p.space.wr(output, &[0xa5; 104]).unwrap();
            let &(_, full, denied) = handles.iter().find(|h| h.0 == row.flags).unwrap();
            let handle = if row.access == 5 { full } else { denied };
            assert_eq!(
                call(p, &mut thread, &[handle, 1, output, row.size, returned]),
                row.status
            );
            assert_eq!(p.space.u64(returned).unwrap(), row.returned);
            assert_eq!(p.space.bytes(output + 64, 32).unwrap(), [0xa5; 32]);
            if row.unchanged {
                assert_eq!(p.space.bytes(output, 64).unwrap(), [0xa5; 64]);
            } else {
                assert_eq!(
                    p.space.u64(output).unwrap(),
                    headers.image_base + u64::from(headers.entry_rva)
                );
                assert_eq!(p.space.u64(output + 16).unwrap(), headers.stack_reserve);
                assert_eq!(p.space.u64(output + 24).unwrap(), headers.stack_commit);
                assert_eq!(p.space.u16(output + 48).unwrap(), headers.machine);
                assert_eq!(p.space.u32(output + 56).unwrap(), data.len() as u32);
                assert_eq!(p.space.u32(output + 60).unwrap(), headers.checksum);
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct Wow64Controls {
    entry_rva: u32,
    native64_words: [u32; 16],
    wow64_words: [u32; 12],
    rows: Vec<Wow64Observation>,
}

#[derive(serde::Deserialize)]
struct Wow64Observation {
    wow64: bool,
    flags: u32,
    access: u32,
    size: u64,
    status: u32,
    returned: u64,
}

#[test]
fn section_image_query_projects_x86_file_metadata_to_both_caller_widths() {
    let controls: Wow64Controls = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-file-section/image-information-29708-wow64.json"
    )))
    .unwrap();
    assert_eq!(controls.rows.len(), 24);
    assert_eq!(controls.native64_words[0], controls.entry_rva);
    assert_eq!(controls.wow64_words[0], controls.entry_rva);
    for arch in [WinArch::Arm64, WinArch::X86] {
        let directory = Directory::new();
        let path = directory.0.join("fixture.exe");
        let data = image(WinArch::X86);
        let parsed = PeImage::parse(data).unwrap();
        let headers = parsed.headers();
        let entry = headers.image_base + u64::from(headers.entry_rva);
        std::fs::write(&path, data).unwrap();
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let file = insert_file(p, &path, 0x1000A1);
        let output = scratch(p);
        let handles = [0x0100_0000, 0x1100_0000].map(|flags| {
            assert_eq!(
                call(p, &mut thread, &[output, 5, 0, 0, 2, flags.into(), file]),
                STATUS_SUCCESS
            );
            let full = get(p, output);
            let Object::ImageSection(section) = p.objects.get(full).unwrap() else {
                panic!("expected a file-backed image section");
            };
            let image = section.image().unwrap();
            let mut captured = [0u8; 64];
            for (bytes, word) in captured.chunks_exact_mut(4).zip(controls.native64_words) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            let native_transfer = 0x003e_0000 + image.entry_rva();
            captured[..8].copy_from_slice(&native_transfer.to_le_bytes());
            let captured = SectionImageInformation::capture(&image, captured).unwrap();
            let mut expected = controls.wow64_words;
            expected[0] = entry as u32;
            let projected = captured.wow64_bytes().unwrap();
            for (actual, expected) in projected.chunks_exact(4).zip(expected) {
                assert_eq!(u32::from_le_bytes(actual.try_into().unwrap()), expected);
            }
            let id = p.objects.id(full).unwrap();
            let denied = u64::from(p.objects.open_access(id, false, 4).unwrap());
            (flags, full, denied)
        });
        p.objects.close(file).unwrap();
        p.modules.nt_services = Some((
            p.modules.nt_services.as_ref().unwrap().0,
            table(arch, "NtQuerySection", SERVICE),
        ));
        let returned = output + 96;
        let width = if arch == WinArch::X86 { 48 } else { 64 };
        for row in controls
            .rows
            .iter()
            .filter(|row| row.wow64 == (arch == WinArch::X86))
        {
            p.space.wr(output, &[0xa5; 104]).unwrap();
            p.space.w32(returned, 0x1122_3344).unwrap();
            if arch.is64() {
                p.space.w32(returned + 4, 0).unwrap();
            }
            let &(_, full, denied) = handles.iter().find(|h| h.0 == row.flags).unwrap();
            let handle = if row.access == 5 { full } else { denied };
            assert_eq!(
                call(p, &mut thread, &[handle, 1, output, row.size, returned]),
                row.status
            );
            assert_eq!(get(p, returned), row.returned);
            if arch == WinArch::X86 {
                assert_eq!(p.space.u32(returned + 4).unwrap(), 0xa5a5_a5a5);
            }
            let output_bytes = p.space.bytes(output, 96).unwrap();
            if row.status != STATUS_SUCCESS {
                assert_eq!(output_bytes, [0xa5; 96]);
                continue;
            }
            assert_eq!(get(p, output), entry);
            let subsystem = if arch == WinArch::X86 { 16 } else { 32 };
            let reserve = if arch == WinArch::X86 { 8 } else { 16 };
            assert_eq!(get(p, output + reserve), headers.stack_reserve);
            assert_eq!(
                get(p, output + reserve + arch.ptr_size()),
                headers.stack_commit
            );
            assert_eq!(
                p.space.u16(output + subsystem + 16).unwrap(),
                headers.machine
            );
            assert_eq!(
                p.space.u32(output + subsystem + 24).unwrap(),
                data.len() as u32
            );
            assert_eq!(
                p.space.u32(output + subsystem + 28).unwrap(),
                headers.checksum
            );
            assert!(output_bytes[width..].iter().all(|&byte| byte == 0xa5));
        }
    }
}

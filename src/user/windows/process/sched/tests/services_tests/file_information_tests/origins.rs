//! Naming crosses real opens without acquiring additional guest access rights.
use super::super::file_open_tests::{Harness, selection};
use super::*;
use std::sync::Arc;

fn open(h: &mut Harness, directory: bool) -> u64 {
    assert_eq!(
        h.invoke_api(
            "NtOpenFile",
            &[
                h.base,
                0x100000,
                h.attrs(),
                h.base + PAGE_SIZE,
                7,
                if directory { 0x21 } else { 0x60 },
            ],
        ),
        STATUS_SUCCESS
    );
    let p = h.process.state();
    let handle = p.space.ptr(h.base, p.arch.ptr_size()).unwrap();
    assert_eq!(p.objects.access(handle), Some(0x100000));
    handle
}

fn name(h: &mut Harness, handle: u64, expected: &str) {
    let output = h.base + 4 * PAGE_SIZE;
    assert_eq!(
        h.invoke_api(
            "NtQueryInformationFile",
            &[handle, h.base + PAGE_SIZE, output, 512, 9],
        ),
        STATUS_SUCCESS
    );
    let expected: Vec<u8> = expected.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let p = h.process.state();
    assert_eq!(p.space.u32(output).unwrap() as usize, expected.len());
    assert_eq!(p.space.bytes(output + 4, expected.len()).unwrap(), expected);
    assert_eq!(p.objects.access(handle), Some(0x100000));
}

#[test]
fn file_information_names_nt_open_retains_volume_and_relative_root_with_sync_only_access() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let nested = h.directory.0.join("nested");
        let replacement = h.directory.0.join("replacement");
        std::fs::create_dir(&nested).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(nested.join("fixture.bin"), b"retained naming identity").unwrap();
        Arc::make_mut(&mut h.process.state_mut().cfg)
            .drives
            .set('D', &nested);
        h.name("\\??\\C:\\nested");
        let directory = open(&mut h, true);
        h.name("fixture.bin");
        let attrs = h.attrs();
        let p = h.process.state_mut();
        p.space
            .wptr(attrs + arch.ptr_size(), arch.ptr_size(), directory)
            .unwrap();
        let relative = open(&mut h, false);
        h.name("\\??\\D:\\fixture.bin");
        let other_volume = open(&mut h, false);
        name(&mut h, directory, "\\nested");
        name(&mut h, relative, "\\nested\\fixture.bin");
        name(&mut h, other_volume, "\\fixture.bin");
        let cfg = Arc::make_mut(&mut h.process.state_mut().cfg);
        cfg.drives.set('C', &replacement);
        cfg.drives.set('D', &replacement);
        name(&mut h, directory, "\\nested");
        name(&mut h, relative, "\\nested\\fixture.bin");
        name(&mut h, other_volume, "\\fixture.bin");
        for handle in [directory, relative, other_volume] {
            h.process.state_mut().objects.close(handle).unwrap();
        }
    }
}

#[test]
fn file_information_names_selected_library_keeps_guest_namespace_and_read_only_authority() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let directory = selection(&mut h);
        h.name("\\??\\C:\\Windows\\System32\\fixture.dll");
        let handle = open(&mut h, false);
        let component = if arch == WinArch::X86 {
            "SysWOW64"
        } else {
            "System32"
        };
        name(
            &mut h,
            handle,
            &format!("\\Windows\\{component}\\fixture.dll"),
        );
        assert!(!h.process.state().cfg.host_filesystem);
        assert!(h.process.state().objects.runtime_library(handle));
        assert_eq!(
            std::fs::read(directory.join("fixture.dll")).unwrap(),
            b"native"
        );
        h.process.state_mut().objects.close(handle).unwrap();
    }
}

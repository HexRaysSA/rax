use super::*;
use std::sync::Arc;

#[test]
fn file_information_names_win32_opens_keep_the_original_mapped_volume() {
    for arch in WinArch::ALL {
        for wide in [false, true] {
            let mut h = Harness::new(arch);
            let nested = h.directory.0.join("nested");
            std::fs::create_dir(&nested).unwrap();
            std::fs::write(nested.join("fixture.bin"), b"Win32 retained name").unwrap();
            h.filename("C:\\nested\\fixture.bin", wide);
            let handle = h.value(
                if wide { "CreateFileW" } else { "CreateFileA" },
                &[h.memory, u64::from(GENERIC_READ), 7, 0, 3, 0x80, 0],
            );
            assert_ne!(handle, h.invalid());
            Arc::make_mut(&mut h.process.state_mut().cfg)
                .drives
                .set('C', &nested);
            let output = h.memory + 0x1000;
            assert_eq!(
                h.value(
                    "NtQueryInformationFile",
                    &[handle, h.memory + 0x2000, output, 512, 9],
                ),
                0
            );
            let expected: Vec<u8> = "\\nested\\fixture.bin"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let p = h.process.state();
            assert_eq!(p.space.u32(output).unwrap() as usize, expected.len());
            assert_eq!(p.space.bytes(output + 4, expected.len()).unwrap(), expected);
            h.close(handle);
        }
    }
}

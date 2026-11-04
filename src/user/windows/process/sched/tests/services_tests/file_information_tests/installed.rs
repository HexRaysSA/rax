//! Installed native and WoW64 service leaves, including x86 RET20.
use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn file_information_installed_native_and_wow64_leaves_preserve_five_argument_return_abi() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    for arch in if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    } {
        let image: &[u8] = match arch {
            WinArch::Arm64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            )),
            WinArch::X64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x64/smoke.exe"
            )),
            WinArch::X86 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x86/smoke.exe"
            )),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-file-information.exe", vec![], vec![], 4096)
                .unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert!(p.native.is_some());
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let base =
            p.vm.allocate(
                None,
                3 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let handle = u64::from(p.objects.insert(Object::Console(StdStream::In)));
        for (class, bytes, value) in [
            (14, 8, 0),
            (8, 4, 0x12019f),
            (16, 4, 0x20),
            (17, 4, 0),
            (41, 4, 0),
            (43, 4, 2),
            (51, 1, 0),
        ] {
            p.space.wr(base, &[0xA5; 128]).unwrap();
            let status = super::super::secure_connect_tests::installed::leaf(
                p,
                &mut thread,
                "NtQueryInformationFile",
                &[handle, base, base + 64, bytes, class],
            );
            assert_eq!(status, STATUS_SUCCESS, "{arch} class{class}");
            assert_eq!(
                p.space
                    .ptr(base + arch.ptr_size(), arch.ptr_size())
                    .unwrap(),
                bytes
            );
            match bytes {
                8 => assert_eq!(p.space.u64(base + 64).unwrap(), value),
                4 => assert_eq!(u64::from(p.space.u32(base + 64).unwrap()), value),
                _ => assert_eq!(u64::from(p.space.u8(base + 64).unwrap()), value),
            }
        }
    }
}

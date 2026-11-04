//! Execute selected installed NTDLL leaves, including x86 RET36 cleanup.
use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn nt_read_file_installed_native_and_wow64_nine_argument_leaves() {
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
            WindowsConfig::embedded("C:\\native-read.exe", vec![], b"hello".to_vec(), 4096)
                .unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert!(p.native.is_some());
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let base = pages(p);
        let handle = u64::from(p.objects.insert(Object::Console(StdStream::In)));
        p.space.wr(base, &[0xa5; 128]).unwrap();
        let code = super::super::secure_connect_tests::installed::leaf(
            p,
            &mut t,
            "NtReadFile",
            &[handle, 0, 0, 0, base, base + 64, 2, 0, 0],
        );
        assert_eq!(code, STATUS_SUCCESS, "{arch}");
        assert_eq!(p.space.bytes(base + 64, 2).unwrap(), b"he");
        assert_eq!(
            p.space
                .ptr(base + arch.ptr_size(), arch.ptr_size())
                .unwrap(),
            2
        );
        let code = super::super::secure_connect_tests::installed::leaf(
            p,
            &mut t,
            "NtReadFile",
            &[handle, 0, 0, 0, base, base + 64, 1, 0, 1],
        );
        assert_eq!(code, STATUS_ACCESS_VIOLATION, "{arch}");
    }
}

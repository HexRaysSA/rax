//! Installed native and WoW64 leaves, including x86 RET20 cleanup.
use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn file_state_set_installed_native_and_wow64_leaves_apply_changes_with_five_argument_return_abi() {
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
            WindowsConfig::embedded("C:\\file-state-set.exe", vec![], vec![], 4096).unwrap();
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
        for (class, bytes, value, expected) in [
            (14, 8, 37, STATUS_SUCCESS),
            (16, 4, 0x24, STATUS_SUCCESS),
            (43, 4, 1, STATUS_SUCCESS),
            (41, 4, 1, STATUS_INVALID_PARAMETER),
        ] {
            p.space.wr(base, &[0xA5; 128]).unwrap();
            p.space.w64(base + 64, value).unwrap();
            let result = super::super::secure_connect_tests::installed::leaf(
                p,
                &mut thread,
                "NtSetInformationFile",
                &[handle, base, base + 64, bytes, class],
            );
            assert_eq!(result, expected, "{arch} class{class}");
            if expected == STATUS_SUCCESS {
                assert_eq!(
                    p.space
                        .ptr(base + arch.ptr_size(), arch.ptr_size())
                        .unwrap(),
                    0
                );
                let result = super::super::secure_connect_tests::installed::leaf(
                    p,
                    &mut thread,
                    "NtQueryInformationFile",
                    &[handle, base, base + 64, bytes, class],
                );
                assert_eq!(result, STATUS_SUCCESS);
                assert_eq!(
                    p.space.u64(base + 64).unwrap()
                        & if bytes == 4 {
                            u32::MAX as u64
                        } else {
                            u64::MAX
                        },
                    value
                );
            }
        }
    }
}

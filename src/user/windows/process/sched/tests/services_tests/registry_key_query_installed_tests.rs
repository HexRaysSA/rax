//! Installed native NTDLL leaves, including x86 RET20 and five-slot dispatch.
use super::*;
use crate::user::windows::loader;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn native_query_key_installed_leaf_views_length_faults_and_ret20() {
    let native_arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else {
        WinArch::X64
    };
    for arch in [native_arch, WinArch::X86] {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-query-key.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let base =
            p.vm.allocate(
                None,
                PAGE_SIZE * 2,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let attrs = base + 128;
        unicode(p, attrs + 64, base + 256, NLS_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x240);
        let before = (p.objects.handle_count(), p.objects.iter().count());
        for (view, expected) in [(0, 0x400), (0x100, 0x100), (0x200, 0x600)] {
            assert_eq!(
                super::super::installed::invoke(
                    p,
                    &mut t,
                    module,
                    "NtOpenKey",
                    &[base, 1 | view, attrs]
                ),
                STATUS_SUCCESS
            );
            let h = p.space.ptr(base, arch.ptr_size()).unwrap();
            for offset in [0, 4] {
                let output = base + PAGE_SIZE + offset;
                let returned = base + 64;
                p.space.w32(returned, 0xA5A5_A5A5).unwrap();
                assert_eq!(
                    super::super::installed::invoke(
                        p,
                        &mut t,
                        module,
                        "NtQueryKey",
                        &[h, 7, output, 0, returned]
                    ),
                    STATUS_BUFFER_TOO_SMALL
                );
                assert_eq!(p.space.u32(returned).unwrap(), 4);
                assert_eq!(
                    super::super::installed::invoke(
                        p,
                        &mut t,
                        module,
                        "NtQueryKey",
                        &[h | 3, 7, output, 4, returned]
                    ),
                    STATUS_SUCCESS
                );
                assert_eq!(
                    p.space.u32(output).unwrap(),
                    if arch == WinArch::X86 { expected } else { 0 }
                );
                assert_eq!(
                    super::super::installed::invoke(
                        p,
                        &mut t,
                        module,
                        "NtQueryKey",
                        &[h, 7, output, 4, 0]
                    ),
                    STATUS_ACCESS_VIOLATION
                );
            }
            assert_eq!(
                super::super::installed::invoke(p, &mut t, module, "NtClose", &[h]),
                STATUS_SUCCESS
            );
        }
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

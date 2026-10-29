//! Execute installed native NTDLL entry points, including x86 RET16.
use super::*;
use crate::user::windows::loader;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};
use crate::user::windows::registry::MACHINE_HIVE_KEY;

#[test]
fn installed_set_key_leaf_consumes_four_slots_and_replaces_guest_key_body_tags() {
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
            WindowsConfig::embedded("C:\\native-set-key.exe", vec![], vec![], 4096).unwrap();
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
        unicode(p, attrs + 64, base + 256, MACHINE_HIVE_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x40);
        let before = (p.objects.handle_count(), p.objects.iter().count());
        assert_eq!(
            super::super::installed::invoke(
                p,
                &mut t,
                module,
                "NtOpenKeyEx",
                &[base, 0x20019, attrs, 0]
            ),
            STATUS_SUCCESS
        );
        let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
        let input = base + 1025;
        let output = base + PAGE_SIZE;
        for value in [0, 0x100, 0x12345678, u32::MAX] {
            p.space.w32(input, value).unwrap();
            assert_eq!(
                super::super::installed::invoke(
                    p,
                    &mut t,
                    module,
                    "NtSetInformationKey",
                    &[handle | 3, 5, input, 4]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(
                super::super::installed::invoke(
                    p,
                    &mut t,
                    module,
                    "NtQueryKey",
                    &[handle, 7, output, 4, base + 64]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(output).unwrap(), value & 0xffff);
            assert_eq!(p.space.u32(input).unwrap(), value);
        }
        assert_eq!(
            super::super::installed::invoke(
                p,
                &mut t,
                module,
                "NtSetInformationKey",
                &[0, 5, input, 4]
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            super::super::installed::invoke(
                p,
                &mut t,
                module,
                "NtSetInformationKey",
                &[handle, 5, input, 8]
            ),
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            super::super::installed::invoke(p, &mut t, module, "NtClose", &[handle]),
            STATUS_SUCCESS
        );
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

//! Actual installed leaf execution over guest images without kernel SCP owners.
use super::*;
use crate::user::windows::{
    loader,
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn native_image_extension_installed_leaf_matches_guest_flags_and_wow_rejection() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let archs = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in archs {
        let input: &[u8] = match arch {
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-image-extension.exe", vec![], vec![], 4096)
                .unwrap();
        config.native_libraries = true;
        let mut process = WindowsProcess::spawn_image(config, input.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let target = p.modules.exe().base;
        let base =
            p.vm.allocate(
                None,
                PAGE_SIZE * 4,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let invoke = super::super::installed::invoke;
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtQueryVirtualMemory",
                &[arch.ptr(u64::MAX), target, 6, base + 512, 24, 0]
            ),
            STATUS_SUCCESS
        );
        let flags_at = base + 512 + arch.ptr_size() * 2;
        assert_eq!(p.space.u32(flags_at).unwrap() & 0x40, 0);
        for kind in [0, 1] {
            p.space
                .wr(base, &vec![0xa5; PAGE_SIZE as usize * 4])
                .unwrap();
            p.space.w32(base + 128, kind).unwrap();
            p.space.w32(base + 132, 0).unwrap();
            let returned = base + 256;
            let args = [arch.ptr(u64::MAX), target, 14, base + 128, 24, returned];
            let status = invoke(p, &mut t, module, "NtQueryVirtualMemory", &args);
            // Expected AMD64 capability statuses come from the independent
            // native captures, not the image-query policy under test.
            let expected = if arch == WinArch::X86 {
                STATUS_INVALID_INFO_CLASS
            } else if p.object_namespace.native_machine == Some(0x8664) {
                let build = super::super::super::native_host_profile::build();
                match (build, kind) {
                    (20348, _) => STATUS_INVALID_INFO_CLASS,
                    (26100, 0) => STATUS_SUCCESS,
                    (26100, 1) => STATUS_NOT_SUPPORTED,
                    _ => panic!("uncaptured native AMD64 image-query profile: {build}"),
                }
            } else {
                STATUS_SUCCESS
            };
            assert_eq!(status, expected, "{arch} kind {kind}");
            if expected != STATUS_SUCCESS {
                assert_eq!(read_ptr(p, returned), arch.ptr(0xa5a5_a5a5_a5a5_a5a5));
                assert_eq!(p.space.u32(base + 128).unwrap(), kind);
                assert_eq!(p.space.u32(base + 132).unwrap(), 0);
                assert_eq!(p.space.bytes(base + 136, 16).unwrap(), vec![0xa5; 16]);
            } else {
                assert_eq!(p.space.u32(base + 128).unwrap(), kind);
                assert_eq!(p.space.bytes(base + 136, 16).unwrap(), vec![0; 16]);
                assert_eq!(p.space.u64(returned).unwrap(), 24);
            }
        }
    }
}

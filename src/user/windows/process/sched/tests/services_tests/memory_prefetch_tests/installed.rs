//! Execute installed six-argument leaves, including the WoW64 RET24 epilogue.
use super::*;
use crate::user::windows::{
    loader,
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn native_memory_prefetch_installed_leaves_populate_guest_pages_and_keep_ret24() {
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
        let mut cfg =
            WindowsConfig::embedded("C:\\native-prefetch.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let kernel = p.native.as_ref().unwrap();
        let working_set = match (kernel.version.build, kernel.object_namespace.native_machine) {
            (20348, Some(0x8664)) => false,
            (26100, Some(0x8664)) | (29695, Some(0xaa64)) => true,
            other => panic!("uncaptured installed prefetch kernel {other:?}"),
        };
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let setup = inputs::prepare(p, 0);
        let last_error = t.teb + layout::offsets(arch).teb_last_error;
        let invoke = |p: &mut Proc, t: &mut Thread, args: &[u64]| {
            p.space.w32(last_error, LAST_ERROR).unwrap();
            let status = super::super::virtual_memory_tests::installed::invoke(
                p,
                t,
                module,
                "NtSetInformationVirtualMemory",
                args,
            );
            assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
            status
        };
        assert_eq!(invoke(p, &mut t, &setup.args), 0);
        assert_eq!(valid_mask(p, setup.target), 0);
        p.space.w32(setup.args[4], 1).unwrap();
        let expected_status = if working_set {
            0
        } else {
            STATUS_INVALID_PARAMETER_5
        };
        assert_eq!(invoke(p, &mut t, &setup.args), expected_status);
        assert_eq!(valid_mask(p, setup.target), u32::from(working_set));
        let working_set_available = working_set;
        let working_set = setup.base + 4096 + 128;
        let width = arch.ptr_size();
        p.space.wptr(working_set, width, setup.target).unwrap();
        p.space.wptr(working_set + width, width, u64::MAX).unwrap();
        assert_eq!(
            super::super::virtual_memory_tests::installed::invoke(
                p,
                &mut t,
                module,
                "NtQueryVirtualMemory",
                &[arch.ptr(u64::MAX), 0, 4, working_set, 2 * width, 0],
            ),
            0,
        );
        assert_eq!(
            p.space.ptr(working_set + width, width).unwrap(),
            if working_set_available {
                0x0500_0041
            } else {
                0
            }
        );
        assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
        p.vm.protect(setup.target + 4096, 4096, prot::READWRITE | prot::GUARD)
            .unwrap();
        p.space
            .wptr(setup.args[3], arch.ptr_size(), setup.target + 4096)
            .unwrap();
        assert_eq!(invoke(p, &mut t, &setup.args), expected_status);
        assert!(!p.space.is_resident(setup.target + 4096));
        assert_eq!(
            p.vm.query(setup.target + 4096).unwrap().protect,
            prot::READWRITE | prot::GUARD
        );
        let mut bad_length = setup.args;
        bad_length[5] = 0;
        assert_eq!(invoke(p, &mut t, &bad_length), STATUS_INVALID_PARAMETER_6);
    }
}

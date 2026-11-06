//! Installed syscall leaves register guest targets without a supplied sysroot.
use super::*;
use crate::user::windows::{
    loader,
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn cfg_target_installed_ntdll_leaves_register_without_commitment_and_preserve_ret24() {
    let native = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if native == WinArch::X86 {
        vec![native]
    } else {
        vec![native, WinArch::X86]
    };
    for arch in arches {
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
            WindowsConfig::embedded("C:\\native-cfg-target.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let setup = inputs::prepare(p, "uncommitted-exec-target");
        let committed = p.vm.committed_bytes();
        let last_error = thread.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, LAST_ERROR).unwrap();
        let result = super::super::virtual_memory_tests::installed::invoke(
            p,
            &mut thread,
            module,
            "NtSetInformationVirtualMemory",
            &setup.args,
        );
        assert_eq!(result, 0, "{arch}");
        assert!(p.vm.valid_call_target(setup.target));
        assert!(!p.vm.accessible(setup.target, MemoryAccessKind::Fetch));
        assert_eq!(p.vm.committed_bytes(), committed);
        assert_eq!(p.space.u32(setup.buffers[3].1).unwrap(), 1);
        assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
        assert!(thread.frames.is_empty());
    }
}

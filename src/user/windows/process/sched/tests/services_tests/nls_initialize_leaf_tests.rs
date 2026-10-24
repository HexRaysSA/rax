//! Actual installed ABI-specific leaves and independent locale.nls file bytes.
use super::*;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDefaultLCID() -> u32;
}

#[test]
fn native_nls_initialize_installed_leaves_map_locale_file_and_preserve_ignored_outputs() {
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
            WindowsConfig::embedded("C:\\native-nls-initialize.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert_eq!(
            p.cfg.version.build,
            native_host_profile::build(),
            "installed profile must report the current host build"
        );
        // The native initialization profile (ignored casing/version outputs,
        // WoW64 capture ordering) was measured on build 29683, and the snapshot
        // only records it there. Other builds expose the entry as unimplemented
        // rather than an unverified emulation; the recorded 29683 corpora keep
        // the semantics covered on any host.
        if p.cfg.version.major != 10 || p.cfg.version.build != 29683 {
            assert!(
                p.nls.as_ref().and_then(|nls| nls.initialize()).is_none(),
                "unmeasured build must not record an initialization profile"
            );
            eprintln!(
                "Validated unmeasured native build {}: no NtInitializeNlsFiles profile",
                p.cfg.version.build
            );
            continue;
        }
        let file = std::fs::read(
            std::path::Path::new(&p.native.as_ref().unwrap().guest_root)
                .join("System32")
                .join("locale.nls"),
        )
        .unwrap();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let base =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(base, &[0xA5; 64]).unwrap();
        let args = [base + 1, base + 17, 1, arch.ptr(u64::MAX)];
        let count = if arch == WinArch::X86 { 3 } else { 4 };
        assert_eq!(
            invoke(
                p,
                &mut thread,
                module,
                "NtInitializeNlsFiles",
                &args[..count]
            ),
            0
        );
        let view = ptr(p, base + 1);
        // SAFETY: fixed no-argument initialized-host metadata query, not guest input.
        assert_eq!(p.space.u32(base + 17).unwrap(), unsafe {
            GetSystemDefaultLCID()
        });
        let size = (file.len() + 4095) & !4095;
        assert_eq!(p.vm.query(view).unwrap().size, size as u64);
        assert_eq!(p.vm.query(view).unwrap().protect, prot::READONLY);
        assert_eq!(p.space.bytes(view, file.len()).unwrap(), file);
        assert!(
            p.space
                .bytes(view + file.len() as u64, size - file.len())
                .unwrap()
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(p.space.bytes(base + 21, 43).unwrap(), vec![0xA5; 43]);
        assert_eq!(
            invoke(
                p,
                &mut thread,
                module,
                "NtUnmapViewOfSection",
                &[arch.ptr(u64::MAX), view + 4095]
            ),
            0
        );
        assert_eq!(p.vm.nls_view_count(), 0);
        println!(
            "Validated installed {arch} NtInitializeNlsFiles ABI-specific arguments and locale.nls bytes with real unmap"
        );
    }
}

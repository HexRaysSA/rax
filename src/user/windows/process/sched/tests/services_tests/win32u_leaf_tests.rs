//! Execute installed leaves with missing GUI prerequisites and preserve state.
use super::*;
use crate::user::windows::{
    layout,
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn win32u_installed_init2_leaf_requires_gui_prerequisites_without_state_changes() {
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
            WindowsConfig::embedded("C:\\win32u-leaf.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let expected = match &p.native.as_ref().unwrap().gui {
            crate::user::windows::gui::Availability::Available(_) => {
                assert_ne!(arch, WinArch::X86);
                assert_eq!(p.space.u64(p.peb + 0x58).unwrap(), 0);
                "USER callback table is absent or unreadable".to_owned()
            }
            crate::user::windows::gui::Availability::Unavailable(reason) => {
                if arch == WinArch::X86 {
                    assert!(reason.contains("WoW64") && reason.contains("paired contexts"));
                } else {
                    assert!(
                        reason.ends_with("selected Win32u has no NtGdiInit2"),
                        "{arch}: unexpected unavailable GUI inputs: {reason}"
                    );
                }
                format!("not implemented for unavailable GUI inputs: {reason}")
            }
        };
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "win32u.dll").unwrap();
        assert_eq!(p.modules.win32u_services.as_ref().unwrap().0, module);
        let entry = loader::lookup(p, module, &SymRef::Name(b"NtGdiInit2".to_vec(), None)).unwrap();
        let error = t.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(error, 0x1234_5678).unwrap();
        let rng = p.rng;
        let handles = p.objects.handle_count();
        let committed = p.vm.committed_bytes();
        let peb = p.space.bytes(p.peb, 512).unwrap();
        let teb = p.space.bytes(t.teb, 4096).unwrap();
        if let Some(entry) = entry {
            let sp = t.cpu.sp() - 128;
            let resume = p.traps.callback_return();
            t.cpu.set_sp(sp);
            t.cpu.set_pc(entry);
            match arch {
                WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
                WinArch::X64 => p.space.w64(sp, resume).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            let mut named = false;
            for _ in 0..32 {
                let boundary = run_cpu(p, &mut t.cpu, 64);
                assert_ne!(
                    t.cpu.pc(),
                    resume,
                    "Win32u leaf with missing GUI prerequisites cannot return success"
                );
                match handle_stop(p, &mut t, boundary) {
                    Outcome::Continue | Outcome::Yield => (),
                    Outcome::Fail(reason) => {
                        assert!(
                            reason.starts_with("native Win32u service NtGdiInit2 (")
                                && reason.ends_with(&expected),
                            "{arch}: {reason}"
                        );
                        named = true;
                        break;
                    }
                    other => panic!("{arch}: {other:?}"),
                }
            }
            assert!(named, "{arch}");
        } else {
            // The strict reason check above also permits the earlier WoW64
            // paired-context failure, which precedes export discovery.
            assert!(
                matches!(
                    &p.native.as_ref().unwrap().gui,
                    crate::user::windows::gui::Availability::Unavailable(_)
                ),
                "{arch}: missing export must have an explicit unavailable capability"
            );
            println!(
                "{arch}: validated missing NtGdiInit2 capability and preserved state; no leaf execution"
            );
        }
        assert_eq!(p.space.u32(error).unwrap(), 0x1234_5678);
        assert_eq!(p.rng, rng);
        assert_eq!(p.objects.handle_count(), handles);
        assert_eq!(p.vm.committed_bytes(), committed);
        assert_eq!(p.space.bytes(p.peb, 512).unwrap(), peb);
        assert_eq!(p.space.bytes(t.teb, 4096).unwrap(), teb);
        assert!(p.gui.value.is_none());
        assert!(p.gui.threads.is_empty());
        assert!(t.frames.is_empty());
    }
}

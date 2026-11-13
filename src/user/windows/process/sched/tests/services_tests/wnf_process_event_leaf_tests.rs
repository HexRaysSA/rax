//! Actual installed registration leaves, native/WoW64 return and x86 RET4 cleanup.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn installed_wnf_process_event_leaf_registers_once_and_returns_one_argument() {
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
            WindowsConfig::embedded("C:\\native-wnf-event.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtSetWnfProcessNotificationEvent".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let sp = t.cpu.sp() - 128;
        let resume = p.traps.callback_return();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let handle = event(p, true, 1);
        let id = p.objects.id(handle).unwrap();
        for (selected, expected) in [
            (0, STATUS_INVALID_HANDLE),
            (handle, 0),
            (handle, ALREADY as u32),
            (0, STATUS_INVALID_HANDLE),
        ] {
            let args = [selected];
            t.cpu.set_sp(sp);
            t.cpu.set_pc(entry);
            for (i, value) in args.into_iter().enumerate() {
                match arch {
                    WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
                    WinArch::X64 => t.cpu.set_gpr([1, 2, 8, 9][i], value),
                    WinArch::Arm64 => t.cpu.set_gpr(i, value),
                }
            }
            match arch {
                WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
                WinArch::X64 => p.space.w64(sp, resume).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            let mut returned = false;
            for _ in 0..32 {
                let boundary = run_cpu(p, &mut t.cpu, 64);
                if t.cpu.pc() == resume {
                    returned = true;
                    break;
                }
                assert!(
                    matches!(
                        handle_stop(p, &mut t, boundary),
                        Outcome::Continue | Outcome::Yield
                    ),
                    "{arch}: installed setter leaf"
                );
            }
            assert!(returned);
            assert_eq!(t.cpu.gpr(0), u64::from(expected));
            assert!(t.frames.is_empty());
            assert_eq!(
                t.cpu.sp(),
                sp + match arch {
                    WinArch::X86 => 8,
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
            assert!(matches!(
                p.objects.obj(id),
                Some(Object::Event {
                    manual: true,
                    signaled: 1
                })
            ));
        }
        p.objects.close(handle).unwrap();
        assert!(p.objects.obj(id).is_some());
        assert_eq!(p.objects.handle_count(), before.0);
        assert_eq!(p.objects.iter().count(), before.1 + 1);
        p.objects.drain().for_each(drop);
        assert_eq!(p.objects.iter().count(), 0);
    }
}

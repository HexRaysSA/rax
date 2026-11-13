//! Actual installed setter leaves, native/WoW64 return and x86 RET16 cleanup.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn installed_worker_factory_binding_leaf_updates_state_and_returns_four_arguments() {
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
            WindowsConfig::embedded("C:\\native-worker-binding.exe", vec![], vec![], 4096).unwrap();
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
            &SymRef::Name(b"NtSetInformationWorkerFactory".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let sp = t.cpu.sp() - 128;
        let input = sp - 64;
        let resume = p.traps.callback_return();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let (handle, port) = factory(p);
        for (value, pointer, length, expected) in [
            (0, input, 4, 0),
            (u32::MAX, input, 4, 0),
            (768, input, 5, STATUS_INFO_LENGTH_MISMATCH),
            (768, 0, 4, STATUS_ACCESS_VIOLATION),
            (768, input, 4, 0),
        ] {
            p.space.w32(input, value).unwrap();
            let old = maximum(p, handle);
            let prior_binding = binding_count(p, handle);

            let args = [handle, 3, pointer, length];
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
                    WinArch::X86 => 20,
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
            assert_eq!(maximum(p, handle), old);
            assert_eq!(
                binding_count(p, handle),
                if expected != 0 {
                    prior_binding
                } else if value == 0 {
                    u32::MAX
                } else {
                    prior_binding.saturating_add_signed(value as i32)
                }
            );
            assert_eq!(p.space.u32(input).unwrap(), value);
        }
        p.objects.close(handle).unwrap();
        p.objects.close(port).unwrap();
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

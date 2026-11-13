//! Installed class2 native/WoW64 leaves and four-argument x86 cleanup.
use super::super::handle_stop;
use super::{Outcome, WinArch, factory, idle_timeout, maximum};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER,
};
use crate::user::windows::process::sched::run_cpu;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn native_worker_factory_idle_installed_leaf_updates_request_and_four_argument_cleanup() {
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
            WindowsConfig::embedded("C:\\native-worker-idle.exe", vec![], vec![], 4096).unwrap();
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
        for (value, pointer, length, expected, applied) in [
            (-1i64, input, 8, 0, Some(-10000000)),
            (i64::MIN, input, 8, 0, Some(-6000000000)),
            (0, input, 8, STATUS_INVALID_PARAMETER, None),
            (-300000000, input, 7, STATUS_INFO_LENGTH_MISMATCH, None),
            (-300000000, 0, 8, STATUS_ACCESS_VIOLATION, None),
            (-300000000, input + 4, 8, 0, Some(-300000000)),
            (
                -300000000,
                input,
                9,
                if arch == WinArch::X86 {
                    0
                } else {
                    STATUS_INFO_LENGTH_MISMATCH
                },
                Some(-300000000),
            ),
            (-300000000, input, 8, 0, Some(-300000000)),
        ] {
            if pointer != 0 {
                p.space.w64(pointer, value as u64).unwrap();
            }
            let old = maximum(p, handle);
            let old_idle = idle_timeout(p, handle);
            let args = [handle, 2, pointer, length];
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
                idle_timeout(p, handle),
                if expected == 0 { applied } else { old_idle }
            );
            if pointer != 0 {
                assert_eq!(p.space.u64(pointer).unwrap(), value as u64);
            }
        }
        p.objects.close(handle).unwrap();
        p.objects.close(port).unwrap();
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

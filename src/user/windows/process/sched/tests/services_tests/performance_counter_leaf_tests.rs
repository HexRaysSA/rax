//! Installed NT/public counter entries use the same host frequency and epoch.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
fn leaf(p: &mut Proc, t: &mut Thread, library: &str, name: &str, args: &[u64]) -> u32 {
    let m = loader::load_dll(p, library).unwrap();
    let entry = loader::lookup(p, m, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let saved_sp = t.cpu.sp();
    let sp = saved_sp - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    for (i, &value) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::X64 => p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap(),
            WinArch::Arm64 if i < 8 => t.cpu.set_gpr(i, value),
            WinArch::Arm64 => p.space.w32(sp + (i - 8) as u64 * 8, value as u32).unwrap(),
        }
    }
    match p.arch {
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
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{name} {}",
            p.arch
        );
    }
    assert!(returned, "{name} {}", p.arch);
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 4 + args.len() as u64 * 4,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(saved_sp);
    t.cpu.gpr(0) as u32
}
#[test]
fn native_performance_counter_installed_leaves_and_public_helpers_share_clock() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn QueryPerformanceCounter(output: *mut i64) -> i32;
        fn QueryPerformanceFrequency(output: *mut i64) -> i32;
    }
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in arches {
        let bytes: &[u8] = match arch {
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
            WindowsConfig::embedded("C:\\performance-counter.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let base = scratch(p);
        let mut expected_frequency = 0i64;
        let mut before = 0i64;
        let mut after = 0i64;
        // SAFETY: exact host ABI and exclusive initialized native outputs.
        assert_ne!(
            unsafe { QueryPerformanceFrequency(&mut expected_frequency) },
            0
        );
        assert_ne!(unsafe { QueryPerformanceCounter(&mut before) }, 0);
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQueryPerformanceCounter",
                &[base + 4, base + 20]
            ),
            STATUS_SUCCESS
        );
        // SAFETY: exclusive initialized native output.
        assert_ne!(unsafe { QueryPerformanceCounter(&mut after) }, 0);
        assert!((before as u64..=after as u64).contains(&p.space.u64(base + 4).unwrap()));
        assert_eq!(p.space.u64(base + 20).unwrap(), expected_frequency as u64);
        assert_eq!(
            p.space
                .u64(layout::KUSER_SHARED_DATA + layout::kuser::QPC_FREQUENCY)
                .unwrap(),
            expected_frequency as u64
        );
        for (name, output) in [
            ("QueryPerformanceFrequency", base + 40),
            ("QueryPerformanceCounter", base + 56),
        ] {
            // SAFETY: exclusive initialized native output.
            assert_ne!(unsafe { QueryPerformanceCounter(&mut before) }, 0);
            assert_eq!(leaf(p, &mut thread, "kernel32.dll", name, &[output]), 1);
            // SAFETY: exclusive initialized native output.
            assert_ne!(unsafe { QueryPerformanceCounter(&mut after) }, 0);
            if name == "QueryPerformanceFrequency" {
                assert_eq!(p.space.u64(output).unwrap(), expected_frequency as u64);
            } else {
                assert!((before as u64..=after as u64).contains(&p.space.u64(output).unwrap()));
            }
        }
        p.vm.protect(base + 4096, 4096, prot::READONLY).unwrap();
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQueryPerformanceCounter",
                &[base + 4, base + 4096]
            ),
            STATUS_ACCESS_VIOLATION
        );
        assert!(p.space.u64(base + 4).unwrap() >= before as u64);
    }
}

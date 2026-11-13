//! Installed NTDLL entry, real syscall selection, and true x86 RET24.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

fn run_leaf(p: &mut Proc, t: &mut Thread, args: [u64; 6], expected: u32) {
    let module = loader::load_dll(p, "ntdll.dll").unwrap();
    let entry = loader::lookup(p, module, &SymRef::Name(b"NtTraceControl".to_vec(), None))
        .unwrap()
        .unwrap();
    let sp = t.cpu.sp() - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    for (i, value) in args.into_iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 => {
                if i < 4 {
                    t.cpu.set_gpr([1, 2, 8, 9][i], value);
                } else {
                    p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap();
                }
            }
            WinArch::Arm64 => t.cpu.set_gpr(i, value),
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
            "{}: NtTraceControl",
            p.arch
        );
    }
    assert!(returned);
    assert_eq!(t.cpu.gpr(0), u64::from(expected));
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 28,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(sp + 128);
}

#[test]
fn installed_etw_provider_traits_leaf_captures_once_faults_and_ret24_cleanup() {
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
            WindowsConfig::embedded("C:\\etw-provider-traits.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let b = scratch(p, 3);
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let h = own(p);
        p.space.wr(b, &packet(h, b + 512, 7, 0)).unwrap();
        p.space.wr(b + 512, b"\x07\0name\0").unwrap();
        p.space.wr(b + PAGE_SIZE, &[0xA5; 120]).unwrap();
        p.space.w32(b + 2 * PAGE_SIZE, 0xA5A5A5A5).unwrap();
        p.vm.protect(b + 2 * PAGE_SIZE, PAGE_SIZE, prot::READONLY)
            .unwrap();
        run_leaf(
            p,
            &mut t,
            [30, b, 24, b + PAGE_SIZE, 120, b + 2 * PAGE_SIZE],
            STATUS_ACCESS_VIOLATION,
        );
        assert_eq!(stored(p, h), None);
        p.vm.protect(b + 2 * PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        run_leaf(
            p,
            &mut t,
            [30, b, 24, b + PAGE_SIZE, 120, b + 2 * PAGE_SIZE],
            0,
        );
        assert_eq!(stored(p, h), Some(&b"\x07\0name\0"[..]));
        assert_eq!(p.space.u32(b + 2 * PAGE_SIZE).unwrap(), 0);
        assert_eq!(p.space.bytes(b + PAGE_SIZE, 120).unwrap(), [0xA5; 120]);
        p.space.wr(b, &packet(h, 1, 7, 0)).unwrap();
        run_leaf(
            p,
            &mut t,
            [30, b, 24, b + PAGE_SIZE, 120, b + 2 * PAGE_SIZE],
            STATUS_UNSUCCESSFUL,
        );
        p.objects.close(h).unwrap();
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}

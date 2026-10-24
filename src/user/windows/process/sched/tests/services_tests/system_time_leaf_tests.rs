//! Execute the selected installed NTDLL leaf, including x86 RET 4 cleanup.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemTime(output: *mut i64) -> i32;
}

fn native_time() -> u64 {
    let mut ticks = 0i64;
    // SAFETY: one initialized, aligned, private host LARGE_INTEGER.
    assert_eq!(unsafe { NtQuerySystemTime(&mut ticks) }, 0);
    u64::try_from(ticks).unwrap()
}

fn native_unaligned_status() -> u32 {
    #[repr(align(8))]
    struct Scratch([u8; 24]);
    let mut scratch = Scratch([0xa5; 24]);
    // SAFETY: eight writable bytes in owned scratch, deliberately unaligned;
    // no Rust reference or guest operand crosses the native ABI.
    let status = unsafe { NtQuerySystemTime(scratch.0.as_mut_ptr().add(1).cast()) } as u32;
    assert!(matches!(
        status,
        STATUS_SUCCESS | STATUS_DATATYPE_MISALIGNMENT
    ));
    assert_eq!(scratch.0[0], 0xa5);
    assert_eq!(scratch.0[9..], [0xa5; 15]);
    if status != STATUS_SUCCESS {
        assert_eq!(scratch.0, [0xa5; 24]);
    }
    status
}
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
        let boundary = t.cpu.run(64);
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
fn native_system_time_installed_leaf_uses_host_clock_and_preserves_guards() {
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
            WindowsConfig::embedded("C:\\system-time.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let base = scratch(p);
        let last_error = thread.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x4A2E19F7).unwrap();
        let before = native_time();
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQuerySystemTime",
                &[base + 4]
            ),
            STATUS_SUCCESS
        );
        let after = native_time();
        let observed = p.space.u64(base + 4).unwrap();
        let module = p.modules.by_name("ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQuerySystemTime".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        assert!(
            (before..=after).contains(&observed),
            "{arch}/build{}: FILETIME ticks before={before} observed={observed} after={after}; installed leaf={:02x?}",
            p.cfg.version.build,
            p.space.bytes(entry, 48).unwrap()
        );
        assert_eq!(p.space.u32(last_error).unwrap(), 0x4A2E19F7);
        p.vm.poke(base + 4092, &[0xA5; 8]).unwrap();
        p.vm.protect(base + 4096, 4096, prot::READWRITE | prot::GUARD)
            .unwrap();
        let expected_unaligned = native_unaligned_status();
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQuerySystemTime",
                &[base + 4092]
            ),
            STATUS_GUARD_PAGE_VIOLATION
        );
        assert_eq!(p.vm.query(base + 4096).unwrap().protect, prot::READWRITE);
        assert_eq!(p.space.bytes(base + 4092, 8).unwrap(), [0xA5; 8]);
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQuerySystemTime",
                &[base + 1]
            ),
            expected_unaligned
        );
        assert_eq!(native_unaligned_status(), expected_unaligned);
    }
}

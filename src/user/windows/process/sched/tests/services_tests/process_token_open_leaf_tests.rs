//! Execute the selected installed NTDLL leaf, including x86 RET 12 cleanup.
use super::*;
use crate::user::windows::process::sched::run_cpu;
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
fn native_process_token_installed_leaf_matches_grants_faults_and_ret12() {
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
            WindowsConfig::embedded("C:\\process-token-leaf.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let output = scratch(p);
        let last_error = thread.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, LAST_ERROR).unwrap();
        let current = arch.ptr(u64::MAX);
        assert!(p.objects.primary_token_access().is_some());
        let count = p.objects.handle_count();
        let args = [current, 8, output];
        assert_eq!(
            leaf(p, &mut thread, "ntdll.dll", "NtOpenProcessToken", &args),
            STATUS_SUCCESS
        );
        let first = p.space.ptr(output, arch.ptr_size()).unwrap();
        let id = p.objects.id(first).unwrap();
        assert_eq!(p.objects.access(first), Some(8));
        assert_eq!(p.objects.flags(first), Some(0));
        assert_eq!(p.objects.handle_count(), count + 1);
        let expected = p
            .objects
            .primary_token_access()
            .unwrap()
            .grant(0x0200_0000)
            .unwrap();
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtOpenProcessToken",
                &[current, 0x0200_0000, output]
            ),
            STATUS_SUCCESS
        );
        let second = p.space.ptr(output, arch.ptr_size()).unwrap();
        assert_eq!(p.objects.id(second), Some(id));
        assert_eq!(p.objects.access(second), Some(expected));
        p.objects.close(first).unwrap();
        p.objects.close(second).unwrap();
        for (target, desired, status) in [
            (0, 8, STATUS_INVALID_HANDLE),
            (current, 0, STATUS_ACCESS_DENIED),
            (current, 0x0010_0000, STATUS_ACCESS_DENIED),
        ] {
            p.space.wr(output, &[0xA5; 8]).unwrap();
            assert_eq!(
                leaf(
                    p,
                    &mut thread,
                    "ntdll.dll",
                    "NtOpenProcessToken",
                    &[target, desired, output]
                ),
                status
            );
            assert_eq!(p.objects.handle_count(), count);
            let value = if arch == WinArch::X86 {
                0
            } else {
                0xA5A5_A5A5_A5A5_A5A5
            };
            assert_eq!(p.space.ptr(output, arch.ptr_size()).unwrap(), value);
        }
        p.vm.protect(output, 4096, prot::READWRITE | prot::GUARD)
            .unwrap();
        assert_eq!(
            leaf(p, &mut thread, "ntdll.dll", "NtOpenProcessToken", &args),
            STATUS_GUARD_PAGE_VIOLATION
        );
        assert_eq!(p.vm.query(output).unwrap().protect, prot::READWRITE);
        assert_eq!(p.objects.handle_count(), count);
        assert_eq!(
            leaf(p, &mut thread, "ntdll.dll", "NtOpenProcessToken", &args),
            STATUS_SUCCESS
        );
        let reopened = p.space.ptr(output, arch.ptr_size()).unwrap();
        assert_eq!(p.objects.id(reopened), Some(id));
        p.objects.close(reopened).unwrap();
        assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
    }
}

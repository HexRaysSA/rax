//! Execute the installed leaves and their own RET/RET imm16 on Windows.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

fn leaf(p: &mut Proc, t: &mut Thread, module: usize, name: &str, args: &[u64]) -> u32 {
    let entry = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let arch = p.arch;
    let sp = t.cpu.sp();
    let resume = p.traps.callback_return();
    for (index, &value) in args.iter().enumerate() {
        match arch {
            WinArch::X86 => p
                .space
                .w32(sp + 4 + index as u64 * 4, value as u32)
                .unwrap(),
            WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], value),
            WinArch::X64 => p.space.w64(sp + 8 + index as u64 * 8, value).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(index, value),
        }
    }
    match arch {
        WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
        WinArch::X64 => p.space.w64(sp, resume).unwrap(),
        WinArch::Arm64 => t.cpu.set_gpr(30, resume),
    }
    t.cpu.set_pc(entry);
    let mut completed = false;
    for _ in 0..64 {
        let boundary = run_cpu(p, &mut t.cpu, 64);
        if t.cpu.pc() == resume {
            completed = true;
            break;
        }
        assert!(
            matches!(
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{arch}/{name}"
        );
    }
    assert!(completed, "{arch}/{name} did not return");
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match arch {
            WinArch::X86 => 4 * (args.len() as u64 + 1),
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_console_owner_installed_native_and_wow_leaves_preserve_values_faults_and_actual_returns()
{
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
        let mut cfg =
            WindowsConfig::embedded("C:\\console-owner.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert_eq!(
            p.cfg.version.build,
            native_host_profile::build(),
            "installed profile must report the current host build"
        );
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let base =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wptr(base, arch.ptr_size(), 0).unwrap();
        let args = [arch.ptr(u64::MAX), 49, base, arch.ptr_size()];
        assert_eq!(
            leaf(p, &mut t, module, "NtSetInformationProcess", &args),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(p.console_host_process, 2);
        p.space.wptr(base, arch.ptr_size(), 1).unwrap();
        assert_eq!(
            leaf(p, &mut t, module, "NtSetInformationProcess", &args),
            STATUS_SUCCESS
        );
        assert_eq!(p.console_host_process, 1);
        p.space.wr(base + 64, &[0xA5; 32]).unwrap();
        let query = [
            arch.ptr(u64::MAX),
            49,
            base + 64,
            arch.ptr_size(),
            base + 88,
        ];
        let status = leaf(p, &mut t, module, "NtQueryInformationProcess", &query);
        if arch == WinArch::X86 {
            assert_eq!(status, STATUS_INVALID_INFO_CLASS);
            assert_eq!(p.space.bytes(base + 64, 32).unwrap(), [0xA5; 32]);
        } else {
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(p.space.u64(base + 64).unwrap(), 1);
            assert_eq!(p.space.u32(base + 88).unwrap(), 8);
        }
    }
}

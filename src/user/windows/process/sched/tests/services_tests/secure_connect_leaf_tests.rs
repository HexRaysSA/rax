//! Actual installed NTDLL entry/return execution, including the ninth argument.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
pub(in super::super) fn leaf(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    try_leaf(p, t, name, args).unwrap_or_else(|error| panic!("{name}: {error}"))
}

pub(in super::super) fn try_leaf(
    p: &mut Proc,
    t: &mut Thread,
    name: &str,
    args: &[u64],
) -> Result<u32, String> {
    let m = loader::load_dll(p, "ntdll.dll").unwrap();
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
            WinArch::Arm64 => p.space.w64(sp + (i - 8) as u64 * 8, value).unwrap(),
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
        match handle_stop(p, t, boundary) {
            Outcome::Continue | Outcome::Yield => {}
            Outcome::Fail(error) => {
                t.cpu.set_sp(saved_sp);
                return Err(error);
            }
            outcome => panic!("{name} {}: {outcome:?}", p.arch),
        }
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
    Ok(t.cpu.gpr(0) as u32)
}

#[test]
fn native_secure_connect_installed_nine_argument_leaves_preserve_failure_copyback_and_ret36() {
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
            WindowsConfig::embedded("C:\\native-secure-capture.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert!(p.native.is_some());
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let b = scratch(p, 32768);
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        name(
            p,
            b + 128,
            b + 256,
            "\\Windows\\RaxLpcMissing-native-capture-leaf",
        );
        p.space.w32(b + 64, 32).unwrap();
        let args = [b, b + 128, 0, 0, 0, 0, b + 80, b + 4096, b + 64];
        p.space.wr(b, &[0xA5; 32]).unwrap();
        assert_eq!(
            leaf(p, &mut thread, "NtSecureConnectPort", &args),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        let mut expected = vec![0xA5; 32];
        if arch == WinArch::X86 {
            expected[..4].fill(0);
        }
        assert_eq!(p.space.bytes(b, 32).unwrap(), expected);
        assert_eq!(p.space.u32(b + 64).unwrap(), 32);
        assert_eq!(p.objects.handle_count(), handles);
        assert_eq!(p.objects.iter().count(), objects);
    }
}

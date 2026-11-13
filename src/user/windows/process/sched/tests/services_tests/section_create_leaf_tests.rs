//! Execute actual installed NtCreateSection and NtClose leaves, including RET28.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
pub(super) fn leaf(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
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
fn native_section_create_installed_original_seven_argument_leaves_own_backing_until_close() {
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
            WindowsConfig::embedded("C:\\native-section-create.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let out = scratch(p);
        let maximum = out + 64;
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        p.space.w64(maximum, 65536).unwrap();
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtCreateSection",
                &[out, 0xF001F, 0, maximum, 4, 0x08000000, 0]
            ),
            0
        );
        let handle = get(p, out);
        assert_eq!(p.objects.access(handle), Some(0xF001F));
        assert_eq!(p.space.u64(maximum).unwrap(), 65536);
        let Object::Mapping {
            file: None,
            size,
            protect,
            attributes,
            shared: Some(shared),
        } = p.objects.get(handle).unwrap()
        else {
            panic!("real section object")
        };
        assert_eq!((*size, *protect, *attributes), (65536, 4, 0x08000000));
        let weak = std::sync::Arc::downgrade(shared);
        let mut bytes = vec![0xA5; 65536];
        assert_eq!(shared.read_at(0, &mut bytes).unwrap(), 65536);
        assert!(bytes.iter().all(|b| *b == 0));
        assert_eq!(leaf(p, &mut t, "NtClose", &[handle]), 0);
        assert!(weak.upgrade().is_none());
        assert_eq!(p.objects.handle_count(), handles);
        assert_eq!(p.objects.iter().count(), objects);
    }
}

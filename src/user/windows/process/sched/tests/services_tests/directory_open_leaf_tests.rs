//! Installed NTDLL entry, real syscall selection, and true x86 RET12.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

pub(super) fn run_leaf(p: &mut Proc, t: &mut Thread, args: [u64; 3], expected: u32) {
    let module = loader::load_dll(p, "ntdll.dll").unwrap();
    let entry = loader::lookup(
        p,
        module,
        &SymRef::Name(b"NtOpenDirectoryObject".to_vec(), None),
    )
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
            "{}: NtOpenDirectoryObject",
            p.arch
        );
    }
    assert!(returned);
    assert_eq!(t.cpu.gpr(0), u64::from(expected));
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 16,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(sp + 128);
}

#[test]
fn installed_directory_open_leaf_resolves_snapshot_and_ret12_cleanup() {
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
        let mut cfg =
            WindowsConfig::embedded("C:\\directory-open.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let b =
            p.vm.allocate(
                None,
                3 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let text: Vec<_> = "\\KnownDlls".encode_utf16().collect();
        p.space.put_wunits(b + 128, &text).unwrap();
        descriptor(p, b + 64, b + 128, 20, 22);
        attributes(
            p,
            b + 16,
            b + 64,
            0,
            0x40,
            if arch.is64() { 48 } else { 24 },
        );
        run_leaf(p, &mut t, [b, 3, b + 16], 0);
        let h = p.space.ptr(b, arch.ptr_size()).unwrap();
        assert_eq!(p.objects.get(h).unwrap().type_name(), "Directory");
        assert_eq!(p.objects.access(h), Some(3));
        p.objects.close(h).unwrap();
        run_leaf(p, &mut t, [0, 3, b + 16], STATUS_ACCESS_VIOLATION);
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            baseline
        );
        p.threads.insert(tid, t);
    }
}

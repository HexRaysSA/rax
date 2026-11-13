//! Execute installed NTDLL leaves, including its real WoW64 transition/RET.
use super::*;
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn native_timer2_arm_installed_ntdll_leaves_set_and_cancel_host_and_wow64() {
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
        let mut cfg = WindowsConfig::embedded("C:\\timer2-leaf.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let id = p.objects.create(Object::IrTimer {
            attributes: 8,
            timer_id: None,
            signaled: false,
            schedule: None,
        });
        let handle = u64::from(p.objects.open_access(id, false, 0x1f0003).unwrap());
        let data =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.w64(data, (-3_000_000_000i64) as u64).unwrap();
        p.space.wr(data + 16, &[0; 16]).unwrap();
        p.space.w64(data + 24, 750_000_000).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        for (name, args) in [
            ("NtSetTimer2", vec![handle, data, 0, data + 16]),
            ("NtCancelTimer2", vec![handle, 1]),
        ] {
            let entry = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                .unwrap()
                .unwrap();
            let sp = t.cpu.sp() - 128;
            let resume = p.traps.callback_return();
            t.cpu.set_sp(sp);
            t.cpu.set_pc(entry);
            for (i, value) in args.iter().copied().enumerate() {
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
            for _ in 0..64 {
                let boundary = run_cpu(p, &mut t.cpu, 64);
                if t.cpu.pc() == resume {
                    returned = true;
                    break;
                }
                assert_eq!(
                    handle_stop(p, &mut t, boundary),
                    Outcome::Continue,
                    "{arch}/{name}"
                );
            }
            assert!(returned, "{arch}/{name} did not return");
            assert_eq!(t.cpu.gpr(0), 0, "{arch}/{name}");
            assert_eq!(
                t.cpu.sp(),
                sp + match arch {
                    WinArch::X86 => 4 + 4 * args.len() as u64,
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
            assert!(t.frames.is_empty());
            assert!(
                matches!(p.objects.obj(id),Some(Object::IrTimer {schedule,signaled:false,..}) if schedule.is_some()==(name=="NtSetTimer2"))
            );
        }
        p.objects.close(handle).unwrap();
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            baseline
        );
    }
}

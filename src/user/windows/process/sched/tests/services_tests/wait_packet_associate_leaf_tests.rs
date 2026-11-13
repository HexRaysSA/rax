//! Installed leaves prove the real caller return, including x86 RET 32/RET 8.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
#[test]
fn installed_wait_packet_associate_and_cancel_leaves_return_all_arguments() {
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
            WindowsConfig::embedded("C:\\native-associate.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let sp = t.cpu.sp();
        let out = sp - 256;
        let resume = p.traps.callback_return();
        let before = (p.objects.handle_count(), p.objects.iter().count());
        for initial in [0, 1] {
            let w = object(p, 0, 0x1F0001);
            let port = object(p, 1, 0x1F0003);
            let target = p.objects.insert(Object::Event {
                manual: true,
                signaled: initial,
            }) as u64;
            for name in [
                "NtAssociateWaitCompletionPacket",
                "NtCancelWaitCompletionPacket",
            ] {
                let args = if name == "NtAssociateWaitCompletionPacket" {
                    p.space.wr(out, &[0xA5; 16]).unwrap();
                    vec![
                        w,
                        port,
                        target,
                        0x1234567887654321,
                        0xA1B2C3D4CCCCDDDD,
                        0xC1234567,
                        0xFEDCBA9876543210,
                        out,
                    ]
                } else {
                    vec![w, 1]
                };
                let entry =
                    loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap()
                        .unwrap();
                t.cpu.set_sp(sp);
                t.cpu.set_pc(entry);
                for (i, value) in args.iter().copied().enumerate() {
                    match arch {
                        WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
                        WinArch::X64 => {
                            if i < 4 {
                                t.cpu.set_gpr([1, 2, 8, 9][i], value)
                            } else {
                                p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap()
                            }
                        }
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
                        "{arch}/{name}"
                    );
                }
                assert!(returned, "{arch}/{name}: no return in 2048 instructions");
                assert_eq!(t.cpu.gpr(0), 0);
                assert!(t.frames.is_empty());
                assert_eq!(
                    t.cpu.sp(),
                    sp + match arch {
                        WinArch::X86 => 4 + 4 * args.len() as u64,
                        WinArch::X64 => 8,
                        WinArch::Arm64 => 0,
                    }
                );
                if name == "NtAssociateWaitCompletionPacket" {
                    assert_eq!(
                        p.space.bytes(out, 16).unwrap(),
                        [vec![initial as u8], vec![0xA5; 15]].concat()
                    );
                    assert_eq!(queued(p, port), initial as usize);
                } else {
                    assert_eq!(queued(p, port), 0);
                }
            }
            for h in [target, port, w] {
                p.objects.close(h).unwrap();
            }
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        }
    }
}

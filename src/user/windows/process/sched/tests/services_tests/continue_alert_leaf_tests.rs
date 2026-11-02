//! Actual installed NtContinue leaves resume the supplied target, including
//! owned CPU APC callbacks, without executing the leaf's normal return.
use super::*;
use crate::user::windows::process::thread::UserApc;
use crate::user::windows::{
    context::RegContext,
    layout,
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

fn invoke(p: &mut Proc, t: &mut Thread, entry: u64, address: u64, test: u64, target: &RegContext) {
    let sp = target.sp() - 128;
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    match p.arch {
        WinArch::X86 => {
            for (index, value) in [0xDEAD_0000, address, test].into_iter().enumerate() {
                p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
            }
        }
        WinArch::X64 => {
            p.space.w64(sp, 0xDEAD_0000).unwrap();
            t.cpu.set_gpr(1, address);
            t.cpu.set_gpr(2, test);
        }
        WinArch::Arm64 => {
            t.cpu.set_gpr(0, address);
            t.cpu.set_gpr(1, test);
            t.cpu.set_gpr(30, 0xDEAD_0000);
        }
    }
    let mut reached = false;
    for _ in 0..64 {
        if t.cpu.pc() == target.pc() && t.frames.is_empty() {
            reached = true;
            break;
        }
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == target.pc() && t.frames.is_empty() {
            reached = true;
            break;
        }
        match handle_stop(p, t, boundary) {
            Outcome::Continue | Outcome::Yield => (),
            other => panic!("installed NtContinue {}: {other:?}", p.arch),
        }
    }
    assert!(
        reached,
        "{} pc={:#x} frames={}",
        p.arch,
        t.cpu.pc(),
        t.frames.len()
    );
    assert_eq!(t.cpu.sp(), target.sp());
    assert_eq!(
        t.cpu.gpr(0),
        0x1234_5678,
        "restored result register is not an NTSTATUS"
    );
    assert_eq!(t.cpu.gpr(3), 0xCC55);
    assert!(t.frames.is_empty());
    assert!(t.wait_status.is_none());
}

#[test]
fn native_continue_alert_installed_leaves_execute_callbacks_against_the_replaced_context() {
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
            WindowsConfig::embedded("C:\\continue-alert-leaf.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(p, module, &SymRef::Name(b"NtContinue".to_vec(), None))
            .unwrap()
            .unwrap();
        let address =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let callback =
            p.vm.allocate(
                None,
                4096,
                mem::RESERVE | mem::COMMIT,
                prot::EXECUTE_READWRITE,
            )
            .unwrap()
            .0;
        let counter = address + 2048;
        let code: Vec<u8> = match arch {
            WinArch::X86 => vec![0x8B, 0x44, 0x24, 4, 0xFF, 0, 0xC2, 4, 0],
            WinArch::X64 => vec![0xFF, 1, 0xC3],
            WinArch::Arm64 => [0xB9400001u32, 0x11000421, 0xB9000001, 0xD65F03C0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        };
        p.vm.poke(callback, &code).unwrap();
        let mut target = RegContext::capture(&t.cpu);
        target.set_pc(p.traps.callback_return());
        target.set_sp((t.cpu.sp() - 512) & !15);
        target.set_gpr(0, 0x1234_5678);
        target.set_gpr(3, 0xCC55);
        target.write(&p.space, address).unwrap();
        let error = t.teb + layout::offsets(arch).teb_last_error;
        for alerted in [false, true] {
            p.space.w32(error, 0xC0DE).unwrap();
            p.space.w32(counter, 0).unwrap();
            t.apcs.extend(
                [(callback, counter), (callback, counter)]
                    .into_iter()
                    .map(UserApc::from),
            );
            t.user_alerted = alerted;
            invoke(p, &mut t, entry, address, 0, &target);
            assert_eq!(t.user_alerted, alerted);
            assert_eq!(t.apcs.len(), 2);
            assert_eq!(p.space.u32(counter).unwrap(), 0);
            invoke(p, &mut t, entry, address, 1, &target);
            assert!(!t.user_alerted);
            assert_eq!(t.apcs.len(), if alerted { 2 } else { 0 });
            assert_eq!(p.space.u32(counter).unwrap(), if alerted { 0 } else { 2 });
            invoke(p, &mut t, entry, address, 255, &target);
            assert!(t.apcs.is_empty());
            assert_eq!(p.space.u32(counter).unwrap(), 2);
            assert_eq!(p.space.u32(error).unwrap(), 0xC0DE);
        }
        // The callback replaces itself with the exact interrupted context via
        // the installed NtContinue leaf. Its native return path is unreachable.
        let abandon: Vec<u8> = match arch {
            WinArch::X86 => {
                let mut bytes = vec![
                    0x8B, 0x4C, 0x24, 4, 0xFF, 0x81, 0, 8, 0, 0, 0x6A, 0, 0x51, 0xB8,
                ];
                bytes.extend_from_slice(&(entry as u32).to_le_bytes());
                bytes.extend_from_slice(&[0xFF, 0xD0, 0x0F, 0x0B]);
                bytes
            }
            WinArch::X64 => {
                let mut bytes = vec![0xFF, 0x81, 0, 8, 0, 0, 0x31, 0xD2, 0x48, 0xB8];
                bytes.extend_from_slice(&entry.to_le_bytes());
                bytes.extend_from_slice(&[0xFF, 0xE0]);
                bytes
            }
            WinArch::Arm64 => {
                let mut bytes: Vec<_> = [
                    0xB9480002u32,
                    0x11000442,
                    0xB9080002,
                    0xD2800001,
                    0x58000090,
                    0xD61F0200,
                    0xD4200000,
                    0xD503201F,
                ]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
                bytes.extend_from_slice(&entry.to_le_bytes());
                bytes
            }
        };
        p.vm.poke(callback, &abandon).unwrap();
        p.space.w32(counter, 0).unwrap();
        t.apcs.push_back((callback, address).into());
        invoke(p, &mut t, entry, address, 1, &target);
        assert_eq!(p.space.u32(counter).unwrap(), 1);
        assert!(t.frames.is_empty());
        assert!(t.apcs.is_empty());
        assert!(t.wait_status.is_none());
    }
}

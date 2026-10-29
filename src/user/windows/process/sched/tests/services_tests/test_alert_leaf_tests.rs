//! Installed NTDLL zero-argument entry, actual CPU APC callbacks and RET 4.
use super::*;
use crate::user::windows::process::thread::UserApc;
use crate::user::windows::{
    layout,
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};
use std::ffi::c_void;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtTestAlert() -> i32;
    fn NtAlertThread(thread: *mut c_void) -> i32;
}

fn native_reference() -> [u32; 3] {
    std::thread::spawn(|| {
        // SAFETY: no pointer arguments; the pseudo handle selects only this
        // private validation thread. No caller/ambient host alert is consumed.
        unsafe {
            let first = NtTestAlert() as u32;
            assert_eq!(NtAlertThread((usize::MAX - 1) as *mut c_void), 0);
            [first, NtTestAlert() as u32, NtTestAlert() as u32]
        }
    })
    .join()
    .unwrap()
}

fn leaf(p: &mut Proc, t: &mut Thread, entry: u64) -> u32 {
    let saved = t.cpu.sp();
    let sp = saved - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    match p.arch {
        WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
        WinArch::X64 => p.space.w64(sp, resume).unwrap(),
        WinArch::Arm64 => t.cpu.set_gpr(30, resume),
    }
    let mut returned = false;
    for _ in 0..64 {
        if let Some(status) = t.wait_status.take() {
            assert_eq!(dispatch::wait_complete(p, t, status), Outcome::Continue);
        }
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == resume && t.frames.is_empty() {
            returned = true;
            break;
        }
        match handle_stop(p, t, boundary) {
            Outcome::Continue | Outcome::Yield => (),
            Outcome::Park => {
                let ThreadState::Waiting(wait) = t.state.clone() else {
                    panic!("missing native alert continuation")
                };
                let status = sync::poll(p, t.tid, &wait, Instant::now(), !t.apcs.is_empty())
                    .unwrap()
                    .unwrap();
                assert_eq!(status, sync::WAIT_IO_COMPLETION);
                sync::on_cancel(p, t.tid, &wait).unwrap();
                t.state = ThreadState::Ready;
                assert_eq!(begin_apcs(p, t, Some(status)), Outcome::Continue);
            }
            other => panic!("installed alert leaf: {other:?}"),
        }
    }
    assert!(returned, "{}", p.arch);
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 4,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(saved);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_test_alert_installed_leaves_match_private_native_alert_and_execute_apcs_with_ret4() {
    let expected = native_reference();
    assert_eq!(expected, [0, STATUS_ALERTED, 0]);
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
            WindowsConfig::embedded("C:\\test-alert-leaf.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let m = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(p, m, &SymRef::Name(b"NtTestAlert".to_vec(), None))
            .unwrap()
            .unwrap();
        let last_error = t.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0xC0DE).unwrap();
        assert_eq!(leaf(p, &mut t, entry), expected[0]);
        let code: Vec<u8> = match arch {
            // INC dword [context]; RET with the callback's native cleanup.
            WinArch::X86 => vec![0x8B, 0x44, 0x24, 4, 0xFF, 0, 0xC2, 4, 0],
            WinArch::X64 => vec![0xFF, 1, 0xC3],
            WinArch::Arm64 => [0xB9400001u32, 0x11000421, 0xB9000001, 0xD65F03C0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        };
        let callback =
            p.vm.allocate(
                None,
                4096,
                mem::RESERVE | mem::COMMIT,
                prot::EXECUTE_READWRITE,
            )
            .unwrap()
            .0;
        let counter =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.vm.poke(callback, &code).unwrap();
        p.space.w32(counter, 0).unwrap();
        t.apcs.extend(
            [(callback, counter), (callback, counter)]
                .into_iter()
                .map(UserApc::from),
        );
        t.user_alerted = true;
        assert_eq!(leaf(p, &mut t, entry), expected[1]);
        assert_eq!(t.apcs.len(), 2);
        assert_eq!(p.space.u32(counter).unwrap(), 0);
        assert_eq!(leaf(p, &mut t, entry), expected[2]);
        assert!(t.apcs.is_empty());
        assert_eq!(p.space.u32(counter).unwrap(), 2);
        assert_eq!(leaf(p, &mut t, entry), 0);
        assert_eq!(p.space.u32(counter).unwrap(), 2);
        assert_eq!(p.space.u32(last_error).unwrap(), 0xC0DE);
    }
}

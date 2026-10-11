//! Execute the selected installed six-argument leaf, including WoW64 RET 24.

use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn installed_group_topology_query_leaf_returns_guest_topology_and_actual_cleanup() {
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
        let mut config =
            WindowsConfig::embedded("C:\\native-topology.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQuerySystemInformationEx".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let scratch =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let call_sp = t.cpu.sp();
        for output_bytes in [0, 96] {
            t.cpu.set_sp(call_sp);
            p.space.wr(scratch, &[0xA5; 256]).unwrap();
            p.space.w32(scratch, 4).unwrap();
            let (output, returned) = (scratch + 32, scratch + 160);
            let args = [107, scratch, 4, output, output_bytes, returned];
            // Reuse the kernel transport setup, then restore the ordinary
            // leaf caller's positions before any instruction executes.
            group_call_arguments(p, &mut t, args, call_sp);
            let resume = p.traps.callback_return();
            match arch {
                WinArch::X86 => {
                    p.space.w32(call_sp, resume as u32).unwrap();
                    for (index, value) in args.into_iter().enumerate() {
                        p.space
                            .w32(call_sp + 4 + index as u64 * 4, value as u32)
                            .unwrap();
                    }
                }
                WinArch::X64 => {
                    p.space.w64(call_sp, resume).unwrap();
                    t.cpu.set_gpr(1, 107);
                }
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            t.cpu.set_pc(entry);
            let mut reached = false;
            for _ in 0..32 {
                let boundary = t.cpu.run(64);
                if t.cpu.pc() == resume {
                    reached = true;
                    break;
                }
                let outcome = handle_stop(p, &mut t, boundary);
                assert!(
                    matches!(outcome, Outcome::Continue | Outcome::Yield),
                    "{arch}: {outcome:?}"
                );
            }
            assert!(reached, "{arch}: selected leaf did not return");
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if output_bytes == 0 {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_SUCCESS
                })
            );
            let record = group_record(arch);
            assert_eq!(p.space.u32(returned).unwrap(), record.len() as u32);
            let mut expected = vec![0xA5; 96];
            if output_bytes != 0 {
                expected[..record.len()].copy_from_slice(&record);
            }
            assert_eq!(p.space.bytes(output, 96).unwrap(), expected);
            assert_eq!(
                t.cpu.sp(),
                call_sp
                    + match arch {
                        WinArch::X86 => 28,
                        WinArch::X64 => 8,
                        WinArch::Arm64 => 0,
                    }
            );
            assert!(t.frames.is_empty());
        }
    }
}

fn group_call_arguments(p: &mut Proc, t: &mut Thread, args: [u64; 6], sp: u64) {
    match p.arch {
        WinArch::X86 => {} // Ordinary caller slots are filled above.
        WinArch::X64 => {
            for (register, value) in [1, 2, 8, 9].into_iter().zip(args[..4].iter().copied()) {
                t.cpu.set_gpr(register, value);
            }
            for (index, value) in args[4..].iter().copied().enumerate() {
                p.space.w64(sp + 40 + index as u64 * 8, value).unwrap();
            }
        }
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
    }
}

//! Execute the actual selected installed NTDLL entry, including WoW64 RET 28.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn installed_allocate_ex_leaf_reserves_and_commits_constrained_guest_memory() {
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
            WindowsConfig::embedded("C:\\native-allocation.exe", vec![], vec![], 4096).unwrap();
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
            &SymRef::Name(b"NtAllocateVirtualMemoryEx".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let scratch =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let call_sp = t.cpu.sp();
        for constrained in [false, true] {
            // Recreate the caller's frame after the preceding callee cleanup.
            // Letting SP advance between calls can put arguments into scratch.
            t.cpu.set_sp(call_sp);
            ptr(p, scratch, 0);
            ptr(
                p,
                scratch + 16,
                if constrained { 0x1001 } else { 0x02001000 },
            );
            requirements(
                p,
                scratch,
                if constrained { 0x30000000 } else { 0 },
                if constrained { 0x30ffffff } else { 0 },
                if constrained { 0x100000 } else { 0 },
            );
            let sp = t.cpu.sp();
            let resume = p.traps.callback_return();
            let args = [
                arch.ptr(u64::MAX),
                scratch,
                scratch + 16,
                u64::from(if constrained {
                    mem::COMMIT
                } else {
                    mem::RESERVE | mem::TOP_DOWN
                }),
                u64::from(prot::READWRITE),
                scratch + 64,
                1,
            ];
            arguments(p, &mut t, &args);
            match arch {
                WinArch::X86 => {
                    p.space.w32(sp, resume as u32).unwrap();
                    for (i, value) in args.into_iter().enumerate() {
                        p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap();
                    }
                }
                WinArch::X64 => {
                    p.space.w64(sp, resume).unwrap();
                    t.cpu.set_gpr(1, arch.ptr(u64::MAX));
                }
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            t.cpu.set_pc(entry);
            let mut returned = false;
            for _ in 0..32 {
                let boundary = t.cpu.run(64);
                if t.cpu.pc() == resume {
                    returned = true;
                    break;
                }
                let description = format!("{arch:?} boundary={boundary:?}");
                assert!(
                    matches!(
                        handle_stop(p, &mut t, boundary),
                        Outcome::Continue | Outcome::Yield
                    ),
                    "{description}"
                );
            }
            assert!(
                returned,
                "installed NtAllocateVirtualMemoryEx did not return within 2048 instructions"
            );
            assert_eq!(t.cpu.gpr(0), 0, "{arch:?} constrained={constrained}");
            assert!(t.frames.is_empty());
            let base = get(p, scratch);
            assert_eq!(
                get(p, scratch + 16),
                if constrained { 0x2000 } else { 0x02001000 }
            );
            if constrained {
                assert_eq!(base, 0x30000000);
                assert_eq!(p.space.u8(base).unwrap(), 0);
                p.space.w8(base + 4096, 0x5a).unwrap();
            } else {
                assert_eq!(base % 65536, 0);
                assert!(p.space.u8(base).is_err());
            }
            assert_eq!(
                p.vm.query(base).unwrap().state,
                if constrained {
                    mem::COMMIT
                } else {
                    mem::RESERVE
                }
            );
            assert_eq!(
                t.cpu.sp(),
                sp + match arch {
                    WinArch::X86 => 32,
                    WinArch::X64 => 8,
                    WinArch::Arm64 => 0,
                }
            );
            p.vm.release(base).unwrap();
        }
    }
}

//! Real selected NTDLL class55 entry, including WoW64 CALL/thunk/RET16.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn installed_numa_map_query_leaf_preserves_padding_and_actual_cleanup() {
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
            WindowsConfig::embedded("C:\\native-numa-map.exe", vec![], vec![], 4096).unwrap();
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
            &SymRef::Name(b"NtQuerySystemInformation".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let data =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let call_sp = t.cpu.sp();
        for length in [0, 4, 20, 24, 1032] {
            t.cpu.set_sp(call_sp);
            p.space.wr(data, &[0xA5; 256]).unwrap();
            let output = data + 32;
            let returned = data + 160;
            query_arguments(p, &mut t, 55, output, length, returned);
            let resume = p.traps.callback_return();
            match arch {
                WinArch::X86 => {
                    p.space.w32(call_sp, resume as u32).unwrap();
                    for (index, value) in [55, output, u64::from(length), returned]
                        .into_iter()
                        .enumerate()
                    {
                        p.space
                            .w32(call_sp + 4 + index as u64 * 4, value as u32)
                            .unwrap();
                    }
                }
                WinArch::X64 => {
                    p.space.w64(call_sp, resume).unwrap();
                    t.cpu.set_gpr(1, 55);
                }
                WinArch::Arm64 => t.cpu.set_gpr(30, resume),
            }
            t.cpu.set_pc(entry);
            let mut resumed = false;
            for _ in 0..32 {
                let boundary = t.cpu.run(64);
                if t.cpu.pc() == resume {
                    resumed = true;
                    break;
                }
                assert!(
                    matches!(
                        handle_stop(p, &mut t, boundary),
                        Outcome::Continue | Outcome::Yield
                    ),
                    "{arch} PC={:#x}",
                    t.cpu.pc()
                );
            }
            assert!(resumed, "{arch} class55 did not return");
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(if length == 0 {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_SUCCESS
                })
            );
            assert_eq!(
                p.space.bytes(output, 64).unwrap(),
                expected_record(length, 64)
            );
            assert_eq!(
                p.space.u32(returned).unwrap(),
                returned_length(arch, length)
            );
            assert_eq!(
                t.cpu.sp(),
                call_sp
                    + match arch {
                        WinArch::X86 => 20,
                        WinArch::X64 => 8,
                        WinArch::Arm64 => 0,
                    }
            );
            assert!(t.frames.is_empty());
        }
    }
}

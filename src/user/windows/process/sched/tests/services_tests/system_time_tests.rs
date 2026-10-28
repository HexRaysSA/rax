//! ULONG alignment, atomic output, guard lifetime and native syscall transport.
use super::*;
use crate::user::windows::layout;

const SERVICE: u32 = 0x5a;
#[cfg(windows)]
#[path = "system_time_leaf_tests.rs"]
mod installed;
#[path = "system_time_replay_tests.rs"]
mod replay;

fn now() -> u64 {
    let duration = crate::host::time::system_now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    116_444_736_000_000_000 + u64::try_from(duration.as_nanos() / 100).unwrap()
}

fn call(p: &mut Proc, t: &mut Thread, output: u64) -> u32 {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::Arm64 => {
            t.cpu.set_gpr(0, output);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(10, output);
            t.cpu.set_gpr(1, 0x1234_0004);
        }
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            p.space.w32(sp + 8, output as u32).unwrap();
            t.cpu.set_gpr(0, SERVICE.into());
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(result, Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

fn scratch(p: &mut Proc) -> u64 {
    p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

#[test]
fn native_system_time_alignment_atomic_output_and_last_error_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQuerySystemTime", SERVICE);
        let p = process.state_mut();
        let base = scratch(p);
        let last_error = t.teb + layout::offsets(arch).teb_last_error;
        for offset in [0, 4, 8, 12, 4092] {
            p.vm.poke(base, &[0xA5; 8192]).unwrap();
            p.space.w32(last_error, 0x4A2E19F7).unwrap();
            let before = now();
            assert_eq!(call(p, &mut t, base + offset), STATUS_SUCCESS);
            let after = now();
            let actual = p.space.u64(base + offset).unwrap();
            assert!(
                (before..=after).contains(&actual),
                "{arch} host clock interval"
            );
            let mut expected = vec![0xA5; 8192];
            expected[offset as usize..offset as usize + 8].copy_from_slice(&actual.to_le_bytes());
            assert_eq!(p.space.bytes(base, 8192).unwrap(), expected);
            assert_eq!(p.space.u32(last_error).unwrap(), 0x4A2E19F7);
        }
        for address in [0, 1, arch.ptr(u64::MAX), arch.ptr(u64::MAX & !3)] {
            let expected = if address % 4 == 0 {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_DATATYPE_MISALIGNMENT
            };
            assert_eq!(call(p, &mut t, address), expected);
        }
    }
}

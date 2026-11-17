//! Raw native CDB name and packet controls through every syscall transport.
use super::*;
use crate::user::windows::appcompat::Catalog;

const SERVICE: u32 = 0x4c;

#[path = "apphelp_replay_tests.rs"]
mod replay;

#[path = "apphelp_executable_process_tests.rs"]
mod executable_process;

#[cfg(windows)]
#[path = "apphelp_leaf_tests.rs"]
mod installed;

fn call(p: &mut Proc, t: &mut Thread, operation: u32, input: u64) -> u32 {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    let args = [u64::from(operation), input];
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr([10, 2][index], value);
            }
        }
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (index, value) in args.into_iter().enumerate() {
                p.space
                    .w32(sp + 8 + index as u64 * 4, value as u32)
                    .unwrap();
            }
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

fn catalog() -> Catalog {
    let values: serde_json::Value = serde_json::from_str(include_str!("../../../../../../../docs/specifications/windows/native-apphelp-cache/cdb-candidate-flags.json")).unwrap();
    let entries: Vec<_> = values["names"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_u64().unwrap() as u32))
        .collect();
    Catalog::fixture(&entries)
}

fn scratch(p: &mut Proc) -> u64 {
    p.vm.allocate(
        None,
        PAGE_SIZE * 16,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap()
    .0
}

fn packet(p: &mut Proc, input: u64, name: u64, output: u64, length: u16, maximum: u16, size: u32) {
    let (name_at, out_at) = if p.arch.is64() {
        (248, 376)
    } else {
        (132, 196)
    };
    p.space.w16(input + name_at, length).unwrap();
    p.space.w16(input + name_at + 2, maximum).unwrap();
    if p.arch.is64() {
        p.space.w32(input + name_at + 4, 0).unwrap();
    }
    p.space
        .wptr(
            input + name_at + if p.arch.is64() { 8 } else { 4 },
            p.arch.ptr_size(),
            name,
        )
        .unwrap();
    p.space
        .wptr(input + out_at, p.arch.ptr_size(), output)
        .unwrap();
    p.space
        .w32(input + out_at + p.arch.ptr_size(), size)
        .unwrap();
}

#[test]
fn native_apphelp_cache_rejects_other_operations_without_mutating_guest_or_host() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtApphelpCacheControl", SERVICE);
        let p = process.state_mut();
        t.cpu.set_pc(0x1234_0004);
        if arch == WinArch::Arm64 {
            t.cpu.set_gpr(0, 7);
            t.cpu.set_gpr(1, 1);
        } else if arch == WinArch::X64 {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(10, 7);
            t.cpu.set_gpr(2, 1);
        } else {
            let sp = t.cpu.sp();
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0).unwrap();
            p.space.w32(sp + 8, 7).unwrap();
            p.space.w32(sp + 12, 1).unwrap();
            t.cpu.set_gpr(0, SERVICE.into());
        }
        let outcome = if arch == WinArch::X86 {
            super::super::super::super::services::wow64(p, &mut t, 0x1234_0000)
        } else {
            handle_stop(p, &mut t, stop(arch, SERVICE))
        };
        assert!(matches!(outcome, Outcome::Fail(message) if message.contains("operation 7")));
    }
}

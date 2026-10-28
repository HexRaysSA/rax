//! Independent native controls, guest residency and six-argument service ABI.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

#[path = "memory_prefetch_tests/inputs.rs"]
mod inputs;
#[cfg(windows)]
#[path = "memory_prefetch_tests/installed.rs"]
mod installed;
#[path = "memory_prefetch_tests/replay.rs"]
mod replay;

const SERVICE: u32 = 0x1b0;
const LAST_ERROR: u32 = 0x1234_5678;

fn enter(p: &mut Proc, t: &mut Thread, args: [u64; 6]) -> Outcome {
    let last_error = t.teb + layout::offsets(p.arch).teb_last_error;
    p.space.w32(last_error, LAST_ERROR).unwrap();
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
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
                if index < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][index], value);
                } else {
                    p.space.w64(sp + 8 + index as u64 * 8, value).unwrap();
                }
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
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}

fn valid_mask(p: &Proc, target: u64) -> u32 {
    (0..4).fold(0, |mask, page| {
        let address = target + page * 4096;
        mask | (u32::from(p.space.is_resident(address)) << page)
    })
}

#[test]
fn native_memory_prefetch_foreign_and_declared_class_frontiers_preserve_state() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
        let p = process.state_mut();
        let setup = inputs::prepare(p, 1);
        let object = p.objects.create(Object::Process {
            pid: p.pid + 4,
            exit_code: None,
        });
        let handle = p.objects.open_access(object, false, 8).unwrap();
        let mut args = setup.args;
        args[0] = handle.into();
        let before = p.objects.handle_count();
        let result = enter(p, &mut t, args);
        assert!(matches!(result, Outcome::Fail(ref text) if text.contains("for another process")));
        assert_eq!(valid_mask(p, setup.target), 0);
        assert_eq!(p.objects.handle_count(), before);
        assert_eq!(
            p.space
                .u32(t.teb + layout::offsets(arch).teb_last_error)
                .unwrap(),
            LAST_ERROR
        );
        for class in 1..9 {
            args = setup.args;
            args[1] = class;
            let result = enter(p, &mut t, args);
            assert!(
                matches!(result, Outcome::Fail(ref text) if text.contains(&format!("class {class}")))
            );
            assert_eq!(valid_mask(p, setup.target), 0);
            assert_eq!(p.objects.handle_count(), before);
            assert_eq!(
                p.space
                    .u32(t.teb + layout::offsets(arch).teb_last_error)
                    .unwrap(),
                LAST_ERROR
            );
        }
    }
}

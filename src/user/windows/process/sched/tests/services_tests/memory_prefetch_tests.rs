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

#[test]
fn native_memory_prefetch_kernel_capability_ignores_guest_version_and_refuses_unknown_flags_profile()
 {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
        let p = process.state_mut();
        let setup = inputs::prepare(p, 1);
        super::system_processor_tests::kernel_profile(p, 0x8664);
        let native = p.native.as_mut().unwrap();
        native.version.major = 10;
        native.version.minor = 0;
        native.version.build = 20348;
        std::sync::Arc::make_mut(&mut p.cfg).version.build = 26100;
        assert_eq!(enter(p, &mut t, setup.args), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_PARAMETER_5));
        assert_eq!(valid_mask(p, setup.target), 0);
        p.native.as_mut().unwrap().version.build = 99999;
        let result = enter(p, &mut t, setup.args);
        assert!(
            matches!(result, Outcome::Fail(ref text) if text.contains("memory-prefetch flag profile is not captured"))
        );
        assert_eq!(valid_mask(p, setup.target), 0);
        p.space.w32(setup.args[4], 0).unwrap();
        assert_eq!(enter(p, &mut t, setup.args), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(valid_mask(p, setup.target), 0);
    }
}

#[test]
fn native_memory_prefetch_29698_binds_exact_kernel_identity_and_preserves_rejected_state() {
    for arch in WinArch::ALL {
        for (major, minor, build, machine, admitted) in [
            (10, 0, 29698, Some(0xAA64), true),
            (10, 0, 29697, Some(0xAA64), false),
            (10, 0, 29699, Some(0xAA64), false),
            (10, 0, 29698, Some(0x8664), false),
            (10, 0, 29698, Some(0x14C), false),
            (10, 0, 29698, None, false),
            (11, 0, 29698, Some(0xAA64), false),
            (10, 1, 29698, Some(0xAA64), false),
        ] {
            let (mut process, mut t) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
            let p = process.state_mut();
            let setup = inputs::prepare(p, 1);
            super::system_processor_tests::kernel_profile(p, machine.unwrap_or(0));
            let native = p.native.as_mut().unwrap();
            native.version.major = major;
            native.version.minor = minor;
            native.version.build = build;
            native.object_namespace.native_machine = machine;
            std::sync::Arc::make_mut(&mut p.cfg).version.build = 29698;
            let handles = p.objects.handle_count();
            let committed = p.vm.committed_bytes();
            let ranges = p.space.bytes(setup.args[3], 32).unwrap();
            let information = p.space.bytes(setup.args[4], 32).unwrap();
            let outcome = enter(p, &mut t, setup.args);
            if admitted {
                assert_eq!(outcome, Outcome::Continue);
                assert_eq!(t.cpu.gpr(0), 0);
                assert_eq!(valid_mask(p, setup.target), 1);
            } else {
                assert!(matches!(outcome, Outcome::Fail(ref text)
                    if text.contains("memory-prefetch flag profile is not captured")));
                assert_eq!(valid_mask(p, setup.target), 0);
            }
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.vm.committed_bytes(), committed);
            assert_eq!(p.space.bytes(setup.args[3], 32).unwrap(), ranges);
            assert_eq!(p.space.bytes(setup.args[4], 32).unwrap(), information);
        }
    }
}

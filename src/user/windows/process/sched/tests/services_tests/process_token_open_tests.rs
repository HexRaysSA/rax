//! Captured primary-token grants, caller stores and process-owned handles.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::security::token::Access;

const SERVICE: u32 = 0x133;
const LAST_ERROR: u32 = 0x4A2E_19F7;

#[cfg(windows)]
#[path = "process_token_open_leaf_tests.rs"]
mod installed;
#[path = "process_token_open_replay_tests.rs"]
mod replay;

#[path = "process_token_open_tests/open_ex_29708.rs"]
mod open_ex_29708;

#[path = "process_token_open_tests/duplicate_29708.rs"]
mod duplicate_29708;

#[path = "process_token_open_tests/kind_29708.rs"]
mod kind_29708;

fn enter(p: &mut Proc, thread: &mut Thread, args: [u64; 3]) -> Outcome {
    let last_error = thread.teb + layout::offsets(p.arch).teb_last_error;
    p.space.w32(last_error, LAST_ERROR).unwrap();
    let sp = thread.cpu.sp();
    thread.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                thread.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            thread.cpu.set_gpr(0, SERVICE.into());
            thread.cpu.set_gpr(1, 0x1234_0004);
            for (index, value) in args.into_iter().enumerate() {
                thread.cpu.set_gpr([10, 2, 8][index], value);
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
            thread.cpu.set_gpr(0, SERVICE.into());
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, thread, 0x1234_0000)
    } else {
        handle_stop(p, thread, stop(p.arch, SERVICE))
    };
    if result == Outcome::Continue {
        assert_eq!(thread.cpu.pc(), 0x1234_0004);
        assert_eq!(
            thread.cpu.sp(),
            sp + if p.arch == WinArch::X86 { 4 } else { 0 }
        );
        assert!(thread.frames.is_empty());
    }
    assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
    thread.cpu.set_sp(sp);
    result
}

fn call(p: &mut Proc, thread: &mut Thread, process: u64, desired: u32, output: u64) -> u32 {
    assert_eq!(
        enter(p, thread, [process, desired.into(), output]),
        Outcome::Continue
    );
    thread.cpu.gpr(0) as u32
}

fn scratch(p: &mut Proc) -> u64 {
    p.vm.allocate(None, 8192, mem::COMMIT | mem::RESERVE, prot::READWRITE)
        .unwrap()
        .0
}

fn captured(p: &mut Proc) {
    p.objects.select_wnf_catalog(
        crate::user::windows::wnf::tests::catalog().with_primary_token_access(
            Access::new(0x000F_01FF, STATUS_PRIVILEGE_NOT_HELD).unwrap(),
        ),
    );
}

#[test]
fn native_process_token_opens_share_identity_and_keep_independent_grants_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtOpenProcessToken", SERVICE);
        let p = process.state_mut();
        captured(p);
        let output = scratch(p);
        let current = arch.ptr(u64::MAX);
        assert_eq!(call(p, &mut thread, current, 8, output), STATUS_SUCCESS);
        let a = p.space.ptr(output, arch.ptr_size()).unwrap();
        assert_eq!(call(p, &mut thread, current, 2, output), STATUS_SUCCESS);
        let b = p.space.ptr(output, arch.ptr_size()).unwrap();
        let id = p.objects.id(a).unwrap();
        assert_eq!(p.objects.id(b), Some(id));
        assert_eq!(p.objects.access(a), Some(8));
        assert_eq!(p.objects.access(b), Some(2));
        assert_eq!(p.objects.flags(a), Some(0));
        let duplicate = u64::from(p.objects.duplicate(a, false).unwrap());
        p.objects.close(a).unwrap();
        assert!(matches!(
            p.objects.get(duplicate | 3),
            Some(Object::PrimaryToken)
        ));
        p.objects.close(duplicate | 3).unwrap();
        p.objects.close(b).unwrap();
        assert!(matches!(p.objects.obj(id), Some(Object::PrimaryToken)));
        assert_eq!(call(p, &mut thread, current, 8, output), STATUS_SUCCESS);
        assert_eq!(
            p.objects.id(p.space.ptr(output, arch.ptr_size()).unwrap()),
            Some(id)
        );
    }
}

#[test]
fn native_process_token_missing_capture_and_foreign_subject_refuse_without_birth() {
    for arch in WinArch::ALL {
        for mode in 0..4 {
            let (mut process, mut thread) = fixture(arch, "NtOpenProcessToken", SERVICE);
            let p = process.state_mut();
            match mode {
                0 => p.objects.select_wnf_catalog(Default::default()),
                1 => p
                    .objects
                    .select_wnf_catalog(crate::user::windows::wnf::tests::catalog()),
                2 => p.objects.select_wnf_catalog(
                    crate::user::windows::wnf::Catalog::default().with_primary_token_access(
                        Access::new(8, STATUS_PRIVILEGE_NOT_HELD).unwrap(),
                    ),
                ),
                _ => captured(p),
            }
            let target = if mode == 3 {
                let id = p.objects.create(Object::Process {
                    pid: p.pid + 1,
                    exit_code: None,
                });
                u64::from(p.objects.open_access(id, false, 0x1000).unwrap())
            } else {
                arch.ptr(u64::MAX)
            };
            let output = scratch(p);
            p.space.wr(output, &[0xA5; 8]).unwrap();
            let before = (p.objects.handle_count(), p.objects.iter().count());
            assert_ne!(
                enter(p, &mut thread, [target, 8, output]),
                Outcome::Continue
            );
            assert_eq!(p.space.bytes(output, 8).unwrap(), [0xA5; 8]);
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        }
    }
}

#[test]
fn native_process_token_respects_a_reduced_captured_ceiling_and_security_grant() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtOpenProcessToken", SERVICE);
        let p = process.state_mut();
        p.objects.select_wnf_catalog(
            crate::user::windows::wnf::tests::catalog()
                .with_primary_token_access(Access::new(8, STATUS_SUCCESS).unwrap()),
        );
        let output = scratch(p);
        for (desired, expected) in [
            (2, Err(STATUS_ACCESS_DENIED)),
            (0x0200_0000, Ok(8)),
            (0x0300_0000, Ok(0x0100_0008)),
            (0x8000_0000, Err(STATUS_ACCESS_DENIED)),
        ] {
            let count = p.objects.handle_count();
            let status = call(p, &mut thread, arch.ptr(u64::MAX), desired, output);
            match expected {
                Ok(grant) => {
                    assert_eq!(status, STATUS_SUCCESS);
                    let handle = p.space.ptr(output, arch.ptr_size()).unwrap();
                    assert_eq!(p.objects.access(handle), Some(grant));
                    p.objects.close(handle).unwrap();
                }
                Err(expected) => assert_eq!(status, expected),
            }
            assert_eq!(p.objects.handle_count(), count);
        }
    }
}

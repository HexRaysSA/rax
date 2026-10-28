//! Independently observed caller stores, grants and object identity/lifetime.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::security::thread::Access;

#[cfg(windows)]
#[path = "thread_open_tests/installed.rs"]
mod installed;
#[path = "thread_open_tests/replay.rs"]
mod replay;

const SERVICE: u32 = 0x139;
const LAST_ERROR: u32 = 0x1234_5678;

fn enter(p: &mut Proc, t: &mut Thread, args: [u64; 4]) -> Outcome {
    let last_error = t.teb + layout::offsets(p.arch).teb_last_error;
    p.space.w32(last_error, LAST_ERROR).unwrap();
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::Arm64 => {
            for (n, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(n, value);
            }
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (n, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr([10, 2, 8, 9][n], value);
            }
        }
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (n, value) in args.into_iter().enumerate() {
                p.space.w32(sp + 8 + n as u64 * 4, value as u32).unwrap();
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
    assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
    t.cpu.set_sp(sp);
    result
}

fn call(p: &mut Proc, t: &mut Thread, args: [u64; 4]) -> u32 {
    assert_eq!(enter(p, t, args), Outcome::Continue);
    t.cpu.gpr(0) as u32
}

fn scratch(p: &mut Proc) -> u64 {
    p.vm.allocate(None, 24576, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

fn inputs(p: &mut Proc, t: &Thread, base: u64) -> (u64, u64) {
    let (oa, cid) = (base + 4096 + 128, base + 8192 + 128);
    let width = p.arch.ptr_size();
    let size = if width == 4 { 24 } else { 48 };
    p.space.wr(oa, &vec![0; size]).unwrap();
    p.space.w32(oa, size as u32).unwrap();
    p.space.wptr(cid, width, p.pid.into()).unwrap();
    p.space.wptr(cid + width, width, t.tid.into()).unwrap();
    (oa, cid)
}

#[test]
fn native_thread_open_retains_identity_independent_grants_and_exited_objects() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtOpenThread", SERVICE);
        let p = process.state_mut();
        let base = scratch(p);
        let (oa, cid) = inputs(p, &t, base);
        p.space.wptr(cid, arch.ptr_size(), 0).unwrap();
        p.space.w32(oa + 3 * arch.ptr_size(), 2).unwrap();
        assert_eq!(call(p, &mut t, [base, 0x40, oa, cid]), 0);
        let first = p.space.ptr(base, arch.ptr_size()).unwrap();
        assert_eq!(p.objects.id(first), Some(t.obj));
        assert_eq!(p.objects.access(first), Some(0x840));
        assert_eq!(p.objects.flags(first), Some(1));
        p.space.w32(oa + 3 * arch.ptr_size(), 0).unwrap();
        assert_eq!(call(p, &mut t, [base, 0x20, oa, cid]), 0);
        let second = p.space.ptr(base, arch.ptr_size()).unwrap();
        assert_ne!(first, second);
        assert_eq!(p.objects.access(second), Some(0x420));
        assert_eq!(p.objects.flags(second), Some(0));
        p.objects.close(first).unwrap();
        assert_eq!(p.objects.id(second), Some(t.obj));
        let peer = p.objects.create(Object::Thread {
            tid: 0x44,
            exit_code: Some(37),
        });
        p.objects.retain(peer); // The scheduler's reference before final exit.
        let retained = p.objects.open_access(peer, false, 0x100000).unwrap();
        p.space
            .wptr(cid + arch.ptr_size(), arch.ptr_size(), 0x45)
            .unwrap();
        assert_eq!(call(p, &mut t, [base, 0x800, oa, cid]), 0);
        let reopened = p.space.ptr(base, arch.ptr_size()).unwrap();
        assert_eq!(p.objects.id(reopened), Some(peer));
        p.objects.release(peer);
        p.objects.close(retained.into()).unwrap();
        assert!(p.objects.obj(peer).is_some());
        p.objects.close(reopened).unwrap();
        assert!(p.objects.obj(peer).is_none());
        assert_eq!(call(p, &mut t, [base, 0x800, oa, cid]), STATUS_INVALID_CID);
    }
}

#[test]
fn native_thread_open_unavailable_capture_and_reduced_ceiling_do_not_create_handles() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtOpenThread", SERVICE);
        let p = process.state_mut();
        let base = scratch(p);
        let (oa, cid) = inputs(p, &t, base);
        let count = p.objects.handle_count();
        p.thread_access = Err("controlled missing rights".into());
        let result = enter(p, &mut t, [base, 0x800, oa, cid]);
        assert!(
            matches!(result, Outcome::Fail(ref text) if text.contains("controlled missing rights"))
        );
        assert_eq!(p.objects.handle_count(), count);
        p.thread_access = Ok(Access::new(0x800, STATUS_PRIVILEGE_NOT_HELD, false, None).unwrap());
        assert_eq!(call(p, &mut t, [base, 0x40, oa, cid]), STATUS_ACCESS_DENIED);
        assert_eq!(
            call(p, &mut t, [base, 0x1000000, oa, cid]),
            STATUS_PRIVILEGE_NOT_HELD
        );
        assert_eq!(p.objects.handle_count(), count);
        assert_eq!(call(p, &mut t, [base, 0x2000000, oa, cid]), 0);
        let handle = p.space.ptr(base, arch.ptr_size()).unwrap();
        assert_eq!(p.objects.access(handle), Some(0x800));
    }
}

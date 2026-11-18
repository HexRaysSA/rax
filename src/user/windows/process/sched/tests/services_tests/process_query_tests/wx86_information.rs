use super::*;
use crate::user::windows::nt::status::{
    STATUS_GUARD_PAGE_VIOLATION, STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS,
};

const CLASS: u32 = 19;
const SENTINEL: u32 = 0xa5a5_a5a5;

fn query(p: &mut Proc, t: &mut Thread, handle: u64, output: u64, size: u32, returned: u64) -> u32 {
    let sp = t.cpu.sp();
    arguments(p, t, handle, CLASS, output, size, returned);
    assert_eq!(dispatch(p, t), Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_process_wx86_copies_scalar_after_length_and_handle_checks() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let own = arch.ptr(u64::MAX);
        let child = p.objects.create(Object::Process {
            pid: p.pid + 4,
            exit_code: None,
        });
        let permitted = u64::from(p.objects.open_access(child, false, 0x0400).unwrap());
        let limited = u64::from(p.objects.open_access(child, false, 0x1000).unwrap());
        let event = u64::from(p.objects.insert(Object::Event {
            manual: false,
            signaled: 0,
        }));
        let returned = base + 65;
        for (handle, output, len, size_dest, expected) in [
            (own, base, 4, returned, STATUS_SUCCESS),
            (permitted | 1, base, 4, returned, STATUS_SUCCESS),
            (limited, base, 4, returned, STATUS_ACCESS_DENIED),
            (own, 0, 4, returned, STATUS_ACCESS_VIOLATION),
            (0, 0, 4, returned, STATUS_INVALID_HANDLE),
            (0, base, 0, returned, STATUS_INFO_LENGTH_MISMATCH),
            (own, base, 3, returned, STATUS_INFO_LENGTH_MISMATCH),
            (own, base, 5, returned, STATUS_INFO_LENGTH_MISMATCH),
            (own, base + 1, 4, 1, STATUS_DATATYPE_MISALIGNMENT),
            (own, base, 3, 1, STATUS_ACCESS_VIOLATION),
            (event, base, 4, returned, STATUS_OBJECT_TYPE_MISMATCH),
            (
                arch.ptr(u64::MAX - 1),
                base,
                4,
                returned,
                STATUS_OBJECT_TYPE_MISMATCH,
            ),
        ] {
            p.space.wr(base, &[0xa5; 128]).unwrap();
            assert_eq!(
                query(p, &mut thread, handle, output, len, size_dest),
                expected
            );
            let (value, written) = if expected == STATUS_SUCCESS {
                (0, 4)
            } else {
                (SENTINEL, SENTINEL)
            };
            assert_eq!(p.space.u32(base).unwrap(), value);
            assert_eq!(p.space.u32(base + 4).unwrap(), SENTINEL);
            assert_eq!(p.space.u32(returned).unwrap(), written);
        }
        assert_eq!(query(p, &mut thread, own, base, 4, 0), STATUS_SUCCESS);
        assert_eq!(p.space.u32(base).unwrap(), 0);
        assert_eq!(query(p, &mut thread, own, base, 4, base), STATUS_SUCCESS);
        assert_eq!(p.space.u32(base).unwrap(), 4);
        if arch != WinArch::X86 {
            let high = p.vm.high();
            assert_eq!(
                query(p, &mut thread, 0, high, 4, returned),
                STATUS_ACCESS_VIOLATION
            );
        }
    }
}

#[test]
fn native_process_wx86_probes_return_length_before_writing_output() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let other =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let own = arch.ptr(u64::MAX);
        for (page, access, expected, post_access) in [
            (
                base,
                prot::READWRITE,
                STATUS_GUARD_PAGE_VIOLATION,
                prot::READWRITE,
            ),
            (
                other,
                prot::READWRITE,
                STATUS_GUARD_PAGE_VIOLATION,
                prot::READWRITE,
            ),
            (
                base,
                prot::READONLY,
                STATUS_ACCESS_VIOLATION,
                prot::READONLY | prot::GUARD,
            ),
            (
                other,
                prot::READONLY,
                STATUS_GUARD_PAGE_VIOLATION,
                prot::READONLY,
            ),
        ] {
            p.space.w32(base, SENTINEL).unwrap();
            p.space.w32(other, SENTINEL).unwrap();
            p.vm.protect(page, PAGE_SIZE, access | prot::GUARD).unwrap();
            assert_eq!(query(p, &mut thread, own, base, 4, other), expected);
            assert_eq!(p.vm.query(page).unwrap().protect, post_access);
            p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
            assert_eq!(p.space.u32(base).unwrap(), SENTINEL);
            assert_eq!(p.space.u32(other).unwrap(), SENTINEL);
        }
    }
}

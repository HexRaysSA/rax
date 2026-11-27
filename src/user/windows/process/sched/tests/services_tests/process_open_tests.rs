//! Replays the ARM64, x64 and WoW64 own-process observations on Windows 29708.
use super::thread_open_tests::enter_client_open;
use super::{Outcome, WinArch, fixture};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

#[test]
fn native_process_open_publishes_guest_query_handles_and_matches_failed_stores() {
    const SERVICE: u32 = 0x26;
    const SENTINEL: u64 = 0x1728_3940;
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtOpenProcess", SERVICE);
        let p = process.state_mut();
        let id = p
            .objects
            .iter()
            .find_map(|(id, object)| {
                matches!(object, Object::Process { pid, .. } if *pid == p.pid).then_some(id)
            })
            .expect("guest startup retains its own process object");
        let pid = u64::from(p.pid);
        let tid = u64::from(thread.tid);
        let width = arch.ptr_size();
        let address =
            p.vm.allocate(None, 0x1000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let (out, attrs, client) = (address, address + 32, address + 128);
        let length = if arch == WinArch::X86 { 24 } else { 48 };
        let flags_offset = 3 * width;
        let handles = p.objects.handle_count();

        for (desired, flags, pid, tid, status, grant) in [
            (0x400, 0, pid, 0, STATUS_SUCCESS, 0x1400),
            (0x1000, 2, pid, 0, STATUS_SUCCESS, 0x1000),
            (0x100000, 0, pid, 0, STATUS_SUCCESS, 0x100000),
            (0x101000, 0, pid, 0, STATUS_SUCCESS, 0x101000),
            (0x400, 0x200, pid | 3, 0, STATUS_SUCCESS, 0x1400),
            (0x400, 0, pid, tid | 3, STATUS_SUCCESS, 0x1400),
            (0x400, 0, pid | 3, tid, STATUS_INVALID_CID, 0),
            (0x400, 0, 0, tid, STATUS_INVALID_CID, 0),
            (0x400, 0, pid, tid + 0x100, STATUS_INVALID_CID, 0),
            (0x400, 0, pid + 0x100, 0, STATUS_INVALID_CID, 0),
            (0x400, 0x20, pid, 0, STATUS_INVALID_PARAMETER, 0),
            (0, 0, pid, 0, STATUS_ACCESS_DENIED, 0),
        ] {
            p.space.wptr(out, width, SENTINEL).unwrap();
            p.space.w32(attrs, length).unwrap();
            p.space.w32(attrs + flags_offset, flags).unwrap();
            p.space.wptr(client, width, pid).unwrap();
            p.space.wptr(client + width, width, tid).unwrap();
            assert_eq!(
                enter_client_open(p, &mut thread, SERVICE, [out, desired, attrs, client]),
                Outcome::Continue
            );
            assert_eq!(thread.cpu.gpr(0) as u32, status, "{arch:?} {desired:#x}");
            let handle = p.space.ptr(out, width).unwrap();
            if status == STATUS_SUCCESS {
                assert_eq!(p.objects.id(handle), Some(id));
                assert_eq!(p.objects.access(handle), Some(grant));
                assert_eq!(p.objects.flags(handle), Some(u32::from(flags & 2 != 0)));
                p.objects.close(handle).unwrap();
            } else {
                assert_eq!(handle, if width == 4 { 0 } else { SENTINEL });
            }
            assert_eq!(p.objects.handle_count(), handles);
        }

        p.space.wptr(client, width, pid).unwrap();
        p.space.wptr(client + width, width, 0).unwrap();
        p.space.w32(attrs, length).unwrap();
        for (attributes, id, status) in [
            (0, client, STATUS_ACCESS_VIOLATION),
            (attrs, 0, STATUS_INVALID_PARAMETER_MIX),
        ] {
            p.space.wptr(out, width, SENTINEL).unwrap();
            assert_eq!(
                enter_client_open(p, &mut thread, SERVICE, [out, 0x400, attributes, id]),
                Outcome::Continue
            );
            assert_eq!(thread.cpu.gpr(0) as u32, status);
            assert_eq!(
                p.space.ptr(out, width).unwrap(),
                if width == 4 { 0 } else { SENTINEL }
            );
        }
        p.space.w32(attrs, 0).unwrap();
        p.space.wptr(out, width, SENTINEL).unwrap();
        assert_eq!(
            enter_client_open(p, &mut thread, SERVICE, [out, 0x400, attrs, client]),
            Outcome::Continue
        );
        if width == 4 {
            assert_eq!(thread.cpu.gpr(0) as u32, STATUS_INVALID_PARAMETER);
            assert_eq!(p.space.ptr(out, width).unwrap(), SENTINEL);
        } else {
            assert_eq!(thread.cpu.gpr(0) as u32, STATUS_SUCCESS);
            let handle = p.space.ptr(out, width).unwrap();
            assert_eq!(p.objects.id(handle), Some(id));
            p.objects.close(handle).unwrap();
        }
        assert_eq!(p.objects.handle_count(), handles);
    }
}

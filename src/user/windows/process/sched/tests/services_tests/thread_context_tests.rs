use super::event_tests::{setup, status};
use super::*;
use crate::user::windows::context::RegContext;
use crate::user::windows::process::thread;

#[path = "thread_context_tests/native_replay.rs"]
mod native_replay;

#[test]
fn native_thread_context_integer_updates_are_transactional_and_preserve_control_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        let object = p.threads[&tid].obj;
        let handle = u64::from(p.objects.open_access(object, false, 24).unwrap());
        let before = RegContext::capture(&p.threads[&tid].cpu);
        let mut selected = before.clone();
        selected.set_flags(RegContext::arch_flag(arch) | 2);
        selected.set_gpr(0, 0x8877);
        selected.set_pc(0x5678);
        selected.set_sp(0x9999);
        selected.write(&p.space, scratch).unwrap();
        assert_eq!(
            status(p, &mut current, "NtSetContextThread", &[handle, scratch]),
            0
        );
        let after = RegContext::capture(&p.threads[&tid].cpu);
        assert_eq!(after.gpr(0), 0x8877);
        assert_eq!(after.pc(), before.pc());
        assert_eq!(after.sp(), before.sp());
        let flags_offset = if arch == WinArch::X64 { 48 } else { 0 };
        p.space.wr(scratch, &vec![0xa5; 2048]).unwrap();
        p.space
            .w32(scratch + flags_offset, RegContext::arch_flag(arch) | 2)
            .unwrap();
        assert_eq!(
            status(p, &mut current, "NtGetContextThread", &[handle, scratch]),
            0
        );
        let received = RegContext::read(&p.space, arch, scratch).unwrap();
        assert_eq!(received.gpr(0), 0x8877);
        assert_eq!(received.pc(), arch.ptr(0xa5a5_a5a5_a5a5_a5a5));
        let crossing = scratch + PAGE_SIZE - 64;
        selected.write(&p.space, crossing).unwrap();
        p.vm.protect(scratch + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let unchanged = RegContext::capture(&p.threads[&tid].cpu);
        assert_eq!(
            status(p, &mut current, "NtSetContextThread", &[handle, crossing]),
            0xc000_0005
        );
        assert_eq!(RegContext::capture(&p.threads[&tid].cpu), unchanged);
        p.vm.protect(scratch + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_thread_context_denied_or_wrong_handles_do_not_consume_output_guards() {
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        let object = p.threads[&tid].obj;
        let denied = u64::from(p.objects.open_access(object, false, 0).unwrap());
        let wrong = arch.ptr(u64::MAX);
        for name in ["NtGetContextThread", "NtSetContextThread"] {
            for (handle, expected) in [(denied, 0xc000_0022), (wrong, 0xc000_0024)] {
                p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                assert_eq!(status(p, &mut current, name, &[handle, scratch]), expected);
                assert_eq!(
                    p.vm.query(scratch).unwrap().protect,
                    prot::READWRITE | prot::GUARD
                );
            }
        }
        p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE).unwrap();
        p.objects.close(denied).unwrap();
    }
}

#[path = "thread_context_tests/debug_replay.rs"]
mod debug_replay;

#[path = "thread_context_tests/flags_replay.rs"]
mod flags_replay;

#[path = "thread_context_tests/extended_replay.rs"]
mod extended_replay;

#[path = "thread_context_tests/lifecycle_replay.rs"]
mod lifecycle_replay;

#[test]
fn native_thread_context_rejects_wrapping_flag_addresses_without_target_mutation() {
    for arch in WinArch::ALL {
        let (mut process, mut current, _) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        let handle = u64::from(
            p.objects
                .open_access(p.threads[&tid].obj, false, 24)
                .unwrap(),
        );
        for native in [false, true] {
            if native {
                native_replay::select_native(p, tid);
            }
            let before = RegContext::capture(&p.threads[&tid].cpu);
            for address in [u64::MAX - 15, u64::MAX - 31, u64::MAX - 47, u64::MAX - 63] {
                for api in ["NtGetContextThread", "NtSetContextThread"] {
                    assert_eq!(
                        status(p, &mut current, api, &[handle, arch.ptr(address)]),
                        0xc000_0005,
                        "{arch}/{native}/{api}/{address:#x}"
                    );
                    assert_eq!(RegContext::capture(&p.threads[&tid].cpu), before);
                }
            }
        }
        p.objects.close(handle).unwrap();
    }
}

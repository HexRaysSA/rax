//! Installed ordinary APC entry, NTSTATUS, and guest callback arguments.
use super::file_open_tests::arguments;
use super::*;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

const NUMBER: u32 = 0x33;
const BASIC: &str = "NtQueueApcThread";
const EXTENDED: &str = "NtQueueApcThreadEx";
const FLAGS: &str = "NtQueueApcThreadEx2";

fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, NUMBER)));
    let sp = t.cpu.sp();
    arguments(p, t, args);
    let outcome = if p.arch == WinArch::X86 {
        crate::user::windows::process::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, NUMBER))
    };
    assert_eq!(outcome, Outcome::Continue, "{}/{name}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

#[test]
fn ordinary_native_apc_forms_capture_and_deliver_fifo_arguments_on_every_abi() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, FLAGS, NUMBER);
        let state = process.state_mut();
        let own = arch.ptr(CURRENT_THREAD);
        let base = 0x1234_0000_0000_0000;
        let first = [base + 11, base + 12, base + 13].map(|value| arch.ptr(value));
        let second = [base + 21, base + 22, base + 23].map(|value| arch.ptr(value));
        let third = [base + 31, base + 32, base + 33].map(|value| arch.ptr(value));
        for (name, args) in [
            (BASIC, vec![own, 0x50000, first[0], first[1], first[2]]),
            (
                EXTENDED,
                vec![own, 0, 0x50004, second[0], second[1], second[2]],
            ),
            (
                FLAGS,
                vec![own, 0, 0, 0x50008, third[0], third[1], third[2]],
            ),
        ] {
            assert_eq!(call(state, &mut thread, name, &args), STATUS_SUCCESS);
        }
        assert_eq!(thread.apcs.len(), 3);
        let pc = thread.cpu.pc();
        let sp = thread.cpu.sp();
        assert_eq!(begin_apcs(state, &mut thread, None), Outcome::Continue);
        for (routine, expected) in [(0x50000, first), (0x50004, second), (0x50008, third)] {
            assert_eq!(thread.cpu.pc(), routine);
            let actual = match arch {
                WinArch::X86 => std::array::from_fn(|index| {
                    u64::from(
                        state
                            .space
                            .u32(thread.cpu.sp() + (index as u64 + 1) * 4)
                            .unwrap(),
                    )
                }),
                WinArch::X64 => [1, 2, 8].map(|reg| thread.cpu.gpr(reg)),
                WinArch::Arm64 => [0, 1, 2].map(|reg| thread.cpu.gpr(reg)),
            };
            assert_eq!(actual, expected);
            assert_eq!(
                dispatch::callback_return(state, &mut thread),
                Outcome::Continue
            );
        }
        assert_eq!(thread.cpu.pc(), pc);
        assert_eq!(thread.cpu.sp(), sp);
        assert!(thread.apcs.is_empty());
    }
}

#[test]
fn ordinary_native_apc_checks_handle_rights_and_thread_lifetime() {
    for arch in WinArch::ALL {
        let (mut process, mut current) = fixture(arch, FLAGS, NUMBER);
        let state = process.state_mut();
        let tid = thread::create(state, 0x50000, 0, 0x10000, false).unwrap();
        let object = state.threads[&tid].obj;
        let limited = u64::from(state.objects.open_access(object, false, 0x0800).unwrap());
        let granted = u64::from(state.objects.open_access(object, false, 0x0010).unwrap());
        let last_error = current.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        state.space.w32(last_error, 0x5aa5).unwrap();
        let queue = |state: &mut Proc, current: &mut Thread, handle| {
            call(state, current, FLAGS, &[handle, 0, 0, 0x50008, 1, 2, 3])
        };
        assert_eq!(queue(state, &mut current, 0), STATUS_INVALID_HANDLE);
        assert_eq!(
            queue(state, &mut current, arch.ptr(CURRENT_PROCESS)),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(queue(state, &mut current, limited), STATUS_ACCESS_DENIED);
        state.objects.close(limited).unwrap();
        assert_eq!(queue(state, &mut current, limited), STATUS_INVALID_HANDLE);
        assert!(state.threads[&tid].apcs.is_empty());
        assert_eq!(queue(state, &mut current, granted), STATUS_SUCCESS);
        assert_eq!(
            state.threads[&tid].apcs.front(),
            Some(&thread::UserApc::Native {
                routine: 0x50008,
                arguments: [1, 2, 3],
            })
        );
        assert!(current.apcs.is_empty());
        let Some(Object::Thread { exit_code, .. }) = state.objects.obj_mut(object) else {
            unreachable!();
        };
        *exit_code = Some(33);
        assert_eq!(queue(state, &mut current, granted), STATUS_UNSUCCESSFUL);
        assert_eq!(state.threads[&tid].apcs.len(), 1);
        assert_eq!(state.space.u32(last_error).unwrap(), 0x5aa5);
    }
}

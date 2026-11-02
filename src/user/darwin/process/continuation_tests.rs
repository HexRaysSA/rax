//! Scheduler regressions for entered calls and independently writable user state.
use super::*;
use crate::user::darwin::abi::tables::nr;

const ENTRY: u64 = 0x1_0000_1000;
const SVC: u32 = 0xd400_1001;
const NOP: u32 = 0xd503_201f;

fn blocked() -> (DarwinProcess, u64) {
    blocked_call(false)
}

fn blocked_call(indirect: bool) -> (DarwinProcess, u64) {
    let mut p = bounded_tests::process(DarwinAbi::Arm64);
    let (&tid, thread) = p.proc.threads.first_key_value().unwrap();
    let at = thread.cpu.sp() - 1024;
    p.proc.space.write(at, &7u32.to_le_bytes()).unwrap();
    let code: Vec<_> = [SVC, NOP, NOP, NOP]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    p.proc.space.write_raw(ENTRY, &code).unwrap();
    let thread = p.proc.threads.get_mut(&tid).unwrap();
    for (i, value) in [1, at, 7, 60_000_000].into_iter().enumerate() {
        thread.cpu.set_reg(i + usize::from(indirect), value);
    }
    if indirect {
        thread.cpu.set_reg(0, u64::from(nr::ULOCK_WAIT));
        thread.cpu.set_reg(16, 0);
    } else {
        thread.cpu.set_reg(16, u64::from(nr::ULOCK_WAIT));
    }
    thread.cpu.set_pc(ENTRY);
    assert_eq!(
        p.run_slice(1, &AtomicBool::new(false)),
        RunStatus::BudgetExhausted
    );
    let thread = &p.proc.threads[&tid];
    assert!(thread.wait.is_some());
    assert_eq!(thread.cpu.pc(), ENTRY + 4);
    assert_eq!(thread.pending_unix.unwrap().nr, nr::ULOCK_WAIT);
    assert_eq!(p.proc.task.syscalls.1, 1);
    (p, tid)
}

fn wake(p: &mut DarwinProcess, tid: u64, targeted: bool) {
    let thread = p.proc.threads.get_mut(&tid).unwrap();
    thread.woken = true;
    thread.wake_event = targeted;
}

#[test]
fn completed_bsd_return_preserves_only_successful_general_state_writes() {
    use crate::user::darwin::arch::Rv;
    use crate::user::darwin::{syscall, thread_status as ts};

    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for mutation in 0..8 {
            let mut process = bounded_tests::process(abi);
            let (_, mut thread) = process.proc.threads.pop_first().unwrap();
            let (general, unified, float, debug, flags, carry) = match abi {
                DarwinAbi::Arm64 => (6, 1, 17, 15, 66, 1 << 29),
                DarwinAbi::X86_64 => (4, 7, 5, 11, 34, 1),
            };
            let entry_value = match abi {
                DarwinAbi::Arm64 => 3,
                DarwinAbi::X86_64 => 0x200_0003,
            };
            thread.cpu.set_reg(0, entry_value);
            thread.cpu.set_pc(ENTRY + 16);
            thread.pending_unix = Some(syscall::PendingUnix {
                nr: nr::READ,
                args: [0; 8],
                pc: ENTRY + 4,
                completed: None,
                result_prepared: false,
            });
            syscall::complete_unix(&mut thread, Ok(Rv::one(0)));
            let arm = abi == DarwinAbi::Arm64;
            assert_eq!(thread.cpu.reg(0), if arm { 0 } else { entry_value });
            assert_eq!(thread.pending_unix.unwrap().result_prepared, arm);
            let flavor = match mutation {
                3 | 4 => unified,
                5 => float,
                6 => debug,
                _ => general,
            };
            let view = ts::View {
                cpu: &thread.cpu,
                entry: &thread.sig.entry,
                debug: &thread.mach.debug_state,
                ptrauth: false,
            };
            let mut state = ts::get(&view, flavor, ts::machine_state_count(abi, flavor)).unwrap();
            let offset = if matches!(mutation, 3 | 4) { 2 } else { 0 };
            if matches!(mutation, 1 | 3) {
                state[offset] = 0x1234;
                state[offset + 1] = 0;
                state[offset + flags] |= carry;
            }
            if mutation == 7 {
                state.pop();
                assert!(ts::set_thread(&mut thread, flavor, &state).is_err());
            } else if mutation != 0 {
                ts::set_thread(&mut thread, flavor, &state).unwrap();
            }
            let written = matches!(mutation, 1..=4);
            assert_eq!(thread.pending_unix.unwrap().result_prepared, arm || written);
            syscall::resume_unix(&mut process.proc, &mut thread);
            let expected = if matches!(mutation, 1 | 3) {
                0x1234
            } else if written && !arm {
                entry_value
            } else {
                0
            };
            assert_eq!(thread.cpu.reg(0), expected, "{abi:?}/{mutation}");
            let view = ts::View {
                cpu: &thread.cpu,
                entry: &thread.sig.entry,
                debug: &thread.mach.debug_state,
                ptrauth: false,
            };
            let state = ts::get(&view, general, ts::machine_state_count(abi, general)).unwrap();
            assert_eq!(state[flags] & carry != 0, matches!(mutation, 1 | 3));
            assert_eq!(thread.cpu.pc(), ENTRY + 16, "independent return PC");
            assert!(thread.pending_unix.is_none());
        }
    }
}

#[test]
fn entered_x86_bsd_call_keeps_decoded_arguments_and_independent_return_state() {
    for indirect in [false, true] {
        for mutation in 0..5 {
            let mut process = bounded_tests::process(DarwinAbi::X86_64);
            let (&tid, thread) = process.proc.threads.first_key_value().unwrap();
            let value = thread.cpu.sp() - 1024;
            process
                .proc
                .space
                .write(value, &7u32.to_le_bytes())
                .unwrap();
            process
                .proc
                .space
                .write_raw(ENTRY, &[0x0f, 0x05, 0x90, 0x90, 0x90, 0x90])
                .unwrap();
            let thread = process.proc.threads.get_mut(&tid).unwrap();
            thread.cpu.set_reg(
                0,
                if indirect {
                    0x200_0000
                } else {
                    0x200_0000 | u64::from(nr::ULOCK_WAIT)
                },
            );
            let arguments = [1, value, 7, 60_000_000];
            let registers = [7, 6, 2, 10, 8, 9];
            if indirect {
                thread.cpu.set_reg(7, u64::from(nr::ULOCK_WAIT));
            }
            for (index, argument) in arguments.into_iter().enumerate() {
                thread
                    .cpu
                    .set_reg(registers[index + usize::from(indirect)], argument);
            }
            thread.cpu.set_pc(ENTRY);
            assert_eq!(
                process.run_slice(1, &AtomicBool::new(false)),
                RunStatus::BudgetExhausted
            );
            let thread = process.proc.threads.get_mut(&tid).unwrap();
            assert!(thread.wait.is_some());
            assert_eq!(thread.cpu.pc(), ENTRY + 2);
            let entered = thread.pending_unix.unwrap();
            assert_eq!(entered.nr, nr::ULOCK_WAIT);
            assert_eq!(&entered.args[..4], &arguments);
            let selected = if mutation == 4 { ENTRY + 4 } else { ENTRY + 2 };
            thread.cpu.set_reg(12, 0x3456);
            match mutation {
                1 => thread
                    .cpu
                    .set_reg(registers[1 + usize::from(indirect)], u64::MAX),
                2 => thread.cpu.set_reg(0, 0x200_0014),
                3 => process.proc.space.write_raw(ENTRY, &[0x0f, 0x0b]).unwrap(),
                4 => thread.cpu.set_pc(selected),
                _ => {}
            }
            wake(&mut process, tid, true);
            assert_eq!(
                process.run_slice(1, &AtomicBool::new(false)),
                RunStatus::BudgetExhausted
            );
            let thread = &process.proc.threads[&tid];
            assert_eq!(thread.cpu.reg(0), 0, "{indirect}/{mutation}");
            assert_eq!(thread.cpu.reg(12), 0x3456);
            assert_eq!(thread.cpu.pc(), selected);
            assert!(
                thread.wait.is_none() && thread.resume.is_none() && thread.pending_unix.is_none()
            );
            assert_eq!(process.proc.task.syscalls.1, 1);
        }
    }
}

#[test]
fn entered_arm_bsd_call_keeps_arguments_number_and_return_pc_without_refetching_svc() {
    for mutation in 0..5 {
        let (mut p, tid) = blocked();
        let selected_pc = if mutation == 4 { ENTRY + 8 } else { ENTRY + 4 };
        let thread = p.proc.threads.get_mut(&tid).unwrap();
        thread.cpu.set_reg(19, 0x3456);
        match mutation {
            1 => {
                thread.cpu.set_reg(0, 0xffff);
                thread.cpu.set_reg(1, u64::MAX);
            }
            2 => thread.cpu.set_reg(16, u64::from(nr::GETPID)),
            3 => p.proc.space.write_raw(ENTRY, &0u32.to_le_bytes()).unwrap(),
            4 => thread.cpu.set_pc(selected_pc),
            _ => {}
        }
        wake(&mut p, tid, true);
        assert_eq!(
            p.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        let thread = &p.proc.threads[&tid];
        assert!(thread.wait.is_none() && thread.resume.is_none() && thread.pending_unix.is_none());
        assert_eq!(thread.cpu.reg(0), 0, "mutation {mutation}");
        assert_eq!(thread.cpu.reg(19), 0x3456);
        assert_eq!(thread.cpu.pc(), selected_pc);
        assert_eq!(
            p.proc.task.syscalls.1, 1,
            "a continuation is not another kernel entry"
        );
        assert_eq!(
            p.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        assert_eq!(p.proc.threads[&tid].cpu.pc(), selected_pc + 4);
    }
}

#[test]
fn entered_arm_bsd_spurious_wakes_keep_progress_and_one_entry_count() {
    let (mut p, tid) = blocked();
    let progress = p.proc.threads[&tid].resume.unwrap();
    let entered = p.proc.threads[&tid].pending_unix.unwrap();
    for _ in 0..3 {
        wake(&mut p, tid, false);
        assert_eq!(
            p.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        let thread = &p.proc.threads[&tid];
        assert!(thread.wait.is_some());
        assert_eq!(thread.resume, Some(progress));
        assert_eq!(thread.pending_unix, Some(entered));
        assert_eq!(thread.cpu.pc(), ENTRY + 4);
        assert_eq!(p.proc.task.syscalls.1, 1);
    }
    wake(&mut p, tid, true);
    assert_eq!(
        p.run_slice(1, &AtomicBool::new(false)),
        RunStatus::BudgetExhausted
    );
    assert!(p.proc.threads[&tid].pending_unix.is_none());
}

#[test]
fn entered_arm_bsd_service_obeys_task_and_thread_holds() {
    use crate::user::darwin::mach::suspend::Hold;
    let (mut p, tid) = blocked();
    wake(&mut p, tid, true);
    p.proc.task.suspension.place(Hold::Legacy).unwrap();
    assert_eq!(p.run_slice(1, &AtomicBool::new(false)), RunStatus::Blocked);
    assert!(p.proc.threads[&tid].pending_unix.is_some());
    p.proc.task.suspension.release(Hold::Legacy).unwrap();
    p.proc.threads.get_mut(&tid).unwrap().mach.suspend_count = 1;
    assert_eq!(p.run_slice(1, &AtomicBool::new(false)), RunStatus::Blocked);
    assert!(p.proc.threads[&tid].pending_unix.is_some());
    p.proc.threads.get_mut(&tid).unwrap().mach.suspend_count = 0;
    assert_eq!(
        p.run_slice(1, &AtomicBool::new(false)),
        RunStatus::BudgetExhausted
    );
    assert!(p.proc.threads[&tid].pending_unix.is_none());
}

#[test]
fn entered_arm_bsd_indirect_number_and_shifted_arguments_survive_user_state_writes() {
    let (mut p, tid) = blocked_call(true);
    let thread = p.proc.threads.get_mut(&tid).unwrap();
    thread.cpu.set_reg(0, u64::from(nr::GETPID));
    thread.cpu.set_reg(1, 0xffff);
    thread.cpu.set_reg(2, u64::MAX);
    wake(&mut p, tid, true);
    assert_eq!(
        p.run_slice(1, &AtomicBool::new(false)),
        RunStatus::BudgetExhausted
    );
    let thread = &p.proc.threads[&tid];
    assert_eq!(thread.cpu.reg(0), 0);
    assert_eq!(thread.cpu.pc(), ENTRY + 4);
    assert!(thread.pending_unix.is_none() && thread.resume.is_none());
    assert_eq!(p.proc.task.syscalls.1, 1);
}

#[test]
fn entered_arm_bsd_signal_return_retires_entry_and_restarts_from_current_saved_pc() {
    use crate::user::darwin::abi::Errno;
    for restart in [false, true] {
        for edited_pc in [false, true] {
            let (mut p, tid) = blocked();
            let mut thread = p.proc.threads.remove(&tid).unwrap();
            let pc = ENTRY + if edited_pc { 8 } else { 4 };
            thread.cpu.set_pc(pc);
            let sig = signal::SIGUSR1;
            let bit = signal::bit(sig);
            thread.sig.pending |= bit;
            p.proc.sigacts.ignore &= !bit;
            p.proc.sigacts.handler[sig as usize] = ENTRY + 12;
            if restart {
                p.proc.sigacts.intr &= !bit;
            } else {
                p.proc.sigacts.intr |= bit;
            }
            // The scheduler removes the registered wait before continuing
            // its service; inspect kernel return before the following AST.
            thread.wait = None;
            syscall::resume_unix(&mut p.proc, &mut thread);
            assert!(
                thread.wait.is_none() && thread.resume.is_none() && thread.pending_unix.is_none()
            );
            assert_eq!(thread.cpu.pc(), if restart { pc - 4 } else { pc });
            assert_eq!(
                thread.cpu.reg(0),
                if restart { 1 } else { Errno::EINTR.0 as u64 }
            );
            assert_ne!(
                thread.sig.pending & bit,
                0,
                "the user handler still needs delivery"
            );
            assert_eq!(p.proc.task.syscalls.1, 1);
        }
    }
}

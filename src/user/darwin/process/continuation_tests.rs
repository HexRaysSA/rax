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

//! A BSD signal wait is distinct from the task's user hold.

use super::*;
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::ipc::{KObject, Port};
use crate::user::darwin::mach::suspend::Hold;
use crate::user::darwin::process::{DarwinProcess, RunStatus, bounded_tests::process};
use std::sync::atomic::AtomicBool;

fn stopped_pair(abi: DarwinAbi) -> (DarwinProcess, u64, u64, transport::Link) {
    let mut process = process(abi);
    process.proc.ppid = 1001;
    process.proc.tracing.tracer = Some(1001);
    let (parent, child) = transport::Link::pair().unwrap();
    process.proc.tracing.family.parent = Some(child);
    let selected = *process.proc.threads.keys().next().unwrap();
    let worker = selected + 1;
    let mut other = crate::user::darwin::process::bounded_tests::process(abi)
        .proc
        .threads
        .pop_first()
        .unwrap()
        .1;
    other.tid = worker;
    other.kport = Port::new(KObject::Thread(worker));
    other.cpu = process.proc.new_thread_cpu();
    other.cpu.set_pc(process.proc.threads[&selected].cpu.pc());
    process.proc.threads.insert(worker, other);
    assert!(stop_for_signal(
        &mut process.proc,
        selected,
        signal::SIGSTOP,
        0
    ));
    (process, selected, worker, parent)
}

#[test]
fn an_out_of_band_task_resume_runs_the_other_thread_without_a_signal_verdict() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let (mut process, selected, _, peer) = stopped_pair(abi);
        let pc = process.proc.threads[&selected].cpu.pc();
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        process.proc.task.suspension.release(Hold::Legacy).unwrap();
        assert_eq!(
            process.run_slice(16, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        assert_eq!(process.proc.exit, Some(ExitStatus::Exited(37)));
        assert_eq!(process.proc.threads[&selected].cpu.pc(), pc);
        drop(peer);
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::Complete(ExitStatus::Exited(37))
        );
    }
}

#[test]
fn another_signal_keeps_its_pending_bit_and_cannot_replace_the_active_stop() {
    let (mut process, selected, worker, _peer) = stopped_pair(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    let mut thread = process.proc.threads.remove(&worker).unwrap();
    thread.sig.pending |= signal::bit(signal::SIGUSR1);
    signal::ast(&mut process.proc, &mut thread);
    assert_ne!(thread.sig.pending & signal::bit(signal::SIGUSR1), 0);
    assert_eq!(process.proc.tracing.stopped.unwrap().thread, selected);
    assert_eq!(process.proc.task.suspension.count(), 0);
}

#[test]
fn a_verdict_releases_sigwait_before_the_next_pending_signal_enters() {
    let (mut process, selected, worker, _peer) = stopped_pair(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    process.proc.tracing.stopped = None;
    process.proc.tracing.verdict = Some(Verdict {
        thread: selected,
        original: signal::SIGSTOP,
        signal: 0,
    });
    let mut next = process.proc.threads.remove(&worker).unwrap();
    next.sig.pending |= signal::bit(signal::SIGUSR1);
    signal::ast(&mut process.proc, &mut next);
    assert_ne!(next.sig.pending & signal::bit(signal::SIGUSR1), 0);
    let mut original = process.proc.threads.remove(&selected).unwrap();
    signal::ast(&mut process.proc, &mut original);
    assert!(process.proc.tracing.sigwait.is_none());
    signal::ast(&mut process.proc, &mut next);
    assert_eq!(process.proc.tracing.stopped.unwrap().thread, worker);
    assert_eq!(next.sig.pending & signal::bit(signal::SIGUSR1), 0);
    assert_eq!(process.proc.task.suspension.count(), 1);
}

#[test]
fn a_soft_wait_keeps_its_kind_across_detach_and_ends_on_its_reply_verdict() {
    let (mut process, selected, worker, _peer) = stopped_pair(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    sigwait::begin(&mut process.proc.tracing, selected, false);
    process.proc.tracing.tracer = None;
    process.proc.tracing.signal_exceptions = false;
    assert!(!thread_suspended(
        &process.proc.tracing,
        &process.proc.threads[&selected]
    ));
    assert!(signal_wait_blocked(&process.proc.tracing, worker));
    bsd_signal_returned(&mut process.proc.tracing, selected, signal::SIGUSR1);
    assert!(signal_wait_blocked(&process.proc.tracing, worker));
    assert_eq!(
        take_verdict(&mut process.proc.tracing, selected),
        Some((signal::SIGUSR1, signal::SIGUSR1))
    );
    assert!(!signal_wait_blocked(&process.proc.tracing, worker));
    // SSTOP can remain after a failed/returned bsd_exception.
    assert_eq!(process.proc.tracing.stopped.unwrap().thread, selected);
}

#[test]
fn a_missing_exception_handler_finishes_sigwait_without_clearing_stop_metadata() {
    let (mut process, selected, worker, _peer) = stopped_pair(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    end_sigwait(&mut process.proc.tracing, selected);
    process.proc.tracing.stopped = None;
    process.proc.tracing.signal_exceptions = true;
    process.proc.sigacts.handler[signal::SIGUSR1 as usize] = signal::SIG_IGN;
    let mut original = process.proc.threads.remove(&selected).unwrap();
    original.sig.pending |= signal::bit(signal::SIGUSR1);
    signal::ast(&mut process.proc, &mut original);
    assert!(process.proc.exit.is_none());
    assert!(process.proc.tracing.sigwait.is_none());
    assert_eq!(process.proc.tracing.stopped.unwrap().thread, selected);
    assert!(!signal_wait_blocked(&process.proc.tracing, worker));
}

#[test]
fn a_terminated_wait_owner_cannot_strand_the_next_signal() {
    let (mut process, selected, worker, _peer) = stopped_pair(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    process.proc.threads.get_mut(&selected).unwrap().exited = true;
    sigwait::reap(&mut process.proc, None);
    let mut next = process.proc.threads.remove(&worker).unwrap();
    next.sig.pending |= signal::bit(signal::SIGUSR1);
    signal::ast(&mut process.proc, &mut next);
    assert_eq!(process.proc.tracing.stopped.unwrap().thread, worker);
    assert_eq!(process.proc.task.suspension.count(), 1);
}

#[test]
fn exec_does_not_carry_the_old_images_signal_wait() {
    let (process, _, _, _peer) = stopped_pair(DarwinAbi::Arm64);
    let replacement = process.proc.tracing.for_exec();
    assert!(replacement.sigwait.is_none());
    assert!(replacement.stopped.is_none());
}

#[test]
fn pending_signals_become_waits_only_after_entering_signal_processing() {
    let (mut process, selected, worker, _peer) = stopped_pair(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    let mut next = process.proc.threads.remove(&worker).unwrap();
    next.sig.pending |= signal::bit(signal::SIGUSR1);
    assert!(!signal_waiting(&process.proc.tracing, next.tid));
    signal::ast(&mut process.proc, &mut next);
    assert!(signal_waiting(&process.proc.tracing, next.tid));
    assert_eq!(
        crate::user::darwin::mig::thread::basic_info(&next, false, false, true)[6],
        3
    );
    end_sigwait(&mut process.proc.tracing, selected);
    process.proc.tracing.tracer = None;
    next.sig.pending = 0;
    assert!(needs_signal_ast(&process.proc.tracing, &next));
    signal::ast(&mut process.proc, &mut next);
    assert!(!process.proc.tracing.sigwaiters.contains(&next.tid));
    assert!(!needs_signal_ast(&process.proc.tracing, &next));
}

#[test]
fn a_hard_signal_wait_is_waiting_with_and_without_its_task_hold() {
    let (mut process, selected, _, _peer) = stopped_pair(DarwinAbi::Arm64);
    for task_stopped in [true, false] {
        let thread = &process.proc.threads[&selected];
        let waiting = signal_waiting(&process.proc.tracing, thread.tid);
        assert!(waiting);
        assert_eq!(
            crate::user::darwin::mig::thread::basic_info(thread, true, task_stopped, waiting)[6],
            3
        );
        if task_stopped {
            process.proc.task.suspension.release(Hold::Legacy).unwrap();
        }
    }
}

#[test]
fn enabling_signal_exceptions_does_not_change_how_an_existing_hard_wait_wakes() {
    let (mut process, selected, _, mut peer) = stopped_pair(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    process.proc.tracing.signal_exceptions = true;
    peer.queue(
        &protocol::Message::Resume {
            id: 1,
            signal: 0,
            mode: protocol::ResumeMode::Continue,
            uid: process.proc.creds.0,
        }
        .encode(),
    )
    .unwrap();
    peer.flush().unwrap();
    pump(&mut process.proc, None);
    assert!(has_verdict(&process.proc.tracing, selected));
    assert_eq!(
        take_verdict(&mut process.proc.tracing, selected),
        Some((0, signal::SIGSTOP))
    );
    assert!(process.proc.tracing.sigwait.is_none());
}

#[test]
fn a_substituted_signal_completes_the_exact_kernel_continuation_before_its_handler() {
    use crate::user::darwin::wait::Resume;
    for (abi, length) in [(DarwinAbi::Arm64, 4), (DarwinAbi::X86_64, 2)] {
        let (mut process, selected, _, _peer) = stopped_pair(abi);
        let mut thread = process.proc.threads.remove(&selected).unwrap();
        let pc = thread.cpu.pc();
        process.proc.sigacts.handler[signal::SIGUSR1 as usize] = pc;
        thread.resume = Some(Resume {
            pc: pc + length,
            call: 111,
            deadline: None,
            step: 0,
        });
        process.proc.tracing.verdict = Some(Verdict {
            thread: selected,
            signal: signal::SIGUSR1,
            original: signal::SIGSTOP,
        });
        assert!(resume_before_verdict(&process.proc, &mut thread));
        assert_ne!(thread.sig.pending & signal::bit(signal::SIGUSR1), 0);
        assert!(has_verdict(&process.proc.tracing, selected));
        thread.cpu.set_pc(pc + length);
        assert!(!resume_before_verdict(&process.proc, &mut thread));
        thread.cpu.set_pc(pc);
        thread.sig.mask |= signal::bit(signal::SIGUSR1);
        assert!(!resume_before_verdict(&process.proc, &mut thread));
        thread.sig.mask = 0;
        for value in [0, signal::SIGKILL] {
            process.proc.tracing.verdict.as_mut().unwrap().signal = value;
            assert!(!resume_before_verdict(&process.proc, &mut thread));
        }
    }
}

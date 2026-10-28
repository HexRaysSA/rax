//! Job-stop metadata is independent of task holds and quiescent APC waits.

use super::*;
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::suspend::Hold;
use crate::user::darwin::process::{DarwinProcess, RunStatus, bounded_tests::process};
use std::sync::atomic::AtomicBool;

fn job(abi: DarwinAbi) -> (DarwinProcess, u64, transport::Link) {
    let mut process = process(abi);
    process.proc.config.host_job_control = true;
    process.proc.ppid = 1001;
    let (peer, child) = transport::Link::pair().unwrap();
    process.proc.tracing.family.parent = Some(child);
    let thread = *process.proc.threads.keys().next().unwrap();
    assert!(stop_job(&mut process.proc, thread, signal::SIGSTOP));
    (process, thread, peer)
}

#[test]
fn draining_the_job_hold_runs_the_thread_without_a_continue_signal() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let (mut process, _, _peer) = job(abi);
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        process.proc.task.suspension.place(Hold::Legacy).unwrap();
        process.proc.task.suspension.release(Hold::Legacy).unwrap();
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        process.proc.task.suspension.release(Hold::Legacy).unwrap();
        assert_eq!(
            process.run_slice(16, &AtomicBool::new(false)),
            RunStatus::Complete(ExitStatus::Exited(37))
        );
        assert!(job_stopped(&process.proc.tracing));
    }
}

#[test]
fn a_resumed_job_can_take_a_signal_while_its_bsd_status_is_stopped() {
    let (mut process, thread, _peer) = job(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    let mut thread = process.proc.threads.remove(&thread).unwrap();
    thread.sig.pending |= signal::bit(signal::SIGUSR1);
    signal::ast(&mut process.proc, &mut thread);
    assert!(matches!(
        process.proc.exit,
        Some(ExitStatus::Signaled {
            signo: signal::SIGUSR1,
            ..
        })
    ));
}

#[test]
fn own_job_status_stays_sstop_until_sigcont_even_after_the_hold_drains() {
    let (mut process, _, _peer) = job(DarwinAbi::Arm64);
    process.proc.task.suspension.release(Hold::Legacy).unwrap();
    let pid = process.proc.pid;
    assert_eq!(
        known_signal_status(&process.proc.tracing, pid, pid),
        Some((true, signal::SIGSTOP))
    );
    continue_job(&mut process.proc);
    assert_eq!(
        known_signal_status(&process.proc.tracing, pid, pid),
        Some((false, signal::SIGCONT))
    );
    assert_eq!(process.proc.task.suspension.count(), 0);
}

#[test]
fn quiescent_task_and_thread_holds_are_waiting_and_keep_the_suspend_count() {
    let process = process(DarwinAbi::Arm64);
    let mut thread = process.proc.threads.into_values().next().unwrap();
    for task_hold in [false, true] {
        for thread_holds in [0, 1, 2] {
            thread.mach.suspend_count = thread_holds;
            let info =
                crate::user::darwin::mig::thread::basic_info(&thread, true, task_hold, false);
            assert_eq!(info[6], if task_hold || thread_holds != 0 { 3 } else { 1 });
            assert_eq!(info[8], thread_holds);
        }
    }
}

#[test]
fn resuming_stop_metadata_without_sigwait_keeps_independent_holds_and_no_verdict() {
    use protocol::{Message, ResumeMode};

    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for mode in [
            ResumeMode::Continue,
            ResumeMode::Step,
            ResumeMode::Detach,
            ResumeMode::Kill,
        ] {
            let (mut process, _, mut peer) = job(abi);
            process.proc.task.suspension.release(Hold::Legacy).unwrap();
            // PT_ATTACH preserves SSTOP while its new SIGSTOP has not yet
            // entered issignal. An independent hold is not a BSD sigwait.
            process.proc.tracing.stopped = process.proc.tracing.job_stopped.take();
            process.proc.tracing.tracer = Some(process.proc.ppid);
            process.proc.tracing.attached_job_stop = true;
            process.proc.task.suspension.place(Hold::Normal).unwrap();
            peer.queue(
                &Message::Resume {
                    id: 71,
                    signal: 0,
                    mode,
                    uid: 501,
                }
                .encode(),
            )
            .unwrap();
            peer.flush().unwrap();
            pump(&mut process.proc, None);
            assert_eq!(process.proc.task.suspension.count(), 1, "{abi:?} {mode:?}");
            assert!(process.proc.tracing.sigwait.is_none());
            assert!(process.proc.tracing.verdict.is_none(), "{abi:?} {mode:?}");
            assert!(process.proc.tracing.exit_after_reply.is_none());
            assert!(process.proc.tracing.stopped.is_none());
        }
    }
}

#[test]
fn an_attach_stop_replaces_old_job_metadata_and_is_reported_once() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for waited in [false, true] {
            for attaching in [false, true] {
                let mut parent = process(abi);
                let (link, mut peer) = transport::Link::pair().unwrap();
                let mut child = Child::new(link, parent.proc.pid);
                child.traced = true;
                child.stop = Some(ChildStop {
                    thread: 9,
                    signal: signal::SIGTSTP,
                    waited,
                });
                child.attach_stop_pending = attaching;
                parent.proc.tracing.family.children.insert(1002, child);
                peer.queue(
                    &protocol::Message::Stop {
                        thread: 9,
                        signal: signal::SIGSTOP,
                        uid: 501,
                        notify: true,
                    }
                    .encode(),
                )
                .unwrap();
                peer.flush().unwrap();
                pump(&mut parent.proc, None);
                let expected = if attaching {
                    Some((1002, signal::SIGSTOP))
                } else if waited {
                    None
                } else {
                    Some((1002, signal::SIGTSTP))
                };
                assert_eq!(
                    wait_stop(&mut parent.proc.tracing, 1002, false),
                    expected,
                    "{abi:?} waited={waited} attaching={attaching}"
                );
                assert_eq!(wait_stop(&mut parent.proc.tracing, 1002, false), None);
                assert!(!parent.proc.tracing.family.children[&1002].attach_stop_pending);
            }
        }
    }
}

#[test]
fn an_authenticated_registry_wake_preserves_a_guest_stop_without_double_holding() {
    let mut process = process(DarwinAbi::Arm64);
    let thread = *process.proc.threads.keys().next().unwrap();
    job_control::registry_woke(&mut process.proc);
    assert_eq!(process.proc.task.suspension.count(), 1);
    assert!(job_stopped(&process.proc.tracing));
    assert_eq!(
        process.run_slice(8, &AtomicBool::new(false)),
        RunStatus::Blocked
    );
    process.proc.tracing.native_host_stop = true;
    job_control::registry_woke(&mut process.proc);
    assert!(!process.proc.tracing.native_host_stop);
    assert_eq!(process.proc.tracing.job_stopped.unwrap().thread, thread);
    assert_eq!(process.proc.task.suspension.count(), 1);
    continue_job(&mut process.proc);
    assert_eq!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Exited(37))
    );
}

//! Backpressure and exit ordering on the family connection.

use super::*;

#[test]
fn reply_backpressure_delays_requests_without_closing_the_link() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let _task_name = tracer.proc.insert_send(&task);
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 1024]).unwrap();
    let state = &mut tracee.proc.tracing.family.mach;
    for _ in 0..4 {
        state.parent_server.replies.push_back(transport::Frame {
            payload: vec![0; MAX_FRAME],
            fd: None,
        });
        state.parent_server.queued_bytes += MAX_FRAME;
    }
    let notice = Message::Dead {
        generation: 7,
        instance: 8,
        object: Object::Thread(9),
    };
    let expected_notice = notice.encode().unwrap();
    assert!(queue_response(&mut tracee.proc, notice));
    tracee.proc.config.host_job_control = true;
    tracee.proc.config.host_services = false;
    assert!(ptrace::stop_job(
        &mut tracee.proc,
        tid,
        crate::user::darwin::signal::SIGSTOP
    ));
    assert!(ptrace::suspended(&tracee.proc.tracing));
    let expected_stop = super::super::super::protocol::Message::JobStop {
        thread: tid,
        signal: crate::user::darwin::signal::SIGSTOP,
        uid: 501,
    }
    .encode();
    ptrace::pump(&mut tracee.proc, None);
    assert!(tracee.proc.tracing.family.parent.is_some());
    assert!(
        !tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Task))
    );
    let fds = ptrace::wait_fds(&tracee.proc.tracing);
    assert!(
        !fds[0].1,
        "read readiness must be paused while replies are blocked"
    );

    let mut received_notice = false;
    let mut received_stop = false;
    for _ in 0..10_000 {
        let link = tracer
            .proc
            .tracing
            .family
            .children
            .get_mut(&1002)
            .unwrap()
            .link
            .as_mut()
            .unwrap();
        let (frames, _) = link.receive().unwrap();
        received_notice |= frames.iter().any(|frame| *frame == expected_notice);
        received_stop |= frames.iter().any(|frame| *frame == expected_stop);
        ptrace::pump(&mut tracee.proc, None);
        if received_notice
            && received_stop
            && tracee
                .proc
                .tracing
                .family
                .mach
                .parent_server
                .exports
                .contains_key(&(instance, Object::Task))
        {
            break;
        }
    }
    assert!(tracee.proc.tracing.family.parent.is_some());
    assert!(received_notice, "deferred death notice was lost");
    assert!(received_stop, "deferred job-stop notice was lost");
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Task))
    );
}

#[test]
fn traced_stop_survives_a_full_output_queue() {
    let (mut tracer, mut tracee, tid) = pair();
    tracee.proc.tracing.tracer = Some(1001);
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 16]).unwrap();
    assert!(ptrace::stop_for_signal(
        &mut tracee.proc,
        tid,
        crate::user::darwin::signal::SIGUSR1,
        0x1234,
    ));
    assert!(tracee.proc.exit.is_none(), "backpressure killed the tracee");
    assert!(tracee.proc.tracing.family.parent.is_some());
    let expected = super::super::super::protocol::Message::Stop {
        thread: tid,
        signal: crate::user::darwin::signal::SIGUSR1,
        uid: 501,
        notify: true,
    }
    .encode();
    let mut saw_stop = false;
    for _ in 0..10000 {
        let link = tracer
            .proc
            .tracing
            .family
            .children
            .get_mut(&1002)
            .unwrap()
            .link
            .as_mut()
            .unwrap();
        let (frames, _) = link.receive().unwrap();
        saw_stop |= frames.iter().any(|frame| *frame == expected);
        ptrace::pump(&mut tracee.proc, None);
        if saw_stop {
            break;
        }
    }
    assert!(saw_stop, "queued trace stop was not delivered");
    assert!(tracee.proc.exit.is_none());
}

fn exercise_trace_reply_backpressure(
    mode: Option<super::super::super::protocol::ResumeMode>,
    disconnect: bool,
    suspend: bool,
    ordinary_exit: bool,
) {
    use super::super::super::protocol::{Message as TraceMessage, ResumeMode};
    use std::os::fd::{AsFd, AsRawFd};
    let fatal = mode == Some(ResumeMode::Kill);
    let (mut tracer, mut tracee, tid) = pair();
    tracee.proc.tracing.tracer = Some(1001);
    tracee.proc.tracing.stopped = Some(super::super::super::TraceStop {
        thread: tid,
        signal: crate::user::darwin::signal::SIGSTOP,
    });
    super::super::super::sigwait::begin(&mut tracee.proc.tracing, tid, true);
    if suspend {
        tracee
            .proc
            .threads
            .get_mut(&tid)
            .unwrap()
            .mach
            .suspend_count = 1;
    }
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    let size: libc::c_int = 4096;
    // SAFETY: the link owns the socket and `size` is an initialized value.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                link.as_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const size).cast(),
                std::mem::size_of_val(&size) as _,
            )
        },
        0
    );
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 16]).unwrap();
    link.flush().unwrap();
    while link.queue(&[]).is_ok() {}
    let request = match mode {
        Some(mode) => TraceMessage::Resume {
            id: 42,
            signal: 0,
            mode,
            uid: 501,
        },
        None => TraceMessage::Attach {
            id: 42,
            ruid: 501,
            euid: 501,
            sigexc: false,
        },
    };
    let sender = tracer
        .proc
        .tracing
        .family
        .children
        .get_mut(&1002)
        .unwrap()
        .link
        .as_mut()
        .unwrap();
    sender.queue(&request.encode()).unwrap();
    sender.flush().unwrap();
    ptrace::pump(&mut tracee.proc, None);
    assert!(
        tracee.proc.tracing.family.parent.is_some(),
        "backpressure closed the tracing link"
    );
    assert!(tracee.proc.exit.is_none());
    if fatal {
        assert!(tracee.proc.tracing.exit_after_reply.is_some());
        assert!(ptrace::suspended(&tracee.proc.tracing));
        assert!(!ptrace::wait_fds(&tracee.proc.tracing)[0].1);
    }
    if ordinary_exit {
        use crate::user::darwin::process::{ExitStatus, RunStatus};
        tracee.proc.exit = Some(ExitStatus::Exited(42));
        assert_eq!(
            tracee.run_slice(1, &std::sync::atomic::AtomicBool::new(false)),
            RunStatus::Blocked
        );
        assert_eq!(
            tracee.run_slice(1, &std::sync::atomic::AtomicBool::new(true)),
            RunStatus::Cancelled
        );
    }
    if disconnect {
        let link = tracer
            .proc
            .tracing
            .family
            .children
            .get_mut(&1002)
            .unwrap()
            .link
            .take();
        drop(link);
        if ordinary_exit {
            assert_eq!(
                tracee.run_slice(1, &std::sync::atomic::AtomicBool::new(false)),
                crate::user::darwin::process::RunStatus::Complete(
                    crate::user::darwin::process::ExitStatus::Exited(42)
                )
            );
            assert!(!tracee.proc.tracing.output_barrier);
            return;
        }
        assert!(fatal);
        for _ in 0..1000 {
            ptrace::pump(&mut tracee.proc, None);
            if tracee.proc.exit.is_some() {
                break;
            }
        }
        assert!(matches!(
            tracee.proc.exit,
            Some(crate::user::darwin::process::ExitStatus::Signaled {
                signo: crate::user::darwin::signal::SIGKILL,
                ..
            })
        ));
        assert!(tracee.proc.tracing.exit_after_reply.is_none());
        return;
    }
    let expected = match mode {
        Some(_) => TraceMessage::Reply { id: 42, errno: 0 },
        None => TraceMessage::AttachReply {
            id: 42,
            errno: crate::user::darwin::abi::Errno::EBUSY.0,
            denied: false,
            original_parent: None,
        },
    }
    .encode();
    let mut saw_reply = false;
    for _ in 0..10000 {
        let link = tracer
            .proc
            .tracing
            .family
            .children
            .get_mut(&1002)
            .unwrap()
            .link
            .as_mut()
            .unwrap();
        let (frames, _) = link.receive().unwrap();
        saw_reply |= frames.iter().any(|frame| *frame == expected);
        if ordinary_exit {
            let _ = tracee.run_slice(1, &std::sync::atomic::AtomicBool::new(false));
        } else {
            ptrace::pump(&mut tracee.proc, None);
        }
        if saw_reply {
            break;
        }
    }
    assert!(saw_reply, "queued trace reply was not delivered");
    assert!(tracee.proc.tracing.family.parent.is_some());
    if fatal {
        assert!(matches!(
            tracee.proc.exit,
            Some(crate::user::darwin::process::ExitStatus::Signaled {
                signo: crate::user::darwin::signal::SIGKILL,
                ..
            })
        ));
        assert!(tracee.proc.tracing.exit_after_reply.is_none());
    } else if ordinary_exit {
        assert_eq!(
            tracee.run_slice(1, &std::sync::atomic::AtomicBool::new(false)),
            crate::user::darwin::process::RunStatus::Blocked
        );
        // A traced exit remains a guest zombie after its control reply has
        // drained. Dropping the tracer completes the dead-parent reap.
        tracer.proc.tracing.family.children.remove(&1002);
        assert_eq!(
            tracee.run_slice(1, &std::sync::atomic::AtomicBool::new(false)),
            crate::user::darwin::process::RunStatus::Complete(
                crate::user::darwin::process::ExitStatus::Exited(42)
            )
        );
    } else {
        assert!(tracee.proc.exit.is_none());
    }
}

#[test]
fn trace_reply_waits_for_a_full_output_queue() {
    exercise_trace_reply_backpressure(
        Some(super::super::super::protocol::ResumeMode::Continue),
        false,
        false,
        false,
    );
}

#[test]
fn fatal_trace_reply_is_flushed_before_exit() {
    exercise_trace_reply_backpressure(
        Some(super::super::super::protocol::ResumeMode::Kill),
        false,
        true,
        false,
    );
}

#[test]
fn attach_reply_waits_for_a_full_output_queue() {
    exercise_trace_reply_backpressure(None, false, false, false);
}

#[test]
fn disconnected_tracer_does_not_strand_a_fatal_reply() {
    exercise_trace_reply_backpressure(
        Some(super::super::super::protocol::ResumeMode::Kill),
        true,
        true,
        false,
    );
}

#[test]
fn runnable_tracee_flushes_fatal_reply_before_exit() {
    exercise_trace_reply_backpressure(
        Some(super::super::super::protocol::ResumeMode::Kill),
        false,
        false,
        false,
    );
}

#[test]
fn ordinary_exit_flushes_queued_trace_reply() {
    exercise_trace_reply_backpressure(
        Some(super::super::super::protocol::ResumeMode::Continue),
        false,
        false,
        true,
    );
}

#[test]
fn disconnected_tracer_does_not_strand_ordinary_exit() {
    exercise_trace_reply_backpressure(
        Some(super::super::super::protocol::ResumeMode::Continue),
        true,
        false,
        true,
    );
}

#[test]
fn ordinary_exit_flushes_queued_mach_reply() {
    use crate::user::darwin::process::{ExitStatus, RunStatus};
    let (mut tracer, mut tracee, _) = pair();
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 16]).unwrap();
    link.flush().unwrap();
    while link.queue(&[]).is_ok() {}
    let reply = Message::Reply {
        sequence: 42,
        bits: 0,
        body: vec![1, 2, 3],
        threads: None,
        memory: None,
    };
    let expected = reply.encode().unwrap();
    assert!(queue_response(&mut tracee.proc, reply));
    tracee.proc.exit = Some(ExitStatus::Exited(42));
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(tracee.run_slice(1, &cancelled), RunStatus::Blocked);
    let mut saw_reply = false;
    for _ in 0..10000 {
        let link = tracer
            .proc
            .tracing
            .family
            .children
            .get_mut(&1002)
            .unwrap()
            .link
            .as_mut()
            .unwrap();
        let (frames, _) = link.receive().unwrap();
        saw_reply |= frames.iter().any(|frame| *frame == expected);
        let _ = tracee.run_slice(1, &cancelled);
        if saw_reply {
            break;
        }
    }
    assert!(saw_reply);
    assert_eq!(
        tracee.run_slice(1, &cancelled),
        RunStatus::Complete(ExitStatus::Exited(42))
    );
}

#[test]
fn trace_me_announcement_survives_backpressure_and_exit() {
    use crate::user::darwin::process::{ExitStatus, RunStatus};
    let (mut tracer, mut tracee, tid) = pair();
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 16]).unwrap();
    link.flush().unwrap();
    while link.queue(&[]).is_ok() {}
    let mut thread = tracee.proc.threads.remove(&tid).unwrap();
    let mut ctx = Ctx {
        proc: &mut tracee.proc,
        thread: &mut thread,
        nr: 26,
        pc: 0,
    };
    assert!(ptrace::ptrace(&mut ctx, 0, 0, 0, 0).is_ok());
    assert_eq!(ctx.proc.tracing.tracer, Some(1001));
    assert!(ctx.proc.tracing.output_barrier);
    for _ in 0..100 {
        assert!(ptrace::ptrace(&mut ctx, 0, 0, 0, 0).is_ok());
    }
    tracee.proc.threads.insert(tid, thread);
    tracee.proc.exit = Some(ExitStatus::Exited(42));
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(tracee.run_slice(1, &cancelled), RunStatus::Blocked);
    let expected = super::super::super::protocol::Message::TraceMe.encode();
    let mut seen = 0;
    for _ in 0..10000 {
        let link = tracer
            .proc
            .tracing
            .family
            .children
            .get_mut(&1002)
            .unwrap()
            .link
            .as_mut()
            .unwrap();
        let (frames, _) = link.receive().unwrap();
        seen += frames.iter().filter(|frame| **frame == expected).count();
        let status = tracee.run_slice(1, &cancelled);
        if seen == 1 && frames.is_empty() {
            assert_eq!(status, RunStatus::Blocked);
            break;
        }
    }
    assert_eq!(seen, 1);
    tracer.proc.tracing.family.children.remove(&1002);
    assert_eq!(
        tracee.run_slice(1, &cancelled),
        RunStatus::Complete(ExitStatus::Exited(42))
    );
}

#[test]
fn repeated_trace_me_detects_disconnected_tracer_with_pending_output() {
    let (mut tracer, mut tracee, tid) = pair();
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 16]).unwrap();
    link.flush().unwrap();
    while link.queue(&[]).is_ok() {}
    let mut thread = tracee.proc.threads.remove(&tid).unwrap();
    let mut ctx = Ctx {
        proc: &mut tracee.proc,
        thread: &mut thread,
        nr: 26,
        pc: 0,
    };
    assert!(ptrace::ptrace(&mut ctx, 0, 0, 0, 0).is_ok());
    let peer = tracer
        .proc
        .tracing
        .family
        .children
        .get_mut(&1002)
        .unwrap()
        .link
        .take();
    drop(peer);
    // Wait for the host to publish the close. On XNU a full socket can
    // transiently report EAGAIN before its terminal readiness is visible.
    let mut pfd = libc::pollfd {
        fd: ctx.proc.tracing.family.parent.as_ref().unwrap().fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: pfd refers to the retained endpoint and remains valid.
        let result = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if result >= 0 {
            assert_eq!(result, 1, "peer close was not published within 1 s");
            assert_ne!(pfd.revents & libc::POLLHUP, 0);
            break;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
    assert!(ptrace::ptrace(&mut ctx, 0, 0, 0, 0).is_err());
    assert!(ctx.proc.tracing.family.parent.is_none());
}

#[test]
fn exec_transfers_the_pending_output_barrier() {
    let (_, mut tracee, _) = pair();
    tracee.proc.tracing.output_barrier = true;
    let mut replacement = tracee.proc.tracing.for_exec();
    replacement.take_connections(&mut tracee.proc.tracing);
    assert!(replacement.output_barrier);
    assert!(replacement.family.parent.is_some());
    assert!(!tracee.proc.tracing.output_barrier);
    assert!(tracee.proc.tracing.family.parent.is_none());
}

//! Trace controls shared by ancestral and independently registered callers.

use super::channels::ServerRoute;
use super::*;
use protocol::{Message, ResumeMode};

pub(super) fn dispatch(
    proc: &mut Proc,
    mut running: Option<&mut Thread>,
    route: ServerRoute,
    message: Message,
) {
    let Some(caller) = route.pid(proc) else {
        return;
    };
    if let Message::Signal {
        signal,
        sender,
        uid,
    } = message
    {
        // Ordinary kill authority is independent of the ptrace owner. In
        // particular an ancestral parent can signal a foreign-traced child.
        let parent_signal = route == ServerRoute::Parent
            && proc
                .tracing
                .family
                .parent_status
                .as_ref()
                .and_then(|shared| shared.parent_credentials())
                .is_some_and(|(ruid, euid)| {
                    uid == ruid && (euid == 0 || ruid == proc.creds.0 || euid == proc.creds.0)
                });
        let controller_signal = channels::tracer(proc) == Some(route);
        let untraced_job =
            proc.tracing.tracer.is_none() && matches!(signal, signal::SIGSTOP | signal::SIGCONT);
        if sender == caller
            && (parent_signal || controller_signal || untraced_job)
            && (1..signal::NSIG).contains(&signal)
        {
            let stop = proc.tracing.stopped.or_else(|| {
                proc.tracing.soft_override.map(|verdict| TraceStop {
                    thread: verdict.thread,
                    signal: verdict.original,
                })
            });
            if signal == signal::SIGKILL
                && stop.is_none()
                && !proc.tracing.signal_exceptions
                && let Some(pc) = job_control::all_suspended_pc(proc, running.as_deref())
            {
                signal::psignal(
                    proc,
                    running.as_deref_mut(),
                    signal,
                    Origin::process(sender, uid),
                );
                proc.exit_with(ExitStatus::Signaled {
                    signo: signal,
                    core: false,
                    pc,
                });
            } else if signal == signal::SIGKILL && stop.is_some() {
                if proc.tracing.signal_exceptions {
                    let stop = stop.expect("checked stop");
                    let in_exception = proc.threads.get(&stop.thread).is_some_and(|thread| {
                        thread.mach.exception.as_ref().is_some_and(|exception| {
                            exception.raised.exception == signal::exc::SOFTWARE
                                && exception.raised.codes[0] == 0x10003
                        })
                    });
                    if in_exception {
                        crate::user::darwin::kevent::filters::post_signal(proc, signal);
                        proc.tracing.pending_kill = true;
                        proc.tracing.soft_override = Some(Verdict {
                            thread: stop.thread,
                            signal,
                            original: stop.signal,
                        });
                    } else {
                        signal::psignal(
                            proc,
                            running.as_deref_mut(),
                            signal,
                            Origin::process(sender, uid),
                        );
                    }
                } else {
                    crate::user::darwin::kevent::filters::post_signal(proc, signal);
                    proc.tracing.pending_kill = true;
                }
            } else {
                signal::psignal(
                    proc,
                    running.as_deref_mut(),
                    signal,
                    Origin::process(sender, uid),
                );
            }
        }
        return;
    }
    if let Message::Attach {
        id,
        ruid,
        euid,
        sigexc,
    } = message
    {
        let mut observed = None;
        let errno = if proc.tracing.tracer.is_some() {
            Errno::EBUSY.0
        } else if ruid != proc.creds.0 && euid != 0 {
            Errno::EPERM.0
        } else if proc.tracing.deny_attach {
            Errno::EBUSY.0
        } else {
            observed = crate::user::darwin::codesign::prepare_trace_me(proc);
            let principal_matches = match route {
                ServerRoute::Parent => {
                    proc.tracing
                        .family
                        .parent_status
                        .as_ref()
                        .and_then(|shared| shared.parent_credentials())
                        == Some((ruid, euid))
                }
                ServerRoute::Registered(connection) => proc
                    .tracing
                    .family
                    .peers
                    .incoming
                    .get(&connection)
                    .is_some_and(|peer| peer.record.uid == ruid && ruid == euid),
            };
            let known_debuggable = observed.is_some()
                && euid != 0
                && principal_matches
                && (ruid, euid) == (proc.creds.0, proc.creds.1)
                && proc.codesign.as_ref().is_some_and(|signing| {
                    signing.flags & crate::user::darwin::codesign::cs::GET_TASK_ALLOW != 0
                        && signing.flags & crate::user::darwin::codesign::cs::PLATFORM_BINARY == 0
                });
            if known_debuggable { 0 } else { Errno::ENOSYS.0 }
        };
        if errno == 0 && proc.task.suspension.is_stopped() {
            remote_mach::suspension::trace_resume_on(proc, route, id);
        }
        let reply = Message::AttachReply {
            id,
            errno,
            denied: proc.tracing.deny_attach,
            original_parent: (route != ServerRoute::Parent).then_some(proc.ppid),
        };
        if errno == 0 {
            proc.tracing.original_parent = Some(proc.ppid);
            proc.ppid = caller;
            proc.tracing.tracer = Some(caller);
            proc.tracing.tracer_route = Some(route);
            route.server_mut(proc).expect("connected caller").allowed = true;
            proc.tracing.signal_exceptions = sigexc;
            if let Some(stop) = proc.tracing.job_stopped.take() {
                // Preserve SSTOP until the queued SIGSTOP enters
                // issignal. A job stop does not own BSD sigwait;
                // inventing one here prevents the new stop's AST.
                proc.tracing.stopped = Some(TraceStop {
                    thread: stop.thread,
                    // PT_ATTACH clears p_xstat before posting SIGSTOP.
                    signal: 0,
                });
                proc.tracing.attached_job_stop = true;
            }
            if let Some(shared) = &proc.tracing.family.parent_status {
                shared.set_tracer(proc.tracing.original_parent.unwrap_or(0), Some(caller));
            }
            let job_signal = proc.tracing.stopped.map(|stop| stop.signal);
            set_signal_status(
                &mut proc.tracing,
                job_signal.is_some(),
                job_signal.unwrap_or(0),
            );
            crate::user::darwin::codesign::trace_me_allow_invalid(proc, observed);
            signal::psignal(
                proc,
                running.as_deref_mut(),
                signal::SIGSTOP,
                Origin::KERNEL,
            );
        }
        let queued = channels::queue_reply(proc, route, reply.encode());
        if !queued {
            channels::disconnect(proc, route);
            return;
        }
        return;
    }
    if let Message::CommitUpdate { id } | Message::CommitRemoteUpdate { id, .. } = message {
        let remote = match message {
            Message::CommitRemoteUpdate {
                instance, thread, ..
            } => Some((instance, thread)),
            _ => None,
        };
        let errno = if channels::tracer(proc) == Some(route) {
            commit_update_on(proc, running.as_deref_mut(), route, id, remote)
        } else {
            Errno::EBUSY.0
        };
        if route.link(proc).is_some()
            && !channels::queue_reply(proc, route, Message::Reply { id, errno }.encode())
        {
            channels::disconnect(proc, route);
        }
        return;
    }
    if let Message::Resume {
        id,
        signal,
        mode,
        uid,
    } = message
    {
        let first_thread = proc
            .threads
            .values()
            .filter(|thread| !thread.exited)
            .map(|thread| thread.tid)
            .chain(
                running
                    .as_deref()
                    .filter(|thread| !thread.exited)
                    .map(|thread| thread.tid),
            )
            .min();
        let valid = channels::tracer(proc) == Some(route)
            && proc.tracing.tracer == Some(caller)
            && proc.tracing.stopped.is_some()
            && proc.tracing.trace_update.is_none()
            && proc.tracing.reserved_update.is_none()
            && (!matches!(
                mode,
                ResumeMode::Continue | ResumeMode::Step | ResumeMode::ThreadUpdate
            ) || (0..signal::NSIG).contains(&signal))
            && matches!(
                mode,
                ResumeMode::Continue
                    | ResumeMode::Kill
                    | ResumeMode::Step
                    | ResumeMode::Detach
                    | ResumeMode::ThreadUpdate
            )
            && (!matches!(mode, ResumeMode::Continue | ResumeMode::Step) || first_thread.is_some());
        let errno = if valid { 0 } else { Errno::EBUSY.0 };
        if errno == 0 && mode == ResumeMode::ThreadUpdate {
            proc.tracing.reserved_update = Some(ReservedUpdate {
                id,
                signal,
                stop: proc.tracing.stopped.expect("validated stop"),
            });
        } else if errno == 0 {
            let posted = if mode == ResumeMode::Kill {
                signal::SIGKILL
            } else if matches!(mode, ResumeMode::Continue | ResumeMode::Step) {
                signal
            } else {
                0
            };
            if posted != 0 {
                let origin = Origin::process(caller, uid);
                signal::psignal(proc, running.as_deref_mut(), posted, origin);
            }
            let stop = proc.tracing.stopped.take().expect("validated stop");
            let waiting = proc.tracing.sigwait.is_some();
            if waiting && (!proc.tracing.signal_exceptions || mode == ResumeMode::Detach) {
                remote_mach::suspension::trace_resume_on(proc, route, id);
            }
            proc.tracing.attached_job_stop = false;
            let status = if matches!(mode, ResumeMode::Detach | ResumeMode::Kill) {
                // The observed macOS 27.2 detach and PT_KILL paths
                // retain the original stopped signal in p_xstat.
                stop.signal
            } else {
                signal
            };
            set_signal_status(&mut proc.tracing, false, status);
            if matches!(mode, ResumeMode::Continue | ResumeMode::Step)
                && let Some(tid) = first_thread
            {
                if let Some(thread) = running.as_deref_mut().filter(|thread| thread.tid == tid) {
                    set_step_state(thread, mode == ResumeMode::Step);
                } else if let Some(thread) = proc.threads.get_mut(&tid) {
                    set_step_state(thread, mode == ResumeMode::Step);
                }
            }
            let soft = proc.tracing.signal_exceptions;
            let hard_wait = sigwait::is_hard_wait(&proc.tracing, stop.thread);
            let in_exception = proc.threads.get(&stop.thread).is_some_and(|thread| {
                thread.mach.exception.as_ref().is_some_and(|exception| {
                    exception.raised.exception == signal::exc::SOFTWARE
                        && exception.raised.codes[0] == 0x10003
                })
            });
            if mode == ResumeMode::Detach {
                proc.tracing.tracer = None;
                proc.tracing.tracer_route = None;
                if let Some(parent) = proc.tracing.original_parent {
                    proc.ppid = parent;
                }
                proc.tracing.original_parent = None;
                if let Some(shared) = &proc.tracing.family.parent_status {
                    shared.set_parent(0, proc.ppid, false);
                }
                proc.tracing.signal_exceptions = false;
            }
            proc.tracing.stepping = if mode == ResumeMode::Step {
                first_thread
            } else {
                None
            };
            let verdict = Verdict {
                thread: stop.thread,
                original: stop.signal,
                signal: if std::mem::take(&mut proc.tracing.pending_kill) {
                    signal::SIGKILL
                } else {
                    match mode {
                        ResumeMode::Kill => signal::SIGKILL,
                        // macOS 27.2 retains the stopped signal on detach,
                        // even if `data` names a different signal.
                        ResumeMode::Detach => stop.signal,
                        _ => signal,
                    }
                },
            };
            let selected = job_control::live_thread(proc, running.as_deref(), stop.thread);
            if waiting
                && ((soft && mode == ResumeMode::Kill && !in_exception)
                    || ((!soft || hard_wait) && verdict.signal == signal::SIGKILL))
            {
                // A hard-stop SIGKILL verdict terminates before the
                // next guest instruction. Keep the process alive
                // until its tracing reply has entered the socket.
                let pc = selected.map_or(0, |thread| thread.cpu.pc());
                proc.tracing.exit_after_reply = Some(ExitStatus::Signaled {
                    signo: signal::SIGKILL,
                    core: false,
                    pc,
                });
            } else if waiting && soft && in_exception {
                proc.tracing.soft_override = Some(verdict);
            } else if waiting && (!soft || hard_wait) {
                // PT_SIGEXC may have been enabled by another thread
                // after the task hold drained. PT_CONTINUE still
                // wakes the original hard sigwait (mach_process.c).
                proc.tracing.verdict = Some(verdict);
            }
        }
        if route.link(proc).is_some()
            && !channels::queue_reply(proc, route, Message::Reply { id, errno }.encode())
        {
            channels::disconnect(proc, route);
        }
    }
}

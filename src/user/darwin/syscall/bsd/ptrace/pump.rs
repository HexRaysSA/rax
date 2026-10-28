//! Ordered tracing controls and remote Mach dispatch at scheduler boundaries.

use super::*;

/// Poll the private family links without blocking the emulator. Complete
/// messages are processed in wire order before a closed endpoint is removed.
#[cfg(unix)]
pub(crate) fn pump(proc: &mut Proc, mut running: Option<&mut Thread>) {
    use protocol::{Message, ResumeMode};

    use incoming::{Incoming, receive};

    peers::pump(proc, running.as_deref());
    super::reap::poll_automatic(proc);
    remote_mach::grant::reap(proc, running.as_deref());
    sigwait::reap(proc, running.as_deref());

    for _ in 0..32 {
        let parent = if std::mem::take(&mut proc.tracing.family.mach.parent_server.failed)
            || !remote_mach::flush_responses(proc)
        {
            Some((Vec::new(), true))
        } else if proc.tracing.exit_after_reply.is_none()
            && remote_mach::can_receive_request(&proc.tracing.family.mach)
        {
            proc.tracing
                .family
                .parent
                .as_mut()
                .map(|link| receive(link, true))
        } else {
            None
        };
        let Some((messages, closed)) = parent else {
            break;
        };
        let empty = messages.is_empty();
        for message in messages {
            let message = match message {
                Incoming::Token(packet) => {
                    remote_mach::token::from_parent(proc, running.as_deref_mut(), packet);
                    continue;
                }
                Incoming::Grant(packet) => {
                    remote_mach::grant::from_parent(proc, packet);
                    continue;
                }
                Incoming::Suspension(packet) => {
                    remote_mach::suspension::from_parent(proc, packet);
                    continue;
                }
                Incoming::Callback(packet) => {
                    remote_mach::callback_runtime::from_parent(
                        proc,
                        running.as_deref_mut(),
                        packet,
                    );
                    continue;
                }
                Incoming::Trace(message) => message,
                Incoming::MachFailure(remote_mach::Message::Request {
                    sequence,
                    expects_reply,
                    ..
                }) => {
                    if !remote_mach::failed_request(proc, sequence, expects_reply) {
                        proc.tracing.family.parent = None;
                        break;
                    }
                    continue;
                }
                Incoming::MachFailure(_) => continue,
                Incoming::Mach(message @ remote_mach::Message::Request { .. }) => {
                    let expects_reply = matches!(
                        &message,
                        remote_mach::Message::Request {
                            expects_reply: true,
                            ..
                        }
                    );
                    let reply = remote_mach::serve(proc, running.as_deref_mut(), message);
                    if !remote_mach::queue_served(proc, expects_reply, reply) {
                        proc.tracing.family.parent = None;
                        break;
                    }
                    continue;
                }
                Incoming::Mach(remote_mach::Message::Acquire {
                    generation,
                    instance,
                    epoch,
                    object,
                }) => {
                    remote_mach::acquire(proc, generation, instance, epoch, object);
                    continue;
                }
                Incoming::Mach(remote_mach::Message::Release {
                    generation,
                    instance,
                    object,
                }) => {
                    remote_mach::release(proc, generation, instance, object);
                    continue;
                }
                Incoming::Mach(_) => continue,
            };
            trace_control::dispatch(
                proc,
                running.as_deref_mut(),
                channels::ServerRoute::Parent,
                message,
            );
        }
        if closed {
            proc.tracing.family.parent = None;
        }
        if proc.tracing.family.parent.is_none() {
            remote_mach::parent_died(proc);
        }
        if proc.tracing.family.parent.is_none()
            && channels::tracer(proc) == Some(channels::ServerRoute::Parent)
        {
            channels::tracer_died(proc);
        }
        if empty || closed || proc.tracing.family.parent.is_none() {
            break;
        }
    }

    registered_pump::pump(proc, running.as_deref_mut());

    let output_done = channels::output_done(proc);
    if output_done {
        proc.tracing.output_barrier = false;
    }
    if output_done && let Some(exit) = proc.tracing.exit_after_reply.take() {
        proc.exit_with(exit);
    }
    remote_mach::flush_releases(proc);
    let children: Vec<i32> = proc.tracing.family.children.keys().copied().collect();
    for pid in children {
        let result = proc
            .tracing
            .family
            .children
            .get_mut(&pid)
            .and_then(|child| child.link.as_mut())
            .map(|link| receive(link, false));
        let Some((messages, closed)) = result else {
            continue;
        };
        for message in messages {
            let message = match message {
                Incoming::Token(packet) => {
                    remote_mach::token::from_child(proc, pid, packet);
                    continue;
                }
                Incoming::Grant(packet) => {
                    remote_mach::grant::from_child(proc, pid, packet);
                    continue;
                }
                Incoming::Suspension(packet) => {
                    remote_mach::suspension::from_child(proc, pid, packet);
                    continue;
                }
                Incoming::Callback(packet) => {
                    remote_mach::callback_runtime::from_child(proc, pid, packet);
                    continue;
                }
                Incoming::Trace(message) => message,
                Incoming::MachFailure(remote_mach::Message::Reply { sequence, .. }) => {
                    remote_mach::failed_reply(proc, pid, sequence);
                    continue;
                }
                Incoming::MachFailure(_) => continue,
                Incoming::Mach(message @ remote_mach::Message::Reply { .. }) => {
                    remote_mach::receive_reply(proc, pid, message);
                    continue;
                }
                Incoming::Mach(remote_mach::Message::Dead {
                    generation,
                    instance,
                    object,
                }) => {
                    remote_mach::remote_dead(proc, pid, instance, generation, object);
                    continue;
                }
                Incoming::Mach(_) => continue,
            };
            match message {
                Message::ImageEpoch { epoch } => {
                    if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
                        if child.registry_instance.is_some() && epoch > child.registry_epoch {
                            child.registry_epoch = epoch;
                            child.registry_codesign = None;
                            proc.post(WaitKey::Child);
                        }
                    }
                }
                Message::CodeFlags { epoch, flags } => {
                    if let Some(child) = proc.tracing.family.children.get_mut(&pid)
                        && child.registry_instance.is_some()
                        && epoch == child.registry_epoch
                    {
                        child.registry_codesign = flags;
                    }
                }
                Message::ExitReport {
                    status,
                    uid,
                    rusage,
                    reparented,
                } => {
                    lifecycle::observe(
                        proc,
                        running.as_deref_mut(),
                        pid,
                        lifecycle::Report { status, rusage },
                        uid,
                        reparented,
                    );
                }
                Message::ReapReply { id, retained } => super::reap::reply(proc, pid, id, retained),
                Message::JobStop {
                    thread,
                    signal,
                    uid,
                } if thread != 0
                    && (1..signal::NSIG).contains(&signal)
                    && matches!(
                        signal,
                        signal::SIGSTOP | signal::SIGTSTP | signal::SIGTTIN | signal::SIGTTOU
                    ) =>
                {
                    job_control::observe_stop(
                        proc,
                        running.as_deref_mut(),
                        pid,
                        thread,
                        signal,
                        uid,
                    );
                }
                Message::JobContinue => job_control::observe_continue(proc, pid),
                Message::TraceMe => {
                    if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
                        child.traced = true;
                        child.original_parent = Some(proc.pid);
                        child.mach_attached = true;
                    }
                }
                Message::Stop {
                    thread,
                    signal,
                    uid,
                    notify,
                } if (1..signal::NSIG).contains(&signal) => {
                    let child = proc
                        .tracing
                        .family
                        .children
                        .get_mut(&pid)
                        .expect("listed child");
                    if child.is_traced()
                        && (child.stop.is_none() || child.attach_stop_pending || !notify)
                    {
                        child.attach_stop_pending = false;
                        child.stop = Some(ChildStop {
                            thread,
                            signal,
                            waited: false,
                        });
                        if notify {
                            proc.post(WaitKey::Child);
                            let origin = Origin {
                                pid,
                                uid,
                                // kern_sig stores p_xstat unencoded; the
                                // signal-frame copyout extracts its high byte.
                                status: signal,
                                code: 4,
                            };
                            proc.sigacts.origin = origin;
                            signal::psignal(proc, running.as_deref_mut(), signal::SIGCHLD, origin);
                        }
                    }
                }
                Message::Reply { id, errno } => {
                    let kind = proc.tracing.pending.values_mut().find_map(|call| {
                        (call.pid == pid
                            && call.id == id
                            && matches!(
                                call.kind,
                                CallKind::Resume { .. }
                                    | CallKind::ThreadUpdate {
                                        phase: UpdatePhase::Preparing | UpdatePhase::Committing,
                                        ..
                                    }
                            ))
                        .then(|| {
                            let kind = call.kind;
                            if let CallKind::ThreadUpdate {
                                thread,
                                remote_instance,
                                signal,
                                phase: UpdatePhase::Preparing,
                            } = kind
                                && errno == 0
                            {
                                call.kind = CallKind::ThreadUpdate {
                                    thread,
                                    remote_instance,
                                    signal,
                                    phase: UpdatePhase::Prepared,
                                };
                            } else {
                                call.errno = Some(errno);
                            }
                            kind
                        })
                    });
                    if let Some(kind) = kind {
                        if matches!(
                            kind,
                            CallKind::ThreadUpdate {
                                phase: UpdatePhase::Preparing,
                                ..
                            }
                        ) && errno == 0
                        {
                            continue;
                        }
                        if errno == 0 {
                            let child = proc
                                .tracing
                                .family
                                .children
                                .get_mut(&pid)
                                .expect("listed child");
                            child.stop = None;
                            if kind == (CallKind::Resume { detach: true }) {
                                child.attach_stop_pending = false;
                                child.traced = false;
                                child.original_parent = None;
                                child.mach_attached = false;
                            }
                        }
                        proc.post(WaitKey::Child);
                    }
                }
                Message::AttachReply {
                    id,
                    errno,
                    denied,
                    original_parent,
                } => {
                    let caller = proc.tracing.pending.iter_mut().find_map(|(&tid, call)| {
                        (call.pid == pid && call.id == id && call.kind == CallKind::Attach).then(
                            || {
                                call.errno = Some(errno);
                                tid
                            },
                        )
                    });
                    if caller.is_some() {
                        if errno == 0
                            && let Some(child) = proc.tracing.family.children.get_mut(&pid)
                        {
                            child.attach_stop_pending = child.stop.is_some();
                            child.traced = true;
                            child.original_parent = Some(original_parent.unwrap_or(proc.pid));
                            child.mach_attached = true;
                        }
                        proc.post(WaitKey::Child);
                        if denied && errno != 0 {
                            let origin = Origin::own(proc);
                            signal::psignal(proc, running.as_deref_mut(), SIGSEGV, origin);
                        }
                    }
                }
                _ => {}
            }
        }
        if closed {
            remote_mach::peer_died(proc, pid);
            if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
                child.link = None;
                child.stop = None;
                child.attach_stop_pending = false;
                child.job_stop_requested = false;
                // exit1 clears P_LTRACED before publishing the zombie.
                child.traced = false;
            }
            for call in proc
                .tracing
                .pending
                .values_mut()
                .filter(|call| call.pid == pid && call.errno.is_none())
            {
                call.errno = Some(Errno::ESRCH.0);
            }
            proc.post(WaitKey::Child);
        }
    }

    // Reserve space for the commit before setting the local thread's bit.
    // No transport write occurs between that store and the commit flush, so
    // the target cannot change p_stat before the signal is pending.
    let prepared: Vec<_> = proc
        .tracing
        .pending
        .iter()
        .filter_map(|(&caller, call)| match call.kind {
            CallKind::ThreadUpdate {
                thread,
                remote_instance,
                signal,
                phase: UpdatePhase::Prepared,
            } if call.errno.is_none() => {
                Some((caller, call.pid, call.id, thread, remote_instance, signal))
            }
            _ => None,
        })
        .collect();
    for (caller, pid, id, thread, remote_instance, signal) in prepared {
        if remote_mach::callback_runtime::wants_write(&proc.tracing.family.mach, pid) {
            continue;
        }
        let commit = match remote_instance {
            Some(instance) => Message::CommitRemoteUpdate {
                id,
                instance,
                thread,
            },
            None => Message::CommitUpdate { id },
        };
        let queued = proc
            .tracing
            .family
            .children
            .get_mut(&pid)
            .and_then(|child| child.link.as_mut())
            .map(|link| link.queue(&commit.encode()));
        match queued {
            Some(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            None | Some(Err(_)) => {
                if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
                    child.link = None;
                }
                if let Some(call) = proc.tracing.pending.get_mut(&caller) {
                    call.errno = Some(Errno::ESRCH.0);
                }
                proc.post(WaitKey::Child);
                continue;
            }
            Some(Ok(())) => {}
        }
        if signal != 0 && remote_instance.is_none() {
            let target = running
                .as_deref_mut()
                .filter(|running| running.tid == thread)
                .or_else(|| proc.threads.get_mut(&thread));
            if let Some(target) = target {
                // mach_process.c sets uu_siglist directly, without psignal.
                target.sig.pending |= signal::bit(signal);
            }
        }
        if let Some(call) = proc.tracing.pending.get_mut(&caller) {
            call.kind = CallKind::ThreadUpdate {
                thread,
                remote_instance,
                signal,
                phase: UpdatePhase::Committing,
            };
        }
        let flushed = proc
            .tracing
            .family
            .children
            .get_mut(&pid)
            .and_then(|child| child.link.as_mut())
            .is_some_and(|link| link.flush().is_ok());
        if !flushed {
            if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
                child.link = None;
            }
            if let Some(call) = proc.tracing.pending.get_mut(&caller) {
                call.errno = Some(Errno::ESRCH.0);
            }
            proc.post(WaitKey::Child);
        }
    }
    job_control::orphaned(proc);
}

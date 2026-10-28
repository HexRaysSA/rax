//! Cooperative job-control stops for processes connected to their parent.

use super::{State, TraceStop, protocol, set_signal_status};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::signal;
use crate::user::darwin::signal::Origin;
use crate::user::darwin::wait::WaitKey;

/// Keep the process alive until a synchronous tracing reply has been sent.
pub(super) fn queue_reply(proc: &mut Proc, bytes: Vec<u8>) -> bool {
    let queued = super::remote_mach::queue_control(proc, bytes);
    proc.tracing.output_barrier |= queued;
    queued
}

/// One outstanding trace-me announcement suffices for a traced child.
pub(super) fn queue_trace_me(proc: &mut Proc) -> std::io::Result<()> {
    let route = super::channels::trace_me_route(proc).ok_or(std::io::ErrorKind::BrokenPipe)?;
    if proc.tracing.tracer == Some(proc.ppid) && proc.tracing.output_barrier {
        super::remote_mach::try_flush_responses_on(proc, route)?;
        if route.link(proc).is_some_and(|link| {
            link.wants_write()
                || !route
                    .server(proc)
                    .is_some_and(super::remote_mach::server_output_empty)
        }) {
            return Ok(());
        }
    }
    super::remote_mach::try_queue_control_on(proc, route, protocol::Message::TraceMe.encode())?;
    proc.tracing.output_barrier = true;
    Ok(())
}

/// Flush essential tracing output after guest exit, returning a writable fd
/// while the host process must remain alive to deliver it.
pub(crate) fn flush_exit_output(proc: &mut Proc) -> Option<i32> {
    if !proc.tracing.output_barrier {
        return None;
    }
    if !super::remote_mach::flush_responses(proc) {
        proc.tracing.family.parent = None;
        super::remote_mach::parent_died(proc);
    }
    let fd = proc.tracing.family.parent.as_ref().and_then(|link| {
        (link.wants_write() || !super::remote_mach::output_empty(&proc.tracing.family.mach))
            .then(|| link.fd())
    });
    if fd.is_none() {
        proc.tracing.output_barrier = false;
    }
    fd
}

/// The live selected thread, including one temporarily borrowed by a syscall.
pub(super) fn live_thread<'a>(
    proc: &'a Proc,
    running: Option<&'a Thread>,
    tid: u64,
) -> Option<&'a Thread> {
    running
        .filter(|thread| thread.tid == tid && !thread.exited)
        .or_else(|| proc.threads.get(&tid).filter(|thread| !thread.exited))
}

/// A representative PC when task or thread holds prevent all user execution.
pub(super) fn all_suspended_pc(proc: &Proc, running: Option<&Thread>) -> Option<u64> {
    let mut live = running
        .filter(|thread| !thread.exited)
        .into_iter()
        .chain(proc.threads.values().filter(|thread| !thread.exited));
    let first = live.next()?;
    (proc.task.suspension.is_stopped()
        || (first.mach.suspend_count != 0 && live.all(|thread| thread.mach.suspend_count != 0)))
    .then(|| first.cpu.pc())
}

/// Stops the guest while leaving its emulator able to serve its parent.
pub(crate) fn stop_job(proc: &mut Proc, thread: u64, signal: i32) -> bool {
    let connected = proc.tracing.family.parent.is_some() || super::peers::has_controller(proc);
    if thread == 0 || !proc.config.host_job_control || (!connected && !proc.config.host_services) {
        return false;
    }
    if proc.tracing.job_stopped.is_some() {
        return true;
    }
    if proc
        .task
        .suspension
        .place(crate::user::darwin::mach::suspend::Hold::Normal)
        .is_err()
    {
        return false;
    }
    if proc.config.host_services && connected {
        signal::host::sync_sigcont(true);
    }
    let message = protocol::Message::JobStop {
        thread,
        signal,
        uid: proc.creds.0,
    };
    let sent = proc.tracing.family.parent.is_none()
        || super::remote_mach::queue_control(proc, message.encode());
    if !sent {
        let _ = proc
            .task
            .suspension
            .release(crate::user::darwin::mach::suspend::Hold::Normal);
        proc.tracing.family.parent = None;
        return false;
    }
    proc.tracing.job_stopped = Some(TraceStop { thread, signal });
    if let Some(shared) = &proc.tracing.family.parent_status {
        shared.set_target_credentials((proc.creds.0, proc.creds.1));
    }
    set_signal_status(&mut proc.tracing, true, signal);
    if !connected {
        park_host(proc);
    }
    true
}

/// Releases a cooperative stop before applying SIGCONT's disposition.
pub(crate) fn continue_job(proc: &mut Proc) {
    if proc.tracing.job_stopped.take().is_none() {
        return;
    }
    let _ = proc
        .task
        .suspension
        .release(crate::user::darwin::mach::suspend::Hold::Normal);
    set_signal_status(&mut proc.tracing, false, signal::SIGCONT);
    if proc.tracing.family.parent.is_some()
        && !super::remote_mach::queue_control(proc, protocol::Message::JobContinue.encode())
    {
        proc.tracing.family.parent = None;
    }
}

/// A detached target with no remaining guest controller returns its stop to
/// ordinary host job control. Otherwise its final cooperative hold would be
/// invisible to the original native parent and could never be continued.
pub(super) fn orphaned(proc: &mut Proc) {
    if !proc.config.host_services
        || !proc.config.host_job_control
        || proc.pid != unsafe { libc::getpid() }
        || proc.exit.is_some()
        || proc.tracing.tracer.is_some()
        || proc.tracing.family.parent.is_some()
        || super::peers::has_controller(proc)
        || proc.tracing.job_stopped.is_none()
        || proc.tracing.host_parking
    {
        return;
    }
    park_host(proc);
}

/// Preserve the guest stop while the host is stopped for its native parent.
/// A registry wake keeps the hold; an ordinary SIGCONT releases it. SIGCONT
/// is caught only according to the guest disposition, preserving host wait
/// semantics for ordinary shell job control.
fn park_host(proc: &mut Proc) {
    if proc.pid != unsafe { libc::getpid() } {
        proc.exit_with(super::ExitStatus::Internal(
            "host tracing process identity mismatch".into(),
        ));
        return;
    }
    // Queue cleanup can re-enter orphaned() while setup completes. Keep
    // repeated failed wakes iterative instead of nesting host-stop frames.
    if proc.tracing.host_parking {
        return;
    }
    proc.tracing.host_parking = true;
    loop {
        proc.tracing.native_host_stop = true;
        signal::host::sync_sigcont(proc.sigacts.catch & signal::bit(signal::SIGCONT) != 0);
        signal::host::stop(proc);
        super::peers::poll(proc);
        if proc.tracing.native_host_stop {
            proc.tracing.native_host_stop = false;
            super::peers::forget_host_wakes(&mut proc.tracing);
            continue_job(proc);
            break;
        }
        if super::peers::has_controller(proc)
            || proc.tracing.family.parent.is_some()
            || proc.exit.is_some()
        {
            break;
        }
        // The waking caller vanished during setup. The original stop must
        // remain in effect until another controller or a real SIGCONT arrives.
        super::peers::forget_host_wakes(&mut proc.tracing);
    }
    proc.tracing.host_parking = false;
}

/// The setup hello was authenticated before the client sent its generation-
/// checked host wake. Reconstruct an external host SIGSTOP as a guest stop.
pub(super) fn registry_woke(proc: &mut Proc) {
    proc.tracing.native_host_stop = false;
    if proc.exit.is_some() {
        return;
    }
    if proc.tracing.tracer.is_some() {
        signal::psignal(proc, None, signal::SIGSTOP, Origin::KERNEL);
        return;
    }
    if proc.tracing.job_stopped.is_some() {
        return;
    }
    let Some(thread) = proc
        .threads
        .values()
        .find(|thread| !thread.exited)
        .map(|thread| thread.tid)
    else {
        proc.exit_with(super::ExitStatus::Internal(
            "registry wake has no live guest thread".into(),
        ));
        return;
    };
    if proc
        .task
        .suspension
        .place(crate::user::darwin::mach::suspend::Hold::Normal)
        .is_err()
    {
        proc.exit_with(super::ExitStatus::Internal(
            "registry stop hold exhausted".into(),
        ));
        return;
    }
    // An external host stop may have frozen an interruptible kernel wait
    // before the guest entered its signal AST. Preserve the continuation,
    // but let the new attach stop enter once its task hold is released.
    if let Some(selected) = proc.threads.get_mut(&thread) {
        selected.woken = true;
    }
    proc.tracing.job_stopped = Some(TraceStop {
        thread,
        signal: signal::SIGSTOP,
    });
    set_signal_status(&mut proc.tracing, true, signal::SIGSTOP);
    if let Some(shared) = &proc.tracing.family.parent_status {
        shared.set_target_credentials((proc.creds.0, proc.creds.1));
    }
    if proc.tracing.family.parent.is_some()
        && !super::remote_mach::queue_control(
            proc,
            protocol::Message::JobStop {
                thread,
                signal: signal::SIGSTOP,
                uid: proc.creds.0,
            }
            .encode(),
        )
    {
        proc.tracing.family.parent = None;
    }
}

pub(crate) fn job_stopped(state: &State) -> bool {
    state.job_stopped.is_some()
}

pub(crate) fn note_host_stop(state: &mut State, pid: i32, stopped: bool) {
    if let Some(child) = state.family.children.get_mut(&pid) {
        child.host_stopped = stopped;
    }
}

/// A host stop layered on an existing cooperative stop is not a new guest stop.
pub(crate) fn duplicate_host_stop(state: &mut State, pid: i32) -> bool {
    let Some(child) = state.family.children.get_mut(&pid) else {
        return false;
    };
    if child.stop.is_some() && !child.is_traced() {
        child.host_stopped = true;
        true
    } else {
        false
    }
}

pub(super) fn observe_stop(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    pid: i32,
    thread: u64,
    signal: i32,
    uid: u32,
) {
    let Some(child) = proc.tracing.family.children.get_mut(&pid) else {
        return;
    };
    if !child.waitable() {
        return;
    }
    child.stop = Some(super::ChildStop {
        thread,
        signal,
        waited: false,
    });
    child.continued = false;
    child.job_stop_requested = false;
    proc.post(WaitKey::Child);
    let origin = signal::Origin {
        pid,
        uid,
        status: (signal << 8) | 0x7f,
        code: 5, // CLD_STOPPED
    };
    if signal::child_changed(proc, &origin) {
        signal::psignal(proc, running, signal::SIGCHLD, origin);
    }
}

pub(super) fn observe_continue(proc: &mut Proc, pid: i32) {
    if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
        if !child.waitable() {
            return;
        }
        child.stop = None;
        child.continued = true;
        child.job_stop_requested = false;
        proc.post(WaitKey::Child);
    }
}

/// Consumes one traced-child stop for wait4. XNU marks it waited before
/// attempting the status copyout, and does not copy rusage for this case.
pub(crate) fn wait_stop(
    state: &mut State,
    requested: i32,
    include_job: bool,
) -> Option<(i32, i32)> {
    let group = if requested == 0 {
        // SAFETY: getpgrp takes no arguments.
        unsafe { libc::getpgrp() }
    } else {
        -requested
    };
    state.family.children.iter_mut().find_map(|(&pid, child)| {
        if !child.waitable() || !include_job && !child.is_traced() {
            return None;
        }
        let matches = requested == -1
            || requested == pid
            || (requested <= 0 && {
                // SAFETY: getpgid takes a process identifier and no pointers.
                unsafe { libc::getpgid(pid) == group }
            });
        let stop = child.stop.as_mut()?;
        if matches && !stop.waited {
            stop.waited = true;
            Some((pid, stop.signal))
        } else {
            None
        }
    })
}

pub(crate) fn peek_stop(
    state: &State,
    idtype: i32,
    id: u32,
    include_job: bool,
) -> Option<(i32, i32)> {
    state.family.children.iter().find_map(|(&pid, child)| {
        if !child.waitable() || !include_job && !child.is_traced() {
            return None;
        }
        let matches = match idtype {
            1 => pid == id as i32,
            // SAFETY: getpgid takes a process identifier and no pointers.
            2 => unsafe { libc::getpgid(pid) == id as i32 },
            _ => true,
        };
        let stop = child.stop.as_ref()?;
        (matches && !stop.waited).then_some((pid, stop.signal))
    })
}

fn matches_wait4(pid: i32, requested: i32) -> bool {
    if requested == -1 || requested == pid {
        return true;
    }
    if requested > 0 {
        return false;
    }
    // SAFETY: both calls take no pointer arguments.
    let group = if requested == 0 {
        unsafe { libc::getpgrp() }
    } else {
        -requested
    };
    unsafe { libc::getpgid(pid) == group }
}

pub(crate) fn wait_continue(state: &mut State, requested: i32) -> Option<i32> {
    state.family.children.iter_mut().find_map(|(&pid, child)| {
        if child.waitable() && child.continued && matches_wait4(pid, requested) {
            child.continued = false;
            Some(pid)
        } else {
            None
        }
    })
}

pub(crate) fn peek_continue(state: &State, idtype: i32, id: u32) -> Option<i32> {
    state.family.children.iter().find_map(|(&pid, child)| {
        let matches = match idtype {
            1 => pid == id as i32,
            // SAFETY: getpgid takes a process identifier and no pointers.
            2 => unsafe { libc::getpgid(pid) == id as i32 },
            _ => true,
        };
        (child.waitable() && matches && child.continued).then_some(pid)
    })
}

pub(crate) fn consume_continue(state: &mut State, pid: i32) {
    if let Some(child) = state.family.children.get_mut(&pid) {
        child.continued = false;
    }
}

pub(crate) fn consume_stop(state: &mut State, pid: i32) {
    if let Some(stop) = state
        .family
        .children
        .get_mut(&pid)
        .and_then(|child| child.stop.as_mut())
    {
        stop.waited = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_waits_require_untraced_and_preserve_peeks() {
        let (link, _peer) = super::super::transport::Link::pair().unwrap();
        let mut state = State::default();
        let mut child = super::super::Child::new(link, 1);
        child.stop = Some(super::super::ChildStop {
            thread: 7,
            signal: signal::SIGSTOP,
            waited: false,
        });
        state.family.children.insert(42, child);
        assert_eq!(wait_stop(&mut state, 42, false), None);
        assert_eq!(peek_stop(&state, 1, 42, true), Some((42, signal::SIGSTOP)));
        assert_eq!(peek_stop(&state, 1, 42, true), Some((42, signal::SIGSTOP)));
        assert_eq!(wait_stop(&mut state, 42, true), Some((42, signal::SIGSTOP)));
        assert_eq!(wait_stop(&mut state, 42, true), None);
        state.family.children.get_mut(&42).unwrap().continued = true;
        assert_eq!(peek_continue(&state, 1, 42), Some(42));
        assert_eq!(peek_continue(&state, 1, 42), Some(42));
        assert_eq!(wait_continue(&mut state, 42), Some(42));
        assert_eq!(peek_continue(&state, 1, 42), None);
    }
}

/// Peeks a host stop or continuation without consuming the guest's event.
fn host_transition_pending(pid: i32) -> Option<bool> {
    // SAFETY: an all-zero siginfo_t is valid for waitid to fill, and
    // WNOWAIT leaves the host event available to the guest's wait call.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WSTOPPED | libc::WCONTINUED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 || unsafe { info.si_pid() != pid } {
        return None;
    }
    match info.si_code {
        libc::CLD_STOPPED => Some(true),
        libc::CLD_CONTINUED => Some(false),
        _ => None,
    }
}

/// Sends a traced signal or a cooperative job-control signal to a child.
/// False selects the usual host signal path.
pub(crate) fn send_traced_signal(
    state: &mut State,
    pid: i32,
    signal: i32,
    origin: Origin,
) -> Result<bool, Errno> {
    let callbacks_pending =
        super::remote_mach::callback_runtime::wants_write(&state.family.mach, pid);
    let Some(child) = state.family.children.get_mut(&pid) else {
        return Ok(false);
    };
    let traced = child.is_traced()
        || child
            .shared_status
            .as_ref()
            .is_some_and(|shared| shared.trace_owner().0.is_some());
    if !traced
        && matches!(signal, signal::SIGSTOP | signal::SIGCONT)
        && let Some(stopped) = host_transition_pending(pid)
    {
        child.host_stopped = stopped;
    }
    if !traced && child.host_stopped && matches!(signal, signal::SIGSTOP | signal::SIGCONT) {
        if signal == signal::SIGCONT && child.job_stop_requested {
            if callbacks_pending {
                return Err(Errno::EAGAIN);
            }
            let link = child.link.as_mut().ok_or(Errno::ESRCH)?;
            let message = protocol::Message::Signal {
                signal,
                sender: origin.pid,
                uid: origin.uid,
            };
            link.queue(&message.encode())
                .map_err(|e| Errno::from_io(&e))?;
            link.flush().map_err(|e| Errno::from_io(&e))?;
        }
        return Ok(false);
    }
    if !traced
        && signal != signal::SIGSTOP
        && !(signal == signal::SIGCONT
            && (child.registry_instance.is_some()
                || child.job_stop_requested
                || child.stop.is_some()))
    {
        return Ok(false);
    }
    if callbacks_pending {
        return Err(Errno::EAGAIN);
    }
    let link = child.link.as_mut().ok_or(Errno::ESRCH)?;
    let message = protocol::Message::Signal {
        signal,
        sender: origin.pid,
        uid: origin.uid,
    };
    link.queue(&message.encode())
        .map_err(|e| Errno::from_io(&e))?;
    link.flush().map_err(|e| Errno::from_io(&e))?;
    if !traced && signal == signal::SIGSTOP {
        child.job_stop_requested = true;
    }
    Ok(true)
}

pub(crate) fn is_signal_peer(state: &State, pid: i32) -> bool {
    state.family.children.get(&pid).is_some_and(|child| {
        child.is_traced()
            || child
                .shared_status
                .as_ref()
                .is_some_and(|shared| shared.trace_owner().0.is_some())
    })
}

pub(crate) fn is_traced_child(state: &State, pid: i32) -> bool {
    state
        .family
        .children
        .get(&pid)
        .is_some_and(|child| child.is_traced())
}

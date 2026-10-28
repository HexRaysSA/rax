//! A reap is committed after copyout, then acknowledged by the target before
//! the guest wait returns. This serializes immediate successive WNOHANG waits.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::{protocol::Message, *};
use crate::user::darwin::syscall;

#[derive(Debug, Default)]
pub(super) struct State {
    next: u64,
    pending: BTreeMap<u64, Pending>,
    automatic: BTreeMap<i32, bool>,
}

#[derive(Debug)]
struct Pending {
    id: u64,
    pid: i32,
    pc: u64,
    nr: i64,
    retained: Option<bool>,
    host_child: bool,
}

pub(super) fn owns(state: &super::State, pid: i32) -> bool {
    state.reaps.pending.values().any(|call| call.pid == pid)
        || state.reaps.automatic.contains_key(&pid)
}

pub(super) fn reply(proc: &mut Proc, pid: i32, id: u64, retained: bool) {
    if id == 0 {
        if !retained && let Some(ready) = proc.tracing.reaps.automatic.get_mut(&pid) {
            *ready = true;
        }
    } else if let Some(call) = proc
        .tracing
        .reaps
        .pending
        .values_mut()
        .find(|call| call.id == id && call.pid == pid)
    {
        call.retained = Some(retained);
    }
    proc.post(WaitKey::Child);
}

pub(super) fn automatic(proc: &mut Proc, pid: i32) {
    proc.tracing.reaps.automatic.insert(pid, false);
}

/// SA_NOCLDWAIT still requires the physical host child to be collected after
/// its cooperative zombie has been consumed. Never reap another guest parent’s
/// live tracee through a broad host wait.
pub(super) fn poll_automatic(proc: &mut Proc) {
    let candidates: Vec<_> = proc
        .tracing
        .reaps
        .automatic
        .iter()
        .filter_map(|(&pid, &ready)| {
            (ready
                || proc
                    .tracing
                    .family
                    .children
                    .get(&pid)
                    .is_none_or(|child| child.link.is_none()))
            .then_some(pid)
        })
        .collect();
    for pid in candidates {
        let complete = if proc.children.contains(&pid) {
            let mut status = 0;
            // SAFETY: pid names a tracked physical child and status is writable.
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
                || result < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
        } else {
            true
        };
        if complete {
            proc.tracing.reaps.automatic.remove(&pid);
            proc.children.remove(&pid);
            remote_mach::peer_died(proc, pid);
            child_reaped(&mut proc.tracing, pid);
        }
    }
}

pub(super) fn deadline(state: &super::State) -> Option<Instant> {
    (!state.reaps.automatic.is_empty()).then(|| Instant::now() + Duration::from_millis(10))
}

/// Begin only after all requested output buffers have been copied successfully.
/// The report is reserved by this thread until its kernel continuation ends.
pub(crate) fn begin_reap(ctx: &mut Ctx<'_>, pid: i32) -> SysResult {
    let state = &mut ctx.proc.tracing;
    let id = state.reaps.next.checked_add(1).ok_or(Errno::EOVERFLOW)?;
    state.reaps.next = id;
    let child = state.family.children.get_mut(&pid).ok_or(Errno::ECHILD)?;
    child.registered_exit.take().ok_or(Errno::ECHILD)?;
    let queued = child.link.as_mut().is_some_and(|link| {
        link.queue(&Message::ReapAck { id }.encode()).is_ok() && link.flush().is_ok()
    });
    state.reaps.pending.insert(
        ctx.thread.tid,
        Pending {
            id,
            pid,
            pc: ctx.pc,
            nr: ctx.nr,
            retained: (!queued).then_some(false),
            host_child: ctx.proc.children.contains(&pid),
        },
    );
    pending_reap(ctx).expect("inserted reap continuation")
}

/// Re-entering a committed reap never repeats guest copyout. The wait is
/// uninterruptible, matching the kernel's post-copyout reap critical section.
pub(crate) fn pending_reap(ctx: &mut Ctx<'_>) -> Option<SysResult> {
    let call = ctx.proc.tracing.reaps.pending.get(&ctx.thread.tid)?;
    if call.pc != ctx.pc || call.nr != ctx.nr {
        return None;
    }
    let pid = call.pid;
    let disconnected = ctx
        .proc
        .tracing
        .family
        .children
        .get(&pid)
        .is_none_or(|child| child.link.is_none());
    let ready = call.retained.or(disconnected.then_some(false));
    let host_child = call.host_child;
    let mut complete = ready.is_some();
    if ready == Some(false) && host_child {
        let mut status = 0;
        // SAFETY: this PID is a tracked host child; status is writable.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        complete = got == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
            || got < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
    }
    if complete {
        ctx.proc.tracing.reaps.pending.remove(&ctx.thread.tid);
        if ready == Some(false) {
            remote_mach::peer_died(ctx.proc, pid);
            child_reaped(&mut ctx.proc.tracing, pid);
            ctx.proc.children.remove(&pid);
        }
        // BSD waitid and waitid_nocancel return zero; wait4 returns the PID.
        return Some(Ok(Rv::one(if matches!(ctx.nr, 173 | 416) {
            0
        } else {
            pid as u64
        })));
    }
    // Poll while waiting for the final host reap as SIGCHLD may coalesce with
    // the earlier guest zombie event. Link readiness is pumped by the runtime.
    Some(syscall::sleep(
        ctx,
        Wait {
            keys: vec![WaitKey::Child],
            deadline: Some(Instant::now() + Duration::from_millis(10)),
            interruptible: false,
            ..Default::default()
        },
    ))
}

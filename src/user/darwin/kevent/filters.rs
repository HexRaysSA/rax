//! Filters (`struct filterops`): attach, touch, process, and detach for
//! each kind of knote, and the hooks event sources call.
//!
//! - `EVFILT_TIMER`, `EVFILT_USER` (`kern_event.c`);
//! - `EVFILT_SIGNAL` (`kern_sig.c`): process-directed signals, counted;
//! - `EVFILT_MACHPORT` (`osfmk/ipc/ipc_pset.c`): a receive right or port
//!   set with a message, received directly with `MACH_RCV_MSG`;
//! - `EVFILT_READ` on a kqueue descriptor (`kqread_filtops`);
//! - descriptor filters and `EVFILT_PROC` through the host ([`super::host`]);
//! - `EVFILT_WORKLOOP` on workloops ([`super::workloop`]);
//! - `EVFILT_FS` and `EVFILT_MEMORYSTATUS`, which attach and never fire;
//! - the rest are not supported (`ENOTSUP`, `bad_filtops`).

use std::time::Duration;

use super::{DataArea, Kev, ev, evfilt, fr, host};
use crate::user::darwin::abi::{DarwinAbi, Errno};
use crate::user::darwin::mach::ipc::Object;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::absolute_time;
use crate::user::darwin::syscall::mach::msg::Watched;

/// A filter's per-knote state.
#[derive(Clone, Debug)]
pub enum State {
    /// Not attached yet.
    None,
    /// Detached (`EVFILTID_DETACHED`: vanished).
    Detached,
    /// A timer: its state and parameters.
    Timer(Timer),
    /// A user event: triggered (`kn_hook32`).
    User(bool),
    /// A signal count since the last delivery.
    Signal(u32),
    /// A Mach receive right or port set.
    MachPort(Watched),
    /// Another kqueue (`EVFILT_READ` on its descriptor).
    Kqueue(u64),
    /// A knote the host kernel carries.
    Host(host::HostKnote),
    /// A workloop's thread request, waiter, or sync IPC knote.
    Workloop,
    /// Attached, never fires.
    Inert,
}

/// Timer states (`TIMER_IDLE`, `TIMER_ARMED`, `TIMER_FIRED`,
/// `TIMER_IMMEDIATE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerState {
    Idle,
    Armed,
    Fired,
    Immediate,
}

/// A timer knote's parameters (`filt_timer_params` in `kn_ext[0]`,
/// `kn_ext[1]`, `kn_sdata`), in Mach absolute time.
#[derive(Clone, Copy, Debug)]
pub struct Timer {
    pub state: TimerState,
    pub deadline: u64,
    pub leeway: u64,
    pub interval: u64,
}

/// `NOTE_*` timer flags.
mod note {
    pub const SECONDS: u32 = 0x01;
    pub const USECONDS: u32 = 0x02;
    pub const NSECONDS: u32 = 0x04;
    pub const ABSOLUTE: u32 = 0x08;
    pub const LEEWAY: u32 = 0x10;
    pub const MACHTIME: u32 = 0x100;
    pub const TRIGGER: u32 = 0x0100_0000;
    pub const FFCTRLMASK: u32 = 0xc000_0000;
    pub const FFLAGSMASK: u32 = 0x00ff_ffff;
    pub const FFAND: u32 = 0x4000_0000;
    pub const FFOR: u32 = 0x8000_0000;
    pub const FFCOPY: u32 = 0xc000_0000;
}

/// `MACH_RCV_MSG` and the receive options a Mach-port knote may carry.
mod rcv {
    pub const MSG: u32 = 0x0000_0002;
    pub const LARGE: u32 = 0x0000_0004;
    pub const LARGE_IDENTITY: u32 = 0x0000_0008;
    pub const TRAILER_MASK: u32 = 0x0f00_0000;
    pub const VOUCHER: u32 = 0x0000_0800;
    pub const STRICT_REPLY: u32 = 0x0000_0200;
    pub const SYNC_PEEK: u32 = 0x0000_8000;
}

/// Mach absolute time units as a duration.
pub fn abs_to_duration(abi: DarwinAbi, ticks: u64) -> Duration {
    let (n, d) = crate::user::darwin::commpage::timebase(abi);
    Duration::from_nanos(
        (u128::from(ticks) * u128::from(n) / u128::from(d)).min(u128::from(u64::MAX)) as u64,
    )
}

fn ns_to_abs(abi: DarwinAbi, ns: u64) -> u64 {
    let (n, d) = crate::user::darwin::commpage::timebase(abi);
    (u128::from(ns) * u128::from(d) / u128::from(n)).min(u128::from(u64::MAX)) as u64
}

/// `filt_timervalidate`: the deadline, leeway, and interval of a timer
/// registration.
fn timer_validate(abi: DarwinAbi, kev: &Kev) -> Result<Timer, Errno> {
    let (mult, abstime): (u64, bool) =
        match kev.fflags & (note::SECONDS | note::USECONDS | note::NSECONDS | note::MACHTIME) {
            note::SECONDS => (1_000_000_000, false),
            note::USECONDS => (1_000, false),
            note::NSECONDS => (1, false),
            note::MACHTIME => (0, true),
            0 => (1_000_000, false),
            _ => return Err(Errno::EINVAL),
        };
    let to_abs = |v: u64| -> Result<u64, Errno> {
        if abstime {
            Ok(v)
        } else {
            v.checked_mul(mult)
                .map(|ns| ns_to_abs(abi, ns))
                .ok_or(Errno::ERANGE)
        }
    };
    let leeway = if kev.fflags & note::LEEWAY != 0 {
        to_abs(kev.ext[1])?
    } else {
        0
    };
    let now = absolute_time(abi);
    let (deadline, interval) = if kev.fflags & note::ABSOLUTE != 0 {
        if abstime {
            (kev.data as u64, 0)
        } else {
            let deadline_ns = (kev.data as u64).checked_mul(mult).ok_or(Errno::ERANGE)?;
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            if now_ns < deadline_ns {
                (now + ns_to_abs(abi, deadline_ns - now_ns), 0)
            } else {
                (0, 0)
            }
        }
    } else if kev.data < 0 {
        // Negative intervals fire once, immediately.
        (0, 0)
    } else {
        let interval = to_abs(kev.data as u64)?;
        (now.saturating_add(interval), interval)
    };
    Ok(Timer {
        state: TimerState::Idle,
        deadline,
        leeway,
        interval,
    })
}

fn knote_mut<'a>(proc: &'a mut Proc, kq: u64, knote: u64) -> &'a mut super::Knote {
    proc.kq
        .kqueues
        .get_mut(&kq)
        .and_then(|q| q.knotes.get_mut(&knote))
        .expect("live knote")
}

/// Arms a timer knote (`filt_timerarm`).
fn timer_arm(proc: &mut Proc, kq: u64, knote: u64, deadline: u64) {
    proc.kq.timers.retain(|t| !(t.0 == kq && t.1 == knote));
    proc.kq.timers.push((kq, knote, deadline));
}

fn timer_disarm(proc: &mut Proc, kq: u64, knote: u64) {
    proc.kq.timers.retain(|t| !(t.0 == kq && t.1 == knote));
}

/// Fires the armed timers whose deadlines passed (`filt_timerexpire`), in
/// deadline order.
pub fn fire_timers(proc: &mut Proc) {
    if proc.kq.timers.is_empty() {
        return;
    }
    let now = absolute_time(proc.abi);
    let mut due: Vec<(u64, u64, u64)> = proc
        .kq
        .timers
        .iter()
        .filter(|t| t.2 <= now)
        .copied()
        .collect();
    if due.is_empty() {
        return;
    }
    due.sort_by_key(|t| t.2);
    proc.kq.timers.retain(|t| t.2 > now);
    for (kq, knote, _) in due {
        if let Some(k) = proc
            .kq
            .kqueues
            .get_mut(&kq)
            .and_then(|q| q.knotes.get_mut(&knote))
            && let State::Timer(t) = &mut k.state
            && t.state == TimerState::Armed
        {
            t.state = TimerState::Fired;
            super::activate(proc, kq, knote);
        }
    }
}

/// The earliest armed timer deadline of the process (Mach absolute time).
pub fn earliest_timer(proc: &Proc) -> Option<u64> {
    proc.kq.timers.iter().map(|t| t.2).min()
}

/// `f_attach`: returns the filter result (errors are left on the knote).
pub fn attach(ctx: &mut Ctx<'_>, kq: u64, knote: u64, kev: &mut Kev) -> i32 {
    let abi = ctx.proc.abi;
    match kev.filter {
        evfilt::TIMER => match timer_validate(abi, kev) {
            Err(e) => {
                knote_mut(ctx.proc, kq, knote).set_error(e);
                0
            }
            Ok(mut t) => {
                let k = knote_mut(ctx.proc, kq, knote);
                k.flags |= ev::CLEAR;
                // NOTE_ABSOLUTE implies EV_ONESHOT.
                if k.sfflags & note::ABSOLUTE != 0 {
                    k.flags |= ev::ONESHOT;
                }
                k.sdata = t.interval as i64;
                let ready = t.deadline == 0 || t.deadline <= absolute_time(abi);
                t.state = if ready {
                    TimerState::Immediate
                } else {
                    TimerState::Armed
                };
                let deadline = t.deadline;
                k.state = State::Timer(t);
                if ready {
                    fr::ACTIVE
                } else {
                    timer_arm(ctx.proc, kq, knote, deadline);
                    0
                }
            }
        },
        evfilt::USER => {
            let k = knote_mut(ctx.proc, kq, knote);
            let fired = k.sfflags & note::TRIGGER != 0;
            k.state = State::User(fired);
            if fired { fr::ACTIVE } else { 0 }
        }
        evfilt::SIGNAL => {
            let k = knote_mut(ctx.proc, kq, knote);
            k.flags |= ev::CLEAR;
            k.sdata = 0;
            k.state = State::Signal(0);
            ctx.proc.kq.signal_knotes.push((kq, knote));
            0
        }
        evfilt::MACHPORT => machport_attach(ctx, kq, knote),
        evfilt::READ
        | evfilt::WRITE
        | evfilt::VNODE
        | evfilt::SOCK
        | evfilt::EXCEPT
        | evfilt::NW_CHANNEL => {
            let file = ctx
                .proc
                .fds
                .file(kev.ident as i32)
                .expect("checked descriptor");
            if let crate::user::darwin::fd::FileKind::Kqueue(target) = file.kind {
                // kqueue_kqfilter: only EVFILT_READ, not on itself.
                if kev.filter != evfilt::READ || target == kq {
                    knote_mut(ctx.proc, kq, knote).set_error(Errno::EINVAL);
                    return 0;
                }
                knote_mut(ctx.proc, kq, knote).state = State::Kqueue(target);
                if let Some(t) = ctx.proc.kq.kqueues.get_mut(&target) {
                    t.watchers.push((kq, knote));
                }
                return i32::from(ctx.proc.kq.count(target) > 0);
            }
            host::attach(ctx.proc, kq, knote, file.host_fd())
        }
        evfilt::PROC => host::attach(ctx.proc, kq, knote, None),
        evfilt::FS | evfilt::MEMORYSTATUS => {
            knote_mut(ctx.proc, kq, knote).state = State::Inert;
            0
        }
        evfilt::WORKLOOP => {
            knote_mut(ctx.proc, kq, knote).state = State::Workloop;
            super::workloop::attach(ctx, kq, knote, kev)
        }
        _ => {
            knote_mut(ctx.proc, kq, knote).set_error(Errno::ENOTSUP);
            0
        }
    }
}

/// `filt_machportattach`: a receive right or port set of the task.
fn machport_attach(ctx: &mut Ctx<'_>, kq: u64, knote: u64) -> i32 {
    let name = knote_mut(ctx.proc, kq, knote).ident as u32;
    {
        let k = knote_mut(ctx.proc, kq, knote);
        k.flags &= !ev::EOF;
        k.ext[3] = 0;
    }
    let target = match ctx.proc.ipc.lookup(name) {
        Err(_) => Err(Errno::ENOENT),
        Ok(e) => match &e.object {
            Some(Object::Set(s)) => Ok(Watched::Set(s.clone())),
            Some(Object::Port(p)) if e.receive => Ok(Watched::Port(p.clone())),
            _ => Err(Errno::ENOTSUP),
        },
    };
    match target {
        Err(e) => {
            knote_mut(ctx.proc, kq, knote).set_error(e);
            0
        }
        Ok(w) => {
            let ready = w.has_message();
            ctx.proc
                .kq
                .port_klists
                .entry(w.id())
                .or_default()
                .push((kq, knote));
            knote_mut(ctx.proc, kq, knote).state = State::MachPort(w);
            i32::from(ready)
        }
    }
}

/// `f_touch`.
pub fn touch(ctx: &mut Ctx<'_>, kq: u64, knote: u64, kev: &mut Kev) -> i32 {
    let abi = ctx.proc.abi;
    let filter = knote_mut(ctx.proc, kq, knote).filter;
    match filter {
        evfilt::TIMER => {
            let k = knote_mut(ctx.proc, kq, knote);
            if (k.sfflags ^ kev.fflags) & note::ABSOLUTE != 0 {
                kev.flags |= ev::ERROR;
                kev.data = i64::from(Errno::EINVAL.0);
                return 0;
            }
            match timer_validate(abi, kev) {
                Err(e) => {
                    kev.flags |= ev::ERROR;
                    kev.data = i64::from(e.0);
                    0
                }
                Ok(mut t) => {
                    let k = knote_mut(ctx.proc, kq, knote);
                    k.sdata = t.interval as i64;
                    k.sfflags = kev.fflags;
                    let ready = t.deadline == 0 || t.deadline <= absolute_time(abi);
                    t.state = if ready {
                        TimerState::Immediate
                    } else {
                        TimerState::Armed
                    };
                    let deadline = t.deadline;
                    k.state = State::Timer(t);
                    if ready {
                        timer_disarm(ctx.proc, kq, knote);
                        fr::ACTIVE | fr::UPDATE_REQ_QOS
                    } else {
                        timer_arm(ctx.proc, kq, knote, deadline);
                        fr::UPDATE_REQ_QOS
                    }
                }
            }
        }
        evfilt::USER => {
            let k = knote_mut(ctx.proc, kq, knote);
            let fflags = kev.fflags & note::FFLAGSMASK;
            match kev.fflags & note::FFCTRLMASK {
                note::FFAND => k.sfflags &= fflags,
                note::FFOR => k.sfflags |= fflags,
                note::FFCOPY => k.sfflags = fflags,
                _ => {}
            }
            k.sdata = kev.data;
            let State::User(fired) = &mut k.state else {
                return 0;
            };
            if kev.fflags & note::TRIGGER != 0 {
                *fired = true;
            }
            i32::from(*fired)
        }
        evfilt::SIGNAL => {
            let k = knote_mut(ctx.proc, kq, knote);
            i32::from(matches!(k.state, State::Signal(n) if n > 0))
        }
        evfilt::MACHPORT => {
            let k = knote_mut(ctx.proc, kq, knote);
            // filt_machporttouch: the receive mode cannot change.
            if (k.sfflags ^ kev.fflags) & (rcv::MSG | rcv::SYNC_PEEK) != 0 {
                kev.flags |= ev::ERROR;
                kev.data = i64::from(Errno::EINVAL.0);
                return 0;
            }
            k.sfflags = kev.fflags;
            k.ext[0] = kev.ext[0];
            k.ext[1] = kev.ext[1];
            match &k.state {
                State::MachPort(w) => i32::from(w.has_message()),
                _ => 0,
            }
        }
        evfilt::WORKLOOP => super::workloop::touch(ctx, kq, knote, kev),
        _ => {
            let state = knote_mut(ctx.proc, kq, knote).state.clone();
            match state {
                State::Kqueue(target) => i32::from(ctx.proc.kq.count(target) > 0),
                State::Host(_) => host::touch(ctx.proc, kq, knote, kev),
                _ => 0,
            }
        }
    }
}

/// `f_process`: the event to deliver and the filter result.
pub fn process(ctx: &mut Ctx<'_>, kq: u64, knote: u64, data: &mut DataArea) -> (Kev, i32) {
    let abi = ctx.proc.abi;
    let state = knote_mut(ctx.proc, kq, knote).state.clone();
    match state {
        State::Timer(t) => {
            if matches!(t.state, TimerState::Idle | TimerState::Armed) {
                return (Kev::default(), 0);
            }
            let k = knote_mut(ctx.proc, kq, knote);
            let mut kev = k.fill(1);
            kev.ext[0] = 0;
            let mut next = None;
            if k.sdata != 0 {
                // A repeating timer: how many intervals passed.
                let now = absolute_time(abi);
                let interval = k.sdata as u64;
                let first_deadline = t.deadline;
                let orig = first_deadline.saturating_sub(interval);
                let fired = (now.saturating_sub(orig) / interval).max(1);
                kev.data = fired as i64;
                if k.flags & ev::ONESHOT == 0 {
                    next = Some(first_deadline + fired * interval);
                }
            }
            if let State::Timer(tt) = &mut k.state {
                tt.state = TimerState::Idle;
                if let Some(d) = next {
                    tt.deadline = d;
                    tt.state = TimerState::Armed;
                }
            }
            if let Some(d) = next {
                timer_arm(ctx.proc, kq, knote, d);
            }
            (kev, fr::ACTIVE)
        }
        State::User(fired) => {
            if !fired {
                return (Kev::default(), 0);
            }
            let k = knote_mut(ctx.proc, kq, knote);
            let mut kev = k.fill_with_sdata();
            kev.fflags = k.sfflags;
            if k.flags & ev::CLEAR != 0 {
                k.state = State::User(false);
            }
            (kev, fr::ACTIVE)
        }
        State::Signal(n) => {
            if n == 0 {
                return (Kev::default(), 0);
            }
            let k = knote_mut(ctx.proc, kq, knote);
            let kev = k.fill(i64::from(n));
            k.state = State::Signal(0);
            (kev, fr::ACTIVE)
        }
        State::MachPort(w) => machport_process(ctx, kq, knote, &w, data),
        State::Kqueue(target) => {
            let count = ctx.proc.kq.count(target);
            if count == 0 {
                return (Kev::default(), 0);
            }
            (
                knote_mut(ctx.proc, kq, knote).fill(count as i64),
                fr::ACTIVE,
            )
        }
        State::Host(_) => host::process(ctx.proc, kq, knote),
        State::Workloop => super::workloop::process(ctx.proc, kq, knote),
        State::None | State::Detached | State::Inert => (Kev::default(), 0),
    }
}

/// `filt_machportprocess`: with `MACH_RCV_MSG`, receives the message into
/// the knote's buffer (or the call's data area); otherwise reports the
/// port with a message.
fn machport_process(
    ctx: &mut Ctx<'_>,
    kq: u64,
    knote: u64,
    w: &Watched,
    data: &mut DataArea,
) -> (Kev, i32) {
    let k = knote_mut(ctx.proc, kq, knote);
    let mut kev = k.fill(0);
    kev.ext[3] = 0;
    if kev.flags & ev::EOF != 0 {
        return (kev, fr::ACTIVE | fr::RESET_EVENT_QOS);
    }
    let sfflags = k.sfflags;
    let (buf_addr, buf_size) = (k.ext[0], k.ext[1] as u32);
    let mut options = u64::from(
        sfflags
            & (rcv::MSG
                | rcv::LARGE
                | rcv::LARGE_IDENTITY
                | rcv::TRAILER_MASK
                | rcv::VOUCHER
                | rcv::STRICT_REPLY),
    );
    let (addr, size, from_area) = if sfflags & rcv::MSG != 0 {
        if buf_size == 0 {
            options |= u64::from(rcv::LARGE | rcv::LARGE_IDENTITY);
            let size = data.resid as u32;
            let addr = if data.stack {
                data.out + data.resid - u64::from(size)
            } else {
                data.out
            };
            (addr, size, true)
        } else {
            (buf_addr, buf_size, false)
        }
    } else {
        options = u64::from(rcv::LARGE);
        (0, 0, false)
    };
    let r = crate::user::darwin::syscall::mach::msg::receive_object(
        ctx,
        w,
        options,
        addr,
        size,
        from_area && data.stack,
    );
    let Some(r) = r else {
        // Nothing queued (MACH_RCV_TIMED_OUT): not active.
        return (Kev::default(), 0);
    };
    if sfflags & rcv::MSG == 0 {
        // Not received: the port with a message (MACH_RCV_TOO_LARGE).
        kev.data = i64::from(r.name);
        return (kev, fr::ACTIVE);
    }
    kev.fflags = r.kr as u32;
    kev.ext[1] = u64::from(r.msg_size) + u64::from(r.trailer_size);
    kev.ext[3] = u64::from(r.aux_size);
    kev.data = if r.kr == crate::user::darwin::mach::kr::MACH_RCV_TOO_LARGE
        && options & u64::from(rcv::LARGE_IDENTITY) != 0
    {
        i64::from(r.name)
    } else {
        0
    };
    if from_area && r.kr != crate::user::darwin::mach::kr::MACH_RCV_TOO_LARGE {
        let used = u64::from(r.msg_size) + u64::from(r.trailer_size) + u64::from(r.aux_size);
        data.resid -= used.min(data.resid);
        if data.stack {
            kev.ext[0] = data.out + data.resid;
        } else {
            kev.ext[0] = data.out;
            data.out += used;
        }
    }
    if r.kr == crate::user::darwin::mach::kr::MACH_MSG_SUCCESS {
        kev.ext[2] = 0;
    }
    (kev, fr::ACTIVE)
}

/// `f_detach`.
pub fn detach(proc: &mut Proc, kq: u64, knote: u64) {
    let Some(k) = proc.kq.kqueues.get(&kq).and_then(|q| q.knotes.get(&knote)) else {
        return;
    };
    match k.state.clone() {
        State::Timer(_) => timer_disarm(proc, kq, knote),
        State::Signal(_) => proc.kq.signal_knotes.retain(|&e| e != (kq, knote)),
        State::MachPort(w) => {
            let id = w.id();
            if let Some(l) = proc.kq.port_klists.get_mut(&id) {
                l.retain(|&e| e != (kq, knote));
                if l.is_empty() {
                    proc.kq.port_klists.remove(&id);
                }
            }
        }
        State::Kqueue(target) => {
            if let Some(t) = proc.kq.kqueues.get_mut(&target) {
                t.watchers.retain(|&e| e != (kq, knote));
            }
        }
        State::Host(_) => host::detach(proc, kq, knote),
        State::Workloop => super::workloop::detach(proc, kq, knote),
        _ => {}
    }
}

/// The knote was enabled or disabled (the host must stop reporting a
/// disabled knote).
pub fn enabled(proc: &mut Proc, kq: u64, knote: u64, on: bool) {
    if proc
        .kq
        .kqueues
        .get(&kq)
        .and_then(|q| q.knotes.get(&knote))
        .is_some_and(|k| matches!(k.state, State::Host(_)))
    {
        host::enable(proc, kq, knote, on);
    }
}

/// A message arrived on the port or set `id` (`KNOTE` on `ip_klist` /
/// `ips_klist`).
pub fn post_machport(proc: &mut Proc, id: u64) {
    let Some(list) = proc.kq.port_klists.get(&id).cloned() else {
        return;
    };
    fire_timers(proc);
    for (kq, knote) in list {
        super::activate(proc, kq, knote);
    }
}

/// A signal was sent to the process (`proc_knote(NOTE_SIGNAL | sig)`).
pub fn post_signal(proc: &mut Proc, sig: i32) {
    if proc.kq.signal_knotes.is_empty() {
        return;
    }
    fire_timers(proc);
    for (kq, knote) in proc.kq.signal_knotes.clone() {
        let Some(k) = proc
            .kq
            .kqueues
            .get_mut(&kq)
            .and_then(|q| q.knotes.get_mut(&knote))
        else {
            continue;
        };
        if k.ident == sig as u64
            && let State::Signal(n) = &mut k.state
        {
            *n += 1;
            super::activate(proc, kq, knote);
        }
    }
}

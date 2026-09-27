//! `EVFILT_WORKLOOP`: the knotes of a workloop (`filt_wl*` in
//! `bsd/kern/kern_event.c`, `bsd/sys/event_private.h`).
//!
//! A workloop has three kinds of knote, chosen by the command in the
//! filter flags:
//!
//! - the thread request (`NOTE_WL_THREAD_REQUEST`, ident the workloop's
//!   ID, at most one): attaching or touching it fires it, which makes the
//!   workloop ask for a servicer; its QoS is the workloop's;
//! - synchronous waiters (`NOTE_WL_SYNC_WAIT`, ident the waiter's thread
//!   ID): registering one blocks the caller in `kevent_id` until a
//!   `NOTE_WL_SYNC_WAKE` touch (or a delete) of the same knote;
//! - sync IPC links (`NOTE_WL_SYNC_IPC`), which need special reply ports
//!   and fail with `ENOENT` here.
//!
//! Every update may first check a 64-bit word in user memory against an
//! expected value under a mask (`ESTALE` on a mismatch, unless
//! `NOTE_WL_IGNORE_ESTALE`), take the owner's thread port name from its
//! low 32 bits (`NOTE_WL_DISCOVER_OWNER`), or end the caller's ownership
//! (`NOTE_WL_END_OWNERSHIP`). A workloop with an owner gets no servicer.

use super::workq::{self, KqrRef, Utq};
use super::{Kev, Knote, Layout, ev, fr};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::mach::ipc::KObject;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::{Resume, Wait, WaitKey};
use crate::user::darwin::workq::priority;

/// `NOTE_WL_*`.
pub mod note {
    pub const THREAD_REQUEST: u32 = 0x0000_0001;
    pub const SYNC_WAIT: u32 = 0x0000_0004;
    pub const SYNC_WAKE: u32 = 0x0000_0008;
    pub const SYNC_IPC: u32 = 0x8000_0000;
    pub const COMMANDS_MASK: u32 = 0x8000_000f;
    pub const UPDATE_QOS: u32 = 0x0000_0010;
    pub const END_OWNERSHIP: u32 = 0x0000_0020;
    pub const DISCOVER_OWNER: u32 = 0x0000_0080;
    pub const IGNORE_ESTALE: u32 = 0x0000_0100;
    pub const UPDATES_MASK: u32 = 0x0000_01f0;
}

/// `EV_EXTIDX_WL_ADDR`, `EV_EXTIDX_WL_MASK`, `EV_EXTIDX_WL_VALUE`.
const EXT_ADDR: usize = 1;
const EXT_MASK: usize = 2;
const EXT_VALUE: usize = 3;

/// `FILT_WLATTACH`, `FILT_WLTOUCH`, `FILT_WLDROP`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Attach,
    Touch,
    Drop,
}

/// A registration the caller sleeps in (`struct _kevent_register`).
#[derive(Clone, Copy, Debug)]
pub struct RegisterWait {
    /// The registration, returned when it carries an error or a receipt.
    pub kev: Kev,
    /// The workloop.
    pub kq: u64,
    /// The waiter knote.
    pub knote: u64,
    /// Events already written.
    pub eventout: u32,
    /// Where the next event goes.
    pub ueventlist: u64,
    /// The call that sleeps.
    pub call: i64,
    /// A `NOTE_WL_SYNC_WAKE` ended the wait.
    pub awakened: bool,
}

fn knote_mut(proc: &mut Proc, kq: u64, knote: u64) -> &mut Knote {
    proc.kq
        .kqueues
        .get_mut(&kq)
        .and_then(|q| q.knotes.get_mut(&knote))
        .expect("live knote")
}

/// `copyin_atomic64`.
fn load(ctx: &Ctx<'_>, addr: u64) -> Result<u64, Errno> {
    if addr & 7 != 0 {
        return Err(Errno::EINVAL);
    }
    ctx.read_u64(addr)
}

/// `port_name_to_thread(name, PORT_INTRANS_THREAD_IN_CURRENT_TASK)`.
fn name_to_thread(ctx: &Ctx<'_>, name: u32) -> Option<u64> {
    let port = ctx.proc.ipc.lookup(name).ok()?.port()?.clone();
    match port.kobject {
        KObject::Thread(tid)
            if tid == ctx.thread.tid || ctx.proc.threads.get(&tid).is_some_and(|t| !t.exited) =>
        {
            Some(tid)
        }
        _ => None,
    }
}

/// `filt_wlupdate`: the debounce check, then ownership and QoS changes,
/// and the wake of a synchronous waiter.
fn update(
    ctx: &mut Ctx<'_>,
    kq: u64,
    knote: u64,
    kev: &mut Kev,
    qos_index: u8,
    op: Op,
) -> Result<(), Errno> {
    let (uaddr, kdata, mask) = (kev.ext[EXT_ADDR], kev.ext[EXT_VALUE], kev.ext[EXT_MASK]);
    let Some(cur_owner) = workq::kqwl(ctx.proc, kq).map(|w| w.owner) else {
        return Err(Errno::ENOTSUP);
    };
    let mut new_owner = cur_owner;
    if uaddr != 0 {
        let udata = load(ctx, uaddr)?;
        kev.ext[EXT_VALUE] = udata;
        if udata & mask != kdata & mask {
            return Err(Errno::ESTALE);
        }
        if kev.fflags & note::DISCOVER_OWNER != 0 {
            // The low two bits were borrowed for flags; the name's
            // generation roll bits come back (ipc_entry_name_mask).
            let name = udata as u32 & !0x3;
            if name != 0 {
                let tid = name_to_thread(ctx, name | 0x3).ok_or(Errno::EOWNERDEAD)?;
                new_owner = Some(tid);
            }
        }
    }
    let me = ctx.thread.tid;
    if kev.fflags & note::END_OWNERSHIP != 0 && new_owner == Some(me) {
        new_owner = None;
    }
    let kqr_index = workq::kqr(ctx.proc, KqrRef { kq, idx: 0 }).map_or(0, |q| q.qos_index);
    let action = if kev.fflags & note::THREAD_REQUEST != 0 && kev.flags & ev::DELETE != 0 {
        Some((Utq::SetQosIndex, qos_index))
    } else if qos_index != 0 && kqr_index != qos_index {
        Some((Utq::SetQosIndex, qos_index))
    } else {
        None
    };
    let mut needs_wake = false;
    let k = knote_mut(ctx.proc, kq, knote);
    match op {
        Op::Touch => {
            // Keep only the last round of update bits.
            k.sfflags &= !note::UPDATES_MASK;
            k.sfflags |= kev.fflags;
            if kev.fflags & note::SYNC_WAKE != 0 {
                needs_wake = k.thread.is_some();
            }
        }
        Op::Drop => {
            if k.sfflags & (note::SYNC_WAIT | note::SYNC_WAKE) == note::SYNC_WAIT {
                // Deleting a waiter that was not woken wakes it.
                k.sfflags |= note::SYNC_WAKE;
                needs_wake = k.thread.is_some();
            }
        }
        Op::Attach => {}
    }
    let waiter = k.thread;
    if cur_owner == new_owner && action.is_none() && !needs_wake {
        return Ok(());
    }
    workq::set_owner(ctx.proc, kq, new_owner, action);
    if needs_wake && let Some(tid) = waiter {
        wake_waiter(ctx.proc, tid, knote);
    }
    Ok(())
}

/// Wakes thread `tid` if it sleeps registering `knote`
/// (`waitq_wakeup64_thread` on the knote's event).
fn wake_waiter(proc: &mut Proc, tid: u64, knote: u64) {
    let Some(t) = proc.threads.get_mut(&tid) else {
        return;
    };
    if t.woken
        || !t
            .wait
            .as_ref()
            .is_some_and(|w| w.keys.contains(&WaitKey::Knote(knote)))
    {
        return;
    }
    t.woken = true;
    if let Some(w) = proc.kq.register_waits.get_mut(&tid) {
        w.awakened = true;
    }
}

/// `filt_wlremember_last_update`.
fn remember_last_update(proc: &mut Proc, kq: u64, knote: u64, kev: &Kev, error: Option<Errno>) {
    let k = knote_mut(proc, kq, knote);
    k.fflags = kev.fflags;
    k.sdata = error.map_or(0, |e| i64::from(e.0));
    k.ext = kev.ext;
}

/// `filt_wlupdate_sync_ipc`: the debounce check; attaching needs a port
/// in a sync IPC inheritance chain, which the emulation has none of
/// (`filt_wlattach_sync_ipc`: `ENOENT`).
fn update_sync_ipc(
    ctx: &mut Ctx<'_>,
    kq: u64,
    knote: u64,
    kev: &mut Kev,
    op: Op,
) -> Result<(), Errno> {
    let (uaddr, kdata, mask) = (kev.ext[EXT_ADDR], kev.ext[EXT_VALUE], kev.ext[EXT_MASK]);
    if op != Op::Attach && uaddr == 0 {
        return Ok(());
    }
    if uaddr != 0 {
        let udata = load(ctx, uaddr)?;
        kev.ext[EXT_VALUE] = udata;
        knote_mut(ctx.proc, kq, knote).ext[EXT_VALUE] = udata;
        if udata & mask != kdata & mask {
            return Err(Errno::ESTALE);
        }
    }
    if op == Op::Attach {
        return Err(Errno::ENOENT);
    }
    Ok(())
}

/// `kevent_register_wait_prepare`: the caller will sleep on the knote.
fn register_wait_prepare(ctx: &mut Ctx<'_>, kq: u64, knote: u64, kev: &mut Kev, rc: i32) -> i32 {
    let me = ctx.thread.tid;
    let k = knote_mut(ctx.proc, kq, knote);
    match k.thread {
        None => k.thread = Some(me),
        Some(t) if t != me => {
            // From an aborted wait of another thread.
            kev.flags |= ev::ERROR;
            kev.data = i64::from(Errno::EXDEV.0);
            return 0;
        }
        Some(_) => {}
    }
    fr::REGISTER_WAIT | rc
}

/// `filt_wlattach`.
pub fn attach(ctx: &mut Ctx<'_>, kq: u64, knote: u64, kev: &mut Kev) -> i32 {
    let Some(id) = workq::kqwl(ctx.proc, kq).map(|w| w.dynamic_id) else {
        knote_mut(ctx.proc, kq, knote).set_error(Errno::ENOTSUP);
        return 0;
    };
    let k = knote_mut(ctx.proc, kq, knote);
    let (sfflags, flags, ident, qos) = (k.sfflags, k.flags, k.ident, k.qos);
    let command = sfflags & note::COMMANDS_MASK;
    let mut qos_index = 0;
    let check = match command {
        note::THREAD_REQUEST => {
            qos_index = priority::thread_qos(qos as u32);
            if ident != id {
                Err(Errno::EINVAL)
            } else if qos_index == 0 {
                Err(Errno::ERANGE)
            } else if workq::kqr(ctx.proc, KqrRef { kq, idx: 0 }).is_some_and(|q| q.qos_index != 0)
            {
                // One thread request per workloop.
                Err(Errno::EALREADY)
            } else {
                Ok(())
            }
        }
        note::SYNC_WAIT | note::SYNC_WAKE => {
            if ident == id || flags & ev::DISABLE == 0 || sfflags & note::END_OWNERSHIP != 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(())
            }
        }
        note::SYNC_IPC => {
            if flags & ev::DISABLE == 0 || sfflags & (note::UPDATE_QOS | note::DISCOVER_OWNER) != 0
            {
                Err(Errno::EINVAL)
            } else {
                Ok(())
            }
        }
        _ => Err(Errno::EINVAL),
    };
    let r = check.and_then(|()| {
        if command == note::SYNC_IPC {
            update_sync_ipc(ctx, kq, knote, kev, Op::Attach)
        } else {
            update(ctx, kq, knote, kev, qos_index, Op::Attach)
        }
    });
    if let Err(e) = r {
        // A hidden ESTALE still fails the attach, silently.
        let e = if e == Errno::ESTALE && sfflags & note::IGNORE_ESTALE != 0 {
            Errno(0)
        } else {
            e
        };
        knote_mut(ctx.proc, kq, knote).set_error(e);
        return 0;
    }
    if command == note::SYNC_WAIT {
        return register_wait_prepare(ctx, kq, knote, kev, 0);
    }
    if command == note::THREAD_REQUEST {
        // Delivering the request consumes it: it needs a touch to fire
        // again.
        knote_mut(ctx.proc, kq, knote).flags |= ev::CLEAR;
        return fr::ACTIVE;
    }
    0
}

/// `filt_wlvalidate_kev_flags`: the new QoS for `NOTE_WL_UPDATE_QOS`.
fn validate(k: &Knote, kev: &Kev) -> Result<u8, Errno> {
    let new = kev.fflags & note::COMMANDS_MASK;
    let saved = k.sfflags & note::COMMANDS_MASK;
    let mut qos_index = 0;
    if kev.fflags & note::DISCOVER_OWNER != 0 && kev.flags & ev::DELETE != 0 {
        return Err(Errno::EINVAL);
    }
    if kev.fflags & note::UPDATE_QOS != 0 {
        if kev.flags & ev::DELETE != 0 || saved != note::THREAD_REQUEST {
            return Err(Errno::EINVAL);
        }
        qos_index = priority::thread_qos(kev.qos as u32);
        if qos_index == 0 {
            return Err(Errno::ERANGE);
        }
    }
    let sync_checks = || {
        if saved & (note::SYNC_WAIT | note::SYNC_WAKE) == 0
            || kev.flags & (ev::ENABLE | ev::DELETE) == ev::ENABLE
        {
            Err(Errno::EINVAL)
        } else {
            Ok(qos_index)
        }
    };
    match new {
        note::THREAD_REQUEST if saved == note::THREAD_REQUEST => Ok(qos_index),
        note::SYNC_WAIT if kev.fflags & note::END_OWNERSHIP == 0 => sync_checks(),
        note::SYNC_WAKE => sync_checks(),
        note::SYNC_IPC
            if saved == note::SYNC_IPC && kev.flags & (ev::ENABLE | ev::DELETE) != ev::ENABLE =>
        {
            Ok(qos_index)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `filt_wltouch`.
pub fn touch(ctx: &mut Ctx<'_>, kq: u64, knote: u64, kev: &mut Kev) -> i32 {
    let command = kev.fflags & note::COMMANDS_MASK;
    let r = validate(knote_mut(ctx.proc, kq, knote), kev).and_then(|qos_index| {
        if command == note::SYNC_IPC {
            update_sync_ipc(ctx, kq, knote, kev, Op::Touch)
        } else {
            let r = update(ctx, kq, knote, kev, qos_index, Op::Touch);
            remember_last_update(ctx.proc, kq, knote, kev, r.err());
            r
        }
    });
    if let Err(e) = r {
        if !(e == Errno::ESTALE && kev.fflags & note::IGNORE_ESTALE != 0) {
            kev.flags |= ev::ERROR;
            kev.data = i64::from(e.0);
        }
        return 0;
    }
    let sfflags = knote_mut(ctx.proc, kq, knote).sfflags;
    if command == note::SYNC_WAIT && sfflags & note::SYNC_WAKE == 0 {
        return register_wait_prepare(ctx, kq, knote, kev, 0);
    }
    if command == note::THREAD_REQUEST {
        let mut result = fr::ACTIVE;
        if kev.fflags & note::UPDATE_QOS != 0 {
            result |= fr::UPDATE_REQ_QOS;
        }
        return result;
    }
    0
}

/// `filt_wlallow_drop`: whether the delete may proceed.
pub fn allow_drop(ctx: &mut Ctx<'_>, kq: u64, knote: u64, kev: &mut Kev) -> bool {
    let command = kev.fflags & note::COMMANDS_MASK;
    let r = validate(knote_mut(ctx.proc, kq, knote), kev).and_then(|_| {
        if command == note::SYNC_IPC {
            update_sync_ipc(ctx, kq, knote, kev, Op::Drop)
        } else {
            let r = update(ctx, kq, knote, kev, 0, Op::Drop);
            remember_last_update(ctx.proc, kq, knote, kev, r.err());
            r
        }
    });
    if let Err(e) = r {
        if !(e == Errno::ESTALE && kev.fflags & note::IGNORE_ESTALE != 0) {
            kev.flags |= ev::ERROR;
            kev.data = i64::from(e.0);
        }
        return false;
    }
    true
}

/// `filt_wlprocess`: the thread request's event, unless the workloop has
/// an owner (then it stays active for later).
pub fn process(proc: &mut Proc, kq: u64, knote: u64) -> (Kev, i32) {
    if workq::kqwl(proc, kq).is_some_and(|w| w.owner.is_some()) {
        knote_mut(proc, kq, knote).status |= super::kn::ACTIVE;
        return (Kev::default(), 0);
    }
    let k = knote_mut(proc, kq, knote);
    let mut kev = k.fill(0);
    kev.fflags = k.sfflags;
    (kev, fr::ACTIVE)
}

/// `filt_wldetach`: a waiter knote forgets its thread.
pub fn detach(proc: &mut Proc, kq: u64, knote: u64) {
    if let Some(k) = proc
        .kq
        .kqueues
        .get_mut(&kq)
        .and_then(|q| q.knotes.get_mut(&knote))
        && k.sfflags & note::SYNC_IPC == 0
    {
        k.thread = None;
    }
}

/// `filt_wlpost_register_wait`: the caller sleeps on the waiter knote
/// until it is woken or interrupted, and finishes the call in [`resume`]
/// (`ERESTART` with the wait recorded). Interrupted before it blocks,
/// the call finishes at once with the number of records.
pub fn post_register_wait(ctx: &mut Ctx<'_>, w: RegisterWait) -> Result<usize, Errno> {
    if crate::user::darwin::signal::interruption(ctx.proc, ctx.thread).is_some()
        || ctx.thread.sig.take_abort()
    {
        // THREAD_ABORTSAFE: interrupted before it blocks.
        return finish(ctx, w, false);
    }
    ctx.proc.kq.register_waits.insert(ctx.thread.tid, w);
    ctx.thread.resume = Some(Resume {
        pc: ctx.pc,
        call: ctx.nr,
        deadline: None,
        step: 2,
    });
    ctx.thread.wait = Some(Wait {
        keys: vec![WaitKey::Knote(w.knote)],
        interruptible: true,
        seq: crate::user::darwin::wait::next_seq(),
        ..Default::default()
    });
    Err(Errno::ERESTART)
}

/// The call that slept registering a waiter returns
/// (`filt_wlwait_continue`, `kevent_register_wait_return`), dropping its
/// reference on the workloop. `None` when the thread did not sleep in
/// this call.
pub fn resume(ctx: &mut Ctx<'_>) -> Option<SysResult> {
    let tid = ctx.thread.tid;
    let w = ctx
        .proc
        .kq
        .register_waits
        .get(&tid)
        .filter(|w| w.call == ctx.nr)
        .copied()?;
    ctx.proc.kq.register_waits.remove(&tid);
    ctx.thread.resume = None;
    let r = finish(ctx, w, w.awakened);
    workq::release(ctx.proc, w.kq);
    Some(r.map(|n| Rv::one(n as u64)))
}

/// `kevent_register_wait_return`: the registration comes back when it
/// carries an error (`EINTR` when a signal ended the wait) or a receipt.
fn finish(ctx: &mut Ctx<'_>, w: RegisterWait, awakened: bool) -> Result<usize, Errno> {
    let mut kev = w.kev;
    if !awakened {
        // The abort is spent.
        ctx.thread.sig.abort = false;
        kev.flags |= ev::ERROR;
        kev.data = i64::from(Errno::EINTR.0);
    }
    let mut out = w.eventout as usize;
    if kev.flags & (ev::ERROR | ev::RECEIPT) != 0 {
        if kev.flags & ev::ERROR == 0 {
            kev.flags |= ev::ERROR;
            kev.data = 0;
        }
        ctx.write(w.ueventlist, &kev.encode(Layout::Qos))?;
        out += 1;
    }
    Ok(out)
}

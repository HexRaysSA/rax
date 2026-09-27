//! The `kevent` family of calls on a kqueue (`kevent_internal`,
//! `kevent_id`, `kevent_workq_internal`, `kevent_get_data_size` in
//! `bsd/kern/kern_event.c`): changes are registered, then events are
//! collected — by waiting for a file kqueue's, or for a workqueue
//! thread's kqueue request into its stack.

use std::time::{Duration, Instant};

use super::{
    DataArea, Kev, KevApi, KqKind, Layout, ev, host, kflag, kqueue_process, next_timer, register,
    workloop, workq,
};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::{Resume, Wait, WaitKey};

/// The arguments of a `kevent` family call.
#[derive(Clone, Copy, Debug)]
pub struct Call {
    pub fd: i32,
    pub changelist: u64,
    pub nchanges: i32,
    pub eventlist: u64,
    pub nevents: i32,
    pub flags: u32,
    pub layout: Layout,
    /// The relative timeout (`None`: forever).
    pub timeout: Option<Duration>,
    pub data_out: u64,
    pub data_available: u64,
}

/// `kevent_args_requesting_events`.
fn requesting_events(flags: u32, nevents: i32) -> bool {
    flags & kflag::ERROR_EVENTS == 0 && nevents > 0
}

/// `kevent_legacy_internal`, `kevent_qos`: the call on a file kqueue or
/// the workqueue kqueue. Returns the number of records written.
pub fn kevent(ctx: &mut Ctx<'_>, c: Call) -> SysResult {
    let kq = if c.flags & kflag::WORKQ != 0 {
        // kevent_get_kqwq: no events to receive here.
        if requesting_events(c.flags, c.nevents) {
            return Err(Errno::EINVAL);
        }
        workq::get_kqwq(ctx.proc, c.flags)
    } else {
        let file = ctx.proc.fds.file(c.fd)?;
        let crate::user::darwin::fd::FileKind::Kqueue(kq) = file.kind else {
            return Err(Errno::EBADF);
        };
        kq
    };
    // kqfiles cannot be used through kevent() and the others at once.
    let api = match c.layout {
        Layout::Kevent => KevApi::Kev32,
        Layout::Kevent64 => KevApi::Kev64,
        Layout::Qos => KevApi::Qos,
    };
    let q = ctx.proc.kq.kqueues.get_mut(&kq).ok_or(Errno::EBADF)?;
    let bound = *q.api.get_or_insert(api);
    if (bound == KevApi::Kev32) != (api == KevApi::Kev32) {
        return Err(Errno::EINVAL);
    }
    let data = data_area(ctx, c.flags, c.data_out, c.data_available)?;
    let n = kevent_internal(ctx, kq, &c, data)?;
    Ok(Rv::one(n as u64))
}

/// `kevent_get_data_size`.
fn data_area(ctx: &Ctx<'_>, flags: u32, out: u64, avail: u64) -> Result<DataArea, Errno> {
    if out == 0 || avail == 0 {
        return Ok(DataArea::default());
    }
    let size = ctx.read_u64(avail)?;
    Ok(DataArea {
        out,
        resid: size,
        size,
        stack: flags & kflag::STACK_DATA != 0,
    })
}

/// `kevent_id(id, changelist, nchanges, eventlist, nevents, data_out,
/// data_available, flags)`: the call on the workloop `id` (the calling
/// servicer's own workloop, or looked up and made).
pub fn kevent_id(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    if let Some(r) = workloop::resume(ctx) {
        return r;
    }
    let id = a[0];
    let flags = (a[7] as u32 & kflag::USER) | kflag::PROC64 | kflag::DYNAMIC_KQUEUE;
    if flags & (kflag::WORKQ | kflag::WORKLOOP) != kflag::WORKLOOP {
        return Err(Errno::EINVAL);
    }
    let data = data_area(ctx, flags, a[5], a[6])?;
    let c = Call {
        fd: -1,
        changelist: a[1],
        nchanges: a[2] as i32,
        eventlist: a[3],
        nevents: a[4] as i32,
        flags,
        layout: Layout::Qos,
        timeout: None,
        data_out: a[5],
        data_available: a[6],
    };
    // The fast path: the workloop the caller services.
    let tid = ctx.thread.tid;
    let own = ctx
        .proc
        .wq
        .threads
        .get(&tid)
        .and_then(|w| w.bound)
        .filter(|r| workq::kqwl(ctx.proc, r.kq).is_some_and(|w| w.dynamic_id == id));
    let kq = if let Some(r) = own {
        if flags & kflag::DYNAMIC_KQ_MUST_NOT_EXIST != 0 {
            return Err(Errno::EEXIST);
        }
        workq::retain(ctx.proc, r.kq);
        r.kq
    } else if requesting_events(flags, c.nevents) {
        // Only a workloop's servicer receives its events.
        return Err(Errno::EXDEV);
    } else {
        workq::workloop_get_or_create(ctx.proc, id, None, flags)?
    };
    let n = kevent_internal(ctx, kq, &c, data)?;
    Ok(Rv::one(n as u64))
}

/// `kevent_workq_internal`: a workqueue thread's kqueue request is
/// serviced into its stack (`changes` are its pending changes when it
/// returns). A workloop's ID goes just below the event list. Returns the
/// number of events and the data left.
#[allow(clippy::too_many_arguments)]
pub fn kevent_workq_internal(
    ctx: &mut Ctx<'_>,
    changelist: u64,
    nchanges: i32,
    eventlist: u64,
    nevents: i32,
    data_out: u64,
    data_size: u64,
    flags: u32,
) -> Result<(i32, u64), Errno> {
    let tid = ctx.thread.tid;
    let Some(r) = ctx.proc.wq.threads.get(&tid).and_then(|w| w.bound) else {
        return Ok((-1, data_size));
    };
    let mut flags = flags | kflag::PROC64 | kflag::KERNEL;
    if workq::is_workloop(ctx.proc, r) {
        workq::retain(ctx.proc, r.kq);
        flags |= kflag::WORKLOOP | kflag::DYNAMIC_KQUEUE;
    } else {
        flags |= kflag::WORKQ;
    }
    let c = Call {
        fd: -1,
        changelist,
        nchanges,
        eventlist,
        nevents,
        flags,
        layout: Layout::Qos,
        timeout: None,
        data_out,
        data_available: 0,
    };
    let mut data = DataArea {
        out: data_out,
        resid: data_size,
        size: data_size,
        stack: true,
    };
    let n = kevent_internal_with(ctx, r.kq, &c, &mut data)?;
    Ok((n as i32, data.resid))
}

/// `kevent_internal`: registers the changes, then scans for events (and
/// for a file kqueue, waits). Returns the number of records written.
fn kevent_internal(
    ctx: &mut Ctx<'_>,
    kq: u64,
    c: &Call,
    mut data: DataArea,
) -> Result<usize, Errno> {
    let n = kevent_internal_with(ctx, kq, c, &mut data);
    if matches!(n, Ok(_)) && data.resid != data.size && c.data_available != 0 {
        // kevent_put_data_size.
        let _ = ctx.write_u64(c.data_available, data.resid);
    }
    n
}

fn kevent_internal_with(
    ctx: &mut Ctx<'_>,
    kq: u64,
    c: &Call,
    data: &mut DataArea,
) -> Result<usize, Errno> {
    let r = kevent_body(ctx, kq, c, data);
    // kevent_cleanup: the workloop reference goes (not while the caller
    // sleeps in a registration, whose return drops it).
    let sleeping = matches!(r, Err(Errno::ERESTART))
        && ctx.proc.kq.register_waits.contains_key(&ctx.thread.tid);
    if c.flags & kflag::WORKLOOP != 0 && !sleeping {
        workq::release(ctx.proc, kq);
    }
    r
}

/// Registers a call's changes, writing error and receipt records.
/// `Ok(Some(n))` ends the call with `n` records (a registration that slept
/// and was interrupted before blocking); `Err(ERESTART)` with a
/// registration wait means the caller sleeps.
fn register_changes(
    ctx: &mut Ctx<'_>,
    kq: u64,
    c: &Call,
    flags: u32,
    noutputs: &mut usize,
    out_addr: &mut u64,
) -> Result<Option<usize>, Errno> {
    let rec = c.layout.size();
    let mut changes = c.changelist;
    let mut left = c.nchanges.max(0);
    while left > 0 {
        let b = ctx.read(changes, rec as usize)?;
        changes += rec;
        let mut kev = Kev::decode(&b, c.layout);
        let (_, wait) = register(ctx, kq, &mut kev);
        if let Some(knote) = wait {
            // Only the last change of an error-events workloop call may
            // sleep (f_post_register_wait).
            if left == 1
                && (*noutputs as i32) < c.nevents
                && flags & (kflag::KERNEL | kflag::PARKING) == 0
                && flags & kflag::ERROR_EVENTS != 0
                && flags & kflag::WORKLOOP != 0
            {
                let w = workloop::RegisterWait {
                    kev,
                    kq,
                    knote,
                    eventout: *noutputs as u32,
                    ueventlist: *out_addr,
                    call: ctx.nr,
                    awakened: false,
                };
                return workloop::post_register_wait(ctx, w).map(|n| Some(n as usize));
            }
            kev.flags |= ev::ERROR;
            kev.data = i64::from(Errno::ENOTSUP.0);
        }
        if (*noutputs as i32) < c.nevents && kev.flags & (ev::ERROR | ev::RECEIPT) != 0 {
            if kev.flags & ev::ERROR == 0 {
                kev.flags |= ev::ERROR;
                kev.data = 0;
            }
            ctx.write(*out_addr, &kev.encode(c.layout))?;
            *out_addr += rec;
            *noutputs += 1;
        } else if kev.flags & ev::ERROR != 0 {
            return Err(Errno(kev.data as i32));
        }
        left -= 1;
    }
    Ok(None)
}

fn kevent_body(ctx: &mut Ctx<'_>, kq: u64, c: &Call, data: &mut DataArea) -> Result<usize, Errno> {
    let mut flags = c.flags;
    // A file kqueue's wait restarts the call past its changes.
    let resumed = flags & kflag::KERNEL == 0 && ctx.thread.resume.is_some_and(|r| r.step == 1);
    let mut noutputs = 0usize;
    let mut out_addr = c.eventlist;
    let rec = c.layout.size();
    let modern_workloop = c.layout == Layout::Qos && flags & kflag::WORKLOOP != 0;
    if modern_workloop {
        if flags & kflag::KERNEL != 0 {
            // The workloop's ID, just below the event list.
            let id = workq::kqwl(ctx.proc, kq).map_or(0, |w| w.dynamic_id);
            ctx.write_u64(c.eventlist.wrapping_sub(8), id)?;
            data.resid = data.resid.saturating_sub(8);
        }
        if requesting_events(flags, c.nevents) {
            flags |= kflag::NEEDS_END_PROCESSING;
        }
    }
    if !resumed {
        let r = register_changes(ctx, kq, c, flags, &mut noutputs, &mut out_addr);
        if !matches!(r, Ok(None)) {
            if modern_workloop
                && flags & kflag::NEEDS_END_PROCESSING != 0
                && r.as_ref().is_err_and(|&e| e != Errno::ERESTART)
            {
                workq::workloop_end_processing(ctx.proc, kq, 0);
            }
            return r.map(|n| n.unwrap_or(0));
        }
    }
    if !requesting_events(flags, c.nevents) || noutputs != 0 {
        if modern_workloop && flags & kflag::NEEDS_END_PROCESSING != 0 {
            workq::workloop_end_processing(ctx.proc, kq, 0);
        }
        return Ok(noutputs);
    }
    let events = kqueue_process(ctx, kq, flags, c.nevents as usize, data);
    if !events.is_empty() {
        for e in &events {
            ctx.write(out_addr, &e.encode(c.layout))?;
            out_addr += rec;
        }
        return Ok(events.len());
    }
    let kind = ctx.proc.kq.kqueues.get(&kq).map(|q| q.kind);
    if flags & kflag::IMMEDIATE != 0 || kind != Some(KqKind::File) {
        return Ok(0);
    }
    // Wait for an event (THREAD_ABORTSAFE), the timeout, or a signal.
    let deadline = match ctx.thread.resume.filter(|_| resumed) {
        Some(r) => r.deadline,
        None => c.timeout.map(|d| Instant::now() + d),
    };
    if deadline.is_some_and(|d| d <= Instant::now()) {
        return Ok(0);
    }
    if crate::user::darwin::signal::sleep_interruption(ctx.proc, ctx.thread).is_some() {
        // kevent is not restarted after signals.
        ctx.thread.resume = None;
        return Err(Errno::EINTR);
    }
    let timer = next_timer(ctx.proc, kq);
    let wake_at = match (deadline, timer) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let fds = host::wait_fds(ctx.proc, kq);
    ctx.thread.resume = Some(Resume {
        pc: ctx.pc,
        call: ctx.nr,
        deadline,
        step: 1,
    });
    ctx.thread.wait = Some(Wait {
        keys: vec![WaitKey::Kqueue(kq)],
        fds,
        deadline: wake_at,
        interruptible: true,
        seq: crate::user::darwin::wait::next_seq(),
    });
    Err(Errno::ERESTART)
}

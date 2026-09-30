//! Polling (`io_uring/poll.c`, Linux 6.19): `IORING_OP_POLL_ADD`,
//! `IORING_OP_POLL_REMOVE`, the requests waiting for their files
//! (`io_arm_poll_handler`), the poll table they share (`cancel_table`),
//! which `/proc/<pid>/fdinfo` lists, and its part in cancellations.
//!
//! Nothing wakes an entry here as a file's wait queue does: the process's
//! rings with entries are noted, and the entries looked at as each system
//! call of the process begins and ends ([`task`](super::task); a call that
//! sleeps also wakes for their files). An entry whose file then reports an
//! event it waits for is woken: its task work is queued (`io_poll_wake`), which an ordinary ring
//! runs at once, as on the return to user mode after a wake-up, and a
//! deferring ring in its next wait. A one-shot entry wakes while its file
//! reports the event; a multishot poll, which is edge-triggered, when a
//! wanted event appears or the file's level (bytes queued, a counter)
//! grows, which stands for the wake-up each such change causes.
//!
//! The task work (`io_poll_task_func`) polls the file again: a request
//! waiting to be retried is issued again, a one-shot poll completes with
//! the events, and a multishot poll posts them with `IORING_CQE_F_MORE` and
//! stays. A wake-up of io_uring's own (the CQ of a ring polled through its
//! descriptor, or an eventfd a ring signals: `EPOLL_URING_WAKE`) takes a
//! poll off its file's wait queue, so a multishot poll reports once more
//! and then no more.

use std::cmp::Reverse;
use std::fmt::Write as _;
use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::anon::Anon;
use super::super::super::fs::epoll::{EPOLLET, EPOLLEXCLUSIVE, EPOLLONESHOT};
use super::super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::super::uring::abi::cqe_flags;
use super::super::super::uring::{Chain, Poll, Req, Ring, State, Work, req_flags as rf};
use super::super::Ctx;
use super::super::ready::{Polled, ev, poll_files};
use super::cancel::{self, Match};
use super::ops::{Done, assign_file};
use super::{submit, task, timeout};

/// `IORING_POLL_*`: a poll request's `len`.
const ADD_MULTI: u32 = 1 << 0;
const UPDATE_EVENTS: u32 = 1 << 1;
const UPDATE_USER_DATA: u32 = 1 << 2;
const ADD_LEVEL: u32 = 1 << 3;

/// `IO_POLL_UNMASK`: the events every poll waits for.
const UNMASK: u32 = ev::ERR | ev::HUP | ev::NVAL | ev::RDHUP;

/// The poll events proper, as `mangle_poll` reports them.
const EVENTS: u32 = 0xffff;

/// A poll armed on its file ([`Done::Poll`]): the events it waits for,
/// what the file reported, and whether it is ready already, which queues
/// its task work at once (a multishot poll's first report).
#[derive(Clone, Debug)]
pub(super) struct Arm {
    file: Arc<OpenFile>,
    events: u32,
    now: Polled,
    execute: bool,
}

/// What `__io_arm_poll_handler` did.
enum Armed {
    /// Ready now: the events (`ipt.result_mask`).
    Now(u32),
    /// Refused: the file has no wait queue and is not ready (`EINVAL`).
    Refused,
    /// Waiting on the file.
    Waiting(Arm),
}

/// `file_can_poll`: the file has a `poll` operation, which queues its
/// pollers on a wait queue; regular files, directories, and `/proc`'s
/// synthesized files have none.
fn can_poll(file: &OpenFile) -> bool {
    match &file.object {
        FileObject::Host(_) => !matches!(file.ftype, FileType::Regular | FileType::Directory),
        FileObject::Synthetic(_) | FileObject::PathOnly | FileObject::Console { .. } => false,
        _ => true,
    }
}

/// What the file reports now.
fn look(c: &Ctx<'_>, file: &OpenFile, events: u32) -> Polled {
    poll_files(c, &[(file, events)]).0[0]
}

/// The io_uring signals an eventfd counted.
fn uring_signals(file: &OpenFile) -> u64 {
    match &file.object {
        FileObject::Anon(Anon::Event(e)) => e.uring_signals(),
        _ => 0,
    }
}

/// `io_poll_parse_events`: one-shot unless `IORING_POLL_ADD_MULTI`,
/// edge-triggered unless `IORING_POLL_ADD_LEVEL`, and of the high bits
/// only those. (`demangle_poll` changes no bit on the architectures
/// modelled.)
fn parse_events(events: u32, flags: u32) -> u32 {
    let mut events = events;
    if flags & ADD_MULTI == 0 {
        events |= EPOLLONESHOT;
    }
    if flags & ADD_LEVEL == 0 {
        events |= EPOLLET;
    }
    events & EVENTS | events & (EPOLLEXCLUSIVE | EPOLLONESHOT | EPOLLET)
}

/// `__io_arm_poll_handler` for a poll request: a file without a wait
/// queue reports at once or never (`EINVAL`); a ready one-shot poll
/// completes at once; any other waits, its task work queued already if it
/// is ready.
fn arm_handler(c: &Ctx<'_>, file: Arc<OpenFile>, events: u32) -> Armed {
    let events = events | UNMASK;
    let now = look(c, &file, events);
    let mask = now.mask & events;
    if !can_poll(&file) {
        return if mask != 0 && events & EPOLLET != 0 {
            Armed::Now(mask)
        } else {
            Armed::Refused
        };
    }
    if mask != 0 && events & (EPOLLET | EPOLLONESHOT) == EPOLLET | EPOLLONESHOT {
        return Armed::Now(mask);
    }
    Armed::Waiting(Arm {
        file,
        events,
        now,
        execute: mask != 0 && events & EPOLLET != 0,
    })
}

/// `io_poll_add_prep`: no buffer, offset, or address (`EINVAL`); of the
/// flags only `IORING_POLL_ADD_MULTI`, which a request that skips its
/// successful CQE may not use; the events.
pub(super) fn add_prep(req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.buf_index != 0 || sqe.off != 0 || sqe.addr != 0 {
        return Err(Errno(EINVAL));
    }
    if sqe.len & !ADD_MULTI != 0 {
        return Err(Errno(EINVAL));
    }
    if sqe.len & ADD_MULTI != 0 && req.flags & rf::CQE_SKIP != 0 {
        return Err(Errno(EINVAL));
    }
    req.how[0] = u64::from(parse_events(sqe.op_flags, sqe.len));
    Ok(())
}

/// `io_poll_add`: the events the file reports now, or the request waits
/// for them in the poll table.
pub(super) fn add_issue(c: &Ctx<'_>, st: &mut State, req: &mut Req) -> Done {
    let file = match assign_file(c, st, req) {
        Ok(f) => f,
        Err(Errno(e)) => {
            req.fail(-e);
            return Done::Inline;
        }
    };
    match arm_handler(c, file, req.how[0] as u32) {
        Armed::Now(mask) => {
            req.res = mask as i32;
            req.cflags = 0;
            Done::Inline
        }
        Armed::Refused => {
            req.fail(-EINVAL);
            Done::Inline
        }
        Armed::Waiting(arm) => Done::Poll(arm),
    }
}

/// `io_poll_remove_prep`: no buffer or file slot (`EINVAL`); the flags
/// (`IORING_POLL_UPDATE_EVENTS`, `_UPDATE_USER_DATA`, and `_ADD_MULTI`,
/// which alone means nothing); a new user data only to update it, and
/// events only to update them.
pub(super) fn remove_prep(req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.buf_index != 0 || sqe.file_index != 0 {
        return Err(Errno(EINVAL));
    }
    let flags = sqe.len;
    if flags & !(UPDATE_EVENTS | UPDATE_USER_DATA | ADD_MULTI) != 0 || flags == ADD_MULTI {
        return Err(Errno(EINVAL));
    }
    if flags & UPDATE_USER_DATA == 0 && sqe.off != 0 {
        return Err(Errno(EINVAL));
    }
    let events = if flags & UPDATE_EVENTS != 0 {
        parse_events(sqe.op_flags, flags)
    } else if sqe.op_flags != 0 {
        return Err(Errno(EINVAL));
    } else {
        0
    };
    req.how = [sqe.addr, sqe.off, u64::from(flags), u64::from(events)];
    Ok(())
}

/// `io_poll_remove`: completes with 0, or fails with the error of
/// [`remove`].
pub(super) fn remove_issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) -> Done {
    match remove(c, ring, st, req.how) {
        Ok(()) => {
            req.res = 0;
            req.cflags = 0;
        }
        Err(Errno(e)) => req.fail(-e),
    }
    Done::Inline
}

/// The newest poll request for `user_data` (`io_poll_find`, `poll_only`)
/// leaves the table (`ENOENT` if there is none, `EALREADY` while its task
/// work is queued: `io_poll_disarm`). Updated (only the 16 event bits, the
/// behaviour ones kept; the user data), it is armed again; otherwise, or
/// if it cannot be, it completes with `-ECANCELED`. Either completion is
/// task work.
fn remove(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, how: [u64; 4]) -> Result<(), Errno> {
    let [old, new, flags, events] = how;
    let (flags, events) = (flags as u32, events as u32);
    let pos = find(st, old, true).ok_or(Errno(ENOENT))?;
    if st.polls[pos].queued {
        return Err(Errno(EALREADY));
    }
    let mut p = st.polls.remove(pos);
    let mut res = -ECANCELED;
    if flags & (UPDATE_EVENTS | UPDATE_USER_DATA) != 0 {
        if flags & UPDATE_EVENTS != 0 {
            p.events = p.events & !EVENTS | events & EVENTS | UNMASK;
        }
        if flags & UPDATE_USER_DATA != 0 {
            p.chain[0].sqe.user_data = new;
            timeout::relink(st, &p.chain[0]);
        }
        match arm_handler(c, p.file.clone(), p.events) {
            Armed::Waiting(armed) => {
                arm(c, ring, st, p.chain, armed);
                return Ok(());
            }
            Armed::Now(mask) => res = mask as i32,
            Armed::Refused => {}
        }
    }
    let head = &mut p.chain[0];
    head.res = res;
    head.cflags = 0;
    if res < 0 {
        head.set_fail();
    }
    st.task_work.push_back(Work::Complete(p.chain));
    Ok(())
}

/// The newest entry whose request has `user_data` (a poll request, with
/// `poll_only`): the first of its hash bucket.
fn find(st: &State, user_data: u64, poll_only: bool) -> Option<usize> {
    st.polls
        .iter()
        .enumerate()
        .filter(|(_, p)| p.chain[0].sqe.user_data == user_data && !(poll_only && p.retry))
        .max_by_key(|(_, p)| p.id)
        .map(|(i, _)| i)
}

/// Adds an entry to the table.
fn insert(
    st: &mut State,
    chain: Chain,
    file: Arc<OpenFile>,
    events: u32,
    retry: bool,
    now: Polled,
) -> u64 {
    let id = st.next_poll;
    st.next_poll += 1;
    let uring_seen = uring_signals(&file);
    st.polls.push(Poll {
        id,
        chain,
        file,
        events,
        retry,
        seen: now,
        uring_seen,
        queued: false,
        cancelled: false,
        detached: false,
    });
    id
}

/// `io_poll_add_hash`: an armed poll request joins the table, its task
/// work queued at once if it is ready (`__io_poll_execute`).
pub(super) fn arm(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, chain: Chain, arm: Arm) {
    let id = insert(st, chain, arm.file, arm.events, false, arm.now);
    if arm.execute {
        queue(st, id);
    }
    task::note(c, ring);
}

/// `io_arm_poll_handler`: `chain`, whose head `file` cannot serve now,
/// waits for an event of `mask` (or `EPOLLPRI`, an error, or a hang-up),
/// edge-triggered, to be issued again: once, or for a multishot request
/// (`REQ_F_APOLL_MULTISHOT`) each time the file reports it anew.
pub(super) fn park(
    c: &mut Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    mut chain: Chain,
    file: Arc<OpenFile>,
    mask: u32,
) {
    let head = &mut chain[0];
    head.flags |= rf::POLLED;
    let oneshot = if head.flags & rf::APOLL_MULTISHOT == 0 {
        EPOLLONESHOT
    } else {
        0
    };
    let events = mask | ev::PRI | ev::ERR | UNMASK | EPOLLET | oneshot;
    insert(st, chain, file, events, true, Polled::default());
    task::note(c, ring);
}

/// A multishot request's entry, issued again and still waiting, goes back
/// to the table under its key, its file's state noted as it is now.
pub(super) fn rearm(c: &Ctx<'_>, st: &mut State, mut p: Poll) {
    p.seen = look(c, &p.file, p.events);
    p.queued = false;
    st.polls.push(p);
}

/// `__io_poll_execute` without a wake-up: the entry's task work, queued.
pub(super) fn requeue(st: &mut State, id: u64) {
    queue(st, id);
}

/// Whether the file reports an event [`park`] would wait for with `mask`.
pub(super) fn ready(c: &Ctx<'_>, file: &OpenFile, mask: u32) -> bool {
    let events = mask | ev::PRI | ev::ERR | UNMASK;
    look(c, file, events).mask & events != 0
}

/// Whether the file has a wait queue to poll on ([`can_poll`]).
pub(super) fn pollable(file: &OpenFile) -> bool {
    can_poll(file)
}

/// Queues an entry's task work (it takes `poll_refs`).
fn queue(st: &mut State, id: u64) {
    if let Some(p) = st.polls.iter_mut().find(|p| p.id == id) {
        p.queued = true;
        st.task_work.push_back(Work::Poll(id));
    }
}

/// `io_poll_wake`: the entries whose files report what they wait for (a
/// multishot poll: newly) are woken, the newest first, as a wait queue
/// wakes the pollers `add_wait_queue` put at its head; a wake-up of
/// io_uring's own takes the entry off its wait queue.
pub(super) fn wake(c: &Ctx<'_>, st: &mut State) {
    let mut woken = Vec::new();
    for p in st.polls.iter_mut().rev() {
        if p.queued || p.detached {
            continue;
        }
        let now = look(c, &p.file, p.events);
        let wanted = now.mask & p.events;
        let fire = if p.events & EPOLLONESHOT != 0 {
            wanted != 0
        } else {
            wanted != 0 && (wanted & !p.seen.mask != 0 || now.level > p.seen.level)
        };
        p.seen = now;
        let signals = uring_signals(&p.file);
        let by_uring =
            matches!(p.file.object, FileObject::Anon(Anon::Uring(_))) || signals != p.uring_seen;
        p.uring_seen = signals;
        if fire {
            p.detached |= by_uring;
            woken.push(p.id);
        }
    }
    for id in woken {
        queue(st, id);
    }
}

/// What a poll's task work leads to ([`task`]).
pub(super) enum Fired {
    /// The chain completes, its head's result set.
    Complete(Chain),
    /// Its head is issued again (`io_req_task_submit`).
    Issue(Chain),
    /// A multishot request's issue in place (`io_poll_issue`): the key of
    /// its entry.
    Reissue(u64),
}

/// `io_poll_task_func` for entry `id`: a cancelled entry completes with
/// `-ECANCELED`; otherwise the file is polled again. A multishot poll with
/// nothing to report waits on, and posts what there is otherwise with
/// `IORING_CQE_F_MORE` (`io_req_post_cqe`; without room in the ring it
/// completes with it instead); a one-shot entry leaves the table, a retry
/// to be issued again, a poll to complete with its events or, with none
/// left, to be issued again (`IOU_POLL_REISSUE`).
pub(super) fn task(c: &Ctx<'_>, ring: &Ring, st: &mut State, id: u64) -> Option<Fired> {
    let pos = st.polls.iter().position(|p| p.id == id)?;
    let p = &mut st.polls[pos];
    p.queued = false;
    if p.cancelled {
        let mut p = st.polls.remove(pos);
        p.chain[0].defer_failed(-ECANCELED);
        return Some(Fired::Complete(p.chain));
    }
    let now = look(c, &p.file, p.events);
    p.seen = now;
    let mask = now.mask & p.events;
    if p.events & EPOLLONESHOT == 0 {
        if mask == 0 {
            return None;
        }
        if p.retry {
            return Some(Fired::Reissue(id));
        }
        let (user_data, res) = (p.chain[0].sqe.user_data, (mask & EVENTS) as i32);
        if submit::post_cqe(ring, st, user_data, res, cqe_flags::MORE) {
            return None;
        }
        // IOU_POLL_REMOVE_POLL_USE_RES.
        let pos = st.polls.iter().position(|p| p.id == id)?;
        let mut p = st.polls.remove(pos);
        p.chain[0].res = res;
        p.chain[0].cflags = 0;
        return Some(Fired::Complete(p.chain));
    }
    let mut p = st.polls.remove(pos);
    if p.retry || mask == 0 {
        return Some(Fired::Issue(p.chain));
    }
    let head = &mut p.chain[0];
    head.res = (mask & EVENTS) as i32;
    head.cflags = 0;
    Some(Fired::Complete(p.chain))
}

/// The table in its order: by hash bucket of the user data
/// (`hash_long(user_data, hash_bits)`: `hash_64`'s golden-ratio multiply,
/// with `hash_bits` the CQ's `ilog2` less 5, from 1 to 8), the newest
/// first in each (`hlist_add_head`).
pub(super) fn table_order(ring: &Ring, st: &State) -> Vec<usize> {
    let bits = (ring.cq_entries.ilog2() as i32 - 5).clamp(1, 8) as u32;
    let bucket = |data: u64| data.wrapping_mul(0x61c8_8646_80b5_83eb) >> (64 - bits);
    let mut order: Vec<usize> = (0..st.polls.len()).collect();
    order.sort_by_key(|&i| {
        let p = &st.polls[i];
        (bucket(p.chain[0].sqe.user_data), Reverse(p.id))
    });
    order
}

/// fdinfo's `PollList`: each entry's operation, and whether the task has
/// task work pending, which it never has as a call reads the file.
pub(super) fn poll_list(ring: &Ring, st: &State) -> String {
    let mut s = String::new();
    for i in table_order(ring, st) {
        let _ = writeln!(s, "  op={}, task_works=0", st.polls[i].chain[0].sqe.opcode);
    }
    s
}

/// `io_poll_cancel`: by file, operation, or any, the first entry of the
/// table in its order `cd` matches (`io_poll_file_find`), and otherwise the
/// newest with the user data (`io_poll_find`; with
/// `IORING_ASYNC_CANCEL_ALL`, not one this pass matched), is cancelled: its
/// task work, queued now if it is not already, completes it with
/// `-ECANCELED` (`io_poll_cancel_req`). `ENOENT` if there is none.
pub(super) fn cancel(ring: &Ring, st: &mut State, cd: &Match) -> Result<(), Errno> {
    let pos = if cd.by_file_or_op() {
        table_order(ring, st).into_iter().find(|&i| {
            let p = &mut st.polls[i];
            cancel::matches(&mut p.chain[0], Some(&p.file), cd)
        })
    } else {
        let mut order: Vec<usize> = (0..st.polls.len())
            .filter(|&i| st.polls[i].chain[0].sqe.user_data == cd.data)
            .collect();
        order.sort_by_key(|&i| Reverse(st.polls[i].id));
        order
            .into_iter()
            .find(|&i| !cd.all() || !cancel::seen(&mut st.polls[i].chain[0], cd.seq))
    };
    let p = &mut st.polls[pos.ok_or(Errno(ENOENT))?];
    p.cancelled = true;
    if !p.queued {
        let id = p.id;
        queue(st, id);
    }
    Ok(())
}

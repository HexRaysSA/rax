//! Timeouts (`io_uring/timeout.c`, Linux 6.19): `IORING_OP_TIMEOUT`,
//! `IORING_OP_TIMEOUT_REMOVE` (a removal or an update), and
//! `IORING_OP_LINK_TIMEOUT`.
//!
//! A timeout joins the ring's list and expires at its time, completing
//! with `-ETIME` (failed, so its link with it, unless
//! `IORING_TIMEOUT_ETIME_SUCCESS`); one that counts completions (`off`)
//! completes with 0 once that many other CQEs were posted after it was
//! issued, as each commit of the CQ looks (`io_flush_timeouts`). A
//! multishot timeout reports each expiry with `IORING_CQE_F_MORE` and is
//! armed again, `off` times or for ever. Nothing fires here as the
//! kernel's timers do: expired timers are looked for where the poll
//! table's wake-ups are (as each system call of the process begins and
//! ends), and a sleeping call also wakes at the next one.
//!
//! A linked timeout bounds the request before it in its link. It is armed
//! as that request is issued, which takes it out of the link; completing
//! first, the request cancels it (`-ECANCELED`); expiring first, it
//! cancels the request by its user data (`io_try_cancel`), and completes
//! with `-ETIME` if that worked or the cancellation's error if not.

use std::time::{Duration, Instant};

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::posix_timers::{Base, clock_now};
use super::super::super::uring::abi::op;
use super::super::super::uring::{
    Chain, LinkTimeout, Req, Ring, State, Timeout, Timer, Work, req_flags as rf,
};
use super::super::Ctx;
use super::cancel::Match;
use super::{cancel, task};

/// `IORING_TIMEOUT_*`.
const ABS: u32 = 1 << 0;
const UPDATE: u32 = 1 << 1;
const BOOTTIME: u32 = 1 << 2;
const REALTIME: u32 = 1 << 3;
const LINK_UPDATE: u32 = 1 << 4;
const ETIME_SUCCESS: u32 = 1 << 5;
const MULTISHOT: u32 = 1 << 6;
const CLOCK_MASK: u32 = BOOTTIME | REALTIME;
const UPDATE_MASK: u32 = UPDATE | LINK_UPDATE;

/// `KTIME_SEC_MAX`: the seconds past which a time is `KTIME_MAX`.
const KTIME_SEC_MAX: i64 = i64::MAX / 1_000_000_000;

/// `get_timespec64` at `addr` (`EFAULT`), a negative field refused
/// (`EINVAL`), as `timespec64_to_ktime` nanoseconds.
fn read_time(c: &Ctx<'_>, addr: u64) -> Result<i64, Errno> {
    let t = c.get_timespec(addr)?;
    if t.sec < 0 || t.nsec < 0 {
        return Err(Errno(EINVAL));
    }
    Ok(if t.sec >= KTIME_SEC_MAX {
        i64::MAX
    } else {
        (t.sec * 1_000_000_000).wrapping_add(t.nsec)
    })
}

/// When a timer of clock `flags` started now for `ns` expires: after `ns`,
/// or (`abs`) at `ns` on the clock (`CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`,
/// or `CLOCK_REALTIME`: `io_timeout_get_clock`).
fn deadline(flags: u32, ns: i64, abs: bool) -> Instant {
    let left = if abs {
        let base = if flags & REALTIME != 0 {
            Base::Realtime
        } else {
            Base::Monotonic
        };
        ns.saturating_sub(clock_now(base))
    } else {
        ns
    };
    let now = Instant::now();
    let wait = Duration::from_nanos(left.max(0) as u64);
    now.checked_add(wait)
        .unwrap_or(now + Duration::from_secs(1 << 32))
}

/// `io_is_timeout_noseq`: a timeout that counts no completions (or is
/// multishot).
fn noseq(t: &Timer) -> bool {
    t.off == 0 || t.flags & MULTISHOT != 0
}

/// `__io_timeout_prep`: no buffer or file slot, a count of 1 (`EINVAL`);
/// a linked timeout counts no completions; known flags, one clock, and
/// no absolute multishot timeout (`EINVAL`); the time (`EFAULT`, and
/// `EINVAL` if negative). A multishot timeout that counts expires that
/// many times. (Whether a linked timeout follows a request is
/// [`link_prep`]'s.)
pub(super) fn prep(c: &Ctx<'_>, req: &mut Req, link: bool) -> Result<(), Errno> {
    let sqe = req.sqe;
    if sqe.buf_index != 0 || sqe.len != 1 || sqe.file_index != 0 {
        return Err(Errno(EINVAL));
    }
    let off = sqe.off as u32;
    if off != 0 && link {
        return Err(Errno(EINVAL));
    }
    let flags = sqe.op_flags;
    if flags & !(ABS | CLOCK_MASK | ETIME_SUCCESS | MULTISHOT) != 0
        || (flags & CLOCK_MASK).count_ones() > 1
        || flags & (MULTISHOT | ABS) == MULTISHOT | ABS
    {
        return Err(Errno(EINVAL));
    }
    let ns = read_time(c, sqe.addr)?;
    req.timer = Timer {
        flags,
        ns,
        off,
        target_seq: 0,
        repeats: if flags & MULTISHOT != 0 { off } else { 0 },
    };
    Ok(())
}

/// The end of `io_link_timeout_prep`: the linked timeout follows a request
/// of the link being assembled that is not one itself (`EINVAL`), which
/// arms it as it is issued (`REQ_F_ARM_LTIMEOUT`).
pub(super) fn link_prep(link: &mut Option<Chain>) -> Result<(), Errno> {
    let last = link
        .as_mut()
        .and_then(|l| l.back_mut())
        .ok_or(Errno(EINVAL))?;
    if last.sqe.opcode == op::LINK_TIMEOUT {
        return Err(Errno(EINVAL));
    }
    last.flags |= rf::ARM_LTIMEOUT;
    Ok(())
}

/// `io_timeout`: the chain the timeout heads joins the list, at its end if
/// it counts no completions, else ahead of those that wait for more (its
/// target the sequence now plus its count); its timer starts.
pub(super) fn arm(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, mut chain: Chain) {
    let t = chain[0].timer;
    let at = if noseq(&t) {
        st.timeouts.len()
    } else {
        st.off_timeout_used = true;
        let tail = st.cached_cq_tail.wrapping_sub(st.cq_timeouts);
        chain[0].timer.target_seq = tail.wrapping_add(t.off);
        st.cq_last_tm_flush = tail;
        st.timeouts
            .iter()
            .rposition(|x| {
                let xt = &x.chain[0].timer;
                !noseq(xt) && t.off >= xt.target_seq.wrapping_sub(tail)
            })
            .map_or(0, |i| i + 1)
    };
    let key = st.next_timer;
    st.next_timer += 1;
    st.timeouts.insert(
        at,
        Timeout {
            key,
            chain,
            deadline: deadline(t.flags, t.ns, t.flags & ABS != 0),
        },
    );
    task::note(c, ring);
}

/// `io_flush_timeouts`, as a commit of the CQ runs it once a timeout counts
/// completions: those whose count the CQEs posted since (less the
/// timeouts' own) reached, from the list's front, complete with 0.
pub(super) fn flush(st: &mut State) {
    let seq = st.cached_cq_tail.wrapping_sub(st.cq_timeouts);
    while let Some(first) = st.timeouts.first() {
        let t = &first.chain[0].timer;
        if noseq(t) {
            break;
        }
        let needed = t.target_seq.wrapping_sub(st.cq_last_tm_flush);
        let got = seq.wrapping_sub(st.cq_last_tm_flush);
        if got < needed {
            break;
        }
        st.cq_timeouts = st.cq_timeouts.wrapping_add(1);
        let mut chain = st.timeouts.remove(0).chain;
        chain[0].res = 0;
        chain[0].cflags = 0;
        st.task_work.push_back(Work::Complete(chain));
    }
    st.cq_last_tm_flush = seq;
}

/// The timers that expired by now, in the order they did: a timeout
/// leaves the list (`io_timeout_fn`: counted in `cq_timeouts`, `-ETIME`,
/// failed unless `IORING_TIMEOUT_ETIME_SUCCESS`), a linked timeout its own
/// (`io_link_timeout_fn`); each runs as task work.
pub(super) fn fire(st: &mut State) {
    let now = Instant::now();
    let mut due: Vec<(Instant, bool, u64)> = st
        .timeouts
        .iter()
        .filter(|t| t.deadline <= now)
        .map(|t| (t.deadline, false, t.key))
        .chain(
            st.ltimeouts
                .iter()
                .filter(|t| t.deadline <= now)
                .map(|t| (t.deadline, true, t.key)),
        )
        .collect();
    due.sort_by_key(|&(at, _, key)| (at, key));
    for (_, linked, key) in due {
        if linked {
            let pos = st.ltimeouts.iter().position(|t| t.key == key).unwrap();
            let lt = st.ltimeouts.remove(pos);
            st.task_work
                .push_back(Work::LinkTimeout(Box::new(lt.req), lt.prev));
        } else {
            let pos = st.timeouts.iter().position(|t| t.key == key).unwrap();
            let mut chain = st.timeouts.remove(pos).chain;
            st.cq_timeouts = st.cq_timeouts.wrapping_add(1);
            let head = &mut chain[0];
            if head.timer.flags & ETIME_SUCCESS == 0 {
                head.set_fail();
            }
            head.res = -ETIME;
            head.cflags = 0;
            st.task_work.push_back(Work::Timeout(chain));
        }
    }
}

/// When the next timer expires.
pub(super) fn next(st: &State) -> Option<Instant> {
    let a = st.timeouts.iter().map(|t| t.deadline);
    a.chain(st.ltimeouts.iter().map(|t| t.deadline)).min()
}

/// What an expired timeout's task work leads to ([`expired`]).
pub(super) enum Expired {
    /// A multishot timeout's report, with the user data (armed again).
    Again(u64),
    /// The chain completes.
    Done(Chain),
}

/// `io_timeout_complete`: a multishot timeout with expiries left (or no
/// count) reports and is armed again at the list's end, relative to now;
/// any other completes.
pub(super) fn expired(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, mut chain: Chain) -> Expired {
    let t = &mut chain[0].timer;
    let finish = if t.flags & MULTISHOT == 0 {
        true
    } else if t.off == 0 {
        false
    } else if t.repeats != 0 {
        t.repeats -= 1;
        t.repeats == 0
    } else {
        true
    };
    if finish {
        return Expired::Done(chain);
    }
    let (flags, ns) = (t.flags, t.ns);
    let user_data = chain[0].sqe.user_data;
    let key = st.next_timer;
    st.next_timer += 1;
    st.timeouts.push(Timeout {
        key,
        chain,
        deadline: deadline(flags, ns, false),
    });
    task::note(c, ring);
    Expired::Again(user_data)
}

/// `__io_prep_linked_timeout` as a chain's head is issued: its linked
/// timeout is to be armed.
pub(super) fn prep_linked(chain: &mut Chain) -> bool {
    let head = &mut chain[0];
    if head.flags & rf::ARM_LTIMEOUT == 0 {
        return false;
    }
    head.flags &= !rf::ARM_LTIMEOUT;
    head.flags |= rf::LINK_TIMEOUT;
    true
}

/// `io_queue_linked_timeout` once the head was issued: the linked timeout
/// (the head's next request) leaves the chain for the list of armed ones,
/// its timer started, the head keeping its key.
pub(super) fn queue_linked(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, chain: &mut Chain) {
    if chain
        .get(1)
        .is_none_or(|r| r.sqe.opcode != op::LINK_TIMEOUT)
    {
        return;
    }
    let lt = chain.remove(1).expect("the linked timeout");
    let key = st.next_timer;
    st.next_timer += 1;
    chain[0].ltimeout = key;
    let t = lt.timer;
    st.ltimeouts.push(LinkTimeout {
        key,
        prev: chain[0].sqe.user_data,
        deadline: deadline(t.flags, t.ns, t.flags & ABS != 0),
        req: lt,
    });
    task::note(c, ring);
}

/// `io_disarm_next` for a completed head: its linked timeout, taken out of
/// the chain (never armed) or off the list (armed and not expired),
/// completes with `-ECANCELED`, through task work.
pub(super) fn disarm(st: &mut State, head: &mut Req, rest: &mut Chain) -> Option<Req> {
    let mut lt = if head.flags & rf::ARM_LTIMEOUT != 0 {
        head.flags &= !rf::ARM_LTIMEOUT;
        if rest
            .front()
            .is_none_or(|r| r.sqe.opcode != op::LINK_TIMEOUT)
        {
            return None;
        }
        rest.pop_front()?
    } else if head.flags & rf::LINK_TIMEOUT != 0 {
        head.flags &= !rf::LINK_TIMEOUT;
        let pos = st.ltimeouts.iter().position(|t| t.key == head.ltimeout)?;
        st.ltimeouts.remove(pos).req
    } else {
        return None;
    };
    lt.res = -ECANCELED;
    lt.cflags = 0;
    Some(lt)
}

/// `io_req_task_link_timeout`: the request the linked timeout bounded is
/// cancelled by its user data; the timeout completes with `-ETIME` if
/// that worked, the cancellation's error if not.
pub(super) fn link_expired(ring: &Ring, st: &mut State, mut lt: Req, prev: u64) -> Req {
    let r = cancel::try_cancel(ring, st, &Match::user_data(prev));
    lt.res = match r {
        Ok(()) => -ETIME,
        Err(Errno(e)) => -e,
    };
    lt.cflags = 0;
    lt
}

/// A new user data of a head whose linked timeout is armed (a poll
/// request's update): the timeout cancels by it.
pub(super) fn relink(st: &mut State, head: &Req) {
    if head.flags & rf::LINK_TIMEOUT != 0
        && let Some(lt) = st.ltimeouts.iter_mut().find(|t| t.key == head.ltimeout)
    {
        lt.prev = head.sqe.user_data;
    }
}

/// `io_timeout_cancel` (`io_timeout_extract`): the first timeout on the
/// list that `cd` matches leaves it and fails with `-ECANCELED`, through
/// task work (`ENOENT` if none does).
pub(super) fn cancel(st: &mut State, cd: &Match) -> Result<(), Errno> {
    let pos = st
        .timeouts
        .iter_mut()
        .position(|t| cancel::matches(&mut t.chain[0], None, cd))
        .ok_or(Errno(ENOENT))?;
    let mut chain = st.timeouts.remove(pos).chain;
    chain[0].fail(-ECANCELED);
    st.task_work.push_back(Work::Complete(chain));
    Ok(())
}

/// `io_timeout_remove_prep`: no registered file, buffer, count, or file
/// slot (`EINVAL`); the user data at `addr`; an update's flags (one clock
/// at most, and only the update flags and `IORING_TIMEOUT_ABS`) and time
/// at `addr2` (`EFAULT`, `EINVAL` if negative); a removal's none.
pub(super) fn remove_prep(c: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    let sqe = req.sqe;
    if req.flags & rf::FIXED_FILE != 0 || sqe.buf_index != 0 || sqe.len != 0 || sqe.file_index != 0
    {
        return Err(Errno(EINVAL));
    }
    let flags = sqe.op_flags;
    let mut ns = 0;
    if flags & UPDATE_MASK != 0 {
        if (flags & CLOCK_MASK).count_ones() > 1 || flags & !(UPDATE_MASK | ABS) != 0 {
            return Err(Errno(EINVAL));
        }
        ns = read_time(c, sqe.off)?;
    } else if flags != 0 {
        return Err(Errno(EINVAL));
    }
    req.how = [sqe.addr, u64::from(flags), ns as u64, 0];
    Ok(())
}

/// `io_timeout_remove`: without `IORING_TIMEOUT_UPDATE`, the timeout with
/// the user data is cancelled; with it, the linked timeout
/// (`IORING_LINK_TIMEOUT_UPDATE`) or the timeout with the user data
/// restarts with the new time (a timeout then counts no completions and
/// goes to the list's end). `ENOENT` if there is none; the request fails
/// with an error.
pub(super) fn remove_issue(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) {
    let [user_data, flags, ns, _] = req.how;
    let (flags, ns) = (flags as u32, ns as i64);
    let r = if flags & UPDATE == 0 {
        cancel(st, &Match::user_data(user_data))
    } else if flags & LINK_UPDATE != 0 {
        match st
            .ltimeouts
            .iter_mut()
            .find(|t| t.req.sqe.user_data == user_data)
        {
            Some(lt) => {
                lt.deadline = deadline(lt.req.timer.flags, ns, flags & ABS != 0);
                Ok(())
            }
            None => Err(Errno(ENOENT)),
        }
    } else {
        update(c, ring, st, user_data, ns, flags & ABS != 0)
    };
    match r {
        Ok(()) => {
            req.res = 0;
            req.cflags = 0;
        }
        Err(Errno(e)) => req.fail(-e),
    }
}

/// `io_timeout_update`: the first timeout with the user data counts no
/// more completions, takes the new time (its clock kept), and restarts at
/// the list's end.
fn update(
    c: &mut Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    user_data: u64,
    ns: i64,
    abs: bool,
) -> Result<(), Errno> {
    let pos = st
        .timeouts
        .iter_mut()
        .position(|t| cancel::matches(&mut t.chain[0], None, &Match::user_data(user_data)))
        .ok_or(Errno(ENOENT))?;
    let mut t = st.timeouts.remove(pos);
    let timer = &mut t.chain[0].timer;
    timer.off = 0;
    timer.ns = ns;
    t.deadline = deadline(timer.flags, ns, abs);
    st.timeouts.push(t);
    task::note(c, ring);
    Ok(())
}

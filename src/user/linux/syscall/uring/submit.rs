//! Submission and completion (`io_uring/io_uring.c`, Linux 6.19): the SQEs
//! a call consumes, how their requests are checked (`io_init_req`), linked
//! (`io_submit_sqe`, `io_submit_fail_init`), drained (`io_drain_req`,
//! `io_queue_deferred`), issued, and completed (`io_req_complete_defer`,
//! `__io_submit_flush_completions`, `io_req_complete_post`).
//!
//! Requests issued inline complete into the submission's batch, whose CQEs
//! are posted in order when the batch is flushed; a link's next request,
//! and the cancellation of a failed link, are then task work, run as the
//! submitter returns to user mode (or, on an `IORING_SETUP_DEFER_TASKRUN`
//! ring, while it waits for completions). Requests punted to the async
//! workers (`IOSQE_ASYNC`, drains) run as a worker that picks them up at
//! once would: after the submission, a link continuing in the same worker,
//! each completion posted as it happens.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::anon::Anon;
use super::super::super::fs::fd::FileObject;
use super::super::super::uring::abi::{CQ_EVENTFD_DISABLED, OP_DEFS, op, rings, setup, sqe_flags};
use super::super::super::uring::{Chain, Req, Ring, State, Work, req_flags as rf};
use super::super::Ctx;
use super::super::ready::ev as ev_mask;
use super::ops::{self, Done};
use super::{poll, rsrc};

/// A submission's completed requests, flushed together (`compl_reqs`).
type Batch = Vec<Chain>;

/// `io_init_drain`: a drain in the middle of a link drains its head and
/// what follows the link.
fn init_drain(st: &mut State, link: &mut Option<Chain>) {
    st.drain_active = true;
    if let Some(head) = link.as_mut().and_then(|l| l.front_mut()) {
        head.flags |= rf::IO_DRAIN | rf::FORCE_ASYNC;
        st.drain_next = true;
    }
}

/// `io_init_req`: checks the request against its operation and the ring,
/// then prepares it; the error it fails with otherwise.
fn init(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    req: &mut Req,
    link: &mut Option<Chain>,
) -> Result<(), Errno> {
    let opcode = req.sqe.opcode;
    if opcode >= op::LAST {
        req.sqe.opcode = op::NOP;
        return Err(Errno(EINVAL));
    }
    let def = OP_DEFS[usize::from(opcode)];
    // A 128-byte operation needs a 128-byte (or mixed) SQ; mixed SQs are
    // not set up here.
    if def.is_128 && ring.flags & setup::SQE128 == 0 {
        return Err(Errno(EINVAL));
    }
    let flags = req.sqe.flags;
    if flags & !sqe_flags::COMMON != 0 {
        if flags & !sqe_flags::VALID != 0 {
            return Err(Errno(EINVAL));
        }
        if flags & sqe_flags::BUFFER_SELECT != 0 && !def.buffer_select {
            return Err(Errno(EOPNOTSUPP));
        }
        if flags & sqe_flags::CQE_SKIP_SUCCESS != 0 {
            st.drain_disabled = true;
        }
        if flags & sqe_flags::IO_DRAIN != 0 {
            if st.drain_disabled {
                return Err(Errno(EOPNOTSUPP));
            }
            init_drain(st, link);
        }
    }
    if st.drain_active {
        // Knocked to the slow path, drained there.
        req.flags |= rf::FORCE_ASYNC;
    }
    if st.drain_next && link.is_none() {
        st.drain_next = false;
        st.drain_active = true;
        req.flags |= rf::IO_DRAIN | rf::FORCE_ASYNC;
    }
    if !def.ioprio && req.sqe.ioprio != 0 {
        return Err(Errno(EINVAL));
    }
    if !def.iopoll && ring.flags & setup::IOPOLL != 0 {
        return Err(Errno(EINVAL));
    }
    if req.sqe.personality != 0 {
        if !st.personalities.contains_key(&req.sqe.personality) {
            return Err(Errno(EINVAL));
        }
        req.flags |= rf::CREDS;
    }
    ops::prep(c, ring, req)
}

/// `io_req_defer_failed`: completes a request that failed before issue,
/// with the result it failed with.
fn defer_failed(batch: &mut Batch, mut chain: Chain) {
    chain.front_mut().expect("a request").set_fail();
    batch.push(chain);
}

/// `io_queue_iowq`: to the async workers.
fn queue_iowq(st: &mut State, chain: Chain) {
    st.iowq.push_back(chain);
}

/// `io_queue_deferred`: drained chains whose turn came (every live request
/// is drained, or none before a drain is) become task work.
fn queue_deferred(st: &mut State) {
    let (mut drain_seen, mut first) = (false, true);
    while let Some(front) = st.defer.front() {
        drain_seen |= front[0].flags & rf::IO_DRAIN != 0;
        if (drain_seen || first) && st.live != st.drained {
            return;
        }
        let chain = st.defer.pop_front().expect("front");
        st.drained -= chain.len() as u64;
        st.task_work.push_back(Work::Issue(chain));
        first = false;
    }
}

/// `io_drain_req`.
fn drain_req(st: &mut State, chain: Chain) {
    let drain = chain[0].flags & rf::IO_DRAIN != 0;
    st.drained += chain.len() as u64;
    st.defer.push_back(chain);
    queue_deferred(st);
    if !drain && st.defer.is_empty() {
        st.drain_active = false;
    }
}

/// `io_queue_sqe_fallback`: a failed chain completes at once (its hard
/// links made soft, so the failure cancels the rest); others go to the
/// workers, through the drain if one is active.
fn queue_fallback(st: &mut State, batch: &mut Batch, mut chain: Chain) {
    let head = chain.front_mut().expect("a request");
    if head.flags & rf::FAIL != 0 {
        head.flags &= !rf::HARDLINK;
        head.flags |= rf::LINK;
        defer_failed(batch, chain);
    } else if st.drain_active {
        drain_req(st, chain);
    } else {
        queue_iowq(st, chain);
    }
}

/// `io_queue_sqe`: issues a chain's head inline; it completes into the
/// batch (`io_req_complete_defer`) or, if its operation says so, through
/// task work.
fn queue_sqe(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, batch: &mut Batch, mut chain: Chain) {
    match ops::issue(c, ring, st, &mut chain[0]) {
        Done::Inline => batch.push(chain),
        Done::TaskWork => st.task_work.push_back(Work::Complete(chain)),
        Done::Park(file, mask) => poll::park(c, ring, st, chain, file, mask),
    }
}

/// `io_submit_fail_init`: the request fails, and so does the link it
/// joins; a chain that ends here completes failed.
fn fail_init(
    st: &mut State,
    batch: &mut Batch,
    link: &mut Option<Chain>,
    mut req: Req,
    err: Errno,
) -> Result<(), Errno> {
    req.fail(-err.0);
    if let Some(head) = link.as_mut().and_then(|l| l.front_mut())
        && head.flags & rf::FAIL == 0
    {
        head.fail(-ECANCELED);
    }
    let links = req.flags & rf::LINKS != 0;
    match link.as_mut() {
        Some(l) => l.push_back(req),
        None => *link = Some(Chain::from([req])),
    }
    if !links {
        let chain = link.take().expect("assembled");
        queue_fallback(st, batch, chain);
        return Err(err);
    }
    Ok(())
}

/// `io_submit_sqe`: a checked request joins the link being assembled, or
/// starts one, or is queued; a finished link is queued from its head.
fn submit_one(
    c: &mut Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    batch: &mut Batch,
    link: &mut Option<Chain>,
    req: Req,
) {
    if let Some(l) = link.as_mut() {
        let links = req.flags & rf::LINKS != 0;
        l.push_back(req);
        if links {
            return;
        }
        let chain = link.take().expect("assembled");
        if chain[0].flags & (rf::FORCE_ASYNC | rf::FAIL) != 0 {
            queue_fallback(st, batch, chain);
        } else {
            queue_sqe(c, ring, st, batch, chain);
        }
    } else if req.flags & (rf::LINKS | rf::FORCE_ASYNC | rf::FAIL) != 0 {
        if req.flags & rf::LINKS != 0 {
            *link = Some(Chain::from([req]));
        } else {
            queue_fallback(st, batch, Chain::from([req]));
        }
    } else {
        queue_sqe(c, ring, st, batch, Chain::from([req]));
    }
}

/// `io_submit_sqes`: consumes up to `nr` SQEs; the number submitted, which
/// counts a request that failed its checks (submission stops there, unless
/// `IORING_SETUP_SUBMIT_ALL`) but not an SQ index past the ring.
pub(super) fn submit(c: &mut Ctx<'_>, ring: &Ring, st: &mut State, nr: u32) -> i64 {
    let entries = nr.min(ring.sq_pending(st));
    if entries == 0 {
        return 0;
    }
    let mut left = entries;
    let mut batch = Batch::new();
    let mut link: Option<Chain> = None;
    loop {
        let Some((_, sqe)) = ring.fetch_sqe(st) else {
            break;
        };
        st.live += 1;
        let mut req = Req::new(sqe);
        let failed = match init(c, ring, st, &mut req, &mut link) {
            Ok(()) => {
                submit_one(c, ring, st, &mut batch, &mut link, req);
                false
            }
            Err(e) => fail_init(st, &mut batch, &mut link, req, e).is_err(),
        };
        if failed && ring.flags & setup::SUBMIT_ALL == 0 {
            left -= 1;
            break;
        }
        left -= 1;
        if left == 0 {
            break;
        }
    }
    // io_submit_state_end: an unfinished link is queued as it is.
    if let Some(chain) = link.take() {
        queue_fallback(st, &mut batch, chain);
    }
    flush(ring, st, batch);
    ring.commit_sq(st);
    run_iowq(c, ring, st);
    i64::from(entries - left)
}

/// Posts a request's CQE unless it skips it.
fn post(ring: &Ring, st: &mut State, req: &Req) {
    if req.flags & rf::CQE_SKIP == 0 {
        ring.post(st, req.cqe());
    }
}

/// `io_req_find_next` and `io_disarm_next` for a completed chain: its head,
/// and its next request as task work, or, if it failed through a soft
/// link, the rest cancelled as task work.
fn next_work(chain: Chain) -> (Req, Option<Work>) {
    let mut rest = chain;
    let head = rest.pop_front().expect("a request");
    if rest.is_empty() {
        return (head, None);
    }
    if head.flags & rf::FAIL != 0 && head.flags & rf::HARDLINK == 0 {
        let ignore = head.flags & rf::SKIP_LINK_CQES != 0;
        for r in rest.iter_mut() {
            if ignore {
                r.flags |= rf::CQE_SKIP;
            } else {
                r.flags &= !rf::CQE_SKIP;
            }
        }
        (head, Some(Work::FailLinks(rest)))
    } else {
        (head, Some(Work::Issue(rest)))
    }
}

/// [`flush`] for the cancellation of parked requests.
pub(super) fn flush_batch(ring: &Ring, st: &mut State, batch: Vec<Chain>) {
    flush(ring, st, batch);
}

/// `__io_submit_flush_completions`: the batch's CQEs in order, committed
/// (and counted on a registered eventfd); then its requests are freed
/// (`io_free_batch_list`: each one's link queued, then what it held
/// released), and drained chains looked at again.
fn flush(ring: &Ring, st: &mut State, batch: Batch) {
    if batch.is_empty() {
        return;
    }
    for chain in &batch {
        post(ring, st, &chain[0]);
    }
    commit(ring, st, false);
    for chain in batch {
        st.live -= 1;
        let (head, next) = next_work(chain);
        if let Some(w) = next {
            st.task_work.push_back(w);
        }
        rsrc::free_req(ring, st, head);
    }
    if st.drain_active {
        queue_deferred(st);
    }
}

/// `io_commit_cqring` and `__io_commit_cqring_flush`: publishes the tail
/// and counts it on the registered eventfd unless it is disabled, only
/// for the workers' completions if it was registered async, and only once
/// the tail moved.
pub(super) fn commit(ring: &Ring, st: &mut State, from_worker: bool) {
    ring.commit_cq(st);
    let Some(ev) = st.eventfd.as_ref() else {
        return;
    };
    if ring.get32(rings::CQ_FLAGS) & CQ_EVENTFD_DISABLED != 0 {
        return;
    }
    if ev.async_only && !from_worker {
        return;
    }
    if st.eventfd_tail == st.cached_cq_tail {
        return;
    }
    st.eventfd_tail = st.cached_cq_tail;
    // eventfd_signal_mask(EPOLL_URING_WAKE).
    if let FileObject::Anon(Anon::Event(e)) = &ev.file.object {
        e.signal();
        ev.file.woke(ev_mask::IN | ev_mask::RDNORM);
    }
}

/// Runs the async workers' requests: each chain in a worker, its CQEs
/// posted as they complete (through task work on a ring whose CQ only its
/// submitter touches).
fn run_iowq(c: &mut Ctx<'_>, ring: &Ring, st: &mut State) {
    let lockless = ring.flags & (setup::DEFER_TASKRUN | setup::IOPOLL) != 0;
    while let Some(mut chain) = st.iowq.pop_front() {
        loop {
            let done = ops::issue(c, ring, st, &mut chain[0]);
            if let Done::Park(file, mask) = done {
                // A worker that tried without sleeping waits for the file
                // (io_wq_submit_work's poll).
                poll::park(c, ring, st, chain, file, mask);
                break;
            }
            if lockless || matches!(done, Done::TaskWork) {
                // The CQE and the rest of the link through task work.
                st.task_work.push_back(Work::Complete(chain));
                break;
            }
            // io_req_complete_post: the CQE at once. io_wq_free_work: the
            // worker goes on with the link, and the request is freed
            // through task work (io_free_req), posting nothing more.
            post(ring, st, &chain[0]);
            commit(ring, st, true);
            let (head, next) = next_work(chain);
            let free = |st: &mut State, mut head: Req| {
                head.flags |= rf::CQE_SKIP;
                st.task_work.push_back(Work::Complete(Chain::from([head])));
            };
            match next {
                Some(Work::Issue(rest)) => {
                    free(st, head);
                    chain = rest;
                }
                Some(w) => {
                    st.task_work.push_back(w);
                    free(st, head);
                    break;
                }
                None => {
                    free(st, head);
                    break;
                }
            }
        }
    }
    if st.drain_active {
        queue_deferred(st);
    }
}

/// Runs queued task work until none is left (`task_work_run`,
/// `io_run_local_work`): each round's completions flushed together.
pub(super) fn run_task_work(c: &mut Ctx<'_>, ring: &Ring, st: &mut State) {
    while !st.task_work.is_empty() {
        let mut batch = Batch::new();
        while let Some(w) = st.task_work.pop_front() {
            match w {
                // io_req_task_submit: a forced-async request goes to the
                // workers.
                Work::Issue(chain) => {
                    if chain[0].flags & rf::FORCE_ASYNC != 0 {
                        queue_iowq(st, chain);
                    } else {
                        queue_sqe(c, ring, st, &mut batch, chain);
                    }
                }
                // Each request completes alone, its CQE as io_fail_links
                // marked it.
                Work::FailLinks(chain) => {
                    for mut r in chain {
                        if r.flags & rf::FAIL == 0 {
                            r.res = -ECANCELED;
                        }
                        r.cflags = 0;
                        batch.push(Chain::from([r]));
                    }
                }
                Work::Complete(chain) => batch.push(chain),
            }
        }
        flush(ring, st, batch);
        run_iowq(c, ring, st);
    }
}

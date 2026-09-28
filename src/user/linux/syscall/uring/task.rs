//! What the process's rings do outside `io_uring_enter` (Linux 6.19): the
//! wake-ups of their poll tables and the expiries of their timers, looked
//! for as each system call of the process begins and ends, with the task
//! work those queue (`task_work_run` on the return to user mode); what a
//! sleeping call also waits for; and what `fork` and `exec` do to the
//! requests (`io_uring_task_cancel`).

use std::sync::{Arc, Weak};
use std::time::Instant;

use super::super::super::abi::errno_table::*;
use super::super::super::process::ProcState;
use super::super::super::uring::abi::setup;
use super::super::super::uring::{Chain, Req, Ring, State, req_flags as rf};
use super::super::Ctx;
use super::super::ready::poll_files;
use super::{poll, submit, timeout};

/// Notes `ring` in the process's list of rings with something waiting.
pub(super) fn note(c: &mut Ctx<'_>, ring: &Ring) {
    let w = ring.weak();
    if !c.p.uring_parked.iter().any(|x| x.ptr_eq(&w)) {
        c.p.uring_parked.push(w);
    }
}

/// Looks at every ring with something waiting: timers that expired and
/// poll entries whose files report what they wait for queue their task
/// work, which an ordinary ring runs at once. The call's own progress
/// ([`Ctx::resume`]) is kept aside meanwhile.
pub fn drive(c: &mut Ctx<'_>) {
    let rings: Vec<Arc<Ring>> = std::mem::take(&mut c.p.uring_parked)
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
    // The call's own progress and SIGPIPE decision are kept aside.
    let resume = c.resume.take();
    let (decided, nosignal) = (c.sigpipe_decided, c.nosignal);
    for ring in rings {
        {
            let mut st = ring.state();
            timeout::fire(&mut st);
            poll::wake(c, &mut st);
            if ring.flags & setup::DEFER_TASKRUN == 0 {
                submit::run_task_work(c, &ring, &mut st);
            }
            if st.waiting() {
                note(c, &ring);
            }
        }
        ring.reap();
    }
    c.resume = resume;
    (c.sigpipe_decided, c.nosignal) = (decided, nosignal);
}

/// What a sleeping call also waits on: the files of the poll entries a
/// wake-up could reach.
pub fn wait_fds(c: &Ctx<'_>) -> Vec<(i32, bool, bool)> {
    let mut fds = Vec::new();
    for ring in c.p.uring_parked.iter().filter_map(Weak::upgrade) {
        let st = ring.state();
        for p in st.polls.iter().filter(|p| !p.queued && !p.detached) {
            let (_, wait) = poll_files(c, &[(&p.file, p.events)]);
            fds.extend(wait.fds);
        }
    }
    fds
}

/// When a sleeping call also wakes: the next timer's expiry.
pub fn next_deadline(c: &Ctx<'_>) -> Option<Instant> {
    c.p.uring_parked
        .iter()
        .filter_map(Weak::upgrade)
        .filter_map(|ring| timeout::next(&ring.state()))
        .min()
}

/// In a new process: the requests are its parent's (a forked child shares
/// a ring's memory, not its requests), so none waits here.
pub fn forked(p: &mut ProcState) {
    for ring in std::mem::take(&mut p.uring_parked)
        .iter()
        .filter_map(Weak::upgrade)
    {
        let mut st = ring.state();
        let polls: u64 = st.polls.iter().map(|x| x.chain.len() as u64).sum();
        let timeouts: u64 = st.timeouts.iter().map(|x| x.chain.len() as u64).sum();
        let dropped = polls + timeouts + st.ltimeouts.len() as u64;
        st.polls.clear();
        st.timeouts.clear();
        st.ltimeouts.clear();
        st.live -= dropped;
    }
}

/// `io_uring_task_cancel` as the task execs (`io_uring_try_cancel_requests`):
/// the poll table's entries in its order (`io_poll_remove_all`), then the
/// timeouts on the list (`io_kill_timeouts`), complete with `-ECANCELED`
/// together; then, as their requests are freed, their linked timeouts
/// (`-ECANCELED`) and the requests linked after them, hard links too
/// (`io_fail_links`).
pub fn exec_cancel(p: &mut ProcState) {
    for ring in std::mem::take(&mut p.uring_parked)
        .iter()
        .filter_map(Weak::upgrade)
    {
        {
            let mut st = ring.state();
            let order = poll::table_order(&ring, &st);
            let mut polls: Vec<_> = std::mem::take(&mut st.polls)
                .into_iter()
                .map(Some)
                .collect();
            let mut chains: Vec<Chain> = order
                .into_iter()
                .map(|i| polls[i].take().expect("each entry once").chain)
                .collect();
            chains.extend(
                std::mem::take(&mut st.timeouts)
                    .into_iter()
                    .map(|t| t.chain),
            );
            cancel_chains(&ring, &mut st, chains);
        }
        ring.reap();
    }
}

/// Completes cancelled chains: their heads with `-ECANCELED` in one batch,
/// then each one's linked timeout and the requests linked after it (their
/// own error if they failed, `-ECANCELED` otherwise) in another.
fn cancel_chains(ring: &Ring, st: &mut State, chains: Vec<Chain>) {
    let mut heads = Vec::new();
    let mut after = Vec::new();
    for mut chain in chains {
        let mut head = chain.pop_front().expect("a request");
        head.fail(-ECANCELED);
        if let Some(lt) = timeout::disarm(st, &mut head, &mut chain) {
            after.push(Chain::from([lt]));
        }
        head.flags &= !rf::LINKS;
        let ignore = head.flags & rf::SKIP_LINK_CQES != 0;
        heads.push(Chain::from([head]));
        for r in chain {
            after.push(Chain::from([failed_link(r, ignore)]));
        }
    }
    submit::flush_batch(ring, st, heads);
    submit::flush_batch(ring, st, after);
}

/// A request of a failed link (`io_fail_links`, `io_req_tw_fail_links`):
/// its CQE skipped as the head's failure says, its own error kept.
fn failed_link(mut r: Req, ignore: bool) -> Req {
    if ignore {
        r.flags |= rf::CQE_SKIP;
    } else {
        r.flags &= !rf::CQE_SKIP;
    }
    if r.flags & rf::FAIL == 0 {
        r.res = -ECANCELED;
    }
    r.cflags = 0;
    r.flags &= !rf::LINKS;
    r
}

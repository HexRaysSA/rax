//! Requests waiting for their files (`io_uring/poll.c`, Linux 6.19:
//! `io_arm_poll_handler`, `io_poll_wake`, `io_apoll_task_func`), and their
//! cancellation as the task execs (`io_uring_task_cancel`).
//!
//! A request its file cannot serve now is parked with the events it needs,
//! and its ring noted in the process's list. The list is looked at as each
//! system call of the process begins and ends, and a call that sleeps also
//! wakes for the parked files: that stands for the file's wake-up, which
//! queues the request's retry as task work. An ordinary ring's task work
//! then runs at once (as on the return to user mode after a wake-up), a
//! deferring ring's in its next wait. The retry is an issue like the first,
//! so a request its file still cannot serve parks again.

use std::sync::{Arc, Weak};

use super::super::super::abi::errno_table::*;
use super::super::super::fs::fd::OpenFile;
use super::super::super::process::ProcState;
use super::super::super::uring::abi::setup;
use super::super::super::uring::{Chain, Parked, Ring, State, Work, req_flags as rf};
use super::super::Ctx;
use super::super::ready::{ev, poll_files};
use super::submit;

/// Parks `chain`, whose head waits for `file` to report an event of
/// `mask`.
pub(super) fn park(
    c: &mut Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    chain: Chain,
    file: Arc<OpenFile>,
    mask: u32,
) {
    st.parked.push(Parked { chain, file, mask });
    note(c, ring);
}

/// Notes `ring` in the process's list of rings with parked requests.
fn note(c: &mut Ctx<'_>, ring: &Ring) {
    let w = ring.weak();
    if !c.p.uring_parked.iter().any(|x| x.ptr_eq(&w)) {
        c.p.uring_parked.push(w);
    }
}

/// Whether a parked request's file reports an event it waits for, or an
/// error or hang-up (which the retry then reports).
fn ready(c: &Ctx<'_>, p: &Parked) -> bool {
    let (polled, _) = poll_files(c, &[(&p.file, p.mask)]);
    polled[0].mask & (p.mask | ev::ERR | ev::HUP) != 0
}

/// `io_poll_wake`: the parked chains whose files are ready become task
/// work, issued again.
fn wake(c: &Ctx<'_>, st: &mut State) {
    for p in std::mem::take(&mut st.parked) {
        if ready(c, &p) {
            st.task_work.push_back(Work::Issue(p.chain));
        } else {
            st.parked.push(p);
        }
    }
}

/// Looks at every ring with parked requests: those whose files are ready
/// are issued again, at once on an ordinary ring. The call's own progress
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
            wake(c, &mut st);
            if ring.flags & setup::DEFER_TASKRUN == 0 {
                submit::run_task_work(c, &ring, &mut st);
            }
            if !st.parked.is_empty() {
                note(c, &ring);
            }
        }
        ring.reap();
    }
    c.resume = resume;
    (c.sigpipe_decided, c.nosignal) = (decided, nosignal);
}

/// What a sleeping call also waits on: the parked requests' files.
pub fn wait_fds(c: &Ctx<'_>) -> Vec<(i32, bool, bool)> {
    let mut fds = Vec::new();
    for ring in c.p.uring_parked.iter().filter_map(Weak::upgrade) {
        let st = ring.state();
        for p in &st.parked {
            let (_, wait) = poll_files(c, &[(&p.file, p.mask)]);
            fds.extend(wait.fds);
        }
    }
    fds
}

/// In a new process: the parked requests are its parent's (a forked child
/// shares a ring's memory, not its requests), so none waits here.
pub fn forked(p: &mut ProcState) {
    for ring in std::mem::take(&mut p.uring_parked)
        .iter()
        .filter_map(Weak::upgrade)
    {
        let mut st = ring.state();
        let dropped: u64 = st.parked.iter().map(|x| x.chain.len() as u64).sum();
        st.parked.clear();
        st.live -= dropped;
    }
}

/// `io_uring_task_cancel` as the task execs: each parked request completes
/// with `-ECANCELED`, and the requests linked after it fail with it.
pub fn exec_cancel(p: &mut ProcState) {
    for ring in std::mem::take(&mut p.uring_parked)
        .iter()
        .filter_map(Weak::upgrade)
    {
        {
            let mut st = ring.state();
            for parked in std::mem::take(&mut st.parked) {
                cancel(&ring, &mut st, parked.chain);
            }
        }
        ring.reap();
    }
}

/// Completes a parked chain cancelled: its head with `-ECANCELED`, the
/// rest as `io_fail_links` fails them, in one batch.
fn cancel(ring: &Ring, st: &mut State, mut chain: Chain) {
    let mut head = chain.pop_front().expect("a request");
    head.fail(-ECANCELED);
    head.flags &= !rf::LINKS;
    let ignore = head.flags & rf::SKIP_LINK_CQES != 0;
    let mut batch = vec![Chain::from([head])];
    for mut r in chain {
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
        batch.push(Chain::from([r]));
    }
    submit::flush_batch(ring, st, batch);
}

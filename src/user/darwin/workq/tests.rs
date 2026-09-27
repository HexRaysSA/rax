use super::*;

fn running(qos: u8, pool: Pool) -> ThreadWorkq {
    ThreadWorkq {
        sched: Some(Sched {
            qos_req: qos,
            qos_bucket: qos,
            pool,
        }),
        ..Default::default()
    }
}

fn wq(threads: &[(u64, ThreadWorkq)]) -> Workqueue {
    let mut w = Workqueue::default();
    for (tid, t) in threads {
        w.threads.insert(*tid, t.clone());
    }
    w
}

const DEF: u8 = thread_qos::LEGACY;
const UT: u8 = thread_qos::UTILITY;
const UI: u8 = thread_qos::USER_INTERACTIVE;

fn anon(id: u64, qos: u8, flags: u8) -> Candidate {
    (ReqRef::Anon(id), qos, flags)
}

#[test]
fn buckets_and_masks() {
    // Maintenance and background share the first bucket; the manager
    // has the last.
    assert_eq!(bucket(thread_qos::MAINTENANCE), 0);
    assert_eq!(bucket(thread_qos::BACKGROUND), 0);
    assert_eq!(bucket(thread_qos::UTILITY), 1);
    assert_eq!(bucket(QOS_ABOVEUI), 5);
    assert_eq!(bucket(QOS_MANAGER), 6);
    // A workqueue thread blocks everything but the synchronous signals,
    // SIGKILL, SIGSTOP, and SIGPROF, and blocks SIGABRT (the mask a
    // worker reports natively: 0xfbfee027).
    assert_eq!(!WORKQ_THREADMASK, 0xfbfe_e027);
    assert_eq!(pthread_t_offset(DarwinAbi::Arm64), 12 * 1024);
    assert_eq!(pthread_t_offset(DarwinAbi::X86_64), 0);
}

#[test]
fn manager_first_and_one_at_a_time() {
    let reqs = [
        anon(1, UI, trflag::OVERCOMMIT),
        (ReqRef::Anon(2), QOS_MANAGER, trflag::KEVENT),
    ];
    let idle = wq(&[]);
    assert_eq!(
        idle.select(&reqs, None, 1, &|_| true),
        Some(ReqRef::Anon(2))
    );
    // A running manager defers the next, except to itself.
    let busy = wq(&[(7, {
        let mut t = running(QOS_MANAGER, Pool::Overcommit);
        t.sched.as_mut().unwrap().qos_bucket = QOS_MANAGER;
        t
    })]);
    assert_eq!(
        busy.select(&reqs, None, 1, &|_| true),
        Some(ReqRef::Anon(1))
    );
    assert_eq!(
        busy.select(&reqs, Some(7), 1, &|_| true),
        Some(ReqRef::Anon(2))
    );
}

#[test]
fn overcommit_is_always_admitted() {
    // Every CPU busy with an active thread at a higher QoS.
    let w = wq(&[
        (1, running(UI, Pool::Overcommit)),
        (2, running(UI, Pool::Constrained)),
    ]);
    let reqs = [anon(9, UT, trflag::OVERCOMMIT)];
    assert_eq!(w.select(&reqs, None, 1, &|_| true), Some(ReqRef::Anon(9)));
}

#[test]
fn constrained_waits_for_a_free_cpu() {
    let w = wq(&[(1, running(DEF, Pool::Constrained))]);
    let reqs = [anon(9, DEF, 0)];
    // One CPU, one active thread at the same QoS: not admitted.
    assert_eq!(w.select(&reqs, None, 1, &|_| true), None);
    assert_eq!(w.constrained_allowance(DEF, None, 1, &|_| true), 0);
    // It blocks: admitted.
    assert_eq!(w.select(&reqs, None, 1, &|_| false), Some(ReqRef::Anon(9)));
    // The thread itself, returning, does not count against it.
    assert_eq!(
        w.select(&reqs, Some(1), 1, &|_| true),
        Some(ReqRef::Anon(9))
    );
    // A lower-QoS active thread does not count either.
    let low = wq(&[(1, running(UT, Pool::Constrained))]);
    assert_eq!(low.select(&reqs, None, 1, &|_| true), Some(ReqRef::Anon(9)));
    // More CPUs admit more.
    assert_eq!(w.constrained_allowance(DEF, None, 4, &|_| true), 3);
}

#[test]
fn constrained_pool_limit() {
    let threads: Vec<(u64, ThreadWorkq)> = (0..MAX_CONSTRAINED as u64)
        .map(|t| (t, running(UT, Pool::Constrained)))
        .collect();
    let w = wq(&threads);
    // Even with every one of them blocked.
    assert_eq!(w.constrained_allowance(UI, None, 512, &|_| false), 0);
    assert_eq!(w.constrained_allowance(UI, Some(0), 512, &|_| false), 512);
}

#[test]
fn qos_order_between_pools() {
    let w = wq(&[]);
    // A higher-QoS constrained request that is admitted wins.
    let reqs = [anon(1, UT, trflag::OVERCOMMIT), anon(2, UI, 0)];
    assert_eq!(w.select(&reqs, None, 1, &|_| true), Some(ReqRef::Anon(2)));
    // At equal QoS the overcommit request wins.
    let reqs = [anon(2, UI, 0), anon(1, UI, trflag::OVERCOMMIT)];
    assert_eq!(w.select(&reqs, None, 1, &|_| true), Some(ReqRef::Anon(1)));
    // Within a pool: the highest QoS, then the first queued.
    let reqs = [anon(1, UT, 0), anon(2, DEF, 0), anon(3, DEF, 0)];
    assert_eq!(w.select(&reqs, None, 1, &|_| true), Some(ReqRef::Anon(2)));
    // A constrained request that is not admitted leaves the overcommit
    // one.
    let busy = wq(&[(5, running(UI, Pool::Constrained))]);
    let reqs = [anon(1, UT, trflag::OVERCOMMIT), anon(2, UI, 0)];
    assert_eq!(
        busy.select(&reqs, None, 1, &|_| true),
        Some(ReqRef::Anon(1))
    );
}

#[test]
fn cooperative_pool() {
    let reqs = [anon(1, DEF, trflag::COOPERATIVE)];
    // Room in the pool.
    assert_eq!(
        wq(&[]).select(&reqs, None, 1, &|_| true),
        Some(ReqRef::Anon(1))
    );
    // Full, but nothing serves the request's bucket.
    let other = wq(&[(3, running(UT, Pool::Cooperative))]);
    assert!(other.cooperative_allowance(DEF, None, 1));
    // Full and served at this QoS.
    let full = wq(&[(3, running(DEF, Pool::Cooperative))]);
    assert!(!full.cooperative_allowance(DEF, None, 1));
    assert_eq!(full.select(&reqs, None, 1, &|_| true), None);
    // The thread asking is not counted.
    assert!(full.cooperative_allowance(DEF, Some(3), 1));
}

#[test]
fn request_flags() {
    assert!(is_constrained(trflag::KEVENT));
    assert!(!is_constrained(trflag::OVERCOMMIT | trflag::KEVENT));
    assert!(!is_constrained(trflag::COOPERATIVE));
    assert!(!is_constrained(trflag::PERMANENT_BIND));
    assert!(is_overcommit(trflag::WORKLOOP | trflag::OVERCOMMIT));
}

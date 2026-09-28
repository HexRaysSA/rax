//! io_uring's timeouts, linked timeouts, and cancellation
//! (`io_uring/timeout.c`, `cancel.c`, Linux 6.19).

use super::*;

// Operations.
const POLL_ADD: u8 = 6;
const TIMEOUT: u8 = 11;
const TIMEOUT_REMOVE: u8 = 12;
const ASYNC_CANCEL: u8 = 14;
const LINK_TIMEOUT: u8 = 15;
const READ: u8 = 22;
// IORING_TIMEOUT_*.
const ABS: u32 = 1;
const UPDATE: u32 = 1 << 1;
const BOOTTIME: u32 = 1 << 2;
const REALTIME: u32 = 1 << 3;
const LINK_UPDATE: u32 = 1 << 4;
const ETIME_SUCCESS: u32 = 1 << 5;
const MULTISHOT: u32 = 1 << 6;
// IORING_ASYNC_CANCEL_*.
const ALL: u32 = 1;
const FD: u32 = 1 << 1;
const ANY: u32 = 1 << 2;
const FD_FIXED: u32 = 1 << 3;
const OP: u32 = 1 << 5;
const REGISTER_SYNC_CANCEL: u64 = 24;
const IOSQE_FIXED_FILE: u8 = 1;
const MORE: u32 = 1 << 1;
const POLLIN: u32 = 1;

// Timespecs: 2 ms, 10 s, the monotonic epoch, and a negative one.
const SHORT: u64 = 0x400;
const LONG: u64 = 0x410;
const ZERO: u64 = 0x420;
const NEGATIVE: u64 = 0x430;
const CANCEL_REG: u64 = 0x480;

fn run(h: &mut Harness, r: &Ring, sqes: &[Sqe]) -> Vec<(u64, i32, u32)> {
    for s in sqes {
        r.push(h, *s);
    }
    assert_eq!(r.enter(h, sqes.len() as u64, 0, 0), sqes.len() as i64);
    r.reap(h)
}

/// Submits `sqes` and waits for `n` completions.
fn wait(h: &mut Harness, r: &Ring, sqes: &[Sqe], n: u64) -> Vec<(u64, i32, u32)> {
    for s in sqes {
        r.push(h, *s);
    }
    let submitted = sqes.len() as i64;
    let got = r.enter(h, sqes.len() as u64, n, GETEVENTS);
    assert!(got == submitted || (submitted == 0 && got == 0), "{got}");
    r.reap(h)
}

fn neg(e: i32) -> i32 {
    -e
}

fn times(h: &Harness) {
    let ts = |sec: i64, nsec: i64| {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&sec.to_le_bytes());
        b[8..].copy_from_slice(&nsec.to_le_bytes());
        b
    };
    put(h, h.scratch + SHORT, &ts(0, 2_000_000));
    put(h, h.scratch + LONG, &ts(10, 0));
    put(h, h.scratch + ZERO, &ts(0, 0));
    put(h, h.scratch + NEGATIVE, &ts(-1, 0));
}

/// A timeout of the timespec at `ts` (an offset from `base`, the scratch
/// page) counting `off`.
fn timeout(base: u64, ts: u64, off: u64, flags: u32, user_data: u64) -> Sqe {
    Sqe {
        opcode: TIMEOUT,
        addr: base + ts,
        len: 1,
        off,
        op_flags: flags,
        user_data,
        ..Sqe::default()
    }
}

fn link_timeout(base: u64, ts: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode: LINK_TIMEOUT,
        ..timeout(base, ts, 0, 0, user_data)
    }
}

/// A removal (or with `flags`, an update to the timespec at `ts`).
fn remove(base: u64, target: u64, flags: u32, ts: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode: TIMEOUT_REMOVE,
        addr: target,
        off: if ts == 0 { 0 } else { base + ts },
        op_flags: flags,
        user_data,
        ..Sqe::default()
    }
}

fn cancel(target: u64, flags: u32, user_data: u64) -> Sqe {
    Sqe {
        opcode: ASYNC_CANCEL,
        addr: target,
        op_flags: flags,
        user_data,
        ..Sqe::default()
    }
}

fn poll(fd: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode: POLL_ADD,
        fd: fd as i32,
        op_flags: POLLIN,
        user_data,
        ..Sqe::default()
    }
}

fn read(fd: u64, buf: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode: READ,
        fd: fd as i32,
        addr: buf,
        len: 4,
        off: u64::MAX,
        user_data,
        ..Sqe::default()
    }
}

fn pipe(h: &mut Harness) -> (u64, u64) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Pipe2, &[at, 0]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn linked(mut s: Sqe) -> Sqe {
    s.flags |= LINK;
    s
}

#[test]
fn a_timeout_expires_or_counts_completions() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let b = h.scratch;
        times(&h);
        let r = setup(&mut h, 8, 0, 0);
        // io_timeout_fn: -ETIME.
        let t = timeout(b, SHORT, 0, 0, 1);
        assert_eq!(wait(&mut h, &r, &[t], 1), [(1, neg(ETIME), 0)], "{abi:?}");
        // io_should_wake: an expiry ends a wait for more.
        let t = timeout(b, SHORT, 0, 0, 30);
        assert_eq!(wait(&mut h, &r, &[t], 2), [(30, neg(ETIME), 0)]);
        // io_flush_timeouts: complete with 0 once `off` other CQEs posted.
        let t = timeout(b, LONG, 2, 0, 2);
        assert_eq!(
            run(&mut h, &r, &[t, Sqe::nop(3), Sqe::nop(4)]),
            [(3, 0, 0), (4, 0, 0), (2, 0, 0)]
        );
        assert_eq!(run(&mut h, &r, &[timeout(b, LONG, 1, 0, 5)]), []);
        assert_eq!(run(&mut h, &r, &[Sqe::nop(6)]), [(6, 0, 0), (5, 0, 0)]);
        // A timeout's own CQE is not counted (cq_timeouts).
        assert_eq!(run(&mut h, &r, &[timeout(b, LONG, 1, 0, 7)]), []);
        let t = timeout(b, SHORT, 0, 0, 8);
        assert_eq!(wait(&mut h, &r, &[t], 1), [(8, neg(ETIME), 0)]);
        assert_eq!(run(&mut h, &r, &[Sqe::nop(9)]), [(9, 0, 0), (7, 0, 0)]);
        // Kept in order of the sequence each waits for.
        let (t20, t21) = (timeout(b, LONG, 3, 0, 20), timeout(b, LONG, 1, 0, 21));
        assert_eq!(run(&mut h, &r, &[t20, t21]), []);
        assert_eq!(run(&mut h, &r, &[Sqe::nop(22)]), [(22, 0, 0), (21, 0, 0)]);
        assert_eq!(
            run(&mut h, &r, &[Sqe::nop(23), Sqe::nop(24)]),
            [(23, 0, 0), (24, 0, 0), (20, 0, 0)]
        );
    });
}

#[test]
fn an_expired_timeout_fails_its_link_unless_etime_is_success() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let b = h.scratch;
    times(&h);
    let r = setup(&mut h, 8, 0, 0);
    let t = linked(timeout(b, SHORT, 0, 0, 1));
    assert_eq!(
        wait(&mut h, &r, &[t, Sqe::nop(2)], 2),
        [(1, neg(ETIME), 0), (2, neg(ECANCELED), 0)]
    );
    let t = linked(timeout(b, SHORT, 0, ETIME_SUCCESS, 3));
    assert_eq!(
        wait(&mut h, &r, &[t, Sqe::nop(4)], 2),
        [(3, neg(ETIME), 0), (4, 0, 0)]
    );
    // A timeout counting completions completes with 0, keeping its link.
    let t = linked(timeout(b, LONG, 1, 0, 5));
    assert_eq!(run(&mut h, &r, &[t, Sqe::nop(6)]), []);
    assert_eq!(
        run(&mut h, &r, &[Sqe::nop(7)]),
        [(7, 0, 0), (5, 0, 0), (6, 0, 0)]
    );
}

#[test]
fn a_multishot_timeout_reports_each_expiry() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let b = h.scratch;
    times(&h);
    let r = setup(&mut h, 8, 0, 0);
    // Three expiries: two with IORING_CQE_F_MORE, the last without; each
    // ends a wait.
    let t = timeout(b, SHORT, 3, MULTISHOT, 1);
    let mut got = wait(&mut h, &r, &[t], 3);
    assert_eq!(got, [(1, neg(ETIME), MORE)]);
    while got.len() < 3 {
        got.extend(wait(&mut h, &r, &[], 1));
    }
    assert_eq!(
        got,
        [
            (1, neg(ETIME), MORE),
            (1, neg(ETIME), MORE),
            (1, neg(ETIME), 0)
        ]
    );
    // No count: for ever, until removed.
    let mut got = wait(&mut h, &r, &[timeout(b, SHORT, 0, MULTISHOT, 2)], 2);
    while got.len() < 2 {
        got.extend(wait(&mut h, &r, &[], 1));
    }
    assert!(got.iter().all(|&c| c == (2, neg(ETIME), MORE)), "{got:?}");
    let mut got = run(&mut h, &r, &[remove(b, 2, 0, 0, 3)]);
    got.retain(|&c| c != (2, neg(ETIME), MORE));
    assert_eq!(got, [(3, 0, 0), (2, neg(ECANCELED), 0)]);
}

#[test]
fn timeout_preparation_checks_the_request() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let b = h.scratch;
    times(&h);
    let r = setup(&mut h, 8, 0, 0);
    let t = |off, flags, ud| timeout(b, LONG, off, flags, ud);
    let bad = [
        (
            Sqe {
                len: 2,
                ..t(0, 0, 1)
            },
            EINVAL,
        ),
        (
            Sqe {
                buf_index: 1,
                ..t(0, 0, 2)
            },
            EINVAL,
        ),
        (
            Sqe {
                file_index: 1,
                ..t(0, 0, 3)
            },
            EINVAL,
        ),
        (t(0, 1 << 7, 4), EINVAL),
        (t(0, BOOTTIME | REALTIME, 5), EINVAL),
        (t(0, MULTISHOT | ABS, 6), EINVAL),
        (
            Sqe {
                addr: 16,
                ..t(0, 0, 7)
            },
            EFAULT,
        ),
        (timeout(b, NEGATIVE, 0, 0, 8), EINVAL),
        (
            Sqe {
                flags: BUFFER_SELECT,
                ..t(0, 0, 9)
            },
            EOPNOTSUPP,
        ),
        // A linked timeout counts nothing and follows a request.
        (
            Sqe {
                off: 1,
                ..link_timeout(b, LONG, 10)
            },
            EINVAL,
        ),
        (link_timeout(b, LONG, 11), EINVAL),
        // io_timeout_remove_prep.
        (
            Sqe {
                len: 1,
                ..remove(b, 1, 0, 0, 12)
            },
            EINVAL,
        ),
        (
            Sqe {
                buf_index: 1,
                ..remove(b, 1, 0, 0, 13)
            },
            EINVAL,
        ),
        (
            Sqe {
                flags: IOSQE_FIXED_FILE,
                ..remove(b, 1, 0, 0, 14)
            },
            EINVAL,
        ),
        (remove(b, 1, ABS, 0, 15), EINVAL),
        (remove(b, 1, UPDATE | REALTIME, LONG, 16), EINVAL),
        (remove(b, 1, UPDATE, 0, 17), EFAULT),
        (remove(b, 1, UPDATE, NEGATIVE, 18), EINVAL),
    ];
    for (s, e) in bad {
        r.push(&h, s);
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
        assert_eq!(r.reap(&h), [(s.user_data, neg(e), 0)], "{s:?}");
    }
    // A linked timeout after another fails, and so does its link.
    let sqes = [
        linked(Sqe::nop(20)),
        linked(link_timeout(b, LONG, 21)),
        link_timeout(b, LONG, 22),
    ];
    for s in sqes {
        r.push(&h, s);
    }
    assert_eq!(r.enter(&mut h, 3, 0, 0), 3);
    assert_eq!(
        r.reap(&h),
        [
            (20, neg(ECANCELED), 0),
            (21, neg(ECANCELED), 0),
            (22, neg(EINVAL), 0)
        ]
    );
}

#[test]
fn a_timeout_is_removed_or_updated() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let b = h.scratch;
    times(&h);
    let r = setup(&mut h, 8, 0, 0);
    assert_eq!(run(&mut h, &r, &[timeout(b, LONG, 0, 0, 1)]), []);
    assert_eq!(
        run(&mut h, &r, &[remove(b, 1, 0, 0, 2)]),
        [(2, 0, 0), (1, neg(ECANCELED), 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[remove(b, 1, 0, 0, 3)]),
        [(3, neg(ENOENT), 0)]
    );
    // Updated: the new time.
    assert_eq!(run(&mut h, &r, &[timeout(b, LONG, 0, 0, 4)]), []);
    assert_eq!(
        run(&mut h, &r, &[remove(b, 4, UPDATE, SHORT, 5)]),
        [(5, 0, 0)]
    );
    assert_eq!(wait(&mut h, &r, &[], 1), [(4, neg(ETIME), 0)]);
    // An updated timeout counts no more completions.
    assert_eq!(run(&mut h, &r, &[timeout(b, LONG, 1, 0, 6)]), []);
    assert_eq!(
        run(&mut h, &r, &[remove(b, 6, UPDATE, LONG, 7)]),
        [(7, 0, 0)]
    );
    assert_eq!(run(&mut h, &r, &[Sqe::nop(8)]), [(8, 0, 0)]);
    assert_eq!(
        run(&mut h, &r, &[remove(b, 6, 0, 0, 9)]),
        [(9, 0, 0), (6, neg(ECANCELED), 0)]
    );
    // An absolute time already past: at once (here as the call returns;
    // Linux's timer interrupt races the return).
    assert_eq!(run(&mut h, &r, &[timeout(b, LONG, 0, 0, 10)]), []);
    assert_eq!(
        wait(&mut h, &r, &[remove(b, 10, UPDATE | ABS, ZERO, 11)], 2),
        [(11, 0, 0), (10, neg(ETIME), 0)]
    );
    // IORING_LINK_TIMEOUT_UPDATE without IORING_TIMEOUT_UPDATE removes.
    assert_eq!(run(&mut h, &r, &[timeout(b, LONG, 0, 0, 12)]), []);
    assert_eq!(
        run(&mut h, &r, &[remove(b, 12, LINK_UPDATE, LONG, 13)]),
        [(13, 0, 0), (12, neg(ECANCELED), 0)]
    );
}

#[test]
fn a_linked_timeout_bounds_the_request_before_it() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let b = h.scratch;
        times(&h);
        let r = setup(&mut h, 8, 0, 0);
        let (rd, wr) = pipe(&mut h);
        // Expiring first: it cancels the poll (io_try_cancel) and reports
        // -ETIME.
        let sqes = [linked(poll(rd, 1)), link_timeout(b, SHORT, 2)];
        assert_eq!(
            wait(&mut h, &r, &sqes, 2),
            [(2, neg(ETIME), 0), (1, neg(ECANCELED), 0)],
            "{abi:?}"
        );
        // The poll completing first cancels it.
        let sqes = [linked(poll(rd, 3)), link_timeout(b, LONG, 4)];
        assert_eq!(run(&mut h, &r, &sqes), []);
        let at = h.scratch + 0xd00;
        put(&h, at, b"x");
        h.ok(Sysno::Write, &[wr, at, 1]);
        assert_eq!(r.reap(&h), [(3, POLLIN as i32, 0), (4, neg(ECANCELED), 0)]);
        // Out of the link, the rest follows its request.
        let sqes = [
            linked(Sqe::nop(5)),
            linked(link_timeout(b, LONG, 6)),
            Sqe::nop(7),
        ];
        assert_eq!(
            run(&mut h, &r, &sqes),
            [(5, 0, 0), (6, neg(ECANCELED), 0), (7, 0, 0)]
        );
        h.ok(Sysno::Read, &[rd, at, 1]);
        let sqes = [
            linked(poll(rd, 8)),
            linked(link_timeout(b, SHORT, 9)),
            Sqe::nop(10),
        ];
        assert_eq!(
            wait(&mut h, &r, &sqes, 3),
            [
                (9, neg(ETIME), 0),
                (8, neg(ECANCELED), 0),
                (10, neg(ECANCELED), 0)
            ]
        );
        // IORING_LINK_TIMEOUT_UPDATE restarts it.
        let sqes = [linked(poll(rd, 11)), link_timeout(b, LONG, 12)];
        assert_eq!(run(&mut h, &r, &sqes), []);
        assert_eq!(
            run(
                &mut h,
                &r,
                &[remove(b, 12, UPDATE | LINK_UPDATE, SHORT, 13)]
            ),
            [(13, 0, 0)]
        );
        assert_eq!(
            wait(&mut h, &r, &[], 2),
            [(12, neg(ETIME), 0), (11, neg(ECANCELED), 0)]
        );
        assert_eq!(
            run(
                &mut h,
                &r,
                &[remove(b, 12, UPDATE | LINK_UPDATE, SHORT, 14)]
            ),
            [(14, neg(ENOENT), 0)]
        );
    });
}

#[test]
fn async_cancel_finds_queued_polled_and_timed_requests() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let b = h.scratch;
    times(&h);
    let r = setup(&mut h, 8, 0, 0);
    let buf = h.anon(P, RW, false);
    let (rd, _wr) = pipe(&mut h);
    let (other, _ow) = pipe(&mut h);
    assert_eq!(run(&mut h, &r, &[cancel(99, 0, 1)]), [(1, neg(ENOENT), 0)]);
    // By user data: a poll, a request waiting for its file, a timeout.
    for (s, ud) in [
        (poll(rd, 2), 2),
        (read(rd, buf, 4), 4),
        (timeout(b, LONG, 0, 0, 6), 6),
    ] {
        assert_eq!(run(&mut h, &r, &[s]), []);
        assert_eq!(
            run(&mut h, &r, &[cancel(ud, 0, ud + 1)]),
            [(ud + 1, 0, 0), (ud, neg(ECANCELED), 0)]
        );
    }
    // A request queued for the workers, in the same submission.
    let queued = Sqe {
        flags: ASYNC,
        ..poll(rd, 30)
    };
    assert_eq!(
        run(&mut h, &r, &[queued, cancel(30, 0, 31)]),
        [(31, 0, 0), (30, neg(ECANCELED), 0)]
    );
    // IORING_ASYNC_CANCEL_ALL: each one, counted.
    assert_eq!(run(&mut h, &r, &[poll(rd, 8), poll(other, 8)]), []);
    assert_eq!(
        run(&mut h, &r, &[cancel(8, ALL, 9)]),
        [(9, 2, 0), (8, neg(ECANCELED), 0), (8, neg(ECANCELED), 0)]
    );
    // _ANY: the poll table in its order (user data 14 in bucket 0; 12,
    // then 10, in bucket 1), then the timeouts.
    let sqes = [
        poll(rd, 10),
        timeout(b, LONG, 0, 0, 11),
        read(rd, buf, 12),
        poll(other, 14),
    ];
    assert_eq!(run(&mut h, &r, &sqes), []);
    assert_eq!(
        run(&mut h, &r, &[cancel(0, ANY, 13)]),
        [
            (13, 4, 0),
            (14, neg(ECANCELED), 0),
            (12, neg(ECANCELED), 0),
            (10, neg(ECANCELED), 0),
            (11, neg(ECANCELED), 0)
        ]
    );
    // By file and by operation.
    assert_eq!(run(&mut h, &r, &[poll(rd, 15), poll(other, 16)]), []);
    let by_file = Sqe {
        fd: other as i32,
        ..cancel(0, FD, 17)
    };
    assert_eq!(
        run(&mut h, &r, &[by_file]),
        [(17, 0, 0), (16, neg(ECANCELED), 0)]
    );
    assert_eq!(run(&mut h, &r, &[read(rd, buf, 18)]), []);
    let by_op = Sqe {
        len: u32::from(READ),
        ..cancel(0, OP, 19)
    };
    assert_eq!(
        run(&mut h, &r, &[by_op]),
        [(19, 0, 0), (18, neg(ECANCELED), 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[cancel(0, ANY, 20)]),
        [(20, 1, 0), (15, neg(ECANCELED), 0)]
    );
    // No such file (EBADF), or no registered one.
    let bad_fd = Sqe {
        fd: 999,
        ..cancel(0, FD, 21)
    };
    let bad_fixed = Sqe {
        fd: 0,
        ..cancel(0, FD | FD_FIXED, 22)
    };
    assert_eq!(
        run(&mut h, &r, &[bad_fd, bad_fixed]),
        [(21, neg(EBADF), 0), (22, neg(EBADF), 0)]
    );
    // io_async_cancel_prep.
    for (s, e) in [
        (
            Sqe {
                off: 1,
                ..cancel(1, 0, 23)
            },
            EINVAL,
        ),
        (
            Sqe {
                file_index: 1,
                ..cancel(1, 0, 24)
            },
            EINVAL,
        ),
        (cancel(1, 1 << 6, 25), EINVAL),
        (cancel(1, ANY | FD, 26), EINVAL),
        (cancel(1, ANY | OP, 27), EINVAL),
    ] {
        r.push(&h, s);
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
        assert_eq!(r.reap(&h), [(s.user_data, neg(e), 0)], "{s:?}");
    }
}

#[test]
fn sync_cancel_cancels_through_registration() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let (rd, _wr) = pipe(&mut h);
    let reg = h.scratch + CANCEL_REG;
    let args = |h: &Harness, addr: u64, flags: u32, pad: u8| {
        let mut b = [0u8; 64];
        b[..8].copy_from_slice(&addr.to_le_bytes());
        b[12..16].copy_from_slice(&flags.to_le_bytes());
        b[33] = pad;
        put(h, reg, &b);
    };
    assert_eq!(run(&mut h, &r, &[poll(rd, 1)]), []);
    args(&h, 1, 0, 0);
    let sync = |h: &mut Harness, nr: u64| {
        h.call(
            Sysno::IoUringRegister,
            &[r.fd, REGISTER_SYNC_CANCEL, reg, nr],
        )
    };
    assert_eq!(sync(&mut h, 1), 0);
    // The poll's task work runs as the call returns.
    assert_eq!(r.reap(&h), [(1, neg(ECANCELED), 0)]);
    assert_eq!(sync(&mut h, 1), -(ENOENT as i64));
    assert_eq!(sync(&mut h, 2), -(EINVAL as i64));
    args(&h, 1, 1 << 6, 0);
    assert_eq!(sync(&mut h, 1), -(EINVAL as i64));
    args(&h, 1, 0, 1);
    assert_eq!(sync(&mut h, 1), -(EINVAL as i64));
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, REGISTER_SYNC_CANCEL, 16, 1]),
        -(EFAULT as i64)
    );
}

#[test]
fn timers_do_not_outlive_exec_or_cross_fork() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let b = h.scratch;
    times(&h);
    let r = setup(&mut h, 8, 0, 0);
    let (rd, _wr) = pipe(&mut h);
    let t = linked(timeout(b, LONG, 0, 0, 1));
    assert_eq!(run(&mut h, &r, &[t, Sqe::nop(2), poll(rd, 3)]), []);
    // io_poll_remove_all, then io_kill_timeouts; then the links.
    crate::user::linux::syscall::uring::exec_cancel(&mut h.proc.state);
    assert_eq!(
        r.reap(&h),
        [
            (3, neg(ECANCELED), 0),
            (1, neg(ECANCELED), 0),
            (2, neg(ECANCELED), 0)
        ]
    );
    assert!(h.proc.state.uring_parked.is_empty());
    // A sleeping call wakes as the timer expires.
    assert_eq!(run(&mut h, &r, &[timeout(b, SHORT, 0, 0, 4)]), []);
    let (other, _ow) = pipe(&mut h);
    let buf = h.scratch + 0xd00;
    assert_eq!(h.start(0, Sysno::Read, &[other, buf, 1]), None);
    let deadline = h.proc.threads[0].blocked.as_ref().unwrap().wait.deadline;
    assert!(
        deadline
            .is_some_and(|d| d <= std::time::Instant::now() + std::time::Duration::from_millis(3))
    );
    // A forked child has none of its parent's timers.
    let mut h = Harness::new(LinuxAbi::X86_64);
    let b = h.scratch;
    times(&h);
    let r = setup(&mut h, 8, 0, 0);
    let t = linked(poll(rd_of(&mut h), 5));
    assert_eq!(
        run(
            &mut h,
            &r,
            &[timeout(b, LONG, 0, 0, 6), t, link_timeout(b, LONG, 7)]
        ),
        []
    );
    crate::user::linux::syscall::uring::forked(&mut h.proc.state);
    let rs = r.state(&h);
    let st = rs.state();
    assert!(st.timeouts.is_empty() && st.ltimeouts.is_empty() && st.polls.is_empty());
    assert_eq!(st.live, 0);
}

fn rd_of(h: &mut Harness) -> u64 {
    pipe(h).0
}

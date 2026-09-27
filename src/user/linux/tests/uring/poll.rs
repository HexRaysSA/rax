//! io_uring's poll requests and its poll table (`io_uring/poll.c`, Linux
//! 6.19).

use super::*;

// Operations.
const POLL_ADD: u8 = 6;
const POLL_REMOVE: u8 = 7;
const READ: u8 = 22;
// IORING_POLL_*.
const ADD_MULTI: u32 = 1;
const UPDATE_EVENTS: u32 = 1 << 1;
const UPDATE_USER_DATA: u32 = 1 << 2;
const ADD_LEVEL: u32 = 1 << 3;
// Poll events.
const POLLIN: u32 = 0x1;
const POLLPRI: u32 = 0x2;
const POLLOUT: u32 = 0x4;
const POLLHUP: u32 = 0x10;
const POLLRDNORM: u32 = 0x40;
// IORING_CQE_F_MORE.
const MORE: u32 = 1 << 1;
const EFD_NONBLOCK: u64 = 0o4000;

fn run(h: &mut Harness, r: &Ring, sqes: &[Sqe]) -> Vec<(u64, i32, u32)> {
    for s in sqes {
        r.push(h, *s);
    }
    assert_eq!(r.enter(h, sqes.len() as u64, 0, 0), sqes.len() as i64);
    r.reap(h)
}

fn neg(e: i32) -> i32 {
    -e
}

/// A poll request for `events` of `fd`, with `flags` in `len`.
fn poll(fd: u64, events: u32, flags: u32, user_data: u64) -> Sqe {
    Sqe {
        opcode: POLL_ADD,
        fd: fd as i32,
        op_flags: events,
        len: flags,
        user_data,
        ..Sqe::default()
    }
}

/// A removal of the poll with user data `old`, updating as `flags` says.
fn remove(old: u64, flags: u32, new: u64, events: u32, user_data: u64) -> Sqe {
    Sqe {
        opcode: POLL_REMOVE,
        addr: old,
        off: new,
        len: flags,
        op_flags: events,
        user_data,
        ..Sqe::default()
    }
}

fn pipe(h: &mut Harness) -> (u64, u64) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Pipe2, &[at, 0]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn write(h: &mut Harness, fd: u64, b: &[u8]) {
    let at = h.scratch + 0xd00;
    put(h, at, b);
    assert_eq!(
        h.ok(Sysno::Write, &[fd, at, b.len() as u64]),
        b.len() as u64
    );
}

fn read(h: &mut Harness, fd: u64, n: u64) -> u64 {
    h.ok(Sysno::Read, &[fd, h.scratch + 0xd00, n])
}

fn eventfd(h: &mut Harness) -> u64 {
    h.ok(Sysno::Eventfd2, &[0, EFD_NONBLOCK])
}

/// fdinfo's `PollList` lines.
fn poll_list(h: &Harness, r: &Ring) -> String {
    let own = |_: i32| true;
    let text = String::from_utf8(
        crate::user::linux::fdinfo::fdinfo(&h.proc.state, &own, r.fd as i32).unwrap(),
    )
    .unwrap();
    let from = text.find("PollList:\n").unwrap() + "PollList:\n".len();
    let to = text.find("CqOverflowList:").unwrap();
    text[from..to].to_string()
}

#[test]
fn a_poll_completes_with_the_events_its_file_reports() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let r = setup(&mut h, 8, 0, 0);
        let (rd, wr) = pipe(&mut h);
        // Not ready: the request waits in the poll table.
        assert_eq!(run(&mut h, &r, &[poll(rd, POLLIN, 0, 1)]), []);
        assert_eq!(poll_list(&h, &r), "  op=6, task_works=0\n");
        // The write's wake-up completes it (mangle_poll(res & events)).
        write(&mut h, wr, b"ab");
        assert_eq!(r.reap(&h), [(1, POLLIN as i32, 0)], "{abi:?}");
        assert_eq!(poll_list(&h, &r), "");
        assert!(h.proc.state.uring_parked.is_empty());
        // Ready: at once, the events asked for; IO_POLL_UNMASK's always.
        assert_eq!(
            run(&mut h, &r, &[poll(rd, POLLIN | POLLRDNORM, 0, 2)]),
            [(2, (POLLIN | POLLRDNORM) as i32, 0)]
        );
        assert_eq!(
            run(&mut h, &r, &[poll(wr, POLLOUT, 0, 3)]),
            [(3, POLLOUT as i32, 0)]
        );
        read(&mut h, rd, 2);
        h.ok(Sysno::Close, &[wr]);
        assert_eq!(
            run(&mut h, &r, &[poll(rd, POLLIN, 0, 4)]),
            [(4, POLLHUP as i32, 0)]
        );
    });
}

#[test]
fn a_file_without_a_wait_queue_reports_at_once_or_never() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let path = h.scratch + 0xe00;
    put(&h, path, b"/tmp\0");
    let dir = h.ok(Sysno::Openat, &[-100i64 as u64, path, 0o200000, 0]);
    // DEFAULT_POLLMASK, as vfs_poll gives for a file without ->poll.
    assert_eq!(
        run(&mut h, &r, &[poll(dir, POLLIN | POLLOUT, 0, 1)]),
        [(1, (POLLIN | POLLOUT) as i32, 0)]
    );
    // Multishot too completes at once, and for good.
    assert_eq!(
        run(&mut h, &r, &[poll(dir, POLLIN, ADD_MULTI, 2)]),
        [(2, POLLIN as i32, 0)]
    );
    // Nothing it reports: no wait-queue entry, so EINVAL.
    assert_eq!(
        run(&mut h, &r, &[poll(dir, POLLPRI, 0, 3)]),
        [(3, neg(EINVAL), 0)]
    );
    // No such file: EBADF at issue.
    assert_eq!(
        run(&mut h, &r, &[poll(999, POLLIN, 0, 4)]),
        [(4, neg(EBADF), 0)]
    );
}

#[test]
fn poll_preparation_checks_the_request() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let (rd, _wr) = pipe(&mut h);
    let bad = [
        // io_poll_add_prep.
        Sqe {
            addr: 1,
            ..poll(rd, POLLIN, 0, 1)
        },
        Sqe {
            off: 1,
            ..poll(rd, POLLIN, 0, 2)
        },
        Sqe {
            buf_index: 1,
            ..poll(rd, POLLIN, 0, 3)
        },
        poll(rd, POLLIN, ADD_LEVEL, 4),
        poll(rd, POLLIN, UPDATE_EVENTS, 5),
        Sqe {
            flags: SKIP,
            ..poll(rd, POLLIN, ADD_MULTI, 6)
        },
        // io_poll_remove_prep.
        remove(1, ADD_MULTI, 0, 0, 7),
        remove(1, 1 << 4, 0, 0, 8),
        remove(1, 0, 5, 0, 9),
        remove(1, 0, 0, POLLIN, 10),
        Sqe {
            buf_index: 1,
            ..remove(1, 0, 0, 0, 11)
        },
        Sqe {
            file_index: 1,
            ..remove(1, 0, 0, 0, 12)
        },
    ];
    for s in bad {
        r.push(&h, s);
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
        assert_eq!(r.reap(&h), [(s.user_data, neg(EINVAL), 0)], "{s:?}");
    }
    assert_eq!(poll_list(&h, &r), "");
}

#[test]
fn a_multishot_poll_reports_each_wake_up() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let r = setup(&mut h, 8, 0, 0);
        let (rd, wr) = pipe(&mut h);
        assert_eq!(run(&mut h, &r, &[poll(rd, POLLIN, ADD_MULTI, 1)]), []);
        // Each write wakes it (pipe_write wakes a polled pipe's readers
        // whether it was empty or not).
        write(&mut h, wr, b"a");
        assert_eq!(r.reap(&h), [(1, POLLIN as i32, MORE)], "{abi:?}");
        write(&mut h, wr, b"b");
        assert_eq!(r.reap(&h), [(1, POLLIN as i32, MORE)]);
        // A read wakes no reader, and the empty pipe reports nothing.
        read(&mut h, rd, 2);
        assert_eq!(r.reap(&h), []);
        write(&mut h, wr, b"c");
        assert_eq!(r.reap(&h), [(1, POLLIN as i32, MORE)]);
        // Removed: the removal's CQE, then the poll's (task work).
        assert_eq!(
            run(&mut h, &r, &[remove(1, 0, 0, 0, 2)]),
            [(2, 0, 0), (1, neg(ECANCELED), 0)]
        );
        assert!(h.proc.state.uring_parked.is_empty());
        // Ready as it is armed: the first report is task work at once.
        assert_eq!(
            run(&mut h, &r, &[poll(rd, POLLIN, ADD_MULTI, 3)]),
            [(3, POLLIN as i32, MORE)]
        );
        write(&mut h, wr, b"d");
        assert_eq!(r.reap(&h), [(3, POLLIN as i32, MORE)]);
        // The writer's close reports the hang-up too.
        h.ok(Sysno::Close, &[wr]);
        assert_eq!(r.reap(&h), [(3, (POLLIN | POLLHUP) as i32, MORE)]);
    });
}

#[test]
fn a_removal_finds_updates_or_cancels_a_poll() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let ev = eventfd(&mut h);
    let buf = h.anon(P, RW, false);
    let (rd, _wr) = pipe(&mut h);
    // io_poll_find: nothing with the user data.
    assert_eq!(
        run(&mut h, &r, &[remove(9, 0, 0, 0, 1)]),
        [(1, neg(ENOENT), 0)]
    );
    // A request waiting for its file is no poll request.
    let wait = Sqe {
        opcode: READ,
        fd: rd as i32,
        addr: buf,
        len: 4,
        off: u64::MAX,
        user_data: 9,
        ..Sqe::default()
    };
    assert_eq!(run(&mut h, &r, &[wait]), []);
    assert_eq!(
        run(&mut h, &r, &[remove(9, 0, 0, 0, 2)]),
        [(2, neg(ENOENT), 0)]
    );
    // The events updated (POLLOUT: an empty eventfd is writable), the
    // poll is armed again, and ready now, completes through task work.
    assert_eq!(run(&mut h, &r, &[poll(ev, POLLIN, 0, 3)]), []);
    assert_eq!(
        run(&mut h, &r, &[remove(3, UPDATE_EVENTS, 0, POLLOUT, 4)]),
        [(4, 0, 0), (3, POLLOUT as i32, 0)]
    );
    // The user data updated: the poll completes under the new one.
    assert_eq!(run(&mut h, &r, &[poll(ev, POLLIN, 0, 5)]), []);
    assert_eq!(
        run(&mut h, &r, &[remove(5, UPDATE_USER_DATA, 6, 0, 7)]),
        [(7, 0, 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[remove(5, 0, 0, 0, 8)]),
        [(8, neg(ENOENT), 0)]
    );
    write(&mut h, ev, &1u64.to_le_bytes());
    assert_eq!(r.reap(&h), [(6, POLLIN as i32, 0)]);
    // The newest of two with the same user data goes first.
    let (rd2, _wr2) = pipe(&mut h);
    assert_eq!(
        run(
            &mut h,
            &r,
            &[poll(rd, POLLIN, 0, 10), poll(rd2, POLLIN, 0, 10)]
        ),
        []
    );
    assert_eq!(
        run(&mut h, &r, &[remove(10, 0, 0, 0, 11)]),
        [(11, 0, 0), (10, neg(ECANCELED), 0)]
    );
    let rest = r.state(&h);
    let st = rest.state();
    let left: Vec<_> = st.polls.iter().filter(|p| !p.retry).collect();
    assert_eq!(left.len(), 1);
    assert!(std::ptr::eq(
        std::sync::Arc::as_ptr(&left[0].file),
        std::sync::Arc::as_ptr(&h.proc.state.fds.file(rd as i32).unwrap())
    ));
}

#[test]
fn a_poll_whose_task_work_is_queued_cannot_be_removed() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    let (rd, wr) = pipe(&mut h);
    assert_eq!(run(&mut h, &r, &[poll(rd, POLLIN, 0, 1)]), []);
    // The write wakes it; a deferring ring runs the task work only as it
    // waits, so the removal cannot take it (io_poll_disarm: EALREADY).
    write(&mut h, wr, b"x");
    assert_eq!(r.reap(&h), []);
    r.push(&h, remove(1, 0, 0, 0, 2));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(2, neg(EALREADY), 0)]);
    assert_eq!(r.enter(&mut h, 0, 1, GETEVENTS), 0);
    assert_eq!(r.reap(&h), [(1, POLLIN as i32, 0)]);
}

#[test]
fn a_poll_keeps_its_link() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let (rd, wr) = pipe(&mut h);
    let head = Sqe {
        flags: LINK,
        ..poll(rd, POLLIN, 0, 1)
    };
    assert_eq!(run(&mut h, &r, &[head, Sqe::nop(2)]), []);
    write(&mut h, wr, b"x");
    assert_eq!(r.reap(&h), [(1, POLLIN as i32, 0), (2, 0, 0)]);
    // Forced to the workers, it waits the same way.
    let async_poll = Sqe {
        flags: ASYNC,
        ..poll(rd, POLLOUT, 0, 3)
    };
    assert_eq!(run(&mut h, &r, &[async_poll]), []);
    h.ok(Sysno::Close, &[wr]);
    assert_eq!(r.reap(&h), [(3, POLLHUP as i32, 0)]);
    // Cancelled as the task execs, with its link.
    let (rd, _wr) = pipe(&mut h);
    let head = Sqe {
        flags: LINK,
        ..poll(rd, POLLIN, ADD_MULTI, 4)
    };
    assert_eq!(run(&mut h, &r, &[head, Sqe::nop(5)]), []);
    crate::user::linux::syscall::uring::exec_cancel(&mut h.proc.state);
    assert_eq!(r.reap(&h), [(4, neg(ECANCELED), 0), (5, neg(ECANCELED), 0)]);
    // A forked child has none of its parent's polls.
    assert_eq!(run(&mut h, &r, &[poll(rd, POLLIN, 0, 6)]), []);
    crate::user::linux::syscall::uring::forked(&mut h.proc.state);
    assert!(r.state(&h).state().polls.is_empty());
    assert_eq!(r.reap(&h), []);
}

#[test]
fn fdinfo_lists_the_poll_table_by_hash_bucket() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    // 16 CQ entries: one hash bit (ilog2(16) - 5, at least 1); hash_64
    // puts user data 1, 3, and 6 in bucket 0, and 2 and 4 in bucket 1.
    let r = setup(&mut h, 8, 0, 0);
    let buf = h.anon(P, RW, false);
    let (rd, _wr) = pipe(&mut h);
    let read = |user_data| Sqe {
        opcode: READ,
        fd: rd as i32,
        addr: buf,
        len: 4,
        off: u64::MAX,
        user_data,
        ..Sqe::default()
    };
    let sqes = [
        poll(rd, POLLIN, 0, 1),
        read(2),
        poll(rd, POLLIN, 0, 3),
        poll(rd, POLLIN, 0, 4),
        read(6),
    ];
    assert_eq!(run(&mut h, &r, &sqes), []);
    // Each bucket newest first: 6, 3, 1; then 4, 2.
    assert_eq!(
        poll_list(&h, &r),
        "  op=22, task_works=0\n  op=6, task_works=0\n  op=6, task_works=0\n  \
         op=6, task_works=0\n  op=22, task_works=0\n"
    );
}

#[test]
fn a_wake_up_of_io_urings_own_ends_a_multishot_poll() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let ev = eventfd(&mut h);
    // Written by the process, the eventfd wakes a multishot poll each time.
    assert_eq!(run(&mut h, &r, &[poll(ev, POLLIN, ADD_MULTI, 1)]), []);
    write(&mut h, ev, &1u64.to_le_bytes());
    assert_eq!(r.reap(&h), [(1, POLLIN as i32, MORE)]);
    write(&mut h, ev, &1u64.to_le_bytes());
    assert_eq!(r.reap(&h), [(1, POLLIN as i32, MORE)]);
    // Registered, it counts the ring's completions with EPOLL_URING_WAKE:
    // the poll reports that once more and leaves the wait queue.
    let (rd, _wr) = pipe(&mut h);
    let p = h.scratch + 0x300;
    put(&h, p, &(ev as u32).to_le_bytes());
    h.ok(Sysno::IoUringRegister, &[r.fd, REGISTER_EVENTFD, p, 1]);
    h.ok(Sysno::Read, &[ev, h.scratch + 0xd00, 8]);
    assert_eq!(run(&mut h, &r, &[poll(rd, POLLIN, ADD_MULTI, 2)]), []);
    assert_eq!(
        run(&mut h, &r, &[Sqe::nop(3)]),
        [(3, 0, 0), (1, POLLIN as i32, MORE)]
    );
    assert_eq!(run(&mut h, &r, &[Sqe::nop(4)]), [(4, 0, 0)]);
    write(&mut h, ev, &1u64.to_le_bytes());
    assert_eq!(r.reap(&h), []);
    // Still in the table: a removal cancels it.
    assert_eq!(
        run(&mut h, &r, &[remove(1, 0, 0, 0, 5)]),
        [(5, 0, 0), (1, neg(ECANCELED), 0)]
    );
}

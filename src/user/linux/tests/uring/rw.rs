//! io_uring's reads and writes, the file operations that move no data,
//! and requests that wait for their files (`io_uring/rw.c`, `sync.c`,
//! `advise.c`, `truncate.c`, `poll.c`, Linux 6.19).

use super::*;
use crate::user::linux::signal::{SIGPIPE, SigPending, sa};

// Operations.
const READV_OP: u8 = 1;
const WRITEV: u8 = 2;
const FSYNC: u8 = 3;
const READ_FIXED: u8 = 4;
const WRITE_FIXED: u8 = 5;
const SYNC_FILE_RANGE: u8 = 8;
const FALLOCATE: u8 = 17;
const READ: u8 = 22;
const WRITE: u8 = 23;
const FADVISE: u8 = 24;
const MADVISE: u8 = 25;
const FTRUNCATE: u8 = 55;
const READV_FIXED: u8 = 60;
const WRITEV_FIXED: u8 = 61;
// IOSQE_FIXED_FILE; the registrations.
const FIXED_FILE: u8 = 1;
const REGISTER_BUFFERS: u64 = 0;
const REGISTER_FILES2: u64 = 13;
const REGISTER_FILES_UPDATE2: u64 = 14;
// RWF_*.
const RWF_HIPRI: u32 = 0x1;
const RWF_NOWAIT: u32 = 0x8;
const RWF_APPEND: u32 = 0x10;
const RWF_NOAPPEND: u32 = 0x20;
const RWF_ATOMIC: u32 = 0x40;
const RWF_NOSIGNAL: u32 = 0x100;
// Open flags (x86-64).
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_NONBLOCK: u64 = 0o4000;
const O_DIRECTORY: u64 = 0o200000;
const O_PATH: u64 = 0o10000000;
const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const MADV_DONTNEED: u64 = 4;

/// A transfer's SQE.
fn rw(opcode: u8, fd: u64, addr: u64, len: u32, off: i64, user_data: u64) -> Sqe {
    Sqe {
        opcode,
        fd: fd as i32,
        addr,
        len,
        off: off as u64,
        user_data,
        ..Sqe::default()
    }
}

/// Submits `sqes` in one call (all taken) and reaps.
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

fn bytes(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    b
}

fn pipe(h: &mut Harness, flags: u64) -> (u64, u64) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Pipe2, &[at, flags]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn open(h: &mut Harness, path: &str, flags: u64) -> u64 {
    let at = h.scratch + 0xe00;
    put(h, at, format!("{path}\0").as_bytes());
    h.ok(Sysno::Openat, &[-100i64 as u64, at, flags, 0])
}

fn write(h: &mut Harness, fd: u64, b: &[u8]) {
    let at = h.scratch + 0xd00;
    put(h, at, b);
    assert_eq!(
        h.ok(Sysno::Write, &[fd, at, b.len() as u64]),
        b.len() as u64
    );
}

fn size(h: &Harness, fd: u64) -> u64 {
    let file = h.proc.state.fds.file(fd as i32).unwrap();
    match &file.object {
        crate::user::linux::fs::fd::FileObject::Host(f) => f.metadata().unwrap().len(),
        _ => panic!("not a host file"),
    }
}

fn put_iovs(h: &Harness, at: u64, iovs: &[(u64, u64)]) {
    let b: Vec<u8> = iovs
        .iter()
        .flat_map(|&(base, len)| [base.to_le_bytes(), len.to_le_bytes()].concat())
        .collect();
    put(h, at, &b);
}

#[test]
fn transfers_on_a_regular_file() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let fd = h.file("uring-rw", 10, b'a', O_RDWR);
    let buf = h.anon(P, RW, false);
    // io_write at an offset; io_read of the whole file.
    put(&h, buf, b"xyz");
    assert_eq!(run(&mut h, &r, &[rw(WRITE, fd, buf, 3, 2, 1)]), [(1, 3, 0)]);
    assert_eq!(
        run(&mut h, &r, &[rw(READ, fd, buf + 0x100, 10, 0, 2)]),
        [(2, 10, 0)]
    );
    assert_eq!(bytes(&h, buf + 0x100, 10), b"aaxyzaaaaa");
    // Offset -1: the file position, which the transfer moves.
    h.ok(Sysno::Lseek, &[fd, 4, SEEK_SET]);
    assert_eq!(
        run(&mut h, &r, &[rw(READ, fd, buf + 0x200, 3, -1, 3)]),
        [(3, 3, 0)]
    );
    assert_eq!(bytes(&h, buf + 0x200, 3), b"zaa");
    assert_eq!(h.ok(Sysno::Lseek, &[fd, 0, SEEK_CUR]), 7);
    // __io_complete_rw_common: fewer bytes than asked fails the request,
    // and so its link (the next request is then task work).
    let short = Sqe {
        flags: LINK,
        ..rw(READ, fd, buf, 5, 8, 4)
    };
    assert_eq!(
        run(&mut h, &r, &[short, Sqe::nop(5)]),
        [(4, 2, 0), (5, neg(ECANCELED), 0)]
    );
    // At the end, nothing; asking for nothing is not short.
    let empty = Sqe {
        flags: LINK,
        ..rw(READ, fd, buf, 0, 10, 6)
    };
    assert_eq!(
        run(&mut h, &r, &[empty, Sqe::nop(7)]),
        [(6, 0, 0), (7, 0, 0)]
    );
    let end = Sqe {
        flags: LINK,
        ..rw(READ, fd, buf, 4, 10, 8)
    };
    assert_eq!(
        run(&mut h, &r, &[end, Sqe::nop(9)]),
        [(8, 0, 0), (9, neg(ECANCELED), 0)]
    );
    // Writing at the position moves it too.
    h.ok(Sysno::Lseek, &[fd, 0, SEEK_SET]);
    assert_eq!(
        run(&mut h, &r, &[rw(WRITE, fd, buf, 3, -1, 10)]),
        [(10, 3, 0)]
    );
    assert_eq!(h.ok(Sysno::Lseek, &[fd, 0, SEEK_CUR]), 3);
}

#[test]
fn vectored_and_registered_buffer_transfers() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let fd = h.file("uring-rwv", 16, b'0', O_RDWR);
    let buf = h.anon(2 * P, RW, false);
    let iovs = h.anon(P, RW, false);
    put(&h, buf, b"ABCDEFGH");
    // io_prep_rwv: one transfer gathered and scattered over the vectors.
    put_iovs(&h, iovs, &[(buf, 3), (buf + 5, 3)]);
    assert_eq!(
        run(&mut h, &r, &[rw(WRITEV, fd, iovs, 2, 0, 1)]),
        [(1, 6, 0)]
    );
    put_iovs(&h, iovs, &[(buf + 0x100, 4), (buf + 0x200, 4)]);
    assert_eq!(
        run(&mut h, &r, &[rw(READV_OP, fd, iovs, 2, 0, 2)]),
        [(2, 8, 0)]
    );
    assert_eq!(bytes(&h, buf + 0x100, 4), b"ABCF");
    assert_eq!(bytes(&h, buf + 0x200, 4), b"GH00");
    // io_import_reg_buf: without a registered buffer EFAULT; then within
    // it only.
    let fixed = |op: u8, addr: u64, len: u32, index: u16, ud: u64| Sqe {
        buf_index: index,
        ..rw(op, fd, addr, len, 0, ud)
    };
    assert_eq!(
        run(&mut h, &r, &[fixed(READ_FIXED, buf, 4, 0, 3)]),
        [(3, neg(EFAULT), 0)]
    );
    put_iovs(&h, iovs, &[(buf, P)]);
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, REGISTER_BUFFERS, iovs, 1]),
        0
    );
    assert_eq!(
        run(&mut h, &r, &[fixed(READ_FIXED, buf + 10, 4, 0, 4)]),
        [(4, 4, 0)]
    );
    assert_eq!(bytes(&h, buf + 10, 4), b"ABCF");
    let refused = [
        fixed(READ_FIXED, buf - 1, 4, 0, 5),
        fixed(READ_FIXED, buf + P - 2, 4, 0, 6),
        fixed(WRITE_FIXED, buf, 4, 1, 7),
    ];
    for s in refused {
        assert_eq!(run(&mut h, &r, &[s]), [(s.user_data, neg(EFAULT), 0)]);
    }
    assert_eq!(
        run(&mut h, &r, &[fixed(WRITE_FIXED, buf + 10, 2, 0, 8)]),
        [(8, 2, 0)]
    );
    // io_import_reg_vec: each vector within the buffer and not empty; a
    // length too long to count in pages overflows.
    let vfixed = |op: u8, n: u32, ud: u64| Sqe {
        buf_index: 0,
        ..rw(op, fd, iovs + 0x100, n, 0, ud)
    };
    put_iovs(&h, iovs + 0x100, &[(buf + 0x300, 2), (buf + 0x310, 2)]);
    assert_eq!(run(&mut h, &r, &[vfixed(READV_FIXED, 2, 9)]), [(9, 4, 0)]);
    assert_eq!(bytes(&h, buf + 0x300, 2), b"AB");
    assert_eq!(bytes(&h, buf + 0x310, 2), b"CF");
    assert_eq!(
        run(&mut h, &r, &[vfixed(WRITEV_FIXED, 2, 10)]),
        [(10, 4, 0)]
    );
    for (iov, e) in [
        ((buf, 0), EFAULT),
        ((buf + P - 1, 2), EFAULT),
        ((buf, 1 << 62), EOVERFLOW),
        // io_vec_realloc: 524289 bio_vecs are more than kmalloc gives.
        ((buf, 0x7fff_ffff), ENOMEM),
    ] {
        put_iovs(&h, iovs + 0x100, &[iov]);
        assert_eq!(
            run(&mut h, &r, &[vfixed(READV_FIXED, 1, 11)]),
            [(11, neg(e), 0)],
            "{iov:x?}"
        );
    }
}

#[test]
fn transfers_check_the_request_and_the_file() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let fd = h.file("uring-chk", 8, b'x', O_RDWR);
    let ro = h.file("uring-chk-ro", 8, b'x', O_RDONLY);
    let wo = h.file("uring-chk-wo", 8, b'x', O_WRONLY);
    let buf = h.anon(P, RW, false);
    let path = open(&mut h, "/", O_PATH);
    let dir = open(&mut h, "/", O_RDONLY | O_DIRECTORY);
    let ep = h.ok(Sysno::EpollCreate1, &[0]);
    let flagged = |flags: u32, ud: u64| Sqe {
        op_flags: flags,
        ..rw(READ, fd, buf, 4, 0, ud)
    };
    // Issue: io_assign_file, io_rw_init_file (the mode, kiocb_set_rw_flags,
    // RWF_HIPRI without polling, protection information), rw_verify_area,
    // then a file without the operation.
    let refused = [
        (rw(READ, 99, buf, 4, 0, 1), EBADF),
        (rw(READ, path, buf, 4, 0, 2), EBADF),
        (rw(READ, wo, buf, 4, 0, 3), EBADF),
        (rw(WRITE, ro, buf, 4, 0, 4), EBADF),
        (flagged(RWF_HIPRI, 5), EINVAL),
        (flagged(0x1000, 6), EOPNOTSUPP),
        (flagged(RWF_APPEND | RWF_NOAPPEND, 7), EINVAL),
        (flagged(RWF_ATOMIC, 8), EOPNOTSUPP),
        (rw(READ, fd, buf, 4, -2, 9), EINVAL),
        (rw(READ, fd, buf, 4, i64::MAX - 2, 10), EINVAL),
        (rw(READ, ep, buf, 4, 0, 11), EINVAL),
        (rw(READ, dir, buf, 4, 0, 12), EISDIR),
        (rw(READ, fd, 0x10_0000, 4, 0, 13), EFAULT),
        (
            Sqe {
                flags: BUFFER_SELECT,
                ..rw(READ, fd, 0, 4, 0, 14)
            },
            ENOBUFS,
        ),
        (
            Sqe {
                pad2: 1,
                addr3: buf + 0x800,
                ..rw(READ, fd, buf, 4, 0, 15)
            },
            EINVAL,
        ),
    ];
    // Protection information: rsvd zero, its buffer in user space.
    let mut pi = [0u8; 32];
    pi[4..8].copy_from_slice(&16u32.to_le_bytes());
    pi[8..16].copy_from_slice(&(buf + 0x900).to_le_bytes());
    put(&h, buf + 0x800, &pi);
    for (s, e) in refused {
        assert_eq!(run(&mut h, &r, &[s]), [(s.user_data, neg(e), 0)], "{s:?}");
    }
    // Preparation: the I/O priority, an attribute other than protection
    // information, a buffer beyond user space; with a buffer group, one
    // vector (and none for a fixed read, whose operation has no groups).
    let prep = [
        (
            Sqe {
                ioprio: 7 << 13,
                ..rw(READ, fd, buf, 4, 0, 21)
            },
            EINVAL,
        ),
        (
            Sqe {
                pad2: 2,
                ..rw(READ, fd, buf, 4, 0, 22)
            },
            EINVAL,
        ),
        (rw(READ, fd, 1 << 63, 4, 0, 23), EFAULT),
        (
            Sqe {
                flags: BUFFER_SELECT,
                ..rw(READV_OP, fd, buf, 2, 0, 24)
            },
            EINVAL,
        ),
        (
            Sqe {
                flags: BUFFER_SELECT,
                ..rw(READ_FIXED, fd, buf, 4, 0, 25)
            },
            EOPNOTSUPP,
        ),
    ];
    for (s, e) in prep {
        r.push(&h, s);
        r.push(&h, Sqe::nop(99));
        // A request failing its preparation ends the submission.
        assert_eq!(r.enter(&mut h, 2, 0, 0), 1, "{s:?}");
        assert_eq!(r.reap(&h), [(s.user_data, neg(e), 0)], "{s:?}");
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
        assert_eq!(r.reap(&h), [(99, 0, 0)]);
    }
}

#[test]
fn a_transfer_waits_for_its_file() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let buf = h.anon(P, RW, false);
    // O_NONBLOCK does not stop the wait (io_rw_init_file: pipes support
    // FMODE_NOWAIT).
    let (rd, wr) = pipe(&mut h, O_NONBLOCK);
    assert_eq!(run(&mut h, &r, &[rw(READ, rd, buf, 8, -1, 1)]), []);
    assert_eq!(h.proc.state.uring_parked.len(), 1);
    // The write's wake-up retries the read as the write returns.
    write(&mut h, wr, b"abc");
    assert_eq!(r.reap(&h), [(1, 3, 0)]);
    assert_eq!(bytes(&h, buf, 3), b"abc");
    assert!(h.proc.state.uring_parked.is_empty());
    // RWF_NOWAIT: EAGAIN at once.
    let nowait = Sqe {
        op_flags: RWF_NOWAIT,
        ..rw(READ, rd, buf, 8, -1, 2)
    };
    assert_eq!(run(&mut h, &r, &[nowait]), [(2, neg(EAGAIN), 0)]);
    // A link waits with its head; any offset but a negative one reads a
    // pipe from its start.
    let head = Sqe {
        flags: LINK,
        ..rw(READ, rd, buf, 4, 0, 3)
    };
    assert_eq!(run(&mut h, &r, &[head, Sqe::nop(4)]), []);
    write(&mut h, wr, b"wxyz");
    assert_eq!(r.reap(&h), [(3, 4, 0), (4, 0, 0)]);
    assert_eq!(
        run(&mut h, &r, &[rw(READ, rd, buf, 4, -5, 5)]),
        [(5, neg(EINVAL), 0)]
    );
    // A write waits for room.
    let fill = vec![b'f'; 4096];
    put(&h, buf, &fill);
    while h.call(Sysno::Write, &[wr, buf, 4096]) > 0 {}
    assert_eq!(run(&mut h, &r, &[rw(WRITE, wr, buf, 10, -1, 6)]), []);
    // (A whole page frees room on a Linux host's pipe too.)
    assert_eq!(h.ok(Sysno::Read, &[rd, buf + 0x800, 2048]), 2048);
    assert_eq!(h.ok(Sysno::Read, &[rd, buf + 0x800, 2048]), 2048);
    assert_eq!(r.reap(&h), [(6, 10, 0)]);
    // A deferring ring retries only in its waits.
    let d = setup(&mut h, 4, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    let (rd2, wr2) = pipe(&mut h, 0);
    assert_eq!(run(&mut h, &d, &[rw(READ, rd2, buf, 8, -1, 7)]), []);
    write(&mut h, wr2, b"12");
    assert_eq!(d.reap(&h), []);
    assert_eq!(d.enter(&mut h, 0, 1, GETEVENTS), 0);
    assert_eq!(d.reap(&h), [(7, 2, 0)]);
}

#[test]
fn a_sleeping_call_wakes_for_a_waiting_request() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    let buf = h.anon(P, RW, false);
    let (rd, _wr) = pipe(&mut h, 0);
    let (other, _ow) = pipe(&mut h, 0);
    assert_eq!(run(&mut h, &r, &[rw(READ, rd, buf, 8, -1, 1)]), []);
    // A read of another empty pipe sleeps, and on the parked pipe too.
    assert_eq!(h.start(0, Sysno::Read, &[other, buf, 1]), None);
    let file = h.proc.state.fds.file(rd as i32).unwrap();
    let raw = crate::user::linux::syscall::ready::raw_fd(&file).unwrap();
    let blocked = h.proc.threads[0].blocked.as_ref().unwrap();
    assert!(
        blocked
            .wait
            .fds
            .iter()
            .any(|&(fd, readable, _)| fd == raw && readable),
        "{:?}",
        blocked.wait.fds
    );
}

#[test]
fn a_write_without_readers_fails_through_task_work() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let buf = h.anon(P, RW, false);
    let (rd, wr) = pipe(&mut h, 0);
    h.ok(Sysno::Close, &[rd]);
    // Handle SIGPIPE, so its delivery is only pending.
    let act = h.scratch + 0xc00;
    let b: Vec<u8> = [0x40_1000u64, sa::RESTORER, 0x40_1100, 0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    put(&h, act, &b);
    h.ok(Sysno::RtSigaction, &[SIGPIPE as u64, act, 0, 8]);
    // io_rw_done: after the inline NOP; pipe_write raises SIGPIPE unless
    // RWF_NOSIGNAL.
    let quiet = Sqe {
        op_flags: RWF_NOSIGNAL,
        ..rw(WRITE, wr, buf, 1, -1, 1)
    };
    assert_eq!(
        run(&mut h, &r, &[quiet, Sqe::nop(2)]),
        [(2, 0, 0), (1, neg(EPIPE), 0)]
    );
    assert!(!h.proc.threads[0].pending.contains(SIGPIPE));
    assert_eq!(
        run(&mut h, &r, &[rw(WRITE, wr, buf, 1, -1, 3)]),
        [(3, neg(EPIPE), 0)]
    );
    assert!(h.proc.threads[0].pending.contains(SIGPIPE));
    h.proc.threads[0].pending = SigPending::new();
}

#[test]
fn registered_files_serve_transfers() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let buf = h.anon(P, RW, false);
    let fd = h.file("uring-fixed", 8, b'q', O_RDWR);
    let (rd, wr) = pipe(&mut h, 0);
    let fds = buf + 0x800;
    put(
        &h,
        fds,
        &[(fd as u32).to_le_bytes(), (rd as u32).to_le_bytes()].concat(),
    );
    let tags = buf + 0x900;
    put(&h, tags, &[0u64.to_le_bytes(), 7u64.to_le_bytes()].concat());
    let mut rr = [0u8; 32];
    rr[0..4].copy_from_slice(&2u32.to_le_bytes());
    rr[16..24].copy_from_slice(&fds.to_le_bytes());
    rr[24..32].copy_from_slice(&tags.to_le_bytes());
    put(&h, buf + 0xa00, &rr);
    assert_eq!(
        h.call(
            Sysno::IoUringRegister,
            &[r.fd, REGISTER_FILES2, buf + 0xa00, 32]
        ),
        0
    );
    let fixed = |index: i32, ud: u64| Sqe {
        flags: FIXED_FILE,
        fd: index,
        ..rw(READ, 0, buf, 4, 0, ud)
    };
    assert_eq!(run(&mut h, &r, &[fixed(0, 1)]), [(1, 4, 0)]);
    assert_eq!(run(&mut h, &r, &[fixed(2, 2)]), [(2, neg(EBADF), 0)]);
    // A parked request holds its registered file's node: emptying the slot
    // posts the tag only once the request is done.
    assert_eq!(run(&mut h, &r, &[fixed(1, 3)]), []);
    let mut u = [0u8; 32];
    put(&h, fds, &(-1i32).to_le_bytes());
    u[0..4].copy_from_slice(&1u32.to_le_bytes());
    u[8..16].copy_from_slice(&fds.to_le_bytes());
    u[24..28].copy_from_slice(&1u32.to_le_bytes());
    put(&h, buf + 0xb00, &u);
    assert_eq!(
        h.call(
            Sysno::IoUringRegister,
            &[r.fd, REGISTER_FILES_UPDATE2, buf + 0xb00, 32]
        ),
        1
    );
    assert_eq!(r.reap(&h), []);
    write(&mut h, wr, b"12345");
    assert_eq!(r.reap(&h), [(3, 4, 0), (7, 0, 0)]);
}

#[test]
fn the_other_file_operations_run_on_the_workers() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let fd = h.file("uring-sync", 8, b's', O_RDWR);
    let ro = h.file("uring-sync-ro", 8, b's', O_RDONLY);
    let (rd, _wr) = pipe(&mut h, 0);
    let op = |opcode: u8, fd: u64, ud: u64| Sqe {
        opcode,
        fd: fd as i32,
        user_data: ud,
        ..Sqe::default()
    };
    // REQ_F_FORCE_ASYNC: after an inline request of the same submission.
    assert_eq!(
        run(&mut h, &r, &[op(FSYNC, fd, 1), Sqe::nop(2)]),
        [(2, 0, 0), (1, 0, 0)]
    );
    // io_fsync keeps its link going even when it fails.
    let failing = Sqe {
        flags: LINK,
        ..op(FSYNC, rd, 3)
    };
    assert_eq!(
        run(&mut h, &r, &[failing, Sqe::nop(4)]),
        [(3, neg(EINVAL), 0), (4, 0, 0)]
    );
    // io_fsync_prep, io_sfr_prep, io_fallocate_prep, io_ftruncate_prep:
    // the fields they do not use.
    for s in [
        Sqe {
            op_flags: 2,
            ..op(FSYNC, fd, 5)
        },
        Sqe {
            addr: 1,
            ..op(FSYNC, fd, 6)
        },
        Sqe {
            buf_index: 1,
            ..op(SYNC_FILE_RANGE, fd, 7)
        },
        Sqe {
            op_flags: 1,
            ..op(FALLOCATE, fd, 8)
        },
        Sqe {
            len: 1,
            ..op(FTRUNCATE, fd, 9)
        },
        Sqe {
            file_index: 1,
            ..op(MADVISE, 0, 10)
        },
    ] {
        assert_eq!(
            run(&mut h, &r, &[s]),
            [(s.user_data, neg(EINVAL), 0)],
            "{s:?}"
        );
    }
    // vfs_fallocate (the length in addr, the mode in len), do_ftruncate.
    let alloc = Sqe {
        addr: 100,
        ..op(FALLOCATE, fd, 11)
    };
    assert_eq!(run(&mut h, &r, &[alloc]), [(11, 0, 0)]);
    assert_eq!(size(&h, fd), 100);
    let trunc = Sqe {
        off: 10,
        ..op(FTRUNCATE, fd, 12)
    };
    assert_eq!(run(&mut h, &r, &[trunc]), [(12, 0, 0)]);
    assert_eq!(size(&h, fd), 10);
    let trunc_ro = Sqe {
        off: 1,
        ..op(FTRUNCATE, ro, 13)
    };
    assert_eq!(run(&mut h, &r, &[trunc_ro]), [(13, neg(EINVAL), 0)]);
    // sync_file_range: a pipe is ESPIPE, unknown flags EINVAL.
    assert_eq!(
        run(&mut h, &r, &[op(SYNC_FILE_RANGE, fd, 14)]),
        [(14, 0, 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[op(SYNC_FILE_RANGE, rd, 15)]),
        [(15, neg(ESPIPE), 0)]
    );
    let sfr_flags = Sqe {
        op_flags: 8,
        ..op(SYNC_FILE_RANGE, fd, 16)
    };
    assert_eq!(run(&mut h, &r, &[sfr_flags]), [(16, neg(EINVAL), 0)]);
    // io_fadvise: inline for the read pattern; its failure fails its link.
    assert_eq!(
        run(&mut h, &r, &[op(FADVISE, fd, 17), Sqe::nop(18)]),
        [(17, 0, 0), (18, 0, 0)]
    );
    let bad_advice = Sqe {
        op_flags: 9,
        flags: LINK,
        ..op(FADVISE, fd, 19)
    };
    assert_eq!(
        run(&mut h, &r, &[bad_advice, Sqe::nop(20)]),
        [(19, neg(EINVAL), 0), (20, neg(ECANCELED), 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[op(FADVISE, rd, 21)]),
        [(21, neg(ESPIPE), 0)]
    );
    // do_madvise: the length in off (or len); MADV_DONTNEED drops the
    // page's contents.
    let page = h.anon(P, RW, false);
    put(&h, page, b"data");
    let dontneed = Sqe {
        addr: page,
        off: P,
        op_flags: MADV_DONTNEED as u32,
        ..op(MADVISE, 0, 22)
    };
    assert_eq!(run(&mut h, &r, &[dontneed]), [(22, 0, 0)]);
    assert_eq!(bytes(&h, page, 4), [0; 4]);
    let bad = Sqe {
        addr: page,
        len: P as u32,
        op_flags: 1000,
        ..op(MADVISE, 0, 23)
    };
    assert_eq!(run(&mut h, &r, &[bad]), [(23, neg(EINVAL), 0)]);
}

#[test]
fn waiting_requests_do_not_outlive_exec_or_cross_fork() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let buf = h.anon(P, RW, false);
    let (rd, _wr) = pipe(&mut h, 0);
    let head = Sqe {
        flags: LINK,
        ..rw(READ, rd, buf, 4, -1, 1)
    };
    assert_eq!(run(&mut h, &r, &[head, Sqe::nop(2)]), []);
    // io_uring_task_cancel: cancelled, and its link with it.
    crate::user::linux::syscall::uring::exec_cancel(&mut h.proc.state);
    assert_eq!(r.reap(&h), [(1, neg(ECANCELED), 0), (2, neg(ECANCELED), 0)]);
    assert!(h.proc.state.uring_parked.is_empty());
    // A forked child has none of its parent's requests.
    assert_eq!(run(&mut h, &r, &[rw(READ, rd, buf, 4, -1, 3)]), []);
    crate::user::linux::syscall::uring::forked(&mut h.proc.state);
    assert!(h.proc.state.uring_parked.is_empty());
    assert!(r.state(&h).state().parked.is_empty());
    assert_eq!(r.reap(&h), []);
}

#[test]
fn o_path_descriptors_are_not_files_to_io_uring() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    let buf = h.anon(P, RW, false);
    let path = open(&mut h, "/", O_PATH);
    // fget, as io_uring looks descriptors up, passes over O_PATH ones.
    put(&h, buf, &(path as u32).to_le_bytes());
    let register =
        |h: &mut Harness, op: u64, n: u64| h.call(Sysno::IoUringRegister, &[r.fd, op, buf, n]);
    assert_eq!(register(&mut h, 2, 1), -(EBADF as i64)); // IORING_REGISTER_FILES
    assert_eq!(register(&mut h, REGISTER_EVENTFD, 1), -(EBADF as i64));
    assert_eq!(
        h.call(Sysno::IoUringEnter, &[path, 0, 0, 0, 0, 0]),
        -(EBADF as i64)
    );
    let nop_file = Sqe {
        op_flags: NOP_FILE,
        fd: path as i32,
        flags: LINK,
        ..Sqe::nop(1)
    };
    assert_eq!(
        run(&mut h, &r, &[nop_file, Sqe::nop(2)]),
        [(1, 0, 0), (2, neg(ECANCELED), 0)]
    );
}

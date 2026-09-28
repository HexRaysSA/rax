//! io_uring's socket requests (`io_uring/net.c`, Linux 6.19).

use super::*;

// Operations.
const SENDMSG: u8 = 9;
const RECVMSG: u8 = 10;
const ACCEPT: u8 = 13;
const CONNECT: u8 = 16;
const SEND: u8 = 26;
const RECV: u8 = 27;
const SHUTDOWN: u8 = 34;
const SOCKET: u8 = 45;
const BIND: u8 = 56;
const LISTEN: u8 = 57;
const ASYNC_CANCEL: u8 = 14;
// IORING_RECVSEND_*, IORING_ACCEPT_*.
const POLL_FIRST: u16 = 1;
const RECV_MULTISHOT: u16 = 1 << 1;
const BUNDLE: u16 = 1 << 4;
const ACCEPT_MULTISHOT: u16 = 1;
const ACCEPT_DONTWAIT: u16 = 1 << 1;
// IORING_CQE_F_*.
const MORE: u32 = 1 << 1;
const SOCK_NONEMPTY: u32 = 1 << 2;
// Sockets.
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u32 = 0x40;
const MSG_WAITALL: u32 = 0x100;
const SHUT_WR: u32 = 1;
const REGISTER_FILES: u64 = 2;
const FILE_INDEX_ALLOC: u32 = u32::MAX;

// Scratch: data at 0x400, a second buffer at 0x500, a msghdr at 0x600,
// iovecs at 0x680, an address at 0x700 and its length at 0x780.
const DATA: u64 = 0x400;
const BUF: u64 = 0x500;
const MSG: u64 = 0x600;
const IOV: u64 = 0x680;
const ADDR: u64 = 0x700;
const ALEN: u64 = 0x780;

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

fn pair(h: &mut Harness, kind: u64) -> (u64, u64) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Socketpair, &[AF_UNIX, kind, 0, at]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn bytes(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    b
}

/// A send or receive of `len` bytes at `buf`.
fn sr(opcode: u8, fd: u64, buf: u64, len: u32, flags: u32, user_data: u64) -> Sqe {
    Sqe {
        opcode,
        fd: fd as i32,
        addr: buf,
        len,
        op_flags: flags,
        user_data,
        ..Sqe::default()
    }
}

fn op(opcode: u8, fd: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode,
        fd: fd as i32,
        user_data,
        ..Sqe::default()
    }
}

/// A `struct msghdr` at `MSG` with the vectors `iov` at `IOV`.
fn msghdr(h: &Harness, iov: &[(u64, u64)]) {
    let mut m = [0u8; 56];
    m[16..24].copy_from_slice(&(h.scratch + IOV).to_le_bytes());
    m[24..32].copy_from_slice(&(iov.len() as u64).to_le_bytes());
    put(h, h.scratch + MSG, &m);
    for (i, &(base, len)) in iov.iter().enumerate() {
        let mut v = [0u8; 16];
        v[..8].copy_from_slice(&base.to_le_bytes());
        v[8..].copy_from_slice(&len.to_le_bytes());
        put(h, h.scratch + IOV + 16 * i as u64, &v);
    }
}

/// An abstract Unix address `name`, its length.
fn unix_addr(h: &Harness, name: &[u8]) -> u64 {
    let mut a = vec![1u8, 0, 0];
    a.extend_from_slice(name);
    put(h, h.scratch + ADDR, &a);
    a.len() as u64
}

#[test]
fn sends_and_receives_on_a_socket_pair() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let s = h.scratch;
        let r = setup(&mut h, 8, 0, 0);
        let (a, b) = pair(&mut h, SOCK_STREAM);
        put(&h, s + DATA, b"hello");
        assert_eq!(
            run(&mut h, &r, &[sr(SEND, a, s + DATA, 5, 0, 1)]),
            [(1, 5, 0)],
            "{abi:?}"
        );
        // msg_inq: data left reports IORING_CQE_F_SOCK_NONEMPTY.
        assert_eq!(
            run(&mut h, &r, &[sr(RECV, b, s + BUF, 3, 0, 2)]),
            [(2, 3, SOCK_NONEMPTY)]
        );
        assert_eq!(
            run(&mut h, &r, &[sr(RECV, b, s + BUF + 3, 10, 0, 3)]),
            [(3, 2, 0)]
        );
        assert_eq!(bytes(&h, s + BUF, 5), b"hello");
        // Nothing to receive: the request waits, and the send wakes it
        // (its task work as the call returns).
        assert_eq!(
            run(
                &mut h,
                &r,
                &[
                    sr(RECV, b, s + BUF, 8, 0, 4),
                    sr(SEND, a, s + DATA, 2, 0, 5)
                ]
            ),
            [(5, 2, 0), (4, 2, 0)]
        );
        // MSG_DONTWAIT: -EAGAIN rather than waiting.
        assert_eq!(
            run(&mut h, &r, &[sr(RECV, b, s + BUF, 8, MSG_DONTWAIT, 6)]),
            [(6, neg(EAGAIN), 0)]
        );
    });
}

#[test]
fn waitall_counts_what_moved() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let (a, b) = pair(&mut h, SOCK_STREAM);
    put(&h, s + DATA, b"abcdef");
    assert_eq!(
        run(&mut h, &r, &[sr(RECV, b, s + BUF, 6, MSG_WAITALL, 1)]),
        []
    );
    h.ok(Sysno::Write, &[a, s + DATA, 3]);
    assert_eq!(r.reap(&h), []);
    h.ok(Sysno::Write, &[a, s + DATA + 3, 3]);
    assert_eq!(r.reap(&h), [(1, 6, 0)]);
    assert_eq!(bytes(&h, s + BUF, 6), b"abcdef");
    // Cancelled in part, it reports what it moved (io_sendrecv_fail).
    assert_eq!(
        run(&mut h, &r, &[sr(RECV, b, s + BUF, 6, MSG_WAITALL, 2)]),
        []
    );
    h.ok(Sysno::Write, &[a, s + DATA, 2]);
    let cancel = Sqe {
        opcode: ASYNC_CANCEL,
        addr: 2,
        user_data: 3,
        ..Sqe::default()
    };
    assert_eq!(run(&mut h, &r, &[cancel]), [(3, 0, 0), (2, 2, 0)]);
}

#[test]
fn messages_carry_vectors_and_flags() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let (a, b) = pair(&mut h, SOCK_DGRAM);
    put(&h, s + DATA, b"onetwo");
    msghdr(&h, &[(s + DATA, 3), (s + DATA + 3, 3)]);
    assert_eq!(
        run(&mut h, &r, &[sr(SENDMSG, a, s + MSG, 0, 0, 1)]),
        [(1, 6, 0)]
    );
    // A datagram longer than the vectors: MSG_TRUNC in msg_flags.
    msghdr(&h, &[(s + BUF, 2), (s + BUF + 2, 2)]);
    assert_eq!(
        run(&mut h, &r, &[sr(RECVMSG, b, s + MSG, 0, 0, 2)]),
        [(2, 4, 0)]
    );
    assert_eq!(bytes(&h, s + BUF, 4), b"onet");
    assert_eq!(u32_at(&h, s + MSG + 48), MSG_TRUNC);
    // The header and vectors are read as the request is prepared.
    msghdr(&h, &[(s + BUF, 8)]);
    put(&h, s + DATA, b"x");
    let recv = sr(RECVMSG, b, s + MSG, 0, 0, 3);
    r.push(&h, recv);
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), []);
    msghdr(&h, &[(s + BUF + 100, 8)]);
    h.ok(Sysno::Write, &[a, s + DATA, 1]);
    assert_eq!(r.reap(&h), [(3, 1, 0)]);
    assert_eq!(bytes(&h, s + BUF, 1), b"x");
}

#[test]
fn socket_preparation_checks_the_request() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let (a, _b) = pair(&mut h, SOCK_STREAM);
    let bad = [
        (
            Sqe {
                ioprio: 1 << 6,
                ..sr(SEND, a, s, 1, 0, 1)
            },
            EINVAL,
        ),
        (
            Sqe {
                ioprio: RECV_MULTISHOT,
                ..sr(SEND, a, s, 1, 0, 2)
            },
            EINVAL,
        ),
        (
            Sqe {
                file_index: 1 << 16,
                ..sr(SEND, a, s, 1, 0, 3)
            },
            EINVAL,
        ),
        (
            Sqe {
                off: s + ADDR,
                file_index: 200,
                ..sr(SEND, a, s, 1, 0, 4)
            },
            EINVAL,
        ),
        (
            Sqe {
                off: 1,
                ..sr(RECV, a, s, 1, 0, 5)
            },
            EINVAL,
        ),
        (
            Sqe {
                file_index: 1,
                ..sr(RECV, a, s, 1, 0, 6)
            },
            EINVAL,
        ),
        (
            Sqe {
                ioprio: RECV_MULTISHOT,
                ..sr(RECV, a, s, 1, 0, 7)
            },
            EINVAL,
        ),
        (
            Sqe {
                ioprio: BUNDLE,
                ..sr(SENDMSG, a, s + MSG, 0, 0, 8)
            },
            EINVAL,
        ),
        (
            Sqe {
                ioprio: BUNDLE,
                ..sr(RECVMSG, a, s + MSG, 0, 0, 9)
            },
            EINVAL,
        ),
        (
            Sqe {
                off: 1,
                ..sr(SENDMSG, a, s + MSG, 0, 0, 10)
            },
            EINVAL,
        ),
        (sr(RECVMSG, a, 16, 0, 0, 11), EFAULT),
        (
            Sqe {
                flags: BUFFER_SELECT,
                ..sr(SENDMSG, a, s + MSG, 0, 0, 12)
            },
            EOPNOTSUPP,
        ),
        (
            Sqe {
                len: 1,
                ..op(ACCEPT, a, 13)
            },
            EINVAL,
        ),
        (
            Sqe {
                ioprio: 1 << 3,
                ..op(ACCEPT, a, 14)
            },
            EINVAL,
        ),
        (
            Sqe {
                op_flags: 1,
                ..op(ACCEPT, a, 15)
            },
            EINVAL,
        ),
        (
            Sqe {
                file_index: 1,
                op_flags: 0o2000000,
                ..op(ACCEPT, a, 16)
            },
            EINVAL,
        ),
        (
            Sqe {
                file_index: 1,
                ioprio: ACCEPT_MULTISHOT,
                ..op(ACCEPT, a, 17)
            },
            EINVAL,
        ),
        (
            Sqe {
                addr: 1,
                ..op(SOCKET, AF_UNIX, 18)
            },
            EINVAL,
        ),
        (
            Sqe {
                off: SOCK_STREAM | 1 << 12,
                ..op(SOCKET, AF_UNIX, 19)
            },
            EINVAL,
        ),
        (
            Sqe {
                len: 1,
                ..op(CONNECT, a, 20)
            },
            EINVAL,
        ),
        (
            Sqe {
                addr: s + ADDR,
                off: 200,
                ..op(CONNECT, a, 21)
            },
            EINVAL,
        ),
        (
            Sqe {
                addr: 1,
                ..op(LISTEN, a, 22)
            },
            EINVAL,
        ),
        (
            Sqe {
                off: 1,
                ..op(SHUTDOWN, a, 23)
            },
            EINVAL,
        ),
    ];
    for (sqe, e) in bad {
        r.push(&h, sqe);
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
        assert_eq!(r.reap(&h), [(sqe.user_data, neg(e), 0)], "{sqe:?}");
    }
}

#[test]
fn transfers_check_the_socket_and_buffer_selection() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let (a, b) = pair(&mut h, SOCK_STREAM);
    let pipe = s + 0xf80;
    h.ok(Sysno::Pipe2, &[pipe, 0]);
    let rd = u64::from(u32_at(&h, pipe));
    assert_eq!(
        run(
            &mut h,
            &r,
            &[sr(RECV, rd, s + BUF, 4, 0, 1), sr(SEND, rd, s, 1, 0, 2)]
        ),
        [(1, neg(ENOTSOCK), 0), (2, neg(ENOTSOCK), 0)]
    );
    // No buffer can be provided: ENOBUFS from io_buffer_select, ENOENT
    // from io_buffers_select without the group.
    let select = |opcode, ud| Sqe {
        flags: BUFFER_SELECT,
        ..sr(opcode, b, 0, 4, 0, ud)
    };
    assert_eq!(
        run(&mut h, &r, &[select(RECV, 3), select(SEND, 4)]),
        [(3, neg(ENOBUFS), 0), (4, neg(ENOENT), 0)]
    );
    // IORING_RECVSEND_POLL_FIRST: waits first, though data is there.
    put(&h, s + DATA, b"zz");
    h.ok(Sysno::Write, &[a, s + DATA, 2]);
    let first = Sqe {
        ioprio: POLL_FIRST,
        ..sr(RECV, b, s + BUF, 4, 0, 5)
    };
    assert_eq!(run(&mut h, &r, &[first]), [(5, 2, 0)]);
    // SHUTDOWN's error keeps its link.
    let bad = Sqe {
        flags: LINK,
        len: 7,
        ..op(SHUTDOWN, a, 6)
    };
    let wr = Sqe {
        len: SHUT_WR,
        ..op(SHUTDOWN, a, 8)
    };
    assert_eq!(
        run(&mut h, &r, &[bad, Sqe::nop(7)]),
        [(6, neg(EINVAL), 0), (7, 0, 0)]
    );
    assert_eq!(run(&mut h, &r, &[wr]), [(8, 0, 0)]);
}

#[test]
fn sockets_are_made_bound_listened_connected_and_accepted() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let s = h.scratch;
        let r = setup(&mut h, 8, 0, 0);
        let name = format!("rax-uring-net-{}-{abi:?}", std::process::id());
        let alen = unix_addr(&h, name.as_bytes());
        let sock = |ud| Sqe {
            off: SOCK_STREAM,
            ..op(SOCKET, AF_UNIX, ud)
        };
        let got = run(&mut h, &r, &[sock(1), sock(2)]);
        let (lfd, cfd) = (got[0].1 as u64, got[1].1 as u64);
        assert!(lfd > 2 && cfd > lfd, "{got:?}");
        let bind = Sqe {
            addr: s + ADDR,
            off: alen,
            ..op(BIND, lfd, 3)
        };
        let listen = Sqe {
            len: 4,
            ..op(LISTEN, lfd, 4)
        };
        assert_eq!(run(&mut h, &r, &[bind, listen]), [(3, 0, 0), (4, 0, 0)]);
        // The accept waits; the connect completes and wakes it.
        put(&h, s + ALEN, &16u32.to_le_bytes());
        let accept = Sqe {
            addr: s + BUF,
            off: s + ALEN,
            ..op(ACCEPT, lfd, 5)
        };
        assert_eq!(run(&mut h, &r, &[accept]), []);
        let connect = Sqe {
            addr: s + ADDR,
            off: alen,
            ..op(CONNECT, cfd, 6)
        };
        let got = run(&mut h, &r, &[connect]);
        assert_eq!(got[0], (6, 0, 0), "{abi:?}");
        assert_eq!((got[1].0, got[1].2), (5, 0));
        assert!(got[1].1 > cfd as i32);
        // The peer's address: an unbound Unix socket's bare family.
        assert_eq!(u32_at(&h, s + ALEN), 2);
        // ACCEPT_DONTWAIT with nothing queued: -EAGAIN.
        let now = Sqe {
            ioprio: ACCEPT_DONTWAIT,
            ..op(ACCEPT, lfd, 7)
        };
        assert_eq!(run(&mut h, &r, &[now]), [(7, neg(EAGAIN), 0)]);
    });
}

#[test]
fn accepts_into_slots_and_many_at_once() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let name = format!("rax-uring-multi-{}", std::process::id());
    let alen = unix_addr(&h, name.as_bytes());
    let lfd = h.ok(Sysno::Socket, &[AF_UNIX, SOCK_STREAM, 0]);
    h.ok(Sysno::Bind, &[lfd, s + ADDR, alen]);
    h.ok(Sysno::Listen, &[lfd, 8]);
    let connect = |h: &mut Harness| {
        let c = h.ok(Sysno::Socket, &[AF_UNIX, SOCK_STREAM, 0]);
        h.ok(Sysno::Connect, &[c, s + ADDR, alen]);
    };
    // Sparse registered files; accepts into allocated slots.
    let files = [-1i32; 4];
    let mut b = Vec::new();
    for f in files {
        b.extend_from_slice(&f.to_le_bytes());
    }
    put(&h, s + DATA, &b);
    h.ok(Sysno::IoUringRegister, &[r.fd, REGISTER_FILES, s + DATA, 4]);
    connect(&mut h);
    let direct = Sqe {
        file_index: FILE_INDEX_ALLOC,
        ..op(ACCEPT, lfd, 1)
    };
    assert_eq!(run(&mut h, &r, &[direct]), [(1, 0, 0)]);
    // Multishot: each connection with IORING_CQE_F_MORE.
    let multi = Sqe {
        ioprio: ACCEPT_MULTISHOT,
        ..op(ACCEPT, lfd, 2)
    };
    assert_eq!(run(&mut h, &r, &[multi]), []);
    connect(&mut h);
    let got = r.reap(&h);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0, got[0].2), (2, MORE));
    connect(&mut h);
    let next = r.reap(&h);
    assert_eq!((next[0].0, next[0].2), (2, MORE));
    assert!(next[0].1 > got[0].1);
    // Cancelled, it ends without MORE.
    let cancel = Sqe {
        opcode: ASYNC_CANCEL,
        addr: 2,
        user_data: 3,
        ..Sqe::default()
    };
    assert_eq!(
        run(&mut h, &r, &[cancel]),
        [(3, 0, 0), (2, neg(ECANCELED), 0)]
    );
}

#[test]
fn tcp_connects_in_the_background_and_reports_its_queue() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let lfd = h.ok(Sysno::Socket, &[AF_INET, SOCK_STREAM, 0]);
    // 127.0.0.1, any port.
    put(
        &h,
        s + ADDR,
        &[2, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    h.ok(Sysno::Bind, &[lfd, s + ADDR, 16]);
    h.ok(Sysno::Listen, &[lfd, 8]);
    put(&h, s + ALEN, &16u32.to_le_bytes());
    h.ok(Sysno::Getsockname, &[lfd, s + ADDR, s + ALEN]);
    let connect = |ud| Sqe {
        addr: s + ADDR,
        off: 16,
        ..op(CONNECT, 0, ud)
    };
    let c1 = h.ok(Sysno::Socket, &[AF_INET, SOCK_STREAM, 0]);
    let c2 = h.ok(Sysno::Socket, &[AF_INET, SOCK_STREAM, 0]);
    let mut got = run(
        &mut h,
        &r,
        &[
            Sqe {
                fd: c1 as i32,
                ..connect(1)
            },
            Sqe {
                fd: c2 as i32,
                ..connect(2)
            },
        ],
    );
    while got.len() < 2 {
        got.extend(wait_one(&mut h, &r));
    }
    got.sort();
    assert_eq!(got, [(1, 0, 0), (2, 0, 0)]);
    // Two queued: the first accept says more are.
    let got = run(&mut h, &r, &[op(ACCEPT, lfd, 3), op(ACCEPT, lfd, 4)]);
    assert_eq!(got.len(), 2);
    assert_eq!((got[0].0, got[0].2), (3, SOCK_NONEMPTY));
    assert_eq!((got[1].0, got[1].2), (4, 0));
}

fn wait_one(h: &mut Harness, r: &Ring) -> Vec<(u64, i32, u32)> {
    r.enter(h, 0, 1, GETEVENTS);
    r.reap(h)
}

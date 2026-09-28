//! io_uring's provided buffers (`io_uring/kbuf.c`, Linux 6.19): groups of
//! provided buffers, buffer rings, and the requests that select from them.

use super::*;

// Operations.
const READV: u8 = 1;
const SENDMSG: u8 = 9;
const RECVMSG: u8 = 10;
const READ: u8 = 22;
const SEND: u8 = 26;
const RECV: u8 = 27;
const PROVIDE_BUFFERS: u8 = 31;
const REMOVE_BUFFERS: u8 = 32;
const READ_MULTISHOT: u8 = 49;
// io_uring_register.
const REGISTER_PBUF_RING: u64 = 22;
const UNREGISTER_PBUF_RING: u64 = 23;
const REGISTER_PBUF_STATUS: u64 = 26;
// IOU_PBUF_RING_*, IORING_OFF_PBUF_RING.
const RING_MMAP: u16 = 1;
const RING_INC: u16 = 2;
const OFF_PBUF_RING: u64 = 0x8000_0000;
// IORING_CQE_F_*.
const F_BUFFER: u32 = 1;
const MORE: u32 = 1 << 1;
const SOCK_NONEMPTY: u32 = 1 << 2;
const BUF_MORE: u32 = 1 << 4;
// IORING_RECVSEND_*.
const RECV_MULTISHOT: u16 = 1 << 1;
const BUNDLE: u16 = 1 << 4;
// Sockets and files.
const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0o4000;
const MSG_TRUNC: u32 = 0x20;
const O_WRONLY: u64 = 1;
const RWF_NOWAIT: u32 = 0x8;
const RLIMIT_MEMLOCK: usize = 8;

// Scratch: a struct io_uring_buf_reg at 0xa00, a struct io_uring_buf_status
// at 0xa40, iovecs at 0xa80, a msghdr at 0xac0, data at 0xb00, and
// provided buffers from 0xc00.
const REG: u64 = 0xa00;
const STATUS: u64 = 0xa40;
const IOV: u64 = 0xa80;
const MSG: u64 = 0xac0;
const DATA: u64 = 0xb00;
const BUFS: u64 = 0xc00;

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

fn reg(h: &mut Harness, fd: u64, op: u64, arg: u64, nr: u64) -> i64 {
    h.call(Sysno::IoUringRegister, &[fd, op, arg, nr])
}

/// `IORING_CQE_F_BUFFER` with the buffer's ID.
fn buf(bid: u16) -> u32 {
    F_BUFFER | u32::from(bid) << 16
}

fn provide(n: i32, addr: u64, len: u32, group: u16, bid: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode: PROVIDE_BUFFERS,
        fd: n,
        addr,
        len,
        off: bid,
        buf_index: group,
        user_data,
        ..Sqe::default()
    }
}

fn remove(n: i32, group: u16, user_data: u64) -> Sqe {
    Sqe {
        opcode: REMOVE_BUFFERS,
        fd: n,
        buf_index: group,
        user_data,
        ..Sqe::default()
    }
}

/// A request of `len` bytes on `fd` with a buffer of `group`.
fn select(opcode: u8, fd: u64, len: u32, group: u16, user_data: u64) -> Sqe {
    Sqe {
        opcode,
        flags: BUFFER_SELECT,
        fd: fd as i32,
        len,
        buf_index: group,
        user_data,
        ..Sqe::default()
    }
}

/// A `struct io_uring_buf_reg` at `REG`.
fn buf_reg(h: &Harness, ring_addr: u64, entries: u32, bgid: u16, flags: u16) {
    let mut b = [0u8; 40];
    b[..8].copy_from_slice(&ring_addr.to_le_bytes());
    b[8..12].copy_from_slice(&entries.to_le_bytes());
    b[12..14].copy_from_slice(&bgid.to_le_bytes());
    b[14..16].copy_from_slice(&flags.to_le_bytes());
    put(h, h.scratch + REG, &b);
}

fn register_ring(
    h: &mut Harness,
    r: &Ring,
    ring_addr: u64,
    entries: u32,
    bgid: u16,
    flags: u16,
) -> i64 {
    buf_reg(h, ring_addr, entries, bgid, flags);
    let arg = h.scratch + REG;
    reg(h, r.fd, REGISTER_PBUF_RING, arg, 1)
}

/// Ring entry `index` (`struct io_uring_buf`, less the first entry's
/// `resv`, which is the tail).
fn ring_buf(h: &Harness, ring: u64, index: u64, addr: u64, len: u32, bid: u16) {
    let mut b = [0u8; 14];
    b[..8].copy_from_slice(&addr.to_le_bytes());
    b[8..12].copy_from_slice(&len.to_le_bytes());
    b[12..14].copy_from_slice(&bid.to_le_bytes());
    put(h, ring + 16 * index, &b);
}

fn set_tail(h: &Harness, ring: u64, tail: u16) {
    put(h, ring + 14, &tail.to_le_bytes());
}

/// `IORING_REGISTER_PBUF_STATUS` for `group`: the head, or the error.
fn head(h: &mut Harness, r: &Ring, group: u32) -> Result<u32, i64> {
    let at = h.scratch + STATUS;
    let mut b = [0u8; 40];
    b[..4].copy_from_slice(&group.to_le_bytes());
    put(h, at, &b);
    match reg(h, r.fd, REGISTER_PBUF_STATUS, at, 1) {
        0 => Ok(u32_at(h, at + 4)),
        e => Err(e),
    }
}

fn bytes(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    b
}

fn pipe(h: &mut Harness) -> (u64, u64) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Pipe2, &[at, 0]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn pair(h: &mut Harness, kind: u64) -> (u64, u64) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Socketpair, &[AF_UNIX, kind, 0, at]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn write(h: &mut Harness, fd: u64, data: &[u8]) {
    let at = h.scratch + DATA;
    put(h, at, data);
    assert_eq!(
        h.call(Sysno::Write, &[fd, at, data.len() as u64]),
        data.len() as i64
    );
}

fn read(h: &mut Harness, fd: u64, n: usize) -> Vec<u8> {
    let at = h.scratch + DATA;
    let got = h.call(Sysno::Read, &[fd, at, n as u64]);
    assert!(got >= 0, "read: {got}");
    bytes(h, at, got as usize)
}

fn mmap_ring(h: &mut Harness, r: &Ring, len: u64, bgid: u64) -> i64 {
    h.call(
        Sysno::Mmap,
        &[0, len, RW, MAP_SHARED, r.fd, OFF_PBUF_RING | bgid << 16],
    )
}

#[test]
fn provide_and_remove_follow_io_manage_buffers_legacy() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 16, SUBMIT_ALL, 0);
    let mem = h.anon(P, RW, false);
    // io_provide_buffers_prep: 1 to 65536 buffers (the descriptor field,
    // sign-extended), a length, an address range that neither wraps nor
    // leaves user space, IDs within 16 bits; no flags or file slot.
    assert_eq!(
        run(
            &mut h,
            &r,
            &[
                provide(0, mem, 16, 1, 0, 1),
                provide(65537, mem, 16, 1, 0, 2),
                provide(-1, mem, 16, 1, 0, 3),
                provide(1, mem, 0, 1, 0, 4),
                provide(1, u64::MAX - 8, 16, 1, 0, 5),
                provide(1, 0x8000_0000_0000, 16, 1, 0, 6),
                provide(1, mem, 16, 1, 0x1_0000, 7),
                provide(2, mem, 16, 1, 0xffff, 8),
                Sqe {
                    op_flags: 1,
                    ..provide(1, mem, 16, 1, 0, 9)
                },
                Sqe {
                    file_index: 1,
                    ..provide(1, mem, 16, 1, 0, 10)
                },
            ]
        ),
        [
            (1, neg(E2BIG), 0),
            (2, neg(E2BIG), 0),
            (3, neg(E2BIG), 0),
            (4, neg(EINVAL), 0),
            (5, neg(EOVERFLOW), 0),
            (6, neg(EFAULT), 0),
            (7, neg(E2BIG), 0),
            (8, neg(EINVAL), 0),
            (9, neg(EINVAL), 0),
            (10, neg(EINVAL), 0),
        ]
    );
    // Four buffers of 16 bytes, IDs 10 to 13, make group 1.
    assert_eq!(
        run(&mut h, &r, &[provide(4, mem, 16, 1, 10, 11)]),
        [(11, 0, 0)]
    );
    // io_remove_buffers_prep: a count of 1 to 65536 and nothing else; the
    // group must exist (ENOENT), and the removal reports how many went. An
    // emptied group stays.
    assert_eq!(
        run(
            &mut h,
            &r,
            &[
                Sqe {
                    addr: mem,
                    ..remove(1, 1, 12)
                },
                Sqe {
                    len: 1,
                    ..remove(1, 1, 13)
                },
                Sqe {
                    off: 1,
                    ..remove(1, 1, 14)
                },
                Sqe {
                    op_flags: 1,
                    ..remove(1, 1, 15)
                },
                remove(0, 1, 16),
                remove(65537, 1, 17),
                remove(1, 2, 18),
                remove(3, 1, 19),
                remove(3, 1, 20),
                remove(1, 1, 21),
            ]
        ),
        [
            (12, neg(EINVAL), 0),
            (13, neg(EINVAL), 0),
            (14, neg(EINVAL), 0),
            (15, neg(EINVAL), 0),
            (16, neg(EINVAL), 0),
            (17, neg(EINVAL), 0),
            (18, neg(ENOENT), 0),
            (19, 3, 0),
            (20, 1, 0),
            (21, 0, 0),
        ]
    );
    // io_add_buffers: at most 65535 in a group; a provision that adds none
    // fails, one that adds some succeeds.
    assert_eq!(
        run(
            &mut h,
            &r,
            &[
                provide(65535, mem, 1, 2, 0, 22),
                provide(1, mem, 1, 2, 0, 23)
            ]
        ),
        [(22, 0, 0), (23, neg(EOVERFLOW), 0)]
    );
    assert_eq!(
        run(
            &mut h,
            &r,
            &[
                remove(2, 2, 24),
                provide(3, mem, 1, 2, 0, 25),
                remove(65536, 2, 26)
            ]
        ),
        [(24, 2, 0), (25, 0, 0), (26, 65535, 0)]
    );
}

#[test]
fn reads_take_provided_buffers_in_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let s = h.scratch;
        let mem = s + BUFS;
        let r = setup(&mut h, 8, 0, 0);
        let (rd, wr) = pipe(&mut h);
        assert_eq!(
            run(&mut h, &r, &[provide(4, mem, 16, 1, 10, 1)]),
            [(1, 0, 0)]
        );
        write(&mut h, wr, b"abcdefghij");
        // io_buffer_select: the group's first buffer, the length asked for
        // at most its own (0: all of it); the completion reports its ID.
        assert_eq!(
            run(
                &mut h,
                &r,
                &[select(READ, rd, 4, 1, 2), select(READ, rd, 0, 1, 3)]
            ),
            [(2, 4, buf(10)), (3, 6, buf(11))],
            "{abi:?}"
        );
        assert_eq!(bytes(&h, mem, 4), b"abcd");
        assert_eq!(bytes(&h, mem + 16, 6), b"efghij");
        // Waiting, a read keeps its provided buffer (io_read hands back
        // only a ring's): 12 is not in the group while it waits.
        assert_eq!(run(&mut h, &r, &[select(READ, rd, 0, 1, 4)]), []);
        assert_eq!(run(&mut h, &r, &[remove(8, 1, 5)]), [(5, 1, 0)]);
        write(&mut h, wr, b"klm");
        assert_eq!(r.reap(&h), [(4, 3, buf(12))]);
        // An empty group, a missing one: ENOBUFS.
        assert_eq!(
            run(
                &mut h,
                &r,
                &[select(READ, rd, 0, 1, 6), select(READ, rd, 0, 9, 7)]
            ),
            [(6, neg(ENOBUFS), 0), (7, neg(ENOBUFS), 0)]
        );
        // Failing, a read reports the provided buffer it took, which is
        // gone (io_req_defer_failed): the write end cannot be read.
        assert_eq!(
            run(
                &mut h,
                &r,
                &[provide(2, mem, 16, 1, 20, 8), select(READ, wr, 0, 1, 9)]
            ),
            [(8, 0, 0), (9, neg(EBADF), buf(20))]
        );
        // io_iov_buffer_select_prep: READV takes one vector, for its length.
        let iov = s + IOV;
        if abi.is_compat() {
            put(&h, iov, &[0, 0, 0, 0, 3, 0, 0, 0]);
        } else {
            put(&h, iov, &[0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]);
        }
        write(&mut h, wr, b"nopqr");
        assert_eq!(
            run(
                &mut h,
                &r,
                &[Sqe {
                    addr: iov,
                    ..select(READV, rd, 2, 1, 10)
                }]
            ),
            [(10, neg(EINVAL), 0)]
        );
        assert_eq!(
            run(
                &mut h,
                &r,
                &[Sqe {
                    addr: iov,
                    ..select(READV, rd, 1, 1, 11)
                }]
            ),
            [(11, 3, buf(21))]
        );
        assert_eq!(bytes(&h, mem + 16, 3), b"nop");
    });
}

#[test]
fn receives_hand_back_provided_buffers_and_sends_keep_them() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let mem = s + BUFS;
    let r = setup(&mut h, 8, 0, 0);
    let (a, b) = pair(&mut h, SOCK_STREAM | SOCK_NONBLOCK);
    let (rd, wr) = pipe(&mut h);
    assert_eq!(
        run(&mut h, &r, &[provide(2, mem, 16, 1, 30, 1)]),
        [(1, 0, 0)]
    );
    // io_recv's -EAGAIN hands the buffer back (io_kbuf_recycle): a read
    // takes it meanwhile, and the receive then takes the next.
    assert_eq!(run(&mut h, &r, &[select(RECV, b, 0, 1, 2)]), []);
    write(&mut h, wr, b"xy");
    assert_eq!(
        run(&mut h, &r, &[select(READ, rd, 0, 1, 3)]),
        [(3, 2, buf(30))]
    );
    write(&mut h, a, b"hello");
    assert_eq!(r.reap(&h), [(2, 5, buf(31))]);
    // io_send keeps its buffer while it waits for room: with a full
    // socket, only the other buffer is left to remove.
    let big = h.anon(1 << 16, RW, false);
    while h.call(Sysno::Write, &[a, big, 1 << 16]) > 0 {}
    put(&h, mem, b"0123456789abcdef");
    assert_eq!(
        run(
            &mut h,
            &r,
            &[provide(2, mem, 16, 2, 40, 4), select(SEND, a, 0, 2, 5)]
        ),
        [(4, 0, 0)]
    );
    assert_eq!(run(&mut h, &r, &[remove(8, 2, 6)]), [(6, 1, 0)]);
    // Room: the send completes with the buffer it kept, whole.
    while h.call(Sysno::Read, &[b, big, 1 << 16]) == 1 << 16 {}
    assert_eq!(r.reap(&h), [(5, 16, buf(40))]);
    assert_eq!(read(&mut h, b, 64), b"0123456789abcdef");
}

#[test]
fn buffer_rings_follow_io_register_pbuf_ring() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let arg = s + REG;
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(P, RW, false);
    let mem = h.anon(P, RW, false);
    // __io_uring_register: an argument, and one.
    buf_reg(&h, ring, 4, 3, 0);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_PBUF_RING, 0, 1),
        -i64::from(EINVAL)
    );
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_PBUF_RING, arg, 2),
        -i64::from(EINVAL)
    );
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_PBUF_RING, 8, 1),
        -i64::from(EFAULT)
    );
    // io_register_pbuf_ring: reserved words zero, known flags, a power of
    // two below 65536.
    put(&h, arg + 16, &[1]);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_PBUF_RING, arg, 1),
        -i64::from(EINVAL)
    );
    for (entries, flags) in [(4, 4), (3, 0), (0, 0), (65536, 0)] {
        assert_eq!(
            register_ring(&mut h, &r, ring, entries, 3, flags),
            -i64::from(EINVAL),
            "{entries} {flags}"
        );
    }
    // io_create_region: a ring in the process's memory needs its address
    // (EFAULT), page aligned (EINVAL), and mapped to be pinned (EFAULT).
    let gone = h.anon(P, RW, false);
    h.ok(Sysno::Munmap, &[gone, P]);
    assert_eq!(register_ring(&mut h, &r, 0, 4, 3, 0), -i64::from(EFAULT));
    assert_eq!(
        register_ring(&mut h, &r, ring + 8, 4, 3, 0),
        -i64::from(EINVAL)
    );
    assert_eq!(register_ring(&mut h, &r, gone, 4, 3, 0), -i64::from(EFAULT));
    assert_eq!(register_ring(&mut h, &r, ring, 4, 3, 0), 0);
    // A group has one ring and no provided buffers (EEXIST); an emptied
    // group gives way.
    assert_eq!(register_ring(&mut h, &r, ring, 4, 3, 0), -i64::from(EEXIST));
    assert_eq!(
        run(&mut h, &r, &[provide(1, mem, 16, 5, 0, 1)]),
        [(1, 0, 0)]
    );
    assert_eq!(register_ring(&mut h, &r, mem, 4, 5, 0), -i64::from(EEXIST));
    assert_eq!(run(&mut h, &r, &[remove(1, 5, 2)]), [(2, 1, 0)]);
    assert_eq!(register_ring(&mut h, &r, mem, 4, 5, 0), 0);
    // Provided buffers are not for a ring's group.
    assert_eq!(
        run(&mut h, &r, &[provide(1, mem, 16, 5, 0, 3)]),
        [(3, neg(EINVAL), 0)]
    );
    assert_eq!(run(&mut h, &r, &[remove(1, 5, 4)]), [(4, neg(EINVAL), 0)]);
    // io_register_pbuf_status: a ring's head (ENOENT without the group,
    // EINVAL for provided buffers' or with reserved words).
    assert_eq!(head(&mut h, &r, 3), Ok(0));
    assert_eq!(head(&mut h, &r, 9), Err(-i64::from(ENOENT)));
    assert_eq!(head(&mut h, &r, 0x1_0003), Err(-i64::from(ENOENT)));
    assert_eq!(
        run(&mut h, &r, &[provide(1, mem, 16, 6, 0, 5)]),
        [(5, 0, 0)]
    );
    assert_eq!(head(&mut h, &r, 6), Err(-i64::from(EINVAL)));
    put(&h, s + STATUS, &3u32.to_le_bytes());
    put(&h, s + STATUS + 8, &[1]);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_PBUF_STATUS, s + STATUS, 1),
        -i64::from(EINVAL)
    );
    // io_uring_get_unmapped_area: a ring in the process's memory, or a
    // missing one, has no region to map (ENOMEM).
    assert_eq!(mmap_ring(&mut h, &r, P, 3), -i64::from(ENOMEM));
    assert_eq!(mmap_ring(&mut h, &r, P, 9), -i64::from(ENOMEM));
    // IOU_PBUF_RING_MMAP: pages of the ring's own (its address ignored),
    // mapped whole (io_region_mmap: EFAULT for less).
    assert_eq!(register_ring(&mut h, &r, 0x1234, 512, 7, RING_MMAP), 0);
    assert_eq!(mmap_ring(&mut h, &r, P, 7), -i64::from(EFAULT));
    assert!(mmap_ring(&mut h, &r, 2 * P, 7) > 0);
    // io_unregister_pbuf_ring: no flags or reserved words (EINVAL), a
    // group (ENOENT) with a ring (EINVAL).
    buf_reg(&h, 0, 0, 7, RING_MMAP);
    assert_eq!(
        reg(&mut h, r.fd, UNREGISTER_PBUF_RING, arg, 1),
        -i64::from(EINVAL)
    );
    buf_reg(&h, 0, 0, 7, 0);
    put(&h, arg + 39, &[1]);
    assert_eq!(
        reg(&mut h, r.fd, UNREGISTER_PBUF_RING, arg, 1),
        -i64::from(EINVAL)
    );
    for (group, e) in [(9, ENOENT), (6, EINVAL)] {
        buf_reg(&h, 0, 0, group, 0);
        assert_eq!(
            reg(&mut h, r.fd, UNREGISTER_PBUF_RING, arg, 1),
            -i64::from(e)
        );
    }
    buf_reg(&h, 0, 0, 7, 0);
    assert_eq!(
        reg(&mut h, r.fd, UNREGISTER_PBUF_RING, arg, 0),
        -i64::from(EINVAL)
    );
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_PBUF_RING, arg, 1), 0);
    assert_eq!(head(&mut h, &r, 7), Err(-i64::from(ENOENT)));
    assert_eq!(mmap_ring(&mut h, &r, 2 * P, 7), -i64::from(ENOMEM));
}

#[test]
fn buffer_rings_are_charged_to_a_user_without_cap_ipc_lock() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    h.proc.state.creds = (1000, 1000, 1000, 1000);
    // An 8-entry ring's regions: one page of rings, one of SQEs; a ring of
    // 256 buffers is one page more.
    h.proc.state.rlimits[RLIMIT_MEMLOCK].0 = 3 * P;
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(2 * P, RW, false);
    assert_eq!(register_ring(&mut h, &r, ring, 256, 1, 0), 0);
    assert_eq!(
        register_ring(&mut h, &r, 0, 256, 2, RING_MMAP),
        -i64::from(ENOMEM)
    );
    buf_reg(&h, 0, 0, 1, 0);
    let arg = h.scratch + REG;
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_PBUF_RING, arg, 1), 0);
    assert_eq!(register_ring(&mut h, &r, 0, 256, 2, RING_MMAP), 0);
}

#[test]
fn ring_buffers_are_taken_as_requests_complete() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(P, RW, false);
    let mem = h.anon(P, RW, false);
    assert_eq!(register_ring(&mut h, &r, ring, 4, 3, 0), 0);
    ring_buf(&h, ring, 0, mem, 8, 20);
    ring_buf(&h, ring, 1, mem + 8, 8, 21);
    set_tail(&h, ring, 2);
    let (rd, wr) = pipe(&mut h);
    // A file with a wait queue: the head moves as the read completes.
    write(&mut h, wr, b"abcdef");
    assert_eq!(
        run(&mut h, &r, &[select(READ, rd, 0, 3, 1)]),
        [(1, 6, buf(20))]
    );
    assert_eq!(head(&mut h, &r, 3), Ok(1));
    assert_eq!(bytes(&h, mem, 6), b"abcdef");
    // Waiting, the read hands its buffer back (io_kbuf_recycle_ring).
    assert_eq!(run(&mut h, &r, &[select(READ, rd, 0, 3, 2)]), []);
    assert_eq!(head(&mut h, &r, 3), Ok(1));
    write(&mut h, wr, b"xyz");
    assert_eq!(r.reap(&h), [(2, 3, buf(21))]);
    assert_eq!(head(&mut h, &r, 3), Ok(2));
    // Empty (the tail at the head): ENOBUFS.
    assert_eq!(
        run(&mut h, &r, &[select(READ, rd, 0, 3, 3)]),
        [(3, neg(ENOBUFS), 0)]
    );
    ring_buf(&h, ring, 2, mem + 16, 8, 22);
    ring_buf(&h, ring, 3, mem + 24, 8, 23);
    set_tail(&h, ring, 4);
    // Failing, a read hands back a buffer it has not taken...
    assert_eq!(
        run(&mut h, &r, &[select(READ, wr, 0, 3, 4)]),
        [(4, neg(EBADF), 0)]
    );
    assert_eq!(head(&mut h, &r, 3), Ok(2));
    // ... but a file without a wait queue takes it at once
    // (io_should_commit), and the failure reports it.
    let wo = h.file("kbuf-wo", 16, b'w', O_WRONLY);
    assert_eq!(
        run(&mut h, &r, &[select(READ, wo, 0, 3, 5)]),
        [(5, neg(EBADF), buf(22))]
    );
    assert_eq!(head(&mut h, &r, 3), Ok(3));
    let ro = h.file("kbuf-ro", 16, b'r', 0);
    assert_eq!(
        run(&mut h, &r, &[select(READ, ro, 4, 3, 6)]),
        [(6, 4, buf(23))]
    );
    assert_eq!(head(&mut h, &r, 3), Ok(4));
    assert_eq!(bytes(&h, mem + 24, 4), b"rrrr");
    // A receive: IORING_CQE_F_SOCK_NONEMPTY with data left.
    let (a, b) = pair(&mut h, SOCK_STREAM);
    ring_buf(&h, ring, 0, mem, 8, 30);
    set_tail(&h, ring, 5);
    write(&mut h, a, b"hello world");
    assert_eq!(
        run(&mut h, &r, &[select(RECV, b, 5, 3, 7)]),
        [(7, 5, buf(30) | SOCK_NONEMPTY)]
    );
    assert_eq!(read(&mut h, b, 64), b" world");
    // A send takes its buffer at once, cut to the length asked for (the
    // entry's length rewritten: io_ring_buffers_peek).
    put(&h, mem + 32, b"ABCDEFGH");
    ring_buf(&h, ring, 1, mem + 32, 8, 31);
    set_tail(&h, ring, 6);
    assert_eq!(
        run(&mut h, &r, &[select(SEND, a, 3, 3, 8)]),
        [(8, 3, buf(31))]
    );
    assert_eq!(u32_at(&h, ring + 16 + 8), 3);
    assert_eq!(head(&mut h, &r, 3), Ok(6));
    assert_eq!(read(&mut h, b, 64), b"ABC");
    // Without the group: a send's io_buffers_select finds none (ENOENT), a
    // receive's io_buffer_select no buffer (ENOBUFS).
    assert_eq!(
        run(
            &mut h,
            &r,
            &[select(SEND, a, 3, 9, 9), select(RECV, b, 3, 9, 10)]
        ),
        [(9, neg(ENOENT), 0), (10, neg(ENOBUFS), 0)]
    );
}

#[test]
fn incremental_rings_consume_buffers_in_part() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(P, RW, false);
    let mem = h.anon(P, RW, false);
    assert_eq!(register_ring(&mut h, &r, ring, 2, 4, RING_INC), 0);
    ring_buf(&h, ring, 0, mem, 10, 40);
    set_tail(&h, ring, 1);
    let (rd, wr) = pipe(&mut h);
    // io_kbuf_inc_commit: the head buffer moves on by what was used and
    // stays (IORING_CQE_F_BUF_MORE)...
    write(&mut h, wr, b"abcd");
    assert_eq!(
        run(&mut h, &r, &[select(READ, rd, 0, 4, 1)]),
        [(1, 4, buf(40) | BUF_MORE)]
    );
    assert_eq!(u64_at(&h, ring), mem + 4);
    assert_eq!(u32_at(&h, ring + 8), 6);
    assert_eq!(head(&mut h, &r, 4), Ok(0));
    // ... until it is used up.
    write(&mut h, wr, b"efghijkl");
    assert_eq!(
        run(&mut h, &r, &[select(READ, rd, 0, 4, 2)]),
        [(2, 6, buf(40))]
    );
    assert_eq!(u32_at(&h, ring + 8), 0);
    assert_eq!(head(&mut h, &r, 4), Ok(1));
    assert_eq!(bytes(&h, mem, 10), b"abcdefghij");
    // A send uses part of one, its entry left whole but for that part.
    let (a, b) = pair(&mut h, SOCK_STREAM);
    put(&h, mem + 16, b"ABCDEFGH");
    ring_buf(&h, ring, 1, mem + 16, 8, 41);
    set_tail(&h, ring, 2);
    assert_eq!(
        run(&mut h, &r, &[select(SEND, a, 3, 4, 3)]),
        [(3, 3, buf(41))]
    );
    assert_eq!(u64_at(&h, ring + 16), mem + 19);
    assert_eq!(u32_at(&h, ring + 24), 5);
    assert_eq!(head(&mut h, &r, 4), Ok(1));
    assert_eq!(read(&mut h, b, 64), b"ABC");
}

#[test]
fn bundles_take_as_many_buffers_as_the_data_needs() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(P, RW, false);
    let mem = h.anon(P, RW, false);
    assert_eq!(register_ring(&mut h, &r, ring, 8, 5, 0), 0);
    for i in 0..4 {
        ring_buf(&h, ring, i, mem + 4 * i, 4, 50 + i as u16);
    }
    set_tail(&h, ring, 4);
    let (a, b) = pair(&mut h, SOCK_STREAM);
    // io_recv_buf_select: with no length and nothing known to be queued,
    // one buffer; a full one with more queued goes on (IORING_RECV_RETRY)
    // with as many as that needs, and the completion reports the first.
    // (Two writes: Linux's Unix stream counts an skb read in part at its
    // whole length in msg_inq.)
    write(&mut h, a, b"abcd");
    write(&mut h, a, b"efghijkl");
    let bundle = |len, ud| Sqe {
        ioprio: BUNDLE,
        ..select(RECV, b, len, 5, ud)
    };
    assert_eq!(run(&mut h, &r, &[bundle(0, 1)]), [(1, 12, buf(50))]);
    assert_eq!(bytes(&h, mem, 12), b"abcdefghijkl");
    assert_eq!(head(&mut h, &r, 5), Ok(3));
    // A send with three vectors leaves its message state, with an array
    // of three, in the ring's cache (io_netmsg_recycle); the next receive
    // takes it, and with it maps three buffers at once.
    for i in 4..8 {
        ring_buf(&h, ring, i, mem + 4 * i, 4, 50 + i as u16);
    }
    set_tail(&h, ring, 8);
    put(&h, s + DATA, b"0123456789");
    let mut v = Vec::new();
    for (off, len) in [(0u64, 3u64), (3, 3), (6, 4)] {
        v.extend_from_slice(&(s + DATA + off).to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
    }
    put(&h, s + IOV, &v);
    let mut m = [0u8; 56];
    m[16..24].copy_from_slice(&(s + IOV).to_le_bytes());
    m[24..32].copy_from_slice(&3u64.to_le_bytes());
    put(&h, s + MSG, &m);
    let sendmsg = Sqe {
        opcode: SENDMSG,
        fd: a as i32,
        addr: s + MSG,
        user_data: 3,
        ..Sqe::default()
    };
    assert_eq!(run(&mut h, &r, &[sendmsg]), [(3, 10, 0)]);
    assert_eq!(run(&mut h, &r, &[bundle(0, 4)]), [(4, 10, buf(53))]);
    assert_eq!(bytes(&h, mem + 12, 10), b"0123456789");
    assert_eq!(head(&mut h, &r, 5), Ok(6));
    // A length maps whole buffers as far as it goes: one that would be
    // cut ends the mapping (IORING_RECV_PARTIAL_MAP, no retry)...
    write(&mut h, a, b"ABCDEFGH");
    assert_eq!(
        run(&mut h, &r, &[bundle(6, 5)]),
        [(5, 4, buf(56) | SOCK_NONEMPTY)]
    );
    assert_eq!(head(&mut h, &r, 5), Ok(7));
    // ... unless it is the first, cut to fit in the ring.
    assert_eq!(
        run(&mut h, &r, &[bundle(2, 6)]),
        [(6, 2, buf(57) | SOCK_NONEMPTY)]
    );
    assert_eq!(u32_at(&h, ring + 16 * 7 + 8), 2);
    assert_eq!(head(&mut h, &r, 5), Ok(8));
    assert_eq!(read(&mut h, b, 64), b"GH");
    // A bundle send takes buffers for all it asks, sent whole (MSG_WAITALL).
    put(&h, mem, b"abcdefgh");
    ring_buf(&h, ring, 0, mem, 4, 60);
    ring_buf(&h, ring, 1, mem + 4, 4, 61);
    set_tail(&h, ring, 10);
    let send = Sqe {
        ioprio: BUNDLE,
        ..select(SEND, a, 0, 5, 7)
    };
    assert_eq!(run(&mut h, &r, &[send]), [(7, 8, buf(60))]);
    assert_eq!(head(&mut h, &r, 5), Ok(10));
    assert_eq!(read(&mut h, b, 64), b"abcdefgh");
    // io_wq_submit_work: a bundle send (REQ_F_MULTISHOT) never runs in a
    // worker but waits for its socket, once; one already writable ends it
    // (IO_APOLL_READY: ECANCELED).
    let send = Sqe {
        flags: BUFFER_SELECT | ASYNC,
        ioprio: BUNDLE,
        ..select(SEND, a, 0, 5, 8)
    };
    assert_eq!(run(&mut h, &r, &[send]), [(8, neg(ECANCELED), 0)]);
}

#[test]
fn multishot_receives_post_each_buffer() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(P, RW, false);
    let mem = h.anon(P, RW, false);
    assert_eq!(register_ring(&mut h, &r, ring, 4, 6, 0), 0);
    for i in 0..4 {
        ring_buf(&h, ring, i, mem + 4 * i, 4, 60 + i as u16);
    }
    set_tail(&h, ring, 4);
    let (a, b) = pair(&mut h, SOCK_STREAM);
    let mshot = Sqe {
        ioprio: RECV_MULTISHOT,
        ..select(RECV, b, 0, 6, 1)
    };
    // io_recv_finish: each buffer posted with IORING_CQE_F_MORE, at once
    // while data is left, then waiting for more.
    assert_eq!(run(&mut h, &r, &[mshot]), []);
    write(&mut h, a, b"abcdefghij");
    assert_eq!(
        r.reap(&h),
        [
            (1, 4, buf(60) | MORE | SOCK_NONEMPTY),
            (1, 4, buf(61) | MORE | SOCK_NONEMPTY),
            (1, 2, buf(62) | MORE),
        ]
    );
    write(&mut h, a, b"xyz");
    assert_eq!(r.reap(&h), [(1, 3, buf(63) | MORE)]);
    // Out of buffers, the request ends (ENOBUFS).
    write(&mut h, a, b"q");
    assert_eq!(r.reap(&h), [(1, neg(ENOBUFS), 0)]);
    assert_eq!(head(&mut h, &r, 6), Ok(4));
    // A CQ without room ends it too (io_req_post_cqe never overflows): the
    // final completion carries the last receive, and overflows.
    let small = setup(&mut h, 1, 0, 0);
    let ring2 = h.anon(P, RW, false);
    assert_eq!(register_ring(&mut h, &small, ring2, 4, 7, 0), 0);
    for i in 0..4 {
        ring_buf(&h, ring2, i, mem + 64 + 4 * i, 4, 70 + i as u16);
    }
    set_tail(&h, ring2, 4);
    // (The "q" is still queued.)
    write(&mut h, a, b"0123456789");
    let mshot = Sqe {
        ioprio: RECV_MULTISHOT,
        ..select(RECV, b, 0, 7, 2)
    };
    assert_eq!(
        run(&mut h, &small, &[mshot]),
        [
            (2, 4, buf(70) | MORE | SOCK_NONEMPTY),
            (2, 4, buf(71) | MORE | SOCK_NONEMPTY)
        ]
    );
    assert_eq!(small.enter(&mut h, 0, 0, GETEVENTS), 0);
    assert_eq!(small.reap(&h), [(2, 3, buf(72))]);
    assert_eq!(bytes(&h, mem + 64, 11), b"q0123456789");
}

#[test]
fn multishot_recvmsg_lays_out_each_buffer() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let s = h.scratch;
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(P, RW, false);
    let mem = h.anon(P, RW, false);
    assert_eq!(register_ring(&mut h, &r, ring, 4, 8, 0), 0);
    for i in 0..3 {
        ring_buf(&h, ring, i, mem + 64 * i, 64, 80 + i as u16);
    }
    ring_buf(&h, ring, 3, mem + 192, 40, 83);
    set_tail(&h, ring, 4);
    let (a, b) = pair(&mut h, SOCK_DGRAM);
    // The sender bound to an abstract name.
    put(&h, s + DATA, b"\x01\x00\x00kbuf");
    h.ok(Sysno::Bind, &[a, s + DATA, 7]);
    // A msghdr with room for a 16-byte name and no control data.
    let mut m = [0u8; 56];
    m[8..12].copy_from_slice(&16u32.to_le_bytes());
    put(&h, s + MSG, &m);
    write(&mut h, a, b"hi");
    write(&mut h, a, b"there");
    let mshot = |ud| Sqe {
        ioprio: RECV_MULTISHOT,
        addr: s + MSG,
        ..select(RECVMSG, b, 0, 8, ud)
    };
    // io_recvmsg_multishot: struct io_uring_recvmsg_out, the name, then the
    // payload; the result counts the header and name room.
    assert_eq!(
        run(&mut h, &r, &[mshot(1)]),
        [(1, 34, buf(80) | MORE), (1, 37, buf(81) | MORE)]
    );
    // struct io_uring_recvmsg_out: namelen, controllen, payloadlen, flags.
    let out = |h: &Harness, at: u64| (0..4).map(|i| u32_at(h, at + 4 * i)).collect::<Vec<_>>();
    assert_eq!(out(&h, mem), [7, 0, 2, 0]);
    assert_eq!(bytes(&h, mem + 16, 7), b"\x01\x00\x00kbuf");
    assert_eq!(bytes(&h, mem + 32, 2), b"hi");
    assert_eq!(bytes(&h, mem + 64 + 32, 5), b"there");
    // Truncated: MSG_TRUNC, and what fit (the socket reports no more
    // without MSG_TRUNC asked for).
    write(&mut h, a, &[b'x'; 40]);
    assert_eq!(r.reap(&h), [(1, 64, buf(82) | MORE)]);
    assert_eq!(out(&h, mem + 128), [7, 0, 32, MSG_TRUNC]);
    // A datagram socket reports nothing of what is queued (msg_inq -1), so
    // the receive goes on at once, and without a buffer ends (ENOBUFS).
    write(&mut h, a, b"0123456789");
    assert_eq!(r.reap(&h), [(1, 40, buf(83) | MORE), (1, neg(ENOBUFS), 0)]);
    assert_eq!(out(&h, mem + 192), [7, 0, 8, MSG_TRUNC]);
    // io_recvmsg_prep_multishot: a buffer the header does not fit (EFAULT,
    // the buffer handed back).
    ring_buf(&h, ring, 0, mem, 16, 84);
    set_tail(&h, ring, 5);
    write(&mut h, a, b"late");
    assert_eq!(run(&mut h, &r, &[mshot(2)]), [(2, neg(EFAULT), 0)]);
    assert_eq!(head(&mut h, &r, 8), Ok(4));
}

#[test]
fn multishot_reads_read_what_there_is() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let ring = h.anon(P, RW, false);
    let mem = h.anon(P, RW, false);
    assert_eq!(register_ring(&mut h, &r, ring, 4, 9, 0), 0);
    for i in 0..4 {
        ring_buf(&h, ring, i, mem + 8 * i, 8, 90 + i as u16);
    }
    set_tail(&h, ring, 4);
    let (rd, wr) = pipe(&mut h);
    let mshot = |fd: u64, ud| Sqe {
        opcode: READ_MULTISHOT,
        ..select(READ, fd, 0, 9, ud)
    };
    // io_read_mshot_prep: a provided buffer, no address or length.
    assert_eq!(
        run(
            &mut h,
            &r,
            &[Sqe {
                flags: 0,
                ..mshot(rd, 1)
            }]
        ),
        [(1, neg(EINVAL), 0)]
    );
    assert_eq!(
        run(
            &mut h,
            &r,
            &[Sqe {
                len: 8,
                ..mshot(rd, 2)
            }]
        ),
        [(2, neg(EINVAL), 0)]
    );
    assert_eq!(
        run(
            &mut h,
            &r,
            &[Sqe {
                addr: mem,
                ..mshot(rd, 3)
            }]
        ),
        [(3, neg(EINVAL), 0)]
    );
    // io_read_mshot: a file with a wait queue (EBADFD).
    let ro = h.file("kbuf-mshot", 16, b'r', 0);
    assert_eq!(run(&mut h, &r, &[mshot(ro, 4)]), [(4, neg(EBADFD), 0)]);
    // RWF_NOWAIT: nothing to read fails it (-EAGAIN), its buffer handed back.
    assert_eq!(
        run(
            &mut h,
            &r,
            &[Sqe {
                op_flags: RWF_NOWAIT,
                ..mshot(rd, 5)
            }]
        ),
        [(5, neg(EAGAIN), 0)]
    );
    assert_eq!(head(&mut h, &r, 9), Ok(0));
    // Each read posted with IORING_CQE_F_MORE, the next at once
    // (io_poll_multishot_retry), short reads and all.
    assert_eq!(run(&mut h, &r, &[mshot(rd, 6)]), []);
    write(&mut h, wr, b"abcdefghijk");
    assert_eq!(r.reap(&h), [(6, 8, buf(90) | MORE), (6, 3, buf(91) | MORE)]);
    assert_eq!(bytes(&h, mem, 11), b"abcdefghijk");
    // End of file ends it (0), its buffer handed back.
    h.ok(Sysno::Close, &[wr]);
    assert_eq!(r.reap(&h), [(6, 0, 0)]);
    assert_eq!(head(&mut h, &r, 9), Ok(2));
}

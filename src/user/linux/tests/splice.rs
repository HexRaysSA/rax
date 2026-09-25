//! `splice`, `vmsplice`, and `tee` against `fs/splice.c` (Linux 6.19) on
//! every ABI: each call's checks in the kernel's order; transfers between
//! files, pipes, sockets, and devices that move what there is, at an
//! offset or a file's position; the end of a pipe's data, the
//! non-blocking modes, sleeping and a signal ending it, `EPIPE` and
//! `SIGPIPE`; `vmsplice` both ways (and its deafness to `O_NONBLOCK`);
//! `tee` through the host's own on Linux hosts, refused elsewhere.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::signal::deliver::restart::ERESTARTSYS;
use crate::user::linux::signal::{SIGPIPE, SigPending, sa};

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_NONBLOCK: u64 = 0o4000;
const O_APPEND: u64 = 0o2000;
const O_PATH: u64 = 0o10000000;
const F_SETFL: u64 = 4;
const NONBLOCK: u64 = 2;
const SEEK_CUR: u64 = 1;

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    b
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from_le_bytes(get(h, at, 8).try_into().unwrap())
}

/// A scratch area of four pages.
struct Area(u64);

impl Area {
    fn fds(&self) -> u64 {
        self.0
    }
    fn off(&self) -> u64 {
        self.0 + 0x10
    }
    fn buf(&self) -> u64 {
        self.0 + 0x100
    }
    fn iov(&self) -> u64 {
        self.0 + 0x800
    }
    fn path(&self) -> u64 {
        self.0 + 0xc00
    }
}

fn area(h: &mut Harness) -> Area {
    Area(h.anon(4 * P, 3, false))
}

fn pair(h: &mut Harness, a: &Area, call: Sysno, args: &[u64]) -> (u64, u64) {
    h.ok(call, args);
    let b = get(h, a.fds(), 8);
    (
        u64::from(u32::from_le_bytes(b[..4].try_into().unwrap())),
        u64::from(u32::from_le_bytes(b[4..].try_into().unwrap())),
    )
}

fn pipe(h: &mut Harness, a: &Area) -> (u64, u64) {
    pair(h, a, Sysno::Pipe2, &[a.fds(), 0])
}

fn socketpair(h: &mut Harness, a: &Area) -> (u64, u64) {
    pair(h, a, Sysno::Socketpair, &[1, 1, 0, a.fds()])
}

fn open(h: &mut Harness, a: &Area, path: &str, flags: u64) -> u64 {
    put(h, a.path(), format!("{path}\0").as_bytes());
    h.ok(Sysno::Openat, &[-100i64 as u64, a.path(), flags, 0])
}

fn write(h: &mut Harness, a: &Area, fd: u64, b: &[u8]) {
    put(h, a.buf(), b);
    assert_eq!(
        h.ok(Sysno::Write, &[fd, a.buf(), b.len() as u64]),
        b.len() as u64
    );
}

/// What a pipe holds, read without sleeping.
fn drain(h: &mut Harness, a: &Area, fd: u64) -> Vec<u8> {
    h.ok(Sysno::Fcntl, &[fd, F_SETFL, O_NONBLOCK]);
    let n = h.call(Sysno::Read, &[fd, a.buf(), 256]);
    h.ok(Sysno::Fcntl, &[fd, F_SETFL, 0]);
    if n <= 0 {
        return Vec::new();
    }
    get(h, a.buf(), n as usize)
}

fn splice(h: &mut Harness, args: [u64; 6]) -> i64 {
    h.call(Sysno::Splice, &args)
}

/// A handler for `SIGPIPE`, so a sent one stays queued.
fn handle_sigpipe(h: &mut Harness, a: &Area) {
    let act = a.0 + 0xf00;
    let mut words = vec![0x40_1000u64];
    if h.abi().has_sa_restorer() {
        words.extend([sa::RESTORER, 0x40_1100]);
    } else {
        words.push(0);
    }
    words.push(0);
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    put(h, act, &b);
    h.ok(Sysno::RtSigaction, &[SIGPIPE as u64, act, 0, 8]);
}

fn sigpipe_pending(h: &mut Harness) -> bool {
    let p = h.proc.threads[0].pending.contains(SIGPIPE);
    h.proc.threads[0].pending = SigPending::new();
    p
}

#[test]
fn splice_checks_in_the_kernels_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = area(&mut h);
        let f = h.file("splice-checks-f", 10, b'f', O_RDWR);
        let g = h.file("splice-checks-g", 0, 0, O_RDWR);
        let (r, w) = pipe(&mut h, &a);
        let off = a.off();
        put(&h, off, &0u64.to_le_bytes());
        let bad = u64::MAX;
        // The length first, then the flags, then each descriptor.
        assert_eq!(splice(&mut h, [bad, 0, bad, 0, 0, 0x100]), 0);
        assert_eq!(splice(&mut h, [r, 0, f, 0, 1, 0x10]), e(EINVAL));
        assert_eq!(splice(&mut h, [bad, 0, w, 0, 1, 0]), e(EBADF));
        assert_eq!(splice(&mut h, [f, 0, bad, 0, 1, 0]), e(EBADF));
        let path = open(&mut h, &a, "/", O_PATH);
        assert_eq!(splice(&mut h, [path, 0, w, 0, 1, 0]), e(EBADF));
        // A pipe's offsets, before either offset is read; *off_out then
        // *off_in; the access modes.
        assert_eq!(splice(&mut h, [r, off, f, 0, 1, 0]), e(ESPIPE));
        assert_eq!(splice(&mut h, [f, 0, w, off, 1, 0]), e(ESPIPE));
        assert_eq!(splice(&mut h, [r, 16, f, 0, 1, 0]), e(ESPIPE));
        assert_eq!(splice(&mut h, [f, off, g, 16, 1, 0]), e(EFAULT));
        assert_eq!(splice(&mut h, [f, 16, g, off, 1, 0]), e(EFAULT));
        assert_eq!(splice(&mut h, [w, 0, g, 16, 1, 0]), e(EFAULT));
        assert_eq!(splice(&mut h, [w, 0, f, 0, 1, 0]), e(EBADF));
        assert_eq!(splice(&mut h, [f, 0, r, 0, 1, 0]), e(EBADF));
        // Two files; a pipe to itself.
        assert_eq!(splice(&mut h, [f, 0, g, 0, 1, 0]), e(EINVAL));
        assert_eq!(splice(&mut h, [r, 0, w, 0, 1, 0]), e(EINVAL));
        // To a file: a position only where it has them, never O_APPEND,
        // rw_verify_area, and a file that takes a splice.
        let app = h.file("splice-checks-app", 0, 0, O_WRONLY | O_APPEND);
        write(&mut h, &a, w, b"x");
        assert_eq!(splice(&mut h, [r, 0, app, 0, 1, 0]), e(EINVAL));
        let (s0, _s1) = socketpair(&mut h, &a);
        assert_eq!(splice(&mut h, [r, 0, s0, off, 1, 0]), e(EINVAL));
        put(&h, off, &(i64::MAX - 1).to_le_bytes());
        assert_eq!(splice(&mut h, [r, 0, g, off, 2, 0]), e(EINVAL));
        let efd = h.ok(Sysno::Eventfd2, &[0, 0]);
        assert_eq!(splice(&mut h, [r, 0, efd, 0, 1, 0]), e(EINVAL));
        // From a file: likewise, and a file that has a splice_read.
        assert_eq!(splice(&mut h, [s0, off, w, 0, 1, 0]), e(EINVAL));
        put(&h, off, &(-1i64).to_le_bytes());
        assert_eq!(splice(&mut h, [f, off, w, 0, 1, 0]), e(EINVAL));
        assert_eq!(splice(&mut h, [f, 0, w, 0, u64::MAX, 0]), e(EINVAL));
        assert_eq!(splice(&mut h, [efd, 0, w, 0, 1, 0]), e(EINVAL));
        let dir = open(&mut h, &a, "/", O_RDONLY);
        assert_eq!(splice(&mut h, [dir, 0, w, 0, 1, 0]), e(EINVAL));
        let null = open(&mut h, &a, "/dev/null", O_RDWR);
        assert_eq!(splice(&mut h, [null, 0, w, 0, 1, 0]), e(EINVAL));
        assert_eq!(drain(&mut h, &a, r), b"x", "nothing moved");
    });
}

#[test]
fn transfers_move_what_there_is() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = area(&mut h);
        let f = h.file("splice-moves", 10, b'.', O_RDWR);
        put(&h, a.buf(), b"0123456789");
        h.ok(Sysno::Pwrite64, &[f, a.buf(), 10, 0]);
        let (r, w) = pipe(&mut h, &a);
        let (qr, qw) = pipe(&mut h, &a);
        let off = a.off();
        // File to pipe at an offset: the offset moves, the position not.
        put(&h, off, &2u64.to_le_bytes());
        assert_eq!(splice(&mut h, [f, off, w, 0, 100, 0]), 8);
        assert_eq!(u64_at(&h, off), 10);
        assert_eq!(h.ok(Sysno::Lseek, &[f, 0, SEEK_CUR]), 0);
        assert_eq!(drain(&mut h, &a, r), b"23456789");
        // At the file's position, which moves; at the end, nothing.
        assert_eq!(splice(&mut h, [f, 0, w, 0, 4, 0]), 4);
        assert_eq!(h.ok(Sysno::Lseek, &[f, 0, SEEK_CUR]), 4);
        assert_eq!(drain(&mut h, &a, r), b"0123");
        assert_eq!(splice(&mut h, [f, off, w, 0, 4, 0]), 0);
        // Pipe to file: what the pipe holds, without waiting for more.
        write(&mut h, &a, w, b"abc");
        put(&h, off, &5u64.to_le_bytes());
        assert_eq!(splice(&mut h, [r, 0, f, off, 100, 0]), 3);
        assert_eq!(u64_at(&h, off), 8);
        h.ok(Sysno::Pread64, &[f, a.buf(), 10, 0]);
        assert_eq!(get(&h, a.buf(), 10), b"01234abc89");
        write(&mut h, &a, w, b"XYZW");
        assert_eq!(splice(&mut h, [r, 0, f, 0, 2, 0]), 2);
        assert_eq!(h.ok(Sysno::Lseek, &[f, 0, SEEK_CUR]), 6);
        assert_eq!(drain(&mut h, &a, r), b"ZW");
        // Pipe to pipe: at most len, the rest left.
        write(&mut h, &a, w, b"hello");
        assert_eq!(splice(&mut h, [r, 0, qw, 0, 3, 0]), 3);
        assert_eq!(drain(&mut h, &a, qr), b"hel");
        assert_eq!(drain(&mut h, &a, r), b"lo");
        // Empty: SPLICE_F_NONBLOCK or O_NONBLOCK on either end.
        assert_eq!(splice(&mut h, [r, 0, qw, 0, 1, NONBLOCK]), e(EAGAIN));
        h.ok(Sysno::Fcntl, &[qw, F_SETFL, O_NONBLOCK]);
        assert_eq!(splice(&mut h, [r, 0, qw, 0, 1, 0]), e(EAGAIN));
        h.ok(Sysno::Fcntl, &[qw, F_SETFL, 0]);
        assert_eq!(splice(&mut h, [r, 0, f, 0, 1, NONBLOCK]), e(EAGAIN));
        // Sleeping for data, and a signal ending the sleep.
        assert_eq!(h.start(0, Sysno::Splice, &[r, 0, qw, 0, 1, 0]), None);
        h.proc.threads[0].blocked = None;
        h.proc.threads[0].sigpending = true;
        assert_eq!(
            h.start(0, Sysno::Splice, &[r, 0, f, 0, 1, 0]),
            Some(e(ERESTARTSYS))
        );
        h.proc.threads[0].sigpending = false;
        // The end of the pipe's data: 0.
        h.ok(Sysno::Close, &[w]);
        assert_eq!(splice(&mut h, [r, 0, qw, 0, 1, 0]), 0);
        assert_eq!(splice(&mut h, [r, 0, f, 0, 1, 0]), 0);
        // No readers: EPIPE and SIGPIPE, the input untouched.
        handle_sigpipe(&mut h, &a);
        let (r, w) = pipe(&mut h, &a);
        write(&mut h, &a, w, b"x");
        h.ok(Sysno::Close, &[qr]);
        assert_eq!(splice(&mut h, [r, 0, qw, 0, 1, 0]), e(EPIPE));
        assert!(sigpipe_pending(&mut h));
        assert_eq!(drain(&mut h, &a, r), b"x");
        put(&h, off, &0u64.to_le_bytes());
        assert_eq!(splice(&mut h, [f, off, qw, 0, 1, 0]), e(EPIPE));
        assert!(sigpipe_pending(&mut h));
        assert_eq!(u64_at(&h, off), 0);
    });
}

#[test]
fn sockets_and_devices_splice() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = area(&mut h);
        let (r, w) = pipe(&mut h, &a);
        let (s0, s1) = socketpair(&mut h, &a);
        write(&mut h, &a, w, b"xyz");
        assert_eq!(splice(&mut h, [r, 0, s0, 0, 100, 0]), 3);
        assert_eq!(h.ok(Sysno::Read, &[s1, a.buf(), 64]), 3);
        assert_eq!(get(&h, a.buf(), 3), b"xyz");
        write(&mut h, &a, s1, b"sock");
        assert_eq!(splice(&mut h, [s0, 0, w, 0, 100, 0]), 4);
        assert_eq!(drain(&mut h, &a, r), b"sock");
        assert_eq!(splice(&mut h, [s0, 0, w, 0, 1, NONBLOCK]), e(EAGAIN));
        // A socket at its end (the peer shut its writing): 0.
        h.ok(Sysno::Shutdown, &[s1, 1]);
        assert_eq!(splice(&mut h, [s0, 0, w, 0, 1, 0]), 0);
        // The memory devices: /dev/zero gives, /dev/null takes.
        let zero = open(&mut h, &a, "/dev/zero", O_RDONLY);
        assert_eq!(splice(&mut h, [zero, 0, w, 0, 5, 0]), 5);
        let null = open(&mut h, &a, "/dev/null", O_WRONLY);
        assert_eq!(splice(&mut h, [r, 0, null, 0, 100, 0]), 5);
        assert!(drain(&mut h, &a, r).is_empty());
    });
}

#[test]
fn vmsplice_fills_and_empties_pipes() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = area(&mut h);
        let (r, w) = pipe(&mut h, &a);
        let f = h.file("vmsplice", 4, b'v', O_RDWR);
        let iov = a.iov();
        let vecs = |h: &Harness, v: &[(u64, u64)]| {
            let b: Vec<u8> = v
                .iter()
                .flat_map(|&(p, l)| [p.to_le_bytes(), l.to_le_bytes()].concat())
                .collect();
            put(h, iov, &b);
        };
        let src = a.buf() + 0x200;
        put(&h, src, b"abcde");
        vecs(&h, &[(src, 2), (src + 2, 3)]);
        let vm = |h: &mut Harness, fd: u64, n: u64, flags: u64| {
            h.call(Sysno::Vmsplice, &[fd, iov, n, flags])
        };
        // The flags, the descriptor and its direction, the vectors, then
        // nothing to move (whatever the file) or a file not a pipe.
        assert_eq!(vm(&mut h, w, 2, 0x10), e(EINVAL));
        assert_eq!(vm(&mut h, u64::MAX, 2, 0), e(EBADF));
        assert_eq!(vm(&mut h, f, 0, 0), 0);
        assert_eq!(vm(&mut h, f, 2, 0), e(EBADF));
        assert_eq!(h.call(Sysno::Vmsplice, &[w, 16, 2, 0]), e(EFAULT));
        assert_eq!(vm(&mut h, w, 1025, 0), e(EINVAL));
        // Into the pipe, up to the first byte that cannot be read.
        assert_eq!(vm(&mut h, w, 2, 0), 5);
        assert_eq!(drain(&mut h, &a, r), b"abcde");
        vecs(&h, &[(16, 4), (src, 2)]);
        assert_eq!(vm(&mut h, w, 2, 0), e(EFAULT));
        vecs(&h, &[(src, 2), (16, 4)]);
        assert_eq!(vm(&mut h, w, 2, 0), 2);
        assert_eq!(drain(&mut h, &a, r), b"ab");
        // Out of it, up to the first byte that cannot be written (which
        // leaves the data), without sleeping after the first.
        write(&mut h, &a, w, b"hello");
        let (x, y) = (src + 0x100, src + 0x200);
        vecs(&h, &[(x, 2), (y, 10)]);
        assert_eq!(vm(&mut h, r, 2, 0), 5);
        assert_eq!(get(&h, x, 2), b"he");
        assert_eq!(get(&h, y, 3), b"llo");
        write(&mut h, &a, w, b"kept");
        vecs(&h, &[(16, 4)]);
        assert_eq!(vm(&mut h, r, 1, 0), e(EFAULT));
        assert_eq!(drain(&mut h, &a, r), b"kept");
        // Only SPLICE_F_NONBLOCK keeps it from sleeping: O_NONBLOCK does
        // not.
        vecs(&h, &[(x, 2)]);
        assert_eq!(vm(&mut h, r, 1, NONBLOCK), e(EAGAIN));
        h.ok(Sysno::Fcntl, &[r, F_SETFL, O_NONBLOCK]);
        assert_eq!(h.start(0, Sysno::Vmsplice, &[r, iov, 1, 0]), None);
        h.proc.threads[0].blocked = None;
        h.ok(Sysno::Close, &[w]);
        assert_eq!(vm(&mut h, r, 1, 0), 0, "the end");
        // No readers: EPIPE and SIGPIPE.
        handle_sigpipe(&mut h, &a);
        let (r, w) = pipe(&mut h, &a);
        h.ok(Sysno::Close, &[r]);
        vecs(&h, &[(src, 2)]);
        assert_eq!(vm(&mut h, w, 1, 0), e(EPIPE));
        assert!(sigpipe_pending(&mut h));
    });
}

#[test]
fn tee_checks_its_flags_before_its_length() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = area(&mut h);
        let (r, w) = pipe(&mut h, &a);
        let (qr, qw) = pipe(&mut h, &a);
        let f = h.file("tee", 4, b't', O_RDWR);
        let bad = u64::MAX;
        assert_eq!(h.call(Sysno::Tee, &[bad, bad, 0, 0x10]), e(EINVAL));
        assert_eq!(h.call(Sysno::Tee, &[bad, bad, 0, 0]), 0);
        assert_eq!(h.call(Sysno::Tee, &[bad, qw, 1, 0]), e(EBADF));
        assert_eq!(h.call(Sysno::Tee, &[r, bad, 1, 0]), e(EBADF));
        assert_eq!(h.call(Sysno::Tee, &[w, qw, 1, 0]), e(EBADF));
        assert_eq!(h.call(Sysno::Tee, &[r, qr, 1, 0]), e(EBADF));
        assert_eq!(h.call(Sysno::Tee, &[f, qw, 1, 0]), e(EINVAL));
        assert_eq!(h.call(Sysno::Tee, &[r, w, 1, 0]), e(EINVAL));
    });
}

/// `tee` copies what the input holds without consuming it, waiting as
/// `splice` waits.
#[cfg(target_os = "linux")]
#[test]
fn tee_copies_without_consuming() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = area(&mut h);
        let (r, w) = pipe(&mut h, &a);
        let (qr, qw) = pipe(&mut h, &a);
        write(&mut h, &a, w, b"hello");
        assert_eq!(h.call(Sysno::Tee, &[r, qw, 3, 0]), 3);
        assert_eq!(drain(&mut h, &a, qr), b"hel");
        assert_eq!(drain(&mut h, &a, r), b"hello");
        assert_eq!(h.call(Sysno::Tee, &[r, qw, 1, NONBLOCK]), e(EAGAIN));
        assert_eq!(h.start(0, Sysno::Tee, &[r, qw, 1, 0]), None);
        h.proc.threads[0].blocked = None;
        h.ok(Sysno::Close, &[w]);
        assert_eq!(h.call(Sysno::Tee, &[r, qw, 1, 0]), 0, "the end");
        handle_sigpipe(&mut h, &a);
        let (r, w) = pipe(&mut h, &a);
        write(&mut h, &a, w, b"x");
        h.ok(Sysno::Close, &[qr]);
        assert_eq!(h.call(Sysno::Tee, &[r, qw, 1, 0]), e(EPIPE));
        assert!(sigpipe_pending(&mut h));
    });
}

/// Without the host's `tee(2)`, a pipe cannot be copied without consuming
/// it: `EINVAL`, and the input keeps its data.
#[cfg(not(target_os = "linux"))]
#[test]
fn tee_is_refused_without_the_hosts() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = area(&mut h);
        let (r, w) = pipe(&mut h, &a);
        let (_qr, qw) = pipe(&mut h, &a);
        write(&mut h, &a, w, b"hello");
        assert_eq!(h.call(Sysno::Tee, &[r, qw, 3, 0]), e(EINVAL));
        assert_eq!(drain(&mut h, &a, r), b"hello");
    });
}

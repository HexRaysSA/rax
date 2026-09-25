//! Positioned vectored transfers (`fs/read_write.c`, Linux 6.19):
//! `preadv`, `pwritev`, and their `2` forms move each vector in turn from
//! the given position, pass over empty vectors (an `iov_iter` has nothing
//! to copy there), and stop at a short transfer.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;

const O_RDWR: u64 = 2;
/// `MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED`.
const MAP_FIXED_ANON: u64 = 0x32;

/// Writes `struct iovec`s `v` at `at`.
fn iovecs(h: &Harness, at: u64, v: &[(u64, u64)]) -> u64 {
    let b: Vec<u8> = v
        .iter()
        .flat_map(|&(base, len)| [base.to_le_bytes(), len.to_le_bytes()].concat())
        .collect();
    h.proc.state.space.write_raw(at, &b).unwrap();
    at
}

fn bytes(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

#[test]
fn empty_vectors_are_passed_over() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let fd = h.file(&format!("vec-{abi:?}"), 8, b'a', O_RDWR);
        // An empty vector first, one at an unmapped address among them:
        // nothing is copied there, so nothing faults.
        let (a, b) = (m + 0x100, m + 0x200);
        let v = iovecs(&h, m, &[(a, 0), (8, 0), (b, 3), (a, 0), (a, 2)]);
        assert_eq!(h.call(Sysno::Preadv, &[fd, v, 5, 1]), 5);
        assert_eq!(bytes(&h, b, 3), b"aaa");
        assert_eq!(bytes(&h, a, 2), b"aa");
        // Only empty vectors: nothing, and no error.
        let v = iovecs(&h, m, &[(8, 0), (a, 0)]);
        assert_eq!(h.call(Sysno::Preadv2, &[fd, v, 2, 0, 0, 0]), 0);
        assert_eq!(h.call(Sysno::Pwritev, &[fd, v, 2, 0]), 0);
        // Writes likewise.
        h.proc.state.space.write_raw(b, b"xyz").unwrap();
        let v = iovecs(&h, m, &[(8, 0), (b, 3), (a, 0)]);
        assert_eq!(h.call(Sysno::Pwritev2, &[fd, v, 3, 6, 0, 0]), 3);
        let v = iovecs(&h, m, &[(a, 9)]);
        assert_eq!(h.call(Sysno::Preadv, &[fd, v, 1, 0]), 9);
        assert_eq!(bytes(&h, a, 9), b"aaaaaaxyz");
        // A vector that faults still ends the transfer.
        let v = iovecs(&h, m, &[(8, 4)]);
        assert_eq!(h.err(Sysno::Preadv, &[fd, v, 1, 0]), EFAULT);
    });
}

#[test]
fn a_vector_longer_than_memory_reads_what_fits() {
    // A vector's length is the guest's to choose: a read into one far
    // longer than any mapping takes what the data and the memory allow,
    // and must not make the emulator size anything by the length.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let fds = m + 0x800;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let raw = bytes(&h, fds, 8);
        let (r, w) = (
            u64::from(u32::from_le_bytes(raw[..4].try_into().unwrap())),
            u64::from(u32::from_le_bytes(raw[4..].try_into().unwrap())),
        );
        h.proc.state.space.write_raw(m, b"hello").unwrap();
        h.ok(Sysno::Write, &[w, m, 5]);
        // import_ubuf caps one vector at MAX_RW_COUNT before access_ok: a
        // low buffer passes, one near the top of user space does not.
        let low = 0x1000_0000;
        h.ok(Sysno::Mmap, &[low, P, 3, MAP_FIXED_ANON, u64::MAX, 0]);
        let v = iovecs(&h, m + 0x400, &[(m + 0x100, 1 << 62)]);
        assert_eq!(h.err(Sysno::Readv, &[r, v, 1]), EFAULT);
        let v = iovecs(&h, m + 0x400, &[(low, 1 << 62)]);
        assert_eq!(h.call(Sysno::Readv, &[r, v, 1]), 5);
        assert_eq!(bytes(&h, low, 5), b"hello");
    });
}

/// Beyond user space on every ABI.
const KERNEL: u64 = 0xffff_8000_0000_0000;
/// `FIONREAD`.
const FIONREAD: u64 = 0x541b;

/// The bytes waiting on `fd`.
fn pending(h: &mut Harness, fd: u64, at: u64) -> u32 {
    h.ok(Sysno::Ioctl, &[fd, FIONREAD, at]);
    u32::from_le_bytes(bytes(h, at, 4).try_into().unwrap())
}

/// A `struct user_msghdr` at `at` naming vectors `iov` (`n` of them).
fn msghdr(h: &Harness, at: u64, iov: u64, n: u64) -> u64 {
    let mut b = vec![0u8; 56];
    b[16..24].copy_from_slice(&iov.to_le_bytes());
    b[24..32].copy_from_slice(&n.to_le_bytes());
    h.proc.state.space.write_raw(at, &b).unwrap();
    at
}

#[test]
fn vectors_are_imported_before_anything_moves() {
    // __import_iovec: each of several vectors must lie in user space at
    // its full length, so a transfer naming one that does not moves
    // nothing (EFAULT) and leaves a file's position; the count is an
    // unsigned int; a negative length is EINVAL once its vector is read.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let (a, b, q, scratch) = (m + 0x100, m + 0x200, m + 0x800, m + 0xf00);
        h.ok(Sysno::Pipe2, &[q, 0]);
        let raw = bytes(&h, q, 8);
        let (r, w) = (
            u64::from(u32::from_le_bytes(raw[..4].try_into().unwrap())),
            u64::from(u32::from_le_bytes(raw[4..].try_into().unwrap())),
        );
        h.proc.state.space.write_raw(a, b"hello").unwrap();
        let v = iovecs(&h, m, &[(a, 5), (KERNEL, 5)]);
        assert_eq!(h.err(Sysno::Writev, &[w, v, 2]), EFAULT);
        assert_eq!(pending(&mut h, r, scratch), 0, "nothing written");
        let v = iovecs(&h, m, &[(a, 5), (b, 1 << 62)]);
        assert_eq!(h.err(Sysno::Writev, &[w, v, 2]), EFAULT);
        assert_eq!(pending(&mut h, r, scratch), 0);
        h.ok(Sysno::Write, &[w, a, 3]);
        let v = iovecs(&h, m, &[(b, 2), (b + 8, 2)]);
        assert_eq!(h.call(Sysno::Readv, &[r, v, (1 << 32) | 1]), 2);
        assert_eq!(bytes(&h, b, 2), b"he");
        let neg = iovecs(&h, m + 0x40, &[(b, u64::MAX), (KERNEL, 1)]);
        assert_eq!(h.err(Sysno::Readv, &[r, neg, 2]), EINVAL);
        assert_eq!(h.err(Sysno::Readv, &[r, 16, 2]), EFAULT);
        assert_eq!(h.err(Sysno::Readv, &[r, v, 1025]), EINVAL);
        assert_eq!(h.call(Sysno::Readv, &[r, v, 0]), 0);
        // A file's position stays where it was.
        let fd = h.file(&format!("import-{abi:?}"), 10, b'f', O_RDWR);
        let bad = iovecs(&h, m + 0x80, &[(b, 3), (KERNEL, 3)]);
        assert_eq!(h.err(Sysno::Readv, &[fd, bad, 2]), EFAULT);
        assert_eq!(h.call(Sysno::Lseek, &[fd, 0, 1]), 0);
        assert_eq!(h.err(Sysno::Preadv, &[fd, bad, 2, 2]), EFAULT);
        assert_eq!(h.err(Sysno::Pwritev2, &[fd, bad, 2, 2, 0, 0]), EFAULT);
        assert_eq!(h.call(Sysno::Preadv, &[fd, v, (1 << 32) | 1, 4]), 2);
        // Sockets: the vectors are imported after the header's own checks.
        let sv = m + 0x900;
        h.ok(Sysno::Socketpair, &[1, 1, 0, sv]);
        let raw = bytes(&h, sv, 8);
        let (s0, s1) = (
            u64::from(u32::from_le_bytes(raw[..4].try_into().unwrap())),
            u64::from(u32::from_le_bytes(raw[4..].try_into().unwrap())),
        );
        let bad2 = iovecs(&h, m + 0xa00, &[(a, 5), (KERNEL, 5)]);
        let msg = msghdr(&h, m + 0xb00, bad2, 2);
        assert_eq!(h.err(Sysno::Sendmsg, &[s0, msg, 0x40]), EFAULT);
        assert_eq!(pending(&mut h, s1, scratch), 0, "nothing sent");
        let msg = msghdr(&h, m + 0xb00, bad2, (1 << 32) | 1);
        assert_eq!(h.err(Sysno::Sendmsg, &[s0, msg, 0x40]), EMSGSIZE);
        h.ok(Sysno::Sendto, &[s0, a, 2, 0, 0, 0]);
        let msg = msghdr(&h, m + 0xb00, bad2, 2);
        assert_eq!(h.err(Sysno::Recvmsg, &[s1, msg, 0x40]), EFAULT);
        assert_eq!(pending(&mut h, s1, scratch), 2, "left queued");
    });
}

#[test]
fn rwf_flags_are_refused_as_kiocb_set_rw_flags_refuses_them() {
    // Linux 6.19's RWF_SUPPORTED adds RWF_NOAPPEND, RWF_ATOMIC,
    // RWF_DONTCACHE, and RWF_NOSIGNAL; RWF_APPEND with RWF_NOAPPEND is
    // EINVAL, RWF_ATOMIC needs FMODE_CAN_ATOMIC_WRITE, RWF_DONTCACHE
    // FOP_DONTCACHE (which pipes lack), and RWF_NOSIGNAL spares a broken
    // pipe's writer SIGPIPE.
    use crate::user::linux::signal::{SIGPIPE, SigPending, sa};
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let fd = h.file(&format!("rwf-{abi:?}"), 8, b'r', O_RDWR);
        let v = iovecs(&h, m, &[(m + 0x100, 4)]);
        for flags in [0x20, 0x80, 0x100, 0x1f] {
            assert_eq!(
                h.call(Sysno::Preadv2, &[fd, v, 1, 0, 0, flags]),
                4,
                "{flags:#x}"
            );
        }
        assert_eq!(h.err(Sysno::Preadv2, &[fd, v, 1, 0, 0, 0x200]), EOPNOTSUPP);
        assert_eq!(h.err(Sysno::Pwritev2, &[fd, v, 1, 0, 0, 0x30]), EINVAL);
        assert_eq!(h.err(Sysno::Pwritev2, &[fd, v, 1, 0, 0, 0x40]), EOPNOTSUPP);
        assert_eq!(h.err(Sysno::Preadv2, &[fd, v, 1, 0, 0, 0x40]), EOPNOTSUPP);
        let q = m + 0x800;
        h.ok(Sysno::Pipe2, &[q, 0]);
        let raw = bytes(&h, q, 8);
        let (r, w) = (
            u64::from(u32::from_le_bytes(raw[..4].try_into().unwrap())),
            u64::from(u32::from_le_bytes(raw[4..].try_into().unwrap())),
        );
        let pipe_v = u64::MAX;
        assert_eq!(
            h.err(Sysno::Preadv2, &[r, v, 1, pipe_v, 0, 0x80]),
            EOPNOTSUPP
        );
        // A handler keeps a sent SIGPIPE queued.
        let act = m + 0xf00;
        let mut words = vec![0x40_1000u64];
        if h.abi().has_sa_restorer() {
            words.extend([sa::RESTORER, 0x40_1100]);
        } else {
            words.push(0);
        }
        words.push(0);
        let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        h.proc.state.space.write_raw(act, &b).unwrap();
        h.ok(Sysno::RtSigaction, &[SIGPIPE as u64, act, 0, 8]);
        h.ok(Sysno::Close, &[r]);
        assert_eq!(h.err(Sysno::Pwritev2, &[w, v, 1, pipe_v, 0, 0x100]), EPIPE);
        assert!(!h.proc.threads[0].pending.contains(SIGPIPE), "{abi:?}");
        assert_eq!(h.err(Sysno::Pwritev2, &[w, v, 1, pipe_v, 0, 0]), EPIPE);
        assert!(h.proc.threads[0].pending.contains(SIGPIPE), "{abi:?}");
        h.proc.threads[0].pending = SigPending::new();
    });
}

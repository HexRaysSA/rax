//! Positioned vectored transfers (`fs/read_write.c`, Linux 6.19):
//! `preadv`, `pwritev`, and their `2` forms move each vector in turn from
//! the given position, pass over empty vectors (an `iov_iter` has nothing
//! to copy there), and stop at a short transfer.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;

const O_RDWR: u64 = 2;

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
        let buf = m + 0x100;
        let v = iovecs(&h, m + 0x400, &[(buf, 1 << 62)]);
        assert_eq!(h.call(Sysno::Readv, &[r, v, 1]), 5);
        assert_eq!(bytes(&h, buf, 5), b"hello");
    });
}

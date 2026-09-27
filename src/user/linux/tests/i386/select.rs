//! i386 `select`, `pselect6`, and `ppoll` against Linux 6.19 on x86-64
//! (the `CONFIG_COMPAT` part of `fs/select.c`): fd sets of 32-bit words,
//! `struct old_timeval32` in and out, the old `select`'s `struct
//! compat_sel_arg_struct`, `struct compat_sigset_argpack`, and the
//! `*_time32` timeouts beside the `*_time64` ones.

use super::super::harness::Harness;
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const P: u64 = 4096;
const POLLIN: u16 = 1;
/// -1 in a 32-bit register.
const MINUS_1: u64 = u32::MAX as u64;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// The end of a page whose successor is not mapped.
fn page_end(h: &mut Harness) -> u64 {
    let at = h.ok(Sysno::Mmap2, &[0, 2 * P, 3, 0x22, MINUS_1, 0]);
    h.ok(Sysno::Munmap, &[at + P, P]);
    at + P
}

/// A pipe with a byte in it: (read end, write end).
fn ready_pipe(h: &mut Harness) -> (u64, u64) {
    let at = h.scratch + 0xF00;
    h.ok(Sysno::Pipe, &[at]);
    let (r, w) = (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)));
    put(h, at, b"x");
    assert_eq!(h.call(Sysno::Write, &[w, at, 1]), 1);
    (r, w)
}

#[test]
fn fd_sets_are_32_bit_words() {
    let mut h = Harness::new(LinuxAbi::I386);
    let end = page_end(&mut h);
    let (r, _) = ready_pipe(&mut h);
    let bit = 1u32 << r;
    // One word read at a page's end.
    let one = end - 4;
    put(&h, one, &bit.to_le_bytes());
    assert_eq!(h.call(Sysno::Newselect, &[10, one, 0, 0, 0]), 1);
    assert_eq!(u32_at(&h, one), bit);
    // One word written back, bits past the count cleared.
    let set = h.scratch;
    put(&h, set, &words(&[bit | 1 << 20, 0xEEEE_EEEE]));
    assert_eq!(h.call(Sysno::Newselect, &[10, set, 0, 0, 0]), 1);
    assert_eq!((u32_at(&h, set), u32_at(&h, set + 4)), (bit, 0xEEEE_EEEE));
    // 33 descriptors take two words.
    put(&h, one, &bit.to_le_bytes());
    assert_eq!(h.err(Sysno::Newselect, &[33, one, 0, 0, 0]), EFAULT);
    // The old select's struct compat_sel_arg_struct, five words.
    let args = end - 20;
    put(&h, set, &bit.to_le_bytes());
    put(&h, args, &words(&[10, set as u32, 0, 0, 0]));
    assert_eq!(h.call(Sysno::Select, &[args]), 1);
    assert_eq!(u32_at(&h, set), bit);
}

#[test]
fn timeouts_are_32_bit_in_and_out() {
    let mut h = Harness::new(LinuxAbi::I386);
    let end = page_end(&mut h);
    let (r, _) = ready_pipe(&mut h);
    let empty = h.scratch;
    // struct old_timeval32: read, and written back, at 8 bytes.
    let tv = end - 8;
    put(&h, empty, &[0; 4]);
    put(&h, tv, &words(&[0, 1000]));
    assert_eq!(h.call(Sysno::Newselect, &[10, empty, 0, 0, tv]), 0);
    assert_eq!((u32_at(&h, tv), u32_at(&h, tv + 4)), (0, 0));
    put(&h, tv, &words(&[0, u32::MAX]));
    assert_eq!(h.err(Sysno::Newselect, &[10, empty, 0, 0, tv]), EINVAL);
    // pselect6_time32: struct old_timespec32 and struct
    // compat_sigset_argpack.
    let (mask, pack) = (h.scratch + 0x100, end - 8);
    put(&h, mask, &[0; 8]);
    put(&h, pack, &words(&[mask as u32, 8]));
    let set = h.scratch + 0x200;
    put(&h, set, &(1u32 << r).to_le_bytes());
    assert_eq!(h.call(Sysno::Pselect6, &[10, set, 0, 0, 0, pack]), 1);
    put(&h, pack, &words(&[mask as u32, 16]));
    assert_eq!(h.err(Sysno::Pselect6, &[10, set, 0, 0, 0, pack]), EINVAL);
    let ts = end - 8;
    put(&h, ts, &words(&[0, 1_000_000_000]));
    assert_eq!(h.err(Sysno::Pselect6, &[10, empty, 0, 0, ts, 0]), EINVAL);
    // pselect6_time64 clears the padding above tv_nsec.
    let ts64 = h.scratch + 0x300;
    put(&h, ts64, &words(&[0, 0, 1000, u32::MAX]));
    assert_eq!(
        h.call(Sysno::Pselect6Time64, &[10, empty, 0, 0, ts64, 0]),
        0
    );
    // ppoll_time32 writes back 8 bytes, ppoll_time64 16.
    let pfd = h.scratch + 0x400;
    put(
        &h,
        pfd,
        &[
            words(&[r as u32]),
            POLLIN.to_le_bytes().to_vec(),
            vec![0; 2],
        ]
        .concat(),
    );
    put(&h, ts, &words(&[1, 0]));
    assert_eq!(h.call(Sysno::Ppoll, &[pfd, 1, ts, 0, 8]), 1);
    assert!(u32_at(&h, ts) <= 1 && u32_at(&h, ts + 4) < 1_000_000_000);
    put(&h, ts64, &words(&[1, 0, 0, u32::MAX]));
    assert_eq!(h.call(Sysno::PpollTime64, &[pfd, 1, ts64, 0, 8]), 1);
    assert_eq!(u32_at(&h, ts64 + 12), 0);
}

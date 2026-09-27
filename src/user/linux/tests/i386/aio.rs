//! i386 asynchronous I/O against Linux 6.19 on x86-64 (the `CONFIG_COMPAT`
//! parts of `fs/aio.c`): `compat_sys_io_setup`'s 32-bit context,
//! `compat_sys_io_submit`'s `compat_uptr_t` array and `int` count,
//! `io_getevents_time32`'s `__s32` counts and `struct old_timespec32`, and
//! `compat_sys_io_pgetevents`'s `struct __compat_aio_sigset` and
//! `compat_long_t` counts.

use super::super::harness::Harness;
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const P: u64 = 4096;
const IOCB_CMD_PREAD: u16 = 0;
/// -1 in a 32-bit register.
const MINUS_1: u64 = u32::MAX as u64;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn read(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from_le_bytes(read(h, at, 8).try_into().unwrap())
}

/// A `struct iocb` reading `n` bytes of `fd` at `off` into `buf`.
fn pread(h: &Harness, at: u64, data: u64, fd: u32, buf: u64, n: u64, off: u64) {
    let mut b = [0u8; 64];
    b[0..8].copy_from_slice(&data.to_le_bytes());
    b[16..18].copy_from_slice(&IOCB_CMD_PREAD.to_le_bytes());
    b[20..24].copy_from_slice(&fd.to_le_bytes());
    b[24..32].copy_from_slice(&buf.to_le_bytes());
    b[32..40].copy_from_slice(&n.to_le_bytes());
    b[40..48].copy_from_slice(&off.to_le_bytes());
    put(h, at, &b);
}

/// The end of a page whose successor is not mapped: a structure placed
/// just below it can be read only at its 32-bit size.
fn page_end(h: &mut Harness) -> u64 {
    let anon = 0x22;
    let at = h.ok(Sysno::Mmap2, &[0, 2 * P, 3, anon, MINUS_1, 0]);
    h.ok(Sysno::Munmap, &[at + P, P]);
    at + P
}

#[test]
fn contexts_iocbs_and_counts_are_32_bit() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = h.scratch;
    let (ctxp, iocbs, list, buf, events) = (m, m + 0x100, m + 0x200, m + 0x300, m + 0x400);
    let end = page_end(&mut h);
    // compat_sys_io_setup reads and writes 32 bits: the word above is
    // neither checked nor changed.
    put(&h, ctxp, &words(&[0, 1]));
    assert_eq!(h.call(Sysno::IoSetup, &[4, ctxp]), 0);
    let ctx = u64::from(u32_at(&h, ctxp));
    assert!(ctx != 0);
    assert_eq!(u32_at(&h, ctxp + 4), 1);
    // Two reads of a memfd, through an array of 32-bit iocb pointers.
    put(&h, m + 0xF00, b"a\0");
    let fd = h.ok(Sysno::MemfdCreate, &[m + 0xF00, 0]);
    put(&h, buf, b"hello");
    assert_eq!(h.call(Sysno::Write, &[fd, buf, 5]), 5);
    put(&h, buf, &[0; 16]);
    pread(&h, iocbs, 7, fd as u32, buf, 5, 0);
    pread(&h, iocbs + 64, 8, fd as u32, buf + 8, 2, 3);
    put(&h, list, &words(&[iocbs as u32, iocbs as u32 + 64]));
    // compat_sys_io_submit's count is an int: -1 is EINVAL.
    assert_eq!(h.err(Sysno::IoSubmit, &[ctx, MINUS_1, list]), EINVAL);
    assert_eq!(h.call(Sysno::IoSubmit, &[ctx, 2, list]), 2);
    // io_getevents_time32: __s32 counts, and a timeout of 8 bytes.
    assert_eq!(
        h.err(Sysno::IoGetevents, &[ctx, 0, MINUS_1, events, 0]),
        EINVAL
    );
    let ts = end - 8;
    put(&h, ts, &[0; 8]);
    assert_eq!(h.call(Sysno::IoGetevents, &[ctx, 2, 2, events, ts]), 2);
    // struct io_event: data, obj, res, res2.
    assert_eq!((u64_at(&h, events), u64_at(&h, events + 8)), (7, iocbs));
    assert_eq!(u64_at(&h, events + 16), 5);
    assert_eq!((u64_at(&h, events + 32), u64_at(&h, events + 48)), (8, 2));
    assert_eq!(
        (read(&h, buf, 5), read(&h, buf + 8, 2)),
        (b"hello".to_vec(), b"lo".to_vec())
    );
    h.ok(Sysno::IoDestroy, &[ctx]);
}

#[test]
fn pgetevents_reads_compat_aio_sigset() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = h.scratch;
    let (ctxp, events, mask) = (m, m + 0x100, m + 0x200);
    let end = page_end(&mut h);
    put(&h, ctxp, &[0; 4]);
    assert_eq!(h.call(Sysno::IoSetup, &[1, ctxp]), 0);
    let ctx = u64::from(u32_at(&h, ctxp));
    // struct __compat_aio_sigset { sigmask, sigsetsize }: 8 bytes.
    let sig = end - 8;
    put(&h, mask, &[0; 8]);
    put(&h, sig, &words(&[mask as u32, 8]));
    assert_eq!(h.call(Sysno::IoPgetevents, &[ctx, 0, 1, events, 0, sig]), 0);
    assert_eq!(
        h.call(Sysno::IoPgeteventsTime64, &[ctx, 0, 1, events, 0, sig]),
        0
    );
    // compat_long_t counts.
    assert_eq!(
        h.err(Sysno::IoPgetevents, &[ctx, 0, MINUS_1, events, 0, sig]),
        EINVAL
    );
    // set_compat_user_sigmask: the size must be compat_sigset_t's.
    put(&h, sig, &words(&[mask as u32, 16]));
    assert_eq!(
        h.err(Sysno::IoPgetevents, &[ctx, 0, 1, events, 0, sig]),
        EINVAL
    );
    h.ok(Sysno::IoDestroy, &[ctx]);
}

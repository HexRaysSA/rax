//! i386 seccomp filters against Linux 6.19 on x86-64 (`kernel/seccomp.c`'s
//! `seccomp_prepare_user_filter`): `struct compat_sock_fprog` through
//! `seccomp` and `prctl`, and the `struct seccomp_data` of a 32-bit call
//! (`AUDIT_ARCH_I386`, i386 numbers, zero-extended arguments).

use super::super::harness::Harness;
use super::put;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const P: u64 = 4096;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_SET_SECCOMP: u64 = 22;
const SECCOMP_MODE_FILTER: u64 = 2;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
/// i386 `getpid`, `getppid`, and `close`.
const NR_GETPID: u32 = 20;
const NR_GETPPID: u32 = 64;
/// -1 in a 32-bit register.
const MINUS_1: u64 = u32::MAX as u64;

/// A `struct sock_filter`.
fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Vec<u8> {
    [
        code.to_le_bytes().to_vec(),
        vec![jt, jf],
        k.to_le_bytes().to_vec(),
    ]
    .concat()
}

fn ld(off: u32) -> Vec<u8> {
    insn(0x20, 0, 0, off)
}

fn jeq(k: u32, jt: u8, jf: u8) -> Vec<u8> {
    insn(0x15, jt, jf, k)
}

fn ret(k: u32) -> Vec<u8> {
    insn(0x06, 0, 0, k)
}

/// The end of a page whose successor is not mapped.
fn page_end(h: &mut Harness) -> u64 {
    let at = h.ok(Sysno::Mmap2, &[0, 2 * P, 3, 0x22, MINUS_1, 0]);
    h.ok(Sysno::Munmap, &[at + P, P]);
    at + P
}

/// A `struct compat_sock_fprog` for the program at `prog` at `end - 8`.
fn fprog(h: &Harness, end: u64, prog: u64, len: u16) -> u64 {
    let at = end - 8;
    put(
        h,
        at,
        &[u32::from(len).to_le_bytes(), (prog as u32).to_le_bytes()].concat(),
    );
    at
}

#[test]
fn filters_see_the_32_bit_call() {
    let mut h = Harness::new(LinuxAbi::I386);
    let end = page_end(&mut h);
    h.ok(Sysno::Prctl, &[PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0]);
    // The architecture, getpid refused with EIO, then the high word of
    // the first argument.
    let prog: Vec<u8> = [
        ld(4),
        jeq(AUDIT_ARCH_I386, 1, 0),
        ret(RET_KILL_PROCESS),
        ld(0),
        jeq(NR_GETPID, 0, 1),
        ret(RET_ERRNO | EIO as u32),
        ld(20),
        jeq(0, 1, 0),
        ret(RET_KILL_PROCESS),
        ret(RET_ALLOW),
    ]
    .concat();
    let at = h.scratch;
    put(&h, at, &prog);
    let empty = fprog(&h, end, at, 0);
    assert_eq!(
        h.err(Sysno::Seccomp, &[SECCOMP_SET_MODE_FILTER, 0, empty]),
        EINVAL
    );
    let f = fprog(&h, end, at, 10);
    assert_eq!(h.call(Sysno::Seccomp, &[SECCOMP_SET_MODE_FILTER, 0, f]), 0);
    assert_eq!(h.err(Sysno::Getpid, &[]), EIO);
    // A 32-bit -1 reaches the filter zero-extended.
    assert_eq!(h.err(Sysno::Close, &[MINUS_1]), EBADF);
    // prctl(PR_SET_SECCOMP) reads the same structure.
    let deny: Vec<u8> = [
        ld(0),
        jeq(NR_GETPPID, 0, 1),
        ret(RET_ERRNO | EPERM as u32),
        ret(RET_ALLOW),
    ]
    .concat();
    put(&h, at + 0x100, &deny);
    let f = fprog(&h, end, at + 0x100, 4);
    let set = [PR_SET_SECCOMP, SECCOMP_MODE_FILTER, f, 0, 0];
    assert_eq!(h.call(Sysno::Prctl, &set), 0);
    assert_eq!(h.err(Sysno::Getppid, &[]), EPERM);
}

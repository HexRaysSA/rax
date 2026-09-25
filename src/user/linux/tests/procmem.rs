//! `process_vm_readv`, `process_vm_writev`, and `process_madvise` against
//! `mm/process_vm_access.c`, `mm/gup.c`, `lib/iov_iter.c`, and
//! `mm/madvise.c` (Linux 6.19), through the system calls on every ABI:
//! the checks in order, vector import (`access_ok` and `MAX_RW_COUNT`),
//! transfers by page with `VM_READ` and `VM_WRITE`, partial transfers at a
//! remote or local fault, the tasks that can be named, and advice by
//! vector. Every expectation was checked on a Linux 7.0 kernel.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::syscall::thread::cf::*;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const RW: u64 = PROT_READ | PROT_WRITE;
/// Never mapped (below `mmap_min_addr`).
const BAD: u64 = 0x10;
/// Beyond user space on every ABI.
const KERNEL: u64 = 0xffff_8000_0000_0000;
const THREAD: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
const MADV_DONTNEED: u64 = 4;
const MADV_WILLNEED: u64 = 3;
const PIDFD_SELF_THREAD: u64 = -10000i64 as u64;
const PIDFD_SELF_THREAD_GROUP: u64 = -10001i64 as u64;
const PIDFD_THREAD: u64 = 0o200;
/// `MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED`.
const MAP_FIXED_ANON: u64 = 0x32;

/// A process that is not the caller's: the host process that started the
/// tests, which exists and belongs to the same user.
fn other_process() -> u64 {
    u64::from(std::os::unix::process::parent_id())
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    b
}

/// `struct iovec`s at `at`; their address.
fn iov(h: &Harness, at: u64, v: &[(u64, u64)]) -> u64 {
    let b: Vec<u8> = v
        .iter()
        .flat_map(|&(base, len)| [base.to_le_bytes(), len.to_le_bytes()].concat())
        .collect();
    put(h, at, &b);
    at
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + 3) as u8).collect()
}

fn readv(h: &mut Harness, pid: u64, l: u64, ln: u64, r: u64, rn: u64) -> i64 {
    h.call(Sysno::ProcessVmReadv, &[pid, l, ln, r, rn, 0])
}

fn writev(h: &mut Harness, pid: u64, l: u64, ln: u64, r: u64, rn: u64) -> i64 {
    h.call(Sysno::ProcessVmWritev, &[pid, l, ln, r, rn, 0])
}

#[test]
fn process_vm_rw_checks_in_the_kernels_order() {
    // process_vm_rw: flags; import_iovec of the local vectors (an empty
    // transfer returns 0 before anything else); iovec_from_user of the
    // remote ones (none with a length returns 0 before the task is
    // looked up); the task; the right to its memory.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, RW, false);
        let (a, buf) = (m, m + P);
        let me = h.proc.state.pid as u64;
        let (l, r) = (
            iov(&h, a, &[(buf, 16)]),
            iov(&h, a + 0x100, &[(m + 2 * P, 16)]),
        );
        let e = |v: i32| -(v as i64);
        assert_eq!(
            h.call(Sysno::ProcessVmReadv, &[me, l, 1, r, 1, 1]),
            e(EINVAL)
        );
        assert_eq!(readv(&mut h, me, l, 1025, r, 1), e(EINVAL));
        assert_eq!(readv(&mut h, me, BAD, 1, r, 1), e(EFAULT));
        let neg = iov(&h, a + 0x200, &[(buf, u64::MAX)]);
        assert_eq!(readv(&mut h, me, neg, 1, r, 1), e(EINVAL));
        assert_eq!(readv(&mut h, me, l, 1, neg, 1), e(EINVAL));
        let kern = iov(&h, a + 0x300, &[(buf, 10), (KERNEL, 10)]);
        assert_eq!(readv(&mut h, me, kern, 2, r, 1), e(EFAULT), "access_ok");
        let rkern = iov(&h, a + 0x340, &[(KERNEL, 10)]);
        assert_eq!(readv(&mut h, me, l, 1, rkern, 1), e(EFAULT), "no VMA");
        // One vector is capped at MAX_RW_COUNT before access_ok, several
        // are checked at full length.
        let low = 0x1000_0000;
        h.ok(Sysno::Mmap, &[low, P, RW, MAP_FIXED_ANON, u64::MAX, 0]);
        let one = iov(&h, a + 0x380, &[(low, 1 << 62)]);
        assert_eq!(readv(&mut h, me, one, 1, r, 1), 16, "capped, then checked");
        let two = iov(&h, a + 0x3c0, &[(low, 1 << 62), (buf, 1)]);
        assert_eq!(readv(&mut h, me, two, 2, r, 1), e(EFAULT), "full length");
        let top = iov(&h, a + 0x3e0, &[(buf, 1 << 62)]);
        assert_eq!(
            readv(&mut h, me, top, 1, r, 1),
            e(EFAULT),
            "capped, too far"
        );
        // The count is an unsigned int to import_iovec.
        assert_eq!(readv(&mut h, me, l, (1 << 32) | 1, r, 1), 16);
        // Empty transfers.
        let empty = iov(&h, a + 0x400, &[(buf, 0)]);
        assert_eq!(readv(&mut h, 99999, empty, 1, r, 1), 0);
        assert_eq!(readv(&mut h, 99999, l, 0, r, 1), 0);
        assert_eq!(readv(&mut h, 99999, l, 1, BAD, 1), e(EFAULT));
        assert_eq!(readv(&mut h, 99999, l, 1, r, 1025), e(EINVAL));
        let rempty = iov(&h, a + 0x440, &[(BAD, 0), (BAD, 0)]);
        assert_eq!(readv(&mut h, 99999, l, 1, rempty, 2), 0);
        assert_eq!(readv(&mut h, 99999, l, 1, r, 0), 0);
        assert_eq!(readv(&mut h, 99999, l, 1, r, 1), e(ESRCH));
        assert_eq!(readv(&mut h, 0, l, 1, r, 1), e(ESRCH));
        assert_eq!(writev(&mut h, u64::MAX, l, 1, r, 1), e(ESRCH));
    });
}

#[test]
fn transfers_go_page_by_page_with_vm_read_and_vm_write() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(8 * P, RW, false);
        let (a, dst) = (m, m + P);
        let src = h.anon(2 * P, RW, false);
        let data = pattern(2 * P as usize);
        put(&h, src, &data);
        let me = h.proc.state.pid as u64;
        // Vectors on both sides, the local ones filled in order.
        let l = iov(&h, a, &[(dst, 3), (dst + 100, 0), (dst + 200, 5)]);
        let r = iov(&h, a + 0x100, &[(src + 10, 2), (src + 20, 10)]);
        assert_eq!(readv(&mut h, me, l, 3, r, 2), 8);
        assert_eq!(get(&h, dst, 3), [data[10], data[11], data[20]]);
        assert_eq!(get(&h, dst + 200, 5), data[21..26]);
        // A thread names the same memory.
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        let l = iov(&h, a, &[(dst, 8)]);
        let r = iov(&h, a + 0x100, &[(src, 8)]);
        assert_eq!(readv(&mut h, tid, l, 1, r, 1), 8);
        let far = iov(&h, a + 0x200, &[(src + P, 8)]);
        assert_eq!(writev(&mut h, tid, l, 1, far, 1), 8);
        assert_eq!(get(&h, src + P, 8), data[..8]);

        // A remote fault ends the transfer at the pages reached.
        h.ok(Sysno::Munmap, &[src + P, P]);
        let l = iov(&h, a, &[(dst, 4 * P)]);
        let r = iov(&h, a + 0x100, &[(src + 100, 2 * P)]);
        assert_eq!(readv(&mut h, me, l, 1, r, 1), (P - 100) as i64);
        assert_eq!(get(&h, dst, 16), data[100..116]);
        let r = iov(&h, a + 0x100, &[(src + P, 10)]);
        assert_eq!(readv(&mut h, me, l, 1, r, 1), -(EFAULT as i64));
        let r = iov(&h, a + 0x100, &[(src, 10), (src + P, 10)]);
        assert_eq!(readv(&mut h, me, l, 1, r, 2), 10);

        // Reading needs VM_READ, which write-only and execute-only
        // protections lack; writing needs VM_WRITE (no FOLL_FORCE).
        let r = iov(&h, a + 0x100, &[(src, 16)]);
        for prot in [PROT_WRITE, PROT_EXEC, 0] {
            h.ok(Sysno::Mprotect, &[src, P, prot]);
            assert_eq!(readv(&mut h, me, l, 1, r, 1), -(EFAULT as i64), "{prot}");
        }
        h.ok(Sysno::Mprotect, &[src, P, PROT_READ]);
        assert_eq!(readv(&mut h, me, l, 1, r, 1), 16);
        assert_eq!(writev(&mut h, me, l, 1, r, 1), -(EFAULT as i64));
        h.ok(Sysno::Mprotect, &[src, P, PROT_WRITE]);
        put(&h, dst, &[0xAB; 16]);
        assert_eq!(writev(&mut h, me, l, 1, r, 1), 16);
        h.ok(Sysno::Mprotect, &[src, P, RW]);
        assert_eq!(get(&h, src, 16), [0xAB; 16]);

        // A local fault ends it exactly where the local side stops.
        let ro = m + 4 * P;
        h.ok(Sysno::Mprotect, &[ro, P, PROT_READ]);
        let l = iov(&h, a, &[(ro - 100, 1000)]);
        let r = iov(&h, a + 0x100, &[(src, 1000)]);
        assert_eq!(readv(&mut h, me, l, 1, r, 1), 100);
        let l = iov(&h, a, &[(ro, 10)]);
        assert_eq!(readv(&mut h, me, l, 1, r, 1), -(EFAULT as i64));
        let none = m + 6 * P;
        h.ok(Sysno::Mprotect, &[none, P, 0]);
        put(&h, none - 30, &[0x5A; 30]);
        let l = iov(&h, a, &[(none - 30, 100)]);
        assert_eq!(writev(&mut h, me, l, 1, r, 1), 30);
        assert_eq!(
            get(&h, src, 31),
            [[0x5A; 30].as_slice(), &data[30..31]].concat()
        );
    });
}

#[test]
fn another_process_or_an_exited_leader_is_out_of_reach() {
    // mm_access: a task without memory is ESRCH (the leader after its
    // exit); another process's memory is refused as ptrace_may_access
    // refuses it (EACCES, reported as EPERM).
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(2 * P, RW, false);
        let me = h.proc.state.pid as u64;
        let l = iov(&h, m, &[(m + P, 8)]);
        let r = iov(&h, m + 0x100, &[(m + P + 64, 8)]);
        h.proc.state.config.processes = true;
        assert_eq!(readv(&mut h, other_process(), l, 1, r, 1), -(EPERM as i64));
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        assert_eq!(h.start(0, Sysno::Exit, &[0]), None);
        let w = h.index_of(tid);
        let args = [me, l, 1, r, 1, 0];
        assert_eq!(
            h.start(w, Sysno::ProcessVmReadv, &args),
            Some(-(ESRCH as i64))
        );
        let args = [tid as u64, l, 1, r, 1, 0];
        assert_eq!(h.start(w, Sysno::ProcessVmReadv, &args), Some(8));
    });
}

#[test]
fn process_madvise_advises_the_callers_memory_by_vector() {
    // process_madvise: flags, the vectors, the pidfd's task, mm_access;
    // then vector_madvise, whose iterator starts at the first vector even
    // when it is empty and passes the empty ones after each vector.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = h.anon(P, RW, false);
        let m = h.anon(2 * P, RW, false);
        let me = h.proc.state.pid as u64;
        let pfd = h.ok(Sysno::PidfdOpen, &[me, 0]);
        let e = |v: i32| -(v as i64);
        let call = |h: &mut Harness, fd: u64, v: &[(u64, u64)], adv: u64| {
            let at = iov(h, a, v);
            h.call(Sysno::ProcessMadvise, &[fd, at, v.len() as u64, adv, 0])
        };
        h.fill(m, 2 * P, 5);
        assert_eq!(
            call(&mut h, pfd, &[(m, P), (m + P, P)], MADV_DONTNEED),
            2 * P as i64
        );
        assert_eq!((h.byte(m), h.byte(m + P)), (0, 0));
        let v = iov(&h, a, &[(m, P)]);
        assert_eq!(
            h.call(Sysno::ProcessMadvise, &[pfd, v, 1, MADV_WILLNEED, 1]),
            e(EINVAL)
        );
        assert_eq!(
            h.call(Sysno::ProcessMadvise, &[u64::MAX, BAD, 2, 0, 0]),
            e(EFAULT)
        );
        assert_eq!(
            h.call(Sysno::ProcessMadvise, &[pfd, v, 1025, 0, 0]),
            e(EINVAL)
        );
        assert_eq!(call(&mut h, u64::MAX, &[(m, P)], MADV_WILLNEED), e(EBADF));
        assert_eq!(call(&mut h, 99, &[(m, P)], MADV_WILLNEED), e(EBADF));
        let efd = h.ok(Sysno::Eventfd2, &[0, 0]);
        assert_eq!(
            call(&mut h, efd, &[(m, P)], MADV_WILLNEED),
            e(EBADF),
            "not a pidfd"
        );
        assert_eq!(
            call(&mut h, PIDFD_SELF_THREAD, &[(m, P)], MADV_WILLNEED),
            P as i64
        );
        let group = PIDFD_SELF_THREAD_GROUP;
        assert_eq!(call(&mut h, group, &[(m, P)], MADV_WILLNEED), P as i64);
        // Empty and misaligned vectors.
        let dn = MADV_DONTNEED;
        assert_eq!(call(&mut h, pfd, &[(m + 1, 0), (m, P)], dn), e(EINVAL));
        assert_eq!(
            call(&mut h, pfd, &[(m, P), (m + 1, 0), (m + P, P)], dn),
            2 * P as i64
        );
        assert_eq!(call(&mut h, pfd, &[(m, P), (m + 1, P)], dn), P as i64);
        assert_eq!(call(&mut h, pfd, &[(m + 1, 0)], dn), 0);
        assert_eq!(call(&mut h, pfd, &[(m + 1, 0), (m + 1, 0)], dn), 0);
        assert_eq!(call(&mut h, pfd, &[(KERNEL, P)], dn), e(EFAULT));
        assert_eq!(
            call(&mut h, pfd, &[(m, 1 << 40)], dn),
            e(EFAULT),
            "capped, too far"
        );
        let low = 0x1000_0000;
        h.ok(Sysno::Mmap, &[low, P, RW, MAP_FIXED_ANON, u64::MAX, 0]);
        let wn = MADV_WILLNEED;
        assert_eq!(
            call(&mut h, pfd, &[(low, 1 << 40)], wn),
            e(ENOMEM),
            "capped"
        );
        assert_eq!(call(&mut h, pfd, &[(low, 1 << 62), (m, P)], wn), e(EFAULT));
        assert_eq!(call(&mut h, pfd, &[(m, P)], 999), e(EINVAL));
        // A pidfd for a thread other than the leader names no leader.
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        let tfd = h.ok(Sysno::PidfdOpen, &[tid, PIDFD_THREAD]);
        assert_eq!(call(&mut h, tfd, &[(m, P)], MADV_WILLNEED), e(ESRCH));
        // Another process: mm_access's EACCES stands.
        h.proc.state.config.processes = true;
        let other = h.ok(Sysno::PidfdOpen, &[other_process(), 0]);
        assert_eq!(call(&mut h, other, &[(m, P)], MADV_WILLNEED), e(EACCES));
        // The leader gone, its memory is.
        assert_eq!(h.start(0, Sysno::Exit, &[0]), None);
        let w = h.index_of(tid as i32);
        let v = iov(&h, a, &[(m, P)]);
        let args = [group, v, 1, MADV_WILLNEED, 0];
        assert_eq!(h.start(w, Sysno::ProcessMadvise, &args), Some(e(ESRCH)));
        let args = [pfd, v, 1, MADV_WILLNEED, 0];
        assert_eq!(h.start(w, Sysno::ProcessMadvise, &args), Some(e(ESRCH)));
        let args = [PIDFD_SELF_THREAD, v, 1, MADV_WILLNEED, 0];
        assert_eq!(h.start(w, Sysno::ProcessMadvise, &args), Some(P as i64));
    });
}

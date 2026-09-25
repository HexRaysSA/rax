//! `kcmp` against `kernel/kcmp.c` (Linux 6.19), through the system call on
//! every ABI: the checks in order, open file descriptions, the objects
//! threads share or keep apart (address space, tables, signal handlers,
//! I/O contexts, semaphore undo lists), epoll items, an exited leader, and
//! another process. Every expectation was checked on a Linux 7.0 kernel.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::syscall::thread::cf::*;

const KCMP_FILE: u64 = 0;
const KCMP_VM: u64 = 1;
const KCMP_SIGHAND: u64 = 4;
const KCMP_IO: u64 = 5;
const KCMP_SYSVSEM: u64 = 6;
const KCMP_EPOLL_TFD: u64 = 7;
const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
const O_RDONLY: u64 = 0;
const O_PATH: u64 = 0o10_000_000;
const AT_FDCWD: u64 = -100i64 as u64;
/// Never mapped (below `mmap_min_addr`).
const BAD: u64 = 0x10;

fn kcmp(h: &mut Harness, p1: u64, p2: u64, ty: u64, i1: u64, i2: u64) -> i64 {
    h.call(Sysno::Kcmp, &[p1, p2, ty, i1, i2])
}

/// Opens `/` with `flags`.
fn open_root(h: &mut Harness, flags: u64) -> u64 {
    let at = h.scratch;
    h.proc.state.space.write_raw(at, b"/\0").unwrap();
    h.ok(Sysno::Openat, &[AT_FDCWD, at, flags, 0])
}

/// A distinct result for distinct objects: 1 or 2, the other way round
/// when the order of the arguments is.
fn ordered(h: &mut Harness, p1: u64, p2: u64, ty: u64, i1: u64, i2: u64) -> bool {
    let (x, y) = (kcmp(h, p1, p2, ty, i1, i2), kcmp(h, p2, p1, ty, i2, i1));
    matches!((x, y), (1, 2) | (2, 1))
}

#[test]
fn kcmp_checks_in_the_kernels_order_and_compares_files() {
    // Both tasks are found (ESRCH), both may be inspected (EPERM), then
    // the type decides (EINVAL for an unknown one).
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.state.pid as u64;
        assert_eq!(kcmp(&mut h, 99999, me, 99, 0, 0), -(ESRCH as i64));
        assert_eq!(kcmp(&mut h, me, 0, 99, 0, 0), -(ESRCH as i64));
        assert_eq!(kcmp(&mut h, me, me, 8, 0, 0), -(EINVAL as i64));
        assert_eq!(kcmp(&mut h, me, me, u64::MAX, 0, 0), -(EINVAL as i64));
        let a = open_root(&mut h, O_RDONLY);
        let b = open_root(&mut h, O_RDONLY);
        let d = h.ok(Sysno::Dup, &[a]);
        let p = open_root(&mut h, O_PATH);
        assert_eq!(kcmp(&mut h, me, me, KCMP_FILE, a, d), 0, "one description");
        assert!(ordered(&mut h, me, me, KCMP_FILE, a, b));
        assert!(ordered(&mut h, me, me, KCMP_FILE, a, p), "O_PATH counts");
        // The index is an unsigned int to fget_task.
        assert_eq!(kcmp(&mut h, me, me, KCMP_FILE, a, (1 << 32) | d), 0);
        assert_eq!(kcmp(&mut h, me, me, KCMP_FILE, a, 999), -(EBADF as i64));
        assert_eq!(
            kcmp(&mut h, me, me, KCMP_FILE, u64::MAX, a),
            -(EBADF as i64)
        );
        // The order is transitive over three descriptions.
        let c = open_root(&mut h, O_RDONLY);
        let mut v = [a, b, c];
        v.sort_by(|&x, &y| match kcmp(&mut h, me, me, KCMP_FILE, x, y) {
            0 => std::cmp::Ordering::Equal,
            1 => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Greater,
        });
        assert_eq!(kcmp(&mut h, me, me, KCMP_FILE, v[0], v[2]), 1);
        // Another process may not be inspected, whichever side it is on.
        h.proc.state.config.processes = true;
        let other = u64::from(std::os::unix::process::parent_id());
        assert_eq!(kcmp(&mut h, me, other, KCMP_VM, 0, 0), -(EPERM as i64));
        assert_eq!(kcmp(&mut h, other, me, 99, 0, 0), -(EPERM as i64));
    });
}

#[test]
fn threads_share_what_their_clone_flags_shared() {
    // Threads share the address space, tables, and signal handlers; an
    // I/O context or undo list is absent (equal) until made, shared by
    // CLONE_IO or CLONE_SYSVSEM, and otherwise each task's own.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.state.pid as u64;
        let t = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        for ty in 1..=6 {
            assert_eq!(kcmp(&mut h, me, t, ty, 0, 0), 0, "type {ty}");
        }
        h.ok(Sysno::IoprioSet, &[1, 0, (2 << 13) | 4]);
        assert!(
            ordered(&mut h, me, t, KCMP_IO, 0, 0),
            "a context of its own"
        );
        let io = h.ok(Sysno::Clone, &[THREAD | CLONE_IO, 0, 0, 0, 0]);
        assert_eq!(kcmp(&mut h, me, io, KCMP_IO, 0, 0), 0);
        let copy = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        assert!(ordered(&mut h, me, copy, KCMP_IO, 0, 0), "a copy");
        let sem = h.ok(Sysno::Clone, &[THREAD | CLONE_SYSVSEM, 0, 0, 0, 0]);
        assert_eq!(kcmp(&mut h, me, sem, KCMP_SYSVSEM, 0, 0), 0, "shared");
        assert!(ordered(&mut h, me, t, KCMP_SYSVSEM, 0, 0), "made for me");
        // The leader gone, only its signal handlers are still shared.
        assert_eq!(h.start(0, Sysno::Exit, &[0]), None);
        let w = h.index_of(t as i32);
        for ty in [KCMP_VM, 2, 3, KCMP_IO, KCMP_SYSVSEM] {
            let r = h.start(w, Sysno::Kcmp, &[me, sem, ty, 0, 0]);
            assert!(matches!(r, Some(1 | 2)), "type {ty}: {r:?}");
        }
        let r = h.start(w, Sysno::Kcmp, &[me, sem, KCMP_SIGHAND, 0, 0]);
        assert_eq!(r, Some(0));
        let r = h.start(w, Sysno::Kcmp, &[me, t, KCMP_FILE, 0, 0]);
        assert_eq!(r, Some(-(EBADF as i64)), "no descriptors");
    });
}

#[test]
fn epoll_targets_are_found_by_descriptor_and_offset() {
    // kcmp_epoll_target: the slot is read first (EFAULT), then the
    // descriptors (EBADF), then the instance (EINVAL, ENOENT); items with
    // the same descriptor number come in the kernel tree's order.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.state.pid as u64;
        let m = h.anon(P, 3, false);
        let ep = h.ok(Sysno::EpollCreate1, &[0]);
        let fds = m + 0x100;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let mut b = [0u8; 8];
        h.proc.state.space.read_raw(fds, &mut b).unwrap();
        let (r, w) = (
            u64::from(u32::from_le_bytes(b[..4].try_into().unwrap())),
            u64::from(u32::from_le_bytes(b[4..].try_into().unwrap())),
        );
        let ev = m + 0x200;
        h.proc.state.space.write_raw(ev, &[1, 0, 0, 0]).unwrap();
        h.ok(Sysno::EpollCtl, &[ep, 1, r, ev]);
        let slot = m + 0x300;
        let put = |h: &Harness, efd: u64, tfd: u64, toff: u32| {
            let mut v = (efd as u32).to_le_bytes().to_vec();
            v.extend_from_slice(&(tfd as u32).to_le_bytes());
            v.extend_from_slice(&toff.to_le_bytes());
            h.proc.state.space.write_raw(slot, &v).unwrap();
        };
        put(&h, ep, r, 0);
        assert_eq!(kcmp(&mut h, me, me, KCMP_EPOLL_TFD, r, slot), 0);
        let res = kcmp(&mut h, me, me, KCMP_EPOLL_TFD, w, slot);
        assert!(matches!(res, 1 | 2));
        assert_eq!(
            kcmp(&mut h, me, me, KCMP_EPOLL_TFD, 999, BAD),
            -(EFAULT as i64)
        );
        assert_eq!(
            kcmp(&mut h, me, me, KCMP_EPOLL_TFD, 999, slot),
            -(EBADF as i64)
        );
        put(&h, 999, r, 0);
        assert_eq!(
            kcmp(&mut h, me, me, KCMP_EPOLL_TFD, r, slot),
            -(EBADF as i64)
        );
        put(&h, r, r, 0);
        assert_eq!(
            kcmp(&mut h, me, me, KCMP_EPOLL_TFD, r, slot),
            -(EINVAL as i64)
        );
        put(&h, ep, r, 1);
        assert_eq!(
            kcmp(&mut h, me, me, KCMP_EPOLL_TFD, r, slot),
            -(ENOENT as i64)
        );
        put(&h, ep, w, 0);
        assert_eq!(
            kcmp(&mut h, me, me, KCMP_EPOLL_TFD, r, slot),
            -(ENOENT as i64)
        );
        // Two descriptions under one number: the pipe's read end stays in
        // the set through a duplicate after its number is reused.
        let keep = h.ok(Sysno::Dup, &[r]);
        h.ok(Sysno::Close, &[r]);
        let again = h.ok(Sysno::Dup, &[w]);
        assert_eq!(again, r, "the lowest free number");
        h.ok(Sysno::EpollCtl, &[ep, 1, r, ev]);
        let mut found = Vec::new();
        for toff in 0..3 {
            put(&h, ep, r, toff);
            found.push((
                kcmp(&mut h, me, me, KCMP_EPOLL_TFD, keep, slot),
                kcmp(&mut h, me, me, KCMP_EPOLL_TFD, w, slot),
            ));
        }
        let e = -(ENOENT as i64);
        assert_eq!(found[2], (e, e));
        let hits: Vec<_> = found[..2].iter().map(|&(k, w)| (k == 0, w == 0)).collect();
        assert!(
            hits == [(true, false), (false, true)] || hits == [(false, true), (true, false)],
            "{found:?}"
        );
    });
}

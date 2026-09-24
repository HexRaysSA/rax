//! `epoll` against `fs/eventpoll.c`: the checks of `do_epoll_ctl` and
//! `do_epoll_wait` in their order, the per-ABI `struct epoll_event`,
//! level-triggered, edge-triggered, and one-shot reporting, the ready-list
//! order (`ep_poll_callback`, `ep_send_events`, `ep_done_scan`), items
//! keyed by description and descriptor, nesting limits (`ep_loop_check`),
//! and waits: sleeping on the watched files, `EINTR` without restart, and
//! `epoll_pwait`'s temporary mask.

use std::io::Write;
use std::os::fd::AsRawFd;

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::fs::fd::FileObject;
use crate::user::linux::signal::*;

const ADD: u64 = 1;
const DEL: u64 = 2;
const MOD: u64 = 3;
const IN: u32 = 0x1;
const OUT: u32 = 0x4;
const ERR: u32 = 0x8;
const HUP: u32 = 0x10;
const RDHUP: u32 = 0x2000;
const EXCLUSIVE: u32 = 1 << 28;
const ONESHOT: u32 = 1 << 30;
const ET: u32 = 1 << 31;

fn size(abi: LinuxAbi) -> u64 {
    if abi == LinuxAbi::X86_64 { 12 } else { 16 }
}

/// A `struct epoll_event` at `at`.
fn put_event(h: &Harness, at: u64, events: u32, data: u64) {
    let mut b = vec![0u8; size(h.abi()) as usize];
    b[..4].copy_from_slice(&events.to_le_bytes());
    let d = if h.abi() == LinuxAbi::X86_64 { 4 } else { 8 };
    b[d..d + 8].copy_from_slice(&data.to_le_bytes());
    h.proc.state.space.write_raw(at, &b).unwrap();
}

fn ctl(h: &mut Harness, ep: u64, op: u64, fd: u64, events: u32, data: u64) -> i64 {
    let at = h.scratch + 0xe00;
    put_event(h, at, events, data);
    h.call(Sysno::EpollCtl, &[ep, op, fd, at])
}

/// A non-blocking `epoll_pwait`: the `(events, data)` reported.
fn wait(h: &mut Harness, ep: u64, max: u64) -> Vec<(u32, u64)> {
    let buf = h.scratch + 0x800;
    let n = h.call(Sysno::EpollPwait, &[ep, buf, max, 0, 0, 8]);
    assert!(n >= 0, "epoll_pwait: {n}");
    let sz = size(h.abi());
    (0..n as u64)
        .map(|i| {
            let mut b = vec![0u8; sz as usize];
            h.proc.state.space.read(buf + i * sz, &mut b).unwrap();
            let d = if h.abi() == LinuxAbi::X86_64 { 4 } else { 8 };
            (
                u32::from_le_bytes(b[..4].try_into().unwrap()),
                u64::from_le_bytes(b[d..d + 8].try_into().unwrap()),
            )
        })
        .collect()
}

fn pipe(h: &mut Harness) -> (u64, u64) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Pipe2, &[at, 0]);
    let mut b = [0u8; 8];
    h.proc.state.space.read(at, &mut b).unwrap();
    (
        u32::from_le_bytes(b[..4].try_into().unwrap()).into(),
        u32::from_le_bytes(b[4..].try_into().unwrap()).into(),
    )
}

fn write_pipe(h: &mut Harness, fd: u64, bytes: &[u8]) {
    h.proc.state.space.write_raw(h.scratch, bytes).unwrap();
    h.ok(Sysno::Write, &[fd, h.scratch, bytes.len() as u64]);
}

fn create(h: &mut Harness) -> u64 {
    h.ok(Sysno::EpollCreate1, &[0])
}

#[test]
fn epoll_ctl_checks_in_the_kernel_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ep = create(&mut h);
        let (r, w) = pipe(&mut h);
        let err = |h: &mut Harness, args: &[u64]| -> i32 { -h.call(Sysno::EpollCtl, args) as i32 };
        // The event is read first (not for EPOLL_CTL_DEL).
        assert_eq!(err(&mut h, &[99, ADD, r, 8]), EFAULT, "{abi:?}");
        assert_eq!(err(&mut h, &[99, DEL, r, 8]), EBADF, "{abi:?}");
        let ev = h.scratch + 0xe00;
        put_event(&h, ev, IN, 0);
        assert_eq!(err(&mut h, &[ep, ADD, 99, ev]), EBADF, "{abi:?}");
        // A file without a poll operation, then a non-instance.
        let path = h.scratch + 0xd00;
        h.proc
            .state
            .space
            .write_raw(path, b"/proc/self/stat\0")
            .unwrap();
        let proc_file = h.ok(Sysno::Openat, &[-100i64 as u64, path, 0, 0]);
        assert_eq!(err(&mut h, &[ep, ADD, proc_file, ev]), EPERM, "{abi:?}");
        let regular = h.file("epoll-regular", 16, 0, 0);
        assert_eq!(err(&mut h, &[ep, ADD, regular, ev]), EPERM, "{abi:?}");
        h.proc.state.space.write_raw(path, b"/\0").unwrap();
        let opath = h.ok(Sysno::Openat, &[-100i64 as u64, path, 0o10000000, 0]);
        assert_eq!(err(&mut h, &[ep, ADD, opath, ev]), EBADF, "{abi:?}: O_PATH");
        assert_eq!(err(&mut h, &[r, ADD, w, ev]), EINVAL, "{abi:?}");
        assert_eq!(err(&mut h, &[ep, ADD, ep, ev]), EINVAL, "{abi:?}");
        // EPOLLEXCLUSIVE: not with MOD, other bits, or an instance.
        put_event(&h, ev, IN | EXCLUSIVE, 0);
        assert_eq!(err(&mut h, &[ep, MOD, r, ev]), EINVAL, "{abi:?}");
        put_event(&h, ev, IN | RDHUP | EXCLUSIVE, 0);
        assert_eq!(err(&mut h, &[ep, ADD, r, ev]), EINVAL, "{abi:?}");
        let inner = create(&mut h);
        put_event(&h, ev, IN | EXCLUSIVE, 0);
        assert_eq!(err(&mut h, &[ep, ADD, inner, ev]), EINVAL, "{abi:?}");
        // Then the operation itself.
        put_event(&h, ev, IN, 0);
        assert_eq!(err(&mut h, &[ep, 99, r, ev]), EINVAL, "{abi:?}");
        assert_eq!(err(&mut h, &[ep, DEL, r, 0]), ENOENT, "{abi:?}");
        assert_eq!(err(&mut h, &[ep, MOD, r, ev]), ENOENT, "{abi:?}");
        assert_eq!(ctl(&mut h, ep, ADD, r, IN, 1), 0);
        assert_eq!(ctl(&mut h, ep, ADD, r, IN, 1), -(EEXIST as i64));
        // An exclusive item cannot be modified.
        assert_eq!(ctl(&mut h, ep, ADD, w, OUT | EXCLUSIVE, 2), 0);
        assert_eq!(ctl(&mut h, ep, MOD, w, OUT, 2), -(EINVAL as i64));
        assert_eq!(h.ok(Sysno::EpollCtl, &[ep, DEL, r, 0]), 0);
    });
}

#[test]
fn epoll_events_have_each_abis_layout() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ep = create(&mut h);
        let (r, w) = pipe(&mut h);
        ctl(&mut h, ep, ADD, r, IN, 0x1122_3344_5566_7788);
        write_pipe(&mut h, w, b"x");
        assert_eq!(
            wait(&mut h, ep, 4),
            vec![(IN, 0x1122_3344_5566_7788)],
            "{abi:?}"
        );
        // maxevents: positive, at most INT_MAX / sizeof(struct epoll_event).
        let max = i32::MAX as u64 / size(abi);
        let buf = h.scratch + 0x800;
        assert_eq!(h.err(Sysno::EpollPwait, &[ep, buf, 0, 0, 0, 8]), EINVAL);
        assert_eq!(
            h.err(Sysno::EpollPwait, &[ep, buf, max + 1, 0, 0, 8]),
            EINVAL
        );
        assert_eq!(
            h.err(Sysno::EpollPwait, &[ep, (1 << 47) - 8, 4, 0, 0, 8]),
            EFAULT,
            "{abi:?}: beyond user space"
        );
        assert_eq!(h.err(Sysno::EpollPwait, &[99, buf, 4, 0, 0, 8]), EBADF);
        assert_eq!(h.err(Sysno::EpollPwait, &[r, buf, 4, 0, 0, 8]), EINVAL);
        assert_eq!(h.err(Sysno::EpollCreate1, &[1]), EINVAL);
        if abi == LinuxAbi::X86_64 {
            assert_eq!(h.err(Sysno::EpollCreate, &[0]), EINVAL);
        }
    });
}

#[test]
fn level_edge_and_one_shot_items() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let ep = create(&mut h);
    let (r, w) = pipe(&mut h);
    ctl(&mut h, ep, ADD, r, IN, 1);
    assert!(wait(&mut h, ep, 4).is_empty());
    write_pipe(&mut h, w, b"ab");
    assert_eq!(wait(&mut h, ep, 4), vec![(IN, 1)]);
    assert_eq!(wait(&mut h, ep, 4), vec![(IN, 1)], "level: again");
    // Edge-triggered: once per write.
    ctl(&mut h, ep, MOD, r, IN | ET, 2);
    assert_eq!(wait(&mut h, ep, 4), vec![(IN, 2)], "MOD of a ready item");
    assert!(wait(&mut h, ep, 4).is_empty());
    write_pipe(&mut h, w, b"c");
    assert_eq!(wait(&mut h, ep, 4), vec![(IN, 2)]);
    assert!(wait(&mut h, ep, 4).is_empty());
    // A change the emulator did not make (another process writing the
    // host pipe) is found by the growth of the bytes queued.
    let raw = {
        let file = h.proc.state.fds.file(w as i32).unwrap();
        let FileObject::PipeWrite(p) = &file.object else {
            unreachable!()
        };
        p.as_raw_fd()
    };
    // SAFETY: a fresh duplicate of a live descriptor, owned once.
    let mut host =
        unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(libc::dup(raw)) };
    host.write_all(b"d").unwrap();
    assert_eq!(wait(&mut h, ep, 4), vec![(IN, 2)], "external write");
    assert!(wait(&mut h, ep, 4).is_empty());
    // One-shot: disabled after one report until MOD.
    ctl(&mut h, ep, MOD, r, IN | ONESHOT, 3);
    assert_eq!(wait(&mut h, ep, 4), vec![(IN, 3)]);
    write_pipe(&mut h, w, b"e");
    assert!(wait(&mut h, ep, 4).is_empty(), "disabled");
    ctl(&mut h, ep, MOD, r, IN | ONESHOT, 4);
    assert_eq!(wait(&mut h, ep, 4), vec![(IN, 4)]);
    // Hang-up and error are always reported.
    ctl(&mut h, ep, MOD, r, 0, 5);
    h.ok(Sysno::Close, &[w]);
    drop(host);
    // Only the implicit events are watched: the queued data is not IN.
    assert_eq!(wait(&mut h, ep, 4), vec![(HUP, 5)]);
    let (r2, w2) = pipe(&mut h);
    ctl(&mut h, ep, ADD, w2, OUT, 6);
    h.ok(Sysno::EpollCtl, &[ep, DEL, r, 0]);
    h.ok(Sysno::Close, &[r2]);
    assert_eq!(wait(&mut h, ep, 4), vec![(OUT | ERR, 6)]);
}

#[test]
fn the_ready_list_keeps_wake_up_order() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let ep = create(&mut h);
    let pipes: Vec<(u64, u64)> = (0..4).map(|_| pipe(&mut h)).collect();
    for (i, &(r, _)) in pipes.iter().enumerate() {
        ctl(&mut h, ep, ADD, r, IN, i as u64);
    }
    for i in [2, 0, 3] {
        write_pipe(&mut h, pipes[i].1, b"x");
    }
    let order = |v: Vec<(u32, u64)>| v.into_iter().map(|(_, d)| d).collect::<Vec<_>>();
    assert_eq!(order(wait(&mut h, ep, 4)), vec![2, 0, 3]);
    // maxevents takes the head; what is left comes first next time, then
    // the level-triggered items reported before.
    assert_eq!(order(wait(&mut h, ep, 1)), vec![2]);
    assert_eq!(order(wait(&mut h, ep, 4)), vec![0, 3, 2]);
    // A buffer that faults after one event takes one; one that faults at
    // once is EFAULT and loses nothing.
    let page = h.anon(0x2000, 3, false);
    h.ok(Sysno::Munmap, &[page + 0x1000, 0x1000]);
    let n = h.call(Sysno::EpollWait, &[ep, page + 0x1000 - 12, 4, 0]);
    assert_eq!(n, 1);
    assert_eq!(h.err(Sysno::EpollWait, &[ep, page + 0x1000, 4, 0]), EFAULT);
    assert_eq!(wait(&mut h, ep, 4).len(), 3);
}

#[test]
fn items_follow_descriptions_not_descriptors() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let ep = create(&mut h);
    let (r, w) = pipe(&mut h);
    let d = h.ok(Sysno::Dup, &[r]);
    ctl(&mut h, ep, ADD, r, IN, 7);
    // Two descriptors of one description: two items.
    assert_eq!(ctl(&mut h, ep, ADD, d, IN, 8), 0);
    h.ok(Sysno::Close, &[r]);
    write_pipe(&mut h, w, b"x");
    let got = wait(&mut h, ep, 4);
    assert_eq!(got.len(), 2, "the closed descriptor's item remains");
    assert_eq!(h.err(Sysno::EpollCtl, &[ep, DEL, r, 0]), EBADF);
    h.ok(Sysno::Close, &[d]);
    assert!(wait(&mut h, ep, 4).is_empty(), "gone with the description");
}

#[test]
fn nested_instances_and_their_limits() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let (outer, inner) = (create(&mut h), create(&mut h));
    let (r, w) = pipe(&mut h);
    ctl(&mut h, inner, ADD, r, IN, 1);
    assert_eq!(ctl(&mut h, outer, ADD, inner, IN, 2), 0);
    assert_eq!(ctl(&mut h, inner, ADD, outer, IN, 3), -(ELOOP as i64));
    assert!(wait(&mut h, outer, 4).is_empty());
    write_pipe(&mut h, w, b"z");
    assert_eq!(wait(&mut h, outer, 4), vec![(IN, 2)]);
    // A chain e1 -> e0 of depth d may be watched from an instance only if
    // d + 1 + (the chain above it) <= 4.
    let chain: Vec<u64> = (0..6).map(|_| create(&mut h)).collect();
    ctl(&mut h, chain[0], ADD, r, IN, 0);
    for i in 1..=4 {
        assert_eq!(
            ctl(&mut h, chain[i], ADD, chain[i - 1], IN, 0),
            0,
            "depth {i}"
        );
    }
    assert_eq!(ctl(&mut h, chain[5], ADD, chain[4], IN, 0), -(ELOOP as i64));
    // Upward: watching a depth-0 instance from the top of a 4-chain.
    let leaf = create(&mut h);
    assert_eq!(ctl(&mut h, chain[0], ADD, leaf, IN, 0), -(ELOOP as i64));
}

#[test]
fn waits_sleep_on_their_files_and_end_with_eintr() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let ep = create(&mut h);
    let (r, w) = pipe(&mut h);
    ctl(&mut h, ep, ADD, r, IN, 9);
    let buf = h.scratch + 0x800;
    assert_eq!(h.start(0, Sysno::EpollWait, &[ep, buf, 4, u64::MAX]), None);
    let raw = match &h.proc.state.fds.file(r as i32).unwrap().object {
        FileObject::PipeRead(p) => p.as_raw_fd(),
        _ => unreachable!(),
    };
    let b = h.proc.threads[0].blocked.take().unwrap();
    assert!(b.wait.fds.contains(&(raw, true, false)), "{:?}", b.wait.fds);
    assert!(b.wait.deadline.is_none());
    // A pending signal ends the wait with EINTR, which is not restarted.
    h.proc.threads[0].sigpending = true;
    assert_eq!(
        h.start(0, Sysno::EpollWait, &[ep, buf, 4, u64::MAX]),
        Some(-(EINTR as i64))
    );
    h.proc.threads[0].sigpending = false;
    // epoll_pwait: the mask applies during the wait; it is restored unless
    // the wait ends with EINTR.
    let set = h.scratch + 0x700;
    h.proc
        .state
        .space
        .write_raw(set, &sigmask(SIGUSR1).to_le_bytes())
        .unwrap();
    write_pipe(&mut h, w, b"x");
    assert_eq!(
        h.start(0, Sysno::EpollPwait, &[ep, buf, 4, 0, set, 8]),
        Some(1)
    );
    assert_eq!(h.proc.threads[0].sigmask, 0);
    assert!(h.proc.threads[0].saved_sigmask.is_none());
    assert_eq!(h.err(Sysno::EpollPwait, &[ep, buf, 4, 0, set, 4]), EINVAL);
    // epoll_pwait2: a timespec, validated.
    let ts = h.scratch + 0x780;
    let mut bad = [0u8; 16];
    bad[8..].copy_from_slice(&1_000_000_000i64.to_le_bytes());
    h.proc.state.space.write_raw(ts, &bad).unwrap();
    assert_eq!(h.err(Sysno::EpollPwait2, &[ep, buf, 4, ts, 0, 8]), EINVAL);
    assert_eq!(h.err(Sysno::EpollPwait2, &[ep, buf, 4, 8, 0, 8]), EFAULT);
    h.proc.state.space.write_raw(ts, &[0u8; 16]).unwrap();
    assert_eq!(h.ok(Sysno::EpollPwait2, &[ep, buf, 4, ts, 0, 8]), 1);
}

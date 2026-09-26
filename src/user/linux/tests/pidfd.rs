//! pidfds, driven through the system calls without executing guest code:
//! `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`, the pidfd `ioctl`s and
//! `poll`, `CLONE_PIDFD` for threads, and `waitid(P_PIDFD)`
//! (`kernel/pid.c`, `fs/pidfs.c`, `kernel/fork.c`, `kernel/signal.c`,
//! `kernel/exit.c`, Linux 6.19). A process other than the harness's is a
//! host process. Child processes are covered by the `pidfd` fixture, which
//! forks.

use std::sync::Arc;

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::*;
use crate::user::linux::syscall::thread::cf::*;

const PIDFD_NONBLOCK: u64 = 0o4000;
const PIDFD_THREAD: u64 = 0o200;
const O_RDWR: i64 = 2;
const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const P_PIDFD: u64 = 3;
const WEXITED: u64 = 4;
const WNOHANG: u64 = 1;
const PIDFD_SELF_THREAD: u64 = -10000i64 as u64;
const PIDFD_SELF_THREAD_GROUP: u64 = -10001i64 as u64;
const SIGNAL_THREAD: u64 = 1;
const SIGNAL_THREAD_GROUP: u64 = 2;
const SIGNAL_PROCESS_GROUP: u64 = 4;
/// `PIDFD_GET_INFO` for a structure of `size` bytes.
const fn get_info(size: u64) -> u64 {
    (3 << 30) | (size << 16) | (0xff << 8) | 11
}
const INFO: u64 = get_info(80);
const POLLIN: u16 = 0x1;
const POLLHUP: u16 = 0x10;
const POLLRDNORM: u16 = 0x40;

/// What every threads library passes.
const THREAD: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u32_at(h: &Harness, at: u64) -> u32 {
    u32::from_le_bytes(get(h, at, 4).try_into().unwrap())
}

fn open(h: &mut Harness, pid: i32, flags: u64) -> u64 {
    h.ok(Sysno::PidfdOpen, &[pid as u64, flags])
}

/// `poll`'s `revents` for `fd` asking for `POLLIN | POLLRDNORM`, without
/// waiting.
fn revents(h: &mut Harness, fd: u64) -> u16 {
    let (pfd, ts) = (h.scratch + 0x800, h.scratch + 0x810);
    let mut e = (fd as i32).to_le_bytes().to_vec();
    e.extend_from_slice(&(POLLIN | POLLRDNORM).to_le_bytes());
    e.extend_from_slice(&[0, 0]);
    put(h, pfd, &e);
    put(h, ts, &[0; 16]);
    h.ok(Sysno::Ppoll, &[pfd, 1, ts, 0, 8]);
    u16::from_le_bytes(get(h, pfd + 6, 2).try_into().unwrap())
}

/// `PIDFD_GET_INFO` asking for `mask`: the result and the structure.
fn info(h: &mut Harness, fd: u64, mask: u64) -> (i64, Vec<u8>) {
    let at = h.scratch + 0x900;
    put(h, at, &[0; 80]);
    put(h, at, &mask.to_le_bytes());
    let r = h.call(Sysno::Ioctl, &[fd, INFO, at]);
    (r, get(h, at, 80))
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn mask_of(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

/// A handler for `sig`, so that queueing it is never fatal.
fn handle(h: &mut Harness, sig: i32) {
    let act = h.scratch + 0xe00;
    let mut words = vec![0x40_1000u64];
    if h.abi().has_sa_restorer() {
        words.extend([sa::RESTORER, 0x40_1100]);
    } else {
        words.push(0);
    }
    words.push(0);
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    put(h, act, &b);
    h.ok(Sysno::RtSigaction, &[sig as u64, act, 0, 8]);
}

/// Creates a thread of thread 0; returns its TID.
fn spawn(h: &mut Harness) -> i32 {
    h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32
}

#[test]
fn pidfd_open_checks_its_arguments_and_makes_a_pidfs_file() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.state.pid;
        assert_eq!(h.err(Sysno::PidfdOpen, &[me as u64, 1]), EINVAL);
        assert_eq!(h.err(Sysno::PidfdOpen, &[me as u64, 0o2000000]), EINVAL);
        assert_eq!(h.err(Sysno::PidfdOpen, &[0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::PidfdOpen, &[u32::MAX as u64, 0]), EINVAL);
        // Only this process exists without processes enabled.
        assert_eq!(h.err(Sysno::PidfdOpen, &[4_000_000, 0]), ESRCH);
        let fd = open(&mut h, me, 0);
        assert_eq!(h.call(Sysno::Fcntl, &[fd, F_GETFL]), O_RDWR, "{abi:?}");
        assert_eq!(h.call(Sysno::Fcntl, &[fd, F_GETFD]), 1, "close-on-exec");
        let nb = open(&mut h, me, PIDFD_NONBLOCK | PIDFD_THREAD);
        assert_eq!(h.call(Sysno::Fcntl, &[nb, F_GETFL]), O_RDWR | 0o4200);
        // /proc names it as an anonymous inode.
        let (path, buf) = (h.scratch + 0x100, h.scratch + 0x200);
        put(&h, path, format!("/proc/self/fd/{fd}\0").as_bytes());
        let n = h.ok(Sysno::Readlinkat, &[AT_FDCWD_U, path, buf, 64]);
        assert_eq!(get(&h, buf, n as usize), b"anon_inode:[pidfd]");
        // The process runs: nothing to report.
        assert_eq!(revents(&mut h, fd), 0);
    });
}

/// `AT_FDCWD` as a system-call argument.
const AT_FDCWD_U: u64 = -100i64 as u64;

#[test]
fn a_pidfd_is_a_root_owned_file_of_pidfs_that_refuses_io() {
    // The generic struct stat layout (arm64, riscv).
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let me = h.proc.state.pid;
    let fd = open(&mut h, me, 0);
    let st = h.scratch + 0x300;
    h.ok(Sysno::Fstat, &[fd, st]);
    let s = get(&h, st, 128);
    let dev = u64::from_le_bytes(s[..8].try_into().unwrap());
    let ino = u64::from_le_bytes(s[8..16].try_into().unwrap());
    // Mode 0700 without a file type, one link, root's, 4096-byte blocks.
    assert_eq!(
        (word(&s, 16), word(&s, 20), word(&s, 24), word(&s, 28)),
        (0o700, 1, 0, 0)
    );
    assert_eq!(word(&s, 56), 4096);
    assert_eq!(dev, 6, "device 0:6");
    // Every pidfd of the task has its inode.
    let other = open(&mut h, me, PIDFD_THREAD);
    h.ok(Sysno::Fstat, &[other, st]);
    assert_eq!(
        u64::from_le_bytes(get(&h, st + 8, 8).try_into().unwrap()),
        ino
    );
    let buf = h.scratch + 0x400;
    assert_eq!(h.err(Sysno::Read, &[fd, buf, 8]), EINVAL);
    assert_eq!(h.err(Sysno::Read, &[fd, buf, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Write, &[fd, buf, 8]), EINVAL);
    assert_eq!(h.err(Sysno::Pread64, &[fd, buf, 8, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Pwrite64, &[fd, buf, 8, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Lseek, &[fd, 0, 0]), ESPIPE);
    assert_eq!(h.err(Sysno::Fchmod, &[fd, 0o600]), EOPNOTSUPP);
    assert_eq!(h.err(Sysno::Fchown, &[fd, u64::MAX, u64::MAX]), EOPNOTSUPP);
    assert_eq!(h.err(Sysno::Ftruncate, &[fd, 0]), EOPNOTSUPP);
    assert_eq!(h.err(Sysno::Fallocate, &[fd, 0, 0, 1]), EOPNOTSUPP);
    assert_eq!(h.err(Sysno::Fsync, &[fd]), EINVAL);
    assert_eq!(h.err(Sysno::Mmap, &[0, 4096, 1, 1, fd, 0]), ENODEV);
    assert_eq!(h.err(Sysno::Ioctl, &[fd, 0x541b, buf]), ENOTTY, "FIONREAD");
    let sf = h.scratch + 0x500;
    h.ok(Sysno::Fstatfs, &[fd, sf]);
    assert_eq!(get(&h, sf, 8), 0x5049_4446u64.to_le_bytes(), "PID_FS_MAGIC");
    // An eventfd's inode refuses attribute changes as well.
    let ev = h.ok(Sysno::Eventfd2, &[0, 0]);
    assert_eq!(h.err(Sysno::Fchmod, &[ev, 0o600]), EOPNOTSUPP);
}

#[test]
fn pidfd_ioctls_follow_pidfd_ioctl() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let me = h.proc.state.pid;
    let fd = open(&mut h, me, 0);
    let at = h.scratch + 0x600;
    put(&h, at, &[0xff; 4]);
    h.ok(Sysno::Ioctl, &[fd, 0x8008_7601, at]);
    assert_eq!(u32_at(&h, at), 0, "FS_IOC_GETVERSION: generation 0");
    assert_eq!(h.err(Sysno::Ioctl, &[fd, 0x8008_7601, 0]), EINVAL);
    // PIDFD_GET_INFO: the identifiers and credentials always, the
    // supported mask on request, no cgroup ID.
    let (r, b) = info(&mut h, fd, 1 << 5);
    assert_eq!(r, 0);
    assert_eq!(mask_of(&b), 0b10_0011);
    let (u, e, g, eg) = h.proc.state.creds;
    let ppid = h.proc.state.ppid as u32;
    let ids: Vec<u32> = (0..11).map(|i| word(&b, 16 + 4 * i)).collect();
    assert_eq!(ids, [me as u32, me as u32, ppid, u, g, e, eg, e, eg, e, eg]);
    assert_eq!(u64::from_le_bytes(b[72..80].try_into().unwrap()), 0x7f);
    // No exit information while it runs; its dumpability as a core-dump
    // mask.
    let (_, b) = info(&mut h, fd, 1 << 3);
    assert_eq!(mask_of(&b), 0b11);
    let (_, b) = info(&mut h, fd, 1 << 4);
    assert_eq!((mask_of(&b), word(&b, 64)), (0b1_0011, 1 << 2), "USER");
    h.proc.state.dumpable = 0;
    let (_, b) = info(&mut h, fd, 1 << 4);
    assert_eq!(word(&b, 64), 1 << 1, "SKIP");
    // copy_struct_to_user: a shorter structure takes its part, a longer
    // one is zero-filled past the kernel's.
    put(&h, at, &[0xaa; 128]);
    put(&h, at, &1u64.to_le_bytes());
    h.ok(Sysno::Ioctl, &[fd, get_info(64), at]);
    assert_eq!(get(&h, at + 64, 1), [0xaa]);
    h.ok(Sysno::Ioctl, &[fd, get_info(100), at]);
    assert_eq!(get(&h, at + 80, 21), [&[0u8; 20][..], &[0xaa]].concat());
    // extensible_ioctl_valid: the direction, type, and number must match
    // and the size reach PIDFD_INFO_SIZE_VER0.
    assert_eq!(h.err(Sysno::Ioctl, &[fd, get_info(56), at]), ENOTTY);
    assert_eq!(h.err(Sysno::Ioctl, &[fd, INFO & !(1 << 30), at]), ENOTTY);
    assert_eq!(h.err(Sysno::Ioctl, &[fd, INFO, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Ioctl, &[fd, INFO, 8]), EFAULT);
    // The namespace requests find none; an argument is refused first.
    assert_eq!(h.err(Sysno::Ioctl, &[fd, 0xff03, 1]), EINVAL);
    assert_eq!(h.err(Sysno::Ioctl, &[fd, 0xff03, 0]), EOPNOTSUPP);
    assert_eq!(h.err(Sysno::Ioctl, &[fd, 0xff0c, 0]), ENOTTY);
    // Another file does not know them.
    let ev = h.ok(Sysno::Eventfd2, &[0, 0]);
    assert_eq!(h.err(Sysno::Ioctl, &[ev, INFO, at]), ENOTTY);
    // The generic requests still apply: FIONBIO sets O_NONBLOCK.
    put(&h, at, &1u32.to_le_bytes());
    h.ok(Sysno::Ioctl, &[fd, 0x5421, at]);
    assert_eq!(h.call(Sysno::Fcntl, &[fd, F_GETFL]), O_RDWR | 0o4000);
}

#[test]
fn a_thread_pidfd_follows_the_thread_to_its_exit() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.state.pid;
        handle(&mut h, SIGUSR1);
        handle(&mut h, SIGUSR2);
        let tid = spawn(&mut h);
        // pidfd_prepare: a thread other than the leader needs PIDFD_THREAD.
        assert_eq!(h.err(Sysno::PidfdOpen, &[tid as u64, 0]), ENOENT);
        let fd = open(&mut h, tid, PIDFD_THREAD);
        assert_eq!(revents(&mut h, fd), 0);
        let (_, b) = info(&mut h, fd, 0);
        assert_eq!((word(&b, 16), word(&b, 20)), (tid as u32, me as u32));
        assert_eq!(
            h.err(Sysno::Waitid, &[P_PIDFD, fd, 0, WEXITED | WNOHANG]),
            ECHILD
        );
        // A thread pidfd directs its signal at the thread (SI_TKILL); the
        // thread-group scope at its process.
        h.ok(Sysno::PidfdSendSignal, &[fd, SIGUSR1 as u64, 0, 0]);
        let w = h.index_of(tid);
        let got = h.proc.threads[w].pending.dequeue(0).unwrap();
        assert_eq!((got.signo, got.code), (SIGUSR1, code::SI_TKILL), "{abi:?}");
        h.ok(
            Sysno::PidfdSendSignal,
            &[fd, SIGUSR2 as u64, 0, SIGNAL_THREAD_GROUP],
        );
        assert!(h.proc.state.shared_pending.contains(SIGUSR2));
        assert!(!h.proc.threads[w].pending.contains(SIGUSR2));
        h.proc.state.shared_pending.dequeue(0);
        for t in h.proc.threads.iter_mut() {
            t.sigpending = false;
        }
        // A sleeping poll wakes when the thread exits: it is gone at once.
        let pfd = h.scratch + 0x800;
        let mut e = (fd as i32).to_le_bytes().to_vec();
        e.extend_from_slice(&(POLLIN | POLLRDNORM).to_le_bytes());
        e.extend_from_slice(&[0, 0]);
        put(&h, pfd, &e);
        assert_eq!(h.start(0, Sysno::Ppoll, &[pfd, 1, 0, 0, 8]), None);
        assert_eq!(h.start(w, Sysno::Exit, &[3]), None);
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), 1);
        let rev = u16::from_le_bytes(get(&h, pfd + 6, 2).try_into().unwrap());
        assert_eq!(rev, POLLIN | POLLRDNORM | POLLHUP);
        // Gone: only its exit information remains.
        assert_eq!(h.err(Sysno::PidfdSendSignal, &[fd, 0, 0, 0]), ESRCH);
        assert_eq!(info(&mut h, fd, 1).0, -(ESRCH as i64));
        let (r, b) = info(&mut h, fd, 1 << 3);
        assert_eq!((r, mask_of(&b), word(&b, 60)), (0, 1 << 3, 0x300));
        assert_eq!(h.err(Sysno::PidfdGetfd, &[fd, 0, 0]), ESRCH);
    });
}

#[test]
fn clone_returns_a_thread_pidfd() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let slot = h.scratch + 0x700;
        let args = h.scratch + 0x740;
        let set = |h: &Harness, words: &[u64]| {
            let mut w = words.to_vec();
            w.resize(11, 0);
            let b: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
            put(h, args, &b);
        };
        set(&h, &[THREAD | CLONE_PIDFD, slot]);
        let tid = h.ok(Sysno::Clone3, &[args, 88]) as i32;
        let fd = u32_at(&h, slot) as u64;
        assert_eq!(
            h.call(Sysno::Fcntl, &[fd, F_GETFL]),
            O_RDWR | 0o200,
            "{abi:?}"
        );
        assert_eq!(h.call(Sysno::Fcntl, &[fd, F_GETFD]), 1);
        let (_, b) = info(&mut h, fd, 0);
        assert_eq!(word(&b, 16), tid as u32);
        // The legacy call returns it through the parent_tid argument (the
        // third on every ABI).
        put(&h, slot, &[0xff; 4]);
        let tid2 = h.ok(Sysno::Clone, &[THREAD | CLONE_PIDFD, 0, slot, 0, 0]) as i32;
        let fd2 = u32_at(&h, slot) as u64;
        let (_, b) = info(&mut h, fd2, 0);
        assert_eq!(word(&b, 16), tid2 as u32);
        // Nothing is created when the pidfd cannot be: an unwritable word,
        // no free descriptor.
        let threads = h.proc.threads.len();
        set(&h, &[THREAD | CLONE_PIDFD, 16]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EFAULT);
        let used = h.proc.state.fds.open_fds().len() as u64;
        h.proc.state.rlimits[7] = (used, used);
        set(&h, &[THREAD | CLONE_PIDFD, slot]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EMFILE);
        assert_eq!(h.proc.threads.len(), threads);
        assert_eq!(h.proc.state.fds.open_fds().len() as u64, used);
    });
}

#[test]
fn pidfd_send_signal_checks_its_scope_and_record() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let me = h.proc.state.pid;
    handle(&mut h, SIGUSR1);
    let fd = open(&mut h, me, 0);
    assert_eq!(h.err(Sysno::PidfdSendSignal, &[fd, 0, 0, 8]), EINVAL);
    assert_eq!(
        h.err(
            Sysno::PidfdSendSignal,
            &[fd, 0, 0, SIGNAL_THREAD | SIGNAL_PROCESS_GROUP]
        ),
        EINVAL
    );
    assert_eq!(h.err(Sysno::PidfdSendSignal, &[fd, 65, 0, 0]), EINVAL);
    assert_eq!(h.err(Sysno::PidfdSendSignal, &[0, 0, 0, 0]), EBADF);
    assert_eq!(h.err(Sysno::PidfdSendSignal, &[99, 0, 0, 0]), EBADF);
    // A record: its signal number must be the one sent, and only the
    // calling thread may be sent a kill- or kernel-style one.
    let rec = h.scratch + 0xa00;
    let record = |h: &Harness, signo: i32, code: i32, value: u64| {
        let mut b = vec![0u8; 128];
        b[..4].copy_from_slice(&signo.to_le_bytes());
        b[8..12].copy_from_slice(&code.to_le_bytes());
        b[24..32].copy_from_slice(&value.to_le_bytes());
        put(h, rec, &b);
    };
    record(&h, SIGUSR2, code::SI_QUEUE, 0);
    assert_eq!(
        h.err(Sysno::PidfdSendSignal, &[fd, SIGUSR1 as u64, rec, 0]),
        EINVAL
    );
    record(&h, SIGUSR1, code::SI_USER, 0);
    let tid = spawn(&mut h);
    let other = open(&mut h, tid, PIDFD_THREAD);
    assert_eq!(
        h.err(Sysno::PidfdSendSignal, &[other, SIGUSR1 as u64, rec, 0]),
        EPERM
    );
    // The leader is the caller: a forged record is its own business,
    // except for a process group.
    h.ok(
        Sysno::PidfdSendSignal,
        &[fd, SIGUSR1 as u64, rec, SIGNAL_THREAD],
    );
    assert_eq!(
        h.err(
            Sysno::PidfdSendSignal,
            &[fd, SIGUSR1 as u64, rec, SIGNAL_PROCESS_GROUP]
        ),
        EPERM
    );
    let got = h.proc.threads[0].pending.dequeue(0).unwrap();
    assert_eq!((got.signo, got.code), (SIGUSR1, code::SI_USER));
    record(&h, SIGUSR1, code::SI_QUEUE, 42);
    h.ok(
        Sysno::PidfdSendSignal,
        &[PIDFD_SELF_THREAD, SIGUSR1 as u64, rec, 0],
    );
    let got = h.proc.threads[0].pending.dequeue(0).unwrap();
    assert_eq!(
        (got.code, &got.fields[8..16]),
        (code::SI_QUEUE, &42u64.to_le_bytes()[..])
    );
    // Without a record: SI_USER to the process, from the caller.
    h.ok(
        Sysno::PidfdSendSignal,
        &[PIDFD_SELF_THREAD_GROUP, SIGUSR1 as u64, 0, 0],
    );
    let got = h.proc.state.shared_pending.dequeue(0).unwrap();
    assert_eq!(
        got,
        SigInfo::kill(SIGUSR1, code::SI_USER, me, h.proc.state.creds.0)
    );
    // A /proc/<pid> directory names the process; another directory does
    // not.
    let path = h.scratch + 0xb00;
    put(&h, path, b"/proc/self\0");
    let proc = h.ok(Sysno::Openat, &[AT_FDCWD_U, path, 0o200000, 0]);
    h.ok(Sysno::PidfdSendSignal, &[proc, 0, 0, 0]);
    put(&h, path, b"/proc/self/task\0");
    let task = h.ok(Sysno::Openat, &[AT_FDCWD_U, path, 0o200000, 0]);
    assert_eq!(h.err(Sysno::PidfdSendSignal, &[task, 0, 0, 0]), EBADF);
    // The process group scope: this process's own group.
    h.ok(
        Sysno::PidfdSendSignal,
        &[fd, SIGUSR1 as u64, 0, SIGNAL_PROCESS_GROUP],
    );
    assert!(h.proc.state.shared_pending.contains(SIGUSR1));
    assert_eq!(
        h.err(Sysno::PidfdSendSignal, &[other, 0, 0, SIGNAL_PROCESS_GROUP]),
        ESRCH
    );
}

#[test]
fn pidfd_getfd_duplicates_the_callers_descriptors() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let me = h.proc.state.pid;
    let fd = open(&mut h, me, 0);
    let ev = h.ok(Sysno::Eventfd2, &[0, 0]);
    let dup = h.ok(Sysno::PidfdGetfd, &[fd, ev, 0]);
    assert_ne!(dup, ev);
    assert_eq!(h.call(Sysno::Fcntl, &[dup, F_GETFD]), 1, "close-on-exec");
    let fds = &h.proc.state.fds;
    assert!(Arc::ptr_eq(
        &fds.file(ev as i32).unwrap(),
        &fds.file(dup as i32).unwrap()
    ));
    assert_eq!(h.err(Sysno::PidfdGetfd, &[fd, ev, 1]), EINVAL);
    assert_eq!(h.err(Sysno::PidfdGetfd, &[fd, 99, 0]), EBADF);
    assert_eq!(h.err(Sysno::PidfdGetfd, &[ev, 0, 0]), EBADF);
    assert_eq!(h.err(Sysno::PidfdGetfd, &[PIDFD_SELF_THREAD, 0, 0]), EBADF);
    // waitid: a pidfd of the caller names no child.
    assert_eq!(
        h.err(Sysno::Waitid, &[P_PIDFD, fd, 0, WEXITED | WNOHANG]),
        ECHILD
    );
    assert_eq!(
        h.err(Sysno::Waitid, &[P_PIDFD, PIDFD_SELF_THREAD, 0, WEXITED]),
        EINVAL
    );
    assert_eq!(h.err(Sysno::Waitid, &[P_PIDFD, ev, 0, WEXITED]), EBADF);
}

/// A host process forked from the test process, holding only the standard
/// descriptors (so no other test's pipe or socket end stays open in it),
/// until [`HostChild::release`] or a signal ends it.
struct HostChild {
    pid: i32,
    go: libc::c_int,
}

impl HostChild {
    fn new() -> Self {
        let mut p = [0 as libc::c_int; 2];
        // SAFETY: `p` is a two-element array pipe(2) fills.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        // SAFETY: the child calls only async-signal-safe functions (dup2,
        // close, read, _exit) before it ends.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: as above; the loop closes the child's copies only.
            unsafe {
                libc::dup2(p[0], 3);
                let max = libc::getdtablesize().min(1 << 16);
                for fd in 4..max {
                    libc::close(fd);
                }
                let mut b = 0u8;
                libc::read(3, (&mut b as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        // SAFETY: the parent's read end, closed once.
        unsafe { libc::close(p[0]) };
        HostChild { pid, go: p[1] }
    }

    /// Lets it exit.
    fn release(&self) {
        // SAFETY: a one-byte buffer; the pipe's write end.
        unsafe { libc::write(self.go, [1u8].as_ptr().cast(), 1) };
    }

    /// Reaps it: its wait status.
    fn reap(&self) -> i32 {
        let mut status = 0;
        // SAFETY: waits for this child only.
        assert_eq!(unsafe { libc::waitpid(self.pid, &mut status, 0) }, self.pid);
        status
    }
}

impl Drop for HostChild {
    fn drop(&mut self) {
        // SAFETY: the pipe's write end, closed once; ending and reaping
        // this child only (an error if it was reaped already).
        unsafe {
            libc::close(self.go);
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG);
        }
    }
}

#[test]
fn a_host_watch_sees_another_process_end() {
    use crate::user::linux::fs::pidfd::Target;
    let child = HostChild::new();
    let t = Target::new(child.pid, child.pid, true).unwrap();
    assert!(!t.exited());
    let fd = t.watch_fd().unwrap();
    child.release();
    // A host SIGCHLD handler another test installed (watch_children) may
    // interrupt the wait: EINTR, then wait again.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match crate::user::linux::host::poll(&[(fd, true, false)], left.as_millis() as i32) {
            Err(crate::user::linux::abi::errno::Errno(EINTR)) if !left.is_zero() => continue,
            r => break r.map(|_| ()).unwrap(),
        }
    }
    assert!(t.exited(), "exited, even before it is reaped");
    child.reap();
    assert!(t.exited());
    // A process that is gone cannot be named.
    assert_eq!(
        Target::new(child.pid, child.pid, true).unwrap_err(),
        crate::user::linux::abi::errno::Errno(ESRCH)
    );
}

#[test]
fn another_process_is_seen_through_the_host() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    h.proc.state.config.processes = true;
    let child = HostChild::new();
    let pid = child.pid;
    let fd = open(&mut h, pid, 0);
    assert_eq!(revents(&mut h, fd), 0);
    // Its descriptors are out of reach; it is no child of the process.
    assert_eq!(h.err(Sysno::PidfdGetfd, &[fd, 0, 0]), EPERM);
    assert_eq!(
        h.err(Sysno::Waitid, &[P_PIDFD, fd, 0, WEXITED | WNOHANG]),
        ECHILD
    );
    // Its parent and credentials are the host's.
    let (r, b) = info(&mut h, fd, 0);
    assert_eq!(r, 0);
    assert_eq!((word(&b, 16), word(&b, 20)), (pid as u32, pid as u32));
    assert_eq!(word(&b, 24), std::process::id());
    // SAFETY: getuid has no failure mode.
    assert_eq!(word(&b, 28), unsafe { libc::getuid() });
    // A signal through the pidfd ends it; a sleeping poll sees that.
    h.ok(Sysno::PidfdSendSignal, &[fd, SIGKILL as u64, 0, 0]);
    let pfd = h.scratch + 0x800;
    let mut e = (fd as i32).to_le_bytes().to_vec();
    e.extend_from_slice(&(POLLIN | POLLRDNORM).to_le_bytes());
    e.extend_from_slice(&[0, 0]);
    put(&h, pfd, &e);
    assert_eq!(h.call(Sysno::Ppoll, &[pfd, 1, 0, 0, 8]), 1);
    assert_eq!(
        u16::from_le_bytes(get(&h, pfd + 6, 2).try_into().unwrap()),
        POLLIN | POLLRDNORM | POLLHUP
    );
    let status = child.reap();
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
    assert_eq!(h.err(Sysno::PidfdSendSignal, &[fd, 0, 0, 0]), ESRCH);
    assert_eq!(h.err(Sysno::PidfdOpen, &[pid as u64, 0]), ESRCH);
}

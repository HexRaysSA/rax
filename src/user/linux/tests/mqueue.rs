//! POSIX message queues against `ipc/mqueue.c` (Linux 6.19), through the
//! system calls on every ABI: `mq_open` and `mq_unlink` (their checks in
//! order, attributes, limits, permissions), `mq_timedsend` and
//! `mq_timedreceive` (priorities, sizes, waiting, handing over),
//! `mq_notify`, `mq_getsetattr`, and the queue file.

use std::time::Duration;

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::deliver::restart::ERESTARTSYS;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::thread::cf::*;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: u64 = 0o4000;
const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const NOBODY: u32 = 65534;
/// Never mapped (below `mmap_min_addr`).
const BAD: u64 = 0x10;
const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn word(h: &Harness, at: u64) -> u64 {
    u64::from_le_bytes(get(h, at, 8).try_into().unwrap())
}

fn cstr(h: &Harness, at: u64, s: &[u8]) -> u64 {
    put(h, at, &[s, &[0]].concat());
    at
}

/// Makes the process user and group `id` alone, without the host's
/// supplementary groups (which may hold the queues' group).
fn creds(h: &mut Harness, id: u32) {
    h.proc.state.creds = (id, id, id, id);
    h.proc.state.groups = Vec::new();
}

/// A `struct mq_attr` with `maxmsg` and `msgsize` at `at`.
fn attr(h: &Harness, at: u64, maxmsg: i64, msgsize: i64) -> u64 {
    let b: Vec<u8> = [0, maxmsg, msgsize, 0, 0, 0, 0, 0]
        .iter()
        .flat_map(|x: &i64| x.to_le_bytes())
        .collect();
    put(h, at, &b);
    at
}

/// A test's scratch memory with a queue name written at its start.
struct Mem {
    base: u64,
}

impl Mem {
    fn new(h: &mut Harness) -> Self {
        Mem {
            base: h.anon(4 * P, 3, false),
        }
    }

    fn name(&self, h: &Harness, name: &[u8]) -> u64 {
        cstr(h, self.base, name)
    }

    fn buf(&self) -> u64 {
        self.base + 0x1000
    }
}

fn open(h: &mut Harness, m: &Mem, name: &[u8], flags: u64, mode: u64, at: u64) -> i64 {
    let n = m.name(h, name);
    h.call(Sysno::MqOpen, &[n, flags, mode, at])
}

fn send(h: &mut Harness, fd: u64, at: u64, text: &[u8], prio: u64) -> i64 {
    put(h, at, text);
    h.call(Sysno::MqTimedsend, &[fd, at, text.len() as u64, prio, 0])
}

/// Receives into `at` (8192 bytes): the text and its priority.
fn recv(h: &mut Harness, fd: u64, at: u64) -> Result<(Vec<u8>, u32), i32> {
    let prio = at + 0x2000;
    let r = h.call(Sysno::MqTimedreceive, &[fd, at, 8192, prio, 0]);
    if r < 0 {
        return Err(-r as i32);
    }
    let p = u32::from_le_bytes(get(h, prio, 4).try_into().unwrap());
    Ok((get(h, at, r as usize), p))
}

/// The attributes `mq_getsetattr` reports: flags, maxmsg, msgsize,
/// curmsgs.
fn getattr(h: &mut Harness, fd: u64, at: u64) -> [u64; 4] {
    put(h, at, &[0xff; 64]);
    assert_eq!(h.call(Sysno::MqGetsetattr, &[fd, 0, at]), 0);
    assert!(get(h, at + 32, 32).iter().all(|&b| b == 0), "reserved");
    [
        word(h, at),
        word(h, at + 8),
        word(h, at + 16),
        word(h, at + 24),
    ]
}

#[test]
fn mq_open_checks_in_the_kernels_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = Mem::new(&mut h);
        let a = m.base + 0x800;
        // The attributes are copied first, with or without O_CREAT.
        let n = m.name(&h, b"q");
        assert_eq!(h.err(Sysno::MqOpen, &[BAD, O_RDWR, 0, BAD]), EFAULT);
        assert_eq!(h.err(Sysno::MqOpen, &[n, O_RDWR, 0, BAD]), EFAULT);
        // Then the name (getname), then a descriptor, then the look-up.
        assert_eq!(h.err(Sysno::MqOpen, &[BAD, O_RDWR, 0, 0]), EFAULT);
        let empty = cstr(&h, m.base + 0x100, b"");
        assert_eq!(
            h.err(Sysno::MqOpen, &[empty, O_RDWR | O_CREAT, 0o600, 0]),
            ENOENT
        );
        put(&h, m.buf(), &[b'n'; 4096]);
        put(&h, m.buf() + 4096, &[0]);
        assert_eq!(h.err(Sysno::MqOpen, &[m.buf(), O_RDWR, 0, 0]), ENAMETOOLONG);
        for bad in [&b"a/b"[..], b"/lead", b".", b".."] {
            assert_eq!(
                open(&mut h, &m, bad, O_RDWR | O_CREAT, 0o600, 0),
                -(EACCES as i64)
            );
        }
        assert_eq!(
            open(&mut h, &m, &[b'n'; 256], O_RDWR | O_CREAT, 0o600, 0),
            -(ENAMETOOLONG as i64)
        );
        let long = open(&mut h, &m, &[b'n'; 255], O_RDWR | O_CREAT, 0o600, 0);
        assert!(long >= 0);
        assert_eq!(open(&mut h, &m, b"none", O_RDWR, 0, 0), -(ENOENT as i64));
        // Attributes at creation.
        for (maxmsg, msgsize) in [(0, 8), (-1, 8), (11, 8), (10, 0), (10, 8193)] {
            attr(&h, a, maxmsg, msgsize);
            assert_eq!(
                open(&mut h, &m, b"q", O_RDWR | O_CREAT, 0o600, a),
                -(EINVAL as i64)
            );
        }
        attr(&h, a, 3, 16);
        let fd = open(&mut h, &m, b"q", O_RDWR | O_CREAT | O_EXCL, 0o640, a) as u64;
        assert_eq!(getattr(&mut h, fd, m.buf()), [0, 3, 16, 0]);
        // Close-on-exec, and the flags less those of creation.
        assert_eq!(h.call(Sysno::Fcntl, &[fd, F_GETFD, 0]), 1);
        assert_eq!(h.call(Sysno::Fcntl, &[fd, F_GETFL, 0]) as u64, O_RDWR);
        // Existing: O_EXCL, access mode 3, then the permission; the
        // attributes are copied but not checked.
        attr(&h, a, 0, 0);
        assert_eq!(
            open(&mut h, &m, b"q", O_RDWR | O_CREAT | O_EXCL, 0, a),
            -(EEXIST as i64)
        );
        assert_eq!(open(&mut h, &m, b"q", 3, 0, 0), -(EINVAL as i64));
        let again = open(&mut h, &m, b"q", O_RDONLY | O_CREAT, 0, a);
        assert!(again >= 0);
        // A default queue.
        let d = open(&mut h, &m, b"default", O_WRONLY | O_CREAT, 0o600, 0) as u64;
        assert_eq!(getattr(&mut h, d, m.buf()), [0, 10, 8192, 0]);
        // Access mode 3 creates a queue it can neither send to nor
        // receive from.
        let neither = open(&mut h, &m, b"neither", 3 | O_CREAT, 0o600, 0) as u64;
        assert_eq!(h.call(Sysno::Fcntl, &[neither, F_GETFL, 0]), 3);
        assert_eq!(send(&mut h, neither, m.buf(), b"x", 0), -(EBADF as i64));
        assert_eq!(recv(&mut h, neither, m.buf()), Err(EBADF));
        // The descriptor is taken before the name is looked up.
        let low = h.ok(Sysno::Dup, &[fd]);
        h.ok(Sysno::Close, &[low]);
        h.proc.state.rlimits[7].0 = low;
        assert_eq!(
            open(&mut h, &m, b"a/b", O_RDWR | O_CREAT, 0o600, 0),
            -(EMFILE as i64)
        );
    });
}

#[test]
fn a_queue_has_the_creators_ids_and_permissions() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = Mem::new(&mut h);
        creds(&mut h, 0);
        h.proc.state.umask = 0o022;
        let fd = open(&mut h, &m, b"perm", O_RDWR | O_CREAT, 0o7666, 0) as u64;
        let st = m.buf();
        h.ok(Sysno::Fstat, &[fd, st]);
        let (mode_at, uid_at, size_at) = if abi == LinuxAbi::X86_64 {
            (24, 28, 48)
        } else {
            (16, 24, 48)
        };
        let u32_at = |h: &Harness, at| u32::from_le_bytes(get(h, st + at, 4).try_into().unwrap());
        // S_IFREG with the S_IALLUGO bits the umask leaves.
        assert_eq!(u32_at(&h, mode_at), 0o100000 | 0o7644);
        assert_eq!(u32_at(&h, uid_at), 0);
        assert_eq!(word(&h, st + size_at), 80, "FILENT_SIZE");
        h.ok(Sysno::Fchmod, &[fd, 0o600]);
        h.ok(Sysno::Fstat, &[fd, st]);
        assert_eq!(u32_at(&h, mode_at), 0o100600);
        // Another user may not open it, nor remove its name.
        creds(&mut h, NOBODY);
        assert_eq!(open(&mut h, &m, b"perm", O_RDONLY, 0, 0), -(EACCES as i64));
        let n = m.name(&h, b"perm");
        assert_eq!(h.err(Sysno::MqUnlink, &[n]), EPERM);
        assert_eq!(h.err(Sysno::Fchmod, &[fd, 0o666]), EPERM);
        creds(&mut h, 0);
        h.ok(Sysno::Fchmod, &[fd, 0o604]);
        creds(&mut h, NOBODY);
        let r = open(&mut h, &m, b"perm", O_RDONLY, 0, 0);
        assert!(r >= 0);
        assert_eq!(open(&mut h, &m, b"perm", O_WRONLY, 0, 0), -(EACCES as i64));
        // Root passes over the permission bits and the limits.
        creds(&mut h, 0);
        h.ok(Sysno::Fchmod, &[fd, 0]);
        assert!(open(&mut h, &m, b"perm", O_RDWR, 0, 0) >= 0);
        let a = attr(&h, m.base + 0x800, 64, 64);
        assert!(open(&mut h, &m, b"big", O_RDWR | O_CREAT, 0o600, a) >= 0);
        attr(&h, a, 65537, 64);
        assert_eq!(
            open(&mut h, &m, b"huge", O_RDWR | O_CREAT, 0o600, a),
            -(EINVAL as i64)
        );
    });
}

#[test]
fn queues_are_charged_to_their_creators_rlimit_and_counted() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = Mem::new(&mut h);
        creds(&mut h, NOBODY);
        // A default queue costs 10 * 8192 bytes and 10 message and tree
        // nodes of 48 bytes each: 82880.
        h.proc.state.rlimits[12].0 = 2 * 82880 - 1;
        assert!(open(&mut h, &m, b"one", O_RDWR | O_CREAT, 0o600, 0) >= 0);
        assert_eq!(
            open(&mut h, &m, b"two", O_RDWR | O_CREAT, 0o600, 0),
            -(EMFILE as i64)
        );
        let n = m.name(&h, b"one");
        h.ok(Sysno::MqUnlink, &[n]);
        assert!(open(&mut h, &m, b"two", O_RDWR | O_CREAT, 0o600, 0) >= 0);
        // queues_max: 256 queues without CAP_SYS_RESOURCE.
        h.proc.state.rlimits[12].0 = 1 << 30;
        h.proc.state.rlimits[7].0 = 1024;
        let a = attr(&h, m.base + 0x800, 1, 1);
        for i in 1..256 {
            let fd = open(
                &mut h,
                &m,
                format!("n{i}").as_bytes(),
                O_RDWR | O_CREAT,
                0o600,
                a,
            );
            assert!(fd >= 0, "{i}: {fd}");
            h.ok(Sysno::Close, &[fd as u64]);
        }
        assert_eq!(
            open(&mut h, &m, b"n256", O_RDWR | O_CREAT, 0o600, a),
            -(ENOSPC as i64)
        );
        creds(&mut h, 0);
        assert!(open(&mut h, &m, b"n256", O_RDWR | O_CREAT, 0o600, a) >= 0);
    });
}

#[test]
fn messages_come_highest_priority_first() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = Mem::new(&mut h);
        let a = attr(&h, m.base + 0x800, 4, 16);
        let fd = open(&mut h, &m, b"prio", O_RDWR | O_CREAT, 0o600, a) as u64;
        let b = m.buf();
        assert_eq!(send(&mut h, fd, b, b"low", 1), 0);
        assert_eq!(send(&mut h, fd, b, b"high", 9), 0);
        assert_eq!(send(&mut h, fd, b, b"low2", 1), 0);
        assert_eq!(send(&mut h, fd, b, b"high2", 9), 0);
        assert_eq!(getattr(&mut h, fd, b)[3], 4);
        // The status line: the bytes queued and no notification.
        let mut line = vec![0u8; 64];
        let n = h.call(Sysno::Read, &[fd, b, 64]) as usize;
        line.truncate(n);
        line.copy_from_slice(&get(&h, b, n));
        assert_eq!(
            line,
            b"QSIZE:16         NOTIFY:0     SIGNO:0     NOTIFY_PID:0     \n"
        );
        assert_eq!(h.call(Sysno::Read, &[fd, b, 64]), 0, "at its end");
        assert_eq!(h.call(Sysno::Lseek, &[fd, 6, 0]), 6);
        assert_eq!(h.call(Sysno::Read, &[fd, b, 2]), 2);
        assert_eq!(get(&h, b, 2), b"16");
        assert_eq!(h.call(Sysno::Lseek, &[fd, (-5i64) as u64, 2]), 75);
        assert_eq!(h.err(Sysno::Write, &[fd, b, 1]), EINVAL);
        for (text, prio) in [(&b"high"[..], 9), (b"high2", 9), (b"low", 1), (b"low2", 1)] {
            assert_eq!(recv(&mut h, fd, b), Ok((text.to_vec(), prio)));
        }
        // Sizes, priorities, access, and non-blocking calls.
        assert_eq!(send(&mut h, fd, b, &[0; 17], 0), -(EMSGSIZE as i64));
        assert_eq!(h.err(Sysno::MqTimedsend, &[fd, b, 1, 32768, 0]), EINVAL);
        assert_eq!(h.err(Sysno::MqTimedsend, &[fd, BAD, 1, 32767, 0]), EFAULT);
        assert_eq!(h.err(Sysno::MqTimedreceive, &[fd, b, 15, 0, 0]), EMSGSIZE);
        assert_eq!(h.err(Sysno::MqTimedsend, &[99, b, 1, 0, 0]), EBADF);
        assert_eq!(h.err(Sysno::MqTimedsend, &[1, b, 1, 0, 0]), EBADF);
        let ro = open(&mut h, &m, b"prio", O_RDONLY | O_NONBLOCK, 0, 0) as u64;
        assert_eq!(send(&mut h, ro, b, b"x", 0), -(EBADF as i64));
        assert_eq!(recv(&mut h, ro, b), Err(EAGAIN));
        let wo = open(&mut h, &m, b"prio", O_WRONLY | O_NONBLOCK, 0, 0) as u64;
        assert_eq!(recv(&mut h, wo, b), Err(EBADF));
        assert_eq!(h.err(Sysno::Read, &[wo, b, 8]), EBADF);
        for _ in 0..4 {
            assert_eq!(send(&mut h, wo, b, b"x", 0), 0);
        }
        assert_eq!(send(&mut h, wo, b, b"x", 0), -(EAGAIN as i64));
        // A message is taken even when copying it out faults.
        assert_eq!(h.err(Sysno::MqTimedreceive, &[fd, BAD, 16, 0, 0]), EFAULT);
        assert_eq!(getattr(&mut h, fd, b)[3], 3);
        // The timeout, checked before anything else, is absolute.
        assert_eq!(h.err(Sysno::MqTimedreceive, &[99, b, 16, 0, BAD]), EFAULT);
        let t = m.base + 0x900;
        put(
            &h,
            t,
            &[1i64.to_le_bytes(), 1_000_000_000i64.to_le_bytes()].concat(),
        );
        assert_eq!(h.err(Sysno::MqTimedsend, &[99, b, 1, 0, t]), EINVAL);
        put(&h, t, &[1i64.to_le_bytes(), 0i64.to_le_bytes()].concat());
        assert_eq!(send(&mut h, fd, b, b"x", 0), 0);
        assert_eq!(h.err(Sysno::MqTimedsend, &[fd, b, 1, 0, t]), ETIMEDOUT);
        for _ in 0..4 {
            recv(&mut h, fd, b).unwrap();
        }
        assert_eq!(h.err(Sysno::MqTimedreceive, &[fd, b, 16, 0, t]), ETIMEDOUT);
    });
}

#[test]
fn waiting_tasks_are_handed_messages_and_slots() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = Mem::new(&mut h);
        let a = attr(&h, m.base + 0x800, 1, 16);
        let fd = open(&mut h, &m, b"wait", O_RDWR | O_CREAT, 0o600, a) as u64;
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        let (b, r) = (m.buf(), m.buf() + 0x100);
        // A waiting receiver is handed the next message: it is never
        // queued, and no notification is sent.
        h.proc.threads[0].sigmask = sigmask(SIGUSR1);
        put(&h, m.base + 0xa00, &[0; 64]);
        put(&h, m.base + 0xa08, &SIGUSR1.to_le_bytes());
        put(&h, m.base + 0xa0c, &SIGEV_SIGNAL.to_le_bytes());
        h.ok(Sysno::MqNotify, &[fd, m.base + 0xa00]);
        assert_eq!(h.start(w, Sysno::MqTimedreceive, &[fd, r, 16, 0, 0]), None);
        assert_eq!(send(&mut h, fd, b, b"handed", 3), 0);
        assert_eq!(getattr(&mut h, fd, b)[3], 0);
        std::thread::sleep(Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 6);
        assert_eq!(get(&h, r, 6), b"handed");
        assert!(!h.proc.state.shared_pending.contains(SIGUSR1));
        h.ok(Sysno::MqNotify, &[fd, 0]);
        // A waiting sender's message fills the slot a receive frees.
        assert_eq!(send(&mut h, fd, b, b"first", 0), 0);
        put(&h, r, b"second");
        assert_eq!(h.start(w, Sysno::MqTimedsend, &[fd, r, 6, 0, 0]), None);
        assert_eq!(recv(&mut h, fd, b), Ok((b"first".to_vec(), 0)));
        assert_eq!(getattr(&mut h, fd, b)[3], 1);
        std::thread::sleep(Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 0);
        assert_eq!(recv(&mut h, fd, b), Ok((b"second".to_vec(), 0)));
        // A handled signal ends a wait (-ERESTARTSYS).
        assert_eq!(h.start(w, Sysno::MqTimedreceive, &[fd, r, 16, 0, 0]), None);
        let act = m.base + 0xb00;
        let mut words = vec![0x40_1000u64];
        if h.abi().has_sa_restorer() {
            words.extend([sa::RESTORER, 0x40_1100]);
        } else {
            words.push(0);
        }
        words.push(0);
        let bytes: Vec<u8> = words.iter().flat_map(|x| x.to_le_bytes()).collect();
        put(&h, act, &bytes);
        h.ok(Sysno::RtSigaction, &[SIGUSR2 as u64, act, 0, 8]);
        let pid = h.proc.state.pid as u64;
        h.ok(Sysno::Tgkill, &[pid, tid as u64, SIGUSR2 as u64]);
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), -(ERESTARTSYS as i64));
        // The ended wait left no registration: the message is queued and
        // the notification sent.
        h.ok(Sysno::MqNotify, &[fd, m.base + 0xa00]);
        assert_eq!(send(&mut h, fd, b, b"q", 0), 0);
        assert_eq!(getattr(&mut h, fd, b)[3], 1);
        assert!(h.proc.state.shared_pending.contains(SIGUSR1));
    });
}

/// A `struct sigevent` at `at`.
fn sigevent(h: &Harness, at: u64, value: u64, signo: i32, notify: i32) -> u64 {
    put(h, at, &[0; 64]);
    put(h, at, &value.to_le_bytes());
    put(h, at + 8, &signo.to_le_bytes());
    put(h, at + 12, &notify.to_le_bytes());
    at
}

#[test]
fn a_notification_signals_the_arrival_in_an_empty_queue() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = Mem::new(&mut h);
        let fd = open(&mut h, &m, b"note", O_RDWR | O_CREAT, 0o600, 0) as u64;
        let (b, ev) = (m.buf(), m.base + 0xa00);
        h.proc.threads[0].sigmask = sigmask(SIGUSR2);
        // The checks: the copy, the kind, the signal, then the queue.
        assert_eq!(h.err(Sysno::MqNotify, &[fd, BAD]), EFAULT);
        sigevent(&h, ev, 0, SIGUSR2, 3);
        assert_eq!(h.err(Sysno::MqNotify, &[99, ev]), EINVAL);
        sigevent(&h, ev, 0, 65, SIGEV_SIGNAL);
        assert_eq!(h.err(Sysno::MqNotify, &[99, ev]), EINVAL);
        sigevent(&h, ev, 0, -1, SIGEV_SIGNAL);
        assert_eq!(h.err(Sysno::MqNotify, &[99, ev]), EINVAL);
        sigevent(&h, ev, 0xfeed, SIGUSR2, SIGEV_SIGNAL);
        assert_eq!(h.err(Sysno::MqNotify, &[99, ev]), EBADF);
        assert_eq!(h.err(Sysno::MqNotify, &[1, ev]), EBADF);
        // SIGEV_THREAD: the cookie, the netlink socket, then refused.
        sigevent(&h, ev, BAD, 1, SIGEV_THREAD);
        assert_eq!(h.err(Sysno::MqNotify, &[fd, ev]), EFAULT);
        sigevent(&h, ev, b, 99, SIGEV_THREAD);
        assert_eq!(h.err(Sysno::MqNotify, &[fd, ev]), EBADF);
        sigevent(&h, ev, b, fd as i32, SIGEV_THREAD);
        assert_eq!(h.err(Sysno::MqNotify, &[fd, ev]), ENOTSOCK);
        let unix = h.ok(Sysno::Socket, &[1, 1, 0]);
        sigevent(&h, ev, b, unix as i32, SIGEV_THREAD);
        assert_eq!(h.err(Sysno::MqNotify, &[fd, ev]), EINVAL);
        let nl = h.ok(Sysno::Socket, &[16, 3, 0]);
        sigevent(&h, ev, b, nl as i32, SIGEV_THREAD);
        assert_eq!(h.err(Sysno::MqNotify, &[fd, ev]), ENOSYS);
        // A registration, one at a time.
        sigevent(&h, ev, 0xfeed, SIGUSR2, SIGEV_SIGNAL);
        h.ok(Sysno::MqNotify, &[fd, ev]);
        assert_eq!(h.err(Sysno::MqNotify, &[fd, ev]), EBUSY);
        let pid = h.proc.state.pid;
        let n = h.call(Sysno::Pread64, &[fd, b, 64, 0]) as usize;
        let line = String::from_utf8(get(&h, b, n)).unwrap();
        assert_eq!(
            line,
            format!(
                "QSIZE:0          NOTIFY:0     SIGNO:{:<5} NOTIFY_PID:{:<6}\n",
                SIGUSR2, pid
            )
        );
        // The first message fires it, once.
        assert_eq!(send(&mut h, fd, b, b"one", 0), 0);
        assert_eq!(send(&mut h, fd, b, b"two", 0), 0);
        let info = crate::user::linux::signal::deliver::dequeue_signal(
            &mut h.proc.state,
            &mut h.proc.threads[0],
            0,
        )
        .unwrap();
        assert_eq!((info.signo, info.code), (SIGUSR2, code::SI_MESGQ));
        assert_eq!((info.pid(), info.uid()), (pid, h.proc.state.creds.0));
        assert_eq!(info.value(), 0xfeed);
        assert!(!h.proc.state.shared_pending.contains(SIGUSR2));
        // Consumed: another may register; into a queue that is not empty
        // nothing fires.
        h.ok(Sysno::MqNotify, &[fd, ev]);
        assert_eq!(send(&mut h, fd, b, b"three", 0), 0);
        assert!(!h.proc.state.shared_pending.contains(SIGUSR2));
        // Removed by its owner, by closing any descriptor of the queue.
        h.ok(Sysno::MqNotify, &[fd, 0]);
        h.ok(Sysno::MqNotify, &[fd, 0]);
        h.ok(Sysno::MqNotify, &[fd, ev]);
        let dup = h.ok(Sysno::Dup, &[fd]);
        h.ok(Sysno::Close, &[dup]);
        h.ok(Sysno::MqNotify, &[fd, ev]);
        // SIGEV_NONE registers and fires nothing; so does signal 0.
        h.ok(Sysno::MqNotify, &[fd, 0]);
        for _ in 0..3 {
            recv(&mut h, fd, b).unwrap();
        }
        sigevent(&h, ev, 0, 0, SIGEV_NONE);
        h.ok(Sysno::MqNotify, &[fd, ev]);
        assert!(h.call(Sysno::Pread64, &[fd, b, 64, 17]) >= 43);
        assert_eq!(&get(&h, b, 7), b"NOTIFY:");
        assert_eq!(&get(&h, b + 7, 1), b"1");
        assert_eq!(send(&mut h, fd, b, b"x", 0), 0);
        assert!(!h.proc.state.shared_pending.contains(SIGUSR2));
        sigevent(&h, ev, 0, 0, SIGEV_SIGNAL);
        recv(&mut h, fd, b).unwrap();
        h.ok(Sysno::MqNotify, &[fd, ev]);
        assert_eq!(send(&mut h, fd, b, b"x", 0), 0);
        assert_eq!(h.proc.state.shared_pending.queued(), 0);
    });
}

#[test]
fn mq_getsetattr_sets_only_nonblocking() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = Mem::new(&mut h);
        let fd = open(&mut h, &m, b"attr", O_RDWR | O_CREAT, 0o600, 0) as u64;
        let (new, old) = (m.buf(), m.buf() + 0x100);
        attr(&h, new, 99, 99);
        put(&h, new, &(O_NONBLOCK | O_RDWR).to_le_bytes());
        assert_eq!(h.err(Sysno::MqGetsetattr, &[99, new, 0]), EINVAL);
        put(&h, new, &O_NONBLOCK.to_le_bytes());
        assert_eq!(h.err(Sysno::MqGetsetattr, &[99, new, 0]), EBADF);
        assert_eq!(h.err(Sysno::MqGetsetattr, &[fd, BAD, 0]), EFAULT);
        // The old attributes, then the new flags.
        assert_eq!(h.call(Sysno::MqGetsetattr, &[fd, new, old]), 0);
        assert_eq!(word(&h, old), 0);
        assert_eq!(getattr(&mut h, fd, old), [O_NONBLOCK, 10, 8192, 0]);
        assert_eq!(
            h.call(Sysno::Fcntl, &[fd, F_GETFL, 0]) as u64,
            O_RDWR | O_NONBLOCK
        );
        assert_eq!(recv(&mut h, fd, old), Err(EAGAIN));
        put(&h, new, &0u64.to_le_bytes());
        h.ok(Sysno::MqGetsetattr, &[fd, new, 0]);
        assert_eq!(getattr(&mut h, fd, old)[0], 0);
        // The copy out faults after the change.
        put(&h, new, &O_NONBLOCK.to_le_bytes());
        assert_eq!(h.err(Sysno::MqGetsetattr, &[fd, new, BAD]), EFAULT);
        assert_eq!(getattr(&mut h, fd, old)[0], O_NONBLOCK);
    });
}

#[test]
fn an_unlinked_queue_lives_while_it_is_open() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = Mem::new(&mut h);
        let n = m.name(&h, b"gone");
        assert_eq!(h.err(Sysno::MqUnlink, &[n]), ENOENT);
        assert_eq!(h.err(Sysno::MqUnlink, &[BAD]), EFAULT);
        let slash = cstr(&h, m.base + 0x100, b"/gone");
        assert_eq!(h.err(Sysno::MqUnlink, &[slash]), EACCES);
        let fd = open(&mut h, &m, b"gone", O_RDWR | O_CREAT, 0o600, 0) as u64;
        assert_eq!(send(&mut h, fd, m.buf(), b"kept", 0), 0);
        let n = m.name(&h, b"gone");
        h.ok(Sysno::MqUnlink, &[n]);
        assert_eq!(h.err(Sysno::MqUnlink, &[n]), ENOENT);
        assert_eq!(recv(&mut h, fd, m.buf()), Ok((b"kept".to_vec(), 0)));
        let st = m.buf();
        h.ok(Sysno::Fstat, &[fd, st]);
        let nlink_at = if abi == LinuxAbi::X86_64 { 16 } else { 20 };
        let nlink = if abi == LinuxAbi::X86_64 {
            word(&h, st + nlink_at)
        } else {
            u64::from(u32::from_le_bytes(
                get(&h, st + nlink_at, 4).try_into().unwrap(),
            ))
        };
        assert_eq!(nlink, 0);
        // A new queue of the name is another queue.
        let other = open(&mut h, &m, b"gone", O_RDWR | O_CREAT | O_EXCL, 0o600, 0) as u64;
        assert_eq!(send(&mut h, other, m.buf(), b"new", 0), 0);
        assert_eq!(getattr(&mut h, fd, m.buf())[3], 0);
        // /proc shows the name, and that it is gone.
        let link = |h: &mut Harness, fd: u64| {
            let p = cstr(h, m.base + 0x200, format!("/proc/self/fd/{fd}").as_bytes());
            let n = h.ok(Sysno::Readlinkat, &[(-100i64) as u64, p, m.buf(), 64]) as usize;
            String::from_utf8(get(h, m.buf(), n)).unwrap()
        };
        assert_eq!(link(&mut h, fd), "/gone (deleted)");
        assert_eq!(link(&mut h, other), "/gone");
    });
}

#[test]
fn a_queue_polls_readable_with_messages_and_writable_with_room() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let m = Mem::new(&mut h);
    let a = attr(&h, m.base + 0x800, 1, 8);
    let fd = open(&mut h, &m, b"poll", O_RDWR | O_CREAT, 0o600, a) as u64;
    let pfd = m.base + 0x900;
    let poll = |h: &mut Harness| {
        put(
            h,
            pfd,
            &[fd.to_le_bytes()[..4].to_vec(), vec![5, 0, 0, 0]].concat(),
        );
        let ts = pfd + 16;
        put(h, ts, &[0u8; 16]);
        h.call(Sysno::Ppoll, &[pfd, 1, ts, 0, 8]);
        u16::from_le_bytes(get(h, pfd + 6, 2).try_into().unwrap())
    };
    assert_eq!(poll(&mut h), 4, "POLLOUT");
    assert_eq!(send(&mut h, fd, m.buf(), b"x", 0), 0);
    assert_eq!(poll(&mut h), 1, "POLLIN");
}

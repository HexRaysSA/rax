//! `eventfd`, `timerfd`, and `signalfd` against `fs/eventfd.c`,
//! `fs/timerfd.c`, and `fs/signalfd.c`: the counter's limits and semaphore
//! reads, what a transfer's size and faults do (`vfs_read`, `vfs_write`,
//! `do_loop_readv_writev`), `timerfd` ticks from `hrtimer_forward` (driven
//! by explicit times through the object), the argument checks of each call
//! in the kernel's order, the `struct signalfd_siginfo` of every
//! `siginfo_t` layout (`signalfd_copyinfo`), and the wake-ups sleeping
//! readers and pollers depend on.

use std::cell::Cell;

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::fs::anon::{EventFd, TimerFd};
use crate::user::linux::host;
use crate::user::linux::posix_timers::{Base, Setting};
use crate::user::linux::signal::info::Layout;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::events::signalfd_record;

const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const EFD_SEMAPHORE: u64 = 1;
const MS: i64 = 1_000_000;

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    let mut b = [0u8; 8];
    h.proc.state.space.read(at, &mut b).unwrap();
    u64::from_le_bytes(b)
}

fn readable(fd: i32) -> bool {
    host::poll(&[(fd, true, false)], 0).unwrap()[0].readable
}

#[test]
fn eventfd_counts_and_refuses_what_eventfd_c_refuses() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let buf = h.scratch;
        assert_eq!(h.err(Sysno::Eventfd2, &[0, 0x10]), EINVAL);
        let e = h.ok(Sysno::Eventfd2, &[3, O_NONBLOCK | O_CLOEXEC]);
        assert!(h.proc.state.fds.get(e as i32).unwrap().cloexec);
        assert_eq!(h.ok(Sysno::Read, &[e, buf, 16]), 8);
        assert_eq!(u64_at(&h, buf), 3);
        assert_eq!(h.err(Sysno::Read, &[e, buf, 8]), EAGAIN);
        // The file operation sees every size, zero included.
        assert_eq!(h.err(Sysno::Read, &[e, buf, 7]), EINVAL);
        assert_eq!(h.err(Sysno::Read, &[e, buf, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Write, &[e, buf, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Write, &[e, buf, 9]), EINVAL);
        put(&h, buf, &u64::MAX.to_le_bytes());
        assert_eq!(h.err(Sysno::Write, &[e, buf, 8]), EINVAL);
        // Up to UINT64_MAX - 1, then no more.
        put(&h, buf, &(u64::MAX - 1).to_le_bytes());
        assert_eq!(h.ok(Sysno::Write, &[e, buf, 8]), 8);
        put(&h, buf, &1u64.to_le_bytes());
        assert_eq!(h.err(Sysno::Write, &[e, buf, 8]), EAGAIN);
        put(&h, buf, &0u64.to_le_bytes());
        assert_eq!(h.ok(Sysno::Write, &[e, buf, 8]), 8);
        // A bad destination: the range check first, then the count is
        // taken and the copy faults.
        assert_eq!(h.err(Sysno::Read, &[e, u64::MAX - 4, 8]), EFAULT);
        assert_eq!(h.err(Sysno::Read, &[e, 8, 8]), EFAULT);
        assert_eq!(h.err(Sysno::Read, &[e, buf, 8]), EAGAIN, "taken");
        // No position.
        assert_eq!(h.ok(Sysno::Lseek, &[e, 5, 0]), 0);
        assert_eq!(h.err(Sysno::Pread64, &[e, buf, 8, 0]), ESPIPE);
        assert_eq!(h.err(Sysno::Pwrite64, &[e, buf, 8, 0]), ESPIPE);
        // A semaphore gives 1 at a time.
        let s = h.ok(Sysno::Eventfd2, &[2, EFD_SEMAPHORE | O_NONBLOCK]);
        for _ in 0..2 {
            assert_eq!(h.ok(Sysno::Read, &[s, buf, 8]), 8);
            assert_eq!(u64_at(&h, buf), 1);
        }
        assert_eq!(h.err(Sysno::Read, &[s, buf, 8]), EAGAIN);
    });
}

#[test]
fn vectored_eventfd_transfers() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let (iov, data) = (h.scratch, h.scratch + 0x100);
    let e = h.ok(Sysno::Eventfd2, &[0, O_NONBLOCK]);
    let iovecs = |h: &Harness, v: &[(u64, u64)]| {
        let b: Vec<u8> = v
            .iter()
            .flat_map(|&(a, l)| a.to_le_bytes().into_iter().chain(l.to_le_bytes()))
            .collect();
        put(h, iov, &b);
    };
    put(&h, data, &[2u64.to_le_bytes(), 3u64.to_le_bytes()].concat());
    // Each vector is one write (do_loop_readv_writev).
    iovecs(&h, &[(data, 8), (data + 8, 8)]);
    assert_eq!(h.ok(Sysno::Writev, &[e, iov, 2]), 16);
    iovecs(&h, &[(data, 4), (data + 4, 4)]);
    assert_eq!(h.err(Sysno::Writev, &[e, iov, 2]), EINVAL);
    // A read goes across vectors.
    iovecs(&h, &[(data, 3), (data + 8, 5)]);
    assert_eq!(h.ok(Sysno::Readv, &[e, iov, 2]), 8);
    let mut b = [0u8; 16];
    h.proc.state.space.read(data, &mut b).unwrap();
    let mut v = [0u8; 8];
    v[..3].copy_from_slice(&b[..3]);
    v[3..].copy_from_slice(&b[8..13]);
    assert_eq!(u64::from_le_bytes(v), 5);
}

#[test]
fn eventfd_levels_follow_the_counter() {
    let ev = EventFd::new(0, false).unwrap();
    assert!(!readable(ev.readable_fd()));
    assert!(readable(ev.writable_fd()));
    assert!(ev.write(2));
    assert!(readable(ev.readable_fd()));
    assert_eq!(ev.poll(), (true, true, false));
    assert!(ev.write(u64::MAX - 3));
    assert!(!readable(ev.writable_fd()), "full");
    assert_eq!(ev.poll(), (true, false, false));
    assert!(!ev.write(1));
    assert_eq!(ev.read(), Some(u64::MAX - 1));
    assert!(!readable(ev.readable_fd()));
    assert!(readable(ev.writable_fd()));
}

#[test]
fn a_blocking_eventfd_read_sleeps_on_the_level() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let e = h.ok(Sysno::Eventfd2, &[0, 0]);
    let buf = h.scratch;
    assert_eq!(h.start(0, Sysno::Read, &[e, buf, 8]), None);
    let file = h.proc.state.fds.file(e as i32).unwrap();
    let crate::user::linux::fs::fd::FileObject::Anon(crate::user::linux::fs::anon::Anon::Event(ev)) =
        &file.object
    else {
        unreachable!()
    };
    let b = h.proc.threads[0].blocked.take().unwrap();
    assert_eq!(b.wait.fds, vec![(ev.readable_fd(), true, false)]);
    // A write makes the level readable; the read then finds the count.
    assert!(ev.write(4));
    assert!(readable(ev.readable_fd()));
    assert_eq!(h.start(0, Sysno::Read, &[e, buf, 8]), Some(8));
    assert_eq!(u64_at(&h, buf), 4);
    // With a signal pending, a read that would sleep restarts instead.
    h.proc.threads[0].sigpending = true;
    assert_eq!(
        h.start(0, Sysno::Read, &[e, buf, 8]),
        Some(-(deliver::restart::ERESTARTSYS as i64))
    );
}

/// A `timerfd` with a settable monotonic and realtime clock.
fn timer(clockid: i32) -> (TimerFd, Cell<i64>) {
    (TimerFd::new(clockid).unwrap(), Cell::new(0))
}

#[test]
fn timerfd_ticks_are_expirations_since_the_last_read() {
    let (t, now) = timer(1);
    let clock = |_: Base| now.get();
    let every = Setting {
        value: 10 * MS,
        interval: 10 * MS,
    };
    assert_eq!(t.settime(0, every, &clock), Setting::default());
    assert_eq!(t.read(&clock), None);
    now.set(10 * MS);
    assert!(t.readable(&clock));
    assert!(readable(t.readable_fd()));
    // Fired once, the timer waits for a read: at 45 the read counts
    // 1 + (k - 1) with k = (45 - 10) / 10 + 1 = 4, so 4; E becomes 50.
    now.set(45 * MS);
    assert_eq!(t.read(&clock), Some(4));
    assert!(!readable(t.readable_fd()));
    assert_eq!(t.gettime(&clock).value, 5 * MS);
    // gettime also moves a fired timer on, keeping the ticks: at 72,
    // 1 + (72 - 50) / 10 = 3 periods.
    now.set(72 * MS);
    assert_eq!(
        t.gettime(&clock),
        Setting {
            value: 8 * MS,
            interval: 10 * MS
        }
    );
    assert_eq!(t.read(&clock), Some(3));
    // settime returns the time left and clears the ticks.
    now.set(95 * MS);
    let old = t.settime(0, Setting::default(), &clock);
    assert_eq!(
        old,
        Setting {
            value: 5 * MS,
            interval: 10 * MS
        }
    );
    assert_eq!(t.read(&clock), None);
    // TFD_IOC_SET_TICKS.
    t.set_ticks(42, &clock);
    assert_eq!(t.read(&clock), Some(42));
    // A zero value disarms but keeps the interval (timerfd_setup).
    t.settime(
        0,
        Setting {
            value: 0,
            interval: 7,
        },
        &clock,
    );
    assert_eq!(
        t.gettime(&clock),
        Setting {
            value: 0,
            interval: 7
        }
    );
    assert!(t.deadline().is_none());
}

#[test]
fn timerfd_absolute_and_realtime_settings() {
    let (t, now) = timer(0);
    let clock = |b: Base| match b {
        Base::Realtime => now.get() + 1_000_000 * MS,
        _ => now.get(),
    };
    // A relative CLOCK_REALTIME timer counts on monotonic time.
    t.settime(
        0,
        Setting {
            value: 10 * MS,
            interval: 0,
        },
        &clock,
    );
    now.set(10 * MS);
    assert!(t.readable(&clock));
    assert_eq!(t.read(&clock), Some(1));
    // An absolute one on wall-clock time; one in the past fires.
    let at = 1_000_000 * MS + 30 * MS;
    t.settime(
        1,
        Setting {
            value: at,
            interval: 0,
        },
        &clock,
    );
    assert_eq!(t.gettime(&clock).value, 20 * MS);
    assert_eq!(t.settime_flags(), 1);
    t.settime(
        3,
        Setting {
            value: 5,
            interval: 0,
        },
        &clock,
    );
    assert_eq!(t.settime_flags(), 3);
    assert_eq!(t.read(&clock), Some(1));
}

#[test]
fn timerfd_calls_check_in_the_kernel_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let spec = h.scratch;
        assert_eq!(h.err(Sysno::TimerfdCreate, &[2, 0]), EINVAL);
        assert_eq!(h.err(Sysno::TimerfdCreate, &[1, 1]), EINVAL);
        let alarm = h.call(Sysno::TimerfdCreate, &[9, 0]);
        if h.proc.state.creds.1 == 0 {
            assert!(alarm >= 0);
        } else {
            assert_eq!(alarm, -(EPERM as i64));
        }
        let t = h.ok(Sysno::TimerfdCreate, &[1, O_NONBLOCK]);
        let e = h.ok(Sysno::Eventfd2, &[0, 0]);
        put(&h, spec, &[0u8; 32]);
        // The setting is read first, then checked, then the descriptor.
        assert_eq!(h.err(Sysno::TimerfdSettime, &[99, 0, 0, 0]), EFAULT);
        assert_eq!(h.err(Sysno::TimerfdSettime, &[99, 4, spec, 0]), EINVAL);
        assert_eq!(h.err(Sysno::TimerfdSettime, &[99, 0, spec, 0]), EBADF);
        assert_eq!(h.err(Sysno::TimerfdSettime, &[e, 0, spec, 0]), EINVAL);
        assert_eq!(h.err(Sysno::TimerfdGettime, &[e, spec]), EINVAL);
        assert_eq!(h.err(Sysno::TimerfdGettime, &[t, 8]), EFAULT);
        let mut bad = [0u8; 32];
        bad[24..].copy_from_slice(&1_000_000_000i64.to_le_bytes());
        put(&h, spec, &bad);
        assert_eq!(h.err(Sysno::TimerfdSettime, &[t, 0, spec, 0]), EINVAL);
        // Reads and writes.
        assert_eq!(h.err(Sysno::Read, &[t, spec, 4]), EINVAL);
        assert_eq!(h.err(Sysno::Read, &[t, spec, 8]), EAGAIN);
        assert_eq!(h.err(Sysno::Write, &[t, spec, 8]), EINVAL);
        assert_eq!(h.err(Sysno::Write, &[t, 8, 8]), EINVAL, "before the buffer");
        // An absolute time in the past fires at once.
        let mut past = [0u8; 32];
        past[24..].copy_from_slice(&1i64.to_le_bytes());
        put(&h, spec, &past);
        assert_eq!(h.ok(Sysno::TimerfdSettime, &[t, 1, spec, spec + 64]), 0);
        assert_eq!(h.ok(Sysno::Read, &[t, spec, 8]), 8);
        assert_eq!(u64_at(&h, spec), 1);
        // TFD_IOC_SET_TICKS; other requests are ENOTTY.
        put(&h, spec, &0u64.to_le_bytes());
        assert_eq!(h.err(Sysno::Ioctl, &[t, 0x4008_5400, spec]), EINVAL);
        put(&h, spec, &9u64.to_le_bytes());
        assert_eq!(h.ok(Sysno::Ioctl, &[t, 0x4008_5400, spec]), 0);
        assert_eq!(h.err(Sysno::Ioctl, &[e, 0x4008_5400, spec]), ENOTTY);
        assert_eq!(h.err(Sysno::Ioctl, &[t, 0x541b, spec]), ENOTTY);
        // A short copy reports the bytes copied; the ticks are taken.
        let page = h.anon(0x2000, 3, false);
        h.ok(Sysno::Munmap, &[page + 0x1000, 0x1000]);
        assert_eq!(h.ok(Sysno::Read, &[t, page + 0xffc, 8]), 4);
        assert_eq!(h.err(Sysno::Read, &[t, spec, 8]), EAGAIN);
    });
}

#[test]
fn anonymous_files_look_as_anon_inodes_do() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let buf = h.scratch;
        let e = h.ok(Sysno::Eventfd2, &[0, 0]);
        h.ok(Sysno::Fstat, &[e, buf]);
        let mode_at = match abi {
            LinuxAbi::X86_64 => 24,
            _ => 16,
        };
        let mut m = [0u8; 4];
        h.proc.state.space.read(buf + mode_at, &mut m).unwrap();
        assert_eq!(u32::from_le_bytes(m), 0o600, "{abi:?}: no file type");
        let link = format!("/proc/self/fd/{e}\0");
        put(&h, buf, link.as_bytes());
        let n = h.ok(Sysno::Readlinkat, &[-100i64 as u64, buf, buf + 0x100, 64]);
        let mut name = vec![0u8; n as usize];
        h.proc.state.space.read(buf + 0x100, &mut name).unwrap();
        assert_eq!(name, b"anon_inode:[eventfd]");
        assert_eq!(h.err(Sysno::Fsync, &[e]), EINVAL);
        assert_eq!(h.err(Sysno::Getdents64, &[e, buf, 256]), ENOTDIR);
    });
}

/// A `signalfd` for `mask` in `h`.
fn signalfd(h: &mut Harness, mask: u64, flags: u64) -> u64 {
    let at = h.scratch + 0xf00;
    put(h, at, &mask.to_le_bytes());
    h.ok(Sysno::Signalfd4, &[u64::MAX, at, 8, flags])
}

#[test]
fn signalfd_calls_check_in_the_kernel_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let at = h.scratch;
        put(&h, at, &sigmask(SIGUSR1).to_le_bytes());
        assert_eq!(h.err(Sysno::Signalfd4, &[u64::MAX, at, 4, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Signalfd4, &[u64::MAX, 8, 8, 0]), EFAULT);
        assert_eq!(h.err(Sysno::Signalfd4, &[u64::MAX, at, 8, 1]), EINVAL);
        let s = signalfd(&mut h, sigmask(SIGUSR1), O_NONBLOCK);
        let e = h.ok(Sysno::Eventfd2, &[0, 0]);
        assert_eq!(h.err(Sysno::Signalfd4, &[e, at, 8, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Signalfd4, &[99, at, 8, 0]), EBADF);
        assert_eq!(h.ok(Sysno::Signalfd4, &[s, at, 8, 0]), s);
        assert_eq!(h.err(Sysno::Read, &[s, at, 127]), EINVAL);
        assert_eq!(h.err(Sysno::Read, &[s, at, 128]), EAGAIN);
        assert_eq!(h.err(Sysno::Write, &[s, at, 8]), EINVAL);
        // SIGKILL and SIGSTOP are dropped from the mask.
        let all = signalfd(&mut h, u64::MAX, 0);
        let file = h.proc.state.fds.file(all as i32).unwrap();
        let crate::user::linux::fs::fd::FileObject::Anon(
            crate::user::linux::fs::anon::Anon::Signal(sf),
        ) = &file.object
        else {
            unreachable!()
        };
        assert_eq!(sf.mask(), !(sigmask(SIGKILL) | sigmask(SIGSTOP)));
    });
}

#[test]
fn signalfd_reads_the_callers_signals_in_order() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let buf = h.anon(0x1000, 3, false);
    let blocked = sigmask(SIGUSR1) | sigmask(SIGRTMIN + 2);
    h.proc.threads[0].sigmask = blocked;
    let s = signalfd(&mut h, blocked, O_NONBLOCK);
    let pid = h.proc.state.pid as u64;
    h.ok(Sysno::Tgkill, &[pid, pid, SIGUSR1 as u64]);
    let rt = SIGRTMIN as u64 + 2;
    let info = h.scratch;
    let mut q = [0u8; 128];
    q[..4].copy_from_slice(&(rt as i32).to_le_bytes());
    q[8..12].copy_from_slice(&code::SI_QUEUE.to_le_bytes());
    q[24..32].copy_from_slice(&0x55u64.to_le_bytes());
    put(&h, info, &q);
    h.ok(Sysno::RtSigqueueinfo, &[pid, rt, info]);
    // A signal outside the mask is not read.
    h.proc.threads[0].sigmask |= sigmask(SIGUSR2);
    h.ok(Sysno::Tgkill, &[pid, pid, SIGUSR2 as u64]);
    assert_eq!(h.ok(Sysno::Read, &[s, buf, 3 * 128 + 5]), 256);
    let mut r = [0u8; 256];
    h.proc.state.space.read(buf, &mut r).unwrap();
    let i32_at = |at: usize| i32::from_le_bytes(r[at..at + 4].try_into().unwrap());
    assert_eq!((i32_at(0), i32_at(8)), (SIGUSR1, code::SI_TKILL));
    assert_eq!(i32_at(12), pid as i32, "ssi_pid");
    assert_eq!((i32_at(128), i32_at(136)), (rt as i32, code::SI_QUEUE));
    assert_eq!(i32_at(128 + 44), 0x55, "ssi_int");
    assert_eq!(
        u64::from_le_bytes(r[128 + 48..128 + 56].try_into().unwrap()),
        0x55,
        "ssi_ptr"
    );
    assert_eq!(h.err(Sysno::Read, &[s, buf, 128]), EAGAIN);
    assert!(h.proc.threads[0].pending.contains(SIGUSR2));
}

#[test]
fn a_faulting_signalfd_destination_loses_the_record() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    h.proc.threads[0].sigmask = sigmask(SIGUSR1) | sigmask(SIGUSR2);
    let s = signalfd(&mut h, sigmask(SIGUSR1) | sigmask(SIGUSR2), O_NONBLOCK);
    let pid = h.proc.state.pid as u64;
    let page = h.anon(0x2000, 3, false);
    h.ok(Sysno::Munmap, &[page + 0x1000, 0x1000]);
    h.ok(Sysno::Tgkill, &[pid, pid, SIGUSR1 as u64]);
    h.ok(Sysno::Tgkill, &[pid, pid, SIGUSR2 as u64]);
    // The first record fits; the second does not and is lost.
    assert_eq!(h.ok(Sysno::Read, &[s, page + 0x1000 - 128, 256]), 128);
    assert_eq!(h.err(Sysno::Read, &[s, page, 128]), EAGAIN);
}

#[test]
fn signalfd_records_follow_the_siginfo_layout() {
    let at = |r: &[u8; 128], o: usize| i32::from_le_bytes(r[o..o + 4].try_into().unwrap());
    let q = |r: &[u8; 128], o: usize| u64::from_le_bytes(r[o..o + 8].try_into().unwrap());
    // Timer: ssi_tid, ssi_overrun, ssi_int, ssi_ptr.
    let mut t = SigInfo::timer(SIGRTMIN, 5, 0x1_0000_0007);
    t.set_overrun(3);
    assert_eq!(t.layout(), Layout::Timer);
    let r = signalfd_record(&t);
    assert_eq!((at(&r, 24), at(&r, 32), at(&r, 44)), (5, 3, 7));
    assert_eq!(q(&r, 48), 0x1_0000_0007);
    assert_eq!(at(&r, 12), 0, "no ssi_pid");
    // Child: pid, uid, status, utime, stime.
    let c = SigInfo::child(code::CLD_EXITED, 42, 1000, 9, 11, 12);
    assert_eq!(c.layout(), Layout::Chld);
    let r = signalfd_record(&c);
    assert_eq!((at(&r, 12), at(&r, 16), at(&r, 40)), (42, 1000, 9));
    assert_eq!((q(&r, 56), q(&r, 64)), (11, 12));
    // Fault: the address only.
    let f = SigInfo::fault(SIGSEGV, 1, 0xdead_0000);
    assert_eq!(f.layout(), Layout::Fault);
    let r = signalfd_record(&f);
    assert_eq!(q(&r, 72), 0xdead_0000);
    // A positive code of a signal without its own codes is a poll layout
    // up to NSIGPOLL, then kill; SI_KERNEL is kill; SI_SIGIO poll; other
    // negative codes rt.
    let poll = SigInfo::kill(SIGUSR1, 3, 0, 0);
    assert_eq!(poll.layout(), Layout::Poll);
    assert_eq!(SigInfo::kill(SIGUSR1, 7, 0, 0).layout(), Layout::Kill);
    assert_eq!(SigInfo::kernel(SIGUSR1).layout(), Layout::Kill);
    assert_eq!(SigInfo::kill(SIGUSR1, -5, 0, 0).layout(), Layout::Poll);
    assert_eq!(SigInfo::kill(SIGUSR1, -1, 0, 0).layout(), Layout::Rt);
    // SIGBUS BUS_MCEERR_AR, SIGSYS SYS_SECCOMP.
    assert_eq!(SigInfo::fault(SIGBUS, 4, 0).layout(), Layout::FaultMceErr);
    assert_eq!(SigInfo::fault(SIGSYS, 1, 0).layout(), Layout::Sys);
    assert_eq!(SigInfo::fault(SIGSEGV, 11, 0).layout(), Layout::Kill);
}

#[test]
fn queued_signals_wake_signalfd_readers_and_pollers() {
    use crate::user::linux::syscall::thread::cf::*;
    const THREAD: u64 =
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    let mut h = Harness::new(LinuxAbi::Riscv64);
    h.proc.threads[0].sigmask = sigmask(SIGUSR1);
    let s = signalfd(&mut h, sigmask(SIGUSR1), 0);
    let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
    let other = h.index_of(tid);
    let buf = h.scratch;
    // The read sleeps on the signal set.
    assert_eq!(h.start(0, Sysno::Read, &[s, buf, 128]), None);
    assert_eq!(
        h.proc.threads[0].blocked.as_ref().unwrap().wait.signals,
        sigmask(SIGUSR1)
    );
    // A blocked signal sets no TIF_SIGPENDING, but wakes the reader.
    let pid = h.proc.state.pid as u64;
    let me = h.proc.threads[0].tid as u64;
    assert_eq!(
        h.start(other, Sysno::Tgkill, &[pid, me, SIGUSR1 as u64]),
        Some(0)
    );
    assert!(!h.proc.threads[0].sigpending);
    let b = h.proc.threads[0].blocked.take().unwrap();
    assert!(b.woken);
    assert_eq!(h.start(0, Sysno::Read, &[s, buf, 128]), Some(128));
    // A poll on it sleeps with the set too, and so does a new mask.
    let pfd = h.scratch + 0x200;
    let mut rec = [0u8; 8];
    rec[..4].copy_from_slice(&(s as i32).to_le_bytes());
    rec[4..6].copy_from_slice(&1u16.to_le_bytes());
    put(&h, pfd, &rec);
    assert_eq!(h.start(0, Sysno::Ppoll, &[pfd, 1, 0, 0, 8]), None);
    assert_eq!(
        h.proc.threads[0].blocked.as_ref().unwrap().wait.signals,
        sigmask(SIGUSR1)
    );
    let at = h.scratch + 0x300;
    put(&h, at, &sigmask(SIGUSR2).to_le_bytes());
    assert_eq!(
        h.start(other, Sysno::Signalfd4, &[s, at, 8, 0]),
        Some(s as i64)
    );
    assert!(h.proc.threads[0].blocked.as_ref().unwrap().woken);
}

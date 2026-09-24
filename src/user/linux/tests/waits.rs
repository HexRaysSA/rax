//! Blocking calls, interval timers, and system-call restart, driven through
//! [`dispatch`](crate::user::linux::syscall::dispatch) on a spawned process.
//! Expectations follow `kernel/time/itimer.c`, `kernel/time/hrtimer.c`, and
//! `fs/select.c` (Linux 6.19); timing bounds are generous because the host
//! schedules the test.

use std::time::{Duration, Instant};

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::deliver::restart::*;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::{Outcome, RestartBlock};

fn ret(code: i32) -> Outcome {
    Outcome::Return(-(code as i64) as u64)
}

fn put_u64s(h: &Harness, at: u64, words: &[u64]) {
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    h.proc.state.space.write_raw(at, &b).unwrap();
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    let mut b = [0u8; 8];
    h.proc.state.space.read(at, &mut b).unwrap();
    u64::from_le_bytes(b)
}

/// `struct itimerval {interval, value}` in microseconds.
fn itimerval(h: &Harness, at: u64, interval_us: u64, value_us: u64) {
    put_u64s(
        h,
        at,
        &[
            interval_us / 1_000_000,
            interval_us % 1_000_000,
            value_us / 1_000_000,
            value_us % 1_000_000,
        ],
    );
}

fn read_itimerval_us(h: &Harness, at: u64) -> (u64, u64) {
    let w: Vec<u64> = (0..4).map(|i| u64_at(h, at + 8 * i)).collect();
    (w[0] * 1_000_000 + w[1], w[2] * 1_000_000 + w[3])
}

fn raise(h: &mut Harness, sig: i32) {
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    h.ok(Sysno::Tgkill, &[pid, tid, sig as u64]);
}

#[test]
fn itimer_real_reports_and_replaces_its_setting() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (new, old) = (h.scratch, h.scratch + 0x40);
        itimerval(&h, new, 1_000_000, 5_000_000);
        h.ok(Sysno::Setitimer, &[0, new, old]);
        assert_eq!(read_itimerval_us(&h, old), (0, 0), "nothing was armed");
        h.ok(Sysno::Getitimer, &[0, old]);
        let (interval, value) = read_itimerval_us(&h, old);
        assert_eq!(interval, 1_000_000);
        assert!((4_500_000..=5_000_000).contains(&value), "{value}");
        // A zero value disarms and clears the interval.
        itimerval(&h, new, 7, 0);
        h.ok(Sysno::Setitimer, &[0, new, 0]);
        h.ok(Sysno::Getitimer, &[0, old]);
        assert_eq!(read_itimerval_us(&h, old), (0, 0));
        // timeval_valid: microseconds must be below a second.
        put_u64s(&h, new, &[0, 0, 0, 1_000_000]);
        assert_eq!(h.err(Sysno::Setitimer, &[0, new, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Getitimer, &[3, old]), EINVAL);
        // CPU timers: the value gains TICK_NSEC and reads back in range.
        itimerval(&h, new, 0, 2_000_000);
        h.ok(Sysno::Setitimer, &[1, new, 0]);
        h.ok(Sysno::Getitimer, &[1, old]);
        let (_, value) = read_itimerval_us(&h, old);
        assert!((1_900_000..=2_004_000).contains(&value), "{value}");
    });
}

#[test]
fn alarm_rounds_the_previous_remainder() {
    // alarm_setitimer: a remainder rounds to the nearest second, and a
    // nonzero one is at least 1. Only x86-64 has the call.
    let mut h = Harness::new(LinuxAbi::X86_64);
    assert_eq!(h.ok(Sysno::Alarm, &[10]), 0);
    assert_eq!(h.ok(Sysno::Alarm, &[3]), 10, "9.99 s rounds to 10");
    assert_eq!(h.ok(Sysno::Alarm, &[0]), 3);
    assert_eq!(h.ok(Sysno::Alarm, &[0]), 0);
    assert!(LinuxAbi::Aarch64.number(Sysno::Alarm).is_none());
}

#[test]
fn itimer_expiry_interrupts_a_sleep_and_rearms_on_dequeue() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        // SIGALRM needs a handler (its default terminates).
        let act = h.scratch + 0x100;
        let restorer = if abi.has_sa_restorer() {
            sa::RESTORER
        } else {
            0
        };
        let mut sa_words = vec![0x40_1000, restorer];
        if abi.has_sa_restorer() {
            sa_words.push(0x40_1100);
        }
        sa_words.push(0);
        put_u64s(&h, act, &sa_words);
        h.ok(Sysno::RtSigaction, &[SIGALRM as u64, act, 0, 8]);
        let it = h.scratch;
        itimerval(&h, it, 30_000, 30_000);
        h.ok(Sysno::Setitimer, &[0, it, 0]);
        let (req, rem) = (h.scratch + 0x40, h.scratch + 0x60);
        put_u64s(&h, req, &[1, 0]);
        let start = Instant::now();
        let nr = abi.number(Sysno::Nanosleep).unwrap();
        let out = h.dispatch(Sysno::Nanosleep, &[req, rem]);
        let slept = start.elapsed();
        assert_eq!(out, ret(ERESTART_RESTARTBLOCK), "{abi:?}");
        assert!(slept >= Duration::from_millis(25) && slept < Duration::from_millis(900));
        let left = u64_at(&h, rem) * 1_000_000_000 + u64_at(&h, rem + 8);
        assert!((100_000_000..1_000_000_000).contains(&left), "rem {left}");
        assert!(matches!(
            h.proc.threads[0].restart,
            Some(RestartBlock::Nanosleep { rmtp, .. }) if rmtp == rem
        ));
        assert!(h.proc.state.shared_pending.contains(SIGALRM));
        // Until SIGALRM is dequeued the timer stays expired.
        h.ok(Sysno::Getitimer, &[0, it]);
        assert_eq!(read_itimerval_us(&h, it), (30_000, 0));
        h.proc.threads[0].syscall =
            Some(crate::user::linux::signal::deliver::SyscallEntry { nr, arg0: req });
        h.proc.deliver_signals(0);
        h.ok(Sysno::Getitimer, &[0, it]);
        let (interval, value) = read_itimerval_us(&h, it);
        assert_eq!(interval, 30_000);
        assert!(value > 0 && value <= 30_000, "re-armed: {value}");
    });
}

#[test]
fn restart_syscall_resumes_the_remaining_sleep() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (req, rem) = (h.scratch, h.scratch + 0x20);
        put_u64s(&h, req, &[0, 60_000_000]);
        // A pending unblocked signal interrupts before any sleep.
        raise(&mut h, SIGUSR1);
        assert_eq!(
            h.dispatch(Sysno::Nanosleep, &[req, rem]),
            ret(ERESTART_RESTARTBLOCK)
        );
        let left = u64_at(&h, rem + 8);
        assert!((50_000_000..=60_000_000).contains(&left), "rem {left}");
        h.proc.threads[0].pending.flush(u64::MAX);
        let start = Instant::now();
        assert_eq!(h.dispatch(Sysno::RestartSyscall, &[]), Outcome::Return(0));
        assert!(start.elapsed() >= Duration::from_millis(40));
        // Without a restart block (after completion or rt_sigreturn): EINTR.
        assert_eq!(h.err(Sysno::RestartSyscall, &[]), EINTR);
    });
}

#[test]
fn clock_nanosleep_clocks_and_absolute_sleeps() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let req = h.scratch;
        put_u64s(&h, req, &[0, 1000]);
        // CLOCK_THREAD_CPUTIME_ID has no nsleep; an unknown clock is EINVAL.
        assert_eq!(h.err(Sysno::ClockNanosleep, &[3, 0, req, 0]), EOPNOTSUPP);
        assert_eq!(h.err(Sysno::ClockNanosleep, &[10, 0, req, 0]), EINVAL);
        // An absolute deadline in the past returns at once.
        assert_eq!(
            h.dispatch(Sysno::ClockNanosleep, &[1, 1, req, 0]),
            Outcome::Return(0)
        );
        // An interrupted absolute sleep is -ERESTARTNOHAND without a restart
        // block.
        put_u64s(&h, req, &[u64::MAX >> 2, 0]);
        raise(&mut h, SIGUSR1);
        assert_eq!(
            h.dispatch(Sysno::ClockNanosleep, &[1, 1, req, 0]),
            ret(ERESTARTNOHAND)
        );
        assert_eq!(h.proc.threads[0].restart, None);
    });
}

#[test]
fn an_interrupted_poll_writes_zero_revents_and_restarts() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let fds = h.scratch;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let rd = u64_at(&h, fds) as u32 as u64;
        let wr = u64_at(&h, fds) >> 32;
        let pfd = h.scratch + 0x100;
        // {fd, events = POLLIN, revents = 0xffff}
        put_u64s(&h, pfd, &[rd | (1 << 32) | (0xffff << 48)]);
        raise(&mut h, SIGUSR1);
        if abi.number(Sysno::Poll).is_some() {
            assert_eq!(
                h.dispatch(Sysno::Poll, &[pfd, 1, 5000]),
                ret(ERESTART_RESTARTBLOCK)
            );
        } else {
            // arm64 and riscv have only ppoll: -ERESTARTNOHAND.
            let ts = h.scratch + 0x200;
            put_u64s(&h, ts, &[5, 0]);
            assert_eq!(
                h.dispatch(Sysno::Ppoll, &[pfd, 1, ts, 0, 8]),
                ret(ERESTARTNOHAND)
            );
            let left = u64_at(&h, ts);
            assert!(left <= 5, "time left written back");
        }
        assert_eq!(u64_at(&h, pfd) >> 48, 0, "revents written as zero");
        if abi.number(Sysno::Poll).is_some() {
            assert!(matches!(
                h.proc.threads[0].restart,
                Some(RestartBlock::Poll {
                    nfds: 1,
                    deadline: Some(_),
                    ..
                })
            ));
            h.proc.threads[0].pending.flush(u64::MAX);
            h.ok(Sysno::Write, &[wr, fds, 1]);
            assert_eq!(h.dispatch(Sysno::RestartSyscall, &[]), Outcome::Return(1));
            assert_eq!(u64_at(&h, pfd) >> 48, 1, "POLLIN");
        }
    });
}

#[test]
fn select_clamps_validates_and_updates_the_timeout() {
    each_abi(|abi| {
        let Some(_) = abi.number(Sysno::Select).or(abi.number(Sysno::Pselect6)) else {
            return;
        };
        let mut h = Harness::new(abi);
        let set = h.scratch;
        let tv = h.scratch + 0x200;
        let has_select = abi.number(Sysno::Select).is_some();
        let call = |h: &mut Harness, n: u64, set: u64, tv: u64| -> Outcome {
            if has_select {
                h.dispatch(Sysno::Select, &[n, set, 0, 0, tv])
            } else {
                h.dispatch(Sysno::Pselect6, &[n, set, 0, 0, tv, 0])
            }
        };
        // Bit 10 is not an open descriptor: EBADF.
        put_u64s(&h, set, &[1 << 10]);
        put_u64s(&h, tv, &[0, 0]);
        assert_eq!(call(&mut h, 11, set, tv), ret(EBADF));
        // nfds beyond max_fds (64) is clamped, so bit 1500 is ignored.
        let mut words = vec![0u64; 32];
        words[1500 / 64] = 1 << (1500 % 64);
        put_u64s(&h, set, &words);
        assert_eq!(call(&mut h, 2000, set, tv), Outcome::Return(0));
        assert_eq!(
            u64_at(&h, set + 1500 / 64 * 8),
            1 << (1500 % 64),
            "only 8 bytes written"
        );
        // stdout is writable; the timeout is written back with the time
        // left.
        put_u64s(&h, set, &[1 << 1]);
        if has_select {
            put_u64s(&h, tv, &[2, 1_500_000]); // usec carried into seconds
            assert_eq!(
                h.dispatch(Sysno::Select, &[2, 0, set, 0, tv]),
                Outcome::Return(1)
            );
            let (sec, usec) = (u64_at(&h, tv), u64_at(&h, tv + 8));
            assert!(sec == 3 || (sec == 2 && usec > 900_000), "{sec}.{usec}");
            put_u64s(&h, tv, &[0, u64::MAX]);
            assert_eq!(h.dispatch(Sysno::Select, &[2, 0, set, 0, tv]), ret(EINVAL));
        }
    });
}

#[test]
fn ppoll_and_pselect_masks_are_temporary() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (pfd, ts, mask) = (h.scratch, h.scratch + 0x100, h.scratch + 0x200);
        put_u64s(&h, pfd, &[1 | (4 << 32)]); // stdout, POLLOUT
        put_u64s(&h, ts, &[1, 0]);
        put_u64s(&h, mask, &[sigmask(SIGUSR2)]);
        assert_eq!(
            h.dispatch(Sysno::Ppoll, &[pfd, 1, ts, mask, 8]),
            Outcome::Return(1)
        );
        assert_eq!(h.proc.threads[0].sigmask, 0, "restored after success");
        assert_eq!(h.proc.threads[0].saved_sigmask, None);
        // A blocked pending signal unblocked by the temporary mask
        // interrupts; the saved mask waits for the return to user mode.
        h.proc.threads[0].sigmask = sigmask(SIGUSR1);
        raise(&mut h, SIGUSR1);
        put_u64s(&h, pfd, &[0xffff_ffff]); // fd -1: ignored
        put_u64s(&h, mask, &[0]);
        assert_eq!(
            h.dispatch(Sysno::Ppoll, &[pfd, 1, ts, mask, 8]),
            ret(ERESTARTNOHAND)
        );
        assert_eq!(h.proc.threads[0].saved_sigmask, Some(sigmask(SIGUSR1)));
        assert_eq!(h.err(Sysno::Ppoll, &[pfd, 1, ts, mask, 4]), EINVAL);
    });
}

#[test]
fn blocking_pipe_reads_are_interruptible() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let fds = h.scratch;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let rd = u64_at(&h, fds) as u32 as u64;
        raise(&mut h, SIGUSR1);
        assert_eq!(h.dispatch(Sysno::Read, &[rd, fds, 8]), ret(ERESTARTSYS));
        // Blocked, the signal does not interrupt; with O_NONBLOCK the empty
        // pipe is EAGAIN.
        h.proc.threads[0].sigmask = sigmask(SIGUSR1);
        h.ok(Sysno::Fcntl, &[rd, 4, 0o4000]); // F_SETFL O_NONBLOCK
        assert_eq!(h.err(Sysno::Read, &[rd, fds, 8]), EAGAIN);
        // A bad buffer takes nothing from the pipe.
        let wr = u64_at(&h, fds) >> 32;
        h.ok(Sysno::Write, &[wr, fds, 4]);
        assert_eq!(h.err(Sysno::Read, &[rd, 0x10, 4]), EFAULT);
        assert_eq!(h.ok(Sysno::Read, &[rd, fds + 0x80, 4]), 4);
    });
}

#[test]
fn sigtimedwait_is_woken_by_an_interval_timer() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        h.proc.threads[0].sigmask = sigmask(SIGALRM);
        let it = h.scratch;
        itimerval(&h, it, 0, 20_000);
        h.ok(Sysno::Setitimer, &[0, it, 0]);
        let (set, ts) = (h.scratch + 0x40, h.scratch + 0x60);
        put_u64s(&h, set, &[sigmask(SIGALRM)]);
        put_u64s(&h, ts, &[5, 0]);
        let start = Instant::now();
        assert_eq!(
            h.dispatch(Sysno::RtSigtimedwait, &[set, 0, ts, 8]),
            Outcome::Return(SIGALRM as u64)
        );
        assert!(start.elapsed() < Duration::from_secs(4));
    });
}

#[test]
fn a_wait_nothing_can_end_is_reported() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    assert!(matches!(h.dispatch(Sysno::Pause, &[]), Outcome::Fatal(_)));
    // An interval timer can end it.
    let act = h.scratch + 0x100;
    put_u64s(&h, act, &[0x40_1000, sa::RESTORER, 0x40_1100, 0]);
    h.ok(Sysno::RtSigaction, &[SIGALRM as u64, act, 0, 8]);
    h.ok(Sysno::Alarm, &[1]);
    let start = Instant::now();
    assert_eq!(h.dispatch(Sysno::Pause, &[]), ret(ERESTARTNOHAND));
    assert!(start.elapsed() >= Duration::from_millis(900));
}

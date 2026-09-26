//! A compatibility task's clocks, sleeps, and timers against Linux 6.19
//! (`kernel/time/{time,posix-timers,hrtimer,itimer}.c`, `fs/timerfd.c`,
//! `fs/utimes.c`, `kernel/sched/syscalls.c`): the `*_time32` calls read
//! and write `struct old_timespec32` and `old_time32_t`, and an interrupted
//! one's restart keeps writing them (`TT_COMPAT`); every 32-bit call's
//! `timeval` is `struct old_timeval32` and its `utimbuf`, `itimerval`,
//! `timex`, and `sigevent` their 32-bit forms; the `*_time64` calls read
//! `struct __kernel_timespec`, whose nanoseconds' upper half is padding
//! (`get_timespec64` clears it; a 64-bit caller's is not).

use std::time::{Duration, Instant};

use super::super::harness::Harness;
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::deliver::restart::ERESTART_RESTARTBLOCK;
use crate::user::linux::syscall::{Outcome, RestartBlock};

fn reg(v: i32) -> u64 {
    u64::from(v as u32)
}

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from(u32_at(h, at)) | u64::from(u32_at(h, at + 4)) << 32
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fresh(h: &mut Harness) -> u64 {
    let m = h.ok(Sysno::Mmap2, &[0, 0x2000, 3, 0x22, reg(-1), 0]);
    put(h, m, &[0xAA; 0x2000]);
    m
}

#[test]
fn time32_calls_write_old_timespec32_and_time64_calls_the_kernel_timespec() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // clock_gettime: 8 bytes, the next word untouched.
    assert_eq!(h.call(Sysno::ClockGettime, &[0, m]), 0);
    let sec = u64::from(u32_at(&h, m));
    assert!(sec.abs_diff(now_secs()) < 5, "{sec}");
    assert!(u32_at(&h, m + 4) < 1_000_000_000);
    assert_eq!(u32_at(&h, m + 8), 0xAAAA_AAAA);
    // clock_gettime64: 16 bytes.
    assert_eq!(h.call(Sysno::ClockGettime64, &[1, m + 0x100]), 0);
    assert_eq!(u32_at(&h, m + 0x104), 0, "a 64-bit tv_sec");
    assert!(u64_at(&h, m + 0x108) < 1_000_000_000);
    // clock_getres: 8 and 16 bytes.
    assert_eq!(h.call(Sysno::ClockGetres, &[0, m + 0x200]), 0);
    assert_eq!((u32_at(&h, m + 0x200), u32_at(&h, m + 0x204)), (0, 1));
    assert_eq!(u32_at(&h, m + 0x208), 0xAAAA_AAAA);
    assert_eq!(h.call(Sysno::ClockGetresTime64, &[5, m + 0x300]), 0);
    assert_eq!(u64_at(&h, m + 0x308), 4_000_000, "CLOCK_REALTIME_COARSE");
    // time: an old_time32_t stored and returned.
    let t = h.call(Sysno::Time, &[m + 0x400]);
    assert!((t as u64).abs_diff(now_secs()) < 5);
    assert_eq!(i64::from(u32_at(&h, m + 0x400)), t);
    assert_eq!(u32_at(&h, m + 0x404), 0xAAAA_AAAA);
    // gettimeofday: struct old_timeval32, then the time zone.
    assert_eq!(h.call(Sysno::Gettimeofday, &[m + 0x500, m + 0x510]), 0);
    assert!(u64::from(u32_at(&h, m + 0x500)).abs_diff(now_secs()) < 5);
    assert!(u32_at(&h, m + 0x504) < 1_000_000);
    assert_eq!(u32_at(&h, m + 0x508), 0xAAAA_AAAA);
    assert_eq!(u64_at(&h, m + 0x510), 0);
    // sched_rr_get_interval: 8 and 16 bytes.
    assert_eq!(h.call(Sysno::SchedRrGetInterval, &[0, m + 0x600]), 0);
    assert_eq!(u32_at(&h, m + 0x608), 0xAAAA_AAAA);
    assert_eq!(h.call(Sysno::SchedRrGetIntervalTime64, &[0, m + 0x700]), 0);
    assert_ne!(u64_at(&h, m + 0x708), 0xAAAA_AAAA_AAAA_AAAA);
}

#[test]
fn a_time64_timespec_ignores_the_padding_above_its_nanoseconds() {
    // 5 ns with the upper half of tv_nsec set: padding to a 32-bit caller.
    let padded = [
        &0u64.to_le_bytes()[..],
        &(0xFFFF_FFFF_0000_0005u64).to_le_bytes(),
    ]
    .concat();
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    put(&h, m, &padded);
    assert_eq!(h.call(Sysno::ClockNanosleepTime64, &[1, 0, m, 0]), 0);
    // The same bytes from a 64-bit caller: EINVAL.
    let mut n = Harness::new(LinuxAbi::X86_64);
    let at = n.scratch;
    n.proc.state.space.write_raw(at, &padded).unwrap();
    assert_eq!(
        n.call(Sysno::ClockNanosleep, &[1, 0, at, 0]),
        -i64::from(EINVAL)
    );
    // A 32-bit nanosleep's fields are signed 32-bit: -1 and 10^9 are EINVAL.
    put(&h, m, &words(&[0, u32::MAX]));
    assert_eq!(h.call(Sysno::Nanosleep, &[m, 0]), -i64::from(EINVAL));
    put(&h, m, &words(&[0, 1_000_000_000]));
    assert_eq!(
        h.call(Sysno::ClockNanosleep, &[1, 0, m, 0]),
        -i64::from(EINVAL)
    );
    put(&h, m, &words(&[0, 5]));
    assert_eq!(h.call(Sysno::Nanosleep, &[m, 0]), 0);
}

#[test]
fn an_interrupted_time32_sleep_reports_and_restarts_with_old_timespec32() {
    const SIGALRM: usize = 14;
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // A handled SIGALRM from a 30 ms interval timer ends the sleep.
    h.proc.state.sigactions[SIGALRM - 1].handler = 0x40_1000;
    let (it, req, rem) = (m, m + 0x100, m + 0x200);
    put(&h, it, &words(&[0, 0, 0, 30_000]));
    assert_eq!(h.call(Sysno::Setitimer, &[0, it, 0]), 0);
    put(&h, req, &words(&[1, 0]));
    let start = Instant::now();
    let out = h.dispatch(Sysno::Nanosleep, &[req, rem]);
    assert_eq!(
        out,
        Outcome::Return(-i64::from(ERESTART_RESTARTBLOCK) as u64)
    );
    assert!(start.elapsed() < Duration::from_millis(900));
    // struct old_timespec32: under a second left, the next word untouched.
    assert_eq!(u32_at(&h, rem), 0);
    assert!((1..1_000_000_000).contains(&u32_at(&h, rem + 4)));
    assert_eq!(u32_at(&h, rem + 8), 0xAAAA_AAAA);
    assert!(matches!(
        h.proc.threads[0].restart,
        Some(RestartBlock::Nanosleep { rmtp, time32: true, .. }) if rmtp == rem
    ));
}

#[test]
fn setting_the_time_reads_32_bit_structures() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // settimeofday: microseconds past 10^6 or negative are EINVAL first.
    put(&h, m, &words(&[1, 1_000_001]));
    assert_eq!(h.call(Sysno::Settimeofday, &[m, 0]), -i64::from(EINVAL));
    put(&h, m, &words(&[1, u32::MAX]));
    assert_eq!(h.call(Sysno::Settimeofday, &[m, 0]), -i64::from(EINVAL));
    // Root may set the time; the host's clock is not the guest's
    // (EOPNOTSUPP). An unprivileged caller is refused (EPERM).
    put(&h, m, &words(&[1, 5]));
    let root = h.proc.state.creds.1 == 0;
    let refused = -i64::from(if root { EOPNOTSUPP } else { EPERM });
    assert_eq!(h.call(Sysno::Settimeofday, &[m, 0]), refused);
    assert_eq!(h.call(Sysno::ClockSettime, &[0, m]), refused);
    // stime: an old_time32_t; the privilege before the value's check.
    put(&h, m, &words(&[1000]));
    assert_eq!(h.call(Sysno::Stime, &[m]), refused);
    assert_eq!(h.call(Sysno::Stime, &[8]), -i64::from(EFAULT));
    // clock_settime64 with the nanoseconds' padding set is valid.
    put(
        &h,
        m,
        &[
            &7u64.to_le_bytes()[..],
            &(0xFFFF_FFFF_0000_0000u64).to_le_bytes(),
        ]
        .concat(),
    );
    assert_eq!(h.call(Sysno::ClockSettime64, &[0, m]), refused);
}

#[test]
fn adjtimex_reads_and_writes_old_timex32() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // modes 0: read the NTP state; TIME_ERROR, the whole 128 bytes written.
    put(&h, m, &[0u8; 4]);
    assert_eq!(h.call(Sysno::Adjtimex, &[m]), 5, "TIME_ERROR");
    assert_eq!(u32_at(&h, m + 20), 0x40, "status: STA_UNSYNC");
    assert_eq!(u32_at(&h, m + 24), 2, "constant");
    assert_eq!(u32_at(&h, m + 28), 1, "precision");
    assert!(
        u64::from(u32_at(&h, m + 36)).abs_diff(now_secs()) < 5,
        "time.tv_sec"
    );
    assert!(u32_at(&h, m + 40) < 1_000_000, "time.tv_usec");
    assert_eq!(u32_at(&h, m + 44), 10_000, "tick");
    assert_eq!(u32_at(&h, m + 80), 0, "tai");
    assert_eq!(u32_at(&h, m + 124), 0, "the padding written as zeros");
    assert_eq!(u32_at(&h, m + 128), 0xAAAA_AAAA, "128 bytes");
    // clock_adjtime on CLOCK_REALTIME likewise; on another clock
    // EOPNOTSUPP without a write.
    put(&h, m + 0x200, &[0u8; 4]);
    assert_eq!(h.call(Sysno::ClockAdjtime, &[0, m + 0x200]), 5);
    assert_eq!(u32_at(&h, m + 0x200 + 44), 10_000);
    put(&h, m + 0x400, &[0u8; 4]);
    assert_eq!(
        h.call(Sysno::ClockAdjtime, &[1, m + 0x400]),
        -i64::from(EOPNOTSUPP)
    );
    assert_eq!(u32_at(&h, m + 0x400 + 44), 0xAAAA_AAAA);
    // ADJ_TICK out of range: CAP_SYS_TIME first (EPERM), then EINVAL; the
    // structure is written back either way (its padding zeroed).
    put(&h, m + 0x600, &words(&[0x4000]));
    put(&h, m + 0x600 + 44, &words(&[20_000]));
    let want = if h.proc.state.creds.1 == 0 {
        EINVAL
    } else {
        EPERM
    };
    assert_eq!(h.call(Sysno::Adjtimex, &[m + 0x600]), -i64::from(want));
    assert_eq!(u32_at(&h, m + 0x600 + 44), 20_000);
    assert_eq!(u32_at(&h, m + 0x600 + 84), 0, "written back");
    // clock_adjtime64: the 208-byte struct __kernel_timex.
    put(&h, m + 0x800, &[0u8; 4]);
    assert_eq!(h.call(Sysno::ClockAdjtime64, &[0, m + 0x800]), 5);
    assert_eq!(u64_at(&h, m + 0x800 + 88), 10_000, "tick");
}

#[test]
fn interval_timers_and_file_times_use_32_bit_timevals() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // struct old_itimerval32: interval then value, 16 bytes.
    put(&h, m, &words(&[0, 0, 100, 0]));
    assert_eq!(h.call(Sysno::Setitimer, &[0, m, m + 0x100]), 0);
    assert_eq!(&words(&[0, 0, 0, 0])[..], &{
        let mut b = [0u8; 16];
        h.proc.state.space.read_raw(m + 0x100, &mut b).unwrap();
        b
    });
    assert_eq!(u32_at(&h, m + 0x110), 0xAAAA_AAAA);
    assert_eq!(h.call(Sysno::Getitimer, &[0, m + 0x200]), 0);
    let value = u32_at(&h, m + 0x208);
    assert!((98..=100).contains(&value), "{value}");
    assert_eq!(u32_at(&h, m + 0x210), 0xAAAA_AAAA);
    put(&h, m, &words(&[0, 0, 1, 1_000_000]));
    assert_eq!(h.call(Sysno::Setitimer, &[0, m, 0]), -i64::from(EINVAL));
    // utimes and futimesat: struct old_timeval32[2]; utime: old_utimbuf32.
    let path = std::env::temp_dir().join(format!("rax-i386-times-{}", std::process::id()));
    std::fs::write(&path, b"x").unwrap();
    let p = m + 0x400;
    let mut s = path.to_str().unwrap().as_bytes().to_vec();
    s.push(0);
    put(&h, p, &s);
    let mtime = || {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&path).unwrap().mtime()
    };
    put(&h, m, &words(&[1_000_000, 0, 2_000_000, 5]));
    assert_eq!(h.call(Sysno::Utimes, &[p, m]), 0);
    assert_eq!(mtime(), 2_000_000);
    put(&h, m, &words(&[1, 0, 2, 1_000_000]));
    assert_eq!(
        h.call(Sysno::Futimesat, &[reg(-100), p, m]),
        -i64::from(EINVAL)
    );
    put(&h, m, &words(&[3_000_000, 4_000_000]));
    assert_eq!(h.call(Sysno::Utime, &[p, m]), 0);
    assert_eq!(mtime(), 4_000_000);
    // utimensat: struct old_timespec32[2]; utimensat_time64 with padding.
    put(&h, m, &words(&[0, (1 << 30) - 2, 5_000_000, 0]));
    assert_eq!(h.call(Sysno::Utimensat, &[reg(-100), p, m, 0]), 0);
    assert_eq!(mtime(), 5_000_000);
    let t64 = [
        &0u64.to_le_bytes()[..],
        &(0xFFFF_FFFF_3FFF_FFFEu64).to_le_bytes(),
        &6_000_000u64.to_le_bytes(),
        &(0xFFFF_FFFF_0000_0000u64).to_le_bytes(),
    ]
    .concat();
    put(&h, m, &t64);
    assert_eq!(h.call(Sysno::UtimensatTime64, &[reg(-100), p, m, 0]), 0);
    assert_eq!(mtime(), 6_000_000);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn posix_timers_and_timerfds_take_32_bit_structures() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = fresh(&mut h);
    // struct compat_sigevent: sival_int, signo, notify, then the thread.
    let (ev, id) = (m, m + 0x100);
    put(&h, ev, &words(&[0x1234, 10, 0, 0]));
    assert_eq!(h.call(Sysno::TimerCreate, &[1, ev, id]), 0);
    let timer = u64::from(u32_at(&h, id));
    let t = h.proc.state.timers.get(timer as i32).expect("the timer");
    assert_eq!((t.signo, t.value), (10, 0x1234));
    // A thread ID that is not ours: EINVAL (SIGEV_THREAD_ID).
    put(&h, ev, &words(&[0, 10, 4, 99_999]));
    assert_eq!(h.call(Sysno::TimerCreate, &[1, ev, id]), -i64::from(EINVAL));
    // timer_settime: struct old_itimerspec32 in and out.
    let (new, old) = (m + 0x200, m + 0x300);
    put(&h, new, &words(&[0, 0, 100, 0]));
    assert_eq!(h.call(Sysno::TimerSettime, &[timer, 0, new, old]), 0);
    assert_eq!(u32_at(&h, old + 8), 0);
    assert_eq!(u32_at(&h, old + 16), 0xAAAA_AAAA, "16 bytes");
    assert_eq!(h.call(Sysno::TimerGettime, &[timer, m + 0x400]), 0);
    assert!((98..=100).contains(&u32_at(&h, m + 0x408)));
    assert_eq!(u32_at(&h, m + 0x410), 0xAAAA_AAAA);
    // timer_gettime64: struct __kernel_itimerspec.
    assert_eq!(h.call(Sysno::TimerGettime64, &[timer, m + 0x500]), 0);
    assert!((98..=100).contains(&u64_at(&h, m + 0x510)));
    // timerfd_settime and timerfd_gettime likewise.
    let fd = h.ok(Sysno::TimerfdCreate, &[1, 0]);
    put(&h, new, &words(&[0, 0, 50, 0]));
    assert_eq!(h.call(Sysno::TimerfdSettime, &[fd, 0, new, 0]), 0);
    assert_eq!(h.call(Sysno::TimerfdGettime, &[fd, m + 0x600]), 0);
    assert!((48..=50).contains(&u32_at(&h, m + 0x608)));
    assert_eq!(u32_at(&h, m + 0x610), 0xAAAA_AAAA);
    let padded = [
        &0u64.to_le_bytes()[..],
        &0xFFFF_FFFF_0000_0000u64.to_le_bytes(),
        &60u64.to_le_bytes(),
        &0xFFFF_FFFF_0000_0000u64.to_le_bytes(),
    ]
    .concat();
    put(&h, new, &padded);
    assert_eq!(h.call(Sysno::TimerfdSettime64, &[fd, 0, new, 0]), 0);
    assert_eq!(h.call(Sysno::TimerfdGettime64, &[fd, m + 0x700]), 0);
    assert!((58..=60).contains(&u64_at(&h, m + 0x710)));
}

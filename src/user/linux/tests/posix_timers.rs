//! POSIX timers: the state machine against the arithmetic of
//! `kernel/time/posix-timers.c` (`common_timer_get`, `common_timer_set`,
//! `__posixtimer_deliver_signal`) and `hrtimer_forward` (a timer expiring
//! at E with period I, looked at N >= E, moves forward k = (N - E) / I + 1
//! periods), driven by explicit times; and the system calls' argument
//! checks and signal behavior (`do_timer_create`, `good_sigevent`,
//! `posixtimer_send_sigqueue`, `posixtimer_sig_unignore`,
//! `flush_itimer_signals`).

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::posix_timers::*;
use crate::user::linux::signal::pending::SigPending;
use crate::user::linux::signal::*;

const MS: i64 = 1_000_000;

/// A signal-sending monotonic timer with ID 0.
fn timers() -> PosixTimers {
    let mut t = PosixTimers::default();
    let id = t.alloc_id().unwrap();
    assert_eq!(id, 0);
    t.insert(id, 1, Base::Monotonic, Notify::Process, SIGUSR1, 7);
    t
}

fn set(t: &mut PosixTimers, value: i64, interval: i64, now: i64) -> Setting {
    let s = Setting { value, interval };
    t.settime(0, 0, s, Base::Monotonic, now, now).unwrap().0
}

#[test]
fn ids_count_up_and_are_not_reused_at_once() {
    let mut t = PosixTimers::default();
    assert_eq!(t.alloc_id(), Some(0));
    assert_eq!(
        t.alloc_id(),
        Some(1),
        "an ID a failed creation took is gone"
    );
    t.insert(1, 1, Base::Monotonic, Notify::None, 0, 0);
    let id = t.alloc_id().unwrap();
    t.insert(id, 1, Base::Monotonic, Notify::None, 0, 0);
    assert_eq!(id, 2);
    assert!(t.delete(1));
    assert!(!t.delete(1));
    assert_eq!(
        t.alloc_id(),
        Some(3),
        "deleting does not rewind the counter"
    );
}

#[test]
fn a_periodic_timer_counts_missed_periods_as_overruns() {
    let mut t = timers();
    set(&mut t, 10 * MS, 10 * MS, 0);
    assert!(t.expire(|_| 9 * MS).is_empty());
    let f = t.expire(|_| 10 * MS);
    assert_eq!(f.len(), 1);
    assert!(f[0].periodic);
    assert_eq!((f[0].id, f[0].signo, f[0].value), (0, SIGUSR1, 7));
    // Waiting for delivery, it does not fire again.
    assert!(t.expire(|_| 50 * MS).is_empty());
    // gettime at 55: E = 10, k = 45 / 10 + 1 = 5, E = 60; 5 ms left.
    assert_eq!(
        t.gettime(0, 55 * MS),
        Some(Setting {
            value: 5 * MS,
            interval: 10 * MS
        })
    );
    // Delivery at 125: k = 65 / 10 + 1 = 7, E = 130; overrun
    // -1 + 5 + 7 = 11.
    let uid = f[0].uid;
    assert_eq!(t.deliver(uid, |_| 125 * MS), Some(11));
    assert_eq!(t.getoverrun(0), Some(11));
    assert!(t.expire(|_| 129 * MS).is_empty());
    assert_eq!(t.expire(|_| 130 * MS).len(), 1);
}

#[test]
fn a_one_shot_timer_fires_once() {
    let mut t = timers();
    set(&mut t, 10 * MS, 0, 0);
    // Past its expiry but not yet found: 1 ns left, as a fired timer
    // whose signal is not yet queued shows.
    assert_eq!(t.gettime(0, 15 * MS).unwrap().value, 1);
    let f = t.expire(|_| 15 * MS);
    assert!(!f[0].periodic);
    // Disarmed at once, its signal still pending.
    assert_eq!(t.gettime(0, 16 * MS), Some(Setting::default()));
    assert_eq!(t.deliver(f[0].uid, |_| 20 * MS), Some(0));
    assert!(t.expire(|_| 1000 * MS).is_empty());
}

#[test]
fn a_changed_or_deleted_timer_disowns_its_queued_signal() {
    let mut t = timers();
    set(&mut t, 10 * MS, 10 * MS, 0);
    let f = t.expire(|_| 10 * MS)[0];
    let old = set(&mut t, 0, 0, 12 * MS);
    // The old setting: the forward to 20 ms left 8 ms.
    assert_eq!(
        old,
        Setting {
            value: 8 * MS,
            interval: 10 * MS
        }
    );
    assert_eq!(t.deliver(f.uid, |_| 13 * MS), None, "stale");
    assert_eq!(t.getoverrun(0), Some(0), "a new setting resets the count");
    set(&mut t, 10 * MS, 0, 20 * MS);
    let f = t.expire(|_| 30 * MS)[0];
    assert!(t.delete(0));
    assert_eq!(t.deliver(f.uid, |_| 31 * MS), None, "deleted");
}

#[test]
fn a_sigev_none_timer_counts_down_without_firing() {
    let mut t = PosixTimers::default();
    let id = t.alloc_id().unwrap();
    t.insert(id, 1, Base::Monotonic, Notify::None, 0, 0);
    let s = Setting {
        value: 20 * MS,
        interval: 0,
    };
    t.settime(id, 0, s, Base::Monotonic, 0, 0);
    assert!(!t.armed());
    assert!(t.expire(|_| 30 * MS).is_empty());
    assert_eq!(t.gettime(id, 5 * MS).unwrap().value, 15 * MS);
    assert_eq!(
        t.gettime(id, 30 * MS).unwrap().value,
        0,
        "expired: 0, not 1 ns"
    );
    // Disarming with a zero value leaves the old expiry, which
    // common_timer_get still reports for a SIGEV_NONE timer.
    t.settime(id, 0, s, Base::Monotonic, 40 * MS, 40 * MS);
    t.settime(id, 0, Setting::default(), Base::Monotonic, 45 * MS, 45 * MS);
    assert_eq!(t.gettime(id, 50 * MS).unwrap().value, 10 * MS);
    // Periodic: moved forward on every look (E = 10, N = 35, k = 3).
    let p = Setting {
        value: 10 * MS,
        interval: 10 * MS,
    };
    t.settime(id, 0, p, Base::Monotonic, 0, 0);
    assert_eq!(t.gettime(id, 35 * MS).unwrap().value, 5 * MS);
}

#[test]
fn absolute_settings_and_cpu_timers_in_the_past() {
    let mut t = timers();
    let abs = Setting {
        value: 100 * MS,
        interval: 0,
    };
    let (_, firing) = t
        .settime(0, TIMER_ABSTIME, abs, Base::Monotonic, 50 * MS, 50 * MS)
        .unwrap();
    assert!(
        firing.is_none(),
        "a high-resolution timer fires when looked at"
    );
    assert_eq!(t.gettime(0, 60 * MS).unwrap().value, 40 * MS);
    // A CPU-time timer set in the past fires within timer_settime and,
    // one-shot, forgets its expiry.
    let id = t.alloc_id().unwrap();
    t.insert(id, 2, Base::ProcessCpu, Notify::Process, SIGUSR2, 0);
    let past = Setting {
        value: 5 * MS,
        interval: 0,
    };
    let (_, firing) = t
        .settime(id, TIMER_ABSTIME, past, Base::ProcessCpu, 9 * MS, 9 * MS)
        .unwrap();
    assert_eq!(firing.map(|f| f.signo), Some(SIGUSR2));
    assert_eq!(t.gettime(id, 10 * MS), Some(Setting::default()));
    assert!(!t.cpu_armed());
}

#[test]
fn an_ignored_periodic_signal_is_parked_until_unignored() {
    let mut t = timers();
    set(&mut t, 10 * MS, 10 * MS, 0);
    let f = t.expire(|_| 10 * MS)[0];
    t.park_ignored(f.uid);
    assert!(t.is_parked(f.uid));
    assert!(t.sig_unignore(SIGUSR2).is_empty());
    let again = t.sig_unignore(SIGUSR1);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].uid, f.uid);
    assert!(!t.is_parked(f.uid));
    // A one-shot expiry's ignored signal is dropped.
    set(&mut t, 10 * MS, 0, 20 * MS);
    let f = t.expire(|_| 30 * MS)[0];
    t.park_ignored(f.uid);
    assert!(!t.is_parked(f.uid));
    t.sig_ignore(f.uid);
    assert!(!t.is_parked(f.uid));
}

#[test]
fn exec_flushes_timer_records_but_keeps_other_instances() {
    let mut p = SigPending::new();
    let timer = SigInfo::timer(SIGUSR1, 3, 0);
    p.enqueue_timer(timer, 9);
    // A timer's record is queued even beside a pending standard signal
    // (and makes a later instance of it a legacy_queue duplicate).
    assert!(p.enqueue(SigInfo::kill(SIGALRM, code::SI_USER, 1, 0)));
    p.enqueue_timer(SigInfo::timer(SIGALRM, 4, 0), 10);
    assert!(!p.enqueue(SigInfo::kill(SIGALRM, code::SI_USER, 1, 0)));
    assert_eq!(p.queued(), 3);
    assert!(p.has_timer(9));
    p.flush_timer_signals();
    assert!(!p.contains(SIGUSR1));
    assert!(p.contains(SIGALRM), "the kill record remains");
    assert_eq!(p.queued(), 1);
    // A flush reports the timers whose records it discarded.
    p.enqueue_timer(timer, 9);
    assert_eq!(p.flush(sigmask(SIGUSR1)), vec![9]);
}

const CLOCK_MONOTONIC: u64 = 1;

/// A `struct sigevent` at `at`.
fn put_sigevent(h: &Harness, at: u64, value: u64, signo: i32, notify: i32, tid: i32) {
    let mut b = [0u8; 64];
    b[..8].copy_from_slice(&value.to_le_bytes());
    b[8..12].copy_from_slice(&signo.to_le_bytes());
    b[12..16].copy_from_slice(&notify.to_le_bytes());
    b[16..20].copy_from_slice(&tid.to_le_bytes());
    h.proc.state.space.write_raw(at, &b).unwrap();
}

fn u32_at(h: &Harness, at: u64) -> u32 {
    let mut b = [0u8; 4];
    h.proc.state.space.read(at, &mut b).unwrap();
    u32::from_le_bytes(b)
}

#[test]
fn timer_create_checks_in_the_kernel_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (ev, idp) = (h.scratch, h.scratch + 0x100);
        // The sigevent is read before the clock is looked up.
        assert_eq!(h.err(Sysno::TimerCreate, &[10, 8, idp]), EFAULT);
        assert_eq!(h.err(Sysno::TimerCreate, &[10, 0, idp]), EINVAL);
        assert_eq!(h.err(Sysno::TimerCreate, &[12, 0, idp]), EINVAL);
        for clock in [4, 5, 6] {
            assert_eq!(h.err(Sysno::TimerCreate, &[clock, 0, idp]), EOPNOTSUPP);
        }
        // A descriptor clock (CLOCKFD) has no timers.
        assert_eq!(
            h.err(Sysno::TimerCreate, &[(!0i64 << 3 | 3) as u64, 0, idp]),
            EOPNOTSUPP
        );
        // After the ID is allocated: a bad sigevent, a bad ID pointer,
        // another process's CPU clock.
        put_sigevent(&h, ev, 0, 0, 0, 0);
        assert_eq!(
            h.err(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]),
            EINVAL
        );
        put_sigevent(&h, ev, 0, 65, 0, 0);
        assert_eq!(
            h.err(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]),
            EINVAL
        );
        put_sigevent(&h, ev, 0, SIGUSR1, 3, 0);
        assert_eq!(
            h.err(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]),
            EINVAL
        );
        put_sigevent(&h, ev, 0, SIGUSR1, 4, 0x7fff_fff0);
        assert_eq!(
            h.err(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]),
            EINVAL
        );
        assert_eq!(h.err(Sysno::TimerCreate, &[CLOCK_MONOTONIC, 0, 8]), EFAULT);
        // MAKE_PROCESS_CPUCLOCK(pid, CPUCLOCK_SCHED): (~pid << 3) | 2.
        let other_pid = (!(h.proc.state.pid as i64 + 1) << 3 | 2) as u64;
        assert_eq!(h.err(Sysno::TimerCreate, &[other_pid, 0, idp]), EINVAL);
        // Six IDs are used up; the next timer gets 6.
        assert_eq!(h.ok(Sysno::TimerCreate, &[CLOCK_MONOTONIC, 0, idp]), 0);
        assert_eq!(u32_at(&h, idp), 6);
        // Alarm clocks need CAP_WAKE_ALARM (only root).
        let alarm = h.call(Sysno::TimerCreate, &[9, 0, idp]);
        if h.proc.state.creds.1 == 0 {
            assert_eq!(alarm, 0);
        } else {
            assert_eq!(alarm, -(EPERM as i64));
        }
        // A thread of this process may be named; the own CPU clock too.
        let tid = h.proc.threads[0].tid;
        put_sigevent(&h, ev, 0, SIGUSR1, 4, tid);
        assert_eq!(h.ok(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]), 0);
        let own_cpu = (!(h.proc.state.pid as i64) << 3 | 2) as u64;
        assert_eq!(h.ok(Sysno::TimerCreate, &[own_cpu, 0, idp]), 0);
    });
}

#[test]
fn the_other_timer_calls_check_their_arguments() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let (idp, spec) = (h.scratch, h.scratch + 0x100);
    h.ok(Sysno::TimerCreate, &[CLOCK_MONOTONIC, 0, idp]);
    let id = u32_at(&h, idp) as u64;
    assert_eq!(h.err(Sysno::TimerSettime, &[id, 0, 0, 0]), EINVAL);
    assert_eq!(h.err(Sysno::TimerSettime, &[id, 0, 8, 0]), EFAULT);
    let spec_with = |h: &Harness, nsec: i64| {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&nsec.to_le_bytes());
        h.proc.state.space.write_raw(spec, &b).unwrap();
    };
    spec_with(&h, 1_000_000_000);
    assert_eq!(h.err(Sysno::TimerSettime, &[id, 0, spec, 0]), EINVAL);
    spec_with(&h, 5_000_000);
    // IDs outside 0..=INT_MAX name nothing; timer_t is 32 bits wide.
    assert_eq!(
        h.err(Sysno::TimerSettime, &[u32::MAX as u64, 0, spec, 0]),
        EINVAL
    );
    assert_eq!(h.ok(Sysno::TimerSettime, &[id | 1 << 32, 0, spec, 0]), 0);
    // Unknown flag bits are ignored.
    assert_eq!(h.ok(Sysno::TimerSettime, &[id, 6, spec, spec + 64]), 0);
    for s in [
        Sysno::TimerGettime,
        Sysno::TimerGetoverrun,
        Sysno::TimerDelete,
    ] {
        assert_eq!(h.err(s, &[99, spec]), EINVAL, "{s:?}");
    }
    assert_eq!(h.err(Sysno::TimerGettime, &[id, 8]), EFAULT);
    assert_eq!(h.ok(Sysno::TimerDelete, &[id]), 0);
    assert_eq!(h.err(Sysno::TimerDelete, &[id]), EINVAL);
}

/// Arms timer `id` to expire at monotonic time 1 ns (long past), with
/// `interval_ns`.
fn arm_past(h: &mut Harness, id: u64, interval_ns: i64) {
    let spec = h.scratch + 0x200;
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(interval_ns / 1_000_000_000).to_le_bytes());
    b[8..16].copy_from_slice(&(interval_ns % 1_000_000_000).to_le_bytes());
    b[24..].copy_from_slice(&1i64.to_le_bytes());
    h.proc.state.space.write_raw(spec, &b).unwrap();
    assert_eq!(h.ok(Sysno::TimerSettime, &[id, 1, spec, 0]), 0);
}

#[test]
fn an_expired_timer_queues_its_signal_once() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    h.proc.threads[0].sigmask = sigmask(SIGUSR1);
    let (ev, idp) = (h.scratch, h.scratch + 0x100);
    put_sigevent(&h, ev, 0xabcd, SIGUSR1, 0, 0);
    h.ok(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]);
    let id = u32_at(&h, idp);
    arm_past(&mut h, id.into(), 3_600_000_000_000);
    h.proc.collect_async(None);
    h.proc.collect_async(None);
    let q = &h.proc.state.shared_pending;
    assert_eq!(q.queued(), 1, "one preallocated record");
    // Dequeued: SI_TIMER with the timer's ID and value; re-armed.
    let info = crate::user::linux::signal::deliver::dequeue_signal(
        &mut h.proc.state,
        &mut h.proc.threads[0],
        0,
    )
    .unwrap();
    assert_eq!((info.signo, info.code), (SIGUSR1, code::SI_TIMER));
    assert_eq!(info.pid(), id as i32, "si_tid");
    assert_eq!(info.value(), 0xabcd);
    // si_overrun: the hours since boot, as timer_getoverrun reports.
    assert_eq!(
        Some(info.uid() as i32),
        h.proc.state.timers.getoverrun(id as i32)
    );
    assert!(h.proc.state.timers.armed());
    // A new setting makes a queued signal stale: it is dropped.
    arm_past(&mut h, id.into(), 0);
    h.proc.collect_async(None);
    arm_past(&mut h, id.into(), 0);
    assert!(h.proc.state.shared_pending.contains(SIGUSR1));
    let got = crate::user::linux::signal::deliver::dequeue_signal(
        &mut h.proc.state,
        &mut h.proc.threads[0],
        0,
    );
    assert!(got.is_none(), "{got:?}");
}

#[test]
fn an_ignored_timer_signal_comes_back_with_a_handler() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let (ev, idp, act) = (h.scratch, h.scratch + 0x100, h.scratch + 0x300);
    h.proc.state.sigactions[(SIGUSR2 - 1) as usize].handler = SIG_IGN;
    put_sigevent(&h, ev, 0, SIGUSR2, 0, 0);
    h.ok(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]);
    let id = u32_at(&h, idp);
    arm_past(&mut h, id.into(), 3_600_000_000_000);
    h.proc.collect_async(None);
    assert!(!h.proc.state.shared_pending.contains(SIGUSR2), "ignored");
    // A handler replaces SIG_IGN: the parked signal is queued.
    let words: [u64; 4] = [0x1000, 0, 0, 0];
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    h.proc.state.space.write_raw(act, &b).unwrap();
    h.ok(Sysno::RtSigaction, &[SIGUSR2 as u64, act, 0, 8]);
    assert!(h.proc.state.shared_pending.contains(SIGUSR2));
    // SIG_IGN again discards it and parks it once more.
    let ign: [u64; 4] = [SIG_IGN, 0, 0, 0];
    let b: Vec<u8> = ign.iter().flat_map(|w| w.to_le_bytes()).collect();
    h.proc.state.space.write_raw(act, &b).unwrap();
    h.ok(Sysno::RtSigaction, &[SIGUSR2 as u64, act, 0, 8]);
    assert!(!h.proc.state.shared_pending.contains(SIGUSR2));
    let uid = h.proc.state.timers.get(id as i32).unwrap().uid;
    assert!(h.proc.state.timers.is_parked(uid));
}

#[test]
fn a_thread_timer_signals_its_thread() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let (ev, idp) = (h.scratch, h.scratch + 0x100);
    let tid = h.proc.threads[0].tid;
    h.proc.threads[0].sigmask = sigmask(SIGUSR1);
    put_sigevent(&h, ev, 0, SIGUSR1, 4, tid);
    h.ok(Sysno::TimerCreate, &[CLOCK_MONOTONIC, ev, idp]);
    let id = u32_at(&h, idp);
    arm_past(&mut h, id.into(), 0);
    h.proc.collect_async(None);
    assert!(h.proc.threads[0].pending.contains(SIGUSR1));
    assert!(!h.proc.state.shared_pending.contains(SIGUSR1));
}

//! Scheduling attributes against `kernel/sched/syscalls.c`, `kernel/sys.c`,
//! and `block/ioprio.c` (Linux 6.19), through the system calls on every
//! ABI: policies and their checks in order, the permission rules without
//! `CAP_SYS_NICE`, `sched_setattr` and `sched_getattr`, nice values and
//! `RLIMIT_NICE`, time slices, deadline admission, inheritance and
//! `reset_on_fork`, timer slack, I/O priorities, and `/proc`.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::syscall::thread::cf::*;

const NOBODY: u32 = 65534;
/// Never mapped (below `mmap_min_addr`).
const BAD: u64 = 0x10;
const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
const NORMAL: u64 = 0;
const FIFO: u64 = 1;
const RR: u64 = 2;
const BATCH: u64 = 3;
const IDLE: u64 = 5;
const DEADLINE: u64 = 6;
const RESET_ON_FORK: u64 = 0x4000_0000;
const RLIMIT_NICE: usize = 13;
const RLIMIT_RTPRIO: usize = 14;

fn creds(h: &mut Harness, id: u32) {
    h.proc.state.creds = (id, id, id, id);
    h.proc.state.groups = Vec::new();
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u32_at(h: &Harness, at: u64) -> u32 {
    u32::from_le_bytes(get(h, at, 4).try_into().unwrap())
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from_le_bytes(get(h, at, 8).try_into().unwrap())
}

/// `struct sched_attr` fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Attr {
    size: u32,
    policy: u32,
    flags: u64,
    nice: i32,
    prio: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
}

fn write_attr(h: &Harness, at: u64, a: Attr) -> u64 {
    let mut b = Vec::new();
    b.extend_from_slice(&a.size.to_le_bytes());
    b.extend_from_slice(&a.policy.to_le_bytes());
    b.extend_from_slice(&a.flags.to_le_bytes());
    b.extend_from_slice(&a.nice.to_le_bytes());
    b.extend_from_slice(&a.prio.to_le_bytes());
    b.extend_from_slice(&a.runtime.to_le_bytes());
    b.extend_from_slice(&a.deadline.to_le_bytes());
    b.extend_from_slice(&a.period.to_le_bytes());
    b.extend_from_slice(&[0; 8]);
    put(h, at, &b);
    at
}

fn getattr(h: &mut Harness, pid: u64, at: u64) -> Attr {
    put(h, at, &[0xff; 64]);
    assert_eq!(h.call(Sysno::SchedGetattr, &[pid, at, 56, 0]), 0);
    Attr {
        size: u32_at(h, at),
        policy: u32_at(h, at + 4),
        flags: u64_at(h, at + 8),
        nice: u32_at(h, at + 16) as i32,
        prio: u32_at(h, at + 20),
        runtime: u64_at(h, at + 24),
        deadline: u64_at(h, at + 32),
        period: u64_at(h, at + 40),
    }
}

fn setattr(h: &mut Harness, at: u64, a: Attr) -> i64 {
    write_attr(h, at, a);
    h.call(Sysno::SchedSetattr, &[0, at, 0])
}

/// `sched_setscheduler(0, policy, {prio})`.
fn setscheduler(h: &mut Harness, at: u64, policy: u64, prio: u32) -> i64 {
    put(h, at, &prio.to_le_bytes());
    h.call(Sysno::SchedSetscheduler, &[0, policy, at])
}

#[test]
fn a_task_starts_normal_and_reports_so() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        assert_eq!(h.call(Sysno::SchedGetscheduler, &[0]), 0);
        put(&h, m, &[0xff; 4]);
        assert_eq!(h.call(Sysno::SchedGetparam, &[0, m]), 0);
        assert_eq!(u32_at(&h, m), 0);
        let a = getattr(&mut h, 0, m);
        assert_eq!(
            a,
            Attr {
                size: 56,
                runtime: 700_000,
                ..Default::default()
            }
        );
        assert_eq!(h.call(Sysno::Getpriority, &[0, 0]), 20);
        // Its arguments: the pid, the pointer, an unknown task.
        assert_eq!(h.err(Sysno::SchedGetscheduler, &[u64::MAX]), EINVAL);
        assert_eq!(h.err(Sysno::SchedGetparam, &[0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::SchedGetparam, &[99999, m]), ESRCH);
        assert_eq!(h.err(Sysno::SchedGetparam, &[0, BAD]), EFAULT);
        assert_eq!(h.err(Sysno::SchedGetscheduler, &[99999]), ESRCH);
        // The priority ranges, SCHED_EXT's included.
        for (policy, max, min) in [
            (0, 0, 0),
            (1, 99, 1),
            (2, 99, 1),
            (3, 0, 0),
            (5, 0, 0),
            (6, 0, 0),
            (7, 0, 0),
        ] {
            assert_eq!(h.call(Sysno::SchedGetPriorityMax, &[policy]), max);
            assert_eq!(h.call(Sysno::SchedGetPriorityMin, &[policy]), min);
        }
        for policy in [4, 8, u64::MAX] {
            assert_eq!(h.err(Sysno::SchedGetPriorityMax, &[policy]), EINVAL);
            assert_eq!(h.err(Sysno::SchedGetPriorityMin, &[policy]), EINVAL);
        }
    });
}

#[test]
fn sched_setscheduler_checks_in_the_kernels_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(P, 3, false);
        assert_eq!(h.err(Sysno::SchedSetscheduler, &[0, u64::MAX, BAD]), EINVAL);
        assert_eq!(h.err(Sysno::SchedSetscheduler, &[0, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::SchedSetscheduler, &[u64::MAX, 0, m]), EINVAL);
        assert_eq!(h.err(Sysno::SchedSetscheduler, &[0, 0, BAD]), EFAULT);
        put(&h, m, &0u32.to_le_bytes());
        assert_eq!(h.err(Sysno::SchedSetscheduler, &[99999, 4, m]), ESRCH);
        assert_eq!(setscheduler(&mut h, m, 4, 0), -(EINVAL as i64));
        assert_eq!(
            setscheduler(&mut h, m, 7, 0),
            -(EINVAL as i64),
            "no SCHED_EXT"
        );
        // A real-time policy needs a priority, the others none.
        assert_eq!(setscheduler(&mut h, m, FIFO, 0), -(EINVAL as i64));
        assert_eq!(setscheduler(&mut h, m, NORMAL, 1), -(EINVAL as i64));
        assert_eq!(setscheduler(&mut h, m, RR, 100), -(EINVAL as i64));
        // Without RLIMIT_RTPRIO a real-time policy needs CAP_SYS_NICE.
        assert_eq!(setscheduler(&mut h, m, FIFO, 1), -(EPERM as i64));
        h.proc.state.rlimits[RLIMIT_RTPRIO].0 = 10;
        assert_eq!(setscheduler(&mut h, m, FIFO, 10), 0);
        assert_eq!(h.call(Sysno::SchedGetscheduler, &[0]), FIFO as i64);
        h.ok(Sysno::SchedGetparam, &[0, m + 8]);
        assert_eq!(u32_at(&h, m + 8), 10);
        assert_eq!(setscheduler(&mut h, m, FIFO, 11), -(EPERM as i64));
        assert_eq!(setscheduler(&mut h, m, RR, 3), 0);
        // sched_setparam keeps the policy.
        put(&h, m, &5u32.to_le_bytes());
        assert_eq!(h.call(Sysno::SchedSetparam, &[0, m]), 0);
        assert_eq!(h.call(Sysno::SchedGetscheduler, &[0]), RR as i64);
        put(&h, m, &0u32.to_le_bytes());
        assert_eq!(h.err(Sysno::SchedSetparam, &[0, m]), EINVAL);
        // SCHED_RESET_ON_FORK rides on the policy; only privilege clears it.
        assert_eq!(setscheduler(&mut h, m, NORMAL | RESET_ON_FORK, 0), 0);
        assert_eq!(h.call(Sysno::SchedGetscheduler, &[0]), RESET_ON_FORK as i64);
        assert_eq!(setscheduler(&mut h, m, NORMAL, 0), -(EPERM as i64));
        assert_eq!(setscheduler(&mut h, m, BATCH | RESET_ON_FORK, 0), 0);
        assert_eq!(
            h.call(Sysno::SchedGetscheduler, &[0]),
            (BATCH | RESET_ON_FORK) as i64
        );
        creds(&mut h, 0);
        assert_eq!(setscheduler(&mut h, m, NORMAL, 0), 0);
        assert_eq!(h.call(Sysno::SchedGetscheduler, &[0]), 0);
        // Root: any real-time priority.
        assert_eq!(setscheduler(&mut h, m, FIFO, 99), 0);
        let a = getattr(&mut h, 0, m);
        assert_eq!((a.policy, a.prio, a.nice, a.runtime), (1, 99, 0, 0));
    });
}

#[test]
fn sched_setattr_copies_by_size_and_applies_the_rules() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(2 * P, 3, false);
        h.ok(Sysno::Munmap, &[m + P, P]);
        let at = m + 0x100;
        // The arguments, then the size: 0 is the first version's; too
        // small or too big is E2BIG with the kernel's size written back.
        assert_eq!(h.err(Sysno::SchedSetattr, &[0, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::SchedSetattr, &[u64::MAX, at, 0]), EINVAL);
        assert_eq!(h.err(Sysno::SchedSetattr, &[0, at, 1]), EINVAL);
        assert_eq!(h.err(Sysno::SchedSetattr, &[0, BAD, 0]), EFAULT);
        for size in [47, 4097] {
            write_attr(
                &h,
                at,
                Attr {
                    size,
                    ..Default::default()
                },
            );
            assert_eq!(h.err(Sysno::SchedSetattr, &[0, at, 0]), E2BIG);
            assert_eq!(u32_at(&h, at), 56);
        }
        assert_eq!(setattr(&mut h, at, Attr::default()), 0, "size 0");
        // Bytes past the known structure must be zero.
        let edge = m + P - 64;
        write_attr(
            &h,
            edge,
            Attr {
                size: 64,
                ..Default::default()
            },
        );
        put(&h, edge + 56, &[0; 8]);
        assert_eq!(h.call(Sysno::SchedSetattr, &[0, edge, 0]), 0);
        put(&h, edge + 60, &[1]);
        assert_eq!(h.err(Sysno::SchedSetattr, &[0, edge, 0]), E2BIG);
        assert_eq!(u32_at(&h, edge), 56);
        write_attr(
            &h,
            edge,
            Attr {
                size: 65,
                ..Default::default()
            },
        );
        put(&h, edge + 56, &[0; 8]);
        assert_eq!(h.err(Sysno::SchedSetattr, &[0, edge, 0]), EFAULT);
        // Utilization clamping is not built in; asking with the first
        // version's size is EINVAL.
        let clamp = Attr {
            size: 56,
            flags: 0x20,
            ..Default::default()
        };
        assert_eq!(setattr(&mut h, at, clamp), -(EOPNOTSUPP as i64));
        assert_eq!(
            setattr(&mut h, at, Attr { size: 48, ..clamp }),
            -(EINVAL as i64)
        );
        assert_eq!(
            setattr(
                &mut h,
                at,
                Attr {
                    size: 56,
                    flags: 0x80,
                    ..Default::default()
                }
            ),
            -(EINVAL as i64)
        );
        assert_eq!(
            setattr(
                &mut h,
                at,
                Attr {
                    size: 56,
                    policy: u32::MAX,
                    ..Default::default()
                }
            ),
            -(EINVAL as i64)
        );
        // Nice values: raised freely, clamped, lowered only within
        // RLIMIT_NICE (EPERM here, as sched_setattr is not setpriority).
        let batch = |nice| Attr {
            size: 56,
            policy: BATCH as u32,
            nice,
            ..Default::default()
        };
        assert_eq!(setattr(&mut h, at, batch(100)), 0);
        let a = getattr(&mut h, 0, at);
        assert_eq!((a.policy, a.nice), (3, 19));
        assert_eq!(setattr(&mut h, at, batch(10)), -(EPERM as i64));
        h.proc.state.rlimits[RLIMIT_NICE].0 = 10;
        assert_eq!(setattr(&mut h, at, batch(10)), 0);
        assert_eq!(setattr(&mut h, at, batch(9)), -(EPERM as i64));
        // The slice: clamped to 0.1 ms..100 ms, 0 for the default.
        for (asked, got) in [
            (5_000_000, 5_000_000),
            (1, 100_000),
            (u64::MAX, 100_000_000),
            (0, 700_000),
        ] {
            let a = Attr {
                runtime: asked,
                ..batch(10)
            };
            assert_eq!(setattr(&mut h, at, a), 0);
            assert_eq!(getattr(&mut h, 0, at).runtime, got);
        }
        // SCHED_IDLE keeps the nice value; leaving it needs RLIMIT_NICE
        // for that value.
        assert_eq!(
            setattr(
                &mut h,
                at,
                Attr {
                    size: 56,
                    policy: IDLE as u32,
                    ..Default::default()
                }
            ),
            0
        );
        assert_eq!(h.call(Sysno::Getpriority, &[0, 0]), 10);
        assert_eq!(setattr(&mut h, at, batch(19)), 0);
        assert_eq!(
            setattr(
                &mut h,
                at,
                Attr {
                    size: 56,
                    policy: IDLE as u32,
                    ..Default::default()
                }
            ),
            0
        );
        h.proc.state.rlimits[RLIMIT_NICE].0 = 0;
        assert_eq!(setattr(&mut h, at, batch(19)), -(EPERM as i64));
        // Keeping the policy, or the parameters.
        h.proc.state.rlimits[RLIMIT_NICE].0 = 40;
        let keep = Attr {
            size: 56,
            flags: 0x08,
            policy: FIFO as u32,
            nice: 5,
            ..Default::default()
        };
        assert_eq!(setattr(&mut h, at, keep), 0);
        let a = getattr(&mut h, 0, at);
        assert_eq!(
            (a.policy, a.nice),
            (5, 19),
            "SCHED_IDLE keeps its nice value"
        );
        assert_eq!(setattr(&mut h, at, batch(3)), 0);
        // SCHED_FLAG_KEEP_PARAMS keeps the policy too
        // (__setscheduler_params is skipped).
        let params = Attr {
            size: 56,
            flags: 0x10,
            policy: NORMAL as u32,
            nice: -5,
            ..Default::default()
        };
        assert_eq!(setattr(&mut h, at, params), 0);
        let a = getattr(&mut h, 0, at);
        assert_eq!((a.policy, a.nice), (3, 3));
        // Deadline tasks need privilege.
        let dl = Attr {
            size: 56,
            policy: DEADLINE as u32,
            runtime: 10_000_000,
            deadline: 30_000_000,
            period: 100_000_000,
            ..Default::default()
        };
        assert_eq!(setattr(&mut h, at, dl), -(EPERM as i64));
        assert_eq!(
            setattr(
                &mut h,
                at,
                Attr {
                    runtime: 1023,
                    ..dl
                }
            ),
            -(EINVAL as i64)
        );
    });
}

#[test]
fn deadline_tasks_are_admitted_within_the_bandwidth() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, 0);
        let at = h.anon(P, 3, false);
        let dl = Attr {
            size: 56,
            policy: DEADLINE as u32,
            runtime: 10_000_000,
            deadline: 30_000_000,
            period: 100_000_000,
            ..Default::default()
        };
        assert_eq!(setattr(&mut h, at, dl), 0);
        let a = getattr(&mut h, 0, at);
        assert_eq!(
            (a.policy, a.runtime, a.deadline, a.period, a.nice, a.prio),
            (6, 10_000_000, 30_000_000, 100_000_000, 0, 0)
        );
        assert_eq!(h.call(Sysno::SchedGetscheduler, &[0]), 6);
        // A deadline task cannot fork or clone.
        assert_eq!(h.err(Sysno::Clone, &[THREAD, 0, 0, 0, 0]), EAGAIN);
        // The period defaults to the deadline.
        assert_eq!(setattr(&mut h, at, Attr { period: 0, ..dl }), 0);
        assert_eq!(getattr(&mut h, 0, at).period, 30_000_000);
        // 95% of the one CPU, less the fair server's 5%.
        let heavy = Attr {
            runtime: 91_000_000,
            deadline: 100_000_000,
            period: 100_000_000,
            ..dl
        };
        assert_eq!(setattr(&mut h, at, heavy), -(EBUSY as i64));
        let most = Attr {
            runtime: 90_000_000,
            ..heavy
        };
        assert_eq!(setattr(&mut h, at, most), 0);
        // With SCHED_RESET_ON_FORK a clone starts normal.
        assert_eq!(setattr(&mut h, at, Attr { flags: 1, ..most }), 0);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        let a = getattr(&mut h, tid, at);
        assert_eq!((a.policy, a.flags), (0, 0));
        assert_eq!(
            h.call(Sysno::SchedGetscheduler, &[0]),
            (6 | RESET_ON_FORK) as i64
        );
        // Leaving the deadline class.
        assert_eq!(
            setattr(
                &mut h,
                at,
                Attr {
                    size: 56,
                    ..Default::default()
                }
            ),
            0
        );
        assert_eq!(h.call(Sysno::SchedGetscheduler, &[0]), 0);
    });
}

#[test]
fn time_slices_come_in_jiffies_of_4_ms() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, 0);
        let m = h.anon(P, 3, false);
        let ts = m + 0x100;
        let slice = |h: &mut Harness| {
            assert_eq!(h.call(Sysno::SchedRrGetInterval, &[0, ts]), 0);
            (u64_at(h, ts), u64_at(h, ts + 8))
        };
        // 700 us is less than one jiffy.
        assert_eq!(slice(&mut h), (0, 0));
        assert_eq!(
            setattr(
                &mut h,
                m,
                Attr {
                    size: 56,
                    runtime: 9_000_000,
                    ..Default::default()
                }
            ),
            0
        );
        assert_eq!(slice(&mut h), (0, 8_000_000));
        assert_eq!(setscheduler(&mut h, m, RR, 1), 0);
        assert_eq!(slice(&mut h), (0, 100_000_000));
        assert_eq!(setscheduler(&mut h, m, FIFO, 1), 0);
        assert_eq!(slice(&mut h), (0, 0));
        assert_eq!(h.err(Sysno::SchedRrGetInterval, &[u64::MAX, ts]), EINVAL);
        assert_eq!(h.err(Sysno::SchedRrGetInterval, &[99999, ts]), ESRCH);
        assert_eq!(h.err(Sysno::SchedRrGetInterval, &[0, BAD]), EFAULT);
    });
}

#[test]
fn nice_values_and_rlimit_nice() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        assert_eq!(h.err(Sysno::Getpriority, &[3, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Setpriority, &[u64::MAX, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Getpriority, &[0, 99999]), ESRCH);
        assert_eq!(h.err(Sysno::Setpriority, &[0, 99999, 5]), ESRCH);
        // A thread by its ID; raising is free, lowering needs RLIMIT_NICE.
        assert_eq!(h.call(Sysno::Setpriority, &[0, tid, 5]), 0);
        assert_eq!(h.call(Sysno::Getpriority, &[0, tid]), 15);
        assert_eq!(h.call(Sysno::Getpriority, &[0, 0]), 20);
        assert_eq!(h.err(Sysno::Setpriority, &[0, tid, 4]), EACCES);
        assert_eq!(h.call(Sysno::Setpriority, &[0, tid, 100]), 0);
        assert_eq!(h.call(Sysno::Getpriority, &[0, tid]), 1);
        assert_eq!(h.err(Sysno::Setpriority, &[0, 0, (-1i64) as u64]), EACCES);
        h.proc.state.rlimits[RLIMIT_NICE].0 = 25;
        assert_eq!(h.call(Sysno::Setpriority, &[0, 0, (-5i64) as u64]), 0);
        assert_eq!(h.err(Sysno::Setpriority, &[0, 0, (-6i64) as u64]), EACCES);
        assert_eq!(h.call(Sysno::Getpriority, &[0, 0]), 25);
        // The group and the user: the best (highest) value, set on all.
        assert_eq!(h.call(Sysno::Getpriority, &[1, 0]), 25);
        assert_eq!(h.call(Sysno::Getpriority, &[2, 0]), 25);
        assert_eq!(h.call(Sysno::Getpriority, &[2, u64::from(NOBODY)]), 25);
        assert_eq!(h.err(Sysno::Getpriority, &[2, 12345]), ESRCH);
        assert_eq!(h.err(Sysno::Setpriority, &[2, 12345, 5]), ESRCH);
        assert_eq!(h.call(Sysno::Setpriority, &[2, 0, 7]), 0);
        assert_eq!(h.call(Sysno::Getpriority, &[0, tid]), 13);
        // A partial failure still changes the others, and reports.
        assert_eq!(h.call(Sysno::Setpriority, &[0, tid, 19]), 0);
        h.proc.state.rlimits[RLIMIT_NICE].0 = 0;
        assert_eq!(h.err(Sysno::Setpriority, &[1, 0, 10]), EACCES);
        assert_eq!(h.call(Sysno::Getpriority, &[0, 0]), 10);
        assert_eq!(h.call(Sysno::Getpriority, &[0, tid]), 1);
    });
}

#[test]
fn threads_inherit_attributes_and_timer_slack() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let m = h.anon(P, 3, false);
        const PR_SET_TIMERSLACK: u64 = 29;
        const PR_GET_TIMERSLACK: u64 = 30;
        assert_eq!(
            h.call(Sysno::Prctl, &[PR_GET_TIMERSLACK, 0, 0, 0, 0]),
            50_000
        );
        h.ok(Sysno::Prctl, &[PR_SET_TIMERSLACK, 7777, 0, 0, 0]);
        h.ok(Sysno::Setpriority, &[0, 0, 4]);
        assert_eq!(
            setattr(
                &mut h,
                m,
                Attr {
                    size: 56,
                    policy: BATCH as u32,
                    nice: 4,
                    runtime: 2_000_000,
                    ..Default::default()
                }
            ),
            0
        );
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        let a = getattr(&mut h, tid, m);
        assert_eq!((a.policy, a.nice, a.runtime), (3, 4, 2_000_000));
        // The new thread's default slack is the creator's slack.
        let w = h.index_of(tid as i32);
        let s = &h.proc.threads[w].sched;
        assert_eq!((s.timer_slack, s.default_timer_slack), (7777, 7777));
        // A real-time task has no slack, and cannot set one.
        creds(&mut h, 0);
        assert_eq!(setscheduler(&mut h, m, RR, 1), 0);
        assert_eq!(h.call(Sysno::Prctl, &[PR_GET_TIMERSLACK, 0, 0, 0, 0]), 0);
        h.ok(Sysno::Prctl, &[PR_SET_TIMERSLACK, 1, 0, 0, 0]);
        assert_eq!(h.call(Sysno::Prctl, &[PR_GET_TIMERSLACK, 0, 0, 0, 0]), 0);
        // Back to normal: the default comes back; 0 asks for it too.
        assert_eq!(setscheduler(&mut h, m, NORMAL, 0), 0);
        assert_eq!(
            h.call(Sysno::Prctl, &[PR_GET_TIMERSLACK, 0, 0, 0, 0]),
            50_000
        );
        h.ok(Sysno::Prctl, &[PR_SET_TIMERSLACK, 5, 0, 0, 0]);
        h.ok(Sysno::Prctl, &[PR_SET_TIMERSLACK, 0, 0, 0, 0]);
        assert_eq!(
            h.call(Sysno::Prctl, &[PR_GET_TIMERSLACK, 0, 0, 0, 0]),
            50_000
        );
        // /proc/self/task/<tid>/stat: priority, nice, rt_priority, policy.
        assert_eq!(setscheduler(&mut h, m, FIFO, 7), 0);
        let fields = |h: &mut Harness, tid: u64| -> Vec<String> {
            let path = format!("/proc/self/task/{tid}/stat\0");
            put(h, m, path.as_bytes());
            let fd = h.ok(Sysno::Openat, &[(-100i64) as u64, m, 0, 0]);
            let n = h.ok(Sysno::Read, &[fd, m + 0x200, 1024]) as usize;
            h.ok(Sysno::Close, &[fd]);
            let text = String::from_utf8(get(h, m + 0x200, n)).unwrap();
            let rest = &text[text.rfind(')').unwrap() + 2..];
            let f: Vec<&str> = rest.split(' ').collect();
            // Fields 18, 19, 40, 41 (from field 3).
            [f[15], f[16], f[37], f[38]]
                .iter()
                .map(|s| s.to_string())
                .collect()
        };
        let me = h.proc.threads[0].tid as u64;
        assert_eq!(fields(&mut h, me), ["-8", "4", "7", "1"]);
        assert_eq!(fields(&mut h, tid), ["24", "4", "0", "3"]);
    });
}

const IOPRIO_BE: u64 = 2 << 13;

#[test]
fn io_priorities_are_set_per_task_and_derived_from_nice() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        // Unset: 0 as set, the nice value's class and level for a group.
        assert_eq!(h.call(Sysno::IoprioGet, &[1, 0]), 0);
        assert_eq!(h.call(Sysno::IoprioGet, &[2, 0]) as u64, IOPRIO_BE | 4);
        assert_eq!(h.call(Sysno::IoprioGet, &[3, 0]) as u64, IOPRIO_BE | 4);
        assert_eq!(h.err(Sysno::IoprioGet, &[4, 0]), EINVAL);
        assert_eq!(h.err(Sysno::IoprioGet, &[1, 99999]), ESRCH);
        // The value is checked before the target.
        assert_eq!(h.err(Sysno::IoprioSet, &[4, 99999, 1 << 13]), EPERM);
        assert_eq!(h.err(Sysno::IoprioSet, &[4, 99999, 3]), EINVAL);
        assert_eq!(h.err(Sysno::IoprioSet, &[4, 99999, 4 << 13]), EINVAL);
        assert_eq!(h.err(Sysno::IoprioSet, &[4, 0, IOPRIO_BE]), EINVAL);
        assert_eq!(h.err(Sysno::IoprioSet, &[1, 99999, IOPRIO_BE]), ESRCH);
        assert_eq!(h.call(Sysno::IoprioSet, &[1, tid, IOPRIO_BE | 6]), 0);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, tid]) as u64, IOPRIO_BE | 6);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, 0]), 0);
        // The best of a group is the lowest value.
        assert_eq!(h.call(Sysno::IoprioGet, &[2, 0]) as u64, IOPRIO_BE | 4);
        h.ok(Sysno::Setpriority, &[0, 0, 19]);
        assert_eq!(h.call(Sysno::IoprioGet, &[2, 0]) as u64, IOPRIO_BE | 6);
        // IOPRIO_WHO_USER with 0 means root's tasks when setting, which
        // exist and are not the caller's to change.
        assert_eq!(h.err(Sysno::IoprioSet, &[3, 0, IOPRIO_BE]), EPERM);
        assert_eq!(h.err(Sysno::IoprioSet, &[3, u64::MAX, IOPRIO_BE]), ESRCH);
        assert_eq!(
            h.call(Sysno::IoprioSet, &[3, u64::from(NOBODY), IOPRIO_BE | 1]),
            0
        );
        assert_eq!(h.call(Sysno::IoprioGet, &[1, tid]) as u64, IOPRIO_BE | 1);
        // A new thread inherits a valid class.
        let t2 = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, t2]) as u64, IOPRIO_BE | 1);
        creds(&mut h, 0);
        assert_eq!(h.call(Sysno::IoprioSet, &[1, 0, 1 << 13]), 0);
        assert_eq!(
            h.call(Sysno::IoprioSet, &[3, 0, IOPRIO_BE]),
            0,
            "root's tasks"
        );
    });
}

#[test]
fn clone_io_tasks_share_one_io_context() {
    // copy_io: CLONE_IO shares the creator's io_context, so a priority set
    // through either task is both tasks'; without it a valid priority is
    // copied into a new context. A creator without a context gives none.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let early = h.ok(Sysno::Clone, &[THREAD | CLONE_IO, 0, 0, 0, 0]);
        h.ok(Sysno::IoprioSet, &[1, early, IOPRIO_BE | 2]);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, 0]), 0, "nothing to share");

        h.ok(Sysno::IoprioSet, &[1, 0, IOPRIO_BE | 3]);
        let shared = h.ok(Sysno::Clone, &[THREAD | CLONE_IO, 0, 0, 0, 0]);
        let copied = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, shared]) as u64, IOPRIO_BE | 3);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, copied]) as u64, IOPRIO_BE | 3);
        h.ok(Sysno::IoprioSet, &[1, shared, IOPRIO_BE | 5]);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, 0]) as u64, IOPRIO_BE | 5);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, copied]) as u64, IOPRIO_BE | 3);
        h.ok(Sysno::IoprioSet, &[1, copied, IOPRIO_BE | 7]);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, shared]) as u64, IOPRIO_BE | 5);
        // A thread of the sharer, made with CLONE_IO, joins the same one.
        h.ok(Sysno::IoprioSet, &[1, 0, IOPRIO_BE | 1]);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, shared]) as u64, IOPRIO_BE | 1);
        assert_eq!(h.call(Sysno::IoprioGet, &[1, early]) as u64, IOPRIO_BE | 2);
    });
}

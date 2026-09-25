//! A task's scheduling attributes (`kernel/sched/`, `block/ioprio.c`,
//! Linux 6.19): its policy and priorities, nice value, fair slice,
//! deadline parameters, `reset_on_fork`, timer slack, and I/O priority.
//!
//! The system calls set and report them and `/proc/<pid>/stat` shows
//! them; nothing here schedules, the threads of a process sharing one
//! emulated CPU. The kernel is modelled with one CPU (so the fair base
//! slice is `sysctl_sched_base_slice` unscaled, 700 µs), `CONFIG_HZ=250`,
//! without `CONFIG_UCLAMP_TASK` or `CONFIG_SCHED_CLASS_EXT`.

use super::abi::errno::Errno;
use super::abi::errno_table::*;

/// `SCHED_*` policies (`linux/sched.h`).
pub mod policy {
    pub const NORMAL: i32 = 0;
    pub const FIFO: i32 = 1;
    pub const RR: i32 = 2;
    pub const BATCH: i32 = 3;
    pub const IDLE: i32 = 5;
    pub const DEADLINE: i32 = 6;
    /// `SCHED_EXT`: known to the priority range calls only.
    pub const EXT: i32 = 7;
    /// `SCHED_RESET_ON_FORK`, or'd into a policy.
    pub const RESET_ON_FORK: i32 = 0x4000_0000;
    /// `SETPARAM_POLICY`: keep the policy.
    pub const SETPARAM: i32 = -1;
}

/// `SCHED_FLAG_*` (`linux/sched.h`) and the kernel's `SCHED_FLAG_SUGOV`.
pub mod flag {
    pub const RESET_ON_FORK: u64 = 0x01;
    pub const RECLAIM: u64 = 0x02;
    pub const DL_OVERRUN: u64 = 0x04;
    pub const KEEP_POLICY: u64 = 0x08;
    pub const KEEP_PARAMS: u64 = 0x10;
    pub const UTIL_CLAMP: u64 = 0x20 | 0x40;
    pub const ALL: u64 = 0x7f;
    pub const SUGOV: u64 = 0x1000_0000;
    /// `SCHED_DL_FLAGS`.
    pub const DL: u64 = RECLAIM | DL_OVERRUN | SUGOV;
}

/// `MAX_RT_PRIO`, `DEFAULT_PRIO`, `MAX_DL_PRIO`.
pub const MAX_RT_PRIO: i32 = 100;
pub const DEFAULT_PRIO: i32 = 120;
pub const MAX_DL_PRIO: i32 = 0;
/// `MIN_NICE`, `MAX_NICE`.
pub const MIN_NICE: i32 = -20;
pub const MAX_NICE: i32 = 19;
/// `sysctl_sched_base_slice` on one CPU.
pub const BASE_SLICE: u64 = 700_000;
/// The first task's timer slack (`init_task.timer_slack_ns`: 50 µs).
pub const TIMER_SLACK: u64 = 50_000;
/// `NSEC_PER_SEC / HZ` at `CONFIG_HZ=250`.
pub const JIFFY_NS: u64 = 4_000_000;
/// `sched_rr_timeslice`: `RR_TIMESLICE`, 100 ms in jiffies.
pub const RR_TIMESLICE: u64 = 25;
/// `sysctl_sched_dl_period_min` and `_max`, in microseconds.
const DL_PERIOD_MIN_US: u64 = 100;
const DL_PERIOD_MAX_US: u64 = 1 << 22;
/// `DL_SCALE`.
const DL_SCALE: u32 = 10;
/// `BW_SHIFT`, and the deadline bandwidth of one CPU (`global_rt_runtime`
/// over `global_rt_period`: 950000 µs in 1000000 µs).
const BW_SHIFT: u32 = 20;
const DL_CAPACITY: u64 = (950_000u64 << BW_SHIFT) / 1_000_000;
/// The bandwidth the CPU's fair server holds (`dl_server_apply_params`
/// from `sched_init_dl_servers`: 50 ms each second).
const FAIR_SERVER_BW: u64 = (50_000_000u64 << BW_SHIFT) / 1_000_000_000;

pub fn fair(p: i32) -> bool {
    p == policy::NORMAL || p == policy::BATCH
}

pub fn rt(p: i32) -> bool {
    p == policy::FIFO || p == policy::RR
}

pub fn dl(p: i32) -> bool {
    p == policy::DEADLINE
}

/// `valid_policy`, without `SCHED_EXT`.
pub fn valid(p: i32) -> bool {
    fair(p) || p == policy::IDLE || rt(p) || dl(p)
}

/// `nice_to_rlimit`: 19..-20 as 1..40.
pub fn nice_to_rlimit(nice: i32) -> u64 {
    (MAX_NICE - nice + 1) as u64
}

/// `__normal_prio`.
pub fn normal_prio_of(policy: i32, rt_prio: u32, nice: i32) -> i32 {
    if dl(policy) {
        MAX_DL_PRIO - 1
    } else if rt(policy) {
        MAX_RT_PRIO - 1 - rt_prio as i32
    } else {
        nice + DEFAULT_PRIO
    }
}

/// A deadline task's parameters (`struct sched_dl_entity`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deadline {
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    pub flags: u64,
}

impl Deadline {
    /// `to_ratio(period, runtime)`: the bandwidth it asks for, rounded
    /// down.
    pub fn bw(&self) -> u64 {
        if self.period == 0 {
            return 0;
        }
        (((self.runtime as u128) << BW_SHIFT) / self.period as u128) as u64
    }
}

/// `struct sched_attr` (`linux/sched/types.h`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attr {
    pub policy: i32,
    pub flags: u64,
    pub nice: i32,
    pub priority: u32,
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    pub util_min: u32,
    pub util_max: u32,
}

/// `SCHED_ATTR_SIZE_VER0`, `SCHED_ATTR_SIZE_VER1`.
pub const ATTR_VER0: usize = 48;
pub const ATTR_SIZE: usize = 56;

impl Attr {
    /// From a structure's first [`ATTR_SIZE`] bytes.
    pub fn decode(b: &[u8]) -> Self {
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Attr {
            policy: u32_at(4) as i32,
            flags: u64_at(8),
            nice: u32_at(16) as i32,
            priority: u32_at(20),
            runtime: u64_at(24),
            deadline: u64_at(32),
            period: u64_at(40),
            util_min: u32_at(48),
            util_max: u32_at(52),
        }
    }

    /// The structure, its `size` field `size`.
    pub fn encode(&self, size: u32) -> [u8; ATTR_SIZE] {
        let mut b = [0u8; ATTR_SIZE];
        b[0..4].copy_from_slice(&size.to_le_bytes());
        b[4..8].copy_from_slice(&(self.policy as u32).to_le_bytes());
        b[8..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..20].copy_from_slice(&(self.nice as u32).to_le_bytes());
        b[20..24].copy_from_slice(&self.priority.to_le_bytes());
        b[24..32].copy_from_slice(&self.runtime.to_le_bytes());
        b[32..40].copy_from_slice(&self.deadline.to_le_bytes());
        b[40..48].copy_from_slice(&self.period.to_le_bytes());
        b[48..52].copy_from_slice(&self.util_min.to_le_bytes());
        b[52..56].copy_from_slice(&self.util_max.to_le_bytes());
        b
    }
}

/// `__checkparam_dl`.
pub fn checkparam_dl(a: &Attr) -> bool {
    if a.flags & flag::SUGOV != 0 {
        return true;
    }
    if a.deadline == 0 || a.runtime < (1 << DL_SCALE) {
        return false;
    }
    if a.deadline & (1 << 63) != 0 || a.period & (1 << 63) != 0 {
        return false;
    }
    let period = if a.period == 0 { a.deadline } else { a.period };
    if period < a.deadline || a.deadline < a.runtime {
        return false;
    }
    (DL_PERIOD_MIN_US * 1000..=DL_PERIOD_MAX_US * 1000).contains(&period)
}

/// `sched_dl_overflow` on one CPU: whether a task holding deadline
/// bandwidth `old` cannot hold `new` beside the fair server and the
/// `others` (`__dl_overflow`); an unchanged bandwidth is not checked.
pub fn dl_overflow(others: u64, old: u64, new: u64) -> bool {
    new != old && FAIR_SERVER_BW + others + new > DL_CAPACITY
}

/// A task's scheduling attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sched {
    pub policy: i32,
    /// `static_prio`: the nice value, offset by [`DEFAULT_PRIO`].
    pub static_prio: i32,
    pub normal_prio: i32,
    /// `prio`: what the scheduler would use.
    pub prio: i32,
    pub rt_priority: u32,
    pub reset_on_fork: bool,
    /// The fair slice, and whether it was asked for.
    pub slice: u64,
    pub custom_slice: bool,
    pub dl: Deadline,
    /// `timer_slack_ns` and `default_timer_slack_ns`.
    pub timer_slack: u64,
    pub default_timer_slack: u64,
    /// `io_context->ioprio` (`None`: no I/O context).
    pub ioprio: Option<u16>,
}

impl Default for Sched {
    fn default() -> Self {
        Sched {
            policy: policy::NORMAL,
            static_prio: DEFAULT_PRIO,
            normal_prio: DEFAULT_PRIO,
            prio: DEFAULT_PRIO,
            rt_priority: 0,
            reset_on_fork: false,
            slice: BASE_SLICE,
            custom_slice: false,
            dl: Deadline::default(),
            timer_slack: TIMER_SLACK,
            default_timer_slack: TIMER_SLACK,
            ioprio: None,
        }
    }
}

impl Sched {
    /// `task_nice`.
    pub fn nice(&self) -> i32 {
        self.static_prio - DEFAULT_PRIO
    }

    /// `task_prio`: the priority `/proc/<pid>/stat` shows.
    pub fn task_prio(&self) -> i32 {
        self.prio - MAX_RT_PRIO
    }

    /// `normal_prio`.
    fn normal(&self) -> i32 {
        normal_prio_of(self.policy, self.rt_priority, self.nice())
    }

    /// The deadline bandwidth it holds.
    pub fn dl_bw(&self) -> u64 {
        if dl(self.policy) { self.dl.bw() } else { 0 }
    }

    /// `get_params`: its parameters as `sched_getattr` and
    /// `SCHED_FLAG_KEEP_PARAMS` see them.
    pub fn params(&self, a: &mut Attr) {
        if dl(self.policy) {
            a.runtime = self.dl.runtime;
            a.deadline = self.dl.deadline;
            a.period = self.dl.period;
            a.flags |= self.dl.flags;
        } else if rt(self.policy) {
            a.priority = self.rt_priority;
        } else {
            a.nice = self.nice();
            a.runtime = self.slice;
        }
    }

    /// `sched_getattr`'s structure.
    pub fn attr(&self) -> Attr {
        let mut a = Attr {
            policy: self.policy,
            ..Default::default()
        };
        if self.reset_on_fork {
            a.flags |= flag::RESET_ON_FORK;
        }
        self.params(&mut a);
        a.flags &= flag::ALL;
        a
    }

    /// Whether `a` changes anything but `reset_on_fork` for a task keeping
    /// its policy (`__sched_setscheduler`'s short cut).
    pub fn changes(&self, a: &Attr, policy: i32) -> bool {
        if policy != self.policy {
            return true;
        }
        if fair(policy) && (a.nice != self.nice() || a.runtime != self.slice) {
            return true;
        }
        if rt(policy) && a.priority != self.rt_priority {
            return true;
        }
        if dl(policy) {
            // dl_param_changed compares the period as given.
            let changed = self.dl.runtime != a.runtime
                || self.dl.deadline != a.deadline
                || self.dl.period != a.period
                || self.dl.flags != a.flags & flag::DL;
            if changed {
                return true;
            }
        }
        a.flags & flag::UTIL_CLAMP != 0
    }

    /// `__setscheduler_params`, then the new priority unless the
    /// parameters are kept.
    pub fn apply(&mut self, a: &Attr, policy: i32) {
        if a.flags & flag::KEEP_PARAMS != 0 {
            return;
        }
        let new_prio = normal_prio_of(policy, a.priority, a.nice);
        self.policy = policy;
        if dl(policy) {
            self.dl = Deadline {
                runtime: a.runtime,
                deadline: a.deadline,
                period: if a.period == 0 { a.deadline } else { a.period },
                flags: a.flags & flag::DL,
            };
        } else if fair(policy) {
            // __setparam_fair.
            self.static_prio = a.nice + DEFAULT_PRIO;
            if a.runtime != 0 {
                self.custom_slice = true;
                self.slice = a.runtime.clamp(100_000, 100_000_000);
            } else {
                self.custom_slice = false;
                self.slice = BASE_SLICE;
            }
        }
        if rt(policy) || dl(policy) {
            self.timer_slack = 0;
        } else if self.timer_slack == 0 {
            self.timer_slack = self.default_timer_slack;
        }
        self.rt_priority = a.priority;
        self.normal_prio = self.normal();
        self.prio = new_prio;
    }

    /// `set_user_nice`.
    pub fn set_nice(&mut self, nice: i32) {
        if self.nice() == nice || !(MIN_NICE..=MAX_NICE).contains(&nice) {
            return;
        }
        self.static_prio = nice + DEFAULT_PRIO;
        if rt(self.policy) || dl(self.policy) {
            return;
        }
        // effective_prio: a task not boosted takes its normal priority.
        self.normal_prio = self.normal();
        if self.prio >= MAX_RT_PRIO {
            self.prio = self.normal_prio;
        }
    }

    /// `sched_fork` and `copy_io` for a new task (`io` shared with
    /// `CLONE_IO`): `EAGAIN` for a deadline task that keeps its policy.
    pub fn forked(&self, share_io: bool) -> Result<Sched, Errno> {
        let mut s = self.clone();
        s.prio = self.normal_prio;
        if s.reset_on_fork {
            if dl(s.policy) || rt(s.policy) {
                s.policy = policy::NORMAL;
                s.static_prio = DEFAULT_PRIO;
                s.rt_priority = 0;
            } else if s.nice() < 0 {
                s.static_prio = DEFAULT_PRIO;
            }
            s.prio = s.static_prio;
            s.normal_prio = s.static_prio;
            s.custom_slice = false;
            s.slice = BASE_SLICE;
            s.reset_on_fork = false;
        }
        if s.prio < MAX_DL_PRIO {
            return Err(Errno(EAGAIN));
        }
        // copy_process: the child's default slack is the parent's slack.
        s.default_timer_slack = self.timer_slack;
        if !share_io {
            s.ioprio = self.ioprio.filter(|&p| ioprio_valid(p));
        }
        Ok(s)
    }

    /// `sched_rr_get_interval`: the class's `get_rr_interval` in jiffies.
    pub fn rr_interval(&self) -> u64 {
        match self.policy {
            policy::RR => RR_TIMESLICE,
            policy::FIFO | policy::DEADLINE => 0,
            // get_rr_interval_fair: NS_TO_JIFFIES(se->slice).
            _ => self.slice / JIFFY_NS,
        }
    }

    /// `__get_task_ioprio`: the I/O priority, derived from the nice value
    /// and policy for a task without a class of its own.
    pub fn effective_ioprio(&self) -> u16 {
        match self.ioprio {
            Some(p) if ioprio_class(p) != ioprio::CLASS_NONE => p,
            _ => {
                let class = if self.policy == policy::IDLE {
                    ioprio::CLASS_IDLE
                } else if rt(self.policy) || dl(self.policy) {
                    ioprio::CLASS_RT
                } else {
                    ioprio::CLASS_BE
                };
                (class << ioprio::CLASS_SHIFT) | ((self.nice() + 20) / 5) as u16
            }
        }
    }
}

/// I/O priorities (`linux/ioprio.h`).
pub mod ioprio {
    pub const CLASS_SHIFT: u32 = 13;
    pub const CLASS_NONE: u16 = 0;
    pub const CLASS_RT: u16 = 1;
    pub const CLASS_BE: u16 = 2;
    pub const CLASS_IDLE: u16 = 3;
    pub const WHO_PROCESS: i32 = 1;
    pub const WHO_PGRP: i32 = 2;
    pub const WHO_USER: i32 = 3;
}

/// `IOPRIO_PRIO_CLASS`.
pub fn ioprio_class(p: u16) -> u16 {
    (p >> ioprio::CLASS_SHIFT) & 7
}

/// `ioprio_valid`.
pub fn ioprio_valid(p: u16) -> bool {
    (ioprio::CLASS_RT..=ioprio::CLASS_IDLE).contains(&ioprio_class(p))
}

/// `ioprio_check_cap`: the class and level (`EINVAL`), then the right to
/// the real-time class (`EPERM` without privilege).
pub fn ioprio_check(value: i32, privileged: bool) -> Result<(), Errno> {
    let class = ((value >> ioprio::CLASS_SHIFT) & 7) as u16;
    let level = value & 7;
    match class {
        ioprio::CLASS_RT if !privileged => Err(Errno(EPERM)),
        ioprio::CLASS_RT | ioprio::CLASS_BE | ioprio::CLASS_IDLE => Ok(()),
        ioprio::CLASS_NONE if level != 0 => Err(Errno(EINVAL)),
        ioprio::CLASS_NONE => Ok(()),
        _ => Err(Errno(EINVAL)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priorities_follow_the_kernels_mapping() {
        // task_prio: normal 0..39, fifo/rr -2..-100, deadline -101.
        assert_eq!(normal_prio_of(policy::NORMAL, 0, -20) - MAX_RT_PRIO, 0);
        assert_eq!(normal_prio_of(policy::BATCH, 0, 19) - MAX_RT_PRIO, 39);
        assert_eq!(normal_prio_of(policy::FIFO, 1, 0) - MAX_RT_PRIO, -2);
        assert_eq!(normal_prio_of(policy::RR, 99, 0) - MAX_RT_PRIO, -100);
        assert_eq!(normal_prio_of(policy::DEADLINE, 0, 0) - MAX_RT_PRIO, -101);
        assert_eq!(nice_to_rlimit(19), 1);
        assert_eq!(nice_to_rlimit(-20), 40);
    }

    #[test]
    fn an_idle_task_keeps_its_nice_but_takes_the_attributes_priority() {
        let mut s = Sched::default();
        s.set_nice(19);
        let a = Attr {
            policy: policy::IDLE,
            ..Default::default()
        };
        s.apply(&a, policy::IDLE);
        assert_eq!((s.nice(), s.task_prio()), (19, 20));
        // A child starts at the normal priority.
        assert_eq!(s.forked(false).unwrap().task_prio(), 39);
    }

    #[test]
    fn reset_on_fork_returns_a_child_to_the_defaults() {
        let mut s = Sched::default();
        let a = Attr {
            policy: policy::FIFO,
            priority: 10,
            flags: flag::RESET_ON_FORK,
            ..Default::default()
        };
        s.reset_on_fork = true;
        s.apply(&a, policy::FIFO);
        assert_eq!((s.task_prio(), s.timer_slack), (-11, 0));
        let c = s.forked(false).unwrap();
        assert_eq!(
            (c.policy, c.nice(), c.rt_priority, c.reset_on_fork),
            (0, 0, 0, false)
        );
        // A deadline task that keeps its policy cannot fork.
        let d = Attr {
            policy: policy::DEADLINE,
            runtime: 1_000_000,
            deadline: 2_000_000,
            period: 3_000_000,
            ..Default::default()
        };
        let mut s = Sched::default();
        s.apply(&d, policy::DEADLINE);
        assert_eq!(s.forked(false), Err(Errno(EAGAIN)));
        s.reset_on_fork = true;
        assert_eq!(s.forked(false).unwrap().policy, policy::NORMAL);
    }

    #[test]
    fn deadline_parameters_are_checked() {
        let a = |runtime, deadline, period| Attr {
            runtime,
            deadline,
            period,
            ..Default::default()
        };
        assert!(checkparam_dl(&a(1024, 100_000, 0)));
        assert!(
            !checkparam_dl(&a(1023, 100_000, 0)),
            "runtime below DL_SCALE"
        );
        assert!(!checkparam_dl(&a(1024, 0, 0)), "no deadline");
        assert!(!checkparam_dl(&a(1024, 99_999, 0)), "period below 100 us");
        assert!(
            !checkparam_dl(&a(2000, 1500, 0)),
            "runtime past the deadline"
        );
        assert!(
            !checkparam_dl(&a(1024, 200_000, 100_000)),
            "deadline past the period"
        );
        assert!(!checkparam_dl(&a(1024, 1 << 32, 0)), "period past 4.19 s");
        // 95% of one CPU.
        let half = Deadline {
            runtime: 1,
            deadline: 2,
            period: 2,
            flags: 0,
        };
        assert!(!dl_overflow(0, 0, half.bw()));
        assert!(dl_overflow(half.bw(), 0, half.bw()));
    }

    #[test]
    fn io_priorities_default_to_the_nice_value() {
        let mut s = Sched::default();
        assert_eq!(s.effective_ioprio(), (2 << 13) | 4);
        s.set_nice(19);
        assert_eq!(s.effective_ioprio(), (2 << 13) | 7);
        s.ioprio = Some(3 << 13);
        assert_eq!(s.effective_ioprio(), 3 << 13);
        assert_eq!(ioprio_check(1 << 13, false), Err(Errno(EPERM)));
        assert_eq!(ioprio_check(1, false), Err(Errno(EINVAL)));
        assert_eq!(ioprio_check(4 << 13, true), Err(Errno(EINVAL)));
        assert_eq!(ioprio_check((2 << 13) | 0x1ff8, false), Ok(()), "hints");
    }
}

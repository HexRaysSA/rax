//! Scheduling-attribute calls (`kernel/sched/syscalls.c`, `kernel/sys.c`,
//! `block/ioprio.c`): `sched_setscheduler`, `sched_setparam`,
//! `sched_getscheduler`, `sched_getparam`, `sched_setattr`,
//! `sched_getattr`, `sched_get_priority_max` and `_min`,
//! `sched_rr_get_interval`, `setpriority`, `getpriority`, `ioprio_set`,
//! and `ioprio_get`, on the attributes of [`priority`].
//!
//! A task is named by a thread ID of the calling process (0 for the
//! caller); another process's tasks are not reachable (`ESRCH`), so
//! process groups and users hold this process's threads only, except that
//! root always has tasks (`init` among them), which another user may not
//! change (`EPERM`). Without
//! `CAP_SYS_NICE` (root) a task may lower its priority, raise it within
//! `RLIMIT_NICE` and `RLIMIT_RTPRIO`, and not become a deadline task.
//!
//! [`priority`]: super::super::priority

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::Timespec;
use super::super::priority::{
    self, ATTR_SIZE, ATTR_VER0, Attr, MAX_NICE, MAX_RT_PRIO, MIN_NICE, Sched, flag, ioprio,
    nice_to_rlimit, policy,
};
use super::{Ctx, SysResult};

/// `RLIMIT_NICE`, `RLIMIT_RTPRIO`.
const RLIMIT_NICE: usize = 13;
const RLIMIT_RTPRIO: usize = 14;
/// `PRIO_PROCESS`, `PRIO_PGRP`, `PRIO_USER`.
const PRIO_PROCESS: i32 = 0;
const PRIO_PGRP: i32 = 1;
const PRIO_USER: i32 = 2;
/// `PAGE_SIZE`.
const PAGE_SIZE: u32 = 4096;

/// `CAP_SYS_NICE`: only root holds it.
fn capable(c: &Ctx<'_>) -> bool {
    c.p.creds.1 == 0
}

/// `is_nice_reduction`: whether `nice` is within `RLIMIT_NICE`.
fn nice_within(c: &Ctx<'_>, nice: i32) -> bool {
    nice_to_rlimit(nice) <= c.p.rlimits[RLIMIT_NICE].0
}

/// `find_process_by_pid`: the caller for 0, else the thread with that ID.
fn find(c: &Ctx<'_>, pid: i32) -> Result<Sched, Errno> {
    if pid == 0 || pid == c.t.tid {
        return Ok(c.t.sched.clone());
    }
    c.peers
        .lo
        .iter()
        .chain(c.peers.hi.iter())
        .find(|t| t.tid == pid)
        .map(|t| t.sched.clone())
        .ok_or(Errno(ESRCH))
}

/// The thread with ID `tid` (the caller for 0), to change.
fn task_mut<'a>(c: &'a mut Ctx<'_>, pid: i32) -> &'a mut Sched {
    if pid == 0 || pid == c.t.tid {
        return &mut c.t.sched;
    }
    &mut c
        .peers
        .lo
        .iter_mut()
        .chain(c.peers.hi.iter_mut())
        .find(|t| t.tid == pid)
        .expect("found before")
        .sched
}

/// Every thread of the process with its ID.
fn all_tids(c: &Ctx<'_>) -> Vec<i32> {
    c.thread_refs().iter().map(|t| t.tid).collect()
}

/// The deadline bandwidth the process's other tasks hold.
fn dl_others(c: &Ctx<'_>, tid: i32) -> u64 {
    c.thread_refs()
        .iter()
        .filter(|t| t.tid != tid)
        .map(|t| t.sched.dl_bw())
        .sum()
}

/// `user_check_sched_setscheduler`: `EPERM` without `CAP_SYS_NICE` for
/// what an unprivileged task may not do.
fn user_check(c: &Ctx<'_>, p: &Sched, a: &Attr, pol: i32, reset: bool) -> Result<(), Errno> {
    let rtprio = c.p.rlimits[RLIMIT_RTPRIO].0;
    let privileged_only = (priority::fair(pol) && a.nice < p.nice() && !nice_within(c, a.nice))
        || (priority::rt(pol)
            && ((pol != p.policy && rtprio == 0)
                || (a.priority > p.rt_priority && u64::from(a.priority) > rtprio)))
        || priority::dl(pol)
        || (p.policy == policy::IDLE && pol != policy::IDLE && !nice_within(c, p.nice()))
        || (p.reset_on_fork && !reset);
    if privileged_only && !capable(c) {
        return Err(Errno(EPERM));
    }
    Ok(())
}

/// `__sched_setscheduler` on task `pid` with `a` (policy
/// [`policy::SETPARAM`] to keep it).
fn setscheduler(c: &mut Ctx<'_>, pid: i32, a: Attr) -> SysResult {
    let p = find(c, pid)?;
    let (pol, reset) = if a.policy < 0 {
        (p.policy, p.reset_on_fork)
    } else {
        if !priority::valid(a.policy) {
            return Err(Errno(EINVAL));
        }
        (a.policy, a.flags & flag::RESET_ON_FORK != 0)
    };
    if a.flags & !(flag::ALL | flag::SUGOV) != 0 || a.priority > (MAX_RT_PRIO - 1) as u32 {
        return Err(Errno(EINVAL));
    }
    if (priority::dl(pol) && !priority::checkparam_dl(&a)) || priority::rt(pol) != (a.priority != 0)
    {
        return Err(Errno(EINVAL));
    }
    user_check(c, &p, &a, pol, reset)?;
    if a.flags & flag::SUGOV != 0 {
        return Err(Errno(EINVAL));
    }
    // uclamp_validate without CONFIG_UCLAMP_TASK.
    if a.flags & flag::UTIL_CLAMP != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    let tid = if pid == 0 { c.t.tid } else { pid };
    if !p.changes(&a, pol) {
        task_mut(c, pid).reset_on_fork = reset;
        return Ok(0);
    }
    if priority::dl(pol) || priority::dl(p.policy) {
        let new = if priority::dl(pol) {
            let period = if a.period == 0 { a.deadline } else { a.period };
            priority::Deadline {
                runtime: a.runtime,
                deadline: a.deadline,
                period,
                flags: 0,
            }
            .bw()
        } else {
            0
        };
        if priority::dl_overflow(dl_others(c, tid), p.dl_bw(), new) {
            return Err(Errno(EBUSY));
        }
    }
    let t = task_mut(c, pid);
    t.reset_on_fork = reset;
    t.apply(&a, pol);
    Ok(0)
}

/// Reads a `struct sched_param` (`do_sched_setscheduler`).
fn sched_param(c: &Ctx<'_>, pid: i32, param: u64) -> Result<u32, Errno> {
    if param == 0 || pid < 0 {
        return Err(Errno(EINVAL));
    }
    c.read_u32(param)
}

/// `_sched_setscheduler` with the priority from a `struct sched_param`
/// and the task's own nice value and slice.
fn set_with_param(c: &mut Ctx<'_>, pid: i32, pol: i32, param: u64) -> SysResult {
    let priority = sched_param(c, pid, param)?;
    let p = find(c, pid)?;
    let mut a = Attr {
        policy: pol,
        priority,
        nice: p.nice(),
        runtime: if p.custom_slice { p.slice } else { 0 },
        ..Default::default()
    };
    // The legacy SCHED_RESET_ON_FORK bit.
    if pol != policy::SETPARAM && pol & policy::RESET_ON_FORK != 0 {
        a.flags |= flag::RESET_ON_FORK;
        a.policy = pol & !policy::RESET_ON_FORK;
    }
    setscheduler(c, pid, a)
}

/// `sched_setscheduler`.
pub fn sched_setscheduler(c: &mut Ctx<'_>, pid: i32, pol: i32, param: u64) -> SysResult {
    if pol < 0 {
        return Err(Errno(EINVAL));
    }
    set_with_param(c, pid, pol, param)
}

/// `sched_setparam`.
pub fn sched_setparam(c: &mut Ctx<'_>, pid: i32, param: u64) -> SysResult {
    set_with_param(c, pid, policy::SETPARAM, param)
}

/// `sched_getscheduler`: the policy, with `SCHED_RESET_ON_FORK`.
pub fn sched_getscheduler(c: &mut Ctx<'_>, pid: i32) -> SysResult {
    if pid < 0 {
        return Err(Errno(EINVAL));
    }
    let p = find(c, pid)?;
    let reset = if p.reset_on_fork {
        policy::RESET_ON_FORK
    } else {
        0
    };
    Ok((p.policy | reset) as u64)
}

/// `sched_getparam`: the real-time priority (0 for other policies).
pub fn sched_getparam(c: &mut Ctx<'_>, pid: i32, param: u64) -> SysResult {
    if param == 0 || pid < 0 {
        return Err(Errno(EINVAL));
    }
    let p = find(c, pid)?;
    let prio = if priority::rt(p.policy) {
        p.rt_priority
    } else {
        0
    };
    c.write_u32(param, prio)?;
    Ok(0)
}

/// `sched_copy_attr`: the structure's size (0 is the first version's),
/// its known part and zero rest; a bad size is `E2BIG` with the kernel's
/// size written back.
fn copy_attr(c: &Ctx<'_>, uattr: u64) -> Result<Attr, Errno> {
    let size = match c.read_u32(uattr)? {
        0 => ATTR_VER0 as u32,
        s => s,
    };
    let too_big = || {
        let _ = c.write_u32(uattr, ATTR_SIZE as u32);
        Errno(E2BIG)
    };
    if size < ATTR_VER0 as u32 || size > PAGE_SIZE {
        return Err(too_big());
    }
    let b = match super::mount::copy_struct(c, uattr, ATTR_SIZE as u64, u64::from(size)) {
        Err(Errno(E2BIG)) => return Err(too_big()),
        r => r?,
    };
    let mut a = Attr::decode(&b);
    if a.flags & flag::UTIL_CLAMP != 0 && size < ATTR_SIZE as u32 {
        return Err(Errno(EINVAL));
    }
    a.nice = a.nice.clamp(MIN_NICE, MAX_NICE);
    Ok(a)
}

/// `sched_setattr`.
pub fn sched_setattr(c: &mut Ctx<'_>, pid: i32, uattr: u64, flags: u32) -> SysResult {
    if uattr == 0 || pid < 0 || flags != 0 {
        return Err(Errno(EINVAL));
    }
    let mut a = copy_attr(c, uattr)?;
    if a.policy < 0 {
        return Err(Errno(EINVAL));
    }
    if a.flags & flag::KEEP_POLICY != 0 {
        a.policy = policy::SETPARAM;
    }
    let p = find(c, pid)?;
    if a.flags & flag::KEEP_PARAMS != 0 {
        p.params(&mut a);
    }
    setscheduler(c, pid, a)
}

/// `sched_getattr`: the attributes, `size` the smaller of the caller's
/// and the kernel's, and zeros past the kernel's.
pub fn sched_getattr(c: &mut Ctx<'_>, pid: i32, uattr: u64, usize: u32, flags: u32) -> SysResult {
    if uattr == 0 || pid < 0 || usize > PAGE_SIZE || usize < ATTR_VER0 as u32 || flags != 0 {
        return Err(Errno(EINVAL));
    }
    let p = find(c, pid)?;
    let size = usize.min(ATTR_SIZE as u32);
    let b = p.attr().encode(size);
    // copy_struct_to_user.
    let mut out = vec![0u8; usize as usize];
    let n = size as usize;
    out[..n].copy_from_slice(&b[..n]);
    c.write_mem(uattr, &out)?;
    Ok(0)
}

/// `sched_get_priority_max` (`max`) and `sched_get_priority_min`.
pub fn sched_priority(pol: i32, max: bool) -> SysResult {
    match pol {
        policy::FIFO | policy::RR => Ok(if max { 99 } else { 1 }),
        policy::NORMAL | policy::BATCH | policy::IDLE | policy::DEADLINE | policy::EXT => Ok(0),
        _ => Err(Errno(EINVAL)),
    }
}

/// `sched_rr_get_interval`: the task's time slice, in jiffies of 4 ms.
pub fn sched_rr_get_interval(c: &mut Ctx<'_>, pid: i32, interval: u64) -> SysResult {
    if pid < 0 {
        return Err(Errno(EINVAL));
    }
    let jiffies = find(c, pid)?.rr_interval();
    let ns = jiffies * priority::JIFFY_NS;
    let t = Timespec {
        sec: (ns / 1_000_000_000) as i64,
        nsec: (ns % 1_000_000_000) as i64,
    };
    c.write_mem(interval, &t.encode())?;
    Ok(0)
}

/// The threads `which`/`who` names (`PRIO_*` and `IOPRIO_WHO_*` alike):
/// one thread, the process group (which holds this process's threads
/// when it is this process's), or a user's threads, by real user ID
/// (`uid_for_zero` standing for `who` 0).
fn targets(c: &Ctx<'_>, group: bool, who: i32, uid_for_zero: u32) -> Vec<i32> {
    if group {
        let own = if c.p.config.processes {
            super::super::host::getpgid(0).unwrap_or(c.p.pid)
        } else {
            c.p.pid
        };
        if who == 0 || who == own {
            all_tids(c)
        } else {
            Vec::new()
        }
    } else {
        let uid = if who == 0 { uid_for_zero } else { who as u32 };
        if uid == c.p.creds.0 {
            all_tids(c)
        } else {
            Vec::new()
        }
    }
}

/// Whether `ioprio_set` on user `uid`'s tasks meets root's, which a caller
/// of another real user without `CAP_SYS_NICE` may not change.
fn roots_tasks(c: &Ctx<'_>, uid: u32) -> Result<bool, Errno> {
    if uid != 0 || c.p.creds.0 == 0 {
        return Ok(false);
    }
    if capable(c) {
        Ok(true)
    } else {
        Err(Errno(EPERM))
    }
}

/// `setpriority`: the nice value (clamped) of each task named, in order,
/// `EACCES` for a reduction beyond `RLIMIT_NICE`, `ESRCH` for none. The
/// caller's own tasks always pass `set_one_prio_perm`.
pub fn setpriority(c: &mut Ctx<'_>, which: i32, who: i32, niceval: i32) -> SysResult {
    if !(PRIO_PROCESS..=PRIO_USER).contains(&which) {
        return Err(Errno(EINVAL));
    }
    let nice = niceval.clamp(MIN_NICE, MAX_NICE);
    let tids = match which {
        PRIO_PROCESS => match find(c, who) {
            Ok(_) => vec![if who == 0 { c.t.tid } else { who }],
            Err(_) => Vec::new(),
        },
        PRIO_PGRP => targets(c, true, who, 0),
        _ => targets(c, false, who, c.p.creds.0),
    };
    let mut error = Err(Errno(ESRCH));
    for tid in tids {
        // set_one_prio.
        let p = find(c, tid)?;
        if nice < p.nice() && !(nice_within(c, nice) || capable(c)) {
            error = Err(Errno(EACCES));
            continue;
        }
        if error == Err(Errno(ESRCH)) {
            error = Ok(0);
        }
        task_mut(c, tid).set_nice(nice);
    }
    error
}

/// `getpriority`: the highest of the tasks' `20 - nice`, `ESRCH` for none.
pub fn getpriority(c: &mut Ctx<'_>, which: i32, who: i32) -> SysResult {
    if !(PRIO_PROCESS..=PRIO_USER).contains(&which) {
        return Err(Errno(EINVAL));
    }
    let tids = match which {
        PRIO_PROCESS => match find(c, who) {
            Ok(_) => vec![if who == 0 { c.t.tid } else { who }],
            Err(_) => Vec::new(),
        },
        PRIO_PGRP => targets(c, true, who, 0),
        _ => targets(c, false, who, c.p.creds.0),
    };
    tids.iter()
        .map(|&t| nice_to_rlimit(find(c, t).map_or(0, |s| s.nice())))
        .max()
        .ok_or(Errno(ESRCH))
}

/// `ioprio_set`: the value's class and level and the right to the
/// real-time class, then each task named (`set_task_ioprio`).
pub fn ioprio_set(c: &mut Ctx<'_>, which: i32, who: i32, value: i32) -> SysResult {
    priority::ioprio_check(value, capable(c))?;
    let tids = match which {
        ioprio::WHO_PROCESS => match find(c, who) {
            Ok(_) => vec![if who == 0 { c.t.tid } else { who }],
            Err(_) => Vec::new(),
        },
        ioprio::WHO_PGRP => targets(c, true, who, 0),
        // make_kuid of `who`: 0 is root, not the caller.
        ioprio::WHO_USER if who == -1 => Vec::new(),
        ioprio::WHO_USER if roots_tasks(c, who as u32)? => return Ok(0),
        ioprio::WHO_USER => targets(c, false, who, 0),
        _ => return Err(Errno(EINVAL)),
    };
    if tids.is_empty() {
        return Err(Errno(ESRCH));
    }
    // set_task_ioprio: a task of the caller's own process is its user's.
    for tid in tids {
        task_mut(c, tid).ioprio = Some(value as u16);
    }
    Ok(0)
}

/// `ioprio_get`: a task's value as set (none: 0), or the best (lowest)
/// effective value of a group's or user's tasks.
pub fn ioprio_get(c: &mut Ctx<'_>, which: i32, who: i32) -> SysResult {
    let (tids, raw) = match which {
        ioprio::WHO_PROCESS => (
            match find(c, who) {
                Ok(_) => vec![if who == 0 { c.t.tid } else { who }],
                Err(_) => Vec::new(),
            },
            true,
        ),
        ioprio::WHO_PGRP => (targets(c, true, who, 0), false),
        ioprio::WHO_USER => (targets(c, false, who, c.p.creds.0), false),
        _ => return Err(Errno(EINVAL)),
    };
    tids.iter()
        .filter_map(|&t| find(c, t).ok())
        .map(|s| {
            if raw {
                s.ioprio.unwrap_or(0)
            } else {
                s.effective_ioprio()
            }
        })
        .min()
        .map(u64::from)
        .ok_or(Errno(ESRCH))
}

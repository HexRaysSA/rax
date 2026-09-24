//! Futex system calls (`kernel/futex/syscalls.c`, `waitwake.c`,
//! `requeue.c`, `pi.c`): `futex`, `futex_waitv`, the `futex2` calls
//! `futex_wake`/`futex_wait`/`futex_requeue`, and the robust-list head.
//!
//! Timeouts are converted to host instants when the call starts; an
//! absolute `CLOCK_REALTIME` timeout does not follow later changes of the
//! host's wall clock. `FUTEX_WAIT_REQUEUE_PI` and `FUTEX_CMP_REQUEUE_PI`
//! are not implemented (`ENOSYS`).

use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::Timespec;
use super::super::futex::{
    self as fx, BITSET_MATCH_ANY, FUTEX_OWNER_DIED, FUTEX_TID_MASK, FUTEX_WAITERS, FutexKey,
    FutexWait, FutexWaitKind, get_u32, put_u32,
};
use super::super::host::{self, HostClock};
use super::super::signal::deliver::restart::{ERESTART_RESTARTBLOCK, ERESTARTNOINTR, ERESTARTSYS};
use super::super::wait::{Resume, Wait};
use super::{Ctx, Outcome, RestartBlock, SysResult};

/// `futex` operations (`linux/futex.h`).
mod op {
    pub const WAIT: u32 = 0;
    pub const WAKE: u32 = 1;
    pub const REQUEUE: u32 = 3;
    pub const CMP_REQUEUE: u32 = 4;
    pub const WAKE_OP: u32 = 5;
    pub const LOCK_PI: u32 = 6;
    pub const UNLOCK_PI: u32 = 7;
    pub const TRYLOCK_PI: u32 = 8;
    pub const WAIT_BITSET: u32 = 9;
    pub const WAKE_BITSET: u32 = 10;
    pub const WAIT_REQUEUE_PI: u32 = 11;
    pub const CMP_REQUEUE_PI: u32 = 12;
    pub const LOCK_PI2: u32 = 13;
    pub const PRIVATE_FLAG: u32 = 128;
    pub const CLOCK_REALTIME: u32 = 256;
}

/// `futex2` flags.
mod f2 {
    pub const SIZE_MASK: u32 = 0x03;
    pub const SIZE_U32: u32 = 0x02;
    pub const NUMA: u32 = 0x04;
    pub const MPOL: u32 = 0x08;
    pub const PRIVATE: u32 = 128;
    pub const VALID_MASK: u32 = SIZE_MASK | NUMA | MPOL | PRIVATE;
}

/// `FUTEX_WAITV_MAX`.
const WAITV_MAX: u32 = 128;
/// `FUTEX_NO_NODE`.
const NO_NODE: u32 = u32::MAX;
/// `sizeof(struct robust_list_head)` on 64-bit ABIs.
const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// Reads a `struct __kernel_timespec` (`EFAULT`) and checks it
/// (`timespec64_valid`, `EINVAL`).
fn read_timespec(c: &Ctx<'_>, addr: u64) -> Result<Timespec, Errno> {
    let b: [u8; 16] = c.read_mem(addr, 16)?.try_into().unwrap();
    let t = Timespec::decode(&b);
    if t.sec < 0 || !(0..1_000_000_000).contains(&t.nsec) {
        return Err(Errno(EINVAL));
    }
    Ok(t)
}

/// The host instant of absolute time `t` on `clock`.
fn absolute(t: Timespec, clock: HostClock) -> Instant {
    let (s, ns) = host::clock_gettime(clock);
    let now = s as i128 * 1_000_000_000 + ns as i128;
    let at = t.sec as i128 * 1_000_000_000 + t.nsec as i128;
    Instant::now() + Duration::from_nanos((at - now).clamp(0, u64::MAX as i128) as u64)
}

/// A relative timeout from now.
fn relative(t: Timespec) -> Instant {
    Instant::now() + Duration::new(t.sec as u64, t.nsec as u32)
}

/// `futex`.
pub fn futex(
    c: &mut Ctx<'_>,
    uaddr: u64,
    op: u32,
    val: u32,
    utime: u64,
    uaddr2: u64,
    val3: u32,
) -> Result<Outcome, Errno> {
    let cmd = op & !(op::PRIVATE_FLAG | op::CLOCK_REALTIME);
    let shared = op & op::PRIVATE_FLAG == 0;
    let clockrt = op & op::CLOCK_REALTIME != 0;
    // The syscall entry converts the timeout of the commands that have one
    // (futex_init_timeout) before do_futex looks at the command.
    let has_timeout = matches!(
        cmd,
        op::WAIT | op::LOCK_PI | op::LOCK_PI2 | op::WAIT_BITSET | op::WAIT_REQUEUE_PI
    );
    let deadline = if utime != 0 && has_timeout && c.resume.is_none() {
        let t = read_timespec(c, utime)?;
        Some(match cmd {
            op::WAIT => relative(t),
            op::LOCK_PI => absolute(t, HostClock::Realtime),
            _ if clockrt => absolute(t, HostClock::Realtime),
            _ => absolute(t, HostClock::Monotonic),
        })
    } else {
        None
    };
    if clockrt && !matches!(cmd, op::WAIT_BITSET | op::WAIT_REQUEUE_PI | op::LOCK_PI2) {
        return Err(Errno(ENOSYS));
    }
    // The count argument of the requeue and wake-op commands shares the
    // timeout register.
    let val2 = utime as u32 as i32;
    match cmd {
        op::WAIT => wait(c, uaddr, shared, val, deadline, BITSET_MATCH_ANY, true),
        op::WAIT_BITSET => wait(c, uaddr, shared, val, deadline, val3, true),
        op::WAKE => wake(c, uaddr, shared, val as i32, BITSET_MATCH_ANY, false),
        op::WAKE_BITSET => wake(c, uaddr, shared, val as i32, val3, false),
        op::REQUEUE => requeue(c, (uaddr, shared), (uaddr2, shared), val as i32, val2, None),
        op::CMP_REQUEUE => requeue(
            c,
            (uaddr, shared),
            (uaddr2, shared),
            val as i32,
            val2,
            Some(val3),
        ),
        op::WAKE_OP => wake_op(c, uaddr, uaddr2, shared, val as i32, val2, val3),
        op::LOCK_PI | op::LOCK_PI2 => lock_pi(c, uaddr, shared, deadline, false),
        op::TRYLOCK_PI => lock_pi(c, uaddr, shared, None, true),
        op::UNLOCK_PI => {
            let me = c.t.tid;
            let (p, mut th) = c.split();
            fx::unlock_pi(p, &mut th, uaddr, shared, me).map(Outcome::Return)
        }
        // Requeueing condition-variable waiters onto PI futexes is not
        // implemented.
        op::WAIT_REQUEUE_PI | op::CMP_REQUEUE_PI => Err(Errno(ENOSYS)),
        _ => Err(Errno(ENOSYS)),
    }
}

/// `futex_wait`: sleeps while the word at `uaddr` holds `val` until woken
/// (0), the deadline (`ETIMEDOUT`), or a signal (`-ERESTARTSYS`; with a
/// timeout and `restartable`, `futex_wait_restart` through
/// `restart_syscall`). A woken wait returns 0 whatever else happened.
fn wait(
    c: &mut Ctx<'_>,
    uaddr: u64,
    shared: bool,
    val: u32,
    deadline: Option<Instant>,
    bitset: u32,
    restartable: bool,
) -> Result<Outcome, Errno> {
    let tid = c.t.tid;
    let mut deadline = deadline;
    if let Some(Resume::Futex(fw)) = c.resume.take() {
        if c.woken {
            return Ok(Outcome::Return(0));
        }
        c.p.futex.unqueue(tid);
        deadline = fw.deadline;
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(ETIMEDOUT));
        }
        if c.signal_pending() {
            if let (true, Some(deadline)) = (restartable, deadline) {
                c.t.restart = Some(RestartBlock::Futex {
                    uaddr,
                    val,
                    bitset,
                    shared,
                    deadline,
                });
                return Err(Errno(ERESTART_RESTARTBLOCK));
            }
            return Err(Errno(ERESTARTSYS));
        }
        // A spurious wake: set up again.
    }
    if bitset == 0 {
        return Err(Errno(EINVAL));
    }
    let key = fx::key(c.p, uaddr, shared, false)?;
    if get_u32(c.p, uaddr)? != val {
        return Err(Errno(EAGAIN));
    }
    c.p.futex.enqueue(key, tid, bitset, 0);
    let record = FutexWait {
        kind: FutexWaitKind::Wait {
            uaddr,
            val,
            bitset,
            shared,
        },
        deadline,
        woken: None,
    };
    Err(c.block(Wait::until(deadline), Resume::Futex(record)))
}

/// `futex_wait_restart`: an interrupted timed wait continues to its
/// original deadline.
pub fn wait_restart(
    c: &mut Ctx<'_>,
    uaddr: u64,
    val: u32,
    bitset: u32,
    shared: bool,
    deadline: Instant,
) -> Result<Outcome, Errno> {
    wait(c, uaddr, shared, val, Some(deadline), bitset, true)
}

/// `futex_wake`. With `strict` (`FLAGS_STRICT`, the `futex2` call) a count
/// of zero wakes nothing.
fn wake(
    c: &mut Ctx<'_>,
    uaddr: u64,
    shared: bool,
    nr_wake: i32,
    bitset: u32,
    strict: bool,
) -> Result<Outcome, Errno> {
    if bitset == 0 {
        return Err(Errno(EINVAL));
    }
    let key = fx::key(c.p, uaddr, shared, false)?;
    if strict && nr_wake == 0 {
        return Ok(Outcome::Return(0));
    }
    let (p, mut th) = c.split();
    p.futex
        .wake(&mut th, key, nr_wake, bitset)
        .map(Outcome::Return)
}

/// `futex_requeue`: `(address, shared)` of the source and target; with
/// `cmpval` the source must hold it (`EAGAIN`).
fn requeue(
    c: &mut Ctx<'_>,
    (uaddr1, shared1): (u64, bool),
    (uaddr2, shared2): (u64, bool),
    nr_wake: i32,
    nr_requeue: i32,
    cmpval: Option<u32>,
) -> Result<Outcome, Errno> {
    if nr_wake < 0 || nr_requeue < 0 {
        return Err(Errno(EINVAL));
    }
    let key1 = fx::key(c.p, uaddr1, shared1, false)?;
    let key2 = fx::key(c.p, uaddr2, shared2, false)?;
    if let Some(cmp) = cmpval
        && get_u32(c.p, uaddr1)? != cmp
    {
        return Err(Errno(EAGAIN));
    }
    let (p, mut th) = c.split();
    p.futex
        .requeue(&mut th, key1, key2, nr_wake, nr_requeue)
        .map(Outcome::Return)
}

/// `futex_wake_op`: applies the encoded operation to `uaddr2`, wakes up to
/// `nr_wake` waiters of `uaddr1` and, if the comparison of the old value
/// holds, up to `nr_wake2` of `uaddr2`.
fn wake_op(
    c: &mut Ctx<'_>,
    uaddr1: u64,
    uaddr2: u64,
    shared: bool,
    nr_wake: i32,
    nr_wake2: i32,
    encoded: u32,
) -> Result<Outcome, Errno> {
    let key1 = fx::key(c.p, uaddr1, shared, false)?;
    let key2 = fx::key(c.p, uaddr2, shared, true)?;
    let fire = fx::atomic_op(c.p, encoded, uaddr2)?;
    let (p, mut th) = c.split();
    let mut n = p.futex.wake(&mut th, key1, nr_wake, BITSET_MATCH_ANY)?;
    if fire {
        n += p.futex.wake(&mut th, key2, nr_wake2, BITSET_MATCH_ANY)?;
    }
    Ok(Outcome::Return(n))
}

/// `futex_lock_pi`: takes the PI lock at `uaddr` for the caller, sleeping
/// until the owner hands it over (0), the deadline (`ETIMEDOUT`), or a
/// signal (`-ERESTARTNOINTR`: the lock attempt restarts after a handler).
/// A lock without an owner is taken keeping `FUTEX_OWNER_DIED`; an owner
/// that does not exist is `ESRCH`; `trylock` does not sleep
/// (`EWOULDBLOCK`).
fn lock_pi(
    c: &mut Ctx<'_>,
    uaddr: u64,
    shared: bool,
    deadline: Option<Instant>,
    trylock: bool,
) -> Result<Outcome, Errno> {
    let me = c.t.tid;
    let mut deadline = deadline;
    if let Some(Resume::Futex(fw)) = c.resume.take() {
        if c.woken {
            return Ok(Outcome::Return(0));
        }
        c.p.futex.unqueue(me);
        deadline = fw.deadline;
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(ETIMEDOUT));
        }
        if c.signal_pending() {
            return Err(Errno(ERESTARTNOINTR));
        }
    }
    let key = fx::key(c.p, uaddr, shared, true)?;
    let uval = get_u32(c.p, uaddr)?;
    if uval & FUTEX_TID_MASK == me as u32 {
        return Err(Errno(EDEADLK));
    }
    let owner = if let Some(top) = c.p.futex.top_waiter(key) {
        // attach_to_pi_state: a plain waiter at the head (FUTEX_WAIT on a PI
        // futex) or a word naming someone other than the recorded owner is
        // inconsistent.
        match top {
            Some(owner) if (uval & FUTEX_TID_MASK) as i32 == owner => owner,
            _ => return Err(Errno(EINVAL)),
        }
    } else if uval & FUTEX_TID_MASK == 0 {
        // No owner: take it, keeping FUTEX_OWNER_DIED.
        put_u32(c.p, uaddr, (uval & FUTEX_OWNER_DIED) | me as u32)?;
        return Ok(Outcome::Return(0));
    } else {
        // First waiter: FUTEX_WAITERS forces the owner's unlock into the
        // kernel; then the owner must exist (attach_to_pi_owner).
        put_u32(c.p, uaddr, uval | FUTEX_WAITERS)?;
        let owner = (uval & FUTEX_TID_MASK) as i32;
        let (_, th) = c.split();
        if !th.contains(owner) {
            return Err(Errno(ESRCH));
        }
        owner
    };
    if trylock {
        return Err(Errno(EAGAIN));
    }
    c.p.futex.enqueue_pi(key, me, owner);
    let record = FutexWait {
        kind: FutexWaitKind::LockPi,
        deadline,
        woken: None,
    };
    Err(c.block(Wait::until(deadline), Resume::Futex(record)))
}

/// `futex2` flags to `(shared, numa)`, checking them (`futex2_to_flags`,
/// `futex_flags_valid`): only 32-bit futexes exist.
fn futex2_flags(flags: u32) -> Result<(bool, bool), Errno> {
    if flags & !f2::VALID_MASK != 0 || flags & f2::SIZE_MASK != f2::SIZE_U32 {
        return Err(Errno(EINVAL));
    }
    Ok((flags & f2::PRIVATE == 0, flags & f2::NUMA != 0))
}

/// `get_futex_key` for a `futex2` futex: a `FUTEX2_NUMA` futex is a word
/// followed by a node number, aligned to both; the node must be node 0 (the
/// only node) or `FUTEX_NO_NODE`, which is replaced by the current node.
fn key2(c: &Ctx<'_>, uaddr: u64, shared: bool, numa: bool, write: bool) -> Result<FutexKey, Errno> {
    if numa {
        if uaddr % 8 != 0 {
            return Err(Errno(EINVAL));
        }
        let node = get_u32(c.p, uaddr + 4)?;
        if node == NO_NODE {
            put_u32(c.p, uaddr + 4, 0)?;
        } else if node != 0 {
            return Err(Errno(EINVAL));
        }
    }
    fx::key(c.p, uaddr, shared, write)
}

/// `futex2_setup_timeout`: an absolute timeout on `CLOCK_REALTIME` or
/// `CLOCK_MONOTONIC`.
fn futex2_deadline(c: &Ctx<'_>, timeout: u64, clockid: i32) -> Result<Option<Instant>, Errno> {
    if timeout == 0 {
        return Ok(None);
    }
    let clock = match clockid {
        0 => HostClock::Realtime,
        1 => HostClock::Monotonic,
        _ => return Err(Errno(EINVAL)),
    };
    Ok(Some(absolute(read_timespec(c, timeout)?, clock)))
}

/// One parsed `struct futex_waitv`.
struct WaitvEntry {
    val: u32,
    uaddr: u64,
    shared: bool,
    numa: bool,
}

/// `futex_parse_waitv`.
fn parse_waitv(c: &Ctx<'_>, waiters: u64, n: u32) -> Result<Vec<WaitvEntry>, Errno> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..u64::from(n) {
        let b = c.read_mem(waiters + i * 24, 24)?;
        let val = u64::from_le_bytes(b[..8].try_into().unwrap());
        let uaddr = u64::from_le_bytes(b[8..16].try_into().unwrap());
        let flags = u32::from_le_bytes(b[16..20].try_into().unwrap());
        let reserved = u32::from_le_bytes(b[20..24].try_into().unwrap());
        if flags & !f2::VALID_MASK != 0 || reserved != 0 {
            return Err(Errno(EINVAL));
        }
        let (shared, numa) = futex2_flags(flags)?;
        // futex_validate_input: the value fits the futex size.
        if val >> 32 != 0 {
            return Err(Errno(EINVAL));
        }
        out.push(WaitvEntry {
            val: val as u32,
            uaddr,
            shared,
            numa,
        });
    }
    Ok(out)
}

/// `futex_waitv`: sleeps on every futex of the vector until one is woken
/// (its index; if several were, the highest), the deadline, or a signal.
pub fn futex_waitv(
    c: &mut Ctx<'_>,
    waiters: u64,
    nr: u32,
    flags: u32,
    timeout: u64,
    clockid: i32,
) -> Result<Outcome, Errno> {
    let me = c.t.tid;
    let deadline = if let Some(Resume::Futex(fw)) = c.resume.take() {
        c.p.futex.unqueue(me);
        if let Some(i) = fw.woken {
            return Ok(Outcome::Return(u64::from(i)));
        }
        if fw.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(ETIMEDOUT));
        }
        if c.signal_pending() {
            return Err(Errno(ERESTARTSYS));
        }
        fw.deadline
    } else {
        if flags != 0 {
            return Err(Errno(EINVAL));
        }
        if nr == 0 || nr > WAITV_MAX || waiters == 0 {
            return Err(Errno(EINVAL));
        }
        futex2_deadline(c, timeout, clockid)?
    };
    let entries = parse_waitv(c, waiters, nr)?;
    let mut keys = Vec::with_capacity(entries.len());
    for e in &entries {
        keys.push(key2(c, e.uaddr, e.shared, e.numa, false)?);
    }
    for e in &entries {
        if get_u32(c.p, e.uaddr)? != e.val {
            return Err(Errno(EAGAIN));
        }
    }
    for (i, key) in keys.into_iter().enumerate() {
        c.p.futex.enqueue(key, me, BITSET_MATCH_ANY, i as u32);
    }
    let record = FutexWait {
        kind: FutexWaitKind::Vector,
        deadline,
        woken: None,
    };
    Err(c.block(Wait::until(deadline), Resume::Futex(record)))
}

/// `futex_wake` (`futex2`).
pub fn futex_wake(
    c: &mut Ctx<'_>,
    uaddr: u64,
    mask: u64,
    nr: i32,
    flags: u32,
) -> Result<Outcome, Errno> {
    let (shared, numa) = futex2_flags(flags)?;
    if mask >> 32 != 0 {
        return Err(Errno(EINVAL));
    }
    if numa {
        key2(c, uaddr, shared, numa, false)?;
    }
    wake(c, uaddr, shared, nr, mask as u32, true)
}

/// `futex_wait` (`futex2`): an absolute timeout, and no restart block.
pub fn futex_wait(
    c: &mut Ctx<'_>,
    uaddr: u64,
    val: u64,
    mask: u64,
    flags: u32,
    timeout: u64,
    clockid: i32,
) -> Result<Outcome, Errno> {
    let (shared, numa) = futex2_flags(flags)?;
    if val >> 32 != 0 || mask >> 32 != 0 {
        return Err(Errno(EINVAL));
    }
    let deadline = if c.resume.is_some() {
        None
    } else {
        let d = futex2_deadline(c, timeout, clockid)?;
        if numa && mask != 0 {
            key2(c, uaddr, shared, numa, false)?;
        }
        d
    };
    wait(c, uaddr, shared, val as u32, deadline, mask as u32, false)
}

/// `futex_requeue` (`futex2`): a two-entry `futex_waitv` names the source
/// (with the expected value) and the target.
pub fn futex_requeue(
    c: &mut Ctx<'_>,
    waiters: u64,
    flags: u32,
    nr_wake: i32,
    nr_requeue: i32,
) -> Result<Outcome, Errno> {
    if flags != 0 || waiters == 0 {
        return Err(Errno(EINVAL));
    }
    let v = parse_waitv(c, waiters, 2)?;
    for e in &v {
        if e.numa {
            key2(c, e.uaddr, e.shared, true, false)?;
        }
    }
    requeue(
        c,
        (v[0].uaddr, v[0].shared),
        (v[1].uaddr, v[1].shared),
        nr_wake,
        nr_requeue,
        Some(v[0].val),
    )
}

/// `set_robust_list`.
pub fn set_robust_list(c: &mut Ctx<'_>, head: u64, len: u64) -> SysResult {
    if len != ROBUST_LIST_HEAD_SIZE {
        return Err(Errno(EINVAL));
    }
    c.t.robust_list = (head, len);
    Ok(0)
}

/// `get_robust_list` of the caller (`pid` 0) or another thread.
pub fn get_robust_list(c: &mut Ctx<'_>, pid: i32, head_ptr: u64, len_ptr: u64) -> SysResult {
    let head = if pid == 0 || pid == c.t.tid {
        c.t.robust_list.0
    } else {
        let (_, th) = c.split();
        th.iter()
            .find(|t| t.tid == pid)
            .map(|t| t.robust_list.0)
            .ok_or(Errno(ESRCH))?
    };
    c.write_u64(len_ptr, ROBUST_LIST_HEAD_SIZE)?;
    c.write_u64(head_ptr, head)?;
    Ok(0)
}

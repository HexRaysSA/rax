//! Blocking waits and address-keyed synchronization.
//!
//! A thread that must wait parks with a [`Wait`]; the scheduler polls
//! parked threads with [`poll`] and resumes one when its wait is satisfied,
//! times out, or (for an alertable wait) has a user APC queued. Object
//! waits follow `WaitForMultipleObjectsEx`: a wait-any wait is satisfied by
//! the lowest-indexed signaled object, a wait-all wait only when every
//! object is signaled at once; satisfying a wait consumes an auto-reset
//! event or timer, a semaphore count, or acquires a mutex (recursively for
//! its owner). A mutex whose owner ended is *abandoned*: the next acquirer
//! gets `WAIT_ABANDONED_0 + i`.
//!
//! Critical sections, SRW locks, condition variables, and `WaitOnAddress`
//! are keyed by guest address. Every built-in call is atomic with respect
//! to guest threads (all run on one host thread), so these primitives need
//! no guest-visible atomic protocol. These address-keyed helpers are not
//! exposed by the current built-in DLL tables. Their lock-word updates do
//! not yet propagate every guest-memory fault; they are outside the admitted
//! guest API profile.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use super::layout::offsets;
use super::memory::Mem;
use super::nt::status::*;
use super::objects::{ObjId, Object};
use super::process::Proc;

/// `WAIT_ABANDONED_0`.
pub const WAIT_ABANDONED_0: u64 = 0x80;
/// `WAIT_IO_COMPLETION` (`STATUS_USER_APC`).
pub const WAIT_IO_COMPLETION: u64 = 0xC0;
/// `WAIT_TIMEOUT` (`STATUS_TIMEOUT`).
pub const WAIT_TIMEOUT: u64 = 0x102;

/// Tag separating condition-variable keys from `WaitOnAddress` keys.
pub const CONDVAR_KEY: u64 = 1 << 63;

/// What a parked thread waits for.
#[derive(Clone, Debug)]
pub enum Wait {
    /// Kernel objects (`WaitForSingleObject`, `WaitForMultipleObjects`).
    Objects {
        /// The objects.
        objs: Vec<ObjId>,
        /// Wait for all of them.
        all: bool,
        /// Timeout.
        deadline: Option<Instant>,
        /// Alertable (user APCs end the wait).
        alertable: bool,
    },
    /// A delay (`Sleep`, `SleepEx`).
    Sleep {
        /// When it ends (`None`: forever).
        deadline: Option<Instant>,
        /// Alertable.
        alertable: bool,
    },
    /// A wake on an address key (`WaitOnAddress`, condition variables).
    Address {
        /// The key.
        key: u64,
        /// Timeout.
        deadline: Option<Instant>,
    },
    /// Ownership of the critical section at `addr`.
    CritSec {
        /// The `CRITICAL_SECTION`.
        addr: u64,
    },
    /// The SRW lock at `addr`.
    Srw {
        /// The `SRWLOCK`.
        addr: u64,
        /// Exclusive (otherwise shared) mode.
        exclusive: bool,
    },
}

impl Wait {
    /// The wait's deadline.
    pub fn deadline(&self) -> Option<Instant> {
        match self {
            Wait::Objects { deadline, .. }
            | Wait::Sleep { deadline, .. }
            | Wait::Address { deadline, .. } => *deadline,
            Wait::CritSec { .. } | Wait::Srw { .. } => None,
        }
    }
}

/// An SRW lock's state.
#[derive(Clone, Copy, Debug, Default)]
struct SrwState {
    exclusive: Option<u32>,
    shared: u32,
    waiting_exclusive: u32,
}

/// Address-keyed synchronization state.
#[derive(Debug, Default)]
pub struct SyncState {
    /// Threads parked on each address key, in arrival order.
    waiters: HashMap<u64, VecDeque<u32>>,
    /// Threads whose address wait was woken.
    woken: HashSet<u32>,
    /// Threads parked on each critical section.
    cs_waiters: HashMap<u64, u32>,
    /// SRW locks.
    srw: HashMap<u64, SrwState>,
}

impl SyncState {
    /// Wakes up to `count` threads parked on `key` (all for `usize::MAX`).
    pub fn wake(&mut self, key: u64, count: usize) {
        if let Some(q) = self.waiters.get_mut(&key) {
            for _ in 0..count {
                match q.pop_front() {
                    Some(tid) => {
                        self.woken.insert(tid);
                    }
                    None => break,
                }
            }
            if q.is_empty() {
                self.waiters.remove(&key);
            }
        }
    }

    /// Forgets `tid`'s address wait (it timed out or its thread ended).
    fn cancel(&mut self, key: u64, tid: u32) {
        if let Some(q) = self.waiters.get_mut(&key) {
            q.retain(|&t| t != tid);
            if q.is_empty() {
                self.waiters.remove(&key);
            }
        }
        self.woken.remove(&tid);
    }
}

/// Records that `tid` parks on `wait` (queues address waiters).
pub fn on_block(p: &mut Proc, tid: u32, wait: &Wait) {
    match wait {
        Wait::Address { key, .. } => {
            p.sync.woken.remove(&tid);
            p.sync.waiters.entry(*key).or_default().push_back(tid);
        }
        Wait::CritSec { addr } => {
            *p.sync.cs_waiters.entry(*addr).or_default() += 1;
            write_cs_lock_count(p, *addr);
        }
        Wait::Srw {
            addr,
            exclusive: true,
        } => {
            p.sync.srw.entry(*addr).or_default().waiting_exclusive += 1;
            write_srw(p, *addr);
        }
        _ => {}
    }
}

/// Forgets a wait whose thread is terminated while parked.
pub fn on_cancel(p: &mut Proc, tid: u32, wait: &Wait) {
    match wait {
        Wait::Address { key, .. } => p.sync.cancel(*key, tid),
        Wait::CritSec { addr } => {
            if let Some(n) = p.sync.cs_waiters.get_mut(addr) {
                *n = n.saturating_sub(1);
            }
            write_cs_lock_count(p, *addr);
        }
        Wait::Srw {
            addr,
            exclusive: true,
        } => {
            if let Some(s) = p.sync.srw.get_mut(addr) {
                s.waiting_exclusive = s.waiting_exclusive.saturating_sub(1);
            }
            write_srw(p, *addr);
        }
        _ => {}
    }
}

fn expired(deadline: Option<Instant>, now: Instant) -> bool {
    deadline.is_some_and(|d| now >= d)
}

/// Whether object `id` is signaled for thread `tid`.
fn signaled(p: &Proc, id: ObjId, tid: u32) -> bool {
    match p.objects.obj(id) {
        Some(Object::Event { signaled, .. }) | Some(Object::Timer { signaled, .. }) => *signaled,
        Some(Object::Mutex { owner, .. }) => owner.is_none() || *owner == Some(tid),
        Some(Object::Semaphore { count, .. }) => *count > 0,
        Some(Object::Thread { exit_code, .. }) | Some(Object::Process { exit_code, .. }) => {
            exit_code.is_some()
        }
        Some(Object::CompletionPort { queue }) => !queue.is_empty(),
        // Files and console handles are signaled when no I/O is pending,
        // which is always here (I/O completes synchronously).
        Some(Object::File(_) | Object::Console(_) | Object::Null | Object::Pipe { .. }) => true,
        Some(Object::Mapping { .. } | Object::Opaque(_)) | None => false,
    }
}

/// Consumes a signaled object for `tid`; true if a mutex was abandoned.
fn consume(p: &mut Proc, id: ObjId, tid: u32) -> bool {
    match p.objects.obj_mut(id) {
        Some(Object::Event { manual, signaled }) if !*manual => {
            *signaled = false;
            false
        }
        Some(Object::Timer {
            manual, signaled, ..
        }) if !*manual => {
            *signaled = false;
            false
        }
        Some(Object::Mutex {
            owner,
            count,
            abandoned,
        }) => {
            *owner = Some(tid);
            *count += 1;
            std::mem::take(abandoned)
        }
        Some(Object::Semaphore { count, .. }) => {
            *count -= 1;
            false
        }
        _ => false,
    }
}

/// Satisfies an object wait now if possible: the wait status, or `None`.
pub fn try_objects(p: &mut Proc, tid: u32, objs: &[ObjId], all: bool) -> Option<u64> {
    if all {
        if objs.iter().all(|&o| signaled(p, o, tid)) {
            let abandoned = objs.iter().fold(false, |a, &o| consume(p, o, tid) | a);
            return Some(if abandoned { WAIT_ABANDONED_0 } else { 0 });
        }
        return None;
    }
    let i = objs.iter().position(|&o| signaled(p, o, tid))?;
    let abandoned = consume(p, objs[i], tid);
    Some(if abandoned { WAIT_ABANDONED_0 } else { 0 } + i as u64)
}

/// Polls `tid`'s wait at `now`: its completion status, or `None` to keep
/// waiting. `apc_pending` reports queued user APCs for alertable waits.
pub fn poll(p: &mut Proc, tid: u32, wait: &Wait, now: Instant, apc_pending: bool) -> Option<u64> {
    match wait {
        Wait::Objects {
            objs,
            all,
            deadline,
            alertable,
        } => {
            if let Some(s) = try_objects(p, tid, objs, *all) {
                return Some(s);
            }
            if *alertable && apc_pending {
                return Some(WAIT_IO_COMPLETION);
            }
            expired(*deadline, now).then_some(WAIT_TIMEOUT)
        }
        Wait::Sleep {
            deadline,
            alertable,
        } => {
            if *alertable && apc_pending {
                return Some(WAIT_IO_COMPLETION);
            }
            expired(*deadline, now).then_some(0)
        }
        Wait::Address { key, deadline } => {
            if p.sync.woken.remove(&tid) {
                return Some(u64::from(STATUS_SUCCESS));
            }
            if expired(*deadline, now) {
                p.sync.cancel(*key, tid);
                return Some(u64::from(STATUS_TIMEOUT));
            }
            None
        }
        Wait::CritSec { addr } => {
            if cs_try_enter(p, *addr, tid) {
                if let Some(n) = p.sync.cs_waiters.get_mut(addr) {
                    *n = n.saturating_sub(1);
                }
                write_cs_lock_count(p, *addr);
                Some(0)
            } else {
                None
            }
        }
        Wait::Srw { addr, exclusive } => {
            let s = p.sync.srw.entry(*addr).or_default();
            let ok = if *exclusive {
                s.exclusive.is_none() && s.shared == 0
            } else {
                s.exclusive.is_none() && s.waiting_exclusive == 0
            };
            if !ok {
                return None;
            }
            if *exclusive {
                s.waiting_exclusive = s.waiting_exclusive.saturating_sub(1);
                s.exclusive = Some(tid);
            } else {
                s.shared += 1;
            }
            write_srw(p, *addr);
            Some(0)
        }
    }
}

// ------------------------------------------------------ critical sections

/// `CRITICAL_SECTION` field offsets: (LockCount, RecursionCount,
/// OwningThread) — (4, 8, 0xC) on x86, (8, 0xC, 0x10) on 64-bit
/// (winnt.h, verified).
fn cs_fields(p: &Proc) -> (u64, u64, u64) {
    if p.arch.is64() {
        (8, 0xC, 0x10)
    } else {
        (4, 8, 0xC)
    }
}

/// Writes `LockCount` in the Windows Vista+ encoding: -1 when free;
/// when held, bit 0 clear and `-(waiters) * 4 - 2`.
fn write_cs_lock_count(p: &mut Proc, addr: u64) {
    let (lock, _, owner) = cs_fields(p);
    let held = p.space.ptr(addr + owner, p.arch.ptr_size()).unwrap_or(0) != 0;
    let waiters = p.sync.cs_waiters.get(&addr).copied().unwrap_or(0);
    let v: i32 = if held { -2 - 4 * waiters as i32 } else { -1 };
    let _ = p.space.w32(addr + lock, v as u32);
}

/// Enters the critical section at `addr` for `tid` if it is free or
/// already `tid`'s; false if another thread owns it.
pub fn cs_try_enter(p: &mut Proc, addr: u64, tid: u32) -> bool {
    let (_, rec, owner) = cs_fields(p);
    let psize = p.arch.ptr_size();
    let current = p.space.ptr(addr + owner, psize).unwrap_or(0);
    if current != 0 && current != u64::from(tid) {
        return false;
    }
    let count = if current == 0 {
        1
    } else {
        p.space.u32(addr + rec).unwrap_or(0).wrapping_add(1)
    };
    let _ = p.space.wptr(addr + owner, psize, u64::from(tid));
    let _ = p.space.w32(addr + rec, count);
    write_cs_lock_count(p, addr);
    true
}

/// Leaves the critical section at `addr`; true if `tid` owned it.
pub fn cs_leave(p: &mut Proc, addr: u64, tid: u32) -> bool {
    let (_, rec, owner) = cs_fields(p);
    let psize = p.arch.ptr_size();
    if p.space.ptr(addr + owner, psize).unwrap_or(0) != u64::from(tid) {
        return false;
    }
    let count = p.space.u32(addr + rec).unwrap_or(1).saturating_sub(1);
    let _ = p.space.w32(addr + rec, count);
    if count == 0 {
        let _ = p.space.wptr(addr + owner, psize, 0);
    }
    write_cs_lock_count(p, addr);
    true
}

/// Initializes a critical section (`InitializeCriticalSection`): free,
/// no debug information (`DebugInfo` = -1, as Windows 8 and later store
/// when no debug record is allocated).
pub fn cs_init(p: &mut Proc, addr: u64, spin: u64) -> Result<(), super::memory::MemFault> {
    let psize = p.arch.ptr_size();
    let size = if p.arch.is64() { 0x28 } else { 0x18 };
    p.space.wr(addr, &vec![0u8; size])?;
    p.space.wptr(addr, psize, p.arch.ptr(u64::MAX))?;
    let (lock, _, _) = cs_fields(p);
    p.space.w32(addr + lock, u32::MAX)?;
    let spin_off = if p.arch.is64() { 0x20 } else { 0x14 };
    p.space.wptr(addr + spin_off, psize, spin)?;
    Ok(())
}

// --------------------------------------------------------------- SRW locks

/// Writes an SRW lock word: 0 free; bit 0 set while held; shared owners
/// counted from bit 4; bit 1 while exclusive waiters are queued.
fn write_srw(p: &mut Proc, addr: u64) {
    let s = p.sync.srw.get(&addr).copied().unwrap_or_default();
    let mut v = 0u64;
    if s.exclusive.is_some() {
        v = 1;
    } else if s.shared > 0 {
        v = u64::from(s.shared) << 4 | 1;
    }
    if s.waiting_exclusive > 0 {
        v |= 2;
    }
    let _ = p.space.wptr(addr, p.arch.ptr_size(), v);
    if s.exclusive.is_none() && s.shared == 0 && s.waiting_exclusive == 0 {
        p.sync.srw.remove(&addr);
    }
}

/// Tries to acquire an SRW lock; true on success.
pub fn srw_try(p: &mut Proc, addr: u64, tid: u32, exclusive: bool) -> bool {
    poll(
        p,
        tid,
        &Wait::Srw { addr, exclusive },
        Instant::now(),
        false,
    )
    .is_some()
}

/// Releases an SRW lock held in `exclusive` or shared mode.
pub fn srw_release(p: &mut Proc, addr: u64, exclusive: bool) {
    let s = p.sync.srw.entry(addr).or_default();
    if exclusive {
        s.exclusive = None;
    } else {
        s.shared = s.shared.saturating_sub(1);
    }
    write_srw(p, addr);
}

/// The SRW mode `tid` holds on `addr`: `Some(true)` exclusive,
/// `Some(false)` shared (ownership of shared locks is not tracked per
/// thread), `None` not held.
pub fn srw_held(p: &Proc, addr: u64, tid: u32) -> Option<bool> {
    let s = p.sync.srw.get(&addr)?;
    if s.exclusive == Some(tid) {
        Some(true)
    } else if s.shared > 0 {
        Some(false)
    } else {
        None
    }
}

/// `TEB` offset of `LastErrorValue`, used by waits that report errors.
pub fn last_error_offset(p: &Proc) -> u64 {
    offsets(p.arch).teb_last_error
}

//! Fast user-space mutexes (`kernel/futex/`): wait queues, requeueing,
//! priority-inheritance ownership, and robust-list cleanup at thread exit.
//!
//! A waiting thread sleeps in its system call (see [`wait`](super::wait))
//! with a queue entry here. A waker removes the entry and marks the
//! thread's [`Blocked::woken`](super::wait::Blocked::woken), so the woken
//! call returns 0 whatever else happened meanwhile, as `futex_unqueue`
//! reports in the kernel. Queues are FIFO: every emulated thread has the
//! same priority, so the kernel's priority-ordered `plist` degenerates to
//! arrival order.
//!
//! Keys follow `get_futex_key`: a private futex (`FUTEX_PRIVATE_FLAG`) is
//! identified by its address in the process; a shared one by the mapped
//! object, which in one address space without aliased shared mappings is
//! also its address. Private and shared keys never match each other, as
//! in the kernel.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use super::abi::errno::Errno;
use super::abi::errno_table::*;
use super::process::{ProcState, Threads};
use super::wait::Resume;
use crate::error::MemoryAccessKind;

/// `FUTEX_WAITERS`.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
/// `FUTEX_OWNER_DIED`.
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// `FUTEX_TID_MASK`.
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// `FUTEX_BITSET_MATCH_ANY`.
pub const BITSET_MATCH_ANY: u32 = 0xffff_ffff;
/// `ROBUST_LIST_LIMIT`: entries walked at exit before giving up.
const ROBUST_LIST_LIMIT: usize = 2048;

/// A futex key (`union futex_key`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FutexKey {
    /// The futex word's address.
    pub addr: u64,
    /// A shared (`FLAGS_SHARED`) rather than a process-private key.
    pub shared: bool,
}

/// `get_futex_key` for a 32-bit futex: the address must be naturally
/// aligned (`EINVAL`) and a user address (`EFAULT`); a shared key needs the
/// page mapped, writable for `write` access or at least readable
/// otherwise (`get_user_pages_fast`, `EFAULT`).
pub fn key(p: &ProcState, uaddr: u64, shared: bool, write: bool) -> Result<FutexKey, Errno> {
    if uaddr % 4 != 0 {
        return Err(Errno(EINVAL));
    }
    if uaddr
        .checked_add(4)
        .is_none_or(|end| end > p.abi.task_size())
    {
        return Err(Errno(EFAULT));
    }
    if shared {
        let readable = p.space.probe(uaddr, 4, MemoryAccessKind::Read).is_ok();
        let writable = p.space.probe(uaddr, 4, MemoryAccessKind::Write).is_ok();
        if !(writable || (!write && readable)) {
            return Err(Errno(EFAULT));
        }
    }
    Ok(FutexKey {
        addr: uaddr,
        shared,
    })
}

/// A queued waiter (`struct futex_q`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Waiter {
    tid: i32,
    /// `FUTEX_WAIT_BITSET` mask.
    bitset: u32,
    /// A `FUTEX_LOCK_PI` waiter (`pi_state`/`rt_waiter` set).
    pi: bool,
    /// Position in a `futex_waitv` vector (0 for a single futex).
    index: u32,
}

/// The progress record of a thread sleeping in a futex call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FutexWait {
    /// What the thread waits for.
    pub kind: FutexWaitKind,
    /// The timeout, if any.
    pub deadline: Option<Instant>,
    /// Highest index of a woken entry (`futex_unqueue_multiple`).
    pub woken: Option<u32>,
}

/// The kinds of futex sleep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FutexWaitKind {
    /// `FUTEX_WAIT`/`FUTEX_WAIT_BITSET`/`futex_wait`, with what
    /// `futex_wait_restart` needs.
    Wait {
        /// The futex word.
        uaddr: u64,
        /// The expected value.
        val: u32,
        /// The wait mask.
        bitset: u32,
        /// A shared key.
        shared: bool,
    },
    /// `FUTEX_LOCK_PI`/`FUTEX_LOCK_PI2`.
    LockPi,
    /// `futex_waitv`.
    Vector,
}

/// Priority-inheritance state of a contended PI futex (`futex_pi_state`),
/// kept while it has waiters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PiState {
    owner: i32,
}

/// The process's futex wait queues.
#[derive(Clone, Debug, Default)]
pub struct FutexTable {
    queues: HashMap<FutexKey, VecDeque<Waiter>>,
    pi: HashMap<FutexKey, PiState>,
}

/// Marks a sleeping thread's futex entry `index` woken.
fn mark_woken(th: &mut Threads<'_>, tid: i32, index: u32) {
    if let Some(t) = th.get_mut(tid)
        && let Some(b) = t.blocked.as_mut()
    {
        b.woken = true;
        if let Resume::Futex(fw) = &mut b.resume {
            fw.woken = Some(fw.woken.map_or(index, |w| w.max(index)));
        }
    }
}

/// Reads a futex word.
pub fn get_u32(p: &ProcState, addr: u64) -> Result<u32, Errno> {
    let mut b = [0u8; 4];
    p.space.read(addr, &mut b).map_err(|_| Errno(EFAULT))?;
    Ok(u32::from_le_bytes(b))
}

/// Writes a futex word (the emulated CPU runs one thread at a time, so a
/// read followed by a write is an atomic compare-and-exchange).
pub fn put_u32(p: &ProcState, addr: u64, v: u32) -> Result<(), Errno> {
    p.space
        .write(addr, &v.to_le_bytes())
        .map_err(|_| Errno(EFAULT))
}

impl FutexTable {
    fn queue(&mut self, key: FutexKey) -> &mut VecDeque<Waiter> {
        self.queues.entry(key).or_default()
    }

    fn prune(&mut self, key: FutexKey) {
        if self.queues.get(&key).is_some_and(VecDeque::is_empty) {
            self.queues.remove(&key);
            self.pi.remove(&key);
        }
    }

    /// Queues thread `tid` on `key` (`futex_queue`).
    pub fn enqueue(&mut self, key: FutexKey, tid: i32, bitset: u32, index: u32) {
        self.queue(key).push_back(Waiter {
            tid,
            bitset,
            pi: false,
            index,
        });
    }

    /// Removes every entry of thread `tid` (`futex_unqueue`), wherever a
    /// requeue moved it. Returns whether one was still queued.
    pub fn unqueue(&mut self, tid: i32) -> bool {
        let mut found = false;
        let mut emptied = Vec::new();
        for (key, q) in self.queues.iter_mut() {
            let before = q.len();
            q.retain(|w| w.tid != tid);
            found |= q.len() != before;
            if q.is_empty() {
                emptied.push(*key);
            }
        }
        for key in emptied {
            self.prune(key);
        }
        found
    }

    /// Whether thread `tid` has an entry on any queue.
    pub fn is_queued(&self, tid: i32) -> bool {
        self.queues.values().any(|q| q.iter().any(|w| w.tid == tid))
    }

    /// `futex_wake`: wakes up to `nr_wake` waiters whose bitset intersects
    /// `bitset`, in order. As in the kernel the count is tested after each
    /// wake, so any `nr_wake <= 1` wakes one waiter when there is one. A
    /// matching PI waiter is `EINVAL`.
    pub fn wake(
        &mut self,
        th: &mut Threads<'_>,
        key: FutexKey,
        nr_wake: i32,
        bitset: u32,
    ) -> Result<u64, Errno> {
        let Some(q) = self.queues.get_mut(&key) else {
            return Ok(0);
        };
        let mut woken = Vec::new();
        let mut i = 0;
        let mut result = Ok(());
        while i < q.len() {
            let w = q[i];
            if w.pi {
                result = Err(Errno(EINVAL));
                break;
            }
            if w.bitset & bitset == 0 {
                i += 1;
                continue;
            }
            q.remove(i);
            woken.push(w);
            if woken.len() as i64 >= i64::from(nr_wake) {
                break;
            }
        }
        self.prune(key);
        for w in &woken {
            mark_woken(th, w.tid, w.index);
        }
        result.map(|()| woken.len() as u64)
    }

    /// `futex_requeue` (not PI): wakes `nr_wake` waiters of `key1` and moves
    /// up to `nr_requeue` more to `key2`, returning how many were woken or
    /// moved. A PI waiter is `EINVAL`.
    pub fn requeue(
        &mut self,
        th: &mut Threads<'_>,
        key1: FutexKey,
        key2: FutexKey,
        nr_wake: i32,
        nr_requeue: i32,
    ) -> Result<u64, Errno> {
        let mut count: i64 = 0;
        let mut woken = Vec::new();
        let mut moved = Vec::new();
        let mut result = Ok(());
        if let Some(q) = self.queues.get_mut(&key1) {
            let mut kept = VecDeque::new();
            while let Some(w) = q.pop_front() {
                if count - i64::from(nr_wake) >= i64::from(nr_requeue) || result.is_err() {
                    kept.push_back(w);
                    continue;
                }
                if w.pi {
                    result = Err(Errno(EINVAL));
                    kept.push_back(w);
                    continue;
                }
                count += 1;
                if count <= i64::from(nr_wake) {
                    woken.push(w);
                } else {
                    moved.push(w);
                }
            }
            *q = kept;
        }
        self.prune(key1);
        if !moved.is_empty() {
            self.queue(key2).extend(moved);
        }
        for w in &woken {
            mark_woken(th, w.tid, w.index);
        }
        result.map(|()| count as u64)
    }

    // ------------------------------------------------------------- PI

    /// Queues `tid` as a waiter for PI futex `key` owned by `owner`
    /// (`__futex_queue` with `pi_state` attached).
    pub fn enqueue_pi(&mut self, key: FutexKey, tid: i32, owner: i32) {
        self.pi.entry(key).or_insert(PiState { owner });
        self.queue(key).push_back(Waiter {
            tid,
            bitset: BITSET_MATCH_ANY,
            pi: true,
            index: 0,
        });
    }

    /// The first waiter of `key` (`futex_top_waiter`): `Some(Some(owner))`
    /// for a PI waiter with the owner its `pi_state` records, `Some(None)`
    /// for a plain waiter, `None` without waiters.
    pub fn top_waiter(&self, key: FutexKey) -> Option<Option<i32>> {
        let w = self.queues.get(&key)?.front()?;
        Some(if w.pi {
            self.pi.get(&key).map(|s| s.owner)
        } else {
            None
        })
    }

    /// `wake_futex_pi`: hands the lock to the first PI waiter, which
    /// becomes the owner (`FUTEX_WAITERS | tid` is written by the caller),
    /// and returns its TID.
    fn hand_off(&mut self, th: &mut Threads<'_>, key: FutexKey) -> Option<i32> {
        let q = self.queues.get_mut(&key)?;
        let w = q.pop_front()?;
        if let Some(s) = self.pi.get_mut(&key) {
            s.owner = w.tid;
        }
        self.prune(key);
        mark_woken(th, w.tid, 0);
        Some(w.tid)
    }
}

/// `futex_unlock_pi` for the owner `me`: with waiters the first one is
/// the new owner (`wake_futex_pi` writes `FUTEX_WAITERS | tid`); without,
/// the word becomes 0.
pub fn unlock_pi(
    p: &mut ProcState,
    th: &mut Threads<'_>,
    uaddr: u64,
    shared: bool,
    me: i32,
) -> Result<u64, Errno> {
    let uval = get_u32(p, uaddr)?;
    if uval & FUTEX_TID_MASK != me as u32 {
        return Err(Errno(EPERM));
    }
    let key = key(p, uaddr, shared, true)?;
    if let Some(top) = p.futex.queues.get(&key).and_then(|q| q.front().copied()) {
        // A plain waiter at the head, or a PI state owned by someone else,
        // is inconsistent (EINVAL).
        if !top.pi || p.futex.pi.get(&key).map(|s| s.owner) != Some(me) {
            return Err(Errno(EINVAL));
        }
        let new = p.futex.hand_off(th, key).expect("a waiter is queued");
        put_u32(p, uaddr, FUTEX_WAITERS | new as u32)?;
        return Ok(0);
    }
    put_u32(p, uaddr, 0)?;
    Ok(0)
}

/// `exit_pi_state_list`: every contended PI futex the exiting thread owns
/// passes to its first waiter, which records itself as owner keeping
/// `FUTEX_OWNER_DIED` (`fixup_pi_state_owner`).
pub fn exit_pi(p: &mut ProcState, th: &mut Threads<'_>, tid: i32) {
    let owned: Vec<FutexKey> = p
        .futex
        .pi
        .iter()
        .filter(|(_, s)| s.owner == tid)
        .map(|(k, _)| *k)
        .collect();
    for key in owned {
        if let Some(new) = p.futex.hand_off(th, key)
            && let Ok(uval) = get_u32(p, key.addr)
        {
            let _ = put_u32(
                p,
                key.addr,
                (uval & FUTEX_OWNER_DIED) | FUTEX_WAITERS | new as u32,
            );
        }
    }
}

/// The encoded operation of `FUTEX_WAKE_OP` (`futex_atomic_op_inuser`):
/// applies it to the word at `uaddr` and returns whether the comparison of
/// the old value holds. An unknown operation is `ENOSYS` before the word
/// changes; an unknown comparison is `ENOSYS` after it changed.
pub fn atomic_op(p: &ProcState, encoded: u32, uaddr: u64) -> Result<bool, Errno> {
    const FUTEX_OP_OPARG_SHIFT: u32 = 8;
    let op = (encoded & 0x7000_0000) >> 28;
    let cmp = (encoded & 0x0f00_0000) >> 24;
    let sext12 = |v: u32| ((v << 20) as i32) >> 20;
    let mut oparg = sext12((encoded & 0x00ff_f000) >> 12);
    let cmparg = sext12(encoded & 0x0000_0fff);
    if encoded & (FUTEX_OP_OPARG_SHIFT << 28) != 0 {
        // Out-of-range shifts are masked (with a kernel warning).
        oparg = 1i32.wrapping_shl((oparg & 31) as u32);
    }
    let old = get_u32(p, uaddr)? as i32;
    let new = match op {
        0 => oparg,
        1 => old.wrapping_add(oparg),
        2 => old | oparg,
        3 => old & !oparg,
        4 => old ^ oparg,
        _ => return Err(Errno(ENOSYS)),
    };
    put_u32(p, uaddr, new as u32)?;
    Ok(match cmp {
        0 => old == cmparg,
        1 => old != cmparg,
        2 => old < cmparg,
        3 => old <= cmparg,
        4 => old > cmparg,
        5 => old >= cmparg,
        _ => return Err(Errno(ENOSYS)),
    })
}

/// `handle_futex_death` for the futex at `uaddr` of exiting thread `tid`:
/// a lock it owns gets `FUTEX_OWNER_DIED` (keeping `FUTEX_WAITERS`) and,
/// unless it is a PI futex, one waiter is woken. A pending operation on a
/// futex without an owner wakes a waiter too. Returns false to stop the
/// walk (a fault).
fn futex_death(
    p: &mut ProcState,
    th: &mut Threads<'_>,
    uaddr: u64,
    tid: i32,
    pi: bool,
    pending: bool,
) -> bool {
    if uaddr % 4 != 0 {
        return false;
    }
    let Ok(uval) = get_u32(p, uaddr) else {
        return false;
    };
    let owner = uval & FUTEX_TID_MASK;
    let shared = FutexKey {
        addr: uaddr,
        shared: true,
    };
    if pending && !pi && owner == 0 {
        let _ = p.futex.wake(th, shared, 1, BITSET_MATCH_ANY);
        return true;
    }
    if owner != tid as u32 {
        return true;
    }
    if put_u32(p, uaddr, (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED).is_err() {
        return false;
    }
    if !pi && uval & FUTEX_WAITERS != 0 {
        let _ = p.futex.wake(th, shared, 1, BITSET_MATCH_ANY);
    }
    true
}

/// `exit_robust_list` for exiting thread `tid` with list head `head`
/// (`struct robust_list_head`: `list.next`, `futex_offset`,
/// `list_op_pending`; bit 0 of an entry pointer marks a PI futex).
pub fn exit_robust_list(p: &mut ProcState, th: &mut Threads<'_>, tid: i32, head: u64) {
    let read = |p: &ProcState, addr: u64| -> Option<u64> {
        let mut b = [0u8; 8];
        p.space.read(addr, &mut b).ok()?;
        Some(u64::from_le_bytes(b))
    };
    let Some(first) = read(p, head) else {
        return;
    };
    let Some(offset) = read(p, head + 8) else {
        return;
    };
    let Some(pending_raw) = read(p, head + 16) else {
        return;
    };
    let (pending, pending_pi) = (pending_raw & !1, pending_raw & 1 != 0);
    let (mut entry, mut pi) = (first & !1, first & 1 != 0);
    let mut limit = ROBUST_LIST_LIMIT;
    while entry != head {
        let next = read(p, entry);
        if entry != pending && !futex_death(p, th, entry.wrapping_add(offset), tid, pi, false) {
            return;
        }
        let Some(next) = next else {
            return;
        };
        (entry, pi) = (next & !1, next & 1 != 0);
        limit -= 1;
        if limit == 0 {
            break;
        }
    }
    if pending != 0 {
        futex_death(p, th, pending.wrapping_add(offset), tid, pending_pi, true);
    }
}

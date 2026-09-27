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
//! no guest-visible atomic protocol. Guest lock storage is logically opaque:
//! the synthetic encodings below are not native Windows private layouts.
//! Every transition writes guest storage transactionally before host state
//! publication. AddressSpace::write checks/materializes every page before any
//! byte write; mappings must remain stable under the serialized-process contract.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use super::layout::offsets;
use super::memory::{Mem, MemFault};
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
pub const CONDVAR_KEY: u128 = 1 << 64;

/// Checked memory failure or fail-closed policy for invalid/undefined lock use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// Preserve guest address and access direction.
    Fault(MemFault),
    /// Invalid ownership, storage, alignment, or arithmetic; native status unknown.
    Invalid(&'static str),
}

impl From<MemFault> for SyncError {
    fn from(value: MemFault) -> Self {
        Self::Fault(value)
    }
}

impl From<SyncError> for super::hle::ApiErr {
    fn from(value: SyncError) -> Self {
        match value {
            SyncError::Fault(fault) => Self::Fault(fault),
            SyncError::Invalid(message) => {
                Self::Internal(format!("invalid synchronization operation: {message}"))
            }
        }
    }
}

/// What a parked thread waits for.
#[derive(Clone, Debug, PartialEq, Eq)]
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
        key: u128,
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
#[derive(Clone, Debug, Default)]
struct SrwState {
    exclusive: Option<u32>,
    shared: HashSet<u32>,
    waiting_exclusive: u32,
}

/// Address-keyed synchronization state.
#[derive(Debug, Default)]
pub struct SyncState {
    /// Threads parked on each address key, in arrival order.
    waiters: HashMap<u128, VecDeque<u32>>,
    /// Threads whose address wait was woken.
    woken: HashSet<u32>,
    /// Threads parked on each critical section.
    cs_waiters: HashMap<u64, u32>,
    /// SRW locks.
    srw: HashMap<u64, SrwState>,
    /// Explicitly initialized critical sections; use after delete is rejected.
    initialized_cs: HashSet<u64>,
    /// One registration per parked thread, including retained object IDs.
    parked: HashMap<u32, Wait>,
    /// Successful poll already consumed/dequeued its lock registration.
    completed: HashSet<u32>,
}

impl SyncState {
    /// Wakes up to `count` threads parked on `key` (all for `usize::MAX`).
    pub fn wake(&mut self, key: u128, count: usize) {
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
    fn cancel(&mut self, key: u128, tid: u32) {
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
pub fn on_block(p: &mut Proc, tid: u32, wait: &Wait) -> Result<(), SyncError> {
    if p.sync.parked.contains_key(&tid) {
        return Err(SyncError::Invalid("thread already has a registered wait"));
    }
    match wait {
        Wait::Objects { objs, .. } => {
            validate_objects(p, objs)?;
            p.objects.retain_many(objs).map_err(SyncError::Invalid)?;
        }
        Wait::Address { key, .. } => {
            p.sync.woken.remove(&tid);
            p.sync.waiters.entry(*key).or_default().push_back(tid);
        }
        Wait::CritSec { addr } => {
            let n = p
                .sync
                .cs_waiters
                .get(addr)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(SyncError::Invalid("critical-section waiter overflow"))?;
            update_cs_waiters(p, *addr, n)?;
        }
        Wait::Srw {
            addr,
            exclusive: true,
        } => {
            let mut state = srw_state(p, *addr)?;
            state.waiting_exclusive = state
                .waiting_exclusive
                .checked_add(1)
                .ok_or(SyncError::Invalid("SRW waiter overflow"))?;
            commit_srw(p, *addr, state)?;
        }
        _ => {}
    }
    p.sync.parked.insert(tid, wait.clone());
    p.sync.completed.remove(&tid);
    Ok(())
}

/// Releases a registered wait after completion or cancellation. Repeated
/// cleanup is harmless; a different wait cannot cancel this thread's entry.
pub fn on_cancel(p: &mut Proc, tid: u32, wait: &Wait) -> Result<(), SyncError> {
    match p.sync.parked.get(&tid) {
        None => return Ok(()),
        Some(registered) if registered != wait => {
            return Err(SyncError::Invalid(
                "wait cancellation registration mismatch",
            ));
        }
        _ => {}
    }
    if p.sync.completed.contains(&tid) {
        if let Some(Wait::Objects { objs, .. }) = p.sync.parked.remove(&tid) {
            for obj in objs {
                p.objects.release(obj);
            }
        } else {
            p.sync.parked.remove(&tid);
        }
        p.sync.completed.remove(&tid);
        return Ok(());
    }
    match wait {
        Wait::Objects { .. } => {
            if let Some(Wait::Objects { objs, .. }) = p.sync.parked.get(&tid) {
                for obj in objs.clone() {
                    p.objects.release(obj);
                }
            }
        }
        Wait::Address { key, .. } => p.sync.cancel(*key, tid),
        Wait::CritSec { addr } => {
            let n = p
                .sync
                .cs_waiters
                .get(addr)
                .copied()
                .unwrap_or(0)
                .checked_sub(1)
                .ok_or(SyncError::Invalid("unregistered critical-section wait"))?;
            update_cs_waiters(p, *addr, n)?;
        }
        Wait::Srw {
            addr,
            exclusive: true,
        } => {
            let mut state = srw_state(p, *addr)?;
            state.waiting_exclusive = state
                .waiting_exclusive
                .checked_sub(1)
                .ok_or(SyncError::Invalid("unregistered SRW wait"))?;
            commit_srw(p, *addr, state)?;
        }
        _ => {}
    }
    p.sync.parked.remove(&tid);
    Ok(())
}

/// Process termination drops every wait pin without touching obsolete guest
/// lock storage. Ownership and queues cease to exist with the process; the
/// retained address space is diagnostic state, not a live lock protocol.
pub fn on_process_exit(p: &mut Proc) {
    let state = std::mem::take(&mut p.sync);
    for wait in state.parked.into_values() {
        if let Wait::Objects { objs, .. } = wait {
            for obj in objs {
                p.objects.release(obj);
            }
        }
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

/// Checks the complete set before consuming anything. Public builders also
/// validate handles/access rights; duplicate object aliases are unsupported.
fn validate_objects(p: &Proc, objs: &[ObjId]) -> Result<(), SyncError> {
    if objs.is_empty() || objs.len() > 64 {
        return Err(SyncError::Invalid("invalid object wait count"));
    }
    let mut distinct = HashSet::with_capacity(objs.len());
    for &id in objs {
        if !distinct.insert(id) {
            return Err(SyncError::Invalid("duplicate object in wait set"));
        }
        let object = p
            .objects
            .obj(id)
            .ok_or(SyncError::Invalid("wait object disappeared"))?;
        if let Object::Mutex { owner, count, .. } = object {
            if owner.is_none() != (*count == 0) {
                return Err(SyncError::Invalid("corrupt mutex ownership/recursion"));
            }
        }
    }
    Ok(())
}

fn validate_consumption(p: &Proc, id: ObjId) -> Result<(), SyncError> {
    if let Some(Object::Mutex { count, .. }) = p.objects.obj(id) {
        count
            .checked_add(1)
            .ok_or(SyncError::Invalid("mutex recursion overflow"))?;
    }
    Ok(())
}

/// Satisfies an object wait now if possible: the wait status, or `None`.
/// Wait-all errors cannot partially consume earlier signaled objects. Public
/// Microsoft docs permit the whole abandoned-status range for wait-all; this
/// profile returns its base, not a claimed native abandoned-mutex index.
pub fn try_objects(
    p: &mut Proc,
    tid: u32,
    objs: &[ObjId],
    all: bool,
) -> Result<Option<u64>, SyncError> {
    validate_objects(p, objs)?;
    if all {
        if objs.iter().all(|&o| signaled(p, o, tid)) {
            for &id in objs {
                validate_consumption(p, id)?;
            }
            let abandoned = objs.iter().fold(false, |a, &o| consume(p, o, tid) | a);
            return Ok(Some(if abandoned { WAIT_ABANDONED_0 } else { 0 }));
        }
        return Ok(None);
    }
    let Some(i) = objs.iter().position(|&o| signaled(p, o, tid)) else {
        return Ok(None);
    };
    validate_consumption(p, objs[i])?;
    let abandoned = consume(p, objs[i], tid);
    Ok(Some(
        if abandoned { WAIT_ABANDONED_0 } else { 0 } + i as u64,
    ))
}

/// Polls `tid`'s wait at `now`: its completion status, or `None` to keep
/// waiting. `apc_pending` reports queued user APCs for alertable waits.
pub fn poll(
    p: &mut Proc,
    tid: u32,
    wait: &Wait,
    now: Instant,
    apc_pending: bool,
) -> Result<Option<u64>, SyncError> {
    if p.sync.completed.contains(&tid) {
        return Err(SyncError::Invalid(
            "completed wait must be cleaned up before polling",
        ));
    }
    if p.sync
        .parked
        .get(&tid)
        .is_some_and(|registered| registered != wait)
    {
        return Err(SyncError::Invalid("wait poll registration mismatch"));
    }
    let result = poll_inner(p, tid, wait, now, apc_pending)?;
    if result.is_some() && p.sync.parked.contains_key(&tid) {
        p.sync.completed.insert(tid);
    }
    Ok(result)
}

fn poll_inner(
    p: &mut Proc,
    tid: u32,
    wait: &Wait,
    now: Instant,
    apc_pending: bool,
) -> Result<Option<u64>, SyncError> {
    Ok(match wait {
        Wait::Objects {
            objs,
            all,
            deadline,
            alertable,
        } => {
            if let Some(s) = try_objects(p, tid, objs, *all)? {
                return Ok(Some(s));
            }
            if *alertable && apc_pending {
                return Ok(Some(WAIT_IO_COMPLETION));
            }
            expired(*deadline, now).then_some(WAIT_TIMEOUT)
        }
        Wait::Sleep {
            deadline,
            alertable,
        } => {
            if *alertable && apc_pending {
                return Ok(Some(WAIT_IO_COMPLETION));
            }
            expired(*deadline, now).then_some(0)
        }
        Wait::Address { key, deadline } => {
            if p.sync.woken.remove(&tid) {
                return Ok(Some(u64::from(STATUS_SUCCESS)));
            }
            if expired(*deadline, now) {
                p.sync.cancel(*key, tid);
                return Ok(Some(u64::from(STATUS_TIMEOUT)));
            }
            None
        }
        Wait::CritSec { addr } => {
            let n = p
                .sync
                .cs_waiters
                .get(addr)
                .copied()
                .unwrap_or(0)
                .checked_sub(1)
                .ok_or(SyncError::Invalid("unregistered critical-section poll"))?;
            if cs_acquire(p, *addr, tid, n)? {
                Some(0)
            } else {
                None
            }
        }
        Wait::Srw { addr, exclusive } => {
            let mut s = srw_state(p, *addr)?;
            let ok = if *exclusive {
                s.exclusive.is_none() && s.shared.is_empty()
            } else {
                s.exclusive.is_none() && s.waiting_exclusive == 0
            };
            if !ok {
                return Ok(None);
            }
            if *exclusive {
                s.waiting_exclusive = s
                    .waiting_exclusive
                    .checked_sub(1)
                    .ok_or(SyncError::Invalid("unregistered SRW poll"))?;
                s.exclusive = Some(tid);
            } else {
                if !s.shared.insert(tid) {
                    return Err(SyncError::Invalid("recursive shared SRW acquisition"));
                }
            }
            commit_srw(p, *addr, s)?;
            Some(0)
        }
    })
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

/// Validated storage extent and natural pointer alignment. Misuse diagnostics
/// are policy; native behavior for malformed objects is not an oracle here.
fn storage(p: &Proc, addr: u64, size: u64) -> Result<(), SyncError> {
    if addr == 0 || addr % p.arch.ptr_size() != 0 || addr.checked_add(size).is_none() {
        return Err(SyncError::Invalid(
            "unaligned/null/overflowing synchronization storage",
        ));
    }
    if !p.arch.is64() && addr.checked_add(size).is_none_or(|end| end > 1 << 32) {
        return Err(SyncError::Invalid(
            "synchronization storage exceeds guest pointer width",
        ));
    }
    Ok(())
}

fn cs_size(p: &Proc) -> usize {
    if p.arch.is64() { 0x28 } else { 0x18 }
}
fn get32(bytes: &[u8], at: u64) -> u32 {
    u32::from_le_bytes(bytes[at as usize..at as usize + 4].try_into().unwrap())
}
fn getptr(bytes: &[u8], at: u64, size: u64) -> u64 {
    let mut value = [0; 8];
    value[..size as usize].copy_from_slice(&bytes[at as usize..(at + size) as usize]);
    u64::from_le_bytes(value)
}
fn put32(bytes: &mut [u8], at: u64, value: u32) {
    bytes[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
}
fn putptr(bytes: &mut [u8], at: u64, size: u64, value: u64) {
    bytes[at as usize..(at + size) as usize].copy_from_slice(&value.to_le_bytes()[..size as usize]);
}

fn cs_image(p: &Proc, addr: u64) -> Result<Vec<u8>, SyncError> {
    storage(p, addr, cs_size(p) as u64)?;
    if !p.sync.initialized_cs.contains(&addr) {
        return Err(SyncError::Invalid("uninitialized/deleted critical section"));
    }
    let bytes = p.space.bytes(addr, cs_size(p))?;
    let (_, rec, owner) = cs_fields(p);
    let recursion = get32(&bytes, rec);
    let owner = getptr(&bytes, owner, p.arch.ptr_size());
    if (owner == 0) != (recursion == 0) || recursion > i32::MAX as u32 || owner > u32::MAX as u64 {
        return Err(SyncError::Invalid(
            "corrupt critical-section owner/recursion",
        ));
    }
    Ok(bytes)
}

fn cs_word(bytes: &mut [u8], p: &Proc, waiters: u32) -> Result<(), SyncError> {
    let (lock, _, owner) = cs_fields(p);
    let count = if getptr(bytes, owner, p.arch.ptr_size()) == 0 {
        -1i64
    } else {
        -2i64 - 4 * i64::from(waiters)
    };
    let count = i32::try_from(count)
        .map_err(|_| SyncError::Invalid("critical-section waiter encoding overflow"))?;
    put32(bytes, lock, count as u32);
    Ok(())
}

fn set_cs_waiters(p: &mut Proc, addr: u64, n: u32) {
    if n == 0 {
        p.sync.cs_waiters.remove(&addr);
    } else {
        p.sync.cs_waiters.insert(addr, n);
    }
}

fn update_cs_waiters(p: &mut Proc, addr: u64, n: u32) -> Result<(), SyncError> {
    let mut bytes = cs_image(p, addr)?;
    cs_word(&mut bytes, p, n)?;
    p.space.wr(addr, &bytes)?;
    set_cs_waiters(p, addr, n);
    Ok(())
}

fn cs_acquire(p: &mut Proc, addr: u64, tid: u32, waiters: u32) -> Result<bool, SyncError> {
    if tid == 0 {
        return Err(SyncError::Invalid("zero critical-section thread ID"));
    }
    let mut bytes = cs_image(p, addr)?;
    let (_, rec, owner) = cs_fields(p);
    let current = getptr(&bytes, owner, p.arch.ptr_size());
    if current != 0 && current != u64::from(tid) {
        return Ok(false);
    }
    let count = if current == 0 {
        1
    } else {
        get32(&bytes, rec)
            .checked_add(1)
            .filter(|n| *n <= i32::MAX as u32)
            .ok_or(SyncError::Invalid("critical-section recursion overflow"))?
    };
    putptr(&mut bytes, owner, p.arch.ptr_size(), tid.into());
    put32(&mut bytes, rec, count);
    cs_word(&mut bytes, p, waiters)?;
    p.space.wr(addr, &bytes)?;
    set_cs_waiters(p, addr, waiters);
    Ok(true)
}

pub fn cs_try_enter(p: &mut Proc, addr: u64, tid: u32) -> Result<bool, SyncError> {
    let waiters = p.sync.cs_waiters.get(&addr).copied().unwrap_or(0);
    cs_acquire(p, addr, tid, waiters)
}

pub fn cs_leave(p: &mut Proc, addr: u64, tid: u32) -> Result<bool, SyncError> {
    let mut bytes = cs_image(p, addr)?;
    let (_, rec, owner) = cs_fields(p);
    if tid == 0 || getptr(&bytes, owner, p.arch.ptr_size()) != u64::from(tid) {
        return Ok(false);
    }
    let count = get32(&bytes, rec)
        .checked_sub(1)
        .ok_or(SyncError::Invalid("critical-section recursion underflow"))?;
    put32(&mut bytes, rec, count);
    if count == 0 {
        putptr(&mut bytes, owner, p.arch.ptr_size(), 0);
    }
    cs_word(
        &mut bytes,
        p,
        p.sync.cs_waiters.get(&addr).copied().unwrap_or(0),
    )?;
    p.space.wr(addr, &bytes)?;
    Ok(true)
}

pub fn cs_recursion(p: &Proc, addr: u64, tid: u32) -> Result<u32, SyncError> {
    let bytes = cs_image(p, addr)?;
    let (_, rec, owner) = cs_fields(p);
    if tid == 0 || getptr(&bytes, owner, p.arch.ptr_size()) != u64::from(tid) {
        return Err(SyncError::Invalid("critical section not owned by caller"));
    }
    Ok(get32(&bytes, rec))
}

pub fn cs_init(p: &mut Proc, addr: u64, spin: u64) -> Result<(), SyncError> {
    storage(p, addr, cs_size(p) as u64)?;
    if p.sync.initialized_cs.contains(&addr) {
        return Err(SyncError::Invalid(
            "critical section reinitialization without delete",
        ));
    }
    let mut bytes = vec![0u8; cs_size(p)];
    putptr(&mut bytes, 0, p.arch.ptr_size(), p.arch.ptr(u64::MAX));
    put32(&mut bytes, cs_fields(p).0, u32::MAX);
    putptr(
        &mut bytes,
        if p.arch.is64() { 0x20 } else { 0x14 },
        p.arch.ptr_size(),
        // The current Windows processor profile exposes one processor.
        // Microsoft specifies a zero effective spin count for that profile.
        {
            let _ = spin;
            0
        },
    );
    p.space.wr(addr, &bytes)?;
    p.sync.initialized_cs.insert(addr);
    Ok(())
}

pub fn cs_delete(p: &mut Proc, addr: u64) -> Result<(), SyncError> {
    let bytes = cs_image(p, addr)?;
    if getptr(&bytes, cs_fields(p).2, p.arch.ptr_size()) != 0
        || p.sync.cs_waiters.contains_key(&addr)
    {
        return Err(SyncError::Invalid("deleting active critical section"));
    }
    p.space.wr(addr, &vec![0; bytes.len()])?;
    p.sync.initialized_cs.remove(&addr);
    Ok(())
}

pub fn cs_spin(p: &mut Proc, addr: u64, spin: u64) -> Result<u64, SyncError> {
    let mut bytes = cs_image(p, addr)?;
    let at = if p.arch.is64() { 0x20 } else { 0x14 };
    let old = getptr(&bytes, at, p.arch.ptr_size());
    let _ = spin;
    putptr(&mut bytes, at, p.arch.ptr_size(), 0);
    p.space.wr(addr, &bytes)?;
    Ok(old)
}

fn srw_word(p: &Proc, s: &SrwState) -> Result<u64, SyncError> {
    let shared =
        u64::try_from(s.shared.len()).map_err(|_| SyncError::Invalid("SRW reader overflow"))?;
    if shared > p.arch.ptr(u64::MAX) >> 4 {
        return Err(SyncError::Invalid("SRW reader encoding overflow"));
    }
    Ok(if s.exclusive.is_some() {
        1
    } else if shared > 0 {
        shared << 4 | 1
    } else {
        0
    } | if s.waiting_exclusive > 0 { 2 } else { 0 })
}

fn srw_state(p: &Proc, addr: u64) -> Result<SrwState, SyncError> {
    storage(p, addr, p.arch.ptr_size())?;
    let s = p.sync.srw.get(&addr).cloned().unwrap_or_default();
    if p.space.ptr(addr, p.arch.ptr_size())? != srw_word(p, &s)? {
        return Err(SyncError::Invalid("modified/uninitialized SRW lock word"));
    }
    Ok(s)
}

fn commit_srw(p: &mut Proc, addr: u64, s: SrwState) -> Result<(), SyncError> {
    p.space.wptr(addr, p.arch.ptr_size(), srw_word(p, &s)?)?;
    if s.exclusive.is_none() && s.shared.is_empty() && s.waiting_exclusive == 0 {
        p.sync.srw.remove(&addr);
    } else {
        p.sync.srw.insert(addr, s);
    }
    Ok(())
}

pub fn srw_init(p: &mut Proc, addr: u64) -> Result<(), SyncError> {
    storage(p, addr, p.arch.ptr_size())?;
    if p.sync.srw.contains_key(&addr) {
        return Err(SyncError::Invalid("reinitializing active SRW lock"));
    }
    p.space.wptr(addr, p.arch.ptr_size(), 0)?;
    Ok(())
}

pub fn srw_try(p: &mut Proc, addr: u64, tid: u32, exclusive: bool) -> Result<bool, SyncError> {
    let mut s = srw_state(p, addr)?;
    if tid == 0 {
        return Err(SyncError::Invalid("zero SRW thread ID"));
    }
    if s.exclusive == Some(tid) || s.shared.contains(&tid) {
        return Ok(false);
    }
    if s.exclusive.is_some()
        || (exclusive && !s.shared.is_empty())
        || (!exclusive && s.waiting_exclusive > 0)
    {
        return Ok(false);
    }
    if exclusive {
        s.exclusive = Some(tid);
    } else {
        s.shared.insert(tid);
    }
    commit_srw(p, addr, s)?;
    Ok(true)
}

pub fn srw_release(p: &mut Proc, addr: u64, tid: u32, exclusive: bool) -> Result<(), SyncError> {
    let mut s = srw_state(p, addr)?;
    if exclusive {
        if s.exclusive != Some(tid) {
            return Err(SyncError::Invalid("exclusive SRW release by non-owner"));
        }
        s.exclusive = None;
    } else if !s.shared.remove(&tid) {
        return Err(SyncError::Invalid("shared SRW release by non-owner"));
    }
    commit_srw(p, addr, s)
}

pub fn srw_held(p: &Proc, addr: u64, tid: u32) -> Result<Option<bool>, SyncError> {
    let s = srw_state(p, addr)?;
    if s.exclusive == Some(tid) {
        Ok(Some(true))
    } else if s.shared.contains(&tid) {
        Ok(Some(false))
    } else {
        Ok(None)
    }
}

pub fn cv_init(p: &mut Proc, addr: u64) -> Result<(), SyncError> {
    storage(p, addr, p.arch.ptr_size())?;
    if p.sync
        .waiters
        .contains_key(&(u128::from(addr) | CONDVAR_KEY))
    {
        return Err(SyncError::Invalid(
            "reinitializing active condition variable",
        ));
    }
    p.space.wptr(addr, p.arch.ptr_size(), 0)?;
    Ok(())
}

pub fn cv_check(p: &Proc, addr: u64) -> Result<(), SyncError> {
    storage(p, addr, p.arch.ptr_size())?;
    if p.space.ptr(addr, p.arch.ptr_size())? != 0 {
        return Err(SyncError::Invalid(
            "modified/uninitialized condition variable",
        ));
    }
    p.space
        .probe(
            addr,
            p.arch.ptr_size() as usize,
            crate::error::MemoryAccessKind::Write,
        )
        .map_err(|f| {
            SyncError::Fault(MemFault {
                addr: f.address,
                write: true,
            })
        })?;
    Ok(())
}

/// `TEB` offset of `LastErrorValue`, used by waits that report errors.
pub fn last_error_offset(p: &Proc) -> u64 {
    offsets(p.arch).teb_last_error
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::memory::{mem, prot};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    #[test]
    fn waiter_counter_overflow_rejects_without_publishing_or_writing() {
        for arch in WinArch::ALL {
            let bytes: &[u8] = match arch {
                WinArch::X86 => {
                    include_bytes!("../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
                }
                WinArch::X64 => {
                    include_bytes!("../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
                }
                WinArch::Arm64 => {
                    include_bytes!("../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
                }
            };
            let mut cfg = WindowsConfig::new("waiter-overflow.exe", vec![]);
            cfg.seed = Some(1);
            cfg.arena_bytes = 64 << 20;
            let mut process = WindowsProcess::spawn_image(cfg, bytes.to_vec()).unwrap();
            let p = process.state_mut();
            let (addr, _) =
                p.vm.allocate(None, 0x1000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap();
            cs_init(p, addr, 0).unwrap();
            cs_try_enter(p, addr, 1).unwrap();
            p.sync.cs_waiters.insert(addr, u32::MAX);
            let before = p.space.bytes(addr, cs_size(p)).unwrap();
            assert!(matches!(
                on_block(p, 2, &Wait::CritSec { addr }),
                Err(SyncError::Invalid(_))
            ));
            assert_eq!(p.space.bytes(addr, before.len()).unwrap(), before);
            assert_eq!(p.sync.cs_waiters[&addr], u32::MAX);
            assert!(!p.sync.parked.contains_key(&2));

            let lock = addr + 0x80;
            let state = SrwState {
                exclusive: Some(1),
                waiting_exclusive: u32::MAX,
                ..SrwState::default()
            };
            commit_srw(p, lock, state).unwrap();
            let word = p.space.ptr(lock, arch.ptr_size()).unwrap();
            assert!(matches!(
                on_block(
                    p,
                    2,
                    &Wait::Srw {
                        addr: lock,
                        exclusive: true
                    }
                ),
                Err(SyncError::Invalid(_))
            ));
            assert_eq!(p.space.ptr(lock, arch.ptr_size()).unwrap(), word);
            assert_eq!(p.sync.srw[&lock].waiting_exclusive, u32::MAX);
            assert!(!p.sync.parked.contains_key(&2));
        }
    }
}

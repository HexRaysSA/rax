//! psynch: the kernel side of libpthread's mutexes, condition variables,
//! and read-write locks (libpthread `kern/kern_synch.c` and
//! `kern/synch_internal.h`).
//!
//! User space keeps each object's state in sequence words (L: lock or
//! wait count, U: unlock count, S: signal count, each counting in steps of
//! [`PTHRW_INC`] with flag bits below) and enters the kernel only under
//! contention. The kernel keeps a wait queue per object address
//! ([`Kwq`]): waiting threads in sequence order, and "fake" entries that
//! record wakeups that arrived before their waiters (preposts, broadcasts).
//!
//! A thread that must wait is parked ([`Parked`]) with its entry in the
//! queue; a waker removes the entry, records the grant, and wakes the
//! thread, whose system call then finishes in the operation's continuation
//! (`psynch_mtxcontinue`, `psynch_cvcontinue`, `psynch_rw_*continue`) with
//! the kernel's wait result: awakened, timed out, or interrupted.

pub mod cond;
pub mod mutex;
pub mod rwlock;

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use super::abi::Errno;
use super::arch::{Rv, SysResult};
use super::process::Thread;
use super::syscall::Ctx;
use super::wait::{Resume, Wait};

/// `PTHRW_COUNT_SHIFT`.
pub const PTHRW_COUNT_SHIFT: u32 = 8;
/// `PTHRW_INC`: one count in a sequence word.
pub const PTHRW_INC: u32 = 1 << PTHRW_COUNT_SHIFT;
/// `PTHRW_BIT_MASK`: the flag bits.
pub const PTHRW_BIT_MASK: u32 = PTHRW_INC - 1;
/// `PTHRW_COUNT_MASK`: the count bits.
pub const PTHRW_COUNT_MASK: u32 = !PTHRW_BIT_MASK;
/// `PTHRW_MAX_READERS`.
const PTHRW_MAX_READERS: u32 = PTHRW_COUNT_MASK;

/// L-word bits.
pub mod lbit {
    /// `PTH_RWL_KBIT`: cannot acquire in user mode.
    pub const K: u32 = 0x01;
    /// `PTH_RWL_EBIT`: exclusive lock in progress.
    pub const E: u32 = 0x02;
    /// `PTH_RWL_WBIT`: write waiters pending in the kernel.
    pub const W: u32 = 0x04;
    /// `PTH_RWL_MTX_WAIT`: in a condition wait, waiting for the mutex.
    pub const MTX_WAIT: u32 = 0x20;
    /// `PTH_RWL_MBIT`: overlapping grants from the kernel.
    pub const M: u32 = 0x40;
    /// `PTH_RWL_IBIT`: lock reset, held until the first unlock.
    pub const I: u32 = 0x80;
}

/// S-word bits.
pub mod sbit {
    /// `PTH_RWS_SBIT`: kernel transition sequence not set yet.
    pub const S: u32 = 0x01;
    /// `PTH_RWS_CV_CBIT`: the kernel cleared a condition variable.
    pub const CV_C: u32 = 0x01;
    /// `PTH_RWS_CV_PBIT`: only fake entries remain.
    pub const CV_P: u32 = 0x02;
    /// `PTH_RWS_CV_MBIT`: a prepost return.
    pub const CV_M: u32 = 0x40;
    /// `PTHRW_RWS_SAVEMASK`.
    pub const SAVEMASK: u32 = 0x04;
}

/// `PTHRW_RWL_INIT`.
pub const PTHRW_RWL_INIT: u32 = lbit::I;
/// `PTHRW_RWS_INIT`.
pub const PTHRW_RWS_INIT: u32 = sbit::S;

/// `ECVCLEARED`: returned with a condition wait's error when the kernel
/// cleared the condition variable.
pub const ECVCLEARED: i32 = 0x100;
/// `ECVPREPOST`: only fake entries remain.
pub const ECVPREPOST: i32 = 0x200;

/// Mutex option flags passed in `flags`.
pub mod opt {
    /// `_PTHREAD_MTX_OPT_PSHARED` (`PTHREAD_PROCESS_SHARED`).
    pub const PSHARED: u32 = 0x010;
    /// `PTHREAD_PSHARED_FLAGS_MASK`.
    pub const PSHARED_MASK: u32 = 0x030;
    /// `_PTHREAD_MTX_OPT_POLICY_FIRSTFIT`.
    pub const POLICY_FIRSTFIT: u32 = 0x080;
    /// `_PTHREAD_MTX_OPT_POLICY_MASK`.
    pub const POLICY_MASK: u32 = 0x1c0;
    /// `_PTHREAD_MTX_OPT_MUTEX`.
    pub const MUTEX: u32 = 0x2000;
}

/// Wait-queue types (`KSYN_WQTYPE_*`).
pub mod wqtype {
    /// `KSYN_WQTYPE_INWAIT`.
    pub const INWAIT: u32 = 0x1000;
    /// `KSYN_WQTYPE_INDROP`.
    pub const INDROP: u32 = 0x2000;
    /// `KSYN_WQTYPE_MTX`.
    pub const MTX: u32 = 0x01;
    /// `KSYN_WQTYPE_CVAR`.
    pub const CVAR: u32 = 0x02;
    /// `KSYN_WQTYPE_RWLOCK`.
    pub const RWLOCK: u32 = 0x04;
    /// `KSYN_WQTYPE_MASK`.
    pub const MASK: u32 = 0xff;
    /// `KSYN_WQTYPE_MUTEXDROP`.
    pub const MUTEXDROP: u32 = INDROP | MTX;
}

/// `KSYN_KWF_*`.
mod kwf {
    pub const INITCLEARED: u16 = 0x1;
    pub const ZEROEDOUT: u16 = 0x2;
    pub const OVERLAP_GUARD: u16 = 0x8;
}

/// `KW_UNLOCK_PREPOST*`.
mod unlock {
    pub const PREPOST: u32 = 0x01;
    pub const PREPOST_READLOCK: u32 = 0x08;
    pub const PREPOST_WRLOCK: u32 = 0x20;
}

/// `PTH_RW_TYPE_*` and the shifted forms.
mod rwt {
    pub const READ: u32 = 0x01;
    pub const WRITE: u32 = 0x04;
    pub const MASK: u32 = 0xff;
    pub const SHFT_READ: u32 = 0x0100;
    pub const SHFT_WRITE: u32 = 0x0400;
    pub const SHFT_MASK: u32 = 0xff00;
}

/// `KWQ_INTR_*`.
mod intr {
    pub const NONE: u32 = 0;
    pub const READ: u32 = 0x1;
    pub const WRITE: u32 = 0x2;
}

/// `KSYN_CLEANUP_DEADLINE`: how long an unused wait queue keeps its state.
const CLEANUP_DEADLINE: Duration = Duration::from_secs(10);

/// `SEQFIT` and `FIRSTFIT` insertion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// In sequence order.
    Seq,
    /// In arrival order.
    First,
}

/// `KSYN_QUEUE_READ`.
pub const QUEUE_READ: usize = 0;
/// `KSYN_QUEUE_WRITE`.
pub const QUEUE_WRITE: usize = 1;

/// `is_seqlower`.
pub fn is_seqlower(x: u32, y: u32) -> bool {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x < y {
        y - x < PTHRW_MAX_READERS / 2
    } else {
        x - y > PTHRW_MAX_READERS / 2
    }
}

/// `is_seqlower_eq`.
pub fn is_seqlower_eq(x: u32, y: u32) -> bool {
    x & PTHRW_COUNT_MASK == y & PTHRW_COUNT_MASK || is_seqlower(x, y)
}

/// `is_seqhigher`.
pub fn is_seqhigher(x: u32, y: u32) -> bool {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x > y {
        x - y < PTHRW_MAX_READERS / 2
    } else {
        y - x > PTHRW_MAX_READERS / 2
    }
}

/// `is_seqhigher_eq`.
pub fn is_seqhigher_eq(x: u32, y: u32) -> bool {
    x & PTHRW_COUNT_MASK == y & PTHRW_COUNT_MASK || is_seqhigher(x, y)
}

/// `diff_genseq`.
pub fn diff_genseq(x: u32, y: u32) -> u32 {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x == y {
        0
    } else if x > y {
        x - y
    } else {
        (PTHRW_MAX_READERS - y)
            .wrapping_add(x)
            .wrapping_add(PTHRW_INC)
    }
}

/// `find_diff`: the count between two sequence words.
pub fn find_diff(upto: u32, lowest: u32) -> u32 {
    if upto == lowest {
        return 0;
    }
    let diff = if is_seqlower(upto, lowest) {
        diff_genseq(lowest, upto)
    } else {
        diff_genseq(upto, lowest)
    };
    diff >> PTHRW_COUNT_SHIFT
}

/// A queue entry's kind (`kwe_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KweState {
    /// A waiting thread.
    InWait,
    /// A wakeup that arrived before its waiter.
    Prepost,
    /// A broadcast that arrived before its waiters.
    Broadcast,
}

/// A wait-queue entry (`struct ksyn_waitq_element`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kwe {
    /// What it is.
    pub state: KweState,
    /// Its sequence (count bits).
    pub lockseq: u32,
    /// How many wakeups a fake entry stands for.
    pub count: u32,
    /// The waiting thread (0 for fake entries).
    pub tid: u64,
}

/// One of a wait queue's two queues (`struct ksyn_queue`).
#[derive(Clone, Debug, Default)]
pub struct Queue {
    /// Entries in order.
    pub list: Vec<Kwe>,
    /// Lowest sequence in the queue.
    pub firstnum: u32,
    /// Highest sequence in the queue.
    pub lastnum: u32,
}

/// Kernel wait queue of one synchronization object (`struct
/// ksyn_wait_queue`).
#[derive(Clone, Debug, Default)]
pub struct Kwq {
    /// `kw_type` (0: to be initialized).
    pub kind: u32,
    /// `kw_kflags`.
    pub kflags: u16,
    /// In-flight users (`kw_iocount`).
    pub iocount: u32,
    /// In-flight unlockers (`kw_dropcount`).
    pub dropcount: u32,
    /// Entries in both queues (`kw_inqueue`).
    pub inqueue: u32,
    /// Fake entries (`kw_fakecount`).
    pub fakecount: u32,
    /// Highest sequence queued.
    pub highseq: u32,
    /// Lowest sequence queued.
    pub lowseq: u32,
    /// L word from user space.
    pub lword: u32,
    /// U word.
    pub uword: u32,
    /// S word.
    pub sword: u32,
    /// The last unlock sequence (`kw_cvkernelseq` for condition variables).
    pub lastunlockseq: u32,
    /// The last S word an unlock used.
    pub lastseqword: u32,
    /// The next expected sequence word (read-write locks).
    pub nextseqword: u32,
    /// Preposted wakeups: count, target L and S sequences.
    pub prepost: (u32, u32, u32),
    /// Wakeups missed because their thread was interrupted: type, count,
    /// sequence limit, the bits to return.
    pub intr: (u32, u32, u32, u32),
    /// The owner the kernel knows (a thread ID).
    pub owner: Option<u64>,
    /// Read and write queues.
    pub queues: [Queue; 2],
    /// When the queue became unused (on the free list), if it did.
    pub freed_at: Option<Instant>,
}

/// A process's wait queues, by object address.
#[derive(Debug, Default)]
pub struct Table {
    kwqs: HashMap<u64, Kwq>,
}

/// A thread's psynch wait state (`uu_kwe` and the wait it blocks in).
#[derive(Clone, Debug, Default)]
pub struct ThreadPsynch {
    /// The wait the thread is parked in.
    pub parked: Option<Parked>,
    /// `kwe_psynchretval`: what a waker granted.
    pub retval: u32,
    /// A waker woke the thread (`THREAD_AWAKENED`).
    pub awakened: bool,
}

/// Where a parked thread waits and how its call finishes.
#[derive(Clone, Copy, Debug)]
pub struct Parked {
    /// The object's address.
    pub addr: u64,
    /// The continuation.
    pub cont: Cont,
    /// The system call that parked.
    pub call: i64,
    /// The wait's deadline.
    pub deadline: Option<Instant>,
}

/// The continuation a parked call finishes in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cont {
    /// `psynch_mtxcontinue`.
    Mutex,
    /// `psynch_cvcontinue`.
    Cond,
    /// `psynch_rw_rdcontinue`.
    RwRead,
    /// `psynch_rw_wrcontinue`.
    RwWrite,
}

impl Cont {
    /// How the waiting call drops its wait-queue reference: freeing an
    /// unused queue at once, and the reference's type.
    fn release(self) -> (bool, u32) {
        match self {
            Cont::Mutex => (true, wqtype::INWAIT | wqtype::MTX),
            Cont::Cond => (true, wqtype::INWAIT | wqtype::CVAR),
            Cont::RwRead | Cont::RwWrite => (false, wqtype::INWAIT | wqtype::RWLOCK),
        }
    }
}

/// A wait's outcome (`wait_result_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitResult {
    /// `THREAD_AWAKENED`.
    Awakened,
    /// `THREAD_TIMED_OUT`.
    TimedOut,
    /// `THREAD_INTERRUPTED`.
    Interrupted,
}

impl WaitResult {
    /// `_wait_result_to_errno`.
    pub fn errno(self) -> i32 {
        match self {
            WaitResult::Awakened => 0,
            WaitResult::TimedOut => Errno::ETIMEDOUT.0,
            WaitResult::Interrupted => Errno::EINTR.0,
        }
    }
}

/// Whether a wakeup reached its thread (`KERN_SUCCESS`) or the thread no
/// longer waited (`KERN_NOT_WAITING`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woke {
    /// The thread was woken.
    Success,
    /// The thread was not waiting.
    NotWaiting,
}

/// The threads a psynch operation may wake: the caller (running, not in
/// the thread map) and the others.
pub struct Threads<'a> {
    /// The calling thread.
    pub running: &'a mut Thread,
    /// The process's other threads.
    pub others: &'a mut BTreeMap<u64, Thread>,
}

impl Threads<'_> {
    fn get(&mut self, tid: u64) -> Option<&mut Thread> {
        if self.running.tid == tid {
            Some(&mut *self.running)
        } else {
            self.others.get_mut(&tid)
        }
    }

    /// `uthread_is_cancelled`.
    fn cancelled(&mut self, tid: u64) -> bool {
        self.get(tid).is_some_and(|t| t.sig.cancelled())
    }
}

impl Queue {
    fn count(&self) -> u32 {
        self.list.len() as u32
    }
}

impl Kwq {
    /// `CLEAR_REINIT_BITS`.
    fn clear_reinit_bits(&mut self) {
        if self.kind & wqtype::MASK == wqtype::RWLOCK {
            self.nextseqword = PTHRW_RWS_INIT;
            self.kflags &= !kwf::OVERLAP_GUARD;
        }
        self.clear_preposted();
        self.lastunlockseq = PTHRW_RWL_INIT;
        self.lastseqword = PTHRW_RWS_INIT;
        self.intr = (intr::NONE, 0, 0, 0);
        self.lword = 0;
        self.uword = 0;
        self.sword = PTHRW_RWS_INIT;
    }

    fn clear_preposted(&mut self) {
        self.prepost = (0, 0, PTHRW_RWS_INIT);
    }

    /// `_kwq_is_used`.
    fn used(&self) -> bool {
        self.inqueue != 0 || self.prepost.0 != 0 || self.intr.1 != 0
    }

    /// `_ksyn_check_init`.
    fn check_init(&mut self, lgenval: u32) -> bool {
        let res = lgenval & PTHRW_RWL_INIT != 0;
        if res && self.kflags & kwf::INITCLEARED == 0 {
            self.clear_reinit_bits();
            self.kflags |= kwf::INITCLEARED;
        }
        res
    }

    /// `UPDATE_CVKWQ`.
    fn update_cv(&mut self, mgen: u32, ugen: u32, rw_wc: u32) {
        let sinit = rw_wc & sbit::CV_C != 0;
        if self.kflags & kwf::ZEROEDOUT != 0 {
            self.lword = mgen;
            self.uword = ugen;
            self.sword = rw_wc;
            self.kflags &= !kwf::ZEROEDOUT;
        } else {
            if is_seqhigher(mgen, self.lword) {
                self.lword = mgen;
            }
            if is_seqhigher(ugen, self.uword) {
                self.uword = ugen;
            }
            if sinit && is_seqhigher(rw_wc, self.sword) {
                self.sword = rw_wc;
            }
        }
        if sinit && is_seqlower(self.lastunlockseq, rw_wc) {
            self.lastunlockseq = rw_wc & PTHRW_COUNT_MASK;
        }
    }

    /// `update_low_high`.
    fn update_low_high(&mut self, lockseq: u32) {
        if self.inqueue == 1 {
            self.lowseq = lockseq;
            self.highseq = lockseq;
        } else {
            if is_seqlower(lockseq, self.lowseq) {
                self.lowseq = lockseq;
            }
            if is_seqhigher(lockseq, self.highseq) {
                self.highseq = lockseq;
            }
        }
    }

    fn next_low(&self) -> u32 {
        let mut lowest = 0;
        let mut first = true;
        for q in &self.queues {
            if q.count() > 0 && (first || is_seqlower(q.firstnum, lowest)) {
                lowest = q.firstnum;
                first = false;
            }
        }
        lowest
    }

    fn next_high(&self) -> u32 {
        let mut highest = 0;
        let mut first = true;
        for q in &self.queues {
            if q.count() > 0 && (first || is_seqhigher(q.lastnum, highest)) {
                highest = q.lastnum;
                first = false;
            }
        }
        highest
    }

    /// `ksyn_queue_insert`; `cancelled` tells whether a thread is being
    /// cancelled. Returns 0 or an errno.
    fn insert(
        &mut self,
        kqi: usize,
        kwe: Kwe,
        mgen: u32,
        fit: Fit,
        cancelled: &mut dyn FnMut(u64) -> bool,
    ) -> i32 {
        let lockseq = mgen & PTHRW_COUNT_MASK;
        let kq = &mut self.queues[kqi];
        let mut res = 0;
        if kq.list.is_empty() {
            kq.list.insert(0, kwe);
            kq.firstnum = lockseq;
            kq.lastnum = lockseq;
        } else if fit == Fit::First {
            kq.list.push(kwe);
            if is_seqlower(lockseq, kq.firstnum) {
                kq.firstnum = lockseq;
            }
            if is_seqhigher(lockseq, kq.lastnum) {
                kq.lastnum = lockseq;
            }
        } else if lockseq == kq.firstnum || lockseq == kq.lastnum {
            // Two entries with one sequence: allowed only for a prepost
            // beside a thread being cancelled.
            res = Errno::EBUSY.0;
            if kwe.state == KweState::Prepost
                && let Some(tmp) = kq
                    .list
                    .iter()
                    .find(|k| k.lockseq & PTHRW_COUNT_MASK == lockseq)
                && tmp.tid != 0
                && cancelled(tmp.tid)
            {
                kq.list.push(kwe);
                res = 0;
            }
        } else if is_seqlower(kq.lastnum, lockseq) {
            kq.list.push(kwe);
            kq.lastnum = lockseq;
        } else if is_seqlower(lockseq, kq.firstnum) {
            kq.list.insert(0, kwe);
            kq.firstnum = lockseq;
        } else {
            res = Errno::ESRCH.0;
            if let Some(i) = kq
                .list
                .iter()
                .position(|k| is_seqhigher(k.lockseq, lockseq))
            {
                kq.list.insert(i, kwe);
                res = 0;
            }
        }
        if res == 0 {
            self.inqueue += 1;
            self.update_low_high(lockseq);
        }
        res
    }

    /// `ksyn_queue_remove_item` for the entry at `i` of queue `kqi`.
    fn remove(&mut self, kqi: usize, i: usize) -> Kwe {
        let kq = &mut self.queues[kqi];
        let kwe = kq.list.remove(i);
        if let (Some(first), Some(last)) = (kq.list.first(), kq.list.last()) {
            kq.firstnum = first.lockseq & PTHRW_COUNT_MASK;
            kq.lastnum = last.lockseq & PTHRW_COUNT_MASK;
        } else {
            kq.firstnum = 0;
            kq.lastnum = 0;
        }
        self.inqueue -= 1;
        if self.inqueue > 0 {
            let curseq = kwe.lockseq & PTHRW_COUNT_MASK;
            if self.lowseq == curseq {
                self.lowseq = self.next_low();
            }
            if self.highseq == curseq {
                self.highseq = self.next_high();
            }
        } else {
            self.lowseq = 0;
            self.highseq = 0;
        }
        kwe
    }

    /// The position of thread `tid`'s entry in queue `kqi`.
    fn position_of(&self, kqi: usize, tid: u64) -> Option<usize> {
        self.queues[kqi]
            .list
            .iter()
            .position(|k| k.state == KweState::InWait && k.tid == tid)
    }

    /// `ksyn_queue_find_seq`.
    fn find_seq(&self, kqi: usize, seq: u32) -> Option<usize> {
        self.queues[kqi]
            .list
            .iter()
            .position(|k| k.lockseq & PTHRW_COUNT_MASK == seq)
    }

    /// `ksyn_queue_count_tolowest`.
    fn count_tolowest(&self, kqi: usize, upto: u32) -> u32 {
        let kq = &self.queues[kqi];
        if kq.list.is_empty() || is_seqhigher(kq.firstnum, upto) {
            return 0;
        }
        if upto == kq.firstnum {
            return 1;
        }
        let mut i = 0;
        for k in &kq.list {
            let curval = k.lockseq & PTHRW_COUNT_MASK;
            if is_seqhigher(curval, upto) {
                break;
            }
            i += 1;
            if upto == curval {
                break;
            }
        }
        i
    }

    /// `find_seq_till`: whether `nwaiters` waiters up to `upto` are
    /// queued, and how many are.
    fn find_seq_till(&self, upto: u32, nwaiters: u32) -> (bool, u32) {
        let mut count = 0;
        for kqi in 0..2 {
            count += self.count_tolowest(kqi, upto);
            if count >= nwaiters {
                break;
            }
        }
        (count != 0 && count >= nwaiters, count)
    }

    /// `ksyn_prepost`: a fake entry of `state` at `lockseq`.
    fn prepost(&mut self, state: KweState, lockseq: u32, cancelled: &mut dyn FnMut(u64) -> bool) {
        let kwe = Kwe {
            state,
            lockseq,
            count: 1,
            tid: 0,
        };
        // The kernel counts the entry even when a conflicting sequence
        // keeps it out of the queue.
        let _ = self.insert(QUEUE_WRITE, kwe, lockseq, Fit::Seq, cancelled);
        self.fakecount += 1;
    }
}

impl Table {
    /// The wait queue at `addr`.
    pub fn get_mut(&mut self, addr: u64) -> &mut Kwq {
        self.kwqs.get_mut(&addr).expect("found wait queue")
    }

    /// Frees wait queues unused for [`CLEANUP_DEADLINE`]
    /// (`psynch_wq_cleanup`).
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.kwqs.retain(|_, k| {
            !(k.iocount == 0
                && !k.used()
                && k.freed_at
                    .is_some_and(|t| now.duration_since(t) >= CLEANUP_DEADLINE))
        });
    }

    /// `ksyn_wqfind`: finds or creates the wait queue at `addr` and takes
    /// a reference.
    pub fn find(
        &mut self,
        addr: u64,
        mgen: u32,
        ugen: u32,
        sgen: u32,
        wqtype: u32,
    ) -> Result<(), Errno> {
        self.cleanup();
        let kwq = self.kwqs.entry(addr).or_default();
        kwq.freed_at = None;
        if kwq.kind != 0 && kwq.kind & wqtype::MASK != wqtype & wqtype::MASK {
            if !kwq.used() && kwq.iocount == 0 {
                kwq.kind = 0;
            } else {
                // In use as another kind of object (an unlocker still in
                // flight is not possible here: calls do not interleave).
                return Err(Errno::EINVAL);
            }
        }
        if kwq.kind == 0 {
            kwq.kind = wqtype & wqtype::MASK;
            kwq.clear_reinit_bits();
            kwq.lword = mgen;
            kwq.uword = ugen;
            kwq.sword = sgen;
            kwq.owner = None;
            kwq.kflags = 0;
        }
        kwq.iocount += 1;
        if wqtype == wqtype::MUTEXDROP {
            kwq.dropcount += 1;
        }
        Ok(())
    }

    /// `ksyn_wqrelease`: drops a reference; an unused queue is freed now
    /// (`qfreenow`) or after the cleanup delay.
    pub fn release(&mut self, addr: u64, qfreenow: bool, wqtype: u32) {
        let kwq = self.get_mut(addr);
        if wqtype == wqtype::MUTEXDROP {
            kwq.dropcount -= 1;
        }
        kwq.iocount -= 1;
        if kwq.iocount == 0 && !kwq.used() {
            if qfreenow {
                self.kwqs.remove(&addr);
            } else {
                kwq.freed_at = Some(Instant::now());
            }
        }
    }
}

/// Whether thread `t` is blocked in a psynch wait on `addr` that nothing
/// ended yet.
fn waiting_on(t: &Thread, addr: u64) -> bool {
    t.pw.parked.is_some_and(|p| p.addr == addr) && t.wait.is_some() && !t.woken
}

/// Grants `updateval` to a waiting thread and wakes it
/// (`psynch_wait_wakeup`).
fn wake(t: &mut Thread, addr: u64, updateval: u32) -> Woke {
    t.pw.retval = updateval;
    if waiting_on(t, addr) {
        t.pw.awakened = true;
        t.woken = true;
        t.wake_event = true;
        Woke::Success
    } else {
        Woke::NotWaiting
    }
}

/// `ksyn_signal`: removes the entry at `i` (the first when `None`) of
/// queue `kqi` and grants its thread `updateval`.
fn ksyn_signal(
    kwq: &mut Kwq,
    addr: u64,
    kqi: usize,
    i: Option<usize>,
    updateval: u32,
    threads: &mut Threads<'_>,
) -> Woke {
    let i = i.unwrap_or(0);
    let kwe = kwq.remove(kqi, i);
    debug_assert_eq!(kwe.state, KweState::InWait);
    match threads.get(kwe.tid) {
        Some(t) => wake(t, addr, updateval),
        None => Woke::NotWaiting,
    }
}

/// `ksyn_signal_thread`: wakes thread `tid` if it waits in this queue,
/// and only then removes its entry.
fn ksyn_signal_thread(
    kwq: &mut Kwq,
    addr: u64,
    kqi: usize,
    tid: u64,
    updateval: u32,
    threads: &mut Threads<'_>,
) -> (Woke, Option<Kwe>) {
    let Some(t) = threads.get(tid) else {
        return (Woke::NotWaiting, None);
    };
    if !waiting_on(t, addr) {
        return (Woke::NotWaiting, None);
    }
    let Some(i) = kwq.position_of(kqi, tid) else {
        return (Woke::NotWaiting, None);
    };
    wake(t, addr, updateval);
    (Woke::Success, Some(kwq.remove(kqi, i)))
}

/// `ksyn_wait`: queues the caller at `lockseq` and parks it; a pending
/// signal or cancellation interrupts the wait at once
/// (`THREAD_ABORTSAFE`), finishing it in the continuation. The wait
/// queue's reference passes to the continuation; when the queue refuses
/// the entry, it is dropped here with the error.
#[allow(clippy::too_many_arguments)]
pub fn ksyn_wait(
    ctx: &mut Ctx<'_>,
    addr: u64,
    kqi: usize,
    lockseq: u32,
    fit: Fit,
    deadline: Option<Instant>,
    cont: Cont,
) -> SysResult {
    let tid = ctx.thread.tid;
    let kwe = Kwe {
        state: KweState::InWait,
        lockseq: lockseq & PTHRW_COUNT_MASK,
        count: 1,
        tid,
    };
    let res = {
        let proc = &mut *ctx.proc;
        let (table, others) = (&mut proc.psynch, &proc.threads);
        let running = &*ctx.thread;
        let mut cancelled = |t: u64| {
            if t == running.tid {
                running.sig.cancelled()
            } else {
                others.get(&t).is_some_and(|th| th.sig.cancelled())
            }
        };
        table
            .get_mut(addr)
            .insert(kqi, kwe, lockseq, fit, &mut cancelled)
    };
    if res != 0 {
        let (now, kind) = cont.release();
        ctx.proc.psynch.release(addr, now, kind);
        return Err(Errno(res));
    }
    ctx.thread.pw.retval = 0;
    ctx.thread.pw.awakened = false;
    ctx.thread.pw.parked = Some(Parked {
        addr,
        cont,
        call: ctx.nr,
        deadline,
    });
    if crate::user::darwin::signal::interruption(ctx.proc, ctx.thread).is_some()
        || ctx.thread.sig.take_abort()
    {
        // THREAD_ABORTSAFE: interrupted before it blocks.
        let p = ctx.thread.pw.parked.take().expect("just parked");
        return finish(ctx, p, WaitResult::Interrupted);
    }
    ctx.thread.resume = Some(Resume {
        pc: ctx.pc,
        call: ctx.nr,
        deadline,
        step: 0,
    });
    ctx.thread.wait = Some(Wait {
        deadline,
        interruptible: true,
        seq: crate::user::darwin::wait::next_seq(),
        ..Default::default()
    });
    Err(Errno::ERESTART)
}

/// The continuation of a call the thread parked in, when it runs again;
/// `None` when the thread is not parked in this call.
pub fn resume(ctx: &mut Ctx<'_>) -> Option<SysResult> {
    let p = ctx.thread.pw.parked.filter(|p| p.call == ctx.nr)?;
    ctx.thread.pw.parked = None;
    let result = if std::mem::take(&mut ctx.thread.pw.awakened) {
        WaitResult::Awakened
    } else if p.deadline.is_some_and(|d| d <= Instant::now()) {
        WaitResult::TimedOut
    } else {
        // A signal or an abort ended the wait; the abort is spent.
        ctx.thread.sig.abort = false;
        WaitResult::Interrupted
    };
    Some(finish(ctx, p, result))
}

fn finish(ctx: &mut Ctx<'_>, p: Parked, result: WaitResult) -> SysResult {
    match p.cont {
        Cont::Mutex => mutex::continuation(ctx, p.addr, result),
        Cont::Cond => cond::continuation(ctx, p.addr, result),
        Cont::RwRead => rwlock::continuation(ctx, p.addr, QUEUE_READ, result),
        Cont::RwWrite => rwlock::continuation(ctx, p.addr, QUEUE_WRITE, result),
    }
}

/// Splits a call's context into the process's wait queues and its
/// threads.
pub fn parts<'a>(ctx: &'a mut Ctx<'_>) -> (&'a mut Table, Threads<'a>) {
    let proc = &mut *ctx.proc;
    (
        &mut proc.psynch,
        Threads {
            running: &mut *ctx.thread,
            others: &mut proc.threads,
        },
    )
}

/// A call's result from a kernel error value (which may carry
/// [`ECVCLEARED`] and [`ECVPREPOST`] bits) and return value.
fn result(error: i32, retval: u32) -> SysResult {
    if error != 0 {
        Err(Errno(error))
    } else {
        Ok(Rv::one(u64::from(retval)))
    }
}

#[cfg(test)]
mod tests;

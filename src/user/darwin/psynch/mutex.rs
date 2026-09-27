//! Contended mutexes: `psynch_mutexwait` and `psynch_mutexdrop`
//! (`_psynch_mutexwait`, `_psynch_mutexdrop_internal`, `psynch_mtxcontinue`).

use super::{
    Fit, Kwq, PTHRW_COUNT_MASK, PTHRW_INC, PTHRW_RWL_INIT, QUEUE_WRITE, Table, Threads, WaitResult,
    Woke, intr, is_seqhigher, is_seqlower, lbit, opt, parts, result, wqtype,
};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// `PTHREAD_MTX_TID_SWITCHING`: the owner is being changed.
const TID_SWITCHING: u64 = u64::MAX;

fn firstfit(flags: u32) -> bool {
    flags & opt::POLICY_MASK == opt::POLICY_FIRSTFIT
}

/// `_kwq_handle_interrupted_wakeup`: a grant an interrupted waiter missed,
/// for a later waiter of `type` at `lseq`.
pub(super) fn take_interrupted(kwq: &mut Kwq, kind: u32, lseq: u32) -> Option<u32> {
    let (itype, count, seq, bits) = kwq.intr;
    if count != 0 && itype == kind && (seq == 0 || super::is_seqlower_eq(lseq, seq)) {
        kwq.intr.1 -= 1;
        if bits == 0 {
            kwq.intr = (intr::NONE, 0, 0, 0);
        }
        return Some(bits);
    }
    None
}

/// `psynch_mutexwait(mutex, mgen, ugen, tid, flags)`.
pub fn mutexwait(
    ctx: &mut Ctx<'_>,
    addr: u64,
    mgen: u32,
    ugen: u32,
    tid: u64,
    flags: u32,
) -> SysResult {
    if let Some(r) = super::resume(ctx) {
        return r;
    }
    let first = firstfit(flags);
    let lseq = mgen & PTHRW_COUNT_MASK;
    let me = ctx.thread.tid;
    ctx.proc
        .psynch
        .find(addr, mgen, ugen, 0, wqtype::INWAIT | wqtype::MTX)?;
    let hint = if tid == me {
        Some(me)
    } else {
        ctx.proc
            .threads
            .get(&tid)
            .filter(|t| !t.exited)
            .map(|t| t.tid)
    };
    let kwq = ctx.proc.psynch.get_mut(addr);
    let granted = if let Some(bits) = take_interrupted(kwq, intr::WRITE, lseq) {
        kwq.owner = Some(me);
        Some(Ok(bits))
    } else if kwq.prepost.0 != 0 && (first || lseq == kwq.prepost.1) {
        // A preposted unlock: the lock is ours.
        kwq.prepost.0 -= 1;
        if !first && kwq.prepost.0 > 0 {
            kwq.prepost.1 = kwq.prepost.1.wrapping_add(PTHRW_INC);
            Some(Err(Errno::EINVAL))
        } else {
            if !first {
                kwq.clear_preposted();
            }
            let mut updatebits = if kwq.inqueue == 0 {
                lseq | lbit::K | lbit::E
            } else {
                (kwq.highseq & PTHRW_COUNT_MASK) | lbit::K | lbit::E
            };
            updatebits &= !lbit::MTX_WAIT;
            kwq.owner = Some(me);
            Some(Ok(updatebits))
        }
    } else {
        // The owner hint is trusted unless it is the known owner, missing,
        // stale (an unlock came after it was read), or switching; an
        // unknown thread leaves the owner as it is.
        let stale = kwq.lastunlockseq != PTHRW_RWL_INIT && is_seqlower(ugen, kwq.lastunlockseq);
        if tid != kwq.owner.unwrap_or(0) && tid != 0 && !stale && tid != TID_SWITCHING {
            if let Some(t) = hint {
                kwq.owner = Some(t);
            }
        }
        None
    };
    match granted {
        None => {
            let fit = if first { Fit::First } else { Fit::Seq };
            super::ksyn_wait(ctx, addr, QUEUE_WRITE, mgen, fit, None, super::Cont::Mutex)
        }
        Some(r) => {
            ctx.proc
                .psynch
                .release(addr, true, wqtype::INWAIT | wqtype::MTX);
            r.map(|v| Rv::one(u64::from(v)))
        }
    }
}

/// `psynch_mtxcontinue`.
pub fn continuation(ctx: &mut Ctx<'_>, addr: u64, r: WaitResult) -> SysResult {
    let tid = ctx.thread.tid;
    let retval = ctx.thread.pw.retval;
    let kwq = ctx.proc.psynch.get_mut(addr);
    let error = r.errno();
    let mut out = 0;
    if error != 0 {
        if let Some(i) = kwq.position_of(QUEUE_WRITE, tid) {
            kwq.remove(QUEUE_WRITE, i);
        }
    } else {
        out = retval & !lbit::MTX_WAIT;
    }
    ctx.proc
        .psynch
        .release(addr, true, wqtype::INWAIT | wqtype::MTX);
    result(error, out)
}

/// `psynch_mutexdrop(mutex, mgen, ugen, tid, flags)`.
pub fn mutexdrop(ctx: &mut Ctx<'_>, addr: u64, mgen: u32, ugen: u32, flags: u32) -> SysResult {
    ctx.proc
        .psynch
        .find(addr, mgen, ugen, 0, wqtype::MUTEXDROP)?;
    let (table, mut threads) = parts(ctx);
    let v = drop_internal(table, &mut threads, addr, mgen, ugen, flags);
    result(0, v)
}

/// `ksyn_mtxsignal`: grants the lock to the entry at `i` (the first when
/// `None`).
fn mtxsignal(
    kwq: &mut Kwq,
    addr: u64,
    i: Option<usize>,
    updateval: u32,
    threads: &mut Threads<'_>,
) -> Woke {
    let idx = i.unwrap_or(0);
    let tid = kwq.queues[QUEUE_WRITE].list[idx].tid;
    let w = super::ksyn_signal(kwq, addr, QUEUE_WRITE, Some(idx), updateval, threads);
    kwq.owner = (w == Woke::Success).then_some(tid);
    w
}

/// `_psynch_mutexdrop_internal`: releases the mutex to its next waiter,
/// or preposts the unlock for a waiter still on its way. Drops the
/// reference `find` took.
pub(super) fn drop_internal(
    table: &mut Table,
    threads: &mut Threads<'_>,
    addr: u64,
    mgen: u32,
    ugen: u32,
    flags: u32,
) -> u32 {
    let first = firstfit(flags);
    let nextgen = ugen.wrapping_add(PTHRW_INC);
    let kwq = table.get_mut(addr);
    kwq.lastunlockseq = ugen & PTHRW_COUNT_MASK;
    loop {
        let updatebits = (kwq.highseq & PTHRW_COUNT_MASK) | lbit::E | lbit::K;
        if first {
            if kwq.inqueue == 0 {
                // A locker is on its way into the kernel: prepost.
                let count = kwq.prepost.0 + 1;
                kwq.prepost = (count, mgen & PTHRW_COUNT_MASK, 0);
                kwq.owner = None;
            } else if mtxsignal(kwq, addr, None, updatebits, threads) == Woke::NotWaiting {
                continue;
            }
            break;
        }
        let mut prepost = false;
        if kwq.inqueue == 0 {
            prepost = true;
        } else {
            let low_writer = kwq.queues[QUEUE_WRITE].firstnum & PTHRW_COUNT_MASK;
            if low_writer == nextgen {
                // The grant could be a condition wait's: mark the mutex
                // wait in case the thread was interrupted.
                if mtxsignal(kwq, addr, None, updatebits | lbit::MTX_WAIT, threads)
                    == Woke::NotWaiting
                {
                    kwq.intr = (intr::WRITE, 1, nextgen, updatebits);
                }
            } else if is_seqhigher(low_writer, nextgen) {
                prepost = true;
            } else if let Some(i) = kwq.find_seq(QUEUE_WRITE, nextgen) {
                if mtxsignal(kwq, addr, Some(i), updatebits | lbit::MTX_WAIT, threads)
                    == Woke::NotWaiting
                {
                    continue;
                }
            } else {
                prepost = true;
            }
        }
        if prepost {
            // One prepost at a time ("multiple preposts" is a user error
            // the kernel only logs).
            if kwq.prepost.0 == 0 {
                kwq.prepost = (1, nextgen & PTHRW_COUNT_MASK, 0);
            }
            kwq.owner = None;
        }
        break;
    }
    table.release(addr, true, wqtype::MUTEXDROP);
    0
}

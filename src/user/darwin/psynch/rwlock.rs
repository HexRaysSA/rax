//! Read-write locks: `psynch_rw_rdlock`, `psynch_rw_wrlock`, and
//! `psynch_rw_unlock` (`__psynch_rw_lock`, `_psynch_rw_unlock`,
//! `kwq_handle_unlock`, `kwq_find_rw_lowest`, `ksyn_wakeupreaders`,
//! `_psynch_rw_continue`).

use super::{
    Cont, Fit, Kwq, PTHRW_BIT_MASK, PTHRW_COUNT_MASK, PTHRW_COUNT_SHIFT, PTHRW_INC, PTHRW_RWL_INIT,
    QUEUE_READ, QUEUE_WRITE, Threads, WaitResult, Woke, find_diff, intr, is_seqhigher_eq,
    is_seqlower, is_seqlower_eq, kwf, lbit, parts, result, rwt, sbit, unlock, wqtype,
};
use crate::user::darwin::arch::SysResult;
use crate::user::darwin::syscall::Ctx;

/// `_kwq_handle_overlap`: a reader may join readers the kernel already
/// granted (`KSYN_KWF_OVERLAP_GUARD`) when no writer waits.
fn handle_overlap(kwq: &mut Kwq, kind: u32, lgenval: u32, rw_wc: u32) -> Option<u32> {
    if kind != rwt::READ {
        return None;
    }
    if kwq.kflags & kwf::OVERLAP_GUARD != 0
        && rw_wc & sbit::SAVEMASK == 0
        && lgenval & lbit::W == 0
        && (is_seqlower_eq(rw_wc, kwq.nextseqword) || is_seqhigher_eq(kwq.lastseqword, rw_wc))
    {
        kwq.nextseqword = kwq.nextseqword.wrapping_add(PTHRW_INC);
        return Some(PTHRW_INC | (kwq.nextseqword & PTHRW_BIT_MASK) | lbit::M);
    }
    None
}

/// `_kwq_handle_preposted_wakeup`: the last of the preposted waiters
/// arrived; hand out the unlock now.
fn handle_preposted(
    kwq: &mut Kwq,
    addr: u64,
    kind: u32,
    lseq: u32,
    threads: &mut Threads<'_>,
) -> Option<u32> {
    if kwq.prepost.0 == 0 || !is_seqlower_eq(lseq, kwq.prepost.1) {
        return None;
    }
    kwq.prepost.0 -= 1;
    if kwq.prepost.0 > 0 {
        return None;
    }
    let (pp_lseq, pp_sseq) = (kwq.prepost.1, kwq.prepost.2);
    kwq.clear_preposted();
    kwq.kflags &= !kwf::INITCLEARED;
    let (updatebits, block) = handle_unlock(
        kwq,
        addr,
        pp_lseq,
        pp_sseq,
        kind | unlock::PREPOST,
        lseq,
        threads,
    );
    (!block).then_some(updatebits)
}

/// `kwq_find_rw_lowest`: the type of the lowest waiter (read or write),
/// with the shifted types present, and the lowest sequence of each queue.
fn find_rw_lowest(kwq: &Kwq, flags: u32, premgen: u32) -> (u32, [u32; 2]) {
    let mut kind = 0;
    let mut lowest = [0u32; 2];
    let mut candidates: Vec<(u32, u32)> = Vec::new();
    let read = &kwq.queues[QUEUE_READ];
    if !read.list.is_empty() || flags & unlock::PREPOST_READLOCK != 0 {
        kind |= rwt::SHFT_READ;
        let mut fr = if !read.list.is_empty() {
            read.firstnum
        } else {
            premgen
        };
        if !read.list.is_empty()
            && flags & unlock::PREPOST_READLOCK != 0
            && is_seqlower(premgen, fr)
        {
            fr = premgen;
        }
        lowest[QUEUE_READ] = fr;
        candidates.push((fr, rwt::READ));
    }
    let write = &kwq.queues[QUEUE_WRITE];
    if !write.list.is_empty() || flags & unlock::PREPOST_WRLOCK != 0 {
        kind |= rwt::SHFT_WRITE;
        let mut fw = if !write.list.is_empty() {
            write.firstnum
        } else {
            premgen
        };
        if !write.list.is_empty() && flags & unlock::PREPOST_WRLOCK != 0 && is_seqlower(premgen, fw)
        {
            fw = premgen;
        }
        lowest[QUEUE_WRITE] = fw;
        candidates.push((fw, rwt::WRITE));
    }
    let (mut low, mut lowtype) = candidates[0];
    for &(n, t) in &candidates[1..] {
        if is_seqlower(n, low) {
            low = n;
            lowtype = t;
        }
    }
    (kind | lowtype, lowest)
}

/// `ksyn_wakeupreaders`: grants `updatebits` to the readers below
/// `limitread` (or all); returns how many were no longer waiting.
fn wake_readers(
    kwq: &mut Kwq,
    addr: u64,
    limitread: u32,
    all: bool,
    updatebits: u32,
    threads: &mut Threads<'_>,
) -> u32 {
    let mut failed = 0;
    while !kwq.queues[QUEUE_READ].list.is_empty()
        && (all || is_seqlower(kwq.queues[QUEUE_READ].firstnum, limitread))
    {
        if super::ksyn_signal(kwq, addr, QUEUE_READ, None, updatebits, threads) == Woke::NotWaiting
        {
            failed += 1;
        }
    }
    failed
}

/// `kwq_handle_unlock`: grants the lock to the next set of waiters (all
/// readers below the lowest writer, or one writer). With a prepost,
/// `premgen` is the arriving waiter's sequence and it may take the grant
/// itself. Returns the update bits and whether that waiter must block.
fn handle_unlock(
    kwq: &mut Kwq,
    addr: u64,
    _mgen: u32,
    rw_wc: u32,
    flags: u32,
    premgen: u32,
    threads: &mut Threads<'_>,
) -> (u32, bool) {
    let mut block = true;
    kwq.lastseqword = rw_wc;
    kwq.lastunlockseq = rw_wc & PTHRW_COUNT_MASK;
    kwq.kflags &= !kwf::OVERLAP_GUARD;
    let (rwtype, lowest) = find_rw_lowest(kwq, flags, premgen);
    let low_writer = lowest[QUEUE_WRITE];
    let mut updatebits = 0u32;
    match rwtype & rwt::MASK {
        rwt::READ => {
            if rwtype & rwt::SHFT_MASK != 0 && rwtype & rwt::SHFT_WRITE != 0 {
                updatebits |= lbit::W | lbit::K;
            }
            let mut limitrdnum = 0;
            let mut allreaders = false;
            let mut numneeded = 0;
            let mut curthreturns = false;
            if rwtype & rwt::SHFT_WRITE != 0 {
                limitrdnum = low_writer;
                numneeded = kwq.count_tolowest(QUEUE_READ, limitrdnum);
                if flags & unlock::PREPOST_READLOCK != 0 && is_seqlower(premgen, limitrdnum) {
                    curthreturns = true;
                    numneeded += 1;
                }
            } else {
                allreaders = true;
                // Only readers: later readers may overlap.
                kwq.kflags |= kwf::OVERLAP_GUARD;
                numneeded += kwq.queues[QUEUE_READ].list.len() as u32;
                if flags & unlock::PREPOST_READLOCK != 0 {
                    curthreturns = true;
                    numneeded += 1;
                }
            }
            updatebits = updatebits.wrapping_add(numneeded << PTHRW_COUNT_SHIFT);
            kwq.nextseqword = (rw_wc & PTHRW_COUNT_MASK).wrapping_add(updatebits);
            if curthreturns {
                block = false;
                threads.running.pw.retval = updatebits;
            }
            let nfailed = wake_readers(kwq, addr, limitrdnum, allreaders, updatebits, threads);
            if nfailed != 0 {
                kwq.intr = (intr::READ, nfailed, limitrdnum, updatebits);
            }
        }
        rwt::WRITE => {
            updatebits |= PTHRW_INC | lbit::K | lbit::E;
            if flags & unlock::PREPOST_WRLOCK != 0 && low_writer == premgen {
                block = false;
                if !kwq.queues[QUEUE_WRITE].list.is_empty() {
                    updatebits |= lbit::W;
                }
                threads.running.pw.retval = updatebits;
            } else {
                // Not the preposting writer: set W when other writers remain.
                if kwq.queues[QUEUE_WRITE].list.len() > 1 || flags & unlock::PREPOST_WRLOCK != 0 {
                    updatebits |= lbit::W;
                }
                if super::ksyn_signal(kwq, addr, QUEUE_WRITE, None, updatebits, threads)
                    == Woke::NotWaiting
                {
                    kwq.intr = (intr::WRITE, 1, low_writer, updatebits);
                }
            }
            kwq.nextseqword = (rw_wc & PTHRW_COUNT_MASK).wrapping_add(updatebits);
        }
        _ => unreachable!("kwq_find_rw_lowest reports read or write"),
    }
    (updatebits, block)
}

/// `__psynch_rw_lock` for `psynch_rw_rdlock` and `psynch_rw_wrlock`.
pub fn lock(
    ctx: &mut Ctx<'_>,
    write: bool,
    addr: u64,
    lgenval: u32,
    ugenval: u32,
    rw_wc: u32,
) -> SysResult {
    if let Some(r) = super::resume(ctx) {
        return r;
    }
    let lockseq = lgenval & PTHRW_COUNT_MASK;
    let (kind, prepost_type, kqi, cont) = if write {
        (
            rwt::WRITE,
            unlock::PREPOST_WRLOCK,
            QUEUE_WRITE,
            Cont::RwWrite,
        )
    } else {
        (
            rwt::READ,
            unlock::PREPOST_READLOCK,
            QUEUE_READ,
            Cont::RwRead,
        )
    };
    ctx.proc.psynch.find(
        addr,
        lgenval,
        ugenval,
        rw_wc,
        wqtype::INWAIT | wqtype::RWLOCK,
    )?;
    let (table, mut threads) = parts(ctx);
    let kwq = table.get_mut(addr);
    kwq.check_init(lgenval);
    // The kernel compares the interrupted-wakeup type with the lock type
    // itself (PTH_RW_TYPE_*, not KWQ_INTR_*).
    let granted = super::mutex::take_interrupted(kwq, kind, lockseq)
        .or_else(|| handle_overlap(kwq, kind, lgenval, rw_wc))
        .or_else(|| handle_preposted(kwq, addr, prepost_type, lockseq, &mut threads));
    if let Some(v) = granted {
        table.release(addr, false, wqtype::INWAIT | wqtype::RWLOCK);
        return result(0, v);
    }
    super::ksyn_wait(ctx, addr, kqi, lgenval, Fit::Seq, None, cont)
}

/// `psynch_rw_rdcontinue`, `psynch_rw_wrcontinue`.
pub fn continuation(ctx: &mut Ctx<'_>, addr: u64, kqi: usize, r: WaitResult) -> SysResult {
    let me = ctx.thread.tid;
    let retval = ctx.thread.pw.retval;
    let kwq = ctx.proc.psynch.get_mut(addr);
    let error = r.errno();
    if error != 0
        && let Some(i) = kwq.position_of(kqi, me)
    {
        kwq.remove(kqi, i);
    }
    ctx.proc
        .psynch
        .release(addr, false, wqtype::INWAIT | wqtype::RWLOCK);
    result(error, if error == 0 { retval } else { 0 })
}

/// `psynch_rw_unlock(rwlock, lgenval, ugenval, rw_wc, flags)`.
pub fn unlock_call(
    ctx: &mut Ctx<'_>,
    addr: u64,
    lgenval: u32,
    ugenval: u32,
    rw_wc: u32,
) -> SysResult {
    let curgen = lgenval & PTHRW_COUNT_MASK;
    ctx.proc.psynch.find(
        addr,
        lgenval,
        ugenval,
        rw_wc,
        wqtype::INDROP | wqtype::RWLOCK,
    )?;
    let (table, mut threads) = parts(ctx);
    let kwq = table.get_mut(addr);
    let isinit = kwq.check_init(lgenval);
    let mut updatebits = 0;
    let mut clearedkflags = false;
    // An unlock below the last one is spurious.
    let spurious = kwq.lastunlockseq != PTHRW_RWL_INIT && is_seqlower(ugenval, kwq.lastunlockseq);
    if !spurious {
        // L - U waiters must all be here, else prepost.
        let diff = find_diff(lgenval, ugenval);
        let (found, count) = kwq.find_seq_till(curgen, diff);
        if !found && (count == 0 || count < diff) {
            if kwq.prepost.2 & sbit::S != 0 || is_seqhigher_eq(rw_wc, kwq.prepost.2) {
                kwq.prepost = (diff - count, curgen, rw_wc);
                updatebits = lgenval;
            }
        } else {
            if isinit && kwq.kflags & kwf::INITCLEARED != 0 {
                kwq.kflags &= !kwf::INITCLEARED;
                clearedkflags = true;
            }
            kwq.clear_preposted();
            updatebits = handle_unlock(kwq, addr, lgenval, rw_wc, 0, 0, &mut threads).0;
        }
    }
    // A wakeup that failed because its thread returned for a signal must
    // not let that thread clear the reset state.
    if clearedkflags && kwq.intr.1 > 0 {
        kwq.kflags |= kwf::INITCLEARED;
    }
    table.release(addr, false, wqtype::INDROP | wqtype::RWLOCK);
    result(0, updatebits)
}

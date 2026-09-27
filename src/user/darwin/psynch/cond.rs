//! Condition variables: `psynch_cvwait`, `psynch_cvsignal`,
//! `psynch_cvbroad`, and `psynch_cvclrprepost` (`_psynch_cvwait`,
//! `__psynch_cvsignal`, `psynch_cvcontinue`, `ksyn_handle_cvbroad`,
//! `ksyn_cvupdate_fixup`, `ksyn_queue_free_items`).

use std::time::{Duration, Instant};

use super::{
    Cont, ECVCLEARED, ECVPREPOST, Fit, KweState, Kwq, PTHRW_COUNT_MASK, PTHRW_COUNT_SHIFT,
    PTHRW_INC, QUEUE_WRITE, Threads, WaitResult, Woke, diff_genseq, is_seqhigher, is_seqhigher_eq,
    is_seqlower, is_seqlower_eq, lbit, opt, parts, result, sbit, wqtype,
};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::SysResult;
use crate::user::darwin::mach::ipc::KObject;
use crate::user::darwin::syscall::Ctx;

/// `ksyn_queue_find_cvpreposeq`: the entry at or above `cgen` (a waiting
/// thread only at exactly `cgen`).
fn find_cvpreposeq(kwq: &Kwq, cgen: u32) -> Option<usize> {
    let lgen = cgen & PTHRW_COUNT_MASK;
    for (i, k) in kwq.queues[QUEUE_WRITE].list.iter().enumerate() {
        if is_seqhigher_eq(k.lockseq, cgen) {
            if k.state == KweState::InWait && k.lockseq & PTHRW_COUNT_MASK != lgen {
                return None;
            }
            return Some(i);
        }
    }
    None
}

/// `ksyn_queue_find_signalseq`: a fake entry at or above `uptoseq`, or a
/// waiting (not cancelled) thread at or below it, preferring one at or
/// above `signalseq`.
fn find_signalseq(
    kwq: &Kwq,
    uptoseq: u32,
    signalseq: u32,
    threads: &mut Threads<'_>,
) -> Option<usize> {
    let mut result = None;
    for (i, k) in kwq.queues[QUEUE_WRITE].list.iter().enumerate() {
        if k.state == KweState::Prepost && is_seqhigher(k.lockseq, uptoseq) {
            return result;
        }
        match k.state {
            KweState::Prepost | KweState::Broadcast => {
                if is_seqlower(k.lockseq, uptoseq) {
                    continue;
                }
                return Some(i);
            }
            KweState::InWait => {
                if is_seqhigher(k.lockseq, uptoseq) {
                    return result;
                }
                if !threads.cancelled(k.tid) {
                    if is_seqhigher_eq(k.lockseq, signalseq) {
                        return Some(i);
                    }
                    if result.is_none() {
                        result = Some(i);
                    }
                }
            }
        }
    }
    result
}

fn cancelled_fn<'a>(threads: &'a mut Threads<'_>) -> impl FnMut(u64) -> bool + 'a {
    move |tid| threads.cancelled(tid)
}

/// `ksyn_queue_free_items`: wakes waiting threads (as spurious wakeups
/// that reset the variable) and frees fake entries up to `upto` (or all).
pub(super) fn free_items(
    kwq: &mut Kwq,
    addr: u64,
    upto: u32,
    all: bool,
    threads: &mut Threads<'_>,
) {
    let tseq = upto & PTHRW_COUNT_MASK;
    while let Some(k) = kwq.queues[QUEUE_WRITE].list.first().copied() {
        if !all && is_seqhigher(k.lockseq, tseq) {
            break;
        }
        if k.state == KweState::InWait {
            super::ksyn_signal(
                kwq,
                addr,
                QUEUE_WRITE,
                Some(0),
                PTHRW_INC | sbit::CV_M | lbit::MTX_WAIT,
                threads,
            );
        } else {
            kwq.remove(QUEUE_WRITE, 0);
            kwq.fakecount -= 1;
        }
    }
}

/// `ksyn_handle_cvbroad`: wakes every (not cancelled) waiter up to `upto`,
/// drops fake entries there, and leaves a broadcast entry for waiters
/// still on their way when the variable is not balanced.
fn handle_broadcast(
    kwq: &mut Kwq,
    addr: u64,
    upto: u32,
    updatep: &mut u32,
    threads: &mut Threads<'_>,
) {
    let mut updatebits = 0u32;
    let mut i = 0;
    while let Some(k) = kwq.queues[QUEUE_WRITE].list.get(i).copied() {
        if is_seqhigher(k.lockseq, upto) {
            break;
        }
        match k.state {
            KweState::InWait => {
                if threads.cancelled(k.tid) {
                    i += 1;
                } else {
                    super::ksyn_signal(kwq, addr, QUEUE_WRITE, Some(i), lbit::MTX_WAIT, threads);
                    updatebits = updatebits.wrapping_add(PTHRW_INC);
                }
            }
            KweState::Broadcast | KweState::Prepost => {
                kwq.remove(QUEUE_WRITE, i);
                kwq.fakecount -= 1;
            }
        }
    }
    if diff_genseq(kwq.lword, kwq.sword) != 0 {
        kwq.prepost(KweState::Broadcast, upto, &mut cancelled_fn(threads));
    }
    *updatep |= updatebits;
}

/// `ksyn_cvupdate_fixup`: clears a balanced variable (`PTH_RWS_CV_CBIT`)
/// or reports one with only fake entries (`PTH_RWS_CV_PBIT`).
fn update_fixup(kwq: &mut Kwq, addr: u64, updatebits: &mut u32, threads: &mut Threads<'_>) {
    if kwq.lword & PTHRW_COUNT_MASK == kwq.sword & PTHRW_COUNT_MASK {
        if kwq.inqueue != 0 {
            free_items(kwq, addr, kwq.lword, false, threads);
        }
        kwq.lword = 0;
        kwq.uword = 0;
        kwq.sword = 0;
        kwq.kflags |= super::kwf::ZEROEDOUT;
        *updatebits |= sbit::CV_C;
    } else if kwq.inqueue != 0 && kwq.fakecount == kwq.inqueue {
        *updatebits |= sbit::CV_P;
    }
}

/// `_ksyn_cvsignal_any`.
fn signal_any(
    kwq: &mut Kwq,
    addr: u64,
    uptoseq: u32,
    signalseq: u32,
    updatebits: &mut u32,
    broadcast: &mut bool,
    threads: &mut Threads<'_>,
) {
    match find_signalseq(kwq, uptoseq, signalseq, threads) {
        Some(i) => {
            let k = kwq.queues[QUEUE_WRITE].list[i];
            match k.state {
                KweState::InWait => {
                    if is_seqlower(k.lockseq, signalseq) {
                        // Waking a lower waiter could strand this signal's
                        // own; broadcast instead (spurious wakeups are
                        // allowed).
                        *broadcast = true;
                    } else {
                        super::ksyn_signal(
                            kwq,
                            addr,
                            QUEUE_WRITE,
                            Some(i),
                            lbit::MTX_WAIT,
                            threads,
                        );
                        *updatebits = updatebits.wrapping_add(PTHRW_INC);
                    }
                }
                KweState::Prepost => kwq.queues[QUEUE_WRITE].list[i].count += 1,
                KweState::Broadcast => {}
            }
        }
        None => kwq.prepost(KweState::Prepost, uptoseq, &mut cancelled_fn(threads)),
    }
}

/// `_ksyn_cvsignal_thread`.
fn signal_thread(
    kwq: &mut Kwq,
    addr: u64,
    tid: u64,
    uptoseq: u32,
    signalseq: u32,
    updatebits: &mut u32,
    broadcast: &mut bool,
    threads: &mut Threads<'_>,
) {
    let (w, kwe) = super::ksyn_signal_thread(kwq, addr, QUEUE_WRITE, tid, lbit::MTX_WAIT, threads);
    let Some(kwe) = kwe.filter(|_| w == Woke::Success) else {
        *broadcast = true;
        return;
    };
    if is_seqhigher(kwe.lockseq, uptoseq) || is_seqlower(kwe.lockseq, signalseq) {
        *broadcast = true;
        return;
    }
    *updatebits = updatebits.wrapping_add(PTHRW_INC);
}

/// `__psynch_cvsignal` for `psynch_cvsignal` (one waiter, or the thread
/// `threadport`) and `psynch_cvbroad` (every waiter).
#[allow(clippy::too_many_arguments)]
fn cvsignal(
    ctx: &mut Ctx<'_>,
    addr: u64,
    cgen: u32,
    cugen: u32,
    csgen: u32,
    flags: u32,
    mut broadcast: bool,
    threadport: u32,
) -> SysResult {
    let _ = flags;
    let uptoseq = cgen & PTHRW_COUNT_MASK;
    let fromseq = (cugen & PTHRW_COUNT_MASK).wrapping_add(PTHRW_INC);
    if (threadport == 0 && is_seqhigher(fromseq, uptoseq)) || is_seqhigher(csgen, uptoseq) {
        return Err(Errno::EINVAL);
    }
    let target = if threadport != 0 {
        let tid = ctx
            .proc
            .ipc
            .lookup(threadport)
            .ok()
            .and_then(|e| e.port().cloned())
            .and_then(|p| match p.kobject {
                KObject::Thread(tid) => Some(tid),
                _ => None,
            });
        Some(tid.ok_or(Errno::ESRCH)?)
    } else {
        None
    };
    ctx.proc
        .psynch
        .find(addr, cgen, cugen, csgen, wqtype::CVAR | wqtype::INDROP)?;
    let (table, mut threads) = parts(ctx);
    let kwq = table.get_mut(addr);
    let mut updatebits = 0u32;
    kwq.update_cv(cgen, cugen, csgen);
    if !broadcast && diff_genseq(kwq.lword, kwq.sword) != 0 {
        match target {
            Some(tid) => signal_thread(
                kwq,
                addr,
                tid,
                uptoseq,
                fromseq,
                &mut updatebits,
                &mut broadcast,
                &mut threads,
            ),
            None => signal_any(
                kwq,
                addr,
                uptoseq,
                fromseq,
                &mut updatebits,
                &mut broadcast,
                &mut threads,
            ),
        }
    }
    if broadcast {
        handle_broadcast(kwq, addr, uptoseq, &mut updatebits, &mut threads);
    }
    kwq.sword = kwq.sword.wrapping_add(updatebits & PTHRW_COUNT_MASK);
    update_fixup(kwq, addr, &mut updatebits, &mut threads);
    table.release(addr, true, wqtype::INDROP | wqtype::CVAR);
    result(0, updatebits)
}

/// The most threads a task may have (`task_threadmax`), the bound on a
/// broadcast's waiter count.
const TASK_THREADMAX: u32 = 1 << 15;

/// `psynch_cvbroad(cv, cvlsgen, cvudgen, flags, mutex, mugen, tid)`.
pub fn cvbroad(ctx: &mut Ctx<'_>, addr: u64, cvlsgen: u64, cvudgen: u64, flags: u32) -> SysResult {
    let diffgen = cvudgen as u32;
    if diffgen >> PTHRW_COUNT_SHIFT > TASK_THREADMAX {
        return Err(Errno::EBUSY);
    }
    let csgen = (cvlsgen >> 32) as u32;
    let cgen = cvlsgen as u32;
    let cugen = (cvudgen >> 32) as u32;
    cvsignal(ctx, addr, cgen, cugen, csgen, flags, true, 0)
}

/// `psynch_cvsignal(cv, cvlsgen, cvugen, thread_port, mutex, mugen, tid,
/// flags)`.
pub fn cvsignal_call(
    ctx: &mut Ctx<'_>,
    addr: u64,
    cvlsgen: u64,
    cvugen: u32,
    threadport: u32,
    flags: u32,
) -> SysResult {
    let csgen = (cvlsgen >> 32) as u32;
    let cgen = cvlsgen as u32;
    cvsignal(ctx, addr, cgen, cvugen, csgen, flags, false, threadport)
}

/// `psynch_cvwait(cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec)`:
/// drops the mutex and waits; the timeout is relative.
#[allow(clippy::too_many_arguments)]
pub fn cvwait(
    ctx: &mut Ctx<'_>,
    addr: u64,
    cvlsgen: u64,
    cvugen: u32,
    mutex: u64,
    mugen: u64,
    flags: u32,
    sec: i64,
    nsec: u32,
) -> SysResult {
    if let Some(r) = super::resume(ctx) {
        return r;
    }
    // A cancellation point for conformance (`__pthread_testcancel(0)`).
    crate::user::darwin::syscall::bsd::pthread::testcancel_abort(ctx);
    let csgen = (cvlsgen >> 32) as u32;
    let cgen = cvlsgen as u32;
    let ugen = (mugen >> 32) as u32;
    let mgen = mugen as u32;
    let lockseq = cgen & PTHRW_COUNT_MASK;
    if is_seqhigher_eq(csgen, lockseq) {
        return Err(Errno::EINVAL);
    }
    ctx.proc
        .psynch
        .find(addr, cgen, cvugen, csgen, wqtype::CVAR | wqtype::INWAIT)?;
    if mutex != 0 {
        if let Err(e) = super::mutex::mutexdrop(ctx, mutex, mgen, ugen, flags) {
            ctx.proc
                .psynch
                .release(addr, true, wqtype::INWAIT | wqtype::CVAR);
            return Err(e);
        }
    }
    let (table, mut threads) = parts(ctx);
    let kwq = table.get_mut(addr);
    kwq.update_cv(cgen, cvugen, csgen);
    if let Some(i) = find_cvpreposeq(kwq, lockseq) {
        // A signal or broadcast got here first.
        let mut updatebits = 0u32;
        let k = kwq.queues[QUEUE_WRITE].list[i];
        let mut error = 0;
        match k.state {
            KweState::Prepost => {
                if k.lockseq & PTHRW_COUNT_MASK == lockseq {
                    kwq.queues[QUEUE_WRITE].list[i].count -= 1;
                    if k.count == 1 {
                        kwq.remove(QUEUE_WRITE, i);
                        kwq.fakecount -= 1;
                    }
                } else {
                    // A prepost above this waiter's sequence: convert it to
                    // a broadcast so the higher waiter is not stranded.
                    handle_broadcast(kwq, addr, k.lockseq, &mut updatebits, &mut threads);
                }
            }
            KweState::Broadcast => {}
            KweState::InWait => error = Errno::EBUSY.0,
        }
        if error == 0 {
            updatebits |= PTHRW_INC;
            kwq.sword = kwq.sword.wrapping_add(PTHRW_INC);
            update_fixup(kwq, addr, &mut updatebits, &mut threads);
        }
        table.release(addr, true, wqtype::INWAIT | wqtype::CVAR);
        return result(error, updatebits);
    }
    let deadline = if sec != 0 || nsec & 0x3fff_ffff != 0 {
        let d = Duration::from_secs(sec.max(0) as u64)
            + Duration::from_nanos(u64::from(nsec & 0x3fff_ffff));
        Some(Instant::now() + d)
    } else {
        None
    };
    super::ksyn_wait(ctx, addr, QUEUE_WRITE, cgen, Fit::Seq, deadline, Cont::Cond)
}

/// `psynch_cvcontinue`.
pub fn continuation(ctx: &mut Ctx<'_>, addr: u64, r: WaitResult) -> SysResult {
    let me = ctx.thread.tid;
    let kwe_retval = ctx.thread.pw.retval;
    let (table, mut threads) = parts(ctx);
    let kwq = table.get_mut(addr);
    let mut error = r.errno();
    let mut retval = 0;
    if error != 0 {
        // Just in case it was granted as it was interrupted.
        retval = kwe_retval;
        if let Some(i) = kwq.position_of(QUEUE_WRITE, me) {
            kwq.remove(QUEUE_WRITE, i);
        }
        if kwe_retval & lbit::MTX_WAIT != 0 {
            // The variable was granted: the thread returns normally.
            error = 0;
        } else {
            kwq.sword = kwq.sword.wrapping_add(PTHRW_INC);
            if kwq.lword & PTHRW_COUNT_MASK == kwq.sword & PTHRW_COUNT_MASK {
                error |= ECVCLEARED;
                if kwq.inqueue != 0 {
                    let lword = kwq.lword;
                    free_items(kwq, addr, lword, true, &mut threads);
                }
                kwq.lword = 0;
                kwq.uword = 0;
                kwq.sword = 0;
                kwq.kflags |= super::kwf::ZEROEDOUT;
            } else if kwq.inqueue != 0 && kwq.fakecount == kwq.inqueue {
                error |= ECVPREPOST;
            }
        }
    } else if kwe_retval & sbit::CV_M != 0 {
        retval = PTHRW_INC | sbit::CV_C;
    }
    table.release(addr, true, wqtype::INWAIT | wqtype::CVAR);
    result(error, retval)
}

/// `psynch_cvclrprepost(cv, cvgen, cvugen, cvsgen, prepocnt, preposeq,
/// flags)`: drops preposts a returning waiter no longer needs (for a
/// mutex, a first-fit prepost at or below `cvgen`).
pub fn cvclrprepost(
    ctx: &mut Ctx<'_>,
    addr: u64,
    cvgen: u32,
    cvugen: u32,
    cvsgen: u32,
    preposeq: u32,
    flags: u32,
) -> SysResult {
    let mutex = flags & opt::MUTEX != 0;
    let kind = if mutex { wqtype::MTX } else { wqtype::CVAR } | wqtype::INDROP;
    ctx.proc
        .psynch
        .find(addr, cvgen, cvugen, if mutex { 0 } else { cvsgen }, kind)?;
    let (table, mut threads) = parts(ctx);
    let kwq = table.get_mut(addr);
    if mutex {
        let firstfit = flags & opt::POLICY_MASK == opt::POLICY_FIRSTFIT;
        if firstfit && kwq.prepost.0 != 0 && is_seqlower_eq(kwq.prepost.1, cvgen) {
            kwq.clear_preposted();
        }
    } else {
        free_items(kwq, addr, preposeq, false, &mut threads);
    }
    table.release(addr, true, kind);
    result(0, 0)
}

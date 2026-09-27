//! Signal actions, masks, alternate stacks, waiting for and sending
//! signals, `sigreturn`, and interval timers (`bsd/kern/kern_sig.c`,
//! `bsd/kern/kern_time.c`).

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::signal::timer::{ITIMER_PROF, ITimerVal, TimeVal};
use crate::user::darwin::signal::{
    self, CANTMASK, NSIG, Origin, SIGKILL, SIGSTOP, SS_DISABLE, SS_ONSTACK, SigAction, Validation,
    bit, frame, sa,
};
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::Wait;

/// `__sigaction(sig, nsa, osa)`: `nsa` is a `struct __sigaction` (handler,
/// trampoline, mask, flags: 24 bytes), `osa` a `struct sigaction`
/// (handler, mask, flags: 16 bytes).
pub fn sigaction(ctx: &mut Ctx<'_>, sig: i32, nsa: u64, osa: u64) -> SysResult {
    if sig <= 0 || sig >= NSIG || sig == SIGKILL || sig == SIGSTOP {
        return Err(Errno::EINVAL);
    }
    let new = if nsa != 0 {
        let b = ctx.read(nsa, 24)?;
        let flags = u32::from_le_bytes(b[20..24].try_into().expect("4 bytes"));
        let validation = if flags & sa::VALIDATE_SIGRETURN != 0 {
            Validation::Enabled
        } else {
            Validation::Disabled
        };
        let action = SigAction {
            handler: u64::from_le_bytes(b[0..8].try_into().expect("8 bytes")),
            tramp: u64::from_le_bytes(b[8..16].try_into().expect("8 bytes")),
            mask: u32::from_le_bytes(b[16..20].try_into().expect("4 bytes")),
            flags: flags & sa::USERSPACE_MASK,
        };
        Some((action, validation))
    } else {
        None
    };
    if osa != 0 {
        let old = ctx.proc.sigacts.get(sig);
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&old.handler.to_le_bytes());
        b[8..12].copy_from_slice(&old.mask.to_le_bytes());
        b[12..16].copy_from_slice(&old.flags.to_le_bytes());
        ctx.write(osa, &b)?;
    }
    if let Some((action, validation)) = new {
        let acts = &mut ctx.proc.sigacts;
        if acts.validation == Validation::Default {
            acts.validation = validation;
        }
        if acts.set(sig, &action) {
            signal::clear_pending(ctx.proc, Some(ctx.thread), sig);
        }
    }
    Ok(Rv::one(0))
}

/// `SIG_BLOCK`, `SIG_UNBLOCK`, `SIG_SETMASK`.
const SIG_BLOCK: i32 = 1;
const SIG_UNBLOCK: i32 = 2;
const SIG_SETMASK: i32 = 3;

/// `sigprocmask(how, set, oset)`: on Darwin the new mask applies to every
/// thread of the process (`block_procsigmask`, `set_procsigmask`); the old
/// mask reported is the caller's.
pub fn sigprocmask(ctx: &mut Ctx<'_>, how: i32, set: u64, oset: u64) -> SysResult {
    let old = ctx.thread.sig.mask;
    if set != 0 {
        let s = ctx.read_u32(set)? & !CANTMASK;
        let apply = |m: u32| match how {
            SIG_BLOCK => Some(m | s),
            SIG_UNBLOCK => Some(m & !s),
            SIG_SETMASK => Some(s),
            _ => None,
        };
        if apply(0).is_none() {
            return Err(Errno::EINVAL);
        }
        ctx.thread.sig.mask = apply(ctx.thread.sig.mask).expect("valid how");
        for t in ctx.proc.threads.values_mut() {
            t.sig.mask = apply(t.sig.mask).expect("valid how");
        }
    }
    if oset != 0 {
        let _ = ctx.write_u32(oset, old);
    }
    Ok(Rv::one(0))
}

/// `__pthread_sigmask(how, set, oset)`: the calling thread's mask.
pub fn pthread_sigmask(ctx: &mut Ctx<'_>, how: i32, set: u64, oset: u64) -> SysResult {
    let old = ctx.thread.sig.mask;
    if set != 0 {
        let s = ctx.read_u32(set)?;
        let m = &mut ctx.thread.sig.mask;
        match how {
            SIG_BLOCK => *m |= s & !CANTMASK,
            SIG_UNBLOCK => *m &= !s,
            SIG_SETMASK => *m = s & !CANTMASK,
            _ => return Err(Errno::EINVAL),
        }
    }
    if oset != 0 {
        let _ = ctx.write_u32(oset, old);
    }
    Ok(Rv::one(0))
}

/// `sigpending(osv)`: the calling thread's pending signals (a copy-out
/// failure is not reported).
pub fn sigpending(ctx: &mut Ctx<'_>, set: u64) -> SysResult {
    let pending = ctx.thread.sig.pending & !CANTMASK;
    if set != 0 {
        let _ = ctx.write_u32(set, pending);
    }
    Ok(Rv::one(0))
}

/// `__sigsuspend(mask)`: waits for a signal with `mask` in place; the
/// handler's return restores the previous mask. Always `EINTR`.
pub fn sigsuspend(ctx: &mut Ctx<'_>, mask: u32) -> SysResult {
    if ctx.thread.resume.is_none() {
        let t = &mut ctx.thread.sig;
        t.oldmask = Some(t.mask);
        t.mask = mask & !CANTMASK;
    }
    match syscall::sleep(ctx, Wait::until(None)) {
        r if syscall::interrupted(ctx, &r) => Err(Errno::EINTR),
        r => r,
    }
}

/// `__sigwait(set, sig)`: takes a pending signal of `set` from any thread,
/// or waits for one with every other signal blocked.
pub fn sigwait(ctx: &mut Ctx<'_>, set: u64, sig_out: u64) -> SysResult {
    if set == 0 {
        return Err(Errno::EINVAL);
    }
    let siglist = ctx.read_u32(set)? & !CANTMASK;
    if siglist == 0 {
        return Err(Errno::EINVAL);
    }
    let sigw = if ctx.thread.resume.is_none() {
        // Pending on some thread (in creation order): take it there.
        let running = ctx.thread.tid;
        let mut tids: Vec<u64> = ctx
            .proc
            .threads
            .values()
            .filter(|t| !t.exited)
            .map(|t| t.tid)
            .chain([running])
            .collect();
        tids.sort_unstable();
        let pending = |ctx: &Ctx<'_>, tid: u64| {
            if tid == running {
                ctx.thread.sig.pending
            } else {
                ctx.proc.threads[&tid].sig.pending
            }
        };
        let found = tids
            .into_iter()
            .find(|&tid| pending(ctx, tid) & siglist != 0);
        match found {
            Some(tid) => {
                let t = if tid == running {
                    &mut *ctx.thread
                } else {
                    ctx.proc.threads.get_mut(&tid).expect("listed thread")
                };
                let sig = (t.sig.pending & siglist).trailing_zeros() + 1;
                t.sig.pending &= !(1 << (sig - 1));
                return sigwait_done(ctx, sig as i32, sig_out);
            }
            None => {
                let t = &mut ctx.thread.sig;
                t.oldmask = Some(t.mask);
                t.mask = !(siglist | CANTMASK);
                t.waiting = siglist;
                t.waited = 0;
                None
            }
        }
    } else if ctx.thread.sig.waited != 0 {
        // psignal handed a signal to this wait.
        Some(ctx.thread.sig.waited & siglist)
    } else {
        match signal::interruption(ctx.proc, ctx.thread) {
            Some(Errno::EINTR) => {
                end_sigwait(ctx);
                return Err(Errno::EINTR);
            }
            // An interrupted wait that would restart counts as woken: the
            // kernel returns the lowest signal of the set.
            Some(_) => Some(siglist),
            None => None,
        }
    };
    if let Some(w) = sigw {
        end_sigwait(ctx);
        return sigwait_done(ctx, w.trailing_zeros() as i32 + 1, sig_out);
    }
    syscall::sleep(ctx, Wait::until(None))
}

/// Ends a `sigwait` wait: the previous mask returns.
fn end_sigwait(ctx: &mut Ctx<'_>) {
    let t = &mut ctx.thread.sig;
    if let Some(m) = t.oldmask.take() {
        t.mask = m;
    }
    t.waiting = 0;
    t.waited = 0;
}

fn sigwait_done(ctx: &mut Ctx<'_>, sig: i32, sig_out: u64) -> SysResult {
    ctx.thread.sig.waiting = 0;
    ctx.thread.sig.pending &= !bit(sig);
    if sig_out != 0 {
        ctx.write_u32(sig_out, sig as u32)?;
    }
    Ok(Rv::one(0))
}

/// `OLDMINSIGSTKSZ`: the smallest alternate stack `sigaltstack` takes.
const OLDMINSIGSTKSZ: u64 = 8 * 1024;

/// `sigaltstack(nss, oss)`: `stack_t` is `ss_sp`, `ss_size`, `ss_flags`.
pub fn sigaltstack(ctx: &mut Ctx<'_>, nss: u64, oss: u64) -> SysResult {
    let alt = &mut ctx.thread.sig.altstack;
    if !alt.enabled {
        alt.flags |= SS_DISABLE;
    }
    let old = *alt;
    let onstack = old.flags & SS_ONSTACK != 0;
    if oss != 0 {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&old.sp.to_le_bytes());
        b[8..16].copy_from_slice(&old.size.to_le_bytes());
        b[16..20].copy_from_slice(&old.flags.to_le_bytes());
        ctx.write(oss, &b)?;
    }
    if nss == 0 {
        return Ok(Rv::one(0));
    }
    let b = ctx.read(nss, 24)?;
    let sp = u64::from_le_bytes(b[0..8].try_into().expect("8 bytes"));
    let size = u64::from_le_bytes(b[8..16].try_into().expect("8 bytes"));
    let flags = u32::from_le_bytes(b[16..20].try_into().expect("4 bytes"));
    if flags & !SS_DISABLE != 0 {
        return Err(Errno::EINVAL);
    }
    let alt = &mut ctx.thread.sig.altstack;
    if flags & SS_DISABLE != 0 {
        if alt.flags & SS_ONSTACK != 0 {
            return Err(Errno::EINVAL);
        }
        alt.enabled = false;
        alt.flags = flags;
        return Ok(Rv::one(0));
    }
    if onstack {
        return Err(Errno::EPERM);
    }
    if size < OLDMINSIGSTKSZ {
        return Err(Errno::ENOMEM);
    }
    *alt = signal::AltStack {
        sp,
        size,
        flags,
        enabled: true,
    };
    Ok(Rv::one(0))
}

/// Posts the host signals the host delivered to this process during the
/// call, so that they are taken on its way back to user mode as the
/// kernel's own signals would be.
fn take_host_signals(ctx: &mut Ctx<'_>) {
    for (sig, origin) in signal::host::take() {
        signal::psignal(ctx.proc, Some(ctx.thread), sig, origin);
    }
}

/// `kill(pid, signum, posix)`.
///
/// The process itself is signalled directly. Other processes are the
/// host's: the host sends the signal, and a process group that includes
/// this process reaches it through host-signal forwarding. `kill(-1)`
/// ("every process the user may signal") signals only this process.
pub fn kill(ctx: &mut Ctx<'_>, pid: i32, sig: i32, posix: i32) -> SysResult {
    let _ = posix;
    if !(0..NSIG).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let own = Origin::own(ctx.proc);
    if pid == ctx.proc.pid || pid == -1 {
        if sig != 0 {
            signal::psignal(ctx.proc, Some(ctx.thread), sig, own);
        }
        return Ok(Rv::one(0));
    }
    // SAFETY: getpgrp takes no arguments.
    let pgrp = unsafe { libc::getpgrp() };
    let own_group = pid == 0 || pid == -pgrp;
    if own_group && !signal::host::forwarding() {
        // Without forwarding the host's signal would not reach the guest:
        // signal this process only.
        if sig != 0 {
            signal::psignal(ctx.proc, Some(ctx.thread), sig, own);
        }
        return Ok(Rv::one(0));
    }
    let hsig = signal::to_host(sig).ok_or(Errno::EINVAL)?;
    // SAFETY: kill takes no pointers.
    crate::user::darwin::host::check(unsafe { libc::kill(pid, hsig) })?;
    if own_group {
        take_host_signals(ctx);
    }
    Ok(Rv::one(0))
}

/// `__pthread_kill(thread_port, sig)`.
pub fn pthread_kill(ctx: &mut Ctx<'_>, port: u32, sig: i32) -> SysResult {
    let tid = if port == ctx.thread.port {
        Some(ctx.thread.tid)
    } else {
        ctx.proc
            .threads
            .values()
            .find(|t| t.port == port && !t.exited)
            .map(|t| t.tid)
    };
    let Some(tid) = tid else {
        return Err(Errno::ESRCH);
    };
    if !(0..NSIG).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let uflags = if tid == ctx.thread.tid {
        ctx.thread.sig.uflags
    } else {
        ctx.proc.threads.get(&tid).map_or(0, |t| t.sig.uflags)
    };
    if uflags & signal::uflag::NO_SIGMASK != 0 {
        return Err(Errno::ESRCH);
    }
    // Workqueue threads must have allowed kills.
    if crate::user::darwin::workq::kill_denied(ctx.proc, tid) {
        return Err(Errno::ENOTSUP);
    }
    if sig != 0 {
        let own = Origin::own(ctx.proc);
        signal::psignal_thread(ctx.proc, Some(ctx.thread), tid, sig, own);
    }
    Ok(Rv::one(0))
}

/// `sigreturn(uctx, infostyle, token)`.
pub fn sigreturn(ctx: &mut Ctx<'_>, uctx: u64, infostyle: u32, token: u64) -> SysResult {
    match frame::sigreturn(ctx.proc, ctx.thread, uctx, infostyle, token)? {
        frame::Returned::Zero => Ok(Rv::one(0)),
        frame::Returned::State => Err(Errno::EJUSTRETURN),
    }
}

/// Reads a `struct itimerval` (two 16-byte `timeval`s: interval, value).
fn read_itimerval(ctx: &Ctx<'_>, addr: u64) -> Result<ITimerVal, Errno> {
    let b = ctx.read(addr, 32)?;
    let tv = |off: usize| TimeVal {
        sec: i64::from_le_bytes(b[off..off + 8].try_into().expect("8 bytes")),
        usec: i64::from(i32::from_le_bytes(
            b[off + 8..off + 12].try_into().expect("4 bytes"),
        )),
    };
    Ok(ITimerVal {
        interval: tv(0),
        value: tv(16),
    })
}

fn write_itimerval(ctx: &Ctx<'_>, addr: u64, v: &ITimerVal) -> Result<(), Errno> {
    let mut b = [0u8; 32];
    for (off, t) in [(0, v.interval), (16, v.value)] {
        b[off..off + 8].copy_from_slice(&t.sec.to_le_bytes());
        b[off + 8..off + 12].copy_from_slice(&(t.usec as i32).to_le_bytes());
    }
    ctx.write(addr, &b)
}

/// `getitimer(which, itv)`.
pub fn getitimer(ctx: &mut Ctx<'_>, which: u32, itv: u64) -> SysResult {
    if which > ITIMER_PROF {
        return Err(Errno::EINVAL);
    }
    let v = ctx.proc.itimers.get(which);
    write_itimerval(ctx, itv, &v)?;
    Ok(Rv::one(0))
}

/// `setitimer(which, itv, oitv)`.
pub fn setitimer(ctx: &mut Ctx<'_>, which: u32, itv: u64, oitv: u64) -> SysResult {
    if which > ITIMER_PROF {
        return Err(Errno::EINVAL);
    }
    let new = if itv != 0 {
        Some(read_itimerval(ctx, itv)?)
    } else {
        None
    };
    if oitv != 0 {
        getitimer(ctx, which, oitv)?;
    }
    let Some(v) = new else {
        return Ok(Rv::one(0));
    };
    if !v.value.valid() || !v.interval.valid() {
        return Err(Errno::EINVAL);
    }
    ctx.proc.itimers.set(which, v);
    Ok(Rv::one(0))
}

//! Signal dispositions, masks, alternate stacks, and sending.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::signal::{self, SIGKILL, SIGSTOP, SigAction};
use crate::user::darwin::syscall::Ctx;

/// `sigcantmask`: signals that can be neither caught nor blocked.
const CANTMASK: u32 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

/// `__sigaction(sig, nsa, osa)`: `nsa` is a `struct __sigaction`
/// (handler, trampoline, mask, flags: 24 bytes), `osa` a `struct
/// sigaction` (handler, mask, flags: 16 bytes).
pub fn sigaction(ctx: &mut Ctx<'_>, sig: i32, nsa: u64, osa: u64) -> SysResult {
    if !(1..=31).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let old = ctx.proc.sigactions[sig as usize - 1];
    if nsa != 0 {
        let b = ctx.read(nsa, 24)?;
        let handler = u64::from_le_bytes(b[0..8].try_into().expect("8 bytes"));
        let tramp = u64::from_le_bytes(b[8..16].try_into().expect("8 bytes"));
        let mask = u32::from_le_bytes(b[16..20].try_into().expect("4 bytes"));
        let flags = u32::from_le_bytes(b[20..24].try_into().expect("4 bytes"));
        // SIGKILL and SIGSTOP keep their default action.
        if (sig == SIGKILL || sig == SIGSTOP) && handler != signal::SIG_DFL {
            return Err(Errno::EINVAL);
        }
        ctx.proc.sigactions[sig as usize - 1] = SigAction {
            handler,
            tramp,
            mask: mask & !CANTMASK,
            flags,
        };
    }
    if osa != 0 {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&old.handler.to_le_bytes());
        b[8..12].copy_from_slice(&old.mask.to_le_bytes());
        b[12..16].copy_from_slice(&old.flags.to_le_bytes());
        ctx.write(osa, &b)?;
    }
    Ok(Rv::one(0))
}

/// `SIG_BLOCK`, `SIG_UNBLOCK`, `SIG_SETMASK`.
const SIG_BLOCK: i32 = 1;
const SIG_UNBLOCK: i32 = 2;
const SIG_SETMASK: i32 = 3;

/// `sigprocmask(how, set, oset)` and `__pthread_sigmask`: the calling
/// thread's mask.
pub fn sigprocmask(ctx: &mut Ctx<'_>, how: i32, set: u64, oset: u64) -> SysResult {
    let old = ctx.thread.sigmask;
    if set != 0 {
        let s = ctx.read_u32(set)?;
        let new = match how {
            SIG_BLOCK => old | s,
            SIG_UNBLOCK => old & !s,
            SIG_SETMASK => s,
            _ => return Err(Errno::EINVAL),
        };
        ctx.thread.sigmask = new & !CANTMASK;
    }
    if oset != 0 {
        ctx.write_u32(oset, old)?;
    }
    Ok(Rv::one(0))
}

/// `sigpending(set)`.
pub fn sigpending(ctx: &mut Ctx<'_>, set: u64) -> SysResult {
    let pending = (ctx.thread.pending | ctx.proc.pending) & ctx.thread.sigmask;
    ctx.write_u32(set, pending)?;
    Ok(Rv::one(0))
}

/// `sigaltstack(ss, oss)`: `stack_t` is `ss_sp`, `ss_size`, `ss_flags`.
pub fn sigaltstack(ctx: &mut Ctx<'_>, ss: u64, oss: u64) -> SysResult {
    const SS_ONSTACK: u32 = 1;
    const SS_DISABLE: u32 = 4;
    const MINSIGSTKSZ: u64 = 32768;
    let old = ctx.thread.altstack;
    if oss != 0 {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&old.0.to_le_bytes());
        b[8..16].copy_from_slice(&old.1.to_le_bytes());
        b[16..20].copy_from_slice(&old.2.to_le_bytes());
        ctx.write(oss, &b)?;
    }
    if ss != 0 {
        let b = ctx.read(ss, 24)?;
        let sp = u64::from_le_bytes(b[0..8].try_into().expect("8 bytes"));
        let size = u64::from_le_bytes(b[8..16].try_into().expect("8 bytes"));
        let flags = u32::from_le_bytes(b[16..20].try_into().expect("4 bytes"));
        if old.2 & SS_ONSTACK != 0 {
            return Err(Errno::EPERM);
        }
        if flags & !SS_DISABLE != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & SS_DISABLE != 0 {
            ctx.thread.altstack = (0, 0, SS_DISABLE);
        } else {
            if size < MINSIGSTKSZ {
                return Err(Errno::ENOMEM);
            }
            ctx.thread.altstack = (sp, size, 0);
        }
    }
    Ok(Rv::one(0))
}

/// `kill(pid, signum, posix)`.
pub fn kill(ctx: &mut Ctx<'_>, pid: i32, sig: i32, posix: i32) -> SysResult {
    let _ = posix;
    if !(0..=31).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let own = pid == ctx.proc.pid || pid == 0 || pid == -ctx.proc.pid;
    if own || pid == -1 {
        if sig != 0 {
            signal::post_process(ctx.proc, ctx.thread, sig);
        }
        if own {
            return Ok(Rv::one(0));
        }
    }
    // Another process: the host delivers it.
    let hsig = signal::to_host(sig).ok_or(Errno::EINVAL)?;
    // SAFETY: kill takes no pointers.
    crate::user::darwin::host::check(unsafe { libc::kill(pid, hsig) })?;
    Ok(Rv::one(0))
}

/// `__pthread_kill(thread_port, sig)`.
pub fn pthread_kill(ctx: &mut Ctx<'_>, port: u32, sig: i32) -> SysResult {
    if !(0..=31).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    if port == ctx.thread.port {
        if sig != 0 {
            signal::post_thread(ctx.proc, ctx.thread, sig);
        }
        return Ok(Rv::one(0));
    }
    let Some(t) = ctx.proc.threads.values_mut().find(|t| t.port == port) else {
        return Err(Errno::ESRCH);
    };
    if sig != 0 {
        t.pending |= 1 << (sig - 1);
        if t.wait.as_ref().is_some_and(|w| w.interruptible) {
            t.woken = true;
        }
    }
    Ok(Rv::one(0))
}

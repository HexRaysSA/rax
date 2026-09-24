//! Signal-disposition and signal-mask system calls.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::process::SigAction;
use super::super::signal::{NSIG, SIGKILL, SIGSTOP, SigInfo, code};
use super::{Ctx, Outcome, SysResult};

/// `sizeof(sigset_t)` in the kernel ABI.
const SIGSET_SIZE: u64 = 8;

/// Signals that cannot be caught, blocked, or ignored.
const UNBLOCKABLE: u64 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

/// `rt_sigaction`. The structure is `{handler, flags, restorer, mask}`
/// where the ABI has `SA_RESTORER` and `{handler, flags, mask}` on riscv.
pub fn rt_sigaction(c: &mut Ctx<'_>, sig: i32, act: u64, oact: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    if !(1..=NSIG).contains(&sig) || (act != 0 && (sig == SIGKILL || sig == SIGSTOP)) {
        return Err(Errno(EINVAL));
    }
    let restorer = c.p.abi.has_sa_restorer();
    let len = if restorer { 32 } else { 24 };
    let new = if act != 0 {
        let b = c.read_mem(act, len)?;
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Some(if restorer {
            SigAction {
                handler: w(0),
                flags: w(1),
                restorer: w(2),
                mask: w(3) & !UNBLOCKABLE,
            }
        } else {
            SigAction {
                handler: w(0),
                flags: w(1),
                restorer: 0,
                mask: w(2) & !UNBLOCKABLE,
            }
        })
    } else {
        None
    };
    let idx = (sig - 1) as usize;
    if oact != 0 {
        let o = c.p.sigactions[idx];
        let mut b = Vec::with_capacity(len);
        b.extend_from_slice(&o.handler.to_le_bytes());
        b.extend_from_slice(&o.flags.to_le_bytes());
        if restorer {
            b.extend_from_slice(&o.restorer.to_le_bytes());
        }
        b.extend_from_slice(&o.mask.to_le_bytes());
        c.write_mem(oact, &b)?;
    }
    if let Some(a) = new {
        c.p.sigactions[idx] = a;
    }
    Ok(0)
}

/// `rt_sigprocmask`.
pub fn rt_sigprocmask(c: &mut Ctx<'_>, how: i32, set: u64, oset: u64, size: u64) -> SysResult {
    const SIG_BLOCK: i32 = 0;
    const SIG_UNBLOCK: i32 = 1;
    const SIG_SETMASK: i32 = 2;
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let old = c.t.sigmask;
    if set != 0 {
        let s = c.read_u64(set)?;
        let new = match how {
            SIG_BLOCK => old | s,
            SIG_UNBLOCK => old & !s,
            SIG_SETMASK => s,
            _ => return Err(Errno(EINVAL)),
        };
        c.t.sigmask = new & !UNBLOCKABLE;
    }
    if oset != 0 {
        c.write_u64(oset, old)?;
    }
    Ok(0)
}

/// `sigaltstack` (`stack_t`: `ss_sp`, `ss_flags`, `ss_size`; 24 bytes).
pub fn sigaltstack(c: &mut Ctx<'_>, ss: u64, old: u64) -> SysResult {
    const SS_ONSTACK: u32 = 1;
    const SS_DISABLE: u32 = 2;
    const SS_AUTODISARM: u32 = 1 << 31;
    let (sp, flags, size) = c.t.altstack;
    let cur_sp = c.t.cpu.sp();
    let on_stack = flags & SS_DISABLE == 0 && cur_sp > sp && cur_sp - sp <= size;
    if old != 0 {
        let reported = if on_stack {
            SS_ONSTACK | (flags & SS_AUTODISARM)
        } else {
            flags
        };
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&sp.to_le_bytes());
        b[8..12].copy_from_slice(&reported.to_le_bytes());
        b[16..].copy_from_slice(&size.to_le_bytes());
        c.write_mem(old, &b)?;
    }
    if ss != 0 {
        let b = c.read_mem(ss, 24)?;
        let new_sp = u64::from_le_bytes(b[..8].try_into().unwrap());
        let new_flags = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let new_size = u64::from_le_bytes(b[16..].try_into().unwrap());
        if on_stack {
            return Err(Errno(EPERM));
        }
        let mode = new_flags & !SS_AUTODISARM;
        if mode != 0 && mode != SS_DISABLE && mode != SS_ONSTACK {
            return Err(Errno(EINVAL));
        }
        if mode == SS_DISABLE {
            c.t.altstack = (0, SS_DISABLE, 0);
        } else {
            // MINSIGSTKSZ: 5120 on arm64, 2048 on x86-64 and riscv.
            let min = if c.p.abi == super::super::abi::LinuxAbi::Aarch64 {
                5120
            } else {
                2048
            };
            if new_size < min {
                return Err(Errno(ENOMEM));
            }
            c.t.altstack = (new_sp, new_flags & SS_AUTODISARM, new_size);
        }
    }
    Ok(0)
}

/// `rt_sigpending`: no signal is ever left pending.
pub fn rt_sigpending(c: &mut Ctx<'_>, set: u64, size: u64) -> SysResult {
    if size > SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    c.write_mem(set, &vec![0u8; size as usize])?;
    Ok(0)
}

/// `kill`: only the calling process exists to receive signals.
pub fn kill(c: &mut Ctx<'_>, pid: i32, sig: i32) -> Result<Outcome, Errno> {
    if !(0..=NSIG).contains(&sig) {
        return Err(Errno(EINVAL));
    }
    let own = pid == c.p.pid || pid == 0 || pid == -1 || pid == -c.p.pid;
    if !own {
        return Err(Errno(ESRCH));
    }
    if sig == 0 {
        return Ok(Outcome::Return(0));
    }
    Ok(Outcome::Kill(SigInfo::fault(sig, code::SI_USER, 0)))
}

/// `tgkill` (and `tkill` with the process's own thread group).
pub fn tgkill(c: &mut Ctx<'_>, tgid: i32, tid: i32, sig: i32) -> Result<Outcome, Errno> {
    if tgid <= 0 || tid <= 0 || !(0..=NSIG).contains(&sig) {
        return Err(Errno(EINVAL));
    }
    if tgid != c.p.pid || tid != c.t.tid {
        return Err(Errno(ESRCH));
    }
    if sig == 0 {
        return Ok(Outcome::Return(0));
    }
    Ok(Outcome::Kill(SigInfo::fault(sig, code::SI_TKILL, 0)))
}

//! The signal calls of a compatibility task with 32-bit structures:
//! `struct compat_sigaction` (`compat_sys_rt_sigaction`), the old
//! single-word calls (`compat_sys_sigaction` with `struct
//! compat_old_sigaction`, `sys_signal`, `sys_sgetmask`, `sys_ssetmask`,
//! `compat_sys_sigprocmask` in `kernel/compat.c`, `compat_sys_sigpending`,
//! and `sys_sigsuspend` with x86's three arguments), and `compat_stack_t`
//! (`compat_sys_sigaltstack`), all from `kernel/signal.c` unless noted.
//!
//! A `compat_old_sigset_t` is the low 32 bits of the mask: the old calls
//! neither see nor, except where noted, change the real-time signals.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::process::SigAction;
use super::super::super::signal::{AltStack, KERNEL_ONLY_MASK, sa};
use super::super::signal::{do_sigaction, do_sigaltstack, sigsuspend};
use super::super::{Ctx, Outcome, SysResult};

/// `sizeof(compat_sigset_t)`.
const SIGSET_SIZE: u64 = 8;

fn word(b: &[u8], i: usize) -> u64 {
    u64::from(u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()))
}

/// `compat_sys_rt_sigaction`: `struct compat_sigaction` is `{handler,
/// flags, restorer, mask}` with 32-bit pointers and flags and the 64-bit
/// `compat_sigset_t`. The old action is stored field by field.
pub fn rt_sigaction(c: &mut Ctx<'_>, sig: i32, act: u64, oact: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(Errno(EINVAL));
    }
    let new = if act != 0 {
        let b = c.read_mem(act, 20)?;
        Some(SigAction {
            handler: word(&b, 0),
            flags: word(&b, 1),
            restorer: word(&b, 2),
            mask: word(&b, 3) | word(&b, 4) << 32,
        })
    } else {
        None
    };
    let old = do_sigaction(c, sig, new)?;
    if oact != 0 {
        c.write_mem(oact, &(old.handler as u32).to_le_bytes())?;
        c.write_mem(oact + 12, &old.mask.to_le_bytes())?;
        c.write_mem(oact + 4, &(old.flags as u32).to_le_bytes())?;
        c.write_mem(oact + 8, &(old.restorer as u32).to_le_bytes())?;
    }
    Ok(0)
}

/// `compat_sys_sigaction`: `struct compat_old_sigaction` is `{handler,
/// mask, flags, restorer}`, the mask one word, which becomes the whole new
/// mask (`siginitset`). The old action is stored field by field.
pub fn sigaction(c: &mut Ctx<'_>, sig: i32, act: u64, oact: u64) -> SysResult {
    let new = if act != 0 {
        let b = c.read_mem(act, 16)?;
        Some(SigAction {
            handler: word(&b, 0),
            mask: word(&b, 1),
            flags: word(&b, 2),
            restorer: word(&b, 3),
        })
    } else {
        None
    };
    let old = do_sigaction(c, sig, new)?;
    if oact != 0 {
        for (at, v) in [
            (0, old.handler),
            (12, old.restorer),
            (8, old.flags),
            (4, old.mask),
        ] {
            c.write_mem(oact + at, &(v as u32).to_le_bytes())?;
        }
    }
    Ok(0)
}

/// `sys_signal`: a one-shot handler that does not block its own signal
/// (`SA_ONESHOT | SA_NOMASK`) and an empty mask; returns the old handler.
pub fn signal(c: &mut Ctx<'_>, sig: i32, handler: u64) -> SysResult {
    let new = SigAction {
        handler,
        flags: sa::RESETHAND | sa::NODEFER,
        restorer: 0,
        mask: 0,
    };
    Ok(u64::from(do_sigaction(c, sig, Some(new))?.handler as u32))
}

/// `sys_sgetmask`: `blocked.sig[0]`, a `long` of which the caller's EAX
/// holds the low word.
pub fn sgetmask(c: &Ctx<'_>) -> u64 {
    c.t.sigmask
}

/// `sys_ssetmask`: the `int` argument, sign-extended by `siginitset`,
/// becomes the whole mask (a negative one blocks the real-time signals as
/// well); returns the old low word as an `int`.
pub fn ssetmask(c: &mut Ctx<'_>, newmask: u64) -> u64 {
    let old = c.t.sigmask as u32 as i32;
    c.set_blocked(i64::from(newmask as u32 as i32) as u64);
    i64::from(old) as u64
}

/// `compat_sys_sigprocmask`: `SIG_BLOCK` and `SIG_UNBLOCK` change the low
/// word's signals, `SIG_SETMASK` replaces only the low word
/// (`compat_sig_setmask`); the old low word is stored.
pub fn sigprocmask(c: &mut Ctx<'_>, how: i32, nset: u64, oset: u64) -> SysResult {
    const SIG_BLOCK: i32 = 0;
    const SIG_UNBLOCK: i32 = 1;
    const SIG_SETMASK: i32 = 2;
    let old = c.t.sigmask;
    if nset != 0 {
        let set = u64::from(c.read_u32(nset)?) & !KERNEL_ONLY_MASK;
        let new = match how {
            SIG_BLOCK => old | set,
            SIG_UNBLOCK => old & !set,
            SIG_SETMASK => (old & !0xFFFF_FFFF) | set,
            _ => return Err(Errno(EINVAL)),
        };
        c.set_blocked(new);
    }
    if oset != 0 {
        c.write_mem(oset, &(old as u32).to_le_bytes())?;
    }
    Ok(0)
}

/// `compat_sys_sigpending`: the low word of the blocked pending signals.
pub fn sigpending(c: &mut Ctx<'_>, set: u64) -> SysResult {
    let pending = (c.t.pending.set() | c.p.shared_pending.set()) & c.t.sigmask;
    c.write_mem(set, &(pending as u32).to_le_bytes())?;
    Ok(0)
}

/// `sys_sigsuspend` (`CONFIG_OLD_SIGSUSPEND3`): the third argument, one
/// word, is the whole mask while waiting.
pub fn sigsuspend_old(c: &mut Ctx<'_>, mask: u64) -> Result<Outcome, Errno> {
    let set = if c.resume.is_some() {
        0
    } else {
        mask & 0xFFFF_FFFF
    };
    sigsuspend(c, set)
}

/// `compat_sys_sigaltstack`: `compat_stack_t` (`ss_sp`, `ss_flags`,
/// `ss_size`; 12 bytes), the old stack written zero-padded after a
/// successful change.
pub fn sigaltstack(c: &mut Ctx<'_>, ss: u64, old: u64) -> SysResult {
    let new = if ss != 0 {
        let b: [u8; 12] = c.read_mem(ss, 12)?.try_into().unwrap();
        Some(AltStack::decode_compat_stack_t(&b))
    } else {
        None
    };
    let (s, f, z) = do_sigaltstack(c, new)?;
    if old != 0 {
        c.write_mem(old, &AltStack::encode_compat_stack_t(s, f, z))?;
    }
    Ok(0)
}

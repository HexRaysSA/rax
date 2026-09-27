//! The calling process's controls and the questions only it can be asked
//! about itself: `PROC_INFO_CALL_SETCONTROL` (a thread's name),
//! `PROC_INFO_CALL_SET_DYLD_IMAGES` (dyld's image-info registration),
//! and `PIDFILEPORTINFO` and `PIDDYNKQUEUEINFO` for its own fileports and
//! workloops.

use super::{Args, Out, passthrough};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// `PROC_SELFSET_THREADNAME`.
const SELFSET_THREADNAME: i32 = 2;

/// `MAXTHREADNAMESIZE` less its NUL.
const THREADNAME_MAX: u32 = 63;

/// `proc_setcontrol`: only for the calling process (`EINVAL`); a thread's
/// name is the guest thread's, the other controls (process control
/// action, VM resource ownership, delayed idle sleep) the host process's.
pub fn setcontrol(ctx: &mut Ctx<'_>, a: &Args) -> SysResult {
    if a.pid != ctx.proc.pid {
        return Err(Errno::EINVAL);
    }
    if a.flavor != SELFSET_THREADNAME {
        return passthrough(ctx, a, |_| {});
    }
    if a.size > THREADNAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    let raw = if a.size > 0 {
        ctx.read(a.buffer, a.size as usize)?
    } else {
        Vec::new()
    };
    let name: Vec<u8> = raw.into_iter().take_while(|&c| c != 0).collect();
    ctx.thread.name = name;
    Ok(Rv::one(0))
}

/// `proc_set_dyld_images`: dyld's all-image-info address and size for
/// `TASK_DYLD_INFO` (`task_set_dyld_info`, nothing copied in); `EINVAL`
/// once the registration is final.
pub fn set_dyld_images(ctx: &mut Ctx<'_>, a: &Args) -> SysResult {
    if a.pid != ctx.proc.pid || a.buffer == 0 {
        return Err(Errno::EINVAL);
    }
    if !ctx
        .proc
        .task
        .set_dyld_info(a.buffer, u64::from(a.size), false)
    {
        return Err(Errno::EINVAL);
    }
    Ok(Rv::one(0))
}

/// `proc_pidfileportinfo` for the calling process: no port name is a
/// fileport (the emulation makes none), after the size checks.
pub fn fileportinfo(_: &mut Ctx<'_>, a: &Args) -> SysResult {
    let size = match a.flavor {
        2 => 1200,
        3 => 792,
        5 => 1192,
        6 => 184,
        _ => return Err(Errno::EINVAL),
    };
    if a.size < size {
        return Err(Errno::ENOMEM);
    }
    Err(Errno::EINVAL)
}

/// `proc_piddynkqueueinfo` for the calling process's workloops:
/// `kqueue_info` (or `kqueue_dyninfo` for a large enough buffer, its
/// servicing state left zero), or the workloop's knotes.
pub fn dynkqueueinfo(ctx: &mut Ctx<'_>, a: &Args) -> SysResult {
    if a.buffer == 0 {
        return Err(Errno::EFAULT);
    }
    let lookup = |ctx: &Ctx<'_>| {
        ctx.proc
            .kq
            .workloops
            .get(&a.arg)
            .copied()
            .filter(|kq| ctx.proc.kq.kqueues.contains_key(kq))
            .ok_or(Errno::ESRCH)
    };
    match a.flavor {
        0 => {
            if a.size < 144 {
                return Err(Errno::ENOBUFS);
            }
            let kq = lookup(ctx)?;
            let k = &ctx.proc.kq.kqueues[&kq];
            let pending: usize = k.queues.iter().map(|q| q.len()).sum();
            let size = if a.size >= 208 { 208 } else { 144 };
            let mut o = Out::new(size);
            o.u16(4, 0o010000) // S_IFIFO
                .u64(8, a.arg)
                .u64(88, pending as u64)
                .u32(104, 72)
                .u32(136, 0x20 | 0x80); // KQ_KEV_QOS | KQ_WORKLOOP
            ctx.write(a.buffer, &o.0)?;
            Ok(Rv::one(size as u64))
        }
        1 => {
            let kq = lookup(ctx)?;
            let k = &ctx.proc.kq.kqueues[&kq];
            let n = k.knotes.len().min(super::fdinfo::KNOTES_MAX);
            let fit = n.min(a.size as usize / 104);
            let bytes: Vec<u8> = k
                .knotes
                .values()
                .take(fit)
                .flat_map(super::fdinfo::extinfo)
                .collect();
            ctx.write(a.buffer, &bytes)?;
            Ok(Rv::one(n as u64))
        }
        _ => Err(Errno::ENOTSUP),
    }
}

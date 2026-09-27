//! `bsdthread_ctl`: a thread's QoS, voucher, and workqueue properties
//! (`bsdthread_ctl` and its helpers in `bsd/pthread/pthread_workqueue.c`,
//! `bsd/pthread/bsdthread_private.h`).

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::mach::ipc::KObject;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::bsd::pthread::tag;
use crate::user::darwin::workq::{self, Pool, QOS_ABOVEUI, QOS_MANAGER, priority};

/// `BSDTHREAD_CTL_*`.
mod cmd {
    pub const SET_QOS: u64 = 0x10;
    pub const QOS_OVERRIDE_START: u64 = 0x40;
    pub const QOS_OVERRIDE_END: u64 = 0x80;
    pub const SET_SELF: u64 = 0x100;
    pub const QOS_OVERRIDE_RESET: u64 = 0x200;
    pub const QOS_OVERRIDE_DISPATCH: u64 = 0x400;
    pub const QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD: u64 = 0x401;
    pub const QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET: u64 = 0x402;
    pub const QOS_MAX_PARALLELISM: u64 = 0x800;
    pub const WORKQ_ALLOW_KILL: u64 = 0x1000;
    pub const DISPATCH_APPLY_ATTR: u64 = 0x2000;
    pub const WORKQ_ALLOW_SIGMASK: u64 = 0x4000;
}

/// `enum workq_set_self_flags`.
mod set_self {
    pub const QOS: u64 = 0x01;
    pub const VOUCHER: u64 = 0x02;
    pub const FIXEDPRIORITY: u64 = 0x04;
    pub const TIMESHARE: u64 = 0x08;
    pub const WQ_KEVENT_UNBIND: u64 = 0x10;
    pub const QOS_OVERRIDE: u64 = 0x40;
}

/// `QOS_PARALLELISM_*` (`_PTHREAD_QOS_PARALLELISM_*`).
mod parallelism {
    pub const COUNT_LOGICAL: u64 = 0x1;
    pub const REALTIME: u64 = 0x2;
    pub const CLUSTER_SHARED_RESOURCE: u64 = 0x4;
}

/// `_PTHREAD_DISPATCH_APPLY_ATTR_CLUSTER_SHARED_RSRC_{SET,CLEAR}`.
mod apply_attr {
    pub const SET: u64 = 0x1;
    pub const CLEAR: u64 = 0x2;
}

/// `port_name_to_thread(name, PORT_INTRANS_THREAD_IN_CURRENT_TASK)`.
fn thread_of(ctx: &Ctx<'_>, name: u32) -> Option<u64> {
    let port = ctx.proc.ipc.lookup(name).ok()?.port()?.clone();
    match port.kobject {
        KObject::Thread(tid)
            if tid == ctx.thread.tid || ctx.proc.threads.get(&tid).is_some_and(|t| !t.exited) =>
        {
            Some(tid)
        }
        _ => None,
    }
}

fn thread_tag(ctx: &Ctx<'_>, tid: u64) -> u16 {
    if tid == ctx.thread.tid {
        ctx.thread.mach.tag
    } else {
        ctx.proc.threads.get(&tid).map_or(0, |t| t.mach.tag)
    }
}

/// `bsdthread_ctl(cmd, arg1, arg2, arg3)`.
pub fn bsdthread_ctl(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (c, arg1, arg2, arg3) = (a[0], a[1], a[2], a[3]);
    let ok = Ok(Rv::one(0));
    match c {
        cmd::QOS_OVERRIDE_START => {
            // bsdthread_add_explicit_override.
            if priority::thread_qos(arg2 as u32) == 0 {
                return Err(Errno::EINVAL);
            }
            thread_of(ctx, arg1 as u32).ok_or(Errno::ESRCH)?;
            ok
        }
        cmd::QOS_OVERRIDE_END => {
            if arg3 != 0 {
                return Err(Errno::EINVAL);
            }
            thread_of(ctx, arg1 as u32).ok_or(Errno::ESRCH)?;
            ok
        }
        cmd::QOS_OVERRIDE_DISPATCH => dispatch_override(ctx, arg1 as u32, arg2 as u32, arg3),
        cmd::QOS_OVERRIDE_RESET => {
            // workq_thread_reset_dispatch_override on the caller.
            if ctx.thread.mach.tag & tag::WORKQUEUE == 0 {
                return Err(Errno::EPERM);
            }
            set_override(ctx.proc, ctx.thread.tid, 0, true);
            ok
        }
        cmd::SET_SELF => set_self(ctx, arg1 as u32, arg2 as u32, arg3),
        cmd::QOS_MAX_PARALLELISM => {
            if arg3 != 0 {
                return Err(Errno::EINVAL);
            }
            max_parallelism(arg1, arg2)
        }
        cmd::WORKQ_ALLOW_KILL => {
            if arg2 != 0 || arg3 != 0 {
                return Err(Errno::EINVAL);
            }
            // Only a workqueue thread keeps the bit; others succeed.
            if ctx.thread.mach.tag & tag::WORKQUEUE != 0
                && let Some(w) = ctx.proc.wq.threads.get_mut(&ctx.thread.tid)
            {
                w.kill_allowed = arg1 != 0;
            }
            ok
        }
        cmd::DISPATCH_APPLY_ATTR => dispatch_apply_attr(ctx, arg1, arg2),
        cmd::WORKQ_ALLOW_SIGMASK => {
            // workq_allow_sigmask.
            let mask = arg1 as u32;
            if mask & workq::WORKQ_THREADMASK != 0 {
                return Err(Errno::EINVAL);
            }
            ctx.proc.wq.allow_sigmask |= mask;
            ok
        }
        cmd::SET_QOS
        | cmd::QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD
        | cmd::QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET => Err(Errno::ENOTSUP),
        _ => Err(Errno::EINVAL),
    }
}

/// `bsdthread_dispatch_apply_attr(flags, worker_index)`: marks the caller
/// as a user of the cluster's shared resources
/// (`thread_shared_rsrc_policy_set`/`_clear`). The Edge scheduler (Apple
/// silicon) keeps a flag, failing a repeated set or a clear without a
/// set; elsewhere the thread is soft-bound to processor set
/// `worker_index`, of which the emulated machine has one.
fn dispatch_apply_attr(ctx: &mut Ctx<'_>, flags: u64, index: u64) -> SysResult {
    let tid = ctx.thread.tid;
    let edge = ctx.proc.abi == crate::user::darwin::abi::DarwinAbi::Arm64;
    let set = &mut ctx.proc.wq.shared_rsrc;
    let ok = match flags {
        apply_attr::SET if edge => set.insert(tid),
        apply_attr::SET => index as u32 == 0,
        apply_attr::CLEAR if edge => set.remove(&tid),
        apply_attr::CLEAR => true,
        _ => false,
    };
    if ok {
        Ok(Rv::one(0))
    } else {
        Err(Errno::EINVAL)
    }
}

/// `bsdthread_get_max_parallelism`.
fn max_parallelism(qos: u64, flags: u64) -> SysResult {
    use parallelism::*;
    if flags & !(REALTIME | COUNT_LOGICAL | CLUSTER_SHARED_RESOURCE) != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & CLUSTER_SHARED_RESOURCE != 0 {
        // No such units without SME.
        return Err(Errno::ENOTSUP);
    }
    if flags & REALTIME != 0 {
        if qos != 0 {
            return Err(Errno::EINVAL);
        }
    } else if qos == 0 || qos >= u64::from(priority::thread_qos::LAST) {
        return Err(Errno::EINVAL);
    }
    // sched_qos_max_parallelism: the logical (or physical) CPU count.
    Ok(Rv::one(workq::parallelism() as u64))
}

/// Applies a dispatch override to workqueue thread `tid`: its bucket is
/// the higher of its request and the override (`workq_thread_update_bucket`).
fn set_override(proc: &mut crate::user::darwin::process::Proc, tid: u64, qos: u8, reset: bool) {
    let Some(w) = proc.wq.threads.get_mut(&tid) else {
        return;
    };
    if reset {
        w.qos_override = 0;
    } else if w.qos_override < qos {
        w.qos_override = qos;
    }
    let o = w.qos_override;
    if let Some(s) = &mut w.sched
        && s.qos_bucket != QOS_MANAGER
    {
        s.qos_bucket = s.qos_req.max(o);
    }
}

/// `workq_thread_add_dispatch_override(kport, pp, ulock_addr)`: raises a
/// workqueue thread's QoS while it holds the lock at `ulock_addr` (if
/// given, and still owned by it).
fn dispatch_override(ctx: &mut Ctx<'_>, kport: u32, pp: u32, ulock_addr: u64) -> SysResult {
    let qos = priority::thread_qos(pp);
    if qos == 0 {
        return Err(Errno::EINVAL);
    }
    let tid = thread_of(ctx, kport).ok_or(Errno::ESRCH)?;
    if thread_tag(ctx, tid) & tag::WORKQUEUE == 0 {
        return Err(Errno::EPERM);
    }
    if ulock_addr != 0
        && let Ok(b) = ctx.read(ulock_addr, 4)
    {
        // ulock_owner_value_to_port_name: the owner's name with its low
        // bits set.
        let v = u32::from_le_bytes(b.try_into().expect("4 bytes"));
        if (v | 0x3) != kport {
            return Ok(Rv::one(0));
        }
    }
    set_override(ctx.proc, tid, qos, false);
    Ok(Rv::one(0))
}

/// `bsdthread_set_self(priority, voucher, flags)`: unbinds a workqueue
/// thread from its kevent request, changes the caller's QoS (moving a
/// workqueue thread between pools), adopts a voucher, and sets the
/// scheduling policy, reporting the first failure.
fn set_self(ctx: &mut Ctx<'_>, pp: u32, voucher: u32, flags: u64) -> SysResult {
    let tid = ctx.thread.tid;
    let is_wq = ctx.thread.mach.tag & tag::WORKQUEUE != 0;
    let wq = ctx.proc.wq.threads.get(&tid).cloned().unwrap_or_default();
    let mut unbind_rv = None;
    let mut qos_rv = None;
    let mut voucher_rv = None;
    let mut fixedpri_rv = None;
    if flags & set_self::WQ_KEVENT_UNBIND != 0 {
        unbind_rv = if !is_wq {
            Some(Errno::EINVAL)
        } else if wq.sched.is_some_and(|s| s.qos_bucket == QOS_MANAGER) {
            Some(Errno::EINVAL)
        } else {
            match wq.bound {
                None => Some(Errno::EALREADY),
                Some(r) if crate::user::darwin::kevent::workq::is_workloop(ctx.proc, r) => {
                    Some(Errno::EINVAL)
                }
                Some(r) => {
                    crate::user::darwin::kevent::workq::threadreq_unbind(ctx.proc, r, tid);
                    None
                }
            }
        };
    }
    if flags & (set_self::QOS | set_self::QOS_OVERRIDE) != 0 {
        qos_rv = set_qos(ctx, pp, flags, is_wq);
    }
    if flags & set_self::VOUCHER != 0 && voucher != 0 {
        // thread_set_voucher_name: a valid name must name a voucher.
        let is_voucher = voucher != u32::MAX
            && ctx
                .proc
                .ipc
                .lookup(voucher)
                .ok()
                .and_then(|e| e.port().cloned())
                .is_some_and(|p| matches!(p.kobject, KObject::Voucher));
        if !is_voucher {
            voucher_rv = Some(Errno::ENOENT);
        }
    }
    if qos_rv.is_none() && flags & (set_self::FIXEDPRIORITY | set_self::TIMESHARE) != 0 && is_wq {
        // Not allowed on workqueue threads.
        fixedpri_rv = Some(Errno::ENOTSUP);
    }
    if qos_rv.is_some() && voucher_rv.is_some() {
        return Err(Errno::EBADMSG);
    }
    match unbind_rv.or(qos_rv).or(voucher_rv).or(fixedpri_rv) {
        Some(e) => Err(e),
        None => Ok(Rv::one(0)),
    }
}

/// The QoS part of `bsdthread_set_self`.
fn set_qos(ctx: &mut Ctx<'_>, pp: u32, flags: u64, is_wq: bool) -> Option<Errno> {
    if !priority::to_policy_valid(pp) {
        return Some(Errno::EINVAL);
    }
    let mut qos_override = 0;
    if flags & set_self::QOS_OVERRIDE != 0 {
        // Only cooperative requests clarify their override.
        if !priority::has_override_qos(pp) || !priority::is_cooperative(pp) {
            return Some(Errno::EINVAL);
        }
        qos_override = priority::thread_override_qos(pp);
    } else if priority::has_override_qos(pp) {
        return Some(Errno::EINVAL);
    }
    if !is_wq {
        // thread_policy_set(THREAD_QOS_POLICY).
        return None;
    }
    let tid = ctx.thread.tid;
    let Some(w) = ctx.proc.wq.threads.get_mut(&tid) else {
        return Some(Errno::EINVAL);
    };
    let Some(s) = &mut w.sched else {
        return None;
    };
    if s.qos_bucket == QOS_MANAGER || s.qos_bucket == QOS_ABOVEUI {
        // The manager and threads above UI keep their priority.
        return Some(Errno::EINVAL);
    }
    let coop = priority::is_cooperative(pp);
    match s.pool {
        Pool::Overcommit | Pool::Constrained if coop => return Some(Errno::EINVAL),
        Pool::Cooperative if !coop => return Some(Errno::EINVAL),
        _ => {}
    }
    if s.pool == Pool::Overcommit && !priority::is_overcommit(pp) && !coop {
        s.pool = Pool::Constrained;
    } else if s.pool == Pool::Constrained && priority::is_overcommit(pp) {
        s.pool = Pool::Overcommit;
    }
    s.qos_req = priority::thread_qos(pp);
    if w.qos_override < qos_override {
        w.qos_override = qos_override;
    }
    s.qos_bucket = s.qos_req.max(w.qos_override);
    None
}

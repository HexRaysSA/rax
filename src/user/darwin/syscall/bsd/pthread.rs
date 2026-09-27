//! Thread creation and termination for libpthread (`bsdthread_create`,
//! `bsdthread_terminate`: libpthread `kern/kern_support.c` and XNU's
//! `bsd/pthread/pthread_shims.c`), and thread cancellation
//! (`__pthread_markcancel`, `__pthread_canceled`, `__pthread_testcancel`,
//! `__disable_threadsignal` in `bsd/kern/kern_sig.c`).

use crate::user::darwin::abi::{DarwinAbi, Errno};
use crate::user::darwin::arch::{DarwinCpu, Rv, SysResult};
use crate::user::darwin::mach::ipc::{KObject, Port, Right};
use crate::user::darwin::mach::task::ThreadMach;
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::signal::{ThreadSig, uflag};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::WaitKey;

/// `bsdthread_create` flags (`PTHREAD_START_*`).
mod start {
    pub const CUSTOM: u32 = 0x0100_0000;
    pub const SETSCHED: u32 = 0x0200_0000;
    pub const QOSCLASS: u32 = 0x0800_0000;
    pub const TSD_BASE_SET: u32 = 0x1000_0000;
    pub const SUSPENDED: u32 = 0x2000_0000;
    pub const QOSCLASS_MASK: u32 = 0x00ff_ffff;
}

/// Thread tags (`THREAD_TAG_*`).
pub mod tag {
    /// The main thread.
    pub const MAINTHREAD: u16 = 0x1;
    /// A thread `bsdthread_create` made.
    pub const PTHREAD: u16 = 0x10;
    /// A work-queue thread.
    pub const WORKQUEUE: u16 = 0x20;
    /// A thread whose exit wakes a join ulock (`THREAD_TAG_USER_JOIN`).
    pub const USER_JOIN: u16 = 0x400;
}

/// `THREAD_QOS_MIN_TIER_IMPORTANCE`.
const QOS_MIN_TIER_IMPORTANCE: i32 = -15;

/// `_pthread_priority_to_policy`: whether a QoS class request is valid.
fn qos_valid(pp: u32) -> bool {
    const SCHED_PRI_FLAG: u32 = 0x2000_0000;
    const EVENT_MANAGER_FLAG: u32 = 0x0200_0000;
    const VALID_QOS_CLASS_MASK: u32 = 0x3f00;
    let has_qos = pp & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0 && pp & VALID_QOS_CLASS_MASK != 0;
    if !has_qos {
        return false;
    }
    let importance = i32::from(pp as u8 as i8) + 1;
    importance <= 0 && importance >= QOS_MIN_TIER_IMPORTANCE
}

/// Whether `base` is a TSD base the machine accepts
/// (`machine_thread_set_tsd_base`).
fn tsd_base_valid(abi: DarwinAbi, base: u64) -> bool {
    match abi {
        DarwinAbi::X86_64 => base < 0x0000_8000_0000_0000,
        DarwinAbi::Arm64 => base <= DarwinAbi::Arm64.max_address(),
    }
}

/// `bsdthread_create(func, func_arg, stack, pthread, flags)`: a new thread
/// that starts in libpthread's `thread_start` with `(pthread, kport, func,
/// func_arg, stack, flags)` on `stack`. Returns `pthread`.
pub fn bsdthread_create(
    ctx: &mut Ctx<'_>,
    func: u64,
    funcarg: u64,
    stack: u64,
    pthread: u64,
    flags: u32,
) -> SysResult {
    let reg = ctx.proc.pthread;
    if !reg.registered {
        return Err(Errno::EINVAL);
    }
    let tid = ctx.proc.next_tid;
    ctx.proc.next_tid += 1;
    let kport = Port::new(KObject::Thread(tid));
    kport.state.lock().unwrap().srights += 1;
    let Ok(port) = ctx.proc.ipc.insert(Right::Send(kport.clone())) else {
        // Userland turns this into a crash.
        return Err(Errno::EMFILE);
    };
    let fail = |ctx: &mut Ctx<'_>, e: Errno| {
        let _ = crate::user::darwin::syscall::mach::port::deallocate(ctx.proc, port);
        Err(e)
    };
    if flags & start::CUSTOM == 0 {
        return fail(ctx, Errno::EINVAL);
    }
    let abi = ctx.proc.abi;
    let mut cpu = DarwinCpu::new(abi, &ctx.proc.space);
    let mut flags = flags;
    if reg.tsd_offset != 0 {
        let base = pthread.wrapping_add(u64::from(reg.tsd_offset));
        if tsd_base_valid(abi, base) {
            cpu.set_tsd_base(base);
            flags |= start::TSD_BASE_SET;
        }
    }
    let suspended = flags & start::SUSPENDED != 0;
    flags &= !start::SUSPENDED;
    // thread_start(pthread, kport, func, arg, stack, flags) on `stack`.
    let args = [
        pthread,
        u64::from(port),
        func,
        funcarg,
        stack,
        u64::from(flags),
    ];
    set_start_state(&mut cpu, reg.thread_start, stack, &args);
    if flags & start::SETSCHED == 0 && flags & start::QOSCLASS != 0 {
        if !qos_valid(flags & start::QOSCLASS_MASK) {
            return fail(ctx, Errno::EINVAL);
        }
    }
    if reg.mach_thread_self_offset != 0 && reg.tsd_offset != 0 {
        let at = pthread
            .wrapping_add(u64::from(reg.tsd_offset))
            .wrapping_add(u64::from(reg.mach_thread_self_offset));
        if ctx.write_u64(at, u64::from(port)).is_err() {
            return fail(ctx, Errno::EFAULT);
        }
    }
    // The creator's mask (the one sigsuspend or sigwait will restore, if
    // either is in progress).
    let mask = ctx.thread.sig.oldmask.unwrap_or(ctx.thread.sig.mask);
    let thread = Thread {
        tid,
        port,
        kport,
        cpu,
        sig: ThreadSig {
            mask,
            ..Default::default()
        },
        wait: None,
        resume: None,
        pthread,
        exited: false,
        woken: false,
        wake_event: false,
        mach: ThreadMach {
            suspend_count: u32::from(suspended),
            tag: tag::PTHREAD,
            ..Default::default()
        },
        name: Vec::new(),
        pw: Default::default(),
    };
    ctx.proc.threads.insert(tid, thread);
    Ok(Rv::one(pthread))
}

/// Starts a thread at `pc` with `args` in the argument registers and
/// `sp` (`thread_set_wq_state64`).
pub fn set_start_state(cpu: &mut DarwinCpu, pc: u64, sp: u64, args: &[u64; 6]) {
    match cpu {
        DarwinCpu::X86_64(c) => {
            let v = c.vcpu_mut();
            let r = v.user_regs_mut();
            r.rdi = args[0];
            r.rsi = args[1];
            r.rdx = args[2];
            r.rcx = args[3];
            r.r8 = args[4];
            r.r9 = args[5];
            r.rsp = sp;
            r.rip = pc;
            v.set_user_rflags(0x202);
        }
        DarwinCpu::Arm64(c) => {
            for (i, a) in args.iter().enumerate() {
                c.core_mut().set_x(i as u8, *a);
            }
            crate::isa::arm::common::cpu::ArmCpu::set_pc(c.core_mut(), pc);
            c.set_sp(sp);
        }
    }
}

/// `bsdthread_terminate(stackaddr, freesize, port, sema_or_ulock)`: frees
/// the thread's stack, ends the thread, and signals the joiner's
/// semaphore, or (a value that is not a port name) wakes the join ulock
/// at that address once the thread is gone.
pub fn bsdthread_terminate(
    ctx: &mut Ctx<'_>,
    stackaddr: u64,
    freesize: u64,
    kthport: u32,
    sema_or_ulock: u64,
) -> SysResult {
    let (mut sem, mut thp) = (sema_or_ulock as u32, kthport);
    if sema_or_ulock != 0 && u64::from(sem | 0x3) != sema_or_ulock {
        // Ports end in 0x3 and ulocks are aligned: a join ulock.
        ctx.thread.mach.tag |= tag::USER_JOIN;
        ctx.thread.mach.join = Some((sema_or_ulock, kthport));
        sem = 0;
        thp = 0;
    }
    if freesize != 0 && stackaddr != 0 {
        use crate::user::darwin::syscall::mach::vm;
        if ctx.thread.mach.tag & tag::MAINTHREAD != 0 {
            // The main thread's stack stays mapped, but inaccessible.
            let page = ctx.proc.vm.page;
            let size = (freesize - 1) & !(page - 1);
            let _ = vm::protect(ctx, stackaddr, size, false, 0);
        } else {
            let _ = vm::deallocate(ctx, stackaddr, freesize);
        }
    }
    ctx.thread.exited = true;
    if sem != 0 {
        let _ = crate::user::darwin::syscall::mach::sync::signal(ctx, sem, false);
    }
    if thp != 0 {
        let _ = crate::user::darwin::syscall::mach::port::deallocate(ctx.proc, thp);
    }
    Err(Errno::EJUSTRETURN)
}

/// The end of a thread (`thread_terminate`, `uthread_cleanup`): its
/// control port dies, joiners are woken, and a join ulock is woken
/// (`uthread_joiner_wake`).
pub fn reap(proc: &mut Proc, thread: &mut Thread) {
    crate::user::darwin::workq::thread_terminated(proc, thread.tid);
    if let Some((addr, kport)) = thread.mach.join.take() {
        // UL_UNFAIR_LOCK | ULF_WAKE_ALL | ULF_WAKE_ALLOW_NON_OWNER.
        proc.wake(WaitKey::Address(addr), usize::MAX);
        let _ = crate::user::darwin::syscall::mach::port::deallocate(proc, kport);
    }
    proc.post(WaitKey::ThreadExit(thread.tid));
    crate::user::darwin::syscall::mach::kmsg::destroy_receive(proc, &thread.kport);
}

/// `__pthread_testcancel(1)` at a cancellation point: `EINTR` when a
/// cancellation is pending and enabled; the call is a cancellation point
/// for the rest of its run.
pub fn testcancel(ctx: &mut Ctx<'_>) -> Result<(), Errno> {
    let s = &mut ctx.thread.sig;
    s.uflags &= !uflag::NOTCANCELPT;
    if s.cancelled() {
        return Err(Errno::EINTR);
    }
    Ok(())
}

/// `__pthread_testcancel(0)`: a pending, enabled cancellation interrupts
/// the call's next wait (`thread_abort_safely` on the caller).
pub fn testcancel_abort(ctx: &mut Ctx<'_>) {
    let s = &mut ctx.thread.sig;
    s.uflags &= !uflag::NOTCANCELPT;
    if s.cancelled() {
        s.abort = true;
    }
}

/// `__pthread_markcancel(thread_port)`: marks the thread for
/// cancellation and interrupts its wait unless it is in a call that is not
/// a cancellation point, or cancellation is disabled.
pub fn markcancel(ctx: &mut Ctx<'_>, port: u32) -> SysResult {
    let running = ctx.thread.tid;
    let tid = ctx
        .proc
        .ipc
        .lookup(port)
        .ok()
        .and_then(|e| e.port().cloned())
        .and_then(|p| match p.kobject {
            KObject::Thread(tid) => Some(tid),
            _ => None,
        })
        .filter(|&tid| tid == running || ctx.proc.threads.get(&tid).is_some_and(|t| !t.exited))
        .ok_or(Errno::ESRCH)?;
    let t = if tid == running {
        &mut *ctx.thread
    } else {
        ctx.proc.threads.get_mut(&tid).expect("live thread")
    };
    let s = &mut t.sig;
    if s.uflags & (uflag::CANCEL | uflag::CANCELED) == 0 {
        s.uflags |= uflag::CANCEL | uflag::NO_SIGMASK;
        if s.uflags & (uflag::NOTCANCELPT | uflag::CANCELDISABLE) == 0 {
            // thread_abort_safely: interrupt an interruptible wait now, or
            // the next one.
            s.abort = true;
            if t.wait.as_ref().is_some_and(|w| w.interruptible) {
                t.woken = true;
            }
        }
    }
    Ok(Rv::one(0))
}

/// `__pthread_canceled(action)`: 1 enables cancellation, 2 disables it,
/// and 0 turns a pending cancellation into a cancelled thread (else
/// `EINVAL`).
pub fn canceled(ctx: &mut Ctx<'_>, action: i32) -> SysResult {
    let s = &mut ctx.thread.sig;
    match action {
        1 => s.uflags &= !uflag::CANCELDISABLE,
        2 => s.uflags |= uflag::CANCELDISABLE,
        _ => {
            if !s.cancelled() {
                return Err(Errno::EINVAL);
            }
            s.uflags &= !uflag::CANCEL;
            s.uflags |= uflag::CANCELED | uflag::NO_SIGMASK;
        }
    }
    Ok(Rv::one(0))
}

/// `__disable_threadsignal(value)`: no signal is delivered to the thread
/// any more, and it cannot be cancelled (a thread on its way out).
pub fn disable_threadsignal(ctx: &mut Ctx<'_>) -> SysResult {
    ctx.thread.sig.uflags |= uflag::NO_SIGMASK | uflag::CANCELDISABLE;
    Ok(Rv::one(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qos_requests() {
        // QOS_CLASS_DEFAULT (4) with relative priority 0: bit 3 of the
        // class mask, priority byte 0xff (-1 + 1 = 0).
        assert!(qos_valid(0x08ff));
        // Relative priority -15 is the floor.
        assert!(qos_valid(0x0800 | (-16i8 as u8 as u32)));
        assert!(!qos_valid(0x0800 | (-17i8 as u8 as u32)));
        // A positive relative priority, or no class, is invalid.
        assert!(!qos_valid(0x0800));
        assert!(!qos_valid(0x00ff));
    }

    #[test]
    fn start_flags_do_not_overlap_the_qos_class() {
        for f in [
            start::CUSTOM,
            start::SETSCHED,
            start::QOSCLASS,
            start::TSD_BASE_SET,
            start::SUSPENDED,
        ] {
            assert_eq!(f & start::QOSCLASS_MASK, 0);
        }
    }
}

//! Kernel entry: BSD system calls, Mach traps, and machine-dependent calls.
//!
//! [`dispatch`] handles one kernel entry of a thread: it decodes the call
//! from the registers, fetches the arguments the call's `sysent` entry
//! declares, runs the handler with a [`Ctx`], and writes the result back in
//! the machine's convention ([`DarwinCpu::set_unix_result`]). A handler
//! that must sleep registers a [`Wait`] and returns `ERESTART`, which backs
//! the PC up so the call runs again when the thread wakes.
//!
//! [`DarwinCpu::set_unix_result`]: super::arch::DarwinCpu::set_unix_result

pub mod bsd;
pub mod mach;
pub mod mdep;
pub mod mem;
pub mod util;

use super::abi::{self, Errno, Kind};
use super::arch::{SysResult, Trap};
use super::process::{Proc, Thread};
use super::wait::{Resume, Wait};

pub use util::Ctx;

/// `ESR_EL1` of `SVC #0x80` from AArch64 EL0: EC 0x15, IL, the immediate.
const ESR_SVC_0X80: u32 = (0x15 << 26) | (1 << 25) | 0x80;

/// `T_SYSCALL`: the x86-64 trap number of a `SYSCALL` entry
/// (`osfmk/i386/trap.h`, `hndl_syscall`).
const T_SYSCALL: u32 = 0x85;

/// Records a system-call entry in `thread`'s exception state (FAR and
/// CR2 keep the last fault's).
pub fn entered(abi: abi::DarwinAbi, thread: &mut Thread) {
    let entry = &mut thread.sig.entry;
    match abi {
        abi::DarwinAbi::Arm64 => entry.esr = ESR_SVC_0X80,
        abi::DarwinAbi::X86_64 => {
            entry.trapno = T_SYSCALL;
            entry.err = 0;
        }
    }
}

/// Handles one kernel entry of `thread`.
pub fn dispatch(proc: &mut Proc, thread: &mut Thread, trap: Trap) {
    entered(proc.abi, thread);
    match trap {
        Trap::Unix { code } => unix(proc, thread, code),
        Trap::Mach { nr } => mach::trap(proc, thread, nr),
        Trap::Machdep { nr } => mdep::machdep(proc, thread, nr),
        Trap::Platform { code } => mdep::platform(proc, thread, code),
        Trap::Diag { .. } => {
            // diagCall64: without the diagnostics boot-arg every selector
            // fails with 0.
            thread.cpu.set_reg(0, 0);
        }
        Trap::AbsoluteTime | Trap::ContinuousTime => {
            let now = mach::absolute_time(proc.abi);
            thread.cpu.set_reg(0, now);
        }
        Trap::Exception(_) | Trap::BadSyscall { .. } | Trap::Yield | Trap::Internal(_) => {}
    }
}

/// A BSD system call.
fn unix(proc: &mut Proc, thread: &mut Thread, code: u32) {
    let (nr, indirect) = if code == 0 {
        (thread.cpu.indirect_number(), true)
    } else {
        (code, false)
    };
    let sc = abi::bsd_syscall(nr);
    let pc = thread.cpu.pc();
    proc.task.syscalls.1 += 1;
    let result = match sc.kind {
        Kind::Nosys => {
            // nosys: SIGSYS to the thread (default action: terminate with
            // a core dump), and ENOSYS should it return.
            if proc.config.strace {
                eprintln!("[{:#x}] nosys({nr})", thread.tid);
            }
            let (tid, origin) = (thread.tid, super::signal::Origin::own(proc));
            super::signal::psignal_thread(proc, Some(thread), tid, super::signal::SIGSYS, origin);
            Err(Errno::ENOSYS)
        }
        Kind::Enosys => Err(Errno::ENOSYS),
        Kind::Call => match thread.cpu.unix_args(sc.nargs as usize, indirect) {
            Err(e) => Err(e),
            Ok(args) => {
                // A restarted call keeps its progress only if it is the
                // same call at the same place.
                if thread
                    .resume
                    .is_some_and(|r| r.pc != pc || r.call != i64::from(nr))
                {
                    thread.resume = None;
                }
                // Not a cancellation point unless the call says so
                // (__pthread_testcancel clears the flag).
                thread.sig.uflags |= super::signal::uflag::NOTCANCELPT;
                let mut ctx = Ctx {
                    proc,
                    thread,
                    nr: i64::from(nr),
                    pc,
                };
                let r = bsd::call(&mut ctx, nr, &args);
                if ctx.thread.wait.is_none() {
                    ctx.thread.sig.uflags &= !super::signal::uflag::NOTCANCELPT;
                }
                if ctx.proc.config.strace {
                    util::trace_unix(&ctx, sc.name, &args[..sc.nargs as usize], &r);
                }
                r
            }
        },
    };
    finish(thread, sc.ret, result);
}

/// Writes a BSD call's result and parks the thread when it sleeps.
fn finish(thread: &mut Thread, ret: abi::Ret, result: SysResult) {
    if result != Err(Errno::ERESTART) || thread.wait.is_none() {
        thread.resume = None;
    }
    thread.cpu.set_unix_result(ret, result);
}

/// Parks the running thread on `wait`, keeping `deadline` for the restart.
///
/// An interruptible wait does not begin while a signal is deliverable
/// (`msleep` with `PCATCH`): the call fails with `EINTR`, or returns
/// `ERESTART` without a wait so that it runs again after the handler when
/// the action has `SA_RESTART` (see [`interrupted`]).
pub fn sleep(ctx: &mut Ctx<'_>, mut wait: Wait) -> SysResult {
    if wait.interruptible
        && let Some(e) = super::signal::sleep_interruption(ctx.proc, ctx.thread)
    {
        ctx.thread.resume = None;
        return Err(e);
    }
    wait.seq = crate::user::darwin::wait::next_seq();
    ctx.thread.resume = Some(Resume {
        pc: ctx.pc,
        call: ctx.nr,
        deadline: wait.deadline,
        step: 0,
    });
    ctx.thread.wait = Some(wait);
    Err(Errno::ERESTART)
}

/// Whether a [`sleep`] result is a signal's interruption rather than a
/// parked wait.
pub fn interrupted(ctx: &Ctx<'_>, r: &SysResult) -> bool {
    match r {
        Err(Errno::EINTR) => true,
        Err(Errno::ERESTART) => ctx.thread.wait.is_none(),
        _ => false,
    }
}

/// [`sleep`] for calls that are never restarted after a handler
/// (`select`, `poll`: "not restarted after signals"): `ERESTART` becomes
/// `EINTR`.
pub fn sleep_no_restart(ctx: &mut Ctx<'_>, wait: Wait) -> SysResult {
    match sleep(ctx, wait) {
        Err(Errno::ERESTART) if ctx.thread.wait.is_none() => Err(Errno::EINTR),
        r => r,
    }
}

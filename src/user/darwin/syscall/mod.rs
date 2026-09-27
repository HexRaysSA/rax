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

/// Handles one kernel entry of `thread`.
pub fn dispatch(proc: &mut Proc, thread: &mut Thread, trap: Trap) {
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
            super::signal::terminate(proc, thread, super::signal::SIGSYS, pc);
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
                let mut ctx = Ctx {
                    proc,
                    thread,
                    nr: i64::from(nr),
                    pc,
                };
                let r = bsd::call(&mut ctx, nr, &args);
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
pub fn sleep(ctx: &mut Ctx<'_>, mut wait: Wait) -> SysResult {
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

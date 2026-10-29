//! Entered BSD calls own their scalar arguments and completion until return.
use super::super::abi;
use super::super::arch::{DarwinCpu, SysResult};
use super::super::process::{Proc, Thread};
use super::{Ctx, bsd, finish, util};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingUnix {
    pub(crate) nr: u32,
    pub(crate) args: [u64; 8],
    /// Original trap successor, used for kernel progress identity. The
    /// mutable CPU PC independently selects where user execution returns.
    pub(crate) pc: u64,
    /// An operation completed by another thread while this thread was parked.
    pub(crate) completed: Option<SysResult>,
    /// Return registers are prepared or replaced by a completed state write.
    pub(crate) result_prepared: bool,
}

pub(super) fn start_unix(proc: &mut Proc, thread: &mut Thread, nr: u32, args: [u64; 8], pc: u64) {
    let entry = PendingUnix {
        nr,
        args,
        pc,
        completed: None,
        result_prepared: false,
    };
    thread.pending_unix = Some(entry);
    service(proc, thread, entry);
}

/// Continue the entered service without decoding instructions or user registers.
/// One bounded record is retained per thread, with no entry-time allocation.
pub(crate) fn resume_unix(proc: &mut Proc, thread: &mut Thread) {
    let entry = thread
        .pending_unix
        .expect("scheduler selected an entered BSD call");
    if entry.result_prepared {
        // A later Mach state write is authoritative after return preparation.
        thread.pending_unix = None;
        return;
    }
    service(proc, thread, entry);
}

/// Commit an entered operation completed by another thread. Native ARM64
/// exposes its prepared result while held; x86 prepares it on kernel return.
pub(crate) fn complete_unix(thread: &mut Thread, result: SysResult) {
    let entry = thread
        .pending_unix
        .as_mut()
        .expect("completed entered call");
    entry.completed = Some(result);
    if matches!(&thread.cpu, DarwinCpu::Arm64(_)) {
        thread
            .cpu
            .set_unix_result(abi::bsd_syscall(entry.nr).ret, result);
        entry.result_prepared = true;
        thread.resume = None;
        thread.sig.uflags &= !super::super::signal::uflag::NOTCANCELPT;
    }
    thread.wait = None;
    thread.woken = true;
}

/// A successful general-register write after completion supplies the user
/// return state, including an unchanged snapshot written back by a debugger.
pub(crate) fn user_state_written(thread: &mut Thread) {
    if let Some(entry) = &mut thread.pending_unix
        && entry.completed.is_some()
    {
        entry.result_prepared = true;
        thread.resume = None;
        thread.sig.uflags &= !super::super::signal::uflag::NOTCANCELPT;
    }
}

fn service(proc: &mut Proc, thread: &mut Thread, entry: PendingUnix) {
    let PendingUnix {
        nr,
        args,
        pc,
        completed,
        ..
    } = entry;
    let sc = abi::bsd_syscall(nr);
    if thread
        .resume
        .is_some_and(|r| r.pc != pc || r.call != i64::from(nr))
    {
        thread.resume = None;
    }
    // __pthread_testcancel clears this for cancellation points. A parked
    // continuation remains inside the same kernel entry until final return.
    thread.sig.uflags |= super::super::signal::uflag::NOTCANCELPT;
    let mut ctx = Ctx {
        proc,
        thread,
        nr: i64::from(nr),
        pc,
    };
    let result = completed.unwrap_or_else(|| bsd::call(&mut ctx, nr, &args));
    if ctx.thread.wait.is_none() {
        ctx.thread.sig.uflags &= !super::super::signal::uflag::NOTCANCELPT;
    }
    if ctx.proc.config.strace {
        util::trace_unix(&ctx, sc.name, &args[..sc.nargs as usize], &result);
    }
    finish(ctx.thread, sc.ret, result);
}

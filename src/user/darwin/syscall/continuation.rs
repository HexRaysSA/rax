//! Entered ARM64 BSD calls own their scalar arguments until kernel return.
use super::super::abi::{self, DarwinAbi};
use super::super::process::{Proc, Thread};
use super::{Ctx, bsd, finish, util};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingUnix {
    pub(crate) nr: u32,
    pub(crate) args: [u64; 8],
    /// Original successor of SVC, used for kernel progress identity. The
    /// mutable CPU PC independently selects where user execution returns.
    pub(crate) pc: u64,
}

pub(super) fn start_unix(proc: &mut Proc, thread: &mut Thread, nr: u32, args: [u64; 8], pc: u64) {
    let entry = PendingUnix { nr, args, pc };
    if proc.abi == DarwinAbi::Arm64 {
        thread.pending_unix = Some(entry);
    }
    service(proc, thread, entry);
}

/// Continue the entered service without decoding instructions or user registers.
/// One bounded record is retained per thread, with no entry-time allocation.
pub(crate) fn resume_unix(proc: &mut Proc, thread: &mut Thread) {
    let entry = thread
        .pending_unix
        .expect("scheduler selected an entered BSD call");
    service(proc, thread, entry);
}

fn service(proc: &mut Proc, thread: &mut Thread, entry: PendingUnix) {
    let PendingUnix { nr, args, pc } = entry;
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
    let result = bsd::call(&mut ctx, nr, &args);
    if ctx.thread.wait.is_none() {
        ctx.thread.sig.uflags &= !super::super::signal::uflag::NOTCANCELPT;
    }
    if ctx.proc.config.strace {
        util::trace_unix(&ctx, sc.name, &args[..sc.nargs as usize], &result);
    }
    finish(ctx.thread, sc.ret, result);
}

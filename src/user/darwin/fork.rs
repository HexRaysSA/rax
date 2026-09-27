//! `fork` (`bsd/kern/kern_fork.c`: `fork`, `fork1`, `forkproc`,
//! `uthread_init`, `thread_set_child`; `osfmk/kern/ipc_tt.c`:
//! `ipc_task_init`; `bsd/kern/kern_descrip.c`: `fdt_fork`).
//!
//! The emulated process is the host process, so a guest `fork` forks the
//! host process: the child is a copy of the emulator with its guest,
//! memory copied on write by the host (shared mappings stay shared, as
//! their pages are host shared objects). The child then becomes what XNU
//! makes of a forked process:
//!
//! - one thread, the caller's, with a new thread ID and control port, the
//!   caller's signal mask (the one `sigsuspend` or `sigwait` would
//!   restore), and nothing else of its thread state: no pending signals,
//!   no alternate stack, no cancellation;
//! - a new task: a fresh port name space holding the task's and the
//!   thread's control ports; the task keeps the bootstrap, access, and
//!   host special ports, the registered ports, the exception actions, and
//!   the guard-exception behavior;
//! - the signal actions (but not `SA_NOCLDSTOP` and `SA_NOCLDWAIT`, which
//!   are process flags `forkproc` does not copy), resource limits,
//!   working directory, and descriptors, except kqueues (`FG_CONFINED`);
//!   no interval timers, no work queue, no psynch or kqueue state;
//! - the address space less its `VM_INHERIT_NONE` regions.
//!
//! The parent's call returns the child's pid with 0 in the second return
//! register; the child's returns its own pid with 1 there, which
//! libsyscall's `fork` turns into 0.

use std::time::Instant;

use super::arch::{Rv, SysResult};
use super::mach::ipc::{IpcSpace, KObject, Port, Right};
use super::mach::task::{TaskState, ThreadMach, special};
use super::process::Proc;
use super::signal::{self, ThreadSig};
use super::syscall::Ctx;
use super::syscall::bsd::pthread::tag;

/// `VM_INHERIT_NONE`.
const VM_INHERIT_NONE: u32 = 2;

/// `fork()`.
pub fn fork(ctx: &mut Ctx<'_>) -> SysResult {
    let parent = ctx.proc.pid;
    match signal::host::fork_host()? {
        Some(pid) => {
            ctx.proc.children.insert(pid);
            // A pid the kernel reaped before is a new child now.
            ctx.proc.hidden.remove(&pid);
            Ok(Rv(pid as u64, 0))
        }
        None => {
            become_child(ctx, parent);
            Ok(Rv(ctx.proc.pid as u64, 1))
        }
    }
}

/// Turns the copy of the parent into the forked child.
fn become_child(ctx: &mut Ctx<'_>, ppid: i32) {
    let proc = &mut *ctx.proc;
    let thread = &mut *ctx.thread;
    // SAFETY: getpid takes no arguments.
    let pid = unsafe { libc::getpid() };
    proc.pid = pid;
    proc.ppid = ppid;
    proc.audit = super::process::host_audit_token(pid, proc.creds);
    proc.started = Instant::now();
    proc.exit = None;
    proc.posted.clear();
    proc.children.clear();
    proc.hidden.clear();
    proc.execed = false;

    // The caller is the only thread (the others were never copied).
    proc.threads.clear();
    let tid = ((pid as u64) << 20) | 1;
    proc.next_tid = tid + 1;

    // A new task: its control port is copied out into the fresh space at
    // creation (ipc_task_copyout_control_port), the thread's after it.
    let mut ipc = IpcSpace::new();
    let task_port = Port::new(KObject::Task);
    task_port.state.lock().unwrap().srights += 1;
    ipc.insert(Right::Send(task_port.clone()))
        .expect("a fresh space has room");
    let kport = Port::new(KObject::Thread(tid));
    kport.state.lock().unwrap().srights += 1;
    let thread_port = ipc
        .insert(Right::Send(kport.clone()))
        .expect("a fresh space has room");
    proc.ipc = ipc;
    proc.task_port = task_port;
    proc.task = inherited_task(&proc.task);

    let mask = thread.sig.oldmask.unwrap_or(thread.sig.mask);
    thread.tid = tid;
    thread.kport = kport;
    thread.port = thread_port;
    thread.sig = ThreadSig {
        mask,
        ..Default::default()
    };
    thread.mach = ThreadMach {
        tag: tag::MAINTHREAD,
        ..Default::default()
    };
    thread.name.clear();
    thread.pw = Default::default();
    thread.assumed = None;
    thread.wait = None;
    thread.resume = None;
    thread.woken = false;
    thread.wake_event = false;

    // Pending signals and their records stay with the parent, and so do
    // P_NOCLDSTOP and P_NOCLDWAIT (forkproc keeps only some p_flag bits;
    // the actions stay).
    proc.sigacts.origin = Default::default();
    proc.sigacts.nocldstop = false;
    proc.sigacts.nocldwait = false;
    proc.itimers = Default::default();
    // The timers' receive rights stayed in the parent's space.
    proc.mk_timers = Default::default();
    proc.vouchers.fork();
    proc.psynch = Default::default();
    proc.wq = Default::default();
    // The host kqueues behind guest kqueues are not inherited by the host
    // child either: their descriptors are closed, so they are not closed
    // again here.
    std::mem::forget(std::mem::take(&mut proc.kq));
    // Nor are close-on-fork descriptors; the child's copies of their host
    // descriptors close.
    proc.fds = super::exec::fdt_fork(&proc.fds, false);

    unmap_uninherited(proc);
}

/// The child's task state (`ipc_task_init` with a parent,
/// `task_create_internal`): the inherited special ports, registered
/// ports, exception actions, guard behavior, dyld's image-info
/// registration, and the deferred-reclamation ring (its pages are the
/// child's copy).
pub(crate) fn inherited_task(parent: &TaskState) -> TaskState {
    let mut t = TaskState {
        exc: parent.exc.clone(),
        exc_guard: parent.exc_guard,
        dyld_info: parent.dyld_info,
        dyld_final: parent.dyld_final,
        reclaim: parent.reclaim,
        registered: parent.registered.clone(),
        ..Default::default()
    };
    for s in [special::HOST, special::BOOTSTRAP, special::ACCESS] {
        t.special[s as usize] = parent.special[s as usize].clone();
    }
    t
}

/// Unmaps the regions whose inheritance is `VM_INHERIT_NONE`.
fn unmap_uninherited(proc: &mut Proc) {
    let limit = proc.space.va_limit();
    let none: Vec<(u64, u64)> = proc
        .space
        .vmas_in(0, limit)
        .iter()
        .filter(|v| super::vm::VmFlags::from_bits(v.flags).inheritance() == VM_INHERIT_NONE)
        .map(|v| (v.start, v.end - v.start))
        .collect();
    for (start, len) in none {
        let _ = proc.space.unmap(start, len);
    }
}

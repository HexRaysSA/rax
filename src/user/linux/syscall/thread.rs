//! Thread creation: `clone`, `clone3`, and `set_tid_address`
//! (`kernel/fork.c`, the architectures' `copy_thread`).
//!
//! A clone that shares the address space, signal handlers, descriptor
//! table, and file-system context with the caller (`CLONE_VM |
//! CLONE_SIGHAND | CLONE_THREAD | CLONE_FILES | CLONE_FS`, what every
//! threads library passes) creates a thread of this process. Other clones —
//! new processes, and threads with a private descriptor table or
//! file-system context — are not supported.

use super::super::abi::LinuxAbi;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::ipc::UndoList;
use super::super::process::Thread;
use super::super::signal::deliver::recalc_sigpending;
use super::super::signal::deliver::restart::ERESTARTNOINTR;
use super::super::signal::{AltStack, valid_signal};
use super::super::wait::{Resume, Wait};
use super::{Ctx, Outcome, SysResult};

/// `clone` flags (`linux/sched.h`).
pub mod cf {
    /// Exit signal bits of legacy `clone`.
    pub const CSIGNAL: u64 = 0x0000_00ff;
    /// Share the address space.
    pub const CLONE_VM: u64 = 0x0000_0100;
    /// Share the file-system context.
    pub const CLONE_FS: u64 = 0x0000_0200;
    /// Share the descriptor table.
    pub const CLONE_FILES: u64 = 0x0000_0400;
    /// Share signal handlers.
    pub const CLONE_SIGHAND: u64 = 0x0000_0800;
    /// Return a pidfd.
    pub const CLONE_PIDFD: u64 = 0x0000_1000;
    /// Continue tracing.
    pub const CLONE_PTRACE: u64 = 0x0000_2000;
    /// Suspend the parent until the child releases the address space.
    pub const CLONE_VFORK: u64 = 0x0000_4000;
    /// Same parent as the caller.
    pub const CLONE_PARENT: u64 = 0x0000_8000;
    /// Same thread group.
    pub const CLONE_THREAD: u64 = 0x0001_0000;
    /// New mount namespace.
    pub const CLONE_NEWNS: u64 = 0x0002_0000;
    /// Share System V semaphore undo.
    pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
    /// Set the child's thread pointer.
    pub const CLONE_SETTLS: u64 = 0x0008_0000;
    /// Store the TID in the parent.
    pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
    /// Clear the TID and wake its futex at exit.
    pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
    /// Unused, ignored (rejected by `clone3`).
    pub const CLONE_DETACHED: u64 = 0x0040_0000;
    /// No forced tracing.
    pub const CLONE_UNTRACED: u64 = 0x0080_0000;
    /// Store the TID in the child.
    pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
    /// New cgroup namespace.
    pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
    /// New UTS namespace.
    pub const CLONE_NEWUTS: u64 = 0x0400_0000;
    /// New IPC namespace.
    pub const CLONE_NEWIPC: u64 = 0x0800_0000;
    /// New user namespace.
    pub const CLONE_NEWUSER: u64 = 0x1000_0000;
    /// New PID namespace.
    pub const CLONE_NEWPID: u64 = 0x2000_0000;
    /// New network namespace.
    pub const CLONE_NEWNET: u64 = 0x4000_0000;
    /// Share the I/O context.
    pub const CLONE_IO: u64 = 0x8000_0000;
    /// Reset every handler in the child (`clone3`).
    pub const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
    /// Start in a cgroup (`clone3`).
    pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
    /// New time namespace.
    pub const CLONE_NEWTIME: u64 = 0x0000_0080;
    /// The flags legacy `clone` can express.
    pub const CLONE_LEGACY_FLAGS: u64 = 0xffff_ffff;
    /// Every namespace flag.
    pub const NAMESPACES: u64 = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWNET
        | CLONE_NEWTIME;
}

use cf::*;

/// `CLONE_ARGS_SIZE_VER0`, the smallest `struct clone_args`.
const CLONE_ARGS_SIZE_VER0: u64 = 64;
/// `CLONE_ARGS_SIZE_VER2`, the full `struct clone_args`.
const CLONE_ARGS_SIZE_VER2: u64 = 88;
/// `MAX_PID_NS_LEVEL`.
const MAX_PID_NS_LEVEL: u64 = 32;
/// `PID_MAX_LIMIT` on 64-bit kernels: the largest `pid_max`.
const PID_MAX_LIMIT: i32 = 4 * 1024 * 1024;

/// `struct kernel_clone_args`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    /// The child's stack pointer (zero keeps the caller's).
    stack: u64,
    tls: u64,
    set_tid: Vec<i32>,
    cgroup: u64,
}

/// `clone`. x86-64 passes `(flags, newsp, parent_tid, child_tid, tls)`;
/// arm64 and riscv (`CONFIG_CLONE_BACKWARDS`) swap the last two. Only the
/// low 32 bits of `flags` count; their low byte is the exit signal.
pub fn clone(c: &mut Ctx<'_>, a: [u64; 6]) -> Result<Outcome, Errno> {
    match c.resume.take() {
        Some(Resume::Vfork { child }) => return vfork_done(c, child),
        Some(Resume::VforkChild { pid }) => return super::child::vfork_wait(c, pid),
        _ => {}
    }
    let (child_tid, tls) = match c.p.abi {
        LinuxAbi::X86_64 => (a[3], a[4]),
        // compat_sys_ia32_clone has the same order.
        LinuxAbi::Aarch64 | LinuxAbi::Riscv64 | LinuxAbi::I386 => (a[4], a[3]),
    };
    let low = a[0] & CLONE_LEGACY_FLAGS;
    let args = CloneArgs {
        flags: low & !CSIGNAL,
        pidfd: a[2],
        child_tid,
        parent_tid: a[2],
        exit_signal: low & CSIGNAL,
        stack: a[1],
        tls,
        set_tid: Vec::new(),
        cgroup: 0,
    };
    kernel_clone(c, args)
}

/// `clone3` (`copy_clone_args_from_user`, `clone3_args_valid`).
pub fn clone3(c: &mut Ctx<'_>, uargs: u64, size: u64) -> Result<Outcome, Errno> {
    match c.resume.take() {
        Some(Resume::Vfork { child }) => return vfork_done(c, child),
        Some(Resume::VforkChild { pid }) => return super::child::vfork_wait(c, pid),
        _ => {}
    }
    if size > super::super::abi::PAGE_SIZE {
        return Err(Errno(E2BIG));
    }
    if size < CLONE_ARGS_SIZE_VER0 {
        return Err(Errno(EINVAL));
    }
    // copy_struct_from_user: bytes past the known structure must be zero.
    if size > CLONE_ARGS_SIZE_VER2 {
        let rest = c.read_mem(
            uargs + CLONE_ARGS_SIZE_VER2,
            (size - CLONE_ARGS_SIZE_VER2) as usize,
        )?;
        if rest.iter().any(|&b| b != 0) {
            return Err(Errno(E2BIG));
        }
    }
    let known = size.min(CLONE_ARGS_SIZE_VER2) as usize;
    let mut raw = c.read_mem(uargs, known)?;
    raw.resize(CLONE_ARGS_SIZE_VER2 as usize, 0);
    let w = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
    let (set_tid, set_tid_size) = (w(8), w(9));
    if set_tid_size > MAX_PID_NS_LEVEL
        || (set_tid == 0 && set_tid_size > 0)
        || (set_tid != 0 && set_tid_size == 0)
    {
        return Err(Errno(EINVAL));
    }
    // The kernel's valid_signal (`sig <= _NSIG`) accepts 0: no signal.
    let exit_signal = w(4);
    if exit_signal & !CSIGNAL != 0 || (exit_signal != 0 && !valid_signal(exit_signal as i32)) {
        return Err(Errno(EINVAL));
    }
    let (flags, cgroup) = (w(0), w(10));
    if flags & CLONE_INTO_CGROUP != 0 && (cgroup > i32::MAX as u64 || size < CLONE_ARGS_SIZE_VER2) {
        return Err(Errno(EINVAL));
    }
    let tids = if set_tid != 0 {
        c.read_mem(set_tid, set_tid_size as usize * 4)?
            .chunks_exact(4)
            .map(|b| i32::from_le_bytes(b.try_into().unwrap()))
            .collect()
    } else {
        Vec::new()
    };
    // clone3_args_valid.
    if flags & !(CLONE_LEGACY_FLAGS | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) != 0
        || flags & (CLONE_DETACHED | (CSIGNAL & !CLONE_NEWTIME)) != 0
        || flags & (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND) == CLONE_SIGHAND | CLONE_CLEAR_SIGHAND
        || (flags & (CLONE_THREAD | CLONE_PARENT) != 0 && exit_signal != 0)
    {
        return Err(Errno(EINVAL));
    }
    // clone3_stack_valid: the stack is given as base and size.
    let (stack, stack_size) = (w(5), w(6));
    let stack = match (stack, stack_size) {
        (0, 0) => 0,
        (0, _) | (_, 0) => return Err(Errno(EINVAL)),
        (base, len) => {
            let end = base.checked_add(len).ok_or(Errno(EINVAL))?;
            if end > c.p.abi.task_size() {
                return Err(Errno(EINVAL));
            }
            end
        }
    };
    let args = CloneArgs {
        flags,
        pidfd: w(1),
        child_tid: w(2),
        parent_tid: w(3),
        exit_signal,
        stack,
        tls: w(7),
        set_tid: tids,
        cgroup,
    };
    kernel_clone(c, args)
}

/// `kernel_clone` and `copy_process` for a thread of this process.
fn kernel_clone(c: &mut Ctx<'_>, args: CloneArgs) -> Result<Outcome, Errno> {
    let flags = args.flags;
    if flags & CLONE_PIDFD != 0 && flags & CLONE_PARENT_SETTID != 0 && args.pidfd == args.parent_tid
    {
        return Err(Errno(EINVAL));
    }
    // copy_process: flag combinations.
    let both = |a: u64, b: u64| flags & (a | b) == a | b;
    if both(CLONE_NEWNS, CLONE_FS)
        || both(CLONE_NEWUSER, CLONE_FS)
        || (flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0)
        || (flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0)
        || (flags & CLONE_PARENT != 0 && c.p.unkillable)
        || (flags & CLONE_THREAD != 0 && flags & (CLONE_NEWUSER | CLONE_NEWPID) != 0)
        || (flags & CLONE_PIDFD != 0 && flags & CLONE_DETACHED != 0)
    {
        return Err(Errno(EINVAL));
    }
    // A signal pending for the caller is delivered before the fork.
    c.t.sigpending = recalc_sigpending(c.p, c.t);
    if c.t.sigpending {
        return Err(Errno(ERESTARTNOINTR));
    }
    // Namespaces need privileges the emulated process does not have.
    if flags & NAMESPACES != 0 {
        return Err(Errno(EPERM));
    }
    // A new process.
    if flags & CLONE_THREAD == 0 {
        return super::child::fork(
            c,
            super::child::ForkArgs {
                flags,
                exit_signal: args.exit_signal,
                stack: args.stack,
                tls: args.tls,
                parent_tid: args.parent_tid,
                child_tid: args.child_tid,
                pidfd: args.pidfd,
                set_tid: args.set_tid,
            },
        );
    }
    if flags & (CLONE_FILES | CLONE_FS) != CLONE_FILES | CLONE_FS || flags & CLONE_INTO_CGROUP != 0
    {
        return Err(Errno(EINVAL));
    }
    // sched_fork (EAGAIN for a deadline task), then copy_thread.
    let sched = c.t.sched.forked(flags & CLONE_IO != 0)?;
    let sysvsem = copy_semundo(c, flags);
    if flags & CLONE_SETTLS != 0 && c.p.abi == LinuxAbi::X86_64 && args.tls >= c.p.abi.task_size() {
        // x86-64 set_new_tls: ARCH_SET_FS refuses a kernel address.
        return Err(Errno(EPERM));
    }
    // alloc_pid: one PID namespace level exists, a chosen TID must be in
    // range, and choosing one needs CAP_CHECKPOINT_RESTORE.
    let tid = match args.set_tid.as_slice() {
        [] => next_tid(c),
        [want] => {
            if !(1..PID_MAX_LIMIT).contains(want) {
                return Err(Errno(EINVAL));
            }
            if c.p.creds.1 != 0 {
                return Err(Errno(EPERM));
            }
            if tid_in_use(c, *want) {
                return Err(Errno(EEXIST));
            }
            *want
        }
        _ => return Err(Errno(EINVAL)),
    };
    // pidfd_prepare with PIDFD_THREAD, then its number for the caller.
    if flags & CLONE_PIDFD != 0 {
        super::pidfd::clone_check(c, args.pidfd)?;
        super::pidfd::clone_install(c, c.p.pid, tid, args.pidfd)?;
    }
    let mut cpu = c.t.cpu.clone_thread();
    cpu.set_syscall_result(0);
    if args.stack != 0 {
        cpu.set_sp(args.stack);
    }
    if flags & CLONE_SETTLS != 0 {
        cpu.set_thread_pointer(args.tls);
    }
    let mut child = Thread::new(tid, cpu);
    child.sigmask = c.t.sigmask;
    child.comm = c.t.comm.clone();
    // copy_seccomp: the filters are shared, and no_new_privs is kept, as
    // are the thread flags.
    child.seccomp = c.t.seccomp.clone();
    child.no_new_privs = c.t.no_new_privs;
    child.notsc = c.t.notsc;
    child.cpu.set_tsc_disabled(child.notsc);
    child.sched = sched;
    child.sysvsem = sysvsem;
    // A thread sharing the address space gets no alternate stack.
    child.altstack = if flags & CLONE_VFORK == 0 {
        AltStack::DISABLED
    } else {
        c.t.altstack
    };
    if flags & CLONE_CHILD_SETTID != 0 {
        child.set_child_tid = args.child_tid;
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        child.clear_child_tid = args.child_tid;
    }
    c.p.next_tid = c.p.next_tid.max(tid + 1);
    if flags & CLONE_PARENT_SETTID != 0 {
        let _ = c.write_u32(args.parent_tid, tid as u32);
    }
    trace_child(c, &mut child, flags);
    if flags & CLONE_VFORK != 0 {
        child.vfork_parent = Some(c.t.tid);
        c.spawned.push(child);
        return Err(c.block(Wait::uninterruptible(), Resume::Vfork { child: tid }));
    }
    c.spawned.push(child);
    Ok(Outcome::Return(tid as u64))
}

/// `ptrace_init_task` and `kernel_clone`'s event for a new thread: traced
/// as its maker is when the maker's tracer asked for its event
/// (`PTRACE_O_TRACECLONE`: a thread's exit signal is none) or
/// `CLONE_PTRACE` asks, unless `CLONE_UNTRACED`; it starts with `SIGSTOP`
/// pending (a trap when seized), its tracer is told of it, and the maker
/// stops for the event as the call finishes. (A thread made with
/// `CLONE_VFORK` has no event here: `PTRACE_EVENT_VFORK` comes before the
/// maker waits, which this does not model.)
fn trace_child(c: &mut Ctx<'_>, child: &mut Thread, flags: u64) {
    use super::super::ptrace::{EVENT_CLONE, Msg, Traced, send, tracee};
    use super::super::signal::{SIGSTOP, SigInfo, code};
    let Some(tr) = c.t.ptrace.as_ref().filter(|tr| tr.tracer >= 0) else {
        return;
    };
    let event = EVENT_CLONE;
    let traced = flags & (CLONE_UNTRACED | CLONE_VFORK) == 0 && tr.event_enabled(event);
    if !traced && flags & CLONE_PTRACE == 0 {
        return;
    }
    let mut t = Traced::new(tr.tracer, tr.link, tr.seized, tr.options);
    if tr.seized {
        t.trap_stop = true;
    } else {
        // sigaddset alone: taken with no siginfo of its own (SI_USER).
        child
            .pending
            .enqueue(SigInfo::kill(SIGSTOP, code::SI_USER, 0, 0));
    }
    child.sigpending = true;
    child.ptrace = Some(t);
    let (link, seized) = (tr.link, tr.seized);
    let m = Msg::Traced {
        tid: child.tid,
        parent: c.t.tid,
        seized,
    };
    send(c.p, link, &m);
    if traced {
        tracee::due_event(c.t, event, child.tid as u64);
    }
}

/// `wait_for_vfork_done`, when the parent runs again: the child has
/// exited.
pub fn vfork_done(c: &mut Ctx<'_>, child: i32) -> Result<Outcome, Errno> {
    if !c.woken {
        return Err(c.block(Wait::uninterruptible(), Resume::Vfork { child }));
    }
    Ok(Outcome::Return(child as u64))
}

/// Whether a thread of the process uses TID `tid` (the exited leader keeps
/// its ID).
fn tid_in_use(c: &Ctx<'_>, tid: i32) -> bool {
    tid == c.p.pid
        || tid == c.t.tid
        || c.peers
            .lo
            .iter()
            .chain(c.peers.hi.iter())
            .any(|t| t.tid == tid)
        || c.spawned.iter().any(|t| t.tid == tid)
}

/// The next free TID.
fn next_tid(c: &mut Ctx<'_>) -> i32 {
    let mut tid = c.p.next_tid;
    while tid_in_use(c, tid) {
        tid = tid.checked_add(1).unwrap_or(c.p.pid + 1);
    }
    c.p.next_tid = tid + 1;
    tid
}

/// `set_tid_address`.
pub fn set_tid_address(c: &mut Ctx<'_>, tidptr: u64) -> SysResult {
    c.t.clear_child_tid = tidptr;
    Ok(c.t.tid as u64)
}

/// `copy_semundo`: with `CLONE_SYSVSEM` the new task shares the creator's
/// undo list, which is made now if the creator had none; without, it has
/// none.
pub(super) fn copy_semundo(c: &mut Ctx<'_>, flags: u64) -> Option<UndoList> {
    (flags & CLONE_SYSVSEM != 0).then(|| c.t.sysvsem.get_or_insert_with(UndoList::new).clone())
}

/// `unshare` (`ksys_unshare`): the flags a request implies are added
/// (`CLONE_NEWUSER` needs `CLONE_THREAD` and `CLONE_FS`, `CLONE_VM`
/// `CLONE_SIGHAND`, which needs `CLONE_THREAD`, and `CLONE_NEWNS`
/// `CLONE_FS`); unknown flags are `EINVAL`, and so is unsharing the thread
/// group, signal handlers, or address space while other threads exist
/// (`check_unshare_flags`). A process's threads share their descriptor
/// table and file-system context, which a single thread need not unshare;
/// a thread of several cannot have its own (`EINVAL`, as for `clone`).
/// Namespaces need privileges the emulated process does not have
/// (`EPERM`). `CLONE_SYSVSEM` leaves the caller's semaphore undo list as
/// an exit would (`exit_sem`).
pub fn unshare(c: &mut Ctx<'_>, flags: u64) -> SysResult {
    const ALLOWED: u64 = CLONE_THREAD
        | CLONE_FS
        | CLONE_NEWNS
        | CLONE_SIGHAND
        | CLONE_VM
        | CLONE_FILES
        | CLONE_SYSVSEM
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWNET
        | CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWCGROUP
        | CLONE_NEWTIME;
    let mut flags = flags;
    if flags & CLONE_NEWUSER != 0 {
        flags |= CLONE_THREAD | CLONE_FS;
    }
    if flags & CLONE_VM != 0 {
        flags |= CLONE_SIGHAND;
    }
    if flags & CLONE_SIGHAND != 0 {
        flags |= CLONE_THREAD;
    }
    if flags & CLONE_NEWNS != 0 {
        flags |= CLONE_FS;
    }
    if flags & !ALLOWED != 0 {
        return Err(Errno(EINVAL));
    }
    let others = !c.peers.lo.is_empty() || !c.peers.hi.is_empty();
    // thread_group_empty: the leader, alone.
    let group_empty = c.t.tid == c.p.pid && !others;
    if flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0 && !group_empty {
        return Err(Errno(EINVAL));
    }
    // unshare_fs, unshare_fd: tables other threads share.
    if flags & (CLONE_FILES | CLONE_FS) != 0 && others {
        return Err(Errno(EINVAL));
    }
    if flags & NAMESPACES != 0 {
        return Err(Errno(EPERM));
    }
    if flags & CLONE_SYSVSEM != 0 && c.t.sysvsem.take().is_some() {
        let others = c.thread_refs().iter().any(|t| t.sysvsem.is_some());
        super::ipc::leave_undo_list(c.p, others);
    }
    Ok(0)
}

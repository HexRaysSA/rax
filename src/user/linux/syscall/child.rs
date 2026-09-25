//! New processes and waiting for them: `fork`, `vfork`, and `clone`/`clone3`
//! without `CLONE_THREAD` (`kernel/fork.c`), and `wait4`/`waitid`
//! (`kernel/exit.c`).
//!
//! A new process is a fork of the emulator (see
//! [`children`](crate::user::linux::children)). Its memory is a copy, so a
//! `CLONE_VM | CLONE_VFORK` child (as `posix_spawn` makes) runs with copy
//! semantics: the parent sleeps until the child calls `execve` or ends, but
//! does not see the child's stores. Processes that share memory without
//! `CLONE_VFORK`, a descriptor table, a file-system context, or handlers
//! with their parent, and `CLONE_PARENT`, are not supported.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::children::{ChildEvent, ForkedSelf};
use super::super::host;
use super::super::process::{ProcState, Threads};
use super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::signal::deliver::{self, Dest};
use super::super::signal::{SIG_IGN, SIGCHLD, SIGCONT, SigInfo, code, sa};
use super::super::wait::{Resume, Wait};
use super::thread::cf::*;
use super::{Ctx, Outcome};

/// `wait4`/`waitid` options (`linux/wait.h`).
pub mod wf {
    /// Do not sleep.
    pub const WNOHANG: u32 = 0x0000_0001;
    /// Report stopped children (`WSTOPPED`).
    pub const WUNTRACED: u32 = 0x0000_0002;
    /// Report exited children.
    pub const WEXITED: u32 = 0x0000_0004;
    /// Report continued children.
    pub const WCONTINUED: u32 = 0x0000_0008;
    /// Leave the child waitable.
    pub const WNOWAIT: u32 = 0x0100_0000;
    /// Only children of the calling thread.
    pub const WNOTHREAD: u32 = 0x2000_0000;
    /// Every child, whatever its exit signal.
    pub const WALL: u32 = 0x4000_0000;
    /// Only children whose exit signal is not `SIGCHLD`.
    pub const WCLONE: u32 = 0x8000_0000;
}
use wf::*;

/// USER_HZ: `clock_t` ticks per second.
const USER_HZ: u64 = 100;

/// A `struct kernel_clone_args` for a new process.
pub struct ForkArgs {
    /// Flags.
    pub flags: u64,
    /// `exit_signal`.
    pub exit_signal: u64,
    /// The child's stack pointer (0 keeps the caller's).
    pub stack: u64,
    /// `CLONE_SETTLS` value.
    pub tls: u64,
    /// `CLONE_PARENT_SETTID` address.
    pub parent_tid: u64,
    /// `CLONE_CHILD_SETTID`/`CLONE_CHILD_CLEARTID` address.
    pub child_tid: u64,
    /// `CLONE_PIDFD` address.
    pub pidfd: u64,
    /// `set_tid`.
    pub set_tid: Vec<i32>,
}

/// `kernel_clone` for a new process, after the checks it shares with
/// thread creation.
pub fn fork(c: &mut Ctx<'_>, args: ForkArgs) -> Result<Outcome, Errno> {
    let flags = args.flags;
    if !c.p.config.processes {
        return Err(Errno(ENOSYS));
    }
    // Sharing memory without CLONE_VFORK, or any table, is unsupported.
    if flags & CLONE_VM != 0 && flags & CLONE_VFORK == 0 {
        return Err(Errno(ENOSYS));
    }
    if flags & (CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_PARENT | CLONE_INTO_CGROUP) != 0 {
        return Err(Errno(EINVAL));
    }
    // sched_fork (EAGAIN for a deadline task), then copy_thread.
    let sched = c.t.sched.forked(flags & CLONE_IO != 0)?;
    let sysvsem = super::thread::copy_semundo(c, flags);
    if flags & CLONE_SETTLS != 0
        && c.p.abi == super::super::abi::LinuxAbi::X86_64
        && args.tls >= c.p.abi.task_size()
    {
        return Err(Errno(EPERM));
    }
    // alloc_pid: a chosen PID needs CAP_CHECKPOINT_RESTORE; the host
    // chooses a new process's PID, so it cannot be honored.
    if let Some(&want) = args.set_tid.first() {
        if !(1..4 * 1024 * 1024).contains(&want) || args.set_tid.len() > 1 {
            return Err(Errno(EINVAL));
        }
        return Err(Errno(if c.p.creds.1 != 0 { EPERM } else { EINVAL }));
    }
    // The pidfd is prepared before the child exists (and is not the
    // child's): its descriptor and result word must be available.
    if flags & CLONE_PIDFD != 0 {
        super::pidfd::clone_check(c, args.pidfd)?;
    }
    host::watch_children()?;
    let (read, write) = host::status_pipe()?;
    // The child shares the open file descriptions.
    if let Some(h) = &c.p.fsnotify {
        h.before_fork();
    }
    let forked = host::fork_process();
    if forked.is_err()
        && let Some(h) = &c.p.fsnotify
    {
        h.fork_failed();
    }
    match forked? {
        Some(pid) => {
            drop(write);
            let (tid, exec_id) = (c.t.tid, c.p.exec_id);
            c.p.children
                .add(pid, read, args.exit_signal as i32, tid, exec_id);
            if flags & CLONE_PIDFD != 0 {
                super::pidfd::clone_install(c, pid, pid, args.pidfd)?;
            }
            if flags & CLONE_PARENT_SETTID != 0 {
                let _ = c.write_u32(args.parent_tid, pid as u32);
            }
            if flags & CLONE_VFORK != 0 {
                return vfork_wait(c, pid);
            }
            Ok(Outcome::Return(pid as u64))
        }
        None => {
            drop(read);
            c.t.sched = sched;
            // With CLONE_SYSVSEM the child's list stands for the one its
            // parent shares with it; each process applies its own
            // adjustments at its exit.
            c.t.sysvsem = sysvsem;
            become_child(c, &args);
            Ok(Outcome::Forked(ForkedSelf {
                status: write,
                vfork: flags & CLONE_VFORK != 0,
            }))
        }
    }
}

/// `copy_process` for the calling thread in the new process: a new PID,
/// no children, pending signals, interval timers, robust list, or other
/// threads; the child's stack, TLS, and TID words.
fn become_child(c: &mut Ctx<'_>, args: &ForkArgs) {
    let pid = host::pid();
    c.p.pidfds.forked(pid);
    // copy_process: POSIX locks are not inherited.
    super::super::fs::locks::forked();
    // Emulated netlink sockets get readiness levels of their own.
    super::super::net::netlink::forked();
    // It holds the inotify instances its parent held.
    if let Some(h) = &c.p.fsnotify {
        h.forked();
    }
    let p = &mut *c.p;
    p.pid = pid;
    // dup_mmap: the inherited System V mappings are the child's attaches,
    // and no mapping stays locked (mm_init drops MCL_FUTURE too).
    super::ipc::forked(p);
    super::mlock::forked(p);
    p.ppid = host::ppid();
    p.next_tid = pid + 1;
    p.children = Default::default();
    p.shared_pending = super::super::signal::SigPending::new();
    p.itimers = Default::default();
    p.timers = Default::default();
    p.futex = Default::default();
    p.curr_target = pid;
    p.leader_exit = None;
    p.unkillable = false;
    p.pdeathsig = 0;
    if args.flags & CLONE_CLEAR_SIGHAND != 0 {
        for a in p.sigactions.iter_mut() {
            if a.handler != SIG_IGN {
                a.handler = 0;
            }
            a.flags = 0;
            a.restorer = 0;
            a.mask = 0;
        }
    }
    let t = &mut *c.t;
    t.tid = pid;
    t.pending = super::super::signal::SigPending::new();
    t.sigpending = false;
    t.robust_list = (0, 0);
    t.restart = None;
    t.clear_child_tid = if args.flags & CLONE_CHILD_CLEARTID != 0 {
        args.child_tid
    } else {
        0
    };
    t.set_child_tid = if args.flags & CLONE_CHILD_SETTID != 0 {
        args.child_tid
    } else {
        0
    };
    if args.stack != 0 {
        t.cpu.set_sp(args.stack);
    }
    if args.flags & CLONE_SETTLS != 0 {
        t.cpu.set_thread_pointer(args.tls);
    }
}

/// `wait_for_vfork_done`: sleeps (killable only) until child `pid` calls
/// `execve` or ends, then returns its PID.
pub fn vfork_wait(c: &mut Ctx<'_>, pid: i32) -> Result<Outcome, Errno> {
    let (p, mut th) = c.split();
    refresh(p, &mut th);
    let fds = match p.children.list.iter().find(|ch| ch.pid == pid) {
        Some(ch) if !ch.released => p.children.live_fds(|x| x.pid == pid),
        _ => return Ok(Outcome::Return(pid as u64)),
    };
    let mut wait = Wait::fds(fds, None);
    wait.interruptible = false;
    Err(c.block(wait, Resume::VforkChild { pid }))
}

/// `fork` (x86-64).
pub fn sys_fork(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    fork_like(c, 0)
}

/// `vfork` (x86-64).
pub fn sys_vfork(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    if let Some(Resume::VforkChild { pid }) = c.resume.take() {
        return vfork_wait(c, pid);
    }
    fork_like(c, CLONE_VM | CLONE_VFORK)
}

fn fork_like(c: &mut Ctx<'_>, flags: u64) -> Result<Outcome, Errno> {
    c.t.sigpending = deliver::recalc_sigpending(c.p, c.t);
    if c.t.sigpending {
        return Err(Errno(
            super::super::signal::deliver::restart::ERESTARTNOINTR,
        ));
    }
    fork(
        c,
        ForkArgs {
            flags,
            exit_signal: SIGCHLD as u64,
            stack: 0,
            tls: 0,
            parent_tid: 0,
            child_tid: 0,
            pidfd: 0,
            set_tid: Vec::new(),
        },
    )
}

/// Takes the children's state changes: `do_notify_parent` for exits
/// (`SIGCHLD`, or the child's exit signal, with its status; a child whose
/// `SIGCHLD` is ignored or has `SA_NOCLDWAIT` is reaped at once) and
/// `do_notify_parent_cldstop` for stops and continuations (unless
/// `SA_NOCLDSTOP`); threads sleeping in `wait` or `vfork` run again.
pub fn refresh(p: &mut ProcState, th: &mut Threads<'_>) {
    let events = p.children.poll();
    if events.is_empty() {
        return;
    }
    let chld = p.sigactions[(SIGCHLD - 1) as usize];
    // A child named by a pidfd became readable: its pollers look again.
    let polled = events
        .iter()
        .any(|e| matches!(e, ChildEvent::Exited(pid) if p.pidfds.names_process(*pid)));
    for e in events {
        match e {
            ChildEvent::Exited(pid) => {
                let Some(ch) = p.children.get_mut(pid) else {
                    continue;
                };
                let (status, (utime, stime, _)) = ch.zombie.expect("an exited child is a zombie");
                let mut sig = ch.exit_signal;
                // An exit signal other than SIGCHLD reverts to SIGCHLD
                // after the parent's execve.
                if sig != SIGCHLD && ch.parent_exec_id != p.exec_id {
                    sig = SIGCHLD;
                }
                let (cause, si_status) = cause_of(status);
                let mut info = SigInfo::child(
                    cause,
                    pid,
                    p.creds.0,
                    si_status,
                    (utime * USER_HZ / 1_000_000) as i64,
                    (stime * USER_HZ / 1_000_000) as i64,
                );
                let autoreap =
                    sig == SIGCHLD && (chld.handler == SIG_IGN || chld.flags & sa::NOCLDWAIT != 0);
                if sig == SIGCHLD && chld.handler == SIG_IGN {
                    sig = 0;
                }
                if autoreap {
                    reap(p, pid);
                }
                if sig > 0 && sig <= 64 {
                    info.signo = sig;
                    let pid = p.pid;
                    deliver::send_signal(p, th, info, Dest::Process(pid), false);
                }
            }
            ChildEvent::Stopped(..) | ChildEvent::Continued(_) => {
                let (pid, cause, status) = match e {
                    ChildEvent::Stopped(pid, sig) => (pid, code::CLD_STOPPED, sig),
                    ChildEvent::Continued(pid) => (pid, code::CLD_CONTINUED, SIGCONT),
                    ChildEvent::Exited(_) => unreachable!("handled above"),
                };
                if chld.handler != SIG_IGN && chld.flags & sa::NOCLDSTOP == 0 {
                    let info = SigInfo::child(cause, pid, p.creds.0, status, 0, 0);
                    let me = p.pid;
                    deliver::send_signal(p, th, info, Dest::Process(me), false);
                }
            }
        }
    }
    for t in th.iter_mut() {
        if let Some(b) = t.blocked.as_mut()
            && (matches!(b.resume, Resume::WaitChild | Resume::VforkChild { .. })
                || (polled && matches!(b.resume, Resume::Until(_))))
        {
            b.woken = true;
        }
    }
}

/// `release_task` for a child: its record goes, and its pidfds see it gone
/// with its wait status (`pidfs_exit`).
fn reap(p: &mut ProcState, pid: i32) {
    if let Some(ch) = p.children.reap(pid) {
        p.pidfds
            .task_ended(pid, pid, ch.zombie.map(|(status, _)| status));
    }
}

/// `si_code` and `si_status` of an exit's wait status.
fn cause_of(status: i32) -> (i32, i32) {
    if status & 0x7f == 0 {
        (code::CLD_EXITED, status >> 8)
    } else if status & 0x80 != 0 {
        (code::CLD_DUMPED, status & 0x7f)
    } else {
        (code::CLD_KILLED, status & 0x7f)
    }
}

/// Which children a wait selects (`wo_type`, `wo_pid`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Select {
    Any,
    Pid(i32),
    Pgid(i32),
    /// A task that is no child (a pidfd's thread, or a task that is gone).
    Nothing,
}

/// What a wait found: the child, its wait status, `si_code`, `si_status`,
/// and resource use.
struct Found {
    pid: i32,
    status: i32,
    cause: i32,
    si_status: i32,
    rusage: (u64, u64, u64),
}

/// `do_wait`: the first eligible child with something to report, in
/// creation order (an exit, then a stop, then a continuation); `ECHILD`
/// without eligible children; `None` with `WNOHANG` when none is ready;
/// otherwise the thread sleeps until a child changes (`-ERESTARTSYS` if a
/// signal comes first).
fn do_wait(c: &mut Ctx<'_>, sel: Select, flags: u32) -> Result<Option<Found>, Errno> {
    c.resume = None;
    let me = c.t.tid;
    {
        let (p, mut th) = c.split();
        refresh(p, &mut th);
    }
    let eligible = |ch: &super::super::children::Child| {
        let matches = match sel {
            Select::Any => true,
            Select::Pid(pid) => ch.pid == pid,
            Select::Pgid(g) => ch.pgid == g,
            Select::Nothing => false,
        };
        let kind = flags & WALL != 0 || ((ch.exit_signal != SIGCHLD) == (flags & WCLONE != 0));
        let thread = flags & WNOTHREAD == 0 || ch.creator == me;
        matches && kind && thread
    };
    if !c.p.children.list.iter().any(|ch| eligible(ch)) {
        return Err(Errno(ECHILD));
    }
    let mut found = None;
    for ch in c.p.children.list.iter_mut().filter(|ch| eligible(ch)) {
        if let Some((status, rusage)) = ch.zombie {
            if flags & WEXITED != 0 {
                let (cause, si_status) = cause_of(status);
                found = Some((
                    Found {
                        pid: ch.pid,
                        status,
                        cause,
                        si_status,
                        rusage,
                    },
                    true,
                ));
                break;
            }
            continue;
        }
        if flags & WUNTRACED != 0
            && let Some(sig) = ch.stopped
        {
            if flags & WNOWAIT == 0 {
                ch.stopped = None;
            }
            found = Some((
                Found {
                    pid: ch.pid,
                    status: (sig << 8) | 0x7f,
                    cause: code::CLD_STOPPED,
                    si_status: sig,
                    rusage: (0, 0, 0),
                },
                false,
            ));
            break;
        }
        if flags & WCONTINUED != 0 && ch.continued {
            if flags & WNOWAIT == 0 {
                ch.continued = false;
            }
            found = Some((
                Found {
                    pid: ch.pid,
                    status: 0xffff,
                    cause: code::CLD_CONTINUED,
                    si_status: SIGCONT,
                    rusage: (0, 0, 0),
                },
                false,
            ));
            break;
        }
    }
    if let Some((f, exited)) = found {
        if exited && flags & WNOWAIT == 0 {
            reap(c.p, f.pid);
        }
        return Ok(Some(f));
    }
    if flags & WNOHANG != 0 {
        return Ok(None);
    }
    if c.signal_pending() {
        return Err(Errno(ERESTARTSYS));
    }
    let fds = c.p.children.live_fds(|ch| eligible(ch));
    Err(c.block(Wait::fds(fds, None), Resume::WaitChild))
}

/// Encodes a `struct rusage` with user and system microseconds and the
/// maximum resident size.
fn rusage_bytes((user, system, maxrss): (u64, u64, u64)) -> [u8; 144] {
    let mut b = [0u8; 144];
    let tv = |us: u64| {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&((us / 1_000_000) as i64).to_le_bytes());
        t[8..].copy_from_slice(&((us % 1_000_000) as i64).to_le_bytes());
        t
    };
    b[..16].copy_from_slice(&tv(user));
    b[16..32].copy_from_slice(&tv(system));
    b[32..40].copy_from_slice(&(maxrss as i64).to_le_bytes());
    b
}

/// The caller's process group.
fn own_pgid() -> Result<i32, Errno> {
    host::getpgid(0)
}

/// `wait4` (`kernel_wait4`).
pub fn wait4(
    c: &mut Ctx<'_>,
    upid: i32,
    stat: u64,
    options: u32,
    ru: u64,
) -> Result<Outcome, Errno> {
    if options & !(WNOHANG | WUNTRACED | WCONTINUED | WNOTHREAD | WCLONE | WALL) != 0 {
        return Err(Errno(EINVAL));
    }
    if upid == i32::MIN {
        return Err(Errno(ESRCH));
    }
    let sel = match upid {
        -1 => Select::Any,
        p if p < 0 => Select::Pgid(-p),
        0 => Select::Pgid(own_pgid()?),
        p => Select::Pid(p),
    };
    let Some(f) = do_wait(c, sel, options | WEXITED)? else {
        return Ok(Outcome::Return(0));
    };
    if stat != 0 {
        c.write_u32(stat, f.status as u32)?;
    }
    if ru != 0 {
        c.write_mem(ru, &rusage_bytes(f.rusage))?;
    }
    Ok(Outcome::Return(f.pid as u64))
}

/// `waitid`: `kernel_waitid`, then the `siginfo_t` fields `si_signo`,
/// `si_errno`, `si_code`, `si_pid`, `si_uid`, and `si_status` are written
/// on every return but `EFAULT` (zeros when no child was found, errors
/// included); the rest of the structure is left alone.
pub fn waitid(
    c: &mut Ctx<'_>,
    which: i32,
    id: i32,
    infop: u64,
    options: u32,
    ru: u64,
) -> Result<Outcome, Errno> {
    let found = match waitid_select(c, which, id, options) {
        // A non-blocking pidfd does not sleep, and says so with EAGAIN.
        Ok((sel, nohang)) if nohang && options & WNOHANG == 0 => {
            match do_wait(c, sel, options | WNOHANG) {
                Ok(None) => Err(Errno(EAGAIN)),
                other => other,
            }
        }
        Ok((sel, _)) => do_wait(c, sel, options),
        Err(e) => Err(e),
    };
    // A sleeping wait writes nothing until it finishes.
    if super::is_blocked(&found) {
        return Err(found.err().expect("blocked"));
    }
    if let Ok(Some(f)) = &found
        && ru != 0
    {
        c.write_mem(ru, &rusage_bytes(f.rusage))?;
    }
    if infop != 0 {
        // user_write_access_begin covers the whole 128-byte siginfo_t.
        if infop
            .checked_add(128)
            .is_none_or(|end| end > c.p.abi.task_size())
        {
            return Err(Errno(EFAULT));
        }
        let (mut head, mut body) = ([0u8; 12], [0u8; 12]);
        if let Ok(Some(f)) = &found {
            head[..4].copy_from_slice(&SIGCHLD.to_le_bytes());
            head[8..].copy_from_slice(&f.cause.to_le_bytes());
            body[..4].copy_from_slice(&f.pid.to_le_bytes());
            body[4..8].copy_from_slice(&c.p.creds.0.to_le_bytes());
            body[8..].copy_from_slice(&f.si_status.to_le_bytes());
        }
        c.write_mem(infop, &head)?;
        c.write_mem(infop + 16, &body)?;
    }
    found.map(|_| Outcome::Return(0))
}

/// `kernel_waitid_prepare`: the options and the children `which` and `id`
/// select, and whether a non-blocking pidfd adds `WNOHANG`.
fn waitid_select(c: &Ctx<'_>, which: i32, id: i32, options: u32) -> Result<(Select, bool), Errno> {
    const P_ALL: i32 = 0;
    const P_PID: i32 = 1;
    const P_PGID: i32 = 2;
    const P_PIDFD: i32 = 3;
    if options & !(WNOHANG | WNOWAIT | WEXITED | WUNTRACED | WCONTINUED | WNOTHREAD | WCLONE | WALL)
        != 0
    {
        return Err(Errno(EINVAL));
    }
    if options & (WEXITED | WUNTRACED | WCONTINUED) == 0 {
        return Err(Errno(EINVAL));
    }
    let sel = match which {
        P_ALL => Select::Any,
        P_PID if id <= 0 => return Err(Errno(EINVAL)),
        P_PID => Select::Pid(id),
        P_PGID if id < 0 => return Err(Errno(EINVAL)),
        P_PGID if id == 0 => Select::Pgid(own_pgid()?),
        P_PGID => Select::Pgid(id),
        P_PIDFD if id < 0 => return Err(Errno(EINVAL)),
        // The pidfd's task (PIDTYPE_PID): a child only if it names one.
        P_PIDFD => {
            let (child, nonblock) = super::pidfd::wait_target(c, id)?;
            return Ok((child.map_or(Select::Nothing, Select::Pid), nonblock));
        }
        _ => return Err(Errno(EINVAL)),
    };
    Ok((sel, false))
}

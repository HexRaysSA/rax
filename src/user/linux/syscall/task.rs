//! Naming another task and the right to look into it
//! (`find_task_by_vpid`, `pidfd_get_task`, `mm_access`, and
//! `__ptrace_may_access`, Linux 6.19) for the calls that reach into a task
//! by its ID or a pidfd.
//!
//! The calling process's threads are reachable, and so is their exited
//! leader while others run (`delay_group_leader`), without an address
//! space or tables. Another process is a host process whose memory and
//! tables this one cannot reach, so the right to inspect it is refused as
//! a denied `ptrace_may_access` is, for root too.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::host;
use super::Ctx;
use super::pidfd::{PIDFD_SELF_THREAD, PIDFD_SELF_THREAD_GROUP, Task as PidfdTask};

/// A task a call names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// A live thread of the calling process, by TID.
    Own(i32),
    /// The calling process's leader, exited while other threads run: its
    /// memory, descriptors, file-system context, I/O context, and undo list
    /// are gone (`exit_mm`, `exit_files`, `exit_fs`, `exit_io_context`,
    /// `exit_sem`); its signal handlers stay.
    ExitedLeader,
    /// A task of another process; `zombie` when it has exited but was not
    /// reaped, so it has no memory either.
    Other { zombie: bool },
}

/// `find_task_by_vpid`: the task with ID `pid`, `ESRCH` for none. Another
/// process's threads other than its leader cannot be named.
pub fn find(c: &Ctx<'_>, pid: i32) -> Result<Task, Errno> {
    if pid <= 0 {
        return Err(Errno(ESRCH));
    }
    if c.is_own_tid(pid) {
        return Ok(Task::Own(pid));
    }
    if pid == c.p.pid {
        return if c.p.leader_exit.is_some() {
            Ok(Task::ExitedLeader)
        } else {
            Err(Errno(ESRCH))
        };
    }
    if let Some(ch) = c.p.children.list.iter().find(|ch| ch.pid == pid) {
        return Ok(Task::Other {
            zombie: ch.zombie.is_some(),
        });
    }
    if !c.p.config.processes {
        return Err(Errno(ESRCH));
    }
    match host::kill(pid, 0) {
        Err(Errno(ESRCH)) => Err(Errno(ESRCH)),
        _ => Ok(Task::Other { zombie: false }),
    }
}

/// `pidfd_get_task`: the thread-group leader a pidfd names (the caller or
/// its process for `PIDFD_SELF_THREAD` and `PIDFD_SELF_THREAD_GROUP`).
/// `EBADF` for a descriptor that is not a pidfd, `ESRCH` for a task gone
/// or a pidfd naming a thread other than a leader.
pub fn from_pidfd(c: &Ctx<'_>, pidfd: i32) -> Result<Task, Errno> {
    let leader = || {
        if c.p.leader_exit.is_some() {
            Task::ExitedLeader
        } else {
            Task::Own(c.p.pid)
        }
    };
    match pidfd {
        PIDFD_SELF_THREAD => return Ok(Task::Own(c.t.tid)),
        PIDFD_SELF_THREAD_GROUP => return Ok(leader()),
        _ => {}
    }
    let file = c.p.fds.file(pidfd)?;
    let t = super::pidfd::target_of(&file).ok_or(Errno(EBADF))?.clone();
    // get_pid_task(pid, PIDTYPE_TGID): a leader's PID only.
    if t.tid != t.tgid {
        return Err(Errno(ESRCH));
    }
    match super::pidfd::state(c, &t) {
        PidfdTask::Gone(_) => Err(Errno(ESRCH)),
        _ if t.tgid == c.p.pid => Ok(leader()),
        PidfdTask::Zombie(_) => Ok(Task::Other { zombie: true }),
        PidfdTask::Alive => Ok(Task::Other { zombie: false }),
    }
}

/// `mm_access`: `ESRCH` for a task without memory, `EACCES` when it may
/// not be inspected.
pub fn mm_access(task: Task) -> Result<(), Errno> {
    match task {
        Task::Own(_) => Ok(()),
        Task::ExitedLeader | Task::Other { zombie: true } => Err(Errno(ESRCH)),
        Task::Other { zombie: false } => Err(Errno(EACCES)),
    }
}

/// `ptrace_may_access`: a task of the caller's thread group always may be
/// inspected (`same_thread_group`), another process's may not.
pub fn may_inspect(task: Task) -> bool {
    !matches!(task, Task::Other { .. })
}

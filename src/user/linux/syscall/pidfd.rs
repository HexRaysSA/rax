//! pidfds (`kernel/pid.c`, `fs/pidfs.c`): `pidfd_open`,
//! `pidfd_send_signal`, `pidfd_getfd`, the pidfd `ioctl`s and `poll`, and
//! the pidfds `clone` returns (`CLONE_PIDFD`, `kernel/fork.c`) and `waitid`
//! takes (`P_PIDFD`, `kernel/exit.c`).
//!
//! A pidfd is an anonymous-inode file (mode `0700` without a file type,
//! owned by root, on `pidfs`) opened `O_RDWR`, with `O_NONBLOCK` from
//! `PIDFD_NONBLOCK` and `O_EXCL` for `PIDFD_THREAD`, always close-on-exec.
//! It cannot be read, written, or mapped. It polls readable once the task
//! has exited (a thread-group leader: once its whole group has), and hung
//! up once the task is gone (reaped; a thread other than the leader is gone
//! as it exits).
//!
//! What a pidfd knows of its task depends on where the task lives (see
//! [`fs::pidfd`](super::super::fs::pidfd)): a thread of the calling
//! process and a child of it are known exactly; any other process is seen
//! ending through a host watch, and is then gone, even while its parent
//! has not reaped it (only the parent's records know that zombie). Beyond
//! that, this implementation differs from the kernel where the host cannot
//! show what it shows:
//!
//! - `pidfd_getfd` reaches only the calling process's descriptors; another
//!   process's are refused with `EPERM`, as when `ptrace` access is denied.
//! - `PIDFD_GET_INFO` reports no cgroup ID (as a kernel without
//!   `CONFIG_CGROUPS`), the host's credentials and parent for a process
//!   that is not the caller (the caller's credentials for a zombie child),
//!   and exit information only for the tasks whose end this process
//!   recorded: its threads and the children it reaped.
//! - The namespace `ioctl`s find no namespaces (`EOPNOTSUPP`, as a kernel
//!   built without them).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::{O_NONBLOCK, O_RDWR};
use super::super::fs::anon::Anon;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::fs::pidfd::{PIDFD_THREAD, Target};
use super::super::host;
use super::super::process::ProcState;
use super::super::signal::{SigInfo, code, valid_signal};
use super::super::wait::Wait;
use super::ready::{Polled, ev};
use super::{Ctx, SysResult};

/// `pidfd_send_signal` scopes (`PIDFD_SIGNAL_*`).
mod scope {
    pub const THREAD: u32 = 1 << 0;
    pub const THREAD_GROUP: u32 = 1 << 1;
    pub const PROCESS_GROUP: u32 = 1 << 2;
    pub const ALL: u32 = THREAD | THREAD_GROUP | PROCESS_GROUP;
}

/// `PIDFD_SELF_THREAD`: the calling thread, without a descriptor.
pub const PIDFD_SELF_THREAD: i32 = -10000;
/// `PIDFD_SELF_THREAD_GROUP`: the calling process.
pub const PIDFD_SELF_THREAD_GROUP: i32 = -10001;

/// How often a task the host cannot watch is probed while a caller sleeps
/// on it.
const PROBE_INTERVAL: Duration = Duration::from_millis(10);

/// What a pidfd's task is now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Running (for a thread-group leader: while any thread of its group
    /// runs).
    Alive,
    /// Exited but not reaped, with its wait status.
    Zombie(i32),
    /// Reaped, with its wait status when known.
    Gone(Option<i32>),
}

/// The task `t` names, seen from process `p` whose thread IDs `own`
/// recognizes.
pub fn state_of(p: &ProcState, own: &dyn Fn(i32) -> bool, t: &Target) -> Task {
    if let Some(status) = t.ended() {
        return Task::Gone(status);
    }
    if t.tgid == p.pid {
        // A leader that exited before its group stays (delay_group_leader).
        if t.tid == t.tgid || own(t.tid) {
            return Task::Alive;
        }
        t.end(None);
        return Task::Gone(None);
    }
    if t.tid == t.tgid
        && let Some(ch) = p.children.list.iter().find(|ch| ch.pid == t.tgid)
    {
        return ch
            .zombie
            .map_or(Task::Alive, |(status, _)| Task::Zombie(status));
    }
    if t.exited() {
        t.end(None);
        return Task::Gone(None);
    }
    Task::Alive
}

/// The task `t` names, seen from the caller.
pub fn state(c: &Ctx<'_>, t: &Target) -> Task {
    state_of(c.p, &|tid| c.is_own_tid(tid), t)
}

/// The task a pidfd names; `None` for another file.
pub fn target_of(file: &OpenFile) -> Option<&Arc<Target>> {
    match &file.object {
        FileObject::Anon(Anon::Pid(t)) => Some(t),
        _ => None,
    }
}

/// `pidfs_alloc_file`: a pidfd for `target` with status flags `flags`
/// (`O_RDWR` is added).
fn pidfd_file(target: Arc<Target>, flags: u32) -> Arc<OpenFile> {
    OpenFile::new(
        FileObject::Anon(Anon::Pid(target)),
        FileType::Anon,
        "anon_inode:[pidfd]",
        None,
        O_RDWR | flags,
    )
}

/// `find_get_pid` and `pidfd_prepare`'s checks: the task `pid` names for
/// a pidfd (`thread`: `PIDFD_THREAD`). `ESRCH` when there is none (or it
/// was reaped), `ENOENT` for a thread other than a leader without
/// `thread`.
fn find(c: &Ctx<'_>, pid: i32, thread: bool) -> Result<Arc<Target>, Errno> {
    if pid == c.p.pid {
        return Target::new(pid, pid, false);
    }
    if c.is_own_tid(pid) {
        if !thread {
            return Err(Errno(ENOENT));
        }
        return Target::new(c.p.pid, pid, false);
    }
    if c.p.children.list.iter().any(|ch| ch.pid == pid) {
        return Target::new(pid, pid, false);
    }
    if !c.p.config.processes {
        return Err(Errno(ESRCH));
    }
    Target::new(pid, pid, true)
}

/// `pidfd_open`.
pub fn pidfd_open(c: &mut Ctx<'_>, pid: i32, flags: u32) -> SysResult {
    if flags & !(O_NONBLOCK | PIDFD_THREAD) != 0 {
        return Err(Errno(EINVAL));
    }
    if pid <= 0 {
        return Err(Errno(EINVAL));
    }
    let target = find(c, pid, flags & PIDFD_THREAD != 0)?;
    c.p.pidfds.add(&target);
    super::io::install(c, pidfd_file(target, flags), true)
}

/// `CLONE_PIDFD`, before the task exists: a descriptor must be free
/// (`get_unused_fd_flags`) and the result word at `addr` writable
/// (`put_user`), or the clone fails without a task.
pub fn clone_check(c: &Ctx<'_>, addr: u64) -> Result<(), Errno> {
    let limit = super::io::nofile(c);
    c.p.fds.free_fds(1, limit)?;
    c.p.space
        .probe(addr, 4, crate::error::MemoryAccessKind::Write)
        .map_err(|_| Errno(EFAULT))
}

/// `CLONE_PIDFD`, once the task exists: its pidfd (a thread's with
/// `PIDFD_THREAD`), installed close-on-exec, its number stored at `addr`.
pub fn clone_install(c: &mut Ctx<'_>, tgid: i32, tid: i32, addr: u64) -> Result<(), Errno> {
    let thread = tid != tgid;
    let target = Target::new(tgid, tid, false)?;
    c.p.pidfds.add(&target);
    let flags = if thread { PIDFD_THREAD } else { 0 };
    let fd = super::io::install(c, pidfd_file(target, flags), true)?;
    if let Err(e) = c.write_u32(addr, fd as u32) {
        let _ = c.p.fds.close(fd as i32);
        return Err(e);
    }
    Ok(())
}

/// `waitid(P_PIDFD, fd)` (`pidfd_get_pid`): the child the pidfd names
/// (`None` when it names no child: a thread, or a task that is gone) and
/// whether the pidfd is non-blocking (`WNOHANG`).
pub fn wait_target(c: &Ctx<'_>, fd: i32) -> Result<(Option<i32>, bool), Errno> {
    let file = c.p.fds.file(fd)?;
    let t = target_of(&file).ok_or(Errno(EBADF))?;
    let nonblock = file.flags() & O_NONBLOCK != 0;
    let child = (t.tid == t.tgid && t.ended().is_none()).then_some(t.tgid);
    Ok((child, nonblock))
}

/// `pidfd_poll`: `EPOLLIN | EPOLLRDNORM` once the task has exited, with
/// `EPOLLHUP` once it is gone; and what a sleeper waits on until then.
pub fn poll(c: &Ctx<'_>, t: &Target) -> (Polled, Wait) {
    let mut wait = Wait::event();
    let mask = match state(c, t) {
        Task::Alive => {
            // A thread's exit and a child's end wake sleepers directly;
            // another process's end comes through its host watch.
            if t.tgid != c.p.pid && !c.p.children.list.iter().any(|ch| ch.pid == t.tgid) {
                if let Some(fd) = t.watch_fd() {
                    wait.fds.push((fd, true, false));
                } else if t.probed() {
                    wait.deadline = Some(Instant::now() + PROBE_INTERVAL);
                }
            }
            0
        }
        Task::Zombie(_) => ev::IN | ev::RDNORM,
        Task::Gone(_) => ev::IN | ev::RDNORM | ev::HUP,
    };
    (Polled { mask, level: 0 }, wait)
}

/// The `Pid:` and `NSpid:` lines of a pidfd's `fdinfo`
/// (`pidfd_show_fdinfo`): the task's ID, `-1` once it is gone.
pub fn fdinfo(p: &ProcState, own: &dyn Fn(i32) -> bool, t: &Target) -> String {
    let nr = match state_of(p, own, t) {
        Task::Gone(_) => -1,
        _ => t.tid,
    };
    format!("Pid:\t{nr}\nNSpid:\t{nr}\n")
}

/// The target and signal scope of `pidfd_send_signal`'s descriptor: the
/// caller itself for `PIDFD_SELF_*`, a pidfd's task (a thread for a
/// `PIDFD_THREAD` pidfd), or the process whose `/proc/<pid>` directory the
/// descriptor is (`tgid_pidfd_to_pid`).
fn signal_target(c: &Ctx<'_>, pidfd: i32) -> Result<(Arc<Target>, Scope), Errno> {
    let me = c.p.pid;
    match pidfd {
        PIDFD_SELF_THREAD => return Ok((Target::new(me, c.t.tid, false)?, Scope::Thread)),
        PIDFD_SELF_THREAD_GROUP => return Ok((Target::new(me, me, false)?, Scope::Group)),
        _ => {}
    }
    let file = c.p.fds.file(pidfd)?;
    if let Some(t) = target_of(&file) {
        let scope = if file.flags() & PIDFD_THREAD != 0 {
            Scope::Thread
        } else {
            Scope::Group
        };
        return Ok((t.clone(), scope));
    }
    // A /proc/<pid> directory of this process names it.
    if file.ftype == FileType::Directory && matches!(file.object, FileObject::Synthetic(_)) {
        let name = file.path.trim_end_matches('/');
        let pid = match name.strip_prefix("/proc/") {
            Some("self") => Some(me),
            Some(n) => n.parse::<i32>().ok(),
            None => None,
        };
        if let Some(pid) = pid
            && (pid == me || c.is_own_tid(pid))
        {
            return Ok((Target::new(me, pid, false)?, Scope::Group));
        }
    }
    Err(Errno(EBADF))
}

/// `pidfd_send_signal`'s scope (`enum pid_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    /// `PIDTYPE_PID`.
    Thread,
    /// `PIDTYPE_TGID`.
    Group,
    /// `PIDTYPE_PGID`.
    ProcessGroup,
}

/// `pidfd_send_signal`.
pub fn pidfd_send_signal(
    c: &mut Ctx<'_>,
    pidfd: i32,
    sig: i32,
    uinfo: u64,
    flags: u32,
) -> SysResult {
    if flags & !scope::ALL != 0 || (flags & scope::ALL).count_ones() > 1 {
        return Err(Errno(EINVAL));
    }
    let (t, mut kind) = signal_target(c, pidfd)?;
    match flags {
        scope::THREAD => kind = Scope::Thread,
        scope::THREAD_GROUP => kind = Scope::Group,
        scope::PROCESS_GROUP => kind = Scope::ProcessGroup,
        _ => {}
    }
    let info = if uinfo != 0 {
        // copy_siginfo_from_user: the record as given, laid out by its own
        // signal number, which must be `sig`.
        let raw = c.read_mem(uinfo, 4)?;
        let signo = i32::from_le_bytes(raw.try_into().unwrap());
        let info = super::signal::read_user_siginfo(c, signo, uinfo)?;
        if signo != sig {
            return Err(Errno(EINVAL));
        }
        // Only the caller may be sent arbitrary records.
        let to_self = t.tgid == c.p.pid && t.tid == c.t.tid;
        if (!to_self || kind == Scope::ProcessGroup)
            && (info.code >= 0 || info.code == code::SI_TKILL)
        {
            return Err(Errno(EPERM));
        }
        info
    } else {
        let code = if kind == Scope::Thread {
            code::SI_TKILL
        } else {
            code::SI_USER
        };
        super::signal::kill_info(c, sig, code)
    };
    match kind {
        Scope::ProcessGroup => process_group(c, t.tid, sig, info),
        Scope::Group | Scope::Thread => task(c, &t, kind, sig, info),
    }
}

/// `kill_pid_info_type`: the task found by its own ID, the signal directed
/// at it (`Thread`) or at its thread group (`Group`). The calling
/// process's threads get `info` itself; a child that exited takes nothing;
/// another process is signaled through the host (as `kill` does), its
/// leader alone being nameable.
fn task(c: &mut Ctx<'_>, t: &Target, kind: Scope, sig: i32, info: SigInfo) -> SysResult {
    let checked = || {
        if !valid_signal(sig) && sig != 0 {
            Err(Errno(EINVAL))
        } else {
            Ok(0)
        }
    };
    match state(c, t) {
        Task::Gone(_) => Err(Errno(ESRCH)),
        Task::Zombie(_) => checked(),
        Task::Alive if t.tgid == c.p.pid => {
            if kind == Scope::Thread {
                return super::signal::send_specific(c, t.tgid, t.tid, sig, Some(info));
            }
            checked()?;
            if sig != 0 {
                super::signal::send_process(c, info, t.tid);
            }
            Ok(0)
        }
        Task::Alive => super::signal::other_process(c, t.tgid, sig),
    }
}

/// `kill_pgrp_info`: the process group `pgid` (the pidfd's task ID as a
/// group ID); `ESRCH` when it has no member.
fn process_group(c: &mut Ctx<'_>, pgid: i32, sig: i32, info: SigInfo) -> SysResult {
    if !c.p.config.processes {
        if pgid != c.p.pid {
            return Err(Errno(ESRCH));
        }
    } else if pgid != host::getpgid(0)? {
        return super::signal::other_process(c, -pgid, sig);
    }
    // The caller's own group: its other members through the host, the
    // caller with the record.
    if !valid_signal(sig) && sig != 0 {
        return Err(Errno(EINVAL));
    }
    if c.p.config.processes && (host::host_signal(sig).is_some() || sig == 0) {
        host::kill_group_but_self(pgid, sig)?;
    }
    if sig != 0 {
        let me = c.p.pid;
        super::signal::send_process(c, info, me);
    }
    Ok(0)
}

/// `pidfd_getfd`: a close-on-exec duplicate of descriptor `fd` of the
/// pidfd's process. Only the calling process's descriptors can be taken.
pub fn pidfd_getfd(c: &mut Ctx<'_>, pidfd: i32, fd: i32, flags: u32) -> SysResult {
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    let file = c.p.fds.file(pidfd)?;
    let t = target_of(&file).ok_or(Errno(EBADF))?.clone();
    match state(c, &t) {
        // A task that is gone, or exiting (its files released).
        Task::Gone(_) | Task::Zombie(_) => Err(Errno(ESRCH)),
        Task::Alive if t.tgid == c.p.pid => {
            let target = c.p.fds.file(fd)?;
            super::io::install(c, target, true)
        }
        Task::Alive => Err(Errno(EPERM)),
    }
}

/// pidfd `ioctl` requests (`linux/pidfd.h`, `linux/fs.h`).
mod req {
    /// `FS_IOC_GETVERSION`: `_IOR('v', 1, long)`.
    pub const FS_IOC_GETVERSION: u32 = 0x8008_7601;
    /// `PIDFD_GET_CGROUP_NAMESPACE` through `PIDFD_GET_UTS_NAMESPACE`:
    /// `_IO(0xFF, 1..=10)`.
    pub const NAMESPACES: std::ops::RangeInclusive<u32> = 0xff01..=0xff0a;
    /// `PIDFD_GET_INFO`: `_IOWR(0xFF, 11, struct pidfd_info)`.
    pub const GET_INFO: u32 = 0xc050_ff0b;
    /// `_IOC_SIZE`.
    pub fn size(r: u32) -> u32 {
        (r >> 16) & 0x3fff
    }
}

/// `PIDFD_INFO_SIZE_VER0`, the smallest `struct pidfd_info`.
const INFO_SIZE_VER0: u32 = 64;
/// `sizeof(struct pidfd_info)` (`PIDFD_INFO_SIZE_VER2`).
const INFO_SIZE: usize = 80;

/// `pidfd_ioctl` for the requests it knows (`pidfs_ioctl_valid`);
/// `ENOTTY` for others.
pub fn ioctl(c: &mut Ctx<'_>, t: &Target, r: u32, arg: u64) -> SysResult {
    // extensible_ioctl_valid: PIDFD_GET_INFO of any size from VER0 up.
    let info =
        r & !(0x3fff << 16) == req::GET_INFO & !(0x3fff << 16) && req::size(r) >= INFO_SIZE_VER0;
    if info {
        return pidfd_info(c, t, req::size(r) as usize, arg);
    }
    if r == req::FS_IOC_GETVERSION {
        if arg == 0 {
            return Err(Errno(EINVAL));
        }
        // The inode generation: 0 on 64-bit kernels (pidfs_gen).
        c.write_u32(arg, 0)?;
        return Ok(0);
    }
    if !req::NAMESPACES.contains(&r) {
        return Err(Errno(ENOTTY));
    }
    let st = state(c, t);
    if let Task::Gone(_) = st {
        return Err(Errno(ESRCH));
    }
    if arg != 0 {
        return Err(Errno(EINVAL));
    }
    // A zombie has released its namespaces (it is treated as gone).
    if let Task::Zombie(_) = st {
        return Err(Errno(ESRCH));
    }
    Err(Errno(EOPNOTSUPP))
}

/// `PIDFD_INFO_*` (`linux/pidfd.h`).
mod info {
    pub const PID: u64 = 1 << 0;
    pub const CREDS: u64 = 1 << 1;
    pub const EXIT: u64 = 1 << 3;
    pub const COREDUMP: u64 = 1 << 4;
    pub const SUPPORTED_MASK: u64 = 1 << 5;
    pub const COREDUMP_SIGNAL: u64 = 1 << 6;
    /// `PIDFD_INFO_SUPPORTED`: every flag this kernel knows, the cgroup
    /// ID's included.
    pub const SUPPORTED: u64 = 0x7f;
    /// `PIDFD_COREDUMPED`.
    pub const COREDUMPED: u32 = 1 << 0;
    /// `PIDFD_COREDUMP_SKIP`.
    pub const COREDUMP_SKIP: u32 = 1 << 1;
    /// `PIDFD_COREDUMP_USER`.
    pub const COREDUMP_USER: u32 = 1 << 2;
    /// `PIDFD_COREDUMP_ROOT`.
    pub const COREDUMP_ROOT: u32 = 1 << 3;
}

/// `struct pidfd_info`.
#[derive(Default)]
struct PidfdInfo {
    mask: u64,
    ids: [u32; 11],
    exit_code: i32,
    coredump_mask: u32,
    coredump_signal: u32,
    supported_mask: u64,
}

impl PidfdInfo {
    fn encode(&self) -> [u8; INFO_SIZE] {
        let mut b = [0u8; INFO_SIZE];
        b[..8].copy_from_slice(&self.mask.to_le_bytes());
        // cgroupid (bytes 8..16) stays zero.
        for (i, v) in self.ids.iter().enumerate() {
            b[16 + 4 * i..20 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        b[60..64].copy_from_slice(&self.exit_code.to_le_bytes());
        b[64..68].copy_from_slice(&self.coredump_mask.to_le_bytes());
        b[68..72].copy_from_slice(&self.coredump_signal.to_le_bytes());
        b[72..80].copy_from_slice(&self.supported_mask.to_le_bytes());
        b
    }
}

/// `pidfs_coredump_mask` for `PR_SET_DUMPABLE` value `dumpable`.
fn coredump_mask(dumpable: u64) -> u32 {
    match dumpable {
        1 => info::COREDUMP_USER,
        2 => info::COREDUMP_ROOT,
        _ => info::COREDUMP_SKIP,
    }
}

/// `pidfd_info` for a `usize`-byte structure at `arg`.
fn pidfd_info(c: &mut Ctx<'_>, t: &Target, usize: usize, arg: u64) -> SysResult {
    if arg == 0 {
        return Err(Errno(EINVAL));
    }
    let mask = c.read_u64(arg)?;
    let mut k = PidfdInfo::default();
    let st = state(c, t);
    let status = match st {
        Task::Zombie(s) | Task::Gone(Some(s)) => Some(s),
        _ => None,
    };
    // pidfs_exit: recorded when the task is reaped.
    if mask & info::EXIT != 0
        && let Task::Gone(Some(s)) = st
    {
        k.mask |= info::EXIT;
        k.exit_code = s;
    }
    // pidfs_coredump: recorded when the task dumps core.
    if mask & info::COREDUMP != 0
        && let Some(s) = status.filter(|s| s & 0x80 != 0)
    {
        k.mask |= info::COREDUMP | info::COREDUMP_SIGNAL;
        k.coredump_mask = info::COREDUMPED | info::COREDUMP_USER;
        k.coredump_signal = (s & 0x7f) as u32;
    }
    if let Task::Gone(_) = st {
        if mask & info::EXIT == 0 {
            return Err(Errno(ESRCH));
        }
    } else {
        let own = t.tgid == c.p.pid;
        // A running task has its memory, whose dumpability says how it
        // would dump core.
        if mask & info::COREDUMP != 0 && k.coredump_mask == 0 && st == Task::Alive {
            k.coredump_mask = coredump_mask(if own { c.p.dumpable } else { 1 });
            k.mask |= info::COREDUMP;
        }
        let (u, e, g, eg) = c.p.creds;
        let (ppid, uids, gids) = if own {
            (c.p.ppid, (u, e, e), (g, eg, eg))
        } else {
            match (host::proc_ids(t.tgid), st) {
                (Ok(ids), _) => (ids.ppid, ids.uids, ids.gids),
                // A zombie child: the host no longer has it.
                (Err(_), Task::Zombie(_)) => (c.p.pid, (u, e, e), (g, eg, eg)),
                (Err(_), _) => return Err(Errno(ESRCH)),
            }
        };
        let ppid = if matches!(st, Task::Zombie(_)) {
            c.p.pid
        } else {
            ppid
        };
        // pid, tgid, ppid, then the real, effective, saved, and file-system
        // user and group IDs (the file-system IDs are the effective ones).
        k.ids = [
            t.tid as u32,
            t.tgid as u32,
            ppid as u32,
            uids.0,
            gids.0,
            uids.1,
            gids.1,
            uids.2,
            gids.2,
            uids.1,
            gids.1,
        ];
        k.mask |= info::PID | info::CREDS;
    }
    if mask & info::SUPPORTED_MASK != 0 {
        k.mask |= info::SUPPORTED_MASK;
        k.supported_mask = info::SUPPORTED;
    }
    // copy_struct_to_user: a larger structure's tail is zeroed first.
    let bytes = k.encode();
    if usize > INFO_SIZE {
        c.write_mem(arg + INFO_SIZE as u64, &vec![0; usize - INFO_SIZE])?;
    }
    c.write_mem(arg, &bytes[..usize.min(INFO_SIZE)])?;
    Ok(0)
}

/// `vfs_statfs` of a pidfd's file system (`PID_FS_MAGIC`).
pub const PID_FS_MAGIC: u64 = 0x5049_4446;

/// The device of `pidfs` (an anonymous device, `0:6` in the reference
/// system).
pub const PIDFS_DEV_MINOR: u32 = 6;

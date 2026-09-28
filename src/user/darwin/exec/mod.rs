//! `execve` and `posix_spawn` (`bsd/kern/kern_exec.c`).
//!
//! Running a new image has two halves, separated by the point of no
//! return. Before it, everything is checked and prepared without
//! touching the caller: the image is activated ([`image`]: lookup,
//! permissions, the Mach-O, fat, and `#!` activators, binary
//! preferences), the arguments and environment are copied in ([`args`]),
//! and a spawn's file actions work on a copy of the descriptor table. An
//! error there is the call's error. After it, the new image is built —
//! a new address space, `dyld`, the initial stack, one thread — and a
//! failure kills the process with `SIGKILL`, as XNU's does when
//! `load_machfile` fails in an `execve` (a true spawn reports the error to
//! its parent instead, having touched nothing of it).
//!
//! The new image is a new [`Proc`] built while the old one still runs the
//! call; the scheduler swaps it in when the call returns ([`Swap`]). What
//! it keeps of the old process is XNU's (`proc_exec_switch_task`,
//! `execsigs`, `fdt_exec`, `ipc_task_init`, `proc_inherit_itimers`):
//!
//! - the pid, parent, credentials, working directory, file-creation
//!   mask, resource limits, children, start time, and interval timers;
//! - the descriptors, less those marked close-on-exec and every kqueue
//!   (`FG_CONFINED`);
//! - the calling thread's signal mask and pending signals (on the new
//!   image's only thread); caught signals return to their default action
//!   (and are discarded if that ignores them), ignored ones stay ignored,
//!   the alternate stack and the `sigreturn` validation policy are reset,
//!   and `SA_NOCLDSTOP`/`SA_NOCLDWAIT` are dropped (process flags a new
//!   process does not inherit);
//! - the bootstrap, host, and access special ports and the exception
//!   actions (a new task's inheritance); the guard-exception behavior is
//!   the default again.
//!
//! Everything else — the other threads, the address space, the port name
//! space, psynch and work-queue state, libpthread's registration — is
//! new. The audit token's pid version changes, as a new `proc` gets one.

pub mod args;
pub mod image;
pub mod spawn;

use std::collections::BTreeSet;
use std::os::fd::OwnedFd;

use super::abi::Errno;
use super::arch::SysResult;
use super::fd::{FdTable, FileKind};
use super::mach::task::TaskState;
use super::process::{self, Carried, ExitStatus, Proc, SpawnError, Thread};
use super::signal::{self, SIGCONT, SigActs};
use super::syscall::Ctx;
use image::{Activated, Binprefs, Dir};

/// A new image to run in place of the process once the current call
/// returns.
pub struct Swap {
    /// The new process image.
    pub proc: Proc,
    /// The working directory a spawn's file actions chose (a host
    /// descriptor the host's working directory moves to).
    pub chdir: Option<OwnedFd>,
    /// `POSIX_SPAWN_START_SUSPENDED`: the process stops before it runs.
    pub suspend: bool,
}

/// `execve(path, argv, envp)`.
pub fn execve(ctx: &mut Ctx<'_>, path: u64, argv: u64, envp: u64) -> SysResult {
    let act = image::activate(ctx, path, Dir::Cwd, &Binprefs::default())?;
    let strings = args::extract(ctx, &act.interp, &act.user_path, argv, envp)?;
    let fds = fdt_fork(&ctx.proc.fds, true);
    let carried = carry(ctx.proc, ctx.thread, fds, None);
    let built = build(ctx.proc, act, strings, carried);
    swap_or_kill(ctx, built, None, false)
}

/// Swaps the built image in when the call returns; past the point of no
/// return, a failure to build it kills the process.
fn swap_or_kill(
    ctx: &mut Ctx<'_>,
    built: Result<Proc, SpawnError>,
    chdir: Option<OwnedFd>,
    suspend: bool,
) -> SysResult {
    match built {
        Ok(mut proc) => {
            // The same host process: its host rights stay; the old image's
            // exported ports go with it.
            proc.bridge = std::mem::take(&mut ctx.proc.bridge);
            proc.bridge.exec();
            ctx.proc.exec = Some(Box::new(Swap {
                proc,
                chdir,
                suspend,
            }));
        }
        Err(e) => {
            if ctx.proc.config.strace {
                eprintln!("[{:#x}] exec failed after commit: {e}", ctx.thread.tid);
            }
            ctx.proc.exit_with(ExitStatus::Signaled {
                signo: signal::SIGKILL,
                core: false,
                pc: ctx.pc,
            });
        }
    }
    // The old image's registers are gone with it.
    Err(Errno::EJUSTRETURN)
}

/// Loads the activated image into a new process image carrying
/// `carried` (`load_machfile` onward).
fn build(
    old: &Proc,
    act: Activated,
    strings: args::Strings,
    carried: Carried,
) -> Result<Proc, SpawnError> {
    let mut config = old.config.clone();
    config.argv = strings.argv;
    config.envp = strings.envp;
    config.exec_path = act.image.path.clone();
    config.abi = Some(act.abi);
    config.inherited = None;
    process::start(config, act.image, Some(carried))
}

/// The errno a failure to build a spawned image reports.
fn build_errno(e: &SpawnError) -> Errno {
    match e {
        SpawnError::Io(_, io) => Errno::from_io(io),
        other => Errno(other.errno()),
    }
}

/// `fdt_fork`: the descriptor table a new process (`in_exec` false: a
/// fork, or a spawn's child) or image (`in_exec`: an exec, or a spawn that
/// sets it) starts from. Kqueues are never inherited (`FG_CONFINED`);
/// close-on-fork descriptors are not by a new process, whose descriptors
/// keep only their close-on-exec flag.
pub fn fdt_fork(fds: &FdTable, in_exec: bool) -> FdTable {
    let mut t = fds.clone();
    let dropped: Vec<i32> = t
        .iter()
        .filter(|(_, f)| matches!(f.file.kind, FileKind::Kqueue(_)) || (f.clofork && !in_exec))
        .map(|(fd, _)| fd)
        .collect();
    for fd in dropped {
        let _ = t.remove(fd);
    }
    t
}

/// `fdt_exec`: closes the close-on-exec descriptors; with
/// `POSIX_SPAWN_CLOEXEC_DEFAULT`, every descriptor not in `inherit`.
pub fn fdt_exec(fds: &mut FdTable, inherit: Option<&BTreeSet<i32>>) {
    let close: Vec<i32> = fds
        .iter()
        .filter(|(fd, f)| f.cloexec || inherit.is_some_and(|keep| !keep.contains(fd)))
        .map(|(fd, _)| fd)
        .collect();
    for fd in close {
        let _ = fds.remove(fd);
    }
}

/// `execsigs`: caught signals take their default action again (and join
/// the discarded set if it ignores them, `SIGCONT` excepted); the
/// alternate-stack set and the `sigreturn` policy are reset. The new
/// process does not inherit `P_NOCLDSTOP` or `P_NOCLDWAIT`.
pub fn execsigs(acts: &SigActs) -> SigActs {
    let mut a = acts.clone();
    for sig in 1..signal::NSIG {
        let b = signal::bit(sig);
        if a.catch & b == 0 {
            continue;
        }
        a.handler[sig as usize] = signal::SIG_DFL;
        a.tramp[sig as usize] = 0;
        if signal::props(sig) & signal::prop::IGNORE != 0 && sig != SIGCONT {
            a.ignore |= b;
        }
    }
    a.catch = 0;
    a.onstack = 0;
    a.validation = signal::Validation::Default;
    a.nocldstop = false;
    a.nocldwait = false;
    a.origin = Default::default();
    a
}

/// A new task's port state from its parent's (`ipc_task_init`): the
/// inherited special ports and exception actions, the default guard
/// behavior (`task_set_exc_guard_default`), and no image-info
/// registration or reclamation ring (the task does not inherit the old
/// address space).
pub fn exec_task(parent: &TaskState) -> TaskState {
    let mut t = super::fork::inherited_task(parent);
    let fresh = TaskState::default();
    t.exc_guard = fresh.exc_guard;
    t.dyld_info = fresh.dyld_info;
    t.dyld_final = fresh.dyld_final;
    t.reclaim = None;
    t
}

/// What the process carries into a new image when `thread` execs with
/// `fds` (already without kqueues and after any file actions) and, for
/// `POSIX_SPAWN_CLOEXEC_DEFAULT`, the descriptors to inherit.
pub fn carry(
    proc: &Proc,
    thread: &Thread,
    mut fds: FdTable,
    inherit: Option<&BTreeSet<i32>>,
) -> Carried {
    fdt_exec(&mut fds, inherit);
    let mut audit = proc.audit;
    // A new proc has a new pid version.
    audit[7] = audit[7].wrapping_add(1).max(1);
    Carried {
        pid: proc.pid,
        ppid: proc.ppid,
        creds: proc.creds,
        cwd: proc.cwd.clone(),
        umask: proc.umask,
        rlimits: proc.rlimits,
        fds,
        sigacts: execsigs(&proc.sigacts),
        mask: thread.sig.mask,
        pending: thread.sig.pending,
        itimers: proc.itimers,
        children: proc.children.clone(),
        task: exec_task(&proc.task),
        host_port: proc.host_port.clone(),
        started: proc.started,
        audit,
        entropy: proc.entropy.clone(),
        tid: proc.next_tid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::signal::{SIGCHLD, SIGURG, SIGUSR1, SIGUSR2, SigAction, bit, sa};

    #[test]
    fn execsigs_resets_caught_signals_and_keeps_ignored_ones() {
        let mut acts = SigActs::default();
        let handler = |h: u64, flags: u32| SigAction {
            handler: h,
            tramp: 0x1000,
            mask: 0,
            flags,
        };
        acts.set(SIGUSR1, &handler(0x4000, sa::ONSTACK | sa::SIGINFO));
        acts.set(SIGURG, &handler(0x4000, 0));
        acts.set(SIGUSR2, &handler(signal::SIG_IGN, 0));
        acts.set(SIGCHLD, &handler(0x4000, sa::NOCLDSTOP | sa::NOCLDWAIT));
        acts.validation = signal::Validation::Enabled;
        let a = execsigs(&acts);
        assert_eq!(a.handler[SIGUSR1 as usize], signal::SIG_DFL);
        assert_eq!(a.handler[SIGUSR2 as usize], signal::SIG_IGN);
        assert_eq!(a.catch, 0);
        // A caught signal whose default ignores it is discarded again.
        assert_ne!(a.ignore & bit(SIGURG), 0);
        assert_ne!(a.ignore & bit(SIGUSR2), 0);
        assert_eq!(a.ignore & bit(SIGUSR1), 0);
        assert_eq!(a.onstack, 0);
        // Not reset: the other flags.
        assert_ne!(a.siginfo & bit(SIGUSR1), 0);
        assert!(!a.nocldstop && !a.nocldwait);
        assert_eq!(a.validation, signal::Validation::Default);
    }

    fn devnull() -> super::super::fd::FileRef {
        let f = std::fs::File::open("/dev/null").unwrap();
        std::sync::Arc::new(super::super::fd::OpenFile::host(f.into(), 0, None))
    }

    #[test]
    fn fdt_exec_closes_close_on_exec_and_uninherited_descriptors() {
        let mut t = FdTable::new();
        for cloexec in [false, true, false, false] {
            t.install(devnull(), cloexec, 0, 256).unwrap();
        }
        let mut plain = t.clone();
        fdt_exec(&mut plain, None);
        assert_eq!(
            plain.iter().map(|(fd, _)| fd).collect::<Vec<_>>(),
            [0, 2, 3]
        );
        // CLOEXEC_DEFAULT: only the inherited ones, and never a
        // close-on-exec one.
        let keep: BTreeSet<i32> = [1, 3].into_iter().collect();
        fdt_exec(&mut t, Some(&keep));
        assert_eq!(t.iter().map(|(fd, _)| fd).collect::<Vec<_>>(), [3]);
    }

    #[test]
    fn fdt_fork_drops_kqueues_and_close_on_fork_descriptors_from_new_processes() {
        let mut t = FdTable::new();
        for (cloexec, clofork) in [(false, false), (true, false), (false, true), (true, true)] {
            t.install_with(devnull(), cloexec, clofork, 0, 256).unwrap();
        }
        let kqueue = std::sync::Arc::new(super::super::fd::OpenFile {
            kind: FileKind::Kqueue(1),
            path: None,
            flags: std::sync::Mutex::new(2),
        });
        t.install(kqueue, false, 0, 256).unwrap();
        let fds = |t: &FdTable| t.iter().map(|(fd, _)| fd).collect::<Vec<_>>();
        // A fork (or a spawn's child) keeps neither; an exec keeps the
        // close-on-fork ones, flags and all.
        assert_eq!(fds(&fdt_fork(&t, false)), [0, 1]);
        let exec = fdt_fork(&t, true);
        assert_eq!(fds(&exec), [0, 1, 2, 3]);
        assert!(exec.get(3).unwrap().clofork && exec.get(3).unwrap().cloexec);
    }
}

//! Descriptor uses outlive entered FIFO I/O and reserve a closing fileproc slot.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::user::darwin::abi::{Errno, tables::nr};
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{Fd, FileRef};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::Wait;

/// An entered operation's reference to one descriptor, independently of aliases.
#[derive(Clone, Debug)]
pub(crate) struct Use {
    pub(crate) fd: i32,
    pub(crate) file: FileRef,
    pub(crate) read: bool,
    /// The bounded vector copied at entry, rather than its mutable user array.
    pub(super) vectors: Option<Vec<(u64, u64)>>,
}

#[derive(Clone)]
struct Replacement {
    from: i32,
    file: FileRef,
    cloexec: bool,
    clofork: bool,
}

struct Closing {
    fd: i32,
    /// None while another closer owns the destination reservation.
    removed: Option<Fd>,
    replacement: Option<Replacement>,
}

/// At most one closing operation per entered thread; no worker host thread.
#[derive(Default)]
pub(crate) struct Closers(BTreeMap<u64, Closing>);

pub(super) fn read_file(ctx: &Ctx<'_>, fd: i32) -> Result<FileRef, Errno> {
    if let Some(entered) = &ctx.thread.file_io
        && entered.read
        && entered.fd == fd
    {
        return Ok(entered.file.clone());
    }
    ctx.proc.fds.file(fd)
}

#[cfg(unix)]
pub(super) fn parked_read(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: &FileRef,
    vectors: Option<Vec<(u64, u64)>>,
) {
    let Some(host) = file.host_fd() else { return };
    if ctx.thread.wait.is_none()
        || ctx.thread.file_io.is_some()
        || !crate::user::darwin::host::fstat(host)
            .is_ok_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFIFO)
        || crate::user::darwin::host::anonymous_pipe(host)
    {
        return;
    }
    ctx.thread.file_io = Some(Use {
        fd,
        file: file.clone(),
        read: true,
        vectors,
    });
    // The measured Rosetta FIFO READ entry exposes CF=1 while parked;
    // READ_NOCANCEL and vector entries preserve their incoming flags.
    if ctx.nr == i64::from(nr::READ)
        && let crate::user::darwin::arch::DarwinCpu::X86_64(cpu) = &mut ctx.thread.cpu
    {
        let flags = cpu.vcpu().user_rflags();
        cpu.vcpu_mut().set_user_rflags(flags | 1);
    }
}

fn used(proc: &Proc, fd: i32) -> bool {
    proc.threads
        .values()
        .any(|t| !t.exited && t.file_io.as_ref().is_some_and(|u| u.fd == fd))
}

fn dispose(proc: &mut Proc, fd: i32, old: Fd) {
    crate::user::darwin::kevent::fd_closed(proc, fd, Some(old.file));
}

fn reserve(proc: &mut Proc, fd: i32) -> Result<Fd, Errno> {
    let old = proc.fds.reserve(fd)?;
    super::pipe_drain::closed(proc, fd, &old.file);
    Ok(old)
}

fn install(proc: &mut Proc, fd: i32, replacement: &Replacement) {
    assert!(
        proc.fds
            .install_at(fd as usize, replacement.file.clone(), replacement.cloexec)
            .is_none()
    );
    proc.fds.get_mut(fd).expect("installed descriptor").clofork = replacement.clofork;
}

fn park(ctx: &mut Ctx<'_>, operation: Closing) -> SysResult {
    assert!(
        ctx.proc
            .closers
            .0
            .insert(ctx.thread.tid, operation)
            .is_none()
    );
    // A kernel fileproc drain is uninterruptible. Completion below wakes its
    // owner directly, including while a Mach suspension holds its user return.
    syscall::sleep(ctx, Wait::default())
}

pub(super) fn close(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    let removed = reserve(ctx.proc, fd)?;
    if !used(ctx.proc, fd) {
        ctx.proc.fds.release(fd);
        dispose(ctx.proc, fd, removed);
        return Ok(Rv::one(0));
    }
    park(
        ctx,
        Closing {
            fd,
            removed: Some(removed),
            replacement: None,
        },
    )
}

pub(super) fn replace(
    ctx: &mut Ctx<'_>,
    from: i32,
    to: i32,
    file: FileRef,
    cloexec: bool,
    clofork: bool,
) -> SysResult {
    let replacement = Replacement {
        from,
        file: file.clone(),
        cloexec,
        clofork,
    };
    let removed = if ctx.proc.fds.is_reserved(to) {
        None
    } else if ctx.proc.fds.get(to).is_ok() {
        Some(reserve(ctx.proc, to)?)
    } else {
        install(ctx.proc, to, &replacement);
        return Ok(Rv::one(to as u64));
    };
    if removed.is_some() && !used(ctx.proc, to) {
        ctx.proc.fds.release(to);
        dispose(ctx.proc, to, removed.expect("owned reservation"));
        install(ctx.proc, to, &replacement);
        return Ok(Rv::one(to as u64));
    }
    ctx.thread.file_io = Some(Use {
        fd: from,
        file,
        read: false,
        vectors: None,
    });
    park(
        ctx,
        Closing {
            fd: to,
            removed,
            replacement: Some(replacement),
        },
    )
}

/// Progress kernel-owned I/O and close barriers independently of user holds.
pub(crate) fn progress(proc: &mut Proc) {
    for thread in proc.threads.values_mut().filter(|thread| thread.exited) {
        thread.file_io = None;
    }
    #[cfg(unix)]
    {
        let mut reads: Vec<_> = proc
            .threads
            .values()
            .filter_map(|t| {
                let entered = t.file_io.as_ref()?;
                let pending = t.pending_unix?;
                let wait = t.wait.as_ref()?;
                if !entered.read || t.exited || pending.completed.is_some() {
                    return None;
                }
                let host = entered.file.host_fd()?;
                crate::user::darwin::wait::ready_now(&[(host, true, false)])[0]
                    .then_some((wait.seq, t.tid))
            })
            .collect();
        reads.sort_unstable();
        for (_, tid) in reads {
            let mut thread = proc.threads.remove(&tid).expect("listed FIFO reader");
            syscall::ready_file_io(proc, &mut thread);
            proc.threads.insert(tid, thread);
        }
    }
    loop {
        let mut changed = false;
        let tids: Vec<_> = proc.closers.0.keys().copied().collect();
        for tid in tids {
            let mut operation = proc.closers.0.remove(&tid).expect("listed closer");
            let alive = proc.threads.get(&tid).is_some_and(|t| !t.exited);
            if operation.removed.is_none() {
                if !alive {
                    changed = true;
                    continue;
                }
                if proc.fds.is_reserved(operation.fd) {
                    proc.closers.0.insert(tid, operation);
                    continue;
                }
                let source_valid = operation.replacement.as_ref().is_some_and(|replacement| {
                    proc.fds
                        .file(replacement.from)
                        .is_ok_and(|file| Arc::ptr_eq(&file, &replacement.file))
                });
                if !source_valid {
                    if let Some(thread) = proc.threads.get_mut(&tid) {
                        thread.file_io = None;
                        if thread.pending_unix.is_some() {
                            syscall::complete_unix(thread, Err(Errno::EBADF));
                        }
                    }
                    changed = true;
                    continue;
                }
                if proc.fds.get(operation.fd).is_ok() {
                    operation.removed =
                        Some(reserve(proc, operation.fd).expect("open destination"));
                }
            }
            if operation.removed.is_some() && used(proc, operation.fd) {
                proc.closers.0.insert(tid, operation);
                continue;
            }
            let result = if let Some(replacement) = &operation.replacement {
                // A source close can start while dup2 drains its destination.
                // Its reference keeps the object alive, but its closing slot
                // is no longer a valid source at installation time.
                let valid = alive
                    && proc
                        .fds
                        .file(replacement.from)
                        .is_ok_and(|file| Arc::ptr_eq(&file, &replacement.file));
                if valid {
                    Ok(Rv::one(operation.fd as u64))
                } else {
                    Err(Errno::EBADF)
                }
            } else {
                Ok(Rv::one(0))
            };
            if let Some(old) = operation.removed.take() {
                proc.fds.release(operation.fd);
                dispose(proc, operation.fd, old);
            }
            if result.is_ok()
                && alive
                && let Some(replacement) = &operation.replacement
            {
                install(proc, operation.fd, replacement);
            }
            if let Some(thread) = proc.threads.get_mut(&tid) {
                thread.file_io = None;
                if alive && thread.pending_unix.is_some() {
                    syscall::complete_unix(thread, result);
                }
            }
            changed = true;
        }
        if !changed {
            break;
        }
    }
}

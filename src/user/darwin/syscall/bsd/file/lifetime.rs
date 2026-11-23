//! Descriptor uses outlive entered FIFO I/O and reserve a closing fileproc slot.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::user::darwin::abi::{Errno, tables::nr};
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{Fd, FileRef};
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::{Wait, WaitKey};
use crate::user::darwin::workspace_locks::{self, Waiter};

/// An entered operation's reference to one descriptor, independently of aliases.
#[derive(Clone, Debug)]
pub(crate) struct Use {
    pub(crate) fd: i32,
    pub(crate) file: FileRef,
    pub(crate) read: bool,
    /// A parked write that already passed descriptor/guard authorization.
    pub(crate) write: bool,
    /// The bounded vector copied at entry, rather than its mutable user array.
    pub(super) vectors: Option<Vec<(u64, u64)>>,
    /// Bytes already accepted by a guest pipe during a blocking write.
    pub(super) pipe_written: usize,
    pub(super) workspace_lock: Option<Waiter>,
    /// Timed record locks retain their copied request and original deadline.
    #[cfg(unix)]
    pub(super) lock: Option<super::record_lock::Entered>,
    /// A native named-FIFO read, including its retained completion buffer.
    #[cfg(target_os = "macos")]
    pub(super) read_job: Option<Arc<super::fifo_read::Job>>,
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

pub(super) fn parked_pipe(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: &FileRef,
    read: bool,
    vectors: Vec<(u64, u64)>,
    written: usize,
) {
    if let Some(entered) = &mut ctx.thread.file_io {
        entered.pipe_written = written;
        return;
    }
    ctx.thread.file_io = Some(Use {
        fd,
        file: file.clone(),
        read,
        write: !read,
        vectors: Some(vectors),
        pipe_written: written,
        workspace_lock: None,
        #[cfg(unix)]
        lock: None,
        #[cfg(target_os = "macos")]
        read_job: None,
    });
    if read {
        super::pipe_drain::read_parked(ctx);
    }
}

pub(super) fn read_file(ctx: &Ctx<'_>, fd: i32) -> Result<FileRef, Errno> {
    if let Some(entered) = &ctx.thread.file_io
        && entered.read
        && entered.fd == fd
    {
        return Ok(entered.file.clone());
    }
    ctx.proc.fds.file(fd)
}

pub(in crate::user::darwin::syscall::bsd) fn entered_write(ctx: &Ctx<'_>, fd: i32) -> bool {
    ctx.thread
        .file_io
        .as_ref()
        .is_some_and(|entered| entered.write && entered.fd == fd)
}

pub(super) fn write_file(ctx: &Ctx<'_>, fd: i32) -> Result<FileRef, Errno> {
    if let Some(entered) = &ctx.thread.file_io
        && entered.write
        && entered.fd == fd
    {
        return Ok(entered.file.clone());
    }
    ctx.proc.fds.file(fd)
}

#[cfg(unix)]
pub(super) fn parked_write(
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
    {
        return;
    }
    ctx.thread.file_io = Some(Use {
        fd,
        file: file.clone(),
        read: false,
        write: true,
        vectors,
        pipe_written: 0,
        workspace_lock: None,
        #[cfg(unix)]
        lock: None,
        #[cfg(target_os = "macos")]
        read_job: None,
    });
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
        write: false,
        vectors,
        pipe_written: 0,
        workspace_lock: None,
        #[cfg(unix)]
        lock: None,
        #[cfg(target_os = "macos")]
        read_job: None,
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

pub(in crate::user::darwin) fn parked_workspace_lock(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: &FileRef,
    waiter: Waiter,
) {
    ctx.thread.file_io = Some(Use {
        fd,
        file: file.clone(),
        read: false,
        write: false,
        vectors: None,
        pipe_written: 0,
        workspace_lock: Some(waiter),
        #[cfg(unix)]
        lock: None,
        #[cfg(target_os = "macos")]
        read_job: None,
    });
}

pub(in crate::user::darwin) fn entered_workspace_open(
    thread: &Thread,
) -> Option<(i32, FileRef, Waiter, u32)> {
    let entered = thread.file_io.as_ref()?;
    let waiter = entered.workspace_lock?;
    Some((entered.fd, entered.file.clone(), waiter, waiter.open_flags?))
}

fn used(proc: &Proc, fd: i32) -> bool {
    proc.threads
        .values()
        .any(|t| !t.exited && t.file_io.as_ref().is_some_and(|u| u.fd == fd))
}

fn dispose(proc: &mut Proc, fd: i32, old: Fd) {
    if let Some(member) = &proc.family
        && let Some(ino) = workspace_locks::inode(&old.file)
    {
        member.workspace_locks(|locks| locks.close(ino, proc.pid));
    }
    crate::user::darwin::kevent::fd_closed(proc, fd, Some(old.file));
}

fn reserve(proc: &mut Proc, fd: i32) -> Result<Fd, Errno> {
    let old = proc.fds.reserve(fd)?;
    if !proc.config.host_services {
        proc.post(WaitKey::DescriptorClosed);
    }
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

/// The native fork boundary used by both fork and posix_spawn. Joined jobs
/// contain no native thread handle or held mutex in the child. A failed fork
/// still rearms the parent's unperformed reads.
#[cfg(unix)]
pub(crate) fn fork_host(proc: &mut Proc) -> Result<Option<i32>, Errno> {
    #[cfg(target_os = "macos")]
    for thread in proc.threads.values() {
        if let Some(job) = thread
            .file_io
            .as_ref()
            .and_then(|entry| entry.read_job.as_ref())
        {
            job.pause();
        }
    }
    let result = crate::user::darwin::signal::host::fork_host();
    #[cfg(target_os = "macos")]
    if !matches!(result, Ok(None)) {
        let failures: Vec<_> = proc
            .threads
            .iter()
            .filter_map(|(&tid, thread)| {
                let job = thread.file_io.as_ref()?.read_job.as_ref()?;
                job.resume().err().map(|error| (tid, Errno::from(error)))
            })
            .collect();
        for (tid, error) in failures {
            let thread = proc.threads.get_mut(&tid).expect("listed native reader");
            syscall::complete_unix(thread, Err(error));
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = proc;
    result
}

/// A finalized guest process retains inspectable CPU/memory state, but must
/// not leave native read workers running until its library handle is closed.
#[cfg(target_os = "macos")]
pub(crate) fn cancel_reads(proc: &mut Proc) {
    for thread in proc.threads.values_mut() {
        if let Some(entry) = &mut thread.file_io {
            entry.read_job = None;
        }
    }
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
    syscall::sleep(
        ctx,
        Wait {
            keys: vec![WaitKey::FileDrain],
            ..Wait::default()
        },
    )
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
        write: false,
        vectors: None,
        pipe_written: 0,
        workspace_lock: None,
        #[cfg(unix)]
        lock: None,
        #[cfg(target_os = "macos")]
        read_job: None,
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

pub(in crate::user::darwin) fn abandon_workspace_lock(proc: &mut Proc, thread: &mut Thread) {
    if let Some(entered) = &thread.file_io
        && let Some(waiter) = entered.workspace_lock
    {
        if waiter.open_flags.is_some() {
            proc.fds.release(entered.fd);
        }
        thread.file_io = None;
        workspace_locks::cancel_wait(proc, thread.tid);
    }
}

/// Progress kernel-owned I/O and close barriers independently of user holds.
pub(crate) fn progress(proc: &mut Proc) {
    for thread in proc.threads.values_mut().filter(|thread| thread.exited) {
        if let Some(entered) = thread.file_io.take()
            && let Some(waiter) = entered.workspace_lock
        {
            if waiter.open_flags.is_some() {
                proc.fds.release(entered.fd);
            }
            if let Some(member) = &proc.family {
                member.workspace_locks(|locks| locks.cancel(proc.pid, thread.tid));
            }
        }
    }
    let mut io: Vec<_> = proc
        .threads
        .values()
        .filter_map(|t| {
            let entered = t.file_io.as_ref()?;
            let pending = t.pending_unix?;
            let wait = t.wait.as_ref()?;
            if t.exited || pending.completed.is_some() {
                return None;
            }
            if entered.workspace_lock.is_some() {
                return t.woken.then_some((wait.seq, t.tid));
            }
            if entered.file.pipe_end().is_some() {
                return (t.woken && (entered.read || entered.write)).then_some((wait.seq, t.tid));
            }
            #[cfg(unix)]
            {
                if !entered.read && !entered.write && entered.lock.is_none() {
                    return None;
                }
                // A signal also releases entered I/O while a Mach hold
                // keeps the prepared return from reaching user space.
                if t.woken && wait.interruptible {
                    return Some((wait.seq, t.tid));
                }
                if entered.lock.is_some() {
                    return wait
                        .deadline
                        .is_some_and(|deadline| deadline <= crate::host::time::Instant::now())
                        .then_some((wait.seq, t.tid));
                }
                #[cfg(target_os = "macos")]
                if let Some(job) = &entered.read_job {
                    return job.ready().then_some((wait.seq, t.tid));
                }
                let host = entered.file.host_fd()?;
                crate::user::darwin::wait::ready_now(&[(host, entered.read, entered.write)])[0]
                    .then_some((wait.seq, t.tid))
            }
            #[cfg(not(unix))]
            None
        })
        .collect();
    io.sort_unstable();
    for (_, tid) in io {
        let mut thread = proc
            .threads
            .remove(&tid)
            .expect("listed entered file operation");
        syscall::ready_file_io(proc, &mut thread);
        proc.threads.insert(tid, thread);
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

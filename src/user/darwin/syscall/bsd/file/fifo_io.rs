//! Project native FIFO read completion into the entered guest BSD service.
#[cfg(target_os = "macos")]
use std::os::fd::BorrowedFd;
#[cfg(target_os = "macos")]
use std::sync::Arc;

#[cfg(target_os = "macos")]
use super::fifo_read::Job;
use super::lifetime;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::FileRef;
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::Wait;

pub(super) fn eligible(ctx: &Ctx<'_>, fd: i32, host: i32) -> bool {
    #[cfg(target_os = "macos")]
    if ctx
        .thread
        .file_io
        .as_ref()
        .is_some_and(|entry| entry.fd == fd && entry.read && entry.read_job.is_some())
    {
        return true;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (ctx, fd);
    !super::nonblocking(host)
        && crate::user::darwin::host::fstat(host)
            .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFIFO)
        && !crate::user::darwin::host::anonymous_pipe(host)
}

#[cfg(target_os = "macos")]
pub(super) fn read(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: &FileRef,
    targets: Vec<(u64, u64)>,
    vector: bool,
) -> SysResult {
    let job = ctx
        .thread
        .file_io
        .as_ref()
        .and_then(|entry| entry.read_job.as_ref())
        .cloned();
    let job = match job {
        Some(job) => job,
        None => {
            let host = file.host_fd().ok_or(Errno::EBADF)?;
            let capacity = super::vector_length(&targets)? as usize;
            // SAFETY: file keeps the descriptor live while Job duplicates it.
            let host = unsafe { BorrowedFd::borrow_raw(host) };
            Arc::new(Job::start(host, capacity).map_err(Errno::from)?)
        }
    };
    if let Some(result) = job.take() {
        return copy_result(ctx, &targets, result);
    }
    let sleeping = syscall::sleep(ctx, Wait::fds(vec![(job.fd(), true, false)], None));
    if syscall::interrupted(ctx, &sleeping) {
        job.interrupt();
        let result = job.take().expect("joined native read publishes its result");
        if result
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(libc::EINTR))
        {
            return sleeping;
        }
        // Native bytes or EOF can win the interruption race. Never discard
        // bytes that have already been consumed from the host FIFO.
        return copy_result(ctx, &targets, result);
    }
    lifetime::parked_read(ctx, fd, file, vector.then(|| targets.clone()));
    let entered = ctx
        .thread
        .file_io
        .as_mut()
        .expect("parked native FIFO read");
    debug_assert!(entered.read && entered.fd == fd);
    entered.read_job = Some(job);
    sleeping
}

#[cfg(target_os = "linux")]
pub(super) fn read(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: &FileRef,
    targets: Vec<(u64, u64)>,
    vector: bool,
) -> SysResult {
    let host = file.host_fd().ok_or(Errno::EBADF)?;
    let capacity = super::vector_length(&targets)? as usize;
    match super::fifo_linux::read(host, capacity) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            let sleeping = syscall::sleep(ctx, Wait::fds(vec![(host, true, false)], None));
            lifetime::parked_read(ctx, fd, file, vector.then_some(targets));
            sleeping
        }
        result => copy_result(ctx, &targets, result),
    }
}

fn copy_result(
    ctx: &Ctx<'_>,
    targets: &[(u64, u64)],
    result: std::io::Result<Vec<u8>>,
) -> SysResult {
    let bytes = result.map_err(Errno::from)?;
    let mut copied = 0;
    for &(base, length) in targets {
        let count = (length as usize).min(bytes.len() - copied);
        if count != 0 {
            ctx.write(base, &bytes[copied..copied + count])?;
            copied += count;
        }
        if copied == bytes.len() {
            break;
        }
    }
    Ok(Rv::one(copied as u64))
}

//! Guest-owned fileproc guards (`kern_guarded.c`), never native host guards.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::exception::{self, GuardAst};
use crate::user::darwin::fd::{DescriptorGuard, FileKind};
use crate::user::darwin::host::AT_FDCWD;
use crate::user::darwin::io;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::guard;

/// `GUARD_CLOSE`.
pub(crate) const CLOSE: u32 = 1;
/// `GUARD_DUP` (required for every guard).
pub(crate) const DUP: u32 = 2;
/// `GUARD_SOCKET_IPC`.
pub(crate) const SOCKET_IPC: u32 = 4;
/// `GUARD_FILEPORT`.
pub(crate) const FILEPORT: u32 = 8;
/// `GUARD_WRITE`.
pub(crate) const WRITE: u32 = 16;
const ALL: u32 = CLOSE | DUP | SOCKET_IPC | FILEPORT | WRITE;

/// File-descriptor exception flavors (`guard_fd_exception_codes`).
pub(crate) mod reason {
    pub(crate) const CLOSE: u32 = 1;
    pub(crate) const DUP: u32 = 2;
    pub(crate) const NOCLOEXEC: u32 = 4;
    pub(crate) const SOCKET_IPC: u32 = 8;
    pub(crate) const FILEPORT: u32 = 16;
    pub(crate) const WRITE: u32 = 64;
}

fn valid_attributes(attributes: u32) -> bool {
    attributes & DUP != 0 && attributes & !ALL == 0
}

fn supports_guard(kind: &FileKind) -> bool {
    match kind {
        #[cfg(unix)]
        FileKind::Shm(_) | FileKind::Sem(_) => false,
        _ => true,
    }
}

fn cookie(ctx: &Ctx<'_>, pointer: u64) -> Result<u64, Errno> {
    ctx.read_u64(pointer)
}

fn write_cookie(ctx: &mut Ctx<'_>, pointer: u64) -> Result<u64, Errno> {
    if let Some(cookie) = ctx.thread.pending_unix.and_then(|entry| entry.guard_cookie) {
        return Ok(cookie);
    }
    let cookie = cookie(ctx, pointer)?;
    if let Some(entry) = &mut ctx.thread.pending_unix {
        entry.guard_cookie = Some(cookie);
    }
    Ok(cookie)
}

fn new_guard(ctx: &Ctx<'_>, pointer: u64, attributes: u32) -> Result<DescriptorGuard, Errno> {
    if !valid_attributes(attributes) {
        return Err(Errno::EINVAL);
    }
    let cookie = cookie(ctx, pointer)?;
    if cookie == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(DescriptorGuard { cookie, attributes })
}

/// `fp_lookup_guarded`: a mismatch is EPERM without an exception.
pub(super) fn lookup(ctx: &Ctx<'_>, fd: i32, cookie: u64) -> Result<DescriptorGuard, Errno> {
    let guard = ctx.proc.fds.get(fd)?.guard.ok_or(Errno::EINVAL)?;
    if guard.cookie != cookie {
        return Err(Errno::EPERM);
    }
    Ok(guard)
}

/// `fp_guard_exception`: the guest handles the fatal exception on user return.
fn violation(ctx: &mut Ctx<'_>, fd: i32, descriptor: DescriptorGuard, reason: u32) -> Errno {
    exception::post_guard(
        &mut ctx.proc.guard_ast,
        GuardAst {
            code: guard::code(2, reason, fd as u32),
            subcode: descriptor.cookie,
            sticky: true,
        },
    );
    Errno::EPERM
}

/// Check an ordinary operation before any descriptor or host mutation.
pub(crate) fn check(ctx: &mut Ctx<'_>, fd: i32, attribute: u32, reason: u32) -> Result<(), Errno> {
    if let Some(descriptor) = ctx.proc.fds.get(fd)?.guard
        && descriptor.attributes & attribute != 0
    {
        return Err(violation(ctx, fd, descriptor, reason));
    }
    Ok(())
}

/// `preparefilewrite`: access permission precedes an ordinary write violation.
pub(super) fn check_write(ctx: &mut Ctx<'_>, fd: i32, supplied: Option<u64>) -> Result<(), Errno> {
    if super::file::lifetime::entered_write(ctx, fd) {
        return Ok(());
    }
    if let Some(cookie) = supplied {
        lookup(ctx, fd, cookie)?;
    }
    let file = ctx.proc.fds.file(fd)?;
    if *file.flags.lock().map_err(|_| Errno::EIO)? & io::O_ACCMODE == io::O_RDONLY {
        return Err(Errno::EBADF);
    }
    if supplied.is_none() {
        check(ctx, fd, WRITE, reason::WRITE)?;
    }
    Ok(())
}

fn install(ctx: &mut Ctx<'_>, result: SysResult, descriptor: DescriptorGuard) -> SysResult {
    let result = result?;
    ctx.proc.fds.get_mut(result.0 as i32)?.guard = Some(descriptor);
    Ok(result)
}

/// `guarded_open_np`: flags and attributes precede the guard and path copies.
pub(super) fn open(
    ctx: &mut Ctx<'_>,
    path: u64,
    pointer: u64,
    attributes: u32,
    flags: u32,
    mode: u32,
) -> SysResult {
    if flags & io::O_CLOEXEC == 0 {
        return Err(Errno::EINVAL);
    }
    let descriptor = new_guard(ctx, pointer, attributes)?;
    let result = super::path::openat(ctx, AT_FDCWD, path, flags | io::O_CLOFORK, mode & 0o777);
    install(ctx, result, descriptor)
}

/// `guarded_open_dprotected_np`, preserving the guarded variant's raw flags.
pub(super) fn open_dprotected(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let flags = a[3] as u32;
    if flags & io::O_CLOEXEC == 0 {
        return Err(Errno::EINVAL);
    }
    let descriptor = new_guard(ctx, a[1], a[2] as u32)?;
    // This guarded API selects the two raw-data flags and does not select
    // openat_authenticated_np's authentication operation.
    let result = super::path::openat_dprotected(
        ctx,
        AT_FDCWD,
        a[0],
        flags | io::O_CLOFORK,
        a[4] as i32,
        a[5] as i32 & 3,
        a[6] as u32 & 0o777,
        None,
    );
    install(ctx, result, descriptor)
}

/// `guarded_kqueue_np` uses the same guard validation and descriptor lifetime.
pub(super) fn kqueue(ctx: &mut Ctx<'_>, pointer: u64, attributes: u32) -> SysResult {
    let descriptor = new_guard(ctx, pointer, attributes)?;
    let result = crate::user::darwin::kevent::kqueue(ctx);
    install(ctx, result, descriptor)
}

/// Guarded close copies the cookie before descriptor lookup, then drains I/O.
pub(super) fn close(ctx: &mut Ctx<'_>, fd: i32, pointer: u64) -> SysResult {
    let cookie = cookie(ctx, pointer)?;
    super::file::close_with_guard(ctx, fd, Some(cookie))
}

/// Guarded scalar writes copy the cookie before the ordinary I/O validation.
pub(super) fn write(
    ctx: &mut Ctx<'_>,
    fd: i32,
    pointer: u64,
    buffer: u64,
    length: u64,
    offset: Option<i64>,
) -> SysResult {
    let cookie = write_cookie(ctx, pointer)?;
    super::file::write_with_guard(ctx, fd, buffer, length, offset, Some(cookie))
}

/// Guarded vector writes retain the iovec-copy-before-lookup order.
pub(super) fn writev(
    ctx: &mut Ctx<'_>,
    fd: i32,
    pointer: u64,
    vectors: u64,
    count: i32,
) -> SysResult {
    let cookie = write_cookie(ctx, pointer)?;
    super::file::writev_with_guard(ctx, fd, vectors, count, None, Some(cookie))
}

/// Atomically add, exchange, or remove a guard after all input copies.
pub(super) fn change(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let old_cookie = if a[1] == 0 { 0 } else { cookie(ctx, a[1])? };
    let new_cookie = if a[3] == 0 { 0 } else { cookie(ctx, a[3])? };
    let flags = if a[5] == 0 { 0 } else { ctx.read_u32(a[5])? };
    let fd = a[0] as i32;
    let slot = ctx.proc.fds.get(fd)?.clone();
    if a[5] != 0 {
        ctx.write_u32(
            a[5],
            u32::from(slot.cloexec) | (u32::from(slot.clofork) << 1),
        )?;
    }
    let old_attributes = a[2] as u32;
    let attributes = a[4] as u32;
    if slot.guard.is_some() {
        if a[1] == 0 || old_attributes == 0 {
            return Err(Errno::EINVAL);
        }
        if old_cookie == 0 {
            return Err(Errno::EPERM);
        }
    } else if a[1] != 0 || old_attributes != 0 {
        return Err(Errno::EINVAL);
    }
    if a[3] != 0 {
        if new_cookie == 0 || !valid_attributes(attributes) {
            return Err(Errno::EINVAL);
        }
        if let Some(old) = slot.guard {
            if old.cookie != old_cookie || old.attributes != old_attributes {
                return Err(Errno::EPERM);
            }
        } else if !supports_guard(&slot.file.kind) {
            return Err(Errno::ENOTSUP);
        }
        let next = ctx.proc.fds.get_mut(fd)?;
        if slot.guard.is_some_and(|g| g.attributes & CLOSE != 0) {
            next.clofork = false;
        }
        next.guard = Some(DescriptorGuard {
            cookie: new_cookie,
            attributes,
        });
        if attributes & CLOSE != 0 || flags & 2 != 0 {
            next.clofork = true;
        }
        next.cloexec = true;
    } else if let Some(old) = slot.guard {
        if attributes != 0 {
            return Err(Errno::EINVAL);
        }
        if old.cookie != old_cookie || old.attributes != old_attributes {
            return Err(Errno::EPERM);
        }
        let next = ctx.proc.fds.get_mut(fd)?;
        next.guard = None;
        next.cloexec = flags & 1 != 0;
        next.clofork = flags & 2 != 0;
    } else {
        return Err(Errno::EINVAL);
    }
    Ok(Rv::one(0))
}

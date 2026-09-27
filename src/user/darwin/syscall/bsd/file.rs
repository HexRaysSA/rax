//! Descriptor calls: I/O, duplication, control, status, and readiness.
//!
//! A call that would block the host (a read with no data, a write to a
//! full pipe, `select`/`poll` with nothing ready) parks the calling thread
//! on the descriptor's readiness instead, so other guest threads keep
//! running; when every thread sleeps the scheduler waits in the host's
//! `poll`. A descriptor in non-blocking mode fails with `EAGAIN` as the
//! host reports.

use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{FileRef, OpenFile};
use crate::user::darwin::host::{self, check, check_size};
use crate::user::darwin::io::{self, O_NONBLOCK, O_STATUS_FLAGS};
use crate::user::darwin::signal;
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::{self, Wait};

/// The largest single transfer (`read`/`write` fail larger `nbyte` with
/// `EINVAL`, as `rd_uio`/`wr_uio` do).
const IO_MAX: u64 = i32::MAX as u64;

/// Bytes moved per host call.
const CHUNK: usize = 1 << 20;

/// `UIO_MAXIOV`.
const UIO_MAXIOV: u64 = 1024;

fn host_fd(ctx: &Ctx<'_>, fd: i32) -> Result<(FileRef, i32), Errno> {
    let file = ctx.proc.fds.file(fd)?;
    let h = file.host_fd().ok_or(Errno::EBADF)?;
    Ok((file, h))
}

fn nonblocking(h: i32) -> bool {
    // SAFETY: F_GETFL on a live descriptor takes no pointers.
    let fl = unsafe { libc::fcntl(h, libc::F_GETFL) };
    fl >= 0 && fl & libc::O_NONBLOCK != 0
}

/// Parks the thread until `h` is ready (for reading or writing) when a
/// blocking-mode call would block; `None` when the call can proceed.
fn block_until_ready(ctx: &mut Ctx<'_>, h: i32, read: bool) -> Option<SysResult> {
    if wait::ready_now(&[(h, read, !read)])[0] || nonblocking(h) {
        return None;
    }
    Some(syscall::sleep(ctx, Wait::fds(vec![(h, read, !read)], None)))
}

/// `read(fd, cbuf, nbyte)` and `pread` (`offset` given).
pub fn read(ctx: &mut Ctx<'_>, fd: i32, buf: u64, nbyte: u64, offset: Option<i64>) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    if nbyte > IO_MAX {
        return Err(Errno::EINVAL);
    }
    if offset.is_none()
        && let Some(r) = block_until_ready(ctx, h, true)
    {
        return r;
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; (nbyte as usize).min(CHUNK)];
    while done < nbyte {
        let want = ((nbyte - done) as usize).min(CHUNK);
        // SAFETY: `chunk` holds at least `want` writable bytes.
        let n = unsafe {
            match offset {
                None => libc::read(h, chunk.as_mut_ptr().cast(), want),
                Some(o) => libc::pread(
                    h,
                    chunk.as_mut_ptr().cast(),
                    want,
                    (o + done as i64) as libc::off_t,
                ),
            }
        };
        if n < 0 {
            if done > 0 {
                break;
            }
            return Err(Errno::last());
        }
        let n = n as usize;
        ctx.write(buf + done, &chunk[..n])?;
        done += n as u64;
        if n < want {
            break;
        }
    }
    Ok(Rv::one(done))
}

/// `write(fd, cbuf, nbyte)` and `pwrite` (`offset` given).
pub fn write(ctx: &mut Ctx<'_>, fd: i32, buf: u64, nbyte: u64, offset: Option<i64>) -> SysResult {
    let r = write_file(ctx, fd, buf, nbyte, offset);
    sigpipe(ctx, fd, r)
}

/// `dofilewrite`'s `EPIPE` rule: a write to a broken pipe (not a socket,
/// whose layer has its own rule) sends `SIGPIPE` to the process unless the
/// descriptor has `F_SETNOSIGPIPE`.
fn sigpipe(ctx: &mut Ctx<'_>, fd: i32, r: SysResult) -> SysResult {
    if r == Err(Errno::EPIPE)
        && let Ok((_, h)) = host_fd(ctx, fd)
        && !is_socket(h)
        && !nosigpipe(h)
    {
        let own = signal::Origin::own(ctx.proc);
        signal::psignal(ctx.proc, Some(ctx.thread), signal::SIGPIPE, own);
    }
    r
}

fn is_socket(h: i32) -> bool {
    // SAFETY: `st` is written by fstat on success only.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat on a live descriptor with a valid stat buffer.
    unsafe { libc::fstat(h, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFSOCK }
}

/// Whether the descriptor's open file has `FG_NOSIGPIPE` (kept by the host
/// kernel on a Mac; other hosts have no such flag).
fn nosigpipe(h: i32) -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: F_GETNOSIGPIPE takes no argument.
        unsafe { libc::fcntl(h, cmd::F_GETNOSIGPIPE) > 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = h;
        false
    }
}

fn write_file(ctx: &mut Ctx<'_>, fd: i32, buf: u64, nbyte: u64, offset: Option<i64>) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    if nbyte > IO_MAX {
        return Err(Errno::EINVAL);
    }
    if offset.is_none()
        && nbyte > 0
        && let Some(r) = block_until_ready(ctx, h, false)
    {
        return r;
    }
    let mut done = 0u64;
    while done < nbyte {
        let want = ((nbyte - done) as usize).min(CHUNK);
        let data = match ctx.read(buf + done, want) {
            Ok(d) => d,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        // SAFETY: `data` holds `want` readable bytes.
        let n = unsafe {
            match offset {
                None => libc::write(h, data.as_ptr().cast(), want),
                Some(o) => libc::pwrite(
                    h,
                    data.as_ptr().cast(),
                    want,
                    (o + done as i64) as libc::off_t,
                ),
            }
        };
        if n < 0 {
            if done > 0 {
                break;
            }
            return Err(Errno::last());
        }
        done += n as u64;
        if (n as usize) < want {
            break;
        }
    }
    Ok(Rv::one(done))
}

/// Reads a guest iovec array: `(base, len)` pairs.
fn iovecs(ctx: &Ctx<'_>, iov: u64, cnt: i32) -> Result<Vec<(u64, u64)>, Errno> {
    if cnt < 0 || cnt as u64 > UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    let raw = ctx.read(iov, 16 * cnt as usize)?;
    let mut out = Vec::with_capacity(cnt as usize);
    let mut total = 0u64;
    for c in raw.chunks(16) {
        let base = u64::from_le_bytes(c[..8].try_into().expect("8 bytes"));
        let len = u64::from_le_bytes(c[8..].try_into().expect("8 bytes"));
        total = total.checked_add(len).ok_or(Errno::EINVAL)?;
        if total > IO_MAX {
            return Err(Errno::EINVAL);
        }
        out.push((base, len));
    }
    Ok(out)
}

/// `readv(fd, iov, cnt)` and `preadv`.
pub fn readv(ctx: &mut Ctx<'_>, fd: i32, iov: u64, cnt: i32, offset: Option<i64>) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    let v = iovecs(ctx, iov, cnt)?;
    let total: u64 = v.iter().map(|x| x.1).sum();
    if offset.is_none()
        && let Some(r) = block_until_ready(ctx, h, true)
    {
        return r;
    }
    let mut buf = vec![0u8; total as usize];
    // SAFETY: `buf` holds `total` writable bytes.
    let n = check_size(unsafe {
        match offset {
            None => libc::read(h, buf.as_mut_ptr().cast(), buf.len()),
            Some(o) => libc::pread(h, buf.as_mut_ptr().cast(), buf.len(), o as libc::off_t),
        }
    })?;
    let mut off = 0usize;
    for (base, len) in v {
        if off >= n {
            break;
        }
        let k = (len as usize).min(n - off);
        ctx.write(base, &buf[off..off + k])?;
        off += k;
    }
    Ok(Rv::one(n as u64))
}

/// `writev(fd, iov, cnt)` and `pwritev`.
pub fn writev(ctx: &mut Ctx<'_>, fd: i32, iov: u64, cnt: i32, offset: Option<i64>) -> SysResult {
    let r = writev_file(ctx, fd, iov, cnt, offset);
    sigpipe(ctx, fd, r)
}

fn writev_file(ctx: &mut Ctx<'_>, fd: i32, iov: u64, cnt: i32, offset: Option<i64>) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    let v = iovecs(ctx, iov, cnt)?;
    let mut buf = Vec::new();
    for (base, len) in v {
        buf.extend_from_slice(&ctx.read(base, len as usize)?);
    }
    if offset.is_none()
        && !buf.is_empty()
        && let Some(r) = block_until_ready(ctx, h, false)
    {
        return r;
    }
    // SAFETY: `buf` holds `buf.len()` readable bytes.
    let n = check_size(unsafe {
        match offset {
            None => libc::write(h, buf.as_ptr().cast(), buf.len()),
            Some(o) => libc::pwrite(h, buf.as_ptr().cast(), buf.len(), o as libc::off_t),
        }
    })?;
    Ok(Rv::one(n as u64))
}

/// `lseek(fd, offset, whence)`.
pub fn lseek(ctx: &mut Ctx<'_>, fd: i32, offset: i64, whence: i32) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    // Darwin SEEK_HOLE and SEEK_DATA are 3 and 4.
    let hw = match whence {
        0..=2 => whence,
        3 => host_seek_hole(),
        4 => host_seek_data(),
        _ => return Err(Errno::EINVAL),
    };
    // SAFETY: lseek on a live descriptor takes no pointers.
    let r = unsafe { libc::lseek(h, offset as libc::off_t, hw) };
    if r < 0 {
        return Err(Errno::last());
    }
    Ok(Rv::one(r as u64))
}

#[cfg(target_os = "macos")]
fn host_seek_hole() -> i32 {
    3
}
#[cfg(target_os = "macos")]
fn host_seek_data() -> i32 {
    4
}
#[cfg(not(target_os = "macos"))]
fn host_seek_hole() -> i32 {
    libc::SEEK_HOLE
}
#[cfg(not(target_os = "macos"))]
fn host_seek_data() -> i32 {
    libc::SEEK_DATA
}

/// `close(fd)`.
pub fn close(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    ctx.proc.fds.remove(fd)?;
    Ok(Rv::one(0))
}

/// `dup(fd)`.
pub fn dup(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = ctx.proc.fds.file(fd)?;
    let limit = ctx.proc.rlimits[8].0;
    let n = ctx.proc.fds.install(file, false, 0, limit)?;
    Ok(Rv::one(n as u64))
}

/// `dup2(from, to)`.
pub fn dup2(ctx: &mut Ctx<'_>, from: i32, to: i32) -> SysResult {
    let file = ctx.proc.fds.file(from)?;
    let limit = ctx.proc.rlimits[8].0;
    if to < 0 || to as u64 >= limit {
        return Err(Errno::EBADF);
    }
    if from == to {
        return Ok(Rv::one(to as u64));
    }
    ctx.proc.fds.install_at(to as usize, file, false);
    Ok(Rv::one(to as u64))
}

/// `pipe()`: the read and write ends in the two result words.
pub fn pipe(ctx: &mut Ctx<'_>) -> SysResult {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` has room for the two descriptors.
    check(unsafe { libc::pipe(fds.as_mut_ptr()) })?;
    for f in fds {
        // SAFETY: setting close-on-exec on the new descriptors.
        unsafe { libc::fcntl(f, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    // SAFETY: both descriptors were just created and are owned here.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let limit = ctx.proc.rlimits[8].0;
    let rfd = ctx.proc.fds.install(
        Arc::new(OpenFile::host(r, io::O_RDONLY, None)),
        false,
        0,
        limit,
    )?;
    let wfd = match ctx.proc.fds.install(
        Arc::new(OpenFile::host(w, io::O_WRONLY, None)),
        false,
        0,
        limit,
    ) {
        Ok(n) => n,
        Err(e) => {
            let _ = ctx.proc.fds.remove(rfd);
            return Err(e);
        }
    };
    Ok(Rv(rfd as u64, wfd as u64))
}

/// `fstat64(fd, buf)`.
pub fn fstat64(ctx: &mut Ctx<'_>, fd: i32, buf: u64) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    let st = host::fstat(h)?;
    super::path::put_stat(ctx, buf, &st)
}

/// `fsync(fd)`, `fdatasync(fd)`.
pub fn fsync(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    // SAFETY: fsync on a live descriptor.
    check(unsafe { libc::fsync(h) })?;
    Ok(Rv::one(0))
}

/// `ftruncate(fd, length)`.
pub fn ftruncate(ctx: &mut Ctx<'_>, fd: i32, length: i64) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    // SAFETY: ftruncate on a live descriptor.
    check(unsafe { libc::ftruncate(h, length as libc::off_t) })?;
    Ok(Rv::one(0))
}

/// `flock(fd, how)`.
pub fn flock(ctx: &mut Ctx<'_>, fd: i32, how: i32) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    // SAFETY: flock on a live descriptor.
    check(unsafe { libc::flock(h, how) })?;
    Ok(Rv::one(0))
}

/// `fchmod(fd, mode)`.
pub fn fchmod(ctx: &mut Ctx<'_>, fd: i32, mode: u32) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    // SAFETY: fchmod on a live descriptor.
    check(unsafe { libc::fchmod(h, mode as libc::mode_t) })?;
    Ok(Rv::one(0))
}

/// `fchown(fd, uid, gid)`.
pub fn fchown(ctx: &mut Ctx<'_>, fd: i32, uid: u32, gid: u32) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    // SAFETY: fchown on a live descriptor.
    check(unsafe { libc::fchown(h, uid, gid) })?;
    Ok(Rv::one(0))
}

/// `futimes(fd, times)`.
pub fn futimes(ctx: &mut Ctx<'_>, fd: i32, times: u64) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    let tv = super::path::read_timevals(ctx, times)?;
    let ptr = tv.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
    // SAFETY: `ptr` is null or two timevals; `h` is live.
    check(unsafe { libc::futimes(h, ptr) })?;
    Ok(Rv::one(0))
}

/// `fpathconf(fd, name)`.
pub fn fpathconf(ctx: &mut Ctx<'_>, fd: i32, name: i32) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    host::set_errno(0);
    // SAFETY: fpathconf on a live descriptor.
    let r = unsafe { libc::fpathconf(h, name) };
    if r < 0 {
        let e = Errno::last();
        if e.0 != 0 {
            return Err(e);
        }
    }
    Ok(Rv::one(r as u64))
}

/// `fcntl` commands.
pub mod cmd {
    pub const F_DUPFD: i32 = 0;
    pub const F_GETFD: i32 = 1;
    pub const F_SETFD: i32 = 2;
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    pub const F_GETOWN: i32 = 5;
    pub const F_SETOWN: i32 = 6;
    pub const F_GETLK: i32 = 7;
    pub const F_SETLK: i32 = 8;
    pub const F_SETLKW: i32 = 9;
    pub const F_FLUSH_DATA: i32 = 40;
    pub const F_PREALLOCATE: i32 = 42;
    pub const F_SETSIZE: i32 = 43;
    pub const F_RDADVISE: i32 = 44;
    pub const F_RDAHEAD: i32 = 45;
    pub const F_NOCACHE: i32 = 48;
    pub const F_GETPATH: i32 = 50;
    pub const F_FULLFSYNC: i32 = 51;
    pub const F_ADDSIGS: i32 = 59;
    pub const F_ADDFILESIGS: i32 = 61;
    pub const F_GETPROTECTIONCLASS: i32 = 63;
    pub const F_DUPFD_CLOEXEC: i32 = 67;
    pub const F_SETNOSIGPIPE: i32 = 73;
    pub const F_GETNOSIGPIPE: i32 = 74;
    pub const F_ADDFILESIGS_FOR_DYLD_SIM: i32 = 83;
    pub const F_BARRIERFSYNC: i32 = 85;
    pub const F_OFD_SETLK: i32 = 90;
    pub const F_OFD_SETLKW: i32 = 91;
    pub const F_OFD_GETLK: i32 = 92;
    pub const F_ADDFILESIGS_RETURN: i32 = 97;
    pub const F_CHECK_LV: i32 = 98;
    pub const F_SPECULATIVE_READ: i32 = 101;
    pub const F_GETPATH_NOFIRMLINK: i32 = 102;
}

/// `FD_CLOEXEC`.
const FD_CLOEXEC: u64 = 1;

/// `fcntl(fd, cmd, arg)`.
pub fn fcntl(ctx: &mut Ctx<'_>, fd: i32, c: i32, arg: u64) -> SysResult {
    use cmd::*;
    let file = ctx.proc.fds.file(fd)?;
    let limit = ctx.proc.rlimits[8].0;
    match c {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let min = arg as i32;
            if min < 0 || min as u64 >= limit {
                return Err(Errno::EINVAL);
            }
            let n = ctx
                .proc
                .fds
                .install(file, c == F_DUPFD_CLOEXEC, min as usize, limit)?;
            return Ok(Rv::one(n as u64));
        }
        F_GETFD => {
            let cl = ctx.proc.fds.get(fd)?.cloexec;
            return Ok(Rv::one(if cl { FD_CLOEXEC } else { 0 }));
        }
        F_SETFD => {
            ctx.proc.fds.get_mut(fd)?.cloexec = arg & FD_CLOEXEC != 0;
            return Ok(Rv::one(0));
        }
        _ => {}
    }
    let h = file.host_fd().ok_or(Errno::EBADF)?;
    match c {
        F_GETFL => {
            // SAFETY: F_GETFL takes no pointer.
            let fl = check(unsafe { libc::fcntl(h, libc::F_GETFL) })?;
            let access = *file.flags.lock().unwrap() & io::O_ACCMODE;
            Ok(Rv::one(u64::from(
                (io::host_to_guest_oflags(fl) & !io::O_ACCMODE) | access,
            )))
        }
        F_SETFL => {
            let want = arg as u32 & O_STATUS_FLAGS;
            // SAFETY: F_GETFL/F_SETFL take no pointers.
            let cur = check(unsafe { libc::fcntl(h, libc::F_GETFL) })?;
            let keep = cur & !io::guest_to_host_oflags(O_STATUS_FLAGS & !io::O_ACCMODE);
            check(unsafe { libc::fcntl(h, libc::F_SETFL, keep | io::guest_to_host_oflags(want)) })?;
            let mut fl = file.flags.lock().unwrap();
            *fl = (*fl & !O_STATUS_FLAGS) | want;
            Ok(Rv::one(0))
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            flock_cmd(ctx, h, c, arg)
        }
        #[cfg(target_os = "macos")]
        F_GETPATH | F_GETPATH_NOFIRMLINK => {
            let mut buf = vec![0u8; super::super::util::MAXPATHLEN];
            // SAFETY: `buf` holds MAXPATHLEN bytes as F_GETPATH requires.
            check(unsafe { libc::fcntl(h, c, buf.as_mut_ptr()) })?;
            ctx.write(arg, &buf)?;
            Ok(Rv::one(0))
        }
        F_NOCACHE | F_RDAHEAD | F_FULLFSYNC | F_BARRIERFSYNC | F_SETNOSIGPIPE | F_GETNOSIGPIPE
        | F_GETPROTECTIONCLASS | F_FLUSH_DATA => {
            #[cfg(target_os = "macos")]
            {
                // SAFETY: these commands take an int argument or none.
                let r = check(unsafe { libc::fcntl(h, c, arg as libc::c_int) })?;
                Ok(Rv::one(r as u64))
            }
            #[cfg(not(target_os = "macos"))]
            {
                match c {
                    F_FULLFSYNC | F_BARRIERFSYNC => {
                        // SAFETY: fsync on a live descriptor.
                        check(unsafe { libc::fsync(h) })?;
                        Ok(Rv::one(0))
                    }
                    _ => Ok(Rv::one(0)),
                }
            }
        }
        F_RDADVISE | F_SPECULATIVE_READ | F_PREALLOCATE => {
            // Advisory: validate the argument's readability.
            let len = match c {
                F_RDADVISE => 16,
                F_SPECULATIVE_READ => 24,
                _ => 32,
            };
            let raw = ctx.read(arg, len)?;
            if c == F_PREALLOCATE {
                #[cfg(target_os = "macos")]
                {
                    let mut st = raw.clone();
                    // SAFETY: `st` is a 32-byte fstore_t the call updates.
                    check(unsafe { libc::fcntl(h, c, st.as_mut_ptr()) })?;
                    ctx.write(arg, &st)?;
                }
                #[cfg(not(target_os = "macos"))]
                let _ = raw;
            }
            Ok(Rv::one(0))
        }
        F_ADDFILESIGS | F_ADDFILESIGS_RETURN | F_ADDFILESIGS_FOR_DYLD_SIM => {
            addfilesigs(ctx, h, c, arg)
        }
        // Library validation admits every image.
        F_CHECK_LV => {
            ctx.read(arg, 24)?;
            Ok(Rv::one(0))
        }
        F_GETOWN | F_SETOWN => {
            // SAFETY: int argument or none.
            let r = check(unsafe { libc::fcntl(h, c, arg as libc::c_int) })?;
            Ok(Rv::one(r as u64))
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `F_GETLK`/`F_SETLK`/`F_SETLKW` (and the OFD forms): `struct flock`
/// is `l_start`, `l_len`, `l_pid`, `l_type`, `l_whence` (24 bytes).
fn flock_cmd(ctx: &mut Ctx<'_>, h: i32, c: i32, arg: u64) -> SysResult {
    let raw = ctx.read(arg, 24)?;
    // SAFETY: an all-zero flock is valid; every field is set below.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_start = i64::from_le_bytes(raw[0..8].try_into().expect("8 bytes")) as libc::off_t;
    fl.l_len = i64::from_le_bytes(raw[8..16].try_into().expect("8 bytes")) as libc::off_t;
    fl.l_pid = i32::from_le_bytes(raw[16..20].try_into().expect("4 bytes"));
    let ltype = i16::from_le_bytes([raw[20], raw[21]]);
    fl.l_type = match ltype {
        1 => libc::F_RDLCK as _,
        2 => libc::F_UNLCK as _,
        3 => libc::F_WRLCK as _,
        _ => return Err(Errno::EINVAL),
    };
    fl.l_whence = i16::from_le_bytes([raw[22], raw[23]]) as _;
    #[cfg(target_os = "macos")]
    let hc = c;
    #[cfg(not(target_os = "macos"))]
    let hc = match c {
        cmd::F_GETLK => libc::F_GETLK,
        cmd::F_SETLK => libc::F_SETLK,
        cmd::F_SETLKW => libc::F_SETLKW,
        cmd::F_OFD_GETLK => libc::F_OFD_GETLK,
        cmd::F_OFD_SETLK => libc::F_OFD_SETLK,
        _ => libc::F_OFD_SETLKW,
    };
    // SAFETY: `fl` is a live flock for the call.
    check(unsafe { libc::fcntl(h, hc, &mut fl) })?;
    if c == cmd::F_GETLK || c == cmd::F_OFD_GETLK {
        let mut out = [0u8; 24];
        out[0..8].copy_from_slice(&(fl.l_start as i64).to_le_bytes());
        out[8..16].copy_from_slice(&(fl.l_len as i64).to_le_bytes());
        out[16..20].copy_from_slice(&(fl.l_pid as i32).to_le_bytes());
        let t: i16 = match fl.l_type as i32 {
            x if x == libc::F_RDLCK as i32 => 1,
            x if x == libc::F_WRLCK as i32 => 3,
            _ => 2,
        };
        out[20..22].copy_from_slice(&t.to_le_bytes());
        out[22..24].copy_from_slice(&(fl.l_whence as i16).to_le_bytes());
        ctx.write(arg, &out)?;
    }
    Ok(Rv::one(0))
}

/// `F_ADDFILESIGS*`: registers the code signature at `fs_blob_start`
/// (an offset into the file, relative to `fs_file_start`). On a macOS host
/// the host kernel registers it for the file and reports the signed
/// range's end, which `F_ADDFILESIGS_RETURN` copies out.
fn addfilesigs(ctx: &mut Ctx<'_>, h: i32, c: i32, arg: u64) -> SysResult {
    let raw = ctx.read(arg, 32)?;
    #[cfg(target_os = "macos")]
    {
        let mut fs = raw.clone();
        // SAFETY: `fs` is a 32-byte fsignatures_t whose fs_blob_start is a
        // file offset for these commands, not a pointer; the kernel copies
        // back at most the first 8 bytes.
        check(unsafe { libc::fcntl(h, c, fs.as_mut_ptr()) })?;
        if c == cmd::F_ADDFILESIGS_RETURN {
            ctx.write(arg, &fs[..8])?;
        }
        Ok(Rv::one(0))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (h, c, raw);
        Err(Errno::ENOTSUP)
    }
}

/// `ioctl` direction bits.
const IOC_VOID: u32 = 0x2000_0000;
const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;
/// `FIOCLEX`, `FIONCLEX`.
const FIOCLEX: u32 = 0x2000_6601;
const FIONCLEX: u32 = 0x2000_6602;

/// `ioctl(fd, request, arg)`: the request encodes the argument's size and
/// direction, so the argument is copied in and out around the host's call.
pub fn ioctl(ctx: &mut Ctx<'_>, fd: i32, request: u64, arg: u64) -> SysResult {
    let req = request as u32;
    match req {
        FIOCLEX | FIONCLEX => {
            ctx.proc.fds.get_mut(fd)?.cloexec = req == FIOCLEX;
            return Ok(Rv::one(0));
        }
        _ => {}
    }
    let (_, h) = host_fd(ctx, fd)?;
    let size = ((req >> 16) & 0x1fff) as usize;
    let dir = req & (IOC_VOID | IOC_OUT | IOC_IN);
    #[cfg(target_os = "macos")]
    {
        if dir == IOC_VOID || size == 0 {
            // SAFETY: a void request takes an int argument or none.
            let r = check(unsafe { libc::ioctl(h, req as libc::c_ulong, arg as libc::c_int) })?;
            return Ok(Rv::one(r as u64));
        }
        let mut buf = if dir & IOC_IN != 0 {
            ctx.read(arg, size)?
        } else {
            vec![0u8; size]
        };
        // SAFETY: `buf` holds the `size` bytes the request encodes.
        let r = check(unsafe { libc::ioctl(h, req as libc::c_ulong, buf.as_mut_ptr()) })?;
        if dir & IOC_OUT != 0 {
            ctx.write(arg, &buf)?;
        }
        Ok(Rv::one(r as u64))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (h, size, dir, arg);
        Err(Errno::ENOTTY)
    }
}

/// `getdirentries64(fd, buf, bufsize, position)`: Darwin `struct
/// direntry` records, copied from the host's.
pub fn getdirentries64(ctx: &mut Ctx<'_>, fd: i32, buf: u64, size: u64, pos: u64) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    #[cfg(target_os = "macos")]
    {
        let mut out = vec![0u8; (size as usize).min(1 << 20)];
        let mut base: i64 = 0;
        // SAFETY: syscall 344 (getdirentries64) writes at most `out.len()`
        // bytes and one off_t.
        #[allow(deprecated)]
        let n =
            unsafe { libc::syscall(344, h, out.as_mut_ptr(), out.len(), &mut base as *mut i64) };
        let n = check_size(n as isize)?;
        ctx.write(buf, &out[..n])?;
        if pos != 0 {
            ctx.write(pos, &base.to_le_bytes())?;
        }
        Ok(Rv::one(n as u64))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (h, buf, size, pos);
        Err(Errno::ENOSYS)
    }
}

/// `poll(fds, nfds, timeout)`.
pub fn poll(ctx: &mut Ctx<'_>, fds: u64, nfds: u32, timeout: i32) -> SysResult {
    if u64::from(nfds) > ctx.proc.rlimits[8].0.max(256) {
        return Err(Errno::EINVAL);
    }
    let raw = ctx.read(fds, 8 * nfds as usize)?;
    let mut entries = Vec::with_capacity(nfds as usize);
    for c in raw.chunks(8) {
        let fd = i32::from_le_bytes(c[..4].try_into().expect("4 bytes"));
        let events = i16::from_le_bytes([c[4], c[5]]);
        entries.push((fd, events));
    }
    let mut pfds: Vec<libc::pollfd> = entries
        .iter()
        .map(|&(fd, ev)| {
            let h = ctx
                .proc
                .fds
                .file(fd)
                .ok()
                .and_then(|f| f.host_fd())
                .unwrap_or(if fd < 0 { -1 } else { i32::MAX });
            libc::pollfd {
                fd: h,
                events: ev,
                revents: 0,
            }
        })
        .collect();
    // SAFETY: `pfds` is a live array of `pfds.len()` pollfd.
    let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 0) };
    if n < 0 {
        return Err(Errno::last());
    }
    if n > 0 || timeout == 0 || expired(ctx) {
        let mut out = raw;
        for (i, p) in pfds.iter().enumerate() {
            // A guest descriptor that is not open reports POLLNVAL.
            let rev = if p.fd == i32::MAX {
                libc::POLLNVAL
            } else {
                p.revents
            };
            out[8 * i + 6..8 * i + 8].copy_from_slice(&rev.to_le_bytes());
        }
        ctx.write(fds, &out)?;
        return Ok(Rv::one(n.max(0) as u64));
    }
    let deadline = deadline(
        ctx,
        (timeout >= 0).then(|| Duration::from_millis(timeout as u64)),
    );
    let wait: Vec<(i32, bool, bool)> = pfds
        .iter()
        .filter(|p| p.fd >= 0 && p.fd != i32::MAX)
        .map(|p| {
            (
                p.fd,
                p.events & (libc::POLLIN | libc::POLLPRI | libc::POLLRDNORM) != 0,
                p.events & (libc::POLLOUT | libc::POLLWRNORM) != 0,
            )
        })
        .collect();
    // Neither poll nor select restarts after a handler.
    syscall::sleep_no_restart(ctx, Wait::fds(wait, deadline))
}

/// The absolute deadline of a timed call: the one computed when the call
/// first ran, kept across its restarts.
pub fn deadline(ctx: &Ctx<'_>, timeout: Option<Duration>) -> Option<Instant> {
    if let Some(r) = ctx.thread.resume {
        return r.deadline;
    }
    timeout.map(|t| Instant::now() + t)
}

/// Whether a restarted timed call's deadline has passed.
pub fn expired(ctx: &Ctx<'_>) -> bool {
    ctx.thread
        .resume
        .and_then(|r| r.deadline)
        .is_some_and(|d| d <= Instant::now())
}

/// `select(nfds, readfds, writefds, exceptfds, timeout)`: evaluated with
/// the host's `poll`, as the guest's descriptors need not be the host's.
pub fn select(ctx: &mut Ctx<'_>, nfds: i32, rd: u64, wr: u64, ex: u64, timeout: u64) -> SysResult {
    if nfds < 0 {
        return Err(Errno::EINVAL);
    }
    let nfds = nfds.min(ctx.proc.fds.len().max(1) as i32 + 1024) as usize;
    let words = nfds.div_ceil(32);
    let read_set = |addr: u64| -> Result<Vec<u32>, Errno> {
        if addr == 0 {
            return Ok(vec![0; words]);
        }
        let b = ctx.read(addr, 4 * words)?;
        Ok(b.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
            .collect())
    };
    let (r, w, e) = (read_set(rd)?, read_set(wr)?, read_set(ex)?);
    let tv = if timeout == 0 {
        None
    } else {
        let b: [u8; 16] = ctx.read(timeout, 16)?.try_into().expect("16 bytes");
        let t = crate::user::darwin::abi::types::Timeval::from_bytes(&b);
        if t.sec < 0 || !(0..1_000_000).contains(&t.usec) {
            return Err(Errno::EINVAL);
        }
        Some(Duration::from_secs(t.sec as u64) + Duration::from_micros(t.usec as u64))
    };
    let bit = |s: &[u32], i: usize| s[i / 32] & (1 << (i % 32)) != 0;
    let mut polls = Vec::new();
    for i in 0..nfds {
        let (a, b, c) = (bit(&r, i), bit(&w, i), bit(&e, i));
        if !(a || b || c) {
            continue;
        }
        let h = ctx.proc.fds.file(i as i32)?.host_fd().ok_or(Errno::EBADF)?;
        let mut ev = 0;
        if a {
            ev |= libc::POLLIN;
        }
        if b {
            ev |= libc::POLLOUT;
        }
        if c {
            ev |= libc::POLLPRI;
        }
        polls.push((
            i,
            libc::pollfd {
                fd: h,
                events: ev,
                revents: 0,
            },
        ));
    }
    let mut pfds: Vec<libc::pollfd> = polls.iter().map(|p| p.1).collect();
    // SAFETY: `pfds` is a live array of pollfd.
    let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 0) };
    if n < 0 {
        return Err(Errno::last());
    }
    let ready = pfds.iter().any(|p| p.revents != 0);
    if ready || tv == Some(Duration::ZERO) || expired(ctx) {
        let (mut ro, mut wo, mut eo) = (vec![0u32; words], vec![0u32; words], vec![0u32; words]);
        let mut count = 0u64;
        for ((i, _), p) in polls.iter().zip(&pfds) {
            let set = |s: &mut Vec<u32>| s[i / 32] |= 1 << (i % 32);
            let rev = p.revents;
            if p.events & libc::POLLIN != 0
                && rev & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            {
                set(&mut ro);
                count += 1;
            }
            if p.events & libc::POLLOUT != 0 && rev & (libc::POLLOUT | libc::POLLERR) != 0 {
                set(&mut wo);
                count += 1;
            }
            if p.events & libc::POLLPRI != 0 && rev & libc::POLLPRI != 0 {
                set(&mut eo);
                count += 1;
            }
        }
        let put = |addr: u64, s: &[u32]| -> Result<(), Errno> {
            if addr == 0 {
                return Ok(());
            }
            let b: Vec<u8> = s.iter().flat_map(|v| v.to_le_bytes()).collect();
            ctx.write(addr, &b)
        };
        put(rd, &ro)?;
        put(wr, &wo)?;
        put(ex, &eo)?;
        return Ok(Rv::one(count));
    }
    let deadline = deadline(ctx, tv);
    let wait: Vec<(i32, bool, bool)> = pfds
        .iter()
        .map(|p| {
            (
                p.fd,
                p.events & libc::POLLIN != 0,
                p.events & libc::POLLOUT != 0,
            )
        })
        .collect();
    // Neither poll nor select restarts after a handler.
    syscall::sleep_no_restart(ctx, Wait::fds(wait, deadline))
}

/// `fstatfs64(fd, buf)`.
pub fn fstatfs64(ctx: &mut Ctx<'_>, fd: i32, buf: u64) -> SysResult {
    let (_, h) = host_fd(ctx, fd)?;
    #[cfg(target_os = "macos")]
    {
        // SAFETY: fstatfs writes a complete struct on success.
        let s = unsafe {
            let mut s: libc::statfs = std::mem::zeroed();
            check(libc::fstatfs(h, &mut s))?;
            s
        };
        ctx.write(
            buf,
            &crate::user::darwin::abi::types::Statfs::from_host(&s).bytes(),
        )?;
        Ok(Rv::one(0))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (h, buf);
        Err(Errno::ENOSYS)
    }
}

/// Whether a descriptor is in non-blocking mode (for callers outside).
pub fn is_nonblocking(file: &FileRef) -> bool {
    *file.flags.lock().unwrap() & O_NONBLOCK != 0
}

//! Descriptor and data-transfer system calls.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::fs;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::host;
use super::super::signal::deliver::restart::{ERESTART_RESTARTBLOCK, ERESTARTNOHAND, ERESTARTSYS};
use super::super::wait::{Resume, Wait};
use super::ready::raw_fd;
use super::{Ctx, Outcome, RestartBlock, SysResult, is_blocked, read_iovecs};
use crate::error::MemoryAccessKind;

/// `MAX_RW_COUNT`: `INT_MAX & PAGE_MASK`.
pub const MAX_RW_COUNT: u64 = 0x7fff_f000;

/// Host bounce-buffer size for one transfer step.
const CHUNK: usize = 1 << 20;

pub(super) fn nofile(c: &Ctx<'_>) -> u64 {
    c.p.rlimits[7].0
}

/// Whether a transfer on `file` can block: pipes, FIFOs, sockets, and
/// character devices (terminals) without `O_NONBLOCK`.
fn may_block(file: &OpenFile) -> bool {
    matches!(
        file.ftype,
        FileType::Fifo | FileType::Socket | FileType::CharDevice
    ) && file.flags() & O_NONBLOCK == 0
}

/// Whether a transfer on `file` would not sleep now: data, end of file,
/// or an error to report (`POLLIN`/`POLLHUP`/`POLLERR`), or (`write`) room
/// or a vanished reader (`POLLOUT`/`POLLERR`; a macOS pipe reports its
/// last reader closing as `POLLHUP`), so the write fails with `EPIPE`.
fn ready_now(file: &OpenFile, write: bool) -> bool {
    raw_fd(file).is_none_or(|fd| {
        host::poll(&[(fd, !write, write)], 0).is_ok_and(|r| {
            let r = r[0];
            r.error || r.hangup || if write { r.writable } else { r.readable }
        })
    })
}

/// A blocking transfer on `file` cannot proceed: a pending signal ends it
/// with `-ERESTARTSYS`, as `pipe_read`, `pipe_write`, and `n_tty_read`
/// return it; otherwise the thread sleeps until the descriptor is ready,
/// with `resume` as its progress.
fn wait_ready(c: &mut Ctx<'_>, file: &OpenFile, write: bool, resume: Resume) -> Errno {
    if c.signal_pending() {
        return Errno(ERESTARTSYS);
    }
    match raw_fd(file) {
        Some(fd) => c.block(Wait::fd(fd, !write, write), resume),
        None => Errno(EAGAIN),
    }
}

/// After a host call failed with `EINTR` (a forwarded host signal arrived
/// during it): whether the guest now has a signal to handle. Otherwise the
/// call is retried, as the kernel would have kept sleeping.
fn interrupted(c: &mut Ctx<'_>) -> bool {
    c.check_async()
}

/// The number of bytes from `addr` the guest may write before the first
/// fault (`copy_to_user` stops there).
fn writable_prefix(c: &Ctx<'_>, addr: u64, len: u64) -> u64 {
    match c.p.space.probe(addr, len as usize, MemoryAccessKind::Write) {
        Ok(()) => len,
        Err(f) => f.address.saturating_sub(addr).min(len),
    }
}

/// Reads up to `count` bytes from `file`. Regular files are read until
/// `count` or end of file, as the kernel's page-cache path does; other files
/// return what one read produces, after waiting for data unless
/// `O_NONBLOCK` is set.
fn read_bytes(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    count: u64,
    pos: Option<u64>,
) -> Result<Vec<u8>, Errno> {
    let count = count.min(MAX_RW_COUNT);
    let blocking = pos.is_none() && may_block(file);
    if blocking && !ready_now(file, false) {
        return Err(wait_ready(c, file, false, Resume::Retry));
    }
    let mut out = Vec::new();
    let mut tmp = vec![0u8; (count as usize).min(CHUNK)];
    while (out.len() as u64) < count {
        let want = ((count - out.len() as u64) as usize).min(tmp.len());
        let at = pos.map(|p| p + out.len() as u64);
        let n = match at {
            Some(p) => file.read_at(&mut tmp[..want], p),
            None => file.read(&mut tmp[..want]),
        };
        let n = match n {
            Ok(n) => n,
            Err(Errno(EINTR)) => {
                if interrupted(c) {
                    return if out.is_empty() {
                        Err(Errno(ERESTARTSYS))
                    } else {
                        Ok(out)
                    };
                }
                continue;
            }
            // Another reader took the data (or the host descriptor does
            // not block): sleep again.
            Err(Errno(EAGAIN)) if blocking && out.is_empty() => {
                return Err(wait_ready(c, file, false, Resume::Retry));
            }
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => break,
        };
        out.extend_from_slice(&tmp[..n]);
        if n == 0 || file.ftype != FileType::Regular || n < want {
            break;
        }
    }
    Ok(out)
}

/// Reads up to `count` bytes into guest memory at `buf`. Only as many bytes
/// as the guest can store are taken from the file, so a bad buffer does not
/// consume pipe or terminal input.
fn read_into(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    buf: u64,
    count: u64,
    pos: Option<u64>,
) -> SysResult {
    let room = writable_prefix(c, buf, count.min(MAX_RW_COUNT));
    if room == 0 {
        return Err(Errno(EFAULT));
    }
    let data = read_bytes(c, file, room, pos)?;
    c.write_mem(buf, &data)?;
    Ok(data.len() as u64)
}

/// Writes `data` to `file`. A pipe or socket without `O_NONBLOCK` that
/// has no room waits for it, continuing after the bytes it wrote before it
/// slept; a signal ends the write with the bytes written so far, or
/// `-ERESTARTSYS` when there are none.
fn write_bytes(c: &mut Ctx<'_>, file: &OpenFile, data: &[u8], pos: Option<u64>) -> SysResult {
    let waits =
        pos.is_none() && may_block(file) && matches!(file.ftype, FileType::Fifo | FileType::Socket);
    let mut done = match c.resume.take() {
        Some(Resume::Written(n)) => (n as usize).min(data.len()),
        _ => 0,
    };
    while done < data.len() {
        if waits && !ready_now(file, true) {
            if c.signal_pending() {
                return if done > 0 {
                    Ok(done as u64)
                } else {
                    Err(Errno(ERESTARTSYS))
                };
            }
            return Err(wait_ready(c, file, true, Resume::Written(done as u64)));
        }
        let chunk = &data[done..(done + CHUNK).min(data.len())];
        let n = match pos {
            Some(p) => file.write_at(chunk, p + done as u64),
            None => file.write(chunk),
        };
        let n = match n {
            Ok(n) => n,
            Err(Errno(EINTR)) => {
                if interrupted(c) {
                    return if done > 0 {
                        Ok(done as u64)
                    } else {
                        Err(Errno(ERESTARTSYS))
                    };
                }
                continue;
            }
            // The room another writer took: wait for more.
            Err(Errno(EAGAIN)) if waits => continue,
            Err(e) if done > 0 && e.0 != EPIPE => return Ok(done as u64),
            Err(e) => return Err(e),
        };
        done += n;
        if n < chunk.len() && !waits {
            break;
        }
    }
    Ok(done as u64)
}

/// Writes `count` bytes from guest memory at `buf`; a buffer that faults
/// part way writes the readable prefix.
fn write_from(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    buf: u64,
    count: u64,
    pos: Option<u64>,
) -> SysResult {
    let count = count.min(MAX_RW_COUNT);
    let readable = match c.p.space.probe(buf, count as usize, MemoryAccessKind::Read) {
        Ok(()) => count,
        Err(f) => f.address.saturating_sub(buf).min(count),
    };
    if readable == 0 {
        return Err(Errno(EFAULT));
    }
    if let Some(tid) = file.state.lock().unwrap().comm_of {
        return comm_write(c, tid, buf, count);
    }
    let data = c.read_mem(buf, readable as usize)?;
    write_bytes(c, file, &data, pos)
}

/// `comm_write`: a thread of this process takes the first 15 bytes as its
/// name, up to a NUL; the whole count is reported written.
fn comm_write(c: &mut Ctx<'_>, tid: i32, buf: u64, count: u64) -> SysResult {
    let mut name = c.read_mem(buf, count.min(15) as usize)?;
    if let Some(nul) = name.iter().position(|&b| b == 0) {
        name.truncate(nul);
    }
    let leader = tid == c.p.pid;
    if leader {
        c.p.comm = name.clone();
    }
    let (_, mut th) = c.split();
    match th.get_mut(tid) {
        Some(t) => {
            t.comm = name;
            Ok(count)
        }
        // The exited leader remains (a zombie); another thread is gone
        // (get_proc_task).
        None if leader => Ok(count),
        None => Err(Errno(ESRCH)),
    }
}

/// `read`.
pub fn read(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if matches!(file.object, FileObject::Anon(_)) {
        return super::events::read_call(c, &file, buf, count);
    }
    if matches!(file.object, FileObject::Socket(_)) {
        return super::net::io::read(c, &file, &[(buf, count.min(MAX_RW_COUNT))]);
    }
    if count == 0 {
        return if file.readable() {
            Ok(0)
        } else {
            Err(Errno(EBADF))
        };
    }
    read_into(c, &file, buf, count, None)
}

/// `write`.
pub fn write(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if matches!(file.object, FileObject::Anon(_)) {
        return super::events::write_call(c, &file, buf, count);
    }
    if matches!(file.object, FileObject::Socket(_)) {
        return super::net::io::write(c, &file, &[(buf, count.min(MAX_RW_COUNT))]);
    }
    if count == 0 {
        return if file.writable() {
            Ok(0)
        } else {
            Err(Errno(EBADF))
        };
    }
    write_from(c, &file, buf, count, None)
}

/// Scatters `data` over `iovecs`, stopping at the first fault.
fn scatter(c: &Ctx<'_>, iovecs: &[(u64, u64)], data: &[u8]) -> SysResult {
    let mut done = 0usize;
    for &(base, len) in iovecs {
        if done == data.len() {
            break;
        }
        let take = (len as usize).min(data.len() - done);
        if c.write_mem(base, &data[done..done + take]).is_err() {
            return if done > 0 {
                Ok(done as u64)
            } else {
                Err(Errno(EFAULT))
            };
        }
        done += take;
    }
    Ok(done as u64)
}

/// The bytes the iovecs can receive before the first unwritable one.
pub(super) fn iovec_room(c: &Ctx<'_>, iovecs: &[(u64, u64)]) -> u64 {
    let mut room = 0u64;
    for &(base, len) in iovecs {
        let ok = writable_prefix(c, base, len);
        room += ok;
        if ok < len {
            break;
        }
    }
    room.min(MAX_RW_COUNT)
}

/// `readv`: one transfer scattered over the vectors, as the kernel's
/// `iov_iter` does.
pub fn readv(c: &mut Ctx<'_>, fd: i32, iov: u64, cnt: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if !file.readable() {
        return Err(Errno(EBADF));
    }
    if !super::events::can_read(&file) {
        return Err(Errno(EINVAL));
    }
    let iovecs = read_iovecs(c, iov, cnt)?;
    let total: u64 = iovecs.iter().map(|&(_, l)| l).sum();
    if total == 0 {
        return Ok(0);
    }
    if matches!(file.object, FileObject::Anon(_)) {
        return super::events::read(c, &file, &iovecs);
    }
    if matches!(file.object, FileObject::Socket(_)) {
        return super::net::io::read(c, &file, &iovecs);
    }
    let room = iovec_room(c, &iovecs);
    if room == 0 {
        return Err(Errno(EFAULT));
    }
    let data = read_bytes(c, &file, room, None)?;
    scatter(c, &iovecs, &data)
}

/// `writev`: the vectors are gathered so the data reaches the file in one
/// write, as the kernel's `iov_iter` does for pipes and terminals.
pub fn writev(c: &mut Ctx<'_>, fd: i32, iov: u64, cnt: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if !file.writable() {
        return Err(Errno(EBADF));
    }
    let anon = matches!(file.object, FileObject::Anon(_));
    if anon && !super::events::can_write(&file) {
        return Err(Errno(EINVAL));
    }
    let vecs = read_iovecs(c, iov, cnt)?;
    if matches!(file.object, FileObject::Socket(_)) {
        return super::net::io::write(c, &file, &vecs);
    }
    if anon {
        if vecs.iter().all(|&(_, l)| l == 0) {
            return Ok(0);
        }
        return super::events::write(c, &file, &vecs);
    }
    let mut data = Vec::new();
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        match c.read_mem(base, len.min(MAX_RW_COUNT) as usize) {
            Ok(d) => data.extend_from_slice(&d),
            Err(e) if data.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    if data.is_empty() {
        return Ok(0);
    }
    write_bytes(c, &file, &data, None)
}

/// `pread64`.
pub fn pread(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64, pos: i64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if pos < 0 {
        return Err(Errno(EINVAL));
    }
    if matches!(file.object, FileObject::Anon(_)) {
        return Err(Errno(positional(&file)));
    }
    read_into(c, &file, buf, count, Some(pos as u64))
}

/// `pwrite64`.
pub fn pwrite(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64, pos: i64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if pos < 0 {
        return Err(Errno(EINVAL));
    }
    if matches!(file.object, FileObject::Anon(_)) {
        return Err(Errno(positional(&file)));
    }
    write_from(c, &file, buf, count, Some(pos as u64))
}

/// Why a positioned transfer on an anonymous-inode file fails: most have
/// no position (`FMODE_PREAD` is not set: `ESPIPE`); a pidfd has one but
/// cannot be read or written (`EINVAL`).
fn positional(file: &OpenFile) -> i32 {
    if super::pidfd::target_of(file).is_some() {
        EINVAL
    } else {
        ESPIPE
    }
}

/// `RWF_*` flags accepted by `preadv2`/`pwritev2`.
const RWF_SUPPORTED: u64 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10;

/// `preadv`/`preadv2` (`pos == -1` means the current position).
pub fn preadv(c: &mut Ctx<'_>, fd: i32, iov: u64, cnt: u64, pos: i64, flags: u64) -> SysResult {
    if flags & !RWF_SUPPORTED != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    let file = c.p.fds.file(fd)?;
    if pos < -1 {
        return Err(Errno(EINVAL));
    }
    if matches!(file.object, FileObject::Anon(_)) {
        return if pos >= 0 {
            Err(Errno(positional(&file)))
        } else {
            readv(c, fd, iov, cnt)
        };
    }
    let mut total = 0;
    for (base, len) in read_iovecs(c, iov, cnt)? {
        let at = (pos >= 0).then(|| pos as u64 + total);
        let n = read_into(c, &file, base, len, at)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

/// `pwritev`/`pwritev2`.
pub fn pwritev(c: &mut Ctx<'_>, fd: i32, iov: u64, cnt: u64, pos: i64, flags: u64) -> SysResult {
    if flags & !RWF_SUPPORTED != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    let file = c.p.fds.file(fd)?;
    if pos < -1 {
        return Err(Errno(EINVAL));
    }
    if matches!(file.object, FileObject::Anon(_)) {
        return if pos >= 0 {
            Err(Errno(positional(&file)))
        } else {
            writev(c, fd, iov, cnt)
        };
    }
    let mut total = 0;
    for (base, len) in read_iovecs(c, iov, cnt)? {
        let at = (pos >= 0).then(|| pos as u64 + total);
        let n = write_from(c, &file, base, len, at)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

/// `close`.
pub fn close(c: &mut Ctx<'_>, fd: i32) -> SysResult {
    c.p.fds.close(fd).map(|_| 0)
}

/// `close_range`.
pub fn close_range(c: &mut Ctx<'_>, first: u32, last: u32, flags: u32) -> SysResult {
    const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
        return Err(Errno(EINVAL));
    }
    for fd in c.p.fds.open_fds() {
        let fd_u = fd as u32;
        if fd_u < first || fd_u > last {
            continue;
        }
        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            c.p.fds.get_mut(fd)?.cloexec = true;
        } else {
            let _ = c.p.fds.close(fd);
        }
    }
    Ok(0)
}

/// `lseek`.
pub fn lseek(c: &mut Ctx<'_>, fd: i32, off: i64, whence: u32) -> SysResult {
    c.p.fds.file(fd)?.seek(off, whence)
}

/// `dup`.
pub fn dup(c: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let limit = nofile(c);
    c.p.fds.install(file, false, limit).map(|n| n as u64)
}

/// `dup2`: `EBADF` for an invalid descriptor; duplicating onto itself
/// returns it unchanged.
pub fn dup2(c: &mut Ctx<'_>, old: i32, new: i32) -> SysResult {
    let file = c.p.fds.file(old)?;
    if old == new {
        return Ok(new as u64);
    }
    let limit = nofile(c);
    c.p.fds.install_at(new, file, false, limit)?;
    Ok(new as u64)
}

/// `dup3`: like `dup2`, but `old == new` is `EINVAL` and only `O_CLOEXEC`
/// is a valid flag.
pub fn dup3(c: &mut Ctx<'_>, old: i32, new: i32, flags: u32) -> SysResult {
    if flags & !O_CLOEXEC != 0 || old == new {
        return Err(Errno(EINVAL));
    }
    let file = c.p.fds.file(old)?;
    let limit = nofile(c);
    c.p.fds
        .install_at(new, file, flags & O_CLOEXEC != 0, limit)?;
    Ok(new as u64)
}

/// `pipe`/`pipe2`.
pub fn pipe2(c: &mut Ctx<'_>, fds: u64, flags: u32) -> SysResult {
    let direct = c.p.abi.open_flags().direct;
    if flags & !(O_CLOEXEC | O_NONBLOCK | direct) != 0 {
        return Err(Errno(EINVAL));
    }
    let (r, w) = std::io::pipe()?;
    // The guest's O_NONBLOCK lives in the status flags; the host ends
    // never block (see set_host_nonblocking).
    host::set_nonblocking(&r, true)?;
    host::set_nonblocking(&w, true)?;
    let nb = flags & O_NONBLOCK;
    let rf = OpenFile::new(
        FileObject::PipeRead(r),
        FileType::Fifo,
        "pipe:",
        None,
        O_RDONLY | nb,
    );
    let wf = OpenFile::new(
        FileObject::PipeWrite(w),
        FileType::Fifo,
        "pipe:",
        None,
        O_WRONLY | nb,
    );
    *rf.peer.lock().unwrap() = Arc::downgrade(&wf);
    *wf.peer.lock().unwrap() = Arc::downgrade(&rf);
    let cloexec = flags & O_CLOEXEC != 0;
    let limit = nofile(c);
    let rfd = c.p.fds.install(rf, cloexec, limit)?;
    let wfd = match c.p.fds.install(wf, cloexec, limit) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = c.p.fds.close(rfd);
            return Err(e);
        }
    };
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&rfd.to_le_bytes());
    b[4..].copy_from_slice(&wfd.to_le_bytes());
    if let Err(e) = c.write_mem(fds, &b) {
        let _ = c.p.fds.close(rfd);
        let _ = c.p.fds.close(wfd);
        return Err(e);
    }
    Ok(0)
}

/// `poll` event bits.
mod pe {
    pub const POLLIN: u16 = 0x001;
    pub const POLLPRI: u16 = 0x002;
    pub const POLLOUT: u16 = 0x004;
    pub const POLLERR: u16 = 0x008;
    pub const POLLHUP: u16 = 0x010;
    pub const POLLNVAL: u16 = 0x020;
    pub const POLLRDNORM: u16 = 0x040;
    pub const POLLWRNORM: u16 = 0x100;
}

/// How a poll ended.
enum Polled {
    /// Revents per request; possibly all zero (timeout).
    Done(Vec<u16>),
    /// A signal interrupted it before anything was ready.
    Interrupted,
}

/// `do_poll`: `revents` for `(fd, events)` pairs, sleeping until `deadline`
/// (`None` waits indefinitely) for one to be ready. Each file's mask
/// ([`ready::poll_files`](super::ready::poll_files)) is filtered by the
/// events asked for, plus `POLLERR` and `POLLHUP`; a descriptor that is
/// not open, or open with `O_PATH`, reports `POLLNVAL` (`fdget` refuses
/// it). The thread sleeps (the internal errno) with
/// `Resume::Until(deadline)`.
fn poll_fds(
    c: &mut Ctx<'_>,
    req: &[(i32, u16)],
    deadline: Option<Instant>,
) -> Result<Polled, Errno> {
    use super::ready::ev;
    let mut out = vec![0u16; req.len()];
    let mut files = Vec::new();
    let mut at = Vec::new();
    for (i, &(fd, events)) in req.iter().enumerate() {
        if fd < 0 {
            continue;
        }
        match c.p.fds.file(fd) {
            Ok(file) => {
                files.push((file, u32::from(events)));
                at.push(i);
            }
            Err(_) => out[i] = pe::POLLNVAL,
        }
    }
    let refs: Vec<(&OpenFile, u32)> = files.iter().map(|(f, e)| (&**f, *e)).collect();
    let (polled, mut wait) = super::ready::poll_files(c, &refs);
    for ((&i, &(_, events)), p) in at.iter().zip(&refs).zip(&polled) {
        out[i] = (p.mask & (events | ev::ERR | ev::HUP | ev::NVAL)) as u16;
    }
    if out.iter().any(|&r| r != 0) || deadline.is_some_and(|d| d <= Instant::now()) {
        return Ok(Polled::Done(out));
    }
    if c.signal_pending() {
        return Ok(Polled::Interrupted);
    }
    // A file's own deadline (a timer expiry) ends the sleep early, and the
    // poll looks again.
    wait.deadline = super::ready::earlier(wait.deadline, deadline);
    Err(c.block(wait, Resume::Until(deadline)))
}

/// The deadline a `poll` or `select` computed when it started, if it is
/// running again after sleeping; its temporary signal mask is installed.
fn resumed_deadline(c: &mut Ctx<'_>) -> Option<Option<Instant>> {
    match c.resume.take() {
        Some(Resume::Until(d)) => Some(d),
        _ => None,
    }
}

/// An absolute deadline `sec`/`nsec` from now (`poll_select_set_timeout`);
/// `None` for an invalid time.
fn timeout_deadline(sec: i64, nsec: i64) -> Option<Instant> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    Some(Instant::now() + Duration::new(sec as u64, nsec as u32))
}

/// `do_sys_poll`: polls the `struct pollfd` array and writes every
/// `revents` back, zero when interrupted.
fn sys_poll(
    c: &mut Ctx<'_>,
    fds: u64,
    nfds: u64,
    deadline: Option<Instant>,
) -> Result<Outcome, Errno> {
    if nfds > c.p.rlimits[7].0 {
        return Err(Errno(EINVAL));
    }
    let raw = c.read_mem(fds, nfds as usize * 8)?;
    let req: Vec<(i32, u16)> = raw
        .chunks_exact(8)
        .map(|e| {
            (
                i32::from_le_bytes(e[..4].try_into().unwrap()),
                u16::from_le_bytes(e[4..6].try_into().unwrap()),
            )
        })
        .collect();
    let (rev, result) = match poll_fds(c, &req, deadline)? {
        Polled::Done(rev) => {
            let n = rev.iter().filter(|&&r| r != 0).count() as u64;
            (rev, Ok(Outcome::Return(n)))
        }
        Polled::Interrupted => (vec![0; req.len()], Err(Errno(ERESTARTNOHAND))),
    };
    let mut out = raw;
    for (i, r) in rev.iter().enumerate() {
        out[i * 8 + 6..i * 8 + 8].copy_from_slice(&r.to_le_bytes());
    }
    c.write_mem(fds, &out)?;
    result
}

/// `poll`. An interrupted poll continues through `do_restart_poll` unless a
/// handler runs.
pub fn poll(c: &mut Ctx<'_>, fds: u64, nfds: u64, timeout_ms: i64) -> Result<Outcome, Errno> {
    let deadline = resumed_deadline(c).unwrap_or_else(|| {
        (timeout_ms >= 0).then(|| Instant::now() + Duration::from_millis(timeout_ms as u64))
    });
    poll_restart(c, fds, nfds, deadline)
}

/// `do_restart_poll`, and `poll` itself.
pub fn poll_restart(
    c: &mut Ctx<'_>,
    fds: u64,
    nfds: u64,
    deadline: Option<Instant>,
) -> Result<Outcome, Errno> {
    let deadline = resumed_deadline(c).unwrap_or(deadline);
    match sys_poll(c, fds, nfds, deadline) {
        Err(Errno(ERESTARTNOHAND)) => {
            c.t.restart = Some(RestartBlock::Poll {
                fds,
                nfds,
                deadline,
            });
            Err(Errno(ERESTART_RESTARTBLOCK))
        }
        other => other,
    }
}

/// `set_user_sigmask`: installs a temporary mask for the call, saving the
/// old one to come back on the return to user mode.
pub(super) fn set_user_sigmask(c: &mut Ctx<'_>, mask: u64, size: u64) -> Result<(), Errno> {
    if mask == 0 {
        return Ok(());
    }
    if size != 8 {
        return Err(Errno(EINVAL));
    }
    let set = c.read_u64(mask)?;
    c.t.saved_sigmask = Some(c.t.sigmask);
    c.set_blocked(set);
    Ok(())
}

/// How `poll_select_finish` reports the remaining time.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TimeFormat {
    /// `struct timeval`.
    Timeval,
    /// `struct timespec`.
    Timespec,
}

/// `poll_select_finish`: restores a temporary mask unless a signal
/// interrupted the call (the handler frame saves it), and writes the time
/// left back to `user` for a nonzero timeout. If that write faults the call
/// cannot be restarted, so `-ERESTARTNOHAND` becomes `-EINTR`.
fn poll_select_finish(
    c: &mut Ctx<'_>,
    deadline: Option<Instant>,
    zero_timeout: bool,
    user: u64,
    format: TimeFormat,
    result: Result<Outcome, Errno>,
) -> Result<Outcome, Errno> {
    if is_blocked(&result) {
        return result;
    }
    let interrupted = matches!(result, Err(Errno(ERESTARTNOHAND)));
    if !interrupted && let Some(saved) = c.t.saved_sigmask.take() {
        c.set_blocked(saved);
    }
    let (Some(deadline), false) = (deadline, zero_timeout || user == 0) else {
        return result;
    };
    let left = deadline.saturating_duration_since(Instant::now());
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(left.as_secs() as i64).to_le_bytes());
    let frac = match format {
        TimeFormat::Timeval => i64::from(left.subsec_micros()),
        TimeFormat::Timespec => i64::from(left.subsec_nanos()),
    };
    b[8..].copy_from_slice(&frac.to_le_bytes());
    if c.write_mem(user, &b).is_ok() {
        return result;
    }
    if interrupted {
        Err(Errno(EINTR))
    } else {
        result
    }
}

/// `ppoll`: `poll` with a timespec timeout and a temporary signal mask; an
/// interruption is `-ERESTARTNOHAND` with the time left written back.
pub fn ppoll(
    c: &mut Ctx<'_>,
    fds: u64,
    nfds: u64,
    tsp: u64,
    mask: u64,
    size: u64,
) -> Result<Outcome, Errno> {
    let (deadline, zero) = match resumed_deadline(c) {
        Some(d) => (d, false),
        None => {
            let (deadline, zero) = if tsp == 0 {
                (None, false)
            } else {
                let b = c.read_mem(tsp, 16)?;
                let ts = super::super::abi::types::Timespec::decode(&b.try_into().unwrap());
                (
                    Some(timeout_deadline(ts.sec, ts.nsec).ok_or(Errno(EINVAL))?),
                    ts.sec == 0 && ts.nsec == 0,
                )
            };
            set_user_sigmask(c, mask, size)?;
            (deadline, zero)
        }
    };
    let result = sys_poll(c, fds, nfds, deadline);
    poll_select_finish(c, deadline, zero, tsp, TimeFormat::Timespec, result)
}

/// `core_sys_select`: `nfds` is clamped to the descriptor table size; a set
/// bit for a descriptor that is not open is `EBADF`. An interrupted select
/// leaves the sets as they were.
fn core_sys_select(
    c: &mut Ctx<'_>,
    nfds: i32,
    rd: u64,
    wr: u64,
    ex: u64,
    deadline: Option<Instant>,
) -> Result<Outcome, Errno> {
    if nfds < 0 {
        return Err(Errno(EINVAL));
    }
    let n = (nfds as usize).min(c.p.fds.max_fds());
    let words = n.div_ceil(64);
    let read_set = |c: &Ctx<'_>, addr: u64| -> Result<Vec<u64>, Errno> {
        if addr == 0 {
            return Ok(vec![0; words]);
        }
        let b = c.read_mem(addr, words * 8)?;
        Ok(b.chunks_exact(8)
            .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
            .collect())
    };
    let (rs, ws, es) = (read_set(c, rd)?, read_set(c, wr)?, read_set(c, ex)?);
    let bit = |set: &[u64], fd: usize| set[fd / 64] >> (fd % 64) & 1 != 0;
    let mut req = Vec::new();
    for fd in 0..n {
        let mut ev = 0u16;
        if bit(&rs, fd) {
            ev |= pe::POLLIN;
        }
        if bit(&ws, fd) {
            ev |= pe::POLLOUT;
        }
        if bit(&es, fd) {
            ev |= pe::POLLPRI;
        }
        if ev != 0 {
            // max_select_fd: every selected descriptor must be open.
            if c.p.fds.get(fd as i32).is_err() {
                return Err(Errno(EBADF));
            }
            req.push((fd as i32, ev));
        }
    }
    let rev = match poll_fds(c, &req, deadline)? {
        Polled::Done(rev) => rev,
        Polled::Interrupted => return Err(Errno(ERESTARTNOHAND)),
    };
    let (mut ro, mut wo, mut eo) = (vec![0u64; words], vec![0u64; words], vec![0u64; words]);
    let mut count = 0;
    for (&(fd, ev), r) in req.iter().zip(rev) {
        let set = |v: &mut Vec<u64>| v[fd as usize / 64] |= 1 << (fd % 64);
        if ev & pe::POLLIN != 0 && r & (pe::POLLIN | pe::POLLHUP | pe::POLLERR) != 0 {
            set(&mut ro);
            count += 1;
        }
        if ev & pe::POLLOUT != 0 && r & (pe::POLLOUT | pe::POLLERR) != 0 {
            set(&mut wo);
            count += 1;
        }
        if ev & pe::POLLPRI != 0 && r & pe::POLLPRI != 0 {
            set(&mut eo);
            count += 1;
        }
    }
    for (addr, v) in [(rd, &ro), (wr, &wo), (ex, &eo)] {
        if addr != 0 {
            let b: Vec<u8> = v.iter().flat_map(|w| w.to_le_bytes()).collect();
            c.write_mem(addr, &b)?;
        }
    }
    Ok(Outcome::Return(count))
}

/// `select` (`struct timeval` timeout; microseconds beyond a second are
/// carried into seconds, as `kern_select` does).
pub fn select(
    c: &mut Ctx<'_>,
    nfds: i32,
    rd: u64,
    wr: u64,
    ex: u64,
    tvp: u64,
) -> Result<Outcome, Errno> {
    let (deadline, zero) = if let Some(d) = resumed_deadline(c) {
        (d, false)
    } else if tvp == 0 {
        (None, false)
    } else {
        let b = c.read_mem(tvp, 16)?;
        let sec = i64::from_le_bytes(b[..8].try_into().unwrap());
        let usec = i64::from_le_bytes(b[8..].try_into().unwrap());
        let (sec, nsec) = (
            sec.checked_add(usec / 1_000_000).ok_or(Errno(EINVAL))?,
            (usec % 1_000_000) * 1000,
        );
        (
            Some(timeout_deadline(sec, nsec).ok_or(Errno(EINVAL))?),
            sec == 0 && nsec == 0,
        )
    };
    let result = core_sys_select(c, nfds, rd, wr, ex, deadline);
    poll_select_finish(c, deadline, zero, tvp, TimeFormat::Timeval, result)
}

/// `pselect6`: `select` with a timespec timeout and a temporary signal mask
/// passed as `{const sigset_t *ss; size_t ss_len;}`.
pub fn pselect6(
    c: &mut Ctx<'_>,
    nfds: i32,
    rd: u64,
    wr: u64,
    ex: u64,
    tsp: u64,
    sig: u64,
) -> Result<Outcome, Errno> {
    let (mask, size) = if sig != 0 && c.resume.is_none() {
        let b = c.read_mem(sig, 16)?;
        (
            u64::from_le_bytes(b[..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..].try_into().unwrap()),
        )
    } else {
        (0, 0)
    };
    let (deadline, zero) = match resumed_deadline(c) {
        Some(d) => (d, false),
        None => {
            let (deadline, zero) = if tsp == 0 {
                (None, false)
            } else {
                let b = c.read_mem(tsp, 16)?;
                let ts = super::super::abi::types::Timespec::decode(&b.try_into().unwrap());
                (
                    Some(timeout_deadline(ts.sec, ts.nsec).ok_or(Errno(EINVAL))?),
                    ts.sec == 0 && ts.nsec == 0,
                )
            };
            set_user_sigmask(c, mask, size)?;
            (deadline, zero)
        }
    };
    let result = core_sys_select(c, nfds, rd, wr, ex, deadline);
    poll_select_finish(c, deadline, zero, tsp, TimeFormat::Timespec, result)
}

/// `sendfile`: copies from `in_fd` (at `*off_ptr`, or its position) to
/// `out_fd`. Bytes the output does not take are left in the input. A pipe
/// or socket output without `O_NONBLOCK` that is full sleeps as `write`
/// does; a signal ends the copy with what was copied, or `-ERESTARTSYS`.
pub fn sendfile(c: &mut Ctx<'_>, out_fd: i32, in_fd: i32, off_ptr: u64, count: u64) -> SysResult {
    let input = c.p.fds.file(in_fd)?;
    let output = c.p.fds.file(out_fd)?;
    if !input.readable() || !output.writable() {
        return Err(Errno(EBADF));
    }
    let mut pos = if off_ptr != 0 {
        let v = c.read_u64(off_ptr)? as i64;
        if v < 0 {
            return Err(Errno(EINVAL));
        }
        Some(v as u64)
    } else {
        None
    };
    let count = count.min(MAX_RW_COUNT);
    let waits = may_block(&output) && matches!(output.ftype, FileType::Fifo | FileType::Socket);
    // After a sleep the offset in memory is still the original one.
    let mut done = match c.resume.take() {
        Some(Resume::Written(n)) => n,
        _ => 0,
    };
    if let Some(p) = pos.as_mut() {
        *p += done;
    }
    let mut buf = vec![0u8; (count as usize).min(CHUNK)];
    let mut stop = None;
    while done < count {
        if waits && !ready_now(&output, true) {
            if c.signal_pending() {
                if done == 0 {
                    stop = Some(Errno(ERESTARTSYS));
                }
                break;
            }
            return Err(wait_ready(c, &output, true, Resume::Written(done)));
        }
        let want = ((count - done) as usize).min(buf.len());
        let n = match pos {
            Some(p) => input.read_at(&mut buf[..want], p)?,
            None => input.read(&mut buf[..want])?,
        };
        if n == 0 {
            break;
        }
        let w = match output.write(&buf[..n]) {
            Ok(w) => w,
            Err(Errno(EAGAIN)) if waits => 0,
            Err(e) => {
                if pos.is_none() {
                    input.seek(-(n as i64), 1)?;
                }
                if done == 0 {
                    return Err(e);
                }
                break;
            }
        };
        if pos.is_none() && w < n {
            input.seek(-((n - w) as i64), 1)?;
        }
        done += w as u64;
        if let Some(p) = pos.as_mut() {
            *p += w as u64;
        }
        if w < n && !waits {
            break;
        }
    }
    if let (Some(p), true) = (pos, off_ptr != 0) {
        c.write_u64(off_ptr, p)?;
    }
    match stop {
        Some(e) => Err(e),
        None => Ok(done),
    }
}

/// `copy_file_range` (emulated with positioned reads and writes).
pub fn copy_file_range(
    c: &mut Ctx<'_>,
    in_fd: i32,
    in_off: u64,
    out_fd: i32,
    out_off: u64,
    len: u64,
) -> SysResult {
    let input = c.p.fds.file(in_fd)?;
    let output = c.p.fds.file(out_fd)?;
    if !input.readable() || !output.writable() || output.flags() & O_APPEND != 0 {
        return Err(Errno(EBADF));
    }
    if input.ftype != FileType::Regular || output.ftype != FileType::Regular {
        return Err(Errno(EINVAL));
    }
    let mut ipos = if in_off != 0 {
        c.read_u64(in_off)?
    } else {
        input.seek(0, 1)?
    };
    let mut opos = if out_off != 0 {
        c.read_u64(out_off)?
    } else {
        output.seek(0, 1)?
    };
    let len = len.min(MAX_RW_COUNT);
    let mut done = 0;
    let mut buf = vec![0u8; (len as usize).min(CHUNK)];
    while done < len {
        let want = ((len - done) as usize).min(buf.len());
        let n = input.read_at(&mut buf[..want], ipos)?;
        if n == 0 {
            break;
        }
        let w = output.write_at(&buf[..n], opos)?;
        done += w as u64;
        ipos += w as u64;
        opos += w as u64;
        if w < n {
            break;
        }
    }
    if in_off != 0 {
        c.write_u64(in_off, ipos)?;
    } else {
        input.seek(ipos as i64, 0)?;
    }
    if out_off != 0 {
        c.write_u64(out_off, opos)?;
    } else {
        output.seek(opos as i64, 0)?;
    }
    Ok(done)
}

/// `fsync`/`fdatasync`.
pub fn fsync(c: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    match (&file.object, file.ftype) {
        // fdget: an O_PATH descriptor is none.
        (FileObject::PathOnly, _) => Err(Errno(EBADF)),
        (FileObject::Host(f), FileType::Regular | FileType::Directory | FileType::BlockDevice) => {
            // Some hosts reject fsync on directories; the data is durable
            // either way for the guest's purposes.
            let _ = f.sync_all();
            Ok(0)
        }
        // vfs_fsync_range: files without the operation, which include
        // character devices (terminals, /dev/null), pipes, sockets, and
        // /proc files.
        _ => Err(Errno(EINVAL)),
    }
}

/// `syncfs`: any open file (not an `O_PATH` one) names a file system to
/// write back, a pseudo one for pipes, sockets, and anonymous files. The
/// host's write-back is relied on, as for `sync`.
pub fn syncfs(c: &mut Ctx<'_>, fd: i32) -> SysResult {
    match c.p.fds.file(fd)?.object {
        FileObject::PathOnly => Err(Errno(EBADF)),
        _ => Ok(0),
    }
}

/// `fadvise64`.
pub fn fadvise(c: &mut Ctx<'_>, fd: i32, advice: u32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if file.ftype == FileType::Fifo {
        return Err(Errno(ESPIPE));
    }
    if advice > 5 {
        return Err(Errno(EINVAL));
    }
    Ok(0)
}

/// `readahead` (`ksys_readahead`): a readable regular file or block
/// device (a synthesized `/proc` file is one too); the host's page cache
/// does the rest. Pipes, sockets, directories, and anonymous inodes are
/// `EINVAL`.
pub fn readahead(c: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if matches!(file.object, FileObject::PathOnly) || !file.readable() {
        return Err(Errno(EBADF));
    }
    let cached = matches!(file.object, FileObject::Host(_) | FileObject::Synthetic(_))
        && matches!(file.ftype, FileType::Regular | FileType::BlockDevice);
    if !cached {
        return Err(Errno(EINVAL));
    }
    Ok(0)
}

/// `sync_file_range`: the flags (`SYNC_FILE_RANGE_WAIT_BEFORE`,
/// `_WRITE`, `_WAIT_AFTER`), a range within `0..LLONG_MAX` (a length of 0
/// runs to the end), then a file with data (`ESPIPE` for pipes, sockets,
/// and other special files). Writing the range writes the file's data.
pub fn sync_file_range(
    c: &mut Ctx<'_>,
    fd: i32,
    offset: i64,
    nbytes: i64,
    flags: u32,
) -> SysResult {
    const WRITE: u32 = 2;
    const VALID: u32 = 1 | WRITE | 4;
    let file = c.p.fds.file(fd)?;
    if matches!(file.object, FileObject::PathOnly) {
        return Err(Errno(EBADF));
    }
    if flags & !VALID != 0 {
        return Err(Errno(EINVAL));
    }
    let end = offset.wrapping_add(nbytes);
    if offset < 0 || end < 0 || end < offset {
        return Err(Errno(EINVAL));
    }
    // A regular file, block device, directory, or link (a pidfd's inode
    // is a regular file to the VFS; /proc's are regular files and
    // directories).
    let data = match &file.object {
        FileObject::Host(_) | FileObject::Synthetic(_) => matches!(
            file.ftype,
            FileType::Regular | FileType::BlockDevice | FileType::Directory | FileType::Symlink
        ),
        FileObject::Anon(super::super::fs::anon::Anon::Pid(_)) => true,
        _ => false,
    };
    if !data {
        return Err(Errno(ESPIPE));
    }
    if flags & WRITE != 0
        && let FileObject::Host(f) = &file.object
    {
        let _ = f.sync_data();
    }
    Ok(0)
}

/// `getdents64` (`struct linux_dirent64`) or legacy `getdents`
/// (`struct linux_dirent`, type in the last byte).
pub fn getdents(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64, is64: bool) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if file.ftype != FileType::Directory {
        return Err(Errno(ENOTDIR));
    }
    let mut st = file.state.lock().unwrap();
    if st.dir.is_none() {
        let entries = match &file.host_path {
            Some(h) => super::super::fs::read_directory(h)?,
            None => Vec::new(),
        };
        st.dir = Some((entries, 0));
    }
    let (entries, cursor) = st.dir.as_mut().unwrap();
    let mut out = Vec::new();
    let mut i = *cursor;
    while i < entries.len() {
        let e = &entries[i];
        let rec = if is64 {
            let reclen = (19 + e.name.len() + 1).div_ceil(8) * 8;
            let mut r = Vec::with_capacity(reclen);
            r.extend_from_slice(&e.ino.to_le_bytes());
            r.extend_from_slice(&((i + 1) as i64).to_le_bytes());
            r.extend_from_slice(&(reclen as u16).to_le_bytes());
            r.push(e.dtype);
            r.extend_from_slice(&e.name);
            r.resize(reclen, 0);
            r
        } else {
            let reclen = (18 + e.name.len() + 2).div_ceil(8) * 8;
            let mut r = Vec::with_capacity(reclen);
            r.extend_from_slice(&e.ino.to_le_bytes());
            r.extend_from_slice(&((i + 1) as i64).to_le_bytes());
            r.extend_from_slice(&(reclen as u16).to_le_bytes());
            r.extend_from_slice(&e.name);
            r.resize(reclen - 1, 0);
            r.push(e.dtype);
            r
        };
        if out.len() + rec.len() > count as usize {
            if out.is_empty() {
                return Err(Errno(EINVAL));
            }
            break;
        }
        out.extend_from_slice(&rec);
        i += 1;
    }
    drop(st);
    c.write_mem(buf, &out)?;
    if let Some((_, cur)) = file.state.lock().unwrap().dir.as_mut() {
        *cur = i;
    }
    Ok(out.len() as u64)
}

/// `ftruncate`.
pub fn ftruncate(c: &mut Ctx<'_>, fd: i32, len: i64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if len < 0 {
        return Err(Errno(EINVAL));
    }
    // A pidfd's inode is a regular file to the VFS, which pidfs_setattr
    // refuses to change.
    if super::pidfd::target_of(&file).is_some() {
        return Err(Errno(EOPNOTSUPP));
    }
    if !file.writable() || file.ftype != FileType::Regular {
        return Err(Errno(EINVAL));
    }
    match &file.object {
        FileObject::Host(f) => {
            if let Some(m) = &file.memfd {
                m.check_resize(f.metadata()?.len(), len as u64)?;
            }
            f.set_len(len as u64)?;
            c.p.space.truncated(fs::identity(f)?, len as u64);
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `fallocate`: mode 0 extends the file, `FALLOC_FL_KEEP_SIZE` only
/// reserves; hole punching and range manipulation are unsupported by the
/// emulated file system.
pub fn fallocate(c: &mut Ctx<'_>, fd: i32, mode: u32, off: i64, len: i64) -> SysResult {
    const FALLOC_FL_KEEP_SIZE: u32 = 1;
    let file = c.p.fds.file(fd)?;
    if off < 0 || len <= 0 {
        return Err(Errno(EINVAL));
    }
    if !file.writable() {
        return Err(Errno(EBADF));
    }
    // A pidfd is a regular file to vfs_fallocate, without the operation.
    if super::pidfd::target_of(&file).is_some() {
        return Err(Errno(EOPNOTSUPP));
    }
    if file.ftype != FileType::Regular {
        return Err(Errno(ENODEV));
    }
    let FileObject::Host(f) = &file.object else {
        return Err(Errno(ENODEV));
    };
    let end = (off as u64).checked_add(len as u64).ok_or(Errno(EFBIG))?;
    let size = f.metadata()?.len();
    match mode {
        0 | FALLOC_FL_KEEP_SIZE => {
            // shmem_fallocate: a grow seal refuses reaching past the end,
            // even when the size is kept.
            if let Some(m) = &file.memfd
                && end > size
            {
                m.check_resize(size, end)?;
            }
            if mode == 0 && size < end {
                f.set_len(end)?;
            }
            Ok(0)
        }
        _ => Err(Errno(EOPNOTSUPP)),
    }
}

/// Installs an open file at the lowest free descriptor.
pub fn install(c: &mut Ctx<'_>, file: Arc<OpenFile>, cloexec: bool) -> SysResult {
    let limit = nofile(c);
    c.p.fds.install(file, cloexec, limit).map(|n| n as u64)
}

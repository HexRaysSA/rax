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
use super::iov::import_iovec;
use super::ready::raw_fd;
use super::{Ctx, Outcome, RestartBlock, SysResult, is_blocked};
use crate::error::MemoryAccessKind;

/// `MAX_RW_COUNT`: `INT_MAX & PAGE_MASK`.
pub const MAX_RW_COUNT: u64 = 0x7fff_f000;

/// Host bounce-buffer size for one transfer step.
pub(super) const CHUNK: usize = 1 << 20;

pub(super) fn nofile(c: &Ctx<'_>) -> u64 {
    c.p.rlimits[7].0
}

/// Whether a transfer on `file` can block: pipes, FIFOs, sockets, and
/// character devices (terminals) without `O_NONBLOCK`.
pub(super) fn may_block(file: &OpenFile) -> bool {
    matches!(
        file.ftype,
        FileType::Fifo | FileType::Socket | FileType::CharDevice
    ) && file.flags() & O_NONBLOCK == 0
}

/// Whether a transfer on `file` would not sleep now: data, end of file,
/// or an error to report (`POLLIN`/`POLLHUP`/`POLLERR`), or (`write`) room
/// or a vanished reader (`POLLOUT`/`POLLERR`; a macOS pipe reports its
/// last reader closing as `POLLHUP`), so the write fails with `EPIPE`.
pub(super) fn ready_now(file: &OpenFile, write: bool) -> bool {
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
pub(super) fn wait_ready(c: &mut Ctx<'_>, file: &OpenFile, write: bool, resume: Resume) -> Errno {
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
/// The bytes of `[addr, addr + len)` that can be read before a fault.
pub(super) fn readable_prefix(c: &Ctx<'_>, addr: u64, len: u64) -> u64 {
    match c.p.space.probe(addr, len as usize, MemoryAccessKind::Read) {
        Ok(()) => len,
        Err(f) => f.address.saturating_sub(addr).min(len),
    }
}

fn writable_prefix(c: &Ctx<'_>, addr: u64, len: u64) -> u64 {
    match c.p.space.probe(addr, len as usize, MemoryAccessKind::Write) {
        Ok(()) => len,
        Err(f) => f.address.saturating_sub(addr).min(len),
    }
}

/// A pipe or FIFO transfer that faults partway (`anon_pipe_write`,
/// `pipe_read`) moves whole pages of it: a write commits each page of the
/// source it copied whole and drops the one the fault cut short, and a read
/// consumes each pipe buffer it copied whole and leaves the one it could
/// not in the pipe, taking pipe buffers as page-aligned in the stream (as
/// consecutive small writes merge into them). Of a transfer of `total`
/// bytes whose first `ok` can be copied, the bytes moved; none is `EFAULT`.
fn pipe_moved(ok: u64, total: u64) -> u64 {
    const PAGE: u64 = 4096;
    if ok >= total { total } else { ok / PAGE * PAGE }
}

/// Of `count` bytes a pipe read may copy to a destination whose first
/// `room` bytes are writable, the bytes it takes (see [`pipe_moved`]); a
/// fault lies in the transfer only when the pipe holds more than `room`.
/// An empty pipe keeps `room`, so the read waits for data as usual.
fn pipe_read_room(file: &OpenFile, room: u64, count: u64) -> u64 {
    let avail = match &file.object {
        FileObject::PipeRead(p) => host::bytes_readable(p),
        FileObject::Host(f) => host::bytes_readable(f),
        _ => return room,
    };
    match avail {
        Ok(n) if n > 0 => pipe_moved(room, count.min(n as u64)),
        _ => room,
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
    let count = count.min(MAX_RW_COUNT);
    let mut room = writable_prefix(c, buf, count);
    if file.ftype == FileType::Fifo && room < count && room > 0 {
        room = pipe_read_room(file, room, count);
    }
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
            // A write that may not sleep ends with what it wrote
            // (IOCB_NOWAIT); none is EAGAIN.
            if c.nowait && done > 0 {
                return Ok(done as u64);
            }
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
    let mut readable = readable_prefix(c, buf, count);
    if file.ftype == FileType::Fifo {
        readable = pipe_moved(readable, count);
    }
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
    let n = read_into(c, &file, buf, count, None)?;
    super::notify::access(&file, n, false);
    Ok(n)
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
    let n = write_from(c, &file, buf, count, None)?;
    super::notify::modify(&file, n);
    Ok(n)
}

/// Scatters `data` over `iovecs`, stopping at the first fault.
pub(super) fn scatter(c: &Ctx<'_>, iovecs: &[(u64, u64)], data: &[u8]) -> SysResult {
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
    let iovecs = import_iovec(c, iov, cnt)?;
    let total: u64 = iovecs.iter().map(|&(_, l)| l).sum();
    // vfs_readv: fsnotify_access for any result that is not an error,
    // an empty transfer included.
    if total == 0 {
        super::notify::vectored_nothing(c, &file);
        return Ok(0);
    }
    if matches!(file.object, FileObject::Anon(_) | FileObject::Socket(_)) {
        return readv_file(c, &file, &iovecs, None);
    }
    let n = readv_file(c, &file, &iovecs, None)?;
    if n == 0 {
        super::notify::vectored_nothing(c, &file);
    } else {
        super::notify::access(&file, n, true);
    }
    Ok(n)
}

/// One read from `file` scattered over `iovecs` (imported, not all
/// empty), at `pos` on a file with positions or at the current position:
/// what `readv` does once the descriptor and vectors are checked, without
/// the notification.
pub(super) fn readv_file(
    c: &mut Ctx<'_>,
    file: &Arc<OpenFile>,
    iovecs: &[(u64, u64)],
    pos: Option<u64>,
) -> SysResult {
    let total: u64 = iovecs.iter().map(|&(_, l)| l).sum();
    if matches!(file.object, FileObject::Anon(_)) {
        return super::events::read(c, file, iovecs);
    }
    if matches!(file.object, FileObject::Socket(_)) {
        return super::net::io::read(c, file, iovecs);
    }
    let mut room = iovec_room(c, iovecs);
    let want = total.min(MAX_RW_COUNT);
    if file.ftype == FileType::Fifo && room < want && room > 0 {
        room = pipe_read_room(file, room, want);
    }
    if room == 0 {
        return Err(Errno(EFAULT));
    }
    let data = read_bytes(c, file, room, pos)?;
    scatter(c, iovecs, &data)
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
    let vecs = import_iovec(c, iov, cnt)?;
    if matches!(file.object, FileObject::Socket(_)) || anon {
        return writev_file(c, &file, &vecs, None);
    }
    let n = writev_file(c, &file, &vecs, None)?;
    super::notify::modify(&file, n);
    Ok(n)
}

/// One write to `file` of the bytes `vecs` gather (imported), at `pos` on
/// a file with positions or at the current position: what `writev` does
/// once the descriptor and vectors are checked, without the notification.
pub(super) fn writev_file(
    c: &mut Ctx<'_>,
    file: &Arc<OpenFile>,
    vecs: &[(u64, u64)],
    pos: Option<u64>,
) -> SysResult {
    if matches!(file.object, FileObject::Socket(_)) {
        return super::net::io::write(c, file, vecs);
    }
    if matches!(file.object, FileObject::Anon(_)) {
        if vecs.iter().all(|&(_, l)| l == 0) {
            return Ok(0);
        }
        return super::events::write(c, file, vecs);
    }
    // The bytes before the first fault, up to MAX_RW_COUNT.
    let total = vecs.iter().map(|&(_, l)| l).sum::<u64>().min(MAX_RW_COUNT);
    let mut data = Vec::new();
    for &(base, len) in vecs {
        let len = len.min(MAX_RW_COUNT - data.len() as u64);
        if len == 0 {
            continue;
        }
        let ok = readable_prefix(c, base, len);
        data.extend_from_slice(&c.read_mem(base, ok as usize)?);
        if ok < len {
            break;
        }
    }
    if file.ftype == FileType::Fifo {
        data.truncate(pipe_moved(data.len() as u64, total) as usize);
    }
    if data.is_empty() {
        return if total == 0 {
            Ok(0)
        } else {
            Err(Errno(EFAULT))
        };
    }
    write_bytes(c, file, &data, pos)
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
    let n = read_into(c, &file, buf, count, Some(pos as u64))?;
    super::notify::access(&file, n, false);
    Ok(n)
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
    let n = write_from(c, &file, buf, count, Some(pos as u64))?;
    super::notify::modify(&file, n);
    Ok(n)
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

/// `RWF_*` (`include/uapi/linux/fs.h`).
pub(super) mod rwf {
    pub const APPEND: u64 = 0x10;
    pub const NOAPPEND: u64 = 0x20;
    pub const ATOMIC: u64 = 0x40;
    pub const DONTCACHE: u64 = 0x80;
    pub const NOSIGNAL: u64 = 0x100;
    /// `RWF_SUPPORTED`: those and `RWF_HIPRI`, `RWF_DSYNC`, `RWF_SYNC`,
    /// and `RWF_NOWAIT`.
    pub const SUPPORTED: u64 = 0x1ff;
}

/// `kiocb_set_rw_flags`'s refusals of `RWF_*` flags for a transfer on
/// `file`: an unknown flag (`EOPNOTSUPP`), `RWF_APPEND` with
/// `RWF_NOAPPEND` (`EINVAL`), `RWF_ATOMIC` (`EOPNOTSUPP`: a read never
/// takes it, and no file here has `FMODE_CAN_ATOMIC_WRITE`, which needs
/// direct I/O on a file system with atomic write units), and
/// `RWF_DONTCACHE` on a file whose operations lack `FOP_DONTCACHE`
/// (`EOPNOTSUPP`; regular files are taken to have it). `RWF_NOSIGNAL`
/// ([`Ctx::nosignal`]) is the one flag with an effect here; the others
/// are hints.
pub(super) fn check_rw_flags(file: &OpenFile, flags: u64) -> Result<(), Errno> {
    if flags & !rwf::SUPPORTED != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    if flags & rwf::APPEND != 0 && flags & rwf::NOAPPEND != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & rwf::ATOMIC != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    if flags & rwf::DONTCACHE != 0 && file.ftype != FileType::Regular {
        return Err(Errno(EOPNOTSUPP));
    }
    Ok(())
}

/// `preadv` and `preadv2` at `pos`, or at the current position for `None`
/// (`preadv2`'s -1: `do_readv`). A negative position is `EINVAL` before
/// the descriptor is looked at (`do_preadv`).
pub fn preadv(
    c: &mut Ctx<'_>,
    fd: i32,
    iov: u64,
    cnt: u64,
    pos: Option<i64>,
    flags: u64,
) -> SysResult {
    if pos.is_some_and(|p| p < 0) {
        return Err(Errno(EINVAL));
    }
    if flags & !rwf::SUPPORTED != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    let file = c.p.fds.file(fd)?;
    check_rw_flags(&file, flags)?;
    if matches!(
        file.object,
        FileObject::Anon(_) | FileObject::Console { .. }
    ) {
        return if pos.is_some() {
            Err(Errno(positional(&file)))
        } else {
            readv(c, fd, iov, cnt)
        };
    }
    let mut total = 0;
    for (base, len) in import_iovec(c, iov, cnt)? {
        // An empty vector has nothing to copy (and so nothing to fault).
        if len == 0 {
            continue;
        }
        let at = pos.map(|p| p as u64 + total);
        // do_iter_readv_writev: a fault after some bytes ends the transfer
        // with them.
        let n = match read_into(c, &file, base, len, at) {
            Ok(n) => n,
            Err(Errno(EFAULT)) if total > 0 => break,
            Err(e) => return Err(e),
        };
        total += n;
        if n < len {
            break;
        }
    }
    if total == 0 {
        super::notify::vectored_nothing(c, &file);
    } else {
        super::notify::access(&file, total, true);
    }
    Ok(total)
}

/// `pwritev` and `pwritev2`, as [`preadv`].
pub fn pwritev(
    c: &mut Ctx<'_>,
    fd: i32,
    iov: u64,
    cnt: u64,
    pos: Option<i64>,
    flags: u64,
) -> SysResult {
    if pos.is_some_and(|p| p < 0) {
        return Err(Errno(EINVAL));
    }
    if flags & !rwf::SUPPORTED != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    let file = c.p.fds.file(fd)?;
    check_rw_flags(&file, flags)?;
    c.nosignal = flags & rwf::NOSIGNAL != 0;
    if matches!(
        file.object,
        FileObject::Anon(_) | FileObject::Console { .. }
    ) {
        return if pos.is_some() {
            Err(Errno(positional(&file)))
        } else {
            writev(c, fd, iov, cnt)
        };
    }
    let mut total = 0;
    for (base, len) in import_iovec(c, iov, cnt)? {
        if len == 0 {
            continue;
        }
        let at = pos.map(|p| p as u64 + total);
        let n = match write_from(c, &file, base, len, at) {
            Ok(n) => n,
            Err(Errno(EFAULT)) if total > 0 => break,
            Err(e) => return Err(e),
        };
        total += n;
        if n < len {
            break;
        }
    }
    super::notify::modify(&file, total);
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
    let (rf, wf) = pipe_files(c, flags)?;
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

/// `__do_pipe_flags` and `create_pipe_files`: the read and write ends of
/// a new pipe, for `O_CLOEXEC`, `O_NONBLOCK`, `O_DIRECT`, and
/// `O_NOTIFICATION_PIPE` (others are `EINVAL`). A notification pipe needs
/// `CONFIG_WATCH_QUEUE`, which the kernel modelled lacks (`ENOPKG`).
pub(super) fn pipe_files(c: &Ctx<'_>, flags: u32) -> Result<(Arc<OpenFile>, Arc<OpenFile>), Errno> {
    let direct = c.p.abi.open_flags().direct;
    let notification = O_EXCL;
    if flags & !(O_CLOEXEC | O_NONBLOCK | direct | notification) != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & notification != 0 {
        return Err(Errno(ENOPKG));
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
    Ok((rf, wf))
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
/// left back to `user` for a nonzero timeout (a 32-bit caller's `struct
/// old_timeval32`, or its `timespec` as [`Ctx::put_timespec`] writes it). If
/// that write faults the call cannot be restarted, so `-ERESTARTNOHAND`
/// becomes `-EINTR`.
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
    let secs = left.as_secs() as i64;
    let written = match format {
        TimeFormat::Timeval if c.compat => {
            let mut b = [0u8; 8];
            b[..4].copy_from_slice(&(secs as i32).to_le_bytes());
            b[4..].copy_from_slice(&(left.subsec_micros() as i32).to_le_bytes());
            c.write_mem(user, &b)
        }
        TimeFormat::Timeval => {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&secs.to_le_bytes());
            b[8..].copy_from_slice(&i64::from(left.subsec_micros()).to_le_bytes());
            c.write_mem(user, &b)
        }
        TimeFormat::Timespec => c.put_timespec(
            user,
            super::super::abi::types::Timespec {
                sec: secs,
                nsec: i64::from(left.subsec_nanos()),
            },
        ),
    };
    if written.is_ok() {
        return result;
    }
    if interrupted {
        Err(Errno(EINTR))
    } else {
        result
    }
}

/// A `timespec` timeout (`struct __kernel_timespec`, or for a `*_time32`
/// call `struct old_timespec32`) as a deadline, and whether it is zero;
/// none without a pointer.
fn timespec_deadline(c: &Ctx<'_>, tsp: u64) -> Result<(Option<Instant>, bool), Errno> {
    if tsp == 0 {
        return Ok((None, false));
    }
    let ts = c.get_timespec(tsp)?;
    Ok((
        Some(timeout_deadline(ts.sec, ts.nsec).ok_or(Errno(EINVAL))?),
        ts.sec == 0 && ts.nsec == 0,
    ))
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
            let (deadline, zero) = timespec_deadline(c, tsp)?;
            set_user_sigmask(c, mask, size)?;
            (deadline, zero)
        }
    };
    let result = sys_poll(c, fds, nfds, deadline);
    poll_select_finish(c, deadline, zero, tsp, TimeFormat::Timespec, result)
}

/// `core_sys_select`: `nfds` is clamped to the descriptor table size; a set
/// bit for a descriptor that is not open is `EBADF`. An interrupted select
/// leaves the sets as they were. The sets are read and written in whole
/// `long`s, a 32-bit caller's 4 bytes each (`compat_core_sys_select`,
/// `compat_get_bitmap`).
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
    // The sets as little-endian bitmaps of whole longs.
    let long = if c.compat { 4 } else { 8 };
    let bytes = n.div_ceil(long * 8) * long;
    let read_set = |c: &Ctx<'_>, addr: u64| -> Result<Vec<u8>, Errno> {
        if addr == 0 {
            return Ok(vec![0; bytes]);
        }
        c.read_mem(addr, bytes)
    };
    let (rs, ws, es) = (read_set(c, rd)?, read_set(c, wr)?, read_set(c, ex)?);
    let bit = |set: &[u8], fd: usize| set[fd / 8] >> (fd % 8) & 1 != 0;
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
    let (mut ro, mut wo, mut eo) = (vec![0u8; bytes], vec![0u8; bytes], vec![0u8; bytes]);
    let mut count = 0;
    for (&(fd, ev), r) in req.iter().zip(rev) {
        let set = |v: &mut Vec<u8>| v[fd as usize / 8] |= 1 << (fd % 8);
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
            c.write_mem(addr, v)?;
        }
    }
    Ok(Outcome::Return(count))
}

/// `select` (`struct timeval` timeout, a 32-bit caller's `struct
/// old_timeval32`; microseconds beyond a second are carried into seconds,
/// as `kern_select` and `do_compat_select` do).
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
        let (sec, usec) = if c.compat {
            let b = c.read_mem(tvp, 8)?;
            let w = |i: usize| i64::from(i32::from_le_bytes(b[i..i + 4].try_into().unwrap()));
            (w(0), w(4))
        } else {
            let b = c.read_mem(tvp, 16)?;
            (
                i64::from_le_bytes(b[..8].try_into().unwrap()),
                i64::from_le_bytes(b[8..].try_into().unwrap()),
            )
        };
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
/// passed as `{const sigset_t *ss; size_t ss_len;}` (a 32-bit caller's
/// `struct compat_sigset_argpack` of two words).
pub fn pselect6(
    c: &mut Ctx<'_>,
    nfds: i32,
    rd: u64,
    wr: u64,
    ex: u64,
    tsp: u64,
    sig: u64,
) -> Result<Outcome, Errno> {
    let (mask, size) = if sig == 0 || c.resume.is_some() {
        (0, 0)
    } else if c.compat {
        let b = c.read_mem(sig, 8)?;
        let w = |i: usize| u64::from(u32::from_le_bytes(b[i..i + 4].try_into().unwrap()));
        (w(0), w(4))
    } else {
        let b = c.read_mem(sig, 16)?;
        (
            u64::from_le_bytes(b[..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..].try_into().unwrap()),
        )
    };
    let (deadline, zero) = match resumed_deadline(c) {
        Some(d) => (d, false),
        None => {
            let (deadline, zero) = timespec_deadline(c, tsp)?;
            set_user_sigmask(c, mask, size)?;
            (deadline, zero)
        }
    };
    let result = core_sys_select(c, nfds, rd, wr, ex, deadline);
    poll_select_finish(c, deadline, zero, tsp, TimeFormat::Timespec, result)
}

/// `fsync`/`fdatasync`.
pub fn fsync(c: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    fsync_file(&file)
}

/// `vfs_fsync_range` on an open file.
pub(super) fn fsync_file(file: &OpenFile) -> SysResult {
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
pub fn fadvise(c: &mut Ctx<'_>, fd: i32, len: i64, advice: u32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    fadvise_file(&file, len, advice)
}

/// `vfs_fadvise` (`generic_fadvise`) on an open file.
pub(super) fn fadvise_file(file: &OpenFile, len: i64, advice: u32) -> SysResult {
    if file.ftype == FileType::Fifo {
        return Err(Errno(ESPIPE));
    }
    // generic_fadvise: a length negative as a loff_t.
    if len < 0 || advice > 5 {
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
    let file = c.p.fds.file(fd)?;
    if matches!(file.object, FileObject::PathOnly) {
        return Err(Errno(EBADF));
    }
    sync_file_range_file(&file, offset, nbytes, flags)
}

/// `sync_file_range` on an open file (not an `O_PATH` one).
pub(super) fn sync_file_range_file(
    file: &OpenFile,
    offset: i64,
    nbytes: i64,
    flags: u32,
) -> SysResult {
    const WRITE: u32 = 2;
    const VALID: u32 = 1 | WRITE | 4;
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

/// `ftruncate`.
pub fn ftruncate(c: &mut Ctx<'_>, fd: i32, len: i64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    ftruncate_file(c, &file, len)
}

/// `do_ftruncate` on an open file.
pub(super) fn ftruncate_file(c: &mut Ctx<'_>, file: &OpenFile, len: i64) -> SysResult {
    if len < 0 {
        return Err(Errno(EINVAL));
    }
    // A pidfd's inode is a regular file to the VFS, which pidfs_setattr
    // refuses to change.
    if super::pidfd::target_of(file).is_some() {
        return Err(Errno(EOPNOTSUPP));
    }
    if !file.writable() || file.ftype != FileType::Regular {
        return Err(Errno(EINVAL));
    }
    match &file.object {
        FileObject::Mqueue(h) => super::mqueue::truncate(file, h, len),
        FileObject::Host(f) => {
            if let Some(m) = &file.memfd {
                m.check_resize(f.metadata()?.len(), len as u64)?;
            }
            f.set_len(len as u64)?;
            c.p.space.truncated(fs::identity(f)?, len as u64);
            // do_truncate: ATTR_SIZE with the times.
            super::notify::changed_file(file, super::super::fsnotify::bits::IN_MODIFY);
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `fallocate`: mode 0 extends the file, `FALLOC_FL_KEEP_SIZE` only
/// reserves; hole punching and range manipulation are unsupported by the
/// emulated file system.
pub fn fallocate(c: &mut Ctx<'_>, fd: i32, mode: u32, off: i64, len: i64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    fallocate_file(&file, mode, off, len)
}

/// `vfs_fallocate` on an open file.
pub(super) fn fallocate_file(file: &OpenFile, mode: u32, off: i64, len: i64) -> SysResult {
    const FALLOC_FL_KEEP_SIZE: u32 = 1;
    if off < 0 || len <= 0 {
        return Err(Errno(EINVAL));
    }
    if !file.writable() {
        return Err(Errno(EBADF));
    }
    // A pidfd is a regular file to vfs_fallocate, without the operation.
    if super::pidfd::target_of(file).is_some() {
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
            super::notify::allocated(file);
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

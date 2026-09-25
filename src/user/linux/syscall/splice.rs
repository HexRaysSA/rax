//! `splice`, `vmsplice`, and `tee` (`fs/splice.c`, Linux 6.19).
//!
//! Pipes here are host pipes, whose buffers the host kernel keeps, so data
//! moves by reading and writing. The checks come in the kernel's order; a
//! transfer sleeps where the kernel's does (for data before anything
//! moved, for room) and, once anything has moved, moves what there is
//! without sleeping. It never takes from a pipe or a stream more than its
//! destination takes at once: a writable host pipe has room for `PIPE_BUF`
//! bytes, and a writable socket or terminal for [`STREAM_STEP`], so data
//! moves in steps of that size. Bytes taken from a stream that the
//! destination then does not take (another writer took the room) are held
//! by the call, which sleeps, killably, until they are written. A transfer
//! ends where the host pipe is full, which is not where the kernel's pipe
//! buffers would fill.
//!
//! `tee` needs the host's own `tee(2)` (Linux hosts): elsewhere a pipe
//! cannot be read without consuming it, and `tee` fails with `EINVAL` as
//! for descriptors that are not pipes.

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::{O_APPEND, O_NONBLOCK, O_PATH};
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::host;
use super::super::wait::{Resume, Wait};
use super::io::{MAX_RW_COUNT, iovec_room, scatter, wait_ready};
use super::iov::import_iovec;
use super::ready::raw_fd;
use super::{Ctx, SysResult};
use crate::error::MemoryAccessKind;

/// `SPLICE_F_NONBLOCK`, and every `SPLICE_F_*` flag (`SPLICE_F_ALL`).
const NONBLOCK: u32 = 2;
const ALL: u32 = 0xf;
/// Bytes a writable host pipe takes at once (`PIPE_BUF`: a page on Linux
/// hosts, 512 bytes on macOS).
const STEP: u64 = libc::PIPE_BUF as u64;
/// Bytes a writable socket or terminal takes at once: the smaller send
/// low-water mark of the hosts.
const STREAM_STEP: u64 = 2048;
/// Bytes a regular file takes from a pipe at a time.
const FILE_STEP: u64 = 1 << 20;
/// `SEEK_SET`, `SEEK_CUR`.
const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;

/// `CLASS(fd)`: an open description, not an `O_PATH` one (`EBADF`).
fn fdget(c: &Ctx<'_>, fd: i32) -> Result<Arc<OpenFile>, Errno> {
    let f = c.p.fds.file(fd)?;
    if matches!(f.object, FileObject::PathOnly) || f.flags() & O_PATH != 0 {
        return Err(Errno(EBADF));
    }
    Ok(f)
}

/// `get_pipe_info`: a pipe or a FIFO.
fn is_pipe(f: &OpenFile) -> bool {
    match f.object {
        FileObject::PipeRead(_) | FileObject::PipeWrite(_) => true,
        FileObject::Host(_) => f.ftype == FileType::Fifo,
        _ => false,
    }
}

/// Whether two descriptions are of one pipe: one description, the two
/// ends the guest's `pipe` made, or one host inode (a FIFO's; on Linux
/// hosts an anonymous pipe's, which both ends share).
fn same_pipe(a: &Arc<OpenFile>, b: &Arc<OpenFile>) -> bool {
    if Arc::ptr_eq(a, b) {
        return true;
    }
    let peer_of = |x: &OpenFile, y: &Arc<OpenFile>| {
        x.peer
            .lock()
            .unwrap()
            .upgrade()
            .is_some_and(|p| Arc::ptr_eq(&p, y))
    };
    if peer_of(a, b) || peer_of(b, a) {
        return true;
    }
    matches!((pipe_inode(a), pipe_inode(b)), (Some(x), Some(y)) if x == y)
}

fn pipe_inode(f: &OpenFile) -> Option<(u64, u64)> {
    if !cfg!(target_os = "linux") && !matches!(f.object, FileObject::Host(_)) {
        return None;
    }
    super::super::fs::locks::identity(raw_fd(f)?)
}

/// A terminal: opened by `nonseekable_open`.
fn is_tty(f: &OpenFile) -> bool {
    use std::io::IsTerminal;
    matches!(&f.object, FileObject::Host(h) if f.ftype == FileType::CharDevice && h.is_terminal())
}

/// `FMODE_PREAD` and `FMODE_PWRITE`: a file with positions (not a pipe,
/// socket, terminal, or anonymous file).
fn has_positions(f: &OpenFile) -> bool {
    match &f.object {
        FileObject::Host(_) => match f.ftype {
            FileType::Regular | FileType::BlockDevice | FileType::Directory => true,
            FileType::CharDevice => !is_tty(f),
            _ => false,
        },
        FileObject::Synthetic(_) | FileObject::Mqueue(_) => true,
        _ => false,
    }
}

/// Whether transfers read or write at a position: regular files and
/// synthesized ones.
fn positioned(f: &OpenFile) -> bool {
    match &f.object {
        FileObject::Host(_) => f.ftype == FileType::Regular,
        FileObject::Synthetic(_) => true,
        _ => false,
    }
}

/// `f_op->splice_read`: regular files (`filemap_splice_read`), sockets,
/// terminals and the memory devices but `/dev/null` (`copy_splice_read`),
/// and synthesized `/proc` files, taken to be `read_iter` ones.
fn has_splice_read(f: &OpenFile) -> bool {
    match &f.object {
        FileObject::Host(_) => match f.ftype {
            FileType::Regular => true,
            FileType::CharDevice => f.path != "/dev/null",
            _ => false,
        },
        FileObject::Socket(_) | FileObject::Synthetic(_) => true,
        _ => false,
    }
}

/// `f_op->splice_write`: regular files and terminals
/// (`iter_file_splice_write`), sockets (`splice_to_socket`), and the
/// memory devices but `/dev/full`.
fn has_splice_write(f: &OpenFile) -> bool {
    match &f.object {
        FileObject::Host(_) => match f.ftype {
            FileType::Regular => true,
            FileType::CharDevice => f.path != "/dev/full",
            _ => false,
        },
        FileObject::Socket(_) => true,
        _ => false,
    }
}

/// `rw_verify_area` over `len` bytes from `pos`.
fn verify_area(pos: i64, len: u64) -> Result<(), Errno> {
    if (len as i64) < 0 || pos < 0 || pos.checked_add(len as i64).is_none() {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// Bytes queued in a pipe, FIFO, socket, or terminal.
fn queued(f: &OpenFile) -> u64 {
    let n = match &f.object {
        FileObject::PipeRead(p) => host::bytes_readable(p),
        FileObject::Host(h) => host::bytes_readable(h),
        FileObject::Socket(s) => host::bytes_readable(&s.file),
        _ => Ok(0),
    };
    n.unwrap_or(0).max(0) as u64
}

fn readiness(f: &OpenFile, read: bool, write: bool) -> host::Readiness {
    raw_fd(f)
        .and_then(|fd| host::poll(&[(fd, read, write)], 0).ok())
        .map(|r| r[0])
        .unwrap_or_default()
}

/// Readiness of a stream destination or source: a memory device is always
/// ready (and macOS hosts do not poll devices).
fn stream_readiness(f: &OpenFile, read: bool, write: bool) -> host::Readiness {
    if f.ftype == FileType::CharDevice && !is_tty(f) {
        return host::Readiness {
            readable: read,
            writable: write,
            ..Default::default()
        };
    }
    readiness(f, read, write)
}

/// A pipe or stream with no reader left: writes fail with `EPIPE` (Linux
/// reports `POLLERR`, macOS `POLLHUP`).
fn broken(r: host::Readiness) -> bool {
    r.error || r.hangup
}

/// Reads at most `n` bytes from a stream without sleeping: empty at its
/// end, `EAGAIN` while there is nothing yet.
fn take(f: &OpenFile, n: u64) -> Result<Vec<u8>, Errno> {
    let mut b = vec![0u8; n as usize];
    let got = match &f.object {
        FileObject::Socket(s) => {
            super::super::net::sys::recv(&s.file, &mut b, libc::MSG_DONTWAIT).map(|(n, _)| n)?
        }
        _ => f.read(&mut b)?,
    };
    b.truncate(got);
    Ok(b)
}

/// Writes to a pipe, stream, or file (at `pos`) without sleeping: the
/// bytes it took.
fn put(f: &OpenFile, data: &[u8], pos: Option<u64>) -> Result<usize, Errno> {
    #[cfg(target_os = "linux")]
    let quiet = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let quiet = 0;
    match (&f.object, pos) {
        (FileObject::Socket(s), _) => {
            super::super::net::sys::send(&s.file, data, libc::MSG_DONTWAIT | quiet, None)
        }
        (_, Some(p)) => f.write_at(data, p),
        (_, None) => f.write(data),
    }
}

/// `ipipe_prep` and `splice_from_pipe_next`: whether the pipe holds data
/// (`false` at its end: no writers and nothing queued); otherwise `EAGAIN`
/// or a sleep.
fn wait_data(c: &mut Ctx<'_>, f: &OpenFile, nonblock: bool) -> Result<bool, Errno> {
    if queued(f) > 0 {
        return Ok(true);
    }
    let r = readiness(f, true, false);
    if r.readable || r.hangup || r.error {
        return Ok(queued(f) > 0);
    }
    if nonblock {
        return Err(Errno(EAGAIN));
    }
    Err(wait_ready(c, f, false, Resume::Retry))
}

/// `wait_for_space` and `opipe_prep`: room in the pipe, or `EPIPE` without
/// readers (the dispatcher sends `SIGPIPE`), `EAGAIN`, or a sleep.
fn wait_room(c: &mut Ctx<'_>, f: &OpenFile, nonblock: bool) -> Result<(), Errno> {
    let r = readiness(f, false, true);
    if broken(r) {
        return Err(Errno(EPIPE));
    }
    if r.writable {
        return Ok(());
    }
    if nonblock {
        return Err(Errno(EAGAIN));
    }
    Err(wait_ready(c, f, true, Resume::Retry))
}

/// `send_sig(SIGPIPE, current, 0)` for a transfer that moved bytes before
/// its pipe lost its readers (and so returns them, not `EPIPE`).
fn sigpipe(c: &mut Ctx<'_>) {
    c.send_sigpipe();
    c.sigpipe_decided = true;
}

/// Bytes taken from a stream that the destination did not take: written
/// before the call returns, the call sleeping for room (only the process's
/// exit ends that sleep). `done` counts them; bytes the destination then
/// refuses (it lost its readers) are lost and not counted.
fn hold(c: &mut Ctx<'_>, output: &OpenFile, done: u64, mut pending: Vec<u8>) -> SysResult {
    while !pending.is_empty() {
        match put(output, &pending, None) {
            Ok(w) if w > 0 => {
                pending.drain(..w);
            }
            Ok(_) | Err(Errno(EAGAIN)) => {
                let Some(fd) = raw_fd(output) else {
                    break;
                };
                let mut wait = Wait::fd(fd, false, true);
                wait.interruptible = false;
                return Err(c.block(wait, Resume::Spliced { done, pending }));
            }
            Err(e) => {
                let written = done - pending.len() as u64;
                return if written > 0 { Ok(written) } else { Err(e) };
            }
        }
    }
    Ok(done - pending.len() as u64)
}

/// Writes `data`, taken from a stream, to `output`: what the destination
/// does not take is held ([`hold`]); `Ok(None)` when all of it went.
fn forward(c: &mut Ctx<'_>, output: &OpenFile, moved: u64, data: Vec<u8>) -> Option<SysResult> {
    match put(output, &data, None) {
        Ok(w) if w == data.len() => None,
        Ok(w) => Some(hold(
            c,
            output,
            moved + data.len() as u64,
            data[w..].to_vec(),
        )),
        Err(Errno(EAGAIN)) => Some(hold(c, output, moved + data.len() as u64, data)),
        Err(e) => Some(if moved > 0 { Ok(moved) } else { Err(e) }),
    }
}

/// `splice_pipe_to_pipe`: data moves while the input holds some and the
/// output has room; the bytes moved (0 at the input's end).
fn pipe_to_pipe(
    c: &mut Ctx<'_>,
    input: &OpenFile,
    output: &OpenFile,
    len: u64,
    nonblock: bool,
) -> SysResult {
    loop {
        let has_data = wait_data(c, input, nonblock)?;
        wait_room(c, output, nonblock)?;
        let mut moved = 0;
        while moved < len {
            let r = readiness(output, false, true);
            if broken(r) {
                if moved == 0 {
                    return Err(Errno(EPIPE));
                }
                sigpipe(c);
                return Ok(moved);
            }
            let q = queued(input);
            if q == 0 || !r.writable {
                break;
            }
            let data = match take(input, (len - moved).min(q).min(STEP)) {
                Ok(d) if !d.is_empty() => d,
                _ => break,
            };
            let n = data.len() as u64;
            if let Some(r) = forward(c, output, moved, data) {
                return r;
            }
            moved += n;
        }
        // Nothing moved though both were ready: another reader or writer
        // came first. Prepare again, unless the input has ended.
        if moved > 0 || !has_data {
            return Ok(moved);
        }
    }
}

/// `splice_file_to_pipe`: room in the pipe first, then as much of the
/// input as fits (for a stream, what it has, sleeping only for its first
/// bytes). The bytes moved.
fn to_pipe(
    c: &mut Ctx<'_>,
    input: &OpenFile,
    pos: Option<u64>,
    output: &OpenFile,
    len: u64,
    nonblock: bool,
) -> SysResult {
    wait_room(c, output, nonblock)?;
    if !has_splice_read(input) {
        return Err(Errno(EINVAL));
    }
    let len = len.min(MAX_RW_COUNT);
    let mut moved = 0;
    while moved < len {
        let r = readiness(output, false, true);
        if broken(r) || !r.writable {
            break;
        }
        let n = (len - moved).min(STEP);
        if let Some(p) = pos {
            // At a position: what the pipe does not take stays unread.
            let mut b = vec![0u8; n as usize];
            let got = match input.read_at(&mut b, p + moved) {
                Ok(got) => got,
                Err(e) if moved == 0 => return Err(e),
                Err(_) => break,
            };
            if got == 0 {
                break;
            }
            let w = match put(output, &b[..got], None) {
                Ok(w) => w,
                Err(Errno(EAGAIN)) => 0,
                Err(e) if moved == 0 => return Err(e),
                Err(_) => break,
            };
            moved += w as u64;
            if w < got {
                break;
            }
            continue;
        }
        // A stream: it sleeps for its first bytes (a socket also when the
        // pipe or the socket is non-blocking).
        let data = match take(input, n) {
            Ok(d) => d,
            Err(Errno(EAGAIN)) if moved == 0 => {
                let own = input.flags() & O_NONBLOCK != 0;
                let socket = matches!(input.object, FileObject::Socket(_));
                if own || (socket && nonblock) {
                    return Err(Errno(EAGAIN));
                }
                return Err(wait_ready(c, input, false, Resume::Retry));
            }
            Err(Errno(EAGAIN)) => break,
            Err(e) if moved == 0 => return Err(e),
            Err(_) => break,
        };
        if data.is_empty() {
            break;
        }
        let n = data.len() as u64;
        if let Some(r) = forward(c, output, moved, data) {
            return r;
        }
        moved += n;
    }
    Ok(moved)
}

/// `do_splice_from`: the output's `splice_write`, which sleeps for the
/// pipe's first bytes (not at its end) and then takes what the pipe holds;
/// a stream output sleeps for room as a write does (`EAGAIN` when it is
/// non-blocking). The bytes moved.
fn from_pipe(
    c: &mut Ctx<'_>,
    input: &OpenFile,
    output: &OpenFile,
    pos: Option<u64>,
    len: u64,
    nonblock: bool,
) -> SysResult {
    if !has_splice_write(output) {
        return Err(Errno(EINVAL));
    }
    let mut moved = 0;
    while moved < len {
        let q = queued(input);
        if q == 0 {
            if moved > 0 || !wait_data(c, input, nonblock)? {
                break;
            }
            continue;
        }
        if let Some(p) = pos {
            let data = match take(input, (len - moved).min(q).min(FILE_STEP)) {
                Ok(d) if !d.is_empty() => d,
                _ => break,
            };
            // A file takes all of it but for an error (no space, a file
            // too large), which loses the rest.
            let mut done = 0;
            while done < data.len() {
                match put(output, &data[done..], Some(p + moved + done as u64)) {
                    Ok(w) if w > 0 => done += w,
                    Ok(_) => break,
                    Err(e) if moved + (done as u64) == 0 => return Err(e),
                    Err(_) => break,
                }
            }
            moved += done as u64;
            if done < data.len() {
                break;
            }
            continue;
        }
        let r = stream_readiness(output, false, true);
        if broken(r) {
            return if moved > 0 {
                Ok(moved)
            } else {
                Err(Errno(EPIPE))
            };
        }
        if !r.writable {
            if moved > 0 {
                break;
            }
            if output.flags() & O_NONBLOCK != 0 {
                return Err(Errno(EAGAIN));
            }
            return Err(wait_ready(c, output, true, Resume::Retry));
        }
        let data = match take(input, (len - moved).min(q).min(STREAM_STEP)) {
            Ok(d) if !d.is_empty() => d,
            _ => break,
        };
        let n = data.len() as u64;
        if let Some(r) = forward(c, output, moved, data) {
            return r;
        }
        moved += n;
    }
    Ok(moved)
}

/// A position read from `*at`.
fn read_pos(c: &Ctx<'_>, at: u64) -> Result<Option<i64>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    Ok(Some(c.read_u64(at)? as i64))
}

/// A file's own position, where it has one.
fn file_pos(f: &OpenFile) -> Result<i64, Errno> {
    if positioned(f) || f.ftype == FileType::BlockDevice {
        return Ok(f.seek(0, SEEK_CUR)? as i64);
    }
    Ok(0)
}

/// The position after `n` bytes moved at `start`: written back to `*at`,
/// or made the file's own.
fn store_pos(c: &mut Ctx<'_>, f: &OpenFile, at: u64, start: i64, n: u64) -> Result<(), Errno> {
    let end = start + n as i64;
    if at != 0 {
        return c.write_u64(at, end as u64);
    }
    if positioned(f) {
        f.seek(end, SEEK_SET)?;
    }
    Ok(())
}

/// `fsnotify_modify` of the output, then `fsnotify_access` of the input.
fn notify(input: &OpenFile, output: &OpenFile, n: u64) {
    super::notify::modify(output, n);
    super::notify::access(input, n, false);
}

/// `splice`: the length (0 is 0 at once), the flags, the descriptors, the
/// offsets a pipe side cannot have (`ESPIPE`), `*off_out` then `*off_in`
/// (`EFAULT`), the access modes (`EBADF`); then a pipe to a pipe (not
/// itself), a pipe to a file (a position only where it has them, never
/// `O_APPEND`), or a file to a pipe, with `rw_verify_area` on the file;
/// two files are `EINVAL`. The offset moves past what moved.
pub fn splice(
    c: &mut Ctx<'_>,
    fd_in: i32,
    off_in: u64,
    fd_out: i32,
    off_out: u64,
    len: u64,
    flags: u32,
) -> SysResult {
    let resumed = c.resume.take();
    if len == 0 {
        return Ok(0);
    }
    if flags & !ALL != 0 {
        return Err(Errno(EINVAL));
    }
    let input = fdget(c, fd_in)?;
    let output = fdget(c, fd_out)?;
    if let Some(Resume::Spliced { done, pending }) = resumed {
        // Bytes this call took and holds: once written, it returns.
        let n = hold(c, &output, done, pending)?;
        notify(&input, &output, n);
        return Ok(n);
    }
    let (ipipe, opipe) = (is_pipe(&input), is_pipe(&output));
    if (ipipe && off_in != 0) || (opipe && off_out != 0) {
        return Err(Errno(ESPIPE));
    }
    let out_pos = read_pos(c, off_out)?;
    let in_pos = read_pos(c, off_in)?;
    if !input.fmode().0 || !output.fmode().1 {
        return Err(Errno(EBADF));
    }
    let nonblock = flags & NONBLOCK != 0;
    let n = if ipipe && opipe {
        if same_pipe(&input, &output) {
            return Err(Errno(EINVAL));
        }
        let nb = nonblock || (input.flags() | output.flags()) & O_NONBLOCK != 0;
        pipe_to_pipe(c, &input, &output, len, nb)?
    } else if ipipe {
        if out_pos.is_some() && !has_positions(&output) {
            return Err(Errno(EINVAL));
        }
        let start = match out_pos {
            Some(p) => p,
            None => file_pos(&output)?,
        };
        if output.flags() & O_APPEND != 0 {
            return Err(Errno(EINVAL));
        }
        verify_area(start, len)?;
        let nb = nonblock || input.flags() & O_NONBLOCK != 0;
        let at = positioned(&output).then_some(start as u64);
        let n = from_pipe(c, &input, &output, at, len, nb)?;
        store_pos(c, &output, off_out, start, n)?;
        n
    } else if opipe {
        if in_pos.is_some() && !has_positions(&input) {
            return Err(Errno(EINVAL));
        }
        let start = match in_pos {
            Some(p) => p,
            None => file_pos(&input)?,
        };
        verify_area(start, len)?;
        let nb = nonblock || output.flags() & O_NONBLOCK != 0;
        let at = positioned(&input).then_some(start as u64);
        let n = to_pipe(c, &input, at, &output, len, nb)?;
        // copy_splice_read leaves a device's position where it was.
        if at.is_some() {
            store_pos(c, &input, off_in, start, n)?;
        }
        n
    } else {
        return Err(Errno(EINVAL));
    };
    notify(&input, &output, n);
    Ok(n)
}

/// `vmsplice`: the flags, the descriptor and its direction (`FMODE_WRITE`
/// fills the pipe, else `FMODE_READ` empties it, else `EBADF`), the
/// vectors, then nothing to move (0, whatever the file) or a file that is
/// not a pipe (`EBADF`). Only `SPLICE_F_NONBLOCK` keeps it from sleeping.
pub fn vmsplice(c: &mut Ctx<'_>, fd: i32, iov: u64, nr_segs: u64, flags: u32) -> SysResult {
    if flags & !ALL != 0 {
        return Err(Errno(EINVAL));
    }
    let file = fdget(c, fd)?;
    let fill = match file.fmode() {
        (_, true) => true,
        (true, false) => false,
        (false, false) => return Err(Errno(EBADF)),
    };
    let vecs = import_iovec(c, iov, nr_segs)?;
    let total: u64 = vecs.iter().map(|&(_, l)| l).sum();
    if total == 0 {
        return Ok(0);
    }
    if !is_pipe(&file) {
        return Err(Errno(EBADF));
    }
    let nonblock = flags & NONBLOCK != 0;
    if fill {
        return vmsplice_to_pipe(c, &file, &vecs, nonblock);
    }
    // vmsplice_to_user: the pipe's data as it comes, up to the first byte
    // the vectors cannot take.
    if !wait_data(c, &file, nonblock)? {
        return Ok(0);
    }
    let room = iovec_room(c, &vecs);
    if room == 0 {
        return Err(Errno(EFAULT));
    }
    let data = match take(&file, total.min(room).min(queued(&file))) {
        Ok(d) => d,
        Err(Errno(EAGAIN)) => return Ok(0),
        Err(e) => return Err(e),
    };
    let n = scatter(c, &vecs, &data)?;
    super::notify::access(&file, n, false);
    Ok(n)
}

/// `vmsplice_to_pipe`: room first (`EPIPE` without readers), then the
/// vectors' bytes while the pipe has room, up to the first that cannot be
/// read (`EFAULT` when that is the first).
fn vmsplice_to_pipe(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    vecs: &[(u64, u64)],
    nonblock: bool,
) -> SysResult {
    wait_room(c, file, nonblock)?;
    let mut moved = 0u64;
    'vectors: for &(base, len) in vecs {
        let mut at = 0;
        while at < len {
            let r = readiness(file, false, true);
            if broken(r) {
                if moved == 0 {
                    return Err(Errno(EPIPE));
                }
                sigpipe(c);
                break 'vectors;
            }
            if !r.writable {
                break 'vectors;
            }
            let n = (len - at).min(STEP);
            let readable = match c
                .p
                .space
                .probe(base + at, n as usize, MemoryAccessKind::Read)
            {
                Ok(()) => n,
                Err(f) => f.address.saturating_sub(base + at).min(n),
            };
            if readable == 0 {
                if moved == 0 {
                    return Err(Errno(EFAULT));
                }
                break 'vectors;
            }
            let data = c.read_mem(base + at, readable as usize)?;
            let w = match file.write(&data) {
                Ok(w) => w as u64,
                Err(Errno(EAGAIN)) => 0,
                Err(e) if moved == 0 => return Err(e),
                Err(_) => break 'vectors,
            };
            moved += w;
            at += w;
            if w < readable || readable < n {
                break 'vectors;
            }
        }
    }
    super::notify::modify(file, moved);
    Ok(moved)
}

/// `tee`: the flags, then the length (0 is 0), the descriptors, the access
/// modes (`EBADF`), two different pipes (`EINVAL`); then data in the input
/// and room in the output, as `splice` waits for them, and the input's
/// bytes copied to the output without consuming them.
pub fn tee(c: &mut Ctx<'_>, fd_in: i32, fd_out: i32, len: u64, flags: u32) -> SysResult {
    if flags & !ALL != 0 {
        return Err(Errno(EINVAL));
    }
    if len == 0 {
        return Ok(0);
    }
    let input = fdget(c, fd_in)?;
    let output = fdget(c, fd_out)?;
    if !input.fmode().0 || !output.fmode().1 {
        return Err(Errno(EBADF));
    }
    if !is_pipe(&input) || !is_pipe(&output) || same_pipe(&input, &output) {
        return Err(Errno(EINVAL));
    }
    let nonblock = flags & NONBLOCK != 0 || (input.flags() | output.flags()) & O_NONBLOCK != 0;
    let n = link_pipe(c, &input, &output, len, nonblock)?;
    if n > 0 {
        super::notify::access(&input, n, false);
        super::notify::modify(&output, n);
    }
    Ok(n)
}

/// `ipipe_prep`, `opipe_prep`, and `link_pipe`, the last through the
/// host's `tee(2)`, which never sleeps here: when it finds nothing to copy
/// or no room after all, another reader or writer came first, and the
/// waits come again.
#[cfg(target_os = "linux")]
fn link_pipe(
    c: &mut Ctx<'_>,
    input: &OpenFile,
    output: &OpenFile,
    len: u64,
    nonblock: bool,
) -> SysResult {
    let (Some(i), Some(o)) = (raw_fd(input), raw_fd(output)) else {
        return Err(Errno(EINVAL));
    };
    loop {
        wait_data(c, input, nonblock)?;
        wait_room(c, output, nonblock)?;
        match host::tee(i, o, len.min(isize::MAX as u64) as usize) {
            Ok(n) => return Ok(n as u64),
            Err(Errno(EAGAIN)) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Without the host's `tee(2)` a pipe's bytes cannot be copied without
/// consuming them.
#[cfg(not(target_os = "linux"))]
fn link_pipe(
    _c: &mut Ctx<'_>,
    _input: &OpenFile,
    _output: &OpenFile,
    _len: u64,
    _nonblock: bool,
) -> SysResult {
    Err(Errno(EINVAL))
}

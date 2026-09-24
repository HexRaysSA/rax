//! Descriptor and data-transfer system calls.

use std::io::IsTerminal;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::host;
use super::{Ctx, SysResult, read_iovecs};

/// `MAX_RW_COUNT`: `INT_MAX & PAGE_MASK`.
pub const MAX_RW_COUNT: u64 = 0x7fff_f000;

/// Host bounce-buffer size for one transfer step.
const CHUNK: usize = 1 << 20;

fn nofile(c: &Ctx<'_>) -> u64 {
    c.p.rlimits[7].0
}

/// Reads up to `count` bytes into guest memory at `buf`. Regular files are
/// read until `count` or end of file, as the kernel's page-cache path does;
/// other files return whatever one host read produced.
fn read_into(c: &Ctx<'_>, file: &OpenFile, buf: u64, count: u64, pos: Option<u64>) -> SysResult {
    let count = count.min(MAX_RW_COUNT);
    let mut done = 0u64;
    let mut tmp = vec![0u8; (count as usize).min(CHUNK)];
    while done < count {
        let want = ((count - done) as usize).min(tmp.len());
        let n = match pos {
            Some(p) => file.read_at(&mut tmp[..want], p + done)?,
            None => file.read(&mut tmp[..want])?,
        };
        if n == 0 {
            break;
        }
        if c.write_mem(buf + done, &tmp[..n]).is_err() {
            return if done > 0 {
                Ok(done)
            } else {
                Err(Errno(EFAULT))
            };
        }
        done += n as u64;
        if file.ftype != FileType::Regular || n < want {
            break;
        }
    }
    Ok(done)
}

/// Writes `count` bytes from guest memory at `buf`.
fn write_from(c: &Ctx<'_>, file: &OpenFile, buf: u64, count: u64, pos: Option<u64>) -> SysResult {
    let count = count.min(MAX_RW_COUNT);
    let mut done = 0u64;
    while done < count {
        let want = ((count - done) as usize).min(CHUNK);
        let data = match c.read_mem(buf + done, want) {
            Ok(d) => d,
            Err(e) => return if done > 0 { Ok(done) } else { Err(e) },
        };
        let n = match pos {
            Some(p) => file.write_at(&data, p + done),
            None => file.write(&data),
        };
        let n = match n {
            Ok(n) => n,
            Err(e) if done > 0 && e.0 != EPIPE => return Ok(done),
            Err(e) => return Err(e),
        };
        done += n as u64;
        if n < want {
            break;
        }
    }
    Ok(done)
}

/// `read`.
pub fn read(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
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
    if count == 0 {
        return if file.writable() {
            Ok(0)
        } else {
            Err(Errno(EBADF))
        };
    }
    write_from(c, &file, buf, count, None)
}

/// `readv`.
pub fn readv(c: &mut Ctx<'_>, fd: i32, iov: u64, cnt: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if !file.readable() {
        return Err(Errno(EBADF));
    }
    let mut total = 0;
    for (base, len) in read_iovecs(c, iov, cnt)? {
        if len == 0 {
            continue;
        }
        let n = read_into(c, &file, base, len, None)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

/// `writev`.
pub fn writev(c: &mut Ctx<'_>, fd: i32, iov: u64, cnt: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if !file.writable() {
        return Err(Errno(EBADF));
    }
    // Gather first so the data reaches the file in one write, as the
    // kernel's iov_iter does for pipes and terminals.
    let vecs = read_iovecs(c, iov, cnt)?;
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
    Ok(file.write(&data)? as u64)
}

/// `pread64`.
pub fn pread(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64, pos: i64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if pos < 0 {
        return Err(Errno(EINVAL));
    }
    read_into(c, &file, buf, count, Some(pos as u64))
}

/// `pwrite64`.
pub fn pwrite(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64, pos: i64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if pos < 0 {
        return Err(Errno(EINVAL));
    }
    write_from(c, &file, buf, count, Some(pos as u64))
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

/// `fcntl` commands (`asm-generic/fcntl.h`, 64-bit numbering).
mod fc {
    pub const F_DUPFD: u32 = 0;
    pub const F_GETFD: u32 = 1;
    pub const F_SETFD: u32 = 2;
    pub const F_GETFL: u32 = 3;
    pub const F_SETFL: u32 = 4;
    pub const F_GETLK: u32 = 5;
    pub const F_SETLK: u32 = 6;
    pub const F_SETLKW: u32 = 7;
    pub const F_SETOWN: u32 = 8;
    pub const F_GETOWN: u32 = 9;
    pub const F_SETSIG: u32 = 10;
    pub const F_GETSIG: u32 = 11;
    pub const F_OFD_GETLK: u32 = 36;
    pub const F_OFD_SETLK: u32 = 37;
    pub const F_OFD_SETLKW: u32 = 38;
    pub const F_DUPFD_CLOEXEC: u32 = 1030;
    pub const F_SETPIPE_SZ: u32 = 1031;
    pub const F_GETPIPE_SZ: u32 = 1032;
    pub const F_ADD_SEALS: u32 = 1033;
    pub const F_GET_SEALS: u32 = 1034;
    pub const FD_CLOEXEC: u64 = 1;
    pub const F_UNLCK: u16 = 2;
}

/// `fcntl`.
pub fn fcntl(c: &mut Ctx<'_>, fd: i32, cmd: u32, arg: u64) -> SysResult {
    use fc::*;
    let limit = nofile(c);
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let file = c.p.fds.file(fd)?;
            if arg as i64 >= limit as i64 || (arg as i32) < 0 {
                return Err(Errno(EINVAL));
            }
            c.p.fds
                .install_from(arg as usize, file, cmd == F_DUPFD_CLOEXEC, limit)
                .map(|n| n as u64)
        }
        F_GETFD => Ok(u64::from(c.p.fds.get(fd)?.cloexec)),
        F_SETFD => {
            c.p.fds.get_mut(fd)?.cloexec = arg & FD_CLOEXEC != 0;
            Ok(0)
        }
        F_GETFL => {
            let file = c.p.fds.file(fd)?;
            // O_LARGEFILE is always set on 64-bit kernels.
            Ok(u64::from(file.flags() | c.p.abi.open_flags().largefile))
        }
        F_SETFL => {
            // SETFL_MASK: O_APPEND | O_NONBLOCK | O_DIRECT | O_NOATIME | FASYNC.
            let file = c.p.fds.file(fd)?;
            let settable = O_APPEND | O_NONBLOCK | O_NOATIME | FASYNC | c.p.abi.open_flags().direct;
            let new = arg as u32 & settable;
            let old = file.flags();
            if (old ^ new) & O_NONBLOCK != 0 {
                set_host_nonblocking(&file, new & O_NONBLOCK != 0)?;
            }
            file.state.lock().unwrap().flags = (old & !settable) | new;
            Ok(0)
        }
        F_GETLK | F_OFD_GETLK => {
            c.p.fds.get(fd)?;
            // struct flock: short l_type, l_whence; off_t l_start, l_len;
            // pid_t l_pid. A single process never conflicts with itself.
            let mut b = c.read_mem(arg, 32)?;
            b[..2].copy_from_slice(&F_UNLCK.to_le_bytes());
            c.write_mem(arg, &b)?;
            Ok(0)
        }
        F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => {
            c.p.fds.get(fd)?;
            c.read_mem(arg, 32)?;
            Ok(0)
        }
        F_GETOWN | F_GETSIG => c.p.fds.get(fd).map(|_| 0),
        F_SETOWN | F_SETSIG => c.p.fds.get(fd).map(|_| 0),
        F_GETPIPE_SZ | F_SETPIPE_SZ => {
            let file = c.p.fds.file(fd)?;
            if file.ftype != FileType::Fifo {
                return Err(Errno(EBADF));
            }
            Ok(65536)
        }
        F_ADD_SEALS | F_GET_SEALS => {
            c.p.fds.get(fd)?;
            Err(Errno(EINVAL))
        }
        _ => Err(Errno(EINVAL)),
    }
}

fn set_host_nonblocking(file: &OpenFile, on: bool) -> Result<(), Errno> {
    match &file.object {
        FileObject::Host(f) => host::set_nonblocking(f, on),
        FileObject::PipeRead(p) => host::set_nonblocking(p, on),
        FileObject::PipeWrite(p) => host::set_nonblocking(p, on),
        FileObject::Synthetic(_) | FileObject::PathOnly => Ok(()),
    }
}

/// Terminal `ioctl` requests (`asm-generic/ioctls.h`).
mod tio {
    pub const TCGETS: u32 = 0x5401;
    pub const TCSETS: u32 = 0x5402;
    pub const TCSETSW: u32 = 0x5403;
    pub const TCSETSF: u32 = 0x5404;
    pub const TIOCSCTTY: u32 = 0x540E;
    pub const TIOCGPGRP: u32 = 0x540F;
    pub const TIOCSPGRP: u32 = 0x5410;
    pub const TIOCGWINSZ: u32 = 0x5413;
    pub const TIOCSWINSZ: u32 = 0x5414;
    pub const FIONREAD: u32 = 0x541B;
    pub const TIOCNOTTY: u32 = 0x5422;
    pub const FIONBIO: u32 = 0x5421;
    pub const FIONCLEX: u32 = 0x5450;
    pub const FIOCLEX: u32 = 0x5451;
    pub const TIOCGPTN: u32 = 0x8004_5430;
}

/// `tty_std_termios` (`drivers/tty/tty_io.c`) as `struct termios`:
/// `c_iflag = ICRNL | IXON`, `c_oflag = OPOST | ONLCR`,
/// `c_cflag = B38400 | CS8 | CREAD | HUPCL`, `c_lflag = ISIG | ICANON | ECHO |
/// ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN`, `c_cc = INIT_C_CC`.
pub fn default_termios() -> [u8; 36] {
    let mut t = [0u8; 36];
    t[0..4].copy_from_slice(&0x0500u32.to_le_bytes());
    t[4..8].copy_from_slice(&0x0005u32.to_le_bytes());
    t[8..12].copy_from_slice(&0x04bfu32.to_le_bytes());
    t[12..16].copy_from_slice(&0x8a3bu32.to_le_bytes());
    t[16] = 0;
    let cc: [u8; 17] = [
        0o3, 0o34, 0o177, 0o25, 0o4, 0, 1, 0, 0o21, 0o23, 0o32, 0, 0o22, 0o17, 0o27, 0o26, 0,
    ];
    t[17..34].copy_from_slice(&cc);
    t
}

fn is_tty(file: &OpenFile) -> bool {
    match &file.object {
        FileObject::Host(f) => f.is_terminal(),
        _ => false,
    }
}

/// `ioctl`.
pub fn ioctl(c: &mut Ctx<'_>, fd: i32, req: u32, arg: u64) -> SysResult {
    use tio::*;
    let file = c.p.fds.file(fd)?;
    match req {
        FIOCLEX | FIONCLEX => {
            c.p.fds.get_mut(fd)?.cloexec = req == FIOCLEX;
            Ok(0)
        }
        FIONBIO => {
            let on = c.read_u32(arg)? != 0;
            set_host_nonblocking(&file, on)?;
            let mut st = file.state.lock().unwrap();
            if on {
                st.flags |= O_NONBLOCK;
            } else {
                st.flags &= !O_NONBLOCK;
            }
            Ok(0)
        }
        FIONREAD => {
            let n = match &file.object {
                FileObject::Host(f) if file.ftype == FileType::Regular => {
                    let len = f.metadata()?.len();
                    let pos = file.seek(0, 1)?;
                    len.saturating_sub(pos).min(i32::MAX as u64) as i32
                }
                FileObject::Host(f) => host::bytes_readable(f)?,
                FileObject::PipeRead(p) => host::bytes_readable(p)?,
                FileObject::Synthetic(d) => {
                    let pos = file.state.lock().unwrap().synth_pos;
                    (d.len() as u64).saturating_sub(pos) as i32
                }
                _ => return Err(Errno(ENOTTY)),
            };
            c.write_u32(arg, n as u32)?;
            Ok(0)
        }
        TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ | TIOCGPGRP | TIOCSPGRP
        | TIOCSCTTY | TIOCNOTTY | TIOCGPTN => {
            if !is_tty(&file) {
                return Err(Errno(ENOTTY));
            }
            match req {
                TCGETS => c.write_mem(arg, &default_termios()).map(|_| 0),
                TCSETS | TCSETSW | TCSETSF => c.read_mem(arg, 36).map(|_| 0),
                TIOCGWINSZ => {
                    let FileObject::Host(f) = &file.object else {
                        return Err(Errno(ENOTTY));
                    };
                    let ws = host::window_size(f)?;
                    let b: Vec<u8> = ws.iter().flat_map(|v| v.to_le_bytes()).collect();
                    c.write_mem(arg, &b).map(|_| 0)
                }
                TIOCSWINSZ => c.read_mem(arg, 8).map(|_| 0),
                TIOCGPGRP => c.write_u32(arg, c.p.pid as u32).map(|_| 0),
                TIOCGPTN => Err(Errno(ENOTTY)),
                _ => Ok(0),
            }
        }
        _ => Err(Errno(ENOTTY)),
    }
}

/// `pipe`/`pipe2`.
pub fn pipe2(c: &mut Ctx<'_>, fds: u64, flags: u32) -> SysResult {
    let direct = c.p.abi.open_flags().direct;
    if flags & !(O_CLOEXEC | O_NONBLOCK | direct) != 0 {
        return Err(Errno(EINVAL));
    }
    let (r, w) = std::io::pipe()?;
    if flags & O_NONBLOCK != 0 {
        host::set_nonblocking(&r, true)?;
        host::set_nonblocking(&w, true)?;
    }
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

fn raw_fd(file: &OpenFile) -> Option<i32> {
    match &file.object {
        FileObject::Host(f) => Some(f.as_raw_fd()),
        FileObject::PipeRead(p) => Some(p.as_raw_fd()),
        FileObject::PipeWrite(p) => Some(p.as_raw_fd()),
        _ => None,
    }
}

/// Computes `revents` for `(fd, events)` pairs, waiting up to `timeout_ms`.
fn poll_fds(c: &Ctx<'_>, req: &[(i32, u16)], timeout_ms: i64) -> Result<Vec<u16>, Errno> {
    use pe::*;
    let mut out = vec![0u16; req.len()];
    let mut host_idx = Vec::new();
    let mut host_req = Vec::new();
    for (i, &(fd, events)) in req.iter().enumerate() {
        if fd < 0 {
            continue;
        }
        let Ok(file) = c.p.fds.file(fd) else {
            out[i] = POLLNVAL;
            continue;
        };
        let want_r = events & (POLLIN | POLLRDNORM | POLLPRI) != 0;
        let want_w = events & (POLLOUT | POLLWRNORM) != 0;
        match (file.ftype, raw_fd(&file)) {
            // Regular files and directories are always ready.
            (FileType::Regular | FileType::Directory, _) | (_, None) => {
                out[i] = events & (POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM);
            }
            (_, Some(raw)) => {
                host_idx.push(i);
                host_req.push((raw, want_r, want_w));
            }
        }
    }
    let ready_now = out.iter().any(|&r| r != 0);
    if !host_req.is_empty() {
        let timeout = if ready_now {
            0
        } else {
            timeout_ms.clamp(-1, i32::MAX as i64) as i32
        };
        let res = host::poll(&host_req, timeout)?;
        for (k, r) in res.into_iter().enumerate() {
            let i = host_idx[k];
            let events = req[i].1;
            let mut rev = 0;
            if r.readable {
                rev |= events & (POLLIN | POLLRDNORM);
            }
            if r.writable {
                rev |= events & (POLLOUT | POLLWRNORM);
            }
            if r.hangup {
                rev |= POLLHUP;
            }
            if r.error {
                rev |= POLLERR;
            }
            out[i] = rev;
        }
    } else if !ready_now && timeout_ms != 0 {
        if timeout_ms < 0 {
            // Nothing can ever become ready: a single-threaded process with
            // no pollable descriptors would block forever.
            return Err(Errno(EINTR));
        }
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
    }
    Ok(out)
}

fn poll_common(c: &Ctx<'_>, fds: u64, nfds: u64, timeout_ms: i64) -> SysResult {
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
    let rev = poll_fds(c, &req, timeout_ms)?;
    let mut out = raw.clone();
    let mut n = 0;
    for (i, r) in rev.iter().enumerate() {
        out[i * 8 + 6..i * 8 + 8].copy_from_slice(&r.to_le_bytes());
        if *r != 0 {
            n += 1;
        }
    }
    c.write_mem(fds, &out)?;
    Ok(n)
}

/// `poll`.
pub fn poll(c: &mut Ctx<'_>, fds: u64, nfds: u64, timeout_ms: i64) -> SysResult {
    poll_common(c, fds, nfds, timeout_ms)
}

/// `ppoll` (the signal mask argument is accepted; RAX delivers no
/// asynchronous signals while a call blocks).
pub fn ppoll(c: &mut Ctx<'_>, fds: u64, nfds: u64, tsp: u64) -> SysResult {
    let timeout_ms = if tsp == 0 {
        -1
    } else {
        let b = c.read_mem(tsp, 16)?;
        let ts = super::super::abi::types::Timespec::decode(&b.try_into().unwrap());
        if ts.sec < 0 || !(0..1_000_000_000).contains(&ts.nsec) {
            return Err(Errno(EINVAL));
        }
        ts.sec.saturating_mul(1000) + (ts.nsec + 999_999) / 1_000_000
    };
    poll_common(c, fds, nfds, timeout_ms)
}

/// `select` and `pselect6` (`timespec` timeout when `ts` is true).
pub fn select(
    c: &mut Ctx<'_>,
    nfds: i32,
    rd: u64,
    wr: u64,
    ex: u64,
    timeout: u64,
    ts: bool,
) -> SysResult {
    // FD_SETSIZE bounds the bitmap; max_fds is the table size.
    if !(0..=1024).contains(&nfds) {
        return Err(Errno(EINVAL));
    }
    let words = (nfds as usize).div_ceil(64);
    let read_set = |addr: u64| -> Result<Vec<u64>, Errno> {
        if addr == 0 {
            return Ok(vec![0; words]);
        }
        let b = c.read_mem(addr, words * 8)?;
        Ok(b.chunks_exact(8)
            .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
            .collect())
    };
    let (rs, ws, es) = (read_set(rd)?, read_set(wr)?, read_set(ex)?);
    let timeout_ms = if timeout == 0 {
        -1
    } else {
        let b = c.read_mem(timeout, 16)?;
        let sec = i64::from_le_bytes(b[..8].try_into().unwrap());
        let frac = i64::from_le_bytes(b[8..].try_into().unwrap());
        let (limit, per_ms) = if ts {
            (1_000_000_000, 1_000_000)
        } else {
            (1_000_000, 1000)
        };
        if sec < 0 || !(0..limit).contains(&frac) {
            return Err(Errno(EINVAL));
        }
        sec.saturating_mul(1000) + (frac + per_ms - 1) / per_ms
    };
    let bit = |set: &[u64], fd: i32| set[fd as usize / 64] >> (fd % 64) & 1 != 0;
    let mut req = Vec::new();
    for fd in 0..nfds {
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
            if c.p.fds.get(fd).is_err() {
                return Err(Errno(EBADF));
            }
            req.push((fd, ev));
        }
    }
    let rev = poll_fds(c, &req, timeout_ms)?;
    let (mut ro, mut wo, mut eo) = (vec![0u64; words], vec![0u64; words], vec![0u64; words]);
    let mut n = 0;
    for (&(fd, ev), r) in req.iter().zip(rev) {
        let set = |v: &mut Vec<u64>| v[fd as usize / 64] |= 1 << (fd % 64);
        if ev & pe::POLLIN != 0 && r & (pe::POLLIN | pe::POLLHUP | pe::POLLERR) != 0 {
            set(&mut ro);
            n += 1;
        }
        if ev & pe::POLLOUT != 0 && r & (pe::POLLOUT | pe::POLLERR) != 0 {
            set(&mut wo);
            n += 1;
        }
        if ev & pe::POLLPRI != 0 && r & pe::POLLPRI != 0 {
            set(&mut eo);
            n += 1;
        }
    }
    let write_set = |addr: u64, v: &[u64]| -> Result<(), Errno> {
        if addr != 0 {
            let b: Vec<u8> = v.iter().flat_map(|w| w.to_le_bytes()).collect();
            c.write_mem(addr, &b)?;
        }
        Ok(())
    };
    write_set(rd, &ro)?;
    write_set(wr, &wo)?;
    write_set(ex, &eo)?;
    if timeout != 0 && n == 0 {
        // Timed out: the remaining time is zero.
        c.write_mem(timeout, &[0u8; 16])?;
    }
    Ok(n)
}

/// `sendfile`.
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
    let mut done = 0u64;
    let mut buf = vec![0u8; (count as usize).min(CHUNK)];
    while done < count {
        let want = ((count - done) as usize).min(buf.len());
        let n = match pos {
            Some(p) => input.read_at(&mut buf[..want], p)?,
            None => input.read(&mut buf[..want])?,
        };
        if n == 0 {
            break;
        }
        let w = output.write(&buf[..n])?;
        done += w as u64;
        if let Some(p) = pos.as_mut() {
            *p += w as u64;
        }
        if w < n {
            break;
        }
    }
    if let (Some(p), true) = (pos, off_ptr != 0) {
        c.write_u64(off_ptr, p)?;
    }
    Ok(done)
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
        (FileObject::Host(f), FileType::Regular | FileType::Directory | FileType::BlockDevice) => {
            // Some hosts reject fsync on directories; the data is durable
            // either way for the guest's purposes.
            let _ = f.sync_all();
            Ok(0)
        }
        (FileObject::Host(_), FileType::CharDevice) => Ok(0),
        _ => Err(Errno(EINVAL)),
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

/// `flock`: a single process can always obtain its own locks.
pub fn flock(c: &mut Ctx<'_>, fd: i32, op: u32) -> SysResult {
    const LOCK_SH: u32 = 1;
    const LOCK_EX: u32 = 2;
    const LOCK_NB: u32 = 4;
    const LOCK_UN: u32 = 8;
    c.p.fds.get(fd)?;
    match op & !LOCK_NB {
        LOCK_SH | LOCK_EX | LOCK_UN => Ok(0),
        _ => Err(Errno(EINVAL)),
    }
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
    if !file.writable() || file.ftype != FileType::Regular {
        return Err(Errno(EINVAL));
    }
    match &file.object {
        FileObject::Host(f) => f.set_len(len as u64).map(|_| 0).map_err(Errno::from),
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
    if file.ftype != FileType::Regular {
        return Err(Errno(ENODEV));
    }
    match mode {
        0 => {
            let FileObject::Host(f) = &file.object else {
                return Err(Errno(ENODEV));
            };
            let end = (off as u64).checked_add(len as u64).ok_or(Errno(EFBIG))?;
            if f.metadata()?.len() < end {
                f.set_len(end)?;
            }
            Ok(0)
        }
        FALLOC_FL_KEEP_SIZE => Ok(0),
        _ => Err(Errno(EOPNOTSUPP)),
    }
}

/// Installs an open file at the lowest free descriptor.
pub fn install(c: &mut Ctx<'_>, file: Arc<OpenFile>, cloexec: bool) -> SysResult {
    let limit = nofile(c);
    c.p.fds.install(file, cloexec, limit).map(|n| n as u64)
}

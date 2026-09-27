//! BSD sockets (`bsd/kern/uipc_syscalls.c`, `bsd/kern/uipc_socket.c`) on
//! a macOS host.
//!
//! A guest socket is a host socket: the host kernel runs the protocols,
//! checks what reaches it in XNU's order, and holds the state other
//! processes share. The emulator's part is the guest's memory, copied in
//! the order XNU reads it (some of it before the descriptor is looked up)
//! and out as XNU writes it (an address cut to the caller's length with
//! the whole length reported, control messages cut at the caller's buffer
//! with `MSG_CTRUNC`); the descriptors `SCM_RIGHTS` carries, translated
//! both ways (received ones are installed even where the caller's buffer
//! cannot report them, as XNU leaks them); `SIGPIPE`, which the guest gets
//! for `EPIPE` without `SO_NOSIGPIPE` or `MSG_NOSIGNAL`; and blocking. A
//! call on a blocking socket is made to the host without blocking
//! (`MSG_NBIO`, or `O_NONBLOCK` around `accept` and `connect`), and when
//! it would block, the calling thread sleeps on the socket's readiness
//! within its `SO_RCVTIMEO` or `SO_SNDTIMEO` while other guest threads
//! run; a signal ends the sleep with `EINTR`, a restart, or the bytes
//! already moved, as `sbwait` does.

mod conn;
mod control;
mod io;
mod ioctl;
mod msgx;
mod opt;

pub use conn::{
    accept, bind, connect, connectx, disconnectx, getpeername, getsockname, listen, peeloff,
    shutdown, socket, socket_delegate, socketpair,
};
pub use io::{read, readv, recvfrom, recvmsg, sendmsg, sendto, write, writev};
pub use ioctl::ioctl;
pub use msgx::{recvmsg_x, sendmsg_x};
pub use opt::{getsockopt, setsockopt};

use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{FileKind, FileRef};
use crate::user::darwin::host;
use crate::user::darwin::signal;
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::{self, Wait};

/// `SOL_SOCKET`.
pub const SOL_SOCKET: i32 = 0xffff;
/// `SCM_RIGHTS`.
pub const SCM_RIGHTS: i32 = 1;

/// `SO_*` options the emulator reads.
mod so {
    pub const SNDTIMEO: i32 = 0x1005;
    pub const RCVTIMEO: i32 = 0x1006;
    pub const TYPE: i32 = 0x1008;
    pub const NOSIGPIPE: i32 = 0x1022;
}

/// `MSG_*` flags.
pub mod msg {
    pub const PEEK: i32 = 0x2;
    pub const CTRUNC: i32 = 0x20;
    pub const WAITALL: i32 = 0x40;
    pub const DONTWAIT: i32 = 0x80;
    /// `MSG_NBIO`: this call does not block (`FIONBIO` for one call).
    pub const NBIO: i32 = 0x20000;
    pub const SKIPCFIL: i32 = 0x40000;
    pub const NOSIGNAL: i32 = 0x80000;
}

/// `SOCK_STREAM`.
const SOCK_STREAM: i32 = 1;

/// `SOCK_MAXADDRLEN`: the longest socket address.
const SOCK_MAXADDRLEN: u32 = 255;
/// `sizeof(struct sockaddr_storage)`.
const SOCKADDR_STORAGE: u32 = 128;

/// How long a blocked call waits before trying the host again when the
/// socket polls ready but the host still refuses (more is wanted than
/// readiness promises: `MSG_WAITALL`, a datagram larger than the free
/// space).
const RETRY: Duration = Duration::from_millis(2);

/// A guest socket's open file and host descriptor (`file_socket`,
/// `fp_get_ftype`): `EBADF` without a descriptor, `ENOTSOCK` for another
/// kind of file.
fn sock(ctx: &Ctx<'_>, fd: i32) -> Result<(FileRef, RawFd), Errno> {
    let file = ctx.proc.fds.file(fd)?;
    let h = match &file.kind {
        FileKind::Socket(h) => h.as_raw_fd(),
        // A socket the process was started with.
        FileKind::Host(h)
            if host::fstat(h.as_raw_fd())
                .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFSOCK) =>
        {
            h.as_raw_fd()
        }
        _ => return Err(Errno::ENOTSOCK),
    };
    Ok((file, h))
}

/// A socket address argument as XNU copies it in (`getsockaddr`,
/// `getsockaddr_s`): `ENAMETOOLONG` over `SOCK_MAXADDRLEN`; up to the
/// size of `sockaddr_storage`, `EINVAL` for a NULL address or one shorter
/// than its family field; then `EFAULT`. (The host overwrites `sa_len`
/// with the length, as XNU does.)
fn sockaddr_in(ctx: &Ctx<'_>, addr: u64, len: u32) -> Result<Vec<u8>, Errno> {
    if len > SOCK_MAXADDRLEN {
        return Err(Errno::ENAMETOOLONG);
    }
    if len <= SOCKADDR_STORAGE && (addr == 0 || len < 2) {
        return Err(Errno::EINVAL);
    }
    ctx.read(addr, len as usize)
}

/// A socket address from the host: its bytes and `sa_len` (0: none).
struct Addr {
    buf: [u8; 256],
    len: u32,
}

impl Addr {
    fn new() -> Self {
        Addr {
            buf: [0; 256],
            len: 256,
        }
    }

    /// The bytes the host wrote.
    fn bytes(&self) -> &[u8] {
        &self.buf[..(self.len as usize).min(256)]
    }
}

/// `copyout_sa`: a received address into the caller's `name` of `namelen`
/// bytes: at most `namelen` bytes copied; the length to report is the
/// whole address's (0 for none, or when `namelen` is 0), or `None` when
/// the copy faults (the length is then left as it was; the fault is not
/// an error).
fn copyout_sa(ctx: &Ctx<'_>, name: u64, namelen: u32, sa: &[u8]) -> Option<u32> {
    if namelen == 0 || sa.is_empty() {
        return Some(0);
    }
    let n = (namelen as usize).min(sa.len());
    ctx.write(name, &sa[..n]).ok()?;
    Some(sa.len() as u32)
}

/// An `int` socket option of the host socket.
fn host_int_opt(h: RawFd, opt: i32) -> Option<i32> {
    let mut v: i32 = 0;
    let mut len = 4 as libc::socklen_t;
    // SAFETY: `v` holds the `len` bytes offered.
    let r = unsafe { libc::getsockopt(h, SOL_SOCKET, opt, (&raw mut v).cast(), &mut len) };
    (r == 0).then_some(v)
}

/// Whether the host socket is a stream socket (not atomic).
fn is_stream(h: RawFd) -> bool {
    host_int_opt(h, so::TYPE) == Some(SOCK_STREAM)
}

/// Whether the socket blocks (the guest's `O_NONBLOCK` is kept on the
/// host description).
fn blocking(h: RawFd) -> bool {
    // SAFETY: F_GETFL on a live descriptor takes no pointers.
    let fl = unsafe { libc::fcntl(h, libc::F_GETFL) };
    fl >= 0 && fl & libc::O_NONBLOCK == 0
}

/// The socket's `SO_RCVTIMEO` or `SO_SNDTIMEO` (`None`: no timeout).
fn timeout(h: RawFd, opt: i32) -> Option<Duration> {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: `tv` holds the `len` bytes offered.
    let r = unsafe { libc::getsockopt(h, SOL_SOCKET, opt, (&raw mut tv).cast(), &mut len) };
    if r != 0 || (tv.tv_sec == 0 && tv.tv_usec == 0) {
        return None;
    }
    Some(Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000))
}

/// The bytes a restarted call has already moved.
fn moved_before(ctx: &Ctx<'_>) -> u64 {
    ctx.thread.resume.map_or(0, |r| u64::from(r.step))
}

/// Whether a restarted call's timeout has passed.
fn timed_out(ctx: &Ctx<'_>) -> bool {
    ctx.thread
        .resume
        .and_then(|r| r.deadline)
        .is_some_and(|d| d <= Instant::now())
}

/// How a socket call that would block sleeps.
struct Block {
    /// Waiting to read (else to write).
    read: bool,
    /// The timeout option that bounds each wait (0: none).
    timeo: i32,
    /// The bytes the call has moved so far.
    done: u64,
    /// Whether this run moved any (a new wait then gets a whole timeout,
    /// as each `sbwait` does).
    moved: bool,
    /// Whether a handler with `SA_RESTART` restarts the call (not
    /// `connect`).
    restart: bool,
}

/// Parks the thread until the socket is ready as `b` says, then runs the
/// call again. A signal ends the wait: the call returns what it moved,
/// if anything, else fails with `EINTR` or restarts after the handler.
fn park(ctx: &mut Ctx<'_>, h: RawFd, b: Block) -> SysResult {
    let deadline = match ctx.thread.resume {
        Some(r) if !b.moved => r.deadline,
        _ if b.timeo != 0 => timeout(h, b.timeo).map(|t| Instant::now() + t),
        _ => None,
    };
    let want = (h, b.read, !b.read);
    let wait = if wait::ready_now(&[want])[0] {
        let soon = Instant::now() + RETRY;
        Wait::fds(Vec::new(), Some(deadline.map_or(soon, |d| d.min(soon))))
    } else {
        Wait::fds(vec![want], deadline)
    };
    let r = if b.restart {
        syscall::sleep(ctx, wait)
    } else {
        syscall::sleep_no_restart(ctx, wait)
    };
    match r {
        Err(Errno::ERESTART) if ctx.thread.wait.is_some() => {
            if let Some(res) = ctx.thread.resume.as_mut() {
                res.step = b.done as u32;
                res.deadline = deadline;
            }
            Err(Errno::ERESTART)
        }
        Err(_) if b.done > 0 => Ok(Rv::one(b.done)),
        r => r,
    }
}

/// `sendit`'s and `soo_write`'s `EPIPE` rule: `SIGPIPE` to the process
/// unless the socket has `SO_NOSIGPIPE` or the call `MSG_NOSIGNAL`.
fn sigpipe(ctx: &mut Ctx<'_>, h: RawFd, r: &SysResult, flags: i32) {
    if *r == Err(Errno::EPIPE)
        && flags & msg::NOSIGNAL == 0
        && host_int_opt(h, so::NOSIGPIPE).is_none_or(|v| v == 0)
    {
        let own = signal::Origin::own(ctx.proc);
        signal::psignal(ctx.proc, Some(ctx.thread), signal::SIGPIPE, own);
    }
}

/// A host call's result.
fn host_result(r: isize) -> Result<usize, Errno> {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(r as usize)
    }
}

/// The free descriptors below the process's limit.
fn free_slots(ctx: &Ctx<'_>) -> u64 {
    let limit = ctx.proc.rlimits[8].0;
    let used = ctx
        .proc
        .fds
        .iter()
        .filter(|(fd, _)| (*fd as u64) < limit)
        .count() as u64;
    limit.saturating_sub(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_addresses_report_what_was_written() {
        let mut a = Addr::new();
        a.len = 16;
        assert_eq!(a.bytes().len(), 16);
        a.len = 0;
        assert!(a.bytes().is_empty());
        // A length over the buffer is clamped.
        a.len = 300;
        assert_eq!(a.bytes().len(), 256);
    }
}

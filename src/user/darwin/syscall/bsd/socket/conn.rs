//! Making, naming, and connecting sockets: `socket`, `socketpair`,
//! `socket_delegate`, `bind`, `listen`, `accept`, `connect`, `connectx`,
//! `disconnectx`, `peeloff`, `shutdown`, `getsockname`, `getpeername`.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use super::{Addr, Block, blocking, free_slots, park, sock, sockaddr_in};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::OpenFile;
use crate::user::darwin::host::check;
use crate::user::darwin::io::{self, O_RDWR};
use crate::user::darwin::syscall::Ctx;

/// The host's `connectx` (whose eight arguments `syscall` cannot pass),
/// `disconnectx`, and `socket_delegate`.
mod sys {
    unsafe extern "C" {
        pub fn connectx(
            s: i32,
            endpoints: *const u8,
            aid: u32,
            flags: u32,
            iov: *const libc::iovec,
            iovcnt: u32,
            len: *mut usize,
            connid: *mut u32,
        ) -> i32;
        pub fn disconnectx(s: i32, aid: u32, cid: u32) -> i32;
        pub fn socket_delegate(domain: i32, ty: i32, protocol: i32, epid: i32) -> i32;
    }
}

/// Installs host socket `h` at the guest's lowest free descriptor with
/// status flags `flags`; the host descriptor is close-on-exec, as every
/// one the emulator holds.
fn install(ctx: &mut Ctx<'_>, h: OwnedFd, flags: u32) -> Result<i32, Errno> {
    use std::os::fd::AsRawFd;
    // SAFETY: F_SETFD on a live descriptor takes an integer.
    unsafe { libc::fcntl(h.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    let limit = ctx.proc.rlimits[8].0;
    ctx.proc
        .fds
        .install(Arc::new(OpenFile::socket(h, flags)), false, 0, limit)
}

/// Takes ownership of a descriptor the host just made.
fn own(h: RawFd) -> OwnedFd {
    // SAFETY: `h` was just returned by the host and nothing else owns it.
    unsafe { OwnedFd::from_raw_fd(h) }
}

/// The host description's status flags.
fn status(h: RawFd) -> Result<i32, Errno> {
    // SAFETY: F_GETFL on a live descriptor takes no pointers.
    check(unsafe { libc::fcntl(h, libc::F_GETFL) })
}

/// Runs `f` with the host description non-blocking (flags `fl` before),
/// then restores them: `accept` and `connect` have no per-call flag.
fn nonblocking<T>(h: RawFd, fl: i32, f: impl FnOnce() -> Result<T, Errno>) -> Result<T, Errno> {
    if fl & libc::O_NONBLOCK != 0 {
        return f();
    }
    // SAFETY: F_SETFL on a live descriptor takes an integer.
    unsafe { libc::fcntl(h, libc::F_SETFL, fl | libc::O_NONBLOCK) };
    let r = f();
    // SAFETY: as above.
    unsafe { libc::fcntl(h, libc::F_SETFL, fl) };
    r
}

/// `socket(domain, type, protocol)`: a descriptor is allocated before
/// the protocol is looked up (`EMFILE` first), then the host's socket
/// (`EAFNOSUPPORT`, `EPROTONOSUPPORT`, `EPROTOTYPE`, ...), blocking and
/// read-write.
pub fn socket(ctx: &mut Ctx<'_>, domain: i32, ty: i32, protocol: i32) -> SysResult {
    ctx.proc.fds.lowest_free(0, ctx.proc.rlimits[8].0)?;
    // SAFETY: socket(2) takes no pointers.
    let h = check(unsafe { libc::socket(domain, ty, protocol) })?;
    let fd = install(ctx, own(h), O_RDWR)?;
    Ok(Rv::one(fd as u64))
}

/// `socketpair(domain, type, protocol, sv)`: the sockets are made before
/// the descriptors (so a bad domain or type is reported before
/// `EMFILE`), which are allocated before the pair is connected (`EMFILE`
/// before `EOPNOTSUPP`); a fault storing `sv` frees both.
pub fn socketpair(ctx: &mut Ctx<'_>, domain: i32, ty: i32, protocol: i32, sv: u64) -> SysResult {
    let room = free_slots(ctx) >= 2;
    let mut pair = [0i32; 2];
    // SAFETY: `pair` holds the two descriptors socketpair writes.
    if unsafe { libc::socketpair(domain, ty, protocol, pair.as_mut_ptr()) } < 0 {
        let e = Errno::last();
        return Err(if e == Errno::EOPNOTSUPP && !room {
            Errno::EMFILE
        } else {
            e
        });
    }
    let (a, b) = (own(pair[0]), own(pair[1]));
    if !room {
        return Err(Errno::EMFILE);
    }
    let a = install(ctx, a, O_RDWR)?;
    let b = install(ctx, b, O_RDWR)?;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&a.to_le_bytes());
    out[4..].copy_from_slice(&b.to_le_bytes());
    if let Err(e) = ctx.write(sv, &out) {
        let _ = ctx.proc.fds.remove(a);
        let _ = ctx.proc.fds.remove(b);
        return Err(e);
    }
    Ok(Rv::one(0))
}

/// `bind(s, name, namelen)`: `EDESTADDRREQ` without an address, then
/// its copy-in, then the host's bind.
pub fn bind(ctx: &mut Ctx<'_>, fd: i32, name: u64, namelen: u32) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    if name == 0 {
        return Err(Errno::EDESTADDRREQ);
    }
    let sa = sockaddr_in(ctx, name, namelen)?;
    // SAFETY: `sa` holds `namelen` bytes.
    check(unsafe { libc::bind(h, sa.as_ptr().cast(), namelen) })?;
    Ok(Rv::one(0))
}

/// `listen(s, backlog)`.
pub fn listen(ctx: &mut Ctx<'_>, fd: i32, backlog: i32) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    // SAFETY: listen(2) takes no pointers.
    check(unsafe { libc::listen(h, backlog) })?;
    Ok(Rv::one(0))
}

/// `accept(s, name, anamelen)`: `*anamelen` is read first when there is
/// a `name`; a blocking socket sleeps (without a timeout) until a
/// connection is queued. The new socket has the listening one's
/// non-blocking and asynchronous modes, not its close-on-exec flag.
/// Its address is copied as XNU copies it: at most `*anamelen` bytes,
/// the whole length written back when the copy succeeds (the copy's
/// length when it faults, which is no error); a fault writing the length
/// fails the call and leaves the descriptor open.
pub fn accept(ctx: &mut Ctx<'_>, fd: i32, name: u64, anamelen: u64) -> SysResult {
    let namelen = if name != 0 {
        Some(ctx.read_u32(anamelen)?)
    } else {
        None
    };
    let (_, h) = sock(ctx, fd)?;
    let fl = status(h)?;
    let mut sa = Addr::new();
    let r = nonblocking(h, fl, || {
        // SAFETY: `sa.buf` holds the `sa.len` bytes offered.
        let n = unsafe { libc::accept(h, sa.buf.as_mut_ptr().cast(), &mut sa.len) };
        check(n)
    });
    let nh = match r {
        Ok(n) => own(n),
        Err(Errno::EAGAIN) if fl & libc::O_NONBLOCK == 0 => {
            return park(
                ctx,
                h,
                Block {
                    read: true,
                    timeo: 0,
                    done: 0,
                    moved: false,
                    restart: true,
                },
            );
        }
        Err(e) => return Err(e),
    };
    {
        use std::os::fd::AsRawFd;
        let inherit = fl & (libc::O_NONBLOCK | libc::O_ASYNC);
        let cur = status(nh.as_raw_fd())?;
        // SAFETY: F_SETFL on a live descriptor takes an integer.
        unsafe {
            libc::fcntl(
                nh.as_raw_fd(),
                libc::F_SETFL,
                (cur & !(libc::O_NONBLOCK | libc::O_ASYNC)) | inherit,
            )
        };
    }
    let flags = O_RDWR | io::host_to_guest_oflags(fl & (libc::O_NONBLOCK | libc::O_ASYNC));
    let new = install(ctx, nh, flags)?;
    if let Some(len) = namelen {
        let out = if sa.len == 0 {
            0
        } else {
            let n = (len as usize).min(sa.bytes().len());
            if ctx.write(name, &sa.bytes()[..n]).is_ok() {
                sa.len
            } else {
                n as u32
            }
        };
        ctx.write_u32(anamelen, out)?;
    }
    Ok(Rv::one(new as u64))
}

/// `socket_delegate(domain, type, protocol, epid)`: a socket made on
/// another process's behalf, which needs a privilege the host checks
/// first (`EACCES` without it); then a descriptor.
pub fn socket_delegate(
    ctx: &mut Ctx<'_>,
    domain: i32,
    ty: i32,
    protocol: i32,
    epid: i32,
) -> SysResult {
    // SAFETY: socket_delegate takes no pointers.
    let h = check(unsafe { sys::socket_delegate(domain, ty, protocol, epid) })?;
    let h = own(h);
    let fd = install(ctx, h, O_RDWR)?;
    Ok(Rv::one(fd as u64))
}

/// `connect(s, name, namelen)`: the address's copy-in, then the host's
/// connect. A blocking socket waits (without a timeout) for the
/// connection and returns its outcome; a signal ends the wait with
/// `EINTR`, never a restart, and the connection goes on (a later
/// `connect` reports `EISCONN`, or `EALREADY` without blocking).
pub fn connect(ctx: &mut Ctx<'_>, fd: i32, name: u64, namelen: u32) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    let sa = sockaddr_in(ctx, name, namelen)?;
    let fl = status(h)?;
    // A restarted call was waiting for its connection.
    if ctx.thread.resume.is_none() {
        let r = nonblocking(h, fl, || {
            // SAFETY: `sa` holds `namelen` bytes.
            check(unsafe { libc::connect(h, sa.as_ptr().cast(), namelen) })
        });
        match r {
            Ok(_) => return Ok(Rv::one(0)),
            Err(Errno::EINPROGRESS) if blocking(h) => {}
            // soconnectlock: a blocking socket already connecting.
            Err(Errno::EALREADY) if blocking(h) => return Err(Errno::EISCONN),
            Err(e) => return Err(e),
        }
    }
    connected(ctx, h)
}

/// Waits for a blocking socket's connection and returns its outcome
/// (cleared from `SO_ERROR`, as `connect` clears it).
fn connected(ctx: &mut Ctx<'_>, h: RawFd) -> SysResult {
    if !crate::user::darwin::wait::ready_now(&[(h, false, true)])[0] {
        return park(
            ctx,
            h,
            Block {
                read: false,
                timeo: 0,
                done: 0,
                moved: false,
                restart: false,
            },
        );
    }
    let mut err: i32 = 0;
    let mut len = 4 as libc::socklen_t;
    // SAFETY: `err` holds the `len` bytes offered.
    unsafe {
        libc::getsockopt(
            h,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut err).cast(),
            &mut len,
        )
    };
    if err != 0 {
        return Err(Errno::from_host(err));
    }
    Ok(Rv::one(0))
}

/// `connectx(s, endpoints, associd, flags, iov, iovcnt, len, connid)`:
/// the descriptor, then the endpoints (`EINVAL` for none), the source
/// address if any, the destination (`EINVAL` for none), and data to
/// send with the connection (`EINVAL` for a bad count or no `len`);
/// the bytes queued and the connection's identifier are written back
/// whatever the outcome (their faults count only when it succeeds).
/// A blocking socket waits for the connection as `connect` does.
#[allow(clippy::too_many_arguments)]
pub fn connectx(
    ctx: &mut Ctx<'_>,
    fd: i32,
    ep: u64,
    aid: u32,
    flags: u32,
    iov: u64,
    iovcnt: u32,
    len: u64,
    connid: u64,
) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    if ctx.thread.resume.is_some() {
        return connectx_done(ctx, h, connid);
    }
    if ep == 0 {
        return Err(Errno::EINVAL);
    }
    let raw = ctx.read(ep, 40)?;
    let word = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().expect("4 bytes"));
    let addr = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().expect("8 bytes"));
    let src = match addr(8) {
        0 => None,
        a => Some(sockaddr_in(ctx, a, word(16))?),
    };
    if addr(24) == 0 {
        return Err(Errno::EINVAL);
    }
    let dst = sockaddr_in(ctx, addr(24), word(32))?;
    let data = if iov != 0 {
        if iovcnt as i32 <= 0 || iovcnt > 1024 {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        let (v, total) = super::io::iovecs(ctx, iov, iovcnt as i32)?;
        Some(super::io::gather(
            ctx,
            &v,
            0,
            (total as usize).min(super::io::SEND_CHUNK),
        )?)
    } else {
        None
    };
    // sa_endpoints_t: srcif, srcaddr, srcaddrlen, dstaddr, dstaddrlen.
    let mut host_ep = [0u8; 40];
    host_ep[0..4].copy_from_slice(&word(0).to_le_bytes());
    if let Some(s) = &src {
        host_ep[8..16].copy_from_slice(&(s.as_ptr() as u64).to_le_bytes());
        host_ep[16..20].copy_from_slice(&(s.len() as u32).to_le_bytes());
    }
    host_ep[24..32].copy_from_slice(&(dst.as_ptr() as u64).to_le_bytes());
    host_ep[32..36].copy_from_slice(&(dst.len() as u32).to_le_bytes());
    let host_iov = data.as_ref().map(|d| libc::iovec {
        iov_base: d.as_ptr() as *mut libc::c_void,
        iov_len: d.len(),
    });
    let mut written: usize = 0;
    let mut cid: u32 = 0;
    let fl = status(h)?;
    let r = nonblocking(h, fl, || {
        let (iovp, cnt) = match &host_iov {
            Some(v) => (v as *const libc::iovec, 1u32),
            None => (std::ptr::null(), 0),
        };
        // SAFETY: the endpoints, addresses, data, and outputs are live
        // buffers of the sizes given.
        check(unsafe {
            sys::connectx(
                h,
                host_ep.as_ptr(),
                aid,
                flags,
                iovp,
                cnt,
                &raw mut written,
                &raw mut cid,
            )
        })
    });
    let mut r = r.map(|_| Rv::one(0));
    if len != 0 && ctx.write_u64(len, written as u64).is_err() && r.is_ok() {
        r = Err(Errno::EFAULT);
    }
    if connid != 0 && ctx.write_u32(connid, cid).is_err() && r.is_ok() {
        r = Err(Errno::EFAULT);
    }
    match r {
        Err(Errno::EINPROGRESS) if blocking(h) => connectx_done(ctx, h, connid),
        Err(Errno::EALREADY) if blocking(h) => Err(Errno::EISCONN),
        r => r,
    }
}

/// Waits for a blocking `connectx`'s connection; once made, its
/// identifier is TCP's one connection's (1), which the host, asked not
/// to block, did not assign.
fn connectx_done(ctx: &mut Ctx<'_>, h: RawFd, connid: u64) -> SysResult {
    let r = connected(ctx, h);
    if r.is_ok() && connid != 0 {
        ctx.write_u32(connid, 1)?;
    }
    r
}

/// `disconnectx(s, associd, connid)`.
pub fn disconnectx(ctx: &mut Ctx<'_>, fd: i32, aid: u32, cid: u32) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    // SAFETY: disconnectx takes no pointers.
    check(unsafe { sys::disconnectx(h, aid, cid) })?;
    Ok(Rv::one(0))
}

/// `peeloff(s, associd)`: does nothing (any descriptor, 0).
pub fn peeloff() -> SysResult {
    Ok(Rv::one(0))
}

/// `shutdown(s, how)`.
pub fn shutdown(ctx: &mut Ctx<'_>, fd: i32, how: i32) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    // SAFETY: shutdown(2) takes no pointers.
    check(unsafe { libc::shutdown(h, how) })?;
    Ok(Rv::one(0))
}

/// Copies a socket's own or peer address out as `getsockname` and
/// `getpeername` do: at most `*alen` bytes (`EFAULT` when that faults),
/// then the whole length (0 for none).
fn name_out(ctx: &Ctx<'_>, asa: u64, alen: u64, len: u32, sa: &Addr) -> SysResult {
    let bytes = sa.bytes();
    let n = (len as usize).min(bytes.len());
    ctx.write(asa, &bytes[..n])?;
    ctx.write_u32(alen, sa.len)?;
    Ok(Rv::one(0))
}

/// `getsockname(s, asa, alen)`: `*alen` is read before the address is
/// asked for.
pub fn getsockname(ctx: &mut Ctx<'_>, fd: i32, asa: u64, alen: u64) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    let len = ctx.read_u32(alen)?;
    let mut sa = Addr::new();
    // SAFETY: `sa.buf` holds the `sa.len` bytes offered.
    check(unsafe { libc::getsockname(h, sa.buf.as_mut_ptr().cast(), &mut sa.len) })?;
    name_out(ctx, asa, alen, len, &sa)
}

/// `getpeername(s, asa, alen)`: a socket shut down both ways
/// (`EINVAL`) or not connected (`ENOTCONN`) fails before `*alen` is
/// read.
pub fn getpeername(ctx: &mut Ctx<'_>, fd: i32, asa: u64, alen: u64) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    let mut sa = Addr::new();
    // SAFETY: `sa.buf` holds the `sa.len` bytes offered.
    check(unsafe { libc::getpeername(h, sa.buf.as_mut_ptr().cast(), &mut sa.len) })?;
    let len = ctx.read_u32(alen)?;
    name_out(ctx, asa, alen, len, &sa)
}

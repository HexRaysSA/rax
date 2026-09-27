//! Sending and receiving: `sendto`, `sendmsg`, `recvfrom`, `recvmsg`,
//! and `read`, `readv`, `write`, `writev` on sockets (`soo_read`,
//! `soo_write`).

use std::os::fd::{OwnedFd, RawFd};

use super::{
    Addr, Block, blocking, control, copyout_sa, host_result, is_stream, moved_before, msg, park,
    sigpipe, so, sock, sockaddr_in, timed_out,
};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// Bytes moved per host send on a stream socket.
pub(super) const SEND_CHUNK: usize = 1 << 20;
/// The most a host receive takes at once (`kern.ipc.maxsockbuf`: no
/// socket buffer holds more).
const RECV_MAX: usize = 8 << 20;
/// Room for any one receive's control data: the most descriptors a
/// message carries (254) and the internet protocols' messages.
const CONTROL_MAX: usize = 8192;
/// `UIO_MAXIOV`.
const UIO_MAXIOV: i32 = 1024;
/// The largest control buffer `sockargs` accepts: twice the payload
/// beyond the header must fit `MCLBYTES`.
const CONTROL_LIMIT: u32 = 12 + (2048 - 12) / 2;
/// `sizeof(struct user64_msghdr)`.
const MSGHDR: usize = 48;
/// `MSG_OOB`.
const MSG_OOB: i32 = 0x1;

/// A guest `struct msghdr` (LP64): name@0, namelen@8, iov@16, iovlen@24,
/// control@32, controllen@40, flags@44.
struct Msghdr([u8; MSGHDR]);

impl Msghdr {
    fn read(ctx: &Ctx<'_>, addr: u64) -> Result<Self, Errno> {
        let mut raw = [0u8; MSGHDR];
        ctx.read_into(addr, &mut raw)?;
        Ok(Msghdr(raw))
    }
    fn u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.0[off..off + 8].try_into().expect("8 bytes"))
    }
    fn u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.0[off..off + 4].try_into().expect("4 bytes"))
    }
    fn set_u32(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn name(&self) -> u64 {
        self.u64(0)
    }
    fn namelen(&self) -> u32 {
        self.u32(8)
    }
    fn iov(&self) -> u64 {
        self.u64(16)
    }
    fn iovlen(&self) -> i32 {
        self.u32(24) as i32
    }
    fn control(&self) -> u64 {
        self.u64(32)
    }
    fn controllen(&self) -> u32 {
        self.u32(40)
    }
}

/// A guest scatter-gather list and its total (`copyin_user_iovec_array`,
/// `uio_calculateresid_user`): `EFAULT`, then `EINVAL` when the lengths
/// overflow.
pub(super) fn iovecs(ctx: &Ctx<'_>, iov: u64, cnt: i32) -> Result<(Vec<(u64, u64)>, u64), Errno> {
    let raw = ctx.read(iov, 16 * cnt.max(0) as usize)?;
    let mut v = Vec::with_capacity(raw.len() / 16);
    let mut total: u64 = 0;
    for c in raw.chunks(16) {
        let base = u64::from_le_bytes(c[..8].try_into().expect("8 bytes"));
        let len = u64::from_le_bytes(c[8..].try_into().expect("8 bytes"));
        total = total
            .checked_add(len)
            .filter(|t| *t <= i64::MAX as u64)
            .ok_or(Errno::EINVAL)?;
        v.push((base, len));
    }
    Ok((v, total))
}

/// A `msghdr`'s scatter-gather list: `EMSGSIZE` for no entries or more
/// than `UIO_MAXIOV`, before it is read.
fn msg_iovecs(ctx: &Ctx<'_>, m: &Msghdr) -> Result<(Vec<(u64, u64)>, u64), Errno> {
    if m.iovlen() <= 0 || m.iovlen() > UIO_MAXIOV {
        return Err(Errno::EMSGSIZE);
    }
    iovecs(ctx, m.iov(), m.iovlen())
}

/// Up to `max` bytes of the guest's data from byte `skip` of `iov`.
pub(super) fn gather(
    ctx: &Ctx<'_>,
    iov: &[(u64, u64)],
    mut skip: u64,
    max: usize,
) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::with_capacity(max);
    for &(base, len) in iov {
        if out.len() >= max {
            break;
        }
        if skip >= len {
            skip -= len;
            continue;
        }
        let take = ((len - skip) as usize).min(max - out.len());
        out.extend_from_slice(&ctx.read(base + skip, take)?);
        skip = 0;
    }
    Ok(out)
}

/// Visits the guest ranges holding `len` bytes from byte `skip` of `iov`.
fn ranges(
    iov: &[(u64, u64)],
    mut skip: u64,
    mut len: usize,
    mut f: impl FnMut(u64, usize, usize) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let mut at = 0usize;
    for &(base, seg) in iov {
        if len == 0 {
            break;
        }
        if skip >= seg {
            skip -= seg;
            continue;
        }
        let n = ((seg - skip) as usize).min(len);
        f(base + skip, at, n)?;
        at += n;
        len -= n;
        skip = 0;
    }
    Ok(())
}

/// Writes received `data` into `iov` from byte `skip`.
fn scatter(ctx: &Ctx<'_>, iov: &[(u64, u64)], skip: u64, data: &[u8]) -> Result<(), Errno> {
    ranges(iov, skip, data.len(), |addr, at, n| {
        ctx.write(addr, &data[at..at + n])
    })
}

/// Whether the guest can take `len` bytes into `iov` from byte `skip`:
/// every byte mapped writable (checked before the host gives up the
/// data, so that a receive into a bad buffer fails with `EFAULT` and
/// leaves the data queued).
fn writable(ctx: &Ctx<'_>, iov: &[(u64, u64)], skip: u64, len: usize) -> Result<(), Errno> {
    use crate::user::mm::Perms;
    ranges(iov, skip, len, |addr, _, n| {
        let end = addr.checked_add(n as u64).ok_or(Errno::EFAULT)?;
        let mut at = addr;
        for v in ctx.proc.space.vmas_in(addr, end) {
            if v.start > at || !v.perms.contains(Perms::WRITE) {
                return Err(Errno::EFAULT);
            }
            at = v.end;
        }
        if at < end {
            return Err(Errno::EFAULT);
        }
        Ok(())
    })
}

/// A send (`sendit`, `soo_write`): the data, a destination, control
/// data, and the flags.
struct Send {
    iov: Vec<(u64, u64)>,
    total: u64,
    name: Option<Vec<u8>>,
    control: Option<Vec<u8>>,
    flags: i32,
}

/// Whether the host socket is an `AF_UNIX` one.
pub(super) fn is_local(h: RawFd) -> bool {
    let mut sa = Addr::new();
    // SAFETY: `sa.buf` holds the `sa.len` bytes offered.
    let r = unsafe { libc::getsockname(h, sa.buf.as_mut_ptr().cast(), &mut sa.len) };
    r == 0 && sa.len >= 2 && sa.buf[1] == libc::AF_UNIX as u8
}

/// One host `sendmsg`.
fn host_send(
    h: RawFd,
    name: Option<&[u8]>,
    data: &[u8],
    control: Option<&[u8]>,
    flags: i32,
) -> Result<usize, Errno> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: an all-zero msghdr is valid; its pointers are set below.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    if let Some(n) = name {
        m.msg_name = n.as_ptr() as *mut libc::c_void;
        m.msg_namelen = n.len() as libc::socklen_t;
    }
    m.msg_iov = &raw mut iov;
    m.msg_iovlen = 1;
    if let Some(c) = control {
        m.msg_control = c.as_ptr() as *mut libc::c_void;
        m.msg_controllen = c.len() as libc::socklen_t;
    }
    // SAFETY: every pointer in `m` is valid for its length for the call.
    host_result(unsafe { libc::sendmsg(h, &m, flags) })
}

/// Sends `s` on host socket `h`. A blocking socket takes it in pieces as
/// room appears (each wait bounded by `SO_SNDTIMEO`), returning what was
/// sent when a wait times out or is interrupted after some of it (the
/// control data goes with the first piece); `MSG_DONTWAIT` does not stop
/// the wait, as on Darwin it only affects the send lock.
fn send(ctx: &mut Ctx<'_>, h: RawFd, s: &Send) -> SysResult {
    if s.total > i32::MAX as u64 {
        return Err(Errno::EINVAL);
    }
    let block = blocking(h) && s.flags & msg::NBIO == 0;
    let stream = is_stream(h);
    let mut done = moved_before(ctx);
    let mut moved = false;
    loop {
        let left = s.total - done;
        let want = if stream {
            (left as usize).min(SEND_CHUNK)
        } else {
            left as usize
        };
        let data = match gather(ctx, &s.iov, done, want) {
            Ok(d) => d,
            Err(_) if done > 0 => return Ok(Rv::one(done)),
            Err(e) => return Err(e),
        };
        let mut flags = s.flags | if block { msg::NBIO } else { 0 };
        // Out-of-band data marks the end of the whole send.
        if stream && (want as u64) < left {
            flags &= !MSG_OOB;
        }
        let mut keep: Option<OwnedFd> = None;
        let mut ctl = if done == 0 { s.control.clone() } else { None };
        if let Some(c) = ctl.as_mut().filter(|_| is_local(h)) {
            control::internalize(ctx, c, &mut keep);
        }
        let r = host_send(h, s.name.as_deref(), &data, ctl.as_deref(), flags);
        drop(keep);
        match r {
            Ok(n) => {
                done += n as u64;
                moved |= n > 0;
                if done >= s.total || !stream {
                    return Ok(Rv::one(done));
                }
                if n == want {
                    continue;
                }
                if !block {
                    return Ok(Rv::one(done));
                }
            }
            // The partial-transfer rule.
            Err(Errno::EAGAIN) if !block && done > 0 => return Ok(Rv::one(done)),
            Err(Errno::EAGAIN) if block => {
                if !moved && timed_out(ctx) {
                    return if done > 0 {
                        Ok(Rv::one(done))
                    } else {
                        Err(Errno::EAGAIN)
                    };
                }
            }
            Err(e) => return Err(e),
        }
        return park(
            ctx,
            h,
            Block {
                read: false,
                timeo: so::SNDTIMEO,
                done,
                moved,
                restart: true,
            },
        );
    }
}

/// A receive (`recvit`, `soo_read`): where the data goes, whether the
/// caller wants the sender's address (`msg_name` and its length) and
/// control data (`msg_control` and its size), and the flags.
struct Recv {
    iov: Vec<(u64, u64)>,
    total: u64,
    name: Option<(u64, u32)>,
    control: Option<(u64, u32)>,
    flags: i32,
}

/// What a receive reports besides its data.
struct Got {
    /// Bytes received in all.
    n: u64,
    /// The address length to report (`None`: leave it).
    namelen: Option<u32>,
    /// The control data copied (`None`: no buffer, or not the first
    /// piece).
    controllen: Option<u32>,
    /// `msg_flags`.
    flags: i32,
    /// `MSG_WAITALL` wants more: once the caller has written what the
    /// first piece reports, the call waits for the rest ([`more`]).
    more: bool,
    /// Whether this is the first piece (the others report no address or
    /// control data).
    first: bool,
}

/// Waits for the rest of a `MSG_WAITALL` receive that has `n` bytes.
fn more(ctx: &mut Ctx<'_>, h: RawFd, n: u64) -> SysResult {
    park(
        ctx,
        h,
        Block {
            read: true,
            timeo: so::RCVTIMEO,
            done: n,
            moved: true,
            restart: true,
        },
    )
}

/// One host `recvmsg` of at most `want` bytes into the spare capacity of
/// empty `data` (whose length becomes what was received): the address
/// when `name`, the whole control data always (so that the descriptors
/// it carries are installed even for a caller without a buffer, as XNU
/// installs them).
fn host_recv(
    h: RawFd,
    data: &mut Vec<u8>,
    want: usize,
    name: Option<&mut Addr>,
    control: &mut [u8],
    flags: i32,
) -> Result<(usize, u32, i32), Errno> {
    data.clear();
    data.reserve(want);
    let room = &mut data.spare_capacity_mut()[..want];
    let mut iov = libc::iovec {
        iov_base: room.as_mut_ptr().cast(),
        iov_len: room.len(),
    };
    // SAFETY: an all-zero msghdr is valid; its pointers are set below.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    let named = name.is_some();
    let mut dummy = Addr::new();
    let sa = name.unwrap_or(&mut dummy);
    if named {
        m.msg_name = sa.buf.as_mut_ptr().cast();
        m.msg_namelen = 256;
    }
    m.msg_iov = &raw mut iov;
    m.msg_iovlen = 1;
    m.msg_control = control.as_mut_ptr().cast();
    m.msg_controllen = control.len() as libc::socklen_t;
    // SAFETY: every pointer in `m` is valid for its length for the call.
    let n = host_result(unsafe { libc::recvmsg(h, &mut m, flags) })?;
    // SAFETY: the host initialized the first `n` (at most `want`) bytes
    // of the spare capacity.
    unsafe { data.set_len(n) };
    if named {
        sa.len = m.msg_namelen;
    }
    Ok((n, m.msg_controllen, m.msg_flags))
}

/// Receives into `r` from host socket `h`. A blocking socket sleeps for
/// data within `SO_RCVTIMEO` (`EAGAIN` after it); with `MSG_WAITALL` a
/// stream socket gathers the whole request unless the stream ends, a
/// wait times out, or a signal comes, which return what it has. The
/// address and control data are those of the first data received,
/// copied out as that piece arrives.
fn recv(ctx: &mut Ctx<'_>, h: RawFd, r: &Recv) -> Result<Got, SysResult> {
    if r.total > i32::MAX as u64 {
        return Err(Err(Errno::EINVAL));
    }
    let added = if blocking(h) && r.flags & (msg::DONTWAIT | msg::NBIO) == 0 {
        msg::NBIO
    } else {
        0
    };
    let block = added != 0;
    let done = moved_before(ctx);
    let want = ((r.total - done) as usize).min(RECV_MAX);
    writable(ctx, &r.iov, done, want).map_err(Err)?;
    let mut data = Vec::with_capacity(want);
    let mut sa = Addr::new();
    let mut ctl = vec![0u8; CONTROL_MAX];
    let got = host_recv(
        h,
        &mut data,
        want,
        r.name.map(|_| &mut sa),
        &mut ctl,
        r.flags | added,
    );
    let (n, ctl_len, flags) = match got {
        Ok(v) => v,
        Err(Errno::EAGAIN) if block => {
            if timed_out(ctx) {
                return Err(if done > 0 {
                    Ok(Rv::one(done))
                } else {
                    Err(Errno::EAGAIN)
                });
            }
            return Err(park(
                ctx,
                h,
                Block {
                    read: true,
                    timeo: so::RCVTIMEO,
                    done,
                    moved: false,
                    restart: true,
                },
            ));
        }
        Err(e) if done > 0 => {
            let _ = e;
            return Err(Ok(Rv::one(done)));
        }
        Err(e) => return Err(Err(e)),
    };
    let flags = flags & !added;
    let ctl = &mut ctl[..(ctl_len as usize).min(CONTROL_MAX)];
    if r.flags & msg::PEEK == 0 {
        control::externalize(ctx, ctl).map_err(Err)?;
    }
    scatter(ctx, &r.iov, done, &data[..n]).map_err(Err)?;
    let total = done + n as u64;
    // MSG_WAITALL on a stream goes on for the rest.
    let more = block
        && r.flags & msg::WAITALL != 0
        && r.flags & msg::PEEK == 0
        && n > 0
        && total < r.total
        && is_stream(h);
    if done > 0 {
        // A later piece: the first reported the address and control.
        return Ok(Got {
            n: total,
            namelen: None,
            controllen: None,
            flags,
            more,
            first: false,
        });
    }
    let namelen = match r.name {
        Some((addr, len)) => copyout_sa(ctx, addr, len, sa.bytes()),
        None => None,
    };
    let mut flags = flags;
    let controllen = match r.control {
        Some((addr, cap)) => {
            let (len, trunc) = control::copyout(ctx, addr, cap, ctl).map_err(Err)?;
            flags |= trunc;
            Some(len)
        }
        None => None,
    };
    Ok(Got {
        n: total,
        namelen,
        controllen,
        flags,
        more,
        first: true,
    })
}

/// `sendto(s, buf, len, flags, to, tolen)`: `MSG_SKIPCFIL` (`EPERM`) and
/// the length (`EINVAL`) are checked before the descriptor.
pub fn sendto(
    ctx: &mut Ctx<'_>,
    fd: i32,
    buf: u64,
    len: u64,
    flags: i32,
    to: u64,
    tolen: u32,
) -> SysResult {
    if flags & msg::SKIPCFIL != 0 {
        return Err(Errno::EPERM);
    }
    if len > i64::MAX as u64 {
        return Err(Errno::EINVAL);
    }
    let (_, h) = sock(ctx, fd)?;
    let name = if to != 0 {
        Some(sockaddr_in(ctx, to, tolen)?)
    } else {
        None
    };
    let s = Send {
        iov: vec![(buf, len)],
        total: len,
        name,
        control: None,
        flags,
    };
    let r = send(ctx, h, &s);
    sigpipe(ctx, h, &r, flags);
    r
}

/// A send's control data (`sockargs`): `EINVAL` for less than a header
/// or more than fits a cluster, then `EFAULT`.
fn control_in(ctx: &Ctx<'_>, addr: u64, len: u32) -> Result<Vec<u8>, Errno> {
    if len < 12 || len > CONTROL_LIMIT {
        return Err(Errno::EINVAL);
    }
    ctx.read(addr, len as usize)
}

/// `sendmsg(s, msg, flags)`: `MSG_SKIPCFIL`, the header, and its
/// scatter-gather list are checked before the descriptor; the address
/// and control data after it.
pub fn sendmsg(ctx: &mut Ctx<'_>, fd: i32, msgp: u64, flags: i32) -> SysResult {
    if flags & msg::SKIPCFIL != 0 {
        return Err(Errno::EPERM);
    }
    let m = Msghdr::read(ctx, msgp)?;
    let (iov, total) = msg_iovecs(ctx, &m)?;
    let (_, h) = sock(ctx, fd)?;
    let name = if m.name() != 0 {
        Some(sockaddr_in(ctx, m.name(), m.namelen())?)
    } else {
        None
    };
    let control = if m.control() != 0 {
        Some(control_in(ctx, m.control(), m.controllen())?)
    } else {
        None
    };
    let s = Send {
        iov,
        total,
        name,
        control,
        flags,
    };
    let r = send(ctx, h, &s);
    sigpipe(ctx, h, &r, flags);
    r
}

/// `recvfrom(s, buf, len, flags, from, fromlenaddr)`: `*fromlenaddr` is
/// read first; after the data, the address as `copyout_sa` copies it and
/// its length (the caller's, when the address could not be copied).
pub fn recvfrom(
    ctx: &mut Ctx<'_>,
    fd: i32,
    buf: u64,
    len: u64,
    flags: i32,
    from: u64,
    fromlenaddr: u64,
) -> SysResult {
    let namelen = if fromlenaddr != 0 {
        ctx.read_u32(fromlenaddr)?
    } else {
        0
    };
    let (_, h) = sock(ctx, fd)?;
    let r = Recv {
        iov: vec![(buf, len)],
        total: len,
        name: (from != 0).then_some((from, namelen)),
        control: None,
        flags,
    };
    let got = match recv(ctx, h, &r) {
        Ok(g) => g,
        Err(r) => return r,
    };
    if got.first && from != 0 && fromlenaddr != 0 {
        ctx.write_u32(fromlenaddr, got.namelen.unwrap_or(namelen))?;
    }
    if got.more {
        return more(ctx, h, got.n);
    }
    Ok(Rv::one(got.n))
}

/// `recvmsg(s, msg, flags)`: the header and its scatter-gather list are
/// read before the descriptor; `msg_flags` starts as `flags` (so the
/// result echoes them), and the header is written back after the data.
pub fn recvmsg(ctx: &mut Ctx<'_>, fd: i32, msgp: u64, flags: i32) -> SysResult {
    let mut m = Msghdr::read(ctx, msgp)?;
    let (iov, total) = msg_iovecs(ctx, &m)?;
    let (_, h) = sock(ctx, fd)?;
    let r = Recv {
        iov,
        total,
        name: (m.name() != 0).then(|| (m.name(), m.namelen())),
        control: (m.control() != 0).then(|| (m.control(), m.controllen())),
        flags,
    };
    let got = match recv(ctx, h, &r) {
        Ok(g) => g,
        Err(r) => return r,
    };
    if let Some(l) = got.namelen {
        m.set_u32(8, l);
    }
    if let Some(l) = got.controllen {
        m.set_u32(40, l);
    }
    m.set_u32(44, got.flags as u32);
    ctx.write(msgp, &m.0)?;
    if got.more {
        return more(ctx, h, got.n);
    }
    Ok(Rv::one(got.n))
}

/// `read`/`readv` on a socket (`soo_read`): a receive without flags.
pub fn readv(ctx: &mut Ctx<'_>, fd: i32, iov: Vec<(u64, u64)>) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    let total = iov.iter().map(|x| x.1).sum();
    let r = Recv {
        iov,
        total,
        name: None,
        control: None,
        flags: 0,
    };
    match recv(ctx, h, &r) {
        Ok(g) if g.more => more(ctx, h, g.n),
        Ok(g) => Ok(Rv::one(g.n)),
        Err(r) => r,
    }
}

/// `read` on a socket.
pub fn read(ctx: &mut Ctx<'_>, fd: i32, buf: u64, nbyte: u64) -> SysResult {
    readv(ctx, fd, vec![(buf, nbyte)])
}

/// `write`/`writev` on a socket (`soo_write`): a send without flags;
/// `EPIPE` raises `SIGPIPE` unless the socket has `SO_NOSIGPIPE`.
pub fn writev(ctx: &mut Ctx<'_>, fd: i32, iov: Vec<(u64, u64)>) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    let total = iov.iter().map(|x| x.1).sum();
    let s = Send {
        iov,
        total,
        name: None,
        control: None,
        flags: 0,
    };
    let r = send(ctx, h, &s);
    sigpipe(ctx, h, &r, 0);
    r
}

/// `write` on a socket.
pub fn write(ctx: &mut Ctx<'_>, fd: i32, buf: u64, nbyte: u64) -> SysResult {
    writev(ctx, fd, vec![(buf, nbyte)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scatter_lists_are_walked_from_an_offset() {
        let iov = [(0x1000, 4), (0x2000, 0), (0x3000, 8)];
        let mut seen = Vec::new();
        ranges(&iov, 2, 7, |addr, at, n| {
            seen.push((addr, at, n));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![(0x1002, 0, 2), (0x3000, 2, 5)]);
        assert_eq!(CONTROL_LIMIT, 1030);
    }
}

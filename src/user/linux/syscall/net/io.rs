//! Socket transfers: `sendto`, `recvfrom`, `sendmsg`, `recvmsg`,
//! `sendmmsg`, `recvmmsg`, and `read`/`write` on sockets
//! (`sock_read_iter`, `sock_write_iter`).
//!
//! | Behavior | Rule |
//! |---|---|
//! | Blocking | a stream send waits until everything is sent, a receive until data (all of it with `MSG_WAITALL`) arrives; `O_NONBLOCK`, `MSG_DONTWAIT`, or a zero timeout never wait |
//! | Timeouts | `SO_RCVTIMEO`/`SO_SNDTIMEO` end a wait with the bytes transferred, or `EAGAIN` |
//! | Signals | end a wait with the bytes transferred, or `-ERESTARTSYS` (`EINTR` with a timeout set) |
//! | `MSG_TRUNC` | a datagram receive returns the datagram's whole length; TCP discards the bytes |
//! | Addresses | TCP ignores a destination and reports no source; a Unix stream refuses one (`EISCONN`, `EOPNOTSUPP`); a Unix sender without a name reports none (`msg_namelen` 0) |
//! | `SIGPIPE` | with `EPIPE` from a stream socket (TCP, Unix stream) that sent nothing, unless `MSG_NOSIGNAL` |
//! | Errors | TCP without a connection is `EPIPE` to send; a Unix stream is `EINVAL` to receive from unconnected and `ENOTCONN` for a Unix datagram send without a peer |
//! | `MSG_CMSG_COMPAT` | 0, as in a kernel without `CONFIG_COMPAT` (the personality provides no 32-bit system calls): the bit is not refused |

use std::os::fd::{OwnedFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::fd::OpenFile;
use super::super::super::net::addr::{self, Addr, UnixName};
use super::super::super::net::msg::Out;
use super::super::super::net::name::{self, Place};
use super::super::super::net::opts::Timeout;
use super::super::super::net::sys::{self, HostAddr};
use super::super::super::net::{Socket, host_msg_flags, lx, netlink};
use super::super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::super::wait::{Resume, SockWait, Wait};
use super::super::io::{MAX_RW_COUNT, iovec_room};
use super::super::iov::import_iovec;
use super::super::{Ctx, SysResult, is_blocked};
use super::{nonblocking, progress, read_addr, scm, sleep, sock_of, unix_target_error, write_addr};

/// A datagram's most bytes, the receive bounce buffer's cap: Linux's
/// largest default send buffer, doubled, is 425,984 bytes; `SO_SNDBUFFORCE`
/// raises it further.
const DGRAM_MAX: usize = 4 << 20;
/// Host bounce size for one stream step.
const CHUNK: usize = 1 << 20;
/// `UIO_MAXIOV`.
const UIO_MAXIOV: u64 = 1024;
/// `sizeof(struct msghdr)` on the 64-bit ABIs.
const MSGHDR: u64 = 56;
/// `sizeof(struct mmsghdr)`.
const MMSGHDR: u64 = 64;

/// What a receive produced.
pub struct Got {
    /// The call's result: the bytes stored, or with `MSG_TRUNC` a
    /// datagram's whole length.
    pub len: usize,
    /// The source address as `msg_name` receives it (empty: none).
    pub from: Vec<u8>,
    /// `msg_flags` the protocol reports (`MSG_TRUNC`, `MSG_EOR`,
    /// `MSG_OOB`, `MSG_CTRUNC`).
    pub flags: u32,
    /// Descriptors passed with the data.
    pub fds: Vec<OwnedFd>,
    /// Control messages of the protocol's level (`SOL_NETLINK`): type and
    /// data.
    pub netlink: Vec<(i32, Vec<u8>)>,
}

/// Writes `data` into the vectors `iov` from byte `skip` on.
fn scatter_at(c: &Ctx<'_>, iov: &[(u64, u64)], mut skip: u64, data: &[u8]) -> Result<(), Errno> {
    let mut done = 0usize;
    for &(base, len) in iov {
        if done == data.len() {
            break;
        }
        if skip >= len {
            skip -= len;
            continue;
        }
        let n = ((len - skip) as usize).min(data.len() - done);
        c.write_mem(base + skip, &data[done..done + n])?;
        skip = 0;
        done += n;
    }
    Ok(())
}

/// The bytes of the vectors `iov` up to the first unreadable one.
fn gather(c: &Ctx<'_>, iov: &[(u64, u64)]) -> Result<(Vec<u8>, u64), Errno> {
    let total = iov.iter().map(|v| v.1).sum::<u64>().min(MAX_RW_COUNT);
    let mut data = Vec::new();
    for &(base, len) in iov {
        let len = len.min(total - data.len() as u64);
        if len == 0 {
            continue;
        }
        match c.read_mem(base, len as usize) {
            Ok(d) => data.extend_from_slice(&d),
            Err(e) if data.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok((data, total))
}

/// The source address a receive reports.
fn source(c: &Ctx<'_>, s: &Socket, h: HostAddr) -> Vec<u8> {
    if s.tcp() {
        return Vec::new();
    }
    // The host may not name a stream's source; it is the peer.
    let h = match h {
        HostAddr::Unix { ref name, .. } if name.is_empty() && s.connected_type() => {
            sys::peername(&s.file).unwrap_or(h)
        }
        HostAddr::Unspec if s.connected_type() => sys::peername(&s.file).unwrap_or(h),
        h => h,
    };
    match name::guest_addr(&c.p.vfs, h) {
        Addr::Unix(UnixName::Unnamed) | Addr::Unspec => Vec::new(),
        a => a.encode(),
    }
}

/// Host `msg_flags` as Linux's.
fn linux_flags(h: i32) -> u32 {
    let mut f = 0;
    if h & libc::MSG_TRUNC != 0 {
        f |= lx::MSG_TRUNC;
    }
    if h & libc::MSG_EOR != 0 {
        f |= lx::MSG_EOR;
    }
    if h & libc::MSG_OOB != 0 {
        f |= lx::MSG_OOB;
    }
    if h & libc::MSG_CTRUNC != 0 {
        f |= lx::MSG_CTRUNC;
    }
    f
}

/// `sock_recvmsg` of socket `s` into the guest vectors `iov`, continuing
/// the progress `w`.
pub fn recv(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    s: &Socket,
    iov: &[(u64, u64)],
    flags: u32,
    mut w: SockWait,
) -> Result<Got, Errno> {
    if let Some(n) = &s.netlink {
        return netlink_recv(c, file, s, n, iov, flags, w);
    }
    let total = iov.iter().map(|v| v.1).sum::<u64>().min(MAX_RW_COUNT);
    let room = iovec_room(c, iov).min(total);
    if total > 0 && room == 0 {
        return Err(Errno(EFAULT));
    }
    // An IP socket's error queue is empty; netlink has none.
    if flags & lx::MSG_ERRQUEUE != 0 && !s.unix() && s.domain != lx::AF_NETLINK {
        return Err(Errno(EAGAIN));
    }
    let timeout = s.state.lock().unwrap().rcvtimeo;
    let nonblock = nonblocking(file, timeout) || flags & lx::MSG_DONTWAIT != 0;
    let peek = flags & lx::MSG_PEEK != 0;
    let trunc = flags & lx::MSG_TRUNC != 0;
    let mut hflags = host_msg_flags(flags) | libc::MSG_DONTWAIT;
    if cfg!(target_os = "linux") && trunc && (s.tcp() || !s.connected_type()) {
        hflags |= libc::MSG_TRUNC;
    }
    loop {
        let step = if s.stream() {
            (room - w.done.min(room)).min(CHUNK as u64) as usize
        } else {
            (room as usize).min(DGRAM_MAX)
        };
        // Darwin cannot report a datagram's length past the buffer: ask
        // first.
        let whole = if trunc && !s.connected_type() && !cfg!(target_os = "linux") {
            sys::next_datagram(&s.file)
        } else {
            0
        };
        let mut buf = vec![0u8; step];
        match sys::recvmsg(&s.file, &mut buf, hflags) {
            Ok(r) => {
                let stored = r.len.min(buf.len());
                if !(s.tcp() && trunc) {
                    scatter_at(c, iov, w.done, &buf[..stored])?;
                }
                let from = source(c, s, r.from);
                let rflags = linux_flags(r.flags);
                if s.stream() {
                    w.done += r.len as u64;
                    let more = flags & lx::MSG_WAITALL != 0
                        && !peek
                        && r.len > 0
                        && r.fds.is_empty()
                        && w.done < room;
                    if more {
                        continue;
                    }
                    return Ok(Got {
                        len: w.done as usize,
                        from,
                        flags: rflags,
                        fds: r.fds,
                        netlink: r.netlink,
                    });
                }
                let len = if trunc && rflags & lx::MSG_TRUNC != 0 {
                    r.len.max(whole)
                } else {
                    stored
                };
                return Ok(Got {
                    len,
                    from,
                    flags: rflags,
                    fds: r.fds,
                    netlink: r.netlink,
                });
            }
            Err(Errno(EINTR)) => continue,
            Err(Errno(EAGAIN)) => {
                let partial = Got {
                    len: w.done as usize,
                    from: Vec::new(),
                    flags: 0,
                    fds: Vec::new(),
                    netlink: Vec::new(),
                };
                if nonblock {
                    return if w.done > 0 {
                        Ok(partial)
                    } else {
                        Err(Errno(EAGAIN))
                    };
                }
                let r = Err(sleep(c, s, false, w, timeout, EAGAIN));
                return if w.done > 0 && !is_blocked(&r) {
                    Ok(partial)
                } else {
                    r
                };
            }
            Err(_) if w.done > 0 => {
                return Ok(Got {
                    len: w.done as usize,
                    from: Vec::new(),
                    flags: 0,
                    fds: Vec::new(),
                    netlink: Vec::new(),
                });
            }
            // unix_stream_read_generic: a stream not connected is EINVAL.
            Err(Errno(ENOTCONN)) if s.unix() && s.stream() => return Err(Errno(EINVAL)),
            Err(e) => return Err(e),
        }
    }
}

/// `netlink_recvmsg` of an emulated netlink socket: the next datagram from
/// the kernel, waited for as any datagram is; the source is the kernel
/// (port ID 0).
fn netlink_recv(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    s: &Socket,
    n: &netlink::Endpoint,
    iov: &[(u64, u64)],
    flags: u32,
    w: SockWait,
) -> Result<Got, Errno> {
    if flags & lx::MSG_OOB != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    let total = iov.iter().map(|v| v.1).sum::<u64>().min(MAX_RW_COUNT) as usize;
    let timeout = s.state.lock().unwrap().rcvtimeo;
    let Some(d) = n.recv(&s.file, total, flags & lx::MSG_PEEK != 0) else {
        if nonblocking(file, timeout) || flags & lx::MSG_DONTWAIT != 0 {
            return Err(Errno(EAGAIN));
        }
        return Err(sleep(c, s, false, w, timeout, EAGAIN));
    };
    let stored = d.bytes.len().min(total);
    scatter_at(c, iov, 0, &d.bytes[..stored])?;
    Ok(Got {
        len: if flags & lx::MSG_TRUNC != 0 {
            d.bytes.len()
        } else {
            stored
        },
        from: netlink::encode_addr(0, 0),
        flags: if stored < d.bytes.len() {
            lx::MSG_TRUNC
        } else {
            0
        },
        fds: Vec::new(),
        // netlink_cmsg_recv_pktinfo: the kernel's unicasts have group 0.
        netlink: if d.pktinfo {
            vec![(netlink::NETLINK_PKTINFO, 0u32.to_le_bytes().to_vec())]
        } else {
            Vec::new()
        },
    })
}

/// `sock_sendmsg` of `data` on socket `s` to `to` (`target` the guest's
/// name for it), passing the host descriptors `fds` with the first bytes,
/// continuing the progress `w`. Returns the result and whether any bytes
/// (and so the descriptors) went.
#[allow(clippy::too_many_arguments)]
pub fn send(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    s: &Socket,
    data: &[u8],
    flags: u32,
    to: Option<(&HostAddr, &Addr)>,
    fds: &[RawFd],
    mut w: SockWait,
) -> (Result<usize, Errno>, bool) {
    c.sigpipe_decided = true;
    let timeout = s.state.lock().unwrap().sndtimeo;
    let nonblock = nonblocking(file, timeout) || flags & lx::MSG_DONTWAIT != 0;
    #[cfg(target_os = "linux")]
    let quiet = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let quiet = 0;
    let hflags = host_msg_flags(flags) | libc::MSG_DONTWAIT | quiet;
    let mut done = (w.done as usize).min(data.len());
    loop {
        let chunk = if s.stream() { &data[done..] } else { data };
        let pass = if done == 0 { fds } else { &[] };
        match sys::sendmsg(&s.file, chunk, hflags, to.map(|t| t.0), pass) {
            Ok(n) => {
                done += n;
                if !s.stream() || done >= data.len() {
                    return (Ok(done), true);
                }
            }
            Err(Errno(EINTR)) => {}
            // Darwin refuses a Unix datagram its receiver has no room for;
            // Linux waits for the room.
            Err(Errno(e @ (EAGAIN | ENOBUFS)))
                if e == EAGAIN || (s.unix() && !s.connected_type()) =>
            {
                let any = done > 0;
                if nonblock {
                    return (if any { Ok(done) } else { Err(Errno(EAGAIN)) }, any);
                }
                w.done = done as u64;
                if e == ENOBUFS {
                    let r = retry_soon(c, w, timeout);
                    return (if any && !is_blocked(&r) { Ok(done) } else { r }, any);
                }
                let r = Err(sleep(c, s, true, w, timeout, EAGAIN));
                return (if any && !is_blocked(&r) { Ok(done) } else { r }, any);
            }
            Err(_) if done > 0 => return (Ok(done), true),
            Err(e) => return (Err(send_error(c, s, flags, to.map(|t| t.1), e)), false),
        }
    }
}

/// Sleeps briefly before trying a send again (a Darwin Unix datagram
/// receiver without room), within the timeout.
fn retry_soon(c: &mut Ctx<'_>, w: SockWait, timeout: Timeout) -> Result<usize, Errno> {
    if w.deadline.is_some_and(|d| Instant::now() >= d) {
        return Err(Errno(EAGAIN));
    }
    if c.signal_pending() {
        return Err(Errno(if timeout.is_some() {
            EINTR
        } else {
            ERESTARTSYS
        }));
    }
    let soon = Instant::now() + Duration::from_millis(1);
    let until = w.deadline.map_or(soon, |d| d.min(soon));
    Err(c.block(Wait::until(Some(until)), Resume::Socket(w)))
}

/// A send's host error as Linux reports it, raising `SIGPIPE` for a
/// stream's `EPIPE` unless `MSG_NOSIGNAL`.
fn send_error(c: &mut Ctx<'_>, s: &Socket, flags: u32, target: Option<&Addr>, e: Errno) -> Errno {
    let e = match e.0 {
        // sk_stream_wait_connect: TCP not connected.
        ENOTCONN if s.tcp() => Errno(EPIPE),
        // unix_dgram_sendmsg: no peer.
        EDESTADDRREQ if s.unix() => Errno(ENOTCONN),
        _ => target.map_or(e, |t| unix_target_error(t, e)),
    };
    if e.0 == EPIPE && s.stream() && flags & lx::MSG_NOSIGNAL == 0 {
        c.send_sigpipe();
    }
    e
}

/// Whether socket `s` has a peer.
fn connected(s: &Socket) -> bool {
    sys::peername(&s.file).is_ok()
}

/// The destination a send names (`None`: the connected peer), by
/// protocol: TCP and a Unix sequenced-packet socket ignore it; a Unix
/// stream refuses it; datagram sockets check it as `unix_validate_addr`,
/// `udp_sendmsg`, and `udpv6_sendmsg` do.
fn destination(
    c: &Ctx<'_>,
    s: &Socket,
    b: Option<&[u8]>,
) -> Result<Option<(HostAddr, Addr)>, Errno> {
    let Some(b) = b else {
        return Ok(None);
    };
    if s.tcp() || (s.unix() && s.stype == lx::SOCK_SEQPACKET) {
        return Ok(None);
    }
    let udp = s.protocol == lx::IPPROTO_UDP;
    let a = match s.domain {
        lx::AF_UNIX if b.is_empty() => return Ok(None),
        lx::AF_UNIX if s.stream() => {
            return Err(Errno(if connected(s) { EISCONN } else { EOPNOTSUPP }));
        }
        lx::AF_UNIX => {
            if b.len() <= addr::SUN_PATH_OFFSET {
                return Err(Errno(EINVAL));
            }
            Addr::Unix(addr::parse_unix(b)?)
        }
        lx::AF_INET => {
            if b.len() < addr::SOCKADDR_IN_SIZE {
                return Err(Errno(EINVAL));
            }
            // AF_UNSPEC reads as AF_INET here.
            let mut v = b.to_vec();
            if addr::family(&v) == Some(lx::AF_UNSPEC as u16) {
                v[..2].copy_from_slice(&(lx::AF_INET as u16).to_le_bytes());
            }
            addr::parse_v4(&v, false)?
        }
        // netlink_sendmsg: a name of no length names no destination.
        lx::AF_NETLINK if b.is_empty() => return Ok(None),
        lx::AF_NETLINK => {
            let (pid, groups) = netlink::parse_addr(b)?;
            Addr::Netlink { pid, groups }
        }
        lx::AF_INET6 => {
            if b.len() < 2 {
                return Err(Errno(EINVAL));
            }
            match addr::family(b).map(i32::from) {
                Some(lx::AF_INET6) => addr::parse_v6(b)?,
                // An IPv4 destination, as its mapped IPv6 address.
                Some(lx::AF_INET) => match addr::parse_v4(b, false)? {
                    Addr::V4 { ip, port } => {
                        let mut v6 = [0u8; 16];
                        v6[10] = 0xff;
                        v6[11] = 0xff;
                        v6[12..].copy_from_slice(&ip);
                        Addr::V6 {
                            ip: v6,
                            port,
                            flow: 0,
                            scope: 0,
                        }
                    }
                    _ => return Err(Errno(EINVAL)),
                },
                Some(lx::AF_UNSPEC) => return Ok(None),
                _ => return Err(Errno(EINVAL)),
            }
        }
        _ => return Err(Errno(EOPNOTSUPP)),
    };
    if udp && matches!(a, Addr::V4 { port: 0, .. } | Addr::V6 { port: 0, .. }) {
        return Err(Errno(EINVAL));
    }
    match name::place(&c.p.vfs, &a, false)? {
        Place::Addr(h) => Ok(Some((h, a))),
        Place::At(..) => Err(Errno(ENAMETOOLONG)),
    }
}

/// The send of one message: its destination and control data checked in
/// the protocol's order, then the data.
#[allow(clippy::too_many_arguments)]
fn send_message(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    s: &Socket,
    data: &[u8],
    flags: u32,
    name: Option<&[u8]>,
    ctl: &[u8],
    w: SockWait,
) -> Result<usize, Errno> {
    if let Some(n) = &s.netlink {
        return netlink_send(c, s, n, data, flags, name, ctl);
    }
    // unix_*_sendmsg take the control data first; IP protocols check the
    // address first. A send resumed in part already passed its
    // descriptors.
    let ctl = if w.done == 0 { ctl } else { &[] };
    let (dest, sending) = if s.unix() {
        let sending = scm::parse(c, s, ctl)?;
        (destination(c, s, name)?, sending)
    } else {
        let dest = destination(c, s, name)?;
        (dest, scm::parse(c, s, ctl)?)
    };
    // OOB data is a stream's (unix_dgram_sendmsg, udp_sendmsg).
    if flags & lx::MSG_OOB != 0 && !s.stream() {
        return Err(Errno(EOPNOTSUPP));
    }
    let carried = scm::carry(&sending.files)?;
    let to = dest.as_ref().map(|(h, a)| (h, a));
    let (r, went) = send(c, file, s, data, flags, to, &carried.raw, w);
    if !went {
        carried.failed();
    }
    r
}

/// `netlink_sendmsg` of an emulated netlink socket: `MSG_OOB`, an empty
/// message, the control data, then the destination and the message.
fn netlink_send(
    c: &mut Ctx<'_>,
    s: &Socket,
    n: &netlink::Endpoint,
    data: &[u8],
    flags: u32,
    name: Option<&[u8]>,
    ctl: &[u8],
) -> Result<usize, Errno> {
    if flags & lx::MSG_OOB != 0 {
        return Err(Errno(EOPNOTSUPP));
    }
    if data.is_empty() {
        return Err(Errno(ENODATA));
    }
    scm::parse(c, s, ctl)?;
    let sndbuf = s
        .state
        .lock()
        .unwrap()
        .sndbuf
        .map_or(netlink::MEM_DEFAULT, |v| v as usize);
    let to = name.filter(|b| !b.is_empty());
    n.send(
        &s.file,
        data,
        to,
        c.p.pid,
        super::admin(c),
        sndbuf,
        &netlink::ifaces::snapshot,
    )
}

/// `sendto` (and `send`).
pub fn sendto(
    c: &mut Ctx<'_>,
    fd: i32,
    buf: u64,
    len: u64,
    flags: u32,
    uaddr: u64,
    alen: i32,
) -> SysResult {
    let len = len.min(MAX_RW_COUNT);
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let name = if uaddr != 0 {
        Some(read_addr(c, uaddr, alen)?)
    } else {
        None
    };
    let data = c.read_mem(buf, len as usize)?;
    let w = progress(c, s.state.lock().unwrap().sndtimeo);
    let flags = flags & !lx::MSG_INTERNAL;
    send_message(c, &file, s, &data, flags, name.as_deref(), &[], w).map(|n| n as u64)
}

/// `recvfrom` (and `recv`).
pub fn recvfrom(
    c: &mut Ctx<'_>,
    fd: i32,
    buf: u64,
    len: u64,
    flags: u32,
    uaddr: u64,
    ulen: u64,
) -> SysResult {
    let len = len.min(MAX_RW_COUNT);
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let w = progress(c, s.state.lock().unwrap().rcvtimeo);
    let got = recv(c, &file, s, &[(buf, len)], flags, w)?;
    scm::discard(got.fds);
    if uaddr != 0 {
        write_addr(c, &got.from, uaddr, ulen)?;
    }
    Ok(got.len as u64)
}

/// A guest `struct msghdr`.
struct MsgHdr {
    name: u64,
    namelen: i32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: u32,
}

/// `copy_msghdr_from_user` and `__copy_msghdr`: a negative name length is
/// `EINVAL`, a longer one than `sockaddr_storage` is cut to it, a null name
/// has none, and more than `UIO_MAXIOV` vectors are `EMSGSIZE`.
fn read_msghdr(c: &Ctx<'_>, at: u64) -> Result<MsgHdr, Errno> {
    let b = c.read_mem(at, MSGHDR as usize)?;
    let q = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
    let d = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    let mut m = MsgHdr {
        name: q(0),
        namelen: d(8) as i32,
        iov: q(16),
        iovlen: q(24),
        control: q(32),
        controllen: q(40),
        flags: d(48),
    };
    if m.name == 0 {
        m.namelen = 0;
    }
    if m.namelen < 0 {
        return Err(Errno(EINVAL));
    }
    m.namelen = m.namelen.min(addr::SOCKADDR_STORAGE_SIZE as i32);
    if m.iovlen > UIO_MAXIOV {
        return Err(Errno(EMSGSIZE));
    }
    Ok(m)
}

/// One `sendmsg` of the header at `at`; `allowed` are the header flags
/// taken (`MSG_EOR` for `sendmmsg`).
fn send_one(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    s: &Socket,
    at: u64,
    flags: u32,
    allowed: u32,
    w: SockWait,
) -> Result<(usize, u64), Errno> {
    let m = read_msghdr(c, at)?;
    let name = if m.namelen > 0 {
        Some(c.read_mem(m.name, m.namelen as usize)?)
    } else {
        None
    };
    let iov = import_iovec(c, m.iov, m.iovlen)?;
    if m.controllen > i32::MAX as u64 {
        return Err(Errno(ENOBUFS));
    }
    let ctl = if m.controllen > 0 {
        c.read_mem(m.control, m.controllen as usize)?
    } else {
        Vec::new()
    };
    let (data, total) = gather(c, &iov)?;
    if !s.stream() && (data.len() as u64) < total {
        return Err(Errno(EFAULT));
    }
    let flags = (flags | (m.flags & allowed)) & !lx::MSG_INTERNAL;
    send_message(c, file, s, &data, flags, name.as_deref(), &ctl, w).map(|n| (n, total))
}

/// `sendmsg`.
pub fn sendmsg(c: &mut Ctx<'_>, fd: i32, at: u64, flags: u32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let w = progress(c, s.state.lock().unwrap().sndtimeo);
    send_one(c, &file, s, at, flags, 0, w).map(|(n, _)| n as u64)
}

/// One `recvmsg` into the header at `at`: the data, the source into
/// `msg_name` (by the guest's `msg_namelen`), the control data, then
/// `msg_flags` and `msg_controllen`.
fn recv_one(
    c: &mut Ctx<'_>,
    file: &OpenFile,
    s: &Socket,
    at: u64,
    flags: u32,
    w: SockWait,
) -> Result<(usize, u32), Errno> {
    let m = read_msghdr(c, at)?;
    let iov = import_iovec(c, m.iov, m.iovlen)?;
    let got = recv(c, file, s, &iov, flags, w)?;
    let files = scm::receive(c, got.fds);
    let mut out = Out::new(m.controllen.min(i32::MAX as u64) as usize);
    for (kind, data) in &got.netlink {
        // put_cmsg: no buffer is MSG_CTRUNC.
        if m.control == 0 {
            out.truncated = true;
        } else {
            out.put(lx::SOL_NETLINK, *kind, data);
        }
    }
    let cloexec = flags & lx::MSG_CMSG_CLOEXEC != 0;
    scm::deliver(c, s, &mut out, m.control == 0, files, cloexec);
    if m.name != 0 {
        write_addr(c, &got.from, m.name, at + 8)?;
    }
    if !out.bytes.is_empty() {
        c.write_mem(m.control, &out.bytes)?;
    }
    let mut oflags = (flags & lx::MSG_CMSG_CLOEXEC) | got.flags;
    if out.truncated {
        oflags |= lx::MSG_CTRUNC;
    }
    c.write_u32(at + 48, oflags)?;
    c.write_u64(at + 40, out.bytes.len() as u64)?;
    Ok((got.len, oflags))
}

/// `recvmsg`.
pub fn recvmsg(c: &mut Ctx<'_>, fd: i32, at: u64, flags: u32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let w = progress(c, s.state.lock().unwrap().rcvtimeo);
    recv_one(c, &file, s, at, flags, w).map(|(n, _)| n as u64)
}

/// `sendmmsg`: up to `UIO_MAXIOV` messages, each `msg_len` written as it
/// is sent; an error after the first is dropped, and a message sent in
/// part ends the batch.
pub fn sendmmsg(c: &mut Ctx<'_>, fd: i32, vec: u64, vlen: u32, flags: u32) -> SysResult {
    let vlen = u64::from(vlen).min(UIO_MAXIOV) as u32;
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let mut w = progress(c, s.state.lock().unwrap().sndtimeo);
    while w.count < vlen {
        let at = vec + u64::from(w.count) * MMSGHDR;
        // A sleep inside records the batch position with the progress.
        let (len, total) = match send_one(c, &file, s, at, flags, lx::MSG_EOR, w) {
            Ok(r) => r,
            Err(e) if is_blocked(&Err::<(), _>(e)) => return Err(e),
            Err(e) if w.count == 0 => return Err(e),
            Err(_) => break,
        };
        if c.write_u32(at + MSGHDR, len as u32).is_err() {
            if w.count == 0 {
                return Err(Errno(EFAULT));
            }
            break;
        }
        w.count += 1;
        w.done = 0;
        w.deadline = s.state.lock().unwrap().sndtimeo.map(|t| Instant::now() + t);
        if (len as u64) < total {
            break;
        }
    }
    Ok(u64::from(w.count))
}

/// `recvmmsg`: up to `vlen` messages; `MSG_WAITFORONE` stops waiting after
/// the first; the timeout is checked only between messages (the kernel's
/// behavior) and its remainder written back; an error after the first
/// message is kept for the next call (`sk_err`) unless it is `EAGAIN`.
pub fn recvmmsg(c: &mut Ctx<'_>, fd: i32, vec: u64, vlen: u32, flags: u32, tmo: u64) -> SysResult {
    let resumed = matches!(c.resume, Some(Resume::Socket(_)));
    let limit = if tmo != 0 && !resumed {
        let b = c.read_mem(tmo, 16)?;
        let sec = i64::from_le_bytes(b[..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(b[8..].try_into().unwrap());
        // poll_select_set_timeout.
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno(EINVAL));
        }
        Some(Instant::now() + Duration::new(sec as u64, nsec as u32))
    } else {
        None
    };
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let mut w = progress(c, s.state.lock().unwrap().rcvtimeo);
    if !resumed {
        w.end = limit;
        if flags & lx::MSG_ERRQUEUE == 0 {
            let own = std::mem::take(&mut s.state.lock().unwrap().error);
            if own != 0 {
                return Err(Errno(own));
            }
        }
    }
    let mut err = None;
    while w.count < vlen {
        let mut f = flags & !lx::MSG_WAITFORONE;
        if flags & lx::MSG_WAITFORONE != 0 && w.count > 0 {
            f |= lx::MSG_DONTWAIT;
        }
        let at = vec + u64::from(w.count) * MMSGHDR;
        match recv_one(c, &file, s, at, f, w) {
            Ok((len, oflags)) => {
                if c.write_u32(at + MSGHDR, len as u32).is_err() {
                    err = Some(Errno(EFAULT));
                    break;
                }
                w.count += 1;
                w.done = 0;
                w.deadline = s.state.lock().unwrap().rcvtimeo.map(|t| Instant::now() + t);
                if w.end.is_some_and(|e| Instant::now() >= e) {
                    break;
                }
                if oflags & lx::MSG_OOB != 0 {
                    break;
                }
            }
            // A sleep inside records the batch position with the progress.
            Err(e) if is_blocked(&Err::<(), _>(e)) => return Err(e),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    if tmo != 0 {
        let left = w.end.map_or(Duration::ZERO, |e| {
            e.saturating_duration_since(Instant::now())
        });
        let mut b = (left.as_secs() as i64).to_le_bytes().to_vec();
        b.extend_from_slice(&i64::from(left.subsec_nanos()).to_le_bytes());
        if w.count > 0 {
            c.write_mem(tmo, &b)?;
        }
    }
    match err {
        None => Ok(u64::from(w.count)),
        Some(e) if w.count == 0 => Err(e),
        Some(e) => {
            if e.0 != EAGAIN {
                s.state.lock().unwrap().error = e.0;
            }
            Ok(u64::from(w.count))
        }
    }
}

/// `read`/`readv` on a socket: a receive without flags; descriptors passed
/// with the data are closed.
pub fn read(c: &mut Ctx<'_>, file: &Arc<OpenFile>, iov: &[(u64, u64)]) -> SysResult {
    let s = sock_of(file)?;
    if iov.iter().all(|v| v.1 == 0) {
        return Ok(0);
    }
    let w = progress(c, s.state.lock().unwrap().rcvtimeo);
    let got = recv(c, file, s, iov, 0, w)?;
    scm::discard(got.fds);
    Ok(got.len as u64)
}

/// `write`/`writev` on a socket: a send without flags (`MSG_EOR` for a
/// sequenced-packet socket).
pub fn write(c: &mut Ctx<'_>, file: &Arc<OpenFile>, iov: &[(u64, u64)]) -> SysResult {
    let s = sock_of(file)?;
    let (data, _) = gather(c, iov)?;
    if let Some(n) = &s.netlink {
        return netlink_send(c, s, n, &data, 0, None, &[]).map(|n| n as u64);
    }
    let flags = if s.stype == lx::SOCK_SEQPACKET {
        lx::MSG_EOR
    } else {
        0
    };
    let w = progress(c, s.state.lock().unwrap().sndtimeo);
    let (r, _) = send(c, file, s, &data, flags, None, &[], w);
    r.map(|n| n as u64)
}

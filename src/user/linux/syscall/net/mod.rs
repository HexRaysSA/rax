//! Socket system calls (`net/socket.c`): creation, naming, connection,
//! options, and shutdown here; the transfers in [`io`], ancillary data in
//! [`scm`].
//!
//! Each call checks in its kernel path's order. Most look up the descriptor
//! (`EBADF`) and then require a socket (`ENOTSOCK`); `connect` copies the
//! address in between, `accept4` checks its flags. Blocking is emulated
//! over non-blocking host sockets: a call that would block sleeps until its
//! socket is ready or the socket timeout (`SO_RCVTIMEO`, `SO_SNDTIMEO`)
//! ends it (`EAGAIN`, `EINPROGRESS` for `connect`); a signal ends it with
//! `-ERESTARTSYS`, or `EINTR` when a timeout is set (`sock_intr_errno`).

pub mod io;
pub mod scm;

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::abi::errno::{Errno, from_host};
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::net::addr::{self, Addr, UnixName};
use super::super::net::ifreq::{self, Shape};
use super::super::net::sys::{self, HostAddr};
use super::super::net::{Socket, host_domain, host_type, lx, name, netlink, opts};
use super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::wait::{Resume, SockWait, Wait};
use super::{Ctx, SysResult};

/// `sysctl_somaxconn`.
const SOMAXCONN: i32 = 4096;
/// `ip_unprivileged_port_start`.
const UNPRIVILEGED_PORT: u16 = 1024;

/// Whether the caller holds the network capabilities (an effective UID of
/// 0: `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`).
fn admin(c: &Ctx<'_>) -> bool {
    c.p.creds.1 == 0
}

fn nofile(c: &Ctx<'_>) -> u64 {
    c.p.rlimits[7].0
}

/// Wraps a new socket in a description (`sock_alloc_file`): `O_RDWR`,
/// and `O_NONBLOCK` when asked.
pub(super) fn socket_file(s: Socket, nonblock: bool) -> Arc<OpenFile> {
    let path = s.dname();
    OpenFile::new(
        FileObject::Socket(s),
        FileType::Socket,
        path,
        None,
        O_RDWR | if nonblock { O_NONBLOCK } else { 0 },
    )
}

/// The socket of `file`, or `ENOTSOCK`.
pub(super) fn sock_of(file: &OpenFile) -> Result<&Socket, Errno> {
    match &file.object {
        FileObject::Socket(s) => Ok(s),
        _ => Err(Errno(ENOTSOCK)),
    }
}

/// `move_addr_to_kernel`: at most `sizeof(struct sockaddr_storage)` bytes.
pub(super) fn read_addr(c: &Ctx<'_>, uaddr: u64, len: i32) -> Result<Vec<u8>, Errno> {
    if len < 0 || len as usize > addr::SOCKADDR_STORAGE_SIZE {
        return Err(Errno(EINVAL));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    c.read_mem(uaddr, len as usize)
}

/// `move_addr_to_user`: as much of address `a` as the guest's length
/// allows, and the address's own length back in `*ulen`.
pub(super) fn write_addr(c: &Ctx<'_>, a: &[u8], uaddr: u64, ulen: u64) -> Result<(), Errno> {
    let len = c.read_u32(ulen)? as i32;
    let klen = a.len() as i32;
    let len = len.min(klen);
    if len >= 0 {
        c.write_u32(ulen, klen as u32)?;
    }
    if len != 0 {
        if len < 0 {
            return Err(Errno(EINVAL));
        }
        c.write_mem(uaddr, &a[..len as usize])?;
    }
    Ok(())
}

/// Splits `socket`'s type argument into the type and its flags (`EINVAL`
/// for other flag bits).
fn split_type(t: i32) -> Result<(i32, bool, bool), Errno> {
    if (t & !lx::SOCK_TYPE_MASK) & !(lx::SOCK_CLOEXEC | lx::SOCK_NONBLOCK) != 0 {
        return Err(Errno(EINVAL));
    }
    Ok((
        t & lx::SOCK_TYPE_MASK,
        t & lx::SOCK_NONBLOCK != 0,
        t & lx::SOCK_CLOEXEC != 0,
    ))
}

/// `inet_create`'s protocol switch lookup (`inetsw`, `inetsw6`): the
/// protocol a type and requested protocol select.
fn inet_protocol(domain: i32, kind: i32, protocol: i32, admin: bool) -> Result<i32, Errno> {
    if !(0..lx::IPPROTO_MAX).contains(&protocol) {
        return Err(Errno(EINVAL));
    }
    let ping = if domain == lx::AF_INET6 {
        lx::IPPROTO_ICMPV6
    } else {
        lx::IPPROTO_ICMP
    };
    let table: &[i32] = match kind {
        lx::SOCK_STREAM => &[lx::IPPROTO_TCP, lx::IPPROTO_MPTCP],
        lx::SOCK_DGRAM => &[lx::IPPROTO_UDP, ping],
        // The wildcard entry.
        lx::SOCK_RAW => &[lx::IPPROTO_IP],
        _ => &[],
    };
    let mut err = ESOCKTNOSUPPORT;
    for &answer in table {
        err = 0;
        if protocol == answer {
            if protocol != lx::IPPROTO_IP {
                break;
            }
        } else if protocol == lx::IPPROTO_IP {
            return Ok(answer);
        } else if answer == lx::IPPROTO_IP {
            break;
        }
        err = EPROTONOSUPPORT;
    }
    if err != 0 {
        return Err(Errno(err));
    }
    if kind == lx::SOCK_RAW && !admin {
        return Err(Errno(EPERM));
    }
    Ok(protocol)
}

/// `__sock_create` and the families' `create` without the host: the
/// family, type, and protocol of the new socket.
fn resolve(c: &Ctx<'_>, family: i32, kind: i32, protocol: i32) -> Result<(i32, i32, i32), Errno> {
    if !(0..lx::AF_MAX).contains(&family) {
        return Err(Errno(EAFNOSUPPORT));
    }
    if !(0..lx::SOCK_MAX).contains(&kind) {
        return Err(Errno(EINVAL));
    }
    let family = if family == lx::AF_INET && kind == lx::SOCK_PACKET {
        lx::AF_PACKET
    } else {
        family
    };
    let (kind, protocol) = match family {
        lx::AF_UNIX => {
            if protocol != 0 && protocol != lx::AF_UNIX {
                return Err(Errno(EPROTONOSUPPORT));
            }
            // unix_create: SOCK_RAW is SOCK_DGRAM; the protocol is not kept.
            let kind = match kind {
                lx::SOCK_STREAM | lx::SOCK_DGRAM | lx::SOCK_SEQPACKET => kind,
                lx::SOCK_RAW => lx::SOCK_DGRAM,
                _ => return Err(Errno(ESOCKTNOSUPPORT)),
            };
            (kind, 0)
        }
        lx::AF_INET | lx::AF_INET6 => (kind, inet_protocol(family, kind, protocol, admin(c))?),
        lx::AF_NETLINK => {
            // netlink_create: raw and datagram sockets of a protocol below
            // MAX_LINKS that is registered (the host's on Linux, only
            // NETLINK_ROUTE elsewhere).
            if kind != lx::SOCK_RAW && kind != lx::SOCK_DGRAM {
                return Err(Errno(ESOCKTNOSUPPORT));
            }
            if !(0..netlink::MAX_LINKS).contains(&protocol)
                || (!cfg!(target_os = "linux") && protocol != netlink::NETLINK_ROUTE)
            {
                return Err(Errno(EPROTONOSUPPORT));
            }
            (kind, protocol)
        }
        _ => return Err(Errno(EAFNOSUPPORT)),
    };
    Ok((family, kind, protocol))
}

/// A new socket (`__sock_create`).
fn create(c: &Ctx<'_>, family: i32, kind: i32, protocol: i32) -> Result<Socket, Errno> {
    let (family, kind, protocol) = resolve(c, family, kind, protocol)?;
    if family == lx::AF_NETLINK && !cfg!(target_os = "linux") {
        return Socket::emulated_netlink(kind);
    }
    let fd = sys::socket(host_domain(family), host_type(kind), protocol)?;
    Ok(Socket::new(fd, family, kind, protocol))
}

/// `socket`.
pub fn socket(c: &mut Ctx<'_>, family: i32, stype: i32, protocol: i32) -> SysResult {
    let (kind, nonblock, cloexec) = split_type(stype)?;
    let s = create(c, family, kind, protocol)?;
    let limit = nofile(c);
    c.p.fds
        .install(socket_file(s, nonblock), cloexec, limit)
        .map(|n| n as u64)
}

/// `socketpair`: the descriptors are reserved and written out before the
/// family is asked for a pair (a failure leaves them written).
pub fn socketpair(c: &mut Ctx<'_>, family: i32, stype: i32, protocol: i32, sv: u64) -> SysResult {
    let (kind, nonblock, cloexec) = split_type(stype)?;
    let limit = nofile(c);
    let fds = c.p.fds.free_fds(2, limit)?;
    c.write_u32(sv, fds[0] as u32)?;
    c.write_u32(sv + 4, fds[1] as u32)?;
    let (family, kind, protocol) = resolve(c, family, kind, protocol)?;
    // Only Unix-domain sockets pair (sock_no_socketpair).
    if family != lx::AF_UNIX {
        return Err(Errno(EOPNOTSUPP));
    }
    let (x, y) = sys::socketpair(libc::AF_UNIX, host_type(kind), 0)?;
    let x = Socket::new(x, family, kind, protocol);
    let y = Socket::new(y, family, kind, protocol);
    let cred = Some((c.p.pid, c.p.creds.1, c.p.creds.3));
    x.state.lock().unwrap().pair_cred = cred;
    y.state.lock().unwrap().pair_cred = cred;
    c.p.fds
        .install_at(fds[0], socket_file(x, nonblock), cloexec, limit)?;
    c.p.fds
        .install_at(fds[1], socket_file(y, nonblock), cloexec, limit)?;
    Ok(0)
}

/// Whether the privileged port `port` needs `CAP_NET_BIND_SERVICE`
/// (`inet_port_requires_bind_service`).
fn privileged(c: &Ctx<'_>, port: u16) -> bool {
    port != 0 && port < UNPRIVILEGED_PORT && !admin(c)
}

/// `bind`.
pub fn bind(c: &mut Ctx<'_>, fd: i32, uaddr: u64, len: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let b = read_addr(c, uaddr, len)?;
    match s.domain {
        lx::AF_UNIX => bind_unix(c, s, &b),
        lx::AF_INET => {
            // inet_bind_sk: the size first, then the family (AF_UNSPEC
            // with the any address for compatibility).
            let a = addr::parse_v4(&b, true)?;
            if let Addr::V4 { port, .. } = a
                && privileged(c, port)
            {
                return Err(Errno(EACCES));
            }
            name::bind(s, &name::place(&c.p.vfs, &a, true)?)?;
            Ok(0)
        }
        lx::AF_INET6 => {
            let a = addr::parse_v6(&b)?;
            if let Addr::V6 { port, .. } = a
                && privileged(c, port)
            {
                return Err(Errno(EACCES));
            }
            name::bind(s, &name::place(&c.p.vfs, &a, true)?)?;
            Ok(0)
        }
        lx::AF_NETLINK => {
            if let Some(n) = &s.netlink {
                n.bind(&b, c.p.pid, admin(c))?;
            } else {
                let (pid, groups) = netlink::parse_addr(&b)?;
                sys::bind(&s.file, &HostAddr::Netlink(pid, groups))?;
            }
            Ok(0)
        }
        _ => Err(Errno(EOPNOTSUPP)),
    }
}

/// `unix_bind`: a bare family autobinds; a path makes a socket node (its
/// existence is `EADDRINUSE`, before a socket already bound is `EINVAL`);
/// an abstract name is taken unless in use.
fn bind_unix(c: &mut Ctx<'_>, s: &Socket, b: &[u8]) -> SysResult {
    let mut st = s.state.lock().unwrap();
    if b.len() == addr::SUN_PATH_OFFSET && addr::family(b) == Some(lx::AF_UNIX as u16) {
        if st.name.is_none() {
            let (n, lock) = name::autobind(&c.p.vfs, s)?;
            st.name = Some(n);
            st.name_lock = lock;
        }
        return Ok(0);
    }
    if b.len() <= addr::SUN_PATH_OFFSET {
        return Err(Errno(EINVAL));
    }
    match addr::parse_unix(b)? {
        UnixName::Path(p) => {
            let host = name::unix_path(&c.p.vfs, &p, true)?;
            if st.name.is_some() {
                // unix_bind_bsd makes the node, then finds the socket bound
                // and removes it again.
                if std::fs::symlink_metadata(&host).is_ok() {
                    return Err(Errno(EADDRINUSE));
                }
                let parent = host.parent().unwrap_or(std::path::Path::new("/"));
                std::fs::metadata(parent)?;
                return Err(Errno(EINVAL));
            }
            let place = name::place(&c.p.vfs, &Addr::Unix(UnixName::Path(p.clone())), true)?;
            name::bind(s, &place)?;
            // The node's mode: every permission the umask leaves.
            use std::os::unix::fs::PermissionsExt;
            let mode = 0o777 & !c.p.umask;
            let _ = std::fs::set_permissions(&host, std::fs::Permissions::from_mode(mode));
            st.name = Some(UnixName::Path(p));
            Ok(0)
        }
        UnixName::Abstract(n) => {
            if st.name.is_some() {
                return Err(Errno(EINVAL));
            }
            st.name_lock = name::bind_abstract(&c.p.vfs, s, &n)?;
            st.name = Some(UnixName::Abstract(n));
            Ok(0)
        }
        UnixName::Unnamed => Err(Errno(EINVAL)),
    }
}

/// `listen`: the backlog capped at `somaxconn` (a negative one is large).
pub fn listen(c: &mut Ctx<'_>, fd: i32, backlog: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    let backlog = if backlog as u32 > SOMAXCONN as u32 {
        SOMAXCONN
    } else {
        backlog
    };
    // Datagram sockets have no listen (sock_no_listen).
    if !s.connected_type() {
        return Err(Errno(EOPNOTSUPP));
    }
    sys::listen(&s.file, backlog)?;
    s.state.lock().unwrap().listening = true;
    Ok(0)
}

/// What a blocking socket call does next when it cannot proceed: sleeps
/// until the socket is ready for `write` (or reading) or `w`'s deadline,
/// or ends with the error the kernel returns: `timed_out` once the timeout
/// passed, `EINTR` or `-ERESTARTSYS` for a signal.
pub(super) fn sleep(
    c: &mut Ctx<'_>,
    s: &Socket,
    write: bool,
    w: SockWait,
    timeout: opts::Timeout,
    timed_out: i32,
) -> Errno {
    if w.deadline.is_some_and(|d| Instant::now() >= d) {
        return Errno(timed_out);
    }
    if c.signal_pending() {
        return Errno(if timeout.is_some() {
            EINTR
        } else {
            ERESTARTSYS
        });
    }
    c.block(
        Wait::fds(vec![(s.raw(), !write, write)], w.deadline),
        Resume::Socket(w),
    )
}

/// The progress of a blocking socket call: the record it left when it
/// slept, or a fresh one whose deadline is `timeout` from now.
pub(super) fn progress(c: &mut Ctx<'_>, timeout: opts::Timeout) -> SockWait {
    match c.resume.take() {
        Some(Resume::Socket(w)) => w,
        _ => SockWait {
            deadline: timeout.map(|t| Instant::now() + t),
            ..SockWait::default()
        },
    }
}

/// Whether a call on `file` must not sleep: `O_NONBLOCK`, or a zero
/// timeout (a negative one set).
fn nonblocking(file: &OpenFile, timeout: opts::Timeout) -> bool {
    file.flags() & O_NONBLOCK != 0 || timeout == Some(Duration::ZERO)
}

/// `accept`/`accept4`: the descriptor is reserved first (`EMFILE` takes no
/// connection); the new socket has only the flags asked for; a TCP socket
/// inherits the listener's options (`sk_clone_lock`), a Unix one its name.
pub fn accept4(c: &mut Ctx<'_>, fd: i32, uaddr: u64, ulen: u64, flags: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if flags & !(lx::SOCK_CLOEXEC | lx::SOCK_NONBLOCK) != 0 {
        return Err(Errno(EINVAL));
    }
    let s = sock_of(&file)?;
    let limit = nofile(c);
    let newfd = c.p.fds.free_fds(1, limit)?[0];
    if !s.connected_type() {
        return Err(Errno(EOPNOTSUPP));
    }
    let timeout = s.state.lock().unwrap().rcvtimeo;
    let w = progress(c, timeout);
    let (fd, peer) = loop {
        match sys::accept(&s.file) {
            Ok(r) => break r,
            Err(Errno(EINTR | ECONNABORTED)) => continue,
            Err(Errno(EAGAIN)) if nonblocking(&file, timeout) => return Err(Errno(EAGAIN)),
            Err(Errno(EAGAIN)) => return Err(sleep(c, s, false, w, timeout, EAGAIN)),
            Err(e) => return Err(e),
        }
    };
    let new = Socket::new(fd, s.domain, s.stype, s.protocol);
    {
        let from = s.state.lock().unwrap();
        let mut to = new.state.lock().unwrap();
        if s.unix() {
            to.name = from.name.clone();
        } else {
            to.rcvtimeo = from.rcvtimeo;
            to.sndtimeo = from.sndtimeo;
            to.rcvbuf = from.rcvbuf;
            to.sndbuf = from.sndbuf;
            to.ints = from.ints.clone();
        }
    }
    if uaddr != 0 {
        // getname of the new socket's peer; a failed copy drops the
        // connection.
        let a = name::guest_addr(&c.p.vfs, peer);
        write_addr(c, &a.encode(), uaddr, ulen)?;
    }
    let nonblock = flags & lx::SOCK_NONBLOCK != 0;
    c.p.fds.install_at(
        newfd,
        socket_file(new, nonblock),
        flags & lx::SOCK_CLOEXEC != 0,
        limit,
    )?;
    Ok(newfd as u64)
}

/// The guest address a `connect` of socket `s` names, `None` for a
/// disconnect (`AF_UNSPEC`).
fn connect_target(s: &Socket, b: &[u8]) -> Result<Option<Addr>, Errno> {
    // inet_stream_connect, inet_dgram_connect, unix_dgram_connect: at
    // least a family.
    if b.len() < 2 {
        return Err(Errno(EINVAL));
    }
    let unspec = addr::family(b) == Some(lx::AF_UNSPEC as u16);
    match s.domain {
        lx::AF_UNIX => {
            if unspec && !s.connected_type() {
                return Ok(None);
            }
            match addr::parse_unix(b)? {
                UnixName::Unnamed => Err(Errno(EINVAL)),
                n => Ok(Some(Addr::Unix(n))),
            }
        }
        _ if unspec => Ok(None),
        lx::AF_INET => addr::parse_v4(b, false).map(Some),
        lx::AF_INET6 => addr::parse_v6(b).map(Some),
        lx::AF_NETLINK => {
            let (pid, groups) = netlink::parse_addr(b)?;
            Ok(Some(Addr::Netlink { pid, groups }))
        }
        _ => Err(Errno(EOPNOTSUPP)),
    }
}

/// A host error of a Unix-domain `connect` or send to `target`, as Linux
/// reports it: a missing abstract name (a missing emulated file) and a
/// file that is no socket are refused connections.
pub(super) fn unix_target_error(target: &Addr, e: Errno) -> Errno {
    match (target, e.0) {
        (Addr::Unix(UnixName::Abstract(_)), ENOENT) => Errno(ECONNREFUSED),
        (Addr::Unix(_), ENOTSOCK) => Errno(ECONNREFUSED),
        _ => e,
    }
}

/// `connect`. A TCP connection the host starts in the background is
/// waited for (at most `SO_SNDTIMEO`, then `EINPROGRESS`) unless the socket
/// is non-blocking; a second `connect` after it completed in the background
/// succeeds once, as `__inet_stream_connect` reports `SS_CONNECTING`
/// turning `SS_CONNECTED`.
pub fn connect(c: &mut Ctx<'_>, fd: i32, uaddr: u64, len: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let b = read_addr(c, uaddr, len)?;
    let s = sock_of(&file)?;
    if let Some(n) = &s.netlink {
        n.connect(&b, c.p.pid, admin(c))?;
        return Ok(0);
    }
    let timeout = s.state.lock().unwrap().sndtimeo;
    let resumed = matches!(c.resume, Some(Resume::Socket(_)));
    let w = progress(c, timeout);
    if resumed && !s.unix() {
        return finish_connect(c, s, w, timeout);
    }
    let Some(target) = connect_target(s, &b)? else {
        // A disconnect: the host dissolves the association (and may
        // report the unspecified family it was given).
        return match sys::connect(&s.file, &HostAddr::Unspec) {
            Ok(()) | Err(Errno(EAFNOSUPPORT | EINVAL)) => Ok(0),
            Err(e) => Err(e),
        };
    };
    let place = name::place(&c.p.vfs, &target, false)?;
    match name::connect(s, &place) {
        Ok(()) => {
            s.state.lock().unwrap().connecting = false;
            Ok(0)
        }
        Err(Errno(EINPROGRESS | EALREADY)) if !nonblocking(&file, timeout) && !s.unix() => {
            s.state.lock().unwrap().connecting = true;
            finish_connect(c, s, w, timeout)
        }
        Err(Errno(EINPROGRESS)) => {
            s.state.lock().unwrap().connecting = true;
            Err(Errno(EINPROGRESS))
        }
        Err(Errno(EISCONN)) if std::mem::take(&mut s.state.lock().unwrap().connecting) => Ok(0),
        // A Unix listener with a full backlog: retry shortly.
        Err(Errno(EAGAIN)) if s.unix() && !nonblocking(&file, timeout) => {
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
            let soon = Instant::now() + Duration::from_millis(2);
            let until = w.deadline.map_or(soon, |d| d.min(soon));
            Err(c.block(Wait::until(Some(until)), Resume::Socket(w)))
        }
        Err(e) => Err(unix_target_error(&target, e)),
    }
}

/// Waits for a TCP connection under way: its result once the host socket
/// reports it (`SO_ERROR`), `EINPROGRESS` when the timeout passes first.
fn finish_connect(c: &mut Ctx<'_>, s: &Socket, w: SockWait, timeout: opts::Timeout) -> SysResult {
    let r = sys::readiness(&s.file);
    if r.writable || r.error || r.hangup {
        s.state.lock().unwrap().connecting = false;
        let e = sys::getsockopt_int(&s.file, libc::SOL_SOCKET, libc::SO_ERROR)?;
        return if e == 0 {
            Ok(0)
        } else {
            Err(Errno(from_host(e)))
        };
    }
    Err(sleep(c, s, true, w, timeout, EINPROGRESS))
}

/// `getsockname` (`peer == false`) and `getpeername`.
pub fn getname(c: &mut Ctx<'_>, fd: i32, uaddr: u64, ulen: u64, peer: bool) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    if let Some(n) = &s.netlink {
        write_addr(c, &n.name(peer), uaddr, ulen)?;
        return Ok(0);
    }
    let own = s.state.lock().unwrap().name.clone();
    let a = match own {
        // unix_getname: the name bound here.
        Some(n) if s.unix() && !peer => Addr::Unix(n),
        _ => {
            let h = if peer {
                sys::peername(&s.file)?
            } else {
                sys::sockname(&s.file)?
            };
            match name::guest_addr(&c.p.vfs, h) {
                // An unbound socket's own name is its bare family.
                Addr::Unspec if s.unix() => Addr::Unix(UnixName::Unnamed),
                a => a,
            }
        }
    };
    write_addr(c, &a.encode(), uaddr, ulen)?;
    Ok(0)
}

/// `shutdown`: `how` is `SHUT_RD`, `SHUT_WR`, or `SHUT_RDWR`; a Unix socket
/// without a peer shuts down without error (`unix_shutdown`).
pub fn shutdown(c: &mut Ctx<'_>, fd: i32, how: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    // Netlink has no shutdown (sock_no_shutdown).
    if s.domain == lx::AF_NETLINK {
        return Err(Errno(EOPNOTSUPP));
    }
    if !(0..=2).contains(&how) {
        return Err(Errno(EINVAL));
    }
    match sys::shutdown(&s.file, how) {
        Ok(()) => {}
        Err(Errno(ENOTCONN)) if s.unix() => {}
        Err(e) => return Err(e),
    }
    // SHUT_RD, SHUT_WR, SHUT_RDWR are the sk_shutdown bits less one.
    s.state.lock().unwrap().shut |= (how + 1) as u8;
    Ok(0)
}

/// `getsockopt`: as much of the value as the guest's length allows, and
/// the length copied.
pub fn getsockopt(
    c: &mut Ctx<'_>,
    fd: i32,
    level: i32,
    opt: i32,
    val: u64,
    ulen: u64,
) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    if level == lx::SOL_NETLINK && s.domain == lx::AF_NETLINK {
        return netlink_getsockopt(c, s, opt, val, ulen);
    }
    let (v, len) = if level == lx::SOL_SOCKET {
        // sk_getsockopt reads the length before the option.
        let len = c.read_u32(ulen)? as i32;
        if len < 0 {
            return Err(Errno(EINVAL));
        }
        if opt == opts::so::PEERNAME {
            return peer_name_opt(c, s, val, ulen, len);
        }
        (opts::get(s, level, opt)?, len)
    } else {
        let v = opts::get(s, level, opt)?;
        let len = c.read_u32(ulen)? as i32;
        // do_tcp_getsockopt compares unsigned: a negative length is large.
        let len = if level == lx::IPPROTO_TCP && len < 0 {
            i32::MAX
        } else {
            len
        };
        if len < 0 {
            return Err(Errno(EINVAL));
        }
        // do_ip_getsockopt: a short buffer gets a byte-sized value as a
        // byte.
        if level == lx::IPPROTO_IP && (1..4).contains(&len) && v.len() == 4 {
            let n = i32::from_le_bytes(v[..4].try_into().unwrap());
            if (0..=255).contains(&n) {
                c.write_mem(val, &[n as u8])?;
                c.write_u32(ulen, 1)?;
                return Ok(0);
            }
        }
        (v, len)
    };
    let n = (len as usize).min(v.len());
    c.write_mem(val, &v[..n])?;
    c.write_u32(ulen, n as u32)?;
    Ok(0)
}

/// `netlink_getsockopt`: the value, and the length the option reports.
fn netlink_getsockopt(c: &Ctx<'_>, s: &Socket, opt: i32, val: u64, ulen: u64) -> SysResult {
    let len = c.read_u32(ulen)? as i32;
    if len < 0 {
        return Err(Errno(EINVAL));
    }
    let (v, report) = match &s.netlink {
        Some(n) => n.getsockopt(opt, len as usize)?,
        None => {
            // The host writes what it writes; the rest stays the guest's.
            let mut v = c.read_mem(val, len as usize)?;
            let n = sys::getsockopt_into(&s.file, lx::SOL_NETLINK, opt, &mut v)?;
            (v, n)
        }
    };
    c.write_mem(val, &v)?;
    c.write_u32(ulen, report)?;
    Ok(0)
}

/// `SO_PEERNAME`: the peer's address; a buffer longer than it is `EINVAL`.
fn peer_name_opt(c: &Ctx<'_>, s: &Socket, val: u64, ulen: u64, len: i32) -> SysResult {
    let h = sys::peername(&s.file).map_err(|_| Errno(ENOTCONN))?;
    let a = name::guest_addr(&c.p.vfs, h).encode();
    if (a.len() as i32) < len {
        return Err(Errno(EINVAL));
    }
    c.write_mem(val, &a[..len as usize])?;
    c.write_u32(ulen, len as u32)?;
    Ok(0)
}

/// `setsockopt`.
pub fn setsockopt(c: &mut Ctx<'_>, fd: i32, level: i32, opt: i32, val: u64, len: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let s = sock_of(&file)?;
    if len < 0 {
        return Err(Errno(EINVAL));
    }
    // The largest option structure taken (struct group_source_req).
    let bytes = c.read_mem(val, (len as usize).min(264))?;
    if level == lx::SOL_NETLINK && s.domain == lx::AF_NETLINK {
        match &s.netlink {
            Some(n) => n.setsockopt(opt, &bytes, admin(c))?,
            None => sys::setsockopt(&s.file, lx::SOL_NETLINK, opt, &bytes)?,
        }
        return Ok(0);
    }
    opts::set(s, level, opt, &bytes, admin(c))?;
    Ok(0)
}

/// Socket `ioctl`s (`sock_ioctl`): `SIOCINQ` (`FIONREAD`), `SIOCOUTQ`,
/// `SIOCATMARK`, and the interface requests ([`interface`]); others are
/// not socket requests (`ENOTTY`).
pub fn ioctl(c: &mut Ctx<'_>, s: &Socket, req: u32, arg: u64) -> SysResult {
    let shape = ifreq::shape(s.domain, req);
    if shape != Shape::Other {
        return interface(c, s, req, arg, shape);
    }
    const FIONREAD: u32 = 0x541B;
    const SIOCOUTQ: u32 = 0x5411;
    const SIOCATMARK: u32 = 0x8905;
    // netlink_ioctl has none, and these are not socket-type requests
    // (sock_do_ioctl).
    if s.domain == lx::AF_NETLINK && matches!(req, FIONREAD | SIOCOUTQ) {
        return Err(Errno(ENOTTY));
    }
    let v = match req {
        FIONREAD => {
            // A listening socket has no bytes (EINVAL, tcp_ioctl).
            if s.tcp() && s.listening() {
                return Err(Errno(EINVAL));
            }
            sys::inq(&s.file, s.connected_type())?
        }
        SIOCOUTQ => sys::outq(&s.file)?,
        SIOCATMARK => sys::at_mark(&s.file)?,
        _ => return Err(Errno(ENOTTY)),
    };
    c.write_u32(arg, v as u32)?;
    Ok(0)
}

/// An interface request ([`ifreq`]) of `shape`: on a Linux host the host
/// answers it for the socket's host descriptor, the argument's bytes
/// passing through (every guest ABI's `struct ifreq` is the host's), except
/// the requests whose `ifr_data` points to more data (`EOPNOTSUPP`);
/// elsewhere, and for emulated sockets, it is answered from rtnetlink's
/// view of the host's interfaces.
fn interface(c: &mut Ctx<'_>, s: &Socket, req: u32, arg: u64, shape: Shape) -> SysResult {
    let emulate = !cfg!(target_os = "linux") || s.netlink.is_some();
    let admin = admin(c);
    match shape {
        Shape::Conf => {
            // dev_ifconf: struct ifconf, its buffer's entries, the length.
            let b = c.read_mem(arg, ifreq::IFCONF)?;
            let len = i32::from_le_bytes(b[..4].try_into().unwrap());
            let buf = u64::from_le_bytes(b[8..16].try_into().unwrap());
            let room = (buf != 0).then_some(len);
            let (entries, total) = if emulate {
                ifreq::ifconf(&netlink::ifaces::snapshot(), room)
            } else {
                host_ifconf(s, room)?
            };
            if !entries.is_empty() {
                c.write_mem(buf, &entries)?;
            }
            c.write_u32(arg, total as u32)?;
            Ok(0)
        }
        Shape::In6 => {
            if emulate && ifreq::in6_needs_admin(req) && !admin {
                return Err(Errno(EPERM));
            }
            let b = c.read_mem(arg, ifreq::IN6_IFREQ)?;
            let mut ireq: [u8; ifreq::IN6_IFREQ] = b.try_into().unwrap();
            if emulate {
                return Err(ifreq::in6(&netlink::ifaces::snapshot(), req, &ireq));
            }
            host_in6(s, req, &mut ireq)?;
            Ok(0)
        }
        Shape::Ifreq { .. } | Shape::Indirect => {
            let b = c.read_mem(arg, ifreq::IFREQ)?;
            let mut ifr: [u8; ifreq::IFREQ] = b.try_into().unwrap();
            let answer = if emulate {
                ifreq::answer(&netlink::ifaces::snapshot(), s.domain, req, &mut ifr, admin)?
            } else {
                host_ifreq(s, req, shape, &mut ifr)?
            };
            if answer {
                c.write_mem(arg, &ifr)?;
            }
            Ok(0)
        }
        Shape::Other => Err(Errno(ENOTTY)),
    }
}

/// The host's `SIOCGIFCONF` (Linux hosts).
fn host_ifconf(s: &Socket, room: Option<i32>) -> Result<(Vec<u8>, i32), Errno> {
    #[cfg(target_os = "linux")]
    {
        sys::ifconf(&s.file, room)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (s, room);
        Err(Errno(ENOTTY))
    }
}

/// The host's answer to IPv6 address change `req` (Linux hosts).
fn host_in6(s: &Socket, req: u32, ireq: &mut [u8; ifreq::IN6_IFREQ]) -> Result<(), Errno> {
    #[cfg(target_os = "linux")]
    {
        sys::ioctl_in6_ifreq(&s.file, req, ireq)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (s, req, ireq);
        Err(Errno(ENOTTY))
    }
}

/// The host's answer to `struct ifreq` request `req` (Linux hosts):
/// whether the answer is copied back.
fn host_ifreq(
    s: &Socket,
    req: u32,
    shape: Shape,
    ifr: &mut [u8; ifreq::IFREQ],
) -> Result<bool, Errno> {
    let Shape::Ifreq { answer } = shape else {
        return Err(Errno(EOPNOTSUPP));
    };
    #[cfg(target_os = "linux")]
    {
        sys::ioctl_ifreq(&s.file, req, ifr)?;
        Ok(answer)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (s, req, ifr, answer);
        Err(Errno(ENOTTY))
    }
}

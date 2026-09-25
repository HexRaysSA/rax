//! Host socket calls. Like [`host`](super::super::host), this module keeps
//! the personality's `unsafe` foreign calls behind safe wrappers: each
//! passes only valid, initialized, correctly sized buffers owned for the
//! duration of the call, and none of the called functions retain pointers
//! or call back. Every host socket is non-blocking and close-on-exec; the
//! personality emulates blocking.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::super::abi::errno::{Errno, from_host};

fn last_errno() -> Errno {
    Errno(from_host(
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    ))
}

fn check(rc: libc::c_int) -> Result<libc::c_int, Errno> {
    if rc < 0 { Err(last_errno()) } else { Ok(rc) }
}

/// A host socket address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostAddr {
    /// `AF_UNSPEC`.
    Unspec,
    /// A Unix-domain name: a host path, or (on Linux hosts) an abstract
    /// name; empty when unnamed.
    Unix {
        /// The name's bytes (without the leading NUL of an abstract one).
        name: Vec<u8>,
        /// Abstract (Linux hosts only).
        abstract_: bool,
    },
    /// IPv4.
    V4([u8; 4], u16),
    /// IPv6: address, port, flow information, scope.
    V6([u8; 16], u16, u32, u32),
    /// Netlink (Linux hosts only): port ID and groups.
    Netlink(u32, u32),
}

/// `sun_path`'s size on the host.
pub fn sun_path_max() -> usize {
    // SAFETY: a zeroed sockaddr_un is valid plain data.
    let un: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    un.sun_path.len()
}

/// Encodes `a` as a host `sockaddr`.
fn encode(a: &HostAddr) -> Result<(libc::sockaddr_storage, libc::socklen_t), Errno> {
    // SAFETY: sockaddr_storage is plain data; a zeroed one is valid, and
    // every cast below reinterprets it as a smaller sockaddr it is sized
    // and aligned for.
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match a {
        HostAddr::Unspec => {
            st.ss_family = libc::AF_UNSPEC as _;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                st.ss_len = 16;
            }
            16
        }
        HostAddr::Unix { name, abstract_ } => {
            let un = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_un) };
            un.sun_family = libc::AF_UNIX as _;
            let off = std::mem::size_of_val(&un.sun_family)
                + if cfg!(any(target_os = "macos", target_os = "ios")) {
                    1
                } else {
                    0
                };
            let start = usize::from(*abstract_);
            if start + name.len() + usize::from(!*abstract_) > un.sun_path.len() {
                return Err(Errno(super::super::abi::errno_table::ENAMETOOLONG));
            }
            for (i, &b) in name.iter().enumerate() {
                un.sun_path[start + i] = b as libc::c_char;
            }
            let len = off + start + name.len() + usize::from(!*abstract_ && !name.is_empty());
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                un.sun_len = len as u8;
            }
            len
        }
        HostAddr::V4(ip, port) => {
            let sin = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as _;
            sin.sin_port = port.to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(*ip);
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        HostAddr::V6(ip, port, flow, scope) => {
            let sin6 = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as _;
            sin6.sin6_port = port.to_be();
            sin6.sin6_flowinfo = flow.to_be();
            sin6.sin6_addr.s6_addr = *ip;
            sin6.sin6_scope_id = *scope;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
        #[cfg(target_os = "linux")]
        HostAddr::Netlink(pid, groups) => {
            let nl = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_nl) };
            nl.nl_family = libc::AF_NETLINK as _;
            nl.nl_pid = *pid;
            nl.nl_groups = *groups;
            std::mem::size_of::<libc::sockaddr_nl>()
        }
        #[cfg(not(target_os = "linux"))]
        HostAddr::Netlink(..) => {
            return Err(Errno(super::super::abi::errno_table::EAFNOSUPPORT));
        }
    };
    Ok((st, len as libc::socklen_t))
}

/// Decodes a host `sockaddr` of `len` bytes.
fn decode(st: &libc::sockaddr_storage, len: libc::socklen_t) -> HostAddr {
    let len = len as usize;
    match i32::from(st.ss_family) {
        libc::AF_UNIX => {
            // SAFETY: the family says the storage holds a sockaddr_un.
            let un = unsafe { &*(st as *const _ as *const libc::sockaddr_un) };
            let off = std::mem::size_of_val(&un.sun_family)
                + if cfg!(any(target_os = "macos", target_os = "ios")) {
                    1
                } else {
                    0
                };
            let n = len.saturating_sub(off).min(un.sun_path.len());
            let raw: Vec<u8> = un.sun_path[..n].iter().map(|&c| c as u8).collect();
            if raw.first() == Some(&0) && n > 0 && cfg!(target_os = "linux") {
                HostAddr::Unix {
                    name: raw[1..].to_vec(),
                    abstract_: true,
                }
            } else {
                let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
                HostAddr::Unix {
                    name: raw[..end].to_vec(),
                    abstract_: false,
                }
            }
        }
        libc::AF_INET => {
            // SAFETY: the family says the storage holds a sockaddr_in.
            let sin = unsafe { &*(st as *const _ as *const libc::sockaddr_in) };
            HostAddr::V4(
                sin.sin_addr.s_addr.to_ne_bytes(),
                u16::from_be(sin.sin_port),
            )
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the storage holds a sockaddr_in6.
            let sin6 = unsafe { &*(st as *const _ as *const libc::sockaddr_in6) };
            HostAddr::V6(
                sin6.sin6_addr.s6_addr,
                u16::from_be(sin6.sin6_port),
                u32::from_be(sin6.sin6_flowinfo),
                sin6.sin6_scope_id,
            )
        }
        #[cfg(target_os = "linux")]
        libc::AF_NETLINK => {
            // SAFETY: the family says the storage holds a sockaddr_nl.
            let nl = unsafe { &*(st as *const _ as *const libc::sockaddr_nl) };
            HostAddr::Netlink(nl.nl_pid, nl.nl_groups)
        }
        _ => HostAddr::Unspec,
    }
}

/// Makes a fresh host descriptor non-blocking and close-on-exec.
fn prepare(fd: RawFd) -> OwnedFd {
    // SAFETY: `fd` was just returned by the host and is owned exactly once
    // here; F_SETFL/F_SETFD take integer flags.
    unsafe {
        libc::fcntl(
            fd,
            libc::F_SETFL,
            libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
        );
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            // The personality raises the guest's SIGPIPE itself.
            let one: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        OwnedFd::from_raw_fd(fd)
    }
}

/// Gives a Darwin Unix datagram socket Linux's default buffer sizes
/// (`sysctl_wmem_default`): Darwin's 2 KiB send and 4 KiB receive space
/// would refuse the datagrams Linux takes.
fn size_buffers(fd: &OwnedFd, domain: i32, stype: i32) {
    if cfg!(target_vendor = "apple") && domain == libc::AF_UNIX && stype == libc::SOCK_DGRAM {
        let v: libc::c_int = 212_992;
        for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            let _ = setsockopt(fd, libc::SOL_SOCKET, opt, &v.to_ne_bytes());
        }
    }
}

/// `socket(2)` on the host.
pub fn socket(domain: i32, stype: i32, protocol: i32) -> Result<OwnedFd, Errno> {
    // SAFETY: integer arguments.
    let fd = prepare(check(unsafe { libc::socket(domain, stype, protocol) })?);
    size_buffers(&fd, domain, stype);
    Ok(fd)
}

/// `socketpair(2)` on the host.
pub fn socketpair(domain: i32, stype: i32, protocol: i32) -> Result<(OwnedFd, OwnedFd), Errno> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid two-element array.
    check(unsafe { libc::socketpair(domain, stype, protocol, fds.as_mut_ptr()) })?;
    let (a, b) = (prepare(fds[0]), prepare(fds[1]));
    size_buffers(&a, domain, stype);
    size_buffers(&b, domain, stype);
    Ok((a, b))
}

/// Makes a received host socket non-blocking and close-on-exec, as the
/// personality keeps every host socket.
pub fn adopt(fd: OwnedFd) -> OwnedFd {
    use std::os::fd::IntoRawFd;
    prepare(fd.into_raw_fd())
}

/// `bind(2)`.
pub fn bind(fd: &impl AsRawFd, a: &HostAddr) -> Result<(), Errno> {
    let (st, len) = encode(a)?;
    // SAFETY: `st` holds `len` valid bytes.
    check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&st as *const libc::sockaddr_storage).cast(),
            len,
        )
    })
    .map(|_| ())
}

/// `connect(2)`.
pub fn connect(fd: &impl AsRawFd, a: &HostAddr) -> Result<(), Errno> {
    let (st, len) = encode(a)?;
    // SAFETY: `st` holds `len` valid bytes.
    check(unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&st as *const libc::sockaddr_storage).cast(),
            len,
        )
    })
    .map(|_| ())
}

/// `listen(2)`.
pub fn listen(fd: &impl AsRawFd, backlog: i32) -> Result<(), Errno> {
    // SAFETY: integer arguments.
    check(unsafe { libc::listen(fd.as_raw_fd(), backlog) }).map(|_| ())
}

/// `accept(2)`: the connection and its peer's address.
pub fn accept(fd: &impl AsRawFd) -> Result<(OwnedFd, HostAddr), Errno> {
    // SAFETY: plain data; the length matches the storage.
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let new = check(unsafe {
        libc::accept(
            fd.as_raw_fd(),
            (&mut st as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    })?;
    Ok((prepare(new), decode(&st, len)))
}

fn name_of(
    fd: RawFd,
    f: unsafe extern "C" fn(libc::c_int, *mut libc::sockaddr, *mut libc::socklen_t) -> libc::c_int,
) -> Result<HostAddr, Errno> {
    // SAFETY: plain data; the length matches the storage.
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    check(unsafe {
        f(
            fd,
            (&mut st as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    })?;
    Ok(decode(&st, len))
}

/// `getsockname(2)`.
pub fn sockname(fd: &impl AsRawFd) -> Result<HostAddr, Errno> {
    name_of(fd.as_raw_fd(), libc::getsockname)
}

/// `getpeername(2)`.
pub fn peername(fd: &impl AsRawFd) -> Result<HostAddr, Errno> {
    name_of(fd.as_raw_fd(), libc::getpeername)
}

/// `shutdown(2)`.
pub fn shutdown(fd: &impl AsRawFd, how: i32) -> Result<(), Errno> {
    // SAFETY: integer arguments.
    check(unsafe { libc::shutdown(fd.as_raw_fd(), how) }).map(|_| ())
}

/// `sendto(2)` with host flags, to `to` if given.
pub fn send(
    fd: &impl AsRawFd,
    data: &[u8],
    flags: i32,
    to: Option<&HostAddr>,
) -> Result<usize, Errno> {
    let dest = to.map(encode).transpose()?;
    // SAFETY: `data` is readable for its length; the address, if any,
    // holds its length's valid bytes.
    let n = unsafe {
        match &dest {
            Some((st, len)) => libc::sendto(
                fd.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                flags,
                (st as *const libc::sockaddr_storage).cast(),
                *len,
            ),
            None => libc::send(fd.as_raw_fd(), data.as_ptr().cast(), data.len(), flags),
        }
    };
    if n < 0 {
        Err(last_errno())
    } else {
        Ok(n as usize)
    }
}

/// `recvfrom(2)` with host flags: the bytes received (the whole datagram's
/// length with `MSG_TRUNC` on Linux hosts), and the sender.
pub fn recv(fd: &impl AsRawFd, buf: &mut [u8], flags: i32) -> Result<(usize, HostAddr), Errno> {
    // SAFETY: `buf` is writable for its length; the address storage and
    // its length match.
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            flags,
            (&mut st as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    if n < 0 {
        return Err(last_errno());
    }
    Ok((n as usize, decode(&st, len)))
}

/// A datagram received with `recvmsg(2)`: its bytes (truncated to the
/// buffer), the sender, whether it was truncated, and the descriptors
/// passed with it.
pub struct Received {
    /// Bytes stored.
    pub len: usize,
    /// The sender.
    pub from: HostAddr,
    /// `MSG_TRUNC`: the message did not fit.
    pub truncated: bool,
    /// The host's `msg_flags`.
    pub flags: i32,
    /// Descriptors received with `SCM_RIGHTS`.
    pub fds: Vec<OwnedFd>,
    /// `SOL_NETLINK` control messages: type and data.
    pub netlink: Vec<(i32, Vec<u8>)>,
}

/// `SOL_NETLINK` (Linux's number; no other host has the level).
const SOL_NETLINK: libc::c_int = 270;

/// `recvmsg(2)` into `buf` with host flags, taking `SCM_RIGHTS`
/// descriptors (up to 253, `SCM_MAX_FD`) and `SOL_NETLINK` control
/// messages.
pub fn recvmsg(fd: &impl AsRawFd, buf: &mut [u8], flags: i32) -> Result<Received, Errno> {
    const MAX_FDS: usize = 253;
    // SAFETY (whole function): the iovec, address storage, and control
    // buffer are owned for the call and sized as the header says; CMSG_*
    // walk only the control bytes the host filled in; each received
    // descriptor is owned exactly once.
    unsafe {
        let mut st: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let space =
            libc::CMSG_SPACE((MAX_FDS * std::mem::size_of::<libc::c_int>()) as u32) as usize;
        let mut control = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut st as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = (control.len() * 8) as _;
        let n = libc::recvmsg(fd.as_raw_fd(), &mut msg, flags);
        if n < 0 {
            return Err(last_errno());
        }
        let mut fds = Vec::new();
        let mut netlink = Vec::new();
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == SOL_NETLINK {
                let len = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = std::slice::from_raw_parts(libc::CMSG_DATA(c), len);
                netlink.push(((*c).cmsg_type, data.to_vec()));
            }
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const libc::c_int;
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<libc::c_int>();
                for i in 0..count {
                    let raw = std::ptr::read_unaligned(data.add(i));
                    libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
                    fds.push(OwnedFd::from_raw_fd(raw));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        Ok(Received {
            len: n as usize,
            from: decode(&st, msg.msg_namelen),
            truncated: msg.msg_flags & libc::MSG_TRUNC != 0,
            flags: msg.msg_flags,
            fds,
            netlink,
        })
    }
}

/// `sendmsg(2)` of `data` with host flags, passing `fds` with
/// `SCM_RIGHTS`, to `to` if given.
pub fn sendmsg(
    fd: &impl AsRawFd,
    data: &[u8],
    flags: i32,
    to: Option<&HostAddr>,
    fds: &[RawFd],
) -> Result<usize, Errno> {
    let dest = to.map(encode).transpose()?;
    // SAFETY (whole function): as for `recvmsg`; the descriptors are only
    // read by the host, which duplicates them into the message.
    unsafe {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        if let Some((st, len)) = &dest {
            msg.msg_name = (st as *const libc::sockaddr_storage) as *mut _;
            msg.msg_namelen = *len;
        }
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let bytes = std::mem::size_of_val(fds) as u32;
        let mut control = vec![0u64; (libc::CMSG_SPACE(bytes) as usize).div_ceil(8)];
        if !fds.is_empty() {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(bytes) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(bytes) as _;
            let data = libc::CMSG_DATA(c) as *mut libc::c_int;
            for (i, &f) in fds.iter().enumerate() {
                std::ptr::write_unaligned(data.add(i), f);
            }
        }
        let n = libc::sendmsg(fd.as_raw_fd(), &msg, flags);
        if n < 0 {
            Err(last_errno())
        } else {
            Ok(n as usize)
        }
    }
}

/// `getsockopt(2)` of up to `len` bytes.
pub fn getsockopt(fd: &impl AsRawFd, level: i32, opt: i32, len: usize) -> Result<Vec<u8>, Errno> {
    let mut b = vec![0u8; len];
    let mut l = len as libc::socklen_t;
    // SAFETY: `b` is writable for `l` bytes.
    check(unsafe { libc::getsockopt(fd.as_raw_fd(), level, opt, b.as_mut_ptr().cast(), &mut l) })?;
    b.truncate(l as usize);
    Ok(b)
}

/// `getsockopt(2)` into `b` (bytes the host does not write keep their
/// values): the length the host reports, which may exceed `b`'s.
pub fn getsockopt_into(
    fd: &impl AsRawFd,
    level: i32,
    opt: i32,
    b: &mut [u8],
) -> Result<u32, Errno> {
    let mut l = b.len() as libc::socklen_t;
    // SAFETY: `b` is writable for `l` bytes.
    check(unsafe { libc::getsockopt(fd.as_raw_fd(), level, opt, b.as_mut_ptr().cast(), &mut l) })?;
    Ok(l as u32)
}

/// An interface request on a Linux host with the `struct ifreq` bytes
/// `ifr`, which the host reads and may rewrite.
#[cfg(target_os = "linux")]
pub fn ioctl_ifreq(fd: &impl AsRawFd, req: u32, ifr: &mut [u8; 40]) -> Result<(), Errno> {
    // SAFETY: `ifr` is a 40-byte `struct ifreq` (every Linux host is LP64)
    // that outlives the call; the requests passed carry no pointers.
    check(unsafe { libc::ioctl(fd.as_raw_fd(), req as _, ifr.as_mut_ptr()) }).map(|_| ())
}

/// An IPv6 address change on a Linux host with the `struct in6_ifreq`
/// bytes `ireq`.
#[cfg(target_os = "linux")]
pub fn ioctl_in6_ifreq(fd: &impl AsRawFd, req: u32, ireq: &mut [u8; 24]) -> Result<(), Errno> {
    // SAFETY: `ireq` is a 24-byte `struct in6_ifreq` that outlives the
    // call.
    check(unsafe { libc::ioctl(fd.as_raw_fd(), req as _, ireq.as_mut_ptr()) }).map(|_| ())
}

/// `SIOCGIFCONF` on a Linux host: the entries that fit `room` bytes (the
/// length alone without a buffer) and the length the host reports. At most
/// 1 MiB is asked for.
#[cfg(target_os = "linux")]
pub fn ifconf(fd: &impl AsRawFd, room: Option<i32>) -> Result<(Vec<u8>, i32), Errno> {
    let mut buf = vec![0u8; room.map_or(0, |r| r.clamp(0, 1 << 20) as usize)];
    // SAFETY: an all-zero struct ifconf is valid; its buffer pointer is
    // `buf` (or null) with its length, both outliving the call.
    unsafe {
        let mut ifc: libc::ifconf = std::mem::zeroed();
        ifc.ifc_len = if room.is_some() { buf.len() as i32 } else { 0 };
        ifc.ifc_ifcu.ifcu_buf = if room.is_some() {
            buf.as_mut_ptr().cast()
        } else {
            std::ptr::null_mut()
        };
        check(libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCGIFCONF as _,
            &mut ifc,
        ))?;
        let n = ifc.ifc_len.max(0) as usize;
        buf.truncate(if room.is_some() { n.min(buf.len()) } else { 0 });
        Ok((buf, ifc.ifc_len))
    }
}

/// `getsockopt(2)` of an `int`.
pub fn getsockopt_int(fd: &impl AsRawFd, level: i32, opt: i32) -> Result<i32, Errno> {
    let b = getsockopt(fd, level, opt, 4)?;
    let mut w = [0u8; 4];
    w[..b.len().min(4)].copy_from_slice(&b[..b.len().min(4)]);
    Ok(i32::from_ne_bytes(w))
}

/// `setsockopt(2)`.
pub fn setsockopt(fd: &impl AsRawFd, level: i32, opt: i32, val: &[u8]) -> Result<(), Errno> {
    // SAFETY: `val` is readable for its length.
    check(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            opt,
            val.as_ptr().cast(),
            val.len() as libc::socklen_t,
        )
    })
    .map(|_| ())
}

/// The credentials of a connected Unix-domain peer: PID, UID, and GID.
pub fn peer_cred(fd: &impl AsRawFd) -> Result<(i32, u32, u32), Errno> {
    #[cfg(target_os = "linux")]
    {
        let b = getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, 12)?;
        let w = |i: usize| u32::from_ne_bytes(b[i..i + 4].try_into().unwrap());
        Ok((w(0) as i32, w(4), w(8)))
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let raw = fd.as_raw_fd();
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: getpeereid writes the two IDs.
        check(unsafe { libc::getpeereid(raw, &mut uid, &mut gid) })?;
        const SOL_LOCAL: i32 = 0;
        const LOCAL_PEERPID: i32 = 2;
        let pid = getsockopt_int(fd, SOL_LOCAL, LOCAL_PEERPID).unwrap_or(0);
        Ok((pid, uid, gid))
    }
}

/// Binds (`connect == false`) or connects Unix socket `fd` to `name` in
/// directory `dir`, for a path longer than the host's `sun_path`, without
/// changing the process's working directory (the emulator may share its
/// process): Linux names the directory by a `/proc/self/fd` link; Darwin
/// by a short symbolic link to it, made for the call.
pub fn unix_at(
    fd: &impl AsRawFd,
    dir: &std::path::Path,
    name: &[u8],
    connect: bool,
) -> Result<(), Errno> {
    use std::os::unix::ffi::OsStrExt;
    #[cfg(target_os = "linux")]
    let (_hold, mut path) = {
        let d = std::fs::File::open(dir).map_err(Errno::from)?;
        let p = format!("/proc/self/fd/{}/", d.as_raw_fd()).into_bytes();
        (d, p)
    };
    #[cfg(not(target_os = "linux"))]
    let (_hold, mut path) = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let link = std::path::PathBuf::from(format!(
            "/tmp/.rax-sock-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(dir, &link).map_err(Errno::from)?;
        let mut p = link.as_os_str().as_bytes().to_vec();
        p.push(b'/');
        (Unlink(link), p)
    };
    path.extend_from_slice(name);
    let a = HostAddr::Unix {
        name: path,
        abstract_: false,
    };
    if connect {
        self::connect(fd, &a)
    } else {
        bind(fd, &a)
    }
}

/// Removes a path when dropped.
#[cfg(not(target_os = "linux"))]
struct Unlink(std::path::PathBuf);

#[cfg(not(target_os = "linux"))]
impl Drop for Unlink {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The length of the next datagram queued on `fd` (`SIOCINQ` on Linux,
/// Darwin's `SO_NREAD`), 0 when none is.
pub fn next_datagram(fd: &impl AsRawFd) -> usize {
    #[cfg(target_vendor = "apple")]
    {
        const SO_NREAD: i32 = 0x1020;
        getsockopt_int(fd, libc::SOL_SOCKET, SO_NREAD)
            .unwrap_or(0)
            .max(0) as usize
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let mut n: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONREAD, &mut n) };
        if rc == 0 { n.max(0) as usize } else { 0 }
    }
}

/// Bytes queued for reading (`SIOCINQ`): a stream's bytes, a datagram
/// socket's next datagram.
pub fn inq(fd: &impl AsRawFd, stream: bool) -> Result<i32, Errno> {
    if !stream {
        return Ok(next_datagram(fd) as i32);
    }
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int.
    check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONREAD, &mut n) })?;
    Ok(n)
}

/// Bytes sent but not yet acknowledged or read (`SIOCOUTQ`; Darwin's
/// `SO_NWRITE`).
pub fn outq(fd: &impl AsRawFd) -> Result<i32, Errno> {
    #[cfg(target_vendor = "apple")]
    {
        const SO_NWRITE: i32 = 0x1024;
        getsockopt_int(fd, libc::SOL_SOCKET, SO_NWRITE)
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let mut n: libc::c_int = 0;
        // SAFETY: TIOCOUTQ (SIOCOUTQ) writes one int.
        check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCOUTQ, &mut n) })?;
        Ok(n)
    }
}

/// `SIOCATMARK`: whether the read position is at the urgent mark.
pub fn at_mark(fd: &impl AsRawFd) -> Result<i32, Errno> {
    #[cfg(target_vendor = "apple")]
    const SIOCATMARK: libc::c_ulong = 0x4004_7307;
    #[cfg(not(target_vendor = "apple"))]
    const SIOCATMARK: libc::c_ulong = 0x8905;
    let mut n: libc::c_int = 0;
    // SAFETY: SIOCATMARK writes one int.
    check(unsafe { libc::ioctl(fd.as_raw_fd(), SIOCATMARK as _, &mut n) })?;
    Ok(n)
}

/// A socket's host readiness (`POLLIN`, `POLLOUT`, `POLLHUP`, `POLLERR`).
pub fn readiness(fd: &impl AsRawFd) -> crate::user::linux::host::Readiness {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    crate::user::linux::host::Readiness {
        readable: rc > 0 && p.revents & libc::POLLIN != 0,
        writable: rc > 0 && p.revents & libc::POLLOUT != 0,
        hangup: rc > 0 && p.revents & libc::POLLHUP != 0,
        error: rc > 0 && p.revents & (libc::POLLERR | libc::POLLNVAL) != 0,
    }
}

/// The host family, type, and protocol of a socket received from another
/// process (Darwin has no `SO_PROTOCOL`: the type's default protocol).
pub fn describe(fd: &impl AsRawFd) -> Result<(i32, i32, i32), Errno> {
    let stype = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_TYPE)?;
    // SAFETY: plain data; the length matches the storage.
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    check(unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut st as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    })?;
    let domain = i32::from(st.ss_family);
    #[cfg(target_os = "linux")]
    let protocol = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)?;
    #[cfg(not(target_os = "linux"))]
    let protocol = match (domain, stype) {
        (libc::AF_INET | libc::AF_INET6, libc::SOCK_STREAM) => libc::IPPROTO_TCP,
        (libc::AF_INET | libc::AF_INET6, libc::SOCK_DGRAM) => libc::IPPROTO_UDP,
        _ => 0,
    };
    Ok((domain, stype, protocol))
}

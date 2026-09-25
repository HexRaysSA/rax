//! Sockets: guest sockets are host sockets (loopback and real networks
//! work), with Linux's addresses, flags, options, errors, and ancillary
//! data translated to and from the host's (`net/socket.c`,
//! `net/unix/af_unix.c`, `net/ipv4/af_inet.c`, `net/ipv6/af_inet6.c`,
//! `net/core/sock.c`, `net/core/scm.c`).
//!
//! | Module | Contents |
//! |---|---|
//! | [`addr`] | guest `struct sockaddr` parsing and encoding |
//! | [`name`] | Unix names and IP addresses between guest and host: file-system paths through the VFS, the abstract namespace, autobind |
//! | [`msg`] | ancillary data: `SCM_RIGHTS` and `SCM_CREDENTIALS` |
//! | [`netlink`] | `AF_NETLINK`: the host's on Linux, `NETLINK_ROUTE` emulated elsewhere |
//! | [`opts`] | socket options |
//! | [`poll`] | readiness as `sock_poll` reports it |
//! | [`sys`] | the host socket calls (with the host interface enumeration in [`netlink::ifaces`], the module's only `unsafe` code) |
//!
//! The families are `AF_UNIX`, `AF_INET`, `AF_INET6`, and `AF_NETLINK`;
//! creating any other is `EAFNOSUPPORT`, as a kernel built without it
//! answers. Every host socket is non-blocking: blocking, the socket
//! timeouts, and signal interruption are the personality's (see
//! [`syscall::net`](super::syscall::net)).

pub mod addr;
pub mod msg;
pub mod name;
pub mod netlink;
pub mod opts;
pub mod poll;
pub mod sys;

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Mutex;

use addr::UnixName;

/// Linux socket constants (`linux/socket.h`, `linux/net.h`, `linux/in.h`).
pub mod lx {
    pub const AF_UNSPEC: i32 = 0;
    pub const AF_UNIX: i32 = 1;
    pub const AF_INET: i32 = 2;
    pub const AF_INET6: i32 = 10;
    pub const AF_NETLINK: i32 = 16;
    pub const AF_PACKET: i32 = 17;
    /// `AF_MAX` (`NPROTO`).
    pub const AF_MAX: i32 = 46;

    pub const SOCK_STREAM: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;
    pub const SOCK_RAW: i32 = 3;
    pub const SOCK_SEQPACKET: i32 = 5;
    pub const SOCK_PACKET: i32 = 10;
    /// `SOCK_MAX`.
    pub const SOCK_MAX: i32 = 11;
    pub const SOCK_TYPE_MASK: i32 = 0xf;
    pub const SOCK_NONBLOCK: i32 = 0o4000;
    pub const SOCK_CLOEXEC: i32 = 0o2000000;

    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_ICMP: i32 = 1;
    pub const IPPROTO_TCP: i32 = 6;
    pub const IPPROTO_UDP: i32 = 17;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const IPPROTO_ICMPV6: i32 = 58;
    pub const IPPROTO_UDPLITE: i32 = 136;
    pub const IPPROTO_MPTCP: i32 = 262;
    /// `IPPROTO_MAX`.
    pub const IPPROTO_MAX: i32 = 263;

    pub const SOL_SOCKET: i32 = 1;
    pub const SOL_NETLINK: i32 = 270;

    pub const MSG_OOB: u32 = 0x1;
    pub const MSG_PEEK: u32 = 0x2;
    pub const MSG_DONTROUTE: u32 = 0x4;
    pub const MSG_CTRUNC: u32 = 0x8;
    pub const MSG_TRUNC: u32 = 0x20;
    pub const MSG_DONTWAIT: u32 = 0x40;
    pub const MSG_EOR: u32 = 0x80;
    pub const MSG_WAITALL: u32 = 0x100;
    pub const MSG_ERRQUEUE: u32 = 0x2000;
    pub const MSG_NOSIGNAL: u32 = 0x4000;
    pub const MSG_MORE: u32 = 0x8000;
    pub const MSG_WAITFORONE: u32 = 0x10000;
    pub const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
    /// `MSG_INTERNAL_SENDMSG_FLAGS`: `MSG_SPLICE_PAGES`,
    /// `MSG_SENDPAGE_NOPOLICY`, `MSG_SENDPAGE_DECRYPTED`.
    pub const MSG_INTERNAL: u32 = 0x0800_0000 | 0x10000 | 0x10_0000;

    pub const SCM_RIGHTS: i32 = 1;
    pub const SCM_CREDENTIALS: i32 = 2;
}

/// The host's family for a Linux family.
pub fn host_domain(domain: i32) -> i32 {
    match domain {
        lx::AF_UNIX => libc::AF_UNIX,
        lx::AF_INET => libc::AF_INET,
        lx::AF_INET6 => libc::AF_INET6,
        other => other,
    }
}

/// The host's socket type for a Linux one.
pub fn host_type(stype: i32) -> i32 {
    match stype {
        lx::SOCK_STREAM => libc::SOCK_STREAM,
        lx::SOCK_DGRAM => libc::SOCK_DGRAM,
        lx::SOCK_RAW => libc::SOCK_RAW,
        lx::SOCK_SEQPACKET => libc::SOCK_SEQPACKET,
        other => other,
    }
}

/// The Linux socket type for a host one.
pub fn linux_type(stype: i32) -> i32 {
    match stype {
        libc::SOCK_STREAM => lx::SOCK_STREAM,
        libc::SOCK_DGRAM => lx::SOCK_DGRAM,
        libc::SOCK_RAW => lx::SOCK_RAW,
        libc::SOCK_SEQPACKET => lx::SOCK_SEQPACKET,
        other => other,
    }
}

/// The Linux family for a host one.
pub fn linux_domain(domain: i32) -> i32 {
    match domain {
        libc::AF_UNIX => lx::AF_UNIX,
        libc::AF_INET => lx::AF_INET,
        libc::AF_INET6 => lx::AF_INET6,
        other => other,
    }
}

/// Host flags for the Linux `MSG_*` flags a transfer passes on; the
/// personality implements the others (`MSG_DONTWAIT`, `MSG_WAITALL`,
/// `MSG_NOSIGNAL`, `MSG_TRUNC`, `MSG_CMSG_CLOEXEC`) or ignores them as
/// hints (`MSG_MORE`, `MSG_CONFIRM`).
pub fn host_msg_flags(flags: u32) -> i32 {
    let mut h = 0;
    if flags & lx::MSG_OOB != 0 {
        h |= libc::MSG_OOB;
    }
    if flags & lx::MSG_PEEK != 0 {
        h |= libc::MSG_PEEK;
    }
    if flags & lx::MSG_DONTROUTE != 0 {
        h |= libc::MSG_DONTROUTE;
    }
    if flags & lx::MSG_EOR != 0 {
        h |= libc::MSG_EOR;
    }
    h
}

/// A socket (`struct socket`).
#[derive(Debug)]
pub struct Socket {
    /// The host socket, as a file for `read` and `write`.
    pub file: std::fs::File,
    /// Linux family.
    pub domain: i32,
    /// Linux type (`SOCK_RAW` Unix sockets are datagram ones).
    pub stype: i32,
    /// Linux protocol.
    pub protocol: i32,
    /// The sockfs inode number (`/proc/<pid>/fd` shows `socket:[ino]`).
    pub ino: u64,
    /// State the kernel keeps and the host does not.
    pub state: Mutex<SockState>,
    /// An emulated netlink socket's state (its host descriptor is a
    /// readiness level).
    pub netlink: Option<netlink::Endpoint>,
}

/// A socket's personality-side state.
#[derive(Debug, Default)]
pub struct SockState {
    /// The Unix name it is bound to, as the guest gave it.
    pub name: Option<UnixName>,
    /// An emulated abstract name's lock (held while the socket is open).
    pub name_lock: Option<OwnedFd>,
    /// `SO_RCVTIMEO`.
    pub rcvtimeo: opts::Timeout,
    /// `SO_SNDTIMEO`.
    pub sndtimeo: opts::Timeout,
    /// `SO_RCVBUF` as Linux reports it (after doubling).
    pub rcvbuf: Option<i32>,
    /// `SO_SNDBUF`.
    pub sndbuf: Option<i32>,
    /// Options only recorded here: `(level, option, value)`.
    pub ints: Vec<(i32, i32, i32)>,
    /// `SO_COOKIE`.
    pub cookie: u64,
    /// `sk_err` the personality set (a Linux errno), reported once by
    /// `SO_ERROR` or the next `recvmmsg`.
    pub error: i32,
    /// A non-blocking `connect` left the connection under way
    /// (`SS_CONNECTING`).
    pub connecting: bool,
    /// `listen` succeeded (`TCP_LISTEN`).
    pub listening: bool,
    /// The directions the socket's own `shutdown` closed
    /// ([`poll::RCV_SHUTDOWN`], [`poll::SEND_SHUTDOWN`]).
    pub shut: u8,
    /// The credentials `socketpair` gave the pair (`init_peercred`: the
    /// creator's PID, effective UID and GID), for hosts that cannot report
    /// a socketpair peer's.
    pub pair_cred: Option<(i32, u32, u32)>,
}

impl Socket {
    /// Wraps a host socket.
    pub fn new(fd: OwnedFd, domain: i32, stype: i32, protocol: i32) -> Self {
        use std::os::unix::fs::MetadataExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static COOKIE: AtomicU64 = AtomicU64::new(1);
        static INO: AtomicU64 = AtomicU64::new(0x5241_5900);
        let file = std::fs::File::from(fd);
        // The host socket's inode where the host numbers them, a fresh
        // number otherwise.
        let ino = file
            .metadata()
            .map(|m| m.ino())
            .ok()
            .filter(|&i| i != 0)
            .unwrap_or_else(|| INO.fetch_add(1, Ordering::Relaxed));
        Socket {
            file,
            domain,
            stype,
            protocol,
            ino,
            state: Mutex::new(SockState {
                cookie: COOKIE.fetch_add(1, Ordering::Relaxed),
                ..Default::default()
            }),
            netlink: None,
        }
    }

    /// An emulated `NETLINK_ROUTE` socket of type `stype`.
    pub fn emulated_netlink(stype: i32) -> Result<Self, super::abi::errno::Errno> {
        let (fd, endpoint) = netlink::Endpoint::new()?;
        let mut s = Socket::new(fd, lx::AF_NETLINK, stype, netlink::NETLINK_ROUTE);
        s.netlink = Some(endpoint);
        Ok(s)
    }

    /// The host descriptor.
    pub fn raw(&self) -> i32 {
        self.file.as_raw_fd()
    }

    /// Whether it is a byte stream (`SOCK_STREAM`).
    pub fn stream(&self) -> bool {
        self.stype == lx::SOCK_STREAM
    }

    /// Whether it is connection-oriented (`SOCK_STREAM`, `SOCK_SEQPACKET`).
    pub fn connected_type(&self) -> bool {
        matches!(self.stype, lx::SOCK_STREAM | lx::SOCK_SEQPACKET)
    }

    /// Whether it is a Unix-domain socket.
    pub fn unix(&self) -> bool {
        self.domain == lx::AF_UNIX
    }

    /// Whether it is a TCP socket.
    pub fn tcp(&self) -> bool {
        self.protocol == lx::IPPROTO_TCP && self.stream()
    }

    /// Whether it listens: `listen` succeeded here, or (for a socket
    /// received from another process) the host says so where it can
    /// (Darwin has no `SO_ACCEPTCONN` to read).
    pub fn listening(&self) -> bool {
        self.state.lock().unwrap().listening
            || sys::getsockopt_int(&self.file, libc::SOL_SOCKET, libc::SO_ACCEPTCONN)
                .is_ok_and(|v| v != 0)
    }

    /// The peer's credentials (`sk_peer_pid`, `sk_peer_cred`): the host's
    /// report, or those the pair was created with.
    pub fn peer_cred(&self) -> Option<(i32, u32, u32)> {
        if self.domain != lx::AF_UNIX {
            return None;
        }
        sys::peer_cred(&self.file)
            .ok()
            .or(self.state.lock().unwrap().pair_cred)
    }

    /// The `/proc/<pid>/fd` name (`sockfs_dname`).
    pub fn dname(&self) -> String {
        format!("socket:[{}]", self.ino)
    }
}

impl Drop for Socket {
    /// An emulated abstract name is released with its socket.
    fn drop(&mut self) {
        let st = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        if let (Some(UnixName::Abstract(n)), Some(lock)) = (&st.name, st.name_lock.take()) {
            name::release_abstract(n, lock);
        }
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

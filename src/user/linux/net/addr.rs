//! Linux socket addresses: parsing a guest `struct sockaddr` with the
//! kernel's checks and encoding an address as the kernel returns it.
//!
//! | Family | Layout (bytes) |
//! |---|---|
//! | `AF_UNIX` | family (u16 LE) @0, `sun_path` @2 (up to 108) |
//! | `AF_INET` | family @0, port (BE) @2, address @4, zero @8; 16 in all |
//! | `AF_INET6` | family @0, port (BE) @2, `sin6_flowinfo` (BE) @4, address @8, `sin6_scope_id` @24; 28 in all |
//!
//! A Unix address's length is significant: a path's is up to and
//! including its NUL (`unix_mkname_bsd`), an abstract name's (first byte
//! NUL) exactly its bytes, and a bare family asks for an autobound name.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::lx;

/// `offsetof(struct sockaddr_un, sun_path)`.
pub const SUN_PATH_OFFSET: usize = 2;
/// `sizeof(struct sockaddr_un)`.
pub const SOCKADDR_UN_SIZE: usize = 110;
/// `sizeof(struct sockaddr_in)`.
pub const SOCKADDR_IN_SIZE: usize = 16;
/// `sizeof(struct sockaddr_in6)`.
pub const SOCKADDR_IN6_SIZE: usize = 28;
/// `sizeof(struct sockaddr_storage)`: the most `move_addr_to_kernel`
/// copies.
pub const SOCKADDR_STORAGE_SIZE: usize = 128;

/// A Unix-domain name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnixName {
    /// No name (unbound, or a `socketpair` end).
    Unnamed,
    /// A file-system path (without its NUL).
    Path(Vec<u8>),
    /// An abstract name (the bytes after the leading NUL).
    Abstract(Vec<u8>),
}

/// A socket address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr {
    /// `AF_UNSPEC` (a datagram socket's disconnect).
    Unspec,
    /// `AF_UNIX`.
    Unix(UnixName),
    /// `AF_INET`.
    V4 {
        /// Address.
        ip: [u8; 4],
        /// Port.
        port: u16,
    },
    /// `AF_INET6`.
    V6 {
        /// Address.
        ip: [u8; 16],
        /// Port.
        port: u16,
        /// `sin6_flowinfo`.
        flow: u32,
        /// `sin6_scope_id`.
        scope: u32,
    },
    /// `AF_NETLINK`.
    Netlink {
        /// `nl_pid`.
        pid: u32,
        /// `nl_groups`.
        groups: u32,
    },
}

/// The family word of a guest address, if it has one.
pub fn family(b: &[u8]) -> Option<u16> {
    b.get(..2)
        .map(|f| u16::from_le_bytes(f.try_into().unwrap()))
}

/// `unix_validate_addr` and the name a bind or connect of `b` means:
/// a bare family is the autobind request (`Unnamed`), a leading NUL an
/// abstract name, anything else a path up to its first NUL.
pub fn parse_unix(b: &[u8]) -> Result<UnixName, Errno> {
    if b.len() < SUN_PATH_OFFSET || b.len() > SOCKADDR_UN_SIZE {
        return Err(Errno(EINVAL));
    }
    if family(b) != Some(lx::AF_UNIX as u16) {
        return Err(Errno(EINVAL));
    }
    let path = &b[SUN_PATH_OFFSET..];
    if path.is_empty() {
        return Ok(UnixName::Unnamed);
    }
    if path[0] == 0 {
        return Ok(UnixName::Abstract(path[1..].to_vec()));
    }
    let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
    Ok(UnixName::Path(path[..end].to_vec()))
}

/// An IPv4 address (`inet_bind`, `inet_dgram_connect`): at least
/// `sizeof(struct sockaddr_in)`, family `AF_INET`, or `AF_UNSPEC` with the
/// any address (bind's compatibility rule, reported as `AF_INET`).
pub fn parse_v4(b: &[u8], unspec_ok: bool) -> Result<Addr, Errno> {
    if b.len() < SOCKADDR_IN_SIZE {
        return Err(Errno(EINVAL));
    }
    let ip: [u8; 4] = b[4..8].try_into().unwrap();
    let port = u16::from_be_bytes([b[2], b[3]]);
    match family(b).map(i32::from) {
        Some(lx::AF_INET) => Ok(Addr::V4 { ip, port }),
        Some(lx::AF_UNSPEC) if unspec_ok && ip == [0; 4] => Ok(Addr::V4 { ip, port }),
        _ => Err(Errno(EAFNOSUPPORT)),
    }
}

/// An IPv6 address (`inet6_bind`): at least `SIN6_LEN_RFC2133` (24) bytes,
/// family `AF_INET6`.
pub fn parse_v6(b: &[u8]) -> Result<Addr, Errno> {
    if b.len() < 24 {
        return Err(Errno(EINVAL));
    }
    if family(b).map(i32::from) != Some(lx::AF_INET6) {
        return Err(Errno(EAFNOSUPPORT));
    }
    let port = u16::from_be_bytes([b[2], b[3]]);
    let flow = u32::from_be_bytes(b[4..8].try_into().unwrap());
    let ip: [u8; 16] = b[8..24].try_into().unwrap();
    let scope = if b.len() >= SOCKADDR_IN6_SIZE {
        u32::from_le_bytes(b[24..28].try_into().unwrap())
    } else {
        0
    };
    Ok(Addr::V6 {
        ip,
        port,
        flow,
        scope,
    })
}

impl Addr {
    /// The kernel's encoding (`getsockname`, `accept`, `recvfrom`).
    pub fn encode(&self) -> Vec<u8> {
        let fam = |f: i32| (f as u16).to_le_bytes();
        match self {
            Addr::Unspec => fam(lx::AF_UNSPEC).to_vec(),
            Addr::Unix(name) => {
                let mut b = fam(lx::AF_UNIX).to_vec();
                match name {
                    UnixName::Unnamed => {}
                    UnixName::Path(p) => {
                        b.extend_from_slice(p);
                        b.push(0);
                    }
                    UnixName::Abstract(n) => {
                        b.push(0);
                        b.extend_from_slice(n);
                    }
                }
                b
            }
            Addr::V4 { ip, port } => {
                let mut b = vec![0u8; SOCKADDR_IN_SIZE];
                b[..2].copy_from_slice(&fam(lx::AF_INET));
                b[2..4].copy_from_slice(&port.to_be_bytes());
                b[4..8].copy_from_slice(ip);
                b
            }
            Addr::V6 {
                ip,
                port,
                flow,
                scope,
            } => {
                let mut b = vec![0u8; SOCKADDR_IN6_SIZE];
                b[..2].copy_from_slice(&fam(lx::AF_INET6));
                b[2..4].copy_from_slice(&port.to_be_bytes());
                b[4..8].copy_from_slice(&flow.to_be_bytes());
                b[8..24].copy_from_slice(ip);
                b[24..28].copy_from_slice(&scope.to_le_bytes());
                b
            }
            Addr::Netlink { pid, groups } => {
                let mut b = vec![0u8; 12];
                b[..2].copy_from_slice(&fam(lx::AF_NETLINK));
                b[4..8].copy_from_slice(&pid.to_le_bytes());
                b[8..12].copy_from_slice(&groups.to_le_bytes());
                b
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn un(path: &[u8]) -> Vec<u8> {
        let mut b = (lx::AF_UNIX as u16).to_le_bytes().to_vec();
        b.extend_from_slice(path);
        b
    }

    #[test]
    fn unix_names_follow_unix_validate_addr() {
        // A path ends at its first NUL; an abstract name keeps every byte.
        assert_eq!(
            parse_unix(&un(b"/a\0junk")),
            Ok(UnixName::Path(b"/a".to_vec()))
        );
        assert_eq!(parse_unix(&un(b"/a")), Ok(UnixName::Path(b"/a".to_vec())));
        assert_eq!(
            parse_unix(&un(b"\0x\0y")),
            Ok(UnixName::Abstract(b"x\0y".to_vec()))
        );
        assert_eq!(parse_unix(&un(b"")), Ok(UnixName::Unnamed));
        // The size and the family.
        assert_eq!(parse_unix(&[1]), Err(Errno(EINVAL)));
        assert_eq!(parse_unix(&un(&[b'p'; 109])), Err(Errno(EINVAL)));
        assert_eq!(
            parse_unix(&un(&[b'p'; 108])),
            Ok(UnixName::Path(vec![b'p'; 108]))
        );
        let mut inet = un(b"/a");
        inet[0] = lx::AF_INET as u8;
        assert_eq!(parse_unix(&inet), Err(Errno(EINVAL)));
    }

    #[test]
    fn inet_addresses_check_size_then_family() {
        let mut b = vec![0u8; 16];
        b[..2].copy_from_slice(&(lx::AF_INET as u16).to_le_bytes());
        b[2..4].copy_from_slice(&8080u16.to_be_bytes());
        b[4..8].copy_from_slice(&[10, 0, 0, 1]);
        let a = parse_v4(&b, false).unwrap();
        assert_eq!(
            a,
            Addr::V4 {
                ip: [10, 0, 0, 1],
                port: 8080
            }
        );
        assert_eq!(a.encode(), b);
        assert_eq!(parse_v4(&b[..15], false), Err(Errno(EINVAL)));
        // AF_UNSPEC: bind's compatibility rule, for the any address only.
        let mut u = b.clone();
        u[..2].fill(0);
        assert_eq!(parse_v4(&u, false), Err(Errno(EAFNOSUPPORT)));
        assert_eq!(parse_v4(&u, true), Err(Errno(EAFNOSUPPORT)));
        u[4..8].fill(0);
        assert!(parse_v4(&u, true).is_ok());
        let mut v6 = vec![0u8; 28];
        v6[..2].copy_from_slice(&(lx::AF_INET6 as u16).to_le_bytes());
        v6[2..4].copy_from_slice(&443u16.to_be_bytes());
        v6[4..8].copy_from_slice(&0x0001_2345u32.to_be_bytes());
        v6[23] = 1;
        v6[24..28].copy_from_slice(&7u32.to_le_bytes());
        let a = parse_v6(&v6).unwrap();
        assert_eq!(a.encode(), v6);
        // SIN6_LEN_RFC2133: 24 bytes suffice (no scope).
        match parse_v6(&v6[..24]).unwrap() {
            Addr::V6 { scope, flow, .. } => assert_eq!((scope, flow), (0, 0x0001_2345)),
            other => panic!("{other:?}"),
        }
        assert_eq!(parse_v6(&v6[..23]), Err(Errno(EINVAL)));
        assert_eq!(parse_v6(&b), Err(Errno(EINVAL)));
        let mut wrong = v6.clone();
        wrong[0] = lx::AF_INET as u8;
        assert_eq!(parse_v6(&wrong), Err(Errno(EAFNOSUPPORT)));
    }

    #[test]
    fn unix_names_encode_as_getname_returns_them() {
        assert_eq!(Addr::Unix(UnixName::Unnamed).encode(), un(b""));
        assert_eq!(
            Addr::Unix(UnixName::Path(b"/s".to_vec())).encode(),
            un(b"/s\0")
        );
        assert_eq!(
            Addr::Unix(UnixName::Abstract(b"n".to_vec())).encode(),
            un(b"\0n")
        );
        assert_eq!(Addr::Unspec.encode(), vec![0, 0]);
    }
}

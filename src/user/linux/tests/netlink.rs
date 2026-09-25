//! Netlink sockets against `net/netlink/af_netlink.c` and
//! `net/core/rtnetlink.c` (Linux 6.19): creation, port IDs and binding,
//! acknowledgements and errors, link and address dumps, truncation and
//! peeking, options, `NETLINK_PKTINFO`, the calls netlink lacks, and
//! readiness. On a Linux host the sockets are the host's; elsewhere
//! `NETLINK_ROUTE` is emulated. What differs with privilege is checked only
//! without it.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;

const AF_NETLINK: u64 = 16;
const STREAM: u64 = 1;
const DGRAM: u64 = 2;
const RAW: u64 = 3;
const SOL_SOCKET: u64 = 1;
const SO_TYPE: u64 = 3;
const SO_RCVTIMEO: u64 = 20;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const SOL_NETLINK: u64 = 270;
const NETLINK_ADD_MEMBERSHIP: u64 = 1;
const NETLINK_DROP_MEMBERSHIP: u64 = 2;
const NETLINK_PKTINFO: u64 = 3;
const NETLINK_LIST_MEMBERSHIPS: u64 = 9;
const NETLINK_CAP_ACK: u64 = 10;
const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CAPPED: u16 = 0x100;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const IFF_LOOPBACK: u32 = 0x8;
const ARPHRD_LOOPBACK: u16 = 772;
const IFA_LOCAL: u16 = 2;

/// The receive buffer's size.
const RCV: u64 = 32 * 1024;

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u16_of(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_of(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// Whether the caller would hold `CAP_NET_ADMIN`.
fn root() -> bool {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() == 0 }
}

/// A netlink message.
fn nlmsg(kind: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut m = (len as u32).to_le_bytes().to_vec();
    m.extend_from_slice(&kind.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    m.extend_from_slice(payload);
    m.resize((m.len() + 3) & !3, 0);
    m
}

/// A received message: type, flags, sequence number, port ID, and the
/// whole message.
struct Msg {
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
    bytes: Vec<u8>,
}

/// The messages of a datagram.
fn split(d: &[u8]) -> Vec<Msg> {
    let mut out = Vec::new();
    let mut at = 0;
    while d.len() - at >= 16 {
        let len = u32_of(d, at) as usize;
        assert!(len >= 16 && at + len <= d.len(), "a malformed datagram");
        let m = &d[at..at + len];
        out.push(Msg {
            kind: u16_of(m, 4),
            flags: u16_of(m, 6),
            seq: u32_of(m, 8),
            pid: u32_of(m, 12),
            bytes: m.to_vec(),
        });
        at += (len + 3) & !3;
    }
    out
}

/// The attributes after a fixed header of `fixed` bytes.
fn attrs(m: &[u8], fixed: usize) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 16 + fixed;
    while at + 4 <= m.len() {
        let len = u16_of(m, at) as usize;
        if len < 4 || at + len > m.len() {
            break;
        }
        out.push((u16_of(m, at + 2) & 0x3FFF, m[at + 4..at + len].to_vec()));
        at += (len + 3) & !3;
    }
    out
}

struct Nl {
    h: Harness,
    /// A scratch area: addresses at 0, options at 0x200, messages from
    /// 0x1000, the receive buffer from 0x10000.
    m: u64,
}

impl Nl {
    fn new(abi: crate::user::linux::abi::LinuxAbi) -> Self {
        let mut h = Harness::new(abi);
        let m = h.anon(32 * P, 3, false);
        Nl { h, m }
    }

    fn socket(&mut self) -> u64 {
        self.h.ok(Sysno::Socket, &[AF_NETLINK, RAW, 0])
    }

    /// `sendto` of `data`, to `to` if given.
    fn send(&mut self, fd: u64, data: &[u8], flags: u64, to: Option<&[u8]>) -> i64 {
        put(&self.h, self.m + 0x1000, data);
        let (p, l) = match to {
            Some(a) => {
                put(&self.h, self.m, a);
                (self.m, a.len() as u64)
            }
            None => (0, 0),
        };
        self.h.call(
            Sysno::Sendto,
            &[fd, self.m + 0x1000, data.len() as u64, flags, p, l],
        )
    }

    /// `recvfrom` into `len` bytes: the result and the bytes stored.
    fn recv(&mut self, fd: u64, len: u64, flags: u64) -> Result<(i64, Vec<u8>), i32> {
        let buf = self.m + 0x10000;
        let r = self.h.call(Sysno::Recvfrom, &[fd, buf, len, flags, 0, 0]);
        if r < 0 {
            return Err(-r as i32);
        }
        Ok((r, get(&self.h, buf, (r as u64).min(len) as usize)))
    }

    /// The next datagram, which must be there.
    fn next(&mut self, fd: u64) -> Vec<Msg> {
        split(&self.recv(fd, RCV, MSG_DONTWAIT).expect("a datagram").1)
    }

    /// Every datagram of a dump, through the one with `NLMSG_DONE`.
    fn dump(&mut self, fd: u64) -> Vec<Vec<Msg>> {
        let mut out = Vec::new();
        loop {
            let d = self.next(fd);
            let done = d.iter().any(|m| m.kind == NLMSG_DONE);
            out.push(d);
            if done {
                return out;
            }
        }
    }

    /// `getsockname` or `getpeername`.
    fn name(&mut self, fd: u64, peer: bool) -> Vec<u8> {
        put(&self.h, self.m + 0x100, &64u32.to_le_bytes());
        let s = if peer {
            Sysno::Getpeername
        } else {
            Sysno::Getsockname
        };
        self.h.ok(s, &[fd, self.m, self.m + 0x100]);
        let n = u32_of(&get(&self.h, self.m + 0x100, 4), 0) as usize;
        get(&self.h, self.m, n)
    }

    fn bind(&mut self, fd: u64, a: &[u8]) -> i64 {
        put(&self.h, self.m, a);
        self.h.call(Sysno::Bind, &[fd, self.m, a.len() as u64])
    }

    fn connect(&mut self, fd: u64, a: &[u8]) -> i64 {
        put(&self.h, self.m, a);
        self.h.call(Sysno::Connect, &[fd, self.m, a.len() as u64])
    }

    fn setopt(&mut self, fd: u64, level: u64, opt: u64, v: &[u8]) -> i64 {
        put(&self.h, self.m + 0x200, v);
        self.h.call(
            Sysno::Setsockopt,
            &[fd, level, opt, self.m + 0x200, v.len() as u64],
        )
    }

    /// `getsockopt` into `len` bytes: the length reported and the bytes
    /// the guest's buffer then holds.
    fn getopt(&mut self, fd: u64, level: u64, opt: u64, len: u32) -> Result<(u32, Vec<u8>), i32> {
        put(&self.h, self.m + 0x200, &[0xAA; 64]);
        put(&self.h, self.m + 0x300, &len.to_le_bytes());
        let r = self.h.call(
            Sysno::Getsockopt,
            &[fd, level, opt, self.m + 0x200, self.m + 0x300],
        );
        if r < 0 {
            return Err(-r as i32);
        }
        let n = u32_of(&get(&self.h, self.m + 0x300, 4), 0);
        Ok((n, get(&self.h, self.m + 0x200, len as usize)))
    }
}

/// A `struct sockaddr_nl`.
fn nladdr(pid: u32, groups: u32) -> Vec<u8> {
    let mut b = vec![0u8; 12];
    b[..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
    b[4..8].copy_from_slice(&pid.to_le_bytes());
    b[8..12].copy_from_slice(&groups.to_le_bytes());
    b
}

/// A `struct ifinfomsg` for link `index`.
fn ifinfo(index: i32) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[4..8].copy_from_slice(&index.to_le_bytes());
    b
}

#[test]
fn creation_follows_netlink_create() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let h = &mut n.h;
        assert_eq!(
            h.err(Sysno::Socket, &[AF_NETLINK, STREAM, 0]),
            ESOCKTNOSUPPORT
        );
        assert_eq!(
            h.err(Sysno::Socket, &[AF_NETLINK, RAW, 32]),
            EPROTONOSUPPORT
        );
        assert_eq!(
            h.err(Sysno::Socket, &[AF_NETLINK, RAW, u32::MAX as u64]),
            EPROTONOSUPPORT
        );
        if !cfg!(target_os = "linux") {
            // Only NETLINK_ROUTE is registered (NETLINK_KOBJECT_UEVENT).
            assert_eq!(
                h.err(Sysno::Socket, &[AF_NETLINK, RAW, 15]),
                EPROTONOSUPPORT
            );
        }
        let fd = h.ok(Sysno::Socket, &[AF_NETLINK, DGRAM | 0o2000000, 0]);
        let int = |n: &mut Nl, opt| {
            let (len, v) = n.getopt(fd, SOL_SOCKET, opt, 4).unwrap();
            assert_eq!(len, 4);
            u32_of(&v, 0)
        };
        assert_eq!(int(&mut n, SO_TYPE), DGRAM as u32);
        assert_eq!(int(&mut n, SO_DOMAIN), AF_NETLINK as u32);
        assert_eq!(int(&mut n, SO_PROTOCOL), 0);
        // Netlink sockets do not pair.
        assert_eq!(
            n.h.err(Sysno::Socketpair, &[AF_NETLINK, RAW, 0, n.m]),
            EOPNOTSUPP
        );
    });
}

#[test]
fn port_ids_follow_netlink_bind() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let a = n.socket();
        // Unbound: port 0.
        assert_eq!(n.name(a, false), nladdr(0, 0));
        assert_eq!(n.bind(a, &nladdr(0, 0)[..11]), -(EINVAL as i64));
        let mut wrong = nladdr(0, 0);
        wrong[0] = 1;
        assert_eq!(n.bind(a, &wrong), -(EINVAL as i64));
        // Autobind: a port of its own, kept.
        assert_eq!(n.bind(a, &nladdr(0, 0)), 0);
        let port = u32_of(&n.name(a, false), 4);
        assert_ne!(port, 0);
        assert_eq!(n.bind(a, &nladdr(port, 0)), 0);
        assert_eq!(n.bind(a, &nladdr(port ^ 1, 0)), -(EINVAL as i64));
        assert_eq!(n.bind(a, &nladdr(0, 0)), -(EINVAL as i64));
        // Another socket cannot take it, and autobinds elsewhere.
        let b = n.socket();
        assert_eq!(n.bind(b, &nladdr(port, 0)), -(EADDRINUSE as i64));
        assert_eq!(n.bind(b, &nladdr(0, 0)), 0);
        assert_ne!(u32_of(&n.name(b, false), 4), port);
        // A send autobinds too.
        let c = n.socket();
        let noop = nlmsg(NLMSG_NOOP, NLM_F_REQUEST, 1, &[]);
        assert_eq!(n.send(c, &noop, 0, None), noop.len() as i64);
        assert_ne!(u32_of(&n.name(c, false), 4), 0);
    });
}

#[test]
fn requests_are_acknowledged_as_netlink_rcv_skb_does() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        assert_eq!(n.send(fd, &[], 0, None), -(ENODATA as i64));
        let noop = nlmsg(NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 7, &[]);
        assert_eq!(n.send(fd, &noop, MSG_OOB, None), -(EOPNOTSUPP as i64));
        assert_eq!(n.send(fd, &noop, 0, None), noop.len() as i64);
        let port = u32_of(&n.name(fd, false), 4);
        // A control message: acknowledged with 0, capped, from the kernel.
        let buf = n.m + 0x10000;
        put(&n.h, n.m + 0x100, &64u32.to_le_bytes());
        let r = n.h.call(
            Sysno::Recvfrom,
            &[fd, buf, RCV, MSG_DONTWAIT, n.m, n.m + 0x100],
        );
        assert_eq!(r, 36);
        assert_eq!(get(&n.h, n.m, 12), nladdr(0, 0));
        let d = split(&get(&n.h, buf, 36));
        assert_eq!(d.len(), 1);
        assert_eq!(
            (d[0].kind, d[0].flags, d[0].seq, d[0].pid),
            (NLMSG_ERROR, NLM_F_CAPPED, 7, port)
        );
        assert_eq!(u32_of(&d[0].bytes, 16), 0);
        assert_eq!(&d[0].bytes[20..36], &noop[..16]);
        // Not a request: acknowledged only when asked.
        assert_eq!(n.send(fd, &nlmsg(RTM_GETLINK, 0, 8, &[0]), 0, None), 20);
        assert_eq!(n.recv(fd, RCV, MSG_DONTWAIT).unwrap_err(), EAGAIN);
        // An error carries the whole request, unless capped.
        let missing = nlmsg(RTM_GETLINK, NLM_F_REQUEST, 9, &ifinfo(i32::MAX));
        n.send(fd, &missing, 0, None);
        let d = n.next(fd);
        assert_eq!((d[0].kind, d[0].flags), (NLMSG_ERROR, 0));
        assert_eq!(u32_of(&d[0].bytes, 16) as i32, -ENODEV);
        assert_eq!(&d[0].bytes[20..], &missing[..]);
        assert_eq!(
            n.setopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &1u32.to_le_bytes()),
            0
        );
        n.send(fd, &missing, 0, None);
        let d = n.next(fd);
        assert_eq!((d[0].flags, d[0].bytes.len()), (NLM_F_CAPPED, 36));
        // Past RTM_MAX; several messages in one send, answered in order.
        let mut two = nlmsg(124, NLM_F_REQUEST, 10, &[0]);
        two.extend(nlmsg(NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 11, &[]));
        n.send(fd, &two, 0, None);
        assert_eq!(u32_of(&n.next(fd)[0].bytes, 16) as i32, -EOPNOTSUPP);
        assert_eq!(n.next(fd)[0].seq, 11);
        if !root() {
            let change = nlmsg(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 12, &ifinfo(1));
            n.send(fd, &change, 0, None);
            assert_eq!(u32_of(&n.next(fd)[0].bytes, 16) as i32, -EPERM);
            // Unicasts to other ports need privilege.
            assert_eq!(
                n.send(fd, &noop, 0, Some(&nladdr(12345, 0))),
                -(EPERM as i64)
            );
        }
    });
}

#[test]
fn links_dump_with_a_loopback() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        let dump = nlmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 3, &[0]);
        n.send(fd, &dump, 0, None);
        // A second dump while one runs is refused.
        n.send(
            fd,
            &nlmsg(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 4, &[0]),
            0,
            None,
        );
        let port = u32_of(&n.name(fd, false), 4);
        let mut links = Vec::new();
        let mut busy = false;
        let datagrams = n.dump(fd);
        for m in datagrams.iter().flatten() {
            if m.seq == 4 {
                assert_eq!(m.kind, NLMSG_ERROR);
                assert_eq!(u32_of(&m.bytes, 16) as i32, -EBUSY);
                busy = true;
                continue;
            }
            assert_eq!((m.seq, m.pid), (3, port));
            assert!(m.flags & NLM_F_MULTI != 0);
            if m.kind == RTM_NEWLINK {
                links.push(m.bytes.clone());
            }
        }
        assert!(busy);
        // rtnl_dump_ifinfo sends NLMSG_DONE (0) alone.
        let last = datagrams.last().unwrap();
        assert_eq!(last.len(), 1);
        assert_eq!(u32_of(&last[0].bytes, 16), 0);
        let lo = links
            .iter()
            .find(|l| u32_of(l, 24) & IFF_LOOPBACK != 0)
            .expect("a loopback link");
        assert_eq!(u16_of(lo, 18), ARPHRD_LOOPBACK);
        let a = attrs(lo, 16);
        let name = &a.iter().find(|x| x.0 == 3).expect("IFLA_IFNAME").1;
        assert_eq!(name.last(), Some(&0));
        assert_eq!(
            a.iter().find(|x| x.0 == 1).map(|x| x.1.clone()),
            Some(vec![0; 6])
        );
        assert!(a.iter().any(|x| x.0 == 4 && x.1.len() == 4), "IFLA_MTU");
        // The same link by index, then by name.
        let index = u32_of(lo, 20) as i32;
        let one = nlmsg(RTM_GETLINK, NLM_F_REQUEST, 5, &ifinfo(index));
        n.send(fd, &one, 0, None);
        let d = n.next(fd);
        assert_eq!((d.len(), d[0].kind, d[0].flags), (1, RTM_NEWLINK, 0));
        assert_eq!(u32_of(&d[0].bytes, 20) as i32, index);
        let mut by_name = ifinfo(0);
        by_name.extend_from_slice(&((4 + name.len()) as u16).to_le_bytes());
        by_name.extend_from_slice(&3u16.to_le_bytes());
        by_name.extend_from_slice(name);
        by_name.resize((by_name.len() + 3) & !3, 0);
        n.send(fd, &nlmsg(RTM_GETLINK, NLM_F_REQUEST, 6, &by_name), 0, None);
        assert_eq!(u32_of(&n.next(fd)[0].bytes, 20) as i32, index);
    });
}

#[test]
fn addresses_dump_by_family() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        let family_dump = |n: &mut Nl, family: u8| -> Vec<Vec<Msg>> {
            let req = nlmsg(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 1, &[family]);
            n.send(fd, &req, 0, None);
            n.dump(fd)
        };
        let v4 = family_dump(&mut n, 2);
        let loopback = v4.iter().flatten().any(|m| {
            m.kind == RTM_NEWADDR
                && m.bytes[16] == 2
                && m.bytes[17] == 8
                && m.bytes[19] == 254
                && attrs(&m.bytes, 8).contains(&(IFA_LOCAL, vec![127, 0, 0, 1]))
        });
        assert!(loopback, "127.0.0.1/8, scope host");
        assert_eq!(v4.last().unwrap().len(), 1, "NLMSG_DONE alone");
        let v6 = family_dump(&mut n, 10);
        let messages: Vec<&Msg> = v6.iter().flatten().collect();
        assert!(
            messages
                .iter()
                .all(|m| m.kind != RTM_NEWADDR || m.bytes[16] == 10)
        );
        // inet6_dump_ifaddr ends its last datagram with NLMSG_DONE.
        if messages.len() > 1 {
            assert!(v6.last().unwrap().len() > 1);
        }
        // Both, IPv4 first.
        let all = family_dump(&mut n, 0);
        let families: Vec<u8> = all
            .iter()
            .flatten()
            .filter(|m| m.kind == RTM_NEWADDR)
            .map(|m| m.bytes[16])
            .collect();
        assert!(families.windows(2).all(|w| w[0] <= w[1]));
        assert!(families.contains(&2));
    });
}

#[test]
fn receives_truncate_and_peek() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        let noop = nlmsg(NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 1, &[]);
        n.send(fd, &noop, 0, None);
        // MSG_TRUNC reports the whole datagram; MSG_PEEK leaves it.
        let (r, _) = n.recv(fd, 4, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT).unwrap();
        assert_eq!(r, 36);
        let (r, b) = n.recv(fd, 8, MSG_DONTWAIT).unwrap();
        assert_eq!((r, b.len()), (8, 8));
        assert_eq!(u32_of(&b, 0), 36);
        // The rest went with it.
        assert_eq!(n.recv(fd, RCV, MSG_DONTWAIT).unwrap_err(), EAGAIN);
        // A timeout ends a blocking wait.
        let mut tv = 0u64.to_le_bytes().to_vec();
        tv.extend_from_slice(&20_000u64.to_le_bytes());
        assert_eq!(n.setopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv), 0);
        let t = std::time::Instant::now();
        assert_eq!(n.recv(fd, RCV, 0).unwrap_err(), EAGAIN);
        assert!(t.elapsed() >= std::time::Duration::from_millis(15));
    });
}

#[test]
fn options_follow_netlink_setsockopt() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        let set = |n: &mut Nl, opt, v: u32| n.setopt(fd, SOL_NETLINK, opt, &v.to_le_bytes());
        assert_eq!(set(&mut n, NETLINK_ADD_MEMBERSHIP, 1), 0);
        // RTNLGRP_IPV6_ACADDR, the last group.
        assert_eq!(set(&mut n, NETLINK_ADD_MEMBERSHIP, 39), 0);
        assert_eq!(set(&mut n, NETLINK_ADD_MEMBERSHIP, 40), -(EINVAL as i64));
        assert_eq!(set(&mut n, NETLINK_ADD_MEMBERSHIP, 0), -(EINVAL as i64));
        if !root() {
            // RTNLGRP_IPV4_MROUTE_R needs CAP_NET_ADMIN.
            assert_eq!(set(&mut n, NETLINK_ADD_MEMBERSHIP, 30), -(EPERM as i64));
        }
        // The bitmap in words, as many as fit, and its whole length.
        let (len, v) = n
            .getopt(fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, 16)
            .unwrap();
        assert_eq!(len, 8);
        assert_eq!((u32_of(&v, 0), u32_of(&v, 4)), (1, 1 << 6));
        assert_eq!(&v[8..], &[0xAA; 8]);
        let (len, v) = n
            .getopt(fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, 6)
            .unwrap();
        assert_eq!((len, u32_of(&v, 0)), (8, 1));
        assert_eq!(&v[4..6], &[0xAA; 2]);
        // The name shows the first 32 groups; a bind replaces them.
        assert_eq!(u32_of(&n.name(fd, false), 8), 1);
        assert_eq!(n.bind(fd, &nladdr(0, 2)), 0);
        let (_, v) = n
            .getopt(fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, 8)
            .unwrap();
        assert_eq!((u32_of(&v, 0), u32_of(&v, 4)), (2, 1 << 6));
        assert_eq!(set(&mut n, NETLINK_DROP_MEMBERSHIP, 39), 0);
        // Flags are ints; a short value is 0.
        assert_eq!(set(&mut n, NETLINK_CAP_ACK, 5), 0);
        assert_eq!(n.getopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, 4).unwrap().0, 4);
        assert_eq!(
            u32_of(&n.getopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, 4).unwrap().1, 0),
            1
        );
        assert_eq!(n.setopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &[]), 0);
        assert_eq!(
            u32_of(&n.getopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, 4).unwrap().1, 0),
            0
        );
        assert_eq!(
            n.getopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, 3).unwrap_err(),
            EINVAL
        );
        assert_eq!(n.getopt(fd, SOL_NETLINK, 99, 4).unwrap_err(), ENOPROTOOPT);
        assert_eq!(set(&mut n, 99, 1), -(ENOPROTOOPT as i64));
    });
}

#[test]
fn pktinfo_reports_the_group() {
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        let on = 1u32.to_le_bytes();
        assert_eq!(n.setopt(fd, SOL_NETLINK, NETLINK_PKTINFO, &on), 0);
        let noop = nlmsg(NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 1, &[]);
        n.send(fd, &noop, 0, None);
        // struct msghdr: an iovec of RCV bytes, 64 bytes of control.
        let (hdr, iov, ctl) = (n.m + 0x400, n.m + 0x500, n.m + 0x600);
        let mut v = (n.m + 0x10000).to_le_bytes().to_vec();
        v.extend_from_slice(&RCV.to_le_bytes());
        put(&n.h, iov, &v);
        let mut b = vec![0u8; 56];
        b[16..24].copy_from_slice(&iov.to_le_bytes());
        b[24..32].copy_from_slice(&1u64.to_le_bytes());
        b[32..40].copy_from_slice(&ctl.to_le_bytes());
        b[40..48].copy_from_slice(&64u64.to_le_bytes());
        put(&n.h, hdr, &b);
        assert_eq!(n.h.call(Sysno::Recvmsg, &[fd, hdr, MSG_DONTWAIT]), 36);
        let clen = u32_of(&get(&n.h, hdr + 40, 4), 0) as usize;
        let c = get(&n.h, ctl, clen);
        // One message: cmsg_len 20, SOL_NETLINK, NETLINK_PKTINFO, group 0.
        assert_eq!(clen, 24);
        assert_eq!(u32_of(&c, 0), 20);
        assert_eq!((u32_of(&c, 8), u32_of(&c, 12)), (270, 3));
        assert_eq!(u32_of(&c, 16), 0);
    });
}

#[test]
fn netlink_lacks_streams_and_answers_its_calls() {
    const IN: u16 = 0x1;
    const OUT: u16 = 0x4;
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        assert_eq!(n.h.err(Sysno::Listen, &[fd, 1]), EOPNOTSUPP);
        assert_eq!(n.h.err(Sysno::Accept4, &[fd, 0, 0, 0]), EOPNOTSUPP);
        assert_eq!(n.h.err(Sysno::Shutdown, &[fd, 1]), EOPNOTSUPP);
        assert_eq!(n.h.err(Sysno::Shutdown, &[fd, 7]), EOPNOTSUPP);
        assert_eq!(n.h.err(Sysno::Ioctl, &[fd, 0x541B, n.m]), ENOTTY);
        // The kernel is the only peer the unprivileged may name.
        assert_eq!(n.connect(fd, &nladdr(0, 0)), 0);
        assert_eq!(n.name(fd, true), nladdr(0, 0));
        assert_eq!(n.connect(fd, &[0, 0]), 0);
        assert_eq!(n.connect(fd, &[16]), -(EINVAL as i64));
        if !root() {
            assert_eq!(n.connect(fd, &nladdr(5, 0)), -(EPERM as i64));
        }
        // Readable once a reply is queued; always writable.
        let poll = |n: &mut Nl| {
            let mut rec = (fd as i32).to_le_bytes().to_vec();
            rec.extend_from_slice(&(IN | OUT).to_le_bytes());
            rec.extend_from_slice(&[0, 0]);
            put(&n.h, n.m + 0x800, &rec);
            put(&n.h, n.m + 0x840, &[0u8; 16]);
            n.h.ok(Sysno::Ppoll, &[n.m + 0x800, 1, n.m + 0x840, 0, 8]);
            u16_of(&get(&n.h, n.m + 0x806, 2), 0)
        };
        assert_eq!(poll(&mut n) & (IN | OUT), OUT);
        n.send(
            fd,
            &nlmsg(NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 1, &[]),
            0,
            None,
        );
        assert_eq!(poll(&mut n) & (IN | OUT), IN | OUT);
        n.next(fd);
        assert_eq!(poll(&mut n) & IN, 0);
    });
}

#[test]
fn a_passed_socket_is_the_same_socket() {
    const AF_UNIX: u64 = 1;
    each_abi(|abi| {
        let mut n = Nl::new(abi);
        let fd = n.socket();
        n.h.ok(Sysno::Socketpair, &[AF_UNIX, DGRAM, 0, n.m + 0x700]);
        let pair = get(&n.h, n.m + 0x700, 8);
        let (a, b) = (u64::from(u32_of(&pair, 0)), u64::from(u32_of(&pair, 4)));
        // sendmsg on `a`: one byte, SCM_RIGHTS with the netlink socket.
        let (hdr, iov, ctl) = (n.m + 0x400, n.m + 0x500, n.m + 0x600);
        put(&n.h, n.m + 0x680, b"x");
        let mut v = (n.m + 0x680).to_le_bytes().to_vec();
        v.extend_from_slice(&1u64.to_le_bytes());
        put(&n.h, iov, &v);
        let mut c = 20u64.to_le_bytes().to_vec();
        c.extend_from_slice(&1i32.to_le_bytes());
        c.extend_from_slice(&1i32.to_le_bytes());
        c.extend_from_slice(&(fd as i32).to_le_bytes());
        c.resize(24, 0);
        put(&n.h, ctl, &c);
        let mut m = vec![0u8; 56];
        m[16..24].copy_from_slice(&iov.to_le_bytes());
        m[24..32].copy_from_slice(&1u64.to_le_bytes());
        m[32..40].copy_from_slice(&ctl.to_le_bytes());
        m[40..48].copy_from_slice(&24u64.to_le_bytes());
        put(&n.h, hdr, &m);
        assert_eq!(n.h.call(Sysno::Sendmsg, &[a, hdr, 0]), 1);
        put(&n.h, ctl, &[0u8; 24]);
        m[40..48].copy_from_slice(&24u64.to_le_bytes());
        put(&n.h, hdr, &m);
        assert_eq!(n.h.call(Sysno::Recvmsg, &[b, hdr, 0]), 1);
        let got = u64::from(u32_of(&get(&n.h, ctl + 16, 4), 0));
        assert_ne!(got, fd);
        // A request on the received descriptor is answered on the original,
        // which it bound.
        n.send(
            got,
            &nlmsg(NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ACK, 9, &[]),
            0,
            None,
        );
        assert_eq!(n.next(fd)[0].seq, 9);
        let port = u32_of(&n.name(fd, false), 4);
        assert_ne!(port, 0);
        assert_eq!(u32_of(&n.name(got, false), 4), port);
    });
}

//! The kernel side of an emulated `NETLINK_ROUTE` socket: `rtnetlink`
//! (`net/core/rtnetlink.c`) answering requests about the host's links and
//! addresses (`net/ipv4/devinet.c`, `net/ipv6/addrconf.c`).
//!
//! Requests are handled as `netlink_rcv_skb` hands them to
//! `rtnetlink_rcv_msg`: messages that are not requests and control
//! messages are only acknowledged (if asked); a type past `RTM_MAX` or
//! without a handler is `-EOPNOTSUPP`; a change (`RTM_NEW*`, `RTM_DEL*`,
//! `RTM_SET*`) is `-EPERM` without `CAP_NET_ADMIN`, and `-EOPNOTSUPP` with
//! it (the host's configuration is not the guest's to change).
//!
//! | Request | Handler | Answer |
//! |---|---|---|
//! | `RTM_GETLINK` dump | `rtnl_dump_ifinfo` (`AF_BRIDGE`: `rtnl_bridge_getlink`) | every link by index (no bridge ports); `NLMSG_DONE` split off |
//! | `RTM_GETLINK` | `rtnl_getlink` | the link by index, else by `IFLA_IFNAME` |
//! | `RTM_GETADDR` dump, `AF_INET` | `inet_dump_ifaddr` | IPv4 addresses; `NLMSG_DONE` split off |
//! | `RTM_GETADDR` dump, `AF_INET6` | `inet6_dump_ifaddr` | IPv6 addresses |
//! | `RTM_GETADDR` dump, other families | `rtnl_dump_all` | IPv4, then IPv6; `NLMSG_DONE` split off |
//! | `RTM_GETADDR`, `AF_INET6` | `inet6_rtm_getaddr` | the address by `IFA_LOCAL` or `IFA_ADDRESS` (on the link, if one is named) |
//!
//! Other requests are answered as by a kernel without their handlers
//! (`-EOPNOTSUPP`): routes, neighbours, rules, and the rest. The kernel
//! answers an `AF_INET6` link dump with IPv6's per-link data
//! (`inet6_dump_ifinfo`); here it is the plain link dump, as without that
//! handler. Replies carry the attributes of `rtnl_fill_ifinfo`,
//! `inet_fill_ifaddr`, and `inet6_fill_ifaddr` that describe the host link
//! or address, in the kernel's order; attributes about the kernel's own
//! structures (offload sizes, queues, driver data) are left out.

use super::*;

/// `RTM_*` message types (`linux/rtnetlink.h`).
pub const RTM_BASE: u16 = 16;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
/// `AF_BRIDGE`.
const AF_BRIDGE: u8 = 7;
/// The last type of Linux 6.19 (`RTM_MAX`, from `__RTM_MAX - 1`).
pub const RTM_MAX: u16 = 123;

/// `IFLA_*` link attributes (`linux/if_link.h`).
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_STATS: u16 = 7;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_STATS64: u16 = 23;
const IFLA_GROUP: u16 = 27;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_CARRIER: u16 = 33;
const IFLA_ALLMULTI: u16 = 61;

/// `IFA_*` address attributes (`linux/if_addr.h`).
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;

/// `IFA_F_PERMANENT`: a configured, not autoconfigured, address.
pub const IFA_F_PERMANENT: u32 = 0x80;
/// `IF_OPER_UNKNOWN`, `IF_OPER_DOWN`, `IF_OPER_UP` (`linux/if.h`).
pub const IF_OPER_UNKNOWN: u8 = 0;
pub const IF_OPER_DOWN: u8 = 2;
pub const IF_OPER_UP: u8 = 6;
/// `RT_SCOPE_*` (`linux/rtnetlink.h`).
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_SITE: u8 = 200;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;
/// `INFINITY_LIFE_TIME`.
const INFINITY_LIFE_TIME: u32 = 0xFFFF_FFFF;

/// A link as `rtnl_fill_ifinfo` describes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub index: i32,
    pub name: String,
    /// `ARPHRD_*`.
    pub kind: u16,
    /// Linux `IFF_*` flags.
    pub flags: u32,
    pub mtu: u32,
    pub txqlen: u32,
    /// `IF_OPER_*`.
    pub operstate: u8,
    pub carrier: bool,
    /// The hardware and broadcast addresses (both of the link's address
    /// length, none for a link without one).
    pub address: Vec<u8>,
    pub broadcast: Vec<u8>,
    /// `rtnl_link_stats64` counters, in its order (25).
    pub stats: [u64; 25],
}

/// An address as `inet_fill_ifaddr` or `inet6_fill_ifaddr` describes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The link's index.
    pub index: i32,
    /// `AF_INET` or `AF_INET6`.
    pub family: u8,
    pub prefixlen: u8,
    /// `IFA_F_*` flags (the message carries the low 8 bits, `IFA_FLAGS`
    /// all).
    pub flags: u32,
    pub scope: u8,
    /// The address (4 or 16 bytes).
    pub local: Vec<u8>,
    /// The peer of a point-to-point address.
    pub peer: Option<Vec<u8>>,
    /// An IPv4 broadcast address.
    pub broadcast: Option<Vec<u8>>,
    /// An IPv4 address's label (its link's name).
    pub label: String,
}

/// What rtnetlink knows about the host.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Host {
    pub links: Vec<Link>,
    pub addresses: Vec<Address>,
}

/// Appends one attribute (`nla_put`): header, payload, padding.
fn put_attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len() + align(len) - len, 0);
}

fn put_u32(out: &mut Vec<u8>, kind: u16, v: u32) {
    put_attr(out, kind, &v.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, kind: u16, s: &str) {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    put_attr(out, kind, &b);
}

/// Starts a message (`nlmsg_put`); [`finish`] writes its length.
fn start(kind: u16, flags: u16, seq: u32, portid: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    m.extend_from_slice(&0u32.to_le_bytes());
    m.extend_from_slice(&kind.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&portid.to_le_bytes());
    m
}

fn finish(mut m: Vec<u8>) -> Vec<u8> {
    let len = m.len() as u32;
    m[..4].copy_from_slice(&len.to_le_bytes());
    m
}

/// An `RTM_NEWLINK` message for `link` (`rtnl_fill_ifinfo`).
pub fn link_message(link: &Link, flags: u16, seq: u32, portid: u32) -> Vec<u8> {
    let mut m = start(RTM_NEWLINK, flags, seq, portid);
    // struct ifinfomsg
    m.push(0); // AF_UNSPEC
    m.push(0);
    m.extend_from_slice(&link.kind.to_le_bytes());
    m.extend_from_slice(&link.index.to_le_bytes());
    m.extend_from_slice(&link.flags.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes()); // ifi_change
    put_str(&mut m, IFLA_IFNAME, &link.name);
    put_u32(&mut m, IFLA_TXQLEN, link.txqlen);
    put_attr(&mut m, IFLA_OPERSTATE, &[link.operstate]);
    put_attr(&mut m, IFLA_LINKMODE, &[0]);
    put_u32(&mut m, IFLA_MTU, link.mtu);
    put_u32(&mut m, IFLA_GROUP, 0);
    put_u32(&mut m, IFLA_PROMISCUITY, 0);
    put_u32(&mut m, IFLA_ALLMULTI, 0);
    put_u32(&mut m, IFLA_NUM_TX_QUEUES, 1);
    put_u32(&mut m, IFLA_NUM_RX_QUEUES, 1);
    put_attr(&mut m, IFLA_CARRIER, &[u8::from(link.carrier)]);
    if !link.address.is_empty() {
        put_attr(&mut m, IFLA_ADDRESS, &link.address);
        put_attr(&mut m, IFLA_BROADCAST, &link.broadcast);
    }
    // rtnl_fill_stats: the 64-bit counters, then the 32-bit ones (the
    // first 24, truncated).
    let s64: Vec<u8> = link.stats.iter().flat_map(|v| v.to_le_bytes()).collect();
    put_attr(&mut m, IFLA_STATS64, &s64);
    let s32: Vec<u8> = link.stats[..24]
        .iter()
        .flat_map(|&v| (v as u32).to_le_bytes())
        .collect();
    put_attr(&mut m, IFLA_STATS, &s32);
    finish(m)
}

/// An `RTM_NEWADDR` message for `a` (`inet_fill_ifaddr` or
/// `inet6_fill_ifaddr`).
pub fn address_message(a: &Address, flags: u16, seq: u32, portid: u32) -> Vec<u8> {
    let mut m = start(RTM_NEWADDR, flags, seq, portid);
    // struct ifaddrmsg
    m.push(a.family);
    m.push(a.prefixlen);
    m.push(a.flags as u8);
    m.push(a.scope);
    m.extend_from_slice(&(a.index as u32).to_le_bytes());
    // struct ifa_cacheinfo: preferred, valid, created, updated (a
    // permanent address lives forever).
    let mut cache = Vec::with_capacity(16);
    cache.extend_from_slice(&INFINITY_LIFE_TIME.to_le_bytes());
    cache.extend_from_slice(&INFINITY_LIFE_TIME.to_le_bytes());
    cache.extend_from_slice(&0u32.to_le_bytes());
    cache.extend_from_slice(&0u32.to_le_bytes());
    if a.family == AF_INET {
        // inet_fill_ifaddr: addresses of 0.0.0.0 are left out.
        let address = a.peer.as_deref().unwrap_or(&a.local);
        if address.iter().any(|&b| b != 0) {
            put_attr(&mut m, IFA_ADDRESS, address);
        }
        if a.local.iter().any(|&b| b != 0) {
            put_attr(&mut m, IFA_LOCAL, &a.local);
        }
        if let Some(b) = &a.broadcast {
            put_attr(&mut m, IFA_BROADCAST, b);
        }
        if !a.label.is_empty() {
            put_str(&mut m, IFA_LABEL, &a.label);
        }
        put_u32(&mut m, IFA_FLAGS, a.flags);
        put_attr(&mut m, IFA_CACHEINFO, &cache);
    } else {
        match &a.peer {
            Some(peer) => {
                put_attr(&mut m, IFA_LOCAL, &a.local);
                put_attr(&mut m, IFA_ADDRESS, peer);
            }
            None => put_attr(&mut m, IFA_ADDRESS, &a.local),
        }
        put_attr(&mut m, IFA_CACHEINFO, &cache);
        put_u32(&mut m, IFA_FLAGS, a.flags);
    }
    finish(m)
}

/// `NLMSG_DONE` ending a dump (`netlink_dump_done`): its payload is the
/// dump's result, `err`.
pub fn done_message(seq: u32, portid: u32, err: i32) -> Vec<u8> {
    let mut m = start(NLMSG_DONE, NLM_F_MULTI, seq, portid);
    m.extend_from_slice(&err.to_le_bytes());
    finish(m)
}

/// `netlink_ack`: `NLMSG_ERROR` carrying `err` and the request's header,
/// and for an error, unless `capped` (`NETLINK_CAP_ACK`), its payload too
/// (`nlmsg_append`: padded to 4 bytes).
pub fn ack_message(request: &[u8], err: i32, capped: bool, portid: u32) -> Vec<u8> {
    let seq = u32::from_le_bytes(request[8..12].try_into().unwrap());
    let flags = if err == 0 || capped { NLM_F_CAPPED } else { 0 };
    let mut m = start(NLMSG_ERROR, flags, seq, portid);
    m.extend_from_slice(&err.to_le_bytes());
    let len = u32::from_le_bytes(request[..4].try_into().unwrap()) as usize;
    let whole = &request[..len.min(request.len())];
    m.extend_from_slice(&whole[..NLMSG_HDRLEN]);
    if flags & NLM_F_CAPPED == 0 {
        m.extend_from_slice(&whole[NLMSG_HDRLEN..]);
        m.resize(align(m.len()), 0);
    }
    finish(m)
}

/// The kernel's answer to one request message.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// Nothing but an acknowledgement, if the request asked for one.
    Ack,
    /// An error, always acknowledged.
    Error(i32),
    /// Messages sent at once (a `doit`).
    Unicast(Vec<Vec<u8>>),
    /// A dump: messages, then `NLMSG_DONE`, in a datagram of its own if
    /// `split_done` (`RTNL_FLAG_DUMP_SPLIT_NLM_DONE`, `rtnl_dump_all`).
    Dump {
        messages: Vec<Vec<u8>>,
        split_done: bool,
    },
}

/// The attributes after a fixed header of `fixed` bytes in a request, as
/// (type, payload).
fn attrs(msg: &[u8], fixed: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = NLMSG_HDRLEN + align(fixed);
    while at + 4 <= msg.len() {
        let len = u16::from_le_bytes([msg[at], msg[at + 1]]) as usize;
        let kind = u16::from_le_bytes([msg[at + 2], msg[at + 3]]) & 0x3FFF;
        if len < 4 || at + len > msg.len() {
            break;
        }
        out.push((kind, &msg[at + 4..at + len]));
        at += align(len);
    }
    out
}

/// `rtnetlink_rcv_msg` for one request message `msg` (whole, at least a
/// header) from a process with (`admin`) or without `CAP_NET_ADMIN`.
pub fn request(host: &Host, msg: &[u8], admin: bool, portid: u32) -> Reply {
    let kind = u16::from_le_bytes([msg[4], msg[5]]);
    let flags = u16::from_le_bytes([msg[6], msg[7]]);
    let seq = u32::from_le_bytes(msg[8..12].try_into().unwrap());
    if kind > RTM_MAX {
        return Reply::Error(-EOPNOTSUPP);
    }
    // Every message has at least a struct rtgenmsg.
    if msg.len() < NLMSG_HDRLEN + 1 {
        return Reply::Ack;
    }
    let family = msg[NLMSG_HDRLEN];
    let get = (kind - RTM_BASE) & 3 == 2;
    if !get && !admin {
        return Reply::Error(-EPERM);
    }
    let dump = get && flags & NLM_F_DUMP != 0;
    let payload = msg.len() - NLMSG_HDRLEN;
    match (kind, dump) {
        (RTM_GETLINK, true) => Reply::Dump {
            messages: if family == AF_BRIDGE {
                Vec::new()
            } else {
                host.links
                    .iter()
                    .map(|l| link_message(l, NLM_F_MULTI, seq, portid))
                    .collect()
            },
            split_done: family != AF_BRIDGE,
        },
        (RTM_GETLINK, false) => {
            // rtnl_getlink: a struct ifinfomsg; the link by index, else by
            // IFLA_IFNAME.
            if payload < 16 {
                return Reply::Error(-EINVAL);
            }
            let index =
                i32::from_le_bytes(msg[NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8].try_into().unwrap());
            let name = attrs(msg, 16).into_iter().find_map(|(k, v)| {
                (k == IFLA_IFNAME).then(|| {
                    let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
                    String::from_utf8_lossy(&v[..end]).into_owned()
                })
            });
            let link = if index > 0 {
                host.links.iter().find(|l| l.index == index)
            } else if let Some(n) = name {
                host.links.iter().find(|l| l.name == n)
            } else {
                return Reply::Error(-EINVAL);
            };
            match link {
                Some(l) => Reply::Unicast(vec![link_message(l, 0, seq, portid)]),
                None => Reply::Error(-ENODEV),
            }
        }
        (RTM_GETADDR, true) => {
            let families: &[u8] = match family {
                AF_INET => &[AF_INET],
                AF_INET6 => &[AF_INET6],
                _ => &[AF_INET, AF_INET6],
            };
            let messages = families
                .iter()
                .flat_map(|&f| host.addresses.iter().filter(move |a| a.family == f))
                .map(|a| address_message(a, NLM_F_MULTI, seq, portid))
                .collect();
            Reply::Dump {
                messages,
                split_done: family != AF_INET6,
            }
        }
        (RTM_GETADDR, false) if family == AF_INET6 => getaddr6(host, msg, seq, portid),
        // A change the guest may make but not to the host, or a request
        // without a handler here.
        _ => Reply::Error(-EOPNOTSUPP),
    }
}

/// `inet6_rtm_getaddr`: a struct ifaddrmsg; the address `IFA_LOCAL` names,
/// else `IFA_ADDRESS` (16 bytes each, `-ERANGE` for fewer), on the link
/// `ifa_index` names if there is one.
fn getaddr6(host: &Host, msg: &[u8], seq: u32, portid: u32) -> Reply {
    if msg.len() - NLMSG_HDRLEN < 8 {
        return Reply::Error(-EINVAL);
    }
    let mut local = None;
    let mut address = None;
    for (k, v) in attrs(msg, 8) {
        let slot = match k {
            IFA_LOCAL => &mut local,
            IFA_ADDRESS => &mut address,
            _ => continue,
        };
        if v.len() < 16 {
            return Reply::Error(-ERANGE);
        }
        *slot = Some(&v[..16]);
    }
    let Some(want) = local.or(address) else {
        return Reply::Error(-EINVAL);
    };
    let index = u32::from_le_bytes(msg[NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8].try_into().unwrap());
    let link = (index != 0)
        .then(|| host.links.iter().find(|l| l.index as u32 == index))
        .flatten();
    let found = host.addresses.iter().find(|a| {
        a.family == AF_INET6 && a.local == want && link.is_none_or(|l| l.index == a.index)
    });
    match found {
        Some(a) => Reply::Unicast(vec![address_message(a, 0, seq, portid)]),
        None => Reply::Error(-EADDRNOTAVAIL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lo() -> Link {
        Link {
            index: 1,
            name: "lo".into(),
            kind: 772,
            flags: 0x49 | 0x10000,
            mtu: 65536,
            txqlen: 1000,
            operstate: IF_OPER_UNKNOWN,
            carrier: true,
            address: vec![0; 6],
            broadcast: vec![0; 6],
            stats: [0; 25],
        }
    }

    fn host() -> Host {
        Host {
            links: vec![lo()],
            addresses: vec![
                Address {
                    index: 1,
                    family: AF_INET,
                    prefixlen: 8,
                    flags: IFA_F_PERMANENT,
                    scope: RT_SCOPE_HOST,
                    local: vec![127, 0, 0, 1],
                    peer: None,
                    broadcast: None,
                    label: "lo".into(),
                },
                Address {
                    index: 1,
                    family: AF_INET6,
                    prefixlen: 128,
                    flags: IFA_F_PERMANENT,
                    scope: RT_SCOPE_HOST,
                    local: [0u8; 15].iter().copied().chain([1]).collect(),
                    peer: None,
                    broadcast: None,
                    label: String::new(),
                },
            ],
        }
    }

    fn req(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut m = start(kind, flags, 7, 0);
        m.extend_from_slice(payload);
        finish(m)
    }

    #[test]
    fn link_messages_follow_rtnl_fill_ifinfo() {
        let m = link_message(&lo(), NLM_F_MULTI, 7, 99);
        assert_eq!(
            u32::from_le_bytes(m[..4].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(u16::from_le_bytes([m[4], m[5]]), RTM_NEWLINK);
        assert_eq!(u16::from_le_bytes([m[6], m[7]]), NLM_F_MULTI);
        assert_eq!(u32::from_le_bytes(m[8..12].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(m[12..16].try_into().unwrap()), 99);
        // ifinfomsg: family, type, index, flags, change.
        assert_eq!(u16::from_le_bytes([m[18], m[19]]), 772);
        assert_eq!(i32::from_le_bytes(m[20..24].try_into().unwrap()), 1);
        let a = attrs(&m, 16);
        let kinds: Vec<u16> = a.iter().map(|x| x.0).collect();
        assert_eq!(
            kinds,
            [
                IFLA_IFNAME,
                IFLA_TXQLEN,
                IFLA_OPERSTATE,
                IFLA_LINKMODE,
                IFLA_MTU,
                IFLA_GROUP,
                IFLA_PROMISCUITY,
                IFLA_ALLMULTI,
                IFLA_NUM_TX_QUEUES,
                IFLA_NUM_RX_QUEUES,
                IFLA_CARRIER,
                IFLA_ADDRESS,
                IFLA_BROADCAST,
                IFLA_STATS64,
                IFLA_STATS
            ]
        );
        assert_eq!(a[0].1, b"lo\0");
        assert_eq!(a[13].1.len(), 200, "rtnl_link_stats64");
        assert_eq!(a[14].1.len(), 96, "rtnl_link_stats");
    }

    /// The messages of a dump, and whether it splits `NLMSG_DONE` off.
    fn dumped(r: Reply) -> (Vec<Vec<u8>>, bool) {
        match r {
            Reply::Dump {
                messages,
                split_done,
            } => (messages, split_done),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn dumps_follow_the_family_handlers() {
        let h = host();
        let dump = |kind, family| {
            dumped(request(
                &h,
                &req(kind, NLM_F_REQUEST | NLM_F_DUMP, &[family]),
                false,
                5,
            ))
        };
        // rtnl_dump_ifinfo, split; rtnl_bridge_getlink: no bridge ports.
        let (m, split) = dump(RTM_GETLINK, AF_UNSPEC);
        assert_eq!((m.len(), split), (1, true));
        assert_eq!(u16::from_le_bytes([m[0][6], m[0][7]]), NLM_F_MULTI);
        assert_eq!(dump(RTM_GETLINK, AF_INET6).0.len(), 1);
        assert_eq!(dump(RTM_GETLINK, AF_BRIDGE), (Vec::new(), false));
        // rtnl_dump_all walks IPv4, then IPv6; inet_dump_ifaddr splits
        // NLMSG_DONE off, inet6_dump_ifaddr does not.
        let (m, split) = dump(RTM_GETADDR, AF_UNSPEC);
        assert!(split);
        assert_eq!(
            m.iter().map(|x| x[16]).collect::<Vec<_>>(),
            [AF_INET, AF_INET6]
        );
        let (m, split) = dump(RTM_GETADDR, AF_INET);
        assert_eq!((m.len(), m[0][16], split), (1, AF_INET, true));
        let (m, split) = dump(RTM_GETADDR, AF_INET6);
        assert_eq!((m.len(), m[0][16], split), (1, AF_INET6, false));
        // A family without a handler falls back to rtnl_dump_all.
        assert_eq!(dump(RTM_GETADDR, 17).0.len(), 2);
    }

    #[test]
    fn requests_follow_rtnetlink_rcv_msg() {
        let h = host();
        // One link by index, a missing one, and by name.
        let mut ifi = [0u8; 16];
        ifi[4..8].copy_from_slice(&1i32.to_le_bytes());
        assert!(matches!(
            request(&h, &req(RTM_GETLINK, NLM_F_REQUEST, &ifi), false, 5),
            Reply::Unicast(m) if m.len() == 1 && m[0][6] == 0
        ));
        ifi[4..8].copy_from_slice(&9i32.to_le_bytes());
        assert_eq!(
            request(&h, &req(RTM_GETLINK, NLM_F_REQUEST, &ifi), false, 5),
            Reply::Error(-ENODEV)
        );
        let mut by_name = [0u8; 16].to_vec();
        put_str(&mut by_name, IFLA_IFNAME, "lo");
        assert!(matches!(
            request(&h, &req(RTM_GETLINK, NLM_F_REQUEST, &by_name), false, 5),
            Reply::Unicast(_)
        ));
        // Neither, and a short struct ifinfomsg.
        assert_eq!(
            request(&h, &req(RTM_GETLINK, NLM_F_REQUEST, &[0; 16]), false, 5),
            Reply::Error(-EINVAL)
        );
        assert_eq!(
            request(&h, &req(RTM_GETLINK, NLM_F_REQUEST, &[0; 8]), false, 5),
            Reply::Error(-EINVAL)
        );
        // Changes need CAP_NET_ADMIN, and are not made to the host.
        assert_eq!(
            request(&h, &req(RTM_NEWLINK, NLM_F_REQUEST, &[0; 16]), false, 5),
            Reply::Error(-EPERM)
        );
        assert_eq!(
            request(&h, &req(RTM_NEWLINK, NLM_F_REQUEST, &[0; 16]), true, 5),
            Reply::Error(-EOPNOTSUPP)
        );
        assert_eq!(
            request(&h, &req(RTM_MAX + 1, NLM_F_REQUEST, &[0]), false, 5),
            Reply::Error(-EOPNOTSUPP)
        );
        // Only IPv6 answers for one address.
        assert_eq!(
            request(
                &h,
                &req(RTM_GETADDR, NLM_F_REQUEST, &[AF_INET, 0, 0, 0, 0, 0, 0, 0]),
                false,
                5
            ),
            Reply::Error(-EOPNOTSUPP)
        );
        // No payload: nothing to do.
        assert_eq!(
            request(&h, &req(RTM_GETLINK, NLM_F_REQUEST, &[]), false, 5),
            Reply::Ack
        );
    }

    #[test]
    fn one_ipv6_address_follows_inet6_rtm_getaddr() {
        let mut h = host();
        h.links.push(Link {
            index: 2,
            name: "eth0".into(),
            ..lo()
        });
        let one = |index: u32, attr: u16, addr: &[u8]| {
            let mut p = vec![AF_INET6, 0, 0, 0];
            p.extend_from_slice(&index.to_le_bytes());
            put_attr(&mut p, attr, addr);
            request(&h, &req(RTM_GETADDR, NLM_F_REQUEST, &p), false, 5)
        };
        let lo6: Vec<u8> = [0u8; 15].iter().copied().chain([1]).collect();
        assert!(matches!(one(0, IFA_ADDRESS, &lo6), Reply::Unicast(m) if m[0][16] == AF_INET6));
        assert!(matches!(one(1, IFA_LOCAL, &lo6), Reply::Unicast(_)));
        // On another link; an unknown link names none (any matches).
        assert_eq!(one(2, IFA_LOCAL, &lo6), Reply::Error(-EADDRNOTAVAIL));
        assert!(matches!(one(9, IFA_LOCAL, &lo6), Reply::Unicast(_)));
        assert_eq!(one(0, IFA_LOCAL, &[0; 16]), Reply::Error(-EADDRNOTAVAIL));
        assert_eq!(one(0, IFA_LOCAL, &lo6[..4]), Reply::Error(-ERANGE));
        assert_eq!(one(0, IFA_LABEL, b"lo\0"), Reply::Error(-EINVAL));
    }

    #[test]
    fn acks_carry_the_request() {
        let r = req(RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, &[0; 16]);
        let ok = ack_message(&r, 0, false, 3);
        assert_eq!(u16::from_le_bytes([ok[6], ok[7]]), NLM_F_CAPPED);
        assert_eq!(ok.len(), NLMSG_HDRLEN + 4 + NLMSG_HDRLEN);
        let e = ack_message(&r, -ENODEV, false, 3);
        assert_eq!(u16::from_le_bytes([e[6], e[7]]), 0);
        assert_eq!(e.len(), NLMSG_HDRLEN + 4 + r.len());
        assert_eq!(i32::from_le_bytes(e[16..20].try_into().unwrap()), -ENODEV);
        let capped = ack_message(&r, -ENODEV, true, 3);
        assert_eq!(capped.len(), NLMSG_HDRLEN + 4 + NLMSG_HDRLEN);
        // The request's payload is padded (nlmsg_append); its header keeps
        // its own length.
        let odd = req(RTM_GETLINK, NLM_F_REQUEST, &[1, 2, 3, 4, 5]);
        let e = ack_message(&odd, -EINVAL, false, 3);
        assert_eq!(e.len(), NLMSG_HDRLEN + 4 + 24);
        assert_eq!(u32::from_le_bytes(e[..4].try_into().unwrap()), 44);
        assert_eq!(u32::from_le_bytes(e[20..24].try_into().unwrap()), 21);
        assert_eq!(&e[36..41], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn done_carries_the_result() {
        let d = done_message(9, 4, -EMSGSIZE);
        assert_eq!(d.len(), NLMSG_HDRLEN + 4);
        assert_eq!(u16::from_le_bytes([d[4], d[5]]), NLMSG_DONE);
        assert_eq!(u16::from_le_bytes([d[6], d[7]]), NLM_F_MULTI);
        assert_eq!(i32::from_le_bytes(d[16..20].try_into().unwrap()), -EMSGSIZE);
    }
}

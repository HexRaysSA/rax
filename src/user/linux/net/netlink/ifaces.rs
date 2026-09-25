//! The host's interfaces as rtnetlink describes them ([`route::Host`]):
//! on a macOS host from `getifaddrs` (each `AF_LINK` entry a link, each
//! `AF_INET` and `AF_INET6` entry an address) and the media status
//! (`SIOCGIFMEDIA`), translated as below.
//!
//! | Linux | From the host |
//! |---|---|
//! | index, name | `sdl_index`, `ifa_name` (the host's names, such as `lo0` and `en0`) |
//! | `ifi_type` | `sdl_type`: Ethernet-like (`IFT_ETHER`, `IFT_L2VLAN`, `IFT_IEEE8023ADLAG`, `IFT_BRIDGE`) is `ARPHRD_ETHER`, `IFT_LOOP` `ARPHRD_LOOPBACK`, `IFT_PPP` `ARPHRD_PPP`, `IFT_GIF` `ARPHRD_TUNNEL`, `IFT_STF` `ARPHRD_SIT`, others (`utun`) `ARPHRD_NONE` |
//! | carrier | the media's link status (`IFM_ACTIVE`), on where the host reports none |
//! | operational state | `IF_OPER_DOWN` while down; an Ethernet-like link `IF_OPER_UP` with carrier, else `IF_OPER_DOWN`; others `IF_OPER_UNKNOWN`, as links without carrier events are |
//! | `ifi_flags` | the flags BSD and Linux number alike, `IFF_MULTICAST` renumbered; `IFF_RUNNING` (`netif_oper_up`) and `IFF_LOWER_UP` (carrier) while up, as `dev_get_flags` reports them |
//! | MTU, counters | `struct if_data` (32-bit counters) |
//! | hardware address | the link-level address (broadcast all ones for Ethernet); a loopback's six zero bytes, as Linux's |
//! | IPv4 address | the prefix from the netmask; the peer (point-to-point) or broadcast address; scope host for 127/8 (`inet_set_ifa`) |
//! | IPv6 address | the prefix from the netmask; the interface index KAME embeds in a link-local address removed; scope host for `::1`, link for `fe80::/10`, site for `fec0::/10` |
//!
//! Addresses are `IFA_F_PERMANENT`. Links are in index order, as are the
//! addresses; a link's IPv6 addresses by scope, widest first
//! (`ipv6_link_dev_addr`). Other hosts report no interfaces.

use super::route::{self, Address, Host, Link};
use super::{AF_INET, AF_INET6};

/// `ARPHRD_*` (`linux/if_arp.h`).
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_PPP: u16 = 512;
pub const ARPHRD_TUNNEL: u16 = 768;
pub const ARPHRD_LOOPBACK: u16 = 772;
pub const ARPHRD_SIT: u16 = 776;
pub const ARPHRD_NONE: u16 = 0xFFFE;

/// Linux `IFF_*` (`linux/if.h`).
pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;
pub const IFF_LOWER_UP: u32 = 0x10000;
/// The flags BSD and Linux number alike: `IFF_UP`, `IFF_BROADCAST`,
/// `IFF_DEBUG`, `IFF_LOOPBACK`, `IFF_POINTOPOINT`, `IFF_NOTRAILERS`,
/// `IFF_NOARP`, `IFF_PROMISC`, `IFF_ALLMULTI`.
const SHARED_FLAGS: u32 = 0x3BF;
/// BSD `IFF_MULTICAST`.
const BSD_MULTICAST: u32 = 0x8000;

/// BSD `IFT_*` (`net/if_types.h`).
const IFT_ETHER: u8 = 0x06;
const IFT_PPP: u8 = 0x17;
const IFT_LOOP: u8 = 0x18;
const IFT_GIF: u8 = 0x37;
const IFT_STF: u8 = 0x39;
const IFT_L2VLAN: u8 = 0x87;
const IFT_IEEE8023ADLAG: u8 = 0x88;
const IFT_BRIDGE: u8 = 0xD1;

/// A link as the host reports it.
#[derive(Clone, Debug, Default)]
pub struct HostLink {
    pub index: i32,
    pub name: String,
    /// `IFT_*`.
    pub ift: u8,
    /// BSD `IFF_*`.
    pub flags: u32,
    pub mtu: u32,
    /// The link-level address.
    pub lladdr: Vec<u8>,
    /// The media's link status, where the host reports one.
    pub active: Option<bool>,
    /// The counters, in `rtnl_link_stats64` order.
    pub stats: [u64; 25],
}

/// An address as the host reports it.
#[derive(Clone, Debug, Default)]
pub struct HostAddress {
    /// The link's index and name.
    pub index: i32,
    pub name: String,
    /// The link's BSD flags.
    pub flags: u32,
    /// `AF_INET` or `AF_INET6` (Linux numbers).
    pub family: u8,
    pub addr: Vec<u8>,
    pub netmask: Vec<u8>,
    /// The peer (point-to-point) or broadcast address.
    pub dst: Option<Vec<u8>>,
}

/// The Linux link for host link `h`.
pub fn link(h: &HostLink) -> Link {
    let kind = match h.ift {
        IFT_ETHER | IFT_L2VLAN | IFT_IEEE8023ADLAG | IFT_BRIDGE => ARPHRD_ETHER,
        IFT_LOOP => ARPHRD_LOOPBACK,
        IFT_PPP => ARPHRD_PPP,
        IFT_GIF => ARPHRD_TUNNEL,
        IFT_STF => ARPHRD_SIT,
        _ => ARPHRD_NONE,
    };
    let up = h.flags & IFF_UP != 0;
    let carrier = h.active.unwrap_or(true);
    let operstate = if !up {
        route::IF_OPER_DOWN
    } else if kind != ARPHRD_ETHER {
        route::IF_OPER_UNKNOWN
    } else if carrier {
        route::IF_OPER_UP
    } else {
        route::IF_OPER_DOWN
    };
    let mut flags = h.flags & SHARED_FLAGS;
    if h.flags & BSD_MULTICAST != 0 {
        flags |= IFF_MULTICAST;
    }
    if up && operstate != route::IF_OPER_DOWN {
        flags |= IFF_RUNNING;
    }
    if up && carrier {
        flags |= IFF_LOWER_UP;
    }
    let (address, broadcast) = match kind {
        ARPHRD_LOOPBACK => (vec![0; 6], vec![0; 6]),
        ARPHRD_ETHER if h.lladdr.len() == 6 => (h.lladdr.clone(), vec![0xFF; 6]),
        _ => (h.lladdr.clone(), vec![0; h.lladdr.len()]),
    };
    Link {
        index: h.index,
        name: h.name.clone(),
        kind,
        flags,
        mtu: h.mtu,
        txqlen: 1000,
        operstate,
        carrier,
        address,
        broadcast,
        stats: h.stats,
    }
}

/// The length of the prefix netmask `m` covers (its leading ones).
fn prefix_len(m: &[u8]) -> u8 {
    let mut n = 0;
    for &b in m {
        n += b.leading_ones() as u8;
        if b != 0xFF {
            break;
        }
    }
    n
}

/// The Linux address for host address `h`.
pub fn address(h: &HostAddress) -> Address {
    let p2p = h.flags & IFF_POINTOPOINT != 0;
    let dst = h.dst.clone().filter(|d| d.iter().any(|&b| b != 0));
    let mut local = h.addr.clone();
    let scope = if h.family == AF_INET {
        if local[0] == 127 {
            route::RT_SCOPE_HOST
        } else {
            route::RT_SCOPE_UNIVERSE
        }
    } else {
        let link_local = |a: &mut Vec<u8>| {
            // KAME: the interface index in the second 16-bit word.
            if a[0] == 0xFE && a[1] & 0xC0 == 0x80 {
                a[2] = 0;
                a[3] = 0;
                true
            } else {
                false
            }
        };
        let loopback = local[..15].iter().all(|&b| b == 0) && local[15] == 1;
        if loopback {
            route::RT_SCOPE_HOST
        } else if link_local(&mut local) {
            route::RT_SCOPE_LINK
        } else if local[0] == 0xFE && local[1] & 0xC0 == 0xC0 {
            route::RT_SCOPE_SITE
        } else {
            route::RT_SCOPE_UNIVERSE
        }
    };
    let peer = dst.clone().filter(|_| p2p).map(|mut d| {
        if d.len() == 16 && d[0] == 0xFE && d[1] & 0xC0 == 0x80 {
            d[2] = 0;
            d[3] = 0;
        }
        d
    });
    let broadcast = dst.filter(|_| h.family == AF_INET && !p2p && h.flags & IFF_BROADCAST != 0);
    Address {
        index: h.index,
        family: h.family,
        prefixlen: prefix_len(&h.netmask),
        flags: route::IFA_F_PERMANENT,
        scope,
        local,
        peer,
        broadcast,
        label: if h.family == AF_INET {
            h.name.clone()
        } else {
            String::new()
        },
    }
}

/// rtnetlink's view of the host links `links` and addresses `addrs`, in
/// the kernel's order.
pub fn describe(links: &[HostLink], addrs: &[HostAddress]) -> Host {
    let mut links: Vec<Link> = links.iter().map(link).collect();
    links.sort_by_key(|l| l.index);
    let mut addresses: Vec<Address> = addrs.iter().map(address).collect();
    // By link; a link's IPv6 addresses widest scope first (the sort is
    // stable, so the host's order stays within a scope).
    addresses.sort_by_key(|a| (a.index, if a.family == AF_INET6 { a.scope } else { 0 }));
    Host { links, addresses }
}

/// The host's interfaces now.
pub fn snapshot() -> Host {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let (links, addrs) = apple::enumerate();
        describe(&links, &addrs)
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        Host::default()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use super::*;

    /// `struct ifmediareq` (`net/if_media.h`).
    #[repr(C)]
    struct IfMediaReq {
        name: [u8; 16],
        current: i32,
        mask: i32,
        status: i32,
        active: i32,
        count: i32,
        ulist: *mut i32,
    }

    /// `SIOCGIFMEDIA`: `_IOWR('i', 56, struct ifmediareq)`.
    const SIOCGIFMEDIA: libc::c_ulong = 0xC000_0000
        | ((std::mem::size_of::<IfMediaReq>() as libc::c_ulong & 0x1FFF) << 16)
        | ((b'i' as libc::c_ulong) << 8)
        | 56;
    /// `IFM_AVALID`, `IFM_ACTIVE`.
    const IFM_AVALID: i32 = 0x1;
    const IFM_ACTIVE: i32 = 0x2;

    /// The media's link status of interface `name`, where it has media.
    fn media_active(sock: libc::c_int, name: &str) -> Option<bool> {
        if name.len() >= 16 {
            return None;
        }
        let mut req = IfMediaReq {
            name: [0; 16],
            current: 0,
            mask: 0,
            status: 0,
            active: 0,
            count: 0,
            ulist: std::ptr::null_mut(),
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: `req` is a valid struct ifmediareq that outlives the
        // call; with no list (count 0, null) the host writes only into it.
        let r = unsafe { libc::ioctl(sock, SIOCGIFMEDIA, &mut req) };
        (r == 0 && req.status & IFM_AVALID != 0).then_some(req.status & IFM_ACTIVE != 0)
    }

    /// The bytes of the socket address at `sa` (`sa_len` of them).
    ///
    /// # Safety
    ///
    /// `sa` is null or points to a socket address `getifaddrs` returned,
    /// valid for its `sa_len` bytes.
    unsafe fn sockaddr_bytes<'a>(sa: *const libc::sockaddr) -> Option<&'a [u8]> {
        if sa.is_null() {
            return None;
        }
        // SAFETY: the caller's contract.
        unsafe {
            let len = usize::from((*sa).sa_len).max(2);
            Some(std::slice::from_raw_parts(sa.cast::<u8>(), len))
        }
    }

    /// The IPv4 or IPv6 address in socket address bytes `b` of `family`.
    fn ip(b: Option<&[u8]>, family: i32) -> Option<Vec<u8>> {
        let b = b?;
        match family {
            libc::AF_INET if b.len() >= 8 => Some(b[4..8].to_vec()),
            libc::AF_INET6 if b.len() >= 24 => Some(b[8..24].to_vec()),
            _ => None,
        }
    }

    /// The host's links and addresses.
    pub fn enumerate() -> (Vec<HostLink>, Vec<HostAddress>) {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs fills `head` with a list freed below.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return (Vec::new(), Vec::new());
        }
        // SAFETY: a datagram socket for the media requests, closed below.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let mut links = Vec::new();
        let mut addrs = Vec::new();
        let mut p = head;
        while !p.is_null() {
            // SAFETY: `p` is an entry of the list getifaddrs returned,
            // which stays valid until freeifaddrs; its name is a C string
            // and its addresses are socket addresses of their sa_len.
            let e = unsafe { &*p };
            p = e.ifa_next;
            let name = unsafe { std::ffi::CStr::from_ptr(e.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let Some(sa) = (unsafe { sockaddr_bytes(e.ifa_addr) }) else {
                continue;
            };
            match i32::from(sa[1]) {
                libc::AF_LINK if sa.len() >= 8 => {
                    // struct sockaddr_dl: index, type, name, address
                    // lengths, then the name and address bytes.
                    let index = i32::from(u16::from_ne_bytes([sa[2], sa[3]]));
                    let (nlen, alen) = (usize::from(sa[5]), usize::from(sa[6]));
                    let lladdr = sa.get(8 + nlen..8 + nlen + alen).unwrap_or(&[]).to_vec();
                    let mut l = HostLink {
                        index,
                        name: name.clone(),
                        ift: sa[4],
                        flags: e.ifa_flags,
                        lladdr,
                        active: if sock >= 0 {
                            media_active(sock, &name)
                        } else {
                            None
                        },
                        ..HostLink::default()
                    };
                    if !e.ifa_data.is_null() {
                        // SAFETY: an AF_LINK entry's data is its struct
                        // if_data.
                        let d: libc::if_data =
                            unsafe { std::ptr::read_unaligned(e.ifa_data.cast()) };
                        l.mtu = d.ifi_mtu;
                        let s = &mut l.stats;
                        s[0] = u64::from(d.ifi_ipackets);
                        s[1] = u64::from(d.ifi_opackets);
                        s[2] = u64::from(d.ifi_ibytes);
                        s[3] = u64::from(d.ifi_obytes);
                        s[4] = u64::from(d.ifi_ierrors);
                        s[5] = u64::from(d.ifi_oerrors);
                        s[6] = u64::from(d.ifi_iqdrops);
                        s[8] = u64::from(d.ifi_imcasts);
                        s[9] = u64::from(d.ifi_collisions);
                        s[23] = u64::from(d.ifi_noproto);
                    }
                    links.push(l);
                }
                family @ (libc::AF_INET | libc::AF_INET6) => {
                    let Some(addr) = ip(Some(sa), family) else {
                        continue;
                    };
                    let mask = unsafe { sockaddr_bytes(e.ifa_netmask) };
                    let width = addr.len();
                    // A netmask's sa_len may cover only its nonzero bytes.
                    let mut netmask = mask
                        .map(|m| {
                            let off = if family == libc::AF_INET { 4 } else { 8 };
                            m.get(off..).unwrap_or(&[]).to_vec()
                        })
                        .unwrap_or_default();
                    netmask.resize(width, 0);
                    let dst = ip(unsafe { sockaddr_bytes(e.ifa_dstaddr) }, family);
                    addrs.push(HostAddress {
                        index: 0,
                        name,
                        flags: e.ifa_flags,
                        family: if family == libc::AF_INET {
                            AF_INET
                        } else {
                            AF_INET6
                        },
                        addr,
                        netmask,
                        dst,
                    });
                }
                _ => {}
            }
        }
        // SAFETY: the list getifaddrs returned, freed once; the socket
        // opened above.
        unsafe {
            libc::freeifaddrs(head);
            if sock >= 0 {
                libc::close(sock);
            }
        }
        for a in &mut addrs {
            a.index = links
                .iter()
                .find(|l| l.name == a.name)
                .map_or(0, |l| l.index);
        }
        addrs.retain(|a| a.index != 0);
        (links, addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lo0() -> HostLink {
        HostLink {
            index: 1,
            name: "lo0".into(),
            ift: IFT_LOOP,
            // UP, LOOPBACK, RUNNING, MULTICAST.
            flags: 0x8049,
            mtu: 16384,
            ..HostLink::default()
        }
    }

    #[test]
    fn links_follow_dev_get_flags() {
        let l = link(&lo0());
        assert_eq!(l.kind, ARPHRD_LOOPBACK);
        assert_eq!(
            l.flags,
            IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_MULTICAST | IFF_LOWER_UP
        );
        assert_eq!(l.operstate, route::IF_OPER_UNKNOWN);
        assert_eq!((l.address.len(), l.broadcast.len()), (6, 6));
        // An Ethernet link without carrier: up, not running.
        let en = HostLink {
            index: 4,
            name: "en0".into(),
            ift: IFT_ETHER,
            // UP, BROADCAST, SMART, RUNNING, SIMPLEX, MULTICAST.
            flags: 0x8863,
            lladdr: vec![2, 0, 0, 0, 0, 1],
            active: Some(false),
            ..HostLink::default()
        };
        let l = link(&en);
        assert_eq!(l.kind, ARPHRD_ETHER);
        assert_eq!(l.flags, IFF_UP | IFF_BROADCAST | 0x20 | IFF_MULTICAST);
        assert_eq!(l.operstate, route::IF_OPER_DOWN);
        assert_eq!(l.broadcast, [0xFF; 6]);
        let l = link(&HostLink {
            active: Some(true),
            ..en.clone()
        });
        assert_eq!(l.operstate, route::IF_OPER_UP);
        assert_eq!(
            l.flags & (IFF_RUNNING | IFF_LOWER_UP),
            IFF_RUNNING | IFF_LOWER_UP
        );
        // Down: neither running nor lower-up, whatever the media says.
        let l = link(&HostLink {
            flags: 0x8862,
            active: Some(true),
            ..en
        });
        assert_eq!(l.flags & (IFF_UP | IFF_RUNNING | IFF_LOWER_UP), 0);
        assert_eq!(l.operstate, route::IF_OPER_DOWN);
        // A tunnel without a link-level address.
        let l = link(&HostLink {
            index: 9,
            name: "utun0".into(),
            ift: 0xFF,
            flags: 0x8051,
            ..HostLink::default()
        });
        assert_eq!(l.kind, ARPHRD_NONE);
        assert!(l.address.is_empty());
        assert_eq!(l.operstate, route::IF_OPER_UNKNOWN);
    }

    #[test]
    fn addresses_follow_linux_scopes() {
        let v4 = address(&HostAddress {
            index: 1,
            name: "lo0".into(),
            flags: 0x8049,
            family: AF_INET,
            addr: vec![127, 0, 0, 1],
            netmask: vec![255, 0, 0, 0],
            dst: Some(vec![127, 0, 0, 1]),
        });
        assert_eq!((v4.prefixlen, v4.scope), (8, route::RT_SCOPE_HOST));
        assert_eq!(v4.label, "lo0");
        // Not point-to-point, not broadcast: neither peer nor broadcast.
        assert_eq!((v4.peer, v4.broadcast), (None, None));
        let en = address(&HostAddress {
            index: 4,
            name: "en0".into(),
            flags: 0x8863,
            family: AF_INET,
            addr: vec![192, 168, 1, 20],
            netmask: vec![255, 255, 255, 0],
            dst: Some(vec![192, 168, 1, 255]),
        });
        assert_eq!((en.prefixlen, en.scope), (24, route::RT_SCOPE_UNIVERSE));
        assert_eq!(en.broadcast, Some(vec![192, 168, 1, 255]));
        // KAME's embedded index goes; the scope is the link's.
        let mut ll = vec![0xFE, 0x80, 0, 4];
        ll.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let v6 = address(&HostAddress {
            index: 4,
            name: "en0".into(),
            flags: 0x8863,
            family: AF_INET6,
            addr: ll,
            netmask: [vec![0xFF; 8], vec![0; 8]].concat(),
            dst: None,
        });
        assert_eq!(&v6.local[..4], &[0xFE, 0x80, 0, 0]);
        assert_eq!((v6.prefixlen, v6.scope), (64, route::RT_SCOPE_LINK));
        assert!(v6.label.is_empty());
        // A point-to-point link's peer.
        let p2p = address(&HostAddress {
            index: 9,
            name: "utun0".into(),
            flags: 0x8051,
            family: AF_INET,
            addr: vec![10, 0, 0, 2],
            netmask: vec![255, 255, 255, 255],
            dst: Some(vec![10, 0, 0, 1]),
        });
        assert_eq!((p2p.peer, p2p.prefixlen), (Some(vec![10, 0, 0, 1]), 32));
    }

    #[test]
    fn descriptions_follow_the_kernel_order() {
        let a = |index: i32, family: u8, addr: Vec<u8>| HostAddress {
            index,
            name: String::new(),
            flags: 0x8863,
            family,
            netmask: vec![0xFF; addr.len()],
            addr,
            dst: None,
        };
        let ll = [vec![0xFE, 0x80], vec![0; 13], vec![1]].concat();
        let global = [vec![0x20, 0x01, 0x0D, 0xB8], vec![0; 11], vec![1]].concat();
        let h = describe(
            &[
                HostLink {
                    index: 4,
                    ..HostLink::default()
                },
                lo0(),
            ],
            &[
                a(4, AF_INET6, ll),
                a(4, AF_INET6, global),
                a(1, AF_INET, vec![127, 0, 0, 1]),
            ],
        );
        assert_eq!(h.links.iter().map(|l| l.index).collect::<Vec<_>>(), [1, 4]);
        let scopes: Vec<(i32, u8)> = h.addresses.iter().map(|x| (x.index, x.scope)).collect();
        assert_eq!(
            scopes,
            [
                (1, route::RT_SCOPE_HOST),
                (4, route::RT_SCOPE_UNIVERSE),
                (4, route::RT_SCOPE_LINK)
            ]
        );
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn the_host_has_a_loopback() {
        let h = snapshot();
        let lo = h
            .links
            .iter()
            .find(|l| l.kind == ARPHRD_LOOPBACK)
            .expect("a loopback link");
        assert!(lo.flags & IFF_LOOPBACK != 0);
        assert!(
            h.addresses
                .iter()
                .any(|a| a.index == lo.index && a.local == [127, 0, 0, 1] && a.prefixlen == 8)
        );
    }
}

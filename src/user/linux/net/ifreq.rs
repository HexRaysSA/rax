//! Interface requests (`linux/sockios.h`): `SIOCGIFCONF` (`dev_ifconf`,
//! `inet_gifconf`), the device requests of `dev_ioctl`, the IPv4 address
//! requests of `devinet_ioctl`, and IPv6's address changes
//! (`addrconf_add_ifaddr` and its kin), answered from rtnetlink's view of
//! the host ([`Host`]).
//!
//! A socket's family routes a request as `sock_ioctl` does: `SIOCGIFCONF`
//! is the socket layer's; an IPv4 socket's `inet_ioctl` takes the address
//! requests; an IPv6 socket's `inet6_ioctl` takes `SIOCSIFADDR`,
//! `SIOCDIFADDR`, and `SIOCSIFDSTADDR` (a `struct in6_ifreq`); every other
//! request reaches `dev_ioctl`, which answers the device requests and
//! knows no other (`ENOTTY`). `dev_ioctl` and `devinet_ioctl` end the name
//! at 15 bytes, look a device up without an alias's `:` suffix (`ENODEV`),
//! and copy the whole `struct ifreq` back, the name's last byte cleared and
//! the `:` restored; bytes a request does not write keep the caller's
//! values. Changes need `CAP_NET_ADMIN` (`EPERM`) and are not made to the
//! host (`EOPNOTSUPP`), nor are the requests that reach a driver
//! (`SIOCETHTOOL`, the MII, bonding, time-stamping, and private requests).

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::lx;
use super::netlink::route::{Address, Host, Link};
use super::netlink::{AF_INET, AF_INET6};

/// `sizeof(struct ifreq)`: a 16-byte name and a 24-byte union.
pub const IFREQ: usize = 40;
/// `IFNAMSIZ`.
const IFNAMSIZ: usize = 16;
/// `sizeof(struct ifconf)`: `ifc_len`, padding, `ifc_buf`.
pub const IFCONF: usize = 16;
/// `sizeof(struct in6_ifreq)`: address, prefix length, index.
pub const IN6_IFREQ: usize = 24;

// linux/sockios.h
pub const SIOCGIFNAME: u32 = 0x8910;
pub const SIOCSIFLINK: u32 = 0x8911;
pub const SIOCGIFCONF: u32 = 0x8912;
pub const SIOCGIFFLAGS: u32 = 0x8913;
pub const SIOCSIFFLAGS: u32 = 0x8914;
pub const SIOCGIFADDR: u32 = 0x8915;
pub const SIOCSIFADDR: u32 = 0x8916;
pub const SIOCGIFDSTADDR: u32 = 0x8917;
pub const SIOCSIFDSTADDR: u32 = 0x8918;
pub const SIOCGIFBRDADDR: u32 = 0x8919;
pub const SIOCSIFBRDADDR: u32 = 0x891A;
pub const SIOCGIFNETMASK: u32 = 0x891B;
pub const SIOCSIFNETMASK: u32 = 0x891C;
pub const SIOCGIFMETRIC: u32 = 0x891D;
pub const SIOCSIFMETRIC: u32 = 0x891E;
pub const SIOCGIFMEM: u32 = 0x891F;
pub const SIOCSIFMEM: u32 = 0x8920;
pub const SIOCGIFMTU: u32 = 0x8921;
pub const SIOCSIFMTU: u32 = 0x8922;
pub const SIOCSIFNAME: u32 = 0x8923;
pub const SIOCSIFHWADDR: u32 = 0x8924;
pub const SIOCGIFHWADDR: u32 = 0x8927;
pub const SIOCGIFSLAVE: u32 = 0x8929;
pub const SIOCSIFSLAVE: u32 = 0x8930;
pub const SIOCADDMULTI: u32 = 0x8931;
pub const SIOCDELMULTI: u32 = 0x8932;
pub const SIOCGIFINDEX: u32 = 0x8933;
pub const SIOCSIFPFLAGS: u32 = 0x8934;
pub const SIOCGIFPFLAGS: u32 = 0x8935;
pub const SIOCDIFADDR: u32 = 0x8936;
pub const SIOCSIFHWBROADCAST: u32 = 0x8937;
pub const SIOCGIFTXQLEN: u32 = 0x8942;
pub const SIOCSIFTXQLEN: u32 = 0x8943;
pub const SIOCETHTOOL: u32 = 0x8946;
pub const SIOCGMIIPHY: u32 = 0x8947;
pub const SIOCGMIIREG: u32 = 0x8948;
pub const SIOCSMIIREG: u32 = 0x8949;
pub const SIOCWANDEV: u32 = 0x894A;
pub const SIOCGIFMAP: u32 = 0x8970;
pub const SIOCSIFMAP: u32 = 0x8971;
pub const SIOCBONDENSLAVE: u32 = 0x8990;
pub const SIOCBONDRELEASE: u32 = 0x8991;
pub const SIOCBONDSETHWADDR: u32 = 0x8992;
pub const SIOCBONDSLAVEINFOQUERY: u32 = 0x8993;
pub const SIOCBONDINFOQUERY: u32 = 0x8994;
pub const SIOCBONDCHANGEACTIVE: u32 = 0x8995;
pub const SIOCSHWTSTAMP: u32 = 0x89B0;
pub const SIOCGHWTSTAMP: u32 = 0x89B1;
pub const SIOCDEVPRIVATE: u32 = 0x89F0;

/// `ARPHRD_SIT`.
const ARPHRD_SIT: u16 = 776;

/// How a request of the socket-type range travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// `SIOCGIFCONF`: a `struct ifconf` naming a buffer.
    Conf,
    /// A `struct ifreq`, copied back when `answer` is set.
    Ifreq { answer: bool },
    /// A `struct in6_ifreq` (an IPv6 socket's address changes).
    In6,
    /// A `struct ifreq` whose `ifr_data` points to more data.
    Indirect,
    /// Not an interface request.
    Other,
}

/// The shape of request `req` on a socket of Linux family `family`.
pub fn shape(family: i32, req: u32) -> Shape {
    match req {
        SIOCGIFCONF => Shape::Conf,
        SIOCSIFADDR | SIOCDIFADDR | SIOCSIFDSTADDR if family == lx::AF_INET6 => Shape::In6,
        SIOCGIFNAME
        | SIOCGIFFLAGS
        | SIOCGIFADDR
        | SIOCGIFDSTADDR
        | SIOCGIFBRDADDR
        | SIOCGIFNETMASK
        | SIOCGIFMETRIC
        | SIOCGIFMTU
        | SIOCGIFHWADDR
        | SIOCGIFSLAVE
        | SIOCGIFINDEX
        | SIOCGIFPFLAGS
        | SIOCGIFTXQLEN
        | SIOCGIFMAP
        | SIOCGMIIPHY
        | SIOCGMIIREG
        | SIOCSIFNAME
        | SIOCBONDSLAVEINFOQUERY
        | SIOCBONDINFOQUERY => Shape::Ifreq { answer: true },
        SIOCSIFLINK | SIOCSIFFLAGS | SIOCSIFADDR | SIOCSIFDSTADDR | SIOCSIFBRDADDR
        | SIOCSIFNETMASK | SIOCSIFMETRIC | SIOCGIFMEM | SIOCSIFMEM | SIOCSIFMTU | SIOCSIFHWADDR
        | SIOCSIFSLAVE | SIOCADDMULTI | SIOCDELMULTI | SIOCSIFPFLAGS | SIOCDIFADDR
        | SIOCSIFHWBROADCAST | SIOCSIFTXQLEN | SIOCSMIIREG | SIOCSIFMAP | SIOCBONDENSLAVE
        | SIOCBONDRELEASE | SIOCBONDSETHWADDR | SIOCBONDCHANGEACTIVE => {
            Shape::Ifreq { answer: false }
        }
        SIOCETHTOOL | SIOCWANDEV | SIOCSHWTSTAMP | SIOCGHWTSTAMP => Shape::Indirect,
        r if (SIOCDEVPRIVATE..=SIOCDEVPRIVATE + 15).contains(&r) => Shape::Indirect,
        _ => Shape::Other,
    }
}

/// The device name of `ifr` as `dev_ioctl` looks it up: at most 15 bytes
/// (the 16th cleared in `ifr`), cut at a `:`; and where the `:` was.
fn device_name(ifr: &mut [u8; IFREQ]) -> (Vec<u8>, Option<usize>) {
    ifr[IFNAMSIZ - 1] = 0;
    let end = ifr[..IFNAMSIZ].iter().position(|&b| b == 0).unwrap();
    let colon = ifr[..end].iter().position(|&b| b == b':');
    (ifr[..colon.unwrap_or(end)].to_vec(), colon)
}

fn link_named<'a>(host: &'a Host, name: &[u8]) -> Option<&'a Link> {
    host.links.iter().find(|l| l.name.as_bytes() == name)
}

fn put_i32(ifr: &mut [u8; IFREQ], v: i32) {
    ifr[16..20].copy_from_slice(&v.to_le_bytes());
}

/// An IPv4 prefix's mask, in network order.
fn mask(prefixlen: u8) -> [u8; 4] {
    let m = if prefixlen == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefixlen.min(32)))
    };
    m.to_be_bytes()
}

/// The kernel's answer to request `req` with `struct ifreq` bytes `ifr` on
/// a socket of Linux family `family` (not `SIOCGIFCONF`), for a caller with
/// (`admin`) or without `CAP_NET_ADMIN`: whether `ifr` now holds bytes to
/// copy back.
pub fn answer(
    host: &Host,
    family: i32,
    req: u32,
    ifr: &mut [u8; IFREQ],
    admin: bool,
) -> Result<bool, Errno> {
    let inet = matches!(
        req,
        SIOCGIFADDR
            | SIOCGIFBRDADDR
            | SIOCGIFNETMASK
            | SIOCGIFDSTADDR
            | SIOCGIFPFLAGS
            | SIOCSIFADDR
            | SIOCSIFBRDADDR
            | SIOCSIFNETMASK
            | SIOCSIFDSTADDR
            | SIOCSIFPFLAGS
            | SIOCSIFFLAGS
    );
    if family == lx::AF_INET && inet {
        return devinet(host, req, ifr, admin);
    }
    dev_ioctl(host, req, ifr, admin)
}

/// `dev_ioctl`.
fn dev_ioctl(host: &Host, req: u32, ifr: &mut [u8; IFREQ], admin: bool) -> Result<bool, Errno> {
    if req == SIOCGIFNAME {
        // dev_ifname: the name of the device by index (strscpy: no
        // padding after the NUL).
        ifr[IFNAMSIZ - 1] = 0;
        let index = i32::from_le_bytes(ifr[16..20].try_into().unwrap());
        let l = host
            .links
            .iter()
            .find(|l| l.index == index)
            .ok_or(Errno(ENODEV))?;
        let n = l.name.as_bytes();
        let n = &n[..n.len().min(IFNAMSIZ - 1)];
        ifr[..n.len()].copy_from_slice(n);
        ifr[n.len()] = 0;
        return Ok(true);
    }
    let (name, colon) = device_name(ifr);
    let restore = |ifr: &mut [u8; IFREQ]| {
        if let Some(at) = colon {
            ifr[at] = b':';
        }
    };
    let find = || link_named(host, &name).ok_or(Errno(ENODEV));
    match req {
        SIOCGIFHWADDR => {
            // netif_get_mac_address: sa_family is the link type; sa_data
            // the address (bytes past it untouched), or zeros.
            let l = find()?;
            if l.address.is_empty() {
                ifr[18..32].fill(0);
            } else {
                let n = l.address.len().min(14);
                ifr[18..18 + n].copy_from_slice(&l.address[..n]);
            }
            ifr[16..18].copy_from_slice(&l.kind.to_le_bytes());
            restore(ifr);
            Ok(true)
        }
        SIOCGIFFLAGS | SIOCGIFMETRIC | SIOCGIFMTU | SIOCGIFSLAVE | SIOCGIFMAP | SIOCGIFINDEX
        | SIOCGIFTXQLEN => {
            // dev_ifsioc_locked.
            let l = find()?;
            match req {
                SIOCGIFFLAGS => ifr[16..18].copy_from_slice(&(l.flags as u16).to_le_bytes()),
                SIOCGIFMETRIC => put_i32(ifr, 0),
                SIOCGIFMTU => put_i32(ifr, l.mtu as i32),
                SIOCGIFSLAVE => return Err(Errno(EINVAL)),
                SIOCGIFMAP => {
                    // dev_getifmap: every field 0 (the padding is not
                    // written).
                    ifr[16..37].fill(0);
                }
                SIOCGIFINDEX => put_i32(ifr, l.index),
                _ => put_i32(ifr, l.txqlen as i32),
            }
            restore(ifr);
            Ok(true)
        }
        SIOCETHTOOL => {
            // dev_ethtool: the device, then its operations.
            find()?;
            Err(Errno(EOPNOTSUPP))
        }
        SIOCGMIIPHY | SIOCGMIIREG | SIOCSIFNAME => {
            if !admin {
                return Err(Errno(EPERM));
            }
            find()?;
            Err(Errno(EOPNOTSUPP))
        }
        SIOCSIFMAP | SIOCSIFTXQLEN | SIOCSIFFLAGS | SIOCSIFMETRIC | SIOCSIFMTU | SIOCSIFHWADDR
        | SIOCSIFSLAVE | SIOCADDMULTI | SIOCDELMULTI | SIOCSIFHWBROADCAST | SIOCSMIIREG
        | SIOCBONDENSLAVE | SIOCBONDRELEASE | SIOCBONDSETHWADDR | SIOCBONDCHANGEACTIVE
        | SIOCSHWTSTAMP => {
            if !admin {
                return Err(Errno(EPERM));
            }
            find()?;
            Err(Errno(EOPNOTSUPP))
        }
        SIOCBONDSLAVEINFOQUERY | SIOCBONDINFOQUERY => {
            find()?;
            Err(Errno(EOPNOTSUPP))
        }
        SIOCGIFMEM | SIOCSIFMEM | SIOCSIFLINK => Err(Errno(ENOTTY)),
        r if r == SIOCWANDEV
            || r == SIOCGHWTSTAMP
            || (SIOCDEVPRIVATE..=SIOCDEVPRIVATE + 15).contains(&r) =>
        {
            find()?;
            Err(Errno(EOPNOTSUPP))
        }
        _ => Err(Errno(ENOTTY)),
    }
}

/// `devinet_ioctl`: an IPv4 address of the device by its label (and, for
/// the requests that read one, first by the address given, 4.4BSD style).
fn devinet(host: &Host, req: u32, ifr: &mut [u8; IFREQ], admin: bool) -> Result<bool, Errno> {
    let (name, colon) = device_name(ifr);
    let given = (u16::from_le_bytes([ifr[16], ifr[17]]) == u16::from(AF_INET))
        .then(|| [ifr[20], ifr[21], ifr[22], ifr[23]]);
    let get = matches!(
        req,
        SIOCGIFADDR | SIOCGIFBRDADDR | SIOCGIFDSTADDR | SIOCGIFNETMASK
    );
    match req {
        _ if get => {
            ifr[16..32].fill(0);
            ifr[16..18].copy_from_slice(&u16::from(AF_INET).to_le_bytes());
        }
        SIOCSIFFLAGS if !admin => return Err(Errno(EPERM)),
        SIOCSIFFLAGS => {}
        SIOCSIFADDR | SIOCSIFBRDADDR | SIOCSIFDSTADDR | SIOCSIFNETMASK => {
            if !admin {
                return Err(Errno(EPERM));
            }
            if given.is_none() {
                return Err(Errno(EINVAL));
            }
        }
        _ => return Err(Errno(EINVAL)),
    }
    let l = link_named(host, &name).ok_or(Errno(ENODEV))?;
    if let Some(at) = colon {
        ifr[at] = b':';
    }
    let label_end = ifr[..IFNAMSIZ].iter().position(|&b| b == 0).unwrap();
    let label = &ifr[..label_end];
    let mine =
        |a: &&Address| a.index == l.index && a.family == AF_INET && a.label.as_bytes() == label;
    let v4 = || host.addresses.iter().filter(mine);
    let ifa = given
        .filter(|_| get)
        .and_then(|g| v4().find(|a| a.local == g))
        .or_else(|| v4().next());
    let Some(a) = ifa else {
        // SIOCSIFADDR adds an address, SIOCSIFFLAGS changes the device (an
        // alias's flags need its address).
        let adds = req == SIOCSIFADDR || (req == SIOCSIFFLAGS && colon.is_none());
        return Err(Errno(if adds { EOPNOTSUPP } else { EADDRNOTAVAIL }));
    };
    if !get {
        return Err(Errno(EOPNOTSUPP));
    }
    let v: [u8; 4] = match req {
        SIOCGIFADDR => a.local[..4].try_into().unwrap(),
        SIOCGIFBRDADDR => a
            .broadcast
            .as_deref()
            .map_or([0; 4], |b| b[..4].try_into().unwrap()),
        SIOCGIFDSTADDR => a.peer.as_deref().unwrap_or(&a.local)[..4]
            .try_into()
            .unwrap(),
        _ => mask(a.prefixlen),
    };
    ifr[20..24].copy_from_slice(&v);
    Ok(true)
}

/// `inet6_ioctl`'s address changes with `struct in6_ifreq` bytes `ireq`,
/// read after the privilege check of `SIOCSIFADDR` and `SIOCDIFADDR`
/// ([`in6_needs_admin`]).
pub fn in6(host: &Host, req: u32, ireq: &[u8; IN6_IFREQ]) -> Errno {
    if req == SIOCSIFDSTADDR {
        // addrconf_set_dstaddr: only a SIT tunnel has one.
        let index = i32::from_le_bytes(ireq[20..24].try_into().unwrap());
        return match host.links.iter().find(|l| l.index == index) {
            Some(l) if l.kind == ARPHRD_SIT => Errno(EOPNOTSUPP),
            _ => Errno(ENODEV),
        };
    }
    Errno(EOPNOTSUPP)
}

/// Whether IPv6 request `req` is refused without `CAP_NET_ADMIN` before its
/// argument is read.
pub fn in6_needs_admin(req: u32) -> bool {
    matches!(req, SIOCSIFADDR | SIOCDIFADDR)
}

/// `dev_ifconf`: the `struct ifreq` of each IPv4 address (its label and
/// address), device by device, as many whole ones as fit `room` bytes
/// (every one, when there is no buffer), and the length they take.
pub fn ifconf(host: &Host, room: Option<i32>) -> (Vec<u8>, i32) {
    let mut out = Vec::new();
    let mut total = 0i32;
    for l in &host.links {
        for a in host
            .addresses
            .iter()
            .filter(|a| a.index == l.index && a.family == AF_INET)
        {
            let Some(len) = room else {
                total += IFREQ as i32;
                continue;
            };
            // inet_gifconf: a device's addresses stop at the first that
            // does not fit.
            if len - total < IFREQ as i32 {
                break;
            }
            let mut ifr = [0u8; IFREQ];
            let label = a.label.as_bytes();
            let n = label.len().min(IFNAMSIZ - 1);
            ifr[..n].copy_from_slice(&label[..n]);
            ifr[16..18].copy_from_slice(&u16::from(AF_INET).to_le_bytes());
            ifr[20..24].copy_from_slice(&a.local[..4]);
            out.extend_from_slice(&ifr);
            total += IFREQ as i32;
        }
    }
    (out, total)
}

#[cfg(test)]
mod tests {
    use super::super::netlink::route::{self, RT_SCOPE_HOST, RT_SCOPE_UNIVERSE};
    use super::*;

    fn host() -> Host {
        let link = |index: i32, name: &str, kind: u16, address: Vec<u8>| Link {
            index,
            name: name.into(),
            kind,
            flags: 0x1_1043,
            mtu: 1500,
            txqlen: 1000,
            operstate: route::IF_OPER_UP,
            carrier: true,
            address,
            broadcast: Vec::new(),
            stats: [0; 25],
        };
        let v4 =
            |index: i32, label: &str, local: [u8; 4], prefixlen: u8, bcast: Option<[u8; 4]>| {
                Address {
                    index,
                    family: AF_INET,
                    prefixlen,
                    flags: route::IFA_F_PERMANENT,
                    scope: if local[0] == 127 {
                        RT_SCOPE_HOST
                    } else {
                        RT_SCOPE_UNIVERSE
                    },
                    local: local.to_vec(),
                    peer: None,
                    broadcast: bcast.map(|b| b.to_vec()),
                    label: label.into(),
                }
            };
        Host {
            links: vec![
                link(1, "lo", 772, vec![0; 6]),
                link(2, "eth0", 1, vec![2, 0, 0, 0, 0, 7]),
                link(3, "tun0", 0xFFFE, Vec::new()),
            ],
            addresses: vec![
                v4(1, "lo", [127, 0, 0, 1], 8, None),
                v4(2, "eth0", [10, 0, 0, 5], 24, Some([10, 0, 0, 255])),
                v4(2, "eth0", [10, 0, 1, 5], 24, Some([10, 0, 1, 255])),
            ],
        }
    }

    fn named(name: &str) -> [u8; IFREQ] {
        let mut r = [0xAAu8; IFREQ];
        r[..name.len()].copy_from_slice(name.as_bytes());
        r[name.len()] = 0;
        r
    }

    #[test]
    fn device_requests_follow_dev_ioctl() {
        let h = host();
        let unix = lx::AF_UNIX;
        let mut r = named("eth0");
        assert_eq!(answer(&h, unix, SIOCGIFINDEX, &mut r, false), Ok(true));
        assert_eq!(i32::from_le_bytes(r[16..20].try_into().unwrap()), 2);
        assert_eq!(&r[20..], &[0xAA; 20], "the rest untouched");
        // Flags are a short: IFF_LOWER_UP (bit 16) is cut off.
        let mut r = named("eth0");
        answer(&h, unix, SIOCGIFFLAGS, &mut r, false).unwrap();
        assert_eq!(u16::from_le_bytes([r[16], r[17]]), 0x1043);
        assert_eq!(r[18], 0xAA);
        // An alias's suffix is ignored and kept; the 16th byte cleared.
        let mut r = named("eth0:3");
        r[15] = b'x';
        answer(&h, unix, SIOCGIFMTU, &mut r, false).unwrap();
        assert_eq!(&r[..7], b"eth0:3\0");
        assert_eq!(r[15], 0);
        assert_eq!(i32::from_le_bytes(r[16..20].try_into().unwrap()), 1500);
        // The hardware address: family and bytes, the rest untouched; none
        // is zeros.
        let mut r = named("eth0");
        answer(&h, unix, SIOCGIFHWADDR, &mut r, false).unwrap();
        assert_eq!(u16::from_le_bytes([r[16], r[17]]), 1);
        assert_eq!(&r[18..24], &[2, 0, 0, 0, 0, 7]);
        assert_eq!(&r[24..32], &[0xAA; 8]);
        let mut r = named("tun0");
        answer(&h, unix, SIOCGIFHWADDR, &mut r, false).unwrap();
        assert_eq!(&r[18..32], &[0; 14]);
        // By index.
        let mut r = [0xAAu8; IFREQ];
        r[16..20].copy_from_slice(&3i32.to_le_bytes());
        answer(&h, unix, SIOCGIFNAME, &mut r, false).unwrap();
        assert_eq!(&r[..5], b"tun0\0");
        assert_eq!(r[5], 0xAA);
        r[16..20].copy_from_slice(&9i32.to_le_bytes());
        assert_eq!(
            answer(&h, unix, SIOCGIFNAME, &mut r, false),
            Err(Errno(ENODEV))
        );
        // Unknown devices, and requests dev_ioctl does not know.
        assert_eq!(
            answer(&h, unix, SIOCGIFMTU, &mut named("nope"), false),
            Err(Errno(ENODEV))
        );
        assert_eq!(
            answer(&h, unix, SIOCGIFADDR, &mut named("lo"), false),
            Err(Errno(ENOTTY))
        );
        assert_eq!(
            answer(&h, unix, SIOCGIFSLAVE, &mut named("lo"), false),
            Err(Errno(EINVAL))
        );
        assert_eq!(
            answer(&h, unix, SIOCGIFMEM, &mut named("lo"), false),
            Err(Errno(ENOTTY))
        );
        // Changes: privilege first, then the device, then not made.
        assert_eq!(
            answer(&h, unix, SIOCSIFMTU, &mut named("nope"), false),
            Err(Errno(EPERM))
        );
        assert_eq!(
            answer(&h, unix, SIOCSIFMTU, &mut named("nope"), true),
            Err(Errno(ENODEV))
        );
        assert_eq!(
            answer(&h, unix, SIOCSIFMTU, &mut named("lo"), true),
            Err(Errno(EOPNOTSUPP))
        );
        let mut r = named("lo");
        answer(&h, unix, SIOCGIFMAP, &mut r, false).unwrap();
        assert_eq!(&r[16..37], &[0; 21]);
        assert_eq!(&r[37..], &[0xAA; 3]);
    }

    #[test]
    fn ipv4_addresses_follow_devinet_ioctl() {
        let h = host();
        let inet = lx::AF_INET;
        let get = |req, r: &mut [u8; IFREQ]| {
            answer(&h, inet, req, r, false).map(|_| [r[20], r[21], r[22], r[23]])
        };
        assert_eq!(get(SIOCGIFADDR, &mut named("lo")), Ok([127, 0, 0, 1]));
        assert_eq!(get(SIOCGIFNETMASK, &mut named("lo")), Ok([255, 0, 0, 0]));
        assert_eq!(get(SIOCGIFBRDADDR, &mut named("lo")), Ok([0; 4]));
        assert_eq!(get(SIOCGIFDSTADDR, &mut named("lo")), Ok([127, 0, 0, 1]));
        assert_eq!(get(SIOCGIFBRDADDR, &mut named("eth0")), Ok([10, 0, 0, 255]));
        // The address given picks among the device's (4.4BSD).
        let mut r = named("eth0");
        r[16..18].copy_from_slice(&2u16.to_le_bytes());
        r[20..24].copy_from_slice(&[10, 0, 1, 5]);
        assert_eq!(get(SIOCGIFBRDADDR, &mut r), Ok([10, 0, 1, 255]));
        assert_eq!(u16::from_le_bytes([r[16], r[17]]), 2);
        assert_eq!(&r[24..32], &[0; 8], "the sockaddr_in cleared");
        // An alias is a label of its own: none here.
        assert_eq!(
            get(SIOCGIFADDR, &mut named("eth0:1")),
            Err(Errno(EADDRNOTAVAIL))
        );
        assert_eq!(
            get(SIOCGIFADDR, &mut named("tun0")),
            Err(Errno(EADDRNOTAVAIL))
        );
        assert_eq!(get(SIOCGIFADDR, &mut named("nope")), Err(Errno(ENODEV)));
        assert_eq!(get(SIOCGIFPFLAGS, &mut named("lo")), Err(Errno(EINVAL)));
        // Changes need privilege, and an IPv4 address.
        assert_eq!(
            answer(&h, inet, SIOCSIFADDR, &mut named("lo"), false),
            Err(Errno(EPERM))
        );
        assert_eq!(
            answer(&h, inet, SIOCSIFADDR, &mut named("lo"), true),
            Err(Errno(EINVAL))
        );
        assert_eq!(
            answer(&h, inet, SIOCSIFFLAGS, &mut named("lo"), false),
            Err(Errno(EPERM))
        );
        // An alias's flags need its address; a device's are not changed.
        assert_eq!(
            answer(&h, inet, SIOCSIFFLAGS, &mut named("eth0:1"), true),
            Err(Errno(EADDRNOTAVAIL))
        );
        assert_eq!(
            answer(&h, inet, SIOCSIFFLAGS, &mut named("eth0"), true),
            Err(Errno(EOPNOTSUPP))
        );
        // An IPv4 socket still reaches dev_ioctl for the device requests.
        assert_eq!(
            answer(&h, inet, SIOCGIFINDEX, &mut named("lo"), false),
            Ok(true)
        );
    }

    #[test]
    fn ifconf_lists_ipv4_addresses() {
        let h = host();
        let (none, total) = ifconf(&h, None);
        assert_eq!((none.len(), total), (0, 120));
        let (all, total) = ifconf(&h, Some(1000));
        assert_eq!((all.len(), total), (120, 120));
        assert_eq!(&all[..3], b"lo\0");
        assert_eq!(&all[40..45], b"eth0\0");
        assert_eq!(&all[100..104], &[10, 0, 1, 5]);
        // Whole entries only.
        let (some, total) = ifconf(&h, Some(79));
        assert_eq!((some.len(), total), (40, 40));
        assert_eq!(ifconf(&h, Some(-1)).1, 0);
    }

    #[test]
    fn ipv6_changes_follow_addrconf() {
        let h = host();
        let mut ireq = [0u8; IN6_IFREQ];
        assert!(in6_needs_admin(SIOCSIFADDR) && !in6_needs_admin(SIOCSIFDSTADDR));
        ireq[20..24].copy_from_slice(&2i32.to_le_bytes());
        assert_eq!(in6(&h, SIOCSIFDSTADDR, &ireq), Errno(ENODEV));
        assert_eq!(in6(&h, SIOCSIFADDR, &ireq), Errno(EOPNOTSUPP));
        assert_eq!(shape(lx::AF_INET6, SIOCSIFADDR), Shape::In6);
        assert_eq!(
            shape(lx::AF_INET, SIOCSIFADDR),
            Shape::Ifreq { answer: false }
        );
        assert_eq!(shape(lx::AF_UNIX, SIOCETHTOOL), Shape::Indirect);
        assert_eq!(shape(lx::AF_UNIX, 0x8905), Shape::Other);
    }
}

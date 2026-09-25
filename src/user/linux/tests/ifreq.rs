//! Interface requests against `net/socket.c` (`sock_ioctl`),
//! `net/core/dev_ioctl.c`, and `net/ipv4/devinet.c` (Linux 6.19), through
//! the socket `ioctl` on every ABI: `SIOCGIFCONF`, the device requests by
//! name and index, the IPv4 address requests on an IPv4 socket only, the
//! argument's untouched bytes, privilege, and faults. On a Linux host the
//! host answers; elsewhere the host's interfaces as rtnetlink describes
//! them do. Only the loopback's values are checked.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_NETLINK: u64 = 16;
const DGRAM: u64 = 2;
const RAW: u64 = 3;
const SIOCGIFCONF: u64 = 0x8912;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCGIFADDR: u64 = 0x8915;
const SIOCGIFNETMASK: u64 = 0x891B;
const SIOCGIFMTU: u64 = 0x8921;
const SIOCSIFMTU: u64 = 0x8922;
const SIOCGIFHWADDR: u64 = 0x8927;
const SIOCGIFINDEX: u64 = 0x8933;
const SIOCGIFNAME: u64 = 0x8910;
const SIOCETHTOOL: u64 = 0x8946;
const IFF_UP: u16 = 0x1;
const IFF_LOOPBACK: u16 = 0x8;

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn get(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn root() -> bool {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() == 0 }
}

/// A `struct ifreq` naming `name`, the rest 0xAA.
fn named(name: &[u8]) -> Vec<u8> {
    let mut r = vec![0xAAu8; 40];
    r[..name.len()].copy_from_slice(name);
    r[name.len()] = 0;
    r
}

/// The loopback's name, from `SIOCGIFCONF`'s entry for 127.0.0.1.
fn loopback(h: &mut Harness, fd: u64, m: u64) -> Vec<u8> {
    let mut conf = 0i32.to_le_bytes().to_vec();
    conf.extend_from_slice(&[0; 12]);
    put(h, m, &conf);
    h.ok(Sysno::Ioctl, &[fd, SIOCGIFCONF, m]);
    let len = i32::from_le_bytes(get(h, m, 4).try_into().unwrap());
    assert!(len > 0 && len % 40 == 0, "{len}");
    conf[..4].copy_from_slice(&len.to_le_bytes());
    conf[8..16].copy_from_slice(&(m + 0x100).to_le_bytes());
    put(h, m, &conf);
    h.ok(Sysno::Ioctl, &[fd, SIOCGIFCONF, m]);
    assert_eq!(i32::from_le_bytes(get(h, m, 4).try_into().unwrap()), len);
    let entries = get(h, m + 0x100, len as usize);
    let lo = entries
        .chunks(40)
        .find(|e| u16::from_le_bytes([e[16], e[17]]) == 2 && e[20..24] == [127, 0, 0, 1])
        .expect("an entry for 127.0.0.1");
    let end = lo.iter().position(|&b| b == 0).unwrap();
    lo[..end].to_vec()
}

#[test]
fn interface_requests_follow_dev_ioctl() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let inet = h.ok(Sysno::Socket, &[AF_INET, DGRAM, 0]);
        let unix = h.ok(Sysno::Socket, &[AF_UNIX, DGRAM, 0]);
        let nl = h.ok(Sysno::Socket, &[AF_NETLINK, RAW, 0]);
        let lo = loopback(&mut h, inet, m);
        let r = m + 0x2000;
        for fd in [inet, unix, nl] {
            put(&h, r, &named(&lo));
            h.ok(Sysno::Ioctl, &[fd, SIOCGIFINDEX, r]);
            let b = get(&h, r, 40);
            let index = i32::from_le_bytes(b[16..20].try_into().unwrap());
            assert!(index > 0);
            assert_eq!(&b[20..], &[0xAA; 20]);
            // Back by index; the name's own bytes only.
            put(&h, r, &[0xAA; 40]);
            put(&h, r + 16, &index.to_le_bytes());
            h.ok(Sysno::Ioctl, &[fd, SIOCGIFNAME, r]);
            let b = get(&h, r, 40);
            assert_eq!(&b[..lo.len()], &lo[..]);
            assert_eq!(b[lo.len()], 0);
            put(&h, r, &named(&lo));
            h.ok(Sysno::Ioctl, &[fd, SIOCGIFFLAGS, r]);
            let flags = u16::from_le_bytes(get(&h, r + 16, 2).try_into().unwrap());
            assert_eq!(flags & (IFF_UP | IFF_LOOPBACK), IFF_UP | IFF_LOOPBACK);
            put(&h, r, &named(&lo));
            h.ok(Sysno::Ioctl, &[fd, SIOCGIFMTU, r]);
            assert!(i32::from_le_bytes(get(&h, r + 16, 4).try_into().unwrap()) > 0);
            // The hardware address: the loopback's type and six zeros.
            put(&h, r, &named(&lo));
            h.ok(Sysno::Ioctl, &[fd, SIOCGIFHWADDR, r]);
            let b = get(&h, r, 40);
            assert_eq!(u16::from_le_bytes([b[16], b[17]]), 772);
            assert_eq!(&b[18..24], &[0; 6]);
            assert_eq!(&b[24..32], &[0xAA; 8]);
            put(&h, r, &named(b"rax-no-device"));
            assert_eq!(h.err(Sysno::Ioctl, &[fd, SIOCGIFMTU, r]), ENODEV);
            assert_eq!(h.err(Sysno::Ioctl, &[fd, SIOCGIFINDEX, 8]), EFAULT);
            // A driver's request: not carried.
            put(&h, r, &named(&lo));
            assert_eq!(h.err(Sysno::Ioctl, &[fd, SIOCETHTOOL, r]), EOPNOTSUPP);
            if !root() {
                assert_eq!(h.err(Sysno::Ioctl, &[fd, SIOCSIFMTU, r]), EPERM);
            }
        }
        // IPv4 addresses are an IPv4 socket's requests.
        put(&h, r, &named(&lo));
        h.ok(Sysno::Ioctl, &[inet, SIOCGIFADDR, r]);
        assert_eq!(get(&h, r + 16, 8), [2, 0, 0, 0, 127, 0, 0, 1]);
        put(&h, r, &named(&lo));
        h.ok(Sysno::Ioctl, &[inet, SIOCGIFNETMASK, r]);
        assert_eq!(get(&h, r + 20, 4), [255, 0, 0, 0]);
        put(&h, r, &named(&lo));
        assert_eq!(h.err(Sysno::Ioctl, &[unix, SIOCGIFADDR, r]), ENOTTY);
        assert_eq!(h.err(Sysno::Ioctl, &[nl, SIOCGIFADDR, r]), ENOTTY);
    });
}

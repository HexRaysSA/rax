//! The socket calls of a compatibility task (`net/compat.c`): the
//! `socketcall` multiplexer (`compat_sys_socketcall`), whose arguments are
//! an array of 32-bit words. The calls themselves are the native ones; those
//! with a `struct msghdr` read and write `struct compat_msghdr` and its
//! control messages when [`Ctx::compat`] is set (`MSG_CMSG_COMPAT`), and the
//! old socket timeouts are `struct old_timeval32`.

use super::super::super::abi::Sysno as S;
use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::{Ctx, Outcome, call_handler};

/// `SYS_SOCKET` .. `SYS_SENDMMSG` (`linux/net.h`).
mod call {
    pub const SOCKET: u32 = 1;
    pub const BIND: u32 = 2;
    pub const CONNECT: u32 = 3;
    pub const LISTEN: u32 = 4;
    pub const ACCEPT: u32 = 5;
    pub const GETSOCKNAME: u32 = 6;
    pub const GETPEERNAME: u32 = 7;
    pub const SOCKETPAIR: u32 = 8;
    pub const SEND: u32 = 9;
    pub const RECV: u32 = 10;
    pub const SENDTO: u32 = 11;
    pub const RECVFROM: u32 = 12;
    pub const SHUTDOWN: u32 = 13;
    pub const SETSOCKOPT: u32 = 14;
    pub const GETSOCKOPT: u32 = 15;
    pub const SENDMSG: u32 = 16;
    pub const RECVMSG: u32 = 17;
    pub const ACCEPT4: u32 = 18;
    pub const RECVMMSG: u32 = 19;
    pub const SENDMMSG: u32 = 20;
}

/// `nas`: the number of 32-bit arguments of each call.
const ARGS: [usize; 21] = [
    0, 3, 3, 3, 2, 3, 3, 3, 4, 4, 4, 6, 6, 2, 5, 5, 3, 3, 4, 5, 4,
];

/// `compat_sys_socketcall`: `number` out of range is `EINVAL` before the
/// arguments are read (`EFAULT`); each call is the native one with its
/// words zero-extended, `SYS_ACCEPT` as `accept4` without flags, `SYS_SEND`
/// and `SYS_RECV` as `sendto` and `recvfrom` without an address, and
/// `SYS_RECVMMSG`'s timeout a `struct old_timespec32`.
pub fn socketcall(c: &mut Ctx<'_>, number: u64, args: u64) -> Result<Outcome, Errno> {
    use call::*;
    let number = number as u32;
    if !(SOCKET..=SENDMMSG).contains(&number) {
        return Err(Errno(EINVAL));
    }
    let n = ARGS[number as usize];
    let b = c.read_mem(args, n * 4)?;
    let mut a = [0u64; 6];
    for (i, w) in a.iter_mut().enumerate().take(n) {
        *w = u64::from(u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()));
    }
    let s = match number {
        SOCKET => S::Socket,
        BIND => S::Bind,
        CONNECT => S::Connect,
        LISTEN => S::Listen,
        ACCEPT | ACCEPT4 => S::Accept4,
        GETSOCKNAME => S::Getsockname,
        GETPEERNAME => S::Getpeername,
        SOCKETPAIR => S::Socketpair,
        SEND | SENDTO => S::Sendto,
        RECV | RECVFROM => S::Recvfrom,
        SHUTDOWN => S::Shutdown,
        SETSOCKOPT => S::Setsockopt,
        GETSOCKOPT => S::Getsockopt,
        SENDMSG => S::Sendmsg,
        RECVMSG => S::Recvmsg,
        RECVMMSG => {
            c.time32 = true;
            S::Recvmmsg
        }
        _ => S::Sendmmsg,
    };
    call_handler(c, s, a)
}

/// Whether `compat_sock_ioctl_trans` passes socket request `cmd` on
/// (`SIOCDEVPRIVATE`..+15, the requests it hands to `sock_ioctl`,
/// `sock_do_ioctl`, `compat_ifr_data_ioctl`, `compat_siocwandev`, or the
/// protocol's `gettstamp`); any other is `ENOIOCTLCMD`, `ENOTTY` to a
/// 32-bit caller, even one a 64-bit caller may issue (`SIOCGIFSLAVE`,
/// `SIOCSIFSLAVE`, `SIOCSIFLINK`).
pub fn sock_ioctl_known(cmd: u32) -> bool {
    use super::super::super::net::ifreq::*;
    const FIOSETOWN: u32 = 0x8901;
    const SIOCSPGRP: u32 = 0x8902;
    const FIOGETOWN: u32 = 0x8903;
    const SIOCGPGRP: u32 = 0x8904;
    const SIOCATMARK: u32 = 0x8905;
    const SIOCGSTAMP_OLD: u32 = 0x8906;
    const SIOCGSTAMPNS_OLD: u32 = 0x8907;
    const SIOCGSTAMP_NEW: u32 = 0x8010_8906;
    const SIOCGSTAMPNS_NEW: u32 = 0x8010_8907;
    const SIOCOUTQ: u32 = 0x5411;
    const SIOCGIFBR: u32 = 0x8940;
    const SIOCSIFBR: u32 = 0x8941;
    const SIOCOUTQNSD: u32 = 0x894B;
    const SIOCGSKNS: u32 = 0x894C;
    const SIOCDARP: u32 = 0x8953;
    const SIOCGARP: u32 = 0x8954;
    const SIOCSARP: u32 = 0x8955;
    const SIOCGIFVLAN: u32 = 0x8982;
    const SIOCSIFVLAN: u32 = 0x8983;
    const SIOCBRADDBR: u32 = 0x89A0;
    const SIOCBRDELIF: u32 = 0x89A3;
    (SIOCDEVPRIVATE..=SIOCDEVPRIVATE + 15).contains(&cmd)
        || (SIOCBRADDBR..=SIOCBRDELIF).contains(&cmd)
        || matches!(
            cmd,
            SIOCWANDEV
                | SIOCGSTAMP_OLD
                | SIOCGSTAMPNS_OLD
                | SIOCETHTOOL
                | SIOCBONDSLAVEINFOQUERY
                | SIOCBONDINFOQUERY
                | SIOCSHWTSTAMP
                | SIOCGHWTSTAMP
                | FIOSETOWN
                | SIOCSPGRP
                | FIOGETOWN
                | SIOCGPGRP
                | SIOCGIFVLAN
                | SIOCSIFVLAN
                | SIOCGSKNS
                | SIOCGSTAMP_NEW
                | SIOCGSTAMPNS_NEW
                | SIOCGIFCONF
                | SIOCSIFBR
                | SIOCGIFBR
                | SIOCGIFFLAGS
                | SIOCSIFFLAGS
                | SIOCGIFMAP
                | SIOCSIFMAP
                | SIOCGIFMETRIC
                | SIOCSIFMETRIC
                | SIOCGIFMTU
                | SIOCSIFMTU
                | SIOCGIFMEM
                | SIOCSIFMEM
                | SIOCGIFHWADDR
                | SIOCSIFHWADDR
                | SIOCADDMULTI
                | SIOCDELMULTI
                | SIOCGIFINDEX
                | SIOCGIFADDR
                | SIOCSIFADDR
                | SIOCSIFHWBROADCAST
                | SIOCDIFADDR
                | SIOCGIFBRDADDR
                | SIOCSIFBRDADDR
                | SIOCGIFDSTADDR
                | SIOCSIFDSTADDR
                | SIOCGIFNETMASK
                | SIOCSIFNETMASK
                | SIOCSIFPFLAGS
                | SIOCGIFPFLAGS
                | SIOCGIFTXQLEN
                | SIOCSIFTXQLEN
                | SIOCGIFNAME
                | SIOCSIFNAME
                | SIOCGMIIPHY
                | SIOCGMIIREG
                | SIOCSMIIREG
                | SIOCBONDENSLAVE
                | SIOCBONDRELEASE
                | SIOCBONDSETHWADDR
                | SIOCBONDCHANGEACTIVE
                | SIOCSARP
                | SIOCGARP
                | SIOCDARP
                | SIOCOUTQ
                | SIOCOUTQNSD
                | SIOCATMARK
        )
}

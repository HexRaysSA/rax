//! Socket options (`sk_setsockopt`, `sk_getsockopt`, and the protocol
//! levels): Linux option numbers mapped to the host's, and the options the
//! personality keeps itself.
//!
//! | Kind | Options |
//! |---|---|
//! | Kept by the personality | `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`, `SO_COOKIE`, `SO_ACCEPTCONN`, `SO_SNDBUF`/`SO_RCVBUF` as Linux reports them (the value set doubled, Linux's defaults and minimums), the receive and send timeouts (which the emulated blocking honors), `SO_PEERCRED` |
//! | Passed to the host | the boolean `SOL_SOCKET` options (reported as 0 or 1), `SO_LINGER`, `SO_RCVLOWAT`, `SO_ERROR`, and the `IPPROTO_IP`, `IPPROTO_IPV6`, and `IPPROTO_TCP` options the host shares |
//! | Recorded only (accepted and reported back; no effect) | `SO_DEBUG`, `SO_PRIORITY`, `SO_NO_CHECK`, `SO_PASSCRED`, `SO_TIMESTAMP*`, `SO_MARK`, `SO_BUSY_POLL`, `SO_INCOMING_CPU`, `SO_ZEROCOPY`, `TCP_QUICKACK`, `TCP_USER_TIMEOUT`, `TCP_FASTOPEN`, and the others marked so in [`carriage`] |
//!
//! Errors follow the kernel: an option of `SOL_SOCKET` needs at least an
//! `int` (`EINVAL`), an unknown one is `ENOPROTOOPT`, and a level the
//! socket's protocol does not handle is `EOPNOTSUPP`. The timeouts are kept
//! in jiffies of a 1000 Hz kernel (`CONFIG_HZ_1000`): a timeout set rounds
//! up to whole milliseconds.

use std::time::Duration;

use super::super::abi::errno::{Errno, from_host};
use super::super::abi::errno_table::*;
use super::{Socket, lx, sys};

/// Linux `SOL_SOCKET` options (`asm-generic/socket.h`).
pub mod so {
    pub const DEBUG: i32 = 1;
    pub const REUSEADDR: i32 = 2;
    pub const TYPE: i32 = 3;
    pub const ERROR: i32 = 4;
    pub const DONTROUTE: i32 = 5;
    pub const BROADCAST: i32 = 6;
    pub const SNDBUF: i32 = 7;
    pub const RCVBUF: i32 = 8;
    pub const KEEPALIVE: i32 = 9;
    pub const OOBINLINE: i32 = 10;
    pub const NO_CHECK: i32 = 11;
    pub const PRIORITY: i32 = 12;
    pub const LINGER: i32 = 13;
    pub const BSDCOMPAT: i32 = 14;
    pub const REUSEPORT: i32 = 15;
    pub const PASSCRED: i32 = 16;
    pub const PEERCRED: i32 = 17;
    pub const RCVLOWAT: i32 = 18;
    pub const SNDLOWAT: i32 = 19;
    pub const RCVTIMEO_OLD: i32 = 20;
    pub const SNDTIMEO_OLD: i32 = 21;
    pub const BINDTODEVICE: i32 = 25;
    pub const PEERNAME: i32 = 28;
    pub const TIMESTAMP_OLD: i32 = 29;
    pub const ACCEPTCONN: i32 = 30;
    pub const SNDBUFFORCE: i32 = 32;
    pub const RCVBUFFORCE: i32 = 33;
    pub const TIMESTAMPNS_OLD: i32 = 35;
    pub const MARK: i32 = 36;
    pub const PROTOCOL: i32 = 38;
    pub const DOMAIN: i32 = 39;
    pub const RXQ_OVFL: i32 = 40;
    pub const PEEK_OFF: i32 = 42;
    pub const BUSY_POLL: i32 = 46;
    pub const INCOMING_CPU: i32 = 49;
    pub const COOKIE: i32 = 57;
    pub const ZEROCOPY: i32 = 60;
    pub const TIMESTAMP_NEW: i32 = 63;
    pub const TIMESTAMPNS_NEW: i32 = 64;
    pub const RCVTIMEO_NEW: i32 = 66;
    pub const SNDTIMEO_NEW: i32 = 67;
}

/// `sysctl_rmem_max` and `sysctl_wmem_max` (defaults).
const MEM_MAX: u32 = 212_992;
/// `sysctl_rmem_default` and `sysctl_wmem_default`.
const MEM_DEFAULT: i32 = 212_992;
/// `SOCK_MIN_RCVBUF`: `TCP_SKB_MIN_TRUESIZE`, 2048 bytes plus the
/// cache-aligned `struct sk_buff` (256 bytes on x86-64 and arm64).
const MIN_RCVBUF: i32 = 2304;
/// `SOCK_MIN_SNDBUF`: twice that.
const MIN_SNDBUF: i32 = 4608;
/// `tcp_rmem[1]` and `tcp_wmem[1]`.
const TCP_RMEM: i32 = 131_072;
const TCP_WMEM: i32 = 16_384;
/// Priorities settable without `CAP_NET_ADMIN` (`TC_PRIO_BESTEFFORT` to
/// `TC_PRIO_INTERACTIVE`).
const PRIO_MAX: i32 = 6;

/// A socket timeout as the kernel keeps it: `None` waits indefinitely
/// (`MAX_SCHEDULE_TIMEOUT`), `Some(ZERO)` not at all.
pub type Timeout = Option<Duration>;

/// How the host carries a Linux option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Host {
    /// An `int` option at the host's `(level, name)`.
    Int(i32, i32),
    /// A boolean the host may report as any nonzero value.
    Bool(i32, i32),
    /// A structure passed through unchanged, of this many bytes at most.
    Raw(i32, i32, usize),
    /// Accepted and reported back; the host has no counterpart.
    Record,
}

/// The host carriage of `(level, opt)` for socket `s`.
fn carriage(s: &Socket, level: i32, opt: i32) -> Result<Host, Errno> {
    use Host::*;
    let inet = matches!(s.domain, lx::AF_INET | lx::AF_INET6);
    let sol = libc::SOL_SOCKET;
    Ok(match level {
        lx::SOL_SOCKET => match opt {
            so::REUSEADDR => Bool(sol, libc::SO_REUSEADDR),
            so::DONTROUTE => Bool(sol, libc::SO_DONTROUTE),
            so::BROADCAST => Bool(sol, libc::SO_BROADCAST),
            so::KEEPALIVE => Bool(sol, libc::SO_KEEPALIVE),
            so::OOBINLINE => Bool(sol, libc::SO_OOBINLINE),
            so::REUSEPORT => Bool(sol, libc::SO_REUSEPORT),
            so::RCVLOWAT => Int(sol, libc::SO_RCVLOWAT),
            // struct linger in seconds on both (Darwin's SO_LINGER counts
            // clock ticks, SO_LINGER_SEC seconds).
            #[cfg(target_vendor = "apple")]
            so::LINGER => Raw(sol, 0x1080, 8),
            #[cfg(not(target_vendor = "apple"))]
            so::LINGER => Raw(sol, libc::SO_LINGER, 8),
            so::DEBUG
            | so::NO_CHECK
            | so::PRIORITY
            | so::PASSCRED
            | so::TIMESTAMP_OLD
            | so::TIMESTAMPNS_OLD
            | so::TIMESTAMP_NEW
            | so::TIMESTAMPNS_NEW
            | so::MARK
            | so::RXQ_OVFL
            | so::BUSY_POLL
            | so::INCOMING_CPU
            | so::ZEROCOPY => Record,
            _ => return Err(Errno(ENOPROTOOPT)),
        },
        lx::IPPROTO_TCP if s.protocol == lx::IPPROTO_TCP => match opt {
            1 => Bool(libc::IPPROTO_TCP, libc::TCP_NODELAY),
            2 => Int(libc::IPPROTO_TCP, libc::TCP_MAXSEG),
            // TCP_CORK: Darwin's TCP_NOPUSH holds partial frames alike.
            #[cfg(target_vendor = "apple")]
            3 => Bool(libc::IPPROTO_TCP, libc::TCP_NOPUSH),
            #[cfg(not(target_vendor = "apple"))]
            3 => Bool(libc::IPPROTO_TCP, libc::TCP_CORK),
            // TCP_KEEPIDLE: Darwin's TCP_KEEPALIVE (seconds).
            #[cfg(target_vendor = "apple")]
            4 => Int(libc::IPPROTO_TCP, libc::TCP_KEEPALIVE),
            #[cfg(not(target_vendor = "apple"))]
            4 => Int(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
            5 => Int(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
            6 => Int(libc::IPPROTO_TCP, libc::TCP_KEEPCNT),
            // TCP_SYNCNT, TCP_LINGER2, TCP_DEFER_ACCEPT, TCP_WINDOW_CLAMP,
            // TCP_QUICKACK, TCP_USER_TIMEOUT, TCP_FASTOPEN, TCP_TIMESTAMP,
            // TCP_NOTSENT_LOWAT, TCP_FASTOPEN_CONNECT.
            7 | 8 | 9 | 10 | 12 | 18 | 23 | 24 | 25 | 30 => Record,
            _ => return Err(Errno(ENOPROTOOPT)),
        },
        // SOL_UDP: UDP_CORK, UDP_ENCAP, UDP_NO_CHECK6_TX/RX, UDP_SEGMENT,
        // UDP_GRO.
        lx::IPPROTO_UDP if s.protocol == lx::IPPROTO_UDP => match opt {
            1 | 100..=104 => Record,
            _ => return Err(Errno(ENOPROTOOPT)),
        },
        lx::IPPROTO_IP if inet => match opt {
            1 => Int(libc::IPPROTO_IP, libc::IP_TOS),
            2 => Int(libc::IPPROTO_IP, libc::IP_TTL),
            3 => Bool(libc::IPPROTO_IP, libc::IP_HDRINCL),
            32 => Raw(libc::IPPROTO_IP, libc::IP_MULTICAST_IF, 4),
            33 => Int(libc::IPPROTO_IP, libc::IP_MULTICAST_TTL),
            34 => Bool(libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP),
            // struct ip_mreq (the leading part of Linux's ip_mreqn).
            35 => Raw(libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, 8),
            36 => Raw(libc::IPPROTO_IP, libc::IP_DROP_MEMBERSHIP, 8),
            // IP_PKTINFO, IP_MTU_DISCOVER, IP_RECVERR, IP_RECVTOS,
            // IP_FREEBIND, IP_BIND_ADDRESS_NO_PORT.
            8 | 10 | 11 | 13 | 15 | 24 => Record,
            _ => return Err(Errno(ENOPROTOOPT)),
        },
        lx::IPPROTO_IPV6 if s.domain == lx::AF_INET6 => match opt {
            16 => Int(libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            17 => Raw(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, 4),
            18 => Int(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS),
            19 => Bool(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP),
            // struct ipv6_mreq.
            #[cfg(target_os = "linux")]
            20 => Raw(libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, 20),
            #[cfg(target_os = "linux")]
            21 => Raw(libc::IPPROTO_IPV6, libc::IPV6_DROP_MEMBERSHIP, 20),
            #[cfg(not(target_os = "linux"))]
            20 => Raw(libc::IPPROTO_IPV6, libc::IPV6_JOIN_GROUP, 20),
            #[cfg(not(target_os = "linux"))]
            21 => Raw(libc::IPPROTO_IPV6, libc::IPV6_LEAVE_GROUP, 20),
            26 => Bool(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY),
            // IPV6_MTU_DISCOVER, IPV6_RECVERR, IPV6_RECVPKTINFO,
            // IPV6_TCLASS.
            23 | 25 | 49 | 67 => Record,
            _ => return Err(Errno(ENOPROTOOPT)),
        },
        _ => return Err(Errno(EOPNOTSUPP)),
    })
}

/// `sock_get_timeout` of a 64-bit `struct __kernel_old_timeval` (which
/// `struct __kernel_sock_timeval` equals on 64-bit ABIs): zero for no limit.
fn timeval(t: Timeout) -> Vec<u8> {
    let d = t.unwrap_or_default();
    let mut b = vec![0u8; 16];
    b[..8].copy_from_slice(&(d.as_secs() as i64).to_le_bytes());
    b[8..].copy_from_slice(&i64::from(d.subsec_micros()).to_le_bytes());
    b
}

/// `sock_set_timeout`: at least a `struct timeval` (`EINVAL`), microseconds
/// in range (`EDOM`); a negative time is zero (never wait), zero is no
/// limit, anything else rounds up to a whole jiffy (1 ms).
pub fn parse_timeout(val: &[u8]) -> Result<Timeout, Errno> {
    if val.len() < 16 {
        return Err(Errno(EINVAL));
    }
    let sec = i64::from_le_bytes(val[..8].try_into().unwrap());
    let usec = i64::from_le_bytes(val[8..16].try_into().unwrap());
    if !(0..1_000_000).contains(&usec) {
        return Err(Errno(EDOM));
    }
    if sec < 0 {
        return Ok(Some(Duration::ZERO));
    }
    // MAX_SCHEDULE_TIMEOUT / HZ - 1 seconds and more: no limit.
    if (sec == 0 && usec == 0) || sec >= i64::MAX / 1000 - 1 {
        return Ok(None);
    }
    Ok(Some(Duration::from_millis(
        sec as u64 * 1000 + (usec as u64).div_ceil(1000),
    )))
}

fn int(v: i32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// The value of `(level, opt)`, whole (`lv` bytes); the caller copies as
/// much as the guest's length allows.
pub fn get(s: &Socket, level: i32, opt: i32) -> Result<Vec<u8>, Errno> {
    let st = || s.state.lock().unwrap();
    let unix = s.domain == lx::AF_UNIX;
    if level == lx::SOL_SOCKET {
        match opt {
            so::TYPE => return Ok(int(s.stype)),
            so::DOMAIN => return Ok(int(s.domain)),
            so::PROTOCOL => return Ok(int(s.protocol)),
            so::COOKIE => return Ok(st().cookie.to_le_bytes().to_vec()),
            so::SNDLOWAT => return Ok(int(1)),
            so::ACCEPTCONN => return Ok(int(i32::from(s.listening()))),
            so::BSDCOMPAT => return Ok(int(0)),
            so::ERROR => {
                // sock_error: an error the personality recorded first, then
                // the host's; reading clears it.
                let own = std::mem::take(&mut st().error);
                if own != 0 {
                    return Ok(int(own));
                }
                let e = sys::getsockopt_int(&s.file, libc::SOL_SOCKET, libc::SO_ERROR)?;
                return Ok(int(if e == 0 { 0 } else { from_host(e) }));
            }
            so::RCVBUF => {
                let d = if s.protocol == lx::IPPROTO_TCP {
                    TCP_RMEM
                } else {
                    MEM_DEFAULT
                };
                return Ok(int(st().rcvbuf.unwrap_or(d)));
            }
            so::SNDBUF => {
                let d = if s.protocol == lx::IPPROTO_TCP {
                    TCP_WMEM
                } else {
                    MEM_DEFAULT
                };
                return Ok(int(st().sndbuf.unwrap_or(d)));
            }
            so::RCVTIMEO_OLD | so::RCVTIMEO_NEW => return Ok(timeval(st().rcvtimeo)),
            so::SNDTIMEO_OLD | so::SNDTIMEO_NEW => return Ok(timeval(st().sndtimeo)),
            so::PEERCRED => {
                // cred_to_ucred: PID 0 and IDs of -1 without a peer.
                let (pid, uid, gid) = s.peer_cred().unwrap_or((0, u32::MAX, u32::MAX));
                let mut b = Vec::with_capacity(12);
                b.extend_from_slice(&pid.to_le_bytes());
                b.extend_from_slice(&uid.to_le_bytes());
                b.extend_from_slice(&gid.to_le_bytes());
                return Ok(b);
            }
            // sk_may_scm_recv.
            so::PASSCRED if !unix => return Err(Errno(EOPNOTSUPP)),
            so::PEEK_OFF => return Err(Errno(EOPNOTSUPP)),
            _ => {}
        }
    }
    match carriage(s, level, opt)? {
        Host::Record => Ok(int(recorded(s, level, opt))),
        Host::Int(hl, ho) => Ok(int(sys::getsockopt_int(&s.file, hl, ho)?)),
        Host::Bool(hl, ho) => Ok(int(i32::from(sys::getsockopt_int(&s.file, hl, ho)? != 0))),
        Host::Raw(hl, ho, n) => {
            let mut b = sys::getsockopt(&s.file, hl, ho, n)?;
            b.resize(n, 0);
            Ok(b)
        }
    }
}

/// A recorded option's value (0 until set).
fn recorded(s: &Socket, level: i32, opt: i32) -> i32 {
    s.state
        .lock()
        .unwrap()
        .ints
        .iter()
        .find(|&&(l, o, _)| l == level && o == opt)
        .map_or(0, |&(_, _, v)| v)
}

/// `sk_setsockopt` and the protocol levels. `admin` is whether the caller
/// holds the network capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`).
pub fn set(s: &Socket, level: i32, opt: i32, val: &[u8], admin: bool) -> Result<(), Errno> {
    let unix = s.domain == lx::AF_UNIX;
    let first_int = || i32::from_le_bytes(val[..4].try_into().unwrap());
    if level == lx::SOL_SOCKET {
        if opt == so::BINDTODEVICE {
            // sock_setbindtodevice: CAP_NET_RAW; an empty name unbinds,
            // and no interface is known by name.
            if !admin {
                return Err(Errno(EPERM));
            }
            let name = &val[..val.len().min(15)];
            return if name.first().is_none_or(|&b| b == 0) {
                Ok(())
            } else {
                Err(Errno(ENODEV))
            };
        }
        if val.len() < 4 {
            return Err(Errno(EINVAL));
        }
        let v = first_int();
        let mut st = s.state.lock().unwrap();
        match opt {
            so::TYPE | so::DOMAIN | so::PROTOCOL | so::ERROR | so::ACCEPTCONN => {
                return Err(Errno(ENOPROTOOPT));
            }
            so::PRIORITY if !admin && !(0..=PRIO_MAX).contains(&v) => return Err(Errno(EPERM)),
            so::DEBUG if v != 0 && !admin => return Err(Errno(EACCES)),
            so::MARK if !admin => return Err(Errno(EPERM)),
            so::REUSEPORT if v != 0 && unix => return Err(Errno(EOPNOTSUPP)),
            so::PASSCRED if !unix => return Err(Errno(EOPNOTSUPP)),
            so::PEEK_OFF => return Err(Errno(EOPNOTSUPP)),
            so::BSDCOMPAT => return Ok(()),
            so::RCVBUF | so::SNDBUF => {
                // __sock_set_rcvbuf / sock_set_sndbuf: capped at the
                // maximum (a negative value is large), doubled, and at
                // least the minimum. The host gets the request as it is.
                let v = (v as u32).min(MEM_MAX) as i32;
                let (min, host) = if opt == so::RCVBUF {
                    (MIN_RCVBUF, libc::SO_RCVBUF)
                } else {
                    (MIN_SNDBUF, libc::SO_SNDBUF)
                };
                let _ = sys::setsockopt(&s.file, libc::SOL_SOCKET, host, &v.to_ne_bytes());
                let kept = Some(v.saturating_mul(2).max(min));
                if opt == so::RCVBUF {
                    st.rcvbuf = kept;
                } else {
                    st.sndbuf = kept;
                }
                return Ok(());
            }
            so::RCVBUFFORCE | so::SNDBUFFORCE => {
                if !admin {
                    return Err(Errno(EPERM));
                }
                // No cap; a negative value is zero.
                let v = v.clamp(0, i32::MAX / 2);
                if opt == so::RCVBUFFORCE {
                    st.rcvbuf = Some((v * 2).max(MIN_RCVBUF));
                } else {
                    st.sndbuf = Some((v * 2).max(MIN_SNDBUF));
                }
                return Ok(());
            }
            so::RCVTIMEO_OLD | so::RCVTIMEO_NEW => {
                st.rcvtimeo = parse_timeout(val)?;
                return Ok(());
            }
            so::SNDTIMEO_OLD | so::SNDTIMEO_NEW => {
                st.sndtimeo = parse_timeout(val)?;
                return Ok(());
            }
            _ => {}
        }
    }
    match carriage(s, level, opt)? {
        Host::Record => {
            if val.len() < 4 {
                return Err(Errno(EINVAL));
            }
            let v = first_int();
            let mut st = s.state.lock().unwrap();
            st.ints.retain(|&(l, o, _)| !(l == level && o == opt));
            st.ints.push((level, opt, v));
            Ok(())
        }
        Host::Int(hl, ho) | Host::Bool(hl, ho) => {
            // An int, or (for the IP byte-sized options) a single byte.
            let v = match val.len() {
                0 => return Err(Errno(EINVAL)),
                1..=3 if level == lx::IPPROTO_IP => i32::from(val[0]),
                1..=3 => return Err(Errno(EINVAL)),
                _ => first_int(),
            };
            let v = if level == lx::SOL_SOCKET && opt == so::RCVLOWAT && v < 0 {
                i32::MAX
            } else {
                v
            };
            sys::setsockopt(&s.file, hl, ho, &v.to_ne_bytes())
        }
        Host::Raw(hl, ho, n) => {
            if val.len() < n.min(8) {
                return Err(Errno(EINVAL));
            }
            sys::setsockopt(&s.file, hl, ho, &val[..val.len().min(n)])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tv(sec: i64, usec: i64) -> Vec<u8> {
        let mut b = sec.to_le_bytes().to_vec();
        b.extend_from_slice(&usec.to_le_bytes());
        b
    }

    #[test]
    fn timeouts_follow_sock_set_timeout() {
        assert_eq!(parse_timeout(&tv(0, 0)), Ok(None));
        assert_eq!(
            parse_timeout(&tv(0, 50_000)),
            Ok(Some(Duration::from_millis(50)))
        );
        // Rounded up to a jiffy of a 1000 Hz kernel.
        assert_eq!(
            parse_timeout(&tv(1, 1)),
            Ok(Some(Duration::from_millis(1001)))
        );
        assert_eq!(parse_timeout(&tv(-1, 0)), Ok(Some(Duration::ZERO)));
        assert_eq!(parse_timeout(&tv(0, 1_000_000)), Err(Errno(EDOM)));
        assert_eq!(parse_timeout(&tv(0, -1)), Err(Errno(EDOM)));
        assert_eq!(parse_timeout(&tv(0, 1)[..15]), Err(Errno(EINVAL)));
        assert_eq!(parse_timeout(&tv(i64::MAX, 0)), Ok(None));
    }

    #[test]
    fn timeval_reports_zero_for_no_limit() {
        assert_eq!(timeval(None), tv(0, 0));
        assert_eq!(timeval(Some(Duration::from_millis(1500))), tv(1, 500_000));
    }
}

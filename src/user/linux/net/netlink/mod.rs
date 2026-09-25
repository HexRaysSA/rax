//! Netlink sockets (`net/netlink/af_netlink.c`).
//!
//! On a Linux host the guest's netlink sockets are the host's: every
//! protocol, with the host kernel's links, addresses, routes, and events.
//! Elsewhere `NETLINK_ROUTE` is emulated ([`Endpoint`]) and other protocols
//! are not registered (`EPROTONOSUPPORT`). An emulated socket keeps its own
//! queue of datagrams from the kernel, which the kernel side ([`route`])
//! fills when the guest sends requests, describing the host's interfaces
//! ([`ifaces`]); its host descriptor is a readiness level, readable while
//! the queue is not empty. It binds, sends, and receives as `af_netlink.c`
//! does: autobind to the process's ID (then to negative IDs), membership
//! of the `RTNLGRP_MAX` groups (the multicast-routing ones privileged),
//! `-ENODATA` for an empty send, `MSG_TRUNC`, `MSG_PEEK`, `NETLINK_PKTINFO`,
//! `NETLINK_CAP_ACK`, and a dump delivered a datagram at a time as the
//! queue drains, sized by the largest receive buffer seen
//! (`max_recvmsg_len`), with `NLMSG_DONE` in a datagram of its own where
//! rtnetlink splits it off.
//!
//! Not emulated: notifications to the groups joined (the host's changes
//! are not observed), messages to other sockets' ports (`ECONNREFUSED`),
//! multicasts from the guest (delivered to no socket), and sharing with a
//! forked child, which gets its own copy of the socket's state ([`forked`]).
//! Port IDs are unique among the process's sockets only.

pub mod ifaces;
pub mod route;

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, Weak};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;

/// `AF_NETLINK`.
pub const AF_NETLINK: i32 = 16;
pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
/// `NETLINK_ROUTE`.
pub const NETLINK_ROUTE: i32 = 0;
/// `MAX_LINKS`: protocols are below it.
pub const MAX_LINKS: i32 = 32;
/// `SOL_NETLINK`.
pub const SOL_NETLINK: i32 = 270;

/// `struct nlmsghdr` is 16 bytes.
pub const NLMSG_HDRLEN: usize = 16;
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_MULTI: u16 = 2;
pub const NLM_F_ACK: u16 = 4;
pub const NLM_F_DUMP: u16 = 0x300;
/// `NLM_F_CAPPED` (an `NLMSG_ERROR` flag).
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
/// `NLMSG_MIN_TYPE`: types below are control messages.
pub const NLMSG_MIN_TYPE: u16 = 0x10;

/// `SOL_NETLINK` options (`linux/netlink.h`).
pub const NETLINK_ADD_MEMBERSHIP: i32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: i32 = 2;
pub const NETLINK_PKTINFO: i32 = 3;
pub const NETLINK_BROADCAST_ERROR: i32 = 4;
pub const NETLINK_NO_ENOBUFS: i32 = 5;
pub const NETLINK_LISTEN_ALL_NSID: i32 = 8;
pub const NETLINK_LIST_MEMBERSHIPS: i32 = 9;
pub const NETLINK_CAP_ACK: i32 = 10;
pub const NETLINK_EXT_ACK: i32 = 11;
pub const NETLINK_GET_STRICT_CHK: i32 = 12;

/// `NLMSG_GOODSIZE` with 4 KiB pages: a dump datagram's size before the
/// guest's receive buffers are known.
pub const NLMSG_GOODSIZE: usize = 3776;
/// `SKB_WITH_OVERHEAD(32768)`: the most `max_recvmsg_len` records.
const MAX_RECVMSG_LEN: usize = 32448;
/// `sizeof(struct sockaddr_nl)`.
pub const SOCKADDR_NL_SIZE: usize = 12;
/// `sysctl_rmem_default` and `sysctl_wmem_default`: a new socket's
/// `sk_rcvbuf` and `sk_sndbuf`.
pub const MEM_DEFAULT: usize = 212_992;
/// `RTNLGRP_MAX`: `NETLINK_ROUTE`'s groups (`nlk->ngroups`).
pub const NGROUPS: u32 = 39;
/// `RTNLGRP_IPV4_MROUTE_R` and `RTNLGRP_IPV6_MROUTE_R`, which
/// `rtnetlink_bind` lets only `CAP_NET_ADMIN` join.
const RTNLGRP_IPV4_MROUTE_R: u32 = 30;
const RTNLGRP_IPV6_MROUTE_R: u32 = 31;

/// `NLMSG_ALIGN`.
pub fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// A `struct sockaddr_nl`: family, pad, `nl_pid`, `nl_groups`.
pub fn encode_addr(portid: u32, groups: u32) -> Vec<u8> {
    let mut b = vec![0u8; SOCKADDR_NL_SIZE];
    b[..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
    b[4..8].copy_from_slice(&portid.to_le_bytes());
    b[8..12].copy_from_slice(&groups.to_le_bytes());
    b
}

/// `nl_pid` and `nl_groups` of a guest `struct sockaddr_nl`: `EINVAL` if
/// it is short or of another family.
pub fn parse_addr(b: &[u8]) -> Result<(u32, u32), Errno> {
    if b.len() < SOCKADDR_NL_SIZE || u16::from_le_bytes([b[0], b[1]]) != AF_NETLINK as u16 {
        return Err(Errno(EINVAL));
    }
    Ok((
        u32::from_le_bytes(b[4..8].try_into().unwrap()),
        u32::from_le_bytes(b[8..12].try_into().unwrap()),
    ))
}

/// `ffs`: the number of the lowest group in a mask, 0 for none.
fn first_group(mask: u32) -> u32 {
    if mask == 0 {
        0
    } else {
        mask.trailing_zeros() + 1
    }
}

/// `netlink_group_mask`: the mask of group number `group`.
fn group_mask(group: u32) -> u32 {
    if group == 0 { 0 } else { 1 << (group - 1) }
}

/// Port IDs the emulated sockets of this process are bound to
/// (`nl_table`, which is per protocol and system-wide in the kernel).
static PORTS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// The emulated sockets of this process: their level descriptors and
/// state, for [`forked`].
static LIVE: Mutex<Vec<Live>> = Mutex::new(Vec::new());

struct Live {
    reader: RawFd,
    writer: RawFd,
    inner: Weak<Mutex<Inner>>,
}

/// The state of an emulated `NETLINK_ROUTE` socket.
#[derive(Debug)]
pub struct Endpoint {
    /// The level's other end: a byte written here makes the socket's host
    /// descriptor readable.
    writer: OwnedFd,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    /// `nlk->portid` once bound.
    portid: Option<u32>,
    /// Groups joined: bit `g - 1` for group `g` (`nlk->groups`).
    groups: u64,
    /// `connect`'s destination port and group number.
    dst_portid: u32,
    dst_group: u32,
    /// Datagrams from the kernel, oldest first.
    queue: VecDeque<Vec<u8>>,
    /// The dump under way (`nlk->cb_running`).
    dump: Option<Dump>,
    max_recvmsg_len: usize,
    cap_ack: bool,
    ext_ack: bool,
    strict_chk: bool,
    no_enobufs: bool,
    pktinfo: bool,
    listen_all_nsid: bool,
    broadcast_error: bool,
    /// Whether the level is set.
    level: bool,
}

/// A dump under way (`nlk->cb`).
#[derive(Debug)]
struct Dump {
    /// Its messages not yet queued.
    messages: VecDeque<Vec<u8>>,
    /// The request's sequence number and the socket's port ID, which
    /// `NLMSG_DONE` carries.
    seq: u32,
    portid: u32,
    /// Whether `NLMSG_DONE` goes in a datagram of its own.
    split_done: bool,
    /// `nlk->dump_done_errno`: positive while the dump callback runs, then
    /// the result `NLMSG_DONE` carries.
    status: i32,
}

/// A datagram received: its bytes (all of it; the kernel sent it).
pub struct Datagram {
    pub bytes: Vec<u8>,
    /// Whether `NETLINK_PKTINFO` asks for its group (0) in the control
    /// data.
    pub pktinfo: bool,
}

/// Queues the next datagram of a running dump (`netlink_dump`): as many
/// messages as fit `max(NLMSG_GOODSIZE, max_recvmsg_len)` bytes, and
/// `NLMSG_DONE` once all went, if it fits too and the dump does not split
/// it off. Nothing while the receive queue has no room.
fn dump_step(inner: &mut Inner) {
    let room = NLMSG_GOODSIZE.max(inner.max_recvmsg_len);
    let queued: usize = inner.queue.iter().map(Vec::len).sum();
    let Some(dump) = inner.dump.as_mut() else {
        return;
    };
    if queued != 0 && queued + room >= MEM_DEFAULT {
        return;
    }
    let mut d = Vec::new();
    if dump.status > 0 {
        while let Some(m) = dump.messages.front() {
            if d.len() + m.len() > room {
                break;
            }
            d.extend_from_slice(&dump.messages.pop_front().unwrap());
        }
        dump.status = if dump.split_done {
            // rtnl_dumpit with RTNL_FLAG_DUMP_SPLIT_NLM_DONE, and
            // rtnl_dump_all: the bytes put, so NLMSG_DONE follows alone
            // (an empty datagram ends the dump).
            if d.is_empty() {
                dump.messages.clear();
            }
            d.len() as i32
        } else if dump.messages.is_empty() {
            0
        } else if d.is_empty() {
            // A message too big for a datagram ends the dump.
            dump.messages.clear();
            -EMSGSIZE
        } else {
            d.len() as i32
        };
    }
    let done_size = NLMSG_HDRLEN + 4;
    if dump.status > 0 || room - d.len() < done_size {
        inner.queue.push_back(d);
        return;
    }
    d.extend_from_slice(&route::done_message(dump.seq, dump.portid, dump.status));
    inner.queue.push_back(d);
    inner.dump = None;
}

impl Endpoint {
    /// A new socket: its host descriptor (a readiness level) and state.
    pub fn new() -> Result<(OwnedFd, Self), Errno> {
        let (reader, writer) = super::super::host::level_pair()?;
        let inner = Arc::new(Mutex::new(Inner::default()));
        LIVE.lock().unwrap().push(Live {
            reader: reader.as_raw_fd(),
            writer: writer.as_raw_fd(),
            inner: Arc::downgrade(&inner),
        });
        Ok((reader, Endpoint { writer, inner }))
    }

    /// `netlink_autobind`: the process's ID if free, else a negative one
    /// from a random start in `[S32_MIN, -4097]`, counting down.
    fn autobind(inner: &mut Inner, pid: i32) {
        use std::hash::{BuildHasher, Hasher};
        let mut ports = PORTS.lock().unwrap();
        let mut id = pid as u32;
        if ports.contains(&id) {
            let r = std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish();
            let span = (-4096i64 - i64::from(i32::MIN)) as u64;
            let mut rover = (i64::from(i32::MIN) + (r % span) as i64) as i32;
            loop {
                id = rover as u32;
                if !ports.contains(&id) {
                    break;
                }
                rover = if rover == i32::MIN { -4097 } else { rover - 1 };
            }
        }
        ports.push(id);
        inner.portid = Some(id);
    }

    /// `netlink_bind`: a bound socket keeps its port ID (another is
    /// `EINVAL`); joining the multicast-routing groups needs `admin`; the
    /// address's groups replace the first 32.
    pub fn bind(&self, b: &[u8], pid: i32, admin: bool) -> Result<(), Errno> {
        let (portid, groups) = parse_addr(b)?;
        let mut inner = self.inner.lock().unwrap();
        if inner.portid.is_some_and(|bound| portid != bound) {
            return Err(Errno(EINVAL));
        }
        let routing = group_mask(RTNLGRP_IPV4_MROUTE_R) | group_mask(RTNLGRP_IPV6_MROUTE_R);
        if groups & routing != 0 && !admin {
            return Err(Errno(EPERM));
        }
        if inner.portid.is_none() {
            if portid == 0 {
                Self::autobind(&mut inner, pid);
            } else {
                let mut ports = PORTS.lock().unwrap();
                if ports.contains(&portid) {
                    return Err(Errno(EADDRINUSE));
                }
                ports.push(portid);
                inner.portid = Some(portid);
            }
        }
        inner.groups = (inner.groups & !0xFFFF_FFFF) | u64::from(groups);
        Ok(())
    }

    /// `netlink_connect`: an unspecified family disconnects; sending to
    /// another port or a group needs privilege (`NL_CFG_F_NONROOT_SEND` is
    /// not set for `NETLINK_ROUTE`).
    pub fn connect(&self, b: &[u8], pid: i32, admin: bool) -> Result<(), Errno> {
        if b.len() < 2 {
            return Err(Errno(EINVAL));
        }
        let mut inner = self.inner.lock().unwrap();
        if u16::from_le_bytes([b[0], b[1]]) == 0 {
            inner.dst_portid = 0;
            inner.dst_group = 0;
            return Ok(());
        }
        let (portid, groups) = parse_addr(b)?;
        if (portid != 0 || groups != 0) && !admin {
            return Err(Errno(EPERM));
        }
        if inner.portid.is_none() {
            Self::autobind(&mut inner, pid);
        }
        inner.dst_portid = portid;
        inner.dst_group = first_group(groups);
        Ok(())
    }

    /// `netlink_getname`: the socket's own address (its first 32 groups),
    /// or its destination.
    pub fn name(&self, peer: bool) -> Vec<u8> {
        let inner = self.inner.lock().unwrap();
        if peer {
            encode_addr(inner.dst_portid, group_mask(inner.dst_group))
        } else {
            encode_addr(inner.portid.unwrap_or(0), inner.groups as u32)
        }
    }

    /// Sets or clears the level under `inner`, with `reader` the socket's
    /// host descriptor.
    fn update_level(&self, inner: &mut Inner, reader: &impl AsRawFd) {
        let on = !inner.queue.is_empty();
        if on == inner.level {
            return;
        }
        if on {
            super::super::host::put_byte(self.writer.as_raw_fd());
        } else {
            super::super::host::take_byte(reader.as_raw_fd());
        }
        inner.level = on;
    }

    /// `netlink_sendmsg` of `data` to the kernel (`to` the guest's
    /// destination address, if it gave one), from process `pid` with
    /// (`admin`) or without `CAP_NET_ADMIN`, within send buffer `sndbuf`;
    /// `host` describes the host to rtnetlink. `MSG_OOB` and the control
    /// data are the caller's.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &self,
        reader: &impl AsRawFd,
        data: &[u8],
        to: Option<&[u8]>,
        pid: i32,
        admin: bool,
        sndbuf: usize,
        host: &dyn Fn() -> route::Host,
    ) -> Result<usize, Errno> {
        if data.is_empty() {
            return Err(Errno(ENODATA));
        }
        let mut inner = self.inner.lock().unwrap();
        let (dst_portid, dst_group) = match to {
            Some(b) => {
                let (portid, groups) = parse_addr(b)?;
                let group = first_group(groups);
                if (portid != 0 || group != 0) && !admin {
                    return Err(Errno(EPERM));
                }
                (portid, group)
            }
            None => (inner.dst_portid, inner.dst_group),
        };
        if inner.portid.is_none() {
            Self::autobind(&mut inner, pid);
        }
        if data.len() > sndbuf.saturating_sub(32) {
            return Err(Errno(EMSGSIZE));
        }
        // netlink_broadcast to dst_group reaches no socket here; the
        // unicast follows, to the kernel or (not here) a user socket.
        let _ = dst_group;
        if dst_portid != 0 {
            return Err(Errno(ECONNREFUSED));
        }
        let portid = inner.portid.unwrap_or(0);
        let mut snapshot = None;
        // netlink_rcv_skb: each whole message in turn.
        let mut at = 0;
        while data.len() - at >= NLMSG_HDRLEN {
            let msg = &data[at..];
            let len = u32::from_le_bytes(msg[..4].try_into().unwrap()) as usize;
            if len < NLMSG_HDRLEN || len > msg.len() {
                break;
            }
            let msg = &msg[..len];
            let kind = u16::from_le_bytes([msg[4], msg[5]]);
            let flags = u16::from_le_bytes([msg[6], msg[7]]);
            let reply = if flags & NLM_F_REQUEST == 0 || kind < NLMSG_MIN_TYPE {
                route::Reply::Ack
            } else {
                route::request(snapshot.get_or_insert_with(host), msg, admin, portid)
            };
            let err = match reply {
                route::Reply::Error(e) => e,
                route::Reply::Unicast(ms) => {
                    inner.queue.extend(ms);
                    0
                }
                // netlink_dump_start: one dump at a time.
                route::Reply::Dump { .. } if inner.dump.is_some() => -EBUSY,
                route::Reply::Dump {
                    messages,
                    split_done,
                } => {
                    // The dump starts with its first datagram, and sends
                    // no acknowledgement (-EINTR).
                    let seq = u32::from_le_bytes(msg[8..12].try_into().unwrap());
                    inner.dump = Some(Dump {
                        messages: messages.into(),
                        seq,
                        portid,
                        split_done,
                        status: 1,
                    });
                    dump_step(&mut inner);
                    at += align(len).min(data.len() - at);
                    continue;
                }
                route::Reply::Ack => 0,
            };
            if flags & NLM_F_ACK != 0 || err != 0 {
                let ack = route::ack_message(msg, err, inner.cap_ack, portid);
                inner.queue.push_back(ack);
            }
            at += align(len).min(data.len() - at);
        }
        self.update_level(&mut inner, reader);
        Ok(data.len())
    }

    /// `netlink_recvmsg` without sleeping: the next datagram (or `None`),
    /// consumed unless `peek`; `len` is the guest's buffer size. A dump
    /// under way queues its next datagram once the queue is at most half
    /// full.
    pub fn recv(&self, reader: &impl AsRawFd, len: usize, peek: bool) -> Option<Datagram> {
        let mut inner = self.inner.lock().unwrap();
        let bytes = if peek {
            inner.queue.front().cloned()?
        } else {
            inner.queue.pop_front()?
        };
        inner.max_recvmsg_len = inner.max_recvmsg_len.max(len).min(MAX_RECVMSG_LEN);
        let queued: usize = inner.queue.iter().map(Vec::len).sum();
        if inner.dump.is_some() && queued <= MEM_DEFAULT / 2 {
            dump_step(&mut inner);
        }
        self.update_level(&mut inner, reader);
        Some(Datagram {
            bytes,
            pktinfo: inner.pktinfo,
        })
    }

    /// Whether a datagram is queued.
    pub fn readable(&self) -> bool {
        !self.inner.lock().unwrap().queue.is_empty()
    }

    /// `netlink_setsockopt` (`SOL_NETLINK`): the value is an int, 0 when
    /// shorter; unknown options are `ENOPROTOOPT`.
    pub fn setsockopt(&self, opt: i32, val: &[u8], admin: bool) -> Result<(), Errno> {
        let v = val
            .get(..4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
        let mut inner = self.inner.lock().unwrap();
        match opt {
            NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP => {
                if v == 0 || v > NGROUPS {
                    return Err(Errno(EINVAL));
                }
                let add = opt == NETLINK_ADD_MEMBERSHIP;
                if add && matches!(v, RTNLGRP_IPV4_MROUTE_R | RTNLGRP_IPV6_MROUTE_R) && !admin {
                    return Err(Errno(EPERM));
                }
                let bit = 1u64 << (v - 1);
                if add {
                    inner.groups |= bit;
                } else {
                    inner.groups &= !bit;
                }
            }
            NETLINK_PKTINFO => inner.pktinfo = v != 0,
            NETLINK_BROADCAST_ERROR => inner.broadcast_error = v != 0,
            NETLINK_NO_ENOBUFS => inner.no_enobufs = v != 0,
            // CAP_NET_BROADCAST.
            NETLINK_LISTEN_ALL_NSID if !admin => return Err(Errno(EPERM)),
            NETLINK_LISTEN_ALL_NSID => inner.listen_all_nsid = v != 0,
            NETLINK_CAP_ACK => inner.cap_ack = v != 0,
            NETLINK_EXT_ACK => inner.ext_ack = v != 0,
            NETLINK_GET_STRICT_CHK => inner.strict_chk = v != 0,
            _ => return Err(Errno(ENOPROTOOPT)),
        }
        Ok(())
    }

    /// `netlink_getsockopt` (`SOL_NETLINK`) into a buffer of `len` bytes:
    /// the bytes to copy out and the length to report. A flag is an int
    /// (`EINVAL` for a shorter buffer); `NETLINK_LIST_MEMBERSHIPS` is the
    /// group bitmap in 32-bit words, as many as fit, and reports the
    /// bitmap's whole length.
    pub fn getsockopt(&self, opt: i32, len: usize) -> Result<(Vec<u8>, u32), Errno> {
        let inner = self.inner.lock().unwrap();
        let flag = match opt {
            NETLINK_LIST_MEMBERSHIPS => {
                let words = NGROUPS.div_ceil(32) as usize;
                let out: Vec<u8> = (0..words.min(len / 4))
                    .flat_map(|i| ((inner.groups >> (32 * i)) as u32).to_le_bytes())
                    .collect();
                return Ok((out, (words * 4) as u32));
            }
            NETLINK_PKTINFO => inner.pktinfo,
            NETLINK_BROADCAST_ERROR => inner.broadcast_error,
            NETLINK_NO_ENOBUFS => inner.no_enobufs,
            NETLINK_LISTEN_ALL_NSID => inner.listen_all_nsid,
            NETLINK_CAP_ACK => inner.cap_ack,
            NETLINK_EXT_ACK => inner.ext_ack,
            NETLINK_GET_STRICT_CHK => inner.strict_chk,
            _ => return Err(Errno(ENOPROTOOPT)),
        };
        if len < 4 {
            return Err(Errno(EINVAL));
        }
        Ok((u32::from(flag).to_le_bytes().to_vec(), 4))
    }
}

impl Drop for Endpoint {
    /// Its port ID is free again.
    fn drop(&mut self) {
        let writer = self.writer.as_raw_fd();
        LIVE.lock().unwrap().retain(|l| l.writer != writer);
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = inner.portid {
            PORTS.lock().unwrap().retain(|&p| p != id);
        }
    }
}

/// In a new process: each emulated socket gets a readiness level of its
/// own, set as its copy of the queue says, since the level descriptors
/// inherited from the parent are shared with it.
pub fn forked() {
    let live = LIVE.lock().unwrap();
    for l in live.iter() {
        let Some(inner) = l.inner.upgrade() else {
            continue;
        };
        let Ok((reader, writer)) = super::super::host::level_pair() else {
            continue;
        };
        if super::super::host::replace_fd(l.reader, reader).is_err()
            || super::super::host::replace_fd(l.writer, writer).is_err()
        {
            continue;
        }
        if inner.lock().unwrap().level {
            super::super::host::put_byte(l.writer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::route::{Address, Host, Link};
    use super::*;

    fn links(n: i32) -> Host {
        let links = (1..=n)
            .map(|i| Link {
                index: i,
                name: format!("eth{i}"),
                kind: 1,
                flags: 0x1043,
                mtu: 1500,
                txqlen: 1000,
                operstate: route::IF_OPER_UP,
                carrier: true,
                address: vec![2, 0, 0, 0, 0, i as u8],
                broadcast: vec![0xFF; 6],
                stats: [0; 25],
            })
            .collect();
        let addresses = (1..=n)
            .map(|i| Address {
                index: i,
                family: AF_INET6,
                prefixlen: 64,
                flags: route::IFA_F_PERMANENT,
                scope: route::RT_SCOPE_LINK,
                local: [vec![0xFE, 0x80], vec![0; 13], vec![i as u8]].concat(),
                peer: None,
                broadcast: None,
                label: String::new(),
            })
            .collect();
        Host { links, addresses }
    }

    fn request(kind: u16, flags: u16, family: u8) -> Vec<u8> {
        let mut m = 17u32.to_le_bytes().to_vec();
        m.extend_from_slice(&kind.to_le_bytes());
        m.extend_from_slice(&flags.to_le_bytes());
        m.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, family]);
        m
    }

    /// The types of a datagram's messages.
    fn kinds(d: &[u8]) -> Vec<u16> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < d.len() {
            out.push(u16::from_le_bytes([d[at + 4], d[at + 5]]));
            at += align(u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize);
        }
        out
    }

    #[test]
    fn dumps_are_paced_as_netlink_dump_does() {
        let (reader, ep) = Endpoint::new().unwrap();
        let host = links(40);
        let dump = request(route::RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 0);
        ep.send(&reader, &dump, None, 1, false, MEM_DEFAULT, &|| {
            host.clone()
        })
        .unwrap();
        // One dump at a time.
        let again = request(route::RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 0);
        ep.send(&reader, &again, None, 1, false, MEM_DEFAULT, &|| {
            host.clone()
        })
        .unwrap();
        // The first datagram fits NLMSG_GOODSIZE.
        let first = ep.recv(&reader, 32768, false).unwrap().bytes;
        assert!(first.len() <= NLMSG_GOODSIZE);
        let n1 = kinds(&first).len();
        assert!(n1 > 1 && kinds(&first).iter().all(|&k| k == route::RTM_NEWLINK));
        let busy = ep.recv(&reader, 32768, false).unwrap().bytes;
        assert_eq!(kinds(&busy), [NLMSG_ERROR]);
        assert_eq!(i32::from_le_bytes(busy[16..20].try_into().unwrap()), -EBUSY);
        // The next is sized by the largest receive seen, then NLMSG_DONE
        // alone (RTNL_FLAG_DUMP_SPLIT_NLM_DONE).
        let second = ep.recv(&reader, 32768, false).unwrap().bytes;
        assert!(second.len() > NLMSG_GOODSIZE && second.len() <= MAX_RECVMSG_LEN);
        assert_eq!(n1 + kinds(&second).len(), 40);
        let done = ep.recv(&reader, 32768, false).unwrap().bytes;
        assert_eq!(kinds(&done), [NLMSG_DONE]);
        assert!(ep.recv(&reader, 32768, false).is_none());
        assert!(!ep.readable());
    }

    #[test]
    fn an_ipv6_dump_ends_with_its_last_datagram() {
        let (reader, ep) = Endpoint::new().unwrap();
        let host = links(3);
        let dump = request(route::RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, AF_INET6);
        ep.send(&reader, &dump, None, 1, false, MEM_DEFAULT, &|| {
            host.clone()
        })
        .unwrap();
        // A peek leaves the datagram and the dump as they are.
        let peeked = ep.recv(&reader, 100, true).unwrap().bytes;
        let d = ep.recv(&reader, 100, false).unwrap().bytes;
        assert_eq!(peeked, d);
        assert_eq!(
            kinds(&d),
            [
                route::RTM_NEWADDR,
                route::RTM_NEWADDR,
                route::RTM_NEWADDR,
                NLMSG_DONE
            ]
        );
        // An empty dump is its NLMSG_DONE.
        let none = Host::default();
        ep.send(&reader, &dump, None, 1, false, MEM_DEFAULT, &|| {
            none.clone()
        })
        .unwrap();
        assert_eq!(
            kinds(&ep.recv(&reader, 100, false).unwrap().bytes),
            [NLMSG_DONE]
        );
    }

    #[test]
    fn sends_check_their_destination_and_size() {
        let (reader, ep) = Endpoint::new().unwrap();
        let host = Host::default;
        let noop = {
            let mut m = 16u32.to_le_bytes().to_vec();
            m.extend_from_slice(&1u16.to_le_bytes());
            m.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_le_bytes());
            m.extend_from_slice(&[0; 8]);
            m
        };
        assert_eq!(
            ep.send(&reader, &[], None, 1, false, MEM_DEFAULT, &host),
            Err(Errno(ENODATA))
        );
        // To a group or another port: privileged; another port is none.
        let to = encode_addr(0, 4);
        assert_eq!(
            ep.send(&reader, &noop, Some(&to), 1, false, MEM_DEFAULT, &host),
            Err(Errno(EPERM))
        );
        // A multicast from the privileged still reaches the kernel.
        assert_eq!(
            ep.send(&reader, &noop, Some(&to), 1, true, MEM_DEFAULT, &host),
            Ok(16)
        );
        assert!(ep.recv(&reader, 100, false).is_some());
        let other = encode_addr(77, 0);
        assert_eq!(
            ep.send(&reader, &noop, Some(&other), 1, true, MEM_DEFAULT, &host),
            Err(Errno(ECONNREFUSED))
        );
        assert_eq!(
            ep.send(&reader, &noop, Some(&to[..11]), 1, true, MEM_DEFAULT, &host),
            Err(Errno(EINVAL))
        );
        // Larger than the send buffer allows.
        assert_eq!(
            ep.send(&reader, &noop, None, 1, false, 16 + 31, &host),
            Err(Errno(EMSGSIZE))
        );
        assert_eq!(
            ep.send(&reader, &noop, None, 1, false, 16 + 32, &host),
            Ok(16)
        );
    }
}

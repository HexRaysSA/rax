//! i386 sockets against Linux 6.19 on x86-64 (`net/compat.c`,
//! `net/socket.c`, `net/core/sock.c`, `net/core/dev_ioctl.c`): `struct
//! compat_msghdr` and `struct compat_mmsghdr`, control messages with a
//! 12-byte `struct compat_cmsghdr` padded to 4 bytes
//! (`cmsghdr_from_user_compat_to_kern`, `put_cmsg_compat`,
//! `scm_detach_fds_compat`), the `socketcall` multiplexer, the old socket
//! timeouts as `struct old_timeval32`, and the interface requests'
//! `struct compat_ifconf` and 32-byte `struct compat_ifreq`.

use super::super::harness::Harness;
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const STREAM: u64 = 1;
const DGRAM: u64 = 2;
const SOL_SOCKET: u32 = 1;
const SCM_RIGHTS: u32 = 1;
const MSG_CTRUNC: u32 = 0x8;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn read(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn pair(h: &mut Harness, kind: u64) -> (u64, u64) {
    let at = h.scratch + 0xF00;
    h.ok(Sysno::Socketpair, &[AF_UNIX, kind, 0, at]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

/// A `struct compat_msghdr` at `at`: name, iovec, control, flags.
fn msghdr(h: &Harness, at: u64, name: (u32, u32), iov: (u32, u32), ctl: (u32, u32)) {
    put(
        h,
        at,
        &words(&[name.0, name.1, iov.0, iov.1, ctl.0, ctl.1, 0]),
    );
}

#[test]
fn msghdr_and_rights_use_the_32_bit_layouts() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (a, b) = pair(&mut h, DGRAM);
    let m = h.scratch;
    let (hdr, iov, data, ctl) = (m, m + 0x40, m + 0x80, m + 0x100);
    put(&h, data, b"hello");
    put(&h, iov, &words(&[data as u32, 5]));
    // One descriptor in a 16-byte compat_cmsghdr message.
    let fd = h.ok(Sysno::Dup, &[a]);
    put(&h, ctl, &words(&[16, SOL_SOCKET, SCM_RIGHTS, fd as u32]));
    msghdr(&h, hdr, (0, 0), (iov as u32, 1), (ctl as u32, 16));
    assert_eq!(h.call(Sysno::Sendmsg, &[a, hdr, 0]), 5);
    // Receive into 5 bytes of data and 16 of control data.
    put(&h, data, &[0; 8]);
    put(&h, ctl, &[0xEE; 24]);
    msghdr(&h, hdr, (0, 0), (iov as u32, 1), (ctl as u32, 16));
    assert_eq!(h.call(Sysno::Recvmsg, &[b, hdr, 0]), 5);
    assert_eq!(read(&h, data, 5), b"hello");
    // The received descriptor's message, 16 bytes, and msg_controllen and
    // msg_flags at the compat offsets (20, 24).
    let got = read(&h, ctl, 24);
    assert_eq!(&got[..12], &words(&[16, SOL_SOCKET, SCM_RIGHTS])[..]);
    let newfd = u32::from_le_bytes(got[12..16].try_into().unwrap());
    assert!(h.proc.state.fds.get(newfd as i32).is_ok());
    assert_eq!(&got[16..], &[0xEE; 8]);
    assert_eq!((u32_at(&h, hdr + 20), u32_at(&h, hdr + 24)), (16, 0));
    // Room for no descriptor: MSG_CTRUNC, nothing written.
    put(&h, ctl, &words(&[16, SOL_SOCKET, SCM_RIGHTS, fd as u32]));
    msghdr(&h, hdr, (0, 0), (iov as u32, 1), (ctl as u32, 16));
    h.ok(Sysno::Sendmsg, &[a, hdr, 0]);
    msghdr(&h, hdr, (0, 0), (iov as u32, 1), (ctl as u32, 12));
    assert_eq!(h.call(Sysno::Recvmsg, &[b, hdr, 0]), 5);
    assert_eq!(
        (u32_at(&h, hdr + 20), u32_at(&h, hdr + 24)),
        (0, MSG_CTRUNC)
    );
}

#[test]
fn compat_control_data_is_checked_before_the_data_is_sent() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (a, b) = pair(&mut h, DGRAM);
    let m = h.scratch;
    let (hdr, iov, data, ctl) = (m, m + 0x40, m + 0x80, m + 0x100);
    put(&h, iov, &words(&[data as u32, 1]));
    // A message too short for its header, a trailing byte after a whole
    // one, and control data without a header: EINVAL, and nothing is sent.
    for (bytes, len) in [
        (words(&[11, SOL_SOCKET, SCM_RIGHTS]), 12),
        ([words(&[12, SOL_SOCKET, SCM_RIGHTS]), vec![0]].concat(), 13),
        (vec![0; 8], 8),
    ] {
        put(&h, ctl, &bytes);
        msghdr(&h, hdr, (0, 0), (iov as u32, 1), (ctl as u32, len));
        assert_eq!(h.err(Sysno::Sendmsg, &[a, hdr, 0]), EINVAL);
    }
    assert_eq!(h.err(Sysno::Recvfrom, &[b, data, 1, 0x40, 0, 0]), EAGAIN);
}

#[test]
fn mmsghdr_entries_are_32_bytes_with_msg_len_at_28() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (a, b) = pair(&mut h, DGRAM);
    let m = h.scratch;
    let (vec, iov, data) = (m, m + 0x100, m + 0x200);
    put(&h, data, b"abcdef");
    put(&h, iov, &words(&[data as u32, 3, data as u32 + 3, 3]));
    // Two entries: 28-byte headers, each followed by msg_len.
    let mut v = words(&[0, 0, iov as u32, 1, 0, 0, 0, 0xEEEE_EEEE]);
    v.extend(words(&[0, 0, iov as u32 + 8, 1, 0, 0, 0, 0xEEEE_EEEE]));
    put(&h, vec, &v);
    assert_eq!(h.call(Sysno::Sendmmsg, &[a, vec, 2, 0]), 2);
    assert_eq!((u32_at(&h, vec + 28), u32_at(&h, vec + 60)), (3, 3));
    put(&h, data, &[0; 6]);
    // recvmmsg_time32: an old_timespec32 timeout, written back.
    let ts = m + 0x300;
    put(&h, ts, &words(&[5, 0]));
    assert_eq!(h.call(Sysno::Recvmmsg, &[b, vec, 2, 0, ts]), 2);
    assert_eq!(read(&h, data, 6), b"abcdef");
    assert!(u32_at(&h, ts) <= 5 && u32_at(&h, ts + 4) < 1_000_000_000);
}

#[test]
fn socketcall_reads_32_bit_arguments() {
    const SYS_SOCKETPAIR: u64 = 8;
    const SYS_SEND: u64 = 9;
    const SYS_RECV: u64 = 10;
    let mut h = Harness::new(LinuxAbi::I386);
    let m = h.scratch;
    let (args, sv, buf) = (m, m + 0x40, m + 0x80);
    put(
        &h,
        args,
        &words(&[AF_UNIX as u32, STREAM as u32, 0, sv as u32]),
    );
    assert_eq!(h.call(Sysno::Socketcall, &[SYS_SOCKETPAIR, args]), 0);
    let (a, b) = (u32_at(&h, sv), u32_at(&h, sv + 4));
    put(&h, buf, b"xyz");
    put(&h, args, &words(&[a, buf as u32, 3, 0]));
    assert_eq!(h.call(Sysno::Socketcall, &[SYS_SEND, args]), 3);
    put(&h, args, &words(&[b, buf as u32 + 8, 8, 0]));
    assert_eq!(h.call(Sysno::Socketcall, &[SYS_RECV, args]), 3);
    assert_eq!(read(&h, buf + 8, 3), b"xyz");
    // The call number first, then the arguments.
    assert_eq!(h.err(Sysno::Socketcall, &[0, args]), EINVAL);
    assert_eq!(h.err(Sysno::Socketcall, &[21, 0x10]), EINVAL);
    assert_eq!(h.err(Sysno::Socketcall, &[SYS_RECV, 0x10]), EFAULT);
}

#[test]
fn old_timeouts_are_old_timeval32_and_new_ones_are_not() {
    const SO_RCVTIMEO_OLD: u64 = 20;
    const SO_RCVTIMEO_NEW: u64 = 66;
    let mut h = Harness::new(LinuxAbi::I386);
    let (a, _) = pair(&mut h, STREAM);
    let (val, len) = (h.scratch, h.scratch + 0x40);
    put(&h, val, &words(&[1, 500_000]));
    assert_eq!(
        h.err(Sysno::Setsockopt, &[a, 1, SO_RCVTIMEO_OLD, val, 7]),
        EINVAL
    );
    assert_eq!(
        h.call(Sysno::Setsockopt, &[a, 1, SO_RCVTIMEO_OLD, val, 8]),
        0
    );
    put(&h, val, &[0xEE; 16]);
    put(&h, len, &16u32.to_le_bytes());
    assert_eq!(
        h.call(Sysno::Getsockopt, &[a, 1, SO_RCVTIMEO_OLD, val, len]),
        0
    );
    assert_eq!(u32_at(&h, len), 8);
    assert_eq!(
        read(&h, val, 16),
        [words(&[1, 500_000]), vec![0xEE; 8]].concat()
    );
    // SO_RCVTIMEO_NEW is struct __kernel_sock_timeval for every caller.
    put(&h, len, &16u32.to_le_bytes());
    assert_eq!(
        h.call(Sysno::Getsockopt, &[a, 1, SO_RCVTIMEO_NEW, val, len]),
        0
    );
    assert_eq!(read(&h, val, 16), words(&[1, 0, 500_000, 0]));
}

#[test]
fn interface_requests_use_compat_ifconf_and_32_byte_requests() {
    const SIOCGIFCONF: u64 = 0x8912;
    const SIOCGIFINDEX: u64 = 0x8933;
    const SIOCGIFSLAVE: u64 = 0x8929;
    let mut h = Harness::new(LinuxAbi::I386);
    let fd = h.ok(Sysno::Socket, &[AF_INET, DGRAM, 0]);
    let m = h.scratch;
    let (conf, buf, ifr) = (m, m + 0x100, m + 0x800);
    // No buffer: the length of every entry, 32 bytes each.
    put(&h, conf, &words(&[0, 0]));
    assert_eq!(h.call(Sysno::Ioctl, &[fd, SIOCGIFCONF, conf]), 0);
    let total = u32_at(&h, conf);
    assert!(total > 0 && total % 32 == 0, "{total}");
    // Room for one entry and a half: one written.
    put(&h, conf, &words(&[48, buf as u32]));
    assert_eq!(h.call(Sysno::Ioctl, &[fd, SIOCGIFCONF, conf]), 0);
    assert_eq!(u32_at(&h, conf), 32);
    // SIOCGIFINDEX of the first entry's device writes back 32 bytes only.
    let mut r = read(&h, buf, 16);
    r.resize(40, 0xAA);
    put(&h, ifr, &r);
    assert_eq!(h.call(Sysno::Ioctl, &[fd, SIOCGIFINDEX, ifr]), 0);
    assert!(u32_at(&h, ifr + 16) > 0);
    assert_eq!(read(&h, ifr + 32, 8), [0xAA; 8]);
    // compat_sock_ioctl_trans has no case for SIOCGIFSLAVE.
    assert_eq!(h.err(Sysno::Ioctl, &[fd, SIOCGIFSLAVE, ifr]), ENOTTY);
}

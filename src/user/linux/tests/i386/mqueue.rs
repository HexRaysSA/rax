//! i386 POSIX message queues against Linux 6.19 on x86-64 (the
//! `CONFIG_COMPAT` part of `ipc/mqueue.c`): `struct compat_mq_attr` (32-bit
//! `long`s, which `compat_sys_mq_open` reads only to create a queue),
//! `struct compat_sigevent`, and `mq_timedsend_time32` and
//! `mq_timedreceive_time32` with the `*_time64` forms beside them.

use super::super::harness::Harness;
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::*;

const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_NONBLOCK: u64 = 0o4000;
const SIGEV_SIGNAL: u32 = 0;
/// Never mapped (below `mmap_min_addr`).
const BAD: u64 = 0x10;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn read(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

#[test]
fn attributes_are_compat_mq_attr() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = h.scratch;
    let (name, attr, out) = (m, m + 0x100, m + 0x200);
    put(&h, name, b"attr32\0");
    // Without O_CREAT the attributes are not read: the look-up fails first.
    assert_eq!(h.err(Sysno::MqOpen, &[name, O_RDWR, 0, BAD]), ENOENT);
    let create = O_RDWR | O_CREAT;
    assert_eq!(h.err(Sysno::MqOpen, &[name, create, 0o600, BAD]), EFAULT);
    // mq_maxmsg and mq_msgsize at 4 and 8.
    put(&h, attr, &words(&[0, u32::MAX, 64, 0, 0, 0, 0, 0]));
    assert_eq!(h.err(Sysno::MqOpen, &[name, create, 0o600, attr]), EINVAL);
    put(&h, attr, &words(&[0, 3, 64, 0, 0, 0, 0, 0]));
    let fd = h.ok(Sysno::MqOpen, &[name, create, 0o600, attr]);
    // mq_getsetattr writes 32 bytes, the reserved words zeroed.
    put(&h, out, &[0xEE; 40]);
    assert_eq!(h.call(Sysno::MqGetsetattr, &[fd, 0, out]), 0);
    assert_eq!(
        read(&h, out, 40),
        [words(&[0, 3, 64, 0, 0, 0, 0, 0]), vec![0xEE; 8]].concat()
    );
    // New flags from the 32-bit mq_flags; the old ones reported.
    put(&h, attr, &words(&[O_NONBLOCK as u32, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(h.call(Sysno::MqGetsetattr, &[fd, attr, out]), 0);
    assert_eq!(u32_at(&h, out), 0);
    assert_eq!(h.call(Sysno::MqGetsetattr, &[fd, 0, out]), 0);
    assert_eq!(u32_at(&h, out), O_NONBLOCK as u32);
    put(&h, attr, &words(&[1, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(h.err(Sysno::MqGetsetattr, &[fd, attr, 0]), EINVAL);
    h.ok(Sysno::MqUnlink, &[name]);
}

#[test]
fn send_and_receive_timeouts_are_old_timespec32() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = h.scratch;
    let (name, msg, ts, prio) = (m, m + 0x100, m + 0x200, m + 0x300);
    put(&h, name, b"time32\0");
    let flags = O_RDWR | O_CREAT | O_NONBLOCK;
    let fd = h.ok(Sysno::MqOpen, &[name, flags, 0o600, 0]);
    put(&h, msg, b"hi");
    // mq_timedsend reads { 1, 1000 }; a struct __kernel_timespec there
    // would be invalid.
    put(&h, ts, &words(&[1, 1000, 0x7FFF_FFFF, 0x7FFF_FFFF]));
    assert_eq!(h.call(Sysno::MqTimedsend, &[fd, msg, 2, 5, ts]), 0);
    put(&h, ts, &words(&[0, 1_000_000_000]));
    assert_eq!(h.err(Sysno::MqTimedsend, &[fd, msg, 2, 5, ts]), EINVAL);
    // mq_timedreceive_time64 clears the padding above tv_nsec.
    put(&h, ts, &words(&[1, 0, 1000, 0xFFFF_FFFF]));
    let buf = msg + 0x10;
    assert_eq!(
        h.call(Sysno::MqTimedreceiveTime64, &[fd, buf, 8192, prio, ts]),
        2
    );
    assert_eq!((read(&h, buf, 2), u32_at(&h, prio)), (b"hi".to_vec(), 5));
    // An empty queue: EAGAIN, once the timeout is found valid.
    put(&h, ts, &words(&[1, 1000]));
    assert_eq!(
        h.err(Sysno::MqTimedreceive, &[fd, buf, 8192, prio, ts]),
        EAGAIN
    );
    put(&h, ts, &words(&[0, 0, 1_000_000_000, 0]));
    assert_eq!(
        h.err(Sysno::MqTimedsendTime64, &[fd, msg, 2, 5, ts]),
        EINVAL
    );
    h.ok(Sysno::MqUnlink, &[name]);
}

#[test]
fn notifications_read_compat_sigevent() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = h.scratch;
    let (name, ev, msg) = (m, m + 0x100, m + 0x200);
    put(&h, name, b"note32\0");
    let fd = h.ok(Sysno::MqOpen, &[name, O_RDWR | O_CREAT, 0o600, 0]);
    h.proc.threads[0].sigmask = sigmask(SIGUSR2);
    // struct compat_sigevent: sival_int, sigev_signo, sigev_notify.
    let signo = SIGUSR2 as u32;
    put(&h, ev, &words(&[0xfeed, signo, 3, 0]));
    assert_eq!(h.err(Sysno::MqNotify, &[fd, ev]), EINVAL);
    put(&h, ev, &words(&[0xfeed, signo, SIGEV_SIGNAL, 0]));
    h.ok(Sysno::MqNotify, &[fd, ev]);
    put(&h, msg, b"x");
    assert_eq!(h.call(Sysno::MqTimedsend, &[fd, msg, 1, 0, 0]), 0);
    let info = crate::user::linux::signal::deliver::dequeue_signal(
        &mut h.proc.state,
        &mut h.proc.threads[0],
        0,
    )
    .unwrap();
    assert_eq!((info.signo, info.value()), (SIGUSR2, 0xfeed));
    h.ok(Sysno::MqUnlink, &[name]);
}

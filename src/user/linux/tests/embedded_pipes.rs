use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::open::{O_CLOEXEC, O_EXCL, O_NONBLOCK};
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::SIGPIPE;
use crate::user::linux::syscall::ready::{ev, raw_fd};
use crate::user::linux::syscall::thread::cf::*;

const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_SETPIPE_SZ: u64 = 1031;
const F_GETPIPE_SZ: u64 = 1032;
const FIONREAD: u64 = 0x541b;
const THREAD_FLAGS: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

fn pipe(h: &mut Harness, flags: u32) -> (u64, u64) {
    let at = h.scratch;
    h.ok(Sysno::Pipe2, &[at, u64::from(flags)]);
    let mut pair = [0; 8];
    h.proc.space().read(at, &mut pair).unwrap();
    let reader = u32::from_le_bytes(pair[..4].try_into().unwrap());
    let writer = u32::from_le_bytes(pair[4..].try_into().unwrap());
    for fd in [reader, writer] {
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        assert!(raw_fd(&file).is_none());
    }
    (reader.into(), writer.into())
}

fn poll_request(h: &Harness, at: u64, fd: u64, mask: u32) {
    let mut request = [0; 8];
    request[..4].copy_from_slice(&(fd as u32).to_le_bytes());
    request[4..6].copy_from_slice(&(mask as u16).to_le_bytes());
    h.proc.space().write_raw(at, &request).unwrap();
}

fn poll_result(h: &Harness, at: u64) -> u32 {
    let mut result = [0; 2];
    h.proc.space().read(at + 6, &mut result).unwrap();
    u16::from_le_bytes(result).into()
}

fn epoll_add(h: &mut Harness, epoll: u64, fd: u64) {
    // The event's data is zero in both packed and aligned ABI layouts.
    let at = h.scratch + 64;
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&(ev::IN | (1 << 31)).to_le_bytes());
    h.proc.space().write_raw(at, &bytes).unwrap();
    h.ok(Sysno::EpollCtl, &[epoll, 1, fd, at]);
}

#[test]
fn closed_linux_pipe_descriptors_and_eof() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        let at = h.scratch;
        let buf = at + 24;
        h.proc.space().write_raw(buf, b"guest pipe").unwrap();
        assert_eq!(h.err(Sysno::Pipe2, &[at, 1u64 << 31]), EINVAL);
        assert_eq!(h.err(Sysno::Pipe2, &[at, O_EXCL.into()]), ENOPKG);
        assert_eq!(h.err(Sysno::Pipe2, &[0, 0]), EFAULT);
        h.proc.state.rlimits[7].0 = 4;
        assert_eq!(h.err(Sysno::Pipe2, &[at, 0]), EMFILE);
        h.proc.state.rlimits[7].0 = 1024;
        let (rd, wr) = pipe(&mut h, O_CLOEXEC | O_NONBLOCK);
        assert_eq!((rd, wr), (3, 4));

        let fcntl = |h: &mut Harness, fd, cmd| h.ok(Sysno::Fcntl, &[fd, cmd, 0]);
        assert_eq!(fcntl(&mut h, rd, F_GETFD), 1);
        assert_eq!(fcntl(&mut h, wr, F_GETFD), 1);
        assert_eq!(fcntl(&mut h, rd, F_GETFL), u64::from(O_NONBLOCK));
        assert_eq!(fcntl(&mut h, wr, F_GETFL), u64::from(O_NONBLOCK) | 1);
        assert_eq!(h.err(Sysno::Read, &[rd, buf, 1]), EAGAIN);
        assert_eq!(h.err(Sysno::Read, &[wr, buf, 1]), EBADF);
        assert_eq!(h.err(Sysno::Write, &[rd, buf, 1]), EBADF);
        let copy = h.ok(Sysno::Dup, &[wr]);
        assert_eq!(fcntl(&mut h, copy, F_GETFD), 0);
        h.ok(Sysno::Fcntl, &[copy, F_SETFL, 0]);
        assert_eq!(fcntl(&mut h, wr, F_GETFL), 1);

        assert_eq!(h.ok(Sysno::Write, &[copy, buf, 10]), 10);
        for fd in [rd, wr] {
            h.ok(Sysno::Ioctl, &[fd, FIONREAD, at]);
            let mut queued = [0; 4];
            h.proc.space().read(at, &mut queued).unwrap();
            assert_eq!(u32::from_le_bytes(queued), 10);
        }
        h.ok(Sysno::Close, &[copy]);
        h.ok(Sysno::Close, &[wr]);
        assert_eq!(h.err(Sysno::Read, &[rd, 0, 10]), EFAULT);
        poll_request(&h, at, rd, ev::IN);
        let deadline = at + 64;
        h.proc.space().write_raw(deadline, &[0; 16]).unwrap();
        assert_eq!(h.ok(Sysno::Ppoll, &[at, 1, deadline, 0, 8]), 1);
        assert_eq!(poll_result(&h, at), ev::IN | ev::HUP);
        assert_eq!(h.ok(Sysno::Read, &[rd, at + 48, 32]), 10);
        let mut actual = [0; 10];
        h.proc.space().read(at + 48, &mut actual).unwrap();
        assert_eq!(&actual, b"guest pipe");
        assert_eq!(h.ok(Sysno::Read, &[rd, buf, 1]), 0);

        let (rd, wr) = pipe(&mut h, 0);
        h.ok(Sysno::Close, &[rd]);
        assert_eq!(h.err(Sysno::Write, &[wr, buf, 1]), EPIPE);
        let info = h.proc.threads[0].pending.dequeue(0).unwrap();
        assert_eq!(info.signo, SIGPIPE);
    });
}

#[test]
fn closed_linux_pipe_capacity_and_packet_boundaries() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        let (rd, wr) = pipe(&mut h, O_NONBLOCK);
        let buf = h.anon(P * 3, 3, false);
        h.fill(buf, P * 3, b'a');
        assert_eq!(h.ok(Sysno::Fcntl, &[rd, F_GETPIPE_SZ, 0]), 16 * P);
        assert_eq!(h.ok(Sysno::Fcntl, &[rd, F_SETPIPE_SZ, P + 1]), 2 * P);
        assert_eq!(h.ok(Sysno::Fcntl, &[wr, F_GETPIPE_SZ, 0]), 2 * P);
        assert_eq!(h.ok(Sysno::Write, &[wr, buf, 2 * P - 1]), 2 * P - 1);
        assert_eq!(h.err(Sysno::Fcntl, &[wr, F_SETPIPE_SZ, P]), EBUSY);
        assert_eq!(h.err(Sysno::Write, &[wr, buf, 2]), EAGAIN);
        assert_eq!(h.ok(Sysno::Write, &[wr, buf, 1]), 1);
        assert_eq!(h.err(Sysno::Write, &[wr, buf, 1]), EAGAIN);
        assert_eq!(h.ok(Sysno::Read, &[rd, buf, P]), P);
        assert_eq!(h.ok(Sysno::Write, &[wr, buf, 2 * P]), P);
        assert_eq!(h.ok(Sysno::Read, &[rd, buf, 3 * P]), 2 * P);
        assert_eq!(h.ok(Sysno::Fcntl, &[wr, F_SETPIPE_SZ, 0]), P);
        assert_eq!(
            h.err(Sysno::Fcntl, &[wr, F_SETPIPE_SZ, (1 << 20) + 1]),
            EPERM
        );

        let direct = abi.open_flags().direct;
        let (rd, wr) = pipe(&mut h, O_NONBLOCK | direct);
        assert_eq!(h.ok(Sysno::Fcntl, &[rd, F_GETFL, 0]), u64::from(O_NONBLOCK));
        assert_eq!(
            h.ok(Sysno::Fcntl, &[wr, F_GETFL, 0]),
            u64::from(O_NONBLOCK | direct) | 1
        );
        h.proc.space().write_raw(buf, b"firstsecond").unwrap();
        assert_eq!(h.ok(Sysno::Write, &[wr, buf, 5]), 5);
        assert_eq!(h.ok(Sysno::Write, &[wr, buf + 5, 6]), 6);
        assert_eq!(h.ok(Sysno::Read, &[rd, buf + P, 2]), 2);
        assert_eq!(h.ok(Sysno::Read, &[rd, buf + P + 2, P]), 6);
        let mut actual = [0; 8];
        h.proc.space().read(buf + P, &mut actual).unwrap();
        assert_eq!(&actual, b"fisecond");
        assert_eq!(h.err(Sysno::Read, &[rd, buf, 1]), EAGAIN);
    });
}

#[test]
fn closed_linux_pipe_capacity_reservations_follow_endpoint_lifetimes() {
    let mut h = Harness::embedded(LinuxAbi::Aarch64);
    let capacity = 1 << 20;
    let mut endpoints = Vec::new();
    for _ in 0..64 {
        let (rd, wr) = pipe(&mut h, 0);
        assert_eq!(h.ok(Sysno::Fcntl, &[rd, F_SETPIPE_SZ, capacity]), capacity);
        endpoints.push((rd, wr));
    }
    let at = h.scratch;
    assert_eq!(h.err(Sysno::Pipe2, &[at, 0]), ENFILE);
    let (rd, wr) = endpoints.pop().unwrap();
    h.ok(Sysno::Close, &[rd]);
    assert_eq!(h.err(Sysno::Pipe2, &[at, 0]), ENFILE);
    h.ok(Sysno::Close, &[wr]);
    assert_eq!(pipe(&mut h, 0), (rd, wr));
}

#[test]
fn closed_linux_pipe_guest_wakeups_and_write_continuations() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        let (rd, wr) = pipe(&mut h, 0);
        assert_eq!(h.ok(Sysno::Clone, &[THREAD_FLAGS, 0, 0, 0, 0]), 101);
        let at = h.scratch + 16;
        let buf = h.anon(P * 3, 3, false);
        h.fill(buf, P, b'a');
        h.fill(buf + P, P, b'b');
        assert_eq!(h.start(0, Sysno::Read, &[rd, at, 1]), None);
        assert_eq!(h.proc.wake_sleepers(), 0);
        assert_eq!(h.start(1, Sysno::Write, &[wr, buf, 1]), Some(1));
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), 1);
        assert_eq!(h.byte(at), b'a');

        assert_eq!(h.ok(Sysno::Fcntl, &[wr, F_SETPIPE_SZ, P]), P);
        assert_eq!(h.start(0, Sysno::Write, &[wr, buf, 2 * P]), None);
        assert_eq!(h.proc.wake_sleepers(), 0);
        assert_eq!(
            h.start(1, Sysno::Read, &[rd, buf + 2 * P, P]),
            Some(P as i64)
        );
        assert_eq!(h.byte(buf + 2 * P), b'a');
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), (2 * P) as i64);
        assert_eq!(h.ok(Sysno::Read, &[rd, buf + 2 * P, P]), P);
        assert_eq!(h.byte(buf + 2 * P), b'b');

        assert_eq!(h.start(0, Sysno::Read, &[rd, at, 1]), None);
        assert_eq!(h.start(1, Sysno::Close, &[wr]), Some(0));
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), 0);
    });
}

#[test]
fn closed_linux_pipe_poll_and_nested_epoll_wake_without_host_handles() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        let (rd, wr) = pipe(&mut h, 0);
        let at = h.scratch + 24;
        let buf = h.scratch + 128;
        let child = h.ok(Sysno::EpollCreate1, &[0]);
        let parent = h.ok(Sysno::EpollCreate1, &[0]);
        epoll_add(&mut h, child, rd);
        epoll_add(&mut h, parent, child);
        assert_eq!(h.ok(Sysno::Clone, &[THREAD_FLAGS, 0, 0, 0, 0]), 101);
        poll_request(&h, at, parent, ev::IN);
        assert_eq!(h.start(0, Sysno::Ppoll, &[at, 1, 0, 0, 8]), None);
        assert!(
            h.proc.threads[0]
                .blocked
                .as_ref()
                .unwrap()
                .wait
                .fds
                .is_empty()
        );
        h.proc.space().write_raw(buf, b"off").unwrap();
        assert_eq!(h.start(1, Sysno::Write, &[wr, buf, 3]), Some(3));
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), 1);
        assert_eq!(poll_result(&h, at), ev::IN);
        assert_eq!(h.ok(Sysno::EpollPwait, &[parent, buf, 1, 0, 0, 8]), 1);
        assert_eq!(h.ok(Sysno::EpollPwait, &[child, buf, 1, 0, 0, 8]), 1);
        assert_eq!(h.ok(Sysno::Read, &[rd, buf, 3]), 3);

        assert_eq!(
            h.start(
                0,
                Sysno::EpollPwait,
                &[child, buf, 1, u32::MAX.into(), 0, 8]
            ),
            None
        );
        assert_eq!(h.start(1, Sysno::Close, &[wr]), Some(0));
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), 1);
        assert_eq!(h.byte(buf), ev::HUP as u8);
    });
}

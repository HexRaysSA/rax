//! i386 descriptor controls against Linux 6.19 on x86-64: `compat_sys_ioctl`
//! (`fs/ioctl.c`) looks up the descriptor first, runs `do_vfs_ioctl`, then
//! the file's `compat_ioctl` (`compat_ptr_ioctl` for pidfds and `epoll`,
//! `inotify_ioctl` for inotify, none for a `timerfd`), and `epoll_pwait2`
//! reads a `struct __kernel_timespec` whose padding a 32-bit caller may leave
//! set (`compat_sys_epoll_pwait2`, `get_timespec64`).

use super::super::harness::Harness;
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

#[test]
fn compat_ioctl_runs_the_files_whose_compat_handler_is_the_native_one() {
    let mut h = Harness::new(LinuxAbi::I386);
    let at = h.scratch + 0x100;
    // The descriptor before the command.
    assert_eq!(h.err(Sysno::Ioctl, &[999, 0x1234, 0]), EBADF);
    // PIDFD_GET_INFO through compat_ptr_ioctl: struct pidfd_info, pid @16.
    let pid = h.proc.state.pid as u64;
    let pidfd = h.ok(Sysno::PidfdOpen, &[pid, 0]);
    put(&h, at, &[0; 80]);
    assert_eq!(h.call(Sysno::Ioctl, &[pidfd, 0xC050_FF0B, at]), 0);
    assert_eq!(u32_at(&h, at + 16), pid as u32);
    // inotify_ioctl: FIONREAD and INOTIFY_IOC_SETNEXTWD.
    let ino = h.ok(Sysno::InotifyInit1, &[0]);
    assert_eq!(h.call(Sysno::Ioctl, &[ino, 0x4004_4900, 7]), 0);
    // A timerfd has no compat_ioctl: TFD_IOC_SET_TICKS is ENOTTY, while
    // do_vfs_ioctl's FIOCLEX works on it as on any file.
    let tfd = h.ok(Sysno::TimerfdCreate, &[1, 0]);
    put(&h, at, &1u64.to_le_bytes());
    assert_eq!(h.err(Sysno::Ioctl, &[tfd, 0x4008_5400, at]), ENOTTY);
    assert_eq!(h.call(Sysno::Ioctl, &[tfd, 0x5451, 0]), 0);
    assert!(h.proc.state.fds.get(tfd as i32).unwrap().cloexec);
}

#[test]
fn epoll_pwait2_ignores_the_padding_above_the_nanoseconds() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (events, ts) = (h.scratch + 0x100, h.scratch + 0x200);
    let ep = h.ok(Sysno::EpollCreate1, &[0]);
    let words: Vec<u8> = [0u32, 0, 1000, 0xFFFF_FFFF]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    put(&h, ts, &words);
    assert_eq!(h.call(Sysno::EpollPwait2, &[ep, events, 1, ts, 0, 8]), 0);
    let words: Vec<u8> = [0u32, 0, 1_000_000_000, 0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    put(&h, ts, &words);
    assert_eq!(
        h.err(Sysno::EpollPwait2, &[ep, events, 1, ts, 0, 8]),
        EINVAL
    );
}

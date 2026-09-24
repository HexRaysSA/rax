//! `/proc/<pid>/fdinfo` (`fs/proc/fd.c` `seq_show` and the files'
//! `show_fdinfo` operations, Linux 6.19), read through the system calls.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const AT_FDCWD: u64 = -100i64 as u64;
const F_GETFL: u64 = 3;
const O_CLOEXEC: u64 = 0o2000000;

/// The contents of guest file `path`, or its `errno`.
fn read(h: &mut Harness, path: &str) -> Result<String, i32> {
    let at = h.scratch + 0x400;
    let mut p = path.as_bytes().to_vec();
    p.push(0);
    h.proc.state.space.write_raw(at, &p).unwrap();
    let fd = h.call(Sysno::Openat, &[AT_FDCWD, at, 0, 0]);
    if fd < 0 {
        return Err(-fd as i32);
    }
    let buf = h.scratch + 0x600;
    let n = h.ok(Sysno::Read, &[fd as u64, buf, 0x800]);
    h.ok(Sysno::Close, &[fd as u64]);
    let mut out = vec![0u8; n as usize];
    h.proc.state.space.read(buf, &mut out).unwrap();
    Ok(String::from_utf8(out).unwrap())
}

/// The entries of `/proc/self/fdinfo` other than `.` and `..`: descriptor
/// numbers and `d_type`s.
fn listing(h: &mut Harness) -> Vec<(i32, u8)> {
    let at = h.scratch + 0x400;
    h.proc
        .state
        .space
        .write_raw(at, b"/proc/self/fdinfo\0")
        .unwrap();
    let dir = h.ok(Sysno::Openat, &[AT_FDCWD, at, 0o200000, 0]);
    let buf = h.scratch + 0x800;
    let n = h.ok(Sysno::Getdents64, &[dir, buf, 0x400]) as usize;
    h.ok(Sysno::Close, &[dir]);
    let mut b = vec![0u8; n];
    h.proc.state.space.read(buf, &mut b).unwrap();
    let mut out = Vec::new();
    let mut at = 0;
    while at < n {
        let reclen = u16::from_le_bytes([b[at + 16], b[at + 17]]) as usize;
        let name = &b[at + 19..at + reclen];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap()];
        if let Ok(fd) = std::str::from_utf8(name).unwrap().parse() {
            out.push((fd, b[at + 18]));
        }
        at += reclen;
    }
    out
}

fn fdinfo(h: &mut Harness, fd: u64) -> String {
    read(h, &format!("/proc/self/fdinfo/{fd}")).unwrap()
}

/// The inode number `fstat` reports for `fd` (`st_ino` is the second
/// word on every ABI).
fn ino(h: &mut Harness, fd: u64) -> u64 {
    let st = h.scratch + 0xc00;
    h.ok(Sysno::Fstat, &[fd, st]);
    let mut b = [0u8; 8];
    h.proc.state.space.read(st + 8, &mut b).unwrap();
    u64::from_le_bytes(b)
}

#[test]
fn every_descriptor_shows_its_position_flags_mount_and_inode() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let fd = h.file("fdinfo", 64, b'x', O_CLOEXEC);
        h.ok(Sysno::Lseek, &[fd, 5, 0]);
        let flags = h.ok(Sysno::Fcntl, &[fd, F_GETFL]) | O_CLOEXEC;
        let want = format!(
            "pos:\t5\nflags:\t0{flags:o}\nmnt_id:\t1\nino:\t{}\n",
            ino(&mut h, fd)
        );
        assert_eq!(fdinfo(&mut h, fd), want, "{abi:?}");
        // A pipe: no position, pipefs.
        let fds = h.scratch + 0x100;
        h.ok(Sysno::Pipe2, &[fds, 0o4000]);
        let mut b = [0u8; 4];
        h.proc.state.space.read(fds, &mut b).unwrap();
        let r = u32::from_le_bytes(b) as u64;
        let text = fdinfo(&mut h, r);
        assert!(
            text.starts_with("pos:\t0\nflags:\t04000\nmnt_id:\t5\n"),
            "{text}"
        );
        // The directory lists the descriptors as regular files; a closed
        // one has no entry.
        assert!(listing(&mut h).contains(&(r as i32, 8)), "{abi:?}");
        h.ok(Sysno::Close, &[r]);
        assert!(!listing(&mut h).iter().any(|&(n, _)| n == r as i32));
        assert_eq!(read(&mut h, &format!("/proc/self/fdinfo/{r}")), Err(ENOENT));
    });
}

#[test]
fn anonymous_files_add_their_own_lines() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    // An eventfd: the counter in 16 columns of hex, its ID (the smallest
    // free one), and whether it is a semaphore.
    let ev = h.ok(Sysno::Eventfd2, &[5, 1]);
    let text = fdinfo(&mut h, ev);
    let id: u32 = text
        .lines()
        .find_map(|l| l.strip_prefix("eventfd-id: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        text.ends_with(&format!(
            "eventfd-count:                5\neventfd-id: {id}\neventfd-semaphore: 1\n"
        )),
        "{text}"
    );
    assert!(text.contains("\nmnt_id:\t6\n"));
    // A signalfd: its mask as render_sigset_t prints it, without SIGKILL.
    let set = h.scratch + 0x100;
    h.proc
        .state
        .space
        .write_raw(set, &((1u64 << 9) | (1 << 11) | (1 << 8)).to_le_bytes())
        .unwrap();
    let sf = h.ok(Sysno::Signalfd4, &[u64::MAX, set, 8, 0]);
    assert!(fdinfo(&mut h, sf).ends_with("sigmask:\t0000000000000a00\n"));
    // A timerfd, disarmed.
    let tf = h.ok(Sysno::TimerfdCreate, &[1, 0]);
    assert!(fdinfo(&mut h, tf).ends_with(
        "clockid: 1\nticks: 0\nsettime flags: 00\nit_value: (0, 0)\nit_interval: (0, 0)\n"
    ));
    // An epoll instance: one line per item, with the events it asked for
    // plus EPOLLERR | EPOLLHUP, its data, and its file's position, inode,
    // and device.
    let ep = h.ok(Sysno::EpollCreate1, &[0]);
    let e = h.scratch + 0x200;
    let mut item = (0x1u32 | 1 << 31).to_le_bytes().to_vec();
    item.extend_from_slice(&[0; 4]);
    item.extend_from_slice(&0x1234u64.to_le_bytes());
    h.proc.state.space.write_raw(e, &item).unwrap();
    h.ok(Sysno::EpollCtl, &[ep, 1, ev, e]);
    let want = format!(
        "tfd: {ev:8} events: {:8x} data: {:16x}  pos:0 ino:{:x} sdev:10\n",
        0x1u32 | 1 << 31 | 0x18,
        0x1234,
        ino(&mut h, ev)
    );
    assert!(fdinfo(&mut h, ep).ends_with(&want), "{want}");
}

#[test]
fn a_pidfd_shows_its_task_until_it_is_gone() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let me = h.proc.state.pid;
    let fd = h.ok(Sysno::PidfdOpen, &[me as u64, 0]);
    assert!(
        fdinfo(&mut h, fd).ends_with(&format!(
            "mnt_id:\t3\nino:\t{me}\nPid:\t{me}\nNSpid:\t{me}\n"
        )),
        "pidfs, one inode per task"
    );
    let tid = h.ok(
        Sysno::Clone,
        &[
            crate::user::linux::syscall::thread::cf::CLONE_VM
                | crate::user::linux::syscall::thread::cf::CLONE_FS
                | crate::user::linux::syscall::thread::cf::CLONE_FILES
                | crate::user::linux::syscall::thread::cf::CLONE_SIGHAND
                | crate::user::linux::syscall::thread::cf::CLONE_THREAD,
            0,
            0,
            0,
            0,
        ],
    ) as i32;
    let tfd = h.ok(Sysno::PidfdOpen, &[tid as u64, 0o200]);
    assert!(fdinfo(&mut h, tfd).ends_with(&format!("Pid:\t{tid}\nNSpid:\t{tid}\n")));
    let w = h.index_of(tid);
    h.start(w, Sysno::Exit, &[0]);
    assert!(fdinfo(&mut h, tfd).ends_with("Pid:\t-1\nNSpid:\t-1\n"));
}

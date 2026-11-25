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

fn open_dir(h: &mut Harness, path: &str) -> u64 {
    let at = h.scratch + 0x400;
    let mut name = path.as_bytes().to_vec();
    name.push(0);
    h.proc.state.space.write_raw(at, &name).unwrap();
    h.ok(Sysno::Openat, &[AT_FDCWD, at, 0, 0])
}

/// The name, type, and offset of each `linux_dirent64` in one read.
fn listing(h: &mut Harness, dir: u64, count: u64) -> Vec<(String, u8, u64)> {
    let buf = h.scratch + 0x800;
    let n = h.ok(Sysno::Getdents64, &[dir, buf, count]) as usize;
    let mut b = vec![0u8; n];
    h.proc.state.space.read(buf, &mut b).unwrap();
    let mut out = Vec::new();
    let mut at = 0;
    while at < n {
        let reclen = u16::from_le_bytes([b[at + 16], b[at + 17]]) as usize;
        let name = &b[at + 19..at + reclen];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap()];
        let position = u64::from_le_bytes(b[at + 8..at + 16].try_into().unwrap());
        out.push((
            String::from_utf8(name.to_vec()).unwrap(),
            b[at + 18],
            position,
        ));
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
        // Keep the directory open so its own descriptor cannot reuse the
        // pipe descriptor under test after close.
        let dir = open_dir(&mut h, "/proc/self/fdinfo");
        let pipe = r.to_string();
        assert!(
            listing(&mut h, dir, 0x400)
                .iter()
                .any(|(name, kind, _)| { name == &pipe && *kind == 8 }),
            "{abi:?}"
        );
        h.ok(Sysno::Close, &[r]);
        h.ok(Sysno::Lseek, &[dir, 0, 0]);
        assert!(
            !listing(&mut h, dir, 0x400)
                .iter()
                .any(|(name, _, _)| name == &pipe)
        );
        assert_eq!(read(&mut h, &format!("/proc/self/fdinfo/{r}")), Err(ENOENT));
        h.ok(Sysno::Close, &[dir]);
    });
}

#[test]
fn descriptor_directories_follow_live_slots_and_share_slot_cookies() {
    use crate::user::linux::fs::fd::dt::{DT_DIR, DT_LNK, DT_REG};

    each_abi(|abi| {
        for (path, kind) in [
            ("/proc/self/fd", DT_LNK),
            ("/proc/thread-self/fdinfo", DT_REG),
        ] {
            let mut h = Harness::embedded(abi);
            let dir = open_dir(&mut h, path);
            let duplicate = h.ok(Sysno::Fcntl, &[dir, 0, 0]); // F_DUPFD
            let name = dir.to_string();
            let duplicate_name = duplicate.to_string();
            assert_eq!(dir, 3);
            assert_eq!(duplicate, 4);
            assert_eq!(h.err(Sysno::Getdents64, &[dir, h.scratch, 23]), EINVAL);
            assert_eq!(
                listing(&mut h, dir, 48),
                [(".".into(), DT_DIR, 1), ("..".into(), DT_DIR, 2)]
            );
            assert_eq!(h.ok(Sysno::Lseek, &[duplicate, 0, 1]), 2);
            assert_eq!(h.ok(Sysno::Fcntl, &[0, 0, 20]), 20);
            assert_eq!(
                listing(&mut h, duplicate, 120),
                [
                    ("0".into(), kind, 3),
                    ("1".into(), kind, 4),
                    ("2".into(), kind, 5),
                    (name, kind, 6),
                    (duplicate_name, kind, 22),
                ],
            );
            assert!(fdinfo(&mut h, dir).starts_with("pos:\t22\n"));
            h.ok(Sysno::Close, &[20]);
            assert_eq!(h.ok(Sysno::Fcntl, &[0, 0, 40]), 40);
            assert_eq!(listing(&mut h, dir, 0x400), [("40".into(), kind, 66)]);
            assert_eq!(h.ok(Sysno::Fcntl, &[0, 0, 50]), 50);
            assert!(listing(&mut h, duplicate, 0x400).is_empty());
            assert_eq!(h.ok(Sysno::Fcntl, &[0, 0, 100]), 100);
            assert_eq!(
                listing(&mut h, duplicate, 0x400),
                [("100".into(), kind, 130)]
            );
            assert_eq!(h.ok(Sysno::Lseek, &[dir, 0, 2]), 0);
            assert_eq!(h.ok(Sysno::Lseek, &[duplicate, 51, 0]), 51);
            assert_eq!(listing(&mut h, dir, 24), [("50".into(), kind, 102)]);
            assert_eq!(h.ok(Sysno::Lseek, &[dir, 0, 1]), 102);
        }
    });
}

#[test]
fn descriptor_directory_retains_its_original_owner_when_the_table_splits() {
    let mut h = Harness::embedded(LinuxAbi::Aarch64);
    let dir = open_dir(&mut h, "/proc/self/fd");
    let mut shared = h.proc.state.fds.share();
    let description = shared.file(dir as i32).unwrap();
    h.proc.state.fds.unshare();
    assert_eq!(h.ok(Sysno::Fcntl, &[0, 0, 40]), 40);
    let input = shared.file(0).unwrap();
    shared.install_at(50, input, false, 64).unwrap();

    {
        let state = description.state.lock().unwrap();
        let owner = state.proc_dir.as_ref().unwrap();
        assert_eq!(owner.slots().unwrap().next(5), (40, true));
        assert_eq!(owner.slots().unwrap().next(41), (64, false));
    }
    drop(h);
    let state = description.state.lock().unwrap();
    assert!(state.proc_dir.as_ref().unwrap().slots().is_err());
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

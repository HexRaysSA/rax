//! Resolution of the synthesized `/proc` (`fs/proc/base.c`, `fs/proc/fd.c`,
//! Linux 6.19): the entries that come and go with the process's
//! descriptors and threads exist exactly while those do, whatever the
//! host's own `/proc` (the emulator's, on a Linux host) holds.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::syscall::thread::cf::*;

const AT_FDCWD: u64 = -100i64 as u64;

/// `readlinkat` of guest path `path`: the result register.
fn readlink(h: &mut Harness, path: &str) -> i64 {
    let (at, buf) = (h.scratch + 0x400, h.scratch + 0x800);
    let mut p = path.as_bytes().to_vec();
    p.push(0);
    h.proc.state.space.write_raw(at, &p).unwrap();
    h.call(Sysno::Readlinkat, &[AT_FDCWD, at, buf, 256])
}

/// `openat` of guest path `path` for reading: the result register.
fn open(h: &mut Harness, path: &str) -> i64 {
    let at = h.scratch + 0x400;
    let mut p = path.as_bytes().to_vec();
    p.push(0);
    h.proc.state.space.write_raw(at, &p).unwrap();
    h.call(Sysno::Openat, &[AT_FDCWD, at, 0, 0])
}

#[test]
fn a_closed_descriptor_or_an_exited_thread_has_no_proc_entry() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.state.pid;
        // Descriptors the emulator itself has open on the host are not the
        // guest's.
        for fd in [3, 5, 9, 17] {
            if h.proc.state.fds.get(fd).is_ok() {
                continue;
            }
            for dir in ["/proc/self", "/proc/thread-self", &format!("/proc/{me}")] {
                let enoent = -(ENOENT as i64);
                assert_eq!(
                    readlink(&mut h, &format!("{dir}/fd/{fd}")),
                    enoent,
                    "{abi:?} {dir} {fd}"
                );
                assert_eq!(open(&mut h, &format!("{dir}/fd/{fd}")), enoent);
                assert_eq!(open(&mut h, &format!("{dir}/fd/{fd}/x")), enoent);
            }
        }
        // A thread that exited.
        let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        let tid = h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]) as i32;
        let status = format!("/proc/self/task/{tid}/status");
        let fd = open(&mut h, &status);
        assert!(fd >= 0);
        h.ok(Sysno::Close, &[fd as u64]);
        let w = h.index_of(tid);
        h.start(w, Sysno::Exit, &[0]);
        assert_eq!(open(&mut h, &status), -(ENOENT as i64));
        assert_eq!(
            open(&mut h, &format!("/proc/{tid}/status")),
            -(ENOENT as i64)
        );
    });
}

//! File locks (`fs/locks.c`, `fs/fcntl.c`, Linux 6.19), driven through
//! the system calls in one host process. Conflicts with other processes,
//! which these tests could observe only by forking the test process (whose
//! children would hold other tests' descriptors), are checked by the
//! `locks` fixture program.

use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::fs::locks;

const AT_FDCWD: u64 = -100i64 as u64;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_PATH: u64 = 0o10000000;

const LOCK_SH: u64 = 1;
const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;
const LOCK_UN: u64 = 8;
const LOCK_MAND: u64 = 32;

const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_GETLK: u64 = 5;
const F_SETLK: u64 = 6;
#[cfg(target_os = "linux")]
const F_OFD_GETLK: u64 = 36;
const F_OFD_SETLK: u64 = 37;

const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

/// The tests that take POSIX locks run one at a time: the lock registry is
/// the host process's.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A host file for one test, removed when dropped.
struct TempFile(PathBuf);

impl TempFile {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rax-locks-t-{tag}-{}", std::process::id()));
        std::fs::write(&p, [0u8; 64]).unwrap();
        TempFile(p)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn open(h: &mut Harness, path: &Path, flags: u64) -> u64 {
    let mut s = path.as_os_str().as_bytes().to_vec();
    s.push(0);
    h.proc.state.space.write_raw(h.scratch, &s).unwrap();
    h.ok(Sysno::Openat, &[AT_FDCWD, h.scratch, flags, 0])
}

/// Writes a guest `struct flock` at scratch + 0x800 and returns its address.
fn flock_at(h: &Harness, kind: i16, whence: i16, start: i64, len: i64, pid: i32) -> u64 {
    let mut b = [0u8; 32];
    b[0..2].copy_from_slice(&kind.to_le_bytes());
    b[2..4].copy_from_slice(&whence.to_le_bytes());
    b[8..16].copy_from_slice(&start.to_le_bytes());
    b[16..24].copy_from_slice(&len.to_le_bytes());
    b[24..28].copy_from_slice(&pid.to_le_bytes());
    let at = h.scratch + 0x800;
    h.proc.state.space.write_raw(at, &b).unwrap();
    at
}

/// The guest `struct flock` at `at`: (type, whence, start, len, pid).
fn read_flock(h: &Harness, at: u64) -> (i16, i16, i64, i64, i32) {
    let mut b = [0u8; 32];
    h.proc.state.space.read(at, &mut b).unwrap();
    (
        i16::from_le_bytes([b[0], b[1]]),
        i16::from_le_bytes([b[2], b[3]]),
        i64::from_le_bytes(b[8..16].try_into().unwrap()),
        i64::from_le_bytes(b[16..24].try_into().unwrap()),
        i32::from_le_bytes(b[24..28].try_into().unwrap()),
    )
}

fn setlk(h: &mut Harness, fd: u64, cmd: u64, kind: i16, start: i64, len: i64) -> i64 {
    let at = flock_at(h, kind, 0, start, len, 0);
    h.call(Sysno::Fcntl, &[fd, cmd, at])
}

/// The POSIX-lock registry's view of guest descriptor `fd`'s inode.
fn posix_state(h: &Harness, fd: u64) -> Option<usize> {
    let file = h.proc.state.fds.file(fd as i32).unwrap();
    locks::posix_state(locks::host_fd(&file).unwrap())
}

#[test]
fn flock_checks_the_command_then_the_descriptor() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = TempFile::new(&format!("flock-args-{abi:?}"));
        // The command comes first, even for a closed descriptor.
        assert_eq!(h.err(Sysno::Flock, &[99, LOCK_SH | LOCK_EX]), EINVAL);
        assert_eq!(h.err(Sysno::Flock, &[99, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Flock, &[99, LOCK_SH]), EBADF);
        // LOCK_MAND requests are ignored.
        assert_eq!(h.call(Sysno::Flock, &[99, LOCK_MAND | LOCK_SH]), 0);
        // fdget does not see O_PATH descriptors, even to unlock.
        let p = open(&mut h, &f.0, O_PATH);
        assert_eq!(h.err(Sysno::Flock, &[p, LOCK_UN]), EBADF);
        let r = open(&mut h, &f.0, O_RDONLY);
        assert_eq!(h.call(Sysno::Flock, &[r, LOCK_EX | LOCK_NB]), 0);
        assert_eq!(h.call(Sysno::Flock, &[r, LOCK_UN]), 0);
    });
}

#[test]
fn flock_locks_belong_to_the_description() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let f = TempFile::new("flock-owner");
    let a = open(&mut h, &f.0, O_RDONLY);
    let b = open(&mut h, &f.0, O_RDONLY);
    assert_eq!(h.call(Sysno::Flock, &[a, LOCK_EX]), 0);
    // Another description of the same file conflicts, in the same process.
    assert_eq!(h.err(Sysno::Flock, &[b, LOCK_EX | LOCK_NB]), EAGAIN);
    assert_eq!(h.err(Sysno::Flock, &[b, LOCK_SH | LOCK_NB]), EAGAIN);
    // A duplicate is the same description: it may unlock.
    let c = h.ok(Sysno::Dup, &[a]);
    assert_eq!(h.call(Sysno::Flock, &[c, LOCK_UN]), 0);
    assert_eq!(h.call(Sysno::Flock, &[b, LOCK_SH | LOCK_NB]), 0);
    assert_eq!(h.call(Sysno::Flock, &[a, LOCK_SH | LOCK_NB]), 0);
    // A conversion that would wait fails, and loses the shared lock
    // (flock_lock_inode removes it first): the other description may now
    // take an exclusive lock.
    assert_eq!(h.err(Sysno::Flock, &[a, LOCK_EX | LOCK_NB]), EAGAIN);
    assert_eq!(h.call(Sysno::Flock, &[b, LOCK_EX | LOCK_NB]), 0);
    // Closing the last descriptor of a description releases its lock.
    assert_eq!(h.err(Sysno::Flock, &[a, LOCK_SH | LOCK_NB]), EAGAIN);
    h.ok(Sysno::Close, &[b]);
    assert_eq!(h.call(Sysno::Flock, &[a, LOCK_EX | LOCK_NB]), 0);
}

#[test]
fn flock_waits_for_the_lock() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let f = TempFile::new("flock-wait");
    let a = open(&mut h, &f.0, O_RDWR);
    // Another description holds an exclusive lock for a while.
    let other = std::fs::File::open(&f.0).unwrap();
    // SAFETY: flock on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX) }, 0);
    let holder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        drop(other);
    });
    assert_eq!(h.err(Sysno::Flock, &[a, LOCK_SH | LOCK_NB]), EAGAIN);
    // Without LOCK_NB the thread sleeps until the holder closes.
    assert_eq!(h.start(0, Sysno::Flock, &[a, LOCK_SH]), None);
    assert_eq!(h.call(Sysno::Flock, &[a, LOCK_SH]), 0);
    holder.join().unwrap();
}

#[test]
fn record_lock_arguments_are_checked_in_the_kernels_order() {
    let _serial = serial();
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = TempFile::new(&format!("setlk-args-{abi:?}"));
        let r = open(&mut h, &f.0, O_RDONLY);
        let w = open(&mut h, &f.0, O_WRONLY);
        let p = open(&mut h, &f.0, O_PATH);
        let cmd =
            |h: &mut Harness, fd: u64, cmd: u64, at: u64| h.call(Sysno::Fcntl, &[fd, cmd, at]);
        let e = |x: i32| -(x as i64);
        let ok = flock_at(&h, F_RDLCK, 0, 0, 10, 0);
        assert_eq!(cmd(&mut h, 99, F_SETLK, ok), e(EBADF));
        // check_fcntl_cmd: an O_PATH descriptor, before the structure.
        assert_eq!(cmd(&mut h, p, F_SETLK, 8), e(EBADF));
        assert_eq!(cmd(&mut h, p, F_GETLK, 8), e(EBADF));
        assert!(h.call(Sysno::Fcntl, &[p, F_GETFL, 0]) >= 0);
        assert_eq!(cmd(&mut h, p, F_SETFL, 0), e(EBADF));
        assert_eq!(cmd(&mut h, r, F_SETLK, 8), e(EFAULT));
        // flock64_to_posix_lock: the whence, the start, the length.
        let at = flock_at(&h, F_RDLCK, 3, 0, 10, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), e(EINVAL));
        let at = flock_at(&h, F_RDLCK, 0, -1, 10, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), e(EINVAL));
        let at = flock_at(&h, F_RDLCK, 2, i64::MAX, 10, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), e(EOVERFLOW), "{abi:?}");
        let at = flock_at(&h, F_RDLCK, 0, 10, i64::MAX, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), e(EOVERFLOW));
        let at = flock_at(&h, F_RDLCK, 0, 5, -6, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), e(EINVAL));
        // Then the type, then the access mode.
        let at = flock_at(&h, 7, 0, 0, 10, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), e(EINVAL));
        let at = flock_at(&h, F_WRLCK, 0, 0, 10, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), e(EBADF));
        let at = flock_at(&h, F_RDLCK, 0, 0, 10, 0);
        assert_eq!(cmd(&mut h, w, F_SETLK, at), e(EBADF));
        assert_eq!(cmd(&mut h, r, F_SETLK, at), 0);
        // A negative length locks the bytes before the start.
        let at = flock_at(&h, F_RDLCK, 0, 5, -5, 0);
        assert_eq!(cmd(&mut h, r, F_SETLK, at), 0);
        // F_GETLK tests only read and write locks.
        let at = flock_at(&h, F_UNLCK, 0, 0, 10, 0);
        assert_eq!(cmd(&mut h, r, F_GETLK, at), e(EINVAL));
        let at = flock_at(&h, F_WRLCK, 1, 0, 10, 77);
        assert_eq!(cmd(&mut h, r, F_GETLK, at), 0);
        // No conflict with the process's own locks: only the type changes.
        assert_eq!(read_flock(&h, at), (F_UNLCK, 1, 0, 10, 77));
    });
}

#[test]
fn closing_any_descriptor_releases_the_processes_record_locks() {
    let _serial = serial();
    let mut h = Harness::new(LinuxAbi::X86_64);
    let f = TempFile::new("setlk-close");
    let a = open(&mut h, &f.0, O_RDWR);
    assert_eq!(posix_state(&h, a), None);
    // An unlock notes nothing.
    assert_eq!(setlk(&mut h, a, F_SETLK, F_UNLCK, 0, 0), 0);
    assert_eq!(posix_state(&h, a), None);
    // The close of a duplicate of the locking descriptor.
    assert_eq!(setlk(&mut h, a, F_SETLK, F_WRLCK, 0, 0), 0);
    assert_eq!(posix_state(&h, a), Some(0));
    let c = h.ok(Sysno::Dup, &[a]);
    h.ok(Sysno::Close, &[c]);
    assert_eq!(posix_state(&h, a), None, "close of a duplicate");
    // The close of another description of the file.
    assert_eq!(setlk(&mut h, a, F_SETLK, F_WRLCK, 0, 0), 0);
    let b = open(&mut h, &f.0, O_RDONLY);
    h.ok(Sysno::Close, &[b]);
    assert_eq!(posix_state(&h, a), None, "close of another description");
    // dup3 over another descriptor of the file.
    assert_eq!(setlk(&mut h, a, F_SETLK, F_WRLCK, 0, 0), 0);
    let b = open(&mut h, &f.0, O_RDONLY);
    let x = open(&mut h, &f.0, O_RDONLY);
    h.ok(Sysno::Dup3, &[x, b, 0]);
    assert_eq!(posix_state(&h, a), None, "dup3 over a descriptor");
}

#[test]
fn unmapping_keeps_the_mappings_descriptor_until_the_locks_go() {
    let _serial = serial();
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let f = TempFile::new("setlk-mmap");
    let a = open(&mut h, &f.0, O_RDWR);
    assert_eq!(setlk(&mut h, a, F_SETLK, F_WRLCK, 0, 0), 0);
    // A shared and a private mapping each keep a descriptor of the file;
    // closing it at munmap would release the process's locks, so it is kept.
    const PROT_READ: u64 = 1;
    const MAP_SHARED: u64 = 1;
    const MAP_PRIVATE: u64 = 2;
    for (kind, kept) in [(MAP_SHARED, 1), (MAP_PRIVATE, 2)] {
        let m = h.map_file(a, 4096, PROT_READ, kind);
        assert_eq!(h.byte(m), 0);
        h.ok(Sysno::Munmap, &[m, 4096]);
        assert_eq!(posix_state(&h, a), Some(kept), "munmap of kind {kind}");
    }
    // The guest's close releases the locks and the kept descriptors.
    let b = h.ok(Sysno::Dup, &[a]);
    h.ok(Sysno::Close, &[a]);
    assert_eq!(posix_state(&h, b), None);
}

#[cfg(target_os = "linux")]
#[test]
fn ofd_locks_belong_to_the_description() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let f = TempFile::new("ofd");
    let a = open(&mut h, &f.0, O_RDWR);
    let b = open(&mut h, &f.0, O_RDWR);
    // l_pid must be zero.
    let at = flock_at(&h, F_WRLCK, 0, 0, 10, 1);
    assert_eq!(h.err(Sysno::Fcntl, &[a, F_OFD_SETLK, at]), EINVAL);
    assert_eq!(setlk(&mut h, a, F_OFD_SETLK, F_WRLCK, 0, 10), 0);
    // Another description conflicts, in the same process; F_OFD_GETLK
    // reports an OFD owner as PID -1.
    assert_eq!(
        setlk(&mut h, b, F_OFD_SETLK, F_RDLCK, 5, 1),
        -(EAGAIN as i64)
    );
    let at = flock_at(&h, F_RDLCK, 0, 0, 0, 0);
    assert_eq!(h.call(Sysno::Fcntl, &[b, F_OFD_GETLK, at]), 0);
    assert_eq!(read_flock(&h, at), (F_WRLCK, 0, 0, 10, -1));
    // An OFD lock is no POSIX lock: nothing is noted, and closing another
    // description leaves it.
    assert_eq!(posix_state(&h, a), None);
    h.ok(Sysno::Close, &[b]);
    let b = open(&mut h, &f.0, O_RDWR);
    assert_eq!(
        setlk(&mut h, b, F_OFD_SETLK, F_RDLCK, 5, 1),
        -(EAGAIN as i64)
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn ofd_locks_are_unavailable_on_this_host() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let f = TempFile::new("ofd");
    let a = open(&mut h, &f.0, O_RDWR);
    assert_eq!(
        setlk(&mut h, a, F_OFD_SETLK, F_WRLCK, 0, 10),
        -(EINVAL as i64)
    );
}

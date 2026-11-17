use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{ProcessLease, record_lock};

#[test]
fn nested_calls_preserve_the_outer_lease_and_reject_another_space() {
    let lease = ProcessLease::new().unwrap();
    let other = ProcessLease::new().unwrap();
    lease.check_fork_ready().unwrap();
    let value = lease
        .with(|| {
            assert_eq!(
                lease.check_fork_ready().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            let entered = AtomicBool::new(false);
            let error = other
                .with(|| entered.store(true, Ordering::Relaxed))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(!entered.load(Ordering::Relaxed));
            lease.with(|| 77).unwrap()
        })
        .unwrap();
    assert_eq!(value, 77);
    lease.check_fork_ready().unwrap();
    other.with(|| ()).unwrap();
}

#[test]
fn host_threads_cannot_execute_owner_transactions_concurrently() {
    let lease = Arc::new(ProcessLease::new().unwrap());
    let active = AtomicBool::new(false);
    let count = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..500 {
                    lease
                        .with(|| {
                            assert!(!active.swap(true, Ordering::SeqCst));
                            let previous = count.load(Ordering::Relaxed);
                            lease
                                .with(|| count.store(previous + 1, Ordering::Relaxed))
                                .unwrap();
                            assert!(active.swap(false, Ordering::SeqCst));
                        })
                        .unwrap();
                }
            });
        }
    });
    assert_eq!(count.load(Ordering::Relaxed), 4000);
    lease.check_fork_ready().unwrap();
}

#[test]
fn panic_releases_the_kernel_lock_and_poison_prevents_continuation() {
    if crate::user::test_fork::isolated(
        "user::mm::process_lease::tests::panic_releases_the_kernel_lock_and_poison_prevents_continuation",
    ) {
        return;
    }
    let lease = ProcessLease::new().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = lease.with(|| panic!("owner transaction interrupted"));
    }));
    assert!(result.is_err());
    assert!(super::ACTIVE.get().is_none());
    assert_eq!(lease.with(|| ()).unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(
        lease.check_fork_ready().unwrap_err().kind(),
        io::ErrorKind::Other
    );
    let fd = lease.file.as_raw_fd();
    // SAFETY: the mutex has unwound and is unlocked, and ACTIVE is empty.
    // The child only makes a nonblocking fcntl call and _exit, with no Rust
    // mutexes, allocations, or inherited destructors.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
    if pid == 0 {
        child_exit(if native_try_lock(fd) == b'Y' { 23 } else { 86 });
    }
    wait_child(pid);
}

#[test]
fn caught_nested_panic_aborts_the_outer_transaction_and_releases_the_lease() {
    if crate::user::test_fork::isolated(
        "user::mm::process_lease::tests::caught_nested_panic_aborts_the_outer_transaction_and_releases_the_lease",
    ) {
        return;
    }
    let lease = ProcessLease::new().unwrap();
    let entered = AtomicBool::new(false);
    let outer = lease.with(|| {
        let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = lease.with(|| panic!("nested owner transaction interrupted"));
        }));
        assert!(nested.is_err());
        assert!(
            lease
                .with(|| entered.store(true, Ordering::Relaxed))
                .is_err()
        );
        77
    });
    assert!(outer.is_err());
    assert!(!entered.load(Ordering::Relaxed));
    assert!(super::ACTIVE.get().is_none());
    assert!(lease.check_fork_ready().is_err());
    assert!(
        lease
            .with(|| entered.store(true, Ordering::Relaxed))
            .is_err()
    );
    assert!(!entered.load(Ordering::Relaxed));
    ProcessLease::new().unwrap().with(|| ()).unwrap();
    let fd = lease.file.as_raw_fd();
    // SAFETY: the outer call returned and released its Rust guard. The child
    // only uses the inherited descriptor in async-signal-safe fcntl/_exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
    if pid == 0 {
        child_exit(if native_try_lock(fd) == b'Y' { 23 } else { 86 });
    }
    wait_child(pid);
}

/// One-byte synchronization without allocation or inherited Rust locks.
fn send(fd: RawFd, byte: u8) -> bool {
    loop {
        // SAFETY: byte is initialized and lives through the synchronous call.
        // write either transfers this byte or reports an error; it retains no
        // pointer and is async-signal-safe in the forked test child.
        let result = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
        if result == 1 {
            return true;
        }
        if result != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
}

fn receive(fd: RawFd) -> Option<u8> {
    let mut byte = 0;
    loop {
        // SAFETY: byte is writable and lives through this synchronous read.
        // No allocation or lock is performed; read is async-signal-safe.
        let result = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if result == 1 {
            return Some(byte);
        }
        if result != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return None;
        }
    }
}

fn native_try_lock(fd: RawFd) -> u8 {
    let lock = record_lock(libc::F_WRLCK as libc::c_int);
    // SAFETY: fd remains live in the child or parent, and lock is a fully
    // initialized native struct. fcntl is async-signal-safe and retains no
    // pointer; this nonblocking request cannot wait on the other test process.
    if unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) } == 0 {
        return b'Y';
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(error) if error == libc::EACCES || error == libc::EAGAIN => b'N',
        _ => b'E',
    }
}

fn child_exit(code: i32) -> ! {
    // SAFETY: immediate termination runs no inherited destructors or locks.
    unsafe { libc::_exit(code) }
}

fn wait_child(pid: libc::pid_t) {
    let mut status = 0;
    loop {
        // SAFETY: status is writable; pid identifies this test's owned child.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            break;
        }
        assert_eq!(result, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 23);
}

#[test]
fn inherited_descriptor_conflicts_until_the_outer_lease_is_released() {
    if crate::user::test_fork::isolated(
        "user::mm::process_lease::tests::inherited_descriptor_conflicts_until_the_outer_lease_is_released",
    ) {
        return;
    }
    let lease = ProcessLease::new().unwrap();
    let (parent, child) = UnixStream::pair().unwrap();
    let (parent_fd, child_fd) = (parent.as_raw_fd(), child.as_raw_fd());
    let fd = lease.file.as_raw_fd();
    let unlock = record_lock(libc::F_UNLCK as libc::c_int);
    lease.check_fork_ready().unwrap();
    // SAFETY: no lease is held. The child performs only initialized stack
    // operations and async-signal-safe close/read/fcntl/write/_exit. It never
    // calls the Rust mutex, allocates, or runs inherited destructors.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
    if pid == 0 {
        // SAFETY: this child owns its copy of the unused parent descriptor.
        unsafe { libc::close(parent_fd) };
        loop {
            match receive(child_fd) {
                Some(b'P') => {
                    let result = native_try_lock(fd);
                    if result == b'Y' {
                        // SAFETY: initialized lock and live inherited fd.
                        if unsafe { libc::fcntl(fd, libc::F_SETLK, &unlock) } != 0 {
                            child_exit(81);
                        }
                    }
                    if !send(child_fd, result) {
                        child_exit(82);
                    }
                }
                Some(b'Q') => child_exit(23),
                _ => child_exit(83),
            }
        }
    }
    drop(child);
    lease
        .with(|| {
            assert!(send(parent_fd, b'P'));
            assert_eq!(receive(parent_fd), Some(b'N'));
            lease.with(|| ()).unwrap();
            assert!(send(parent_fd, b'P'));
            assert_eq!(receive(parent_fd), Some(b'N'));
        })
        .unwrap();
    assert!(send(parent_fd, b'P'));
    assert_eq!(receive(parent_fd), Some(b'Y'));
    assert!(send(parent_fd, b'Q'));
    wait_child(pid);
    lease.check_fork_ready().unwrap();
}

#[test]
fn dead_worker_releases_its_lease_without_an_explicit_unlock() {
    if crate::user::test_fork::isolated(
        "user::mm::process_lease::tests::dead_worker_releases_its_lease_without_an_explicit_unlock",
    ) {
        return;
    }
    let lease = ProcessLease::new().unwrap();
    let (parent, child) = UnixStream::pair().unwrap();
    let (parent_fd, child_fd) = (parent.as_raw_fd(), child.as_raw_fd());
    let fd = lease.file.as_raw_fd();
    lease.check_fork_ready().unwrap();
    // SAFETY: as in the contention test, the child runs only raw, synchronous,
    // async-signal-safe operations and _exit with no inherited destructors.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
    if pid == 0 {
        // SAFETY: this child owns its unused copy of the parent socket.
        unsafe { libc::close(parent_fd) };
        if native_try_lock(fd) != b'Y' || !send(child_fd, b'Y') {
            child_exit(84);
        }
        if receive(child_fd) != Some(b'Q') {
            child_exit(85);
        }
        child_exit(23);
    }
    drop(child);
    assert_eq!(receive(parent_fd), Some(b'Y'));
    assert_eq!(native_try_lock(fd), b'N');
    assert!(send(parent_fd, b'Q'));
    lease.with(|| ()).unwrap();
    wait_child(pid);
    lease.check_fork_ready().unwrap();
}

#[test]
fn owner_turns_follow_kernel_lease_across_reentry_and_worker_death() {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    use crate::user::mm::process_owner::Turns;

    const NAME: &str = "user::mm::process_lease::tests::owner_turns_follow_kernel_lease_across_reentry_and_worker_death";
    const LEASE_FD: &str = "RAX_MM_TURN_TEST_LEASE_FD";
    const SOCKET_FD: &str = "RAX_MM_TURN_TEST_SOCKET_FD";

    if let Ok(fd) = std::env::var(LEASE_FD) {
        let fd: RawFd = fd.parse().unwrap();
        let socket: RawFd = std::env::var(SOCKET_FD).unwrap().parse().unwrap();
        // SAFETY: the parent gives this fresh executable exactly one owned
        // descriptor for the lease and one socket endpoint. No File/stream
        // already owns either descriptor in this process.
        let (file, mut stream) = unsafe {
            (
                std::fs::File::from_raw_fd(fd),
                UnixStream::from_raw_fd(socket),
            )
        };
        let lease = ProcessLease {
            file,
            local: Mutex::new(()),
            available: AtomicBool::new(true),
        };
        stream.write_all(b"I").unwrap();
        loop {
            let mut command = [0];
            stream.read_exact(&mut command).unwrap();
            match command[0] {
                b'L' => lease
                    .with(|| {
                        stream.write_all(b"H").unwrap();
                        stream.read_exact(&mut command).unwrap();
                        assert_eq!(command[0], b'U');
                    })
                    .unwrap(),
                b'B' | b'D' => {
                    let mut lock = record_lock(libc::F_WRLCK as libc::c_int);
                    if command[0] == b'B' {
                        lock.l_len = 2;
                    } else {
                        lock.l_type = libc::F_RDLCK as _;
                    }
                    // SAFETY: initialized flock and the child's canonical,
                    // live descriptor. This child performs no competing calls.
                    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) }, 0);
                    stream.write_all(b"H").unwrap();
                    stream.read_exact(&mut command).unwrap();
                    assert_eq!(command[0], b'U');
                    // A zero-length unlock covers both deliberately tested
                    // ranges, including the malformed two-byte lease.
                    lock.l_type = libc::F_UNLCK as _;
                    lock.l_len = 0;
                    // SAFETY: the same live descriptor and initialized flock.
                    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) }, 0);
                }
                _ => panic!("unexpected test worker command"),
            }
            stream.write_all(b"R").unwrap();
        }
    }

    let lease = ProcessLease::new().unwrap();
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let fds = [lease.file.as_raw_fd(), child.as_raw_fd()];
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
        .env(LEASE_FD, fds[0].to_string())
        .env(SOCKET_FD, fds[1].to_string())
        .stdout(Stdio::null());
    // SAFETY: only async-signal-safe fcntl operations run between host fork
    // and exec. Descriptors remain live in the parent through spawn. Clearing
    // FD_CLOEXEC changes only the child's descriptor flags; it creates no
    // duplicate of the canonical lease descriptor in either process.
    unsafe {
        command.pre_exec(move || {
            for fd in fds {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut worker = ReapWorker(command.spawn().unwrap());
    drop(child);
    let pid = libc::pid_t::try_from(worker.0.id()).unwrap();
    assert_eq!(receive(parent.as_raw_fd()), Some(b'I'));
    assert_eq!(lease.holder().unwrap(), None);
    let mut turns = Turns::new();
    let identity = turns.register().unwrap();
    assert!(turns.begin(identity, pid, &lease).is_err());

    let begin = |parent: &mut UnixStream| {
        parent.write_all(b"L").unwrap();
        assert_eq!(receive(parent.as_raw_fd()), Some(b'H'));
        assert_eq!(lease.holder().unwrap(), Some(pid));
    };
    begin(&mut parent);
    let first = turns.begin(identity, pid, &lease).unwrap();
    turns.validate(first, &lease).unwrap();
    assert!(
        turns
            .begin(identity, pid.checked_add(1).unwrap(), &lease)
            .is_err()
    );
    // A second endpoint cannot impersonate a PID already bound to the first.
    let other = turns.register().unwrap();
    assert!(turns.begin(other, pid, &lease).is_err());
    assert!(send(parent.as_raw_fd(), b'U'));
    assert_eq!(receive(parent.as_raw_fd()), Some(b'R'));
    assert_eq!(lease.holder().unwrap(), None);
    assert!(turns.validate(first, &lease).is_err());
    assert!(turns.end(first, &lease).is_err());

    begin(&mut parent);
    let second = turns.begin(identity, pid, &lease).unwrap();
    assert_ne!(first, second);
    assert!(turns.validate(first, &lease).is_err());
    turns.end(second, &lease).unwrap();
    assert!(turns.validate(second, &lease).is_err());
    assert!(send(parent.as_raw_fd(), b'U'));
    assert_eq!(receive(parent.as_raw_fd()), Some(b'R'));

    // Unexpected lock type/range must not masquerade as the protocol lease.
    for command in [b'B', b'D'] {
        assert!(send(parent.as_raw_fd(), command));
        assert_eq!(receive(parent.as_raw_fd()), Some(b'H'));
        assert_eq!(
            lease.holder().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(turns.begin(identity, pid, &lease).is_err());
        assert!(send(parent.as_raw_fd(), b'U'));
        assert_eq!(receive(parent.as_raw_fd()), Some(b'R'));
        assert_eq!(lease.holder().unwrap(), None);
    }

    begin(&mut parent);
    let third = turns.begin(identity, pid, &lease).unwrap();
    turns.validate(third, &lease).unwrap();
    worker.0.kill().unwrap();
    let status = worker.0.wait().unwrap();
    assert!(!status.success());
    assert_eq!(lease.holder().unwrap(), None);
    assert!(turns.validate(third, &lease).is_err());
    assert!(turns.retire(identity));
    assert!(!turns.retire(identity));
    assert!(turns.begin(identity, pid, &lease).is_err());
}

struct ReapWorker(std::process::Child);

impl Drop for ReapWorker {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

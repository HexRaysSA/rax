//! Native lease-holder processes for broker tests. Only the child pre_exec
//! hook runs after raw host fork; Rust coordination starts in a fresh image.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use super::ProcessLease;

const ROLE: &str = "RAX_MM_OWNER_TEST_WORKER";
const LEASE_FD: &str = "RAX_MM_OWNER_TEST_LEASE_FD";
const SOCKET_FD: &str = "RAX_MM_OWNER_TEST_SOCKET_FD";

pub(crate) fn serve_if_requested(name: &str) {
    let Some((lease, mut stream)) = inherited(name) else {
        return;
    };
    stream.write_all(b"I").unwrap();
    loop {
        let mut command = [0];
        stream.read_exact(&mut command).unwrap();
        match command[0] {
            b'L' => {
                lease
                    .with(|| {
                        stream.write_all(b"H").unwrap();
                        stream.read_exact(&mut command).unwrap();
                        assert_eq!(command[0], b'U');
                    })
                    .unwrap();
                stream.write_all(b"R").unwrap();
            }
            b'Q' => std::process::exit(0),
            _ => panic!("unexpected memory-owner test worker command"),
        }
    }
}

pub(crate) fn rpc_if_requested(name: &str, run: impl FnOnce(&ProcessLease, UnixStream)) {
    if let Some((lease, stream)) = inherited(name) {
        run(&lease, stream);
        std::process::exit(0);
    }
}

fn inherited(name: &str) -> Option<(ProcessLease, UnixStream)> {
    if std::env::var(ROLE).ok().as_deref() != Some(name) {
        return None;
    }
    let fd: RawFd = std::env::var(LEASE_FD).unwrap().parse().unwrap();
    let socket: RawFd = std::env::var(SOCKET_FD).unwrap().parse().unwrap();
    // SAFETY: spawn transfers exactly one owned descriptor of each kind to
    // this fresh executable. Neither has another Rust owner in this process.
    let (file, stream) = unsafe { (File::from_raw_fd(fd), UnixStream::from_raw_fd(socket)) };
    for fd in [fd, socket] {
        // SAFETY: both descriptors are live, owned, and used only here. Restore
        // the close-on-exec invariant after the intentional test-image handoff.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            assert!(flags >= 0);
            assert_eq!(libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC), 0);
        }
    }
    let lease = ProcessLease {
        file,
        local: Mutex::new(()),
        available: AtomicBool::new(true),
    };
    Some((lease, stream))
}

pub(crate) fn spawn_rpc(
    lease: &ProcessLease,
    name: &str,
    stream: &UnixStream,
    phase: &str,
) -> Child {
    let mut command = worker_command(lease, name, stream);
    command
        .env("RAX_MM_OWNER_RPC_PHASE", phase)
        .spawn()
        .unwrap()
}

fn worker_command(lease: &ProcessLease, name: &str, stream: &UnixStream) -> Command {
    let fds = [lease.file.as_raw_fd(), stream.as_raw_fd()];
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env(ROLE, name)
        .env(LEASE_FD, fds[0].to_string())
        .env(SOCKET_FD, fds[1].to_string())
        .stdout(Stdio::null());
    // SAFETY: only async-signal-safe fcntl calls run in the fresh child hook.
    // The caller keeps both canonical descriptors live through spawn. Clearing
    // CLOEXEC changes only this child, and never duplicates the lease file.
    unsafe {
        command.pre_exec(move || {
            for fd in fds {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
}

pub(crate) struct LeaseWorker {
    child: Child,
    stream: UnixStream,
    held: bool,
}

impl LeaseWorker {
    pub(crate) fn spawn(lease: &ProcessLease, name: &str) -> Self {
        let (parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        let mut command = worker_command(lease, name, &child);
        let mut worker = Self {
            child: command.spawn().unwrap(),
            stream: parent,
            held: false,
        };
        drop(child);
        worker.receive(b'I');
        worker
    }

    pub(crate) fn pid(&self) -> libc::pid_t {
        self.child.id().try_into().unwrap()
    }

    pub(crate) fn acquire(&mut self) {
        assert!(!self.held);
        self.stream.write_all(b"L").unwrap();
        self.receive(b'H');
        self.held = true;
    }

    pub(crate) fn release(&mut self) {
        assert!(self.held);
        self.stream.write_all(b"U").unwrap();
        self.receive(b'R');
        self.held = false;
    }

    pub(crate) fn stop(&mut self) {
        if self.held {
            self.release();
        }
        self.stream.write_all(b"Q").unwrap();
        assert!(self.child.wait().unwrap().success());
    }

    fn receive(&mut self, expected: u8) {
        let mut byte = [0];
        self.stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], expected);
    }
}

impl Drop for LeaseWorker {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

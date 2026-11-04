//! Read readiness includes FIFO EOF, including when the last writer closes.
use super::*;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

struct Fifo {
    read: OwnedFd,
    write: Option<OwnedFd>,
}

impl Fifo {
    fn new(writer: bool) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "rax-fifo-eof-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let native = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: fresh task-owned pathname and a terminated native string.
        assert_eq!(unsafe { libc::mkfifo(native.as_ptr(), 0o600) }, 0);
        // SAFETY: the FIFO exists; successful descriptors are owned below.
        let read = unsafe {
            libc::open(
                native.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        assert!(read >= 0);
        // SAFETY: the same live FIFO has its reader, so this open cannot block.
        let write = writer.then(|| unsafe {
            let fd = libc::open(
                native.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            );
            assert!(fd >= 0);
            OwnedFd::from_raw_fd(fd)
        });
        std::fs::remove_file(path).unwrap();
        Self {
            // SAFETY: the successful open above has no other owner.
            read: unsafe { OwnedFd::from_raw_fd(read) },
            write,
        }
    }

    fn assert_eof(&self) {
        let mut byte = 0u8;
        // SAFETY: live nonblocking reader and a one-byte writable output.
        assert_eq!(
            unsafe { libc::read(self.read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0
        );
    }
}

struct TestChild(std::process::Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            // Reap only this regression's child if an assertion or watchdog fails.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Exercise descriptor readiness rather than unrelated native signal wakes.
fn uninterrupted_sleep(fds: &[(i32, bool, bool)], deadline: Option<Instant>) -> Vec<bool> {
    loop {
        let ready = sleep(fds, deadline);
        if ready.iter().any(|&value| value)
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            || deadline.is_some_and(|end| Instant::now() >= end)
        {
            return ready;
        }
        // Preserve the absolute deadline across host interruptions, as a
        // scheduler re-entering the parked guest call does.
    }
}

#[test]
fn named_fifo_writer_does_not_survive_an_unrelated_child_exec() {
    use std::io::{BufRead, Read, Write};
    use std::process::{Command, Stdio};

    const CHILD: &str = "RAX_FIFO_WRITER_INHERITANCE_CHILD";
    const READY: &str = "RAX_FIFO_CHILD_READY";
    if std::env::var_os(CHILD).is_some() {
        println!("\n{READY}");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut [0]).unwrap();
        return;
    }

    let mut fifo = Fifo::new(true);
    let mut child = TestChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "user::darwin::wait::fifo_tests::named_fifo_writer_does_not_survive_an_unrelated_child_exec",
                "--exact", "--test-threads=1", "--nocapture",
            ])
            .env(CHILD, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let output = std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut text = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let ready = line.contains(READY);
            text.push_str(&line);
            if ready {
                send.send(()).unwrap();
                reader.read_to_string(&mut text).unwrap();
                break;
            }
        }
        text
    });
    receive
        .recv_timeout(Duration::from_secs(30))
        .expect("the owned FIFO control child must reach its stdin barrier");
    assert!(child.0.try_wait().unwrap().is_none());
    drop(fifo.write.take());
    // Darwin consumes the FIFO's EOF readiness indication when EOF is read.
    assert_eq!(
        ready_now(&[(fifo.read.as_raw_fd(), true, false)]),
        vec![true]
    );
    fifo.assert_eof();
    child.0.stdin.take().unwrap().write_all(b"x").unwrap();
    let status = child.0.wait().unwrap();
    let output = output.join().unwrap();
    assert!(status.success(), "{output}");
    assert!(output.contains("1 passed; 0 failed;"), "{output}");
}

#[test]
fn named_fifo_eof_after_last_writer_close_is_readable() {
    let mut fifo = Fifo::new(true);
    let entries = [(fifo.read.as_raw_fd(), true, false); 2];
    assert_eq!(ready_now(&entries), vec![false, false]);
    drop(fifo.write.take());
    assert_eq!(ready_now(&entries), vec![true, true]);
    fifo.assert_eof();
}

#[test]
fn named_fifo_before_any_writer_has_no_readiness_event() {
    let fifo = Fifo::new(false);
    assert_eq!(
        ready_now(&[(fifo.read.as_raw_fd(), true, false)]),
        vec![false]
    );
    fifo.assert_eof();
}

#[test]
fn named_fifo_wait_observes_async_writer_close_with_an_independent_wakeup() {
    let mut fifo = Fifo::new(true);
    let mut descriptors = [-1; 2];
    // SAFETY: two writable descriptor outputs; successful handles owned below.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    // SAFETY: each successful pipe descriptor is wrapped exactly once.
    let (wake_read, wake_write) = unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    };
    let writer = fifo.write.take();
    let peer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        drop(writer);
        // SAFETY: live wake descriptor and readable single byte. This makes
        // the pre-fix test fail without hanging in its indefinite native poll.
        assert_eq!(
            unsafe { libc::write(wake_write.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
    });
    let ready = uninterrupted_sleep(
        &[
            (fifo.read.as_raw_fd(), true, false),
            (wake_read.as_raw_fd(), true, false),
        ],
        None,
    );
    peer.join().unwrap();
    fifo.assert_eof();
    assert!(
        ready[0],
        "FIFO EOF must accompany the independent readiness wake"
    );
}

#[test]
fn named_fifo_wait_preserves_a_finite_deadline_while_its_writer_remains_open() {
    let fifo = Fifo::new(true);
    let start = Instant::now();
    assert_eq!(
        uninterrupted_sleep(
            &[(fifo.read.as_raw_fd(), true, false)],
            Some(start + Duration::from_millis(25))
        ),
        vec![false]
    );
    assert!(start.elapsed() >= Duration::from_millis(25));
}

#[test]
fn named_fifo_eof_readiness_handles_descriptors_above_fd_setsize() {
    const CHILD: &str = "RAX_FIFO_EOF_HIGH_FD_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "user::darwin::wait::fifo_tests::named_fifo_eof_readiness_handles_descriptors_above_fd_setsize",
                "--exact", "--test-threads=1", "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("running 1 test") && stdout.contains("1 passed; 0 failed;"));
        assert!(
            stdout.contains("native FIFO fd="),
            "child must execute the native high-fd control"
        );
        return;
    }
    // Raise only this isolated test child's soft limit. The parent test
    // process and every concurrently running test keep their original limits.
    let minimum = libc::FD_SETSIZE as i32 + 17;
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: a complete writable rlimit output; success initializes it.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
        0
    );
    // SAFETY: successful getrlimit initialized both fields.
    let mut limit = unsafe { limit.assume_init() };
    let required = minimum as libc::rlim_t + 1;
    assert!(
        limit.rlim_max >= required,
        "native high-fd control requires the host hard limit"
    );
    if limit.rlim_cur < required {
        limit.rlim_cur = required;
        // SAFETY: initialized limit at or below the unchanged hard limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    }
    let mut fifo = Fifo::new(true);
    // SAFETY: live reader and an integer minimum for the duplicate output.
    let high = unsafe { libc::fcntl(fifo.read.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(high >= minimum);
    // SAFETY: the successful duplicate has no other owning wrapper.
    let high = unsafe { OwnedFd::from_raw_fd(high) };
    assert_eq!(ready_now(&[(high.as_raw_fd(), true, false)]), vec![false]);
    drop(fifo.write.take());
    assert_eq!(ready_now(&[(high.as_raw_fd(), true, false)]), vec![true]);
    fifo.assert_eof();
    println!("native FIFO fd={}", high.as_raw_fd());
}

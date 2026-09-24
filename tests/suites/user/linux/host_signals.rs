//! Signals sent to `rax-user` from outside: forwarded to the guest by
//! default, and passed through as host default actions with
//! `--no-signal-forwarding`.
//!
//! The `hostsig` fixture prints a line before each step and waits for a
//! signal; the tests signal `rax-user`'s host process and follow the lines.
//! Expected guest-visible values are Linux's: `si_code` `SI_USER` (0) with
//! the sender's pid for `kill(2)` (`kernel/signal.c`, `prepare_kill_siginfo`),
//! `EINTR` from a blocking `read` interrupted by a handler without
//! `SA_RESTART`, and death by the signal for a default-action `SIGTERM`.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use super::support::{fixtures, rax_user, shell_status};

const ARCHES: [&str; 3] = ["x86_64", "aarch64", "riscv64"];
const T: Duration = Duration::from_secs(60);

// Linux signal numbers.
const SIGINT: i32 = 2;
const SIGUSR1: i32 = 10;
const SIGTERM: i32 = 15;

/// A running `rax-user hostsig` whose standard input stays open, so a guest
/// `read` of it blocks.
struct Session {
    child: Child,
    lines: Receiver<String>,
}

impl Session {
    fn start(arch: &str, options: &[&str]) -> Self {
        let program = fixtures().join("bin").join(arch).join("hostsig");
        let mut child = Command::new(rax_user())
            .args(options)
            .arg(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rax-user");
        let out = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Session { child, lines }
    }

    /// Sends Linux signal `sig` to `rax-user`.
    fn kill(&self, sig: i32) {
        let host = rax::user::linux::host::host_signal(sig).expect("mapped signal");
        let rc = unsafe { libc::kill(self.child.id() as libc::pid_t, host) };
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    }

    /// The next line, or `None` at end of output.
    fn line(&self, deadline: Instant) -> Option<String> {
        match self
            .lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(line) => Some(line),
            Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => panic!("no output within {T:?}"),
        }
    }

    fn expect(&self, want: &str) {
        assert_eq!(self.line(Instant::now() + T).as_deref(), Some(want));
    }

    /// Sends `sig` every 50 ms until the next line arrives: a signal that
    /// arrives before the guest blocks is handled without interrupting the
    /// wait, so the guest needs another.
    fn signal_until_line(&self, sig: i32) -> Option<String> {
        let deadline = Instant::now() + T;
        loop {
            self.kill(sig);
            match self.lines.recv_timeout(Duration::from_millis(50)) {
                Ok(line) => return Some(line),
                Err(RecvTimeoutError::Disconnected) => return None,
                Err(RecvTimeoutError::Timeout) => {
                    assert!(Instant::now() < deadline, "no output within {T:?}");
                }
            }
        }
    }

    /// Waits for exit: `(shell status, Linux signal)`.
    fn wait(mut self) -> (Option<i32>, Option<i32>) {
        let deadline = Instant::now() + T;
        loop {
            if let Some(s) = self.child.try_wait().expect("wait") {
                return shell_status(s);
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("rax-user did not exit within {T:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn host_signals_are_forwarded_to_the_guest() {
    for arch in ARCHES {
        let s = Session::start(arch, &[]);
        s.expect("ready");
        // SIGUSR1 from this process: the guest sees kill(2)'s siginfo with
        // its parent (rax-user's parent) as the sender. The guest waits in a
        // pause loop, so one signal suffices whenever it arrives.
        s.kill(SIGUSR1);
        s.expect("10 si_code=0 from-parent=1");
        s.expect("reading");
        assert_eq!(
            s.signal_until_line(SIGINT).as_deref(),
            Some("read=-1 eintr=1 signal=2"),
            "{arch}"
        );
        s.expect("waiting");
        // SIGTERM's default action ends the guest, and rax-user dies of the
        // same signal.
        s.kill(SIGTERM);
        assert_eq!(s.line(Instant::now() + T), None, "{arch}");
        assert_eq!(s.wait(), (Some(128 + 15), Some(15)), "{arch}");
    }
}

#[test]
fn without_forwarding_host_signals_act_on_rax_user() {
    let s = Session::start("x86_64", &["--no-signal-forwarding"]);
    s.expect("ready");
    // SIGUSR1's host default action terminates rax-user; the guest handler
    // never runs.
    s.kill(SIGUSR1);
    assert_eq!(s.line(Instant::now() + T), None);
    assert_eq!(s.wait(), (Some(128 + 10), Some(10)));
}

//! Child processes.
//!
//! A guest process's children are host processes: `fork` forks the
//! emulator, and the child emulates the guest child. Each child writes
//! status records to a pipe its parent reads: `E` when a `CLONE_VFORK`
//! child calls `execve`, and `X` with the Linux wait status when it ends,
//! which the host's exit status cannot express (a core dump, for one). The
//! parent learns of exits, stops, and continuations from the host's
//! `SIGCHLD`, reads the records, and keeps an exited child as a zombie
//! until the guest waits for it (`wait_task_zombie`) or it is reaped
//! automatically (`SIGCHLD` ignored, `SA_NOCLDWAIT`).

use std::os::fd::{AsRawFd, OwnedFd};

use super::host::{self, ChildRusage, HostWait};

/// A child process.
#[derive(Debug)]
pub struct Child {
    /// Its PID (the host PID).
    pub pid: i32,
    /// The read end of its status-record pipe.
    status: OwnedFd,
    /// The signal its exit sends the parent (`exit_signal`); 0 for none.
    pub exit_signal: i32,
    /// The thread that created it (`__WNOTHREAD`).
    pub creator: i32,
    /// The parent's `execve` count when it was created (`parent_exec_id`).
    pub parent_exec_id: u64,
    /// Its process group, as last seen alive.
    pub pgid: i32,
    /// It called `execve` (or ended): a `CLONE_VFORK` parent runs again.
    pub released: bool,
    /// The Linux wait status of its final record.
    record: Option<i32>,
    /// A stop not yet reported to `wait` (`group_exit_code`), by signal.
    pub stopped: Option<i32>,
    /// A continuation not yet reported (`SIGNAL_STOP_CONTINUED`).
    pub continued: bool,
    /// Ended: its wait status and resource use (a zombie).
    pub zombie: Option<(i32, ChildRusage)>,
}

/// A state change of a child, for `SIGCHLD` and `wait`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildEvent {
    /// It ended (it is a zombie).
    Exited(i32),
    /// It stopped with this signal.
    Stopped(i32, i32),
    /// It continued.
    Continued(i32),
}

/// A process's children, in creation order.
#[derive(Debug, Default)]
pub struct Children {
    /// The children not yet reaped.
    pub list: Vec<Child>,
    /// Resource use of reaped children (`cutime`, `cstime`, `cmaxrss`).
    pub reaped: ChildRusage,
}

/// The Linux wait status of an exit with `code` (`(code & 0xff) << 8`).
pub fn exited_status(code: i32) -> i32 {
    (code & 0xff) << 8
}

/// The Linux wait status of a death by `sig`, with the core-dump flag.
pub fn signaled_status(sig: i32, core: bool) -> i32 {
    (sig & 0x7f) | if core { 0x80 } else { 0 }
}

impl Children {
    /// Records a new child.
    pub fn add(&mut self, pid: i32, status: OwnedFd, exit_signal: i32, creator: i32, exec_id: u64) {
        let pgid = host::getpgid(pid).unwrap_or(0);
        self.list.push(Child {
            pid,
            status,
            exit_signal,
            creator,
            parent_exec_id: exec_id,
            pgid,
            released: false,
            record: None,
            stopped: None,
            continued: false,
            zombie: None,
        });
    }

    /// The child with `pid`.
    pub fn get_mut(&mut self, pid: i32) -> Option<&mut Child> {
        self.list.iter_mut().find(|c| c.pid == pid)
    }

    /// Removes a child (it was reaped), adding its resource use to the
    /// totals.
    pub fn reap(&mut self, pid: i32) -> Option<Child> {
        let i = self.list.iter().position(|c| c.pid == pid)?;
        let c = self.list.remove(i);
        if let Some((_, (u, s, rss))) = c.zombie {
            self.reaped.0 += u;
            self.reaped.1 += s;
            self.reaped.2 = self.reaped.2.max(rss);
        }
        Some(c)
    }

    /// The status-pipe descriptors of children that have not ended, for a
    /// sleeping `wait` or `vfork`.
    pub fn live_fds(&self, pids: impl Fn(&Child) -> bool) -> Vec<(i32, bool, bool)> {
        self.list
            .iter()
            .filter(|c| c.zombie.is_none() && pids(c))
            .map(|c| (c.status.as_raw_fd(), true, false))
            .collect()
    }

    /// Reads new status records and host state changes, returning the
    /// changes in order.
    pub fn poll(&mut self) -> Vec<ChildEvent> {
        let mut events = Vec::new();
        for c in self.list.iter_mut().filter(|c| c.zombie.is_none()) {
            read_records(c);
            if let Ok(pgid) = host::getpgid(c.pid) {
                c.pgid = pgid;
            }
            loop {
                let change = match host::wait_child(c.pid) {
                    Ok(Some(change)) => change,
                    Ok(None) => break,
                    // Reaped behind the emulator's back: take the record.
                    Err(_) => (HostWait::Exited(0), (0, 0, 0)),
                };
                match change.0 {
                    HostWait::Exited(code) => {
                        read_records(c);
                        let status = c.record.unwrap_or(exited_status(code));
                        c.zombie = Some((status, change.1));
                        c.released = true;
                        events.push(ChildEvent::Exited(c.pid));
                        break;
                    }
                    HostWait::Signaled(sig, core) => {
                        read_records(c);
                        let status = c.record.unwrap_or(signaled_status(sig, core));
                        c.zombie = Some((status, change.1));
                        c.released = true;
                        events.push(ChildEvent::Exited(c.pid));
                        break;
                    }
                    HostWait::Stopped(sig) => {
                        c.stopped = Some(sig);
                        c.continued = false;
                        events.push(ChildEvent::Stopped(c.pid, sig));
                    }
                    HostWait::Continued => {
                        c.stopped = None;
                        c.continued = true;
                        events.push(ChildEvent::Continued(c.pid));
                    }
                }
            }
        }
        events
    }
}

/// Reads a child's available status records: `E` (it called `execve`) and
/// `X` followed by its little-endian Linux wait status.
fn read_records(c: &mut Child) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: `buf` is writable for its length; the descriptor is the
        // non-blocking status pipe this record owns.
        let n = unsafe { libc::read(c.status.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return;
        }
        let mut rec = &buf[..n as usize];
        while let Some((&tag, rest)) = rec.split_first() {
            match tag {
                b'E' => {
                    c.released = true;
                    rec = rest;
                }
                b'X' if rest.len() >= 4 => {
                    c.record = Some(i32::from_le_bytes(rest[..4].try_into().unwrap()));
                    c.released = true;
                    rec = &rest[4..];
                }
                _ => return,
            }
        }
    }
}

/// The forked emulator's end of its status pipe. Compares unequal: it
/// only travels in an [`Outcome`](super::syscall::Outcome).
#[derive(Debug)]
pub struct ForkedSelf {
    /// The write end.
    pub status: OwnedFd,
    /// The parent sleeps in `CLONE_VFORK` until this process calls
    /// `execve` or ends.
    pub vfork: bool,
}

impl PartialEq for ForkedSelf {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl Eq for ForkedSelf {}

impl ForkedSelf {
    fn write(&self, rec: &[u8]) {
        // SAFETY: `rec` is readable for its length; a write of at most
        // PIPE_BUF bytes to a pipe is atomic. A parent that has gone away
        // makes it fail with EPIPE (SIGPIPE is ignored), which is fine.
        unsafe {
            libc::write(self.status.as_raw_fd(), rec.as_ptr().cast(), rec.len());
        }
    }

    /// Reports `execve` to a `CLONE_VFORK` parent.
    pub fn exec(&mut self) {
        if std::mem::take(&mut self.vfork) {
            self.write(b"E");
        }
    }

    /// Reports the process's end with Linux wait status `status`.
    pub fn exit(&self, status: i32) {
        let mut rec = [b'X', 0, 0, 0, 0];
        rec[1..].copy_from_slice(&status.to_le_bytes());
        self.write(&rec);
    }
}

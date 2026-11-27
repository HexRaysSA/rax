//! Child processes.
//!
//! Closed guests schedule children in the same emulator. In the host-service
//! profile, `fork` forks the emulator and the child emulates the guest child. Each child writes
//! status records to a pipe its parent reads: `E` when a `CLONE_VFORK`
//! child calls `execve`, and `X` with the Linux wait status when it ends,
//! which the host's exit status cannot express (a core dump, for one). The
//! parent learns of exits, stops, and continuations from the host's
//! `SIGCHLD`, reads the records, and keeps an exited child as a zombie
//! until the guest waits for it (`wait_task_zombie`) or it is reaped
//! automatically (`SIGCHLD` ignored, `SA_NOCLDWAIT`).

#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};

#[cfg(unix)]
use super::host::{self, HostWait};

mod groups;

use std::collections::BTreeMap;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use self::groups::GroupMember;
use super::abi::errno::Errno;
use super::abi::errno_table::{EAGAIN, EEXIST};
use super::fs::pidfd::Target;
use super::process::{ExitStatus, LinuxProcess};

const PID_LIMIT: i32 = 4 * 1024 * 1024;
/// Bound simultaneously retained children (including zombies) per embedding.
pub(super) const GUEST_CHILD_LIMIT: usize = 32;
// The caller's memory setting bounds each arena. Bound the aggregate
// additional capacity independently so fork cannot multiply that setting
// by the full process count. An exited child keeps its PID but no arena.
const GUEST_CHILD_ARENA_LIMIT: u64 = 2 << 30;

#[derive(Debug)]
struct Namespace {
    next: i32,
    tasks: BTreeMap<i32, Arc<Target>>,
    processes: BTreeMap<i32, GroupMember>,
    next_pidfd_ino: u64,
    children: usize,
    arena_bytes: u64,
    last_selected_process: Option<i32>,
}

/// An allocated guest task ID, released with the thread or reaped child.
#[derive(Debug)]
pub(crate) struct GuestTid {
    id: i32,
    namespace: Arc<Mutex<Namespace>>,
    arena_bytes: Option<u64>,
}

impl GuestTid {
    pub(crate) fn id(&self) -> i32 {
        self.id
    }

    fn release_arena(&mut self) {
        if let Some(bytes) = self.arena_bytes.as_mut() {
            self.namespace.lock().unwrap().arena_bytes -= std::mem::take(bytes);
        }
    }
}

impl Drop for GuestTid {
    fn drop(&mut self) {
        let mut ns = self.namespace.lock().unwrap();
        ns.tasks
            .remove(&self.id)
            .expect("allocated guest task")
            .end(None);
        if let Some(bytes) = self.arena_bytes {
            ns.processes.remove(&self.id);
            ns.children -= 1;
            ns.arena_bytes -= bytes;
        }
    }
}

/// User CPU microseconds, system CPU microseconds, and peak RSS in KiB.
pub type ChildRusage = (u64, u64, u64);

/// A child process.
pub struct Child {
    /// Its PID in the parent's namespace.
    pub pid: i32,
    /// The host child's status-record pipe.
    #[cfg(unix)]
    status: Option<OwnedFd>,
    /// The PID stays allocated through the waitable zombie state.
    pub(super) guest: Option<Box<LinuxProcess>>,
    guest_tid: Option<GuestTid>,
    pub(super) guest_uid: Option<u32>,
    /// Effective UID retained for `capget` after a guest child exits.
    pub(super) guest_euid: Option<u32>,
    /// Live effective UID of a host-backed guest child.
    #[cfg(unix)]
    guest_euid_shared: Option<Arc<host::SharedWords>>,
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
    /// The link to it, along which it traces or is traced.
    pub link: Option<super::ptrace::Link>,
}

impl std::fmt::Debug for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Child")
            .field("pid", &self.pid)
            .field("guest_tid", &self.guest_tid.as_ref().map(GuestTid::id))
            .field("zombie", &self.zombie)
            .finish_non_exhaustive()
    }
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
    /// Live descendants reparented to the closed namespace's synthetic PID 1.
    pub(super) orphans: Vec<Child>,
    namespace: Option<Arc<Mutex<Namespace>>>,
    owner: i32,
    events: Vec<ChildEvent>,
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
    pub(super) fn embedded(pid: i32) -> Self {
        Self {
            namespace: Some(Arc::new(Mutex::new(Namespace {
                next: pid + 1,
                tasks: BTreeMap::from([
                    (1, Target::new_guest(1, 1, 1)),
                    (pid, Target::new_guest(pid, pid, 2)),
                ]),
                processes: BTreeMap::from([(pid, GroupMember::initial(pid))]),
                next_pidfd_ino: 3,
                children: 0,
                arena_bytes: 0,
                last_selected_process: None,
            }))),
            owner: pid,
            ..Self::default()
        }
    }

    pub(super) fn guest_scope(&self, pid: i32) -> Self {
        Self {
            namespace: self.namespace.clone(),
            owner: pid,
            ..Self::default()
        }
    }

    pub(super) fn guest_task(&self, tid: i32) -> Option<Arc<Target>> {
        // PID 1 is the synthetic reparenting identity, with no runnable task.
        if tid == 1 {
            return None;
        }
        self.guest_namespace().tasks.get(&tid).cloned()
    }

    pub(super) fn select_guest_process(&self, pid: i32) -> bool {
        let namespace = self.namespace.as_ref().expect("closed guest namespace");
        namespace.lock().unwrap().last_selected_process.replace(pid) != Some(pid)
    }

    pub(super) fn reserve_guest_id(
        &self,
        requested: Option<i32>,
        arena_bytes: Option<u64>,
    ) -> Result<GuestTid, Errno> {
        let namespace = self.namespace.as_ref().expect("closed guest namespace");
        let mut ns = namespace.lock().unwrap();
        if let Some(bytes) = arena_bytes
            && (ns.children == GUEST_CHILD_LIMIT
                || bytes > GUEST_CHILD_ARENA_LIMIT - ns.arena_bytes)
        {
            return Err(Errno(EAGAIN));
        }
        let id = if let Some(id) = requested {
            if ns.id_in_use(id) {
                return Err(Errno(EEXIST));
            }
            id
        } else {
            let next = |id| if id + 1 == PID_LIMIT { 2 } else { id + 1 };
            let first = ns.next;
            while ns.id_in_use(ns.next) {
                ns.next = next(ns.next);
                if ns.next == first {
                    return Err(Errno(EAGAIN));
                }
            }
            let id = ns.next;
            ns.next = next(id);
            id
        };
        let ino = ns.next_pidfd_ino;
        ns.next_pidfd_ino = ino.checked_add(1).ok_or(Errno(EAGAIN))?;
        if let Some(bytes) = arena_bytes {
            let member = ns.processes[&self.owner].forked();
            ns.processes.insert(id, member);
            ns.children += 1;
            ns.arena_bytes += bytes;
        }
        let tgid = if arena_bytes.is_some() {
            id
        } else {
            self.owner
        };
        ns.tasks.insert(id, Target::new_guest(tgid, id, ino));
        Ok(GuestTid {
            id,
            namespace: namespace.clone(),
            arena_bytes,
        })
    }

    pub(super) fn add_guest(
        &mut self,
        guest: LinuxProcess,
        tid: GuestTid,
        exit_signal: i32,
        creator: i32,
        exec_id: u64,
    ) {
        let pgid = self.guest_group(tid.id()).expect("reserved guest PID").0;
        self.list.push(Child {
            pid: tid.id(),
            #[cfg(unix)]
            status: None,
            guest_tid: Some(tid),
            guest_uid: Some(guest.state.creds.0),
            guest_euid: Some(guest.state.creds.1),
            #[cfg(unix)]
            guest_euid_shared: None,
            guest: Some(Box::new(guest)),
            exit_signal,
            creator,
            parent_exec_id: exec_id,
            pgid,
            released: false,
            record: None,
            stopped: None,
            continued: false,
            zombie: None,
            link: None,
        });
    }

    pub(super) fn guest_event(&mut self, event: ChildEvent) {
        self.events.push(event);
    }

    pub(super) fn inherit_orphans(&mut self, mut children: Self) {
        self.orphans.append(&mut children.orphans);
        for mut child in children.list {
            if let Some(guest) = &mut child.guest {
                guest.state.ppid = 1;
                self.orphans.push(child);
            }
        }
    }

    /// Records a new host child.
    #[cfg(unix)]
    pub fn add(
        &mut self,
        pid: i32,
        status: OwnedFd,
        link: Option<super::ptrace::Link>,
        exit_signal: i32,
        creator: i32,
        exec_id: u64,
        guest_euid_shared: Option<Arc<host::SharedWords>>,
    ) {
        let pgid = host::getpgid(pid).unwrap_or(0);
        self.list.push(Child {
            pid,
            status: Some(status),
            guest_tid: None,
            guest: None,
            guest_uid: None,
            guest_euid: None,
            guest_euid_shared,
            exit_signal,
            creator,
            parent_exec_id: exec_id,
            pgid,
            released: false,
            record: None,
            stopped: None,
            continued: false,
            zombie: None,
            link,
        });
    }

    /// The child with `pid`.
    pub fn get_mut(&mut self, pid: i32) -> Option<&mut Child> {
        self.list.iter_mut().find(|c| c.pid == pid)
    }

    /// Effective UID of a guest child, including a waitable zombie.
    pub(super) fn guest_effective_uid(&self, pid: i32) -> Option<u32> {
        let child = self.list.iter().find(|child| child.pid == pid)?;
        if let Some(guest) = &child.guest {
            return Some(guest.state.creds.1);
        }
        #[cfg(unix)]
        if let Some(shared) = &child.guest_euid_shared {
            return Some(shared.words()[0].load(Ordering::Relaxed) as u32);
        }
        child.guest_euid
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
    #[cfg(unix)]
    pub fn live_fds(&self, pids: impl Fn(&Child) -> bool) -> Vec<(i32, bool, bool)> {
        self.list
            .iter()
            .filter(|c| c.zombie.is_none() && pids(c))
            .filter_map(|c| c.status.as_ref().map(|fd| (fd.as_raw_fd(), true, false)))
            .collect()
    }

    /// Returns child state changes in order.
    pub fn poll(&mut self) -> Vec<ChildEvent> {
        let mut events = std::mem::take(&mut self.events);
        #[cfg(unix)]
        if self.namespace.is_none() {
            self.poll_host(&mut events);
        }
        events
    }

    #[cfg(unix)]
    fn poll_host(&mut self, events: &mut Vec<ChildEvent>) {
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
    }
}

impl Child {
    pub(super) fn finish_guest(&mut self, exit: ExitStatus) -> Children {
        let mut guest = self.guest.take().expect("running child");
        self.guest_uid = Some(guest.state.creds.0);
        self.guest_euid = Some(guest.state.creds.1);
        let status = match exit {
            ExitStatus::Exited(code) => exited_status(code),
            // The embedded guest has no core-file output.
            ExitStatus::Signaled { info, .. } => signaled_status(info.signo, false),
            ExitStatus::Internal(_) => {
                unreachable!("scheduler reports internal errors to the owner")
            }
        };
        guest.state.children.mark_guest_zombie(status);
        self.zombie = Some((status, (0, 0, 0)));
        self.released = true;
        let descendants = std::mem::take(&mut guest.state.children);
        drop(guest);
        self.guest_tid
            .as_mut()
            .expect("guest PID lease")
            .release_arena();
        descendants
    }
}

/// Reads a child's available status records: `E` (it called `execve`) and
/// `X` followed by its little-endian Linux wait status.
#[cfg(unix)]
fn read_records(c: &mut Child) {
    let status = c.status.as_ref().expect("host child has a status pipe");
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: `buf` is writable for its length; the descriptor is the
        // non-blocking status pipe this record owns.
        let n = unsafe { libc::read(status.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
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
    #[cfg(unix)]
    pub status: OwnedFd,
    /// Latest guest effective UID, shared with the fork's parent.
    #[cfg(unix)]
    pub guest_euid: Arc<host::SharedWords>,
    #[cfg(not(unix))]
    unavailable: std::convert::Infallible,
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

#[cfg(unix)]
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

    /// Publishes the latest effective UID to the parent.
    pub fn effective_uid(&self, uid: u32) {
        self.guest_euid.words()[0].store(u64::from(uid), Ordering::Relaxed);
    }

    /// Reports the process's end with Linux wait status `status`.
    pub fn exit(&self, status: i32) {
        let mut rec = [b'X', 0, 0, 0, 0];
        rec[1..].copy_from_slice(&status.to_le_bytes());
        self.write(&rec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_namespace_holds_zombie_pid_without_its_arena() {
        let registry = Children::embedded(100);
        let scope = registry.guest_scope(100);
        let mut first = registry
            .reserve_guest_id(None, Some(GUEST_CHILD_ARENA_LIMIT))
            .unwrap();
        let pid = first.id();
        assert_eq!(scope.reserve_guest_id(None, Some(1)).unwrap_err().0, EAGAIN);
        first.release_arena();
        assert_eq!(
            scope.reserve_guest_id(Some(pid), None).unwrap_err().0,
            EEXIST
        );
        let second = scope
            .reserve_guest_id(None, Some(GUEST_CHILD_ARENA_LIMIT))
            .unwrap();
        drop(first);
        assert!(scope.reserve_guest_id(Some(pid), None).is_ok());
        assert_eq!(scope.reserve_guest_id(None, Some(1)).unwrap_err().0, EAGAIN);
        drop(second);
        assert!(scope.reserve_guest_id(None, Some(1)).is_ok());
    }

    #[test]
    fn guest_namespace_bounds_process_records_across_generations() {
        let registry = Children::embedded(100);
        let scope = registry.guest_scope(100);
        let records: Vec<_> = (0..GUEST_CHILD_LIMIT)
            .map(|_| scope.reserve_guest_id(None, Some(1)).unwrap())
            .collect();
        assert_eq!(
            registry.reserve_guest_id(None, Some(1)).unwrap_err().0,
            EAGAIN
        );
        assert!(registry.reserve_guest_id(None, None).is_ok());
        drop(records);
        assert!(scope.reserve_guest_id(None, Some(1)).is_ok());
    }
}

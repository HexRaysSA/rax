//! pidfds (`fs/pidfs.c`): descriptors that name a process or a thread.
//!
//! A pidfd names a task by its thread-group ID (the host PID of its
//! process) and its own ID: the thread-group ID again for a process (or its
//! leader thread), a thread ID of that process otherwise. The task is the
//! kernel's `struct pid`: it stays named after the task ends, and a new
//! process that reuses the number is not it.
//!
//! What is known of the task depends on where the pidfd is used (see
//! [`syscall::pidfd`](super::super::syscall::pidfd)): the threads of the
//! calling process and its children are in its own records, and the end
//! of a thread or the reaping of a child is recorded here, through the
//! process's [`Registry`] of its pidfds' tasks, when it happens. The end of any other
//! process is seen through a host [`ExitWatch`] made when the pidfd is (or,
//! for a pidfd a forked child inherits, when the child is created), so a
//! PID the host reuses later is never mistaken for the task.

use std::sync::{Arc, Mutex, Weak};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::host::{self, ExitWatch};

/// `PIDFD_THREAD` (`O_EXCL`): the pidfd names a thread, not its thread
/// group.
pub const PIDFD_THREAD: u32 = super::super::abi::open::O_EXCL;

/// How the end of a task of another process is seen.
#[derive(Debug)]
enum Watch {
    /// Not needed yet: the task is in this process or is its child.
    None,
    /// A host watch (made by this process, or inherited where usable).
    Host(ExitWatch),
    /// The host cannot watch it: its PID is probed.
    Probe,
}

/// The task a pidfd names (the kernel's `struct pid`).
#[derive(Debug)]
pub struct Target {
    /// The thread-group ID of its process.
    pub tgid: i32,
    /// Its ID: `tgid` for the process or its leader.
    pub tid: i32,
    /// It ended, with its wait status when known (`pidfs_exit`).
    ended: Mutex<Option<Option<i32>>>,
    watch: Mutex<Watch>,
}

impl Target {
    /// The task `tid` of process `tgid`. `watch` watches its end through
    /// the host (a task of another process); `ESRCH` when it has ended.
    pub fn new(tgid: i32, tid: i32, watch: bool) -> Result<Arc<Self>, Errno> {
        let watch = if watch {
            match ExitWatch::new(tgid) {
                Ok(Some(w)) => Watch::Host(w),
                Ok(None) => return Err(Errno(ESRCH)),
                Err(_) => Watch::Probe,
            }
        } else {
            Watch::None
        };
        Ok(Arc::new(Target {
            tgid,
            tid,
            ended: Mutex::new(None),
            watch: Mutex::new(watch),
        }))
    }

    /// The inode number every pidfd of the task shares (`pid->ino`): the
    /// PID of a process or leader, the thread ID beside its process's PID
    /// for another thread.
    pub fn ino(&self) -> u64 {
        if self.tid == self.tgid {
            self.tgid as u32 as u64
        } else {
            (u64::from(self.tgid as u32) << 32) | u64::from(self.tid as u32)
        }
    }

    /// Whether it ended, and its wait status then if known.
    pub fn ended(&self) -> Option<Option<i32>> {
        *self.ended.lock().unwrap()
    }

    /// Records its end; a known status replaces an unknown one.
    pub fn end(&self, status: Option<i32>) {
        let mut e = self.ended.lock().unwrap();
        if e.is_none_or(|s| s.is_none()) {
            *e = Some(status);
        }
    }

    /// Whether its process has exited, as the host sees it.
    pub fn exited(&self) -> bool {
        let mut w = self.watch.lock().unwrap();
        if let Watch::Host(x) = &*w
            && let Some(done) = x.exited()
        {
            return done;
        }
        if !matches!(*w, Watch::Probe) {
            match ExitWatch::new(self.tgid) {
                Ok(Some(x)) => {
                    let done = x.exited().unwrap_or(false);
                    *w = Watch::Host(x);
                    return done;
                }
                Ok(None) => return true,
                Err(_) => *w = Watch::Probe,
            }
        }
        host::kill(self.tgid, 0) == Err(Errno(ESRCH))
    }

    /// The host descriptor that becomes readable when its process exits,
    /// if it is watched; `None` otherwise (a watch that must be probed, or
    /// none yet).
    pub fn watch_fd(&self) -> Option<i32> {
        match &*self.watch.lock().unwrap() {
            Watch::Host(x) => x.fd(),
            _ => None,
        }
    }

    /// Whether its end is only found by probing.
    pub fn probed(&self) -> bool {
        matches!(*self.watch.lock().unwrap(), Watch::Probe)
    }
}

/// The tasks a process's pidfds name, by which a thread's exit or a
/// child's reaping reaches them.
#[derive(Debug, Default)]
pub struct Registry {
    targets: Vec<Weak<Target>>,
}

impl Registry {
    /// Records a pidfd's task.
    pub fn add(&mut self, t: &Arc<Target>) {
        self.targets.retain(|w| w.strong_count() > 0);
        self.targets.push(Arc::downgrade(t));
    }

    /// The tasks still named.
    fn live(&self) -> impl Iterator<Item = Arc<Target>> + '_ {
        self.targets.iter().filter_map(Weak::upgrade)
    }

    /// Task `tid` of process `tgid` ended with wait status `status` (a
    /// thread exited; a child was reaped): its pidfds report it. Returns
    /// whether any pidfd names it.
    pub fn task_ended(&self, tgid: i32, tid: i32, status: Option<i32>) -> bool {
        let mut any = false;
        for t in self.live().filter(|t| t.tgid == tgid && t.tid == tid) {
            t.end(status);
            any = true;
        }
        any
    }

    /// Whether a pidfd names process `pid`.
    pub fn names_process(&self, pid: i32) -> bool {
        self.live().any(|t| t.tgid == pid && t.tid == pid)
    }

    /// In a new child process `pid` (after `fork`): a task that had this
    /// PID has ended, and the tasks that were the parent's own or its
    /// children are now another process's, watched through the host from
    /// now.
    pub fn forked(&self, pid: i32) {
        for t in self.live() {
            if t.tgid == pid {
                t.end(None);
                continue;
            }
            let mut w = t.watch.lock().unwrap();
            if t.ended().is_some() || matches!(&*w, Watch::Host(x) if x.fd().is_some()) {
                continue;
            }
            match ExitWatch::new(t.tgid) {
                Ok(Some(x)) => *w = Watch::Host(x),
                Ok(None) => {
                    drop(w);
                    t.end(None);
                }
                Err(_) => *w = Watch::Probe,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_numbers_name_the_task() {
        let me = host::pid();
        let a = Target::new(me, me, false).unwrap();
        let b = Target::new(me, me, false).unwrap();
        assert_eq!(a.ino(), b.ino());
        let t = Target::new(me, 7, false).unwrap();
        assert_ne!(t.ino(), a.ino());
        assert_eq!(t.ino() & 0xffff_ffff, 7);
    }

    #[test]
    fn ends_are_recorded_through_the_registry() {
        let mut reg = Registry::default();
        let t = Target::new(10, 11, false).unwrap();
        reg.add(&t);
        assert_eq!(t.ended(), None);
        assert!(!reg.names_process(10));
        assert!(reg.task_ended(10, 11, None));
        assert_eq!(t.ended(), Some(None));
        // A known status replaces the unknown one, and stays.
        reg.task_ended(10, 11, Some(0x100));
        reg.task_ended(10, 11, Some(0x200));
        assert_eq!(t.ended(), Some(Some(0x100)));
        assert!(!reg.task_ended(10, 12, None));
        // A closed pidfd is forgotten.
        let p = Target::new(10, 10, false).unwrap();
        reg.add(&p);
        assert!(reg.names_process(10));
        drop(p);
        assert!(!reg.names_process(10));
        // After a fork, a task that had the child's PID has ended.
        let old = Target::new(20, 20, false).unwrap();
        reg.add(&old);
        reg.forked(20);
        assert_eq!(old.ended(), Some(None));
    }
}

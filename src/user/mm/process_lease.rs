//! Execution and mapping exclusion for a process-shared address space.
//!
//! A process-local mutex excludes host threads; a native lock excludes other
//! host processes. Unix uses a POSIX record lock on an inherited descriptor;
//! Windows uses an unnamed kernel mutex passed by explicit handle transfer.
//! The host releases a dead process's lock. This is an advisory protocol: every
//! worker must acquire the lease before executing or changing translations.
//!
//! Lock order is the lease, then owner transport, then owner-local MM locks.
//! Same-lease nesting is lexical and does not release the outer lock. Nesting
//! another address space is rejected. Never fork, park a guest thread, or wait
//! for another worker while holding the lease. The process-enabled scheduler
//! forks only in a single-threaded host, as required by LinuxConfig::processes.
//!
//! On Unix, keep exactly one descriptor for the lease inode in each host process:
//! closing *any* duplicate would release that process's POSIX locks. The file
//! is private to this type; share an Arc<ProcessLease>, never duplicate its fd.
//! This is separate from the arena file and is never mapped or sent to guests.

use std::cell::Cell;
#[cfg(unix)]
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::{BorrowedHandle, OwnedHandle};
#[cfg(unix)]
use std::sync::TryLockError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

#[cfg(windows)]
#[path = "process_lease/windows.rs"]
mod windows;

#[cfg(unix)]
type ProcessId = libc::pid_t;
#[cfg(windows)]
type ProcessId = u32;

thread_local! {
    static ACTIVE: Cell<Option<(usize, ProcessId)>> = const { Cell::new(None) };
}

#[derive(Debug)]
pub(crate) struct ProcessLease {
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    native: windows::NativeLease,
    local: Mutex<()>,
    available: AtomicBool,
}

impl ProcessLease {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            file: super::anonymous_file()?,
            #[cfg(windows)]
            native: windows::NativeLease::new()?,
            local: Mutex::new(()),
            available: AtomicBool::new(true),
        })
    }

    /// Adopt a deliberately transferred Windows mutex handle. The handle is
    /// validated as a queryable mutex and made noninheritable in this process.
    #[cfg(windows)]
    pub(crate) fn from_handle(handle: OwnedHandle) -> io::Result<Self> {
        Ok(Self {
            native: windows::NativeLease::from_handle(handle)?,
            local: Mutex::new(()),
            available: AtomicBool::new(true),
        })
    }

    /// Borrow the private mutex for an explicit process-bootstrap handle list.
    /// This does not make the handle inheritable or publish an object name.
    #[cfg(windows)]
    pub(crate) fn handle(&self) -> BorrowedHandle<'_> {
        self.native.handle()
    }

    /// Execute one nonblocking guest turn or one owner transaction.
    ///
    /// Acquisition may wait for the current worker. The closure must not wait
    /// for another worker or fork. Same-lease recursive calls are permitted;
    /// an attempted different-lease nesting fails before running its closure.
    /// A panic escaping any nested call, a poisoned local mutex, or failed
    /// unlock makes subsequent calls fail. Catching that nested panic cannot
    /// commit the outer transaction. Closures must propagate other failures;
    /// this guard cannot detect a panic swallowed entirely inside a closure.
    pub(crate) fn with<T>(&self, run: impl FnOnce() -> T) -> io::Result<T> {
        let pid = process_id();
        let key = self as *const Self as usize;
        if let Some((active, owner)) = ACTIVE.get() {
            if owner != pid {
                return Err(io::Error::other("memory lease inherited while held"));
            }
            if active == key {
                if !self.available.load(Ordering::Acquire) {
                    return Err(io::Error::other("memory lease unavailable"));
                }
                return Ok(self.execute(run));
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let local = self
            .local
            .lock()
            .map_err(|_| io::Error::other("memory lease poisoned"))?;
        if !self.available.load(Ordering::Acquire) {
            return Err(io::Error::other("memory lease unavailable"));
        }
        self.acquire_native()?;
        ACTIVE.set(Some((key, pid)));
        let mut guard = Held {
            lease: self,
            _local: local,
            pid,
            released: false,
        };
        let result = self.execute(run);
        guard.release()?;
        Ok(result)
    }

    fn execute<T>(&self, run: impl FnOnce() -> T) -> T {
        let mut invocation = Invocation {
            lease: self,
            completed: false,
        };
        let result = run();
        invocation.completed = true;
        result
    }

    /// Check the existing single-host-thread fork contract at the syscall
    /// boundary. The caller must keep that thread quiescent through fork;
    /// this check alone cannot synchronize arbitrary external host threads.
    #[cfg(unix)]
    pub(crate) fn check_fork_ready(&self) -> io::Result<()> {
        if ACTIVE.get().is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        match self.local.try_lock() {
            Ok(_guard) if self.available.load(Ordering::Acquire) => Ok(()),
            Ok(_) => Err(io::Error::other("memory lease unavailable")),
            Err(TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(TryLockError::Poisoned(_)) => Err(io::Error::other("memory lease poisoned")),
        }
    }

    /// Observe another process's execution lease without acquiring it.
    ///
    /// Only the broker uses this operation. POSIX F_GETLK omits locks held by
    /// the calling process, so the broker must never execute worker turns.
    /// The canonical descriptor remains private: duplicating and later closing
    /// it in a worker would release that process's record lock.
    #[cfg(unix)]
    pub(crate) fn holder(&self) -> io::Result<Option<ProcessId>> {
        loop {
            let mut lock = record_lock(libc::F_WRLCK as libc::c_int);
            // SAFETY: the canonical file remains live and lock is a fully
            // initialized, writable native flock for byte [0, 1). fcntl writes
            // only that struct and retains no pointer or caller-owned state.
            let result = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETLK, &mut lock) };
            if result == 0 {
                if libc::c_int::from(lock.l_type) == libc::F_UNLCK as libc::c_int {
                    return Ok(None);
                }
                if libc::c_int::from(lock.l_type) != libc::F_WRLCK as libc::c_int
                    || libc::c_int::from(lock.l_whence) != libc::SEEK_SET
                    || lock.l_start != 0
                    || lock.l_len != 1
                    || lock.l_pid <= 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected memory lease lock",
                    ));
                }
                return Ok(Some(lock.l_pid));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Observe kernel mutex ownership without acquiring it. Windows reports
    /// the owning process even when it is the calling process.
    #[cfg(windows)]
    pub(crate) fn holder(&self) -> io::Result<Option<ProcessId>> {
        self.native.holder()
    }

    fn acquire_native(&self) -> io::Result<()> {
        #[cfg(unix)]
        return self.set_lock(libc::F_WRLCK as libc::c_int, true);
        #[cfg(windows)]
        self.native.acquire()
    }

    fn release_native(&self) -> io::Result<()> {
        #[cfg(unix)]
        return self.set_lock(libc::F_UNLCK as libc::c_int, false);
        #[cfg(windows)]
        self.native.release()
    }

    #[cfg(unix)]
    fn set_lock(&self, kind: libc::c_int, wait: bool) -> io::Result<()> {
        let lock = record_lock(kind);
        loop {
            // SAFETY: file is our live, private read/write descriptor. lock
            // is a fully initialized native struct flock for byte [0, 1),
            // and remains alive for the synchronous call. fcntl retains no
            // pointer. Host threads hold local before changing this lock.
            let result = unsafe {
                libc::fcntl(
                    self.file.as_raw_fd(),
                    if wait { libc::F_SETLKW } else { libc::F_SETLK },
                    &lock,
                )
            };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(unix)]
fn process_id() -> ProcessId {
    // SAFETY: getpid takes no pointer and has no mutable caller-owned state.
    unsafe { libc::getpid() }
}

#[cfg(windows)]
fn process_id() -> ProcessId {
    std::process::id()
}

#[cfg(unix)]
fn record_lock(kind: libc::c_int) -> libc::flock {
    // SAFETY: all-zero integer fields form a valid struct flock on Unix.
    // Set every field needed for this process-associated record lock below.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = kind as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_len = 1;
    lock
}

struct Invocation<'a> {
    lease: &'a ProcessLease,
    completed: bool,
}

impl Drop for Invocation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.lease.available.store(false, Ordering::Release);
        }
    }
}

struct Held<'a> {
    lease: &'a ProcessLease,
    _local: MutexGuard<'a, ()>,
    pid: ProcessId,
    released: bool,
}

impl Held<'_> {
    fn release(&mut self) -> io::Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        ACTIVE.set(None);
        let result = if process_id() == self.pid {
            self.lease.release_native()
        } else {
            Err(io::Error::other("fork during memory lease"))
        };
        if result.is_err() {
            self.lease.available.store(false, Ordering::Release);
        }
        result?;
        if !self.lease.available.load(Ordering::Acquire) {
            return Err(io::Error::other("memory lease transaction interrupted"));
        }
        Ok(())
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        // Also release during unwinding. Invocation marks the local lease
        // unavailable even when an outer closure catches a nested panic.
        let _ = self.release();
    }
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test, windows))]
#[path = "process_lease/windows_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
pub(crate) mod test_worker;

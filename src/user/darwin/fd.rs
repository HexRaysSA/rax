//! A process's descriptor table.
//!
//! Guest descriptors are numbered independently of the emulator's own: each
//! names an open file ([`FileRef`]) shared by duplicates and by forked
//! children, as `struct fileglob` is. Host files keep their status flags
//! (`O_APPEND`, `O_NONBLOCK`) on the host descriptor, which the host shares
//! between duplicates exactly as the guest expects. The close-on-exec flag
//! belongs to the descriptor slot.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};

use super::abi::Errno;

/// `OPEN_MAX`-like soft limit of the table (`RLIMIT_NOFILE` soft default).
pub const NOFILE_SOFT: u64 = 256;
/// `RLIMIT_NOFILE` hard limit (`maxfilesperproc` on a typical Mac).
pub const NOFILE_HARD: u64 = 10_240;

/// What an open file is.
#[derive(Debug)]
pub enum FileKind {
    /// A host file, directory, pipe, or device (or a socket the process
    /// was started with).
    Host(OwnedFd),
    /// A host socket.
    Socket(OwnedFd),
    /// A kqueue, by its identity in the process's kqueues.
    Kqueue(u64),
    /// A POSIX shared memory object (`shm_open`), the host's.
    Shm(OwnedFd),
    /// A POSIX named semaphore (`sem_open`), the host's.
    Sem(OwnedFd),
}

/// An open file description.
#[derive(Debug)]
pub struct OpenFile {
    /// The object.
    pub kind: FileKind,
    /// The guest path it was opened by, when known (`F_GETPATH` falls back
    /// to it).
    pub path: Option<Vec<u8>>,
    /// Darwin `O_*` access and status flags the guest opened it with.
    pub flags: Mutex<u32>,
}

impl OpenFile {
    /// A description of a host descriptor.
    pub fn host(fd: OwnedFd, flags: u32, path: Option<Vec<u8>>) -> Self {
        OpenFile {
            kind: FileKind::Host(fd),
            path,
            flags: Mutex::new(flags),
        }
    }

    /// A description of a host socket.
    pub fn socket(fd: OwnedFd, flags: u32) -> Self {
        OpenFile {
            kind: FileKind::Socket(fd),
            path: None,
            flags: Mutex::new(flags),
        }
    }

    /// The host descriptor, if this is a host file.
    pub fn host_fd(&self) -> Option<RawFd> {
        match &self.kind {
            FileKind::Host(fd) | FileKind::Socket(fd) | FileKind::Shm(fd) | FileKind::Sem(fd) => {
                Some(fd.as_raw_fd())
            }
            FileKind::Kqueue(_) => None,
        }
    }
}

/// A shared open file.
pub type FileRef = Arc<OpenFile>;

/// One descriptor slot.
#[derive(Clone, Debug)]
pub struct Fd {
    /// The open file.
    pub file: FileRef,
    /// `FD_CLOEXEC` (`FP_CLOEXEC`): a new image does not keep the
    /// descriptor.
    pub cloexec: bool,
    /// `FD_CLOFORK` (`FP_CLOFORK`): a forked (or spawned) child does not
    /// inherit the descriptor.
    pub clofork: bool,
}

/// The descriptor table.
#[derive(Clone, Debug, Default)]
pub struct FdTable {
    slots: Vec<Option<Fd>>,
}

impl FdTable {
    /// An empty table.
    pub fn new() -> Self {
        FdTable::default()
    }

    /// The table a process starts with: the emulator's standard input,
    /// output, and error duplicated as guest descriptors 0-2 (those that are
    /// open), so the guest closing one leaves the emulator's alone.
    pub fn with_stdio() -> Self {
        let mut t = FdTable::new();
        for fd in 0..3 {
            // SAFETY: fcntl(F_DUPFD_CLOEXEC) takes no pointers; a closed
            // descriptor fails with EBADF and is skipped.
            let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if dup < 0 {
                continue;
            }
            // SAFETY: `dup` is a descriptor this process just created and
            // owns exclusively.
            let owned = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(dup) };
            // SAFETY: fcntl(F_GETFL) on an owned descriptor takes no pointers.
            let fl = unsafe { libc::fcntl(dup, libc::F_GETFL) };
            let flags = if fl < 0 {
                0
            } else {
                super::io::host_to_guest_oflags(fl)
            };
            let socket =
                super::host::fstat(dup).is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFSOCK);
            let file = if socket {
                OpenFile::socket(owned, flags)
            } else {
                OpenFile::host(owned, flags, None)
            };
            t.install_at(fd as usize, Arc::new(file), false);
        }
        t
    }

    /// The slot for descriptor `fd`.
    pub fn get(&self, fd: i32) -> Result<&Fd, Errno> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.slots.get(i))
            .and_then(Option::as_ref)
            .ok_or(Errno::EBADF)
    }

    /// Mutable access to the slot for descriptor `fd`.
    pub fn get_mut(&mut self, fd: i32) -> Result<&mut Fd, Errno> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.slots.get_mut(i))
            .and_then(Option::as_mut)
            .ok_or(Errno::EBADF)
    }

    /// The open file of descriptor `fd`.
    pub fn file(&self, fd: i32) -> Result<FileRef, Errno> {
        Ok(self.get(fd)?.file.clone())
    }

    /// The lowest free descriptor at or above `min` below `limit`.
    pub fn lowest_free(&self, min: usize, limit: u64) -> Result<usize, Errno> {
        let mut i = min;
        while i < self.slots.len() && self.slots[i].is_some() {
            i += 1;
        }
        if i as u64 >= limit {
            return Err(Errno::EMFILE);
        }
        Ok(i)
    }

    /// Installs `file` at the lowest free descriptor (at least `min`).
    pub fn install(
        &mut self,
        file: FileRef,
        cloexec: bool,
        min: usize,
        limit: u64,
    ) -> Result<i32, Errno> {
        self.install_with(file, cloexec, false, min, limit)
    }

    /// Installs `file` at the lowest free descriptor (at least `min`),
    /// close-on-exec and close-on-fork as given.
    pub fn install_with(
        &mut self,
        file: FileRef,
        cloexec: bool,
        clofork: bool,
        min: usize,
        limit: u64,
    ) -> Result<i32, Errno> {
        let i = self.lowest_free(min, limit)?;
        self.install_at(i, file, cloexec);
        self.slots[i].as_mut().expect("just installed").clofork = clofork;
        Ok(i as i32)
    }

    /// Installs `file` at descriptor `i` (not close-on-fork), returning
    /// what was there.
    pub fn install_at(&mut self, i: usize, file: FileRef, cloexec: bool) -> Option<Fd> {
        if self.slots.len() <= i {
            self.slots.resize(i + 1, None);
        }
        self.slots[i].replace(Fd {
            file,
            cloexec,
            clofork: false,
        })
    }

    /// Removes descriptor `fd`.
    pub fn remove(&mut self, fd: i32) -> Result<Fd, Errno> {
        let i = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let slot = self.slots.get_mut(i).ok_or(Errno::EBADF)?;
        let fd = slot.take().ok_or(Errno::EBADF)?;
        while matches!(self.slots.last(), Some(None)) {
            self.slots.pop();
        }
        Ok(fd)
    }

    /// Closes every close-on-exec descriptor (`fdt_exec`).
    pub fn close_on_exec(&mut self) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|f| f.cloexec) {
                *slot = None;
            }
        }
        while matches!(self.slots.last(), Some(None)) {
            self.slots.pop();
        }
    }

    /// The open descriptors, in order.
    pub fn iter(&self) -> impl Iterator<Item = (i32, &Fd)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|f| (i as i32, f)))
    }

    /// One past the highest open descriptor.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no descriptor is open.
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devnull() -> FileRef {
        let f = std::fs::File::open("/dev/null").unwrap();
        Arc::new(OpenFile::host(f.into(), 0, None))
    }

    #[test]
    fn lowest_free_descriptor_is_reused() {
        let mut t = FdTable::new();
        assert_eq!(t.install(devnull(), false, 0, 256), Ok(0));
        assert_eq!(t.install(devnull(), true, 0, 256), Ok(1));
        assert_eq!(t.install(devnull(), false, 0, 256), Ok(2));
        t.remove(1).unwrap();
        assert_eq!(t.install(devnull(), false, 0, 256), Ok(1));
        assert_eq!(t.install(devnull(), false, 10, 256), Ok(10));
        assert_eq!(t.get(5).unwrap_err(), Errno::EBADF);
        assert_eq!(t.get(-1).unwrap_err(), Errno::EBADF);
        assert_eq!(
            t.install(devnull(), false, 0, 3),
            Ok(3).and(Err(Errno::EMFILE))
        );
    }

    #[test]
    fn close_on_exec_closes_only_marked_descriptors() {
        let mut t = FdTable::new();
        t.install(devnull(), false, 0, 256).unwrap();
        t.install(devnull(), true, 0, 256).unwrap();
        t.close_on_exec();
        assert!(t.get(0).is_ok());
        assert!(t.get(1).is_err());
        assert_eq!(t.len(), 1);
    }
}

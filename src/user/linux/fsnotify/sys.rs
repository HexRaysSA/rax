//! The host calls file-system notification makes: shared file mappings,
//! FIFOs, locks, and, on Linux hosts, the host's inotify.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;

fn last_errno() -> Errno {
    Errno::from(std::io::Error::last_os_error())
}

/// A file mapped shared and writable: memory every process mapping the
/// file sees.
pub struct Mapping {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
}

// SAFETY: the bytes are only accessed under the namespace lock (one
// accessor at a time across threads and processes) or, for the words
// `word` returns, atomically.
unsafe impl Send for Mapping {}
// SAFETY: as above.
unsafe impl Sync for Mapping {}

impl Mapping {
    /// Maps `path`, made `len` bytes long (sparse, zero-filled) if it is
    /// shorter.
    pub fn open(path: &Path, len: usize) -> Result<Mapping, Errno> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(path)?;
        if file.metadata()?.len() < len as u64 {
            file.set_len(len as u64)?;
        }
        // SAFETY: a shared mapping of `len` bytes of a file at least that
        // long, with no address hint; the result is checked before use.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(last_errno());
        }
        let ptr = std::ptr::NonNull::new(p.cast()).ok_or(Errno(ENOMEM))?;
        Ok(Mapping { ptr, len })
    }

    /// Word `i` (64-bit, from the start), for lock-free reads.
    pub fn word(&self, i: usize) -> &std::sync::atomic::AtomicU64 {
        assert!(i * 8 + 8 <= self.len);
        // SAFETY: the mapping is page-aligned, so word `i` is aligned for
        // `AtomicU64` (the size and alignment of `u64`) and in bounds;
        // zero-filled pages are a valid value; it lives as long as `self`.
        unsafe { &*self.ptr.as_ptr().add(i * 8).cast() }
    }

    /// The bytes. The caller holds the namespace lock, which makes it
    /// their only accessor.
    #[allow(clippy::mut_from_ref)]
    pub fn bytes(&self) -> &mut [u8] {
        // SAFETY: `len` mapped bytes that live as long as `self`; the
        // namespace lock (held by the caller, across processes) excludes
        // every other access but atomic word reads.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the mapping `open` created, unmapped once; no reference
        // from `word` or `bytes` outlives `self`.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

/// An exclusive `flock` of `file`, released when dropped.
pub struct Lock<'a>(&'a File);

impl<'a> Lock<'a> {
    pub fn new(file: &'a File) -> Result<Self, Errno> {
        // SAFETY: flock takes a descriptor and an integer operation.
        while unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(Errno(EIO));
            }
        }
        Ok(Lock(file))
    }
}

impl Drop for Lock<'_> {
    fn drop(&mut self) {
        // SAFETY: as in `new`.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Makes the FIFO `path` (owner-only), unless it exists.
pub fn mkfifo(path: &Path) -> Result<(), Errno> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno(EINVAL))?;
    // SAFETY: a NUL-terminated path that outlives the call.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(Errno::from(e));
        }
    }
    Ok(())
}

/// Opens the FIFO `path` for reading and writing, non-blocking and
/// close-on-exec: it never waits for a peer, and a byte written stays
/// until read.
pub fn open_fifo(path: &Path) -> Result<OwnedFd, Errno> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno(EINVAL))?;
    // SAFETY: a NUL-terminated path; the descriptor returned is owned once.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: a descriptor open just returned.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether host process `pid` exists.
pub fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 checks for existence without sending anything.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The host's inotify (Linux hosts).
#[cfg(target_os = "linux")]
pub mod host {
    use super::*;

    /// `inotify_init1(flags)` with host flags.
    pub fn init(nonblock: bool) -> Result<OwnedFd, Errno> {
        let flags = libc::IN_CLOEXEC | if nonblock { libc::IN_NONBLOCK } else { 0 };
        // SAFETY: an integer argument; the descriptor returned is owned once.
        let fd = unsafe { libc::inotify_init1(flags) };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: a descriptor inotify_init1 just returned.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// `inotify_add_watch` of host path `path`.
    pub fn add_watch(fd: &OwnedFd, path: &Path, mask: u32) -> Result<i32, Errno> {
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno(EINVAL))?;
        // SAFETY: a descriptor, a NUL-terminated path, and a mask.
        let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), mask) };
        if wd < 0 {
            return Err(last_errno());
        }
        Ok(wd)
    }

    /// `inotify_rm_watch`.
    pub fn rm_watch(fd: &OwnedFd, wd: i32) -> Result<(), Errno> {
        // SAFETY: a descriptor and a watch descriptor.
        if unsafe { libc::inotify_rm_watch(fd.as_raw_fd(), wd) } != 0 {
            return Err(last_errno());
        }
        Ok(())
    }
}

//! Shared memory objects: the host files behind shared mappings.
//!
//! A shared mapping's pages are not copies. The frame arena attaches the
//! host object itself, in extents, with a host `MAP_SHARED` mapping laid
//! over the arena (see [`FrameArena::attach`](super::FrameArena::attach)),
//! so the guest's stores reach the host page cache: the file sees them,
//! `read` and `write` and every other mapping of the object agree with the
//! mapping, and a forked process shares the pages as a Linux child does.
//! Anonymous shared memory (`MAP_SHARED | MAP_ANONYMOUS`, a shared mapping
//! of `/dev/zero`) is an object of its own: a Linux `memfd`, or an unlinked
//! temporary file on other hosts, as Linux backs it with a `shmem` file.

use std::fmt;

use super::backing::SourceIdentity;

/// A host object backing shared mappings.
pub struct SharedObject {
    file: super::mapped_file::MappedFile,
    identity: SourceIdentity,
    writable: bool,
    anonymous: bool,
}

impl fmt::Debug for SharedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedObject")
            .field("identity", &self.identity)
            .field("writable", &self.writable)
            .field("anonymous", &self.anonymous)
            .finish()
    }
}

fn identity_of(file: &std::fs::File) -> std::io::Result<SourceIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        Ok(SourceIdentity {
            dev: m.dev(),
            ino: m.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(SourceIdentity::default())
    }
}

impl SharedObject {
    /// A host file, mapped for writing when `writable` (the file must then
    /// be open for reading and writing).
    pub fn file(file: std::fs::File, writable: bool) -> std::io::Result<Self> {
        Ok(SharedObject {
            identity: identity_of(&file)?,
            file: super::mapped_file::MappedFile::new(file),
            writable,
            anonymous: false,
        })
    }

    /// A new anonymous object of `len` bytes, zero-filled
    /// (`shmem_zero_setup`).
    pub fn anonymous(len: u64) -> std::io::Result<Self> {
        let file = anonymous_file()?;
        file.set_len(len)?;
        Ok(SharedObject {
            identity: identity_of(&file)?,
            file: super::mapped_file::MappedFile::new(file),
            writable: true,
            anonymous: true,
        })
    }

    /// Current size in bytes.
    pub fn len(&self) -> u64 {
        self.file.metadata().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether the object is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Device and inode, which also identify the object among others.
    pub fn identity(&self) -> SourceIdentity {
        self.identity
    }

    /// Whether mappings of it may be written.
    pub fn writable(&self) -> bool {
        self.writable
    }

    /// Whether it is anonymous shared memory.
    pub fn is_anonymous(&self) -> bool {
        self.anonymous
    }

    /// The host file.
    pub fn host_file(&self) -> &std::fs::File {
        &self.file
    }

    /// Zeroes `len` bytes from `offset`, within the object's size (a hole
    /// punched with the size kept, as readers see it).
    pub fn zero_range(&self, offset: u64, len: u64) -> std::io::Result<()> {
        let end = offset.saturating_add(len).min(self.len());
        let zeros = vec![0u8; 64 << 10];
        let mut at = offset;
        while at < end {
            let n = ((end - at) as usize).min(zeros.len());
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileExt;
                self.file.write_all_at(&zeros[..n], at)?;
            }
            at += n as u64;
        }
        Ok(())
    }

    /// Reads up to `buf.len()` bytes at `offset` (short only at the end).
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            let mut done = 0;
            while done < buf.len() {
                let n = self.file.read_at(&mut buf[done..], offset + done as u64)?;
                if n == 0 {
                    break;
                }
                done += n;
            }
            Ok(done)
        }
        #[cfg(not(unix))]
        {
            let _ = (offset, buf);
            Ok(0)
        }
    }
}

/// A new, empty, nameless host file: a `memfd` on Linux, an unlinked
/// temporary file elsewhere.
pub fn anonymous_file() -> std::io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        // SAFETY: memfd_create takes a NUL-terminated name and flags and
        // returns a new descriptor this function then owns.
        let fd = unsafe { libc::memfd_create(c"rax-shmem".as_ptr(), libc::MFD_CLOEXEC) };
        if fd >= 0 {
            // SAFETY: `fd` is a fresh descriptor owned by nobody else.
            return Ok(unsafe { std::fs::File::from_raw_fd(fd) });
        }
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "rax-shmem-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_CLOEXEC);
        }
        match opts.open(&path) {
            Ok(f) => {
                std::fs::remove_file(&path)?;
                return Ok(f);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

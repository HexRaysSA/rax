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
//! Host memory that is no file (a [`HostMemory`], such as a Mach memory
//! entry) is attached the same way, mapped by the object itself.

use std::fmt;
use std::sync::Arc;

use super::backing::SourceIdentity;

/// Host memory that is not a file: an object the host maps directly (a
/// Mach memory entry on macOS), which a personality provides. The frame
/// arena lays its extents over the arena with [`HostMemory::map_at`].
pub trait HostMemory: Send + Sync + fmt::Debug {
    /// Its size in bytes, a multiple of the host page.
    fn size(&self) -> u64;

    /// Maps `len` bytes of it from `offset` (host-page aligned, within
    /// [`HostMemory::size`]) over the host memory at `at`, replacing what
    /// is there, shared and writable when `writable`.
    ///
    /// # Safety
    /// `[at, at + len)` must be host-page-aligned memory of the caller's
    /// own mapping that nothing references while it is replaced (an arena
    /// extent).
    unsafe fn map_at(
        &self,
        at: *mut u8,
        offset: u64,
        len: u64,
        writable: bool,
    ) -> std::io::Result<()>;

    /// Reads up to `buf.len()` bytes at `offset` (short only at the end).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// The object itself, for the personality that made it.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// What holds a shared object's contents.
enum Store {
    /// A host file.
    File(super::mapped_file::MappedFile),
    /// Host memory that is no file.
    Memory(Arc<dyn HostMemory>),
}

/// A host object backing shared mappings.
pub struct SharedObject {
    store: Store,
    identity: SourceIdentity,
    writable: bool,
    anonymous: bool,
    /// The System V segment it is, by identifier.
    sysv: Option<i32>,
    /// A size fixed at creation that the host maps no further than (a
    /// Darwin POSIX shared memory object's).
    limit: Option<u64>,
}

impl fmt::Debug for SharedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedObject")
            .field("identity", &self.identity)
            .field("writable", &self.writable)
            .field("anonymous", &self.anonymous)
            .field("sysv", &self.sysv)
            .finish()
    }
}

impl SharedObject {
    /// A host file, mapped for writing when `writable` (the file must then
    /// be open for reading and writing).
    pub fn file(file: std::fs::File, writable: bool) -> std::io::Result<Self> {
        Self::file_keeping(file, writable, None)
    }

    /// [`SharedObject::file`], keeping `keep` while it lives.
    pub fn file_keeping(
        file: std::fs::File,
        writable: bool,
        keep: Option<super::Keep>,
    ) -> std::io::Result<Self> {
        let file = super::mapped_file::MappedFile::keeping(file, keep);
        Ok(SharedObject {
            identity: file.identity()?,
            store: Store::File(file),
            writable,
            anonymous: false,
            sysv: None,
            limit: None,
        })
    }

    /// The host file of System V shared memory segment `id` (a shmem
    /// object, as `/proc/<pid>/maps` shows it).
    pub fn sysv(file: std::fs::File, writable: bool, id: i32) -> std::io::Result<Self> {
        let file = super::mapped_file::MappedFile::new(file);
        Ok(SharedObject {
            identity: file.identity()?,
            store: Store::File(file),
            writable,
            anonymous: true,
            sysv: Some(id),
            limit: None,
        })
    }

    /// The System V segment it is, by identifier.
    pub fn sysv_id(&self) -> Option<i32> {
        self.sysv
    }

    /// A new anonymous object of `len` bytes, zero-filled
    /// (`shmem_zero_setup`).
    pub fn anonymous(len: u64) -> std::io::Result<Self> {
        let file = anonymous_file()?;
        file.set_len(len)?;
        let file = super::mapped_file::MappedFile::new(file);
        Ok(SharedObject {
            identity: file.identity()?,
            store: Store::File(file),
            writable: true,
            anonymous: true,
            sysv: None,
            limit: None,
        })
    }

    /// A host object of fixed size `len` whose device and inode do not
    /// identify it (a Darwin POSIX shared memory object reports zero for
    /// both): it gets an identity of its own, so that its extents are never
    /// taken for another object's, and is mapped no further than `len`
    /// rounded up to a host page.
    pub fn fixed(file: std::fs::File, writable: bool, len: u64) -> Self {
        SharedObject {
            identity: own_identity(),
            store: Store::File(super::mapped_file::MappedFile::new(file)),
            writable,
            anonymous: false,
            sysv: None,
            limit: Some(len),
        }
    }

    /// Host memory `memory`, mapped for writing when `writable`: of fixed
    /// size, with an identity of its own (as [`SharedObject::fixed`]).
    pub fn host_memory(memory: Arc<dyn HostMemory>, writable: bool) -> Self {
        let len = memory.size();
        SharedObject {
            identity: own_identity(),
            store: Store::Memory(memory),
            writable,
            anonymous: false,
            sysv: None,
            limit: Some(len),
        }
    }

    /// How many bytes of the object from `start` (an extent's first byte)
    /// the host maps: an extent's worth, or up to the end of a fixed-size
    /// object rounded to a host page.
    pub fn extent_len(&self, start: u64, extent: u64, host_page: u64) -> u64 {
        match self.limit {
            None => extent,
            Some(len) => len
                .saturating_sub(start)
                .div_ceil(host_page)
                .saturating_mul(host_page)
                .min(extent),
        }
    }

    /// Current size in bytes.
    pub fn len(&self) -> u64 {
        match &self.store {
            Store::File(f) => f.metadata().map(|m| m.len()).unwrap_or(0),
            Store::Memory(m) => m.size(),
        }
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

    /// The host file, unless the object is host memory.
    pub fn host_file(&self) -> Option<&std::fs::File> {
        match &self.store {
            Store::File(f) => Some(f),
            Store::Memory(_) => None,
        }
    }

    /// The host memory, if the object is not a file.
    pub fn memory(&self) -> Option<&Arc<dyn HostMemory>> {
        match &self.store {
            Store::File(_) => None,
            Store::Memory(m) => Some(m),
        }
    }

    /// Writes bytes within this writable object's current size. The
    /// operation does not grow the object or move a backing file's cursor.
    /// Empty writes are no-ops; an invalid range is rejected before writing.
    /// Host-memory objects without a file do not support this operation.
    pub fn write_all_at(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if !self.writable {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        if end > self.len() {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        match &self.store {
            Store::File(file) => file.write_all_at(offset, data),
            Store::Memory(_) => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }

    /// Zeroes `len` bytes from `offset`, within the object's size (a hole
    /// punched with the size kept, as readers see it); host memory cannot
    /// be written this way. Work uses a bounded 64 KiB buffer.
    pub fn zero_range(&self, offset: u64, len: u64) -> std::io::Result<()> {
        if !matches!(self.store, Store::File(_)) {
            return Err(std::io::ErrorKind::Unsupported.into());
        }
        let end = offset.saturating_add(len).min(self.len());
        let zeros = vec![0u8; 64 << 10];
        let mut at = offset;
        while at < end {
            let n = (end - at).min(zeros.len() as u64) as usize;
            self.write_all_at(at, &zeros[..n])?;
            at += n as u64;
        }
        Ok(())
    }

    /// Reads up to `buf.len()` bytes at `offset` (short only at the end),
    /// without moving a backing file's shared cursor.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        match &self.store {
            Store::File(file) => file.read_at(offset, buf),
            Store::Memory(memory) => memory.read_at(offset, buf),
        }
    }
}

/// A new identity no host object has (device `u64::MAX`).
fn own_identity() -> SourceIdentity {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    SourceIdentity {
        dev: u64::MAX,
        ino: NEXT.fetch_add(1, Ordering::Relaxed),
    }
}

/// A new, empty, nameless host file: a `memfd` on Linux, an unlinked
/// temporary file elsewhere.
pub fn anonymous_file() -> std::io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        // The raw system call, not glibc's wrapper: `memfd_create(3)` only
        // exists from glibc 2.27, and older sysroots (the `cross` images'
        // glibc) cannot link it. A kernel before 3.17 answers ENOSYS and
        // the temporary file below stands in.
        // SAFETY: memfd_create takes a NUL-terminated name and flags and
        // returns a new descriptor this function then owns; the name is a
        // static C string and outlives the call.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"rax-shmem".as_ptr(),
                libc::MFD_CLOEXEC,
            )
        };
        if fd >= 0 {
            // SAFETY: `fd` is a fresh descriptor owned by nobody else, and
            // a descriptor fits in a `c_int`.
            return Ok(unsafe { std::fs::File::from_raw_fd(fd as libc::c_int) });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    fn temp() -> std::fs::File {
        let f = anonymous_file().unwrap();
        f.set_len(3 * 4096).unwrap();
        f
    }

    #[test]
    fn fixed_objects_map_to_their_end_and_have_their_own_identity() {
        let extent = 256 << 10;
        let a = SharedObject::fixed(temp(), true, 5000);
        let b = SharedObject::fixed(temp(), true, 5000);
        assert_ne!(a.identity(), b.identity());
        // 5000 bytes round up to two 4 KiB pages or one 16 KiB page.
        assert_eq!(a.extent_len(0, extent, 4096), 8192);
        assert_eq!(a.extent_len(0, extent, 16384), 16384);
        assert_eq!(a.extent_len(extent, extent, 4096), 0);
        let big = SharedObject::fixed(temp(), true, 3 * extent);
        assert_eq!(big.extent_len(extent, extent, 4096), extent);
        // An object that can grow maps whole extents.
        let file = SharedObject::file(temp(), true).unwrap();
        assert_eq!(file.extent_len(0, extent, 4096), extent);
    }

    #[test]
    fn positional_data_crosses_view_boundaries_without_moving_shared_cursor() {
        let offset = 65531;
        let bytes: Vec<u8> = (0..(1 << 20) + 17).map(|i| (i % 251) as u8).collect();
        let object = SharedObject::anonymous(offset + bytes.len() as u64 + 3).unwrap();
        let mut cursor = object.host_file().unwrap();
        cursor.seek(SeekFrom::Start(37)).unwrap();
        object.write_all_at(offset, &bytes).unwrap();
        assert_eq!(cursor.stream_position().unwrap(), 37);
        let mut result = vec![0xcc; bytes.len() + 10];
        let got = object.read_at(offset, &mut result).unwrap();
        assert_eq!(got, bytes.len() + 3);
        assert_eq!(&result[..bytes.len()], &bytes);
        assert_eq!(&result[bytes.len()..got], &[0; 3]);
        assert_eq!(&result[got..], &[0xcc; 7]);
        assert_eq!(cursor.stream_position().unwrap(), 37);

        // Ordinary file I/O sees the write, and a private page source reads
        // the same bytes without moving this duplicate handle's cursor.
        cursor.seek(SeekFrom::Start(offset)).unwrap();
        let mut direct = [0; 17];
        cursor.read_exact(&mut direct).unwrap();
        assert_eq!(&direct, &bytes[..17]);
        let saved = cursor.stream_position().unwrap();
        let source = crate::user::mm::HostFileSource::new(cursor.try_clone().unwrap()).unwrap();
        use crate::user::mm::PageSource;
        assert_eq!(source.read_at(offset + 1, &mut direct).unwrap(), 17);
        assert_eq!(&direct, &bytes[1..18]);
        assert_eq!(cursor.stream_position().unwrap(), saved);
    }

    #[test]
    fn positional_bounds_and_readonly_errors_do_not_mutate_the_object() {
        let object = SharedObject::anonymous(8).unwrap();
        object.write_all_at(0, b"12345678").unwrap();
        for (offset, bytes) in [(7, &b"xx"[..]), (u64::MAX - 1, &b"xxx"[..])] {
            assert_eq!(
                object.write_all_at(offset, bytes).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        object.write_all_at(u64::MAX, &[]).unwrap();
        let readonly =
            SharedObject::file(object.host_file().unwrap().try_clone().unwrap(), false).unwrap();
        assert_eq!(
            readonly.write_all_at(0, b"x").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            readonly.zero_range(0, 1).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let mut bytes = [0; 8];
        assert_eq!(object.read_at(0, &mut bytes).unwrap(), 8);
        assert_eq!(&bytes, b"12345678");
        assert_eq!(object.len(), 8);
        assert_eq!(object.read_at(8, &mut bytes).unwrap(), 0);
        assert_eq!(&bytes, b"12345678");
        assert_eq!(
            object.read_at(u64::MAX, &mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(object.read_at(u64::MAX, &mut []).unwrap(), 0);
    }

    #[test]
    fn zeroing_clamps_at_end_and_preserves_prefix_cursor_and_size() {
        let size = (128 << 10) + 7;
        let object = SharedObject::anonymous(size).unwrap();
        object.write_all_at(0, &vec![0x5a; size as usize]).unwrap();
        let mut cursor = object.host_file().unwrap();
        cursor.seek(SeekFrom::Start(5)).unwrap();
        object.zero_range(3, u64::MAX).unwrap();
        object.zero_range(u64::MAX, 9).unwrap();
        assert_eq!(cursor.stream_position().unwrap(), 5);
        assert_eq!(object.len(), size);
        let mut bytes = vec![0xff; size as usize];
        assert_eq!(object.read_at(0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes[..3], &[0x5a; 3]);
        assert!(bytes[3..].iter().all(|&b| b == 0));
        assert_eq!(cursor.stream_position().unwrap(), 5);
    }
}

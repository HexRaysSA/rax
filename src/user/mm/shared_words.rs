//! Anonymous shared atomic storage for process-personality objects.
//!
//! Unix mappings remain shared across fork. Windows uses an unnamed paging-file
//! section; no filesystem path or globally named IPC object is created. The
//! allocation is owned by this object and accessible only through atomic words.

use std::io;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU64;

/// Zero-initialized atomic words in a host shared-memory mapping.
pub struct SharedWords {
    ptr: NonNull<AtomicU64>,
    len: usize,
    bytes: usize,
}

// SAFETY: shared access exposes atomic operations only; ownership retains the
// mapping until all borrowed slices expire, including borrows on other threads.
unsafe impl Send for SharedWords {}
unsafe impl Sync for SharedWords {}

impl SharedWords {
    /// Allocate `len` zeroed words. Reject byte-size overflow and allocations
    /// larger than Rust's maximum slice before making any host allocation.
    pub fn new(len: usize) -> io::Result<Self> {
        let bytes = len
            .max(1)
            .checked_mul(size_of::<AtomicU64>())
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        let ptr = platform::allocate(bytes)?;
        Ok(Self { ptr, len, bytes })
    }

    /// Access the allocation's atomic words (empty for a zero-length request).
    pub fn words(&self) -> &[AtomicU64] {
        // SAFETY: the host mapping is aligned, zero initialized, and at least
        // len * size_of::<AtomicU64>() bytes. The checked size fits isize. No
        // non-atomic accesses or unmapping occur during this borrow.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for SharedWords {
    fn drop(&mut self) {
        // SAFETY: this is the unique owner of this live mapping.
        unsafe { platform::release(self.ptr, self.bytes) }
    }
}

impl std::fmt::Debug for SharedWords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedWords")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    pub fn allocate(bytes: usize) -> io::Result<NonNull<AtomicU64>> {
        // SAFETY: anonymous mapping, no fixed address, valid positive length.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        match NonNull::new(ptr.cast()) {
            Some(ptr) => Ok(ptr),
            None => {
                // SAFETY: even a mapping at address zero must be released.
                unsafe {
                    libc::munmap(ptr, bytes);
                }
                Err(io::ErrorKind::OutOfMemory.into())
            }
        }
    }
    pub unsafe fn release(ptr: NonNull<AtomicU64>, bytes: usize) {
        // SAFETY: caller owns precisely this live mapping.
        unsafe {
            libc::munmap(ptr.as_ptr().cast(), bytes);
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileMappingW(
            file: Handle,
            attributes: *const c_void,
            protect: u32,
            size_high: u32,
            size_low: u32,
            name: *const u16,
        ) -> Handle;
        fn MapViewOfFile(
            mapping: Handle,
            access: u32,
            offset_high: u32,
            offset_low: u32,
            bytes: usize,
        ) -> *mut c_void;
        fn UnmapViewOfFile(base: *const c_void) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }
    pub fn allocate(bytes: usize) -> io::Result<NonNull<AtomicU64>> {
        let size = bytes as u64;
        // SAFETY: INVALID_HANDLE_VALUE selects zero-filled paging-file storage;
        // null attributes/name create an unnamed non-inheritable object.
        // PAGE_READWRITE=4 and FILE_MAP_WRITE=2 are Win32 constants.
        let mapping = unsafe {
            CreateFileMappingW(
                -1isize as Handle,
                std::ptr::null(),
                4,
                (size >> 32) as u32,
                size as u32,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: valid section handle; offset zero and size match the section.
        let view = unsafe { MapViewOfFile(mapping, 2, 0, 0, bytes) };
        let result = NonNull::new(view.cast()).ok_or_else(io::Error::last_os_error);
        // SAFETY: close our handle once. A successful view keeps an internal
        // reference to the section until UnmapViewOfFile (Microsoft memoryapi).
        unsafe {
            CloseHandle(mapping);
        }
        result
    }
    pub unsafe fn release(ptr: NonNull<AtomicU64>, _bytes: usize) {
        // SAFETY: caller owns precisely this mapped view.
        unsafe {
            UnmapViewOfFile(ptr.as_ptr().cast());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::Ordering};

    #[test]
    fn empty_and_overflowing_lengths() {
        assert!(SharedWords::new(0).unwrap().words().is_empty());
        for len in [usize::MAX, isize::MAX as usize / size_of::<AtomicU64>() + 1] {
            assert_eq!(
                SharedWords::new(len).unwrap_err().kind(),
                io::ErrorKind::OutOfMemory
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_mapping_remains_shared_after_fork() {
        let words = SharedWords::new(1).unwrap();
        // SAFETY: the child performs only lock-free atomic access and _exit;
        // it neither allocates nor calls Rust destructors after fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            words.words()[0].store(0x1234_abcd, Ordering::Release);
            unsafe { libc::_exit(0) }
        }
        let mut status = 0;
        loop {
            // SAFETY: valid status pointer; wait for this exact child only.
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(words.words()[0].load(Ordering::Acquire), 0x1234_abcd);
    }

    #[test]
    fn zeroed_aligned_and_shared_between_threads() {
        let words = Arc::new(SharedWords::new(1025).unwrap());
        assert_eq!(words.words().as_ptr() as usize % align_of::<AtomicU64>(), 0);
        assert!(words.words().iter().all(|w| w.load(Ordering::Relaxed) == 0));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let words = &words;
                scope.spawn(move || {
                    for _ in 0..1000 {
                        words.words()[1024].fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(words.words()[1024].load(Ordering::Relaxed), 4000);
    }
}

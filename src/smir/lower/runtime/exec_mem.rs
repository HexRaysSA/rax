//! Executable-code allocation and platform mapping ownership.

/// W^X executable memory holding a finalized lowered block. Maps RW, copies the
/// code in, then flips to RX. Drop normally unmaps it; x86-64 code running under
/// Rosetta retains an inaccessible virtual-address reservation to prevent stale
/// translated-code aliasing.
pub struct ExecMem {
    pub(super) ptr: *mut u8,
    pub(super) len: usize,
}

#[cfg(windows)]
#[path = "exec_mem/windows.rs"]
mod windows;

impl ExecMem {
    /// Map `code` into a fresh W^X region and make it executable.
    ///
    /// The mechanism is host-specific: x86-64 (and any non-aarch64 unix) map RW,
    /// copy, then `mprotect` to RX. Apple-Silicon macOS uses a `MAP_JIT` region
    /// with `pthread_jit_write_protect_np` toggling plus an explicit I-cache
    /// invalidate. Linux/aarch64 maps RW→RX and flushes via `__clear_cache`.
    /// Windows allocates RW pages, protects them RX and flushes its instruction
    /// cache. Other non-Unix hosts reject native execution.
    pub fn new(code: &[u8]) -> Result<Self, ExecMemError> {
        if code.is_empty() {
            return Err(ExecMemError::Empty);
        }
        let len = (code.len() + 0xFFF) & !0xFFF;
        let ptr = Self::map_code(code, len)?;
        Ok(ExecMem { ptr, len })
    }

    /// Address range of the executable mapping, for async-signal-safe JIT
    /// crash diagnostics. The returned span includes page-alignment padding.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn mapping_bounds(&self) -> (*const u8, usize) {
        (self.ptr.cast_const(), self.len)
    }

    /// RW map → copy → `mprotect` RX. Used on x86-64 and any non-aarch64 Unix.
    #[cfg(all(not(target_arch = "aarch64"), unix))]
    fn map_code(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ExecMemError::Mmap);
        }
        let ptr = ptr as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len()) };
        if unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } != 0
        {
            unsafe { libc::munmap(ptr as *mut libc::c_void, len) };
            return Err(ExecMemError::Mprotect);
        }
        Ok(ptr)
    }

    #[cfg(windows)]
    fn map_code(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
        windows::map(code, len)
    }

    /// Hosts without an executable mapping cannot run lowered native code.
    /// Reject before allocating so interpretation stays the semantic path.
    /// `wasm32-wasip2` is in this set: its `mmap` is not a W^X JIT heap.
    #[cfg(not(any(unix, windows)))]
    fn map_code(_code: &[u8], _len: usize) -> Result<*mut u8, ExecMemError> {
        Err(ExecMemError::Unsupported)
    }

    /// Apple-Silicon macOS: a `MAP_JIT` RWX region. Writing it requires the
    /// calling thread to be in *write* mode (`pthread_jit_write_protect_np(0)`);
    /// after the copy we flip back to *execute* mode and invalidate the I-cache
    /// for the written range. The thread is left in execute mode, so even if a
    /// different thread later runs the block (`ExecMem` is `Send`/`Sync`) it sees
    /// executable pages. The toggle is thread-local; a thread that never wrote
    /// JIT memory is already in execute mode by default.
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    fn map_code(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ExecMemError::Mmap);
        }
        let ptr = ptr as *mut u8;
        unsafe {
            libc::pthread_jit_write_protect_np(0);
            core::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());
            libc::pthread_jit_write_protect_np(1);
            super::sys_icache_invalidate(ptr as *mut core::ffi::c_void, len);
        }
        Ok(ptr)
    }

    /// Linux/aarch64: RW map → copy → `mprotect` RX → `__clear_cache`.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn map_code(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ExecMemError::Mmap);
        }
        let ptr = ptr as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len()) };
        if unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } != 0
        {
            unsafe { libc::munmap(ptr as *mut libc::c_void, len) };
            return Err(ExecMemError::Mprotect);
        }
        unsafe {
            super::__clear_cache(
                ptr as *mut core::ffi::c_char,
                ptr.add(len) as *mut core::ffi::c_char,
            )
        };
        Ok(ptr)
    }
}

impl Drop for ExecMem {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
            if super::running_under_rosetta() {
                // Rosetta can retain a translated block after munmap and reuse it
                // if another thread immediately receives the same executable
                // virtual address. Keep the address reserved for this process while
                // releasing its physical pages, which prevents stale-code aliasing.
                unsafe {
                    libc::mprotect(self.ptr as *mut libc::c_void, self.len, libc::PROT_NONE);
                    libc::madvise(self.ptr as *mut libc::c_void, self.len, libc::MADV_DONTNEED);
                }
                return;
            }
            unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
        }
        #[cfg(windows)]
        unsafe {
            windows::release(self.ptr)
        };
        #[cfg(not(any(unix, windows)))]
        {
            // `map_code` rejects before any allocation, so there is no mapping
            // to release. Touch the fields so an unused-field lint stays quiet.
            let _ = (self.ptr, self.len);
        }
    }
}

// SAFETY: an ExecMem owns a private W^X mapping of immutable native code. After
// construction the bytes never change, and execution only reads them; the
// owning vcpu is the sole accessor. Sending the mapping to another thread (when
// a vcpu migrates) or sharing &ExecMem for read-only execution is therefore
// sound. The raw pointer alone makes ExecMem !Send/!Sync by default.
unsafe impl Send for ExecMem {}
unsafe impl Sync for ExecMem {}

/// Errors mapping/executing a lowered block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMemError {
    /// Empty code buffer.
    Empty,
    /// `mmap` failed.
    Mmap,
    /// `mprotect` to RX failed.
    Mprotect,
    /// A Windows executable-memory operation failed with its native error.
    Windows { operation: &'static str, code: u32 },
    /// This host cannot create executable memory. Native execution is unused.
    Unsupported,
}

impl core::fmt::Display for ExecMemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExecMemError::Empty => write!(f, "empty code buffer"),
            ExecMemError::Mmap => write!(f, "mmap failed"),
            ExecMemError::Mprotect => write!(f, "mprotect to RX failed"),
            ExecMemError::Windows { operation, code } => {
                write!(f, "{operation} failed with Windows error {code}")
            }
            ExecMemError::Unsupported => {
                write!(f, "executable memory is not available on this host")
            }
        }
    }
}

impl std::error::Error for ExecMemError {}

#[cfg(all(test, not(any(unix, windows))))]
mod non_unix_exec_mem {
    use super::*;

    // `ExecMem` owns a mapping and has no `PartialEq`/`Debug`; match the error.
    #[test]
    fn empty_code_is_rejected_before_mapping() {
        assert!(matches!(ExecMem::new(&[]), Err(ExecMemError::Empty)));
    }

    #[test]
    fn executable_mapping_is_unsupported() {
        assert!(matches!(
            ExecMem::new(&[0xC3]),
            Err(ExecMemError::Unsupported)
        ));
    }
}

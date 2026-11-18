//! Memory the host can execute, for native code.
//!
//! The code is written once, when the mapping is made, and never changed.
//! No dependency supplies the system calls: the few this needs are declared
//! here, with the constants of the systems it is built for.

use std::ffi::c_void;

use crate::Error;

unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: i32,
        flags: i32,
        descriptor: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> i32;
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn mprotect(address: *mut c_void, length: usize, protection: i32) -> i32;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe extern "C" {
    fn pthread_jit_write_protect_np(enabled: i32);
    fn sys_icache_invalidate(start: *mut c_void, length: usize);
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
unsafe extern "C" {
    fn __clear_cache(start: *mut c_void, end: *mut c_void);
}

const READ: i32 = 1;
const WRITE: i32 = 2;
const EXECUTE: i32 = 4;
const PRIVATE: i32 = 2;
#[cfg(target_os = "macos")]
const ANONYMOUS: i32 = 0x1000;
#[cfg(not(target_os = "macos"))]
const ANONYMOUS: i32 = 0x20;
/// macOS on Apple silicon maps code with this flag, and a thread writes it
/// only between two calls that switch the mapping for that thread.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const JIT: i32 = 0x800;

fn unavailable(what: &'static str) -> Error {
    Error::resource("EXEC_NATIVE_MEMORY", what)
}

/// A mapping that holds native code.
pub(super) struct Executable {
    base: *mut u8,
    length: usize,
}

// SAFETY: the mapping is written only while it is made and is read-only and
// executable afterwards; any thread may run or read it.
unsafe impl Send for Executable {}
// SAFETY: as above.
unsafe impl Sync for Executable {}

impl Executable {
    /// Map `code` so that it can be run.
    pub(super) fn new(code: &[u8]) -> Result<Self, Error> {
        if code.is_empty() {
            return Err(unavailable("no code to map"));
        }
        let length = code
            .len()
            .checked_next_multiple_of(1 << 14)
            .ok_or_else(|| unavailable("code size"))?;
        let base = Self::map(code, length)?;
        Ok(Self { base, length })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn map(code: &[u8], length: usize) -> Result<*mut u8, Error> {
        // SAFETY: a fresh anonymous mapping; nothing else refers to it.
        let base = unsafe {
            mmap(
                std::ptr::null_mut(),
                length,
                READ | WRITE | EXECUTE,
                PRIVATE | ANONYMOUS | JIT,
                -1,
                0,
            )
        };
        if base as isize == -1 {
            return Err(unavailable("the host refused an executable mapping"));
        }
        // SAFETY: the mapping is `length` bytes, at least `code.len()`, and
        // writable by this thread between the two switches.
        unsafe {
            pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(code.as_ptr(), base.cast::<u8>(), code.len());
            pthread_jit_write_protect_np(1);
            sys_icache_invalidate(base, length);
        }
        Ok(base.cast())
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn map(code: &[u8], length: usize) -> Result<*mut u8, Error> {
        // SAFETY: a fresh anonymous mapping; nothing else refers to it.
        let base = unsafe {
            mmap(
                std::ptr::null_mut(),
                length,
                READ | WRITE,
                PRIVATE | ANONYMOUS,
                -1,
                0,
            )
        };
        if base as isize == -1 {
            return Err(unavailable("the host refused a mapping"));
        }
        // SAFETY: the mapping is `length` bytes, at least `code.len()`, and
        // still writable.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), base.cast::<u8>(), code.len()) };
        // SAFETY: the mapping made above, whole.
        if unsafe { mprotect(base, length, READ | EXECUTE) } != 0 {
            // SAFETY: as above.
            unsafe { munmap(base, length) };
            return Err(unavailable("the host refused to make code executable"));
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        // SAFETY: the range is the mapping.
        unsafe {
            __clear_cache(base, base.cast::<u8>().add(length).cast());
        }
        Ok(base.cast())
    }

    /// The address of the byte at `offset`.
    pub(super) fn address(&self, offset: usize) -> usize {
        debug_assert!(offset < self.length);
        self.base as usize + offset
    }
}

impl Drop for Executable {
    fn drop(&mut self) {
        // Under Rosetta an address that held translated code must not come
        // to hold other code, so there the mapping is kept.
        if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            return;
        }
        // SAFETY: the mapping made in `new`, whole; no code of it runs once
        // its owner is dropped.
        unsafe { munmap(self.base.cast(), self.length) };
    }
}

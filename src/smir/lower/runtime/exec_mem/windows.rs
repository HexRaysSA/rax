//! Windows RW-to-RX mappings with instruction-cache publication.

use super::ExecMemError;
use core::ffi::c_void;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(address: *mut c_void, size: usize, kind: u32, protection: u32) -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, size: usize, protection: u32, old: *mut u32) -> i32;
    fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetLastError() -> u32;
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
}

fn last_error(operation: &'static str) -> ExecMemError {
    ExecMemError::Windows {
        operation,
        code: unsafe { GetLastError() },
    }
}

pub(super) fn map(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
    let pointer = unsafe {
        VirtualAlloc(
            core::ptr::null_mut(),
            len,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if pointer.is_null() {
        return Err(last_error("VirtualAlloc"));
    }
    // The private committed region has at least code.len() writable bytes.
    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), pointer.cast(), code.len()) };
    let mut old = 0;
    if unsafe { VirtualProtect(pointer, len, PAGE_EXECUTE_READ, &mut old) } == 0 {
        let error = last_error("VirtualProtect");
        unsafe { release(pointer.cast()) };
        return Err(error);
    }
    if unsafe { FlushInstructionCache(GetCurrentProcess(), pointer, code.len()) } == 0 {
        let error = last_error("FlushInstructionCache");
        unsafe { release(pointer.cast()) };
        return Err(error);
    }
    Ok(pointer.cast())
}

/// Release only the allocation base returned by VirtualAlloc; MEM_RELEASE
/// requires a zero size and frees its entire reserved region.
pub(super) unsafe fn release(pointer: *mut u8) {
    unsafe { VirtualFree(pointer.cast(), 0, MEM_RELEASE) };
}

#[cfg(test)]
#[path = "windows/tests.rs"]
mod tests;

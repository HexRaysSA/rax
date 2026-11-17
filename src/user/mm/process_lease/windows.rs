//! Windows mechanics for the process execution lease.
//!
//! The mutex is unnamed and noninheritable. Only an explicit bootstrap transfer
//! may give another worker a handle. NtQueryMutant's owner information observes
//! ownership without acquiring the mutex; no process ID is supplied by a peer.
//! The class and CLIENT_ID layout follow phnt's ntexapi.h. See the native control
//! and API references in docs/development/process-memory-owner-cpu.md.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::OnceLock;

type QueryMutant = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;

#[repr(C)]
struct OwnerInformation {
    process: *mut c_void,
    thread: *mut c_void,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(attributes: *const c_void, initial_owner: i32, name: *const u16)
    -> *mut c_void;
    fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn ReleaseMutex(handle: *mut c_void) -> i32;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

#[derive(Debug)]
pub(super) struct NativeLease {
    handle: OwnedHandle,
    query: QueryMutant,
}

impl NativeLease {
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: null attributes select a noninheritable handle; null name
        // creates a private unnamed object, initially unowned. No pointers are
        // retained. A successful call transfers one owned handle to us.
        let raw = unsafe { CreateMutexW(ptr::null(), 0, ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateMutexW returned a live, uniquely owned handle.
        Self::from_handle(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    pub(super) fn from_handle(handle: OwnedHandle) -> io::Result<Self> {
        let lease = Self {
            handle,
            query: query_mutant()?,
        };
        // Querying before adoption rejects other waitable object types and
        // handles without MUTANT_QUERY_STATE. No wait changes their state.
        lease.holder()?;
        // SAFETY: the owned handle is live. HANDLE_FLAG_INHERIT is local to
        // this handle table entry; clearing it cannot change another process.
        if unsafe { SetHandleInformation(lease.handle.as_raw_handle(), 1, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(lease)
    }

    pub(super) fn handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }

    pub(super) fn acquire(&self) -> io::Result<()> {
        // SAFETY: our owned mutex stays live throughout the nonalertable wait.
        // The common guard serializes host threads and balances this wait with
        // one ReleaseMutex on the same thread, including during unwinding.
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), u32::MAX) } {
            0 | 0x80 => Ok(()),
            u32::MAX => Err(io::Error::last_os_error()),
            status => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected memory lease wait: 0x{status:08x}"),
            )),
        }
        // WAIT_ABANDONED grants ownership. As with Unix worker death, guest
        // bytes are not rolled back: structural MM mutations belong to the
        // broker, and its next Begin replaces the dead worker's turn token.
    }

    pub(super) fn release(&self) -> io::Result<()> {
        // SAFETY: the common guard releases only on the acquiring host thread.
        // ReleaseMutex reports failure rather than releasing another owner.
        if unsafe { ReleaseMutex(self.handle.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn holder(&self) -> io::Result<Option<u32>> {
        let mut owner = OwnerInformation {
            process: ptr::null_mut(),
            thread: ptr::null_mut(),
        };
        let mut returned = 0;
        // SAFETY: class 1 is MutantOwnerInformation, a CLIENT_ID containing
        // two pointer-sized IDs. The output and returned-length buffers are
        // initialized, correctly aligned, writable and live through the call.
        // The native API retains neither buffer and does not acquire the mutex.
        let status = unsafe {
            (self.query)(
                self.handle.as_raw_handle(),
                1,
                (&mut owner as *mut OwnerInformation).cast(),
                size_of::<OwnerInformation>() as u32,
                &mut returned,
            )
        };
        if status != 0 {
            return Err(io::Error::other(format!(
                "memory lease owner query: NTSTATUS 0x{:08x}",
                status as u32
            )));
        }
        decode_owner(returned, owner.process as usize, owner.thread as usize)
    }
}

fn decode_owner(bytes: u32, process: usize, thread: usize) -> io::Result<Option<u32>> {
    if bytes as usize != size_of::<OwnerInformation>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected memory lease owner size",
        ));
    }
    match (process, thread) {
        (0, 0) => Ok(None),
        (1.., 1..) if process <= u32::MAX as usize && thread <= u32::MAX as usize => {
            Ok(Some(process as u32))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected memory lease owner identity",
        )),
    }
}

fn query_mutant() -> io::Result<QueryMutant> {
    static QUERY: OnceLock<Option<QueryMutant>> = OnceLock::new();
    QUERY
        .get_or_init(|| {
            let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            // SAFETY: both names are terminated; ntdll is a process-lifetime
            // system module already loaded by Windows. We neither load a path
            // from the environment nor unload the module behind this pointer.
            unsafe {
                let module = GetModuleHandleW(name.as_ptr());
                if module.is_null() {
                    return None;
                }
                let function = GetProcAddress(module, c"NtQueryMutant".as_ptr().cast());
                if function.is_null() {
                    None
                } else {
                    // SAFETY: the named ntdll export has the QueryMutant
                    // system ABI above, verified by the native owner control.
                    Some(std::mem::transmute::<*mut c_void, QueryMutant>(function))
                }
            }
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "memory lease owner query unavailable",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_records_require_exact_size_and_both_native_dword_ids() {
        let bytes = size_of::<OwnerInformation>() as u32;
        assert_eq!(decode_owner(bytes, 0, 0).unwrap(), None);
        assert_eq!(
            decode_owner(bytes, u32::MAX as usize, 4).unwrap(),
            Some(u32::MAX)
        );
        for (size, pid, tid) in [(bytes - 1, 4, 8), (bytes, 4, 0), (bytes, 0, 8)] {
            assert_eq!(
                decode_owner(size, pid, tid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        #[cfg(target_pointer_width = "64")]
        for (pid, tid) in [(u32::MAX as usize + 1, 8), (4, u32::MAX as usize + 1)] {
            assert_eq!(
                decode_owner(bytes, pid, tid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}

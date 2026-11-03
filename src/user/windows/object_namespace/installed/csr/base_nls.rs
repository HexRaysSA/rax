//! Fixed current-process BASE snapshot, acquired before guest publication.
use crate::user::windows::arch::WinArch;
use crate::user::windows::object_namespace::csr::{BASE_NLS_BYTES, BaseNlsReply, CsrMetadata};
use crate::user::windows::object_namespace::installed::{check, invalid};
use std::ffi::c_void;
use std::io;
use std::sync::Arc;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn CsrAllocateCaptureBuffer(pointers: u32, bytes: u32) -> *mut c_void;
    fn CsrAllocateMessagePointer(capture: *mut c_void, bytes: u32, slot: *mut *mut c_void) -> u32;
    fn CsrClientCallServer(message: *mut c_void, capture: *mut c_void, api: u32, bytes: u32)
    -> i32;
    fn CsrFreeCaptureBuffer(capture: *mut c_void);
    fn CsrGetProcessId() -> usize;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn ReadProcessMemory(
        process: *mut c_void,
        address: *const c_void,
        output: *mut c_void,
        bytes: usize,
        returned: *mut usize,
    ) -> i32;
}

struct Capture(*mut c_void);
impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: the exact non-null allocation returned by NTDLL, once only.
        unsafe { CsrFreeCaptureBuffer(self.0) };
    }
}

#[repr(C, align(16))]
struct Message([u8; 952]);

/// O(B) time and space for fixed B=1660 bytes. The native per-user payload is
/// copied whole, without interpreting integers as addresses or synthesizing
/// locale settings. Admission is the independently measured native profile.
pub(super) fn capture(metadata: &CsrMetadata) -> io::Result<Option<BaseNlsReply>> {
    if metadata.arch != WinArch::Arm64 || metadata.kernel != (10, 0, 29698) {
        return Ok(None);
    }
    // SAFETY: fixed current-process query; metadata was independently matched
    // against the native PEB, kernel, session and readonly CSR section.
    if unsafe { CsrGetProcessId() } != metadata.server_pid as usize {
        return Err(invalid("CSR BASE query server identity differs"));
    }
    let mut samples = Vec::with_capacity(2);
    for _ in 0..2 {
        // SAFETY: fixed measured allocation sizes; no guest inputs/callbacks.
        let capture = Capture(unsafe { CsrAllocateCaptureBuffer(1, BASE_NLS_BYTES as u32) });
        if capture.0.is_null() {
            return Err(io::Error::other("allocate fixed CSR BASE capture"));
        }
        let mut message = Message([0; 952]);
        // Register the pointer slot in the message itself. NTDLL converts this
        // exact slot to/from a server-view address during the synchronous call.
        let slot = message.0[64..].as_mut_ptr().cast::<*mut c_void>();
        // SAFETY: aligned exclusive pointer-width slot in a live 952B message;
        // the capture allocation owns the requested 1660B until RAII release.
        let allocated =
            unsafe { CsrAllocateMessagePointer(capture.0, BASE_NLS_BYTES as u32, slot) };
        let mut pointer = [0; 8];
        pointer.copy_from_slice(&message.0[64..72]);
        let information = usize::from_le_bytes(pointer);
        if allocated != BASE_NLS_BYTES as u32 || information == 0 {
            return Err(invalid("CSR BASE capture allocation differs"));
        }
        message.0[72..76].copy_from_slice(&(BASE_NLS_BYTES as u32).to_le_bytes());
        // SAFETY: fixed query-only BASE0x1001b/16B request under the matched
        // ARM64 build29698 ABI. Native controls compare it byte-for-byte with
        // an independent public locale query. Only this local process talks to
        // CSR; no guest addresses, handles, packets or strings enter the call.
        let result =
            unsafe { CsrClientCallServer(message.0.as_mut_ptr().cast(), capture.0, 0x1001B, 16) };
        let status = u32::from_le_bytes(message.0[52..56].try_into().expect("fixed BASE status"));
        if status != result as u32
            || message.0[64..72] != pointer
            || unsafe { CsrGetProcessId() } != metadata.server_pid as usize
        {
            return Err(invalid("CSR BASE reply status, pointer or server differs"));
        }
        if status == 0xC000_0001 {
            samples.push(BaseNlsReply::Unsuccessful);
            continue;
        }
        check(result, "capture fixed CSR BASE NLS information")?;
        if status != 0 {
            return Err(invalid("CSR BASE reply status is unmeasured"));
        }
        let mut sample = [0u8; BASE_NLS_BYTES];
        let mut got = 0usize;
        // SAFETY: current-process pseudo handle and exclusive initialized
        // bounded output. RPM validates the opaque returned local address.
        let read = unsafe {
            ReadProcessMemory(
                (-1isize) as *mut c_void,
                information as *const c_void,
                sample.as_mut_ptr().cast(),
                sample.len(),
                &mut got,
            )
        };
        if read == 0 || got != sample.len() {
            return Err(io::Error::last_os_error());
        }
        samples.push(BaseNlsReply::Information(Arc::new(sample)));
    }
    if samples[0] != samples[1] {
        return Err(invalid("CSR BASE NLS information changed during capture"));
    }
    Ok(samples.pop())
}

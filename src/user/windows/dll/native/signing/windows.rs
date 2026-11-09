//! Query an already admitted retained file; no guest pointer reaches NT.
use super::{Completion, Error, Request};
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;

const SUCCESS: u32 = 0;
const BUFFER_TOO_SMALL: u32 = 0xc000_0023;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtGetCachedSigningLevel(
        file: *mut c_void,
        flags: *mut u32,
        level: *mut u8,
        thumbprint: *mut u8,
        size: *mut u32,
        algorithm: *mut u32,
    ) -> i32;
}

fn resize(bytes: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    bytes
        .try_reserve_exact(length.saturating_sub(bytes.len()))
        .map_err(|_| Error::NoMemory)?;
    bytes.resize(length, 0);
    Ok(())
}

pub(super) fn query(file: &std::fs::File, request: Request) -> Result<Completion, Error> {
    // Capture metadata before touching caller outputs. Native publication first
    // stores flags and level, then probes and reads the caller's length, which
    // can alias either earlier output. Its value must not be captured here.
    // Start with 64 private bytes and grow only for a measured required size.
    let copies_hash = request.thumbprint && request.size;
    let mut bytes = Vec::new();
    if copies_hash {
        resize(&mut bytes, 64)?;
    }
    for _ in 0..3 {
        let (mut flags, mut level, mut algorithm) = (0u32, 0u8, 0u32);
        let mut size = if copies_hash { bytes.len() as u32 } else { 0 };
        // Even a zero-capacity nonnull request receives a live private pointer.
        // Vec's zero-length dangling pointer must never become a kernel output.
        let mut empty = [0u8; 1];
        let thumbprint = if !request.thumbprint {
            std::ptr::null_mut()
        } else if bytes.is_empty() {
            empty.as_mut_ptr()
        } else {
            bytes.as_mut_ptr()
        };
        // SAFETY: file borrows the retained owned host handle for this entire
        // synchronous query. Every nonnull output points to live initialized
        // private storage, with the exact NT field widths (level is one byte).
        // The advertised hash capacity never exceeds the private allocation;
        // absent size/hash/algorithm pointers retain the caller's query shape.
        // No guest address, guest handle, callback, path reopen or signing-cache
        // mutator reaches the kernel. NT retains no output after returning and
        // cannot unwind across this system-ABI boundary.
        let status = unsafe {
            NtGetCachedSigningLevel(
                file.as_raw_handle(),
                &mut flags,
                &mut level,
                thumbprint,
                if request.size {
                    &mut size
                } else {
                    std::ptr::null_mut()
                },
                if request.algorithm {
                    &mut algorithm
                } else {
                    std::ptr::null_mut()
                },
            )
        } as u32;
        if status == BUFFER_TOO_SMALL && copies_hash && size as usize > bytes.len() {
            resize(&mut bytes, size as usize)?;
            continue;
        }
        let published = matches!(status, SUCCESS | BUFFER_TOO_SMALL);
        if status == SUCCESS && copies_hash {
            if size as usize > bytes.len() {
                return Err(Error::Inconsistent(
                    "native signing hash exceeds its buffer",
                ));
            }
            bytes.truncate(size as usize);
        } else {
            bytes.clear();
        }
        return Ok(Completion {
            status,
            flags: published.then_some(flags),
            level: published.then_some(level),
            thumbprint: bytes,
            size: (published && request.size).then_some(size),
            // A signed image's hashless size query can return TOO_SMALL,
            // required length 64 and algorithm 0. Catalog level-only success
            // instead leaves this output untouched. Preserve the host result.
            algorithm: (published
                && request.size
                && request.algorithm
                && (request.thumbprint || status == BUFFER_TOO_SMALL))
                .then_some(algorithm),
        });
    }
    Err(Error::Inconsistent(
        "native signing cache changed across bounded retries",
    ))
}

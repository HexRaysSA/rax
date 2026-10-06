// Copyright (C) 2019 CrowdStrike, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Helper structure for working with mmaped memory regions in Windows.

use std;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::Arc;

use libc::{c_void, size_t};

use winapi::um::errhandlingapi::GetLastError;

use crate::bitmap::{Bitmap, NewBitmap, BS};
use crate::guest_memory::FileOffset;
use crate::volatile_memory::{self, compute_offset, VolatileMemory, VolatileSlice};

#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "stdcall" {
    pub fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: size_t,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;

    pub fn VirtualFree(lpAddress: *mut c_void, dwSize: size_t, dwFreeType: u32) -> u32;

    pub fn CreateFileMappingA(
        hFile: RawHandle,                       // HANDLE
        lpFileMappingAttributes: *const c_void, // LPSECURITY_ATTRIBUTES
        flProtect: u32,                         // DWORD
        dwMaximumSizeHigh: u32,                 // DWORD
        dwMaximumSizeLow: u32,                  // DWORD
        lpName: *const u8,                      // LPCSTR
    ) -> RawHandle; // HANDLE

    pub fn MapViewOfFile(
        hFileMappingObject: RawHandle,
        dwDesiredAccess: u32,
        dwFileOffsetHigh: u32,
        dwFileOffsetLow: u32,
        dwNumberOfBytesToMap: size_t,
    ) -> *mut c_void;

    pub fn CloseHandle(hObject: RawHandle) -> u32; // BOOL
}

const MM_HIGHEST_VAD_ADDRESS: u64 = 0x000007FFFFFDFFFF;

const MEM_COMMIT: u32 = 0x00001000;
const MEM_RELEASE: u32 = 0x00008000;
const FILE_MAP_ALL_ACCESS: u32 = 0xf001f;
const PAGE_READWRITE: u32 = 0x04;

pub const MAP_FAILED: *mut c_void = 0 as *mut c_void;
pub const INVALID_HANDLE_VALUE: RawHandle = (-1isize) as RawHandle;
#[allow(dead_code)]
pub const ERROR_INVALID_PARAMETER: i32 = 87;

/// Validity of an externally owned mapping's subranges.
///
/// The unsafe constructor's caller ensures that a successful check guarantees
/// accessibility for the duration of the operation. Mapping mutations must be
/// synchronized with all memory users, including users of raw host pointers.
/// Returning false prevents safe region access without dereferencing the range.
pub trait ExternalMappingAccess: std::fmt::Debug + Send + Sync {
    /// Whether the complete byte range may be accessed by the current operation.
    fn is_accessible(&self, offset: usize, count: usize) -> bool;
}

/// Helper structure for working with mmaped memory regions in Unix.
///
/// The structure is used for accessing the guest's physical memory by mmapping it into
/// the current process.
///
/// # Limitations
/// When running a 64-bit virtual machine on a 32-bit hypervisor, only part of the guest's
/// physical memory may be mapped into the current process due to the limited virtual address
/// space size of the process.
#[derive(Debug)]
pub struct MmapRegion<B> {
    addr: *mut u8,
    size: usize,
    bitmap: B,
    file_offset: Option<FileOffset>,
    // The allocation may consist of independently replaceable native mappings.
    // Its owner, rather than VirtualFree, supplies their destruction contract.
    external_owner: Option<Arc<dyn std::fmt::Debug + Send + Sync>>,
    external_access: Option<Arc<dyn ExternalMappingAccess>>,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl<B: Send> Send for MmapRegion<B> {}
unsafe impl<B: Sync> Sync for MmapRegion<B> {}

impl<B: NewBitmap> MmapRegion<B> {
    /// Exposes an existing mapping while retaining its native allocation owner.
    ///
    /// This region does not call `VirtualFree`. The last retained owner releases
    /// the allocation according to its own contract. Cloning a `GuestMemoryMmap`
    /// retains the region and therefore also retains the owner.
    ///
    /// # Safety
    /// On accepted input, `[addr, addr + size)` must be initialized, readable,
    /// writable host memory whose allocation remains live and at the same address
    /// for the entire lifetime of `owner`. The owner must release it only after
    /// all uses end. All access must obey the volatile-memory synchronization
    /// contract; no incompatible Rust references may alias this memory. The owner
    /// must support use and destruction on any thread. Changes to native mappings
    /// must be synchronized with all region users and preserve these guarantees.
    /// Null, empty, wrapping, and larger-than-isize ranges are rejected before
    /// memory is accessed or ownership is retained.
    pub unsafe fn from_raw_with_owner(
        addr: *mut u8,
        size: usize,
        owner: Arc<dyn std::fmt::Debug + Send + Sync>,
    ) -> io::Result<Self> {
        Self::external(addr, size, owner, None)
    }

    /// Exposes an externally owned range with a synchronized accessibility check.
    ///
    /// Unlike `from_raw_with_owner`, subranges may be inaccessible. Safe volatile
    /// accesses and host-address lookup reject such subranges. Raw pointers must
    /// not be retained across a mapping change without independently checking
    /// validity again. An accessibility check does not pin the range.
    ///
    /// # Safety
    /// The owner must keep the full virtual-address reservation alive at `addr`
    /// for `size` bytes. Each subrange accepted by `access` must be initialized
    /// and accessible for all operations performed through the returned region.
    /// Mapping changes must be synchronized with all users so an accepted range
    /// cannot become inaccessible while an operation or borrowed slice uses it.
    /// The lifetime, aliasing, and threading requirements of `from_raw_with_owner`
    /// also apply. Malformed ranges are rejected without accessing memory.
    pub unsafe fn from_raw_with_access(
        addr: *mut u8,
        size: usize,
        owner: Arc<dyn std::fmt::Debug + Send + Sync>,
        access: Arc<dyn ExternalMappingAccess>,
    ) -> io::Result<Self> {
        Self::external(addr, size, owner, Some(access))
    }

    fn external(
        addr: *mut u8,
        size: usize,
        owner: Arc<dyn std::fmt::Debug + Send + Sync>,
        access: Option<Arc<dyn ExternalMappingAccess>>,
    ) -> io::Result<Self> {
        if addr.is_null()
            || size == 0
            || size > isize::MAX as usize
            || (addr as usize).checked_add(size).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid external mapping range",
            ));
        }
        Ok(Self {
            addr,
            size,
            bitmap: B::with_len(size),
            file_offset: None,
            external_owner: Some(owner),
            external_access: access,
        })
    }

    /// Creates a shared anonymous mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - The size of the memory region in bytes.
    pub fn new(size: usize) -> io::Result<Self> {
        if (size == 0) || (size > MM_HIGHEST_VAD_ADDRESS as usize) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        let addr = unsafe { VirtualAlloc(0 as *mut c_void, size, MEM_COMMIT, PAGE_READWRITE) };
        if addr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: addr as *mut u8,
            size,
            bitmap: B::with_len(size),
            file_offset: None,
            external_owner: None,
            external_access: None,
        })
    }

    /// Creates a shared file mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `file_offset` - The mapping will be created at offset `file_offset.start` in the file
    ///                   referred to by `file_offset.file`.
    /// * `size` - The size of the memory region in bytes.
    pub fn from_file(file_offset: FileOffset, size: usize) -> io::Result<Self> {
        let handle = file_offset.file().as_raw_handle();
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        let mapping = unsafe {
            CreateFileMappingA(
                handle,
                null(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                null(),
            )
        };
        if mapping == 0 as RawHandle {
            return Err(io::Error::last_os_error());
        }

        let offset = file_offset.start();

        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            MapViewOfFile(
                mapping,
                FILE_MAP_ALL_ACCESS,
                (offset >> 32) as u32,
                offset as u32,
                size,
            )
        };

        unsafe {
            CloseHandle(mapping);
        }

        if addr == null_mut() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: addr as *mut u8,
            size,
            bitmap: B::with_len(size),
            file_offset: Some(file_offset),
            external_owner: None,
            external_access: None,
        })
    }
}

impl<B: Bitmap> MmapRegion<B> {
    pub(crate) fn accessible_range(&self, offset: usize, count: usize) -> bool {
        count == 0
            || self
                .external_access
                .as_ref()
                .map_or(true, |check| check.is_accessible(offset, count))
    }

    /// Returns a pointer to the beginning of the memory region. Mutable accesses performed
    /// using the resulting pointer are not automatically accounted for by the dirty bitmap
    /// tracking functionality.
    ///
    /// Should only be used for passing this region to ioctls for setting guest memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of this region.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns information regarding the offset into the file backing this region (if any).
    pub fn file_offset(&self) -> Option<&FileOffset> {
        self.file_offset.as_ref()
    }

    /// Returns a reference to the inner bitmap object.
    pub fn bitmap(&self) -> &B {
        &self.bitmap
    }
}

impl<B: Bitmap> VolatileMemory for MmapRegion<B> {
    type B = B;

    fn len(&self) -> usize {
        self.size
    }

    fn get_slice(
        &self,
        offset: usize,
        count: usize,
    ) -> volatile_memory::Result<VolatileSlice<'_, BS<'_, Self::B>>> {
        let end = compute_offset(offset, count)?;
        if end > self.size {
            return Err(volatile_memory::Error::OutOfBounds { addr: end });
        }
        if !self.accessible_range(offset, count) {
            return Err(volatile_memory::Error::IOError(io::Error::new(
                io::ErrorKind::Other,
                "external mapping range is inaccessible",
            )));
        }

        // Safe because we checked that offset + count was within our range and we only ever hand
        // out volatile accessors.
        Ok(unsafe {
            VolatileSlice::with_bitmap(
                self.addr.add(offset),
                count,
                self.bitmap.slice_at(offset),
                None,
            )
        })
    }
}

impl<B> Drop for MmapRegion<B> {
    fn drop(&mut self) {
        if self.external_owner.is_some() {
            // Fields drop after this body. The retained owner controls release.
            return;
        }
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        // Note that the size must be set to 0 when using MEM_RELEASE,
        // otherwise the function fails.
        unsafe {
            let ret_val = VirtualFree(self.addr as *mut libc::c_void, 0, MEM_RELEASE);
            if ret_val == 0 {
                let err = GetLastError();
                // We can't use any fancy logger here, yet we want to
                // pin point memory leaks.
                println!(
                    "WARNING: Could not deallocate mmap region. \
                     Address: {:?}. Size: {}. Error: {}",
                    self.addr, self.size, err
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::FromRawHandle;

    #[cfg(feature = "backend-bitmap")]
    use crate::bitmap::AtomicBitmap;
    use crate::guest_memory::FileOffset;
    use crate::mmap::windows::INVALID_HANDLE_VALUE;

    type MmapRegion = super::MmapRegion<()>;

    #[test]
    fn map_invalid_handle() {
        let file = unsafe { std::fs::File::from_raw_handle(INVALID_HANDLE_VALUE) };
        let file_offset = FileOffset::new(file, 0);
        let e = MmapRegion::from_file(file_offset, 1024).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    #[cfg(feature = "backend-bitmap")]
    fn test_dirty_tracking() {
        // Using the `crate` prefix because we aliased `MmapRegion` to `MmapRegion<()>` for
        // the rest of the unit tests above.
        let m = crate::MmapRegion::<AtomicBitmap>::new(0x1_0000).unwrap();
        crate::bitmap::tests::test_volatile_memory(&m);
    }
}

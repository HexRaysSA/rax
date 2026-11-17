//! Physical storage for the process memory owner.
//!
//! Only the owner allocates frames and changes extents. Other processes map
//! this file and use the owner's translations under its execution lease.
//! Sharing these bytes alone does not share allocator or VMA metadata.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use vm_memory::{FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use super::{ArenaState, EXTENT, FrameArena, MmError, PAGE_SIZE};

#[derive(Debug)]
pub(super) struct ProcessBacking {
    file: Arc<File>,
    available: AtomicBool,
}

impl ProcessBacking {
    pub(super) fn available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    /// Restore the owner's physical file after removing an object extent.
    /// The extent is not referenced by a CPU or mapping during replacement.
    pub(super) fn restore(&self, at: *mut u8, pa: u64) {
        let Ok(offset) = libc::off_t::try_from(pa) else {
            self.available.store(false, Ordering::Release);
            return;
        };
        // SAFETY: FrameArena::detach supplies one allocated, unreferenced,
        // host-page-aligned extent of its own reservation. The retained file
        // covers the entire arena. All changes hold the owner's lease.
        let result = unsafe {
            libc::mmap(
                at.cast(),
                EXTENT as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                self.file.as_raw_fd(),
                offset,
            )
        };
        if result == libc::MAP_FAILED {
            self.available.store(false, Ordering::Release);
        }
    }
}

impl FrameArena {
    /// Create the physical storage owned by a process memory owner.
    ///
    /// Frame allocation and extent bookkeeping remain owner-local. This
    /// constructor must not be used to replace clone's address-space policy.
    pub(crate) fn new_process_shared(size: u64, reserved: &[(u64, u64)]) -> Result<Self, MmError> {
        let size = size & !(PAGE_SIZE - 1);
        if size < PAGE_SIZE || size > usize::MAX as u64 {
            return Err(MmError::InvalidArgument("arena size"));
        }
        let file = super::super::shared::anonymous_file().map_err(|_| MmError::OutOfMemory)?;
        file.set_len(size).map_err(|_| MmError::OutOfMemory)?;
        let file = Arc::new(file);
        let region =
            MmapRegion::<()>::from_file(FileOffset::from_arc(file.clone(), 0), size as usize)
                .map_err(|_| MmError::OutOfMemory)?;
        let region = GuestRegionMmap::new(region, GuestAddress(0)).ok_or(MmError::OutOfMemory)?;
        let mem = GuestMemoryMmap::from_regions(vec![region]).map_err(|_| MmError::OutOfMemory)?;
        Ok(Self {
            mem: Arc::new(mem),
            process_backing: Some(ProcessBacking {
                file,
                available: AtomicBool::new(true),
            }),
            size,
            reserved: reserved.to_vec(),
            state: Mutex::new(ArenaState {
                bump: 0,
                free: Vec::new(),
                in_use: 0,
                top: size,
                free_extents: Vec::new(),
            }),
        })
    }

    /// Retain the owner's physical file for an independently mapped worker.
    pub(crate) fn process_file(&self) -> Option<Arc<File>> {
        self.process_backing
            .as_ref()
            .map(|backing| backing.file.clone())
    }
}

#[cfg(test)]
mod tests;

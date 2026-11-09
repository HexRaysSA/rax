//! Anonymous reserved RAM with monotonic, checked page commitment. Stopped
//! snapshot reads preserve logical zeros without committing untouched padding.

use std::ffi::c_void;
use std::io;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use vm_memory::mmap::{ExternalMappingAccess, FromRangesError};
use vm_memory::{
    GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MmapRegion,
};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 4;

#[repr(C)]
struct SystemInfo {
    architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_address: *mut c_void,
    maximum_address: *mut c_void,
    active_processors: usize,
    processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(address: *mut c_void, bytes: usize, flags: u32, protection: u32)
    -> *mut c_void;
    fn VirtualFree(address: *mut c_void, bytes: usize, flags: u32) -> i32;
    fn GetSystemInfo(info: *mut SystemInfo);
}

#[derive(Debug)]
struct Owner {
    base: NonNull<u8>,
    bytes: usize,
    page: usize,
    committed: Mutex<Vec<u64>>,
}

// SAFETY: the private reservation has no thread affinity. Commitment only adds
// initialized read/write pages, synchronized by committed; it never moves or
// removes pages. Every accepted access retains this owner through its region.
// Guest byte accesses retain vm-memory's volatile synchronization contract.
unsafe impl Send for Owner {}
unsafe impl Sync for Owner {}

impl Drop for Owner {
    fn drop(&mut self) {
        // SAFETY: the last owner releases exactly its VirtualAlloc reservation;
        // every region/access callback and in-flight zero-aware read has ended.
        if unsafe { VirtualFree(self.base.as_ptr().cast(), 0, MEM_RELEASE) } == 0 {
            tracing::error!(error = %io::Error::last_os_error(), "RAM reservation release failed");
        }
    }
}

fn registry() -> &'static Mutex<Vec<Weak<Owner>>> {
    static OWNERS: OnceLock<Mutex<Vec<Weak<Owner>>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn poisoned() -> io::Error {
    io::Error::other("private RAM commitment lock poisoned")
}

impl Owner {
    fn reserve(bytes: usize) -> io::Result<Arc<Self>> {
        if bytes == 0 || bytes > isize::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid private RAM extent",
            ));
        }
        // SAFETY: SYSTEM_INFO is a plain initialized output with native layout;
        // GetSystemInfo writes the complete fixed structure synchronously.
        let mut info: SystemInfo = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        let page = info.page_size as usize;
        if !page.is_power_of_two() {
            return Err(io::Error::other("invalid native RAM page size"));
        }
        let pages = bytes.div_ceil(page);
        let mut committed = Vec::new();
        committed
            .try_reserve_exact(pages.div_ceil(64))
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        committed.resize(pages.div_ceil(64), 0);
        // SAFETY: the OS chooses an unoccupied address range. Reservation alone
        // grants no byte access; checked region access commits pages below.
        let base =
            unsafe { VirtualAlloc(std::ptr::null_mut(), bytes, MEM_RESERVE, PAGE_READWRITE) };
        let base = NonNull::new(base.cast::<u8>()).ok_or_else(io::Error::last_os_error)?;
        Ok(Arc::new(Self {
            base,
            bytes,
            page,
            committed: Mutex::new(committed),
        }))
    }

    fn commit_with(
        &self,
        offset: usize,
        count: usize,
        allocate: impl FnOnce(*mut c_void, usize) -> io::Result<()>,
    ) -> io::Result<()> {
        let end = offset
            .checked_add(count)
            .filter(|end| *end <= self.bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "RAM range outside reservation")
            })?;
        if count == 0 {
            return Ok(());
        }
        let first = offset / self.page;
        let last = end.div_ceil(self.page);
        let mut committed = self.committed.lock().map_err(|_| poisoned())?;
        if (first..last).all(|page| committed[page / 64] & (1 << (page % 64)) != 0) {
            return Ok(());
        }
        // SAFETY: checked page offsets remain within the OS-rounded reserved
        // extent. The callback commits this address; no Rust reference is made.
        let address = unsafe { self.base.as_ptr().add(first * self.page).cast() };
        allocate(address, (last - first) * self.page)?;
        for page in first..last {
            committed[page / 64] |= 1 << (page % 64);
        }
        Ok(())
    }

    fn commit(&self, offset: usize, count: usize) -> io::Result<()> {
        self.commit_with(offset, count, |address, bytes| {
            // SAFETY: commit_with holds the owner lock and admitted this exact
            // subrange. Recommitting existing pages preserves their contents.
            let committed = unsafe { VirtualAlloc(address, bytes, MEM_COMMIT, PAGE_READWRITE) };
            if committed.is_null() {
                return Err(io::Error::last_os_error());
            }
            debug_assert_eq!(committed, address);
            Ok(())
        })
    }

    /// The caller has stopped independent RAM writers, as required by snapshot
    /// capture and publication. Never remove commitment while a region is live.
    fn read(&self, offset: usize, output: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(output.len())
            .filter(|end| *end <= self.bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "RAM read outside reservation")
            })?;
        let committed = self.committed.lock().map_err(|_| poisoned())?;
        let mut current = offset;
        while current < end {
            let page = current / self.page;
            let count = (self.page - current % self.page).min(end - current);
            let target = &mut output[current - offset..current - offset + count];
            if committed[page / 64] & (1 << (page % 64)) == 0 {
                target.fill(0);
            } else {
                // SAFETY: the owner and lock retain this initialized committed
                // page; the admitted span remains inside it. The destination is
                // disjoint caller-owned scratch. Use vm-memory's own volatile
                // copying contract, without recursively entering access checks.
                let source = unsafe {
                    vm_memory::VolatileSlice::new(self.base.as_ptr().add(current), count)
                };
                source.copy_to(target);
            }
            current += count;
        }
        Ok(())
    }
}

impl ExternalMappingAccess for Owner {
    fn is_accessible(&self, offset: usize, count: usize) -> bool {
        self.commit(offset, count).is_ok()
    }
}

pub(super) fn allocate(bytes: usize) -> Result<GuestMemoryMmap, FromRangesError> {
    let owner = Owner::reserve(bytes)?;
    let mut owners = registry().lock().map_err(|_| poisoned())?;
    owners.retain(|entry| entry.strong_count() != 0);
    owners
        .try_reserve(1)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    // SAFETY: owner retains the full stable reservation; its access callback
    // commits each accepted span before exposure and never decommits it. Every
    // successful range is zero-initialized or retains earlier guest contents.
    let mapping = unsafe {
        MmapRegion::from_raw_with_access(owner.base.as_ptr(), bytes, owner.clone(), owner.clone())
    }?;
    let region = GuestRegionMmap::new(mapping, GuestAddress(0))
        .ok_or(FromRangesError::InvalidGuestRegion)?;
    let memory = GuestMemoryMmap::from_regions(vec![region])?;
    owners.push(Arc::downgrade(&owner));
    Ok(memory)
}

/// Return None for ordinary/external mappings. Only this module's retained
/// private reservation can supply zeros without dereferencing native memory.
/// Callers must retain the existing stopped-writer snapshot boundary.
pub(super) fn read(
    memory: &GuestMemoryMmap,
    address: u64,
    output: &mut [u8],
) -> Option<Result<(), GuestMemoryError>> {
    let region = memory.find_region(GuestAddress(address))?;
    let offset = usize::try_from(address.checked_sub(region.start_addr().0)?).ok()?;
    if offset.checked_add(output.len())? > region.len() as usize {
        return None;
    }
    let owners = match registry().lock() {
        Ok(owners) => owners,
        Err(_) => return Some(Err(GuestMemoryError::IOError(poisoned()))),
    };
    let owner = owners
        .iter()
        .filter_map(Weak::upgrade)
        .find(|owner| owner.base.as_ptr() == region.as_ptr() && owner.bytes as u64 == region.len());
    drop(owners);
    owner.map(|owner| {
        owner
            .read(offset, output)
            .map_err(GuestMemoryError::IOError)
    })
}

#[cfg(test)]
mod tests;

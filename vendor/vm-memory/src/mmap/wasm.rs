// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Anonymous guest memory for wasm hosts, which have no `mmap`.
//!
//! Regions are zero-filled allocations aligned to 4096 bytes. Protection flags
//! are stored for API compatibility and are not enforced: wasm linear memory is
//! readable and writable, and guest code is interpreted rather than mapped
//! executable. A file-backed region copies the requested file range; it is not
//! a shared mapping.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::result;
use std::sync::Arc;

use crate::bitmap::{Bitmap, NewBitmap, BS};
use crate::guest_memory::FileOffset;
use crate::volatile_memory::{self, VolatileMemory, VolatileSlice};

const PAGE_SIZE: usize = 4096;

// Linux `mmap` flag values. Nothing on this host consumes them as syscall arguments.
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_SHARED: i32 = 0x01;
const MAP_PRIVATE: i32 = 0x02;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_NORESERVE: i32 = 0x4000;

/// Error conditions that may arise when creating a new `MmapRegion` object.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The specified file offset and length cause overflow when added.
    #[error("The specified file offset and length cause overflow when added")]
    InvalidOffsetLength,
    /// The specified pointer to the mapping is not page-aligned.
    #[error("The specified pointer to the mapping is not page-aligned")]
    InvalidPointer,
    /// The forbidden `MAP_FIXED` flag was specified.
    #[error("The forbidden `MAP_FIXED` flag was specified")]
    MapFixed,
    /// Mappings using the same fd overlap in terms of file offset and length.
    #[error("Mappings using the same fd overlap in terms of file offset and length")]
    MappingOverlap,
    /// A mapping with offset + length > EOF was attempted.
    #[error("The specified file offset and length is greater then file length")]
    MappingPastEof,
    /// The allocation or file read returned an error.
    #[error("{0}")]
    Mmap(io::Error),
}

pub type Result<T> = result::Result<T, Error>;

/// A factory struct to build `MmapRegion` objects.
#[derive(Debug)]
pub struct MmapRegionBuilder<B = ()> {
    size: usize,
    prot: i32,
    flags: i32,
    file_offset: Option<FileOffset>,
    raw_ptr: Option<*mut u8>,
    hugetlbfs: Option<bool>,
    bitmap: B,
}

impl<B: Bitmap + Default> MmapRegionBuilder<B> {
    /// Create a new `MmapRegionBuilder` using the default value for
    /// the inner `Bitmap` object.
    pub fn new(size: usize) -> Self {
        Self::new_with_bitmap(size, B::default())
    }
}

impl<B: Bitmap> MmapRegionBuilder<B> {
    /// Create a new `MmapRegionBuilder` using the provided `Bitmap` object.
    pub fn new_with_bitmap(size: usize, bitmap: B) -> Self {
        MmapRegionBuilder {
            size,
            prot: 0,
            flags: MAP_ANONYMOUS | MAP_PRIVATE,
            file_offset: None,
            raw_ptr: None,
            hugetlbfs: None,
            bitmap,
        }
    }

    /// Create the `MmapRegion` object with the specified protection flag `prot`.
    pub fn with_mmap_prot(mut self, prot: i32) -> Self {
        self.prot = prot;
        self
    }

    /// Create the `MmapRegion` object with the specified `flags`.
    pub fn with_mmap_flags(mut self, flags: i32) -> Self {
        self.flags = flags;
        self
    }

    /// Create the `MmapRegion` object with the specified `file_offset`.
    pub fn with_file_offset(mut self, file_offset: FileOffset) -> Self {
        self.file_offset = Some(file_offset);
        self
    }

    /// Create the `MmapRegion` object with the specified `hugetlbfs` flag.
    pub fn with_hugetlbfs(mut self, hugetlbfs: bool) -> Self {
        self.hugetlbfs = Some(hugetlbfs);
        self
    }

    /// Create the `MmapRegion` object with an externally owned pointer.
    ///
    /// # Safety
    ///
    /// `raw_ptr` and `self.size` must define a region that stays valid and
    /// uniquely owned for the life of the built `MmapRegion` when `owned` is
    /// false. The builder does not free this pointer.
    pub unsafe fn with_raw_mmap_pointer(mut self, raw_ptr: *mut u8) -> Self {
        self.raw_ptr = Some(raw_ptr);
        self
    }

    /// Build the `MmapRegion` object.
    pub fn build(self) -> Result<MmapRegion<B>> {
        if self.raw_ptr.is_some() {
            return self.build_raw();
        }
        if self.flags & MAP_FIXED != 0 {
            return Err(Error::MapFixed);
        }

        let addr = allocate(self.size)?;
        if let Some(ref file_offset) = self.file_offset {
            if let Err(error) = read_file(file_offset, addr, self.size) {
                // SAFETY: `allocate` just returned this owned block.
                unsafe { free(addr, self.size) };
                return Err(error);
            }
        }

        Ok(MmapRegion {
            addr,
            size: self.size,
            bitmap: self.bitmap,
            file_offset: self.file_offset,
            prot: self.prot,
            flags: self.flags,
            owned: true,
            hugetlbfs: self.hugetlbfs,
        })
    }

    fn build_raw(self) -> Result<MmapRegion<B>> {
        let addr = self.raw_ptr.unwrap();
        if (addr as usize) & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidPointer);
        }
        Ok(MmapRegion {
            addr,
            size: self.size,
            bitmap: self.bitmap,
            file_offset: self.file_offset,
            prot: self.prot,
            flags: self.flags,
            owned: false,
            hugetlbfs: self.hugetlbfs,
        })
    }
}

/// Guest physical memory backed by a wasm allocation.
///
/// # Limitations
///
/// A region must fit in the host address space. On wasm32 that is at most
/// `isize::MAX` bytes, and the whole module's linear memory is at most 4 GiB.
#[derive(Debug)]
pub struct MmapRegion<B = ()> {
    addr: *mut u8,
    size: usize,
    bitmap: B,
    file_offset: Option<FileOffset>,
    prot: i32,
    flags: i32,
    owned: bool,
    hugetlbfs: Option<bool>,
}

// SAFETY: The raw pointer is only accessed through this type's methods. Moving
// the region moves the pointer, not the allocation. Sharing across threads is
// the same contract as the Unix mmap backend.
unsafe impl<B: Send> Send for MmapRegion<B> {}
// SAFETY: See the `Send` implementation.
unsafe impl<B: Sync> Sync for MmapRegion<B> {}

impl<B: NewBitmap> MmapRegion<B> {
    /// Creates an anonymous zero-filled region of `size` bytes.
    pub fn new(size: usize) -> Result<Self> {
        MmapRegionBuilder::new_with_bitmap(size, B::with_len(size))
            .with_mmap_prot(PROT_READ | PROT_WRITE)
            .with_mmap_flags(MAP_ANONYMOUS | MAP_NORESERVE | MAP_PRIVATE)
            .build()
    }

    /// Copies `size` bytes from `file_offset` into a fresh region.
    pub fn from_file(file_offset: FileOffset, size: usize) -> Result<Self> {
        MmapRegionBuilder::new_with_bitmap(size, B::with_len(size))
            .with_file_offset(file_offset)
            .with_mmap_prot(PROT_READ | PROT_WRITE)
            .with_mmap_flags(MAP_NORESERVE | MAP_SHARED)
            .build()
    }

    /// Creates a region from the same arguments as the Unix constructor.
    pub fn build(
        file_offset: Option<FileOffset>,
        size: usize,
        prot: i32,
        flags: i32,
    ) -> Result<Self> {
        let mut builder = MmapRegionBuilder::new_with_bitmap(size, B::with_len(size))
            .with_mmap_prot(prot)
            .with_mmap_flags(flags);
        if let Some(offset) = file_offset {
            builder = builder.with_file_offset(offset);
        }
        builder.build()
    }

    /// Wraps an externally managed mapping. The region does not free `addr`.
    ///
    /// # Safety
    ///
    /// `addr` and `size` must describe a valid, page-aligned mapping that
    /// outlives this region. `prot` and `flags` are recorded and not checked
    /// against a host mapping.
    pub unsafe fn build_raw(addr: *mut u8, size: usize, prot: i32, flags: i32) -> Result<Self> {
        // SAFETY: The caller guarantees `addr`/`size`. The builder does not free it.
        unsafe {
            MmapRegionBuilder::new_with_bitmap(size, B::with_len(size))
                .with_raw_mmap_pointer(addr)
                .with_mmap_prot(prot)
                .with_mmap_flags(flags)
                .build()
        }
    }
}

impl<B: Bitmap> MmapRegion<B> {
    /// Returns a pointer to the beginning of the memory region.
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

    /// Returns the recorded protection bits.
    pub fn prot(&self) -> i32 {
        self.prot
    }

    /// Returns the recorded mapping flags.
    pub fn flags(&self) -> i32 {
        self.flags
    }

    /// Returns `true` if dropping this region frees the allocation.
    pub fn owned(&self) -> bool {
        self.owned
    }

    /// Checks whether this region and `other` copy overlapping ranges of the same file.
    ///
    /// File identity is the `Arc` inside [`FileOffset`]. Distinct descriptors for
    /// the same host file are not detected.
    pub fn fds_overlap<T: Bitmap>(&self, other: &MmapRegion<T>) -> bool {
        let (Some(first), Some(second)) = (self.file_offset(), other.file_offset()) else {
            return false;
        };
        if !Arc::ptr_eq(first.arc(), second.arc()) {
            return false;
        }
        let start_1 = first.start();
        let start_2 = second.start();
        let len_1 = self.len() as u64;
        let len_2 = other.len() as u64;
        if start_1 < start_2 {
            start_1.saturating_add(len_1) > start_2
        } else {
            start_2.saturating_add(len_2) > start_1
        }
    }

    /// Records the hugetlbfs flag. wasm has no huge pages.
    pub fn set_hugetlbfs(&mut self, hugetlbfs: bool) {
        self.hugetlbfs = Some(hugetlbfs);
    }

    /// Returns the recorded hugetlbfs flag.
    pub fn is_hugetlbfs(&self) -> Option<bool> {
        self.hugetlbfs
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
    ) -> volatile_memory::Result<VolatileSlice<'_, BS<'_, B>>> {
        let _ = self.compute_end_offset(offset, count)?;
        // SAFETY: `offset + count` is inside this allocation. The slice only
        // exposes volatile accessors, and the allocation outlives the region.
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
        if self.owned {
            // SAFETY: `owned` is set only for blocks created by `allocate`.
            unsafe { free(self.addr, self.size) };
        }
    }
}

fn layout(size: usize) -> Result<Layout> {
    // wasm32 `wrapping_offset` takes `isize`. Reject sizes that cannot be an offset.
    if size == 0 || size > isize::MAX as usize {
        return Err(Error::Mmap(io::Error::from(io::ErrorKind::InvalidInput)));
    }
    Layout::from_size_align(size, PAGE_SIZE).map_err(|_| {
        Error::Mmap(io::Error::new(
            io::ErrorKind::InvalidInput,
            "region size and alignment overflow",
        ))
    })
}

fn allocate(size: usize) -> Result<*mut u8> {
    let layout = layout(size)?;
    // SAFETY: `layout` has a non-zero size and a power-of-two alignment.
    let addr = unsafe { alloc_zeroed(layout) };
    if addr.is_null() {
        return Err(Error::Mmap(io::Error::from(io::ErrorKind::OutOfMemory)));
    }
    Ok(addr)
}

/// # Safety
///
/// `addr` must be a block returned by `allocate` for this `size`, and not freed yet.
unsafe fn free(addr: *mut u8, size: usize) {
    let Ok(layout) = layout(size) else {
        return;
    };
    // SAFETY: Caller guarantees this is the matching allocation.
    unsafe { dealloc(addr, layout) }
}

/// Copies `size` bytes at the file offset into `addr`.
///
/// WASI cannot duplicate a descriptor (`File::try_clone` is unsupported) and has
/// no stable positional read, so this reads through the shared cursor and then
/// restores it. The caller's cursor is unchanged on success and on read
/// failure. Concurrent users of the same `File` must not depend on its cursor
/// while a region is being built.
fn read_file(file_offset: &FileOffset, addr: *mut u8, size: usize) -> Result<()> {
    let start = file_offset.start();
    if start.checked_add(size as u64).is_none() {
        return Err(Error::InvalidOffsetLength);
    }
    let mut file: &File = file_offset.file();
    let cursor = file.stream_position().map_err(Error::Mmap)?;

    // SAFETY: `addr` points at `size` allocated bytes that are not aliased.
    let buffer = unsafe { std::slice::from_raw_parts_mut(addr, size) };
    let read = file
        .seek(SeekFrom::Start(start))
        .and_then(|_| file.read_exact(buffer));
    let restored = file.seek(SeekFrom::Start(cursor));

    read.map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::MappingPastEof
        } else {
            Error::Mmap(error)
        }
    })?;
    restored.map(|_| ()).map_err(Error::Mmap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_region_is_writable() {
        let region = MmapRegion::<()>::new(4096).unwrap();
        assert_eq!(region.size(), 4096);
        assert!(region.file_offset().is_none());
        assert!(region.owned());
        unsafe {
            region.as_ptr().write(0xAB);
            assert_eq!(region.as_ptr().read(), 0xAB);
        }
    }

    #[test]
    fn zero_size_is_rejected() {
        assert!(MmapRegion::<()>::new(0).is_err());
    }

    /// A `u64` region offset must not be narrowed to the host `usize`: on wasm32,
    /// 0x1_0000_0010 would otherwise alias offset 0x10.
    #[test]
    fn region_offset_beyond_host_width_is_rejected() {
        use crate::{Bytes, GuestAddress, GuestMemoryRegion, GuestRegionMmap, MemoryRegionAddress};
        use std::sync::atomic::Ordering;

        let mapping = MmapRegion::<()>::new(PAGE_SIZE).unwrap();
        let region = GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap();
        let far = MemoryRegionAddress(0x1_0000_0010);

        assert!(region.write(&[0xAA], far).is_err());
        assert!(region.write_slice(&[0xAA], far).is_err());
        assert!(region.store(0xAAu8, far, Ordering::Relaxed).is_err());
        assert!(region
            .read_volatile_from(far, &mut &[0xAAu8][..], 1)
            .is_err());
        assert!(region.read(&mut [0u8], far).is_err());
        assert!(region.load::<u8>(far, Ordering::Relaxed).is_err());
        assert!(region.get_slice(far, 1).is_err());

        let mut byte = [0xFFu8];
        region
            .read_slice(&mut byte, MemoryRegionAddress(0x10))
            .unwrap();
        assert_eq!(byte, [0]);
    }

    #[cfg(target_os = "wasi")]
    #[test]
    fn file_backed_region_copies_range_and_keeps_cursor() {
        // WASI has no `std::env::temp_dir`; the runner must preopen this directory.
        let dir = std::env::var("TMPDIR")
            .expect("WASI file tests need TMPDIR to name a preopened directory");
        let path = std::path::Path::new(&dir).join("vm-memory-wasm-file-region.bin");
        let bytes: Vec<u8> = (0..2 * PAGE_SIZE).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();

        let mut file = File::open(&path).unwrap();
        file.seek(SeekFrom::Start(3)).unwrap();
        let region =
            MmapRegion::<()>::from_file(FileOffset::new(file, PAGE_SIZE as u64), PAGE_SIZE)
                .unwrap();
        // SAFETY: the region owns `PAGE_SIZE` initialized bytes.
        let copied = unsafe { std::slice::from_raw_parts(region.as_ptr(), PAGE_SIZE) };
        assert_eq!(copied, &bytes[PAGE_SIZE..]);
        let mut cursor: &File = region.file_offset().unwrap().file();
        assert_eq!(cursor.stream_position().unwrap(), 3);

        let past_eof = FileOffset::new(File::open(&path).unwrap(), PAGE_SIZE as u64);
        assert!(matches!(
            MmapRegion::<()>::from_file(past_eof, 2 * PAGE_SIZE),
            Err(Error::MappingPastEof)
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "backend-bitmap")]
    #[test]
    fn dirty_bitmap_tracks_backend_pages() {
        use crate::bitmap::{AtomicBitmap, Bitmap};
        use crate::{Bytes, GuestAddress, GuestMemory, GuestMemoryRegion};

        let memory = crate::GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(
            GuestAddress(0),
            4 * PAGE_SIZE,
        )])
        .unwrap();
        memory
            .write_obj(1u32, GuestAddress(2 * PAGE_SIZE as u64 + 4))
            .unwrap();
        let region = memory.find_region(GuestAddress(0)).unwrap();
        assert!(region.bitmap().dirty_at(2 * PAGE_SIZE));
        assert!(!region.bitmap().dirty_at(PAGE_SIZE));
        assert!(!region.bitmap().dirty_at(3 * PAGE_SIZE));
    }
}

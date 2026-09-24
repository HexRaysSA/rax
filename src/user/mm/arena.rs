//! Host-backed physical frame arena.
//!
//! Guest pages live in one contiguous anonymous host mapping, exposed as a
//! single-region [`GuestMemoryMmap`] at guest-physical address zero so that
//! CPU models built around guest-physical memory (the x86-64 MMU) can use it
//! directly. The mapping is created with `MAP_NORESERVE`; the host commits a
//! page only when it is first written, so the arena size is an upper bound on
//! guest memory, not a reservation of host RAM.
//!
//! Frames are handed out by a bump pointer, then recycled through a free
//! list. Recycled frames are zeroed before reuse. Reserved physical ranges
//! (for example the x86-64 local-APIC window that the x86 MMU shadows) are
//! never handed out.
//!
//! Shared mappings take *extents* instead: [`EXTENT`]-sized, host-page
//! aligned stretches handed out from the top of the arena down, over which
//! [`FrameArena::attach`] lays a host `MAP_SHARED` mapping of a file's
//! extent, so the guest-physical pages there are the host object's pages.
//! [`FrameArena::detach`] lays anonymous memory back. The two allocators
//! meet in the middle; neither passes the other.

use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::{MmError, PAGE_SIZE};

#[derive(Debug)]
struct ArenaState {
    /// Next never-used frame.
    bump: u64,
    /// Frames returned by `free`, reused LIFO.
    free: Vec<u64>,
    /// Frames currently allocated.
    in_use: u64,
    /// Lowest extent ever handed out (the arena's end before any); frames
    /// stay below it.
    top: u64,
    /// Extents returned by `free_extent`.
    free_extents: Vec<u64>,
}

/// Bytes of a shared object attached at once: 256 KiB, a multiple of every
/// host page size (4, 16, or 64 KiB), so host-page-aligned in the arena and
/// in the object.
pub const EXTENT: u64 = 256 << 10;

/// A fixed-size pool of 4 KiB guest frames.
#[derive(Debug)]
pub struct FrameArena {
    mem: Arc<GuestMemoryMmap>,
    size: u64,
    reserved: Vec<(u64, u64)>,
    state: Mutex<ArenaState>,
}

impl FrameArena {
    /// Creates an arena of `size` bytes (rounded down to whole pages) that
    /// never allocates frames overlapping any `(start, len)` in `reserved`.
    pub fn new(size: u64, reserved: &[(u64, u64)]) -> Result<Self, MmError> {
        let size = size & !(PAGE_SIZE - 1);
        if size < PAGE_SIZE || size > usize::MAX as u64 {
            return Err(MmError::InvalidArgument("arena size"));
        }
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), size as usize)])
            .map_err(|_| MmError::OutOfMemory)?;
        Ok(FrameArena {
            mem: Arc::new(mem),
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

    /// The guest-physical memory holding every frame.
    pub fn memory(&self) -> &Arc<GuestMemoryMmap> {
        &self.mem
    }

    /// Arena capacity in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Frames currently allocated.
    pub fn frames_in_use(&self) -> u64 {
        self.state.lock().unwrap().in_use
    }

    fn is_reserved(&self, frame: u64) -> bool {
        self.reserved
            .iter()
            .any(|&(start, len)| frame < start.saturating_add(len) && frame + PAGE_SIZE > start)
    }

    /// Allocates a zero-filled frame and returns its guest-physical address.
    pub fn alloc_zeroed(&self) -> Result<u64, MmError> {
        let mut st = self.state.lock().unwrap();
        if let Some(frame) = st.free.pop() {
            st.in_use += 1;
            drop(st);
            self.write(frame, &[0u8; PAGE_SIZE as usize]);
            return Ok(frame);
        }
        loop {
            let frame = st.bump;
            if frame + PAGE_SIZE > st.top {
                return Err(MmError::OutOfMemory);
            }
            st.bump += PAGE_SIZE;
            if !self.is_reserved(frame) {
                // Never-used frames of an anonymous mapping are already zero.
                st.in_use += 1;
                return Ok(frame);
            }
        }
    }

    /// Returns `frame` to the pool.
    pub fn free(&self, frame: u64) {
        debug_assert_eq!(frame & (PAGE_SIZE - 1), 0);
        debug_assert!(frame < self.size);
        let mut st = self.state.lock().unwrap();
        st.in_use -= 1;
        st.free.push(frame);
    }

    /// Allocates an extent for a shared mapping and returns its
    /// guest-physical address (a multiple of [`EXTENT`]).
    pub fn alloc_extent(&self) -> Result<u64, MmError> {
        let mut st = self.state.lock().unwrap();
        if let Some(pa) = st.free_extents.pop() {
            return Ok(pa);
        }
        loop {
            let pa = st.top.saturating_sub(EXTENT) & !(EXTENT - 1);
            if st.top < EXTENT || pa < st.bump {
                return Err(MmError::OutOfMemory);
            }
            st.top = pa;
            if !self
                .reserved
                .iter()
                .any(|&(start, len)| pa < start.saturating_add(len) && pa + EXTENT > start)
            {
                return Ok(pa);
            }
        }
    }

    /// Returns extent `pa`, detached, to the pool.
    pub fn free_extent(&self, pa: u64) {
        debug_assert_eq!(pa & (EXTENT - 1), 0);
        self.state.lock().unwrap().free_extents.push(pa);
    }

    /// Whether guest-physical `pa` lies in the extents (above every frame).
    pub fn is_extent(&self, pa: u64) -> bool {
        pa >= self.state.lock().unwrap().top
    }

    /// The host address of guest-physical `pa`.
    fn host_address(&self, pa: u64) -> *mut u8 {
        use vm_memory::GuestMemory;
        self.mem
            .get_host_address(GuestAddress(pa))
            .expect("arena address lies inside the arena")
    }

    /// Lays `len` bytes of the host file `fd` from `offset` (a multiple of
    /// [`EXTENT`]) over extent `pa`, shared, writable when `writable`.
    #[cfg(unix)]
    pub fn attach(
        &self,
        pa: u64,
        fd: std::os::fd::RawFd,
        offset: u64,
        writable: bool,
    ) -> std::io::Result<()> {
        debug_assert_eq!(pa & (EXTENT - 1), 0);
        debug_assert_eq!(offset & (EXTENT - 1), 0);
        let prot = libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 };
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        // SAFETY: the extent is EXTENT bytes of the arena's own mapping,
        // host-page aligned (the arena starts on a host page and EXTENT is
        // a multiple of every host page size); no frame, and no reference
        // into the arena, covers it (the extent allocator hands it out
        // once, and every access copies through vm-memory); MAP_FIXED
        // replaces exactly those bytes; `fd` is open for the call.
        let p = unsafe {
            libc::mmap(
                self.host_address(pa).cast(),
                EXTENT as usize,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                offset,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Lays anonymous memory back over extent `pa`.
    #[cfg(unix)]
    pub fn detach(&self, pa: u64) {
        // SAFETY: as for `attach`: the extent is the arena's own memory and
        // no longer referenced by any page; fresh private anonymous memory
        // replaces the shared mapping. Failure leaves the shared mapping,
        // which the next attach replaces.
        unsafe {
            libc::mmap(
                self.host_address(pa).cast(),
                EXTENT as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
        }
    }

    /// Writes extent `pa`'s modified pages to its object (`msync`
    /// `MS_SYNC`).
    #[cfg(unix)]
    pub fn sync(&self, pa: u64) -> std::io::Result<()> {
        // SAFETY: msync of an attached extent of the arena's own mapping.
        let rc =
            unsafe { libc::msync(self.host_address(pa).cast(), EXTENT as usize, libc::MS_SYNC) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Reads `buf.len()` bytes at guest-physical `pa`. The range must lie in
    /// one allocated frame.
    #[inline]
    pub fn read(&self, pa: u64, buf: &mut [u8]) {
        debug_assert!((pa & (PAGE_SIZE - 1)) + buf.len() as u64 <= PAGE_SIZE);
        self.mem
            .read_slice(buf, GuestAddress(pa))
            .expect("arena frame address lies inside the arena");
    }

    /// Writes `data` at guest-physical `pa`. The range must lie in one
    /// allocated frame.
    #[inline]
    pub fn write(&self, pa: u64, data: &[u8]) {
        debug_assert!((pa & (PAGE_SIZE - 1)) + data.len() as u64 <= PAGE_SIZE);
        self.mem
            .write_slice(data, GuestAddress(pa))
            .expect("arena frame address lies inside the arena");
    }
}

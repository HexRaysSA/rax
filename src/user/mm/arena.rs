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
}

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
            if frame + PAGE_SIZE > self.size {
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

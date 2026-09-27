//! Heaps (`HeapCreate`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`,
//! `HeapSize`, and the C runtime allocator built on the process heap).
//!
//! A heap is one or more reserved segments of guest memory; its handle is
//! the base of its first segment, as a Windows heap handle is the heap's
//! address. Blocks are aligned to `MEMORY_ALLOCATION_ALIGNMENT` (8 bytes
//! for 32-bit processes, 16 for 64-bit ones) and placed best-fit, with
//! adjacent free blocks coalesced. Block metadata is kept on the host, so
//! guest writes outside a block cannot corrupt the allocator's own state.
//!
//! A growable heap (maximum size 0) adds segments as needed; a fixed heap
//! fails once its maximum is reached. Freeing or resizing an address that
//! is not a live block of the heap is heap corruption: the caller reports
//! it (the personality ends the process with `STATUS_HEAP_CORRUPTION`, as
//! Windows' terminate-on-corruption policy does).
//!
//! Candidate blocks are published only after initialization succeeds. In
//! particular, a failed reallocation leaves the original block and its
//! requested size unchanged, as required by `HeapReAlloc`:
//! <https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc>.
//! Heap initialization uses checked guest accesses, not loader writes.
//! The scheduler serializes these operations; mappings cannot change between
//! the full-range access probe and the bounded-buffer zero/copy operations.
//! Initial commitment is page-rounded (one page for initial size zero), and
//! allocation commits reserved pages as needed:
//! <https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate>.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::memory::{
    AllocKind, Mem, MemFault, VirtualMemory, mem, page_range, prot,
};

/// `HEAP_NO_SERIALIZE`.
pub const HEAP_NO_SERIALIZE: u32 = 0x1;
/// `HEAP_GROWABLE`.
pub const HEAP_GROWABLE: u32 = 0x2;
/// `HEAP_GENERATE_EXCEPTIONS`.
pub const HEAP_GENERATE_EXCEPTIONS: u32 = 0x4;
/// `HEAP_ZERO_MEMORY`.
pub const HEAP_ZERO_MEMORY: u32 = 0x8;
/// `HEAP_REALLOC_IN_PLACE_ONLY`.
pub const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;
/// `HEAP_CREATE_ENABLE_EXECUTE`.
pub const HEAP_CREATE_ENABLE_EXECUTE: u32 = 0x4_0000;

/// Default segment size of a growable heap.
const SEGMENT: u64 = 1 << 20;

/// A heap operation on an address that is not a live block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapError {
    /// The heap handle is not a heap.
    BadHeap,
    /// The address is not a live block of the heap.
    BadBlock,
    /// No memory (or the fixed maximum was reached).
    NoMemory,
    /// Initialization or copying encountered inaccessible guest memory.
    MemoryFault(MemFault),
}

#[derive(Debug)]
struct Heap {
    flags: u32,
    align: u64,
    /// Maximum total size (0 = growable).
    max: u64,
    segments: Vec<(u64, u64)>,
    /// Free blocks by address.
    free: BTreeMap<u64, u64>,
    /// Free blocks by (size, address), for best fit.
    by_size: BTreeSet<(u64, u64)>,
    /// Live blocks: address → (rounded size, requested size).
    used: HashMap<u64, (u64, u64)>,
}

impl Heap {
    fn insert_free(&mut self, addr: u64, size: u64) {
        let (mut addr, mut size) = (addr, size);
        // Coalesce with the following block.
        let end = addr.checked_add(size).expect("heap block range");
        if let Some(&next) = self.free.get(&end)
            && self.same_segment(addr, end)
        {
            self.free.remove(&end);
            self.by_size.remove(&(next, end));
            size += next;
        }
        // Coalesce with the preceding block.
        if let Some((&prev, &psize)) = self.free.range(..addr).next_back()
            && prev.checked_add(psize) == Some(addr)
            && self.same_segment(prev, addr)
        {
            self.free.remove(&prev);
            self.by_size.remove(&(psize, prev));
            addr = prev;
            size += psize;
        }
        self.free.insert(addr, size);
        self.by_size.insert((size, addr));
    }

    fn same_segment(&self, a: u64, b: u64) -> bool {
        self.segments.iter().any(|&(s, l)| {
            let end = s.checked_add(l).expect("heap segment range");
            a >= s && a < end && b >= s && b < end
        })
    }

    fn take(&mut self, size: u64) -> Option<u64> {
        let &(fsize, addr) = self.by_size.range((size, 0)..).next()?;
        self.by_size.remove(&(fsize, addr));
        self.free.remove(&addr);
        if fsize > size {
            let rest = addr + size;
            self.free.insert(rest, fsize - size);
            self.by_size.insert((fsize - size, rest));
        }
        Some(addr)
    }
}

/// A candidate is not yet present in the heap's live-block index. An existing
/// free block remains indexed until this candidate is published.
struct Candidate {
    addr: u64,
    segment: Option<(u64, u64)>,
    /// Reserved pages committed while preparing this candidate.
    commits: Vec<(u64, u64)>,
}

fn round_up(size: u64, align: u64) -> Option<u64> {
    if !align.is_power_of_two() {
        return None;
    }
    Some(size.checked_add(align - 1)? & !(align - 1))
}

fn rounded_size(size: u64, align: u64) -> Option<u64> {
    round_up(size.max(1), align)
}

fn probe(vm: &VirtualMemory, addr: u64, size: u64, write: bool) -> Result<(), HeapError> {
    addr.checked_add(size).ok_or(HeapError::NoMemory)?;
    let size = usize::try_from(size).map_err(|_| HeapError::NoMemory)?;
    let access = if write {
        MemoryAccessKind::Write
    } else {
        MemoryAccessKind::Read
    };
    vm.space().probe(addr, size, access).map_err(|fault| {
        HeapError::MemoryFault(MemFault {
            addr: fault.address,
            write,
        })
    })
}

/// O(size) byte work and O(PAGE_SIZE) auxiliary space. Probe before writing,
/// so a permission, unmapped-page, or backing-allocation fault writes no byte.
fn zero_range(vm: &VirtualMemory, addr: u64, size: u64) -> Result<(), HeapError> {
    probe(vm, addr, size, true)?;
    let zeros = [0u8; PAGE_SIZE as usize];
    let mut done = 0;
    while done < size {
        let n = (size - done).min(PAGE_SIZE) as usize;
        vm.space()
            .wr(addr + done, &zeros[..n])
            .map_err(HeapError::MemoryFault)?;
        done += n as u64;
    }
    Ok(())
}

/// Both ranges are checked before the first byte is copied. Heap blocks are
/// disjoint, so failed copying can affect only the unpublished destination.
fn copy_range(vm: &VirtualMemory, from: u64, to: u64, size: u64) -> Result<(), HeapError> {
    probe(vm, from, size, false)?;
    probe(vm, to, size, true)?;
    let mut buf = [0u8; PAGE_SIZE as usize];
    let mut done = 0;
    while done < size {
        let n = (size - done).min(PAGE_SIZE) as usize;
        vm.space()
            .rd(from + done, &mut buf[..n])
            .map_err(HeapError::MemoryFault)?;
        vm.space()
            .wr(to + done, &buf[..n])
            .map_err(HeapError::MemoryFault)?;
        done += n as u64;
    }
    Ok(())
}

/// Every heap of the process.
#[derive(Debug, Default)]
pub struct Heaps {
    heaps: BTreeMap<u64, Heap>,
    align: u64,
}

impl Heaps {
    /// Heaps with block alignment `align` (8 or 16).
    pub fn new(align: u64) -> Self {
        Heaps {
            heaps: BTreeMap::new(),
            align,
        }
    }

    fn add_segment(vm: &mut VirtualMemory, size: u64, initial: u64, flags: u32) -> Option<u64> {
        let protect = if flags & HEAP_CREATE_ENABLE_EXECUTE != 0 {
            prot::EXECUTE_READWRITE
        } else {
            prot::READWRITE
        };
        let label: Arc<str> = Arc::from("[heap]");
        let base = vm
            .reserve(None, size, protect, AllocKind::Private, false, Some(label))
            .ok()?;
        if initial != 0 && vm.commit(base, initial, protect).is_err() {
            // The reservation is new and contains no earlier heap allocation.
            let _ = vm.release(base);
            return None;
        }
        Some(base)
    }

    fn candidate(vm: &mut VirtualMemory, heap: &Heap, rounded: u64) -> Option<Candidate> {
        let mut candidate = if let Some(&(_, addr)) = heap.by_size.range((rounded, 0)..).next() {
            Candidate {
                addr,
                segment: None,
                commits: Vec::new(),
            }
        } else {
            // A fixed heap's one reservation already spans its maximum.
            if heap.max != 0 {
                return None;
            }
            let grow = round_up(rounded.max(SEGMENT), 0x1_0000)?;
            let base = Self::add_segment(vm, grow, 0, heap.flags)?;
            Candidate {
                addr: base,
                segment: Some((base, grow)),
                commits: Vec::new(),
            }
        };
        if Self::commit_candidate(vm, heap.flags, &mut candidate, rounded).is_none() {
            Self::abort(vm, &candidate);
            return None;
        }
        Some(candidate)
    }

    /// Commit only reserved pages: never restore the protection of an already
    /// committed heap page changed by guest VirtualProtect. Failed preparation
    /// decommits the newly committed pages, including partial multi-run work.
    fn commit_candidate(
        vm: &mut VirtualMemory,
        flags: u32,
        candidate: &mut Candidate,
        rounded: u64,
    ) -> Option<()> {
        let protect = if flags & HEAP_CREATE_ENABLE_EXECUTE != 0 {
            prot::EXECUTE_READWRITE
        } else {
            prot::READWRITE
        };
        let (mut cur, end) = page_range(candidate.addr, rounded).ok()?;
        while cur < end {
            let info = vm.query(cur)?;
            let len = info.size.min(end - cur);
            if len == 0 {
                return None;
            }
            match info.state {
                mem::RESERVE => {
                    vm.commit(cur, len, protect).ok()?;
                    candidate.commits.push((cur, len));
                }
                mem::COMMIT => {}
                _ => return None,
            }
            cur = cur.checked_add(len)?;
        }
        Some(())
    }

    fn abort(vm: &mut VirtualMemory, candidate: &Candidate) {
        if let Some((base, _)) = candidate.segment {
            let _ = vm.release(base);
        } else {
            for &(base, len) in &candidate.commits {
                let _ = vm.decommit(base, len);
            }
        }
    }

    fn publish(heap: &mut Heap, candidate: Candidate, rounded: u64, size: u64) -> u64 {
        if let Some((base, grow)) = candidate.segment {
            heap.segments.push((base, grow));
            heap.insert_free(base, grow);
        }
        // Neither heap index has changed since candidate selection; newly
        // added segments cannot merge with a different reservation.
        let addr = heap.take(rounded).expect("selected heap candidate");
        assert_eq!(addr, candidate.addr);
        heap.used.insert(addr, (rounded, size));
        addr
    }

    /// `HeapCreate(flags, initial, maximum)`: the new heap's handle.
    pub fn create(
        &mut self,
        vm: &mut VirtualMemory,
        flags: u32,
        initial: u64,
        max: u64,
    ) -> Option<u64> {
        if !matches!(self.align, 8 | 16) {
            return None;
        }
        if max != 0 && initial >= max {
            return None;
        }
        let committed = round_up(initial.max(PAGE_SIZE), PAGE_SIZE)?;
        let max = if max == 0 {
            0
        } else {
            round_up(max, PAGE_SIZE)?
        };
        let first = if max != 0 {
            max
        } else {
            committed.max(SEGMENT)
        };
        let base = Self::add_segment(vm, first, committed, flags)?;
        let mut heap = Heap {
            flags,
            align: self.align,
            max,
            segments: vec![(base, first)],
            free: BTreeMap::new(),
            by_size: BTreeSet::new(),
            used: HashMap::new(),
        };
        // The first 0x100 bytes stand for the heap header: the handle is
        // never a block address.
        heap.insert_free(base + 0x100, first - 0x100);
        self.heaps.insert(base, heap);
        Some(base)
    }

    /// `HeapDestroy`.
    pub fn destroy(&mut self, vm: &mut VirtualMemory, handle: u64) -> bool {
        match self.heaps.remove(&handle) {
            Some(h) => {
                for (base, _) in h.segments {
                    let _ = vm.release(base);
                }
                true
            }
            None => false,
        }
    }

    /// Whether `handle` is a heap.
    pub fn is_heap(&self, handle: u64) -> bool {
        self.heaps.contains_key(&handle)
    }

    /// The flags a heap was created with.
    pub fn flags(&self, handle: u64) -> Option<u32> {
        self.heaps.get(&handle).map(|h| h.flags)
    }

    /// Every heap handle, lowest first.
    pub fn handles(&self) -> Vec<u64> {
        self.heaps.keys().copied().collect()
    }

    /// `HeapAlloc`: a block of at least `size` bytes, zeroed when `zero`.
    pub fn alloc(
        &mut self,
        vm: &mut VirtualMemory,
        handle: u64,
        size: u64,
        zero: bool,
    ) -> Option<u64> {
        self.alloc_checked(vm, handle, size, zero).ok()
    }

    /// Allocation with a precise failure category for built-in guest APIs.
    /// The compatibility [`Self::alloc`] interface maps every failure to None.
    pub fn alloc_checked(
        &mut self,
        vm: &mut VirtualMemory,
        handle: u64,
        size: u64,
        zero: bool,
    ) -> Result<u64, HeapError> {
        let heap = self.heaps.get(&handle).ok_or(HeapError::BadHeap)?;
        let rounded = rounded_size(size, heap.align).ok_or(HeapError::NoMemory)?;
        let candidate = Self::candidate(vm, heap, rounded).ok_or(HeapError::NoMemory)?;
        if zero && let Err(e) = zero_range(vm, candidate.addr, rounded) {
            Self::abort(vm, &candidate);
            return Err(e);
        }
        let heap = self.heaps.get_mut(&handle).expect("validated heap");
        Ok(Self::publish(heap, candidate, rounded, size))
    }

    /// `HeapFree`.
    pub fn free(&mut self, handle: u64, ptr: u64) -> Result<(), HeapError> {
        let heap = self.heaps.get_mut(&handle).ok_or(HeapError::BadHeap)?;
        let (rounded, _) = heap.used.remove(&ptr).ok_or(HeapError::BadBlock)?;
        heap.insert_free(ptr, rounded);
        Ok(())
    }

    /// `HeapSize`: the requested size of a live block.
    pub fn size(&self, handle: u64, ptr: u64) -> Result<u64, HeapError> {
        let heap = self.heaps.get(&handle).ok_or(HeapError::BadHeap)?;
        heap.used.get(&ptr).map(|u| u.1).ok_or(HeapError::BadBlock)
    }

    /// The heap owning live block `ptr`.
    pub fn owner(&self, ptr: u64) -> Option<u64> {
        self.heaps
            .iter()
            .find(|(_, h)| h.used.contains_key(&ptr))
            .map(|(&k, _)| k)
    }

    /// `HeapReAlloc`: resizes a block, moving it unless `in_place`. New
    /// bytes are zeroed when `zero`.
    pub fn realloc(
        &mut self,
        vm: &mut VirtualMemory,
        handle: u64,
        ptr: u64,
        size: u64,
        in_place: bool,
        zero: bool,
    ) -> Result<u64, HeapError> {
        let heap = self.heaps.get(&handle).ok_or(HeapError::BadHeap)?;
        let &(rounded, old) = heap.used.get(&ptr).ok_or(HeapError::BadBlock)?;
        let want = rounded_size(size, heap.align).ok_or(HeapError::NoMemory)?;
        if want <= rounded {
            if zero && size > old {
                zero_range(
                    vm,
                    ptr.checked_add(old).ok_or(HeapError::NoMemory)?,
                    size - old,
                )?;
            }
            // Shrink (or same size) in place; release the tail.
            let heap = self.heaps.get_mut(&handle).expect("validated heap");
            if want < rounded {
                heap.insert_free(
                    ptr.checked_add(want).expect("live block range"),
                    rounded - want,
                );
            }
            heap.used.insert(ptr, (want, size));
            return Ok(ptr);
        }
        // Grow in place from an adjacent free block.
        let end = ptr.checked_add(rounded).ok_or(HeapError::NoMemory)?;
        if let Some(&next) = heap.free.get(&end)
            && next >= want - rounded
            && heap.same_segment(ptr, end)
        {
            let mut candidate = Candidate {
                addr: ptr,
                segment: None,
                commits: Vec::new(),
            };
            if Self::commit_candidate(vm, heap.flags, &mut candidate, want).is_none() {
                Self::abort(vm, &candidate);
                return Err(HeapError::NoMemory);
            }
            if zero
                && let Err(e) = zero_range(
                    vm,
                    ptr.checked_add(old).ok_or(HeapError::NoMemory)?,
                    size - old,
                )
            {
                Self::abort(vm, &candidate);
                return Err(e);
            }
            let heap = self.heaps.get_mut(&handle).expect("validated heap");
            heap.free.remove(&end);
            heap.by_size.remove(&(next, end));
            let spare = next - (want - rounded);
            if spare > 0 {
                let tail = ptr.checked_add(want).expect("resized block range");
                heap.free.insert(tail, spare);
                heap.by_size.insert((spare, tail));
            }
            heap.used.insert(ptr, (want, size));
            return Ok(ptr);
        }
        if in_place {
            return Err(HeapError::NoMemory);
        }
        let candidate = Self::candidate(vm, heap, want).ok_or(HeapError::NoMemory)?;
        let initialize = || -> Result<(), HeapError> {
            // Preflight the tail before copy, so a tail fault also writes no
            // destination bytes. Neither candidate nor old block is published
            // or removed while either operation can fail.
            if zero && size > old {
                probe(
                    vm,
                    candidate.addr.checked_add(old).ok_or(HeapError::NoMemory)?,
                    size - old,
                    true,
                )?;
            }
            copy_range(vm, ptr, candidate.addr, old.min(size))?;
            if zero && size > old {
                zero_range(
                    vm,
                    candidate.addr.checked_add(old).ok_or(HeapError::NoMemory)?,
                    size - old,
                )?;
            }
            Ok(())
        };
        if let Err(e) = initialize() {
            Self::abort(vm, &candidate);
            return Err(e);
        }
        let heap = self.heaps.get_mut(&handle).expect("validated heap");
        let new = Self::publish(heap, candidate, want, size);
        heap.used.remove(&ptr).expect("validated old block");
        heap.insert_free(ptr, rounded);
        Ok(new)
    }

    /// Live blocks of a heap as `(address, requested size)`, by address
    /// (`HeapWalk`).
    pub fn blocks(&self, handle: u64) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self
            .heaps
            .get(&handle)
            .map(|h| h.used.iter().map(|(&a, &(_, s))| (a, s)).collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, PAGE_SIZE, SpaceConfig};

    fn vm() -> VirtualMemory {
        vm_with_limit(1024 * PAGE_SIZE, 1024 * PAGE_SIZE)
    }

    fn vm_with_limit(arena_bytes: u64, limit: u64) -> VirtualMemory {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 40,
            arena_bytes,
            reserved_phys: Vec::new(),
        })
        .unwrap();
        VirtualMemory::new_with_commit_limit(space, 0x1_0000, 1 << 40, limit)
    }

    type Snapshot = (
        Vec<(u64, u64)>,
        BTreeMap<u64, u64>,
        BTreeSet<(u64, u64)>,
        HashMap<u64, (u64, u64)>,
    );

    fn snapshot(heaps: &Heaps, handle: u64) -> Snapshot {
        let heap = &heaps.heaps[&handle];
        (
            heap.segments.clone(),
            heap.free.clone(),
            heap.by_size.clone(),
            heap.used.clone(),
        )
    }

    fn assert_indexes(heaps: &Heaps, handle: u64) {
        let heap = &heaps.heaps[&handle];
        assert_eq!(
            heap.by_size,
            heap.free.iter().map(|(&a, &s)| (s, a)).collect()
        );
        let mut ranges: Vec<(u64, u64)> = heap
            .free
            .iter()
            .map(|(&a, &s)| (a, s))
            .chain(heap.used.iter().map(|(&a, &(s, _))| (a, s)))
            .collect();
        ranges.sort_unstable();
        for &(addr, size) in &ranges {
            assert!(size > 0);
            let end = addr.checked_add(size).unwrap();
            assert!(heap.same_segment(addr, end - 1));
        }
        for pair in ranges.windows(2) {
            assert!(pair[0].0 + pair[0].1 <= pair[1].0, "overlapping blocks");
        }
    }

    #[test]
    fn blocks_are_aligned_distinct_and_reused_after_free() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, 1, false).unwrap();
        let b = heaps.alloc(&mut vm, h, 17, false).unwrap();
        assert_eq!(a % 16, 0);
        assert_eq!(b % 16, 0);
        assert!(b >= a + 16, "blocks do not overlap");
        assert_eq!(heaps.size(h, b), Ok(17));
        heaps.free(h, a).unwrap();
        assert_eq!(heaps.free(h, a), Err(HeapError::BadBlock), "double free");
        let c = heaps.alloc(&mut vm, h, 8, false).unwrap();
        assert_eq!(c, a, "best fit reuses the freed block");
        assert_ne!(
            heaps.alloc(&mut vm, h, 0, false),
            None,
            "zero-size blocks exist"
        );
    }

    #[test]
    fn realloc_grows_in_place_or_moves_and_zeroes() {
        let mut vm = vm();
        let mut heaps = Heaps::new(8);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, 8, false).unwrap();
        vm.poke(a, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        // Nothing after `a` yet: grows in place.
        let a2 = heaps.realloc(&mut vm, h, a, 64, false, true).unwrap();
        assert_eq!(a2, a);
        let mut buf = [0xFFu8; 16];
        vm.peek(a, &mut buf).unwrap();
        assert_eq!(&buf[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&buf[8..], &[0; 8], "zeroed growth");
        // Block `b` after it forces a move.
        let _b = heaps.alloc(&mut vm, h, 8, false).unwrap();
        assert_eq!(
            heaps.realloc(&mut vm, h, a, 4096, true, false),
            Err(HeapError::NoMemory),
            "in-place only"
        );
        let moved = heaps.realloc(&mut vm, h, a, 4096, false, false).unwrap();
        assert_ne!(moved, a);
        let mut buf = [0u8; 8];
        vm.peek(moved, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(heaps.size(h, a), Err(HeapError::BadBlock));
    }

    #[test]
    fn growable_heaps_add_segments_and_fixed_heaps_do_not() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let g = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let big = heaps.alloc(&mut vm, g, 3 << 20, false).unwrap();
        assert_eq!(heaps.size(g, big), Ok(3 << 20));
        assert_eq!(vm.committed_bytes(), (3 << 20) + PAGE_SIZE);
        assert_eq!(heaps.heaps[&g].segments.len(), 2);
        let f = heaps.create(&mut vm, 0, 0, 0x2_0000).unwrap();
        assert!(heaps.alloc(&mut vm, f, 0x1_0000, false).is_some());
        assert!(heaps.alloc(&mut vm, f, 0x2_0000, false).is_none());
        assert!(heaps.destroy(&mut vm, f));
        assert!(!heaps.is_heap(f));
    }

    #[test]
    fn creation_reserves_page_rounded_maximum_and_commits_initial_pages_only() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let fixed = heaps.create(&mut vm, 0, 0, 3 * PAGE_SIZE + 1).unwrap();
        assert_eq!(vm.allocation(fixed).unwrap().size, 4 * PAGE_SIZE);
        assert_eq!(vm.committed_bytes(), PAGE_SIZE);
        assert_eq!(vm.query(fixed).unwrap().state, mem::COMMIT);
        assert_eq!(vm.query(fixed + PAGE_SIZE).unwrap().state, mem::RESERVE);
        let block = heaps.alloc(&mut vm, fixed, 2 * PAGE_SIZE, false).unwrap();
        assert_eq!(block, fixed + 0x100);
        assert_eq!(vm.committed_bytes(), 3 * PAGE_SIZE);
        assert_eq!(vm.query(fixed + 3 * PAGE_SIZE).unwrap().state, mem::RESERVE);
        heaps.free(fixed, block).unwrap();
        assert_eq!(
            vm.committed_bytes(),
            3 * PAGE_SIZE,
            "free retains commitment"
        );
        assert!(heaps.destroy(&mut vm, fixed));
        assert_eq!(vm.committed_bytes(), 0);
        let grow = heaps.create(&mut vm, 0, PAGE_SIZE + 1, 0).unwrap();
        assert_eq!(vm.committed_bytes(), 2 * PAGE_SIZE);
        assert_eq!(vm.allocation(grow).unwrap().size, SEGMENT);
        assert_indexes(&heaps, grow);
    }

    #[test]
    fn failed_initial_commit_releases_reservation_and_reuses_address() {
        let mut vm = vm_with_limit(4 * PAGE_SIZE, PAGE_SIZE);
        let mut heaps = Heaps::new(16);
        assert_eq!(heaps.create(&mut vm, 0, PAGE_SIZE + 1, 0), None);
        assert_eq!(vm.allocations().count(), 0);
        assert_eq!(vm.committed_bytes(), 0);
        assert!(heaps.handles().is_empty());
        assert_eq!(heaps.create(&mut vm, 0, 0, 0), Some(0x1_0000));
    }

    #[test]
    fn failed_growth_releases_new_reservation_without_changing_heap_indexes() {
        let mut vm = vm_with_limit(4 * PAGE_SIZE, PAGE_SIZE);
        let mut heaps = Heaps::new(16);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let before = snapshot(&heaps, h);
        assert_eq!(heaps.alloc(&mut vm, h, SEGMENT + 16, false), None);
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(vm.allocations().count(), 1);
        assert_eq!(vm.committed_bytes(), PAGE_SIZE);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn partial_multi_run_commit_is_rolled_back_and_existing_protection_kept() {
        let mut vm = vm_with_limit(8 * PAGE_SIZE, 3 * PAGE_SIZE);
        let mut heaps = Heaps::new(16);
        let h = heaps.create(&mut vm, 0, 0, 4 * PAGE_SIZE).unwrap();
        vm.commit(h + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let before = snapshot(&heaps, h);
        assert_eq!(heaps.alloc(&mut vm, h, 4 * PAGE_SIZE - 0x100, false), None);
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(vm.committed_bytes(), 2 * PAGE_SIZE);
        assert_eq!(vm.query(h + PAGE_SIZE).unwrap().state, mem::RESERVE);
        assert_eq!(vm.query(h + 2 * PAGE_SIZE).unwrap().protect, prot::NOACCESS);
        assert_eq!(vm.query(h + 3 * PAGE_SIZE).unwrap().state, mem::RESERVE);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn failed_zero_allocation_preserves_indexes_data_and_reserved_page_charge() {
        let mut vm = vm();
        let mut heaps = Heaps::new(8);
        let h = heaps.create(&mut vm, 0, 0, 4 * PAGE_SIZE).unwrap();
        vm.poke(h + 0x100, &[0xA5; 32]).unwrap();
        vm.protect(h, PAGE_SIZE, prot::READONLY).unwrap();
        let before = snapshot(&heaps, h);
        assert_eq!(
            heaps.alloc_checked(&mut vm, h, 2 * PAGE_SIZE, true),
            Err(HeapError::MemoryFault(MemFault {
                addr: h + 0x100,
                write: true
            }))
        );
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(vm.committed_bytes(), PAGE_SIZE);
        assert_eq!(vm.query(h + PAGE_SIZE).unwrap().state, mem::RESERVE);
        assert_eq!(vm.query(h).unwrap().protect, prot::READONLY);
        let mut data = [0; 32];
        vm.peek(h + 0x100, &mut data).unwrap();
        assert_eq!(data, [0xA5; 32]);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn late_zero_fault_does_not_write_earlier_accessible_page() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let h = heaps
            .create(&mut vm, 0, 3 * PAGE_SIZE, 4 * PAGE_SIZE)
            .unwrap();
        vm.poke(h + 0x100, &[0x5A; PAGE_SIZE as usize]).unwrap();
        vm.protect(h + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let before = snapshot(&heaps, h);
        assert_eq!(heaps.alloc(&mut vm, h, 2 * PAGE_SIZE, true), None);
        assert_eq!(snapshot(&heaps, h), before);
        let mut first = [0; 32];
        vm.peek(h + 0x100, &mut first).unwrap();
        assert_eq!(first, [0x5A; 32]);
        assert_eq!(vm.query(h + PAGE_SIZE).unwrap().protect, prot::NOACCESS);
    }

    #[test]
    fn same_rounded_realloc_fault_preserves_requested_size_and_bytes() {
        let mut vm = vm();
        let mut heaps = Heaps::new(8);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, 1, false).unwrap();
        vm.poke(a, &[0xA1, 0xB2, 0xB2, 0xB2, 0xB2, 0xB2, 0xB2, 0xB2])
            .unwrap();
        vm.protect(h, PAGE_SIZE, prot::READONLY).unwrap();
        let before = snapshot(&heaps, h);
        assert_eq!(
            heaps.realloc(&mut vm, h, a, 7, true, true),
            Err(HeapError::MemoryFault(MemFault {
                addr: a + 1,
                write: true
            }))
        );
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(heaps.size(h, a), Ok(1));
        let mut data = [0; 8];
        vm.peek(a, &mut data).unwrap();
        assert_eq!(data, [0xA1, 0xB2, 0xB2, 0xB2, 0xB2, 0xB2, 0xB2, 0xB2]);
    }

    #[test]
    fn in_place_zero_growth_fault_preserves_old_block_and_refunds_new_pages() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, 16, false).unwrap();
        vm.poke(a, &[0xC3; 16]).unwrap();
        vm.commit(h + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS).unwrap();
        let before = snapshot(&heaps, h);
        assert_eq!(
            heaps.realloc(&mut vm, h, a, 3 * PAGE_SIZE, true, true),
            Err(HeapError::MemoryFault(MemFault {
                addr: h + PAGE_SIZE,
                write: true
            }))
        );
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(heaps.size(h, a), Ok(16));
        assert_eq!(vm.committed_bytes(), 2 * PAGE_SIZE);
        assert_eq!(vm.query(h + 2 * PAGE_SIZE).unwrap().state, mem::RESERVE);
        let mut data = [0; 16];
        vm.peek(a, &mut data).unwrap();
        assert_eq!(data, [0xC3; 16]);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn moved_realloc_source_fault_releases_candidate_segment_and_preserves_old_block() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, 16, false).unwrap();
        vm.poke(a, &[0xD4; 16]).unwrap();
        let b = heaps.alloc(&mut vm, h, SEGMENT - 0x110, false).unwrap();
        vm.protect(h, PAGE_SIZE, prot::NOACCESS).unwrap();
        let before = snapshot(&heaps, h);
        let charge = vm.committed_bytes();
        assert_eq!(
            heaps.realloc(&mut vm, h, a, SEGMENT + PAGE_SIZE, false, false),
            Err(HeapError::MemoryFault(MemFault {
                addr: a,
                write: false
            }))
        );
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(heaps.size(h, a), Ok(16));
        assert_eq!(heaps.size(h, b), Ok(SEGMENT - 0x110));
        assert_eq!(vm.allocations().count(), 1);
        assert_eq!(vm.committed_bytes(), charge);
        let mut data = [0; 16];
        vm.peek(a, &mut data).unwrap();
        assert_eq!(data, [0xD4; 16]);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn moved_realloc_destination_fault_rolls_back_commit_and_preserves_original() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, PAGE_SIZE, false).unwrap();
        vm.poke(a, &[0xE5; 32]).unwrap();
        let _barrier = heaps.alloc(&mut vm, h, PAGE_SIZE, false).unwrap();
        let destination = a + 2 * PAGE_SIZE;
        vm.protect(h + 2 * PAGE_SIZE, PAGE_SIZE, prot::READONLY)
            .unwrap();
        let before = snapshot(&heaps, h);
        let charge = vm.committed_bytes();
        assert_eq!(
            heaps.realloc(&mut vm, h, a, 4 * PAGE_SIZE, false, false),
            Err(HeapError::MemoryFault(MemFault {
                addr: destination,
                write: true
            }))
        );
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(heaps.size(h, a), Ok(PAGE_SIZE));
        assert_eq!(vm.committed_bytes(), charge);
        assert_eq!(vm.query(h + 3 * PAGE_SIZE).unwrap().state, mem::RESERVE);
        let mut data = [0; 32];
        vm.peek(a, &mut data).unwrap();
        assert_eq!(data, [0xE5; 32]);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn free_blocks_do_not_coalesce_across_segment_boundaries_in_either_order() {
        let mut vm = vm();
        for reversed in [false, true] {
            let mut heaps = Heaps::new(16);
            let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
            let a = heaps.alloc(&mut vm, h, SEGMENT - 0x100, false).unwrap();
            let b = heaps.alloc(&mut vm, h, SEGMENT, false).unwrap();
            assert_eq!(b, h + SEGMENT, "adjacent separate reservations");
            for block in if reversed { [b, a] } else { [a, b] } {
                heaps.free(h, block).unwrap();
            }
            assert_eq!(heaps.heaps[&h].free.len(), 2);
            assert_eq!(heaps.heaps[&h].free[&a], SEGMENT - 0x100);
            assert_eq!(heaps.heaps[&h].free[&b], SEGMENT);
            assert_indexes(&heaps, h);
            assert!(heaps.destroy(&mut vm, h));
        }
    }

    #[test]
    fn in_place_growth_cannot_cross_adjacent_reservations() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, SEGMENT - 0x100, false).unwrap();
        let b = heaps.alloc(&mut vm, h, SEGMENT, false).unwrap();
        heaps.free(h, b).unwrap();
        let before = snapshot(&heaps, h);
        assert_eq!(
            heaps.realloc(&mut vm, h, a, SEGMENT - 0xF0, true, false),
            Err(HeapError::NoMemory)
        );
        assert_eq!(snapshot(&heaps, h), before);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn guest_size_rounding_overflow_never_mutates_heap_or_vm() {
        let mut vm = vm();
        let mut heaps = Heaps::new(16);
        assert_eq!(heaps.create(&mut vm, 0, u64::MAX, 0), None);
        assert_eq!(heaps.create(&mut vm, 0, 0, u64::MAX), None);
        assert_eq!(vm.allocations().count(), 0);
        let h = heaps.create(&mut vm, 0, 0, 0).unwrap();
        let a = heaps.alloc(&mut vm, h, 16, false).unwrap();
        let before = snapshot(&heaps, h);
        let charge = vm.committed_bytes();
        for size in [u64::MAX, u64::MAX - 0xFFF] {
            assert_eq!(heaps.alloc(&mut vm, h, size, true), None);
            assert_eq!(
                heaps.realloc(&mut vm, h, a, size, false, true),
                Err(HeapError::NoMemory)
            );
        }
        assert_eq!(snapshot(&heaps, h), before);
        assert_eq!(vm.allocations().count(), 1);
        assert_eq!(vm.committed_bytes(), charge);
        assert_indexes(&heaps, h);
    }

    #[test]
    fn invalid_heap_alignment_and_initial_maximum_are_rejected_before_reserving() {
        let mut vm = vm();
        for align in [0, 1, 3, 32] {
            assert_eq!(Heaps::new(align).create(&mut vm, 0, 0, 0), None);
        }
        let mut heaps = Heaps::new(8);
        assert_eq!(heaps.create(&mut vm, 0, PAGE_SIZE, PAGE_SIZE), None);
        assert_eq!(heaps.create(&mut vm, 0, 2 * PAGE_SIZE, PAGE_SIZE), None);
        assert_eq!(vm.allocations().count(), 0);
        assert_eq!(vm.committed_bytes(), 0);
    }
}

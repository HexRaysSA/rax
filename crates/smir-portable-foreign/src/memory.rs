//! The processor's memory for calls: where the engine puts a crossing's
//! frame, arguments and result, which foreign code reads and writes.
//!
//! It is one range of the address space, mapped as far as it has been
//! needed, and handed out in blocks of multiples of 16 bytes. A block that
//! is given back is free for the next call, joined with the free blocks on
//! either side of it, so a program that crosses a million times uses no
//! more than one that crosses once.

use std::collections::BTreeMap;

use rax::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms};
use rax_smir_portable::interp::ForeignFault;

/// How much more is mapped when no free block is large enough, at least.
const GROWTH: u64 = 16 * PAGE_SIZE;

pub(crate) struct Heap {
    /// Where the range may not reach.
    limit: u64,
    /// The end of what is mapped of it, which at first is where it begins.
    mapped: u64,
    /// Blocks by address, each with its size: those that are free, no two
    /// of which touch, and those that are held.
    free: BTreeMap<u64, u64>,
    held: BTreeMap<u64, u64>,
}

impl Heap {
    /// A heap of the pages from `start` up to `limit`, none mapped yet.
    pub(crate) fn new(start: u64, limit: u64) -> Self {
        Self {
            limit,
            mapped: start,
            free: BTreeMap::new(),
            held: BTreeMap::new(),
        }
    }

    /// How many bytes are held.
    pub(crate) fn in_use(&self) -> u64 {
        self.held.values().sum()
    }

    /// A block of at least `bytes` zero bytes, at a multiple of 16.
    pub(crate) fn allocate(
        &mut self,
        space: &AddressSpace,
        bytes: u64,
    ) -> Result<u64, ForeignFault> {
        let bytes = bytes
            .max(1)
            .checked_next_multiple_of(16)
            .ok_or(ForeignFault)?;
        let fits = self
            .free
            .iter()
            .find(|(_, size)| **size >= bytes)
            .map(|(address, size)| (*address, *size));
        let (address, size) = match fits {
            Some(block) => block,
            None => self.grow(space, bytes)?,
        };
        self.free.remove(&address);
        if size > bytes {
            self.free.insert(address + bytes, size - bytes);
        }
        // What was in the block before is not the next call's to see.
        let zeros = vec![0; usize::try_from(bytes).map_err(|_| ForeignFault)?];
        space.write_raw(address, &zeros).map_err(|_| ForeignFault)?;
        self.held.insert(address, bytes);
        Ok(address)
    }

    /// Map more, enough that the last free block holds `bytes`, and return
    /// that block.
    fn grow(&mut self, space: &AddressSpace, bytes: u64) -> Result<(u64, u64), ForeignFault> {
        // A free block that ends where the mapping ends grows with it.
        let last = self
            .free
            .last_key_value()
            .map(|(address, size)| (*address, *size))
            .filter(|(address, size)| address + size == self.mapped);
        let (address, have) = last.unwrap_or((self.mapped, 0));
        let more = (bytes - have)
            .max(GROWTH)
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(ForeignFault)?;
        let end = self.mapped.checked_add(more).ok_or(ForeignFault)?;
        if end > self.limit {
            return Err(ForeignFault);
        }
        space
            .map(
                self.mapped,
                more,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .map_err(|_| ForeignFault)?;
        self.mapped = end;
        self.free.insert(address, have + more);
        Ok((address, have + more))
    }

    /// Give back the block at `address`. An address that is no block's is
    /// nothing to give back.
    pub(crate) fn release(&mut self, address: u64) {
        let Some(size) = self.held.remove(&address) else {
            return;
        };
        let (mut start, mut end) = (address, address + size);
        if let Some((before, length)) = self.free.range(..address).next_back()
            && before + length == address
        {
            start = *before;
        }
        if let Some(length) = self.free.remove(&end) {
            end += length;
        }
        self.free.insert(start, end - start);
    }

    #[cfg(test)]
    fn free(&self) -> Vec<(u64, u64)> {
        self.free.iter().map(|(at, size)| (*at, *size)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rax::user::mm::SpaceConfig;

    const AT: u64 = 0x4000_0000;

    fn space() -> AddressSpace {
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 256 * PAGE_SIZE,
            reserved_phys: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn blocks_are_zero_apart_and_free_again_when_given_back() {
        let space = space();
        let mut heap = Heap::new(AT, AT + 64 * PAGE_SIZE);
        let one = heap.allocate(&space, 150).unwrap();
        let other = heap.allocate(&space, 1).unwrap();
        assert_eq!((one, other), (AT, AT + 160));
        assert_eq!(heap.in_use(), 176);
        // What a call left in its block, the next does not find.
        space.write_raw(one, &[0xAB; 160]).unwrap();
        heap.release(one);
        assert_eq!(heap.in_use(), 16);
        let again = heap.allocate(&space, 160).unwrap();
        let mut found = [1; 160];
        space.read_raw(again, &mut found).unwrap();
        assert_eq!((again, found), (one, [0; 160]));
        // Free blocks join: when all is given back, in any order, there is
        // one, of all that was mapped.
        let third = heap.allocate(&space, 4096).unwrap();
        for block in [other, third, again, again, AT + 8] {
            heap.release(block);
        }
        assert_eq!(heap.free(), [(AT, GROWTH)]);
        assert_eq!(heap.in_use(), 0);
    }

    #[test]
    fn the_heap_grows_as_far_as_its_limit() {
        let space = space();
        let mut heap = Heap::new(AT, AT + 3 * GROWTH);
        // More than one growth at once; then what is left of it and more.
        let large = heap.allocate(&space, GROWTH + 16).unwrap();
        assert_eq!(heap.free(), [(AT + GROWTH + 16, PAGE_SIZE - 16)]);
        let next = heap.allocate(&space, PAGE_SIZE).unwrap();
        assert_eq!(next, AT + GROWTH + 16);
        assert_eq!(heap.free(), [(next + PAGE_SIZE, GROWTH - 16)]);
        // Beyond the limit there is nothing, and nothing is lost by asking.
        assert_eq!(heap.allocate(&space, 2 * GROWTH), Err(ForeignFault));
        assert_eq!(heap.allocate(&space, u64::MAX), Err(ForeignFault));
        heap.release(large);
        heap.release(next);
        assert_eq!(heap.free(), [(AT, 2 * GROWTH + PAGE_SIZE)]);
        assert!(heap.allocate(&space, 2 * GROWTH).is_ok());
    }
}

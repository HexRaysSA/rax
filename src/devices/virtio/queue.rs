//! Split-ring planning and publication; preserve the public queue/descriptor API.
use super::{Mem, VIRTIO_F_INDIRECT_DESC};
use std::collections::BTreeSet;
use std::fmt;

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

#[derive(Clone, Copy, Debug, Default)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}
impl Descriptor {
    pub fn has_next(&self) -> bool {
        self.flags & VRING_DESC_F_NEXT != 0
    }
    pub fn is_write_only(&self) -> bool {
        self.flags & VRING_DESC_F_WRITE != 0
    }
}

pub struct DescriptorChain {
    pub head: u16,
    pub descriptors: Vec<Descriptor>,
}

/// An invalid queue or failed DMA cannot safely be retried automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueError {
    Invalid {
        field: &'static str,
        value: u64,
    },
    Dma {
        address: u64,
        length: usize,
        write: bool,
    },
}
impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { field, value } => write!(f, "invalid virtqueue {field}: {value:#x}"),
            Self::Dma {
                address,
                length,
                write,
            } => write!(
                f,
                "virtqueue DMA {} at {address:#x}, {length} bytes failed",
                if *write { "write" } else { "read" }
            ),
        }
    }
}
impl std::error::Error for QueueError {}
fn invalid(field: &'static str, value: u64) -> QueueError {
    QueueError::Invalid { field, value }
}
fn read<M: Mem>(memory: &M, address: u64, bytes: &mut [u8]) -> Result<(), QueueError> {
    if memory.read(address, bytes) {
        Ok(())
    } else {
        Err(QueueError::Dma {
            address,
            length: bytes.len(),
            write: false,
        })
    }
}
fn write<M: Mem>(memory: &mut M, address: u64, bytes: &[u8]) -> Result<(), QueueError> {
    if memory.write(address, bytes) {
        Ok(())
    } else {
        Err(QueueError::Dma {
            address,
            length: bytes.len(),
            write: true,
        })
    }
}
fn at(base: u64, offset: u64) -> Result<u64, QueueError> {
    base.checked_add(offset)
        .ok_or_else(|| invalid("address addition", base))
}

/// Existing public layout is unchanged. Synchronous processing publishes exactly
/// one used entry for each increment of last_avail_idx; that index owns both
/// counters rather than trusting a guest-written used.idx value.
#[derive(Clone, Debug, Default)]
pub struct VirtQueue {
    pub size: u32,
    pub ready: bool,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
    pub last_avail_idx: u16,
}
impl VirtQueue {
    fn descriptor<M: Mem>(
        &self,
        memory: &M,
        table: u64,
        count: u32,
        index: u16,
    ) -> Result<Descriptor, QueueError> {
        if u32::from(index) >= count {
            return Err(invalid("descriptor index", u64::from(index)));
        }
        let mut bytes = [0; 16];
        read(memory, at(table, u64::from(index) * 16)?, &mut bytes)?;
        Ok(Descriptor {
            addr: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            len: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            flags: u16::from_le_bytes(bytes[12..14].try_into().unwrap()),
            next: u16::from_le_bytes(bytes[14..].try_into().unwrap()),
        })
    }
    fn append(
        &self,
        descriptor: Descriptor,
        descriptors: &mut Vec<Descriptor>,
        total: &mut u64,
        writable: &mut bool,
    ) -> Result<(), QueueError> {
        if descriptors.len() >= self.size as usize {
            return Err(invalid("chain length", descriptors.len() as u64 + 1));
        }
        if *writable && !descriptor.is_write_only() {
            return Err(invalid(
                "readable buffer after writable buffer",
                descriptor.addr,
            ));
        }
        *writable |= descriptor.is_write_only();
        *total += u64::from(descriptor.len);
        if *total > 1u64 << 32 {
            return Err(invalid("chain byte length", *total));
        }
        if u128::from(descriptor.addr) + u128::from(descriptor.len) > 1u128 << 64 {
            return Err(invalid("buffer address extent", descriptor.addr));
        }
        descriptors.push(descriptor);
        Ok(())
    }
    /// Validate all reachable metadata before the device sees any payload.
    /// At most size buffers are retained: O(n log n) time, O(n) storage.
    fn read_chain<M: Mem>(
        &self,
        memory: &M,
        head: u16,
        features: u64,
    ) -> Result<DescriptorChain, QueueError> {
        let mut descriptors = Vec::new();
        let mut index = head;
        let mut direct = BTreeSet::new();
        let mut total = 0;
        let mut writable = false;
        loop {
            if !direct.insert(index) {
                return Err(invalid("direct descriptor cycle", u64::from(index)));
            }
            let descriptor = self.descriptor(memory, self.desc_addr, self.size, index)?;
            if descriptor.flags & VRING_DESC_F_INDIRECT != 0 {
                if features & VIRTIO_F_INDIRECT_DESC == 0 {
                    return Err(invalid(
                        "unnegotiated indirect descriptor",
                        u64::from(index),
                    ));
                }
                if descriptor.has_next() {
                    return Err(invalid("indirect descriptor NEXT flag", u64::from(index)));
                }
                if descriptor.len == 0 || descriptor.len % 16 != 0 {
                    return Err(invalid("indirect table length", u64::from(descriptor.len)));
                }
                if u128::from(descriptor.addr) + u128::from(descriptor.len) > 1u128 << 64 {
                    return Err(invalid("indirect table extent", descriptor.addr));
                }
                let mut indirect = BTreeSet::new();
                let mut next = 0;
                loop {
                    if !indirect.insert(next) {
                        return Err(invalid("indirect descriptor cycle", u64::from(next)));
                    }
                    let entry =
                        self.descriptor(memory, descriptor.addr, descriptor.len / 16, next)?;
                    if entry.flags & VRING_DESC_F_INDIRECT != 0 {
                        return Err(invalid("nested indirect descriptor", u64::from(next)));
                    }
                    self.append(entry, &mut descriptors, &mut total, &mut writable)?;
                    if !entry.has_next() {
                        return Ok(DescriptorChain { head, descriptors });
                    }
                    next = entry.next;
                }
            }
            self.append(descriptor, &mut descriptors, &mut total, &mut writable)?;
            if !descriptor.has_next() {
                return Ok(DescriptorChain { head, descriptors });
            }
            index = descriptor.next;
        }
    }
    fn push_used<M: Mem>(&self, memory: &mut M, head: u16, length: u32) -> Result<(), QueueError> {
        let index = self.last_avail_idx;
        let slot = u64::from(index) % u64::from(self.size);
        let address = at(self.used_addr, 4 + slot * 8)?;
        let mut entry = [0; 8];
        entry[..4].copy_from_slice(&u32::from(head).to_le_bytes());
        entry[4..].copy_from_slice(&length.to_le_bytes());
        write(memory, address, &entry)?;
        // Publication follows the complete entry. A failed write may be partial;
        // the transport reports DEVICE_NEEDS_RESET and never retries the handler.
        write(
            memory,
            at(self.used_addr, 2)?,
            &index.wrapping_add(1).to_le_bytes(),
        )
    }
    pub fn process_checked<M, F>(
        &mut self,
        memory: &mut M,
        features: u64,
        mut handler: F,
    ) -> Result<u32, QueueError>
    where
        M: Mem,
        F: FnMut(&DescriptorChain, &mut M) -> Result<u32, QueueError>,
    {
        if !self.ready {
            return Ok(0);
        }
        if !self.size.is_power_of_two() || self.size > 32768 {
            return Err(invalid("queue size", u64::from(self.size)));
        }
        if self.desc_addr % 16 != 0 || self.avail_addr % 2 != 0 || self.used_addr % 4 != 0 {
            return Err(invalid("queue area alignment", self.desc_addr));
        }
        for (address, length) in [
            (self.desc_addr, u64::from(self.size) * 16),
            (self.avail_addr, 4 + u64::from(self.size) * 2),
            (self.used_addr, 4 + u64::from(self.size) * 8),
        ] {
            if u128::from(address) + u128::from(length) > 1u128 << 64 {
                return Err(invalid("queue area extent", address));
            }
        }
        let mut bytes = [0; 2];
        read(memory, at(self.avail_addr, 2)?, &mut bytes)?;
        let target = u16::from_le_bytes(bytes);
        if u32::from(target.wrapping_sub(self.last_avail_idx)) > self.size {
            return Err(invalid(
                "available index distance",
                u64::from(target.wrapping_sub(self.last_avail_idx)),
            ));
        }
        let mut completed = 0;
        while self.last_avail_idx != target {
            let slot = u64::from(self.last_avail_idx) % u64::from(self.size);
            read(memory, at(self.avail_addr, 4 + slot * 2)?, &mut bytes)?;
            let head = u16::from_le_bytes(bytes);
            let chain = self.read_chain(memory, head, features)?;
            let length = handler(&chain, memory)?;
            self.push_used(memory, head, length)?;
            self.last_avail_idx = self.last_avail_idx.wrapping_add(1);
            completed += 1;
        }
        Ok(completed)
    }
    /// Compatibility entry point for direct descriptors. New feature-aware
    /// devices use process_checked and propagate errors to their transport.
    pub fn process<M, F>(&mut self, memory: &mut M, mut handler: F) -> u32
    where
        M: Mem,
        F: FnMut(&DescriptorChain, &mut M) -> u32,
    {
        let before = self.last_avail_idx;
        match self.process_checked(memory, 0, |chain, memory| Ok(handler(chain, memory))) {
            Ok(completed) => completed,
            Err(_) => {
                self.ready = false;
                u32::from(self.last_avail_idx.wrapping_sub(before))
            }
        }
    }
}

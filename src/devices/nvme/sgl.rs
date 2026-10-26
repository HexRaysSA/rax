//! NVMe1.4c section4.4 PCIe SGLs:byte-granular data/segment/last-segment.
//! Validate the entire metadata chain before payload DMA. Oversized buffers
//! are admitted and truncated to the requested transfer;null data entries
//! remain valid. Optional keyed/bit-bucket/transport/offset forms are gated.
use super::{Mem, SC_DATA_XFER_ERROR};
use std::collections::BTreeSet;

pub(super) const INVALID_SEGMENT: u16 = 0x0d;
pub(super) const INVALID_COUNT: u16 = 0x0e;
pub(super) const INVALID_LENGTH: u16 = 0x0f;
pub(super) const INVALID_TYPE: u16 = 0x11;

#[derive(Clone, Copy)]
struct Descriptor {
    address: u64,
    length: u32,
    kind: u8,
}
impl Descriptor {
    fn decode(first: u64, second: u64) -> Result<Self, u16> {
        let identifier = (second >> 56) as u8;
        if identifier & 0xf != 0 || !matches!(identifier >> 4, 0 | 2 | 3) {
            return Err(INVALID_TYPE);
        }
        let value = Self {
            address: first,
            length: second as u32,
            kind: identifier >> 4,
        };
        // An exclusive endpoint of2^64 is valid;only larger endpoints fail.
        if u128::from(value.address) + u128::from(value.length) > (1u128 << 64) {
            return Err(INVALID_LENGTH);
        }
        Ok(value)
    }
    fn segment(self) -> Result<(), u16> {
        if self.address & 7 != 0 || self.length == 0 || self.length % 16 != 0 {
            return Err(INVALID_SEGMENT);
        }
        Ok(())
    }
}
fn data(descriptor: Descriptor, remaining: &mut u64, plan: &mut Vec<(u64, u64)>) {
    let take = (*remaining).min(u64::from(descriptor.length));
    if take != 0 {
        plan.push((descriptor.address, take));
        *remaining -= take;
    }
}

/// For d descriptors, m metadata segments and k retained payload extents:
/// O(d+m*log(m)) time and O(m+k) storage. Zero-length data does not allocate
/// payload extents. A repeated immutable metadata view is a genuine chain
/// cycle (unlike PRP's length-dependent last-slot interpretation).
pub(super) fn segments<M: Mem>(
    memory: &M,
    first: u64,
    second: u64,
    total: u64,
) -> Result<Vec<(u64, u64)>, u16> {
    let mut descriptor = Descriptor::decode(first, second)?;
    let mut remaining = total;
    let mut plan = Vec::new();
    if descriptor.kind == 0 {
        data(descriptor, &mut remaining, &mut plan);
        return if remaining == 0 {
            Ok(plan)
        } else {
            Err(INVALID_LENGTH)
        };
    }
    let mut visited = BTreeSet::new();
    'segment: loop {
        descriptor.segment()?;
        if !visited.insert((descriptor.address, descriptor.length, descriptor.kind)) {
            return Err(INVALID_SEGMENT);
        }
        let last_segment = descriptor.kind == 3;
        let count = descriptor.length / 16;
        let mut cursor = descriptor.address;
        for index in 0..count {
            let mut raw = [0; 16];
            if !memory.read(cursor, &mut raw) {
                return Err(SC_DATA_XFER_ERROR);
            }
            let next = Descriptor::decode(
                u64::from_le_bytes(raw[..8].try_into().unwrap()),
                u64::from_le_bytes(raw[8..].try_into().unwrap()),
            )?;
            if next.kind == 0 {
                data(next, &mut remaining, &mut plan);
            } else {
                if last_segment {
                    return Err(INVALID_SEGMENT);
                }
                if index + 1 != count {
                    return Err(INVALID_COUNT);
                }
                descriptor = next;
                continue 'segment;
            }
            if index + 1 != count {
                cursor = cursor.checked_add(16).ok_or(INVALID_LENGTH)?;
            }
        }
        // A Segment descriptor denotes a non-final segment;the terminus is
        // represented by Last Segment. Its final metadata view cannot link on.
        if !last_segment {
            return Err(INVALID_SEGMENT);
        }
        return if remaining == 0 {
            Ok(plan)
        } else {
            Err(INVALID_LENGTH)
        };
    }
}

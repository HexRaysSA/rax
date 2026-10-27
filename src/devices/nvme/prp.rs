//! NVMe1.4c section4.3 PRP scatter/gather planning for the4KiB page profile.
use super::{Mem, PAGE_SIZE, SC_DATA_XFER_ERROR, SC_PRP_OFFSET_INVALID};

/// Resolve every PRP before payload DMA. The first data pointer is dword
/// aligned; the first list pointer may have a qword-aligned page offset.
/// All subsequent data and list pointers are page aligned.
///
/// For k data pages, time/storage are O(k). List traversal is bounded by the
/// requested data length:after at most one offset-list link, each further
/// link follows511 data entries. Repeated physical list pages remain legal
/// when they describe the finite requested transfer;no arbitrary cycle rule.
pub(super) fn segments<M: Mem>(
    mem: &M,
    prp1: u64,
    prp2: u64,
    total: u64,
) -> Result<Vec<(u64, u64)>, u16> {
    if total == 0 || total > 65536 * 512 {
        return Err(SC_DATA_XFER_ERROR);
    }
    if prp1 & 3 != 0 {
        return Err(SC_PRP_OFFSET_INVALID);
    }
    let first = total.min(PAGE_SIZE - prp1 % PAGE_SIZE);
    prp1.checked_add(first - 1).ok_or(SC_DATA_XFER_ERROR)?;
    let mut result = vec![(prp1, first)];
    let mut remaining = total - first;
    if remaining == 0 {
        return Ok(result);
    }
    if remaining <= PAGE_SIZE {
        if prp2 % PAGE_SIZE != 0 {
            return Err(SC_PRP_OFFSET_INVALID);
        }
        prp2.checked_add(remaining - 1).ok_or(SC_DATA_XFER_ERROR)?;
        result.push((prp2, remaining));
        return Ok(result);
    }
    if prp2 & 7 != 0 {
        return Err(SC_PRP_OFFSET_INVALID);
    }
    let mut cursor = prp2;
    loop {
        cursor.checked_add(7).ok_or(SC_DATA_XFER_ERROR)?;
        let mut bytes = [0u8; 8];
        if !mem.read(cursor, &mut bytes) {
            return Err(SC_DATA_XFER_ERROR);
        }
        let address = u64::from_le_bytes(bytes);
        if address % PAGE_SIZE != 0 {
            return Err(SC_PRP_OFFSET_INVALID);
        }
        if cursor % PAGE_SIZE == PAGE_SIZE - 8 && remaining > PAGE_SIZE {
            cursor = address;
            continue;
        }
        let length = remaining.min(PAGE_SIZE);
        address.checked_add(length - 1).ok_or(SC_DATA_XFER_ERROR)?;
        result.push((address, length));
        remaining -= length;
        if remaining == 0 {
            return Ok(result);
        }
        cursor = cursor.checked_add(8).ok_or(SC_DATA_XFER_ERROR)?;
    }
}

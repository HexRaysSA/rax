//! Stage range metadata before media mutation. Discard selects deterministic
//! zero-filled logical media; WRITE_ZEROES always has the mandatory zero result.
use super::{SECTOR_SIZE, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VirtioBlk};

impl VirtioBlk {
    pub(super) fn apply_ranges(&mut self, metadata: &[u8], zeroes: bool) -> u8 {
        // Unknown flags require UNSUPP, including DISCARD's UNMAP flag. Check
        // every flag before range arithmetic so an earlier bad extent cannot
        // conceal an unsupported flag later in the same request.
        let allowed = if zeroes { 1 } else { 0 };
        if metadata
            .chunks_exact(16)
            .any(|raw| u32::from_le_bytes(raw[12..16].try_into().unwrap()) & !allowed != 0)
        {
            return VIRTIO_BLK_S_UNSUPP;
        }
        let mut ranges = Vec::with_capacity(metadata.len() / 16);
        for raw in metadata.chunks_exact(16) {
            let sector = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let count = u32::from_le_bytes(raw[8..12].try_into().unwrap());
            let Some(start) = sector.checked_mul(SECTOR_SIZE) else {
                return VIRTIO_BLK_S_IOERR;
            };
            let length = u64::from(count) * SECTOR_SIZE;
            let Some(end) = start.checked_add(length) else {
                return VIRTIO_BLK_S_IOERR;
            };
            if end > self.disk.len() as u64 {
                return VIRTIO_BLK_S_IOERR;
            }
            if start != end {
                ranges.push((start as usize, end as usize));
            }
        }
        ranges.sort_unstable();
        let mut merged: Option<(usize, usize)> = None;
        for (start, end) in ranges {
            match merged {
                Some((first, last)) if start <= last => merged = Some((first, last.max(end))),
                Some((first, last)) => {
                    self.disk[first..last].fill(0);
                    merged = Some((start, end));
                }
                None => merged = Some((start, end)),
            }
        }
        if let Some((start, end)) = merged {
            self.disk[start..end].fill(0);
        }
        VIRTIO_BLK_S_OK
    }
}

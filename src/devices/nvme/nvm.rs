//! NVM command data paths for the single 512-byte-LBA, zero-metadata namespace.
use super::{
    LBA_SIZE, Mem, NVM_COMPARE, NVM_DATASET_MANAGEMENT, NVM_FLUSH, NVM_READ, NVM_WRITE,
    NVM_WRITE_ZEROES, NvmeController, SC_COMPARE_FAILURE, SC_DATA_XFER_ERROR, SC_INVALID_FIELD,
    SC_INVALID_NAMESPACE, SC_INVALID_OPCODE, SC_LBA_OUT_OF_RANGE, SC_NAMESPACE_WRITE_PROTECTED,
    SC_SUCCESS, SC_WRITE_FAULT, SubmissionEntry, prp, sgl,
};
use std::ops::Range;

impl<M: Mem> NvmeController<M> {
    pub(super) fn exec_nvm(&mut self, entry: &SubmissionEntry) -> (u16, u32) {
        // Fused operations are not advertised. Never execute either member
        // independently, including commands whose normal data path is valid.
        if entry.flags & 3 != 0 || entry.flags >> 6 == 3 {
            return (SC_INVALID_FIELD, 0);
        }
        if entry.nsid != 1 && !(entry.opcode == NVM_FLUSH && entry.nsid == u32::MAX) {
            return (SC_INVALID_NAMESPACE, 0);
        }
        if self.disk.is_read_only()
            && (matches!(entry.opcode, NVM_WRITE | NVM_WRITE_ZEROES)
                || entry.opcode == NVM_DATASET_MANAGEMENT && entry.cdw11 & 4 != 0)
        {
            return (SC_NAMESPACE_WRITE_PROTECTED, 0); // Namespace is Write Protected.
        }
        let result = match entry.opcode {
            NVM_FLUSH => self.disk.flush().map_err(|_| SC_WRITE_FAULT), // Persistent write-through backend.
            NVM_READ => self.read_blocks(entry),
            NVM_WRITE => self.write_blocks(entry),
            NVM_COMPARE => self.compare_blocks(entry),
            NVM_WRITE_ZEROES => self.zero_blocks(entry),
            NVM_DATASET_MANAGEMENT => self.dataset_management(entry),
            _ => Err(SC_INVALID_OPCODE),
        };
        (result.err().unwrap_or(SC_SUCCESS), 0)
    }

    fn data_segments(&self, entry: &SubmissionEntry, total: u64) -> Result<Vec<(u64, u64)>, u16> {
        match entry.flags >> 6 {
            0 => prp::segments(&self.mem, entry.prp1, entry.prp2, total),
            1 | 2 => sgl::segments(&self.mem, entry.prp1, entry.prp2, total),
            _ => Err(SC_INVALID_FIELD),
        }
    }

    fn byte_range(&self, lba: u64, blocks: u64) -> Option<Range<usize>> {
        let start = lba.checked_mul(LBA_SIZE)?;
        let end = start.checked_add(blocks.checked_mul(LBA_SIZE)?)?;
        (end <= self.disk.len() as u64).then_some(start as usize..end as usize)
    }

    fn command_range(&self, entry: &SubmissionEntry) -> Result<Range<usize>, u16> {
        let lba = u64::from(entry.cdw10) | (u64::from(entry.cdw11) << 32);
        let blocks = u64::from(entry.cdw12 & 0xffff) + 1;
        self.byte_range(lba, blocks).ok_or(SC_LBA_OUT_OF_RANGE)
    }

    /// Plan all metadata and stage every source byte before any media change.
    /// The encoded command bounds total to 32 MiB (RW/Compare) or 4 KiB (DSM).
    fn source_bytes(&self, entry: &SubmissionEntry, total: usize) -> Result<Vec<u8>, u16> {
        let segments = self.data_segments(entry, total as u64)?;
        let mut bytes = vec![0; total];
        let mut offset = 0;
        for (address, length) in segments {
            let end = offset + length as usize;
            if !self.mem.read(address, &mut bytes[offset..end]) {
                return Err(SC_DATA_XFER_ERROR);
            }
            offset = end;
        }
        Ok(bytes)
    }

    fn read_blocks(&mut self, entry: &SubmissionEntry) -> Result<(), u16> {
        let range = self.command_range(entry)?;
        let segments = self.data_segments(entry, range.len() as u64)?;
        let mut offset = range.start;
        for (address, length) in segments {
            let end = offset + length as usize;
            if !self.mem.write(address, &self.disk[offset..end]) {
                // Earlier completed destination writes remain visible.
                return Err(SC_DATA_XFER_ERROR);
            }
            offset = end;
        }
        Ok(())
    }

    fn write_blocks(&mut self, entry: &SubmissionEntry) -> Result<(), u16> {
        let range = self.command_range(entry)?;
        let bytes = self.source_bytes(entry, range.len())?;
        self.disk.write_bytes(range.start, &bytes).map_err(|_| {
            if self.disk.is_read_only() {
                SC_NAMESPACE_WRITE_PROTECTED
            } else {
                SC_WRITE_FAULT
            }
        })
    }

    fn compare_blocks(&self, entry: &SubmissionEntry) -> Result<(), u16> {
        // Compare requires PRACT=0. PRCHK is ignored for this no-PI namespace.
        if entry.cdw12 & (1 << 29) != 0 {
            return Err(0x181); // Command-specific Invalid Protection Information.
        }
        let range = self.command_range(entry)?;
        let bytes = self.source_bytes(entry, range.len())?;
        if self.disk[range] == bytes {
            Ok(())
        } else {
            Err(SC_COMPARE_FAILURE)
        }
    }

    fn zero_blocks(&mut self, entry: &SubmissionEntry) -> Result<(), u16> {
        // Write Zeroes requires PRCHK=0. No metadata/PI is stored here.
        if entry.cdw12 & (7 << 26) != 0 {
            return Err(0x181);
        }
        let range = self.command_range(entry)?;
        // Both DEAC modes return deterministic zero in this advertised profile.
        // DPTR is unused and must never cause DMA for a Write Zeroes command.
        self.disk.zero_bytes(range).map_err(|_| {
            if self.disk.is_read_only() {
                SC_NAMESPACE_WRITE_PROTECTED
            } else {
                SC_WRITE_FAULT
            }
        })
    }

    fn dataset_management(&mut self, entry: &SubmissionEntry) -> Result<(), u16> {
        if entry.cdw11 & 4 == 0 {
            // IDR/IDW are advisory. Ignoring them does not consult the unused
            // range buffer and must not modify namespace bytes.
            return Ok(());
        }
        let count = (entry.cdw10 & 0xff) as usize + 1;
        let bytes = self.source_bytes(entry, count * 16)?;
        let mut ranges = Vec::new();
        for descriptor in bytes.chunks_exact(16) {
            // DSM lengths are one-based, unlike RW/Compare/Write Zeroes NLB.
            let blocks = u32::from_le_bytes(descriptor[4..8].try_into().unwrap());
            let lba = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
            if blocks == 0 {
                continue;
            }
            // Deallocation is advisory. Skip invalid ranges without touching
            // their bytes; valid ranges retain deterministic zero semantics.
            if let Some(range) = self.byte_range(lba, u64::from(blocks)) {
                ranges.push(range);
            }
        }
        // Coalesce overlapping/adjacent advisory ranges before clearing. This
        // bounds repeated-range work by the union, rather than r copies of it.
        ranges.sort_unstable_by_key(|range| range.start);
        let mut cursor = 0;
        while cursor < ranges.len() {
            let start = ranges[cursor].start;
            let mut end = ranges[cursor].end;
            cursor += 1;
            while cursor < ranges.len() && ranges[cursor].start <= end {
                end = end.max(ranges[cursor].end);
                cursor += 1;
            }
            self.disk.zero_bytes(start..end).map_err(|_| {
                if self.disk.is_read_only() {
                    SC_NAMESPACE_WRITE_PROTECTED
                } else {
                    SC_WRITE_FAULT
                }
            })?;
        }
        Ok(())
    }
}

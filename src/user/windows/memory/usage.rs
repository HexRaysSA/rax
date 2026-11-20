//! Telemetry for the existing single-address-space, no-paging-file model.
use super::{AllocKind, VirtualMemory, VmError};
use crate::user::mm::PAGE_SIZE;

/// SYSTEM_MEMORY_USAGE_INFORMATION's seven explicit-width byte counters.
/// File-view reservations retain their existing conservative commitment charge;
/// shared commitment describes unique pagefile-section backing, not file data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryUsage {
    pub total_physical_bytes: u64,
    pub available_bytes: u64,
    pub resident_available_bytes: i64,
    pub committed_bytes: u64,
    pub shared_committed_bytes: u64,
    pub commit_limit_bytes: u64,
    pub peak_commitment_bytes: u64,
}

impl MemoryUsage {
    /// Pointer-width-independent, little-endian NT record; all sizes are bytes.
    pub fn to_bytes(self) -> [u8; 56] {
        let mut output = [0; 56];
        for (slot, bytes) in output.chunks_exact_mut(8).zip([
            self.total_physical_bytes.to_le_bytes(),
            self.available_bytes.to_le_bytes(),
            self.resident_available_bytes.to_le_bytes(),
            self.committed_bytes.to_le_bytes(),
            self.shared_committed_bytes.to_le_bytes(),
            self.commit_limit_bytes.to_le_bytes(),
            self.peak_commitment_bytes.to_le_bytes(),
        ]) {
            slot.copy_from_slice(&bytes);
        }
        output
    }
}

impl VirtualMemory {
    /// Publish only after mapping/metadata work has succeeded. Failed commits
    /// must leave both current commitment and its high-water mark unchanged.
    pub(super) fn publish_commitment(&mut self, bytes: u64) {
        debug_assert!(bytes <= self.commit_limit);
        self.committed = bytes;
        self.peak_committed = self.peak_committed.max(bytes);
        self.peak_private_committed = self
            .peak_private_committed
            .max(bytes - self.shared_committed_bytes());
    }

    /// The 64-bit guest's native process memory record. File-backed and private
    /// commitment follow this manager's backing-budget model. Guest kernel
    /// page pools are absent from that model.
    pub(crate) fn process_counters(&self, extended: bool) -> [u8; 112] {
        let mut data = [0; 112];
        for (slot, word) in data
            .chunks_exact_mut(8)
            .zip(self.process_counter_words(extended))
        {
            slot.copy_from_slice(&word.to_le_bytes());
        }
        data
    }

    /// The WoW64 ABI uses 32-bit counters through PrivateWorkingSetSize,
    /// followed by four padding bytes and a 64-bit SharedCommitUsage.
    pub(crate) fn wow64_process_counters(&self, extended: bool) -> [u8; 64] {
        let words = self.process_counter_words(extended);
        let mut data = [0; 64];
        for (slot, word) in data[..52].chunks_exact_mut(4).zip(words) {
            // Byte counters here fit the guest's bounded 32-bit address
            // space, and the page-fault count is already a u32.
            slot.copy_from_slice(&(word as u32).to_le_bytes());
        }
        data[56..].copy_from_slice(&words[13].to_le_bytes());
        data
    }

    fn process_counter_words(&self, extended: bool) -> [u64; 14] {
        let (resident, peak_resident, faults) = self.space.residency();
        let shared = self.shared_committed_bytes();
        let private = self.committed - shared;
        let private_resident = if extended {
            self.space.private_resident_pages(|address| {
                self.allocation(address)
                    .is_some_and(|region| region.kind == AllocKind::Private)
            }) * PAGE_SIZE
        } else {
            0
        };
        [
            self.peak_reserved,
            self.reserved,
            u64::from(faults),
            peak_resident * PAGE_SIZE,
            resident * PAGE_SIZE,
            0, // peak paged pool
            0, // paged pool
            0, // peak nonpaged pool
            0, // nonpaged pool
            private,
            self.peak_private_committed,
            private,
            private_resident,
            shared,
        ]
    }

    /// O(1) snapshot. Guest commitments are backed by the usable frame budget;
    /// without guest paging, available and resident-available capacity agree.
    /// No host RAM, swap, working-set or unrelated-process counter is sampled.
    pub fn memory_usage(&self) -> Result<MemoryUsage, VmError> {
        let available = self
            .commit_limit
            .checked_sub(self.committed)
            .ok_or(VmError::InvalidParameter)?;
        let resident_available_bytes =
            i64::try_from(available).map_err(|_| VmError::InvalidParameter)?;
        let shared = self.shared_committed_bytes();
        if shared > self.committed || self.peak_committed < self.committed {
            return Err(VmError::InvalidParameter);
        }
        Ok(MemoryUsage {
            total_physical_bytes: self.commit_limit,
            available_bytes: available,
            resident_available_bytes,
            committed_bytes: self.committed,
            shared_committed_bytes: shared,
            commit_limit_bytes: self.commit_limit,
            peak_commitment_bytes: self.peak_committed,
        })
    }
}

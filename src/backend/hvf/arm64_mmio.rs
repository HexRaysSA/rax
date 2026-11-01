//! Staged native AArch64 MMIO load completion and instruction retirement.

// Apple hv_vcpu_types.h assigns SDK register 31 to PC. Architectural Rt=31
// discards the load destination; it must still retire through the PC writer.
const PC_REGISTER: u32 = 31;

/// A data abort's complete scalar load request. A short reply leaves the
/// request pending; no register value is fabricated from absent bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingMmioRead {
    pub(crate) addr: u64,
    pub(crate) rt: u32,
    pub(crate) size: u8,
    pub(crate) sign_extend: bool,
    pub(crate) sixty_four: bool,
    /// Absolute post-load PC; None represents a legacy already-retired read.
    pub(crate) retire_pc: Option<u64>,
}

impl PendingMmioRead {
    /// Publish a complete load, then its absolute PC through the SDK writer.
    /// An incomplete reply performs no write. On either setter failure the
    /// caller retains this request and the obtained input; writing the same
    /// absolute PC on retry is safe even if a failed setter already mutated it.
    pub(crate) fn complete<E>(
        self,
        data: &[u8],
        mut write: impl FnMut(u32, u64) -> Result<(), E>,
    ) -> Result<bool, E> {
        let Some(value) = self.value(data) else {
            return Ok(false);
        };
        if self.rt < 31 {
            write(self.rt, value)?;
        }
        if let Some(pc) = self.retire_pc {
            write(PC_REGISTER, pc)?;
        }
        Ok(true)
    }

    pub(crate) fn value(self, data: &[u8]) -> Option<u64> {
        if !matches!(self.size, 1 | 2 | 4 | 8) {
            return None;
        }
        let bytes = data.get(..usize::from(self.size))?;
        let mut raw = [0u8; 8];
        raw[..bytes.len()].copy_from_slice(bytes);
        let mut value = u64::from_le_bytes(raw);
        if self.sign_extend && self.size < 8 {
            let shift = 64 - u32::from(self.size) * 8;
            value = (((value << shift) as i64) >> shift) as u64;
        }
        if !self.sixty_four {
            value &= u64::from(u32::MAX);
        }
        Some(value)
    }
}

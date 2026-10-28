//! Staged native AArch64 MMIO load completion.

/// A data abort's complete scalar load request. A short reply leaves the
/// request pending; no register value is fabricated from absent bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingMmioRead {
    pub(crate) addr: u64,
    pub(crate) rt: u32,
    pub(crate) size: u8,
    pub(crate) sign_extend: bool,
    pub(crate) sixty_four: bool,
}

impl PendingMmioRead {
    /// Publish a complete load through the backend writer. An incomplete reply
    /// does not invoke the writer; a failed write does not accept the reply.
    pub(crate) fn complete<E>(
        self,
        data: &[u8],
        write: impl FnOnce(u32, u64) -> Result<(), E>,
    ) -> Result<bool, E> {
        let Some(value) = self.value(data) else {
            return Ok(false);
        };
        if self.rt < 31 {
            write(self.rt, value)?;
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

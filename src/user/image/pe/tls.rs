//! The TLS directory (`.tls`): the template, index slot, and callbacks of
//! static thread-local storage. Its address fields are virtual addresses
//! (relocated with the image), not RVAs.

use super::{DataDirectory, PeKind, RvaFault, RvaSource};

/// Upper bound on callbacks read from a callback array.
pub const MAX_TLS_CALLBACKS: usize = 4096;

/// `IMAGE_TLS_DIRECTORY32`/`IMAGE_TLS_DIRECTORY64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsDirectory {
    /// `StartAddressOfRawData`: VA of the template.
    pub raw_data_start: u64,
    /// `EndAddressOfRawData`: VA one past the initialized template bytes.
    pub raw_data_end: u64,
    /// `AddressOfIndex`: VA of the `ULONG` receiving the TLS index.
    pub address_of_index: u64,
    /// `AddressOfCallBacks`: VA of the NULL-terminated callback array.
    pub address_of_callbacks: u64,
    /// `SizeOfZeroFill`.
    pub size_of_zero_fill: u32,
    /// `Characteristics` (bits 23:20 give the alignment).
    pub characteristics: u32,
}

impl TlsDirectory {
    /// Reads the directory of data directory `range` of a `kind` image.
    pub fn read(
        src: &(impl RvaSource + ?Sized),
        kind: PeKind,
        range: DataDirectory,
    ) -> Result<Option<Self>, RvaFault> {
        if !range.is_present() {
            return Ok(None);
        }
        let w = kind.pointer_size() as u64;
        let at = range.extent_at(0, 4 * w + 8)?;
        let directory = TlsDirectory {
            raw_data_start: src.word_at(kind, at)?,
            raw_data_end: src.word_at(kind, at + w)?,
            address_of_index: src.word_at(kind, at + 2 * w)?,
            address_of_callbacks: src.word_at(kind, at + 3 * w)?,
            size_of_zero_fill: src.u32_at(at + 4 * w)?,
            characteristics: src.u32_at(at + 4 * w + 4)?,
        };
        if directory.raw_data_end < directory.raw_data_start
            || directory
                .raw_size()
                .checked_add(u64::from(directory.size_of_zero_fill))
                .is_none()
        {
            return Err(RvaFault { rva: at });
        }
        Ok(Some(directory))
    }

    /// Size of the initialized part of the template (`End - Start`, zero
    /// when `End` precedes `Start`).
    pub fn raw_size(&self) -> u64 {
        self.raw_data_end.saturating_sub(self.raw_data_start)
    }

    /// Total per-thread block size: the initialized part plus the zero fill,
    /// saturated to `u64::MAX` for manually constructed invalid directories.
    /// [`Self::read`] rejects directories whose sum overflows.
    pub fn block_size(&self) -> u64 {
        self.raw_size()
            .saturating_add(u64::from(self.size_of_zero_fill))
    }

    /// Alignment from `Characteristics` bits 23:20 (`IMAGE_SCN_ALIGN_*`:
    /// value n selects 2^(n-1) bytes), or `None` when unspecified.
    pub fn alignment(&self) -> Option<u64> {
        match (self.characteristics >> 20) & 0xF {
            0 => None,
            n => Some(1u64 << (n - 1)),
        }
    }
}

/// Reads the NULL-terminated callback array at `rva` (the callbacks array
/// VA minus the image base) of a `kind` image.
pub fn callbacks(
    src: &(impl RvaSource + ?Sized),
    kind: PeKind,
    rva: u64,
) -> Result<Vec<u64>, RvaFault> {
    let w = kind.pointer_size() as u64;
    let mut out = Vec::new();
    for i in 0..=MAX_TLS_CALLBACKS as u64 {
        let at = rva.checked_add(i * w).ok_or(RvaFault { rva })?;
        let cb = src.word_at(kind, at)?;
        if cb == 0 {
            return Ok(out);
        }
        if i == MAX_TLS_CALLBACKS as u64 {
            return Err(RvaFault { rva: at });
        }
        out.push(cb);
    }
    Err(RvaFault { rva })
}

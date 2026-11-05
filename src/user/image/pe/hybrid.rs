//! ARM64EC/ARM64X CHPE metadata over an explicitly selected image view.
//!
//! Layout and range tags follow LLVM's `chpe_metadata`, `chpe_range_entry`,
//! `chpe_code_range_entry` and `chpe_redirection_entry`; the exact primary
//! source is retained under `docs/specifications/windows/native-arm64x-view/`.
//! The x86 CHPE structure is different and is not decoded by this module.

use super::{RvaFault, RvaSource};
use std::fmt;

/// An instruction set and ABI advertised by one half-open code range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeKind {
    /// Native ARM64 ABI.
    Arm64,
    /// ARM64 instructions using the emulation-compatible ABI.
    Arm64Ec,
    /// AMD64 instructions and ABI.
    Amd64,
}

/// A half-open RVA range `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeRange {
    pub start: u32,
    pub end: u32,
    pub kind: CodeKind,
}

/// A half-open code range and its entry thunk RVA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryRange {
    pub start: u32,
    pub end: u32,
    pub entry: u32,
}

/// An exact source-RVA to destination-RVA redirection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirection {
    pub source: u32,
    pub destination: u32,
}

/// Structural rejection or inaccessible selected image bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HybridError {
    Read(RvaFault),
    Invalid(&'static str),
}

impl From<RvaFault> for HybridError {
    fn from(fault: RvaFault) -> Self {
        Self::Read(fault)
    }
}

impl fmt::Display for HybridError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(fault) => write!(f, "hybrid metadata read at RVA {:#x}", fault.rva),
            Self::Invalid(message) => write!(f, "invalid hybrid metadata: {message}"),
        }
    }
}

impl std::error::Error for HybridError {}

/// Decoded immutable ARM64EC metadata. Parsing does not select an execution
/// architecture, patch emulator-helper pointers or apply dynamic relocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridMetadata {
    pub version: u32,
    pub code: Vec<CodeRange>,
    pub entries: Vec<EntryRange>,
    pub redirections: Vec<Redirection>,
    /// RVAs of call, return, direct/indirect/CFG check, get/set context and jump helper slots.
    pub dispatch_slots: [u32; 8],
    pub alternate_entry: u32,
}

// An implementation bound, not a Windows format limit. Every table must also
// fit the selected image before any allocation or per-record read occurs.
const MAX_RECORDS: u64 = 65_536;

fn extent(rva: u64, bytes: u64, image_size: u64) -> Result<(), HybridError> {
    if rva.checked_add(bytes).is_none_or(|end| end > image_size) {
        return Err(HybridError::Invalid("extent outside the selected image"));
    }
    Ok(())
}

fn table(
    src: &(impl RvaSource + ?Sized),
    at: u64,
    count_at: u64,
    stride: u64,
    size: u64,
) -> Result<(u64, usize), HybridError> {
    let rva = u64::from(src.u32_at(at)?);
    let count = u64::from(src.u32_at(count_at)?);
    if count > MAX_RECORDS || count != 0 && rva == 0 {
        return Err(HybridError::Invalid("table count or null address"));
    }
    extent(rva, count * stride, size)?;
    Ok((rva, count as usize))
}

impl HybridMetadata {
    /// Reads v1/v2 metadata at `metadata_va` using this view's image base.
    /// All address calculations are checked. O(C + E + R) time and storage
    /// for code, entry and redirection records; classification is O(log C).
    pub fn read(
        src: &(impl RvaSource + ?Sized),
        metadata_va: u64,
        image_base: u64,
        image_size: u32,
    ) -> Result<Self, HybridError> {
        let at = metadata_va
            .checked_sub(image_base)
            .ok_or(HybridError::Invalid("metadata VA precedes the image base"))?;
        let size = u64::from(image_size);
        extent(at, 4, size)?;
        let version = src.u32_at(at)?;
        let header_size = match version {
            1 => 80,
            2 => 92,
            _ => return Err(HybridError::Invalid("unsupported metadata version")),
        };
        extent(at, header_size, size)?;
        // Force a read of the complete versioned header, including reserved
        // fields: a sparse RvaSource must not manufacture missing header bytes.
        let mut header = [0; 92];
        src.read_rva(at, &mut header[..header_size as usize])?;
        let (code_at, code_count) = table(src, at + 4, at + 8, 8, size)?;
        let (entry_at, entry_count) = table(src, at + 12, at + 48, 12, size)?;
        let (redirect_at, redirect_count) = table(src, at + 16, at + 52, 8, size)?;
        let mut result = Self {
            version,
            code: Vec::with_capacity(code_count),
            entries: Vec::with_capacity(entry_count),
            redirections: Vec::with_capacity(redirect_count),
            dispatch_slots: [0; 8],
            alternate_entry: src.u32_at(at + 40)?,
        };
        if result.alternate_entry != 0 {
            extent(u64::from(result.alternate_entry), 1, size)?;
        }
        for (slot, offset) in result
            .dispatch_slots
            .iter_mut()
            .zip([20, 24, 28, 32, 36, 56, 60, 72])
        {
            *slot = src.u32_at(at + offset)?;
            if *slot != 0 {
                extent(u64::from(*slot), 8, size)?;
            }
        }
        for index in 0..code_count {
            let row = code_at + index as u64 * 8;
            let encoded = src.u32_at(row)?;
            let start = encoded & !3;
            let length = src.u32_at(row + 4)?;
            let kind = match encoded & 3 {
                0 => CodeKind::Arm64,
                1 => CodeKind::Arm64Ec,
                2 => CodeKind::Amd64,
                _ => return Err(HybridError::Invalid("reserved code-range type")),
            };
            extent(u64::from(start), u64::from(length), size)?;
            let end = start
                .checked_add(length)
                .ok_or(HybridError::Invalid("code range overflow"))?;
            if length == 0 || result.code.last().is_some_and(|prior| prior.end > start) {
                return Err(HybridError::Invalid(
                    "empty, overlapping or unordered code ranges",
                ));
            }
            result.code.push(CodeRange { start, end, kind });
        }
        for index in 0..entry_count {
            let row = entry_at + index as u64 * 12;
            let start = src.u32_at(row)?;
            let end = src.u32_at(row + 4)?;
            let entry = src.u32_at(row + 8)?;
            if start >= end
                || end > image_size
                || entry >= image_size
                || result.entries.last().is_some_and(|prior| prior.end > start)
            {
                return Err(HybridError::Invalid("entry range order or extent"));
            }
            result.entries.push(EntryRange { start, end, entry });
        }
        for index in 0..redirect_count {
            let row = redirect_at + index as u64 * 8;
            let source = src.u32_at(row)?;
            let destination = src.u32_at(row + 4)?;
            if source >= image_size
                || destination >= image_size
                || result
                    .redirections
                    .last()
                    .is_some_and(|prior| prior.source >= source)
            {
                return Err(HybridError::Invalid("redirection order or extent"));
            }
            result.redirections.push(Redirection {
                source,
                destination,
            });
        }
        Ok(result)
    }

    /// Classifies an RVA; gaps and the exclusive end of a range return `None`.
    pub fn code_kind(&self, rva: u32) -> Option<CodeKind> {
        let index = self.code.partition_point(|range| range.start <= rva);
        let range = self.code.get(index.checked_sub(1)?)?;
        (rva < range.end).then_some(range.kind)
    }
}

//! The exception table (`.pdata`): function table entries sorted by start
//! address. x64 entries are `RUNTIME_FUNCTION` (begin, end, unwind-info
//! RVAs; 12 bytes); ARM64 entries are 8 bytes (begin RVA, then an `.xdata`
//! RVA or packed unwind data). Decoding the unwind data itself belongs to
//! the unwinder of the personality that uses it.

use super::{DataDirectory, RvaFault, RvaSource};

/// Size of an x64 `RUNTIME_FUNCTION`.
pub const X64_ENTRY_SIZE: u32 = 12;
/// Size of an ARM64 `.pdata` record.
pub const ARM64_ENTRY_SIZE: u32 = 8;

/// An x64 `RUNTIME_FUNCTION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64RuntimeFunction {
    /// `BeginAddress`.
    pub begin: u32,
    /// `EndAddress` (exclusive).
    pub end: u32,
    /// `UnwindData`: RVA of the `UNWIND_INFO`.
    pub unwind_info: u32,
}

/// An ARM64 `.pdata` record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64RuntimeFunction {
    /// Function start RVA.
    pub begin: u32,
    /// The second word: `.xdata` RVA when `Flag` (bits 1:0) is 0, packed
    /// unwind data otherwise.
    pub unwind: u32,
}

impl Arm64RuntimeFunction {
    /// `Flag`: 0 = `.xdata` record, 1 = packed with a single prolog and
    /// epilog, 2 = packed without prolog or epilog, 3 = reserved.
    pub fn flag(&self) -> u32 {
        self.unwind & 3
    }

    /// The function length in bytes for packed records (`Function Length`,
    /// bits 12:2, times 4); `None` for an `.xdata` record, whose length is in
    /// its header.
    pub fn packed_length(&self) -> Option<u32> {
        matches!(self.flag(), 1 | 2).then(|| ((self.unwind >> 2) & 0x7FF) * 4)
    }
}

/// Binary-searches an x64 function table for the entry containing `rva`.
pub fn lookup_x64(
    src: &(impl RvaSource + ?Sized),
    table: DataDirectory,
    rva: u32,
) -> Result<Option<(u32, X64RuntimeFunction)>, RvaFault> {
    if !table.is_present() {
        return Ok(None);
    }
    if table.size % X64_ENTRY_SIZE != 0 {
        return Err(RvaFault {
            rva: u64::from(table.rva) + u64::from(table.size),
        });
    }
    table.extent_at(0, u64::from(table.size))?;
    let count = table.size / X64_ENTRY_SIZE;
    let base = u64::from(table.rva);
    let (mut lo, mut hi) = (0u32, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let at = base + u64::from(mid) * u64::from(X64_ENTRY_SIZE);
        let f = X64RuntimeFunction {
            begin: src.u32_at(at)?,
            end: src.u32_at(at + 4)?,
            unwind_info: src.u32_at(at + 8)?,
        };
        if rva < f.begin {
            hi = mid;
        } else if rva >= f.end {
            lo = mid + 1;
        } else {
            return Ok(Some((at as u32, f)));
        }
    }
    Ok(None)
}

/// Reads the `.xdata` header's function length (bits 17:0, times 4).
pub fn arm64_xdata_length(src: &(impl RvaSource + ?Sized), xdata: u32) -> Result<u32, RvaFault> {
    Ok((src.u32_at(u64::from(xdata))? & 0x3FFFF) * 4)
}

/// Binary-searches an ARM64 function table for the entry containing `rva`:
/// the last entry starting at or before `rva`, if `rva` lies within its
/// length.
pub fn lookup_arm64(
    src: &(impl RvaSource + ?Sized),
    table: DataDirectory,
    rva: u32,
) -> Result<Option<(u32, Arm64RuntimeFunction)>, RvaFault> {
    if !table.is_present() {
        return Ok(None);
    }
    if table.size % ARM64_ENTRY_SIZE != 0 {
        return Err(RvaFault {
            rva: u64::from(table.rva) + u64::from(table.size),
        });
    }
    table.extent_at(0, u64::from(table.size))?;
    let count = table.size / ARM64_ENTRY_SIZE;
    let base = u64::from(table.rva);
    let entry = |i: u32| -> Result<Arm64RuntimeFunction, RvaFault> {
        let at = base + u64::from(i) * u64::from(ARM64_ENTRY_SIZE);
        Ok(Arm64RuntimeFunction {
            begin: src.u32_at(at)?,
            unwind: src.u32_at(at + 4)?,
        })
    };
    // First entry whose begin exceeds rva.
    let (mut lo, mut hi) = (0u32, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entry(mid)?.begin <= rva {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return Ok(None);
    }
    let i = lo - 1;
    let f = entry(i)?;
    let len = match f.packed_length() {
        Some(len) => len,
        None if f.flag() == 0 => arm64_xdata_length(src, f.unwind)?,
        None => {
            return Err(RvaFault {
                rva: base + u64::from(i) * u64::from(ARM64_ENTRY_SIZE) + 4,
            });
        }
    };
    let inside = u64::from(rva) < u64::from(f.begin) + u64::from(len);
    let at = base + u64::from(i) * u64::from(ARM64_ENTRY_SIZE);
    Ok(inside.then_some((at as u32, f)))
}

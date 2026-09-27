//! Base relocations (`.reloc`): "To apply a base relocation, the difference
//! is calculated between the preferred base address and the base where the
//! image is actually loaded."
//!
//! [`apply`] patches a memory image (see
//! [`PeImage::memory_image`](super::PeImage::memory_image)) for a load at a
//! different base. The types a loader for this machine set applies are
//! `ABSOLUTE` (padding), `HIGH`, `LOW`, `HIGHLOW`, `HIGHADJ`, and `DIR64`;
//! the machine-specific types (`ARM_MOV32`, `THUMB_MOV32`, and the MIPS,
//! RISC-V, and LoongArch forms sharing their values) do not occur in x86,
//! x64, or ARM64 images and are rejected.

use std::fmt;

use super::{DataDirectory, reloc};

/// Why relocation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelocError {
    /// A block header or entry lies outside the image, or a block's size is
    /// smaller than its header or not a whole number of entries.
    BadBlock { rva: u32 },
    /// A fixup's target lies outside the image.
    TargetOutOfImage { rva: u64 },
    /// A type the loader does not apply for this machine.
    UnsupportedType { kind: u8, rva: u64 },
}

impl fmt::Display for RelocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelocError::BadBlock { rva } => write!(f, "malformed relocation block at {rva:#x}"),
            RelocError::TargetOutOfImage { rva } => {
                write!(f, "relocation target {rva:#x} lies outside the image")
            }
            RelocError::UnsupportedType { kind, rva } => {
                write!(f, "unsupported relocation type {kind} at {rva:#x}")
            }
        }
    }
}

impl std::error::Error for RelocError {}

/// One decoded fixup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixup {
    /// `IMAGE_REL_BASED_*`.
    pub kind: u8,
    /// RVA of the patched field.
    pub rva: u64,
    /// For `HIGHADJ`, the low 16 bits the next entry carries.
    pub adjust: Option<u16>,
}

fn read_u32(image: &[u8], at: u64) -> Option<u32> {
    let at = usize::try_from(at).ok()?;
    image
        .get(at..at.checked_add(4)?)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Decodes every fixup of directory `range` in `image`.
pub fn fixups(image: &[u8], range: DataDirectory) -> Result<Vec<Fixup>, RelocError> {
    let mut out = Vec::new();
    if !range.is_present() {
        return Ok(out);
    }
    let end = u64::from(range.rva) + u64::from(range.size);
    let mut block = u64::from(range.rva);
    while block < end {
        let bad = RelocError::BadBlock { rva: block as u32 };
        if block + 8 > end || block % 4 != 0 {
            return Err(bad);
        }
        let page = read_u32(image, block).ok_or_else(|| bad.clone())?;
        let size = read_u32(image, block + 4).ok_or_else(|| bad.clone())?;
        if size < 8 || size % 2 != 0 || block + u64::from(size) > end {
            return Err(bad);
        }
        let count = (u64::from(size) - 8) / 2;
        let mut i = 0;
        while i < count {
            let at = usize::try_from(block + 8 + 2 * i).map_err(|_| bad.clone())?;
            let entry = image
                .get(at..at + 2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .ok_or_else(|| bad.clone())?;
            let kind = (entry >> 12) as u8;
            let rva = u64::from(page) + u64::from(entry & 0xFFF);
            let mut adjust = None;
            if kind == reloc::HIGHADJ {
                // "The low 16 bits of the 32-bit value are stored in the
                // 16-bit word that follows this base relocation."
                i += 1;
                if i >= count {
                    return Err(bad);
                }
                let at = at + 2;
                adjust = Some(
                    image
                        .get(at..at + 2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .ok_or_else(|| bad.clone())?,
                );
            }
            if kind != reloc::ABSOLUTE {
                out.push(Fixup { kind, rva, adjust });
            }
            i += 1;
        }
        block += u64::from(size);
    }
    Ok(out)
}

/// Applies every fixup of directory `range` to `image` for a load `delta`
/// bytes (modulo 2^64) away from the preferred base. Every type and target
/// is validated before the first write, so failure leaves `image` unchanged.
/// Time and auxiliary space are O(n) for n fixups.
pub fn apply(image: &mut [u8], range: DataDirectory, delta: u64) -> Result<(), RelocError> {
    let fixups = fixups(image, range)?;
    if delta == 0 {
        return Ok(());
    }
    for f in &fixups {
        let width = match f.kind {
            reloc::HIGH | reloc::LOW | reloc::HIGHADJ => 2,
            reloc::HIGHLOW => 4,
            reloc::DIR64 => 8,
            kind => return Err(RelocError::UnsupportedType { kind, rva: f.rva }),
        };
        usize::try_from(f.rva)
            .ok()
            .filter(|&a| a.checked_add(width).is_some_and(|e| e <= image.len()))
            .ok_or(RelocError::TargetOutOfImage { rva: f.rva })?;
    }
    for f in fixups {
        let width = match f.kind {
            reloc::HIGH | reloc::LOW | reloc::HIGHADJ => 2,
            reloc::HIGHLOW => 4,
            _ => 8,
        };
        // All types and ranges were validated above, before any writes.
        let at = f.rva as usize;
        let field = &mut image[at..at + width];
        match f.kind {
            reloc::HIGH => {
                let v = u16::from_le_bytes([field[0], field[1]]);
                let v = v.wrapping_add((delta >> 16) as u16);
                field.copy_from_slice(&v.to_le_bytes());
            }
            reloc::LOW => {
                let v = u16::from_le_bytes([field[0], field[1]]);
                let v = v.wrapping_add(delta as u16);
                field.copy_from_slice(&v.to_le_bytes());
            }
            reloc::HIGHADJ => {
                // Reconstruct with the signed adjustment, add the delta,
                // and round the high half with 0x8000. Arithmetic is
                // modulo 2^32, including a negative relocation delta.
                let high = u32::from(u16::from_le_bytes([field[0], field[1]]));
                let low = i32::from(f.adjust.unwrap_or(0) as i16) as u32;
                let value = (high << 16)
                    .wrapping_add(low)
                    .wrapping_add(delta as u32)
                    .wrapping_add(0x8000);
                field.copy_from_slice(&((value >> 16) as u16).to_le_bytes());
            }
            reloc::HIGHLOW => {
                let v = u32::from_le_bytes(field.try_into().unwrap());
                field.copy_from_slice(&v.wrapping_add(delta as u32).to_le_bytes());
            }
            _ => {
                let v = u64::from_le_bytes(field.try_into().unwrap());
                field.copy_from_slice(&v.wrapping_add(delta).to_le_bytes());
            }
        }
    }
    Ok(())
}

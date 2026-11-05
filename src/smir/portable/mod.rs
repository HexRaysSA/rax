//! Experimental portable SMIR envelope, revision 0.1.
//!
//! This decoder validates framing only. Section payloads are opaque and MUST
//! undergo semantic verification before linking or execution. No interpreter
//! admission API accepts this type. See `docs/specifications/smir/portable/`.

use std::fmt;

pub const MAGIC: &[u8; 8] = b"SMIR\r\n\x1a\n";
pub const HEADER_SIZE: usize = 48;
pub const DIRECTORY_ENTRY_SIZE: usize = 24;
pub const NO_ENTRY: u32 = u32::MAX;

/// Loader resource limits, independent of the on-disk representation.
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    pub max_bytes: usize,
    pub max_sections: u32,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1 << 30,
            max_sections: 1024,
        }
    }
}

/// Stable draft diagnostic identifiers. These describe framing, not semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Magic,
    Version,
    Header,
    Limit,
    Directory,
    Section,
    RequiredSection,
    Padding,
}

impl DecodeError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncated => "SMIR-E001",
            Self::Magic => "SMIR-E002",
            Self::Version => "SMIR-E003",
            Self::Header => "SMIR-E004",
            Self::Limit => "SMIR-E005",
            Self::Directory => "SMIR-E006",
            Self::Section => "SMIR-E007",
            Self::RequiredSection => "SMIR-E008",
            Self::Padding => "SMIR-E009",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DecodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    Object,
    Image,
}

/// Borrowed section; unknown optional metadata is retained for round trips.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'a> {
    pub kind: u16,
    pub required: bool,
    pub bytes: &'a [u8],
}

/// Structurally decoded bytes. This is deliberately not a verified module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedEnvelope<'a> {
    pub kind: ModuleKind,
    pub entry_function: Option<u32>,
    pub sections: Vec<Section<'a>>,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn aligned(value: usize) -> Option<usize> {
    value.checked_add(7).map(|n| n & !7)
}

/// Decode the canonical draft envelope in O(bytes + sections) time and
/// O(sections) auxiliary space. Payloads are borrowed, never copied.
pub fn decode(bytes: &[u8], limits: DecodeLimits) -> Result<DecodedEnvelope<'_>, DecodeError> {
    if bytes.len() > limits.max_bytes {
        return Err(DecodeError::Limit);
    }
    if bytes.len() < HEADER_SIZE {
        return Err(DecodeError::Truncated);
    }
    if &bytes[..8] != MAGIC {
        return Err(DecodeError::Magic);
    }
    if u16_at(bytes, 8) != 0 || u16_at(bytes, 10) != 1 {
        return Err(DecodeError::Version);
    }
    let kind = match u16_at(bytes, 12) {
        1 => ModuleKind::Object,
        2 => ModuleKind::Image,
        _ => return Err(DecodeError::Header),
    };
    let entry = u32_at(bytes, 40);
    if u16_at(bytes, 14) != 0
        || u32_at(bytes, 16) != 1
        || u64_at(bytes, 24) != bytes.len() as u64
        || u64_at(bytes, 32) != HEADER_SIZE as u64
        || u32_at(bytes, 44) != 0
        || (kind == ModuleKind::Object && entry != NO_ENTRY)
    {
        return Err(DecodeError::Header);
    }
    let count = u32_at(bytes, 20);
    if count > limits.max_sections {
        return Err(DecodeError::Limit);
    }
    let count = usize::try_from(count).map_err(|_| DecodeError::Limit)?;
    let directory_end = count
        .checked_mul(DIRECTORY_ENTRY_SIZE)
        .and_then(|n| HEADER_SIZE.checked_add(n))
        .ok_or(DecodeError::Directory)?;
    if directory_end > bytes.len() {
        return Err(DecodeError::Directory);
    }
    let mut sections = Vec::new();
    let mut previous_kind = 0;
    let mut cursor = directory_end;
    // The whole header and directory are bounded before fixed-offset reads.
    for index in 0..count {
        let record = HEADER_SIZE + index * DIRECTORY_ENTRY_SIZE;
        let section_kind = u16_at(bytes, record);
        let flags = u16_at(bytes, record + 2);
        if section_kind <= previous_kind || flags > 1 || u32_at(bytes, record + 4) != 0 {
            return Err(DecodeError::Directory);
        }
        let known = matches!(section_kind, 1..=9 | 0x8000..=0x8002);
        if (!known && (section_kind < 0x8000 || flags != 0))
            || (section_kind < 0x8000 && flags != 1)
            || (section_kind >= 0x8000 && flags != 0)
        {
            return Err(DecodeError::RequiredSection);
        }
        let offset =
            usize::try_from(u64_at(bytes, record + 8)).map_err(|_| DecodeError::Section)?;
        let size = usize::try_from(u64_at(bytes, record + 16)).map_err(|_| DecodeError::Section)?;
        let start = aligned(cursor).ok_or(DecodeError::Section)?;
        let end = offset.checked_add(size).ok_or(DecodeError::Section)?;
        if offset != start || end > bytes.len() {
            return Err(DecodeError::Section);
        }
        if bytes[cursor..start].iter().any(|b| *b != 0) {
            return Err(DecodeError::Padding);
        }
        sections.push(Section {
            kind: section_kind,
            required: flags == 1,
            bytes: &bytes[offset..end],
        });
        previous_kind = section_kind;
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(DecodeError::Padding);
    }
    Ok(DecodedEnvelope {
        kind,
        entry_function: (entry != NO_ENTRY).then_some(entry),
        sections,
    })
}

#[cfg(test)]
mod tests;

//! Ordered opaque contexts owned and validated by the producing CPU backend.

use crate::error::{Error, Result};
use std::io::Read;

const TAG: &[u8; 8] = b"RAXBCK01";
const MAX_RECORD: u64 = 16 * 1024 * 1024;
pub(super) const MAX_SECTION: u64 = 1024 * 1024 * 1024;

/// Standalone AArch32 interpreter, versioned by its inner context tag.
pub const AARCH32_CONTEXT: u32 = 1;
/// ARM1176 interpreter and its S3C64xx platform, versioned by its inner tag.
pub const S3C64XX_CONTEXT: u32 = 2;
/// RISC-V interpreter and ordered adapter events, versioned by its inner tag.
pub const RISCV_CONTEXT: u32 = 3;
/// Software x86 CPU/MMU/user context, versioned by its inner tag.
pub const X86_64_CONTEXT: u32 = 4;
/// Software AArch64 core, memory observations and pending adapter execution.
pub const AARCH64_CONTEXT: u32 = 5;
/// Native ARM64 HVF CPU and shared VM producer, with distinct inner tags.
pub const HVF_AARCH64_CONTEXT: u32 = 6;
/// Native Intel HVF CPU and shared VM producer, with distinct inner tags.
pub const HVF_INTEL_CONTEXT: u32 = 7;
/// Software Cortex-M core, internal controllers and adapter execution state.
pub const CORTEX_M_CONTEXT: u32 = 8;
/// Hexagon software packet engine and its represented in-flight transaction.
pub const HEXAGON_CONTEXT: u32 = 9;
/// GSC RV32 hart and its represented platform/runtime state, with resource bindings.
pub const GSC_CONTEXT: u32 = 10;

/// An opaque, bounded backend-owned record. Its kind identifies its producer;
/// an architectural register projection cannot substitute for this payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendContext {
    pub kind: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BackendContexts {
    entries: Vec<Option<BackendContext>>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("backend checkpoint contexts: {message}"))
}
fn record_limit(kind: u32) -> u64 {
    if kind == HVF_INTEL_CONTEXT {
        crate::backend::intel_hvf_context::MAX_CPU_CONTEXT
    } else if kind == HVF_AARCH64_CONTEXT {
        crate::backend::arm64_hvf_context::MAX_CPU_CONTEXT
    } else {
        MAX_RECORD
    }
}

impl BackendContexts {
    pub fn entries(&self) -> &[Option<BackendContext>] {
        &self.entries
    }

    pub(super) fn capture(entries: Vec<Option<BackendContext>>, count: u8) -> Result<Self> {
        let contexts = Self { entries };
        contexts.validate(count)?;
        Ok(contexts)
    }

    pub(super) fn validate(&self, count: u8) -> Result<()> {
        if count == 0 || self.entries.len() != usize::from(count) {
            return Err(invalid("record count differs from configured CPU count"));
        }
        let mut total = 12 + 12 * self.entries.len() as u64;
        let mut present = false;
        for context in self.entries.iter().flatten() {
            if context.kind == 0
                || context.data.is_empty()
                || context.data.len() as u64 > record_limit(context.kind)
            {
                return Err(invalid("invalid context kind or record length"));
            }
            total = total
                .checked_add(context.data.len() as u64)
                .ok_or_else(|| invalid("context length overflow"))?;
            if total > MAX_SECTION {
                return Err(invalid("section exceeds length limit"));
            }
            present = true;
        }
        if !present {
            return Err(invalid("empty extension has no backend contexts"));
        }
        Ok(())
    }

    pub(super) fn encoded(&self, count: u8) -> Result<Vec<u8>> {
        self.validate(count)?;
        let length = 12
            + 12 * self.entries.len()
            + self
                .entries
                .iter()
                .flatten()
                .map(|c| c.data.len())
                .sum::<usize>();
        let mut raw = Vec::new();
        raw.try_reserve_exact(length).map_err(invalid)?;
        raw.extend_from_slice(TAG);
        raw.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for context in &self.entries {
            raw.extend_from_slice(&context.as_ref().map_or(0, |c| c.kind).to_le_bytes());
            raw.extend_from_slice(
                &context
                    .as_ref()
                    .map_or(0, |c| c.data.len() as u64)
                    .to_le_bytes(),
            );
        }
        for context in self.entries.iter().flatten() {
            raw.extend_from_slice(&context.data);
        }
        Ok(raw)
    }

    /// The complete length table must agree with the framed section before any
    /// payload allocation. Backend-specific decoding happens during admission.
    pub(super) fn read_from(reader: &mut impl Read, length: u64, expected: u8) -> Result<Self> {
        if length > MAX_SECTION || length < 12 {
            return Err(invalid("section length outside format limits"));
        }
        let mut reader = reader.take(length);
        let mut header = [0; 12];
        reader.read_exact(&mut header).map_err(invalid)?;
        if &header[..8] != TAG {
            return Err(invalid("invalid context section tag"));
        }
        let count = u32::from_le_bytes(header[8..].try_into().unwrap());
        if count == 0 || count != u32::from(expected) {
            return Err(invalid("record count differs from configured CPU count"));
        }
        let mut total = 12 + 12 * u64::from(count);
        if total > length {
            return Err(invalid("truncated context table"));
        }
        let mut table = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut row = [0; 12];
            reader.read_exact(&mut row).map_err(invalid)?;
            let kind = u32::from_le_bytes(row[..4].try_into().unwrap());
            let size = u64::from_le_bytes(row[4..].try_into().unwrap());
            if (kind == 0) != (size == 0) || size > record_limit(kind) {
                return Err(invalid("invalid context kind or record length"));
            }
            total = total
                .checked_add(size)
                .ok_or_else(|| invalid("context length overflow"))?;
            if total > length {
                return Err(invalid("context payload exceeds framed section"));
            }
            table.push((kind, size));
        }
        if total != length {
            return Err(invalid("context table length differs from framed section"));
        }
        let mut entries = Vec::with_capacity(count as usize);
        for (kind, size) in table {
            if kind == 0 {
                entries.push(None);
            } else {
                let size = usize::try_from(size).map_err(invalid)?;
                let mut data = Vec::new();
                data.try_reserve_exact(size).map_err(invalid)?;
                data.resize(size, 0);
                reader.read_exact(&mut data).map_err(invalid)?;
                entries.push(Some(BackendContext { kind, data }));
            }
        }
        Self::capture(entries, expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> BackendContexts {
        BackendContexts::capture(
            vec![
                Some(BackendContext {
                    kind: AARCH32_CONTEXT,
                    data: vec![0x12, 0x34],
                }),
                None,
            ],
            2,
        )
        .unwrap()
    }

    #[test]
    fn ordered_backend_contexts_roundtrip_with_absent_entries() {
        let contexts = fixture();
        let raw = contexts.encoded(2).unwrap();
        let restored =
            BackendContexts::read_from(&mut raw.as_slice(), raw.len() as u64, 2).unwrap();
        assert_eq!(restored.entries(), contexts.entries());
        assert_eq!(&raw[..12], b"RAXBCK01\x02\0\0\0");
        assert_eq!(&raw[12..24], &[1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn context_table_rejects_every_truncation_count_length_and_empty_extension() {
        let raw = fixture().encoded(2).unwrap();
        for end in 0..raw.len() {
            assert!(
                BackendContexts::read_from(&mut &raw[..end], end as u64, 2).is_err(),
                "prefix {end}"
            );
        }
        for (offset, value) in [
            (8, vec![0, 0, 0, 0]),
            (8, vec![255, 0, 0, 0]),
            (12, vec![0, 0, 0, 0]),
            (16, u64::MAX.to_le_bytes().to_vec()),
            (28, 1u64.to_le_bytes().to_vec()),
        ] {
            let mut bad = raw.clone();
            bad[offset..offset + value.len()].copy_from_slice(&value);
            assert!(
                BackendContexts::read_from(&mut bad.as_slice(), bad.len() as u64, 2).is_err(),
                "offset {offset}"
            );
        }
        let mut trailing = raw;
        trailing.push(0);
        assert!(
            BackendContexts::read_from(&mut trailing.as_slice(), trailing.len() as u64, 2).is_err()
        );
        assert!(BackendContexts::capture(vec![None], 1).is_err());
        assert!(BackendContexts::capture(vec![None], 0).is_err());
        assert!(BackendContexts::read_from(&mut [].as_slice(), MAX_SECTION + 1, 1).is_err());
    }
}

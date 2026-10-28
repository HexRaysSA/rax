//! Deduplicated immutable resources referenced by backend checkpoint contexts.
use super::stream::{FallibleBytes, compressed_limit};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, OnceLock};

pub const BOOT_CDROM_RESOURCE: u32 = 1;
const TAG: &[u8; 8] = b"RAXRES01";
const MAX_RESOURCES: usize = 1024;
// Version1 bounds decoder history to8MiB independently of full media size.
const WINDOW_LOG_MAX: u32 = 23;
const MAX_TOTAL: u64 = 64 * 1024 * 1024 * 1024;
const HEADER: u64 = 12;
const ROW: u64 = 52;
pub(super) const MAX_SECTION: u64 = MAX_TOTAL
    + MAX_TOTAL / 128
    + MAX_RESOURCES as u64 * 1024 * 1024
    + HEADER
    + MAX_RESOURCES as u64 * ROW;

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("checkpoint resources: {message}"))
}

/// The reported RAM/media budget excludes the separately admitted RAM padding.
pub(super) fn remaining_budget(memory: u64, media: u64) -> Result<u64> {
    MAX_TOTAL
        .checked_sub(memory)
        .and_then(|remaining| remaining.checked_sub(media))
        .ok_or_else(|| invalid("RAM plus media exceeds bundle budget"))
}

/// Identity includes the resource's interpretation and complete byte content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceKey {
    kind: u32,
    size: u64,
    digest: [u8; 32],
}
impl ResourceKey {
    pub fn kind(self) -> u32 {
        self.kind
    }
    pub fn size(self) -> u64 {
        self.size
    }
    pub fn sha256(self) -> [u8; 32] {
        self.digest
    }
    fn validate(self) -> Result<()> {
        if self.kind != BOOT_CDROM_RESOURCE || self.size > MAX_TOTAL {
            return Err(invalid("unknown resource kind or excessive size"));
        }
        Ok(())
    }
}

/// A backend's immutable source binding. Empty media remain distinct from none.
#[derive(Clone)]
pub struct CheckpointResource {
    key: ResourceKey,
    bytes: Arc<Vec<u8>>,
}
impl CheckpointResource {
    pub fn boot_cdrom(bytes: Arc<Vec<u8>>) -> Result<Self> {
        if bytes.len() as u64 > MAX_TOTAL {
            return Err(invalid("resource exceeds size limit"));
        }
        let key = ResourceKey {
            kind: BOOT_CDROM_RESOURCE,
            size: bytes.len() as u64,
            digest: Sha256::digest(bytes.as_slice()).into(),
        };
        key.validate()?;
        Ok(Self { key, bytes })
    }
    pub fn key(&self) -> ResourceKey {
        self.key
    }
}

#[derive(Clone)]
struct Record {
    key: ResourceKey,
    data: Vec<u8>,
}

/// Fully verified resources, shared by every restored CPU that references them.
#[derive(Default)]
pub struct PreparedResources {
    entries: BTreeMap<ResourceKey, Arc<Vec<u8>>>,
}
impl PreparedResources {
    /// Admit existing immutable bindings without compressing or copying media.
    pub fn from_bindings(resources: Vec<CheckpointResource>) -> Result<Self> {
        let mut entries: BTreeMap<ResourceKey, Arc<Vec<u8>>> = BTreeMap::new();
        let mut total = 0u64;
        for resource in resources {
            resource.key.validate()?;
            if let Some(bytes) = entries.get(&resource.key) {
                if !Arc::ptr_eq(bytes, &resource.bytes) && **bytes != *resource.bytes {
                    return Err(invalid("conflicting content for one resource identity"));
                }
            } else {
                total = total
                    .checked_add(resource.key.size)
                    .ok_or_else(|| invalid("size overflow"))?;
                if entries.len() == MAX_RESOURCES || total > MAX_TOTAL {
                    return Err(invalid("resource count or aggregate exceeds limit"));
                }
                entries.insert(resource.key, resource.bytes);
            }
        }
        Ok(Self { entries })
    }
    pub fn resolve(&self, key: ResourceKey) -> Result<Arc<Vec<u8>>> {
        self.entries
            .get(&key)
            .cloned()
            .ok_or_else(|| invalid("missing resource binding"))
    }
    pub fn keys(&self) -> impl Iterator<Item = ResourceKey> + '_ {
        self.entries.keys().copied()
    }
}

#[derive(Clone)]
pub struct ResourcesSnapshot {
    records: Vec<Record>,
    prepared: OnceLock<Arc<PreparedResources>>,
}
impl std::fmt::Debug for ResourcesSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourcesSnapshot")
            .field("resources", &self.records.len())
            .field("logical_bytes", &self.total_bytes())
            .finish_non_exhaustive()
    }
}

impl ResourcesSnapshot {
    pub fn capture(resources: Vec<CheckpointResource>) -> Result<Self> {
        let prepared = PreparedResources::from_bindings(resources)?;
        if prepared.entries.is_empty() {
            return Err(invalid("resource count outside 1..=1024"));
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(prepared.entries.len())
            .map_err(invalid)?;
        for (&key, bytes) in &prepared.entries {
            let output = FallibleBytes {
                bytes: Vec::new(),
                limit: usize::try_from(compressed_limit(key.size)).map_err(invalid)?,
            };
            let mut encoder = zstd::stream::write::Encoder::new(output, 3).map_err(invalid)?;
            encoder.window_log(WINDOW_LOG_MAX).map_err(invalid)?;
            encoder.write_all(bytes).map_err(invalid)?;
            records.push(Record {
                key,
                data: encoder.finish().map_err(invalid)?.bytes,
            });
        }
        let snapshot = Self {
            records,
            prepared: OnceLock::new(),
        };
        snapshot.validate_metadata()?;
        let _ = snapshot.prepared.set(Arc::new(prepared));
        Ok(snapshot)
    }

    pub fn total_bytes(&self) -> u64 {
        // Construction admits a checked aggregate before publishing this type.
        self.records.iter().map(|record| record.key.size).sum()
    }
    pub fn keys(&self) -> impl Iterator<Item = ResourceKey> + '_ {
        self.records.iter().map(|record| record.key)
    }
    pub(crate) fn validate_metadata(&self) -> Result<()> {
        if self.records.is_empty() || self.records.len() > MAX_RESOURCES {
            return Err(invalid("resource count outside 1..=1024"));
        }
        let mut logical = 0u64;
        let mut encoded = HEADER + ROW * self.records.len() as u64;
        let mut previous = None;
        for record in &self.records {
            record.key.validate()?;
            if previous.is_some_and(|key| key >= record.key) {
                return Err(invalid("resource identities are not strictly ordered"));
            }
            previous = Some(record.key);
            logical = logical
                .checked_add(record.key.size)
                .ok_or_else(|| invalid("size overflow"))?;
            if logical > MAX_TOTAL
                || record.data.is_empty()
                || record.data.len() as u64 > compressed_limit(record.key.size)
            {
                return Err(invalid("resource payload or aggregate exceeds limit"));
            }
            encoded = encoded
                .checked_add(record.data.len() as u64)
                .ok_or_else(|| invalid("encoded size overflow"))?;
            if encoded > MAX_SECTION {
                return Err(invalid("section exceeds limit"));
            }
        }
        Ok(())
    }
    pub fn prepare(&self) -> Result<Arc<PreparedResources>> {
        if let Some(prepared) = self.prepared.get() {
            return Ok(prepared.clone());
        }
        self.validate_metadata()?;
        let mut entries = BTreeMap::new();
        for record in &self.records {
            if !record.data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
                return Err(invalid("resource requires a regular zstd frame"));
            }
            // Cursor implements BufRead directly: its final position counts
            // consumed frame bytes, not speculative BufReader lookahead.
            let mut decoder =
                zstd::stream::read::Decoder::with_buffer(Cursor::new(record.data.as_slice()))
                    .map_err(invalid)?
                    .single_frame();
            decoder.window_log_max(WINDOW_LOG_MAX).map_err(invalid)?;
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            loop {
                let remaining = record
                    .key
                    .size
                    .checked_sub(bytes.len() as u64)
                    .ok_or_else(|| invalid("resource exceeds declared size"))?;
                let wanted = usize::try_from(remaining.min(chunk.len() as u64 - 1) + 1).unwrap();
                let count = decoder.read(&mut chunk[..wanted]).map_err(invalid)?;
                if count == 0 {
                    break;
                }
                if count as u64 > remaining {
                    return Err(invalid("resource exceeds declared size"));
                }
                bytes.try_reserve(count).map_err(invalid)?;
                bytes.extend_from_slice(&chunk[..count]);
            }
            if decoder.finish().position() != record.data.len() as u64 {
                return Err(invalid("trailing bytes or concatenated resource frames"));
            }
            if bytes.len() as u64 != record.key.size
                || <[u8; 32]>::from(Sha256::digest(&bytes)) != record.key.digest
            {
                return Err(invalid("resource size or SHA-256 mismatch"));
            }
            entries.insert(record.key, Arc::new(bytes));
        }
        let prepared = Arc::new(PreparedResources { entries });
        let _ = self.prepared.set(prepared.clone());
        Ok(self.prepared.get().cloned().unwrap_or(prepared))
    }
    /// Encode the complete bounded section, including its resource table.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let limit = usize::try_from(self.encoded_len()?).map_err(invalid)?;
        let mut output = FallibleBytes {
            bytes: Vec::new(),
            limit,
        };
        self.write_to(&mut output)?;
        Ok(output.bytes)
    }
    /// Decode and verify every full medium before exposing any binding.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        {
            let mut reader = raw;
            Self::read_from(&mut reader, raw.len() as u64)
        }
    }
    pub(crate) fn encoded_len(&self) -> Result<u64> {
        self.validate_metadata()?;
        Ok(HEADER
            + ROW * self.records.len() as u64
            + self
                .records
                .iter()
                .map(|record| record.data.len() as u64)
                .sum::<u64>())
    }
    pub(crate) fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        self.validate_metadata()?;
        writer.write_all(TAG).map_err(invalid)?;
        writer
            .write_all(&(self.records.len() as u32).to_le_bytes())
            .map_err(invalid)?;
        for record in &self.records {
            writer
                .write_all(&record.key.kind.to_le_bytes())
                .map_err(invalid)?;
            writer
                .write_all(&record.key.size.to_le_bytes())
                .map_err(invalid)?;
            writer.write_all(&record.key.digest).map_err(invalid)?;
            writer
                .write_all(&(record.data.len() as u64).to_le_bytes())
                .map_err(invalid)?;
        }
        for record in &self.records {
            writer.write_all(&record.data).map_err(invalid)?;
        }
        Ok(())
    }
    /// Admit the complete table and exact section length before payload reads.
    /// Every payload is hashed before any prepared binding is published.
    pub(crate) fn read_from(reader: &mut impl Read, length: u64) -> Result<Self> {
        Self::read_from_with_budget(reader, length, MAX_TOTAL)
    }

    pub(super) fn read_from_with_budget(
        reader: &mut impl Read,
        length: u64,
        logical_budget: u64,
    ) -> Result<Self> {
        if !(HEADER..=MAX_SECTION).contains(&length) {
            return Err(invalid("invalid section length"));
        }
        let mut reader = reader.take(length);
        let mut tag = [0u8; 8];
        reader.read_exact(&mut tag).map_err(invalid)?;
        if &tag != TAG {
            return Err(invalid("invalid resource tag"));
        }
        let mut word = [0u8; 4];
        reader.read_exact(&mut word).map_err(invalid)?;
        let count = u32::from_le_bytes(word) as usize;
        if count == 0 || count > MAX_RESOURCES {
            return Err(invalid("resource count outside 1..=1024"));
        }
        let mut encoded = HEADER + ROW * count as u64;
        if encoded > length {
            return Err(invalid("truncated resource table"));
        }
        let mut logical = 0u64;
        let mut headers = Vec::new();
        headers.try_reserve_exact(count).map_err(invalid)?;
        let mut previous = None;
        for _ in 0..count {
            let mut raw = [0u8; ROW as usize];
            reader.read_exact(&mut raw).map_err(invalid)?;
            let key = ResourceKey {
                kind: u32::from_le_bytes(raw[..4].try_into().unwrap()),
                size: u64::from_le_bytes(raw[4..12].try_into().unwrap()),
                digest: raw[12..44].try_into().unwrap(),
            };
            let compressed = u64::from_le_bytes(raw[44..52].try_into().unwrap());
            key.validate()?;
            if previous.is_some_and(|old| old >= key) {
                return Err(invalid("unordered or duplicate resource identity"));
            }
            previous = Some(key);
            logical = logical
                .checked_add(key.size)
                .ok_or_else(|| invalid("size overflow"))?;
            if logical > logical_budget {
                return Err(invalid("RAM plus media/resources exceeds bundle budget"));
            }
            encoded = encoded
                .checked_add(compressed)
                .ok_or_else(|| invalid("encoded size overflow"))?;
            if logical > MAX_TOTAL
                || compressed == 0
                || compressed > compressed_limit(key.size)
                || encoded > length
            {
                return Err(invalid("resource table exceeds section limits"));
            }
            headers.push((key, compressed));
        }
        if encoded != length {
            return Err(invalid("resource table disagrees with section length"));
        }
        let mut records = Vec::new();
        records.try_reserve_exact(count).map_err(invalid)?;
        for (key, mut remaining) in headers {
            let mut data = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            while remaining != 0 {
                let count = usize::try_from(remaining.min(chunk.len() as u64)).unwrap();
                reader.read_exact(&mut chunk[..count]).map_err(invalid)?;
                data.try_reserve(count).map_err(invalid)?;
                data.extend_from_slice(&chunk[..count]);
                remaining -= count as u64;
            }
            records.push(Record { key, data });
        }
        let snapshot = Self {
            records,
            prepared: OnceLock::new(),
        };
        snapshot.prepare()?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests;

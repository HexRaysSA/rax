//! Complete mapped backing, separately framed and checked before restore.
use super::stream::{FallibleBytes, compressed_limit};
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::sync::OnceLock;
#[cfg(test)]
use vm_memory::Bytes;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
pub(super) const MAX_TOTAL: u64 = 68 * 1024 * 1024 * 1024;
const MAX_REGIONS: usize = 128;
const CHUNK: usize = 64 * 1024;
const TAG: &[u8; 8] = b"RAXRAM01";
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("physical memory checkpoint: {message}"))
}
#[derive(Clone)]
struct Region {
    start: u64,
    size: u64,
    digest: [u8; 32],
    data: Vec<u8>,
}
/// Every mapped region, including backing outside reported RAM. Capture and
/// restore require callers to quiesce every independent CPU/DMA/RAM writer.
#[derive(Clone)]
pub struct PhysicalMemorySnapshot {
    regions: Vec<Region>,
    verified: OnceLock<[u8; 32]>,
    verified_projection: OnceLock<ProjectionKey>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ProjectionKey {
    physical: [u8; 32],
    projection: [u8; 32],
    reported: u64,
}
/// A checked immutable checkpoint/target pair. Only this module constructs it.
/// Caller-controlled writers/mapping changes must stay quiescent until commit.
pub(crate) struct PhysicalMemoryRestore<'a> {
    checkpoint: &'a PhysicalMemorySnapshot,
    target: &'a GuestMemoryMmap,
}
impl PhysicalMemoryRestore<'_> {
    pub(crate) fn commit(self) -> Result<()> {
        self.checkpoint.write_verified(self.target)
    }
    /// The caller retains the mapping and all writer/controller guards through
    /// publication. All compressed input and destination extents were admitted
    /// by prepare_with_projection before entering this method.
    pub(crate) fn commit_in_scope(
        self,
        scope: &crate::vm::memory::checkpoint::CheckpointPublication<'_>,
    ) -> Result<()> {
        self.checkpoint
            .visit(|address, bytes| scope.write(address, bytes).map_err(invalid))
    }
}
impl std::fmt::Debug for PhysicalMemorySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhysicalMemorySnapshot")
            .field("layout", &self.layout().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}
fn metadata(rows: &[(u64, u64, u64)]) -> Result<u64> {
    if rows.is_empty() || rows.len() > MAX_REGIONS {
        return Err(invalid("region count outside 1..=128"));
    }
    let mut end = 0u128;
    let mut total = 0u64;
    for &(start, size, compressed) in rows {
        if size == 0 || u128::from(start) < end {
            return Err(invalid("empty, unordered or overlapping region"));
        }
        end = u128::from(start) + u128::from(size);
        if end > (1u128 << 64) {
            return Err(invalid("physical address overflow"));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| invalid("size overflow"))?;
        if total > MAX_TOTAL || compressed > compressed_limit(size) {
            return Err(invalid("region or aggregate size exceeds limit"));
        }
    }
    Ok(total)
}
fn encoder(size: u64) -> Result<zstd::stream::write::Encoder<'static, FallibleBytes>> {
    let limit = usize::try_from(compressed_limit(size)).map_err(invalid)?;
    zstd::stream::write::Encoder::new(
        FallibleBytes {
            bytes: Vec::new(),
            limit,
        },
        3,
    )
    .map_err(invalid)
}
impl PhysicalMemorySnapshot {
    pub fn capture(memory: &GuestMemoryMmap) -> Result<Self> {
        Ok(Self::capture_inner(memory, None)?.0)
    }
    pub(crate) fn capture_with_projection(
        memory: &GuestMemoryMmap,
        reported: u64,
    ) -> Result<(Self, Vec<u8>)> {
        let (state, projection) = Self::capture_inner(memory, Some(reported))?;
        Ok((
            state,
            projection.ok_or_else(|| invalid("missing projection"))?,
        ))
    }
    fn capture_inner(
        memory: &GuestMemoryMmap,
        reported: Option<u64>,
    ) -> Result<(Self, Option<Vec<u8>>)> {
        #[cfg(unix)]
        if memory.iter().any(|r| r.prot() & libc::PROT_READ == 0) {
            return Err(invalid("source mapping is not readable"));
        }
        let layout: Vec<_> = memory
            .iter()
            .take(MAX_REGIONS + 1)
            .map(|r| (r.start_addr().raw_value(), r.len(), 0))
            .collect();
        metadata(&layout)?;
        let mut projection = reported.map(encoder).transpose()?;
        let mut covered = 0u64;
        let mut regions = Vec::new();
        regions.try_reserve_exact(layout.len()).map_err(invalid)?;
        let mut chunk = [0u8; CHUNK];
        for (start, size, _) in layout {
            let mut output = encoder(size)?;
            let mut digest = Sha256::new();
            let mut offset = 0u64;
            while offset < size {
                let n = (size - offset).min(CHUNK as u64) as usize;
                let address = start
                    .checked_add(offset)
                    .ok_or_else(|| invalid("address overflow"))?;
                crate::vm::memory::read_checkpoint_memory(memory, address, &mut chunk[..n])
                    .map_err(invalid)?;
                output.write_all(&chunk[..n]).map_err(invalid)?;
                digest.update(&chunk[..n]);
                if let (Some(reported), Some(projection)) = (reported, projection.as_mut()) {
                    if address < reported {
                        if address != covered {
                            return Err(invalid("reported projection has a hole"));
                        }
                        let count = (reported - address).min(n as u64) as usize;
                        projection.write_all(&chunk[..count]).map_err(invalid)?;
                        covered += count as u64;
                    }
                }
                offset += n as u64;
            }
            regions.push(Region {
                start,
                size,
                digest: digest.finalize().into(),
                data: output.finish().map_err(invalid)?.bytes,
            });
        }
        if reported.is_some_and(|n| n != covered) {
            return Err(invalid("reported projection is not backed"));
        }
        let projection = projection
            .map(|p| p.finish().map(|p| p.bytes).map_err(invalid))
            .transpose()?;
        let snapshot = Self::new(regions);
        // Both encoders consumed the same successfully read chunks. Successful
        // finish produces complete frames; the captured digests cover their
        // uncompressed contents. Cache only after all construction checks pass.
        let physical = snapshot.fingerprint();
        let _ = snapshot.verified.set(physical);
        if let (Some(reported), Some(projection)) = (reported, projection.as_ref()) {
            let _ = snapshot.verified_projection.set(ProjectionKey {
                physical,
                projection: Sha256::digest(projection).into(),
                reported,
            });
        }
        Ok((snapshot, projection))
    }

    fn new(regions: Vec<Region>) -> Self {
        Self {
            regions,
            verified: OnceLock::new(),
            verified_projection: OnceLock::new(),
        }
    }

    /// Include every declared extent, expected digest and compressed byte in
    /// cache identity. A changed image cannot inherit another image's proof.
    fn fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"RAXRAM01/verified\0");
        digest.update((self.regions.len() as u64).to_le_bytes());
        for region in &self.regions {
            digest.update(region.start.to_le_bytes());
            digest.update(region.size.to_le_bytes());
            digest.update(region.digest);
            digest.update((region.data.len() as u64).to_le_bytes());
            digest.update(&region.data);
        }
        digest.finalize().into()
    }
    pub fn layout(&self) -> impl ExactSizeIterator<Item = (u64, u64)> + '_ {
        self.regions.iter().map(|r| (r.start, r.size))
    }
    pub fn total_bytes(&self) -> u64 {
        self.regions.iter().map(|r| r.size).sum()
    }
    pub(super) fn validate_metadata(&self, media_bytes: u64) -> Result<()> {
        let rows: Vec<_> = self
            .regions
            .iter()
            .map(|r| (r.start, r.size, r.data.len() as u64))
            .collect();
        let total = metadata(&rows)?;
        if total.checked_add(media_bytes).is_none_or(|n| n > MAX_TOTAL) {
            return Err(invalid(
                "physical memory plus media exceeds aggregate limit",
            ));
        }
        Ok(())
    }
    fn visit(&self, mut visit: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
        self.validate_metadata(0)?;
        let fingerprint = self.fingerprint();
        let needs_digest = self.verified.get() != Some(&fingerprint);
        let mut chunk = [0u8; CHUNK];
        for region in &self.regions {
            let mut decoder =
                zstd::stream::read::Decoder::new(region.data.as_slice()).map_err(invalid)?;
            decoder.window_log_max(27).map_err(invalid)?;
            let mut digest = needs_digest.then(Sha256::new);
            let mut offset = 0u64;
            loop {
                let remaining = region.size - offset;
                let wanted = remaining.min(CHUNK as u64 - 1) as usize + 1;
                let n = decoder.read(&mut chunk[..wanted]).map_err(invalid)?;
                if n == 0 {
                    break;
                }
                if n as u64 > remaining {
                    return Err(invalid("region exceeds declared size"));
                }
                if let Some(digest) = &mut digest {
                    digest.update(&chunk[..n]);
                }
                visit(
                    region
                        .start
                        .checked_add(offset)
                        .ok_or_else(|| invalid("address overflow"))?,
                    &chunk[..n],
                )?;
                offset += n as u64;
            }
            if offset != region.size {
                return Err(invalid("region size mismatch"));
            }
            if let Some(digest) = digest {
                if <[u8; 32]>::from(digest.finalize()) != region.digest {
                    return Err(invalid("region SHA-256 mismatch"));
                }
            }
        }
        let _ = self.verified.set(fingerprint);
        Ok(())
    }
    /// Check all compressed bytes/digests without writing guest memory.
    pub fn verify(&self) -> Result<()> {
        self.validate_metadata(0)?;
        if self.verified.get() == Some(&self.fingerprint()) {
            return Ok(());
        }
        self.visit(|_, _| Ok(()))
    }
    pub(super) fn verify_projection(&self, compressed: &[u8], reported: u64) -> Result<()> {
        self.validate_metadata(0)?;
        let key = ProjectionKey {
            physical: self.fingerprint(),
            projection: Sha256::digest(compressed).into(),
            reported,
        };
        if self.verified_projection.get() == Some(&key) {
            return Ok(());
        }
        let mut base = zstd::stream::read::Decoder::new(compressed).map_err(invalid)?;
        base.window_log_max(27).map_err(invalid)?;
        let mut expected = [0u8; CHUNK];
        let mut covered = 0u64;
        self.visit(|address, bytes| {
            if address < reported {
                if address != covered {
                    return Err(invalid("reported projection has a hole"));
                }
                let n = (reported - address).min(bytes.len() as u64) as usize;
                base.read_exact(&mut expected[..n]).map_err(invalid)?;
                if bytes[..n] != expected[..n] {
                    return Err(invalid("reported and physical memory disagree"));
                }
                covered += n as u64;
            }
            Ok(())
        })?;
        if covered != reported || base.read(&mut expected[..1]).map_err(invalid)? != 0 {
            return Err(invalid("reported projection size mismatch"));
        }
        let _ = self.verified_projection.set(key);
        Ok(())
    }
    /// All layout/content failures precede the first guest write. The immutable
    /// checkpoint is then decoded again with bounded scratch space. Independent
    /// writers and host mapping faults are outside this transaction contract.
    pub fn restore(&self, memory: &GuestMemoryMmap) -> Result<()> {
        self.validate_target(memory)?;
        self.verify()?;
        self.write_verified(memory)
    }
    pub(crate) fn prepare_with_projection<'a>(
        &'a self,
        memory: &'a GuestMemoryMmap,
        projection: &[u8],
        reported: u64,
    ) -> Result<PhysicalMemoryRestore<'a>> {
        self.validate_target(memory)?;
        self.verify_projection(projection, reported)?;
        Ok(PhysicalMemoryRestore {
            checkpoint: self,
            target: memory,
        })
    }
    fn write_verified(&self, memory: &GuestMemoryMmap) -> Result<()> {
        let mut previous = [0u8; CHUNK];
        self.visit(|address, bytes| {
            // Equal bytes need no host write. This preserves sparse zero-backed
            // mappings without assuming that a fresh or reused target is zero.
            #[cfg(unix)]
            let readable = memory
                .find_region(GuestAddress(address))
                .is_some_and(|r| r.prot() & libc::PROT_READ != 0);
            #[cfg(not(unix))]
            let readable = true;
            if readable {
                crate::vm::memory::read_checkpoint_memory(
                    memory,
                    address,
                    &mut previous[..bytes.len()],
                )
                .map_err(invalid)?;
                if previous[..bytes.len()] == *bytes {
                    return Ok(());
                }
            }
            crate::vm::memory::reservations::write(memory, address, bytes).map_err(invalid)
        })
    }
    pub fn validate_target(&self, memory: &GuestMemoryMmap) -> Result<()> {
        #[cfg(unix)]
        if memory.iter().any(|r| r.prot() & libc::PROT_WRITE == 0) {
            return Err(invalid("destination mapping is not writable"));
        }
        if !self
            .layout()
            .eq(memory.iter().map(|r| (r.start_addr().raw_value(), r.len())))
        {
            return Err(invalid("destination physical layout mismatch"));
        }
        Ok(())
    }
    pub(super) fn encoded_len(&self) -> Result<u64> {
        self.validate_metadata(0)?;
        self.regions
            .iter()
            .try_fold(12 + 56 * self.regions.len() as u64, |n, r| {
                n.checked_add(r.data.len() as u64)
                    .ok_or_else(|| invalid("encoded size overflow"))
            })
    }
    pub(super) fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        self.validate_metadata(0)?;
        writer.write_all(TAG).map_err(invalid)?;
        writer
            .write_all(&(self.regions.len() as u32).to_le_bytes())
            .map_err(invalid)?;
        for r in &self.regions {
            writer.write_all(&r.start.to_le_bytes()).map_err(invalid)?;
            writer.write_all(&r.size.to_le_bytes()).map_err(invalid)?;
            writer.write_all(&r.digest).map_err(invalid)?;
            writer
                .write_all(&(r.data.len() as u64).to_le_bytes())
                .map_err(invalid)?;
        }
        for r in &self.regions {
            writer.write_all(&r.data).map_err(invalid)?;
        }
        Ok(())
    }
    pub(super) fn read_from(reader: &mut impl Read, length: u64, media_bytes: u64) -> Result<Self> {
        let mut reader = reader.take(length);
        let mut tag = [0; 8];
        reader.read_exact(&mut tag).map_err(invalid)?;
        if &tag != TAG {
            return Err(invalid("bad region tag"));
        }
        let mut count = [0; 4];
        reader.read_exact(&mut count).map_err(invalid)?;
        let count = u32::from_le_bytes(count) as usize;
        if count == 0 || count > MAX_REGIONS || length < 12 + count as u64 * 56 {
            return Err(invalid("invalid region table length/count"));
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(count).map_err(invalid)?;
        let mut total_length = 12 + count as u64 * 56;
        for _ in 0..count {
            let mut raw = [0; 56];
            reader.read_exact(&mut raw).map_err(invalid)?;
            let start = u64::from_le_bytes(raw[..8].try_into().unwrap());
            let size = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            let digest: [u8; 32] = raw[16..48].try_into().unwrap();
            let compressed = u64::from_le_bytes(raw[48..].try_into().unwrap());
            total_length = total_length
                .checked_add(compressed)
                .ok_or_else(|| invalid("encoded size overflow"))?;
            rows.push((start, size, digest, compressed));
        }
        let extents: Vec<_> = rows.iter().map(|&(s, n, _, c)| (s, n, c)).collect();
        let total = metadata(&extents)?;
        if total.checked_add(media_bytes).is_none_or(|n| n > MAX_TOTAL) || total_length != length {
            return Err(invalid("aggregate size or encoded length mismatch"));
        }
        let mut regions = Vec::new();
        regions.try_reserve_exact(count).map_err(invalid)?;
        for (start, size, digest, compressed) in rows {
            let count = usize::try_from(compressed).map_err(invalid)?;
            let mut data = Vec::new();
            data.try_reserve_exact(count).map_err(invalid)?;
            data.resize(count, 0);
            reader.read_exact(&mut data).map_err(invalid)?;
            regions.push(Region {
                start,
                size,
                digest,
                data,
            });
        }
        Ok(Self::new(regions))
    }
}

#[cfg(test)]
#[path = "physical_cache_tests.rs"]
mod cache_tests;

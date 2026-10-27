//! Bounded PCI control framing and independently compressed logical media.
use super::Snapshot;
use super::stream::FallibleBytes;
pub(super) use super::stream::compressed_limit;
use crate::config::{ArchKind, CheckpointConfig, ImageAccess};
use crate::devices::virtio::block_image::ImageCheckpoint;
use crate::error::{Error, Result};
use crate::vm::runtime::pci_state::{PciDeviceCheckpoint, PciEndpointCheckpoint};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
pub(super) const MAX_CONTROL: u64 = 65 * 1024 * 1024;
const MAX_NETWORK: usize = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 64 * 1024 * 1024 * 1024;
const TAG: &[u8; 8] = b"RAXPCS01";
fn invalid(message: impl Into<String>) -> Error {
    Error::Emulator(format!("PCI checkpoint bundle: {}", message.into()))
}
/// Complete logical media with a checked size/digest and a bounded zstd frame.
/// No source path or writable descriptor is retained.
#[derive(Clone)]
pub struct MediaSnapshot {
    size: u64,
    read_only: bool,
    digest: [u8; 32],
    data: Vec<u8>,
    loaded: bool,
}
impl std::fmt::Debug for MediaSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaSnapshot")
            .field("bytes", &self.size)
            .field("read_only", &self.read_only)
            .field("compressed_bytes", &self.data.len())
            .finish_non_exhaustive()
    }
}
impl MediaSnapshot {
    fn header(image: &ImageCheckpoint) -> Self {
        Self {
            size: image.bytes.len() as u64,
            read_only: image.read_only,
            digest: [0; 32],
            data: Vec::new(),
            loaded: false,
        }
    }
    fn capture(image: ImageCheckpoint) -> Result<Self> {
        let digest = Sha256::digest(&image.bytes).into();
        let limit = usize::try_from(compressed_limit(image.bytes.len() as u64))
            .map_err(|_| invalid("media does not fit host address size"))?;
        let output = FallibleBytes {
            bytes: Vec::new(),
            limit,
        };
        let mut encoder =
            zstd::stream::write::Encoder::new(output, 3).map_err(|e| invalid(e.to_string()))?;
        encoder
            .write_all(&image.bytes)
            .map_err(|e| invalid(e.to_string()))?;
        let data = encoder.finish().map_err(|e| invalid(e.to_string()))?.bytes;
        Ok(Self {
            size: image.bytes.len() as u64,
            read_only: image.read_only,
            digest,
            data,
            loaded: true,
        })
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.digest
    }
    pub fn compressed_bytes(&self) -> &[u8] {
        &self.data
    }
    /// Grow only for produced bytes, fail on the first excess byte, then check
    /// exact output size and SHA-256 before handing bytes to a controller.
    pub fn decompress(&self) -> Result<ImageCheckpoint> {
        if !self.loaded
            || self.size > MAX_TOTAL
            || self.data.len() as u64 > compressed_limit(self.size)
        {
            return Err(invalid("missing or oversized compressed media"));
        }
        let mut decoder = zstd::stream::read::Decoder::new(self.data.as_slice())
            .map_err(|e| invalid(e.to_string()))?;
        let mut bytes = Vec::new();
        let mut chunk = [0; 64 * 1024];
        loop {
            let remaining = self
                .size
                .checked_sub(bytes.len() as u64)
                .ok_or_else(|| invalid("media exceeds declared size"))?;
            let wanted = usize::try_from(remaining.min(chunk.len() as u64 - 1) + 1).unwrap();
            let count = decoder
                .read(&mut chunk[..wanted])
                .map_err(|e| invalid(e.to_string()))?;
            if count == 0 {
                break;
            }
            if count as u64 > remaining {
                return Err(invalid("media exceeds declared size"));
            }
            bytes
                .try_reserve(count)
                .map_err(|e| invalid(e.to_string()))?;
            bytes.extend_from_slice(&chunk[..count]);
        }
        if bytes.len() as u64 != self.size {
            return Err(invalid("media size mismatch"));
        }
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != self.digest {
            return Err(invalid("media SHA-256 mismatch"));
        }
        Ok(ImageCheckpoint {
            bytes,
            read_only: self.read_only,
        })
    }
}
#[derive(Clone)]
struct Endpoints {
    e1000: Vec<u8>,
    uhci: Vec<u8>,
    nvme: Vec<u8>,
    ahci: Vec<u8>,
    ac97: Vec<u8>,
    nvme_media: MediaSnapshot,
    ahci_media: MediaSnapshot,
}
/// PCI records and complete detached media for the fixed runtime profile.
#[derive(Clone)]
pub struct PciSnapshot {
    bridge: Vec<u8>,
    endpoints: Option<Endpoints>,
}
impl std::fmt::Debug for PciSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PciSnapshot")
            .field("optional_endpoints", &self.endpoints.is_some())
            .finish_non_exhaustive()
    }
}
fn fixed(record: &[u8], tag: &[u8; 8], length: usize) -> Result<()> {
    if record.len() != length || record.get(..8) != Some(tag.as_slice()) {
        return Err(invalid("invalid fixed controller record"));
    }
    Ok(())
}
fn media_header(record: &[u8], media: &MediaSnapshot) -> Result<()> {
    if u64::from_le_bytes(record[16..24].try_into().unwrap()) != media.size
        || record[24] != u8::from(media.read_only)
    {
        return Err(invalid("controller/media header mismatch"));
    }
    Ok(())
}
impl PciSnapshot {
    pub(super) fn capture(state: PciDeviceCheckpoint, base: &Snapshot) -> Result<Self> {
        let (mut result, images) = match state.endpoints {
            None => (
                Self {
                    bridge: state.bridge.state,
                    endpoints: None,
                },
                None,
            ),
            Some(e) => {
                let n = MediaSnapshot::header(&e.nvme.media);
                let a = MediaSnapshot::header(&e.ahci.media);
                (
                    Self {
                        bridge: state.bridge.state,
                        endpoints: Some(Endpoints {
                            e1000: e.e1000.state,
                            uhci: e.uhci.state,
                            nvme: e.nvme.state,
                            ahci: e.ahci.state,
                            ac97: e.ac97.state,
                            nvme_media: n,
                            ahci_media: a,
                        }),
                    },
                    Some((e.nvme.media, e.ahci.media)),
                )
            }
        };
        result.validate_metadata(&base.config, base.memory_size)?;
        if let Some((n, a)) = images {
            let e = result.endpoints.as_mut().unwrap();
            e.nvme_media = MediaSnapshot::capture(n)?;
            e.ahci_media = MediaSnapshot::capture(a)?;
        }
        Ok(result)
    }
    pub fn nvme_media(&self) -> Option<&MediaSnapshot> {
        self.endpoints.as_ref().map(|e| &e.nvme_media)
    }
    pub fn ahci_media(&self) -> Option<&MediaSnapshot> {
        self.endpoints.as_ref().map(|e| &e.ahci_media)
    }
    pub fn has_endpoints(&self) -> bool {
        self.endpoints.is_some()
    }
    /// Decompress/check all media before constructing detached device records.
    /// Full controller semantic validation occurs when the runtime imports them.
    pub fn into_devices(self) -> Result<PciDeviceCheckpoint> {
        let endpoints = match self.endpoints {
            None => None,
            Some(e) => Some(PciEndpointCheckpoint {
                e1000: crate::devices::e1000::E1000Checkpoint { state: e.e1000 },
                uhci: crate::devices::uhci::UhciCheckpoint { state: e.uhci },
                nvme: crate::devices::nvme::NvmeCheckpoint {
                    state: e.nvme,
                    media: e.nvme_media.decompress()?,
                },
                ahci: crate::devices::ahci::AhciCheckpoint {
                    state: e.ahci,
                    media: e.ahci_media.decompress()?,
                },
                ac97: crate::devices::ac97::Ac97Checkpoint { state: e.ac97 },
            }),
        };
        Ok(PciDeviceCheckpoint {
            bridge: crate::devices::pci::PciCheckpoint { state: self.bridge },
            endpoints,
        })
    }
    pub(super) fn validate_metadata(&self, config: &CheckpointConfig, memory: u64) -> Result<()> {
        config.storage.validate_metadata()?;
        if config.arch != ArchKind::X86_64 || config.pci_devices != self.endpoints.is_some() {
            return Err(invalid("PCI/config topology mismatch"));
        }
        if self.bridge.len() < 20
            || self.bridge.len() > 4096
            || self.bridge.get(..8) != Some(b"RAXPCI01".as_slice())
        {
            return Err(invalid("invalid bridge record"));
        }
        let functions = u32::from_le_bytes(self.bridge[12..16].try_into().unwrap());
        let windows = u32::from_le_bytes(self.bridge[16..20].try_into().unwrap());
        let expected = if self.endpoints.is_some() {
            (6, 6)
        } else {
            (1, 0)
        };
        if (functions, windows) != expected
            || self.bridge.len() != 20 + functions as usize * 307 + windows as usize * 21
        {
            return Err(invalid("unsupported PCI runtime profile"));
        }
        let mut total = memory;
        if let Some(e) = &self.endpoints {
            if !(751..=MAX_NETWORK).contains(&e.e1000.len())
                || e.e1000.get(..8) != Some(b"RAXE1K01".as_slice())
            {
                return Err(invalid("invalid e1000 record"));
            }
            fixed(&e.uhci, b"RAXUHC01", 39)?;
            fixed(&e.nvme, b"RAXNVM01", 353)?;
            fixed(&e.ahci, b"RAXAHC01", 112)?;
            fixed(&e.ac97, b"RAXAC901", 316)?;
            for (record, media, binding) in [
                (&e.nvme, &e.nvme_media, config.storage.nvme.as_ref()),
                (&e.ahci, &e.ahci_media, config.storage.ahci.as_ref()),
            ] {
                media_header(record, media)?;
                total = total
                    .checked_add(media.size)
                    .ok_or_else(|| invalid("aggregate size overflow"))?;
                if let Some(image) = binding {
                    if media.size != image.identity.bytes
                        || media.read_only != (image.mode == ImageAccess::ReadOnly)
                    {
                        return Err(invalid("configured media geometry/protection mismatch"));
                    }
                }
            }
        } else if config.storage.has_images() {
            return Err(invalid("image bindings require endpoint state"));
        }
        if total > MAX_TOTAL {
            return Err(invalid("RAM plus media exceeds 64 GiB bundle budget"));
        }
        Ok(())
    }
    pub(super) fn validate(&self, config: &CheckpointConfig, memory: u64) -> Result<()> {
        self.validate_metadata(config, memory)?;
        for kind in [8, 9] {
            if let Some(media) = self.medium(kind) {
                if !media.loaded || media.data.len() as u64 > compressed_limit(media.size) {
                    return Err(invalid("missing or oversized media section"));
                }
            }
        }
        Ok(())
    }
    fn medium(&self, kind: u32) -> Option<&MediaSnapshot> {
        self.endpoints.as_ref().and_then(|e| match kind {
            8 => Some(&e.nvme_media),
            9 => Some(&e.ahci_media),
            _ => None,
        })
    }
    pub(super) fn media_size(&self, kind: u32) -> Result<u64> {
        self.medium(kind)
            .map(|m| m.size)
            .ok_or_else(|| invalid("unexpected media section"))
    }
    pub(super) fn media_data(&self, kind: u32) -> Option<&[u8]> {
        self.medium(kind).map(|m| m.data.as_slice())
    }
    pub(super) fn set_media(&mut self, kind: u32, data: Vec<u8>) -> Result<()> {
        let e = self
            .endpoints
            .as_mut()
            .ok_or_else(|| invalid("media without endpoint metadata"))?;
        let media = match kind {
            8 => &mut e.nvme_media,
            9 => &mut e.ahci_media,
            _ => return Err(invalid("unknown media section")),
        };
        if data.len() as u64 > compressed_limit(media.size) {
            return Err(invalid("compressed media exceeds limit"));
        }
        media.data = data;
        media.loaded = true;
        Ok(())
    }
    pub(super) fn control(&self) -> Result<Vec<u8>> {
        let mut w = FallibleBytes {
            bytes: Vec::new(),
            limit: MAX_CONTROL as usize,
        };
        let mut write = |bytes: &[u8]| w.write_all(bytes).map_err(|e| invalid(e.to_string()));
        write(TAG)?;
        write(&[u8::from(self.endpoints.is_some())])?;
        write(&(self.bridge.len() as u32).to_le_bytes())?;
        write(&self.bridge)?;
        if let Some(e) = &self.endpoints {
            for record in [&e.e1000, &e.uhci, &e.nvme, &e.ahci, &e.ac97] {
                write(&(record.len() as u32).to_le_bytes())?;
                write(record)?;
            }
            for media in [&e.nvme_media, &e.ahci_media] {
                write(&media.size.to_le_bytes())?;
                write(&[u8::from(media.read_only)])?;
                write(&media.digest)?;
            }
        }
        Ok(w.bytes)
    }
    pub(super) fn parse_control(raw: &[u8]) -> Result<Self> {
        if raw.len() as u64 > MAX_CONTROL {
            return Err(invalid("control section exceeds limit"));
        }
        let mut r = Reader { raw, at: 0 };
        if r.take(8)? != TAG {
            return Err(invalid("unknown PCI control schema"));
        }
        let present = r.boolean()?;
        let bridge = r.record(20, 4096)?;
        let endpoints = if present {
            let e1000 = r.record(751, MAX_NETWORK)?;
            let uhci = r.record(39, 39)?;
            let nvme = r.record(353, 353)?;
            let ahci = r.record(112, 112)?;
            let ac97 = r.record(316, 316)?;
            Some(Endpoints {
                e1000,
                uhci,
                nvme,
                ahci,
                ac97,
                nvme_media: r.media()?,
                ahci_media: r.media()?,
            })
        } else {
            None
        };
        if r.at != raw.len() {
            return Err(invalid("trailing control bytes"));
        }
        Ok(Self { bridge, endpoints })
    }
}
struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(length)
            .filter(|n| *n <= self.raw.len())
            .ok_or_else(|| invalid("truncated control record"))?;
        let bytes = &self.raw[self.at..end];
        self.at = end;
        Ok(bytes)
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("invalid control boolean")),
        }
    }
    fn record(&mut self, min: usize, max: usize) -> Result<Vec<u8>> {
        let length = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if !(min..=max).contains(&length) {
            return Err(invalid("invalid control record size"));
        }
        let raw = self.take(length)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|e| invalid(e.to_string()))?;
        bytes.extend_from_slice(raw);
        Ok(bytes)
    }
    fn media(&mut self) -> Result<MediaSnapshot> {
        let size = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
        let read_only = self.boolean()?;
        let digest = self.take(32)?.try_into().unwrap();
        Ok(MediaSnapshot {
            size,
            read_only,
            digest,
            data: Vec::new(),
            loaded: false,
        })
    }
}

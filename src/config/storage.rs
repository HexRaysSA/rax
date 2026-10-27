//! Configured PCI raw-image attachments and immutable source identities.
use super::{CliConfig, FileConfig, MemorySize};
use crate::devices::virtio::block_image::{BlockImage, ImageMode, MAX_IMAGE_BYTES};
use crate::error::{Error, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
/// Default per-image admission budget (4 GiB); loaded images are fully resident.
pub const DEFAULT_IMAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Selected guest write policy for an attached raw image.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ImageAccess {
    ReadOnly,
    ReadWrite,
    #[default]
    CopyOnWrite,
}
impl From<ImageAccess> for ImageMode {
    fn from(mode: ImageAccess) -> Self {
        match mode {
            ImageAccess::ReadOnly => Self::ReadOnly,
            ImageAccess::ReadWrite => Self::ReadWrite,
            ImageAccess::CopyOnWrite => Self::CopyOnWrite,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Source length and SHA-256 over the captured file bytes.
pub struct ImageIdentity {
    pub bytes: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Canonical source, access policy, byte budget and captured content identity.
pub struct ImageAttachment {
    pub path: PathBuf,
    pub mode: ImageAccess,
    pub max_bytes: u64,
    pub identity: ImageIdentity,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Optional image bindings for the existing x86 PCI controllers.
pub struct StorageConfig {
    pub nvme: Option<ImageAttachment>,
    pub ahci: Option<ImageAttachment>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// One image table from a TOML configuration.
pub struct FileImageConfig {
    pub path: PathBuf,
    pub mode: Option<ImageAccess>,
    pub max_bytes: Option<MemorySize>,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
/// Typed TOML image tables; unknown names are errors.
pub struct FileStorageConfig {
    pub nvme: Option<FileImageConfig>,
    pub ahci: Option<FileImageConfig>,
}
fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}
impl ImageAttachment {
    /// Resolve canonical path and hash the bounded source under a shared lock.
    /// This does not open a writable descriptor or modify image bytes.
    pub fn capture(path: impl AsRef<Path>, mode: ImageAccess, max_bytes: u64) -> Result<Self> {
        if max_bytes == 0 || max_bytes > MAX_IMAGE_BYTES {
            return Err(invalid("image budget must be between 1 byte and 64 GiB"));
        }
        let path = path.as_ref().canonicalize()?;
        if !std::fs::metadata(&path)?.is_file() {
            return Err(invalid("image path is not a regular file"));
        }
        let mut file = std::fs::File::open(&path)?;
        file.try_lock_shared().map_err(std::io::Error::from)?;
        let size = file.metadata()?.len();
        if size == 0 || size % 512 != 0 || size > max_bytes {
            return Err(invalid(
                "image must be nonempty, sector-aligned and within its byte budget",
            ));
        }
        let mut hasher = Sha256::new();
        let mut bytes = 0u64;
        let mut scratch = [0; 64 * 1024];
        loop {
            let count = match file.read(&mut scratch) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if count == 0 {
                break;
            }
            bytes = bytes
                .checked_add(count as u64)
                .ok_or_else(|| invalid("image byte count overflow"))?;
            if bytes > max_bytes {
                return Err(invalid("image grew beyond its byte budget"));
            }
            hasher.update(&scratch[..count]);
        }
        if bytes != size || file.metadata()?.len() != size {
            return Err(invalid("image size changed during identity capture"));
        }
        Ok(Self {
            path,
            mode,
            max_bytes,
            identity: ImageIdentity {
                bytes,
                sha256: hasher.finalize().into(),
            },
        })
    }
    /// Validate a serialized record without opening its source file.
    pub fn validate_metadata(&self) -> Result<()> {
        if !self.path.is_absolute()
            || self.max_bytes == 0
            || self.max_bytes > MAX_IMAGE_BYTES
            || self.identity.bytes == 0
            || self.identity.bytes % 512 != 0
            || self.identity.bytes > self.max_bytes
        {
            return Err(invalid("invalid recorded storage image metadata"));
        }
        Ok(())
    }
    /// Bind the loaded bytes to the captured identity before exposing a device.
    pub fn open(&self) -> Result<BlockImage> {
        self.validate_metadata()?;
        let image = BlockImage::open(&self.path, self.mode.into(), self.max_bytes)?;
        let digest: [u8; 32] = Sha256::digest(&*image).into();
        if image.len() as u64 != self.identity.bytes || digest != self.identity.sha256 {
            return Err(invalid(format!(
                "storage image identity changed: {}",
                self.path.display()
            )));
        }
        Ok(image)
    }
}
impl StorageConfig {
    /// Whether a configured controller has an image attachment.
    pub fn has_images(&self) -> bool {
        self.nvme.is_some() || self.ahci.is_some()
    }
    pub fn validate_metadata(&self) -> Result<()> {
        for image in [&self.nvme, &self.ahci].into_iter().flatten() {
            image.validate_metadata()?;
        }
        Ok(())
    }
    pub(super) fn from_checkpoint(previous: &Self, cli: &CliConfig) -> Result<Self> {
        if cli.nvme_image.is_none()
            && cli.nvme_image_mode.is_none()
            && cli.nvme_image_limit.is_none()
            && cli.ahci_image.is_none()
            && cli.ahci_image_mode.is_none()
            && cli.ahci_image_limit.is_none()
        {
            return Ok(previous.clone());
        }
        let file = |a: &ImageAttachment| FileImageConfig {
            path: a.path.clone(),
            mode: Some(a.mode),
            max_bytes: Some(MemorySize(a.max_bytes)),
        };
        Self::from_sources(
            cli,
            &FileConfig {
                storage: Some(FileStorageConfig {
                    nvme: previous.nvme.as_ref().map(file),
                    ahci: previous.ahci.as_ref().map(file),
                }),
                ..Default::default()
            },
        )
    }
    pub(super) fn from_sources(cli: &CliConfig, file: &FileConfig) -> Result<Self> {
        fn one(
            name: &str,
            path: Option<&Path>,
            mode: Option<ImageAccess>,
            budget: Option<MemorySize>,
            file: Option<&FileImageConfig>,
        ) -> Result<Option<ImageAttachment>> {
            let path = path.or_else(|| file.map(|f| f.path.as_path()));
            let mode = mode.or_else(|| file.and_then(|f| f.mode));
            let budget = budget.or_else(|| file.and_then(|f| f.max_bytes));
            let Some(path) = path else {
                if mode.is_some() || budget.is_some() {
                    return Err(invalid(format!(
                        "{name} image mode/budget requires an image path"
                    )));
                }
                return Ok(None);
            };
            ImageAttachment::capture(
                path,
                mode.unwrap_or_default(),
                budget.map_or(DEFAULT_IMAGE_BYTES, MemorySize::bytes),
            )
            .map(Some)
        }
        let input = file.storage.as_ref();
        Ok(Self {
            nvme: one(
                "NVMe",
                cli.nvme_image.as_deref(),
                cli.nvme_image_mode,
                cli.nvme_image_limit,
                input.and_then(|s| s.nvme.as_ref()),
            )?,
            ahci: one(
                "AHCI",
                cli.ahci_image.as_deref(),
                cli.ahci_image_mode,
                cli.ahci_image_limit,
                input.and_then(|s| s.ahci.as_ref()),
            )?,
        })
    }
}

//! File-backed configuration input.

use super::kinds::{
    Aarch32Isa, Aarch64Isa, ArchKind, BackendKind, CortexMIsa, CortexRIsa, Endianness, HexagonIsa,
};
use super::values::{Address, MemorySize};
use crate::error::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct FileConfig {
    pub arch: Option<ArchKind>,
    pub backend: Option<BackendKind>,
    pub memory: Option<MemorySize>,
    pub vcpus: Option<u8>,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub cmdline: Option<String>,
    // Hexagon options
    pub hexagon_isa: Option<HexagonIsa>,
    pub hexagon_endian: Option<Endianness>,
    pub hexagon_entry: Option<Address>,
    pub hexagon_load_addr: Option<Address>,
    // ARM options
    pub aarch64_isa: Option<Aarch64Isa>,
    pub aarch32_isa: Option<Aarch32Isa>,
    pub cortexm_isa: Option<CortexMIsa>,
    pub cortexr_isa: Option<CortexRIsa>,
    pub arm_entry: Option<Address>,
    pub arm_load_addr: Option<Address>,
    pub arm_dtb: Option<PathBuf>,
    /// Attach the optional PCI device models (e1000/nvme/ahci/ac97/uhci).
    pub pci_devices: Option<bool>,
    pub storage: Option<super::storage::FileStorageConfig>,
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config = toml::from_str::<FileConfig>(&contents)
            .map_err(|e| Error::InvalidConfig(format!("toml error: {e}")))?;
        if let Some(storage) = &mut config.storage {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            for image in [&mut storage.nvme, &mut storage.ahci].into_iter().flatten() {
                if image.path.is_relative() {
                    image.path = parent.join(&image.path);
                }
            }
        }
        Ok(config)
    }
}

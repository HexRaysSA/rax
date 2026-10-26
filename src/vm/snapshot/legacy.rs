//! Original version-8 configuration layout. Do not append fields here.
use crate::config::{
    Aarch32Isa, Aarch64Isa, ArchKind, BackendKind, CheckpointConfig, CortexMIsa, CortexRIsa,
    Endianness, HexagonIsa,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Serialize, Deserialize)]
pub(super) struct LegacyConfig {
    pub arch: ArchKind,
    pub backend: BackendKind,
    pub memory_bytes: u64,
    pub vcpus: u8,
    pub kernel: PathBuf,
    pub initrd: Option<PathBuf>,
    pub cmdline: String,
    pub hexagon_isa: HexagonIsa,
    pub hexagon_endian: Endianness,
    pub hexagon_entry: Option<u64>,
    pub hexagon_load_addr: Option<u64>,
    pub aarch64_isa: Aarch64Isa,
    pub aarch32_isa: Aarch32Isa,
    pub cortexm_isa: CortexMIsa,
    pub cortexr_isa: CortexRIsa,
    pub arm_entry: Option<u64>,
    pub arm_load_addr: Option<u64>,
    pub arm_dtb: Option<PathBuf>,
}

impl From<LegacyConfig> for CheckpointConfig {
    fn from(value: LegacyConfig) -> Self {
        Self {
            arch: value.arch,
            backend: value.backend,
            memory_bytes: value.memory_bytes,
            vcpus: value.vcpus,
            kernel: value.kernel,
            initrd: value.initrd,
            cmdline: value.cmdline,
            hexagon_isa: value.hexagon_isa,
            hexagon_endian: value.hexagon_endian,
            hexagon_entry: value.hexagon_entry,
            hexagon_load_addr: value.hexagon_load_addr,
            aarch64_isa: value.aarch64_isa,
            aarch32_isa: value.aarch32_isa,
            cortexm_isa: value.cortexm_isa,
            cortexr_isa: value.cortexr_isa,
            arm_entry: value.arm_entry,
            arm_load_addr: value.arm_load_addr,
            arm_dtb: value.arm_dtb,
            pci_devices: false,
        }
    }
}

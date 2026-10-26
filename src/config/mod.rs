//! VM configuration types, input sources, and resolution.

pub mod file;
pub mod kinds;
pub mod runtime;
pub mod values;

pub use file::FileConfig;
pub use kinds::{
    Aarch32Isa, Aarch64Isa, ArchKind, ArmFeatures, BackendKind, CortexMIsa, CortexRIsa, Endianness,
    HexagonIsa,
};
pub use runtime::{CheckpointConfig, CliConfig, VmConfig};
pub use values::{Address, MemorySize};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[test]
    fn memory_size_parses_units() {
        assert_eq!(MemorySize::from_str("1024").unwrap().bytes(), 1024);
        assert_eq!(MemorySize::from_str("1K").unwrap().bytes(), 1024);
        assert_eq!(MemorySize::from_str("1KiB").unwrap().bytes(), 1024);
        assert_eq!(MemorySize::from_str("2M").unwrap().bytes(), 2 * 1024 * 1024);
        assert_eq!(
            MemorySize::from_str("3g").unwrap().bytes(),
            3 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn memory_size_rejects_bad_values() {
        assert!(MemorySize::from_str("").is_err());
        assert!(MemorySize::from_str("abc").is_err());
        assert!(MemorySize::from_str("1Z").is_err());
    }

    #[test]
    fn address_parses_hex_and_decimal() {
        assert_eq!(Address::from_str("0x10").unwrap().raw(), 16);
        assert_eq!(Address::from_str("32").unwrap().raw(), 32);
    }

    fn checkpoint_config(memory_bytes: u64) -> CheckpointConfig {
        CheckpointConfig {
            arch: ArchKind::X86_64,
            backend: BackendKind::Emulator,
            memory_bytes,
            vcpus: 1,
            kernel: PathBuf::from("/checkpoint/kernel"),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
            hexagon_isa: HexagonIsa::default(),
            hexagon_endian: Endianness::default(),
            hexagon_entry: None,
            hexagon_load_addr: None,
            aarch64_isa: Aarch64Isa::default(),
            aarch32_isa: Aarch32Isa::default(),
            cortexm_isa: CortexMIsa::default(),
            cortexr_isa: CortexRIsa::default(),
            arm_entry: None,
            arm_load_addr: None,
            arm_dtb: None,
            pci_devices: false,
        }
    }

    #[test]
    fn from_checkpoint_rejects_config_memory_mismatch() {
        let cp = checkpoint_config(512 << 20);
        let err = VmConfig::from_checkpoint(cp, CliConfig::default(), 256 << 20).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match snapshot memory_size")
        );
    }

    #[test]
    fn from_checkpoint_rejects_oversized_embedded_memory() {
        let memory_bytes = crate::vm::memory::MAX_GUEST_MEMORY_BYTES + crate::vm::memory::PAGE_SIZE;
        let cp = checkpoint_config(memory_bytes);
        let err = VmConfig::from_checkpoint(cp, CliConfig::default(), memory_bytes).unwrap_err();
        assert!(err.to_string().contains("guest memory must not exceed"));
    }

    #[test]
    fn from_checkpoint_allows_cli_memory_override_after_metadata_match() {
        let cp = checkpoint_config(512 << 20);
        let mut cli = CliConfig::default();
        cli.memory = Some(MemorySize(1024 << 20));

        let config = VmConfig::from_checkpoint(cp, cli, 512 << 20).unwrap();

        assert_eq!(config.memory.bytes(), 1024 << 20);
    }
}

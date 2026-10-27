//! CLI configuration input, resolved VM configuration, and checkpoint metadata.

use super::file::FileConfig;
use super::kinds::{
    Aarch32Isa, Aarch64Isa, ArchKind, BackendKind, CortexMIsa, CortexRIsa, Endianness, HexagonIsa,
};
use super::values::{Address, MemorySize};
use super::{ImageAccess, StorageConfig};
use crate::error::{Error, Result};
use crate::vm::memory::validate_guest_memory_size;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MIN_MEM_MIB: u64 = 128;
const DEFAULT_VCPUS: u8 = 1;
/// Default kernel command line for emulator boot.
/// Includes timing options for stable emulation:
/// - tsc=reliable: Don't recalibrate TSC (we provide stable instruction-based TSC)
/// - nohz=off: Disable tickless mode (simplifies timer handling)
/// - clocksource=tsc: Use TSC as clock source (we emulate it based on instruction count)
const DEFAULT_CMDLINE: &str =
    "console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr tsc=reliable nohz=off clocksource=tsc";
/// Default kernel command line for AArch64 guests: PL011 console at the virt
/// machine UART base.
const DEFAULT_CMDLINE_AARCH64: &str = "console=ttyAMA0 earlycon=pl011,mmio32,0x09000000";

#[derive(Clone, Debug, Default)]
pub struct CliConfig {
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
    // Debug/profiling options
    pub trace: Option<PathBuf>,
    /// GDB server port (enables GDB server when set).
    pub gdb_port: Option<u16>,
    /// Wait for GDB connection before starting.
    pub wait_gdb: bool,
    /// Snapshot interval (take snapshot every N instructions, 0 = disabled)
    pub snapshot_interval: u64,
    /// Take snapshot at specific instruction counts (comma-separated)
    pub snapshot_at: Vec<u64>,
    /// Directory to save snapshots
    pub snapshot_dir: Option<PathBuf>,
    /// Snapshot file to resume from
    pub resume: Option<PathBuf>,
    /// Checkpoint (.rxc) file to resume the whole machine from.
    pub checkpoint: Option<PathBuf>,
    /// Output path for checkpoints triggered by hotkey/signal (default
    /// `./checkpoint.rxc` relative to the working directory).
    pub snapshot_out: Option<PathBuf>,
    /// Enable instruction profiling
    pub profile: bool,
    /// JSON output path for profiling results
    pub profile_output: Option<PathBuf>,
    /// Live profiling stats interval (instructions)
    pub profile_interval: Option<u64>,
    /// Attach the optional PCI device models behind the host bridge.
    pub pci_devices: bool,
    pub nvme_image: Option<PathBuf>,
    pub nvme_image_mode: Option<ImageAccess>,
    pub nvme_image_limit: Option<MemorySize>,
    pub ahci_image: Option<PathBuf>,
    pub ahci_image_mode: Option<ImageAccess>,
    pub ahci_image_limit: Option<MemorySize>,
}

#[derive(Clone, Debug)]
pub struct VmConfig {
    pub arch: ArchKind,
    pub backend: BackendKind,
    pub memory: MemorySize,
    pub vcpus: u8,
    pub kernel: PathBuf,
    pub initrd: Option<PathBuf>,
    pub cmdline: String,
    // Hexagon options
    pub hexagon_isa: HexagonIsa,
    pub hexagon_endian: Endianness,
    pub hexagon_entry: Option<Address>,
    pub hexagon_load_addr: Option<Address>,
    // ARM options
    pub aarch64_isa: Aarch64Isa,
    pub aarch32_isa: Aarch32Isa,
    pub cortexm_isa: CortexMIsa,
    pub cortexr_isa: CortexRIsa,
    pub arm_entry: Option<Address>,
    pub arm_load_addr: Option<Address>,
    pub arm_dtb: Option<PathBuf>,
    // Debug/profiling options
    pub trace: Option<PathBuf>,
    /// GDB server port (enables GDB server when set).
    pub gdb_port: Option<u16>,
    /// Wait for GDB connection before starting.
    pub wait_gdb: bool,
    /// Snapshot interval (take snapshot every N instructions, 0 = disabled)
    pub snapshot_interval: u64,
    /// Take snapshot at specific instruction counts
    pub snapshot_at: Vec<u64>,
    /// Directory to save snapshots
    pub snapshot_dir: Option<PathBuf>,
    /// Snapshot file to resume from
    pub resume: Option<PathBuf>,
    /// Checkpoint (.rxc) file to resume the whole machine from.
    pub checkpoint: Option<PathBuf>,
    /// Output path for checkpoints triggered by hotkey/signal.
    pub snapshot_out: Option<PathBuf>,
    /// Enable instruction profiling
    pub profile: bool,
    /// JSON output path for profiling results
    pub profile_output: Option<PathBuf>,
    /// Live profiling stats interval (instructions)
    pub profile_interval: Option<u64>,
    /// Attach the optional PCI device models behind the host bridge. Off by
    /// default so the default machine (and its verified boot) is unchanged.
    pub pci_devices: bool,
    pub storage: StorageConfig,
}

/// Sniff the guest architecture from the kernel image: the ARM64 `Image`
/// magic, or an ELF `e_machine`. Returns None when the format is unknown
/// (e.g. an x86 bzImage), letting the caller fall back to the default.
fn detect_arch_from_kernel(kernel: &Path) -> Option<ArchKind> {
    use std::io::Read;

    let mut head = [0u8; 64];
    let mut f = std::fs::File::open(kernel).ok()?;
    let n = f.read(&mut head).ok()?;
    let head = &head[..n];

    // ARM64 Linux Image: "ARM\x64" magic at offset 56.
    if n >= 60 && u32::from_le_bytes(head[56..60].try_into().unwrap()) == 0x644D_5241 {
        return Some(ArchKind::Aarch64);
    }
    if head.starts_with(b"\x7fELF") && n >= 20 {
        return match u16::from_le_bytes(head[18..20].try_into().unwrap()) {
            62 => Some(ArchKind::X86_64),
            183 => Some(ArchKind::Aarch64),
            243 => Some(ArchKind::Riscv64),
            164 => Some(ArchKind::Hexagon),
            40 => Some(ArchKind::Armv7a),
            _ => None,
        };
    }
    None
}

/// Pick a backend suited to the guest architecture when none was requested.
/// AArch64 defaults to the software emulator everywhere; on Apple Silicon,
/// `--backend hvf` selects near-native Hypervisor.framework instead.
fn default_backend_for(arch: ArchKind) -> BackendKind {
    match arch {
        ArchKind::X86_64 => BackendKind::default(),
        _ => BackendKind::Emulator,
    }
}

impl VmConfig {
    pub fn from_sources(cli: CliConfig, file: Option<FileConfig>) -> Result<Self> {
        let file = file.unwrap_or_default();
        let storage = StorageConfig::from_sources(&cli, &file)?;
        let pci_devices = cli.pci_devices || file.pci_devices.unwrap_or(storage.has_images());
        let kernel = cli
            .kernel
            .or(file.kernel)
            .ok_or_else(|| Error::InvalidConfig("kernel path is required".to_string()))?;
        let arch = cli
            .arch
            .or(file.arch)
            .or_else(|| {
                let detected = detect_arch_from_kernel(&kernel);
                if let Some(a) = detected {
                    tracing::info!(arch = ?a, "auto-detected guest architecture from kernel image");
                }
                detected
            })
            .unwrap_or_default();
        let backend = cli
            .backend
            .or(file.backend)
            .unwrap_or_else(|| default_backend_for(arch));
        let memory = cli.memory.or(file.memory).unwrap_or_default();
        let vcpus = cli.vcpus.or(file.vcpus).unwrap_or(DEFAULT_VCPUS);
        let initrd = cli.initrd.or(file.initrd);
        let cmdline = cli.cmdline.or(file.cmdline).unwrap_or_else(|| {
            match arch {
                ArchKind::Aarch64 => DEFAULT_CMDLINE_AARCH64,
                _ => DEFAULT_CMDLINE,
            }
            .to_string()
        });
        // Hexagon options
        let hexagon_isa = cli.hexagon_isa.or(file.hexagon_isa).unwrap_or_default();
        let hexagon_endian = cli
            .hexagon_endian
            .or(file.hexagon_endian)
            .unwrap_or_default();
        let hexagon_entry = cli.hexagon_entry.or(file.hexagon_entry);
        let hexagon_load_addr = cli.hexagon_load_addr.or(file.hexagon_load_addr);
        // ARM options
        let aarch64_isa = cli.aarch64_isa.or(file.aarch64_isa).unwrap_or_default();
        let aarch32_isa = cli.aarch32_isa.or(file.aarch32_isa).unwrap_or_default();
        let cortexm_isa = cli.cortexm_isa.or(file.cortexm_isa).unwrap_or_default();
        let cortexr_isa = cli.cortexr_isa.or(file.cortexr_isa).unwrap_or_default();
        let arm_entry = cli.arm_entry.or(file.arm_entry);
        let arm_load_addr = cli.arm_load_addr.or(file.arm_load_addr);
        let arm_dtb = cli.arm_dtb.or(file.arm_dtb);

        let config = VmConfig {
            arch,
            backend,
            memory,
            vcpus,
            kernel,
            initrd,
            cmdline,
            hexagon_isa,
            hexagon_endian,
            hexagon_entry,
            hexagon_load_addr,
            aarch64_isa,
            aarch32_isa,
            cortexm_isa,
            cortexr_isa,
            arm_entry,
            arm_load_addr,
            arm_dtb,
            trace: cli.trace,
            gdb_port: cli.gdb_port,
            wait_gdb: cli.wait_gdb,
            snapshot_interval: cli.snapshot_interval,
            snapshot_at: cli.snapshot_at,
            snapshot_dir: cli.snapshot_dir,
            resume: cli.resume,
            checkpoint: cli.checkpoint,
            snapshot_out: cli.snapshot_out,
            profile: cli.profile,
            profile_output: cli.profile_output,
            profile_interval: cli.profile_interval,
            pci_devices,
            storage,
        };

        config.validate()?;
        Ok(config)
    }

    /// Build a config to resume a machine from a checkpoint's embedded config,
    /// applying CLI overrides (CLI takes precedence over the embedded values).
    ///
    /// Unlike [`from_sources`](Self::from_sources) this does NOT require the
    /// kernel/initrd to exist on disk: the entire machine image is restored from
    /// the checkpoint, so the embedded kernel path is informational only. The
    /// user may still override any field (memory size, cmdline, even the arch)
    /// — including in ways that will not work — which is intentional.
    pub fn from_checkpoint(
        cp: CheckpointConfig,
        cli: CliConfig,
        checkpoint_memory_size: u64,
    ) -> Result<Self> {
        Self::from_checkpoint_inner(cp, cli, checkpoint_memory_size, false)
    }

    /// Resolve recorded configuration with CLI overrides while admitting image
    /// metadata only when the bundle represents complete PCI endpoint/media state.
    pub fn from_checkpoint_bundle(
        bundle: &crate::vm::snapshot::SnapshotBundle,
        cli: CliConfig,
    ) -> Result<Self> {
        let base = bundle.base();
        base.validate_for_restore()?;
        Self::from_checkpoint_inner(
            base.config.clone(),
            cli,
            base.memory_size,
            bundle.pci().is_some_and(|p| p.has_endpoints()),
        )
    }
    fn from_checkpoint_inner(
        cp: CheckpointConfig,
        cli: CliConfig,
        checkpoint_memory_size: u64,
        stored_media: bool,
    ) -> Result<Self> {
        if cp.memory_bytes != checkpoint_memory_size {
            return Err(Error::InvalidConfig(format!(
                "checkpoint config memory_bytes ({}) does not match snapshot memory_size ({})",
                cp.memory_bytes, checkpoint_memory_size
            )));
        }

        let storage = StorageConfig::from_checkpoint(&cp.storage, &cli)?;
        let config = VmConfig {
            arch: cli.arch.unwrap_or(cp.arch),
            backend: cli.backend.unwrap_or(cp.backend),
            memory: cli.memory.unwrap_or(MemorySize(cp.memory_bytes)),
            vcpus: cli.vcpus.unwrap_or(cp.vcpus),
            kernel: cli.kernel.unwrap_or(cp.kernel),
            initrd: cli.initrd.or(cp.initrd),
            cmdline: cli.cmdline.unwrap_or(cp.cmdline),
            hexagon_isa: cli.hexagon_isa.unwrap_or(cp.hexagon_isa),
            hexagon_endian: cli.hexagon_endian.unwrap_or(cp.hexagon_endian),
            hexagon_entry: cli.hexagon_entry.or(cp.hexagon_entry.map(Address)),
            hexagon_load_addr: cli.hexagon_load_addr.or(cp.hexagon_load_addr.map(Address)),
            aarch64_isa: cli.aarch64_isa.unwrap_or(cp.aarch64_isa),
            aarch32_isa: cli.aarch32_isa.unwrap_or(cp.aarch32_isa),
            cortexm_isa: cli.cortexm_isa.unwrap_or(cp.cortexm_isa),
            cortexr_isa: cli.cortexr_isa.unwrap_or(cp.cortexr_isa),
            arm_entry: cli.arm_entry.or(cp.arm_entry.map(Address)),
            arm_load_addr: cli.arm_load_addr.or(cp.arm_load_addr.map(Address)),
            arm_dtb: cli.arm_dtb.or(cp.arm_dtb),
            trace: cli.trace,
            gdb_port: cli.gdb_port,
            wait_gdb: cli.wait_gdb,
            snapshot_interval: cli.snapshot_interval,
            snapshot_at: cli.snapshot_at,
            snapshot_dir: cli.snapshot_dir,
            resume: cli.resume,
            checkpoint: cli.checkpoint,
            snapshot_out: cli.snapshot_out,
            profile: cli.profile,
            profile_output: cli.profile_output,
            profile_interval: cli.profile_interval,
            pci_devices: cli.pci_devices || cp.pci_devices || storage.has_images(),
            storage,
        };
        config.validate_inner(false, stored_media)?;
        Ok(config)
    }

    /// Capture the machine-defining portion of this config for embedding in a
    /// checkpoint.
    pub fn to_checkpoint(&self) -> CheckpointConfig {
        CheckpointConfig {
            arch: self.arch,
            backend: self.backend,
            memory_bytes: self.memory.bytes(),
            vcpus: self.vcpus,
            kernel: self.kernel.clone(),
            initrd: self.initrd.clone(),
            cmdline: self.cmdline.clone(),
            hexagon_isa: self.hexagon_isa,
            hexagon_endian: self.hexagon_endian,
            hexagon_entry: self.hexagon_entry.map(|a| a.raw()),
            hexagon_load_addr: self.hexagon_load_addr.map(|a| a.raw()),
            aarch64_isa: self.aarch64_isa,
            aarch32_isa: self.aarch32_isa,
            cortexm_isa: self.cortexm_isa,
            cortexr_isa: self.cortexr_isa,
            arm_entry: self.arm_entry.map(|a| a.raw()),
            arm_load_addr: self.arm_load_addr.map(|a| a.raw()),
            arm_dtb: self.arm_dtb.clone(),
            pci_devices: self.pci_devices,
            storage: self.storage.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_inner(true, false)
    }

    /// Validate a config used to resume from a checkpoint. Identical to
    /// [`validate`](Self::validate) except it does NOT require the kernel/initrd
    /// files to exist on disk — when resuming, the machine image (including the
    /// kernel that was loaded into RAM) comes from the checkpoint itself.
    pub fn validate_resume(&self) -> Result<()> {
        self.validate_inner(false, false)
    }

    /// Validate resume configuration without requiring source paths when the
    /// actual bundle contains the represented endpoint/media state.
    pub fn validate_resume_bundle(
        &self,
        bundle: &crate::vm::snapshot::SnapshotBundle,
    ) -> Result<()> {
        bundle.base().validate_for_restore()?;
        self.validate_inner(false, bundle.pci().is_some_and(|p| p.has_endpoints()))?;
        let base = bundle.base();
        if self.arch != base.config.arch {
            return Err(Error::InvalidConfig(
                "checkpoint architecture does not match target machine".to_string(),
            ));
        }
        // validate_inner already checked overflow and the supported byte limit.
        let allocated =
            crate::vm::memory::align_up(self.memory.bytes(), crate::vm::memory::PAGE_SIZE);
        if allocated != base.memory_size {
            return Err(Error::InvalidConfig(
                "checkpoint RAM extent does not match target machine".to_string(),
            ));
        }
        if self.vcpus != base.config.vcpus {
            return Err(Error::InvalidConfig(
                "checkpoint CPU count does not match target machine".to_string(),
            ));
        }
        if self.pci_devices != base.config.pci_devices {
            return Err(Error::InvalidConfig(
                "checkpoint PCI topology does not match target machine".to_string(),
            ));
        }
        for (source, target) in [
            (&base.config.storage.nvme, &self.storage.nvme),
            (&base.config.storage.ahci, &self.storage.ahci),
        ] {
            match (source, target) {
                (None, None) => (),
                (Some(s), Some(t)) if s.identity == t.identity && s.mode == t.mode => (),
                _ => {
                    return Err(Error::InvalidConfig(
                        "checkpoint storage binding does not match target machine".to_string(),
                    ));
                }
            }
        }
        if bundle.physical_memory().is_some()
            && (self.arch == ArchKind::X86_64) != bundle.pci().is_some()
        {
            return Err(Error::InvalidConfig(
                "checkpoint PCI component does not match target machine".to_string(),
            ));
        }
        Ok(())
    }
    fn validate_inner(&self, check_files: bool, stored_media: bool) -> Result<()> {
        self.storage.validate_metadata()?;
        if self.storage.has_images() && (self.arch != ArchKind::X86_64 || !self.pci_devices) {
            return Err(Error::InvalidConfig(
                "configured NVMe/AHCI images require x86 PCI devices".to_string(),
            ));
        }
        if !check_files && self.storage.has_images() && !stored_media {
            return Err(Error::InvalidConfig(
                "image-backed checkpoint resume requires complete device/media state".to_string(),
            ));
        }
        if self.vcpus == 0 {
            return Err(Error::InvalidConfig("vcpus must be at least 1".to_string()));
        }
        let min_mem_bytes = MIN_MEM_MIB << 20;
        if self.memory.bytes() < min_mem_bytes {
            return Err(Error::InvalidConfig(format!(
                "memory must be at least {MIN_MEM_MIB} MiB"
            )));
        }
        validate_guest_memory_size(self.memory.bytes())?;
        if check_files && !self.kernel.exists() {
            return Err(Error::InvalidConfig(format!(
                "kernel not found: {}",
                self.kernel.display()
            )));
        }
        if check_files {
            if let Some(initrd) = &self.initrd {
                if !initrd.exists() {
                    return Err(Error::InvalidConfig(format!(
                        "initrd not found: {}",
                        initrd.display()
                    )));
                }
            }
        }
        if self.arch == ArchKind::Hexagon && self.backend == BackendKind::Kvm {
            return Err(Error::InvalidConfig(
                "hexagon is only supported with the emulator backend".to_string(),
            ));
        }
        if self.arch == ArchKind::Hexagon && self.backend == BackendKind::Hvf {
            return Err(Error::InvalidConfig(
                "hexagon is only supported with the emulator backend".to_string(),
            ));
        }
        // ARM architecture validation
        match self.arch {
            ArchKind::Aarch64 => {
                // Aarch64 can use HVF on Apple Silicon, or emulator everywhere
                if self.backend == BackendKind::Kvm {
                    return Err(Error::InvalidConfig(
                        "aarch64 with KVM is not yet implemented".to_string(),
                    ));
                }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                if self.backend == BackendKind::Hvf {
                    return Err(Error::InvalidConfig(
                        "HVF for aarch64 guests requires Apple Silicon (ARM64 Mac)".to_string(),
                    ));
                }
            }
            ArchKind::Armv7a | ArchKind::Armv8a32 | ArchKind::CortexM | ArchKind::CortexR => {
                // 32-bit ARM variants only support emulator for now
                if self.backend != BackendKind::Emulator {
                    return Err(Error::InvalidConfig(format!(
                        "{:?} is only supported with the emulator backend",
                        self.arch
                    )));
                }
            }
            ArchKind::Riscv64 => {
                if self.backend != BackendKind::Emulator {
                    return Err(Error::InvalidConfig(
                        "riscv64 is only supported with the emulator backend".to_string(),
                    ));
                }
            }
            _ => {}
        }
        // HVF backend architecture validation
        if self.backend == BackendKind::Hvf {
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            if self.arch != ArchKind::X86_64 {
                return Err(Error::InvalidConfig(
                    "HVF on Intel Mac only supports x86_64 guests".to_string(),
                ));
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if self.arch != ArchKind::Aarch64 {
                return Err(Error::InvalidConfig(
                    "HVF on Apple Silicon only supports aarch64 guests".to_string(),
                ));
            }
        }
        if self.arch == ArchKind::Hexagon {
            let mem_bytes = self.memory.bytes();
            if mem_bytes > (u32::MAX as u64 + 1) {
                return Err(Error::InvalidConfig(
                    "hexagon guest memory must not exceed 4 GiB".to_string(),
                ));
            }
            if let Some(addr) = self.hexagon_load_addr {
                if addr.raw() >= mem_bytes {
                    return Err(Error::InvalidConfig(format!(
                        "hexagon load address {:#x} outside guest memory",
                        addr.raw()
                    )));
                }
            }
            if let Some(entry) = self.hexagon_entry {
                if entry.raw() >= mem_bytes {
                    return Err(Error::InvalidConfig(format!(
                        "hexagon entry address {:#x} outside guest memory",
                        entry.raw()
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The machine-defining configuration embedded in a checkpoint so it can be
/// resumed self-contained (`rax --checkpoint file.rxc`). Uses primitive field
/// types (plain `u64` rather than [`MemorySize`]/[`Address`]) so it serializes
/// cleanly through bincode, which cannot handle the `deserialize_any`-based
/// human-friendly parsers those types use for TOML/CLI input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointConfig {
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
    /// Recreate the optional PCI device topology when resuming.
    #[serde(default)]
    pub pci_devices: bool,
    #[serde(default)]
    pub storage: StorageConfig,
}

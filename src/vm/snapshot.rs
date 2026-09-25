//! Full VM checkpoint (save / restore / resume).
//!
//! A checkpoint is a *self-contained* image of the running machine, written to
//! a `.rxc` file. It captures everything needed to bring the machine back up
//! exactly where it left off, on a host that no longer has the original kernel
//! image:
//!   - the embedded [`CheckpointConfig`] (arch, memory size, vcpus, cmdline …)
//!     so `rax --checkpoint file.rxc` can rebuild the machine with no other
//!     flags (and the user may override any of it),
//!   - the full CPU register file + emulator-specific state (lazy flags, FPU,
//!     kernel_gs_base, IA32_TSC_ADJUST, IA32_TSC_AUX, IA32_MISC_ENABLE,
//!     IA32_PAT, IA32_UMWAIT_CONTROL, PKRU, halted),
//!   - the complete writable guest RAM (zstd compressed) — which also contains
//!     the kernel/initrd that were loaded into it, so read-only images need not
//!     be shipped separately,
//!   - all stateful device models (PIC, PIT, UART, Local APIC).
//!
//! The format is intentionally versioned and magic-tagged; older `.snap` files
//! (CPU + memory only, no devices/config) are a different magic and are
//! rejected with a clear error.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::CheckpointConfig;
use crate::devices::lapic::LocalApic;
use crate::devices::pic::DualPic;
use crate::devices::pit::Pit;
use crate::devices::serial::Serial16550;
use crate::error::{Error, Result};
use crate::vm::memory::validate_guest_memory_size;
use crate::vm::vcpu::state::CpuState;

/// Magic number for checkpoint files: "RAXCKPT\0"
const CHECKPOINT_MAGIC: [u8; 8] = *b"RAXCKPT\0";

/// Current checkpoint format version. Version 2 added embedded config + device
/// state; version 3 added the emulator-private STI interrupt shadow; version 4
/// added IA32_MISC_ENABLE and IA32_PAT; version 5 added IA32_UMWAIT_CONTROL;
/// version 6 stores the x87 registers in their exact 80-bit encoding.
const CHECKPOINT_VERSION: u32 = 6;

/// Canonical checkpoint file extension ("RaX Checkpoint").
pub const CHECKPOINT_EXT: &str = "rxc";

/// Default checkpoint filename, relative to the working directory, used when no
/// `--snapshot-out` path is given.
pub const DEFAULT_CHECKPOINT_FILE: &str = "checkpoint.rxc";

/// x87 FPU state for snapshots
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FpuSnapshot {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u16,
    pub data_ptr: u64,
    pub instr_ptr: u64,
    pub last_opcode: u16,
    /// Physical registers R0-R7 in the exact 80-bit memory encoding.
    pub st: [[u8; 10]; 8],
    pub top: u8,
}

impl Default for FpuSnapshot {
    fn default() -> Self {
        FpuSnapshot {
            control_word: 0x037F,
            status_word: 0,
            tag_word: 0xFFFF,
            data_ptr: 0,
            instr_ptr: 0,
            last_opcode: 0,
            st: [[0; 10]; 8],
            top: 0,
        }
    }
}

/// Lazy flags state for snapshots
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LazyFlagsSnapshot {
    /// 0=None, 1=Add, 2=Sub, 3=Logic, 4=Inc, 5=Dec
    pub op: u8,
    pub result: u64,
    pub src: u64,
    pub dst: u64,
    pub size: u8,
}

impl Default for LazyFlagsSnapshot {
    fn default() -> Self {
        LazyFlagsSnapshot {
            op: 0, // None
            result: 0,
            src: 0,
            dst: 0,
            size: 4,
        }
    }
}

/// Extended CPU state specific to the emulator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmulatorState {
    pub fpu: FpuSnapshot,
    pub lazy_flags: LazyFlagsSnapshot,
    pub kernel_gs_base: u64,
    #[serde(default)]
    pub tsc_adjust: u64,
    #[serde(default)]
    pub tsc_aux: u32,
    #[serde(default = "default_misc_enable")]
    pub misc_enable: u64,
    #[serde(default = "default_pat")]
    pub pat: u64,
    #[serde(default)]
    pub umwait_control: u64,
    pub pkru: u32,
    #[serde(default = "default_mxcsr")]
    pub mxcsr: u32,
    pub halted: bool,
    /// Emulator-private STI interrupt shadow.
    #[serde(default)]
    pub interrupt_inhibit: bool,
}

fn default_mxcsr() -> u32 {
    0x1F80
}

fn default_misc_enable() -> u64 {
    crate::isa::x86_64::execute::system::IA32_MISC_ENABLE_RESET
}

fn default_pat() -> u64 {
    crate::isa::x86_64::execute::system::IA32_PAT_RESET
}

impl Default for EmulatorState {
    fn default() -> Self {
        EmulatorState {
            fpu: FpuSnapshot::default(),
            lazy_flags: LazyFlagsSnapshot::default(),
            kernel_gs_base: 0,
            tsc_adjust: 0,
            tsc_aux: 0,
            misc_enable: default_misc_enable(),
            pat: default_pat(),
            umwait_control: 0,
            pkru: 0,
            mxcsr: default_mxcsr(),
            halted: false,
            interrupt_inhibit: false,
        }
    }
}

/// Snapshot of all stateful device models. Devices implement `Serialize` /
/// `Deserialize` directly; transient host-only fields (e.g. the LAPIC's
/// wall-clock `Instant`) are `#[serde(skip)]` and re-derived on restore.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceState {
    /// Dual i8259 PIC (master + slave): IRR/ISR/IMR, init state, priority.
    pub pic: DualPic,
    /// i8254 PIT: all three channels, modes, reload values, timing refs.
    pub pit: Pit,
    /// 16550 UART: registers, FIFOs, staged input, interrupt state.
    pub serial: Serial16550,
    /// Local APIC: registers, LVT, timer counts, pending IPI/NMI.
    pub lapic: LocalApic,
}

/// Complete, self-contained VM checkpoint.
#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    /// Checkpoint format version
    pub version: u32,
    /// The machine-defining config, so the checkpoint resumes self-contained.
    pub config: CheckpointConfig,
    /// Instruction count when the checkpoint was taken
    pub instruction_count: u64,
    /// Wall-clock nanoseconds elapsed (`timing::elapsed_nanos`) at capture, so
    /// the resumed machine's real-time TSC/timers continue monotonically.
    pub elapsed_nanos: u64,
    /// CPU state (GPRs, segment/control/debug regs, SIMD, …)
    pub cpu_state: CpuState,
    /// Extended emulator state (lazy flags, FPU, kernel_gs_base, IA32_TSC_AUX, PKRU, halted)
    pub emulator_state: EmulatorState,
    /// Device state (PIC/PIT/UART/LAPIC)
    pub devices: DeviceState,
    /// Reported guest memory size in bytes (uncompressed)
    pub memory_size: u64,
    /// Compressed guest RAM (zstd)
    pub memory_data: Vec<u8>,
}

impl Snapshot {
    /// Create a new checkpoint from current VM state.
    pub fn new(
        config: CheckpointConfig,
        instruction_count: u64,
        elapsed_nanos: u64,
        cpu_state: CpuState,
        emulator_state: EmulatorState,
        devices: DeviceState,
        memory: &[u8],
    ) -> Result<Self> {
        // Compress memory with zstd (level 3 for a good speed/ratio balance;
        // mostly-zero guest RAM compresses extremely well).
        let compressed = zstd::encode_all(memory, 3)
            .map_err(|e| Error::Emulator(format!("Failed to compress memory: {}", e)))?;

        Ok(Snapshot {
            version: CHECKPOINT_VERSION,
            config,
            instruction_count,
            elapsed_nanos,
            cpu_state,
            emulator_state,
            devices,
            memory_size: memory.len() as u64,
            memory_data: compressed,
        })
    }

    /// Save snapshot to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let file = File::create(path.as_ref())
            .map_err(|e| Error::Emulator(format!("Failed to create snapshot file: {}", e)))?;
        let mut writer = BufWriter::new(file);

        // Write magic number
        writer
            .write_all(&CHECKPOINT_MAGIC)
            .map_err(|e| Error::Emulator(format!("Failed to write snapshot magic: {}", e)))?;

        // Serialize snapshot with bincode
        bincode::serialize_into(&mut writer, self)
            .map_err(|e| Error::Emulator(format!("Failed to serialize snapshot: {}", e)))?;

        writer
            .flush()
            .map_err(|e| Error::Emulator(format!("Failed to flush snapshot: {}", e)))?;

        Ok(())
    }

    /// Load snapshot from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .map_err(|e| Error::Emulator(format!("Failed to open snapshot file: {}", e)))?;
        let mut reader = BufReader::new(file);

        // Verify magic number
        let mut magic = [0u8; 8];
        reader
            .read_exact(&mut magic)
            .map_err(|e| Error::Emulator(format!("Failed to read snapshot magic: {}", e)))?;

        if magic != CHECKPOINT_MAGIC {
            // Reject the legacy "RAXSNAP\0" (CPU+memory only) format and anything
            // else with a clear, specific message.
            if &magic == b"RAXSNAP\0" {
                return Err(Error::Emulator(
                    "this is a legacy .snap snapshot (no device/config state); \
                     it cannot be resumed as a full checkpoint"
                        .to_string(),
                ));
            }
            return Err(Error::Emulator(
                "not a rax checkpoint file (bad magic)".to_string(),
            ));
        }

        // Deserialize snapshot
        let snapshot: Snapshot = bincode::deserialize_from(&mut reader)
            .map_err(|e| Error::Emulator(format!("Failed to deserialize checkpoint: {}", e)))?;

        if snapshot.version != CHECKPOINT_VERSION {
            return Err(Error::Emulator(format!(
                "Unsupported checkpoint version {} (expected {})",
                snapshot.version, CHECKPOINT_VERSION
            )));
        }
        snapshot.validate_memory_metadata()?;

        Ok(snapshot)
    }

    pub fn validate_memory_metadata(&self) -> Result<()> {
        if self.config.memory_bytes != self.memory_size {
            return Err(Error::InvalidConfig(format!(
                "checkpoint config memory_bytes ({}) does not match snapshot memory_size ({})",
                self.config.memory_bytes, self.memory_size
            )));
        }
        validate_guest_memory_size(self.memory_size)
    }

    /// Decompress and return memory contents
    pub fn decompress_memory(&self) -> Result<Vec<u8>> {
        self.validate_memory_metadata()?;
        let capacity = usize::try_from(self.memory_size).map_err(|_| {
            Error::InvalidConfig("checkpoint memory does not fit in host address size".to_string())
        })?;
        let mut decompressed = Vec::with_capacity(capacity);
        zstd::stream::copy_decode(&self.memory_data[..], &mut decompressed)
            .map_err(|e| Error::Emulator(format!("Failed to decompress memory: {}", e)))?;

        if decompressed.len() as u64 != self.memory_size {
            return Err(Error::Emulator(format!(
                "Memory size mismatch: expected {} bytes, got {}",
                self.memory_size,
                decompressed.len()
            )));
        }

        Ok(decompressed)
    }

    /// Get a summary string for display
    pub fn summary(&self) -> String {
        let mem_mb = self.memory_size / (1024 * 1024);
        let compressed_mb = self.memory_data.len() / (1024 * 1024);
        let ratio = if self.memory_data.is_empty() {
            0.0
        } else {
            self.memory_size as f64 / self.memory_data.len() as f64
        };

        format!(
            "checkpoint @ insn #{}: {:?} {}vCPU, {}MB RAM ({}MB compressed, {:.1}x), devices+config embedded",
            self.instruction_count,
            self.config.arch,
            self.config.vcpus,
            mem_mb,
            compressed_mb,
            ratio
        )
    }
}

/// Configuration for automatic snapshotting
#[derive(Clone, Debug)]
pub struct SnapshotConfig {
    /// Take snapshot every N instructions (0 = disabled)
    pub interval: u64,
    /// Take snapshot at specific instruction counts
    pub at_instructions: Vec<u64>,
    /// Directory to save snapshots
    pub output_dir: String,
    /// Prefix for snapshot filenames
    pub prefix: String,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        SnapshotConfig {
            interval: 0,
            at_instructions: Vec::new(),
            output_dir: ".".to_string(),
            prefix: "snapshot".to_string(),
        }
    }
}

impl SnapshotConfig {
    /// Check if a snapshot should be taken at the given instruction count
    pub fn should_snapshot(&self, insn_count: u64) -> bool {
        // Check interval
        if self.interval > 0 && insn_count > 0 && insn_count % self.interval == 0 {
            return true;
        }
        // Check specific instruction counts
        self.at_instructions.contains(&insn_count)
    }

    /// Generate filename for a snapshot at the given instruction count
    pub fn filename(&self, insn_count: u64) -> String {
        format!(
            "{}/{}_{:012}.{}",
            self.output_dir, self.prefix, insn_count, CHECKPOINT_EXT
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint_config(memory_bytes: u64) -> CheckpointConfig {
        use crate::config::{ArchKind, BackendKind, Endianness, HexagonIsa};
        CheckpointConfig {
            arch: ArchKind::X86_64,
            backend: BackendKind::Emulator,
            memory_bytes,
            vcpus: 1,
            kernel: std::path::PathBuf::from("/some/vmlinux"),
            initrd: Some(std::path::PathBuf::from("/some/initrd.cpio")),
            cmdline: "console=ttyS0 root=/dev/ram0".to_string(),
            hexagon_isa: HexagonIsa::V68,
            hexagon_endian: Endianness::Little,
            hexagon_entry: None,
            hexagon_load_addr: None,
            aarch64_isa: Default::default(),
            aarch32_isa: Default::default(),
            cortexm_isa: Default::default(),
            cortexr_isa: Default::default(),
            arm_entry: None,
            arm_load_addr: None,
            arm_dtb: None,
        }
    }

    fn snapshot_with_memory_metadata(config_memory_bytes: u64, memory_size: u64) -> Snapshot {
        crate::vm::timing::init();
        Snapshot {
            version: CHECKPOINT_VERSION,
            config: checkpoint_config(config_memory_bytes),
            instruction_count: 0,
            elapsed_nanos: 0,
            cpu_state: CpuState::x86_64(Default::default(), Default::default()),
            emulator_state: EmulatorState::default(),
            devices: DeviceState {
                pic: DualPic::new(),
                pit: Pit::new(),
                serial: Serial16550::new(0x3f8),
                lapic: LocalApic::new(0),
            },
            memory_size,
            memory_data: Vec::new(),
        }
    }

    #[test]
    fn device_state_bincode_roundtrip() {
        crate::vm::timing::init();
        let devices = DeviceState {
            pic: DualPic::new(),
            pit: Pit::new(),
            serial: Serial16550::new(0x3f8),
            lapic: LocalApic::new(0),
        };
        let bytes = bincode::serialize(&devices).expect("serialize device state");
        let back: DeviceState = bincode::deserialize(&bytes).expect("deserialize device state");
        // Re-serializing the round-tripped value must reproduce the same bytes:
        // proves every field (and the #[serde(skip)] LAPIC Instant) is stable.
        let bytes2 = bincode::serialize(&back).expect("re-serialize device state");
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn checkpoint_config_bincode_roundtrip() {
        let cp = checkpoint_config(512 << 20);
        let bytes = bincode::serialize(&cp).expect("serialize checkpoint config");
        let back: CheckpointConfig = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(back.memory_bytes, cp.memory_bytes);
        assert_eq!(back.cmdline, cp.cmdline);
        assert_eq!(back.arch, cp.arch);
        assert_eq!(back.backend, cp.backend);
    }

    #[test]
    fn emulator_state_bincode_roundtrip_preserves_interrupt_and_model_msr_state() {
        let state = EmulatorState {
            interrupt_inhibit: true,
            misc_enable: 0x0000_0004_0004_1801,
            pat: 0x0706_0504_0100_0706,
            umwait_control: 0x0000_0000_0001_86A0,
            ..EmulatorState::default()
        };
        let bytes = bincode::serialize(&state).expect("serialize emulator state");
        let back: EmulatorState = bincode::deserialize(&bytes).expect("deserialize emulator state");
        assert!(back.interrupt_inhibit);
        assert_eq!(back.misc_enable, state.misc_enable);
        assert_eq!(back.pat, state.pat);
        assert_eq!(back.umwait_control, state.umwait_control);
    }

    #[test]
    fn snapshot_rejects_config_memory_size_mismatch() {
        let snapshot = snapshot_with_memory_metadata(512 << 20, 256 << 20);
        let err = snapshot.validate_memory_metadata().unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match snapshot memory_size")
        );
    }

    #[test]
    fn snapshot_rejects_oversized_memory_metadata() {
        let memory_size = crate::vm::memory::MAX_GUEST_MEMORY_BYTES + crate::vm::memory::PAGE_SIZE;
        let snapshot = snapshot_with_memory_metadata(memory_size, memory_size);
        let err = snapshot.validate_memory_metadata().unwrap_err();
        assert!(err.to_string().contains("guest memory must not exceed"));
    }

    #[test]
    fn test_snapshot_config() {
        let mut config = SnapshotConfig::default();
        config.interval = 1000;
        config.at_instructions = vec![500, 1500];

        assert!(!config.should_snapshot(0));
        assert!(config.should_snapshot(500));
        assert!(config.should_snapshot(1000));
        assert!(config.should_snapshot(1500));
        assert!(config.should_snapshot(2000));
        assert!(!config.should_snapshot(1234));
    }
}

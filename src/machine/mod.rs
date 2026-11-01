//! Guest machine abstraction layer.
//!
//! A machine owns platform boot, RAM placement, and device wiring. Instruction
//! set semantics live under [`crate::isa`], while execution mechanisms live
//! under [`crate::backend`].

pub mod arm_virt;
pub mod fdt;
pub mod gsc;
pub mod hexagon_baremetal;
pub mod pc;
pub mod riscv_virt;
pub mod s3c64xx;
pub mod s5l8900;

// Compatibility aliases for the previous architecture-named machine modules.
pub use arm_virt as arm;
pub use hexagon_baremetal as hexagon;
pub use pc as x86_64;
pub use riscv_virt as riscv;

use std::sync::Arc;

use vm_memory::{GuestAddress, GuestMemoryMmap};

#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
use crate::backend::kvm::KvmVm;
use crate::config::{ArchKind, VmConfig};
use crate::devices::bus::{IoBus, MmioBus};
use crate::error::Result;
use crate::vm::vcpu::{CpuState, Registers, SystemRegisters};

// Re-export ARM boot info
pub use arm_virt::ArmBootInfo;

/// Boot information for x86_64 kernel loading.
pub struct X86_64BootInfo {
    pub entry_point: u64,
    pub boot_params_addr: GuestAddress,
    pub tss_addr: u64,
    pub identity_map_addr: u64,
    pub real_mode: Option<X86_64RealModeBootInfo>,
}

/// Per-VM real-mode BIOS state for x86_64 El-Torito boot.
pub struct X86_64RealModeBootInfo {
    pub sregs: SystemRegisters,
    pub regs: Registers,
    pub cdrom: Arc<Vec<u8>>,
    pub mem_bytes: u64,
}

/// Boot information for Hexagon bare-metal loading.
pub struct HexagonBootInfo {
    pub entry_point: u64,
    pub load_addr: u64,
    pub image_size: u64,
}

/// Boot information for RISC-V bare-metal loading.
pub struct RiscVBootInfo {
    pub entry_point: u64,
    pub load_addr: u64,
    pub image_size: u64,
    pub tohost_addr: Option<u64>,
}

/// Boot information returned after image loading.
pub enum BootInfo {
    X86_64(X86_64BootInfo),
    Hexagon(HexagonBootInfo),
    Arm(ArmBootInfo),
    RiscV(RiscVBootInfo),
}

impl BootInfo {
    pub fn entry_point(&self) -> u64 {
        match self {
            BootInfo::X86_64(info) => info.entry_point,
            BootInfo::Hexagon(info) => info.entry_point,
            BootInfo::Arm(info) => info.entry_point,
            BootInfo::RiscV(info) => info.entry_point,
        }
    }

    pub fn as_x86_64(&self) -> Option<&X86_64BootInfo> {
        match self {
            BootInfo::X86_64(info) => Some(info),
            _ => None,
        }
    }

    pub fn as_hexagon(&self) -> Option<&HexagonBootInfo> {
        match self {
            BootInfo::Hexagon(info) => Some(info),
            _ => None,
        }
    }

    pub fn as_arm(&self) -> Option<&ArmBootInfo> {
        match self {
            BootInfo::Arm(info) => Some(info),
            _ => None,
        }
    }

    pub fn as_riscv(&self) -> Option<&RiscVBootInfo> {
        match self {
            BootInfo::RiscV(info) => Some(info),
            _ => None,
        }
    }
}

/// Guest machine abstraction.
pub trait Machine: Send + Sync {
    /// Machine name.
    fn name(&self) -> &'static str;

    /// Set up machine-specific I/O devices.
    fn setup_devices(&self, io_bus: &mut IoBus, mmio_bus: &mut MmioBus) -> Result<()>;

    /// Additive ownership hook. Non-PC boards keep their existing setup path.
    fn setup_owned_devices(
        &self,
        io_bus: &mut IoBus,
        mmio_bus: &mut MmioBus,
    ) -> Result<Option<pc::PcDevices>> {
        self.setup_devices(io_bus, mmio_bus)?;
        Ok(None)
    }

    /// Load with the same machine-local devices returned by setup_owned_devices.
    fn load_kernel_with_devices(
        &self,
        mem: &GuestMemoryMmap,
        config: &VmConfig,
        _devices: Option<&pc::PcDevices>,
    ) -> Result<BootInfo> {
        self.load_kernel(mem, config)
    }

    /// Optional MMIO base for the serial device.
    fn serial_mmio_base(&self) -> Option<u64> {
        None
    }

    /// Optional IRQ line for the serial device.
    fn serial_irq(&self) -> Option<u32> {
        None
    }

    /// Guest physical address where platform RAM begins. x86 RAM starts at 0;
    /// ARM platforms place RAM above the device MMIO window.
    fn ram_base(&self) -> u64 {
        0
    }

    /// Load kernel and prepare boot environment.
    fn load_kernel(&self, mem: &GuestMemoryMmap, config: &VmConfig) -> Result<BootInfo>;

    /// Initialize VM-level state (IRQ chip, PIT, TSS, identity map).
    /// This is KVM-specific.
    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    fn init_vm(&self, vm: &KvmVm, boot: &BootInfo) -> Result<()>;

    /// Get initial CPU state for booting.
    /// Writes necessary structures (GDT, page tables) to guest memory
    /// and returns the initial CPU state.
    fn initial_cpu_state(&self, mem: &GuestMemoryMmap, boot: &BootInfo) -> Result<CpuState>;
}

/// Compatibility name retained while callers migrate from `arch` to
/// `machine` terminology.
pub use Machine as Arch;

/// Create a machine implementation from the legacy architecture selector.
pub fn from_arch_kind(kind: ArchKind) -> Box<dyn Machine> {
    match kind {
        ArchKind::X86_64 => Box::new(pc::PcMachine::new()),
        ArchKind::Hexagon => Box::new(hexagon_baremetal::HexagonBaremetalMachine::new()),
        ArchKind::Aarch64 => Box::new(arm_virt::Aarch64VirtMachine::new()),
        ArchKind::Armv7a => Box::new(arm_virt::Armv7aVirtMachine::new()),
        ArchKind::Armv8a32 => Box::new(arm_virt::Armv8a32VirtMachine::new()),
        ArchKind::CortexM => Box::new(arm_virt::CortexMMachine::new()),
        ArchKind::CortexR => Box::new(arm_virt::CortexRMachine::new()),
        ArchKind::Riscv64 => Box::new(riscv_virt::RiscvVirtMachine::new()),
    }
}

/// Compatibility factory retained for callers using the previous module API.
pub fn from_kind(kind: ArchKind) -> Box<dyn Machine> {
    from_arch_kind(kind)
}

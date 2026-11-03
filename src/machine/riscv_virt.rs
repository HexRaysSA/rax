//! RISC-V (RV64) virtual-machine integration: image loading and boot state.
//!
//! This wires the self-contained [`crate::isa::riscv`] interpreter into the VMM as a
//! bootable machine. It loads a flat binary or an ELF image into guest
//! memory and produces the initial register file (entry PC, stack pointer), and
//! exposes a 16550 UART at the RISC-V "virt" MMIO address for console output.

use std::fs::File;
use std::io::Read;

use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use crate::config::VmConfig;
use crate::devices::bus::{IoBus, MmioBus};
use crate::error::{Error, Result};
use crate::machine::{BootInfo, Machine, RiscVBootInfo};
use crate::vm::vcpu::{CpuState, RiscVRegisters};

/// 16550 UART MMIO base (matches the RISC-V "virt" machine convention).
const RISCV_UART_BASE: u64 = 0x1000_0000;
mod image;
pub(crate) mod startup;

pub struct RiscvVirtMachine;

impl RiscvVirtMachine {
    pub fn new() -> Self {
        RiscvVirtMachine
    }

    fn load_raw(mem: &GuestMemoryMmap, buf: &[u8]) -> Result<RiscVBootInfo> {
        crate::vm::memory::reservations::write(mem, 0, buf)?;
        Ok(RiscVBootInfo {
            entry_point: 0,
            load_addr: 0,
            image_size: buf.len() as u64,
            tohost_addr: None,
        })
    }
}

impl Machine for RiscvVirtMachine {
    fn name(&self) -> &'static str {
        "riscv64"
    }

    fn setup_devices(&self, _io_bus: &mut IoBus, _mmio_bus: &mut MmioBus) -> Result<()> {
        Ok(())
    }

    fn serial_mmio_base(&self) -> Option<u64> {
        Some(RISCV_UART_BASE)
    }

    fn load_kernel(&self, mem: &GuestMemoryMmap, config: &VmConfig) -> Result<BootInfo> {
        let mut file = File::open(&config.kernel)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        if buf.len() < 4 {
            return Err(Error::KernelLoad("image is too small".to_string()));
        }
        if std::env::var("RAX_MACHINE").as_deref() == Ok("gsc") {
            return Ok(BootInfo::RiscV(crate::machine::gsc::image::load(
                mem, &buf,
            )?));
        }
        let info = if buf.starts_with(b"\x7fELF") {
            Self::load_elf(mem, &buf)?
        } else {
            Self::load_raw(mem, &buf)?
        };
        Ok(BootInfo::RiscV(info))
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    fn init_vm(&self, _vm: &crate::backend::kvm::KvmVm, _boot: &BootInfo) -> Result<()> {
        Ok(())
    }

    fn initial_cpu_state(&self, mem: &GuestMemoryMmap, boot: &BootInfo) -> Result<CpuState> {
        let boot = boot
            .as_riscv()
            .ok_or_else(|| Error::InvalidConfig("expected riscv boot info".to_string()))?;

        let mut regs = RiscVRegisters::default();
        regs.pc = boot.entry_point;
        regs.tohost_addr = boot.tohost_addr;
        // Stack pointer (x2) at the top of guest RAM, 16-byte aligned.
        let mem_end = mem.last_addr().raw_value().saturating_add(1);
        regs.x[2] = mem_end.saturating_sub(16) & !0xf;
        Ok(CpuState::riscv(regs))
    }
}

// Compatibility name retained for the previous architecture terminology.
pub use RiscvVirtMachine as Riscv64Arch;

#[cfg(test)]
#[path = "riscv_virt/tests.rs"]
mod tests;

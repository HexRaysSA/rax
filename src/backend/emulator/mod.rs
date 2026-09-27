//! Software-emulation backend adapters.
//!
//! Instruction semantics live under [`crate::isa`]. This module selects the
//! appropriate adapter and exposes it through the architecture-neutral VM API.

pub mod aarch32;
pub mod aarch64;
pub mod armv6;
pub mod cortex_m;
pub mod gsc;
pub mod hexagon;
pub mod riscv;
pub mod s5l8900;
pub mod x86_64;

use std::any::Any;
use std::sync::Arc;

use vm_memory::GuestMemoryMmap;

use crate::config::{ArchKind, Endianness, HexagonIsa};
use crate::error::{Error, Result};
use crate::isa::hexagon::HexagonVcpu;
use crate::isa::riscv::RiscVConfig;
use crate::isa::x86_64::X86_64Vcpu;
use crate::machine::gsc::runtime::GscVcpu;
use crate::machine::s3c64xx::runtime::Armv6Vcpu;
use crate::machine::s5l8900::runtime::S5L8900Vcpu;
use crate::vm::vcpu::VCpu;

use super::{Backend, Vm};

/// Software emulator backend.
pub struct EmulatorBackend {
    arch: ArchKind,
    hexagon_isa: HexagonIsa,
    hexagon_endian: Endianness,
    riscv_config: Option<RiscVConfig>,
}

impl EmulatorBackend {
    pub fn new(arch: ArchKind, hexagon_isa: HexagonIsa, hexagon_endian: Endianness) -> Self {
        EmulatorBackend {
            arch,
            hexagon_isa,
            hexagon_endian,
            riscv_config: None,
        }
    }

    pub fn with_riscv_config(
        arch: ArchKind,
        hexagon_isa: HexagonIsa,
        hexagon_endian: Endianness,
        riscv_config: RiscVConfig,
    ) -> Self {
        EmulatorBackend {
            arch,
            hexagon_isa,
            hexagon_endian,
            riscv_config: Some(riscv_config),
        }
    }
}

impl Backend for EmulatorBackend {
    fn name(&self) -> &'static str {
        "emulator"
    }

    fn create_vm(&self) -> Result<Box<dyn Vm>> {
        Ok(Box::new(EmulatorVm::new(
            self.arch,
            self.hexagon_isa,
            self.hexagon_endian,
            self.riscv_config,
        )))
    }
}

/// Emulated VM instance.
pub struct EmulatorVm {
    irq_pending: std::sync::Mutex<Vec<u32>>,
    arch: ArchKind,
    hexagon_isa: HexagonIsa,
    hexagon_endian: Endianness,
    riscv_config: Option<RiscVConfig>,
}

impl EmulatorVm {
    pub fn new(
        arch: ArchKind,
        hexagon_isa: HexagonIsa,
        hexagon_endian: Endianness,
        riscv_config: Option<RiscVConfig>,
    ) -> Self {
        EmulatorVm {
            irq_pending: std::sync::Mutex::new(Vec::new()),
            arch,
            hexagon_isa,
            hexagon_endian,
            riscv_config,
        }
    }
}

impl Vm for EmulatorVm {
    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
        match self.arch {
            ArchKind::X86_64 => Ok(Box::new(X86_64Vcpu::new(id, mem))),
            ArchKind::Hexagon => Ok(Box::new(HexagonVcpu::new(
                id,
                mem,
                self.hexagon_isa,
                self.hexagon_endian,
            ))),
            ArchKind::Riscv64 => {
                if std::env::var("RAX_MACHINE").as_deref() == Ok("gsc") {
                    Ok(Box::new(GscVcpu::new(id, mem)))
                } else {
                    Ok(Box::new(riscv::RiscVVcpu::new_with_config(
                        id,
                        mem,
                        self.riscv_config.unwrap_or_else(RiscVConfig::rv64gc),
                    )))
                }
            }
            ArchKind::Aarch64 => Ok(Box::new(aarch64::Aarch64Vcpu::new(id, mem))),
            ArchKind::Armv7a => {
                if std::env::var("RAX_MACHINE").as_deref() == Ok("s5l8900") {
                    Ok(Box::new(S5L8900Vcpu::new(id, mem)))
                } else {
                    Ok(Box::new(Armv6Vcpu::new(id, mem)))
                }
            }
            _ => Err(Error::Emulator(format!(
                "Unsupported architecture: {:?}",
                self.arch
            ))),
        }
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        if level {
            let mut pending = self.irq_pending.lock().unwrap();
            if !pending.contains(&irq) {
                pending.push(irq);
            }
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

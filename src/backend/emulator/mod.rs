//! Software-emulation backend adapters.
//!
//! Instruction semantics live under [`crate::isa`]. This module selects the
//! appropriate adapter and exposes it through the architecture-neutral VM API.

pub mod aarch32;
pub mod aarch64;
pub mod armv6;
mod checkpoint_machine;
pub mod cortex_m;
pub mod ebpf;
pub mod gsc;
pub mod hexagon;
pub mod riscv;
pub mod s5l8900;
pub mod x86_64;
use checkpoint_machine::MachineFamily;

use std::any::Any;
use std::sync::{Arc, OnceLock};

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
    checkpoint_machine: Option<MachineFamily>,
}

impl EmulatorBackend {
    pub fn new(arch: ArchKind, hexagon_isa: HexagonIsa, hexagon_endian: Endianness) -> Self {
        EmulatorBackend {
            arch,
            hexagon_isa,
            hexagon_endian,
            riscv_config: None,
            checkpoint_machine: None,
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
            checkpoint_machine: None,
        }
    }

    pub(crate) fn for_checkpoint(
        mut self,
        contexts: Option<&crate::vm::snapshot::BackendContexts>,
    ) -> Result<Self> {
        self.checkpoint_machine = checkpoint_machine::family(self.arch, contexts)?;
        Ok(self)
    }
}

impl Backend for EmulatorBackend {
    fn name(&self) -> &'static str {
        "emulator"
    }

    fn create_vm(&self) -> Result<Box<dyn Vm>> {
        let mut vm = EmulatorVm::new(
            self.arch,
            self.hexagon_isa,
            self.hexagon_endian,
            self.riscv_config,
        );
        if let Some(machine) = self.checkpoint_machine {
            vm.machine = machine;
            vm.checkpoint_targets = matches!(machine, MachineFamily::Gsc | MachineFamily::S5l8900);
        }
        Ok(Box::new(vm))
    }
}

/// Emulated VM instance.
pub struct EmulatorVm {
    machine: MachineFamily,
    checkpoint_targets: bool,
    arm_cluster: OnceLock<Arc<aarch64::cluster::ArmCluster>>,
    created_cpus: std::sync::Mutex<Vec<u32>>,
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
            machine: MachineFamily::from_env(arch),
            checkpoint_targets: false,
            arm_cluster: OnceLock::new(),
            created_cpus: std::sync::Mutex::new(Vec::new()),
            irq_pending: std::sync::Mutex::new(Vec::new()),
            arch,
            hexagon_isa,
            hexagon_endian,
            riscv_config,
        }
    }
}

impl EmulatorVm {
    pub(crate) fn arm_cluster(&self) -> Option<Arc<aarch64::cluster::ArmCluster>> {
        self.arm_cluster.get().cloned()
    }
}

impl Vm for EmulatorVm {
    fn configure_cpu_topology(&self, count: u8, ram_end: u64) -> Result<()> {
        if self.arch != ArchKind::Aarch64 {
            return Ok(());
        }
        let created = self
            .created_cpus
            .lock()
            .map_err(|_| Error::Emulator("CPU topology lock poisoned".into()))?;
        if !created.is_empty() {
            return Err(Error::InvalidConfig(
                "CPU topology must precede vCPU creation".into(),
            ));
        }
        if self.arm_cluster.get().is_some() {
            return Err(Error::InvalidConfig(
                "CPU topology is already configured".into(),
            ));
        }
        self.arm_cluster
            .set(Arc::new(aarch64::cluster::ArmCluster::new(count, ram_end)?))
            .map_err(|_| Error::InvalidConfig("CPU topology was configured concurrently".into()))
    }
    fn take_cpu_power_requests(&self) -> Result<Vec<crate::vm::vcpu::CpuPowerRequest>> {
        match self.arm_cluster.get() {
            Some(cluster) => cluster.take_requests(),
            None => Ok(Vec::new()),
        }
    }
    fn complete_cpu_start(&self, id: u32) -> Result<()> {
        self.arm_cluster
            .get()
            .ok_or_else(|| Error::InvalidConfig("missing AArch64 topology".into()))?
            .complete_start(id)
    }

    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
        let mut created = self
            .created_cpus
            .lock()
            .map_err(|_| Error::Emulator("CPU topology lock poisoned".into()))?;
        if self.arm_cluster.get().is_some() && created.contains(&id) {
            return Err(Error::InvalidConfig("AArch64 CPU id already exists".into()));
        }
        let cpu: Result<Box<dyn VCpu>> = match self.arch {
            ArchKind::X86_64 => Ok(Box::new(X86_64Vcpu::new(id, mem))),
            ArchKind::Hexagon => Ok(Box::new(HexagonVcpu::new(
                id,
                mem,
                self.hexagon_isa,
                self.hexagon_endian,
            ))),
            ArchKind::Riscv64 => {
                if self.machine == MachineFamily::Gsc {
                    if self.checkpoint_targets {
                        Ok(Box::new(GscVcpu::new_checkpoint_target(id, mem)?))
                    } else {
                        Ok(Box::new(GscVcpu::new(id, mem)))
                    }
                } else {
                    Ok(Box::new(riscv::RiscVVcpu::new_with_config(
                        id,
                        mem,
                        self.riscv_config.unwrap_or_else(RiscVConfig::rv64gc),
                    )))
                }
            }
            ArchKind::Aarch64 => match self.arm_cluster.get() {
                Some(cluster) => Ok(Box::new(aarch64::Aarch64Vcpu::new_in_cluster(
                    id,
                    mem,
                    cluster.clone(),
                )?)),
                None => Ok(Box::new(aarch64::Aarch64Vcpu::new(id, mem))),
            },
            ArchKind::CortexM => Ok(Box::new(cortex_m::CortexMVcpu::new(id, mem))),
            ArchKind::Armv7a => {
                if self.machine == MachineFamily::S5l8900 {
                    if self.checkpoint_targets {
                        Ok(Box::new(S5L8900Vcpu::new_checkpoint_target(id, mem)?))
                    } else {
                        Ok(Box::new(S5L8900Vcpu::new(id, mem)))
                    }
                } else {
                    Ok(Box::new(Armv6Vcpu::new(id, mem)))
                }
            }
            _ => Err(Error::Emulator(format!(
                "Unsupported architecture: {:?}",
                self.arch
            ))),
        };
        if cpu.is_ok() {
            created.push(id);
        }
        cpu
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        if let Some(cluster) = self.arm_cluster.get() {
            return cluster.set_irq_line(irq, level);
        }
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

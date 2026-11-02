//! Backend abstraction layer.
//!
//! This module provides traits and factory functions for VM backends.

pub mod emulator;

// The native producer's binary format remains readable without a native SDK.
// Actual hardware capture and publication stay in the macOS backend.
#[path = "hvf/arm64_context_format.rs"]
pub(crate) mod arm64_hvf_context;
#[path = "hvf/arm64_power.rs"]
pub(crate) mod arm64_hvf_power;

#[path = "hvf/intel_context_format.rs"]
pub(crate) mod intel_hvf_context;
#[path = "hvf/native_deadline.rs"]
pub(crate) mod intel_hvf_deadline;
#[path = "hvf/intel_io.rs"]
pub(crate) mod intel_hvf_io;
#[path = "hvf/intel_projection.rs"]
pub(crate) mod intel_hvf_projection;
#[path = "hvf/intel_registers.rs"]
pub(crate) mod intel_hvf_registers;
#[path = "hvf/intel_xsave.rs"]
pub(crate) mod intel_hvf_xsave;

#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
pub mod kvm;

// HVF backend for macOS
// - Intel Macs: x86_64 hardware virtualization
// - Apple Silicon: ARM64 hardware virtualization (for aarch64 guests)
#[cfg(all(feature = "hvf", target_os = "macos"))]
pub mod hvf;

use std::any::Any;
use std::sync::Arc;

use vm_memory::GuestMemoryMmap;

use crate::config::{ArchKind, BackendKind, VmConfig};
use crate::error::{Error, Result};
use crate::vm::vcpu::VCpu;

mod checkpoint;
pub use checkpoint::CheckpointBoundary;

/// Abstract VM interface.
///
/// Represents a virtual machine that can create vCPUs and manage interrupts.
pub trait Vm: Send + Sync {
    /// Exclude hardware entry and backend-owned external mutations until the
    /// complete CPU/controller/RAM operation has finished.
    fn checkpoint_boundary(&self) -> Result<CheckpointBoundary<'_>> {
        Ok(CheckpointBoundary::empty())
    }

    /// Shared backend state, captured once at the same stopped boundary.
    fn capture_checkpoint_vm_context(
        &self,
        _boundary: &CheckpointBoundary<'_>,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(None)
    }

    /// Admit the shared record and complete CPU graph before publication.
    fn validate_checkpoint_vm_context(
        &self,
        _config: &crate::config::CheckpointConfig,
        context: Option<&crate::vm::snapshot::BackendContext>,
        _cpus: Option<&crate::vm::snapshot::BackendContexts>,
    ) -> Result<()> {
        if context.is_some() {
            Err(Error::InvalidConfig(
                "checkpoint shared context producer differs from target backend".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Publish an admitted shared record while every native CPU stays stopped.
    fn restore_checkpoint_vm_context(
        &self,
        _boundary: &CheckpointBoundary<'_>,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        if context.is_some() {
            Err(Error::InvalidConfig(
                "backend has no shared checkpoint context".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Restore the original destination's shared state after a failed import.
    /// Backends with host clock bindings can distinguish this from rebasing a
    /// checkpoint onto a new destination epoch.
    fn rollback_checkpoint_vm_context(
        &self,
        boundary: &CheckpointBoundary<'_>,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.restore_checkpoint_vm_context(boundary, context)
    }

    /// Irrecoverable hardware rollback must prohibit further guest entry.
    fn poison_checkpoint_restore(&self) {}

    /// Establish immutable CPU topology before creating any vCPU.
    fn configure_cpu_topology(&self, _count: u8, _ram_end: u64) -> Result<()> {
        Ok(())
    }

    /// Obtain firmware requests at an instruction boundary. Backends may retain
    /// them until acknowledgement so failed publication remains retryable.
    fn take_cpu_power_requests(&self) -> Result<Vec<crate::vm::vcpu::CpuPowerRequest>> {
        Ok(Vec::new())
    }

    /// Publish completion only after a requested CPU entry state is installed.
    fn complete_cpu_start(&self, _cpu_id: u32) -> Result<()> {
        Err(Error::InvalidConfig(
            "CPU startup is not supported by this VM".into(),
        ))
    }

    /// Acknowledge powerdown after removing the CPU from scheduling.
    fn complete_cpu_stop(&self, _cpu_id: u32) -> Result<()> {
        Ok(())
    }

    /// Create a new vCPU.
    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>>;

    /// Set IRQ line level.
    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()>;

    /// Get reference as Any for downcasting to concrete types.
    fn as_any(&self) -> &dyn Any;
}

/// Abstract backend interface.
///
/// Represents a virtualization backend (KVM, emulator, etc.).
pub trait Backend: Send + Sync {
    /// Backend name for logging.
    fn name(&self) -> &'static str;

    /// Create a new VM.
    fn create_vm(&self) -> Result<Box<dyn Vm>>;
}

/// Create a backend based on configuration.
pub(crate) fn create_for_checkpoint(
    config: &VmConfig,
    contexts: Option<&crate::vm::snapshot::BackendContexts>,
) -> Result<Box<dyn Backend>> {
    if config.backend == BackendKind::Emulator {
        return Ok(Box::new(
            emulator::EmulatorBackend::new(config.arch, config.hexagon_isa, config.hexagon_endian)
                .for_checkpoint(contexts)?,
        ));
    }
    create(config)
}

/// Create a backend based on configuration.
pub fn create(config: &VmConfig) -> Result<Box<dyn Backend>> {
    match config.backend {
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
        BackendKind::Kvm => {
            if config.arch != ArchKind::X86_64 {
                return Err(Error::InvalidConfig(
                    "KVM backend only supports x86_64".to_string(),
                ));
            }
            Ok(Box::new(kvm::KvmBackend::new()?))
        }
        #[cfg(not(all(feature = "kvm", target_os = "linux", target_arch = "x86_64")))]
        BackendKind::Kvm => Err(Error::InvalidConfig(
            "KVM backend not available (requires x86_64 Linux with --features kvm)".to_string(),
        )),
        BackendKind::Emulator => Ok(Box::new(emulator::EmulatorBackend::new(
            config.arch,
            config.hexagon_isa,
            config.hexagon_endian,
        ))),
        // Intel Mac - HVF for x86_64 guests
        #[cfg(all(feature = "hvf", target_os = "macos", target_arch = "x86_64"))]
        BackendKind::Hvf => {
            if config.arch != ArchKind::X86_64 {
                return Err(Error::InvalidConfig(
                    "HVF backend on Intel Mac only supports x86_64 guests".to_string(),
                ));
            }
            Ok(Box::new(hvf::HvfBackend::new()?))
        }
        // Apple Silicon - HVF for ARM64 guests only
        #[cfg(all(feature = "hvf", target_os = "macos", target_arch = "aarch64"))]
        BackendKind::Hvf => match config.arch {
            ArchKind::Aarch64 => Ok(Box::new(hvf::arm64::HvfArm64Backend::new()?)),
            ArchKind::X86_64 => Err(Error::InvalidConfig(
                "HVF backend cannot run x86_64 guests on Apple Silicon. \
                         Apple's Hypervisor.framework only supports ARM64 guests on ARM64 hosts. \
                         Use --backend emulator for x86_64 emulation on Apple Silicon."
                    .to_string(),
            )),
            _ => Err(Error::InvalidConfig(format!(
                "HVF backend on Apple Silicon only supports aarch64 guests, not {:?}",
                config.arch
            ))),
        },
        #[cfg(not(all(feature = "hvf", target_os = "macos")))]
        BackendKind::Hvf => Err(Error::InvalidConfig(
            "HVF backend not available (requires macOS with --features hvf)".to_string(),
        )),
    }
}

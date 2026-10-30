//! Apple Hypervisor.framework backend implementation.
//!
//! This backend uses Apple's Hypervisor.framework to provide hardware-accelerated
//! virtualization on macOS:
//! - On Intel Macs: Native x86_64 virtualization
//! - On Apple Silicon: Native ARM64 virtualization for AArch64 guests
//!
//! Note: x86_64 guests on Apple Silicon are NOT supported by HVF.
//! Apple's Hypervisor.framework only supports guests matching the host architecture.
//! For x86_64 emulation on Apple Silicon, use the emulator backend.

mod arm64_mmio;
mod bindings;
#[cfg(target_arch = "x86_64")]
mod controls;
#[cfg(target_arch = "x86_64")]
mod convert;
#[cfg(target_arch = "x86_64")]
mod cr8;
#[cfg(target_arch = "x86_64")]
mod event_injection;
#[cfg(target_arch = "x86_64")]
mod guest_translation;
#[cfg(target_arch = "x86_64")]
mod interrupt_shadow;
#[cfg(target_arch = "x86_64")]
mod mmio;
#[cfg(target_arch = "x86_64")]
mod port_io;
pub mod rosetta;
mod run_loop;
#[cfg(target_arch = "x86_64")]
mod sync_exit;
#[cfg(target_arch = "x86_64")]
mod xsetbv;

// ARM64 HVF backend (Apple Silicon only)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod arm64;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod arm64_bindings;

// Re-export ARM64 backend types on Apple Silicon
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use arm64::{HvfArm64Backend, HvfArm64Vcpu, HvfArm64Vm};

#[cfg(target_arch = "x86_64")]
use std::any::Any;
#[cfg(target_arch = "x86_64")]
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use tracing::{debug, info, warn};
#[cfg(target_arch = "x86_64")]
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

#[cfg(target_arch = "x86_64")]
use crate::error::{Error, Result};
#[cfg(target_arch = "x86_64")]
use crate::vm::memory::GuestMemoryWrapper;
#[cfg(target_arch = "x86_64")]
use crate::vm::vcpu::{CpuState, VCpu, VcpuExit, X86_64CpuState};

use super::{Backend, Vm};
#[cfg(target_arch = "x86_64")]
use bindings::*;
#[cfg(target_arch = "x86_64")]
use convert::*;
#[cfg(target_arch = "x86_64")]
use rosetta::CpuidConfig;

/// HVF backend.
#[cfg(target_arch = "x86_64")]
pub struct HvfBackend {
    /// CPUID configuration for x86_64 guests
    cpuid_config: CpuidConfig,
}

#[cfg(target_arch = "x86_64")]
impl HvfBackend {
    pub fn new() -> Result<Self> {
        // This backend only works on Intel Macs - verified at compile time via cfg
        // Check if Hypervisor.framework is available and we have entitlements
        if let Err(msg) = bindings::hv_check_available() {
            return Err(Error::InvalidConfig(msg.to_string()));
        }

        info!("HVF backend initialized for native x86_64 virtualization (Intel Mac)");

        Ok(HvfBackend {
            cpuid_config: CpuidConfig::default(),
        })
    }
}

#[cfg(target_arch = "x86_64")]
impl Backend for HvfBackend {
    fn name(&self) -> &'static str {
        "hvf"
    }

    fn create_vm(&self) -> Result<Box<dyn Vm>> {
        // Create VM
        let flags = rosetta::get_vm_creation_flags();
        let ret = unsafe { hv_vm_create(flags) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to create VM: {}",
                hv_error_string(ret)
            )));
        }

        info!("Created HVF VM");

        Ok(Box::new(HvfVm {
            cpuid_config: self.cpuid_config.clone(),
            pending_irqs: Mutex::new(Vec::new()),
            memory_mapped: Mutex::new(false),
        }))
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for HvfBackend {
    fn drop(&mut self) {
        // VM is cleaned up in HvfVm::drop
    }
}

/// HVF VM instance.
#[cfg(target_arch = "x86_64")]
pub struct HvfVm {
    /// CPUID configuration
    cpuid_config: CpuidConfig,
    /// Pending IRQs to inject
    pending_irqs: Mutex<Vec<u32>>,
    /// Whether memory has been mapped
    memory_mapped: Mutex<bool>,
}

#[cfg(target_arch = "x86_64")]
impl HvfVm {
    /// Register guest memory with the VM.
    pub fn register_memory(&self, mem: &GuestMemoryWrapper) -> Result<()> {
        let mut mapped = self.memory_mapped.lock().unwrap();
        if *mapped {
            return Ok(());
        }

        for region in mem.memory().iter() {
            let guest_addr = region.start_addr().0;
            let size = region.len() as usize;
            let host_addr = region.as_ptr() as *mut std::ffi::c_void;

            debug!(
                guest_addr = format!("{:#x}", guest_addr),
                size = size,
                "Mapping guest memory region"
            );

            let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
            let ret = unsafe { hv_vm_map(host_addr, guest_addr, size, flags) };
            if ret != HV_SUCCESS {
                return Err(Error::Emulator(format!(
                    "Failed to map memory at {:#x}: {}",
                    guest_addr,
                    hv_error_string(ret)
                )));
            }
        }

        *mapped = true;
        info!("Mapped guest memory to HVF VM");
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl Vm for HvfVm {
    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
        // Create vCPU
        let mut vcpu_id: hv_vcpuid_t = 0;
        let ret = unsafe { hv_vcpu_create(&mut vcpu_id, 0) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to create vCPU {}: {}",
                id,
                hv_error_string(ret)
            )));
        }

        debug!(id, vcpu_id, "Created HVF vCPU");

        // Initialize vCPU state
        let vcpu = HvfVcpu::new(vcpu_id, id, mem, self.cpuid_config.clone())?;

        Ok(Box::new(vcpu))
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        if level {
            let mut irqs = self.pending_irqs.lock().unwrap();
            if !irqs.contains(&irq) {
                irqs.push(irq);
            }
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for HvfVm {
    fn drop(&mut self) {
        let ret = unsafe { hv_vm_destroy() };
        if ret != HV_SUCCESS {
            warn!("Failed to destroy VM: {}", hv_error_string(ret));
        }
    }
}

/// HVF vCPU.
#[cfg(target_arch = "x86_64")]
pub struct HvfVcpu {
    /// HVF vCPU ID
    vcpu_id: hv_vcpuid_t,
    /// Our vCPU ID (index)
    id: u32,
    /// Guest memory reference
    mem: Arc<GuestMemoryMmap>,
    /// CPUID configuration
    cpuid_config: CpuidConfig,
    /// Scalar input request and terminal completion failure.
    port_input: port_io::InputState,
    mmio_input: mmio::InputState,
    /// Whether the vCPU is halted
    halted: bool,
}

// Safety: HvfVcpu is Send because the vCPU ID is a u32 identifier,
// and we synchronize access appropriately.
#[cfg(target_arch = "x86_64")]
unsafe impl Send for HvfVcpu {}

#[cfg(target_arch = "x86_64")]
impl HvfVcpu {
    fn new(
        vcpu_id: hv_vcpuid_t,
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        cpuid_config: CpuidConfig,
    ) -> Result<Self> {
        let vcpu = HvfVcpu {
            vcpu_id,
            id,
            mem,
            cpuid_config,
            port_input: port_io::InputState::default(),
            mmio_input: mmio::InputState::default(),
            halted: false,
        };

        // Initialize VMCS
        vcpu.init_vmcs()?;

        Ok(vcpu)
    }

    fn inject_fault(&self, fault: xsetbv::XsetbvFault) -> Result<()> {
        let (info, error) = fault.injection();
        if let Some(error) = error {
            vmcs_write(
                self.vcpu_id,
                hv_vmx_vmcs_field_t::VMCS_CTRL_VMENTRY_EXCEPTION_ERROR,
                error,
            )?;
        }
        vmcs_write(
            self.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_CTRL_VMENTRY_IRQ_INFO,
            info,
        )
    }

    /// Execute the VM-exited instruction or inject its architectural fault.
    fn handle_xsetbv(&self) -> Result<()> {
        struct Access<'a> {
            vcpu: &'a HvfVcpu,
        }
        impl xsetbv::XsetbvAccess for Access<'_> {
            type Error = Error;

            fn input(&mut self) -> Result<xsetbv::XsetbvInput> {
                let id = self.vcpu.vcpu_id;
                let (_, _, features, _) = self.vcpu.cpuid_config.cpuid(1, 0);
                let (low, _, _, high) = self.vcpu.cpuid_config.cpuid(0x0d, 0);
                Ok(xsetbv::XsetbvInput {
                    xsave_supported: features & (1 << 26) != 0,
                    supported_xcr0: u64::from(low) | (u64::from(high) << 32),
                    cr0: read_register(id, hv_x86_reg_t::HV_X86_CR0)?,
                    cr4: read_register(id, hv_x86_reg_t::HV_X86_CR4)?,
                    rflags: read_register(id, hv_x86_reg_t::HV_X86_RFLAGS)?,
                    cs_selector: vmcs_read(id, hv_vmx_vmcs_field_t::VMCS_GUEST_CS_SELECTOR)? as u16,
                    rax: read_register(id, hv_x86_reg_t::HV_X86_RAX)?,
                    rcx: read_register(id, hv_x86_reg_t::HV_X86_RCX)?,
                    rdx: read_register(id, hv_x86_reg_t::HV_X86_RDX)?,
                })
            }

            fn write_xcr0(&mut self, value: u64) -> Result<()> {
                write_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_XCR0, value)
            }

            fn advance_rip(&mut self) -> Result<()> {
                let length = vmcs_read(
                    self.vcpu.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_EXIT_INSTRUCTION_LENGTH,
                )?;
                self.vcpu.advance_rip(length)
            }

            fn inject_fault(&mut self, fault: xsetbv::XsetbvFault) -> Result<()> {
                self.vcpu.inject_fault(fault)
            }
        }
        xsetbv::handle_xsetbv(&mut Access { vcpu: self })
    }

    fn handle_cr8(&self, qualification: u64) -> Result<bool> {
        struct Access<'a> {
            vcpu: &'a HvfVcpu,
        }
        impl cr8::Cr8Access for Access<'_> {
            type Error = Error;
            fn read_gpr(&mut self, index: u8) -> Result<u64> {
                read_register(self.vcpu.vcpu_id, general_register(index)?)
            }
            fn write_gpr(&mut self, index: u8, value: u64) -> Result<()> {
                write_register(self.vcpu.vcpu_id, general_register(index)?, value)
            }
            fn read_tpr(&mut self) -> Result<u64> {
                read_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_TPR)
            }
            fn write_tpr(&mut self, value: u64) -> Result<()> {
                write_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_TPR, value)
            }
            fn inject_gp(&mut self) -> Result<()> {
                self.vcpu
                    .inject_fault(xsetbv::XsetbvFault::GeneralProtection)
            }
            fn advance_rip(&mut self) -> Result<()> {
                let length = vmcs_read(
                    self.vcpu.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_EXIT_INSTRUCTION_LENGTH,
                )?;
                self.vcpu.advance_rip(length)
            }
        }
        cr8::handle(&mut Access { vcpu: self }, qualification)
    }

    /// Initialize VMCS fields for the vCPU.
    fn init_vmcs(&self) -> Result<()> {
        struct Access {
            id: hv_vcpuid_t,
        }
        impl controls::ControlAccess for Access {
            type Error = Error;
            fn capability(&mut self, field: hv_vmx_capability_t) -> Result<u64> {
                let mut value = 0;
                let status = unsafe { hv_vmx_read_capability(field, &mut value) };
                if status != HV_SUCCESS {
                    return Err(Error::Emulator(format!(
                        "Failed to read VMX capability {field}: {}",
                        hv_error_string(status)
                    )));
                }
                Ok(value)
            }
            fn write(&mut self, field: hv_vmx_vmcs_field_t, value: u64) -> Result<()> {
                vmcs_write(self.id, field, value)
            }
        }
        controls::initialize(&mut Access { id: self.vcpu_id }).map_err(|error| match error {
            controls::ControlError::Host(error) => error,
            controls::ControlError::Inconsistent { capability, bits } => Error::Emulator(format!(
                "VMX capability {capability} requires disallowed control bits {bits:#010x}"
            )),
            controls::ControlError::Unsupported { capability, bits } => Error::Emulator(format!(
                "VMX capability {capability} lacks required control bits {bits:#010x}"
            )),
        })?;
        debug!(vcpu_id = self.vcpu_id, "Initialized VMCS");
        Ok(())
    }

    /// Handle CPUID exit.
    fn handle_cpuid(&self) -> Result<()> {
        let rax = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RAX)?;
        let rcx = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RCX)?;
        let leaf = rax as u32;
        let subleaf = rcx as u32;

        let configured = self.cpuid_config.cpuid(leaf, subleaf);
        let (eax, ebx, ecx, edx) = if leaf == 1 || (leaf == 0x0d && subleaf == 0) {
            let cr4 = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_CR4)?;
            let xcr0 = if leaf == 0x0d {
                read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_XCR0)?
            } else {
                0
            };
            xsetbv::xsave_cpuid(leaf, subleaf, configured, cr4, xcr0)
        } else {
            configured
        };

        write_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RAX, eax as u64)?;
        write_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RBX, ebx as u64)?;
        write_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RCX, ecx as u64)?;
        write_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RDX, edx as u64)?;

        // Advance RIP past the complete CPUID encoding
        self.advance_current_instruction()?;

        Ok(())
    }

    /// Handle RDMSR exit.
    fn handle_rdmsr(&self) -> Result<Option<VcpuExit>> {
        let ecx = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RCX)? as u32;

        // Handle common MSRs
        let value = match ecx {
            0x1B => 0xFEE00000 | 0x800, // IA32_APIC_BASE - LAPIC at default address, enabled
            0xC0000080 => {
                // IA32_EFER - read from VMCS
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_EFER)?
            }
            0xC0000081 => 0, // IA32_STAR
            0xC0000082 => 0, // IA32_LSTAR
            0xC0000083 => 0, // IA32_CSTAR
            0xC0000084 => 0, // IA32_FMASK
            0xC0000100 => {
                // IA32_FS_BASE - read from VMCS
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_FS_BASE)?
            }
            0xC0000101 => {
                // IA32_GS_BASE - read from VMCS
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_GS_BASE)?
            }
            0xC0000102 => 0, // IA32_KERNEL_GS_BASE
            0x174 => {
                // IA32_SYSENTER_CS
                vmcs_read(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_SYSENTER_CS,
                )?
            }
            0x175 => {
                // IA32_SYSENTER_ESP
                vmcs_read(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_SYSENTER_ESP,
                )?
            }
            0x176 => {
                // IA32_SYSENTER_EIP
                vmcs_read(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_SYSENTER_EIP,
                )?
            }
            0x1A0 => rosetta::MsrDefaults::default().misc_enable, // IA32_MISC_ENABLE
            0x277 => rosetta::MsrDefaults::default().pat,         // IA32_PAT
            0x10 => 0, // IA32_TIME_STAMP_COUNTER - return 0, will be handled by TSC offsetting
            0x6E0 => 0, // IA32_TSC_DEADLINE
            _ => {
                debug!(msr = format!("{:#x}", ecx), "Unhandled RDMSR");
                0 // Return 0 for unknown MSRs
            }
        };

        // Set result in EDX:EAX
        write_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RAX, value & 0xFFFFFFFF)?;
        write_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RDX, value >> 32)?;

        // Advance RIP past the complete RDMSR encoding
        self.advance_current_instruction()?;

        Ok(None)
    }

    /// Handle WRMSR exit.
    fn handle_wrmsr(&self) -> Result<Option<VcpuExit>> {
        let ecx = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RCX)? as u32;
        let eax = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RAX)? as u32;
        let edx = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RDX)? as u32;
        let value = ((edx as u64) << 32) | (eax as u64);

        match ecx {
            0x1B => {
                // IA32_APIC_BASE - ignore for now
                debug!(value = format!("{:#x}", value), "WRMSR IA32_APIC_BASE");
            }
            0xC0000080 => {
                // IA32_EFER
                vmcs_write(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_EFER,
                    value,
                )?;
            }
            0xC0000081 => {
                // IA32_STAR - store somewhere or handle syscall
                debug!(value = format!("{:#x}", value), "WRMSR IA32_STAR");
            }
            0xC0000082 => {
                // IA32_LSTAR
                debug!(value = format!("{:#x}", value), "WRMSR IA32_LSTAR");
            }
            0xC0000083 => {
                // IA32_CSTAR
                debug!(value = format!("{:#x}", value), "WRMSR IA32_CSTAR");
            }
            0xC0000084 => {
                // IA32_FMASK
                debug!(value = format!("{:#x}", value), "WRMSR IA32_FMASK");
            }
            0xC0000100 => {
                // IA32_FS_BASE
                vmcs_write(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_FS_BASE, value)?;
            }
            0xC0000101 => {
                // IA32_GS_BASE
                vmcs_write(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_GS_BASE, value)?;
            }
            0xC0000102 => {
                // IA32_KERNEL_GS_BASE
                debug!(value = format!("{:#x}", value), "WRMSR IA32_KERNEL_GS_BASE");
            }
            0x174 => {
                // IA32_SYSENTER_CS
                vmcs_write(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_SYSENTER_CS,
                    value,
                )?;
            }
            0x175 => {
                // IA32_SYSENTER_ESP
                vmcs_write(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_SYSENTER_ESP,
                    value,
                )?;
            }
            0x176 => {
                // IA32_SYSENTER_EIP
                vmcs_write(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_SYSENTER_EIP,
                    value,
                )?;
            }
            0x6E0 => {
                // IA32_TSC_DEADLINE
                debug!(value = format!("{:#x}", value), "WRMSR IA32_TSC_DEADLINE");
            }
            _ => {
                debug!(
                    msr = format!("{:#x}", ecx),
                    value = format!("{:#x}", value),
                    "Unhandled WRMSR"
                );
            }
        }

        // Advance RIP past the complete WRMSR encoding
        self.advance_current_instruction()?;

        Ok(None)
    }

    /// Retire the complete instruction encoding supplied by the VM exit.
    fn advance_current_instruction(&self) -> Result<()> {
        let length = vmcs_read(
            self.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_EXIT_INSTRUCTION_LENGTH,
        )?;
        self.advance_rip(length)
    }

    fn advance_rip(&self, bytes: u64) -> Result<()> {
        struct Access<'a> {
            vcpu: &'a HvfVcpu,
            next: u64,
        }
        impl interrupt_shadow::Access for Access<'_> {
            type Error = Error;
            fn interruptibility(&mut self) -> Result<u64> {
                vmcs_read(
                    self.vcpu.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_INTERRUPTIBILITY_STATE,
                )
            }
            fn advance_ip(&mut self) -> Result<()> {
                write_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RIP, self.next)
            }
            fn write_interruptibility(&mut self, value: u64) -> Result<()> {
                vmcs_write(
                    self.vcpu.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_INTERRUPTIBILITY_STATE,
                    value,
                )
            }
        }
        let rip = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RIP)?;
        let efer = vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_EFER)?;
        let cs = vmcs_read(
            self.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_GUEST_CS_ACCESS_RIGHTS,
        )?;
        let bits = sync_exit::code_width(efer, cs);
        let next = sync_exit::next_ip(rip, bytes, bits).map_err(|reason| {
            Error::Emulator(format!(
                "invalid HVF instruction advance:{reason:?},length={bytes},bits={bits}"
            ))
        })?;
        interrupt_shadow::complete(&mut Access { vcpu: self, next })
    }

    fn io_ready(&self) -> Result<()> {
        self.port_input
            .ready()
            .and_then(|()| self.mmio_input.ready())
            .map_err(|error| Error::Emulator(error.into()))
    }

    fn retire_mmio(&self, length: u64) -> Result<()> {
        struct Access<'a> {
            vcpu: &'a HvfVcpu,
        }
        impl mmio::RetirementAccess for Access<'_> {
            type Error = Error;
            fn rflags(&mut self) -> Result<u64> {
                read_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS)
            }
            fn advance_instruction(&mut self, length: u64) -> Result<()> {
                self.vcpu.advance_rip(length)
            }
            fn write_rflags(&mut self, flags: u64) -> Result<()> {
                write_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS, flags)
            }
        }
        mmio::retire(&mut Access { vcpu: self }, length)
    }

    fn prepare_mmio(&self) -> Result<mmio::Plan> {
        use hv_vmx_vmcs_field_t::*;
        struct Memory<'a> {
            ram: &'a GuestMemoryMmap,
        }
        impl guest_translation::PhysicalMemory for Memory<'_> {
            fn contains_ram(&self, address: u64, size: usize) -> bool {
                self.ram.check_range(GuestAddress(address), size)
            }
            fn read_physical(
                &mut self,
                address: u64,
                bytes: &mut [u8],
            ) -> std::result::Result<(), String> {
                self.ram
                    .read_slice(bytes, GuestAddress(address))
                    .map_err(|error| {
                        format!("HVF guest instruction inspection at {address:#x}: {error}")
                    })
            }
        }
        let id = self.vcpu_id;
        let mut registers = [0; 16];
        for (index, value) in registers.iter_mut().enumerate() {
            *value = read_register(id, general_register(index as u8)?)?;
        }
        let mut segments = [0; 6];
        for (value, field) in segments.iter_mut().zip([
            VMCS_GUEST_ES_BASE,
            VMCS_GUEST_CS_BASE,
            VMCS_GUEST_SS_BASE,
            VMCS_GUEST_DS_BASE,
            VMCS_GUEST_FS_BASE,
            VMCS_GUEST_GS_BASE,
        ]) {
            *value = vmcs_read(id, field)?;
        }
        let cr0 = read_register(id, hv_x86_reg_t::HV_X86_CR0)?;
        let cr3 = read_register(id, hv_x86_reg_t::HV_X86_CR3)?;
        let cr4 = read_register(id, hv_x86_reg_t::HV_X86_CR4)?;
        let efer = vmcs_read(id, VMCS_GUEST_IA32_EFER)?;
        let cs = vmcs_read(id, VMCS_GUEST_CS_ACCESS_RIGHTS)?;
        let code_bits = if efer & (1 << 10) != 0 && cs & (1 << 13) != 0 {
            64
        } else if cs & (1 << 14) != 0 {
            32
        } else {
            16
        };
        let mut pdpte = [0; 4];
        if cr0 & (1 << 31) != 0 && cr4 & (1 << 5) != 0 && efer & (1 << 10) == 0 {
            for (value, field) in pdpte.iter_mut().zip([
                VMCS_GUEST_PDPTE0,
                VMCS_GUEST_PDPTE1,
                VMCS_GUEST_PDPTE2,
                VMCS_GUEST_PDPTE3,
            ]) {
                *value = vmcs_read(id, field)?;
            }
        }
        let context = mmio::Context {
            registers,
            segments,
            code_bits,
            rip: read_register(id, hv_x86_reg_t::HV_X86_RIP)?,
            rflags: read_register(id, hv_x86_reg_t::HV_X86_RFLAGS)?,
            paging: guest_translation::Paging {
                cr0,
                cr3,
                cr4,
                efer,
                pdpte,
                physical_bits: self.cpuid_config.cpuid(0x8000_0008, 0).0 & 0xff,
            },
        };
        let record = mmio::ExitRecord {
            qualification: vmcs_read(id, VMCS_EXIT_QUALIFICATION)?,
            linear: vmcs_read(id, VMCS_GUEST_LINEAR_ADDRESS)?,
            physical: vmcs_read(id, VMCS_GUEST_PHYSICAL_ADDRESS)?,
            vectoring_information: vmcs_read(id, VMCS_IDT_VECTORING_INFO)?,
        };
        mmio::prepare(&context, &mut Memory { ram: &self.mem }, record).map_err(Error::Emulator)
    }

    fn event_access(&self) -> EventAccess<'_> {
        EventAccess { vcpu: self }
    }

    fn inject_event(&mut self, event: event_injection::Event) -> Result<bool> {
        if self.io_ready().is_err() {
            return Ok(false);
        }
        let injected = event_injection::inject(&mut self.event_access(), event)?;
        if injected {
            self.halted = false;
        }
        Ok(injected)
    }
}

#[cfg(target_arch = "x86_64")]
struct EventAccess<'a> {
    vcpu: &'a HvfVcpu,
}

#[cfg(target_arch = "x86_64")]
impl event_injection::Access for EventAccess<'_> {
    type Error = Error;
    fn entry_information(&mut self) -> Result<u64> {
        vmcs_read(
            self.vcpu.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_CTRL_VMENTRY_IRQ_INFO,
        )
    }
    fn rflags(&mut self) -> Result<u64> {
        read_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS)
    }
    fn interruptibility(&mut self) -> Result<u64> {
        vmcs_read(
            self.vcpu.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_GUEST_INTERRUPTIBILITY_STATE,
        )
    }
    fn write_entry_information(&mut self, information: u64) -> Result<()> {
        vmcs_write(
            self.vcpu.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_CTRL_VMENTRY_IRQ_INFO,
            information,
        )
    }
}

#[cfg(target_arch = "x86_64")]
impl sync_exit::HaltAccess for HvfVcpu {
    type Error = Error;
    fn advance_current_instruction(&mut self) -> Result<()> {
        HvfVcpu::advance_current_instruction(self)
    }
    fn set_halted(&mut self, halted: bool) {
        self.halted = halted;
    }
}

#[cfg(target_arch = "x86_64")]
impl run_loop::ExitHandler for HvfVcpu {
    type Exit = VcpuExit;
    type Error = Error;
    fn prepare(&mut self) -> Result<Option<VcpuExit>> {
        self.io_ready()?;
        // Only successful event injection or explicit wake clears the halt.
        if self.halted {
            return Ok(Some(VcpuExit::Hlt));
        }

        Ok(None)
    }
    fn next_reason(&mut self) -> Result<u32> {
        // Run the vCPU
        let ret = unsafe { hv_vcpu_run(self.vcpu_id) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "hv_vcpu_run failed: {}",
                hv_error_string(ret)
            )));
        }

        // Get exit reason
        let exit_reason = vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_EXIT_REASON)? as u32;
        Ok(exit_reason)
    }
    fn halt(&mut self) -> Result<VcpuExit> {
        sync_exit::halt(self)?;
        Ok(VcpuExit::Hlt)
    }
    fn port_io(&mut self) -> Result<VcpuExit> {
        self.io_ready()?;
        let qualification = vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_EXIT_QUALIFICATION)?;
        let io = port_io::decode(qualification).map_err(|reason| {
            Error::Emulator(format!(
                "unsupported HVF port-I/O qualification {qualification:#x}: {reason:?}"
            ))
        })?;
        let length = vmcs_read(
            self.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_EXIT_INSTRUCTION_LENGTH,
        )?;
        if !(1..=15).contains(&length) {
            return Err(Error::Emulator(format!(
                "invalid HVF port-I/O instruction length {length}"
            )));
        }
        let rax = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RAX)?;
        match io.direction {
            port_io::Direction::In => {
                self.port_input
                    .begin(port_io::PendingInput {
                        io,
                        original_rax: rax,
                        length,
                    })
                    .map_err(|error| Error::Emulator(error.into()))?;
                Ok(VcpuExit::IoIn {
                    port: io.port,
                    size: io.size,
                })
            }
            port_io::Direction::Out => {
                let data = port_io::output_bytes(rax, io.size)
                    .ok_or_else(|| Error::Emulator("invalid HVF output width".into()))?;
                self.advance_rip(length)?;
                Ok(VcpuExit::IoOut {
                    port: io.port,
                    data,
                })
            }
        }
    }
    fn mmio(&mut self) -> Result<VcpuExit> {
        self.io_ready()?;
        let plan = self.prepare_mmio()?;
        match plan.action {
            mmio::Action::Read(input) => {
                let size = input.size;
                self.mmio_input.begin(input).map_err(Error::Emulator)?;
                Ok(VcpuExit::MmioRead {
                    addr: plan.physical,
                    size,
                })
            }
            mmio::Action::AluRead(input) => {
                let size = input.size;
                self.mmio_input
                    .begin_alu_read(input)
                    .map_err(Error::Emulator)?;
                Ok(VcpuExit::MmioRead {
                    addr: plan.physical,
                    size,
                })
            }
            mmio::Action::Write(data) => {
                self.retire_mmio(plan.length)?;
                Ok(VcpuExit::MmioWrite {
                    addr: plan.physical,
                    data,
                })
            }
            mmio::Action::Rmw(input) => {
                let size = input.size;
                let operation = input.operation;
                self.mmio_input.begin_rmw(input).map_err(Error::Emulator)?;
                Ok(VcpuExit::MmioRmw {
                    addr: plan.physical,
                    size,
                    operation,
                })
            }
        }
    }
    fn exception(&mut self) -> Result<VcpuExit> {
        struct Access {
            id: hv_vcpuid_t,
        }
        impl sync_exit::ExceptionAccess for Access {
            type Error = Error;
            fn read_vmcs(&mut self, field: u32) -> Result<u64> {
                vmcs_read_raw(self.id, field)
            }
        }
        let vector =
            sync_exit::exception_vector(&mut Access { id: self.vcpu_id })?.ok_or_else(|| {
                Error::Emulator("invalid VMX exception/NMI interruption information".into())
            })?;
        Ok(VcpuExit::Exception(vector))
    }
    fn cpuid(&mut self) -> Result<()> {
        self.handle_cpuid()
    }
    fn rdmsr(&mut self) -> Result<Option<VcpuExit>> {
        self.handle_rdmsr()
    }
    fn wrmsr(&mut self) -> Result<Option<VcpuExit>> {
        self.handle_wrmsr()
    }
    fn shutdown(&mut self) -> Result<VcpuExit> {
        Ok(VcpuExit::Shutdown)
    }
    fn interrupt_window(&mut self) -> Result<()> {
        Ok(())
    }
    fn control_register(&mut self) -> Result<()> {
        let qualification = vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_EXIT_QUALIFICATION)?;
        if self.handle_cr8(qualification)? {
            return Ok(());
        }
        Err(Error::Emulator(format!(
            "unsupported HVF control-register exit qualification {qualification:#x}"
        )))
    }
    fn xsetbv(&mut self) -> Result<()> {
        self.handle_xsetbv()
    }
    fn fail_entry(&mut self, raw_reason: u32) -> Result<VcpuExit> {
        Ok(VcpuExit::FailEntry {
            reason: u64::from(raw_reason),
        })
    }
    fn unknown(&mut self, exit_reason: u32) -> Result<VcpuExit> {
        let rip = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RIP)?;
        Ok(VcpuExit::Unknown(format!(
            "Exit reason {} at RIP {:#x}",
            exit_reason, rip
        )))
    }
}

#[cfg(target_arch = "x86_64")]
impl VCpu for HvfVcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        run_loop::run(self)
    }

    fn wake(&mut self) {
        sync_exit::wake(self);
    }

    fn get_state(&self) -> Result<CpuState> {
        let regs = regs_from_hvf(self.vcpu_id)?;
        let sregs = sregs_from_hvf(self.vcpu_id)?;
        Ok(CpuState::X86_64(X86_64CpuState { regs, sregs }))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::X86_64(state) => state,
            _ => {
                return Err(Error::InvalidConfig(
                    "HVF backend only supports x86_64 state".to_string(),
                ));
            }
        };

        self.io_ready()?;
        // Reject invalid CR8 before any externally supplied CPU state is written.
        if cr8::tpr_value(state.sregs.cr8).is_none() {
            return Err(Error::InvalidConfig(format!(
                "invalid CR8 value {:#x}",
                state.sregs.cr8
            )));
        }
        regs_to_hvf(self.vcpu_id, &state.regs)?;
        sregs_to_hvf(self.vcpu_id, &state.sregs)?;

        Ok(())
    }

    fn io_completion_result(&self) -> Result<()> {
        self.io_ready()
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        if self.mmio_input.pending() {
            struct Access<'a> {
                vcpu: &'a HvfVcpu,
            }
            impl mmio::CompletionAccess for Access<'_> {
                type Error = Error;
                fn write_gpr(&mut self, index: usize, value: u64) -> Result<()> {
                    let index = u8::try_from(index)
                        .map_err(|_| Error::Emulator("invalid MMIO GPR index".into()))?;
                    write_register(self.vcpu.vcpu_id, general_register(index)?, value)
                }
                fn write_rflags(&mut self, flags: u64) -> Result<()> {
                    write_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS, flags)
                }
                fn finish_instruction(&mut self, length: u64) -> Result<()> {
                    self.vcpu.retire_mmio(length)
                }
            }
            let mut state = std::mem::take(&mut self.mmio_input);
            state.complete(&mut Access { vcpu: self }, data);
            self.mmio_input = state;
            return;
        }
        struct Access<'a> {
            vcpu: &'a HvfVcpu,
        }
        impl port_io::CompletionAccess for Access<'_> {
            type Error = Error;
            fn write_rax(&mut self, value: u64) -> Result<()> {
                write_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RAX, value)
            }
            fn advance_instruction(&mut self, length: u64) -> Result<()> {
                self.vcpu.advance_rip(length)
            }
        }
        // Move the private completion state out while the adapter borrows CPU
        // host access; restore it before returning, including retained errors.
        let mut state = std::mem::take(&mut self.port_input);
        state.complete(&mut Access { vcpu: self }, data);
        self.port_input = state;
    }

    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        self.inject_event(event_injection::Event::Interrupt(vector))
    }

    fn can_inject_interrupt(&self) -> bool {
        if self.io_ready().is_err() {
            return false;
        }
        event_injection::available(
            &mut self.event_access(),
            event_injection::Event::Interrupt(0),
        )
        .unwrap_or(false)
    }

    fn inject_nmi(&mut self) -> Result<bool> {
        self.inject_event(event_injection::Event::Nmi)
    }

    #[cfg(feature = "debug")]
    fn set_single_step(&mut self, enabled: bool) {
        // Enable trap flag for single-stepping
        if let Ok(rflags) = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS) {
            let new_rflags = if enabled {
                rflags | RFLAGS_TF
            } else {
                rflags & !RFLAGS_TF
            };
            let _ = write_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS, new_rflags);
        }
    }

    #[cfg(feature = "debug")]
    fn is_single_step(&self) -> bool {
        read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS)
            .map(|f| (f & RFLAGS_TF) != 0)
            .unwrap_or(false)
    }

    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, _addr: u64) {
        // HVF doesn't have a software decode cache to invalidate
        // Just invalidate TLB to be safe
        unsafe {
            hv_vcpu_invalidate_tlb(self.vcpu_id);
        }
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        // HVF doesn't provide instruction count, return 0
        0
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for HvfVcpu {
    fn drop(&mut self) {
        let ret = unsafe { hv_vcpu_destroy(self.vcpu_id) };
        if ret != HV_SUCCESS {
            warn!(
                "Failed to destroy vCPU {}: {}",
                self.id,
                hv_error_string(ret)
            );
        }
    }
}

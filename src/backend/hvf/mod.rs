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

#[cfg(target_arch = "x86_64")]
mod apic_identity;
#[cfg(target_arch = "x86_64")]
mod apic_identity_native;
mod arm64_mmio;
mod bindings;
#[cfg(target_arch = "x86_64")]
mod controls;
#[cfg(target_arch = "x86_64")]
mod convert;
#[cfg(target_arch = "x86_64")]
mod cr8;
#[cfg(all(target_arch = "x86_64", feature = "debug"))]
mod debug_memory;
#[cfg(target_arch = "x86_64")]
mod event_injection;
#[cfg(target_arch = "x86_64")]
mod intel_owner;
#[cfg(target_arch = "x86_64")]
mod intel_vm;
#[cfg(target_arch = "x86_64")]
mod intel_worker;
#[cfg(target_arch = "x86_64")]
use crate::backend::intel_hvf_io::{guest_translation, mmio, port_io};
#[cfg(target_arch = "x86_64")]
mod intel_checkpoint;
#[cfg(target_arch = "x86_64")]
mod intel_clock;
#[cfg(target_arch = "x86_64")]
mod intel_fp;
#[cfg(target_arch = "x86_64")]
mod intel_init;
#[cfg(target_arch = "x86_64")]
mod intel_run;
#[cfg(target_arch = "x86_64")]
mod intel_topology;
#[cfg(target_arch = "x86_64")]
mod intel_vm_checkpoint;
#[cfg(target_arch = "x86_64")]
mod interrupt_shadow;
#[cfg(target_arch = "x86_64")]
mod interrupt_window;
#[cfg(target_arch = "x86_64")]
mod memory_layout;
#[cfg(target_arch = "x86_64")]
mod native_memory;
#[cfg(target_arch = "x86_64")]
mod native_msr;
#[cfg(target_arch = "x86_64")]
use intel_vm::Lifetime;
#[cfg(target_arch = "x86_64")]
pub use intel_worker::HvfVcpu;
#[cfg(target_arch = "x86_64")]
mod native_step;
#[cfg(target_arch = "x86_64")]
mod native_step_host;
#[cfg(target_arch = "x86_64")]
mod output;
#[cfg(target_arch = "x86_64")]
mod priority;
#[cfg(target_arch = "x86_64")]
mod priority_native;
#[cfg(target_arch = "x86_64")]
mod retirement;
#[cfg(target_arch = "x86_64")]
use crate::isa::x86_64::identity as apic_profile;
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
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_arch = "x86_64")]
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use tracing::{debug, info, warn};
#[cfg(target_arch = "x86_64")]
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

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
            lifetime: Arc::new(Lifetime::default()),
        }))
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for HvfBackend {
    fn drop(&mut self) {
        // The final retained Lifetime owns SDK VM destruction.
    }
}

/// HVF VM instance.
#[cfg(target_arch = "x86_64")]
pub struct HvfVm {
    /// CPUID configuration
    cpuid_config: CpuidConfig,
    lifetime: Arc<Lifetime>,
}

#[cfg(target_arch = "x86_64")]
impl HvfVm {
    /// Register guest memory with the VM.
    pub fn register_memory(&self, mem: &GuestMemoryWrapper) -> Result<()> {
        self.register_memory_with_mmio(mem, &[], None)
    }

    /// Map reported RAM excluding fixed device pages and the exact live BARs.
    pub fn register_memory_with_mmio(
        &self,
        mem: &GuestMemoryWrapper,
        holes: &[crate::devices::bus::MmioRange],
        pci: Option<Arc<Mutex<crate::devices::pci::PciStub>>>,
    ) -> Result<()> {
        let _boundary = self.lifetime.stopped()?;
        native_memory::register(&self.lifetime.memory_layout, mem, holes, pci)
    }
}

#[cfg(target_arch = "x86_64")]
impl Vm for HvfVm {
    fn x86_firmware_identity(&self) -> Result<Option<(u32, u32)>> {
        let _boundary = self.lifetime.stopped()?;
        let (eax, _, _, edx) =
            intel_topology::project(&self.cpuid_config, &self.lifetime, 0, 1, 0)?;
        Ok(Some((eax, edx)))
    }

    fn bind_software_ioapic(
        &self,
        controller: Arc<Mutex<crate::devices::ioapic::IoApic>>,
    ) -> Result<()> {
        let _boundary = self
            .lifetime
            .quiescence
            .write()
            .map_err(|_| Error::Emulator("Intel HVF exclusion lock poisoned".into()))?;
        self.lifetime.ready()?;
        self.lifetime.software_ioapic.bind(controller)
    }

    fn configure_cpu_topology(&self, count: u8, ram_end: u64) -> Result<()> {
        let _boundary = self.lifetime.stopped()?;
        if count == 0 || ram_end == 0 {
            return Err(Error::InvalidConfig("invalid native Intel topology".into()));
        }
        let cpus = self
            .lifetime
            .cpus
            .lock()
            .map_err(|_| Error::Emulator("Intel HVF topology lock poisoned".into()))?;
        let mut configured = self
            .lifetime
            .configured
            .lock()
            .map_err(|_| Error::Emulator("Intel HVF configuration lock poisoned".into()))?;
        match *configured {
            Some(current) if current == (count, ram_end) => Ok(()),
            None if cpus.is_empty() => {
                *configured = Some((count, ram_end));
                Ok(())
            }
            _ => Err(Error::InvalidConfig(
                "native Intel topology is already established".into(),
            )),
        }
    }
    fn capture_checkpoint_vm_context(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.lifetime.capture_shared(boundary).map(Some)
    }
    fn validate_checkpoint_vm_context(
        &self,
        config: &crate::config::CheckpointConfig,
        context: Option<&crate::vm::snapshot::BackendContext>,
        cpus: Option<&crate::vm::snapshot::BackendContexts>,
    ) -> Result<()> {
        self.lifetime.validate_shared(config, context, cpus)
    }
    fn restore_checkpoint_vm_context(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.lifetime.restore_shared(boundary, context, false)
    }
    fn rollback_checkpoint_vm_context(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.lifetime.restore_shared(boundary, context, true)
    }
    fn checkpoint_boundary(&self) -> Result<crate::backend::CheckpointBoundary<'_>> {
        self.lifetime.stopped()
    }
    fn poison_checkpoint_restore(&self) {
        self.lifetime
            .poison("checkpoint rollback could not restore the VM".into());
    }
    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
        Ok(Box::new(HvfVcpu::new(
            id,
            mem,
            self.cpuid_config.clone(),
            self.lifetime.clone(),
        )?))
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        // Capture holds PC controller locks before native exclusion. Acquire
        // this source in the same order, with no mutation until both succeed.
        let mut source = self.lifetime.software_ioapic.source(irq)?;
        let _boundary = self
            .lifetime
            .quiescence
            .read()
            .map_err(|_| Error::Emulator("Intel HVF exclusion lock poisoned".into()))?;
        self.lifetime.ready()?;
        source.set_level(level);
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Native core confined to its permanent SDK owner.
#[cfg(target_arch = "x86_64")]
struct HvfCore {
    /// HVF vCPU ID
    vcpu_id: hv_vcpuid_t,
    /// Our vCPU ID (index)
    id: u32,
    /// Guest memory reference
    mem: Arc<GuestMemoryMmap>,
    memory_layout: native_memory::Shared,
    /// CPUID configuration
    cpuid_config: CpuidConfig,
    priority: priority_native::State,
    deadline: crate::devices::lapic::tsc_deadline::Handle,
    apic_base: AtomicU64,
    /// Scalar input request and terminal completion failure.
    port_input: port_io::InputState,
    mmio_input: mmio::InputState,
    output: output::State<VcpuExit>,
    native_step: native_step::State,
    /// Whether the vCPU is halted
    halted: bool,
    shutdown: bool,
    /// Architectural PAT is software-owned: the SDK exposes no PAT access.
    pat: u64,
    checkpoint_profile: Option<crate::backend::intel_hvf_context::Profile>,
    pending_request: Option<crate::backend::intel_hvf_context::Packet>,
    execution_failure: Option<String>,
    restore_failure: Option<String>,
    tsc_offset: i64,
    pending_clock: Option<(u64, bool)>,
    _vm: Arc<Lifetime>,
    _owner_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(target_arch = "x86_64")]
impl HvfCore {
    fn create(
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        cpuid_config: CpuidConfig,
        lifetime: Arc<Lifetime>,
    ) -> Result<Self> {
        lifetime.ready()?;
        let mut native_id = 0;
        // SAFETY: this factory runs on the permanent owner. The SDK receives
        // a live exclusive output word; the resulting handle never leaves it.
        let result = unsafe { hv_vcpu_create(&mut native_id, 0) };
        if result != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to create vCPU {id}: {}",
                hv_error_string(result)
            )));
        }
        Self::new(native_id, id, mem, cpuid_config, lifetime)
    }
    fn new(
        vcpu_id: hv_vcpuid_t,
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        cpuid_config: CpuidConfig,
        lifetime: Arc<Lifetime>,
    ) -> Result<Self> {
        let mut vcpu = HvfCore {
            vcpu_id,
            id,
            mem,
            memory_layout: lifetime.memory_layout.clone(),
            cpuid_config,
            priority: priority_native::new(),
            deadline: crate::devices::lapic::tsc_deadline::TimerLvt::new(1 << 16).handle(),
            apic_base: AtomicU64::new(apic_profile::initial_apic_base(id)),
            port_input: port_io::InputState::default(),
            mmio_input: mmio::InputState::default(),
            output: output::State::default(),
            native_step: native_step::State::default(),
            halted: false,
            shutdown: false,
            pat: rosetta::MsrDefaults::default().pat,
            checkpoint_profile: None,
            pending_request: None,
            execution_failure: None,
            restore_failure: None,
            tsc_offset: 0,
            pending_clock: None,
            _vm: lifetime,
            _owner_thread: std::marker::PhantomData,
        };

        // Initialize VMCS
        native_step_host::validate_halt_activity().map_err(Error::Emulator)?;
        vcpu.init_vmcs()?;
        vcpu.native_step
            .configure(&mut native_step_host::Host(vcpu_id), false)
            .map_err(Error::Emulator)?;
        native_msr::initialize(vcpu_id)?;
        intel_clock::Api::load()?.set(vcpu_id, 0)?;
        write_register(vcpu_id, hv_x86_reg_t::HV_X86_XCR0, 1)?;
        let layout = intel_fp::discover(vcpu_id)?;
        intel_fp::reset(vcpu_id, &layout)?;
        vcpu.checkpoint_profile = Some(intel_fp::profile(vcpu_id, &vcpu.cpuid_config, layout)?);

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
            vcpu: &'a HvfCore,
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
            vcpu: &'a HvfCore,
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
                self.vcpu.priority.read().map_err(Error::Emulator)
            }
            fn write_tpr(&mut self, value: u64) -> Result<()> {
                self.vcpu
                    .priority
                    .write(&mut priority_native::Host(self.vcpu.vcpu_id), value)
                    .map_err(Error::Emulator)
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

        let configured = self.topology_cpuid(leaf, subleaf)?;
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

    fn check_msr_access(&self) -> Result<bool> {
        let protected = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_CR0)? & 1 != 0;
        let flags = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS)?;
        let selector = vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_CS_SELECTOR)?;
        if protected && (flags & (1 << 17) != 0 || selector & 3 != 0) {
            self.inject_fault(xsetbv::XsetbvFault::GeneralProtection)?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Handle RDMSR exit.
    fn handle_rdmsr(&self) -> Result<Option<VcpuExit>> {
        if !self.check_msr_access()? {
            return Ok(None);
        }
        let ecx = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RCX)? as u32;
        if ecx == 0x1b {
            self.handle_apic_base(None)?;
            return Ok(None);
        }

        // Handle common MSRs
        let value = match ecx {
            0xC0000080 => {
                // IA32_EFER - read from VMCS
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_EFER)?
            }
            native_msr::STAR
            | native_msr::LSTAR
            | native_msr::CSTAR
            | native_msr::FMASK
            | native_msr::KERNEL_GS_BASE
            | native_msr::TSC_AUX => native_msr::read(self.vcpu_id, ecx)?,
            0xC0000100 => {
                // IA32_FS_BASE - read from VMCS
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_FS_BASE)?
            }
            0xC0000101 => {
                // IA32_GS_BASE - read from VMCS
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_GS_BASE)?
            }
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
            0x277 => self.pat,                                    // IA32_PAT
            0x10 => self.read_guest_tsc()?,
            0x6E0 => {
                self.deadline.expire(self.read_guest_tsc()?);
                self.deadline.read()
            }
            _ => {
                debug!(msr = format!("{:#x}", ecx), "Unhandled RDMSR");
                self.inject_fault(xsetbv::XsetbvFault::GeneralProtection)?;
                return Ok(None);
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
    fn handle_wrmsr(&mut self) -> Result<Option<VcpuExit>> {
        if !self.check_msr_access()? {
            return Ok(None);
        }
        let ecx = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RCX)? as u32;
        let eax = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RAX)? as u32;
        let edx = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_RDX)? as u32;
        let value = ((edx as u64) << 32) | (eax as u64);
        if ecx == 0x1b {
            self.handle_apic_base(Some(value))?;
            return Ok(None);
        }

        match ecx {
            0x277 => {
                if !crate::isa::x86_64::execute::system::is_valid_pat(value) {
                    self.inject_fault(xsetbv::XsetbvFault::GeneralProtection)?;
                    return Ok(None);
                }
                self.pat = value;
            }
            0x10 => self.write_guest_tsc(value)?,
            0xC0000080 => {
                // IA32_EFER
                vmcs_write(
                    self.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_EFER,
                    value,
                )?;
            }
            native_msr::STAR
            | native_msr::LSTAR
            | native_msr::CSTAR
            | native_msr::FMASK
            | native_msr::KERNEL_GS_BASE
            | native_msr::TSC_AUX => native_msr::write(self.vcpu_id, ecx, value)?,
            0xC0000100 => {
                // IA32_FS_BASE
                vmcs_write(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_FS_BASE, value)?;
            }
            0xC0000101 => {
                // IA32_GS_BASE
                vmcs_write(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_GUEST_GS_BASE, value)?;
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
                self.deadline.expire(self.read_guest_tsc()?);
                self.deadline.write(value);
            }
            _ => {
                debug!(
                    msr = format!("{:#x}", ecx),
                    value = format!("{:#x}", value),
                    "Unhandled WRMSR"
                );
                self.inject_fault(xsetbv::XsetbvFault::GeneralProtection)?;
                return Ok(None);
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
        self.native_step.ready().map_err(Error::Emulator)?;
        struct Access<'a> {
            vcpu: &'a HvfCore,
            next: u64,
        }
        impl retirement::Access for Access<'_> {
            type Error = Error;
            fn rflags(&mut self) -> Result<u64> {
                read_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS)
            }
            fn debug_control(&mut self) -> Result<u64> {
                vmcs_read(
                    self.vcpu.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_IA32_DEBUGCTL,
                )
            }
            fn pending_debug(&mut self) -> Result<u64> {
                vmcs_read(
                    self.vcpu.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
                )
            }
            fn write_rflags(&mut self, value: u64) -> Result<()> {
                write_register(self.vcpu.vcpu_id, hv_x86_reg_t::HV_X86_RFLAGS, value)
            }
            fn write_pending_debug(&mut self, value: u64) -> Result<()> {
                vmcs_write(
                    self.vcpu.vcpu_id,
                    hv_vmx_vmcs_field_t::VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
                    value,
                )
            }
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
        retirement::complete(&mut Access { vcpu: self, next })
            .map_err(|error| Error::Emulator(self.native_step.poison(error.to_string())))?;
        self.native_step.complete_instruction();
        Ok(())
    }

    fn io_ready(&self) -> Result<()> {
        self.execution_ready()?;
        self.priority.ready().map_err(Error::Emulator)?;
        self.output.ready().map_err(Error::Emulator)?;
        self.port_input
            .ready()
            .and_then(|()| self.mmio_input.ready())
            .map_err(|error| Error::Emulator(error.into()))
    }

    fn retire_mmio(&self, length: u64) -> Result<()> {
        self.advance_rip(length)
    }

    fn prepare_mmio(&self) -> Result<mmio::Plan> {
        use hv_vmx_vmcs_field_t::*;
        struct Memory<'a> {
            ram: &'a GuestMemoryMmap,
            layout: &'a memory_layout::Layout,
        }
        impl guest_translation::PhysicalMemory for Memory<'_> {
            fn contains_ram(&self, address: u64, size: usize) -> bool {
                self.layout.contains_mapped(address, size)
            }
            fn read_physical(
                &mut self,
                address: u64,
                bytes: &mut [u8],
            ) -> std::result::Result<(), String> {
                if !self.layout.contains_logical(address, bytes.len()) {
                    return Err(format!(
                        "HVF instruction/page-table inspection is outside logical RAM at {address:#x}"
                    ));
                }
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
        let guard = self
            .memory_layout
            .read()
            .map_err(|_| Error::Emulator("HVF memory layout lock poisoned".into()))?;
        let memory = guard
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("HVF guest RAM is not registered".into()))?;
        memory.mapping.ready().map_err(Error::Emulator)?;
        mmio::prepare(
            &context,
            &mut Memory {
                ram: &self.mem,
                layout: &memory.mapping.layout,
            },
            record,
        )
        .map_err(Error::Emulator)
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
    vcpu: &'a HvfCore,
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
    fn pending_debug(&mut self) -> Result<u64> {
        vmcs_read(
            self.vcpu.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
        )
    }
}

#[cfg(target_arch = "x86_64")]
impl sync_exit::HaltAccess for HvfCore {
    type Error = Error;
    fn advance_current_instruction(&mut self) -> Result<()> {
        HvfCore::advance_current_instruction(self)
    }
    fn set_halted(&mut self, halted: bool) -> Result<()> {
        vmcs_write(
            self.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_GUEST_ACTIVITY_STATE,
            u64::from(halted),
        )?;
        self.halted = halted;
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl run_loop::ExitHandler for HvfCore {
    type Exit = VcpuExit;
    type Error = Error;
    fn prepare(&mut self) -> Result<Option<VcpuExit>> {
        self.execution_ready()?;
        for failure in [self.port_input.failure(), self.mmio_input.failure()] {
            if let Some(failure) = failure {
                return Err(Error::Emulator(failure.to_string()));
            }
        }
        if self.shutdown {
            return Ok(Some(VcpuExit::Shutdown));
        }
        if let Some(request) = &self.pending_request {
            return Ok(Some(request.exit()));
        }
        if let Some(exit) = self.output.pending().map_err(Error::Emulator)? {
            return Ok(Some(exit));
        }
        self.io_ready()?;
        native_memory::validate_cpu_backing(&self.memory_layout, &self.mem)?;
        #[cfg(feature = "debug")]
        if self
            .native_step
            .take_completion()
            .map_err(Error::Emulator)?
        {
            return Ok(Some(VcpuExit::GdbStep));
        }
        if self.halted {
            let pending = vmcs_read(
                self.vcpu_id,
                hv_vmx_vmcs_field_t::VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
            )?;
            let shadow = vmcs_read(
                self.vcpu_id,
                hv_vmx_vmcs_field_t::VMCS_GUEST_INTERRUPTIBILITY_STATE,
            )?;
            if retirement::pending_trap(pending, shadow) {
                // Leave the VMCS in HLT: hardware delivers the guest trap and
                // wakes it before executing any subsequent guest instruction.
                self.halted = false;
            } else {
                return Ok(Some(VcpuExit::Hlt));
            }
        }

        Ok(None)
    }
    fn next_reason(&mut self) -> Result<u32> {
        self.next_unbounded_reason()
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
        let exit = match io.direction {
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
                self.output
                    .begin(
                        VcpuExit::IoOut {
                            port: io.port,
                            data,
                        },
                        length,
                    )
                    .map_err(Error::Emulator)
            }
        }?;
        if matches!(&exit, VcpuExit::IoIn { .. }) {
            self.pending_request =
                Some(crate::backend::intel_hvf_context::Packet::from_exit(&exit)?);
        }
        Ok(exit)
    }
    fn mmio(&mut self) -> Result<VcpuExit> {
        self.io_ready()?;
        let plan = self.prepare_mmio()?;
        let exit = match plan.action {
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
            mmio::Action::Write(data) => self
                .output
                .begin(
                    VcpuExit::MmioWrite {
                        addr: plan.physical,
                        data,
                    },
                    plan.length,
                )
                .map_err(Error::Emulator),
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
        }?;
        if matches!(&exit, VcpuExit::MmioRead { .. } | VcpuExit::MmioRmw { .. }) {
            self.pending_request =
                Some(crate::backend::intel_hvf_context::Packet::from_exit(&exit)?);
        }
        Ok(exit)
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
        self.shutdown = true;
        Ok(VcpuExit::Shutdown)
    }
    fn interrupt_window(&mut self) -> Result<()> {
        struct Controls {
            id: hv_vcpuid_t,
        }
        impl interrupt_window::Access for Controls {
            type Error = Error;
            fn read_controls(&mut self) -> Result<u64> {
                vmcs_read(self.id, hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED)
            }
            fn write_controls(&mut self, value: u64) -> Result<()> {
                vmcs_write(self.id, hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED, value)
            }
        }
        interrupt_window::acknowledge(&mut Controls { id: self.vcpu_id })
            .map_err(|error| match error {
                interrupt_window::ControlError::Host(error) => error,
                interrupt_window::ControlError::Readback { expected, observed } => {
                    Error::Emulator(format!(
                        "HVF interrupt-window control readback differs: expected {expected:#x}, observed {observed:#x}"
                    ))
                }
            })
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
    fn monitor_trap(&mut self) -> Result<VcpuExit> {
        self.native_step.monitor_trap().map_err(Error::Emulator)?;
        #[cfg(feature = "debug")]
        return Ok(VcpuExit::GdbStep);
        #[cfg(not(feature = "debug"))]
        Err(Error::Emulator(self.native_step.poison(
            "monitor-trap exit in a build without debugger support".into(),
        )))
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
impl HvfCore {
    fn is_bootstrap_processor(&self) -> Result<bool> {
        self.priority.ready().map_err(Error::Emulator)?;
        Ok(self.apic_base.load(Ordering::SeqCst) & apic_profile::APIC_BASE_BSP != 0)
    }
    fn wake(&mut self) {
        if self.native_step.ready().is_err() {
            return;
        }
        if let Err(error) = sync_exit::wake(self) {
            self.native_step.poison(error.to_string());
        }
    }

    fn get_state(&self) -> Result<CpuState> {
        self.io_ready()?;
        let mut regs = regs_from_hvf(self.vcpu_id)?;
        let fp = intel_fp::read(self.vcpu_id, &self.native_profile()?.xsave)?;
        self.native_profile()?.xsave.project(&fp, &mut regs)?;
        let mut sregs = sregs_from_hvf(self.vcpu_id)?;
        sregs.cr8 = self.priority.read().map_err(Error::Emulator)? >> 4;
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
        let tpr = crate::devices::lapic::priority::import_value(
            self.priority.read().map_err(Error::Emulator)? as u32,
            state.sregs.cr8,
        )
        .ok_or_else(|| Error::InvalidConfig("invalid CR8/TPR priority projection".into()))?;
        let fp = intel_fp::read(self.vcpu_id, &self.native_profile()?.xsave)?;
        let fp = self.native_profile()?.xsave.overlay(&fp, &state.regs)?;
        regs_to_hvf(self.vcpu_id, &state.regs)
            .and_then(|()| sregs_to_hvf(self.vcpu_id, &state.sregs))
            .and_then(|()| intel_fp::write(self.vcpu_id, &self.native_profile()?.xsave, &fp))
            .map_err(|e| Error::Emulator(self.priority.poison(e.to_string())))?;
        if tpr & 15 != 0 {
            self.priority
                .write(&mut priority_native::Host(self.vcpu_id), u64::from(tpr))
                .map_err(Error::Emulator)?;
        } else {
            self.priority.commit_import(tpr).map_err(Error::Emulator)?;
        }

        self.native_step.discard_completion();
        Ok(())
    }

    fn complete_io_out(&mut self) -> Result<()> {
        self.execution_ready()?;
        let mut output = std::mem::take(&mut self.output);
        let result = output
            .acknowledge(|length| self.advance_rip(length).map_err(|error| error.to_string()));
        self.output = output;
        result.map_err(Error::Emulator)
    }

    fn io_completion_result(&self) -> Result<()> {
        self.io_ready()
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        if let Err(error) = self.execution_ready() {
            if self.mmio_input.pending() {
                self.mmio_input.hold_failure(data, error.to_string());
            } else {
                self.port_input.hold_failure(data, error.to_string());
            }
            return;
        }
        if self.mmio_input.pending() {
            struct Access<'a> {
                vcpu: &'a HvfCore,
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
            if self.mmio_input.ready().is_ok() {
                self.pending_request = None;
            }
            return;
        }
        struct Access<'a> {
            vcpu: &'a HvfCore,
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
        if self.port_input.ready().is_ok() {
            self.pending_request = None;
        }
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
        if let Err(error) = self
            .native_step
            .configure(&mut native_step_host::Host(self.vcpu_id), enabled)
        {
            // The compatibility setter cannot return errors. Retain failure
            // before any subsequent entry or architectural-state capture.
            self.native_step.poison(error);
        }
    }

    #[cfg(feature = "debug")]
    fn is_single_step(&self) -> bool {
        self.native_step.enabled()
    }

    #[cfg(feature = "debug")]
    fn debug_address_space(&self) -> Result<crate::vm::vcpu::DebugAddressSpace> {
        self.debug_paging_state()
    }

    #[cfg(feature = "debug")]
    fn debug_memory_changed(&mut self, _pages: &[u64]) -> Result<()> {
        self.debug_invalidate_translation()
    }

    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, _addr: u64) {
        if let Err(error) = self.debug_invalidate_translation() {
            self.native_step.poison(error.to_string());
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
impl Drop for HvfCore {
    fn drop(&mut self) {
        // SAFETY: the non-Send core is dropped on its creating worker, after
        // every synchronous operation. The VM and RAM remain retained here.
        let ret = unsafe { hv_vcpu_destroy(self.vcpu_id) };
        if ret != HV_SUCCESS {
            self._vm.poison(format!(
                "vCPU {} SDK destruction failed: {}",
                self.id,
                hv_error_string(ret)
            ));
            warn!(
                "Failed to destroy vCPU {}: {}",
                self.id,
                hv_error_string(ret)
            );
        }
    }
}

//! KVM backend implementation.

mod convert;
mod cpuid;
mod deadline;
mod firmware;
mod io;
mod owned_vcpu;
mod run;
mod special;
mod state;
mod xsave;

pub use owned_vcpu::OwnedVcpuFd;

#[cfg(test)]
mod checkpoint_backlog_tests;
#[cfg(test)]
mod cpuid_native_tests;
#[cfg(test)]
mod state_tests;

use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use vm_memory::GuestMemoryMmap;

use crate::error::{Error, Result};
use crate::vm::memory::GuestMemoryWrapper;
use crate::vm::vcpu::{CpuState, VCpu, VcpuExit};

use super::{Backend, Vm};

/// KVM backend.
pub struct KvmBackend {
    kvm: Kvm,
}

impl KvmBackend {
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new()?;
        Ok(KvmBackend { kvm })
    }

    /// Get reference to the Kvm instance (needed for CPUID).
    pub fn kvm(&self) -> &Kvm {
        &self.kvm
    }
}

impl Backend for KvmBackend {
    fn name(&self) -> &'static str {
        "kvm"
    }

    fn create_vm(&self) -> Result<Box<dyn Vm>> {
        let vm_fd = self.kvm.create_vm()?;
        // Create a new Kvm instance for the VM (Kvm doesn't implement Clone)
        let kvm = Kvm::new()?;
        let cpuid = kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
        Ok(Box::new(KvmVm {
            memory: Arc::new(MemoryOwner {
                vm_fd,
                registered: Mutex::new(Vec::new()),
                irqchip_created: AtomicBool::new(false),
            }),
            kvm,
            cpuid,
            profile: Mutex::new(cpuid::Configuration::default()),
        }))
    }
}

/// KVM VM instance.
pub struct KvmVm {
    memory: Arc<MemoryOwner>,
    kvm: Kvm,
    cpuid: kvm_bindings::CpuId,
    profile: Mutex<cpuid::Configuration>,
}

/// Close the VM before releasing any RAM retained by its memory slots. Managed
/// vCPUs share this owner, including after their public VM object is dropped.
struct MemoryOwner {
    vm_fd: VmFd,
    registered: Mutex<Vec<GuestMemoryMmap>>,
    irqchip_created: AtomicBool,
}

impl KvmVm {
    /// Access the native VM without the managed ownership boundary.
    ///
    /// # Safety
    /// Every native object derived from this FD must be destroyed before the
    /// public VM and its registered backing owners can be dropped. The caller
    /// must also exclude native entry while changing memory slots or state.
    /// Prefer register_memory/create_vcpu_fd for managed lifetime retention.
    ///
    /// ```compile_fail
    /// fn bypass(vm: &rax::backend::kvm::KvmVm) {
    ///     let _ = vm.vm_fd();
    /// }
    /// ```
    pub unsafe fn vm_fd(&self) -> &VmFd {
        &self.memory.vm_fd
    }

    /// Get reference to the Kvm instance.
    pub fn kvm(&self) -> &Kvm {
        &self.kvm
    }

    /// Register guest memory with the VM.
    pub fn register_memory(&self, mem: &GuestMemoryWrapper) -> Result<()> {
        let mut registered = self
            .memory
            .registered
            .lock()
            .map_err(|_| Error::Emulator("KVM memory ownership lock poisoned".into()))?;
        // A failed registration may already have changed a prefix of slots.
        // Retain every submitted backing until the native VM is destroyed.
        registered.push(mem.memory().clone());
        mem.register(&self.memory.vm_fd)
    }

    /// Create IRQ chip.
    pub fn create_irq_chip(&self) -> Result<()> {
        self.memory.vm_fd.create_irq_chip()?;
        self.memory.irqchip_created.store(true, Ordering::Release);
        Ok(())
    }

    /// Create PIT2.
    pub fn create_pit2(&self) -> Result<()> {
        self.create_pit2_with_flags(0)
    }

    /// Let the native PC timer own its channel2 gate and OUT at port0x61.
    pub(crate) fn create_pit2_with_speaker(&self) -> Result<()> {
        self.create_pit2_with_flags(kvm_bindings::KVM_PIT_SPEAKER_DUMMY)
    }

    fn create_pit2_with_flags(&self, flags: u32) -> Result<()> {
        use kvm_bindings::kvm_pit_config;
        self.memory.vm_fd.create_pit2(kvm_pit_config {
            flags,
            pad: [0; 15],
        })?;
        Ok(())
    }

    /// Set TSS address.
    pub fn set_tss_address(&self, addr: u64) -> Result<()> {
        self.memory.vm_fd.set_tss_address(addr as usize)?;
        Ok(())
    }

    /// Set identity map address.
    pub fn set_identity_map_address(&self, addr: u64) -> Result<()> {
        self.memory.vm_fd.set_identity_map_address(addr)?;
        Ok(())
    }

    /// Create a native vCPU that retains this VM and its registered backing.
    /// Native immutable ioctls and explicit mutable operations remain available
    /// on the returned owner; no safe operation extracts an unowned VcpuFd.
    pub fn create_vcpu_fd(&self, id: u64) -> Result<OwnedVcpuFd> {
        let mut profile = self
            .profile
            .lock()
            .map_err(|_| Error::Emulator("native CPU profile lock poisoned".into()))?;
        let fd = self.memory.vm_fd.create_vcpu(id)?;
        profile.created = true;
        Ok(OwnedVcpuFd::new(fd, self.memory.clone()))
    }
}

impl Vm for KvmVm {
    fn configure_cpu_topology(&self, count: u8, _ram_end: u64) -> Result<()> {
        cpuid::Topology::new(count)?;
        let mut profile = self
            .profile
            .lock()
            .map_err(|_| Error::Emulator("native CPU profile lock poisoned".into()))?;
        if profile.created || profile.count.is_some() {
            return Err(Error::InvalidConfig(
                "native CPU topology must be configured once, before CPU creation".into(),
            ));
        }
        profile.count = Some(count);
        Ok(())
    }

    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
        use tracing::debug;

        let mut profile = self
            .profile
            .lock()
            .map_err(|_| Error::Emulator("native CPU profile lock poisoned".into()))?;
        // Validate the complete pure record before consuming a native CPU ID.
        let cpuid = match profile.count {
            Some(count) => cpuid::Topology::new(count)?.project(&self.cpuid, id)?,
            None => cpuid::sdk_profile(&self.cpuid, id)?,
        };
        debug!(id, "KvmVm::create_vcpu: calling create_vcpu");
        let vcpu_fd = self.memory.vm_fd.create_vcpu(id as u64)?;
        // Native allocation consumes this ID even if subsequent setup fails.
        // Closing the new CPU FD does not make the VM topology mutable again.
        profile.created = true;
        debug!(id, "KvmVm::create_vcpu: vcpu created, projecting CPUID");

        debug!(id, "KvmVm::create_vcpu: setting CPUID");
        vcpu_fd.set_cpuid2(&cpuid)?;
        debug!(id, "KvmVm::create_vcpu: done");

        Ok(Box::new(KvmVcpu {
            vcpu_fd,
            id,
            pending_io_in: None,
            io: io::State::default(),
            memory_owner: self.memory.clone(),
            _memory: mem,
            state_failure: None,
        }))
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        self.memory.vm_fd.set_irq_line(irq, level)?;
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// KVM vCPU.
pub struct KvmVcpu {
    vcpu_fd: VcpuFd,
    id: u32,
    /// Pointer and length of the outstanding native input buffer. The owned
    /// reply is copied immediately before native entry; neither accepting the
    /// reply nor rejecting an entry drops this pointer before kernel completion.
    /// Its lifetime is the run mapping owned by vcpu_fd, with exclusive access
    /// through this CPU's mutable borrow.
    pending_io_in: Option<(*mut u8, usize)>,
    /// Owned transfer metadata, replies and acknowledged output progress.
    /// The native pointer is retained separately until kernel completion.
    io: io::State,
    memory_owner: Arc<MemoryOwner>,
    _memory: Arc<GuestMemoryMmap>,
    state_failure: Option<String>,
}

// Safety: KvmVcpu is Send because:
// - VcpuFd is Send
// - The raw pointer in pending_io_in points to memory owned by vcpu_fd
//   (the mmap'd kvm_run structure), so it moves with the struct
// - We only access the pointer from methods that take &mut self
unsafe impl Send for KvmVcpu {}

impl KvmVcpu {
    /// Get reference to the VcpuFd.
    /// Bounded managed entry owns the native KVM signal-mask policy.
    pub fn vcpu_fd(&self) -> &VcpuFd {
        &self.vcpu_fd
    }
}

impl VCpu for KvmVcpu {
    fn native_run_eligibility(&mut self) -> Result<Option<bool>> {
        self.state_ready()?;
        if !self.memory_owner.irqchip_created.load(Ordering::Acquire)
            || self.io.has_native_completion()
        {
            // GET_MP_STATE accepts pending INIT/SIPI and can reset this CPU.
            // Complete native instruction emulation before observing those
            // events; the owned transfer and mapped reply buffer remain live.
            return Ok(None);
        }
        let state = self.vcpu_fd.get_mp_state()?.mp_state;
        match state {
            kvm_bindings::KVM_MP_STATE_RUNNABLE
            | kvm_bindings::KVM_MP_STATE_HALTED
            | kvm_bindings::KVM_MP_STATE_SIPI_RECEIVED => Ok(Some(true)),
            kvm_bindings::KVM_MP_STATE_UNINITIALIZED
            | kvm_bindings::KVM_MP_STATE_INIT_RECEIVED
            | kvm_bindings::KVM_MP_STATE_AP_RESET_HOLD => Ok(Some(false)),
            _ => Err(Error::Emulator(format!(
                "unsupported native x86 MP scheduling state {state}"
            ))),
        }
    }

    fn supports_host_slices(&self) -> bool {
        true
    }

    fn run_host_slice(&mut self, limit: std::time::Duration) -> Result<Option<VcpuExit>> {
        deadline::run(self, limit)
    }

    fn run(&mut self) -> Result<VcpuExit> {
        self.run_native()
    }

    fn get_state(&self) -> Result<CpuState> {
        self.public_state()
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.set_public_state(state)
    }

    fn current_pc(&self) -> u64 {
        self.state_ready()
            .ok()
            .and_then(|()| self.vcpu_fd.get_regs().ok())
            .map_or(0, |regs| regs.rip)
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        self.complete_native_input(data);
    }

    fn complete_io_out(&mut self) -> Result<()> {
        self.acknowledge_native_output()
    }

    fn io_completion_result(&self) -> Result<()> {
        self.native_completion_status()
    }

    fn id(&self) -> u32 {
        self.id
    }
}

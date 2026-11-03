//! KVM backend implementation.

mod convert;
mod deadline;
mod owned_vcpu;
mod special;
mod state;
mod xsave;

pub use owned_vcpu::OwnedVcpuFd;

#[cfg(test)]
mod checkpoint_backlog_tests;
#[cfg(test)]
mod state_tests;

use std::any::Any;
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
        Ok(Box::new(KvmVm {
            memory: Arc::new(MemoryOwner {
                vm_fd,
                registered: Mutex::new(Vec::new()),
            }),
            kvm,
        }))
    }
}

/// KVM VM instance.
pub struct KvmVm {
    memory: Arc<MemoryOwner>,
    kvm: Kvm,
}

/// Close the VM before releasing any RAM retained by its memory slots. Managed
/// vCPUs share this owner, including after their public VM object is dropped.
struct MemoryOwner {
    vm_fd: VmFd,
    registered: Mutex<Vec<GuestMemoryMmap>>,
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
        Ok(())
    }

    /// Create PIT2.
    pub fn create_pit2(&self) -> Result<()> {
        use kvm_bindings::kvm_pit_config;
        self.memory.vm_fd.create_pit2(kvm_pit_config {
            flags: 0,
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
        Ok(OwnedVcpuFd::new(
            self.memory.vm_fd.create_vcpu(id)?,
            self.memory.clone(),
        ))
    }
}

impl Vm for KvmVm {
    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
        use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
        use tracing::debug;

        debug!(id, "KvmVm::create_vcpu: calling create_vcpu");
        let vcpu_fd = self.memory.vm_fd.create_vcpu(id as u64)?;
        debug!(id, "KvmVm::create_vcpu: vcpu created, getting CPUID");

        // Set CPUID for the vCPU
        let cpuid = self.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        debug!(id, "KvmVm::create_vcpu: setting CPUID");
        vcpu_fd.set_cpuid2(&cpuid)?;
        debug!(id, "KvmVm::create_vcpu: done");

        Ok(Box::new(KvmVcpu {
            vcpu_fd,
            id,
            pending_io_in: None,
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
    /// Pointer and length to pending IoIn/MmioRead data buffer.
    /// This is set during run() when we get an IoIn/MmioRead exit,
    /// and written to in complete_io_in().
    /// Safety: The pointer is valid between run() calls as it points
    /// to the mmap'd kvm_run structure owned by vcpu_fd.
    pending_io_in: Option<(*mut u8, usize)>,
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
    fn supports_host_slices(&self) -> bool {
        true
    }

    fn run_host_slice(&mut self, limit: std::time::Duration) -> Result<Option<VcpuExit>> {
        deadline::run(self, limit)
    }

    fn run(&mut self) -> Result<VcpuExit> {
        self.state_ready()?;
        // Clear any previous pending I/O
        self.pending_io_in = None;

        match self.vcpu_fd.run()? {
            kvm_ioctls::VcpuExit::Hlt => Ok(VcpuExit::Hlt),
            kvm_ioctls::VcpuExit::Shutdown => Ok(VcpuExit::Shutdown),
            kvm_ioctls::VcpuExit::IoIn(port, data) => {
                // Store pointer to the data buffer so complete_io_in() can write to it
                self.pending_io_in = Some((data.as_mut_ptr(), data.len()));
                Ok(VcpuExit::IoIn {
                    port,
                    size: data.len() as u8,
                })
            }
            kvm_ioctls::VcpuExit::IoOut(port, data) => Ok(VcpuExit::IoOut {
                port,
                data: data.to_vec(),
            }),
            kvm_ioctls::VcpuExit::MmioRead(addr, data) => {
                // Store pointer to the data buffer so complete_io_in() can write to it
                self.pending_io_in = Some((data.as_mut_ptr(), data.len()));
                Ok(VcpuExit::MmioRead {
                    addr,
                    size: data.len() as u8,
                })
            }
            kvm_ioctls::VcpuExit::MmioWrite(addr, data) => Ok(VcpuExit::MmioWrite {
                addr,
                data: data.to_vec(),
            }),
            kvm_ioctls::VcpuExit::SystemEvent(type_, flags) => Ok(VcpuExit::SystemEvent {
                type_,
                flags: flags.first().copied().unwrap_or(0),
            }),
            kvm_ioctls::VcpuExit::FailEntry(reason, _) => Ok(VcpuExit::FailEntry { reason }),
            kvm_ioctls::VcpuExit::InternalError => Ok(VcpuExit::InternalError),
            exit => Ok(VcpuExit::Unknown(format!("{:?}", exit))),
        }
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
        // Write the response data to the KVM I/O buffer
        if let Some((ptr, len)) = self.pending_io_in.take() {
            let to_copy = data.len().min(len);
            // Safety: The pointer is valid as it points to the mmap'd kvm_run
            // structure which stays valid between run() calls. We only write
            // up to the buffer length that KVM told us.
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, to_copy);
            }
        }
    }

    fn id(&self) -> u32 {
        self.id
    }
}

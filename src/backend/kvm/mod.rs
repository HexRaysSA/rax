//! KVM backend implementation.

mod access;
mod checkpoint;
mod checkpoint_io;
mod clock_gate;
mod convert;
mod cpuid;
mod cpuid_apic;
mod deadline;
mod events;
mod firmware;
mod io;
mod irq;
mod owned_vcpu;
mod run;
mod special;
mod state;
mod xsave;

pub use access::NativeVcpuFd;
pub use owned_vcpu::OwnedVcpuFd;

#[cfg(test)]
mod access_tests;
#[cfg(test)]
mod checkpoint_backlog_tests;
#[cfg(test)]
mod checkpoint_io_tests;
#[cfg(test)]
mod cpuid_native_tests;
#[cfg(test)]
mod state_tests;

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};

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
                checkpoint_kvm: Kvm::new()?,
                registered: Mutex::new(Vec::new()),
                irqchip_created: AtomicBool::new(false),
                irq_lines: Mutex::new(irq::Lines::default()),
                external_vm_access: AtomicBool::new(false),
                powered_off: AtomicBool::new(false),
                exclusion: RwLock::new(()),
                waiting_writers: Mutex::new(0),
                entry_ready: Condvar::new(),
                poisoned: AtomicBool::new(false),
                managed_cpus: Mutex::new(BTreeMap::new()),
                sdk_cpus: AtomicUsize::new(0),
                resume_clock: Mutex::new(None),
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
    checkpoint_kvm: Kvm,
    registered: Mutex<Vec<GuestMemoryMmap>>,
    irqchip_created: AtomicBool,
    irq_lines: Mutex<irq::Lines>,
    external_vm_access: AtomicBool,
    powered_off: AtomicBool,
    exclusion: RwLock<()>,
    waiting_writers: Mutex<usize>,
    entry_ready: Condvar,
    poisoned: AtomicBool,
    managed_cpus: Mutex<BTreeMap<u32, Weak<Mutex<NativeCore>>>>,
    sdk_cpus: AtomicUsize,
    /// Canonical restored phase until the first authorized managed guest entry.
    resume_clock: Mutex<Option<clock_gate::PendingClock>>,
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
        // The SDK can install routes, IRQFDs or line sources that managed
        // state cannot reconstruct. Retain ordinary SDK access, but never
        // admit such a VM as an entirely managed checkpoint owner afterwards.
        self.memory
            .external_vm_access
            .store(true, Ordering::Release);
        &self.memory.vm_fd
    }

    /// Get reference to the Kvm instance.
    pub fn kvm(&self) -> &Kvm {
        &self.kvm
    }

    /// Register guest memory with the VM.
    pub fn register_memory(&self, mem: &GuestMemoryWrapper) -> Result<()> {
        let _entry = self.memory.entry()?;
        let mut registered = self
            .memory
            .registered
            .lock()
            .map_err(|_| Error::Emulator("KVM memory ownership lock poisoned".into()))?;
        // A failed registration may already have changed a prefix of slots.
        // Retain every submitted backing until the native VM is destroyed.
        registered.push(mem.memory().clone());
        // SAFETY: the clone was retained before the first slot mutation,
        // including partial failure. Every managed CPU retains this owner;
        // native VM/CPU FDs close before their backing owners are released.
        // This lock serializes managed registration and owner retention.
        unsafe { mem.register(&self.memory.vm_fd) }
    }

    /// Create IRQ chip.
    pub fn create_irq_chip(&self) -> Result<()> {
        let _entry = self.memory.entry()?;
        // Match CPU allocation: the kernel controller and its admission flag
        // must become visible together before any CPU chooses its profile.
        let _profile = self
            .profile
            .lock()
            .map_err(|_| Error::Emulator("native CPU profile lock poisoned".into()))?;
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
        let _entry = self.memory.entry()?;
        use kvm_bindings::kvm_pit_config;
        self.memory.vm_fd.create_pit2(kvm_pit_config {
            flags,
            pad: [0; 15],
        })?;
        Ok(())
    }

    /// Set TSS address.
    pub fn set_tss_address(&self, addr: u64) -> Result<()> {
        let _entry = self.memory.entry()?;
        self.memory.vm_fd.set_tss_address(addr as usize)?;
        Ok(())
    }

    /// Set identity map address.
    pub fn set_identity_map_address(&self, addr: u64) -> Result<()> {
        let _entry = self.memory.entry()?;
        self.memory.vm_fd.set_identity_map_address(addr)?;
        Ok(())
    }

    /// Create a native vCPU that retains this VM and its registered backing.
    /// Native immutable ioctls and explicit mutable operations remain available
    /// on the returned owner; no safe operation extracts an unowned VcpuFd.
    pub fn create_vcpu_fd(&self, id: u64) -> Result<OwnedVcpuFd> {
        let _entry = self.memory.entry()?;
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
    fn uses_native_x86_irqchip(&self) -> bool {
        self.memory.irqchip_created.load(Ordering::Acquire)
    }

    fn checkpoint_boundary(&self) -> Result<crate::backend::CheckpointBoundary<'_>> {
        // Acquire the profile lock only long enough to read the declaration.
        // The exclusion writer then prevents creation/configuration changes.
        let count = self
            .profile
            .lock()
            .map_err(|_| Error::Emulator("native CPU profile lock poisoned".into()))?
            .count;
        self.memory.boundary(count)
    }

    fn poison_checkpoint_restore(&self) {
        self.memory.poisoned.store(true, Ordering::Release);
    }

    fn configure_cpu_topology(&self, count: u8, _ram_end: u64) -> Result<()> {
        let _entry = self.memory.entry()?;
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
        let _entry = self.memory.entry()?;
        use tracing::debug;

        let mut profile = self
            .profile
            .lock()
            .map_err(|_| Error::Emulator("native CPU profile lock poisoned".into()))?;
        // Validate the complete pure record before consuming a native CPU ID.
        let mut cpuid = match profile.count {
            Some(count) => cpuid::Topology::new(count)?.project(&self.cpuid, id)?,
            None => cpuid::sdk_profile(&self.cpuid, id)?,
        };
        cpuid_apic::admit(
            &mut cpuid,
            self.memory.irqchip_created.load(Ordering::Acquire),
            self.kvm.check_extension(kvm_ioctls::Cap::TscDeadlineTimer),
        );
        debug!(id, "KvmVm::create_vcpu: calling create_vcpu");
        let vcpu_fd = self.memory.vm_fd.create_vcpu(id as u64)?;
        // Native allocation consumes this ID even if subsequent setup fails.
        // Closing the new CPU FD does not make the VM topology mutable again.
        profile.created = true;
        debug!(id, "KvmVm::create_vcpu: vcpu created, projecting CPUID");

        debug!(id, "KvmVm::create_vcpu: setting CPUID");
        vcpu_fd.set_cpuid2(&cpuid)?;
        debug!(id, "KvmVm::create_vcpu: done");

        let native_tsc_khz = vcpu_fd.get_tsc_khz().ok();
        let core = Arc::new(Mutex::new(NativeCore {
            vcpu_fd,
            id,
            configured_cpuid: cpuid,
            native_tsc_khz,
            pending_io_in: None,
            native_io_unsettled: false,
            io: io::State::default(),
            memory_owner: self.memory.clone(),
            _memory: mem,
            state_failure: None,
            deferred_exit: None,
            servicing_io: false,
            userspace_halted: false,
        }));
        self.memory
            .managed_cpus
            .lock()
            .map_err(|_| Error::Emulator("native CPU membership lock poisoned".into()))?
            .insert(id, Arc::downgrade(&core));
        Ok(Box::new(KvmVcpu {
            core,
            memory_owner: self.memory.clone(),
            id,
        }))
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        let _entry = self.memory.entry()?;
        let mut lines = self
            .memory
            .irq_lines
            .lock()
            .map_err(|_| Error::Emulator("native IRQ line ownership lock poisoned".into()))?;
        self.memory.vm_fd.set_irq_line(irq, level)?;
        lines.record(irq, level);
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// KVM vCPU.
pub struct KvmVcpu {
    core: Arc<Mutex<NativeCore>>,
    memory_owner: Arc<MemoryOwner>,
    id: u32,
}

struct NativeCore {
    vcpu_fd: VcpuFd,
    id: u32,
    configured_cpuid: kvm_bindings::CpuId,
    native_tsc_khz: Option<u32>,
    /// Pointer and length of the outstanding native input buffer. The owned
    /// reply is copied immediately before native entry; neither accepting the
    /// reply nor rejecting an entry drops this pointer before kernel completion.
    /// Its lifetime is the run mapping owned by vcpu_fd, with exclusive access
    /// through this CPU's mutable borrow.
    pending_io_in: Option<(*mut u8, usize)>,
    /// Native-instance provenance, distinct from a restored terminal record.
    /// Bank installation must retain this marker even if it replaces owned
    /// I/O metadata. Only observed KVM_RUN completion may clear it; otherwise
    /// a later active import requires fresh native VM/CPU owners.
    native_io_unsettled: bool,
    /// Owned transfer metadata, replies and acknowledged output progress.
    /// The native pointer is retained separately until kernel completion.
    io: io::State,
    memory_owner: Arc<MemoryOwner>,
    _memory: Arc<GuestMemoryMmap>,
    state_failure: Option<String>,
    deferred_exit: Option<VcpuExit>,
    servicing_io: bool,
    /// KVM_EXIT_HLT with a userspace interrupt controller leaves MP_STATE
    /// runnable. The adapter owns this wait state until a wake is accepted.
    userspace_halted: bool,
}

// SAFETY: the only raw pointer names the run mapping retained by this core's
// VcpuFd. Every access requires an exclusive mutable core borrow. The wrapper
// and VM registry share the core through one Mutex; no native buffer reference
// escapes the lock or crosses a native entry. Moving the locked core to a
// scoped host-entry worker retains the FD and RAM owners for the whole call.
unsafe impl Send for NativeCore {}

impl VCpu for KvmVcpu {
    fn validate_checkpoint_state(
        &self,
        state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
    ) -> Result<()> {
        self.memory_owner.ready()?;
        if self.memory_owner.resume_clock_pending()? {
            return Err(Error::InvalidConfig(
                "native CPU checkpoint requires its complete pending resume-clock producer".into(),
            ));
        }
        if !matches!(state, CpuState::X86_64(_)) {
            return Err(Error::InvalidConfig(
                "KVM backend only supports x86_64 state".into(),
            ));
        }
        Ok(())
    }

    fn capture_checkpoint_record(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        _scope: Option<&crate::vm::memory::checkpoint::CheckpointPublication<'_>>,
    ) -> Result<(
        crate::vm::snapshot::CpuSnapshot,
        Option<crate::vm::snapshot::BackendContext>,
    )> {
        self.with_checkpoint(boundary, |core| {
            if core.memory_owner.resume_clock_pending()? {
                return Err(Error::InvalidConfig(
                    "native CPU capture requires its complete pending resume-clock producer".into(),
                ));
            }
            if core.native_io_unsettled
                || core.io.has_native_completion()
                || core.deferred_exit.is_some()
                || core.userspace_halted
            {
                return Err(Error::InvalidConfig(
                    "native CPU capture requires its complete I/O/deferred-exit/halt producer"
                        .into(),
                ));
            }
            Ok((
                crate::vm::snapshot::CpuSnapshot {
                    state: core.get_state()?,
                    emulator: crate::vm::snapshot::EmulatorState::default(),
                },
                None,
            ))
        })
    }

    fn restore_checkpoint_record(
        &mut self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_context(state, emulator, context)?;
        self.with_checkpoint(boundary, |core| {
            if core.memory_owner.resume_clock_pending()? {
                return Err(Error::InvalidConfig(
                    "native CPU restore requires its complete pending resume-clock producer".into(),
                ));
            }
            core.set_state(state)
        })
    }

    fn settle_checkpoint_io(
        &self,
        service: &mut dyn FnMut(VcpuExit) -> Result<crate::vm::vcpu::CheckpointIoReply>,
    ) -> Result<crate::vm::vcpu::CheckpointIoState> {
        self.settle_native_checkpoint_io(service)
    }

    fn native_run_eligibility(&mut self) -> Result<Option<bool>> {
        self.with_native(|core| core.native_run_eligibility())
    }

    fn supports_host_slices(&self) -> bool {
        true
    }

    fn run_host_slice(&mut self, limit: std::time::Duration) -> Result<Option<VcpuExit>> {
        self.run_native_host_slice(limit)
    }

    fn run(&mut self) -> Result<VcpuExit> {
        // Release VM/CPU exclusion between host slices so an ordinary
        // checkpoint writer can stop a guest that has no architectural exit.
        // The public call continues to wait for a real guest-visible event.
        loop {
            let exit = self.run_native_host_slice(std::time::Duration::from_millis(10))?;
            if let Some(exit) = exit {
                return Ok(exit);
            }
        }
    }

    fn get_state(&self) -> Result<CpuState> {
        self.with_native(|core| core.get_state())
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.with_native(|core| core.set_state(state))
    }

    fn current_pc(&self) -> u64 {
        self.with_native(|core| {
            // Keep the fault location observable after an I/O protocol error.
            // GET_REGS does not complete I/O, accept INIT/SIPI or clear the
            // error. Full state capture and guest entry remain fenced.
            core.native_state_ready()?;
            Ok(core.vcpu_fd.get_regs()?.rip)
        })
        .unwrap_or(0)
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        if let Err(error) = self.with_native(|core| {
            core.complete_native_input(data);
            Ok(())
        }) {
            self.memory_owner.poisoned.store(true, Ordering::Release);
            tracing::error!(%error, "native input ownership unavailable; guest entry disabled");
        }
    }

    fn complete_io_out(&mut self) -> Result<()> {
        self.with_native(|core| core.acknowledge_native_output())
    }

    fn io_completion_result(&self) -> Result<()> {
        self.with_native(|core| core.native_completion_status())
    }

    fn can_inject_interrupt(&self) -> bool {
        self.with_native(|core| core.native_can_inject_interrupt())
            .unwrap_or(false)
    }

    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        self.with_native(|core| core.native_inject_interrupt(vector))
    }

    fn inject_nmi(&mut self) -> Result<bool> {
        self.with_native(|core| core.native_inject_nmi())
    }

    fn wake(&mut self) {
        if let Err(error) = self.with_native(|core| {
            if let Err(error) = core.native_wake() {
                let failure = format!("KVM native wake failed: {error}; guest entry disabled");
                core.state_failure = Some(failure.clone());
                return Err(Error::Emulator(failure));
            }
            Ok(())
        }) {
            tracing::error!(%error, "native CPU wake unavailable");
        }
    }

    fn id(&self) -> u32 {
        self.id
    }
}

impl NativeCore {
    fn get_state(&self) -> Result<CpuState> {
        self.public_state()
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.set_public_state(state)
    }
    fn run_host_slice(&mut self, limit: std::time::Duration) -> Result<Option<VcpuExit>> {
        deadline::run(self, limit)
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        self.complete_native_input(data);
    }
    fn io_completion_result(&self) -> Result<()> {
        self.native_completion_status()
    }

    fn native_run_eligibility(&mut self) -> Result<Option<bool>> {
        self.memory_owner.ready()?;
        if self.memory_owner.powered_off.load(Ordering::Acquire) {
            // The coordinator must receive Shutdown even for an unstarted or
            // halted peer; do not acknowledge pending INIT/SIPI first.
            return Ok(Some(true));
        }
        self.state_ready()?;
        if !self.memory_owner.irqchip_created.load(Ordering::Acquire)
            || self.native_io_unsettled
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
}

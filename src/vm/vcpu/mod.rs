//! CPU abstraction layer.
//!
//! This module provides backend-agnostic types and traits for CPU emulation.

pub(crate) mod budget;
pub use budget::{DEFAULT_RETIREMENT_QUANTUM, RetirementRun, RetirementStop};
#[cfg(feature = "debug")]
mod debug_memory;
pub mod exit;
#[cfg(feature = "debug")]
pub use debug_memory::{DebugAddressSpace, X86DebugPaging};
mod power;
pub mod state;

pub use exit::VcpuExit;
pub use power::CpuPowerRequest;
pub use state::{
    Aarch32CpuState, Aarch32Registers, Aarch32SystemRegisters, Aarch64CpuState,
    Aarch64ExecutionState, Aarch64Registers, Aarch64SystemRegisters, CortexMCpuState,
    CortexMRegisters, CortexMSystemRegisters, CpuState, DescriptorTable, HexagonCpuState,
    HexagonRegisters, Registers, RiscVCpuState, RiscVRegisters, RiscVVectorState, Segment,
    SystemRegisters, X86_64CpuState,
};

use crate::error::{Error, Result};

/// Intent of a guest memory access, used by [`VCpu::translate_addr`] to select
/// the correct permission check when walking translation structures, and to tag
/// recorded accesses ([`MemRecord`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemAccess {
    /// Data read.
    Read,
    /// Data write.
    Write,
    /// Instruction fetch.
    Exec,
}

/// A single recorded guest memory access, surfaced to embedders via per-access
/// memory hooks. Produced by backends that implement [`VCpu::set_mem_recording`]
/// and collected through [`VCpu::drain_mem_records`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemRecord {
    /// Kind of access: [`MemAccess::Read`], [`MemAccess::Write`], or
    /// [`MemAccess::Exec`] (instruction fetch).
    pub access: MemAccess,
    /// Guest virtual/linear address of the access.
    pub addr: u64,
    /// Access width in bytes.
    pub size: u8,
    /// The value read or written, little-endian, truncated to 64 bits (the low
    /// 8 bytes for wider vector accesses; 0 for fetches).
    pub value: u64,
    /// Address of the instruction that performed the access, when the backend
    /// knows it. Instruction-fetch records carry the fetch address. Backends
    /// that do not track RIP per access report zero.
    pub rip: u64,
}

/// Abstract vCPU interface.
///
/// This trait is implemented by both KVM and emulator backends.
pub trait VCpu: Send {
    /// Test instrumentation only; never part of a checkpoint or public ABI.
    #[cfg(test)]
    fn bounded_native_test_count(&self) -> u64 {
        0
    }
    /// Run the vCPU until an exit condition.
    fn run(&mut self) -> Result<VcpuExit>;

    /// Execute at most `budget` retired units, preserving the reason for yield.
    /// One Hexagon packet is one unit. A zero budget performs no execution.
    /// Non-stepping backends reject before entry; there is no unbounded fallback.
    /// A delivered exception/interrupt with no retirement returns StateChange.
    /// A backend fault retains previously retired work in RetirementRun instead
    /// of losing that progress through an outer error. See RetirementStop.
    fn run_retirement_budget(&mut self, budget: u64) -> Result<RetirementRun> {
        budget::run(self, budget, budget::ErrorRetirement::NoRetirement)
    }

    /// Execute exactly one guest instruction.
    ///
    /// Returns `Ok(Some(exit))` when the instruction produced a synchronous
    /// exit condition (HLT, port/MMIO I/O, software interrupt, ...), or
    /// `Ok(None)` to indicate the vCPU should continue at the next instruction.
    ///
    /// Faults the backend can deliver to the guest (page faults, #GP) are
    /// handled internally exactly as they are by [`VCpu::run`], so single
    /// stepping observes identical architectural behaviour to free-running
    /// execution. Backends that cannot single-step return
    /// [`Error::InvalidConfig`]; callers should consult
    /// [`VCpu::supports_stepping`] first.
    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        Err(Error::InvalidConfig(
            "single-instruction stepping is not supported by this backend".to_string(),
        ))
    }

    /// Whether [`VCpu::step_insn`] is implemented by this backend.
    fn supports_stepping(&self) -> bool {
        false
    }

    /// Translate a guest virtual/linear address to a guest-physical address
    /// using the backend's current paging/translation state.
    ///
    /// Backends with no active translation stage (paging disabled, or a flat
    /// address space) return the input unchanged. This is intended for
    /// tooling/debugger-style access: it never sets accessed/dirty bits and
    /// never injects a fault — a translation failure is reported as `Err`.
    fn translate_addr(&mut self, vaddr: u64, _access: MemAccess) -> Result<u64> {
        Ok(vaddr)
    }

    /// Reset architectural state to this backend's power-on defaults, clearing
    /// the run state (halt/wait) and resetting registers. Attached guest memory
    /// is left untouched. The default reports that reset is unsupported so the
    /// caller can fall back to an explicit state load.
    fn reset(&mut self) -> Result<()> {
        Err(Error::InvalidConfig(
            "architectural reset is not supported by this backend".to_string(),
        ))
    }

    /// The current program counter / instruction pointer. Cheap fast path used
    /// by stepping and hook dispatch; the default reads it from a full state
    /// snapshot, which backends may override for efficiency.
    fn current_pc(&self) -> u64 {
        self.get_state().map(|s| s.pc()).unwrap_or(0)
    }

    /// Deliver an x86 INIT signal while preserving state that INIT leaves unchanged.
    /// Secondary startup/wait-for-SIPI ownership belongs to the VMM coordinator.
    fn deliver_init(&mut self) -> Result<()> {
        Err(Error::InvalidConfig(
            "INIT delivery is not supported by this backend".into(),
        ))
    }

    /// Install the reset state and return width/EL selected by PSCI CPU_ON.
    /// The coordinator publishes online status only after this succeeds.
    fn start_aarch64_cpu(&mut self, _entry: u64, _context: u64, _pstate: u64) -> Result<()> {
        Err(Error::InvalidConfig(
            "AArch64 startup is not supported by this backend".into(),
        ))
    }

    /// Leave a halted or waiting state (x86 `HLT`, AArch64 `WFI`/`WFE`, a
    /// latched shutdown) so the next `run` or `step_insn` executes from the
    /// current PC. Embedders call it when they explicitly restart execution;
    /// guests leave these states through interrupts as usual. Backends without
    /// such a state keep the default no-op.
    fn wake(&mut self) {}

    /// Set only the program counter, preserving all other architectural and
    /// backend execution state. Backends should override this when loading a
    /// full [`CpuState`] has reset semantics or omits implementation-private
    /// state such as vector registers or monotonic counters.
    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        let mut state = self.get_state()?;
        match &mut state {
            CpuState::X86_64(s) => s.regs.rip = pc,
            CpuState::Aarch64(s) => s.regs.pc = pc,
            CpuState::Aarch32(s) => s.regs.pc = pc as u32,
            CpuState::CortexM(s) => s.regs.pc = pc as u32,
            CpuState::RiscV(s) => s.regs.pc = pc,
            CpuState::Hexagon(s) => s.regs.set_pc(pc as u32),
            CpuState::Ebpf(s) => s.regs.pc = pc,
        }
        self.set_state(&state)
    }

    /// Whether this backend records per-access memory events (load/store/fetch)
    /// for memory hooks.
    fn supports_mem_hooks(&self) -> bool {
        false
    }

    /// Enable or disable recording of individual guest memory accesses. While
    /// enabled, every data load/store and instruction fetch is appended to an
    /// internal buffer drained by [`VCpu::drain_mem_records`]. Recording is off
    /// by default and has near-zero cost when disabled. Backends without support
    /// treat this as a no-op.
    fn set_mem_recording(&mut self, _on: bool) {
        let _ = _on;
    }

    /// Append all buffered memory-access records to `out` and clear the buffer.
    /// No-op on backends that do not record.
    fn drain_mem_records(&mut self, _out: &mut Vec<MemRecord>) {}

    /// Get general-purpose registers (x86_64 only).
    fn get_regs(&self) -> Result<Registers> {
        match self.get_state()? {
            CpuState::X86_64(state) => Ok(state.regs),
            _ => Err(Error::InvalidConfig(
                "register access is only supported for x86_64".to_string(),
            )),
        }
    }

    /// Set general-purpose registers (x86_64 only).
    fn set_regs(&mut self, regs: &Registers) -> Result<()> {
        match self.get_state()? {
            CpuState::X86_64(state) => self.set_state(&CpuState::x86_64(regs.clone(), state.sregs)),
            _ => Err(Error::InvalidConfig(
                "register access is only supported for x86_64".to_string(),
            )),
        }
    }

    /// Get system registers (x86_64 only).
    fn get_sregs(&self) -> Result<SystemRegisters> {
        match self.get_state()? {
            CpuState::X86_64(state) => Ok(state.sregs),
            _ => Err(Error::InvalidConfig(
                "system register access is only supported for x86_64".to_string(),
            )),
        }
    }

    /// Set system registers (x86_64 only).
    fn set_sregs(&mut self, sregs: &SystemRegisters) -> Result<()> {
        match self.get_state()? {
            CpuState::X86_64(state) => self.set_state(&CpuState::x86_64(state.regs, sregs.clone())),
            _ => Err(Error::InvalidConfig(
                "system register access is only supported for x86_64".to_string(),
            )),
        }
    }

    /// Get this backend's public architectural register projection. Private
    /// controls, banked registers and in-flight state may require a separate
    /// backend context; this projection alone does not establish a checkpoint.
    fn get_state(&self) -> Result<CpuState>;

    /// Set the public architectural register projection. Private-state/reset
    /// semantics are backend-specific; this is not a complete checkpoint import.
    fn set_state(&mut self, state: &CpuState) -> Result<()>;

    /// Update the exported architectural register state without resetting
    /// implementation-private runtime state (for example monotonic execution
    /// counters, pending device state, or debugger configuration).  Register
    /// APIs use this path after modifying a snapshot returned by
    /// [`VCpu::get_state`].  Backends whose `set_state` operation is already a
    /// non-destructive overlay may use the default implementation.
    fn update_state(&mut self, state: &CpuState) -> Result<()> {
        self.set_state(state)
    }

    /// Complete an I/O in operation by providing the data read from the device.
    fn complete_io_in(&mut self, data: &[u8]);

    /// Acknowledge a successfully dispatched output exit. Backends that stage
    /// an output retain its operand and re-emit it until this call succeeds.
    /// Callers must dispatch and acknowledge before publishing a complete
    /// device/CPU checkpoint; a failed dispatch must leave it unacknowledged.
    fn complete_io_out(&mut self) -> Result<()> {
        Ok(())
    }

    /// Surface a failed or still-pending completion before further execution
    /// or an automatic checkpoint. Fallible SDK backends latch their status in
    /// the compatibility `complete_io_in` callback and report it here.
    fn io_completion_result(&self) -> Result<()> {
        Ok(())
    }

    /// Inject an external interrupt (hardware IRQ).
    /// Returns Ok(true) if the interrupt was injected, Ok(false) if interrupts are disabled.
    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        // Default implementation does nothing
        let _ = vector;
        Ok(false)
    }

    /// Check if interrupts are enabled and can be injected.
    fn can_inject_interrupt(&self) -> bool {
        false
    }

    /// Inject a Non-Maskable Interrupt (NMI).
    /// NMIs are delivered regardless of the IF flag.
    /// Returns Ok(true) if delivered, Ok(false) if blocked (e.g., during NMI handling).
    fn inject_nmi(&mut self) -> Result<bool> {
        Ok(false)
    }

    /// Attach the VMM-owned local APIC for this processor. Software backends
    /// route guest LAPIC MMIO to this same controller. Backends with native
    /// interrupt controllers retain their backend-specific ownership contract.
    fn attach_local_apic(
        &mut self,
        _lapic: std::sync::Arc<std::sync::Mutex<crate::devices::lapic::LocalApic>>,
    ) {
    }

    /// Attach the shared PL011 console device so the vCPU's memory bridge can
    /// service UART MMIO synchronously against the same instance the VMM
    /// feeds with host console input. Default no-op — only the AArch64
    /// emulator backend uses it.
    fn attach_pl011(
        &mut self,
        _base: u64,
        _uart: std::sync::Arc<std::sync::Mutex<crate::devices::pl011::Pl011>>,
    ) {
    }

    /// Attach the shared Samsung S3C UART console device (ARMv6/S3C64xx
    /// machines). Default no-op.
    fn attach_s3c_uart(
        &mut self,
        _uart: std::sync::Arc<std::sync::Mutex<crate::devices::s3c64xx::S3cUart>>,
    ) {
    }

    /// Attach the PCI host bridge so the emulator MMU can divert a physical
    /// MMIO aperture from RAM to PCI device BAR handlers. `ap_base..ap_end`
    /// bounds that aperture. Default no-op — only the x86_64 emulator backend
    /// implements MMIO-BAR routing.
    fn set_pci_bridge(
        &mut self,
        _bridge: std::sync::Arc<std::sync::Mutex<crate::devices::pci::PciStub>>,
        _ap_base: u64,
        _ap_end: u64,
    ) {
    }

    /// Attach x86_64 real-mode BIOS state for El-Torito boot. Default no-op —
    /// only the x86_64 emulator backend services BIOS interrupts directly.
    fn attach_x86_64_bios(&mut self, _cdrom: Option<std::sync::Arc<Vec<u8>>>, _mem_bytes: u64) {}

    /// Retain immutable boot attachment and reported memory across CPU reset.
    fn x86_bios_binding(&self) -> Option<(Option<std::sync::Arc<Vec<u8>>>, u64)> {
        None
    }

    /// Enable or disable single-step mode for debugging.
    #[cfg(feature = "debug")]
    fn set_single_step(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// Check if single-step mode is enabled.
    #[cfg(feature = "debug")]
    fn is_single_step(&self) -> bool {
        false
    }

    /// Mark whether an external debugger is controlling this vCPU.
    ///
    /// Software backends use this to keep debug execution precise (for example by
    /// disabling JIT tiers). Hardware backends may ignore it.
    #[cfg(feature = "debug")]
    fn set_debugger_active(&mut self, active: bool) {
        let _ = active;
    }

    /// Snapshot the selected CPU's address space without executing a guest access.
    #[cfg(feature = "debug")]
    fn debug_address_space(&self) -> Result<DebugAddressSpace> {
        Ok(DebugAddressSpace::Physical)
    }

    /// Prepare code/translation caches before a stopped debugger RAM publication.
    #[cfg(feature = "debug")]
    fn debug_memory_changed(&mut self, pages: &[u64]) -> Result<()> {
        for &page in pages {
            self.invalidate_code_cache(page);
        }
        Ok(())
    }

    /// Whether internal execute breakpoints can be installed on this CPU.
    #[cfg(feature = "debug")]
    fn supports_debug_breakpoints(&self) -> bool {
        false
    }

    /// Set an internal debugger execute breakpoint.
    ///
    /// This must not modify guest memory: guest-owned `INT3` instructions and
    /// anti-debug code that reads its own text must continue to observe the
    /// original bytes.
    #[cfg(feature = "debug")]
    fn set_debug_breakpoint(&mut self, addr: u64) -> Result<()> {
        let _ = addr;
        Err(Error::InvalidConfig(
            "internal debugger breakpoints are not supported by this backend".to_string(),
        ))
    }

    /// Clear an internal debugger execute breakpoint.
    #[cfg(feature = "debug")]
    fn clear_debug_breakpoint(&mut self, addr: u64) -> Result<()> {
        let _ = addr;
        Err(Error::InvalidConfig(
            "internal debugger breakpoints are not supported by this backend".to_string(),
        ))
    }

    /// Invalidate any cached instruction decodes for the given address.
    /// Called when modifying code memory (e.g., for software breakpoints).
    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, addr: u64) {
        let _ = addr;
    }

    /// Get vCPU ID.
    fn id(&self) -> u32;

    /// Current bootstrap role used by x86 INIT. Static-role adapters retain
    /// CPU zero; backends with writable IA32_APIC_BASE override this query.
    fn is_bootstrap_processor(&self) -> Result<bool> {
        Ok(self.id() == 0)
    }

    /// Get current instruction count (for snapshotting).
    fn instruction_count(&self) -> u64 {
        0
    }

    /// Pure checkpoint admission before any live state changes. Backends should
    /// validate private/profile-dependent state here as well. Native setter I/O
    /// may still fail later; this hook does not promise hardware transactions.
    fn validate_checkpoint_state(
        &self,
        state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
    ) -> Result<()> {
        if std::mem::discriminant(state) != std::mem::discriminant(&self.get_state()?) {
            return Err(Error::InvalidConfig(
                "checkpoint CPU kind does not match target vCPU".to_string(),
            ));
        }
        Ok(())
    }

    /// Capture additional backend-owned state, without replacing the stable
    /// public register and legacy emulator projections. The producer's format
    /// must include its version and admit all bytes before changing live state.
    fn capture_backend_context(&self) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(None)
    }

    /// Capture a public/private pair at the caller's backend boundary. Native
    /// producers override this to derive both projections from one capture.
    /// A RAM scope is supplied during complete capture; rollback preparation
    /// can take a stopped CPU record before physical publication begins.
    fn capture_checkpoint_record(
        &self,
        _boundary: &crate::backend::CheckpointBoundary<'_>,
        scope: Option<&crate::vm::memory::checkpoint::CheckpointPublication<'_>>,
    ) -> Result<(
        crate::vm::snapshot::CpuSnapshot,
        Option<crate::vm::snapshot::BackendContext>,
    )> {
        let public = crate::vm::snapshot::CpuSnapshot {
            state: self.get_state()?,
            emulator: self.get_emulator_state().unwrap_or_default(),
        };
        let private = match scope {
            Some(scope) => self.capture_backend_context_in_scope(scope)?,
            None => self.capture_backend_context()?,
        };
        Ok((public, private))
    }

    /// Restore through an already-held backend exclusion boundary. Ordinary
    /// standalone imports retain their existing entry point and semantics.
    fn restore_checkpoint_record(
        &mut self,
        _boundary: &crate::backend::CheckpointBoundary<'_>,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.restore_checkpoint_context(state, emulator, context)
    }

    /// Complete derived controller and translation state after shared RAM and
    /// backend state have been published, with entry still excluded.
    fn finish_checkpoint_restore(
        &mut self,
        _boundary: &crate::backend::CheckpointBoundary<'_>,
        _context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        Ok(())
    }

    /// Preserve execution state across address-map reconstruction. A mapping
    /// change may invalidate reservation rights independently of CPU state.
    fn capture_backend_context_for_remap(
        &self,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.capture_backend_context()
    }

    /// Owned controllers that must be locked before freezing physical memory.
    fn checkpoint_owned_gics(
        &self,
    ) -> Vec<std::sync::Arc<std::sync::Mutex<crate::isa::arm::aarch64::gic::Gic>>> {
        Vec::new()
    }

    /// Software ARM power state, checked against the shared PSCI graph.
    fn checkpoint_powered_off(&self) -> Option<bool> {
        None
    }

    /// Capture at the caller's existing memory/controller boundary.
    fn capture_backend_context_in_scope(
        &self,
        _scope: &crate::vm::memory::checkpoint::CheckpointPublication<'_>,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.capture_backend_context()
    }

    /// Admit detached bindings before any RAM or live CPU changes. The permit
    /// publishes only after restored RAM has been copied under the same scope.
    fn prepare_checkpoint_publication<'scope, 'bindings>(
        &mut self,
        scope: &'scope crate::vm::memory::checkpoint::CheckpointPublication<'bindings>,
    ) -> Result<crate::vm::memory::checkpoint::CpuPublication<'scope, 'bindings>> {
        Ok(scope.empty())
    }

    /// Immutable contents referenced by this CPU's backend context. The bundle
    /// stores each complete identity once, regardless of the number of CPUs.
    fn capture_checkpoint_resources(&self) -> Result<Vec<crate::vm::snapshot::CheckpointResource>> {
        Ok(Vec::new())
    }

    /// Pure resource-reference discovery after backend/machine admission.
    fn checkpoint_resource_references(
        &self,
        _context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<Vec<crate::vm::snapshot::ResourceKey>> {
        Ok(Vec::new())
    }

    /// Prepare a replacement CPU offside, with all resource binding and decode
    /// failures resolved before publication. None retains the existing backend
    /// restore path; it does not promise whole-VM/native setter transactions.
    fn prepare_checkpoint_replacement(
        &self,
        _state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
        _context: Option<&crate::vm::snapshot::BackendContext>,
        _resources: &crate::vm::snapshot::PreparedResources,
    ) -> Result<Option<Box<dyn VCpu>>> {
        Ok(None)
    }

    /// Interpreter profile retained by a RISC-V backend context. Embedders use
    /// it when reconstructing the same engine after a memory-map change/reset.
    fn riscv_configuration(&self) -> Option<crate::isa::riscv::RiscVConfig> {
        None
    }

    /// Selected software AArch64 FP/SIMD ArmFeatures bits, when configurable.
    fn aarch64_fp_features(&self) -> Option<u64> {
        None
    }

    /// Select backend-owned capability flags without replacing execution state.
    fn set_aarch64_fp_features(&mut self, _features: u64) -> Result<()> {
        Err(Error::InvalidConfig(
            "backend has no configurable AArch64 FP/SIMD profile".into(),
        ))
    }

    fn x86_configuration(&self) -> Option<crate::isa::x86_64::X86_64Config> {
        None
    }

    fn set_x86_configuration(&mut self, _config: crate::isa::x86_64::X86_64Config) -> Result<()> {
        Err(Error::InvalidConfig(
            "backend has no software-x86 configuration".into(),
        ))
    }

    /// Admit backend-owned state against the declared machine before any live
    /// restore changes. Standalone context import has no machine envelope.
    fn validate_checkpoint_for_machine(
        &self,
        _config: &crate::config::CheckpointConfig,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_context(state, emulator, context)
    }

    /// Admit the public projection and backend record before any CPU is changed.
    fn validate_checkpoint_context(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_state(state, emulator)?;
        if context.is_some() {
            return Err(Error::InvalidConfig(
                "checkpoint context producer differs from target backend".into(),
            ));
        }
        Ok(())
    }

    /// Import an admitted backend record, or retain the legacy projection path
    /// for files/backends without one. Native publication remains fallible.
    fn restore_checkpoint_context(
        &mut self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_context(state, emulator, context)?;
        self.set_state(state)?;
        self.set_emulator_state(emulator)
    }

    /// Get extended emulator state for snapshotting.
    /// Returns None for backends that don't support it.
    fn get_emulator_state(&self) -> Option<crate::vm::snapshot::EmulatorState> {
        None
    }

    /// Set extended emulator state (for snapshot restore).
    fn set_emulator_state(&mut self, _state: &crate::vm::snapshot::EmulatorState) -> Result<()> {
        Ok(())
    }
}

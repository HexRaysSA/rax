//! CPU abstraction layer.
//!
//! This module provides backend-agnostic types and traits for CPU emulation.

pub mod exit;
pub mod state;

pub use exit::VcpuExit;
pub use state::{
    Aarch32CpuState, Aarch32Registers, Aarch32SystemRegisters, Aarch64CpuState, Aarch64Registers,
    Aarch64SystemRegisters, CortexMCpuState, CortexMRegisters, CortexMSystemRegisters, CpuState,
    DescriptorTable, HexagonCpuState, HexagonRegisters, Registers, RiscVCpuState, RiscVRegisters,
    RiscVVectorState, Segment, SystemRegisters, X86_64CpuState,
};

use crate::error::{Error, Result};

/// Intent of a guest memory access, used by [`VCpu::translate_addr`] to select
/// the correct permission check when walking translation structures, and to tag
/// recorded accesses ([`MemRecord`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug)]
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
}

/// Abstract vCPU interface.
///
/// This trait is implemented by both KVM and emulator backends.
pub trait VCpu: Send {
    /// Run the vCPU until an exit condition.
    fn run(&mut self) -> Result<VcpuExit>;

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

    /// Get complete CPU state.
    fn get_state(&self) -> Result<CpuState>;

    /// Set complete CPU state.
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

    /// Get current instruction count (for snapshotting).
    fn instruction_count(&self) -> u64 {
        0
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

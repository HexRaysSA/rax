//! Cortex-M vCPU for instruction-level embedders.
//!
//! Drives the [`CortexMCpu`] Thumb core (Cortex-M4 by default: Armv7E-M,
//! integer and DSP; no Floating-point Extension) over guest memory that the
//! embedder owns completely. The System Control Space (NVIC, SysTick, SCB)
//! is modeled inside the core and reached through the system registers of
//! the vCPU state, not memory-mapped: addresses in `0xE000_E000` are
//! ordinary guest memory here.
//!
//! The fault policy matches the other ARM instruction engines: exceptions
//! are taken architecturally through the vector table at VTOR (SVC enters
//! SVCall; a BKPT, an unaligned multiple access, a division by zero with
//! CCR.DIV_0_TRP, or an invalid state enters UsageFault or HardFault as the
//! priorities and SHCSR enables decide), while a memory fault or an
//! UNDEFINED (or floating-point) instruction is returned to the embedder at
//! the faulting instruction, which does not retire. `WFI`/`WFE` report
//! [`VcpuExit::Hlt`]; a lockup is an error.

use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::error::{Error, GuestMemoryFault, MemoryAccessKind, MemoryFaultKind, Result};
use crate::isa::arm::cortex_m::exception::number;
use crate::isa::arm::cortex_m::exec::Snapshot;
use crate::isa::arm::cortex_m::{CortexMCpu, CortexMVariant, EntryError, Fault};
use crate::isa::arm::cpu_trait::{AccessType, ArmCpu, CpuExit};
use crate::isa::arm::memory::{ArmMemory, MemResult, MemoryError, MmioHandler};
use crate::vm::vcpu::{CortexMCpuState, CpuState, VCpu, VcpuExit};

/// Guest memory with a local exclusive monitor. A failed access records the
/// first inaccessible byte.
#[derive(Debug)]
struct Bridge {
    mem: Arc<GuestMemoryMmap>,
    fault: Arc<Mutex<Option<GuestMemoryFault>>>,
    exclusive: Option<(u64, u8)>,
}

impl Bridge {
    fn fail(
        &self,
        addr: u64,
        len: usize,
        access: MemoryAccessKind,
        error: vm_memory::GuestMemoryError,
    ) -> MemoryError {
        let address = match error {
            vm_memory::GuestMemoryError::PartialBuffer { completed, .. } => {
                addr.saturating_add(completed as u64)
            }
            vm_memory::GuestMemoryError::InvalidGuestAddress(address) => address.0,
            _ => addr,
        };
        *self.fault.lock().unwrap() = Some(GuestMemoryFault::unmapped(address, len, access));
        MemoryError::Unmapped {
            addr: address,
            size: len,
            access: match access {
                MemoryAccessKind::Read => AccessType::Read,
                MemoryAccessKind::Write => AccessType::Write,
                MemoryAccessKind::Fetch => AccessType::InstructionFetch,
            },
        }
    }

    fn load(&self, addr: u64, buf: &mut [u8], access: MemoryAccessKind) -> MemResult<()> {
        let len = buf.len();
        self.mem
            .read_slice(buf, GuestAddress(addr))
            .map_err(|error| self.fail(addr, len, access, error))
    }
}

impl ArmMemory for Bridge {
    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.load(addr, buf, MemoryAccessKind::Read)
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        // A store that would fault part way publishes nothing.
        if !self.mem.check_range(GuestAddress(addr), data.len()) {
            let mut probe = vec![0u8; data.len()];
            let error = self
                .mem
                .read_slice(&mut probe, GuestAddress(addr))
                .err()
                .unwrap_or(vm_memory::GuestMemoryError::InvalidGuestAddress(
                    GuestAddress(addr),
                ));
            return Err(self.fail(addr, data.len(), MemoryAccessKind::Write, error));
        }
        self.mem
            .write_slice(data, GuestAddress(addr))
            .map_err(|error| self.fail(addr, data.len(), MemoryAccessKind::Write, error))
    }

    fn fetch(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.load(addr, buf, MemoryAccessKind::Fetch)
    }

    fn mark_exclusive(&mut self, addr: u64, size: u8) {
        self.exclusive = Some((addr, size));
    }

    fn check_exclusive(&mut self, addr: u64, size: u8) -> bool {
        self.exclusive.take() == Some((addr, size))
    }

    fn clear_exclusive(&mut self) {
        self.exclusive = None;
    }

    fn requires_alignment(&self) -> bool {
        // ARMv7-M permits unaligned LDR/STR/LDRH/STRH unless CCR.UNALIGN_TRP
        // is set; the core checks the forms that must be aligned.
        false
    }

    /// The System Control Space is modeled inside the core.
    fn register_mmio(&mut self, _base: u64, _size: u64, _handler: Box<dyn MmioHandler>) {}

    fn unregister_mmio(&mut self, _base: u64) {}
}

/// Cortex-M vCPU for embedders that own the whole address space.
pub struct CortexMVcpu {
    id: u32,
    cpu: CortexMCpu,
    fault: Arc<Mutex<Option<GuestMemoryFault>>>,
}

impl CortexMVcpu {
    /// Creates a Cortex-M4 (ARMv7E-M with FPU and DSP) vCPU over `mem` in
    /// Thread mode, privileged, on the main stack.
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        Self::with_variant(id, mem, CortexMVariant::CortexM4)
    }

    /// Creates a vCPU for `variant`.
    pub fn with_variant(id: u32, mem: Arc<GuestMemoryMmap>, variant: CortexMVariant) -> Self {
        let fault = Arc::new(Mutex::new(None));
        let bridge = Bridge {
            mem,
            fault: fault.clone(),
            exclusive: None,
        };
        CortexMVcpu {
            id,
            cpu: CortexMCpu::new(variant, Box::new(bridge)),
            fault,
        }
    }

    fn undefined(&self, pc: u64, insn: u32) -> Error {
        Error::InvalidInstruction {
            pc,
            diagnosis: format!("undefined Thumb encoding {insn:#x}"),
        }
    }

    /// The fault a failed access recorded, or one built from the core's
    /// report when the bridge saw none.
    fn fault_error(&self, address: u64, access: AccessType) -> Error {
        let recorded = self.fault.lock().unwrap().take();
        Error::GuestAccess(recorded.unwrap_or(GuestMemoryFault {
            address,
            size: 0,
            access: match access {
                AccessType::InstructionFetch => MemoryAccessKind::Fetch,
                AccessType::Read => MemoryAccessKind::Read,
                AccessType::Write | AccessType::Atomic => MemoryAccessKind::Write,
            },
            kind: MemoryFaultKind::Other,
        }))
    }

    /// Reports an exception entry that failed. A bus error during stacking
    /// or the vector read is a memory fault of the instruction; a lockup
    /// stops the processor.
    fn entry_error(&self, pc: u64, error: EntryError) -> Error {
        match error {
            EntryError::Bus { address, access } => self.fault_error(u64::from(address), access),
            EntryError::Lockup { exception } => Error::Emulator(format!(
                "Cortex-M lockup at {pc:#x}: exception {exception} escalated at HardFault priority"
            )),
        }
    }

    /// Takes synchronous `exception` with `return_address` stacked; on
    /// failure the state is `before` the instruction, which retries.
    fn take(
        &mut self,
        before: Snapshot,
        pc: u64,
        exception: u16,
        return_address: u32,
    ) -> Result<()> {
        match self.cpu.take_synchronous(exception, return_address) {
            Ok(_) => Ok(()),
            Err(error) => {
                self.cpu.restore(before);
                Err(self.entry_error(pc, error))
            }
        }
    }

    fn step_one(&mut self) -> Result<Option<VcpuExit>> {
        if self.cpu.is_sleeping() {
            // WFI/WFE with no event source: stay asleep until woken.
            return Ok(Some(VcpuExit::Hlt));
        }
        *self.fault.lock().unwrap() = None;
        let pc = self.cpu.get_pc();
        let before = self.cpu.snapshot();
        match self.cpu.execute_one() {
            Ok(CpuExit::Svc(_)) => {
                // The PC is past the SVC, the preferred return address.
                let next = self.cpu.get_pc() as u32;
                self.take(before, pc, number::SV_CALL, next)?;
                Ok(None)
            }
            Ok(CpuExit::Breakpoint(_)) => {
                // Without a debugger a BKPT is a DebugMonitor exception,
                // which escalates to HardFault, returning to the BKPT.
                self.take(before, pc, number::DEBUG_MONITOR, pc as u32)?;
                Ok(None)
            }
            Ok(CpuExit::Wfi | CpuExit::Wfe) => Ok(Some(VcpuExit::Hlt)),
            Ok(_) => Ok(None),
            Err(Fault::Undefined(insn) | Fault::NoCoprocessor(insn)) => {
                Err(self.undefined(pc, insn))
            }
            Err(Fault::Bus { address, access }) => {
                Err(self.fault_error(u64::from(address), access))
            }
            Err(Fault::Lockup) => Err(self.entry_error(pc, EntryError::Lockup { exception: 0 })),
            Err(fault) => {
                // INVSTATE, UNALIGNED, DIVBYZERO: a UsageFault at the
                // instruction.
                match self.cpu.take_fault(fault) {
                    Ok(_) => Ok(None),
                    Err(error) => {
                        self.cpu.restore(before);
                        Err(self.entry_error(pc, error))
                    }
                }
            }
        }
    }
}

impl VCpu for CortexMVcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        loop {
            if let Some(exit) = self.step_one()? {
                return Ok(exit);
            }
        }
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.step_one()
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn current_pc(&self) -> u64 {
        self.cpu.get_pc()
    }

    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        self.cpu.set_pc(pc);
        Ok(())
    }

    fn wake(&mut self) {
        self.cpu.wake();
    }

    fn get_state(&self) -> Result<CpuState> {
        Ok(CpuState::CortexM(CortexMCpuState {
            regs: self.cpu.export_regs(),
            sregs: self.cpu.export_sregs(),
        }))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let CpuState::CortexM(state) = state else {
            return Err(Error::Emulator(
                "expected Cortex-M state for Cortex-M vCPU".to_string(),
            ));
        };
        self.cpu.import_sregs(&state.sregs);
        self.cpu.import_regs(&state.regs);
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {}

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        self.cpu.instruction_count()
    }
}

#[cfg(test)]
#[path = "cortex_m_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cortex_m_oracle_tests.rs"]
mod oracle_tests;

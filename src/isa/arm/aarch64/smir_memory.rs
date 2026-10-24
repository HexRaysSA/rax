//! Exact architectural fetch/load hooks for state-backed SMIR execution.

use super::AArch64Cpu;
use crate::isa::arm::common::cpu::ArmError;
use crate::smir::ir::context::Aarch64RegState;
use crate::smir::ir::memory::{MemoryError, PacketCommitError, PacketWrite, SmirMemory};
use crate::smir::ir::types::{AtomicOp, Endian, FenceKind, MemWidth, MemoryOrder};

/// Add the CPU's MMU, alignment, device and precise-fault behavior to a SMIR
/// memory backend. Generic SMIR accesses retain `memory`'s semantics. The
/// caller must provide coherent backing when mixing generic accesses with
/// architectural AArch64 hooks. No generic fault is guessed into an ESR.
pub struct Aarch64MemoryBridge<'a, M: SmirMemory + ?Sized> {
    cpu: &'a mut AArch64Cpu,
    memory: &'a mut M,
    import_state: bool,
}

impl<'a, M: SmirMemory + ?Sized> Aarch64MemoryBridge<'a, M> {
    pub fn new(cpu: &'a mut AArch64Cpu, memory: &'a mut M) -> Self {
        Self {
            cpu,
            memory,
            import_state: true,
        }
    }

    /// The CPU JIT uses this only for a single typed PAuth instruction whose
    /// full snapshot was taken from this CPU immediately before entry. PAuth
    /// does not write keys, translation roots or controls; ERET's restored
    /// PSTATE is committed after its final memory hook. No external caller can
    /// select this path or mutate the borrowed CPU during the native call.
    pub(crate) fn for_current_pauth_instruction(
        cpu: &'a mut AArch64Cpu,
        memory: &'a mut M,
    ) -> Self {
        Self {
            cpu,
            memory,
            import_state: false,
        }
    }

    fn synchronize(&mut self, state: &Aarch64RegState) -> Result<(), ArmError> {
        if !self.import_state {
            return Ok(());
        }
        let exported = state.to_cpu_state().ok_or_else(|| {
            ArmError::Configuration("AArch64 memory bridge requires complete state".into())
        })?;
        AArch64Cpu::validate_saved_state(exported.regs.pstate, &exported.sregs)?;
        self.cpu.validate_sregs(&exported.sregs)?;
        self.cpu.import_sregs(&exported.sregs)?;
        self.cpu.set_pstate_bits(exported.regs.pstate)?;
        self.cpu.set_current_sp(exported.regs.sp);
        Ok(())
    }
}

impl<M: SmirMemory + ?Sized> SmirMemory for Aarch64MemoryBridge<'_, M> {
    fn aarch64_instruction_guarded(
        &mut self,
        pc: u64,
        state: &Aarch64RegState,
    ) -> Option<Result<bool, ArmError>> {
        Some(
            self.synchronize(state)
                .and_then(|()| self.cpu.smir_fetch_guarded(pc)),
        )
    }

    fn aarch64_load64(
        &mut self,
        address: u64,
        state: &Aarch64RegState,
    ) -> Option<Result<u64, ArmError>> {
        Some(
            self.synchronize(state)
                .and_then(|()| self.cpu.pauth_load64(address)),
        )
    }

    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.memory.read(address, bytes)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write(address, bytes)
    }

    fn probe_write(&self, address: u64, size: usize) -> Result<(), MemoryError> {
        self.memory.probe_write(address, size)
    }

    fn write_packet(&mut self, writes: &[PacketWrite]) -> Result<(), PacketCommitError> {
        self.memory.write_packet(writes)
    }

    fn atomic_load(
        &mut self,
        address: u64,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        self.memory.atomic_load(address, size, order)
    }

    fn atomic_store(
        &mut self,
        address: u64,
        value: u64,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), MemoryError> {
        self.memory.atomic_store(address, value, size, order)
    }

    fn compare_and_swap(
        &mut self,
        address: u64,
        expected: u64,
        new: u64,
        size: MemWidth,
        success: MemoryOrder,
        failure: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError> {
        self.memory
            .compare_and_swap(address, expected, new, size, success, failure)
    }

    fn compare_and_swap_writeback(
        &mut self,
        address: u64,
        expected: u64,
        new: u64,
        size: MemWidth,
        success: MemoryOrder,
        failure: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError> {
        self.memory
            .compare_and_swap_writeback(address, expected, new, size, success, failure)
    }

    fn compare_and_swap_128(
        &mut self,
        address: u64,
        expected: [u64; 2],
        new: [u64; 2],
        success: MemoryOrder,
        failure: MemoryOrder,
    ) -> Result<([u64; 2], bool), MemoryError> {
        self.memory
            .compare_and_swap_128(address, expected, new, success, failure)
    }

    fn compare_and_swap_pair(
        &mut self,
        address: u64,
        expected: [u64; 2],
        new: [u64; 2],
        success: MemoryOrder,
        failure: MemoryOrder,
    ) -> Result<([u64; 2], bool), MemoryError> {
        self.memory
            .compare_and_swap_pair(address, expected, new, success, failure)
    }

    fn atomic_rmw(
        &mut self,
        address: u64,
        operation: AtomicOp,
        value: u64,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        self.memory
            .atomic_rmw(address, operation, value, size, order)
    }

    fn atomic_rmw_endian(
        &mut self,
        address: u64,
        operation: AtomicOp,
        value: u64,
        size: MemWidth,
        order: MemoryOrder,
        endian: Endian,
    ) -> Result<u64, MemoryError> {
        self.memory
            .atomic_rmw_endian(address, operation, value, size, order, endian)
    }

    fn compare_and_swap_endian(
        &mut self,
        address: u64,
        expected: u64,
        new: u64,
        size: MemWidth,
        success: MemoryOrder,
        failure: MemoryOrder,
        endian: Endian,
    ) -> Result<(u64, bool), MemoryError> {
        self.memory
            .compare_and_swap_endian(address, expected, new, size, success, failure, endian)
    }

    fn load_exclusive(&mut self, address: u64, size: MemWidth) -> Result<u64, MemoryError> {
        self.memory.load_exclusive(address, size)
    }

    fn store_exclusive(
        &mut self,
        address: u64,
        value: u64,
        size: MemWidth,
    ) -> Result<bool, MemoryError> {
        self.memory.store_exclusive(address, value, size)
    }

    fn clear_exclusive(&mut self) {
        self.cpu.clear_exclusive_monitor();
        self.memory.clear_exclusive();
    }

    fn fence(&mut self, kind: FenceKind) {
        self.memory.fence(kind);
    }

    fn prefetch(&mut self, address: u64, write: bool) {
        self.memory.prefetch(address, write);
    }

    fn invalidate_translation(&mut self, address: u64) {
        self.memory.invalidate_translation(address);
    }

    fn invalidate_process_context(&mut self, kind: u8, pcid: u16, linear: u64) {
        self.memory.invalidate_process_context(kind, pcid, linear);
    }

    fn probe(&self, address: u64, size: usize, write: bool) -> Result<(), MemoryError> {
        self.memory.probe(address, size, write)
    }
}

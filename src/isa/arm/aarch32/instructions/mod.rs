//! ARM instruction execution handlers.
//!
//! This module implements the execution semantics for ARMv7 instructions,
//! providing handlers that operate on the Armv7Cpu state and memory.
//!
//! # Organization
//!
//! Instructions are grouped by category:
//! - Data processing (arithmetic, logical, shift, compare)
//! - Multiply operations
//! - Load/Store operations (including halfword, signed, exclusive)
//! - Branch operations
//! - System operations
//! - Coprocessor operations
//!
//! # Execution Pattern
//!
//! Each instruction handler follows this pattern:
//! 1. Decode operands from the instruction
//! 2. Read source operands (handling PC+8 for R15)
//! 3. Perform the operation
//! 4. Write destination (handling branch for R15)
//! 5. Optionally update flags if S bit is set

use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{
    ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr, add_with_carry, compute_n_flag,
    compute_z_flag, condition_passed, expand_imm_c, shift_c, sign_extend,
};
use crate::isa::arm::aarch32::vfp::{
    Fpscr, NeonSize, RoundingMode, vabs_f16_bits, vabs_f32, vabs_f64, vadd_f16_bits, vadd_f32,
    vadd_f64, vadd_i, vand, vbic, vcls_i, vclz_i, vcmp_f16_bits_with_exception,
    vcmp_f32_with_exception, vcmp_f64_with_exception, vcnt_i8, vcvt_f16_bits_f32,
    vcvt_f32_f16_bits, vcvt_f32_f64, vcvt_f32_s32, vcvt_f32_s32_fixed, vcvt_f32_u32,
    vcvt_f32_u32_fixed, vcvt_f64_f32, vcvt_f64_s32, vcvt_f64_s32_fixed, vcvt_f64_u32,
    vcvt_f64_u32_fixed, vcvt_s32_f32, vcvt_s32_f32_fixed, vcvt_s32_f32_round, vcvt_s32_f64,
    vcvt_s32_f64_fixed, vcvt_s32_f64_round, vcvt_u32_f32, vcvt_u32_f32_fixed, vcvt_u32_f32_round,
    vcvt_u32_f64, vcvt_u32_f64_fixed, vcvt_u32_f64_round, vcvtr_s32_f32, vcvtr_s32_f64,
    vcvtr_u32_f32, vcvtr_u32_f64, vdiv_f16_bits, vdiv_f32, vdiv_f64, veor, vfma_f16_bits, vfma_f32,
    vfma_f64, vfms_f16_bits, vfms_f32, vfms_f64, vfnma_f16_bits, vfnma_f32, vfnma_f64,
    vfnms_f16_bits, vfnms_f32, vfnms_f64, vfp_expand_imm_f16, vfp_expand_imm_f32,
    vfp_expand_imm_f64, vmaxnm_f16_bits, vmaxnm_f32, vmaxnm_f64, vminnm_f16_bits, vminnm_f32,
    vminnm_f64, vmla_f16_bits, vmla_f32, vmla_f64, vmls_f16_bits, vmls_f32, vmls_f64,
    vmul_f16_bits, vmul_f32, vmul_f64, vmvn, vneg_f16_bits, vneg_f32, vneg_f64, vnmla_f16_bits,
    vnmla_f32, vnmla_f64, vnmls_f16_bits, vnmls_f32, vnmls_f64, vnmul_f16_bits, vnmul_f32,
    vnmul_f64, vorn, vorr, vrev, vrint_f16_bits, vrint_f32, vrint_f64, vsqrt_f16_bits, vsqrt_f32,
    vsqrt_f64, vsub_f16_bits, vsub_f32, vsub_f64, vsub_i,
};
use crate::isa::arm::decoder::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType};

// ---- module tree (auto-split) ----
mod control;
pub use control::*;
mod coproc;
pub use coproc::*;
mod data;
pub use data::*;
mod decode;
pub use decode::*;
mod memory;
pub use memory::*;
mod misc;
pub use misc::*;
mod neon;
pub use neon::*;
mod predicates;
pub use predicates::*;
mod registers;
pub use registers::*;
#[cfg(test)]
mod tests;

/// Result of instruction execution.
#[derive(Clone, Debug)]
pub enum ExecResult {
    /// Instruction executed successfully, advance to next instruction.
    Continue,
    /// Branch taken to specified address.
    Branch(u32),
    /// Exception raised (SVC, UDF, etc.).
    Exception(ExceptionType),
    /// CPU halted (WFI, WFE).
    Halt,
    /// Undefined instruction.
    Undefined,
    /// Memory error during execution.
    MemoryFault(MemoryError),
}

#[derive(Clone, Copy, Debug)]
struct NeonStructMem {
    addr: u32,
    /// The alignment the encoding asks for (1: none).
    align: u32,
    regs: u8,
    first: u8,
    inc: u8,
    ebytes: u8,
    writeback: bool,
    rn: usize,
    rm: usize,
}

#[derive(Clone, Copy, Debug)]
struct NeonAllLanesMem {
    addr: u32,
    /// The alignment the encoding asks for (1: none).
    align: u32,
    streams: u8,
    regs: u8,
    first: u8,
    inc: u8,
    ebytes: u8,
    writeback: bool,
    rn: usize,
    rm: usize,
}

#[derive(Clone, Copy, Debug)]
struct NeonSingleLaneMem {
    addr: u32,
    /// The alignment the encoding asks for (1: none).
    align: u32,
    streams: u8,
    first: u8,
    inc: u8,
    ebytes: u8,
    index: u8,
    writeback: bool,
    rn: usize,
    rm: usize,
}

/// Exception types that can be raised during execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExceptionType {
    /// Supervisor call (SVC/SWI).
    SupervisorCall(u32),
    /// Undefined instruction.
    UndefinedInstruction,
    /// Prefetch abort.
    PrefetchAbort(u32),
    /// Data abort.
    DataAbort(u32),
    /// IRQ interrupt.
    Irq,
    /// FIQ fast interrupt.
    Fiq,
    /// Breakpoint (BKPT).
    Breakpoint(u16),
    /// Reset.
    Reset,
}

impl ExceptionType {
    /// Get the exception vector offset for this exception.
    pub fn vector_offset(&self) -> u32 {
        match self {
            ExceptionType::Reset => 0x00,
            ExceptionType::UndefinedInstruction => 0x04,
            ExceptionType::SupervisorCall(_) => 0x08,
            ExceptionType::PrefetchAbort(_) => 0x0C,
            ExceptionType::DataAbort(_) => 0x10,
            ExceptionType::Irq => 0x18,
            ExceptionType::Fiq => 0x1C,
            ExceptionType::Breakpoint(_) => 0x0C, // Uses prefetch abort vector
        }
    }

    /// Get the mode to enter for this exception.
    pub fn target_mode(&self) -> ProcessorMode {
        match self {
            ExceptionType::Reset | ExceptionType::SupervisorCall(_) => ProcessorMode::Supervisor,
            ExceptionType::UndefinedInstruction => ProcessorMode::Undefined,
            ExceptionType::PrefetchAbort(_) | ExceptionType::Breakpoint(_) => ProcessorMode::Abort,
            ExceptionType::DataAbort(_) => ProcessorMode::Abort,
            ExceptionType::Irq => ProcessorMode::Irq,
            ExceptionType::Fiq => ProcessorMode::Fiq,
        }
    }
}

/// Exclusive monitor state for LDREX/STREX.
#[derive(Clone, Debug, Default)]
pub struct ExclusiveMonitor {
    /// Address being monitored (None if not monitoring).
    pub address: Option<u32>,
    /// Size of the monitored region (1, 2, 4, or 8 bytes).
    pub size: u8,
}

impl ExclusiveMonitor {
    pub fn new() -> Self {
        ExclusiveMonitor {
            address: None,
            size: 0,
        }
    }

    /// Mark an address as exclusive.
    pub fn mark_exclusive(&mut self, addr: u32, size: u8) {
        self.address = Some(addr);
        self.size = size;
    }

    /// Check if address is still exclusive and clear the monitor.
    pub fn check_and_clear(&mut self, addr: u32, size: u8) -> bool {
        if self.address == Some(addr) && self.size == size {
            self.address = None;
            true
        } else {
            self.address = None;
            false
        }
    }

    /// Clear the exclusive monitor.
    pub fn clear(&mut self) {
        self.address = None;
    }
}

/// Coprocessor interface for MRC/MCR instructions.
pub trait Coprocessor {
    /// Read from coprocessor register.
    fn read(&self, crn: u8, crm: u8, opc1: u8, opc2: u8) -> Option<u32>;
    /// Write to coprocessor register.
    fn write(&mut self, crn: u8, crm: u8, opc1: u8, opc2: u8, value: u32) -> bool;
}

/// Null coprocessor (returns all zeros, ignores writes).
pub struct NullCoprocessor;

impl Coprocessor for NullCoprocessor {
    fn read(&self, _crn: u8, _crm: u8, _opc1: u8, _opc2: u8) -> Option<u32> {
        Some(0)
    }
    fn write(&mut self, _crn: u8, _crm: u8, _opc1: u8, _opc2: u8, _value: u32) -> bool {
        true
    }
}

/// Instruction executor that ties together CPU state, memory, and decoded instructions.
pub struct Executor<'a, M: ArmMemory> {
    pub cpu: &'a mut Armv7Cpu,
    pub mem: &'a mut M,
    /// Exclusive monitor for LDREX/STREX.
    pub exclusive_monitor: ExclusiveMonitor,
    /// Vector base address register (VBAR).
    pub vbar: u32,
}

// =============================================================================
// Tests
// =============================================================================

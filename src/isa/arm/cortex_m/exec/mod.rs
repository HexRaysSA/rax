//! Armv7-M Thumb instruction execution (Armv7-M ARM, DDI 0403E.e: chapter
//! A5 for the encodings, chapter A7 for the instruction semantics).
//!
//! [`CortexMCpu::execute_one`] runs one instruction. A fault leaves the
//! architectural registers as they were before the instruction (a multiple
//! store may already have written some words; restarting it rewrites them),
//! and the caller decides whether to take the fault architecturally or to
//! report it.
//!
//! The Floating-point Extension is not implemented: coprocessor instructions
//! report [`Fault::NoCoprocessor`].

mod alu;
mod control;
mod dp;
mod ldst;
mod mul;
mod thumb16;

use super::cpu::CortexMCpu;
use crate::isa::arm::common::cpu::{AccessType, CpuExit};

/// xPSR.T (EPSR bit 24).
pub(super) const XPSR_T: u32 = 1 << 24;
/// xPSR.Q (APSR bit 27).
const XPSR_Q: u32 = 1 << 27;
/// The EPSR IT/ICI bits: [26:25] and [15:10].
const XPSR_IT_MASK: u32 = 0x0600_FC00;

/// Why an instruction did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// An UNDEFINED (or UNPREDICTABLE, treated as UNDEFINED) encoding: a
    /// UsageFault with UFSR.UNDEFINSTR. Carries the encoding (a 32-bit
    /// instruction as `hw1 << 16 | hw2`).
    Undefined(u32),
    /// A coprocessor instruction with no coprocessor: a UsageFault with
    /// UFSR.NOCP.
    NoCoprocessor(u32),
    /// Execution with EPSR.T clear: a UsageFault with UFSR.INVSTATE.
    InvalidState,
    /// An unaligned access that must be aligned: a UsageFault with
    /// UFSR.UNALIGNED.
    Unaligned { address: u32 },
    /// A division by zero with CCR.DIV_0_TRP set: a UsageFault with
    /// UFSR.DIVBYZERO.
    DivideByZero,
    /// A precise bus error at `address`.
    Bus { address: u32, access: AccessType },
    /// An exception return had to take a fault at HardFault priority or
    /// higher: the processor locks up.
    Lockup,
}

/// The registers an instruction can change, restored when it faults.
#[derive(Clone, Copy)]
pub struct Snapshot {
    regs: [u32; 13],
    sp_main: u32,
    sp_process: u32,
    lr: u32,
    pc: u32,
    xpsr: u32,
    primask: bool,
    faultmask: bool,
    basepri: u8,
    control: u8,
    thread_mode: bool,
    current_exception: u16,
    active: [u64; 8],
    sleeping: bool,
    event_register: bool,
    insn_count: u64,
    cycle_count: u64,
}

impl CortexMCpu {
    /// Captures the architectural registers (and the instruction count).
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            regs: self.regs,
            sp_main: self.sp_main,
            sp_process: self.sp_process,
            lr: self.lr,
            pc: self.pc,
            xpsr: self.xpsr,
            primask: self.primask,
            faultmask: self.faultmask,
            basepri: self.basepri,
            control: self.control,
            thread_mode: self.thread_mode,
            current_exception: self.current_exception,
            active: self.active,
            sleeping: self.sleeping,
            event_register: self.event_register,
            insn_count: self.insn_count,
            cycle_count: self.cycle_count,
        }
    }

    /// Reinstates a [`Snapshot`].
    pub fn restore(&mut self, s: Snapshot) {
        self.regs = s.regs;
        self.sp_main = s.sp_main;
        self.sp_process = s.sp_process;
        self.lr = s.lr;
        self.pc = s.pc;
        self.xpsr = s.xpsr;
        self.primask = s.primask;
        self.faultmask = s.faultmask;
        self.basepri = s.basepri;
        self.control = s.control;
        self.thread_mode = s.thread_mode;
        self.current_exception = s.current_exception;
        self.active = s.active;
        self.sleeping = s.sleeping;
        self.event_register = s.event_register;
        self.insn_count = s.insn_count;
        self.cycle_count = s.cycle_count;
    }

    /// Executes the instruction at PC. On a fault the registers are as they
    /// were before it; BKPT is reported before it executes, with PC still
    /// addressing it.
    pub fn execute_one(&mut self) -> Result<CpuExit, Fault> {
        let saved = self.snapshot();
        let result = self.execute_inner();
        if result.is_err() {
            self.restore(saved);
        }
        result
    }

    fn execute_inner(&mut self) -> Result<CpuExit, Fault> {
        let addr = self.pc;
        if self.xpsr & XPSR_T == 0 {
            return Err(Fault::InvalidState);
        }
        let hw1 = self.fetch_halfword(addr)?;
        // A5.1: 0b11101, 0b11110 and 0b11111 in bits [15:11] start a
        // 32-bit instruction.
        let wide = hw1 >> 11 >= 0b11101;
        let insn = if wide {
            let hw2 = self.fetch_halfword(addr.wrapping_add(2))?;
            (u32::from(hw1) << 16) | u32::from(hw2)
        } else {
            u32::from(hw1)
        };
        // BKPT is unconditional, even inside an IT block (A7.7.17).
        if !wide && hw1 & 0xFF00 == 0xBE00 {
            return Ok(CpuExit::Breakpoint(u32::from(hw1 & 0xFF)));
        }
        self.insn_addr = addr;
        self.pc = addr.wrapping_add(if wide { 4 } else { 2 });
        self.it_rewritten = false;
        let it = self.it_state();
        let exit = if it & 0xF != 0 && !self.condition_passed(it >> 4) {
            CpuExit::Continue
        } else if wide {
            self.execute32(insn)?
        } else {
            self.execute16(hw1)?
        };
        if !self.it_rewritten {
            self.it_advance();
        }
        self.insn_count += 1;
        self.cycle_count += 1;
        Ok(exit)
    }

    /// Dispatches a 32-bit instruction (A5.3, Table A5-9).
    fn execute32(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let op1 = (insn >> 27) & 3;
        let op2 = (insn >> 20) & 0x7F;
        let op = (insn >> 15) & 1;
        if !self.has_thumb2() && !(op1 == 0b10 && op == 1) {
            // Armv6-M has only BL, MSR, MRS, the barriers, and UDF.
            return Err(Fault::Undefined(insn));
        }
        match op1 {
            0b01 => {
                if op2 & 0b1100100 == 0 {
                    self.load_store_multiple(insn)
                } else if op2 & 0b1100100 == 0b0000100 {
                    self.load_store_dual_exclusive(insn)
                } else if op2 & 0b1100000 == 0b0100000 {
                    self.dp_shifted_register(insn)
                } else {
                    Err(Fault::NoCoprocessor(insn))
                }
            }
            0b10 if op == 1 => self.branches_misc(insn),
            0b10 if op2 & 0b0100000 == 0 => self.dp_modified_immediate(insn),
            0b10 => self.dp_plain_immediate(insn),
            _ => {
                if op2 & 0b1110001 == 0 {
                    self.store_single(insn)
                } else if op2 & 0b1100111 == 0b0000001 {
                    self.load_byte(insn)
                } else if op2 & 0b1100111 == 0b0000011 {
                    self.load_halfword(insn)
                } else if op2 & 0b1100111 == 0b0000101 {
                    self.load_word(insn)
                } else if op2 & 0b1110000 == 0b0100000 {
                    self.dp_register(insn)
                } else if op2 & 0b1111000 == 0b0110000 {
                    self.multiply(insn)
                } else if op2 & 0b1111000 == 0b0111000 {
                    self.long_multiply_divide(insn)
                } else if op2 & 0b1000000 != 0 {
                    Err(Fault::NoCoprocessor(insn))
                } else {
                    Err(Fault::Undefined(insn))
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Registers
    // ---------------------------------------------------------------------

    /// `R[n]`: the PC reads as this instruction's address plus 4, and the
    /// SP with bits [1:0] clear.
    pub(super) fn r(&self, n: u32) -> u32 {
        match n {
            0..=12 => self.regs[n as usize],
            13 => self.current_sp() & !3,
            14 => self.lr,
            _ => self.insn_addr.wrapping_add(4),
        }
    }

    /// `R[n] = value` for `n <= 14`; the SP ignores bits [1:0].
    pub(super) fn set_r(&mut self, n: u32, value: u32) {
        match n {
            0..=12 => self.regs[n as usize] = value,
            13 => self.set_current_sp(value & !3),
            14 => self.lr = value,
            _ => self.branch_write_pc(value),
        }
    }

    /// `Align(PC, 4)`.
    pub(super) fn pc_aligned(&self) -> u32 {
        self.r(15) & !3
    }

    pub(super) fn flag_c(&self) -> bool {
        self.get_c()
    }

    pub(super) fn set_nzc(&mut self, result: u32, carry: bool) {
        self.update_nz(result);
        self.set_c(carry);
    }

    pub(super) fn set_nzcv(&mut self, result: u32, carry: bool, overflow: bool) {
        self.update_nz(result);
        self.set_c(carry);
        self.set_v(overflow);
    }

    /// Sets APSR.Q (sticky).
    pub(super) fn set_q_flag(&mut self) {
        self.xpsr |= XPSR_Q;
    }

    pub(super) fn ge(&self) -> u32 {
        (self.xpsr >> 16) & 0xF
    }

    pub(super) fn set_ge(&mut self, ge: u32) {
        self.xpsr = (self.xpsr & !0x000F_0000) | ((ge & 0xF) << 16);
    }

    /// Whether the Armv7E-M DSP extension is implemented.
    pub(super) fn has_dsp(&self) -> bool {
        self.variant().has_dsp()
    }

    /// Whether the variant implements the Armv7-M Thumb-2 instruction set
    /// (every variant except Armv6-M and Armv8-M Baseline).
    pub(super) fn has_thumb2(&self) -> bool {
        self.variant().has_thumb2()
    }

    // ---------------------------------------------------------------------
    // IT state (A7.3 "Conditional execution")
    // ---------------------------------------------------------------------

    /// ITSTATE: IT[7:2] is xPSR[15:10], IT[1:0] is xPSR[26:25].
    pub(super) fn it_state(&self) -> u32 {
        ((self.xpsr >> 25) & 3) | (((self.xpsr >> 10) & 0x3F) << 2)
    }

    pub(super) fn set_it_state(&mut self, it: u32) {
        self.xpsr = (self.xpsr & !XPSR_IT_MASK) | ((it & 3) << 25) | (((it >> 2) & 0x3F) << 10);
        self.it_rewritten = true;
    }

    pub(super) fn in_it_block(&self) -> bool {
        self.it_state() & 0xF != 0
    }

    pub(super) fn last_in_it_block(&self) -> bool {
        self.it_state() & 0xF == 0x8
    }

    /// Rejects an instruction that must not be inside an IT block, or
    /// must be the last instruction of one (UNPREDICTABLE otherwise).
    pub(super) fn require_outside_it(&self, insn: u32) -> Result<(), Fault> {
        if self.in_it_block() {
            Err(Fault::Undefined(insn))
        } else {
            Ok(())
        }
    }

    pub(super) fn require_last_in_it(&self, insn: u32) -> Result<(), Fault> {
        if self.in_it_block() && !self.last_in_it_block() {
            Err(Fault::Undefined(insn))
        } else {
            Ok(())
        }
    }

    /// `ITAdvance()`.
    fn it_advance(&mut self) {
        let it = self.it_state();
        let next = if it & 7 == 0 {
            0
        } else {
            (it & 0xE0) | ((it << 1) & 0x1F)
        };
        self.xpsr = (self.xpsr & !XPSR_IT_MASK) | ((next & 3) << 25) | (((next >> 2) & 0x3F) << 10);
    }

    // ---------------------------------------------------------------------
    // PC writes (A2.3.1)
    // ---------------------------------------------------------------------

    pub(super) fn branch_write_pc(&mut self, address: u32) {
        self.pc = address & !1;
    }

    /// `BXWritePC()`: an EXC_RETURN value in Handler mode returns from the
    /// exception; otherwise bit 0 selects EPSR.T (clear faults on the next
    /// instruction).
    pub(super) fn bx_write_pc(&mut self, address: u32) -> Result<(), Fault> {
        if !self.thread_mode && address >> 28 == 0xF {
            self.it_rewritten = true;
            return self.exception_return(address);
        }
        self.blx_write_pc(address);
        Ok(())
    }

    pub(super) fn blx_write_pc(&mut self, address: u32) {
        if address & 1 != 0 {
            self.xpsr |= XPSR_T;
        } else {
            self.xpsr &= !XPSR_T;
        }
        self.pc = address & !1;
    }

    // ---------------------------------------------------------------------
    // Memory (A3.2: MemA is aligned, MemU may be unaligned)
    // ---------------------------------------------------------------------

    fn fetch_halfword(&self, address: u32) -> Result<u16, Fault> {
        let mut b = [0u8; 2];
        self.memory
            .fetch(u64::from(address), &mut b)
            .map_err(|_| Fault::Bus {
                address,
                access: AccessType::InstructionFetch,
            })?;
        Ok(u16::from_le_bytes(b))
    }

    fn load(&self, address: u32, size: u32) -> Result<u32, Fault> {
        let mut b = [0u8; 4];
        self.memory
            .read(u64::from(address), &mut b[..size as usize])
            .map_err(|_| Fault::Bus {
                address,
                access: AccessType::Read,
            })?;
        Ok(u32::from_le_bytes(b))
    }

    fn store(&mut self, address: u32, size: u32, value: u32) -> Result<(), Fault> {
        self.memory
            .write(u64::from(address), &value.to_le_bytes()[..size as usize])
            .map_err(|_| Fault::Bus {
                address,
                access: AccessType::Write,
            })
    }

    fn check_aligned(address: u32, size: u32) -> Result<(), Fault> {
        if address & (size - 1) != 0 {
            Err(Fault::Unaligned { address })
        } else {
            Ok(())
        }
    }

    /// `MemA[address, size]`.
    pub(super) fn mem_a(&self, address: u32, size: u32) -> Result<u32, Fault> {
        Self::check_aligned(address, size)?;
        self.load(address, size)
    }

    /// `MemA[address, size] = value`.
    pub(super) fn set_mem_a(&mut self, address: u32, size: u32, value: u32) -> Result<(), Fault> {
        Self::check_aligned(address, size)?;
        self.store(address, size, value)
    }

    /// `MemU[address, size]`: unaligned unless CCR.UNALIGN_TRP.
    pub(super) fn mem_u(&self, address: u32, size: u32) -> Result<u32, Fault> {
        if self.scb().unaligned_trap() {
            Self::check_aligned(address, size)?;
        }
        self.load(address, size)
    }

    /// `MemU[address, size] = value`.
    pub(super) fn set_mem_u(&mut self, address: u32, size: u32, value: u32) -> Result<(), Fault> {
        if self.scb().unaligned_trap() {
            Self::check_aligned(address, size)?;
        }
        self.store(address, size, value)
    }
}

#[cfg(test)]
#[path = "exec_tests.rs"]
mod tests;

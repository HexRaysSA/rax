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

use crate::arm::decoder::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType};
use crate::arm::execution::{
    add_with_carry, compute_n_flag, compute_z_flag, condition_passed, expand_imm_c, shift_c,
    sign_extend, ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr,
};

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

impl<'a, M: ArmMemory> Executor<'a, M> {
    /// Create a new executor.
    pub fn new(cpu: &'a mut Armv7Cpu, mem: &'a mut M) -> Self {
        Executor {
            cpu,
            mem,
            exclusive_monitor: ExclusiveMonitor::new(),
            vbar: 0,
        }
    }

    /// Create a new executor with custom VBAR.
    pub fn with_vbar(cpu: &'a mut Armv7Cpu, mem: &'a mut M, vbar: u32) -> Self {
        Executor {
            cpu,
            mem,
            exclusive_monitor: ExclusiveMonitor::new(),
            vbar,
        }
    }

    /// Execute a single decoded instruction.
    pub fn execute(&mut self, insn: &DecodedInsn) -> ExecResult {
        // Check condition code
        if let Some(cond) = insn.cond {
            if !self.condition_passed(cond) {
                return ExecResult::Continue;
            }
        }

        // Dispatch based on mnemonic
        match insn.mnemonic {
            // Data Processing - Arithmetic
            Mnemonic::ADD | Mnemonic::ADDS => self.exec_add(insn),
            Mnemonic::ADC | Mnemonic::ADCS => self.exec_adc(insn),
            Mnemonic::SUB | Mnemonic::SUBS => self.exec_sub(insn),
            Mnemonic::SBC | Mnemonic::SBCS => self.exec_sbc(insn),
            Mnemonic::RSB | Mnemonic::RSBS => self.exec_rsb(insn),
            Mnemonic::RSC | Mnemonic::RSCS => self.exec_rsc(insn),
            Mnemonic::NEG | Mnemonic::NEGS => self.exec_neg(insn),

            // Data Processing - Logical
            Mnemonic::AND | Mnemonic::ANDS => self.exec_and(insn),
            Mnemonic::ORR | Mnemonic::ORRS => self.exec_orr(insn),
            Mnemonic::EOR | Mnemonic::EORS => self.exec_eor(insn),
            Mnemonic::BIC | Mnemonic::BICS => self.exec_bic(insn),
            Mnemonic::ORN | Mnemonic::ORNS => self.exec_orn(insn),

            // Data Processing - Move
            Mnemonic::MOV | Mnemonic::MOVS => self.exec_mov(insn),
            Mnemonic::MVN | Mnemonic::MVNS => self.exec_mvn(insn),
            Mnemonic::MOVZ => self.exec_movw(insn),
            Mnemonic::MOVK => self.exec_movt(insn),

            // Data Processing - Compare
            Mnemonic::CMP => self.exec_cmp(insn),
            Mnemonic::CMN => self.exec_cmn(insn),
            Mnemonic::TST => self.exec_tst(insn),
            Mnemonic::TEQ => self.exec_teq(insn),

            // Data Processing - Shift
            Mnemonic::LSL | Mnemonic::LSLS => self.exec_lsl(insn),
            Mnemonic::LSR | Mnemonic::LSRS => self.exec_lsr(insn),
            Mnemonic::ASR | Mnemonic::ASRS => self.exec_asr(insn),
            Mnemonic::ROR | Mnemonic::RORS => self.exec_ror(insn),
            Mnemonic::RRX | Mnemonic::RRXS => self.exec_rrx(insn),

            // Multiply
            Mnemonic::MUL | Mnemonic::MULS => self.exec_mul(insn),
            Mnemonic::MLA => self.exec_mla(insn),
            Mnemonic::MLS => self.exec_mls(insn),
            Mnemonic::UMULL | Mnemonic::UMULLS => self.exec_umull(insn),
            Mnemonic::SMULL | Mnemonic::SMULLS => self.exec_smull(insn),
            Mnemonic::UMLAL => self.exec_umlal(insn),
            Mnemonic::SMLAL => self.exec_smlal(insn),
            Mnemonic::UMAAL => self.exec_umaal(insn),
            Mnemonic::SDIV => self.exec_sdiv(insn),
            Mnemonic::UDIV => self.exec_udiv(insn),

            // Branch
            Mnemonic::B | Mnemonic::BCC => self.exec_b(insn),
            Mnemonic::BL => self.exec_bl(insn),
            Mnemonic::BX => self.exec_bx(insn),
            Mnemonic::BLX => self.exec_blx(insn),
            Mnemonic::CBZ => self.exec_cbz(insn),
            Mnemonic::CBNZ => self.exec_cbnz(insn),
            Mnemonic::TBB => self.exec_tbb(insn),
            Mnemonic::TBH => self.exec_tbh(insn),

            // Load/Store Word/Byte
            Mnemonic::LDR => self.exec_ldr(insn),
            Mnemonic::LDRB => self.exec_ldrb(insn),
            Mnemonic::STR => self.exec_str(insn),
            Mnemonic::STRB => self.exec_strb(insn),

            // Load/Store Halfword/Signed
            Mnemonic::LDRH => self.exec_ldrh(insn),
            Mnemonic::LDRSH => self.exec_ldrsh(insn),
            Mnemonic::LDRSB => self.exec_ldrsb(insn),
            Mnemonic::STRH => self.exec_strh(insn),

            // Load/Store Double
            Mnemonic::LDP => self.exec_ldrd(insn), // LDP is the AArch64 name, LDRD for AArch32
            Mnemonic::STP => self.exec_strd(insn),

            // Load/Store Exclusive
            Mnemonic::LDXR => self.exec_ldrex(insn),
            Mnemonic::STXR => self.exec_strex(insn),
            Mnemonic::LDXRB => self.exec_ldrexb(insn),
            Mnemonic::STXRB => self.exec_strexb(insn),
            Mnemonic::LDXRH => self.exec_ldrexh(insn),
            Mnemonic::STXRH => self.exec_strexh(insn),
            Mnemonic::CLREX => self.exec_clrex(insn),

            // Load/Store Multiple
            Mnemonic::LDM | Mnemonic::LDMIA => self.exec_ldm(insn),
            Mnemonic::LDMDB => self.exec_ldmdb(insn),
            Mnemonic::STM | Mnemonic::STMIA => self.exec_stm(insn),
            Mnemonic::STMDB => self.exec_stmdb(insn),
            Mnemonic::PUSH => self.exec_push(insn),
            Mnemonic::POP => self.exec_pop(insn),

            // System
            Mnemonic::SVC | Mnemonic::SWI => self.exec_svc(insn),
            Mnemonic::NOP | Mnemonic::YIELD | Mnemonic::SEV | Mnemonic::SEVL => {
                ExecResult::Continue
            }
            Mnemonic::WFI | Mnemonic::WFE => ExecResult::Halt,
            Mnemonic::BKPT => self.exec_bkpt(insn),
            Mnemonic::UDF => ExecResult::Exception(ExceptionType::UndefinedInstruction),
            Mnemonic::MRS => self.exec_mrs(insn),
            Mnemonic::MSR => self.exec_msr(insn),
            Mnemonic::DMB | Mnemonic::DSB | Mnemonic::ISB => ExecResult::Continue, // Memory barriers
            Mnemonic::IT => self.exec_it(insn),

            // Coprocessor
            Mnemonic::MCR => self.exec_mcr(insn),
            Mnemonic::MRC => self.exec_mrc(insn),

            // Bit manipulation
            Mnemonic::CLZ => self.exec_clz(insn),
            Mnemonic::REV => self.exec_rev(insn),
            Mnemonic::REV16 => self.exec_rev16(insn),
            Mnemonic::REVSH => self.exec_revsh(insn),
            Mnemonic::RBIT => self.exec_rbit(insn),

            // Bit field
            Mnemonic::BFC => self.exec_bfc(insn),
            Mnemonic::BFI => self.exec_bfi(insn),
            Mnemonic::UBFX => self.exec_ubfx(insn),
            Mnemonic::SBFX => self.exec_sbfx(insn),

            // Extension
            Mnemonic::SXTB => self.exec_sxtb(insn),
            Mnemonic::SXTH => self.exec_sxth(insn),
            Mnemonic::UXTB => self.exec_uxtb(insn),
            Mnemonic::UXTH => self.exec_uxth(insn),

            // Saturating arithmetic
            Mnemonic::USAT => self.exec_usat(insn),
            Mnemonic::SSAT => self.exec_ssat(insn),

            // AArch32 media / DSP
            Mnemonic::A32_PARALLEL => self.exec_a32_parallel(insn),
            Mnemonic::A32_PKH => self.exec_a32_pkh(insn),
            Mnemonic::A32_EXTEND => self.exec_a32_extend(insn),
            Mnemonic::A32_SAT16 => self.exec_a32_sat16(insn),
            Mnemonic::A32_SAT_ADDSUB => self.exec_a32_sat_addsub(insn),
            Mnemonic::A32_HMUL => self.exec_a32_hmul(insn),
            Mnemonic::A32_DUAL => self.exec_a32_dual(insn),
            Mnemonic::A32_SMLALD => self.exec_a32_smlald(insn),
            Mnemonic::A32_SMMUL => self.exec_a32_smmul(insn),
            Mnemonic::A32_USAD => self.exec_a32_usad(insn),
            Mnemonic::A32_SEL => self.exec_a32_sel(insn),

            // Undefined/Unknown
            Mnemonic::UNDEFINED | Mnemonic::UNKNOWN => ExecResult::Undefined,

            // Not yet implemented
            _ => ExecResult::Undefined,
        }
    }

    // =========================================================================
    // Exception Handling
    // =========================================================================

    /// Take an exception and switch to the appropriate mode.
    pub fn take_exception(&mut self, exception: ExceptionType) {
        let target_mode = exception.target_mode();
        let vector_offset = exception.vector_offset();

        // Save CPSR to SPSR of target mode
        let cpsr_value = self.cpu.cpsr.to_u32();

        // Calculate return address based on exception type
        let return_addr = match &exception {
            ExceptionType::SupervisorCall(_) => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::UndefinedInstruction => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::PrefetchAbort(_) => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::DataAbort(_) => self.cpu.regs[15].wrapping_add(8),
            ExceptionType::Irq => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::Fiq => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::Breakpoint(_) => self.cpu.regs[15].wrapping_add(4),
            ExceptionType::Reset => 0,
        };

        // Switch mode
        self.cpu.change_mode(target_mode);

        // Set SPSR
        if let Some(spsr) = self.cpu.get_current_spsr_mut() {
            *spsr = Psr::from_u32(cpsr_value);
        }

        // Set LR to return address
        self.cpu.regs[14] = return_addr;

        // Update CPSR
        self.cpu.cpsr.i = true; // Disable IRQ
        if matches!(exception, ExceptionType::Fiq | ExceptionType::Reset) {
            self.cpu.cpsr.f = true; // Disable FIQ
        }
        self.cpu.cpsr.t = false; // Enter ARM mode

        // Branch to vector
        self.cpu.regs[15] = self.vbar.wrapping_add(vector_offset);
    }

    /// Return from exception (MOVS PC, LR or SUBS PC, LR, #imm with S bit).
    pub fn exception_return(&mut self) {
        if let Some(spsr) = self.cpu.get_current_spsr() {
            let spsr_value = spsr.to_u32();
            let new_mode = ProcessorMode::from_bits(spsr.mode);

            if let Some(mode) = new_mode {
                // Restore CPSR from SPSR
                self.cpu.cpsr = Psr::from_u32(spsr_value);

                // Switch mode
                if mode as u8 != self.cpu.cpsr.mode {
                    self.cpu.change_mode(mode);
                }
            }
        }
    }

    /// Check if condition is passed.
    fn condition_passed(&self, cond: Condition) -> bool {
        condition_passed(
            cond as u8,
            self.cpu.cpsr.n,
            self.cpu.cpsr.z,
            self.cpu.cpsr.c,
            self.cpu.cpsr.v,
        )
    }

    /// Get register value with PC+8 handling.
    #[inline]
    fn reg(&self, r: usize) -> u32 {
        self.cpu.reg(r)
    }

    /// Set register value, handling PC writes as branches.
    #[inline]
    fn set_reg(&mut self, r: usize, value: u32) -> ExecResult {
        if r == 15 {
            ExecResult::Branch(value)
        } else {
            self.cpu.regs[r] = value;
            ExecResult::Continue
        }
    }

    /// Set register value, with S bit handling for PC (exception return).
    fn set_reg_with_s(&mut self, r: usize, value: u32, s_bit: bool) -> ExecResult {
        if r == 15 {
            if s_bit && !self.cpu.is_user_or_system() {
                // Exception return
                self.exception_return();
            }
            ExecResult::Branch(value)
        } else {
            self.cpu.regs[r] = value;
            ExecResult::Continue
        }
    }

    /// Update APSR flags for logical operations (N, Z, C from shifter).
    fn set_flags_logical(&mut self, result: u32) {
        self.cpu.cpsr.n = compute_n_flag(result);
        self.cpu.cpsr.z = compute_z_flag(result);
        self.cpu.cpsr.c = self.cpu.carry_out;
    }

    /// Update APSR flags for arithmetic operations (N, Z, C, V).
    fn set_flags_arithmetic(&mut self, result: u32) {
        self.cpu.cpsr.n = compute_n_flag(result);
        self.cpu.cpsr.z = compute_z_flag(result);
        self.cpu.cpsr.c = self.cpu.carry_out;
        self.cpu.cpsr.v = self.cpu.overflow;
    }

    // =========================================================================
    // Data Processing - Arithmetic
    // =========================================================================

    fn exec_add(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(self.reg(n), operand2, false);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    fn exec_adc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self
            .cpu
            .add_with_carry(self.reg(n), operand2, self.cpu.cpsr.c);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    fn exec_sub(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(self.reg(n), !operand2, true);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    fn exec_sbc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self
            .cpu
            .add_with_carry(self.reg(n), !operand2, self.cpu.cpsr.c);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    fn exec_rsb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(!self.reg(n), operand2, true);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    fn exec_rsc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self
            .cpu
            .add_with_carry(!self.reg(n), operand2, self.cpu.cpsr.c);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    fn exec_neg(&mut self, insn: &DecodedInsn) -> ExecResult {
        // NEG Rd, Rm is RSB Rd, Rm, #0
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let result = self.cpu.add_with_carry(!self.reg(m), 0, true);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg(d, result)
    }

    // =========================================================================
    // Data Processing - Logical
    // =========================================================================

    fn exec_and(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) & operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_orr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) | operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_eor(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) ^ operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_bic(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) & !operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_orn(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) | !operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    // =========================================================================
    // Data Processing - Move
    // =========================================================================

    fn exec_mov(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, _, operand2) = self.decode_dp_operands(insn);
        let result = operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    fn exec_mvn(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, _, operand2) = self.decode_dp_operands(insn);
        let result = !operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_movw(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let imm4 = (insn.raw >> 16) & 0xF;
        let imm12 = insn.raw & 0xFFF;
        let imm16 = (imm4 << 12) | imm12;
        self.cpu.regs[d] = imm16;
        ExecResult::Continue
    }

    fn exec_movt(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let imm4 = (insn.raw >> 16) & 0xF;
        let imm12 = insn.raw & 0xFFF;
        let imm16 = (imm4 << 12) | imm12;
        self.cpu.regs[d] = (self.cpu.regs[d] & 0xFFFF) | (imm16 << 16);
        ExecResult::Continue
    }

    // =========================================================================
    // Data Processing - Compare
    // =========================================================================

    fn exec_cmp(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let rn = self.reg(n);
        let result = self.cpu.add_with_carry(rn, !operand2, true);
        self.set_flags_arithmetic(result);
        ExecResult::Continue
    }

    fn exec_cmn(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(self.reg(n), operand2, false);
        self.set_flags_arithmetic(result);
        ExecResult::Continue
    }

    fn exec_tst(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) & operand2;
        self.set_flags_logical(result);
        ExecResult::Continue
    }

    fn exec_teq(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) ^ operand2;
        self.set_flags_logical(result);
        ExecResult::Continue
    }

    // =========================================================================
    // Data Processing - Shift
    // =========================================================================

    fn exec_lsl(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::LSL, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_lsr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::LSR, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_asr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::ASR, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_ror(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::ROR, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    fn exec_rrx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, _) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::RRX, 1);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    // =========================================================================
    // Multiply Operations
    // =========================================================================

    fn exec_mul(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m) = self.decode_mul_operands(insn);
        let result = self.reg(n).wrapping_mul(self.reg(m));

        if insn.sets_flags {
            self.cpu.cpsr.n = compute_n_flag(result);
            self.cpu.cpsr.z = compute_z_flag(result);
        }
        self.set_reg(d, result)
    }

    fn exec_mla(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m, a) = self.decode_mla_operands(insn);
        let result = self
            .reg(n)
            .wrapping_mul(self.reg(m))
            .wrapping_add(self.reg(a));
        if insn.sets_flags {
            self.cpu.cpsr.n = compute_n_flag(result);
            self.cpu.cpsr.z = compute_z_flag(result);
        }
        self.set_reg(d, result)
    }

    fn exec_mls(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m, a) = self.decode_mla_operands(insn);
        let result = self
            .reg(a)
            .wrapping_sub(self.reg(n).wrapping_mul(self.reg(m)));
        self.set_reg(d, result)
    }

    fn exec_umull(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let result = (self.reg(n) as u64).wrapping_mul(self.reg(m) as u64);

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;

        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    fn exec_smull(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let result = (self.reg(n) as i32 as i64).wrapping_mul(self.reg(m) as i32 as i64) as u64;

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;

        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    fn exec_umlal(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let addend = ((self.cpu.regs[dhi] as u64) << 32) | (self.cpu.regs[dlo] as u64);
        let result = (self.reg(n) as u64)
            .wrapping_mul(self.reg(m) as u64)
            .wrapping_add(addend);

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    fn exec_smlal(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let addend = ((self.cpu.regs[dhi] as u64) << 32) | (self.cpu.regs[dlo] as u64);
        let result = ((self.reg(n) as i32 as i64).wrapping_mul(self.reg(m) as i32 as i64) as u64)
            .wrapping_add(addend);

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    /// UMAAL: RdHi:RdLo = Rn*Rm + RdHi + RdLo (all unsigned). No flags.
    fn exec_umaal(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let result = (self.reg(n) as u64)
            .wrapping_mul(self.reg(m) as u64)
            .wrapping_add(self.cpu.regs[dhi] as u64)
            .wrapping_add(self.cpu.regs[dlo] as u64);
        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        ExecResult::Continue
    }

    fn exec_sdiv(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 16) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;

        let dividend = self.reg(n) as i32;
        let divisor = self.reg(m) as i32;

        let result = if divisor == 0 {
            0 // Division by zero returns 0 in ARM
        } else if dividend == i32::MIN && divisor == -1 {
            i32::MIN as u32 // Overflow case
        } else {
            (dividend / divisor) as u32
        };

        self.set_reg(d, result)
    }

    fn exec_udiv(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 16) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;

        let dividend = self.reg(n);
        let divisor = self.reg(m);

        let result = if divisor == 0 { 0 } else { dividend / divisor };

        self.set_reg(d, result)
    }

    // =========================================================================
    // Branch Operations
    // =========================================================================

    fn exec_b(&mut self, insn: &DecodedInsn) -> ExecResult {
        if let Some(target) = self.decode_branch_target(insn) {
            ExecResult::Branch(target)
        } else {
            ExecResult::Undefined
        }
    }

    fn exec_bl(&mut self, insn: &DecodedInsn) -> ExecResult {
        let return_addr = self.cpu.regs[15].wrapping_add(4);
        self.cpu.regs[14] = return_addr;

        if let Some(target) = self.decode_branch_target(insn) {
            ExecResult::Branch(target)
        } else {
            ExecResult::Undefined
        }
    }

    fn exec_bx(&mut self, insn: &DecodedInsn) -> ExecResult {
        if let Some(m) = self.decode_reg_operand(insn, 0) {
            let target = self.reg(m);
            self.cpu.cpsr.t = (target & 1) != 0;
            ExecResult::Branch(target & !1)
        } else {
            ExecResult::Undefined
        }
    }

    fn exec_blx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let return_addr = self.cpu.regs[15].wrapping_add(4);
        self.cpu.regs[14] = return_addr;

        if let Some(m) = self.decode_reg_operand(insn, 0) {
            let target = self.reg(m);
            self.cpu.cpsr.t = (target & 1) != 0;
            ExecResult::Branch(target & !1)
        } else if let Some(target) = self.decode_branch_target(insn) {
            self.cpu.cpsr.t = true;
            ExecResult::Branch(target)
        } else {
            ExecResult::Undefined
        }
    }

    fn exec_cbz(&mut self, insn: &DecodedInsn) -> ExecResult {
        // Thumb-2 only
        let n = (insn.raw & 0x7) as usize;
        if self.reg(n) == 0 {
            if let Some(target) = self.decode_branch_target(insn) {
                return ExecResult::Branch(target);
            }
        }
        ExecResult::Continue
    }

    fn exec_cbnz(&mut self, insn: &DecodedInsn) -> ExecResult {
        // Thumb-2 only
        let n = (insn.raw & 0x7) as usize;
        if self.reg(n) != 0 {
            if let Some(target) = self.decode_branch_target(insn) {
                return ExecResult::Branch(target);
            }
        }
        ExecResult::Continue
    }

    /// Table Branch Byte (TBB) - Thumb-2.
    ///
    /// TBB [Rn, Rm]
    ///
    /// Reads a byte from memory[Rn + Rm] and branches forward by 2*byte.
    fn exec_tbb(&mut self, insn: &DecodedInsn) -> ExecResult {
        // TBB encoding: 11101000 1101nnnn 1111 0000 0000mmmm
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;

        let base = self.reg(n);
        let index = self.reg(m);
        let address = base.wrapping_add(index);

        match self.mem.read_byte(address) {
            Ok(offset) => {
                // Branch forward by 2 * offset from PC
                let pc = self.cpu.regs[15];
                let target = pc.wrapping_add(4).wrapping_add((offset as u32) * 2);
                ExecResult::Branch(target)
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    /// Table Branch Halfword (TBH) - Thumb-2.
    ///
    /// TBH [Rn, Rm, LSL #1]
    ///
    /// Reads a halfword from memory[Rn + Rm*2] and branches forward by 2*halfword.
    fn exec_tbh(&mut self, insn: &DecodedInsn) -> ExecResult {
        // TBH encoding: 11101000 1101nnnn 1111 0000 0001mmmm
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;

        let base = self.reg(n);
        let index = self.reg(m);
        let address = base.wrapping_add(index << 1);

        match self.mem.read_halfword(address) {
            Ok(offset) => {
                // Branch forward by 2 * offset from PC
                let pc = self.cpu.regs[15];
                let target = pc.wrapping_add(4).wrapping_add((offset as u32) * 2);
                ExecResult::Branch(target)
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    // =========================================================================
    // Load/Store Operations
    // =========================================================================

    fn exec_ldr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.read_word(address) {
            Ok(data) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                self.set_reg(t, data)
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_ldrb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.read_byte(address) {
            Ok(data) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                self.cpu.regs[t] = data as u32;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_ldrh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_halfword_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.read_halfword(address) {
            Ok(data) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                self.cpu.regs[t] = data as u32;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_ldrsb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_halfword_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.read_byte(address) {
            Ok(data) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                self.cpu.regs[t] = sign_extend(data as u32, 8);
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_ldrsh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_halfword_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.read_halfword(address) {
            Ok(data) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                self.cpu.regs[t] = sign_extend(data as u32, 16);
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_str(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.write_word(address, self.reg(t)) {
            Ok(()) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_strb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.write_byte(address, self.reg(t) as u8) {
            Ok(()) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_strh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_halfword_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.write_halfword(address, self.reg(t) as u16) {
            Ok(()) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    // =========================================================================
    // Load/Store Double
    // =========================================================================

    fn exec_ldrd(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_halfword_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };
        let t2 = (t + 1) & 0xF;

        match self.mem.read_word(address) {
            Ok(data1) => match self.mem.read_word(address.wrapping_add(4)) {
                Ok(data2) => {
                    self.cpu.regs[t] = data1;
                    self.cpu.regs[t2] = data2;
                    if let Some((n, addr)) = writeback {
                        self.cpu.regs[n] = addr;
                    }
                    ExecResult::Continue
                }
                Err(e) => ExecResult::MemoryFault(e),
            },
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_strd(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_halfword_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };
        let t2 = (t + 1) & 0xF;

        match self.mem.write_word(address, self.reg(t)) {
            Ok(()) => match self.mem.write_word(address.wrapping_add(4), self.reg(t2)) {
                Ok(()) => {
                    if let Some((n, addr)) = writeback {
                        self.cpu.regs[n] = addr;
                    }
                    ExecResult::Continue
                }
                Err(e) => ExecResult::MemoryFault(e),
            },
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    // =========================================================================
    // Load/Store Exclusive
    // =========================================================================

    fn exec_ldrex(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);

        self.exclusive_monitor.mark_exclusive(address, 4);

        match self.mem.read_word(address) {
            Ok(data) => {
                self.cpu.regs[t] = data;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_strex(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let t = (insn.raw & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);

        if self.exclusive_monitor.check_and_clear(address, 4) {
            match self.mem.write_word(address, self.reg(t)) {
                Ok(()) => {
                    self.cpu.regs[d] = 0; // Success
                    ExecResult::Continue
                }
                Err(e) => ExecResult::MemoryFault(e),
            }
        } else {
            self.cpu.regs[d] = 1; // Failure
            ExecResult::Continue
        }
    }

    fn exec_ldrexb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);

        self.exclusive_monitor.mark_exclusive(address, 1);

        match self.mem.read_byte(address) {
            Ok(data) => {
                self.cpu.regs[t] = data as u32;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_strexb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let t = (insn.raw & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);

        if self.exclusive_monitor.check_and_clear(address, 1) {
            match self.mem.write_byte(address, self.reg(t) as u8) {
                Ok(()) => {
                    self.cpu.regs[d] = 0;
                    ExecResult::Continue
                }
                Err(e) => ExecResult::MemoryFault(e),
            }
        } else {
            self.cpu.regs[d] = 1;
            ExecResult::Continue
        }
    }

    fn exec_ldrexh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);

        self.exclusive_monitor.mark_exclusive(address, 2);

        match self.mem.read_halfword(address) {
            Ok(data) => {
                self.cpu.regs[t] = data as u32;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    fn exec_strexh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let t = (insn.raw & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);

        if self.exclusive_monitor.check_and_clear(address, 2) {
            match self.mem.write_halfword(address, self.reg(t) as u16) {
                Ok(()) => {
                    self.cpu.regs[d] = 0;
                    ExecResult::Continue
                }
                Err(e) => ExecResult::MemoryFault(e),
            }
        } else {
            self.cpu.regs[d] = 1;
            ExecResult::Continue
        }
    }

    fn exec_clrex(&mut self, _insn: &DecodedInsn) -> ExecResult {
        self.exclusive_monitor.clear();
        ExecResult::Continue
    }

    // =========================================================================
    // Load/Store Multiple
    // =========================================================================

    fn exec_ldm(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (n, reglist, wback) = match self.decode_ldstm_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let mut address = self.reg(n);
        let mut branch_target = None;

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                match self.mem.read_word(address) {
                    Ok(data) => {
                        if i == 15 {
                            branch_target = Some(data);
                        } else {
                            self.cpu.regs[i] = data;
                        }
                        address = address.wrapping_add(4);
                    }
                    Err(e) => return ExecResult::MemoryFault(e),
                }
            }
        }

        if wback {
            self.cpu.regs[n] = address;
        }

        if let Some(target) = branch_target {
            ExecResult::Branch(target)
        } else {
            ExecResult::Continue
        }
    }

    fn exec_ldmdb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (n, reglist, wback) = match self.decode_ldstm_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let count = reglist.count_ones();
        let mut address = self.reg(n).wrapping_sub(count * 4);
        let start_address = address;
        let mut branch_target = None;

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                match self.mem.read_word(address) {
                    Ok(data) => {
                        if i == 15 {
                            branch_target = Some(data);
                        } else {
                            self.cpu.regs[i] = data;
                        }
                        address = address.wrapping_add(4);
                    }
                    Err(e) => return ExecResult::MemoryFault(e),
                }
            }
        }

        if wback {
            self.cpu.regs[n] = start_address;
        }

        if let Some(target) = branch_target {
            ExecResult::Branch(target)
        } else {
            ExecResult::Continue
        }
    }

    fn exec_stm(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (n, reglist, wback) = match self.decode_ldstm_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let mut address = self.reg(n);

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                match self.mem.write_word(address, self.reg(i)) {
                    Ok(()) => {
                        address = address.wrapping_add(4);
                    }
                    Err(e) => return ExecResult::MemoryFault(e),
                }
            }
        }

        if wback {
            self.cpu.regs[n] = address;
        }

        ExecResult::Continue
    }

    fn exec_stmdb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (n, reglist, wback) = match self.decode_ldstm_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let count = reglist.count_ones();
        let mut address = self.reg(n).wrapping_sub(count * 4);
        let start_address = address;

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                match self.mem.write_word(address, self.reg(i)) {
                    Ok(()) => {
                        address = address.wrapping_add(4);
                    }
                    Err(e) => return ExecResult::MemoryFault(e),
                }
            }
        }

        if wback {
            self.cpu.regs[n] = start_address;
        }

        ExecResult::Continue
    }

    fn exec_push(&mut self, insn: &DecodedInsn) -> ExecResult {
        let reglist = match self.decode_reglist(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let count = reglist.count_ones();
        let mut address = self.cpu.regs[13].wrapping_sub(count * 4);
        let start_address = address;

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                match self.mem.write_word(address, self.reg(i)) {
                    Ok(()) => {
                        address = address.wrapping_add(4);
                    }
                    Err(e) => return ExecResult::MemoryFault(e),
                }
            }
        }

        self.cpu.regs[13] = start_address;
        ExecResult::Continue
    }

    fn exec_pop(&mut self, insn: &DecodedInsn) -> ExecResult {
        let reglist = match self.decode_reglist(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let mut address = self.cpu.regs[13];
        let mut branch_target = None;

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                match self.mem.read_word(address) {
                    Ok(data) => {
                        if i == 15 {
                            branch_target = Some(data);
                        } else {
                            self.cpu.regs[i] = data;
                        }
                        address = address.wrapping_add(4);
                    }
                    Err(e) => return ExecResult::MemoryFault(e),
                }
            }
        }

        self.cpu.regs[13] = address;

        if let Some(target) = branch_target {
            ExecResult::Branch(target)
        } else {
            ExecResult::Continue
        }
    }

    // =========================================================================
    // System Operations
    // =========================================================================

    fn exec_svc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let imm = insn.raw & 0x00FFFFFF;
        ExecResult::Exception(ExceptionType::SupervisorCall(imm))
    }

    fn exec_bkpt(&mut self, insn: &DecodedInsn) -> ExecResult {
        let imm = ((insn.raw >> 8) & 0xFFF0) | (insn.raw & 0xF);
        ExecResult::Exception(ExceptionType::Breakpoint(imm as u16))
    }

    fn exec_mrs(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let r = (insn.raw >> 22) & 1;

        let value = if r != 0 {
            if let Some(spsr) = self.cpu.get_current_spsr() {
                spsr.to_u32()
            } else {
                return ExecResult::Undefined;
            }
        } else {
            self.cpu.cpsr.to_u32()
        };

        self.cpu.regs[d] = value;
        ExecResult::Continue
    }

    fn exec_msr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let r = (insn.raw >> 22) & 1;
        let mask = (insn.raw >> 16) & 0xF;

        let value = if (insn.raw >> 25) & 1 != 0 {
            let imm12 = insn.raw & 0xFFF;
            expand_imm_c(imm12, self.cpu.cpsr.c).0
        } else {
            let n = (insn.raw & 0xF) as usize;
            self.reg(n)
        };

        if r != 0 {
            self.write_current_spsr_by_mask(value, mask);
        } else {
            self.write_cpsr_by_mask(value, mask);
        }

        ExecResult::Continue
    }

    fn write_current_spsr_by_mask(&mut self, value: u32, mask: u32) {
        if let Some(spsr) = self.cpu.get_current_spsr_mut() {
            if (mask & 8) != 0 {
                spsr.n = (value >> 31) != 0;
                spsr.z = ((value >> 30) & 1) != 0;
                spsr.c = ((value >> 29) & 1) != 0;
                spsr.v = ((value >> 28) & 1) != 0;
                spsr.q = ((value >> 27) & 1) != 0;
            }
            if (mask & 2) != 0 {
                spsr.e = ((value >> 9) & 1) != 0;
                spsr.a = ((value >> 8) & 1) != 0;
            }
            if (mask & 1) != 0 {
                spsr.i = ((value >> 7) & 1) != 0;
                spsr.f = ((value >> 6) & 1) != 0;
                spsr.t = ((value >> 5) & 1) != 0;
                spsr.mode = (value & 0x1F) as u8;
            }
        }
    }

    fn write_cpsr_by_mask(&mut self, value: u32, mask: u32) {
        if (mask & 8) != 0 {
            self.cpu.cpsr.n = (value >> 31) != 0;
            self.cpu.cpsr.z = ((value >> 30) & 1) != 0;
            self.cpu.cpsr.c = ((value >> 29) & 1) != 0;
            self.cpu.cpsr.v = ((value >> 28) & 1) != 0;
            self.cpu.cpsr.q = ((value >> 27) & 1) != 0;
        }
        if (mask & 2) != 0 {
            self.cpu.cpsr.e = ((value >> 9) & 1) != 0;
            if self.cpu.is_privileged() {
                self.cpu.cpsr.a = ((value >> 8) & 1) != 0;
            }
        }
        if (mask & 1) != 0 && self.cpu.is_privileged() {
            self.cpu.cpsr.i = ((value >> 7) & 1) != 0;
            self.cpu.cpsr.f = ((value >> 6) & 1) != 0;
            self.cpu.cpsr.t = ((value >> 5) & 1) != 0;

            let new_mode = value & 0x1F;
            if let Some(mode) = ProcessorMode::from_bits(new_mode as u8) {
                if self.cpu.cpsr.mode != mode as u8 {
                    self.cpu.change_mode(mode);
                }
            }
        }
    }

    /// Execute IT (If-Then) instruction (Thumb-2).
    ///
    /// IT{x{y{z}}} cond
    ///
    /// Sets up IT state for conditional execution of up to 4 following instructions.
    /// The condition and mask determine which instructions execute and which are skipped.
    fn exec_it(&mut self, insn: &DecodedInsn) -> ExecResult {
        // IT instruction encoding (16-bit Thumb):
        // Bits 7:4 = firstcond (base condition code)
        // Bits 3:0 = mask (determines T/E pattern)
        let firstcond = ((insn.raw >> 4) & 0xF) as u8;
        let mask = (insn.raw & 0xF) as u8;

        // Mask of 0 is not allowed (would be NOP)
        if mask == 0 {
            return ExecResult::Undefined;
        }

        // Set IT state in CPSR
        self.cpu.cpsr.set_it_state(firstcond, mask);

        ExecResult::Continue
    }

    // =========================================================================
    // Coprocessor Operations
    // =========================================================================

    fn exec_mcr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let _cp = ((insn.raw >> 8) & 0xF) as u8;
        let _opc1 = ((insn.raw >> 21) & 7) as u8;
        let _crn = ((insn.raw >> 16) & 0xF) as u8;
        let _crm = (insn.raw & 0xF) as u8;
        let _opc2 = ((insn.raw >> 5) & 7) as u8;

        // For now, just consume the value (would write to coprocessor)
        let _value = self.reg(t);

        ExecResult::Continue
    }

    fn exec_mrc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let _cp = ((insn.raw >> 8) & 0xF) as u8;
        let _opc1 = ((insn.raw >> 21) & 7) as u8;
        let _crn = ((insn.raw >> 16) & 0xF) as u8;
        let _crm = (insn.raw & 0xF) as u8;
        let _opc2 = ((insn.raw >> 5) & 7) as u8;

        // For now, return 0 (would read from coprocessor)
        if t != 15 {
            self.cpu.regs[t] = 0;
        }

        ExecResult::Continue
    }

    // =========================================================================
    // Bit Manipulation
    // =========================================================================

    fn exec_clz(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let result = self.reg(m).leading_zeros();
        self.set_reg(d, result)
    }

    fn exec_rev(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let result = self.reg(m).swap_bytes();
        self.set_reg(d, result)
    }

    fn exec_rev16(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let val = self.reg(m);
        let result = ((val >> 8) & 0x00FF00FF) | ((val << 8) & 0xFF00FF00);
        self.set_reg(d, result)
    }

    fn exec_revsh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let val = self.reg(m);
        // Byte-reverse the low halfword and sign-extend
        let lo = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
        let result = sign_extend(lo & 0xFFFF, 16);
        self.set_reg(d, result)
    }

    fn exec_rbit(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let result = self.reg(m).reverse_bits();
        self.set_reg(d, result)
    }

    // =========================================================================
    // Bit Field Operations
    // =========================================================================

    fn exec_bfc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let msb = ((insn.raw >> 16) & 0x1F) as u32;
        let lsb = ((insn.raw >> 7) & 0x1F) as u32;
        let width = msb - lsb + 1;
        let mask = ((1u32 << width) - 1) << lsb;
        let result = self.cpu.regs[d] & !mask;
        self.cpu.regs[d] = result;
        ExecResult::Continue
    }

    fn exec_bfi(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        let msb = ((insn.raw >> 16) & 0x1F) as u32;
        let lsb = ((insn.raw >> 7) & 0x1F) as u32;
        let width = msb - lsb + 1;
        let mask = ((1u32 << width) - 1) << lsb;
        let src = (self.reg(n) << lsb) & mask;
        let result = (self.cpu.regs[d] & !mask) | src;
        self.cpu.regs[d] = result;
        ExecResult::Continue
    }

    fn exec_ubfx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        let lsb = ((insn.raw >> 7) & 0x1F) as u32;
        let width = (((insn.raw >> 16) & 0x1F) + 1) as u32;
        let mask = (1u32 << width) - 1;
        let result = (self.reg(n) >> lsb) & mask;
        self.set_reg(d, result)
    }

    fn exec_sbfx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        let lsb = ((insn.raw >> 7) & 0x1F) as u32;
        let width = (((insn.raw >> 16) & 0x1F) + 1) as u32;
        let mask = (1u32 << width) - 1;
        let extracted = (self.reg(n) >> lsb) & mask;
        let result = sign_extend(extracted, width);
        self.set_reg(d, result)
    }

    // =========================================================================
    // Extension Operations
    // =========================================================================

    fn exec_sxtb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let rotation = ((insn.raw >> 10) & 3) * 8;
        let rotated = self.reg(m).rotate_right(rotation);
        let result = sign_extend(rotated & 0xFF, 8);
        self.set_reg(d, result)
    }

    fn exec_sxth(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let rotation = ((insn.raw >> 10) & 3) * 8;
        let rotated = self.reg(m).rotate_right(rotation);
        let result = sign_extend(rotated & 0xFFFF, 16);
        self.set_reg(d, result)
    }

    fn exec_uxtb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let rotation = ((insn.raw >> 10) & 3) * 8;
        let rotated = self.reg(m).rotate_right(rotation);
        let result = rotated & 0xFF;
        self.set_reg(d, result)
    }

    fn exec_uxth(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;
        let rotation = ((insn.raw >> 10) & 3) * 8;
        let rotated = self.reg(m).rotate_right(rotation);
        let result = rotated & 0xFFFF;
        self.set_reg(d, result)
    }

    // =========================================================================
    // Saturating Arithmetic
    // =========================================================================

    fn exec_usat(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let sat_imm = ((insn.raw >> 16) & 0x1F) as u32;
        let n = (insn.raw & 0xF) as usize;
        let sh = ((insn.raw >> 6) & 1) != 0;
        let imm5 = ((insn.raw >> 7) & 0x1F) as u32;

        let shift_amount = if imm5 == 0 && sh { 32 } else { imm5 };
        let shift_type = if sh { ShiftType::ASR } else { ShiftType::LSL };
        let operand = shift_c(self.reg(n), shift_type, shift_amount, false).0;

        let max_val = (1u32 << sat_imm).saturating_sub(1);
        let signed_operand = operand as i32;

        let result = if signed_operand < 0 {
            self.cpu.cpsr.q = true;
            0
        } else if operand > max_val {
            self.cpu.cpsr.q = true;
            max_val
        } else {
            operand
        };

        self.set_reg(d, result)
    }

    fn exec_ssat(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let sat_imm = ((insn.raw >> 16) & 0x1F) as u32 + 1;
        let n = (insn.raw & 0xF) as usize;
        let sh = ((insn.raw >> 6) & 1) != 0;
        let imm5 = ((insn.raw >> 7) & 0x1F) as u32;

        let shift_amount = if imm5 == 0 && sh { 32 } else { imm5 };
        let shift_type = if sh { ShiftType::ASR } else { ShiftType::LSL };
        let operand = shift_c(self.reg(n), shift_type, shift_amount, false).0 as i32;

        let max_val = (1i32 << (sat_imm - 1)) - 1;
        let min_val = -(1i32 << (sat_imm - 1));

        let result = if operand > max_val {
            self.cpu.cpsr.q = true;
            max_val as u32
        } else if operand < min_val {
            self.cpu.cpsr.q = true;
            min_val as u32
        } else {
            operand as u32
        };

        self.set_reg(d, result)
    }

    // =========================================================================
    // AArch32 media / DSP (A32 encodings; operation derived from the raw word)
    // =========================================================================

    /// Signed-saturate a value to 32 bits, setting the Q flag on saturation.
    fn ssat32(&mut self, x: i64) -> u32 {
        if x > i32::MAX as i64 {
            self.cpu.cpsr.q = true;
            i32::MAX as u32
        } else if x < i32::MIN as i64 {
            self.cpu.cpsr.q = true;
            i32::MIN as u32
        } else {
            x as u32
        }
    }

    /// QADD / QSUB / QDADD / QDSUB.
    fn exec_a32_sat_addsub(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 12) & 0xF) as usize;
        let rn = ((raw >> 16) & 0xF) as usize;
        let rm = (raw & 0xF) as usize;
        let n = self.reg(rn) as i32 as i64;
        let m = self.reg(rm) as i32 as i64;
        let result = match (raw >> 21) & 0x3 {
            0b00 => self.ssat32(m + n),
            0b01 => self.ssat32(m - n),
            0b10 => {
                let dbl = self.ssat32(2 * n) as i32 as i64;
                self.ssat32(m + dbl)
            }
            _ => {
                let dbl = self.ssat32(2 * n) as i32 as i64;
                self.ssat32(m - dbl)
            }
        };
        self.set_reg(rd, result)
    }

    /// SMUL/SMLA/SMULW/SMLAW/SMLAL <x><y> (halfword and word multiplies).
    fn exec_a32_hmul(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 16) & 0xF) as usize;
        let ra = ((raw >> 12) & 0xF) as usize;
        let rm = ((raw >> 8) & 0xF) as usize;
        let rn = (raw & 0xF) as usize;
        let n_top = (raw >> 5) & 1 != 0;
        let m_top = (raw >> 6) & 1 != 0;
        let rn_v = self.reg(rn);
        let rm_v = self.reg(rm);
        let half = |v: u32, top: bool| -> i64 {
            if top {
                (v >> 16) as u16 as i16 as i64
            } else {
                v as u16 as i16 as i64
            }
        };
        match (raw >> 21) & 0x3 {
            0b00 => {
                // SMLA<x><y>: Rd = Rn.x * Rm.y + Ra (Q on signed overflow)
                let result = half(rn_v, n_top) * half(rm_v, m_top) + self.reg(ra) as i32 as i64;
                let r32 = result as i32;
                if result != r32 as i64 {
                    self.cpu.cpsr.q = true;
                }
                self.set_reg(rd, r32 as u32)
            }
            0b01 => {
                // SMLAW<y> (bit5==0) / SMULW<y> (bit5==1)
                let prod = (rn_v as i32 as i64) * half(rm_v, m_top);
                let shifted = prod >> 16;
                if (raw >> 5) & 1 == 0 {
                    let result = shifted + self.reg(ra) as i32 as i64;
                    let r32 = result as i32;
                    if result != r32 as i64 {
                        self.cpu.cpsr.q = true;
                    }
                    self.set_reg(rd, r32 as u32)
                } else {
                    self.set_reg(rd, shifted as i32 as u32)
                }
            }
            0b10 => {
                // SMLAL<x><y>: RdHi:RdLo += Rn.x * Rm.y
                let dhi = ((raw >> 16) & 0xF) as usize;
                let dlo = ((raw >> 12) & 0xF) as usize;
                let acc =
                    (((self.cpu.regs[dhi] as u64) << 32) | self.cpu.regs[dlo] as u64) as i64;
                let result = acc.wrapping_add(half(rn_v, n_top) * half(rm_v, m_top)) as u64;
                self.cpu.regs[dlo] = result as u32;
                self.cpu.regs[dhi] = (result >> 32) as u32;
                ExecResult::Continue
            }
            _ => {
                // SMUL<x><y>: Rd = Rn.x * Rm.y
                self.set_reg(rd, (half(rn_v, n_top) * half(rm_v, m_top)) as i32 as u32)
            }
        }
    }

    /// SMUAD / SMUSD / SMLAD / SMLSD.
    fn exec_a32_dual(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 16) & 0xF) as usize;
        let ra = ((raw >> 12) & 0xF) as usize;
        let rm = ((raw >> 8) & 0xF) as usize;
        let rn = (raw & 0xF) as usize;
        let rn_v = self.reg(rn);
        let mut rm_v = self.reg(rm);
        if (raw >> 5) & 1 != 0 {
            rm_v = rm_v.rotate_right(16); // X: swap Rm halves
        }
        let p1 = (rn_v as u16 as i16 as i64) * (rm_v as u16 as i16 as i64);
        let p2 = ((rn_v >> 16) as u16 as i16 as i64) * ((rm_v >> 16) as u16 as i16 as i64);
        let mut result = if (raw >> 6) & 1 != 0 { p1 - p2 } else { p1 + p2 };
        if ra != 15 {
            result += self.reg(ra) as i32 as i64;
        }
        let r32 = result as i32;
        if result != r32 as i64 {
            self.cpu.cpsr.q = true;
        }
        self.set_reg(rd, r32 as u32)
    }

    /// SMLALD / SMLSLD.
    fn exec_a32_smlald(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let dhi = ((raw >> 16) & 0xF) as usize;
        let dlo = ((raw >> 12) & 0xF) as usize;
        let rm = ((raw >> 8) & 0xF) as usize;
        let rn = (raw & 0xF) as usize;
        let rn_v = self.reg(rn);
        let mut rm_v = self.reg(rm);
        if (raw >> 5) & 1 != 0 {
            rm_v = rm_v.rotate_right(16);
        }
        let p1 = (rn_v as u16 as i16 as i64) * (rm_v as u16 as i16 as i64);
        let p2 = ((rn_v >> 16) as u16 as i16 as i64) * ((rm_v >> 16) as u16 as i16 as i64);
        let prod = if (raw >> 6) & 1 != 0 { p1 - p2 } else { p1 + p2 };
        let acc = (((self.cpu.regs[dhi] as u64) << 32) | self.cpu.regs[dlo] as u64) as i64;
        let result = acc.wrapping_add(prod) as u64;
        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        ExecResult::Continue
    }

    /// SMMUL / SMMLA / SMMLS (signed most-significant-word multiply).
    fn exec_a32_smmul(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 16) & 0xF) as usize;
        let ra = ((raw >> 12) & 0xF) as usize;
        let rm = ((raw >> 8) & 0xF) as usize;
        let rn = (raw & 0xF) as usize;
        let prod = (self.reg(rn) as i32 as i64) * (self.reg(rm) as i32 as i64);
        let acc = if ra == 15 {
            0i64
        } else {
            (self.reg(ra) as i32 as i64) << 32
        };
        let mut result = if (raw >> 6) & 1 != 0 { acc - prod } else { acc + prod };
        if (raw >> 5) & 1 != 0 {
            result += 0x8000_0000; // rounding
        }
        self.set_reg(rd, (result >> 32) as u32)
    }

    /// USAD8 / USADA8 (sum of absolute differences).
    fn exec_a32_usad(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 16) & 0xF) as usize;
        let ra = ((raw >> 12) & 0xF) as usize;
        let rm = ((raw >> 8) & 0xF) as usize;
        let rn = (raw & 0xF) as usize;
        let n = self.reg(rn);
        let m = self.reg(rm);
        let mut sum: u32 = 0;
        for i in 0..4 {
            let a = ((n >> (i * 8)) & 0xFF) as i32;
            let b = ((m >> (i * 8)) & 0xFF) as i32;
            sum = sum.wrapping_add((a - b).unsigned_abs());
        }
        if ra != 15 {
            sum = sum.wrapping_add(self.reg(ra));
        }
        self.set_reg(rd, sum)
    }

    /// PKHBT / PKHTB (pack halfword).
    fn exec_a32_pkh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 12) & 0xF) as usize;
        let rn = ((raw >> 16) & 0xF) as usize;
        let rm = (raw & 0xF) as usize;
        let imm5 = (raw >> 7) & 0x1F;
        let n = self.reg(rn);
        let m = self.reg(rm);
        let result = if (raw >> 6) & 1 != 0 {
            // PKHTB: top from Rn, bottom from (Rm ASR imm5; imm5==0 => 32)
            let op2 = if imm5 == 0 {
                ((m as i32) >> 31) as u32
            } else {
                ((m as i32) >> imm5) as u32
            };
            (n & 0xFFFF_0000) | (op2 & 0xFFFF)
        } else {
            // PKHBT: bottom from Rn, top from (Rm LSL imm5)
            let op2 = m.wrapping_shl(imm5);
            (op2 & 0xFFFF_0000) | (n & 0xFFFF)
        };
        self.set_reg(rd, result)
    }

    /// (U|S)XT(A)(B|H|B16) sign/zero extend, with optional add and rotate.
    fn exec_a32_extend(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 12) & 0xF) as usize;
        let rn = ((raw >> 16) & 0xF) as usize;
        let rm = (raw & 0xF) as usize;
        let unsigned = (raw >> 22) & 1 != 0;
        let size = (raw >> 20) & 0x3; // 00=B16, 10=B, 11=H
        let rotation = ((raw >> 10) & 0x3) * 8;
        let rotated = self.reg(rm).rotate_right(rotation);
        let add = rn != 15;
        let n = self.reg(rn);
        let extb = |b: u32, u: bool| -> u32 {
            if u {
                b & 0xFF
            } else {
                (b & 0xFF) as u8 as i8 as i32 as u32
            }
        };
        let result = match size {
            0b10 => {
                let ext = extb(rotated, unsigned);
                if add {
                    n.wrapping_add(ext)
                } else {
                    ext
                }
            }
            0b11 => {
                let h = rotated & 0xFFFF;
                let ext = if unsigned {
                    h
                } else {
                    h as u16 as i16 as i32 as u32
                };
                if add {
                    n.wrapping_add(ext)
                } else {
                    ext
                }
            }
            _ => {
                let lo = extb(rotated, unsigned) & 0xFFFF;
                let hi = extb(rotated >> 16, unsigned) & 0xFFFF;
                if add {
                    let l = (n & 0xFFFF).wrapping_add(lo) & 0xFFFF;
                    let h = ((n >> 16) & 0xFFFF).wrapping_add(hi) & 0xFFFF;
                    l | (h << 16)
                } else {
                    lo | (hi << 16)
                }
            }
        };
        self.set_reg(rd, result)
    }

    /// SSAT16 / USAT16 (parallel halfword saturate).
    fn exec_a32_sat16(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 12) & 0xF) as usize;
        let rn = (raw & 0xF) as usize;
        let sat = (raw >> 16) & 0xF;
        let unsigned = (raw >> 22) & 1 != 0;
        let n = self.reg(rn);
        let mut out: u32 = 0;
        for i in 0..2u32 {
            let h = ((n >> (i * 16)) & 0xFFFF) as u16 as i16 as i32;
            let clamped = if unsigned {
                let max = ((1u32 << sat) - 1) as i32;
                if h < 0 {
                    self.cpu.cpsr.q = true;
                    0
                } else if h > max {
                    self.cpu.cpsr.q = true;
                    max
                } else {
                    h
                }
            } else {
                let bits = sat + 1;
                let max = (1i32 << (bits - 1)) - 1;
                let min = -(1i32 << (bits - 1));
                if h > max {
                    self.cpu.cpsr.q = true;
                    max
                } else if h < min {
                    self.cpu.cpsr.q = true;
                    min
                } else {
                    h
                }
            };
            out |= ((clamped as u32) & 0xFFFF) << (i * 16);
        }
        self.set_reg(rd, out)
    }

    /// SEL (select bytes by GE flags).
    fn exec_a32_sel(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 12) & 0xF) as usize;
        let rn = ((raw >> 16) & 0xF) as usize;
        let rm = (raw & 0xF) as usize;
        let n = self.reg(rn);
        let m = self.reg(rm);
        let ge = self.cpu.cpsr.ge;
        let mut result: u32 = 0;
        for i in 0..4u32 {
            let byte = if (ge >> i) & 1 != 0 {
                (n >> (i * 8)) & 0xFF
            } else {
                (m >> (i * 8)) & 0xFF
            };
            result |= byte << (i * 8);
        }
        self.set_reg(rd, result)
    }

    /// Signed/unsigned parallel add/sub (SADD8/QADD16/UHASX/...). Sets GE for
    /// the plain signed (S) and unsigned (U) prefixes.
    fn exec_a32_parallel(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let rd = ((raw >> 12) & 0xF) as usize;
        let rn = ((raw >> 16) & 0xF) as usize;
        let rm = (raw & 0xF) as usize;
        let prefix = (raw >> 20) & 0x7; // 001=S 010=Q 011=SH 101=U 110=UQ 111=UH
        let op2 = (raw >> 5) & 0x7; // 000=add16 001=asx 010=sax 011=sub16 100=add8 111=sub8
        let n = self.reg(rn);
        let m = self.reg(rm);

        let eight = op2 == 0b100 || op2 == 0b111;
        let width: u32 = if eight { 8 } else { 16 };
        let lane = |v: u32, idx: u32, w: u32| (v >> (idx * w)) & ((1u32 << w) - 1);

        // (a, b, sub) per lane.
        let mut lanes: [(u32, u32, bool); 4] = [(0, 0, false); 4];
        let nlanes: usize = match op2 {
            0b000 => {
                for i in 0..2 {
                    lanes[i] = (lane(n, i as u32, 16), lane(m, i as u32, 16), false);
                }
                2
            }
            0b011 => {
                for i in 0..2 {
                    lanes[i] = (lane(n, i as u32, 16), lane(m, i as u32, 16), true);
                }
                2
            }
            0b001 => {
                // ASX: lane0 = n.lo - m.hi ; lane1 = n.hi + m.lo
                lanes[0] = (lane(n, 0, 16), lane(m, 1, 16), true);
                lanes[1] = (lane(n, 1, 16), lane(m, 0, 16), false);
                2
            }
            0b010 => {
                // SAX: lane0 = n.lo + m.hi ; lane1 = n.hi - m.lo
                lanes[0] = (lane(n, 0, 16), lane(m, 1, 16), false);
                lanes[1] = (lane(n, 1, 16), lane(m, 0, 16), true);
                2
            }
            0b100 => {
                for i in 0..4 {
                    lanes[i] = (lane(n, i as u32, 8), lane(m, i as u32, 8), false);
                }
                4
            }
            0b111 => {
                for i in 0..4 {
                    lanes[i] = (lane(n, i as u32, 8), lane(m, i as u32, 8), true);
                }
                4
            }
            _ => return ExecResult::Undefined,
        };

        let sign_ext = |v: u32, w: u32| -> i64 {
            let sh = 64 - w;
            ((v as i64) << sh) >> sh
        };
        let maskw: u32 = if width == 32 { u32::MAX } else { (1u32 << width) - 1 };
        let smax = (1i64 << (width - 1)) - 1;
        let smin = -(1i64 << (width - 1));
        let umax = (1i64 << width) - 1;

        let mut result: u32 = 0;
        let mut ge: u8 = 0;
        let mut set_ge = false;
        for (idx, &(a, b, sub)) in lanes.iter().take(nlanes).enumerate() {
            let avs = sign_ext(a, width);
            let bvs = sign_ext(b, width);
            let avu = a as i64;
            let bvu = b as i64;
            let (val, ge_opt): (u32, Option<bool>) = match prefix {
                0b001 => {
                    let r = if sub { avs - bvs } else { avs + bvs };
                    (r as u32, Some(r >= 0))
                }
                0b101 => {
                    if sub {
                        ((avu - bvu) as u32, Some(avu >= bvu))
                    } else {
                        let r = avu + bvu;
                        (r as u32, Some(r >= (1i64 << width)))
                    }
                }
                0b010 => {
                    let r = if sub { avs - bvs } else { avs + bvs };
                    (r.clamp(smin, smax) as u32, None)
                }
                0b110 => {
                    let r = if sub { avu - bvu } else { avu + bvu };
                    (r.clamp(0, umax) as u32, None)
                }
                0b011 => {
                    let r = if sub { avs - bvs } else { avs + bvs };
                    ((r >> 1) as u32, None)
                }
                0b111 => {
                    let r = if sub { avu - bvu } else { avu + bvu };
                    ((r >> 1) as u32, None)
                }
                _ => return ExecResult::Undefined,
            };
            result |= (val & maskw) << (idx as u32 * width);
            if let Some(g) = ge_opt {
                set_ge = true;
                if g {
                    if eight {
                        ge |= 1 << idx;
                    } else {
                        ge |= 0b11 << (idx * 2);
                    }
                }
            }
        }

        if set_ge {
            self.cpu.cpsr.ge = ge;
        }
        self.set_reg(rd, result)
    }

    // =========================================================================
    // Operand Decoding Helpers
    // =========================================================================

    /// Decode data processing operands: (Rd, Rn, operand2)
    fn decode_dp_operands(&mut self, insn: &DecodedInsn) -> (usize, usize, u32) {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;

        let operand2 = if (insn.raw >> 25) & 1 != 0 {
            let imm12 = insn.raw & 0xFFF;
            let (value, carry) = expand_imm_c(imm12, self.cpu.cpsr.c);
            self.cpu.carry_out = carry;
            value
        } else {
            let m = (insn.raw & 0xF) as usize;
            let mut shift_type = ShiftType::from_bits(((insn.raw >> 5) & 3) as u8);

            let shift_amount = if (insn.raw >> 4) & 1 != 0 {
                // Register-controlled shift: amount is Rs[7:0]; RRX is not
                // encodable in this form.
                let s = ((insn.raw >> 8) & 0xF) as usize;
                self.reg(s) & 0xFF
            } else {
                let imm5 = ((insn.raw >> 7) & 0x1F) as u32;
                match shift_type {
                    ShiftType::LSR | ShiftType::ASR if imm5 == 0 => 32,
                    // type==ROR with imm5==0 encodes RRX (rotate right with
                    // extend through carry), not ROR #1.
                    ShiftType::ROR if imm5 == 0 => {
                        shift_type = ShiftType::RRX;
                        1
                    }
                    _ => imm5,
                }
            };

            let (result, carry) = shift_c(self.reg(m), shift_type, shift_amount, self.cpu.cpsr.c);
            self.cpu.carry_out = carry;
            result
        };

        (d, n, operand2)
    }

    /// Decode shift instruction operands: (Rd, Rm, shift_amount)
    fn decode_shift_operands(&self, insn: &DecodedInsn) -> (usize, usize, u32) {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;

        let shift_amount = if (insn.raw >> 4) & 1 != 0 {
            let s = ((insn.raw >> 8) & 0xF) as usize;
            self.reg(s) & 0xFF
        } else {
            let imm5 = ((insn.raw >> 7) & 0x1F) as u32;
            if imm5 == 0 {
                32
            } else {
                imm5
            }
        };

        (d, m, shift_amount)
    }

    /// Decode multiply operands: (Rd, Rn, Rm)
    fn decode_mul_operands(&self, insn: &DecodedInsn) -> (usize, usize, usize) {
        let d = ((insn.raw >> 16) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;
        (d, n, m)
    }

    /// Decode MLA operands: (Rd, Rn, Rm, Ra)
    fn decode_mla_operands(&self, insn: &DecodedInsn) -> (usize, usize, usize, usize) {
        let d = ((insn.raw >> 16) & 0xF) as usize;
        let a = ((insn.raw >> 12) & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        (d, n, m, a)
    }

    /// Decode long multiply operands: (RdLo, RdHi, Rn, Rm)
    fn decode_mull_operands(&self, insn: &DecodedInsn) -> (usize, usize, usize, usize) {
        let dhi = ((insn.raw >> 16) & 0xF) as usize;
        let dlo = ((insn.raw >> 12) & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        (dlo, dhi, n, m)
    }

    /// Decode branch target from instruction.
    fn decode_branch_target(&self, insn: &DecodedInsn) -> Option<u32> {
        let imm24 = insn.raw & 0x00FFFFFF;
        let imm26 = imm24 << 2;
        let imm32 = if (imm26 & 0x02000000) != 0 {
            imm26 | 0xFC000000
        } else {
            imm26
        };
        Some(self.cpu.get_pc().wrapping_add(imm32))
    }

    /// Decode register operand at given position.
    fn decode_reg_operand(&self, insn: &DecodedInsn, pos: usize) -> Option<usize> {
        if pos < insn.operands.len() {
            match &insn.operands[pos] {
                crate::arm::decoder::Operand::Reg(reg) => Some(reg.num as usize),
                _ => None,
            }
        } else {
            Some((insn.raw & 0xF) as usize)
        }
    }

    /// Decode load/store operands for word/byte: (Rt, address, writeback)
    fn decode_ldst_operands(
        &self,
        insn: &DecodedInsn,
    ) -> Option<(usize, u32, Option<(usize, u32)>)> {
        let p = (insn.raw >> 24) & 1;
        let u = (insn.raw >> 23) & 1;
        let w = (insn.raw >> 21) & 1;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let t = ((insn.raw >> 12) & 0xF) as usize;

        let base = self.reg(n);

        let offset = if (insn.raw >> 25) & 1 != 0 {
            let m = (insn.raw & 0xF) as usize;
            let shift_type = ShiftType::from_bits(((insn.raw >> 5) & 3) as u8);
            let imm5 = ((insn.raw >> 7) & 0x1F) as u32;
            let shift_amount = match shift_type {
                ShiftType::LSR | ShiftType::ASR if imm5 == 0 => 32,
                _ => imm5,
            };
            shift_c(self.reg(m), shift_type, shift_amount, false).0
        } else {
            insn.raw & 0xFFF
        };

        let is_add = u != 0;
        let is_index = p != 0;
        let is_wback = p == 0 || w != 0;

        let offset_addr = if is_add {
            base.wrapping_add(offset)
        } else {
            base.wrapping_sub(offset)
        };

        let address = if is_index { offset_addr } else { base };
        let writeback = if is_wback && n != 15 {
            Some((n, offset_addr))
        } else {
            None
        };

        Some((t, address, writeback))
    }

    /// Decode load/store operands for halfword/signed: (Rt, address, writeback)
    /// Uses different encoding: bits[11:8] and bits[3:0] for immediate
    fn decode_ldst_halfword_operands(
        &self,
        insn: &DecodedInsn,
    ) -> Option<(usize, u32, Option<(usize, u32)>)> {
        let p = (insn.raw >> 24) & 1;
        let u = (insn.raw >> 23) & 1;
        let i = (insn.raw >> 22) & 1; // Immediate vs register
        let w = (insn.raw >> 21) & 1;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let t = ((insn.raw >> 12) & 0xF) as usize;

        let base = self.reg(n);

        let offset = if i != 0 {
            // Immediate: bits[11:8] and bits[3:0]
            let imm4h = (insn.raw >> 8) & 0xF;
            let imm4l = insn.raw & 0xF;
            (imm4h << 4) | imm4l
        } else {
            // Register
            let m = (insn.raw & 0xF) as usize;
            self.reg(m)
        };

        let is_add = u != 0;
        let is_index = p != 0;
        let is_wback = p == 0 || w != 0;

        let offset_addr = if is_add {
            base.wrapping_add(offset)
        } else {
            base.wrapping_sub(offset)
        };

        let address = if is_index { offset_addr } else { base };
        let writeback = if is_wback && n != 15 {
            Some((n, offset_addr))
        } else {
            None
        };

        Some((t, address, writeback))
    }

    /// Decode load/store multiple operands: (Rn, reglist, wback)
    fn decode_ldstm_operands(&self, insn: &DecodedInsn) -> Option<(usize, u16, bool)> {
        let w = (insn.raw >> 21) & 1;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let reglist = (insn.raw & 0xFFFF) as u16;
        Some((n, reglist, w != 0))
    }

    /// Decode register list for PUSH/POP.
    fn decode_reglist(&self, insn: &DecodedInsn) -> Option<u16> {
        Some((insn.raw & 0xFFFF) as u16)
    }
}

// =============================================================================
// Full Execution Loop
// =============================================================================

/// Run the ARM emulator in a fetch-decode-execute loop.
///
/// Returns when:
/// - An exception is raised
/// - CPU is halted (WFI/WFE)
/// - max_instructions is reached
/// - A memory fault occurs
pub fn run_emulator<M: ArmMemory>(
    cpu: &mut Armv7Cpu,
    mem: &mut M,
    decoder: &crate::arm::decoder::Decoder,
    max_instructions: u64,
) -> Result<ExecResult, DecodeError> {
    let mut executor = Executor::new(cpu, mem);
    let mut instructions_executed = 0u64;

    while instructions_executed < max_instructions {
        // Fetch instruction
        let pc = executor.cpu.regs[15];
        let insn_size = if executor.cpu.cpsr.t { 2 } else { 4 };

        // Read instruction bytes
        let mut bytes = [0u8; 4];
        for i in 0..insn_size {
            match executor.mem.read_byte(pc.wrapping_add(i as u32)) {
                Ok(b) => bytes[i] = b,
                Err(e) => return Ok(ExecResult::MemoryFault(e)),
            }
        }

        // Decode instruction
        let insn = decoder.decode(&bytes[..insn_size as usize])?;

        // Execute instruction
        let result = executor.execute(&insn);
        instructions_executed += 1;

        match result {
            ExecResult::Continue => {
                // Advance PC
                executor.cpu.regs[15] = executor.cpu.regs[15].wrapping_add(insn.size as u32);
            }
            ExecResult::Branch(target) => {
                executor.cpu.regs[15] = target;
            }
            ExecResult::Halt
            | ExecResult::Exception(_)
            | ExecResult::Undefined
            | ExecResult::MemoryFault(_) => {
                return Ok(result);
            }
        }
    }

    Ok(ExecResult::Continue)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::execution::FlatMemory;
    use crate::arm::ExecutionState;

    fn make_cpu() -> Armv7Cpu {
        Armv7Cpu::new()
    }

    fn make_mem() -> FlatMemory {
        FlatMemory::new(0x10000, 0)
    }

    fn make_insn(mnemonic: Mnemonic, raw: u32, sets_flags: bool) -> DecodedInsn {
        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Arm, raw, 4);
        if sets_flags {
            insn = insn.with_flags();
        }
        insn
    }

    #[test]
    fn test_add_immediate() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[1] = 100;

        let insn = make_insn(Mnemonic::ADD, 0xE2810032, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 150);
    }

    #[test]
    fn test_adds_sets_flags() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[1] = 0xFFFFFFFF;

        let insn = make_insn(Mnemonic::ADDS, 0xE2910001, true);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 0);
        assert!(cpu.cpsr.z);
        assert!(cpu.cpsr.c);
    }

    #[test]
    fn test_sub_immediate() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[1] = 100;

        let insn = make_insn(Mnemonic::SUB, 0xE241001E, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 70);
    }

    #[test]
    fn test_mov_immediate() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        let insn = make_insn(Mnemonic::MOV, 0xE3A000FF, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 0xFF);
    }

    #[test]
    fn test_cmp_sets_flags() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[0] = 50;

        let insn = make_insn(Mnemonic::CMP, 0xE3500032, true);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert!(cpu.cpsr.z);
        assert!(cpu.cpsr.c);
    }

    #[test]
    fn test_branch() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[15] = 0x1000;

        let insn = make_insn(Mnemonic::B, 0xEA000040, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        if let ExecResult::Branch(target) = result {
            assert_eq!(target, 0x1000 + 8 + 0x100);
        } else {
            panic!("Expected Branch result");
        }
    }

    #[test]
    fn test_ldr_str() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        mem.write_word(0x100, 0xDEADBEEF).unwrap();

        cpu.regs[1] = 0x100;

        let insn = make_insn(Mnemonic::LDR, 0xE5910000, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 0xDEADBEEF);
    }

    #[test]
    fn test_mul() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[1] = 7;
        cpu.regs[2] = 6;

        let insn = make_insn(Mnemonic::MUL, 0xE0000291, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 42);
    }

    #[test]
    fn test_condition_ne() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.cpsr.z = true;
        cpu.regs[0] = 0;

        let mut insn = make_insn(Mnemonic::MOV, 0x13A00001, false);
        insn.cond = Some(Condition::NE);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 0);
    }

    #[test]
    fn test_svc() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        let insn = make_insn(Mnemonic::SVC, 0xEF00007B, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        if let ExecResult::Exception(ExceptionType::SupervisorCall(imm)) = result {
            assert_eq!(imm, 123);
        } else {
            panic!("Expected SupervisorCall exception");
        }
    }

    #[test]
    fn test_ldrex_strex() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        mem.write_word(0x100, 0x12345678).unwrap();
        cpu.regs[1] = 0x100;
        cpu.regs[3] = 0xDEADBEEF; // Set this before creating executor

        // LDREX R0, [R1] followed by STREX R2, R3, [R1]
        // Must use same executor to maintain exclusive monitor state
        let ldrex = make_insn(Mnemonic::LDXR, 0xE1910F9F, false);
        let strex = make_insn(Mnemonic::STXR, 0xE1812F93, false);

        let mut exec = Executor::new(&mut cpu, &mut mem);

        // Execute LDREX
        let result = exec.execute(&ldrex);
        assert!(matches!(result, ExecResult::Continue));

        // Execute STREX - should succeed because LDREX was just done
        let result = exec.execute(&strex);
        assert!(matches!(result, ExecResult::Continue));

        // Drop executor to check cpu/mem state
        drop(exec);

        assert_eq!(cpu.regs[0], 0x12345678); // LDREX loaded value
        assert_eq!(cpu.regs[2], 0); // STREX success
        assert_eq!(mem.read_word(0x100).unwrap(), 0xDEADBEEF); // Memory updated
    }

    #[test]
    fn test_strex_fails_without_ldrex() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        mem.write_word(0x100, 0x12345678).unwrap();
        cpu.regs[1] = 0x100;
        cpu.regs[3] = 0xDEADBEEF;

        // STREX without LDREX should fail
        let strex = make_insn(Mnemonic::STXR, 0xE1812F93, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&strex);
        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[2], 1); // Failure

        // Memory should be unchanged
        assert_eq!(mem.read_word(0x100).unwrap(), 0x12345678);
    }

    #[test]
    fn test_sdiv_udiv() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[1] = 100;
        cpu.regs[2] = 7;

        // SDIV R0, R1, R2
        let sdiv = make_insn(Mnemonic::SDIV, 0xE710F211, false);
        {
            let mut exec = Executor::new(&mut cpu, &mut mem);
            let result = exec.execute(&sdiv);
            assert!(matches!(result, ExecResult::Continue));
        }
        assert_eq!(cpu.regs[0], 14);

        // Test division by zero
        cpu.regs[2] = 0;
        {
            let mut exec = Executor::new(&mut cpu, &mut mem);
            let result = exec.execute(&sdiv);
            assert!(matches!(result, ExecResult::Continue));
        }
        assert_eq!(cpu.regs[0], 0);
    }

    #[test]
    fn test_exception_handling() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();
        cpu.regs[15] = 0x1000;

        let mut exec = Executor::new(&mut cpu, &mut mem);
        exec.take_exception(ExceptionType::SupervisorCall(0));

        // Should be in SVC mode
        assert_eq!(cpu.cpsr.mode, ProcessorMode::Supervisor as u8);
        // IRQ should be disabled
        assert!(cpu.cpsr.i);
        // Should be in ARM mode
        assert!(!cpu.cpsr.t);
        // PC should be at SVC vector
        assert_eq!(cpu.regs[15], 0x08);
    }

    #[test]
    fn test_bfc_bfi() {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.regs[0] = 0xFFFFFFFF;

        // BFC R0, #4, #8 - clear bits 4-11
        let bfc = make_insn(Mnemonic::BFC, 0xE7CB021F, false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&bfc);
        assert!(matches!(result, ExecResult::Continue));
        assert_eq!(cpu.regs[0], 0xFFFFF00F);
    }
}

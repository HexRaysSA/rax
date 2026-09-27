//! Cortex-M CPU implementation.
//!
//! This module provides a complete Cortex-M processor implementation including:
//! - All Cortex-M variants (M0, M0+, M3, M4, M7, M23, M33, M55, M85)
//! - Thumb/Thumb-2 instruction execution
//! - Exception handling and NVIC integration
//! - Memory protection (MPU)
//! - FPU support (M4, M7, M33+)
//! - DSP extension support

use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;

use crate::isa::arm::aarch32::vfp::VfpState;
use crate::isa::arm::common::cpu::{
    AccessType, ArmCpu, ArmError, ArmException, ArmProfile, ArmVersion, CpuExit, DebugEvent,
    MemoryFaultInfo, MemoryFaultType, ProcessorState, WatchpointKind,
};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::{ArmMemory, FlatMemory, MemoryError, StandardMemory};

use super::exception::number;
use super::exec::Fault;
use super::nvic::Nvic;
use super::scb::{CortexMVariant, Scb, cfsr, hfsr};
use super::systick::SysTick;

/// EXC_RETURN values.
pub mod exc_return {
    /// Return to Handler mode, use MSP.
    pub const HANDLER_MSP: u32 = 0xFFFF_FFF1;
    /// Return to Thread mode, use MSP.
    pub const THREAD_MSP: u32 = 0xFFFF_FFF9;
    /// Return to Thread mode, use PSP.
    pub const THREAD_PSP: u32 = 0xFFFF_FFFD;
    /// Return with FPU state (ARMv7-M+).
    pub const FPU_ACTIVE: u32 = 0xFFFF_FFE1;

    /// Check if returning to Thread mode.
    pub fn is_thread_mode(exc_return: u32) -> bool {
        exc_return & 0x8 != 0
    }

    /// Check if using PSP.
    pub fn uses_psp(exc_return: u32) -> bool {
        exc_return & 0x4 != 0
    }

    /// Check if FPU context was saved.
    pub fn fpu_active(exc_return: u32) -> bool {
        exc_return & 0x10 == 0
    }
}

/// Cortex-M CPU state.
pub struct CortexMCpu {
    /// CPU variant.
    variant: CortexMVariant,
    /// General purpose registers R0-R12.
    pub(super) regs: [u32; 13],
    /// Stack Pointer (banked: MSP and PSP).
    pub(super) sp_main: u32,
    pub(super) sp_process: u32,
    /// Link Register.
    pub(super) lr: u32,
    /// Program Counter.
    pub(super) pc: u32,
    /// Program Status Register (xPSR).
    pub(super) xpsr: u32,
    /// PRIMASK special register.
    pub(super) primask: bool,
    /// FAULTMASK special register (ARMv7-M+).
    pub(super) faultmask: bool,
    /// BASEPRI special register (ARMv7-M+).
    pub(super) basepri: u8,
    /// CONTROL special register.
    pub(super) control: u8,
    /// Currently in Thread mode (false = Handler mode).
    pub(super) thread_mode: bool,
    /// Current exception number (0 = Thread mode).
    pub(super) current_exception: u16,

    /// Memory subsystem.
    pub(super) memory: Box<dyn ArmMemory>,
    /// NVIC.
    nvic: Nvic,
    /// System Control Block.
    scb: Scb,
    /// SysTick timer.
    systick: SysTick,
    /// VFP/FPU state (optional).
    pub(super) vfp: Option<VfpState>,

    /// Instruction count.
    pub(super) insn_count: u64,
    /// Cycle count.
    pub(super) cycle_count: u64,
    /// Breakpoints.
    breakpoints: HashSet<u64>,
    /// Watchpoints (address, size, kind).
    watchpoints: Vec<(u64, usize, WatchpointKind)>,
    /// Halted state.
    pub(super) halted: bool,
    /// Sleep state.
    pub(super) sleeping: bool,
    /// Pending exceptions queue.
    pending_exceptions: Vec<ArmException>,
    /// ExceptionActive[]: one bit per exception number.
    pub(super) active: [u64; 8],
    /// The event register of WFE and SEV.
    pub(super) event_register: bool,
    /// The address of the instruction executing.
    pub(super) insn_addr: u32,
    /// Set when the executing instruction wrote ITSTATE itself (IT, an
    /// exception return), so it does not advance.
    pub(super) it_rewritten: bool,

    /// ARM features.
    features: ArmFeatures,
    /// Architecture version.
    version: ArmVersion,
}

impl CortexMCpu {
    /// Create a new Cortex-M CPU.
    pub fn new(variant: CortexMVariant, memory: Box<dyn ArmMemory>) -> Self {
        let (nvic, version, features) = match variant {
            CortexMVariant::CortexM0 => {
                (Nvic::for_cortex_m0(), ArmVersion::V6M, ArmFeatures::THUMB)
            }
            CortexMVariant::CortexM0Plus => (
                Nvic::for_cortex_m0plus(),
                ArmVersion::V6M,
                ArmFeatures::THUMB,
            ),
            CortexMVariant::CortexM1 => {
                (Nvic::for_cortex_m0(), ArmVersion::V6M, ArmFeatures::THUMB)
            }
            CortexMVariant::CortexM3 => (
                Nvic::for_cortex_m3(),
                ArmVersion::V7M,
                ArmFeatures::THUMB | ArmFeatures::THUMB2,
            ),
            CortexMVariant::CortexM4 => (
                Nvic::for_cortex_m4(),
                ArmVersion::V7EM,
                ArmFeatures::THUMB | ArmFeatures::THUMB2 | ArmFeatures::DSP | ArmFeatures::VFP,
            ),
            CortexMVariant::CortexM7 => (
                Nvic::for_cortex_m7(),
                ArmVersion::V7EM,
                ArmFeatures::THUMB
                    | ArmFeatures::THUMB2
                    | ArmFeatures::DSP
                    | ArmFeatures::VFP
                    | ArmFeatures::VFP_D32,
            ),
            CortexMVariant::CortexM23 => (
                Nvic::for_cortex_m23(),
                ArmVersion::V8MBaseline,
                ArmFeatures::THUMB | ArmFeatures::TRUSTZONE,
            ),
            CortexMVariant::CortexM33 => (
                Nvic::for_cortex_m33(),
                ArmVersion::V8MMainline,
                ArmFeatures::THUMB
                    | ArmFeatures::THUMB2
                    | ArmFeatures::DSP
                    | ArmFeatures::VFP
                    | ArmFeatures::TRUSTZONE,
            ),
            CortexMVariant::CortexM35P => (
                Nvic::for_cortex_m33(),
                ArmVersion::V8MMainline,
                ArmFeatures::THUMB
                    | ArmFeatures::THUMB2
                    | ArmFeatures::DSP
                    | ArmFeatures::VFP
                    | ArmFeatures::TRUSTZONE,
            ),
            CortexMVariant::CortexM55 => (
                Nvic::for_cortex_m55(),
                ArmVersion::V8_1M,
                ArmFeatures::THUMB
                    | ArmFeatures::THUMB2
                    | ArmFeatures::DSP
                    | ArmFeatures::VFP
                    | ArmFeatures::MVE
                    | ArmFeatures::TRUSTZONE,
            ),
            CortexMVariant::CortexM85 => (
                Nvic::for_cortex_m85(),
                ArmVersion::V8_1M,
                ArmFeatures::THUMB
                    | ArmFeatures::THUMB2
                    | ArmFeatures::DSP
                    | ArmFeatures::VFP
                    | ArmFeatures::MVE
                    | ArmFeatures::TRUSTZONE,
            ),
        };

        // The Floating-point Extension is not implemented: FP instructions
        // are coprocessor instructions with no coprocessor (NOCP).
        let vfp: Option<VfpState> = None;

        Self {
            variant,
            regs: [0; 13],
            sp_main: 0,
            sp_process: 0,
            lr: 0xFFFF_FFFF, // Initial LR is all ones
            pc: 0,
            xpsr: 0x0100_0000, // T bit set (Thumb mode)
            primask: false,
            faultmask: false,
            basepri: 0,
            control: 0,
            thread_mode: true,
            current_exception: 0,
            memory,
            nvic,
            scb: Scb::new(variant),
            systick: SysTick::with_frequency(100_000_000), // 100 MHz default
            vfp,
            insn_count: 0,
            cycle_count: 0,
            breakpoints: HashSet::new(),
            watchpoints: Vec::new(),
            halted: false,
            sleeping: false,
            pending_exceptions: Vec::new(),
            active: [0; 8],
            event_register: false,
            insn_addr: 0,
            it_rewritten: false,
            features,
            version,
        }
    }

    /// Create a new Cortex-M4 with flat memory.
    pub fn new_m4(memory_size: usize) -> Self {
        let memory = Box::new(FlatMemory::new(0, memory_size));
        Self::new(CortexMVariant::CortexM4, memory)
    }

    /// Create a new Cortex-M with standard memory.
    pub fn with_standard_memory(variant: CortexMVariant, ram_base: u64, ram_size: usize) -> Self {
        let memory = Box::new(StandardMemory::with_ram(ram_base, ram_size));
        Self::new(variant, memory)
    }

    /// Get the CPU variant.
    pub fn variant(&self) -> CortexMVariant {
        self.variant
    }

    /// Get reference to NVIC.
    pub fn nvic(&self) -> &Nvic {
        &self.nvic
    }

    /// Get mutable reference to NVIC.
    pub fn nvic_mut(&mut self) -> &mut Nvic {
        &mut self.nvic
    }

    /// Get reference to SCB.
    pub fn scb(&self) -> &Scb {
        &self.scb
    }

    /// Get mutable reference to SCB.
    pub fn scb_mut(&mut self) -> &mut Scb {
        &mut self.scb
    }

    /// Get reference to SysTick.
    pub fn systick(&self) -> &SysTick {
        &self.systick
    }

    /// Get mutable reference to SysTick.
    pub fn systick_mut(&mut self) -> &mut SysTick {
        &mut self.systick
    }

    /// Get reference to memory.
    pub fn memory(&self) -> &dyn ArmMemory {
        self.memory.as_ref()
    }

    /// Get mutable reference to memory.
    pub fn memory_mut(&mut self) -> &mut dyn ArmMemory {
        self.memory.as_mut()
    }

    // =========================================================================
    // Stack Pointer Management
    // =========================================================================

    /// Get current stack pointer.
    pub(super) fn current_sp(&self) -> u32 {
        if self.uses_psp() {
            self.sp_process
        } else {
            self.sp_main
        }
    }

    /// Set current stack pointer.
    pub(super) fn set_current_sp(&mut self, value: u32) {
        if self.uses_psp() {
            self.sp_process = value;
        } else {
            self.sp_main = value;
        }
    }

    /// Check if using PSP.
    fn uses_psp(&self) -> bool {
        self.thread_mode && (self.control & 0x2) != 0
    }

    /// Check if in privileged mode.
    fn is_privileged_mode(&self) -> bool {
        !self.thread_mode || (self.control & 0x1) == 0
    }

    // =========================================================================
    // xPSR Access
    // =========================================================================

    /// Get N flag.
    pub fn get_n(&self) -> bool {
        (self.xpsr >> 31) & 1 != 0
    }

    /// Get Z flag.
    pub fn get_z(&self) -> bool {
        (self.xpsr >> 30) & 1 != 0
    }

    /// Get C flag.
    pub fn get_c(&self) -> bool {
        (self.xpsr >> 29) & 1 != 0
    }

    /// Get V flag.
    pub fn get_v(&self) -> bool {
        (self.xpsr >> 28) & 1 != 0
    }

    /// Get Q flag.
    pub fn get_q(&self) -> bool {
        (self.xpsr >> 27) & 1 != 0
    }

    /// Set N flag.
    pub fn set_n(&mut self, value: bool) {
        if value {
            self.xpsr |= 1 << 31;
        } else {
            self.xpsr &= !(1 << 31);
        }
    }

    /// Set Z flag.
    pub fn set_z(&mut self, value: bool) {
        if value {
            self.xpsr |= 1 << 30;
        } else {
            self.xpsr &= !(1 << 30);
        }
    }

    /// Set C flag.
    pub fn set_c(&mut self, value: bool) {
        if value {
            self.xpsr |= 1 << 29;
        } else {
            self.xpsr &= !(1 << 29);
        }
    }

    /// Set V flag.
    pub fn set_v(&mut self, value: bool) {
        if value {
            self.xpsr |= 1 << 28;
        } else {
            self.xpsr &= !(1 << 28);
        }
    }

    /// Set Q flag (sticky).
    pub fn set_q(&mut self) {
        self.xpsr |= 1 << 27;
    }

    /// Update N and Z flags from result.
    pub fn update_nz(&mut self, result: u32) {
        self.set_n((result as i32) < 0);
        self.set_z(result == 0);
    }

    // =========================================================================
    // Pending asynchronous exceptions
    // =========================================================================

    /// Takes the highest-priority pending NMI, PendSV, SysTick, or external
    /// interrupt that can preempt, returning to the current PC.
    fn check_pending_exceptions(&mut self) -> Result<Option<CpuExit>, ArmError> {
        use super::exception::number;
        if self.systick.is_pending() {
            self.scb.set_systick_pending(true);
        }
        let current = self.execution_priority();
        let mut best: Option<(i32, u16)> = None;
        let mut consider = |exception: u16, priority: i32| {
            if priority < current
                && best.is_none_or(|(p, e)| priority < p || (priority == p && exception < e))
            {
                best = Some((priority, exception));
            }
        };
        if self.scb.is_nmi_pending() {
            consider(number::NMI, -2);
        }
        if self.scb.is_pendsv_pending() {
            consider(
                number::PEND_SV,
                i32::from(self.nvic.get_exception_priority(number::PEND_SV)),
            );
        }
        if self.scb.is_systick_pending() {
            consider(
                number::SYS_TICK,
                i32::from(self.nvic.get_exception_priority(number::SYS_TICK)),
            );
        }
        for irq in 0..496u16 {
            if self.nvic.is_pending(irq) && self.nvic.is_enabled(irq) {
                consider(
                    irq + 16,
                    i32::from(self.nvic.get_exception_priority(irq + 16)),
                );
            }
        }
        let Some((_, exception)) = best else {
            return Ok(None);
        };
        let taken = match exception {
            number::NMI => {
                self.scb.set_nmi_pending(false);
                ArmException::Nmi
            }
            number::PEND_SV => {
                self.scb.set_pendsv_pending(false);
                ArmException::PendSv
            }
            number::SYS_TICK => {
                self.scb.set_systick_pending(false);
                self.systick.take_pending();
                ArmException::SysTick
            }
            irq => {
                self.nvic.clear_pending(irq - 16);
                ArmException::Irq(irq - 16)
            }
        };
        self.enter_asynchronous(exception, self.pc)
            .map_err(|error| {
                ArmError::Internal(format!("exception {exception} entry failed: {error:?}"))
            })?;
        Ok(Some(CpuExit::ExceptionTaken(taken)))
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// `ConditionPassed()` for condition code `cond` (0b1111 passes).
    pub(super) fn condition_passed(&self, cond: u32) -> bool {
        let result = match cond >> 1 {
            0b000 => self.get_z(),                                  // EQ/NE
            0b001 => self.get_c(),                                  // CS/CC
            0b010 => self.get_n(),                                  // MI/PL
            0b011 => self.get_v(),                                  // VS/VC
            0b100 => self.get_c() && !self.get_z(),                 // HI/LS
            0b101 => self.get_n() == self.get_v(),                  // GE/LT
            0b110 => self.get_n() == self.get_v() && !self.get_z(), // GT/LE
            0b111 => true,                                          // AL
            _ => unreachable!(),
        };

        if cond & 1 != 0 && cond != 0xF {
            !result
        } else {
            result
        }
    }

    /// Get register value (handling PC and SP specially).
    fn reg(&self, reg: usize) -> u32 {
        match reg {
            0..=12 => self.regs[reg],
            13 => self.current_sp() & !3,
            14 => self.lr,
            15 => self.pc,
            _ => 0,
        }
    }

    /// Set register value.
    fn set_reg(&mut self, reg: usize, value: u32) {
        match reg {
            0..=12 => self.regs[reg] = value,
            13 => self.set_current_sp(value & !3),
            14 => self.lr = value,
            15 => self.pc = value & !1,
            _ => {}
        }
    }
}

impl Debug for CortexMCpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CortexMCpu")
            .field("variant", &self.variant)
            .field("pc", &format_args!("0x{:08x}", self.pc))
            .field("sp", &format_args!("0x{:08x}", self.current_sp()))
            .field("lr", &format_args!("0x{:08x}", self.lr))
            .field("xpsr", &format_args!("0x{:08x}", self.xpsr))
            .field("insn_count", &self.insn_count)
            .finish()
    }
}

impl ArmCpu for CortexMCpu {
    fn step(&mut self) -> Result<CpuExit, ArmError> {
        if self.halted {
            return Ok(CpuExit::Halt);
        }

        if self.sleeping {
            // Check for wake-up events
            if let Some(exit) = self.check_pending_exceptions()? {
                self.sleeping = false;
                return Ok(exit);
            }
            return Ok(CpuExit::Wfi);
        }

        // Check for pending exceptions
        if let Some(exit) = self.check_pending_exceptions()? {
            return Ok(exit);
        }

        if self.breakpoints.contains(&u64::from(self.pc)) {
            return Ok(CpuExit::Breakpoint(self.pc));
        }

        // Advance SysTick
        self.systick.tick(1);

        // Execute one instruction. UNDEFINED encodings and bus errors are
        // reported; the other faults are taken architecturally.
        match self.execute_one() {
            Ok(exit) => Ok(exit),
            Err(Fault::Undefined(insn) | Fault::NoCoprocessor(insn)) => {
                Err(ArmError::UndefinedInstruction(insn))
            }
            Err(Fault::Bus { address, access }) => Err(ArmError::MemoryError(MemoryFaultInfo {
                address: u64::from(address),
                access,
                fault_type: MemoryFaultType::External,
                stage2: false,
            })),
            Err(fault) => {
                let taken = self
                    .take_fault(fault)
                    .map_err(|error| ArmError::Internal(format!("Cortex-M lockup: {error:?}")))?;
                Ok(CpuExit::ExceptionTaken(if taken == number::HARD_FAULT {
                    ArmException::HardFault
                } else {
                    ArmException::UsageFault(self.scb.get_cfsr() >> 16)
                }))
            }
        }
    }

    fn reset(&mut self) {
        // Reset registers
        self.regs = [0; 13];
        self.lr = 0xFFFF_FFFF;
        self.xpsr = 0x0100_0000; // T bit set

        // Reset special registers
        self.primask = false;
        self.faultmask = false;
        self.basepri = 0;
        self.control = 0;
        self.thread_mode = true;
        self.current_exception = 0;

        // Reset peripherals
        self.nvic.reset();
        self.scb.reset();
        self.systick.reset();

        self.active = [0; 8];
        self.event_register = false;

        // Load initial SP and PC from vector table
        if let Ok(sp) = self.mem_a(0, 4) {
            self.sp_main = sp & !3;
        }
        if let Ok(pc) = self.mem_a(4, 4) {
            self.pc = pc & !1;
            if pc & 1 == 0 {
                self.xpsr &= !0x0100_0000;
            }
        }

        // Clear state
        self.insn_count = 0;
        self.cycle_count = 0;
        self.halted = false;
        self.sleeping = false;
        self.pending_exceptions.clear();
    }

    fn get_gpr(&self, reg: u8) -> u64 {
        self.reg(reg as usize) as u64
    }

    fn set_gpr(&mut self, reg: u8, value: u64) {
        self.set_reg(reg as usize, value as u32);
    }

    fn get_pc(&self) -> u64 {
        self.pc as u64
    }

    fn set_pc(&mut self, value: u64) {
        self.pc = (value as u32) & !1;
    }

    fn get_sp(&self) -> u64 {
        self.current_sp() as u64
    }

    fn set_sp(&mut self, value: u64) {
        self.set_current_sp(value as u32);
    }

    fn get_lr(&self) -> u64 {
        self.lr as u64
    }

    fn set_lr(&mut self, value: u64) {
        self.lr = value as u32;
    }

    fn get_pstate(&self) -> ProcessorState {
        ProcessorState {
            n: self.get_n(),
            z: self.get_z(),
            c: self.get_c(),
            v: self.get_v(),
            q: self.get_q(),
            ge: ((self.xpsr >> 16) & 0xF) as u8,
            t: true, // Always in Thumb mode
            i: self.primask,
            f: self.faultmask,
            mode: if self.thread_mode { 0x10 } else { 0x1F },
            ..Default::default()
        }
    }

    fn set_pstate(&mut self, state: ProcessorState) {
        self.set_n(state.n);
        self.set_z(state.z);
        self.set_c(state.c);
        self.set_v(state.v);
        if state.q {
            self.set_q();
        }
        self.primask = state.i;
        self.faultmask = state.f;
    }

    fn is_privileged(&self) -> bool {
        self.is_privileged_mode()
    }

    fn current_el(&self) -> u8 {
        if self.thread_mode { 0 } else { 1 }
    }

    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, ArmError> {
        let mut buf = vec![0u8; size];
        self.memory.read(addr, &mut buf).map_err(ArmError::from)?;
        Ok(buf)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), ArmError> {
        self.memory.write(addr, data).map_err(ArmError::from)
    }

    fn arch_version(&self) -> ArmVersion {
        self.version
    }

    fn profile(&self) -> ArmProfile {
        ArmProfile::M
    }

    fn features(&self) -> ArmFeatures {
        self.features
    }

    fn pending_exceptions(&self) -> Vec<ArmException> {
        self.pending_exceptions.clone()
    }

    fn inject_exception(&mut self, exception: ArmException) -> Result<(), ArmError> {
        match exception {
            ArmException::Irq(irq) => {
                self.nvic.set_pending(irq);
            }
            ArmException::Nmi => {
                self.scb.set_nmi_pending(true);
            }
            ArmException::PendSv => {
                self.scb.set_pendsv_pending(true);
            }
            ArmException::SysTick => {
                self.scb.set_systick_pending(true);
            }
            _ => {
                self.pending_exceptions.push(exception);
            }
        }
        Ok(())
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<(), ArmError> {
        self.breakpoints.insert(addr);
        Ok(())
    }

    fn clear_breakpoint(&mut self, addr: u64) -> Result<(), ArmError> {
        self.breakpoints.remove(&addr);
        Ok(())
    }

    fn set_watchpoint(
        &mut self,
        addr: u64,
        size: usize,
        kind: WatchpointKind,
    ) -> Result<(), ArmError> {
        self.watchpoints.push((addr, size, kind));
        Ok(())
    }

    fn clear_watchpoint(&mut self, addr: u64) -> Result<(), ArmError> {
        self.watchpoints.retain(|(a, _, _)| *a != addr);
        Ok(())
    }

    fn instruction_count(&self) -> u64 {
        self.insn_count
    }

    fn cycle_count(&self) -> Option<u64> {
        Some(self.cycle_count)
    }

    fn has_fpu(&self) -> bool {
        self.vfp.is_some()
    }

    fn get_simd_reg(&self, reg: u8) -> Option<(u64, u64)> {
        self.vfp.as_ref().map(|v| {
            let low = v.read_d(reg * 2);
            let high = v.read_d(reg * 2 + 1);
            (low.to_bits(), high.to_bits())
        })
    }

    fn set_simd_reg(&mut self, reg: u8, low: u64, high: u64) -> Result<(), ArmError> {
        if let Some(ref mut vfp) = self.vfp {
            vfp.write_d(reg * 2, f64::from_bits(low));
            vfp.write_d(reg * 2 + 1, f64::from_bits(high));
            Ok(())
        } else {
            Err(ArmError::Unimplemented("FPU not available".to_string()))
        }
    }

    fn get_fpcr(&self) -> Option<u32> {
        self.vfp.as_ref().map(|v| v.fpscr.bits())
    }

    fn set_fpcr(&mut self, value: u32) -> Result<(), ArmError> {
        if let Some(ref mut vfp) = self.vfp {
            vfp.fpscr = crate::isa::arm::aarch32::vfp::Fpscr::from_bits(value);
            Ok(())
        } else {
            Err(ArmError::Unimplemented("FPU not available".to_string()))
        }
    }

    fn get_fpsr(&self) -> Option<u32> {
        self.vfp.as_ref().map(|v| v.fpscr.bits() & 0x0000_009F)
    }

    fn set_fpsr(&mut self, value: u32) -> Result<(), ArmError> {
        if let Some(ref mut vfp) = self.vfp {
            let fpscr = vfp.fpscr.bits();
            vfp.fpscr = crate::isa::arm::aarch32::vfp::Fpscr::from_bits(
                (fpscr & !0x0000_009F) | (value & 0x0000_009F),
            );
            Ok(())
        } else {
            Err(ArmError::Unimplemented("FPU not available".to_string()))
        }
    }
}

#[cfg(test)]
#[path = "cpu_tests.rs"]
mod tests;

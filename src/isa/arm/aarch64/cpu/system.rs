//! Exception, barrier, and system instruction execution

use crate::isa::arm::aarch64::cpu::*;
use std::collections::HashSet;
use std::fmt::Debug;

use crate::isa::arm::aarch64::exceptions::{
    ExceptionType, SyndromeRegister, build_spsr, exception_target_el, parse_spsr, vector_offset,
};
use crate::isa::arm::aarch64::gic::{Gic, GicConfig};
use crate::isa::arm::aarch64::mmu::{Mmu, MmuConfig, TranslationFault, TranslationGranule};
use crate::isa::arm::aarch64::sysregs::SystemRegisters;
use crate::isa::arm::aarch64::{NUM_ELS, NUM_GPRS, NUM_SIMD_REGS, sctlr};

use crate::isa::arm::common::cpu::{
    ArmCpu, ArmError, ArmException, ArmProfile, ArmVersion, CpuExit, MemoryFaultInfo,
    MemoryFaultType, ProcessorState, WatchpointKind,
};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::ArmMemory;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::vcpu::Aarch64SystemRegisters;

impl AArch64Cpu {
    // =========================================================================
    // Exception Handling
    // =========================================================================

    /// Take an exception.
    pub(crate) fn take_exception(
        &mut self,
        target_el: u8,
        exc_type: ExceptionType,
        syndrome: SyndromeRegister,
    ) -> Result<(), ArmError> {
        // Build SPSR from current state
        let saved_spsr = build_spsr(
            self.nzcv,
            self.daif,
            self.current_el,
            self.sp_sel,
            self.ssbs,
            self.pan,
            self.uao,
            self.dit,
            self.tco,
            self.btype,
            self.il,
            self.ss,
        );

        // Save state to target EL. Asynchronous exceptions (IRQ/FIQ) do not
        // report a syndrome; leave ESR untouched for them.
        self.sysregs.bank_mut(target_el).spsr = saved_spsr;
        self.sysregs.bank_mut(target_el).elr = self.pc;
        if !matches!(exc_type, ExceptionType::Irq | ExceptionType::Fiq) {
            self.sysregs.bank_mut(target_el).esr = syndrome.value;
        }

        // Calculate vector offset
        let offset = vector_offset(
            exc_type,
            self.current_el,
            target_el,
            true, // from AArch64
            self.sp_sel,
        );

        // Get VBAR
        let vbar = self.sysregs.bank(target_el).vbar;

        // Switch to target EL
        self.current_el = target_el;
        self.sp_sel = true; // Use SP_ELx
        self.daif = 0xF; // Mask all interrupts
        self.uao = false;

        // Clear single-step
        self.ss = false;

        // Clear IL
        self.il = false;

        // Set BTYPE to 0
        self.btype = 0;

        // Branch to handler
        self.pc = vbar.wrapping_add(offset);

        Ok(())
    }

    pub(crate) fn exec_exception_system(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        // Check bits [31:24] to distinguish exception generation from system instructions
        let bits_31_24 = (insn >> 24) & 0xFF;

        if bits_31_24 == 0xD4 {
            // Exception generation: opc (bits 23:21) selects the group and
            // LL (bits 1:0) the target level — SVC/HVC/SMC share opc=000 and
            // differ only in LL.
            let opc = (insn >> 21) & 0x7;
            let op2 = (insn >> 2) & 0x7;
            let ll = insn & 0x3;
            let imm16 = ((insn >> 5) & 0xFFFF) as u16;

            if op2 != 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }

            return match (opc, ll) {
                (0b000, 0b01) => Ok(CpuExit::Svc(imm16 as u32)),
                (0b000, 0b10) => Ok(CpuExit::Hvc(imm16)),
                (0b000, 0b11) => Ok(CpuExit::Smc(imm16)),
                (0b001, 0b00) => Ok(CpuExit::Breakpoint(imm16 as u32)),
                (0b010, 0b00) | (0b101, 0b01..=0b11) => {
                    // HLT / DCPS1-3: halt into (emulated) debug state.
                    self.halted = true;
                    Ok(CpuExit::Halt)
                }
                _ => Err(ArmError::UndefinedInstruction(insn)),
            };
        }

        // bits [31:22] = 0x354 (1101_0101_00) = system instructions
        // This covers hints, barriers, MSR, MRS, etc.
        let l = (insn >> 21) & 1;
        let op0 = (insn >> 19) & 0x3;

        if l == 0 && op0 == 0 {
            // System instructions with L=0, op0=00 (hints, barriers, MSR imm)
            return self.exec_system(insn);
        }

        // SYS/SYSL (op0=01): cache/TLB maintenance, DC ZVA, AT
        if op0 == 1 {
            return self.exec_sys_insn(insn, l == 1);
        }

        if l == 1 && op0 == 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // MSR/MRS (system register access)
        // L=0: MSR (write), L=1: MRS (read)
        // op0 = 10 or 11 for different register categories
        if op0 != 0 || l == 1 {
            return self.exec_msr_mrs(insn);
        }

        Err(ArmError::UndefinedInstruction(insn))
    }

    /// Execute SYS/SYSL (op0=01): DC/IC/TLBI/AT space. Maintenance operations
    /// are mostly no-ops for this memory model, but VA-based operations still
    /// perform their architecturally-visible memory fault checks.
    pub(crate) fn exec_sys_insn(&mut self, insn: u32, is_read: bool) -> Result<CpuExit, ArmError> {
        let op1 = ((insn >> 16) & 0x7) as u8;
        let crn = ((insn >> 12) & 0xF) as u8;
        let crm = ((insn >> 8) & 0xF) as u8;
        let op2 = ((insn >> 5) & 0x7) as u8;
        let rt = (insn & 0x1F) as u8;

        let el0_sys_access = !is_read
            && op1 == 3
            && crn == 7
            && (matches!((crm, op2), (4, 1 | 3 | 4) | (5 | 11, 1))
                || (matches!(crm, 10 | 12 | 13 | 14) && matches!(op2, 1 | 3 | 5)));
        if self.current_el == 0 && !el0_sys_access {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        if is_read {
            // SYSL: nothing implemented reads back state
            if rt != 31 {
                self.set_x(rt, 0);
            }
            return Ok(CpuExit::Continue);
        }

        // DC ZVA / DC GZVA: zero a block of memory at X[rt]. Allocation tags
        // are not modeled, so the tag-generation side of GZVA is ignored.
        if (op1, crn, crm) == (3, 7, 4) && matches!(op2, 1 | 4) {
            let block = 4usize << (self.sysregs.dczid_el0 & 0xF);
            let va = self.get_x(rt) & !(block as u64 - 1);
            for off in (0..block as u64).step_by(8) {
                self.mem_write_u64(va + off, 0)?;
            }
            return Ok(CpuExit::Continue);
        }

        // AT S1E1R/S1E1W/S1E0R/S1E0W: stage-1 address translation probe;
        // result lands in PAR_EL1.
        if (op1, crn, crm) == (0, 7, 8) && op2 < 4 {
            // The EL1&0 regime's top-byte-ignore applies, as to a data access.
            let va = self.effective_data_address(self.get_x(rt), 1);
            let privileged = op2 < 2;
            let is_write = op2 & 1 != 0;
            let par = match self.mmu.translate(
                va,
                self.memory.as_ref(),
                is_write,
                false,
                privileged,
                self.current_el,
            ) {
                // F=0, PA in bits 51:12, outer/inner WB cacheable attrs.
                Ok(desc) => (desc.pa & 0x000F_FFFF_FFFF_F000) | (0xFFu64 << 56),
                // F=1, fault status in bits 6:1.
                Err(fault) => {
                    let fsc = fsc_for_fault(translation_fault_type_of(&fault), fault.level) as u64;
                    1 | (fsc << 1)
                }
            };
            let enc = Aarch64SysRegEncoding::new(3, 0, 7, 4, 0); // PAR_EL1
            let _ = self.sysregs.write(enc, par, self.current_el);
            return Ok(CpuExit::Continue);
        }

        // DC GVA and DC CVA*/CGD* VA operations: cache/tag side effects are not
        // modeled, but the VA operand can still fault before the operation retires.
        if op1 == 3
            && crn == 7
            && (matches!((crm, op2), (4, 3))
                || (matches!(crm, 10 | 12 | 13 | 14) && matches!(op2, 1 | 3 | 5)))
        {
            let _ = self.mem_read_u8(self.get_x(rt))?;
            return Ok(CpuExit::Continue);
        }

        // Everything else (DC/IC/TLBI/...) is a no-op: there are no caches,
        // and translations are walked on every access.
        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_system(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let crn = ((insn >> 12) & 0xF) as u8;
        let op1 = ((insn >> 16) & 0x7) as u8;
        let crm = ((insn >> 8) & 0xF) as u8;
        let op2 = ((insn >> 5) & 0x7) as u8;
        let rt = (insn & 0x1F) as u8;

        if crn == 4 {
            if rt != 31 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            // PSTATE space: MSR (immediate) writes of PSTATE fields (CRm
            // carries the immediate) plus the FEAT_FlagM flag-format ops.
            // Kernels lean on DAIFSet/DAIFClr for interrupt masking, so these
            // must not fall through as hints.
            if self.current_el == 0
                && !((op1 == 0 && op2 <= 0b010)
                    || (op1 == 3 && matches!(op2, 0b001 | 0b010 | 0b100)))
            {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let imm = ((insn >> 8) & 0xF) as u8;
            match (op1, op2) {
                // CFINV
                (0, 0b000) => {
                    let c = self.get_c();
                    self.set_nzcv(self.get_n(), self.get_z(), !c, self.get_v());
                }
                // XAFLAG
                (0, 0b001) => {
                    let (z, c) = (self.get_z(), self.get_c());
                    self.set_nzcv(!c && !z, z && c, c || z, !c && z);
                }
                // AXFLAG
                (0, 0b010) => {
                    let (z, c, v) = (self.get_z(), self.get_c(), self.get_v());
                    self.set_nzcv(false, z || v, c && !v, false);
                }
                // UAO
                (0, 0b011) => {
                    if self.current_el == 0 || !self.has_uao_ext() {
                        return Err(ArmError::UndefinedInstruction(insn));
                    }
                    self.uao = imm & 1 != 0;
                }
                // PAN
                (0, 0b100) => {
                    if self.current_el == 0 || !self.has_pan_ext() {
                        return Err(ArmError::UndefinedInstruction(insn));
                    }
                    self.pan = imm & 1 != 0;
                }
                // SPSel
                (0, 0b101) => self.sp_sel = imm & 1 != 0,
                // SSBS
                (3, 0b001) => self.ssbs = imm & 1 != 0,
                // DIT
                (3, 0b010) => self.dit = imm & 1 != 0,
                // TCO
                (3, 0b100) => self.tco = imm & 1 != 0,
                // DAIFSet
                (3, 0b110) => self.daif |= imm,
                // DAIFClr
                (3, 0b111) => self.daif &= !imm,
                // Unallocated PSTATE ops behave as NOPs here (lenient, like
                // the pre-existing fall-through).
                _ => {}
            }
            return Ok(CpuExit::Continue);
        }

        if crn == 1 && op1 == 3 && crm == 0 && matches!(op2, 0b000 | 0b001) {
            // WFET/WFIT timed wait hints. Timing is not modeled; a zero or
            // expired timeout retires without changing architectural state.
            return Ok(CpuExit::Continue);
        }

        if crn == 2 && op1 == 3 {
            if rt != 31 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            // Hints: HINT #imm7 where imm7 = CRm:op2. Only CRm=0 carries the
            // classic NOP/YIELD/WFE/WFI/SEV/SEVL group; higher CRm values are
            // BTI landing pads, pointer-auth hints (PACIASP/AUTIASP), etc.,
            // which behave as NOPs here.
            if crm != 0 {
                return Ok(CpuExit::Continue);
            }
            match op2 {
                0b000 => Ok(CpuExit::Continue), // NOP
                0b001 => Ok(CpuExit::Continue), // YIELD
                0b010 => {
                    // WFE
                    if self.event_register {
                        self.event_register = false;
                        Ok(CpuExit::Continue)
                    } else {
                        self.wfe = true;
                        Ok(CpuExit::Wfe)
                    }
                }
                0b011 => {
                    // WFI
                    self.wfi = true;
                    Ok(CpuExit::Wfi)
                }
                0b100 => {
                    // SEV
                    self.event_register = true;
                    Ok(CpuExit::Continue)
                }
                0b101 => {
                    // SEVL
                    self.event_register = true;
                    Ok(CpuExit::Continue)
                }
                0b111 => {
                    // XPACLRI: strip instruction-address PAC bits from LR.
                    self.set_x(30, strip_pac(self.get_x(30), false));
                    Ok(CpuExit::Continue)
                }
                _ => Ok(CpuExit::Continue),
            }
        } else if crn == 3 && op1 == 3 {
            if rt != 31 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            match op2 {
                0b010 => Ok(CpuExit::Continue),             // CLREX
                0b100 => Ok(CpuExit::Continue),             // DSB
                0b101 => Ok(CpuExit::Continue),             // DMB
                0b110 => Ok(CpuExit::Continue),             // ISB
                0b111 if crm == 0 => Ok(CpuExit::Continue), // SB
                0b001 if matches!(crm, 0b0010 | 0b0110 | 0b1010 | 0b1110) => {
                    Ok(CpuExit::Continue) // DSB nXS
                }
                _ => Err(ArmError::UndefinedInstruction(insn)),
            }
        } else {
            Err(ArmError::UndefinedInstruction(insn))
        }
    }

    /// Take a synchronous exception with the given syndrome (and FAR, for
    /// aborts).
    pub(crate) fn enter_sync_exception(
        &mut self,
        syndrome: SyndromeRegister,
        far: Option<u64>,
    ) -> Result<(), ArmError> {
        let target = exception_target_el(
            ExceptionType::Synchronous,
            self.current_el,
            self.sysregs.hcr_el2,
            self.sysregs.scr_el3,
        );
        if let Some(addr) = far {
            self.sysregs.bank_mut(target).far = addr;
        }
        self.take_exception(target, ExceptionType::Synchronous, syndrome)
    }

    /// Drain a pending SMC invalidation: evict every cached region (and hot
    /// counters + code-page set). Whole-cache eviction is coarse but correct and
    /// SMC is rare; heads re-promote from the modified bytes. Called at the top
    /// of `step_system`, never mid-region.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_drain_smc(&mut self) {
        if self.jit.smc_dirty {
            self.jit.cache.clear();
            self.jit.hot.clear();
            self.jit.code_pages.clear();
            self.jit.smc_dirty = false;
        }
    }
}

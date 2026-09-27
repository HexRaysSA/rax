//! System/general register and PSTATE access

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
    // Register Access
    // =========================================================================

    /// Get X register (X0-X30, or XZR if reg == 31).
    pub fn get_x(&self, reg: u8) -> u64 {
        if reg < 31 {
            self.x[reg as usize]
        } else {
            0 // XZR
        }
    }

    /// Get the full 128 bits of a V (SIMD/FP) register V0-V31.
    pub fn get_simd(&self, n: u8) -> u128 {
        self.v[(n & 31) as usize]
    }

    /// Set the full 128 bits of a V (SIMD/FP) register V0-V31.
    pub fn set_simd(&mut self, n: u8, value: u128) {
        self.v[(n & 31) as usize] = value;
    }

    /// Floating-point control register, masked to architecturally modeled bits.
    pub fn fpcr_value(&self) -> u32 {
        mask_fpcr(self.fpcr)
    }

    /// Replace the floating-point control register.
    pub fn set_fpcr_value(&mut self, value: u32) {
        self.fpcr = mask_fpcr(value);
    }

    /// Floating-point status register, masked to architecturally modeled bits.
    pub fn fpsr_value(&self) -> u32 {
        mask_fpsr(self.fpsr)
    }

    /// Replace the floating-point status register.
    pub fn set_fpsr_value(&mut self, value: u32) {
        self.fpsr = mask_fpsr(value);
    }

    /// Set X register (X0-X30, write to XZR is ignored).
    pub fn set_x(&mut self, reg: u8, value: u64) {
        if reg < 31 {
            self.x[reg as usize] = value;
        }
    }

    /// Get W register (lower 32 bits of X).
    pub fn get_w(&self, reg: u8) -> u32 {
        self.get_x(reg) as u32
    }

    /// Set W register (zero-extends to X).
    pub fn set_w(&mut self, reg: u8, value: u32) {
        self.set_x(reg, value as u64);
    }

    /// Write a register encoded in the "Xn|SP" slot.
    pub(crate) fn set_gpr_or_sp(&mut self, reg: u8, value: u64) {
        if reg == 31 {
            self.set_current_sp(value);
        } else {
            self.set_x(reg, value);
        }
    }

    /// Set current stack pointer.
    pub fn set_current_sp(&mut self, value: u64) {
        if self.sp_sel || self.current_el == 0 {
            if self.current_el == 0 {
                self.sp_el[0] = value;
            } else {
                self.sp_el[self.current_el as usize] = value;
            }
        } else {
            self.sp_el[0] = value;
        }
    }

    // =========================================================================
    // Flag Access
    // =========================================================================

    /// Get N flag.
    pub fn get_n(&self) -> bool {
        (self.nzcv >> 3) & 1 != 0
    }

    /// Get Z flag.
    pub fn get_z(&self) -> bool {
        (self.nzcv >> 2) & 1 != 0
    }

    /// Get C flag.
    pub fn get_c(&self) -> bool {
        (self.nzcv >> 1) & 1 != 0
    }

    /// Get V flag.
    pub fn get_v(&self) -> bool {
        self.nzcv & 1 != 0
    }

    /// Set N flag.
    pub fn set_n(&mut self, v: bool) {
        if v {
            self.nzcv |= 0x8;
        } else {
            self.nzcv &= !0x8;
        }
    }

    /// Set Z flag.
    pub fn set_z(&mut self, v: bool) {
        if v {
            self.nzcv |= 0x4;
        } else {
            self.nzcv &= !0x4;
        }
    }

    /// Set C flag.
    pub fn set_c(&mut self, v: bool) {
        if v {
            self.nzcv |= 0x2;
        } else {
            self.nzcv &= !0x2;
        }
    }

    /// Set V flag.
    pub fn set_v(&mut self, v: bool) {
        if v {
            self.nzcv |= 0x1;
        } else {
            self.nzcv &= !0x1;
        }
    }

    /// Set all NZCV flags.
    pub fn set_nzcv(&mut self, n: bool, z: bool, c: bool, v: bool) {
        self.nzcv = ((n as u8) << 3) | ((z as u8) << 2) | ((c as u8) << 1) | (v as u8);
    }

    /// Update N and Z flags based on result.
    pub fn update_nz_64(&mut self, result: u64) {
        self.set_n((result as i64) < 0);
        self.set_z(result == 0);
    }

    /// Update N and Z flags based on 32-bit result.
    pub fn update_nz_32(&mut self, result: u32) {
        self.set_n((result as i32) < 0);
        self.set_z(result == 0);
    }

    pub(crate) fn has_uao_ext(&self) -> bool {
        ((self.sysregs.id_aa64mmfr2_el1 >> 4) & 0xF) != 0
    }

    pub(crate) fn has_pan_ext(&self) -> bool {
        ((self.sysregs.id_aa64mmfr1_el1 >> 20) & 0xF) != 0
    }

    // =========================================================================
    // System Register Access
    // =========================================================================

    /// Read system register.
    pub(crate) fn read_sysreg(&self, encoding: Aarch64SysRegEncoding) -> Result<u64, ArmError> {
        if self.current_el == 0 && !Self::sysreg_read_allowed_at_el0(encoding) {
            return Err(ArmError::InvalidExceptionLevel(0));
        }

        // Handle special cases first
        match (
            encoding.op0,
            encoding.op1,
            encoding.crn,
            encoding.crm,
            encoding.op2,
        ) {
            // NZCV
            (3, 3, 4, 2, 0) => {
                return Ok((self.nzcv as u64) << 28);
            }
            // DAIF
            (3, 3, 4, 2, 1) => {
                return Ok((self.daif as u64) << 6);
            }
            // DIT
            (3, 3, 4, 2, 5) => {
                return Ok(if self.dit { 1 << 24 } else { 0 });
            }
            // SSBS
            (3, 3, 4, 2, 6) => {
                return Ok(if self.ssbs { 1 << 12 } else { 0 });
            }
            // TCO
            (3, 3, 4, 2, 7) => {
                return Ok(if self.tco { 1 << 25 } else { 0 });
            }
            // CurrentEL
            (3, 0, 4, 2, 2) => {
                return Ok((self.current_el as u64) << 2);
            }
            // SPSel
            (3, 0, 4, 2, 0) => {
                return Ok(self.sp_sel as u64);
            }
            // SP_EL0
            (3, 0, 4, 1, 0) => {
                return Ok(self.sp_el[0]);
            }
            // SP_EL1
            (3, 4, 4, 1, 0) => {
                return Ok(self.sp_el[1]);
            }
            // SP_EL2
            (3, 6, 4, 1, 0) => {
                return Ok(self.sp_el[2]);
            }
            // FPCR
            (3, 3, 4, 4, 0) => {
                return Ok(mask_fpcr(self.fpcr) as u64);
            }
            // FPSR
            (3, 3, 4, 4, 1) => {
                return Ok(mask_fpsr(self.fpsr) as u64);
            }
            _ => {}
        }

        // GICv3 CPU interface (ICC_*)
        if let Some(value) = self.read_icc(encoding) {
            return Ok(value);
        }

        // Unallocated registers in the ID/cache-info space (op0=3, crn=0:
        // ID_*, AIDR, CCSIDR, ...) and the debug ID space (op0=2, crn=0:
        // MDCCSR, DBGDTR, ...) are RAZ by architecture; a booting kernel
        // reads the whole block.
        if (encoding.op0 == 3 || encoding.op0 == 2) && encoding.crn == 0 {
            return Ok(self.sysregs.read(encoding, self.current_el).unwrap_or(0));
        }

        // Read from sysregs
        self.sysregs
            .read(encoding, self.current_el)
            .ok_or_else(|| ArmError::Unimplemented(format!("System register {}", encoding)))
    }

    /// Read a GICv3 CPU interface (ICC_*) register. Returns None when the
    /// encoding is not an implemented ICC register.
    pub(crate) fn read_icc(&self, encoding: Aarch64SysRegEncoding) -> Option<u64> {
        let gic = self.gic.as_ref()?;
        let enc = (
            encoding.op0,
            encoding.op1,
            encoding.crn,
            encoding.crm,
            encoding.op2,
        );
        let mut gic = gic.lock().ok()?;
        let value = match enc {
            // ICC_PMR_EL1
            (3, 0, 4, 6, 0) => gic.cpu(0)?.priority_mask as u64,
            // ICC_IAR0_EL1 / ICC_IAR1_EL1 (read acknowledges)
            (3, 0, 12, 8, 0) | (3, 0, 12, 12, 0) => gic.acknowledge(0) as u64,
            // ICC_HPPIR0_EL1 / ICC_HPPIR1_EL1
            (3, 0, 12, 8, 2) | (3, 0, 12, 12, 2) => gic.cpu(0)?.highest_pending_intid as u64,
            // ICC_BPR0_EL1
            (3, 0, 12, 8, 3) => gic.cpu(0)?.bpr0 as u64,
            // ICC_BPR1_EL1
            (3, 0, 12, 12, 3) => gic.cpu(0)?.bpr1 as u64,
            // ICC_AP0R / ICC_AP1R (active priorities: RAZ)
            (3, 0, 12, 8, 4..=7) | (3, 0, 12, 9, 0..=3) => 0,
            // ICC_RPR_EL1
            (3, 0, 12, 11, 3) => gic.cpu(0)?.running_priority as u64,
            // ICC_CTLR_EL1: PRIbits=7 (8 priority bits), IDbits=0 (16-bit)
            (3, 0, 12, 12, 4) => {
                let cpu = gic.cpu(0)?;
                (7 << 8) | (cpu.eoi_mode as u64) << 1
            }
            // ICC_SRE_EL1: system register interface enabled, locked on
            (3, 0, 12, 12, 5) => 0x7,
            // ICC_IGRPEN0_EL1
            (3, 0, 12, 12, 6) => gic.cpu(0)?.igrpen0,
            // ICC_IGRPEN1_EL1
            (3, 0, 12, 12, 7) => gic.cpu(0)?.igrpen1,
            _ => return None,
        };
        Some(value)
    }

    /// Write a GICv3 CPU interface (ICC_*) register. Returns true when the
    /// encoding was handled.
    pub(crate) fn write_icc(&mut self, encoding: Aarch64SysRegEncoding, value: u64) -> bool {
        let Some(gic) = self.gic.as_ref() else {
            return false;
        };
        let enc = (
            encoding.op0,
            encoding.op1,
            encoding.crn,
            encoding.crm,
            encoding.op2,
        );
        let Ok(mut gic) = gic.lock() else {
            return false;
        };
        match enc {
            // ICC_PMR_EL1
            (3, 0, 4, 6, 0) => gic.set_priority_mask(0, value as u8),
            // ICC_EOIR0_EL1 / ICC_EOIR1_EL1
            (3, 0, 12, 8, 1) | (3, 0, 12, 12, 1) => gic.end_of_interrupt(0, value as u32),
            // ICC_BPR0_EL1
            (3, 0, 12, 8, 3) => {
                if let Some(cpu) = gic.cpu_mut(0) {
                    cpu.bpr0 = (value & 0x7) as u8;
                }
            }
            // ICC_BPR1_EL1
            (3, 0, 12, 12, 3) => {
                if let Some(cpu) = gic.cpu_mut(0) {
                    cpu.bpr1 = (value & 0x7) as u8;
                }
            }
            // ICC_AP0R / ICC_AP1R: WI
            (3, 0, 12, 8, 4..=7) | (3, 0, 12, 9, 0..=3) => {}
            // ICC_DIR_EL1
            (3, 0, 12, 11, 1) => gic.deactivate(0, value as u32),
            // ICC_SGI1R_EL1 / ICC_ASGI1R_EL1 / ICC_SGI0R_EL1
            (3, 0, 12, 11, 5) | (3, 0, 12, 11, 6) | (3, 0, 12, 11, 7) => gic.raise_sgi(value),
            // ICC_CTLR_EL1: only EOImode is writable here
            (3, 0, 12, 12, 4) => {
                if let Some(cpu) = gic.cpu_mut(0) {
                    cpu.eoi_mode = (value >> 1) & 1 != 0;
                    cpu.ctlr_el1 = value;
                }
            }
            // ICC_SRE_EL1: WI (system register interface is always on)
            (3, 0, 12, 12, 5) => {}
            // ICC_IGRPEN0_EL1
            (3, 0, 12, 12, 6) => gic.set_group_enable(0, false, value & 1 != 0),
            // ICC_IGRPEN1_EL1
            (3, 0, 12, 12, 7) => gic.set_group_enable(0, true, value & 1 != 0),
            _ => return false,
        }
        true
    }

    /// Write system register.
    pub(crate) fn write_sysreg(
        &mut self,
        encoding: Aarch64SysRegEncoding,
        value: u64,
    ) -> Result<(), ArmError> {
        if self.current_el == 0 && !Self::sysreg_write_allowed_at_el0(encoding) {
            return Err(ArmError::InvalidExceptionLevel(0));
        }

        // Handle special cases first
        match (
            encoding.op0,
            encoding.op1,
            encoding.crn,
            encoding.crm,
            encoding.op2,
        ) {
            // NZCV
            (3, 3, 4, 2, 0) => {
                self.nzcv = ((value >> 28) & 0xF) as u8;
                return Ok(());
            }
            // DAIF
            (3, 3, 4, 2, 1) => {
                self.daif = ((value >> 6) & 0xF) as u8;
                return Ok(());
            }
            // DIT
            (3, 3, 4, 2, 5) => {
                self.dit = ((value >> 24) & 1) != 0;
                return Ok(());
            }
            // SSBS
            (3, 3, 4, 2, 6) => {
                self.ssbs = ((value >> 12) & 1) != 0;
                return Ok(());
            }
            // TCO
            (3, 3, 4, 2, 7) => {
                self.tco = ((value >> 25) & 1) != 0;
                return Ok(());
            }
            // SPSel
            (3, 0, 4, 2, 0) => {
                self.sp_sel = (value & 1) != 0;
                return Ok(());
            }
            // SP_EL0
            (3, 0, 4, 1, 0) => {
                self.sp_el[0] = value;
                return Ok(());
            }
            // SP_EL1
            (3, 4, 4, 1, 0) => {
                self.sp_el[1] = value;
                return Ok(());
            }
            // SP_EL2
            (3, 6, 4, 1, 0) => {
                self.sp_el[2] = value;
                return Ok(());
            }
            // FPCR
            (3, 3, 4, 4, 0) => {
                self.fpcr = mask_fpcr(value as u32);
                return Ok(());
            }
            // FPSR
            (3, 3, 4, 4, 1) => {
                self.fpsr = mask_fpsr(value as u32);
                return Ok(());
            }
            // SCTLR_ELx - update MMU config
            (3, 0, 1, 0, 0) | (3, 4, 1, 0, 0) | (3, 6, 1, 0, 0) => {
                let el = encoding.op1 / 2; // 0->EL1, 4->EL2, 6->EL3
                let el = if el == 0 { 1 } else { el };
                self.sysregs.bank_mut(el).sctlr = value;
                self.update_mmu_config();
                return Ok(());
            }
            // TCR_ELx - update MMU config
            (3, 0, 2, 0, 2) | (3, 4, 2, 0, 2) | (3, 6, 2, 0, 2) => {
                let el = encoding.op1 / 2;
                let el = if el == 0 { 1 } else { el };
                self.sysregs.bank_mut(el).tcr = value;
                self.update_mmu_config();
                return Ok(());
            }
            // TTBR0_ELx - update MMU config
            (3, 0, 2, 0, 0) | (3, 4, 2, 0, 0) | (3, 6, 2, 0, 0) => {
                let el = encoding.op1 / 2;
                let el = if el == 0 { 1 } else { el };
                self.sysregs.bank_mut(el).ttbr0 = value;
                self.update_mmu_config();
                return Ok(());
            }
            // TTBR1_EL1
            (3, 0, 2, 0, 1) => {
                self.sysregs.el1.ttbr1 = value;
                self.update_mmu_config();
                return Ok(());
            }
            // MAIR_ELx
            (3, 0, 10, 2, 0) | (3, 4, 10, 2, 0) | (3, 6, 10, 2, 0) => {
                let el = encoding.op1 / 2;
                let el = if el == 0 { 1 } else { el };
                self.sysregs.bank_mut(el).mair = value;
                self.update_mmu_config();
                return Ok(());
            }
            _ => {}
        }

        // GICv3 CPU interface (ICC_*)
        if self.write_icc(encoding, value) {
            return Ok(());
        }

        // Write to sysregs
        if self.sysregs.write(encoding, value, self.current_el) {
            Ok(())
        } else {
            Err(ArmError::Unimplemented(format!(
                "System register write {}",
                encoding
            )))
        }
    }

    pub(crate) fn sysreg_read_allowed_at_el0(encoding: Aarch64SysRegEncoding) -> bool {
        matches!(
            (
                encoding.op0,
                encoding.op1,
                encoding.crn,
                encoding.crm,
                encoding.op2,
            ),
            // Linux exposes these ID registers at EL0 when HWCAP_CPUID is set.
            (3, 0, 0, 0, 0)  // MIDR_EL1
                | (3, 0, 0, 0, 5)  // MPIDR_EL1
                | (3, 0, 0, 0, 6)  // REVIDR_EL1
                // ID_ISAR*, MVFR*, and ID_AA64* groups. Linux exposes future
                // slots in this sub-block as ID values or RAZ.
                | (3, 0, 0, 2..=7, 0..=7)
            // EL0-visible status/control registers.
                | (3, 3, 4, 2, 0)  // NZCV
                | (3, 3, 4, 2, 5)  // DIT
                | (3, 3, 4, 2, 6)  // SSBS
                | (3, 3, 4, 2, 7)  // TCO
                | (3, 3, 4, 4, 0)  // FPCR
                | (3, 3, 4, 4, 1)  // FPSR
                // EL0-visible debug ID/status registers on Linux.
                | (2, 3, 0, 1, 0)  // S2_3_C0_C1_0
                // EL0-visible cache/timer/thread state.
                | (3, 3, 0, 0, 1)  // CTR_EL0
                | (3, 3, 0, 0, 7)  // DCZID_EL0
                | (3, 3, 13, 0, 2) // TPIDR_EL0
                | (3, 3, 13, 0, 3) // TPIDRRO_EL0
                | (3, 3, 14, 0, 0) // CNTFRQ_EL0
                | (3, 3, 14, 0, 2) // CNTVCT_EL0
                | (3, 3, 14, 0, 6) // CNTVCTSS_EL0
                // Random-number registers are architecturally EL0-readable.
                | (3, 3, 2, 4, 0)  // RNDR
                | (3, 3, 2, 4, 1) // RNDRRS
        )
    }

    pub(crate) fn sysreg_write_allowed_at_el0(encoding: Aarch64SysRegEncoding) -> bool {
        matches!(
            (
                encoding.op0,
                encoding.op1,
                encoding.crn,
                encoding.crm,
                encoding.op2,
            ),
            (3, 3, 4, 2, 0)  // NZCV
                | (3, 3, 4, 2, 5)  // DIT
                | (3, 3, 4, 2, 6)  // SSBS
                | (3, 3, 4, 2, 7)  // TCO
                | (3, 3, 4, 4, 0)  // FPCR
                | (3, 3, 4, 4, 1)  // FPSR
                | (2, 3, 0, 4, 0)  // S2_3_C0_C4_0
                | (3, 3, 13, 0, 2) // TPIDR_EL0
        )
    }

    /// Update MMU configuration from system registers.
    pub(crate) fn update_mmu_config(&mut self) {
        let sctlr = self.sysregs.bank(self.current_el).sctlr;
        let tcr = self.sysregs.bank(self.current_el).tcr;
        let ttbr0 = self.sysregs.bank(self.current_el).ttbr0;
        let ttbr1 = if self.current_el == 1 {
            self.sysregs.el1.ttbr1
        } else {
            0
        };
        let mair = self.sysregs.bank(self.current_el).mair;

        let enabled = (sctlr & sctlr::M) != 0;
        let wxn = (sctlr & sctlr::WXN) != 0;

        let t0sz = (tcr & 0x3F) as u8;
        let t1sz = ((tcr >> 16) & 0x3F) as u8;
        let tg0 = ((tcr >> 14) & 0x3) as u8;
        let tg1 = ((tcr >> 30) & 0x3) as u8;

        let granule0 = TranslationGranule::from_tg0(tg0).unwrap_or(TranslationGranule::Granule4KB);
        let granule1 = TranslationGranule::from_tg1(tg1).unwrap_or(TranslationGranule::Granule4KB);

        self.mmu.set_config(MmuConfig {
            enabled,
            pa_size: 48,
            t0sz,
            t1sz,
            tg0: granule0,
            tg1: granule1,
            ttbr0,
            ttbr1,
            mair,
            wxn,
        });
    }

    /// Execute data processing (register) instruction.
    pub(crate) fn exec_dp_reg(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let op1 = (insn >> 28) & 0x1;
        let op2 = (insn >> 21) & 0xF;
        let _op3 = (insn >> 10) & 0x3F;

        if op1 == 0 {
            if (op2 & 0b1000) == 0 {
                // Logical (shifted register)
                return self.exec_logical_shifted(insn);
            } else if (op2 & 1) == 0 || op2 == 0b1001 {
                // Add/sub shifted register uses op2=1xx0; extended register
                // is only op2=1001. The other 1xx1 encodings are unallocated.
                return self.exec_add_sub_shifted_ext(insn);
            }
            return Err(ArmError::UndefinedInstruction(insn));
        } else {
            // op1 = 1
            match op2 {
                0b0000 => {
                    // Add/sub with carry
                    return self.exec_adc_sbc(insn);
                }
                0b0010 => {
                    // Conditional compare (register)
                    return self.exec_ccmp_ccmn(insn);
                }
                0b0100 => {
                    // Conditional select
                    return self.exec_csel(insn);
                }
                0b0110 => {
                    if ((insn >> 30) & 1) == 0 {
                        // Data processing (2 source)
                        return self.exec_dp_2src(insn);
                    }
                    // Data processing (1 source)
                    return self.exec_dp_1src(insn);
                }
                _ if (op2 & 0b1000) != 0 => {
                    // Data processing (3 source)
                    return self.exec_dp_3src(insn);
                }
                _ => {}
            }
        }

        Err(ArmError::UndefinedInstruction(insn))
    }

    pub(crate) fn exec_msr_mrs(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let l = (insn >> 21) & 1; // 0 = MSR, 1 = MRS
        let o0 = ((insn >> 19) & 0x1) as u8 + 2;
        let op1 = ((insn >> 16) & 0x7) as u8;
        let crn = ((insn >> 12) & 0xF) as u8;
        let crm = ((insn >> 8) & 0xF) as u8;
        let op2 = ((insn >> 5) & 0x7) as u8;
        let rt = (insn & 0x1F) as u8;

        let encoding = Aarch64SysRegEncoding::new(o0, op1, crn, crm, op2);

        if l != 0 {
            // MRS
            if self.current_el == 0
                && rt != 0
                && matches!(
                    (
                        encoding.op0,
                        encoding.op1,
                        encoding.crn,
                        encoding.crm,
                        encoding.op2
                    ),
                    (2, 3, 0, 1, 0)
                )
            {
                return Err(ArmError::InvalidExceptionLevel(0));
            }
            let value = self.read_sysreg(encoding)?;
            self.set_x(rt, value);
            if matches!(
                (
                    encoding.op0,
                    encoding.op1,
                    encoding.crn,
                    encoding.crm,
                    encoding.op2
                ),
                (3, 3, 2, 4, 0) | (3, 3, 2, 4, 1)
            ) {
                self.set_nzcv(false, value == 0, false, false);
            }
        } else {
            // MSR
            let value = self.get_x(rt);
            self.write_sysreg(encoding, value)?;
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_br_reg(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let opc = (insn >> 21) & 0xF;
        let op2 = (insn >> 16) & 0x1F;
        let op3 = (insn >> 10) & 0x3F;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let op4 = insn & 0x1F;

        if op2 != 0x1F {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        // FEAT_PAuth forms: op3 = 00001M selects key A (M=0) or B (M=1).
        if op3 & 0b111110 == 0b000010 {
            return self.exec_br_reg_pauth(insn, opc, rn, op4 as u8);
        }
        if op3 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let target = self.get_x(rn);

        match (opc, op4) {
            (0b0000, 0) => {
                // BR
                self.pc = target;
                self.btype = 0b01;
            }
            (0b0001, 0) => {
                // BLR
                self.set_x(30, self.pc);
                self.pc = target;
                self.btype = 0b10;
            }
            (0b0010, 0) => {
                // RET
                self.pc = target;
            }
            (0b0100, 0) => {
                // ERET
                if self.current_el == 0 {
                    return Err(ArmError::InvalidExceptionLevel(0));
                }
                return self.exception_return();
            }
            (0b0101, 0) => {
                // DRPS: debug restore process state. Outside real debug state
                // this behaves as a NOP in our privileged model, but EL0 must
                // not execute it.
                if self.current_el == 0 {
                    return Err(ArmError::InvalidExceptionLevel(0));
                }
                return Ok(CpuExit::Continue);
            }
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        }

        Ok(CpuExit::Continue)
    }

    /// The FEAT_PAuth unconditional branches (register): `BRAA`/`BRAB`
    /// (`opc` 1000, modifier `Xm|SP` in bits[4:0]), `BRAAZ`/`BRABZ` (`opc`
    /// 0000, zero modifier, bits[4:0] = 11111), `BLRAA`/`BLRAB` (1001),
    /// `BLRAAZ`/`BLRABZ` (0001), `RETAA`/`RETAB` (0010, Rn = Rm = 11111,
    /// authenticating X30 with SP), and `ERETAA`/`ERETAB` (0100, EL1 and
    /// above). UNDEFINED without FEAT_PAuth.
    ///
    /// The pointer-authentication algorithm is the implementation's own
    /// (FEAT_PACIMP), one whose PAC field is the pointer's canonical
    /// extension, so `PAC*`/`AUT*` leave a pointer unchanged (see
    /// `exec_dp_1src`); authenticating the target therefore yields `Xn`
    /// itself, and the modifier does not affect the result.
    fn exec_br_reg_pauth(
        &mut self,
        insn: u32,
        opc: u32,
        rn: u8,
        op4: u8,
    ) -> Result<CpuExit, ArmError> {
        if !self.config.features.contains(ArmFeatures::PACA) {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        match opc {
            // BRAAZ/BRABZ, BRAA/BRAB
            0b0000 | 0b1000 => {
                if opc == 0b0000 && op4 != 0b11111 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                self.pc = self.get_x(rn);
                self.btype = 0b01;
            }
            // BLRAAZ/BLRABZ, BLRAA/BLRAB
            0b0001 | 0b1001 => {
                if opc == 0b0001 && op4 != 0b11111 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let target = self.get_x(rn);
                self.set_x(30, self.pc);
                self.pc = target;
                self.btype = 0b10;
            }
            // RETAA/RETAB
            0b0010 => {
                if rn != 0b11111 || op4 != 0b11111 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                self.pc = self.get_x(30);
            }
            // ERETAA/ERETAB
            0b0100 => {
                if rn != 0b11111 || op4 != 0b11111 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                if self.current_el == 0 {
                    return Err(ArmError::InvalidExceptionLevel(0));
                }
                return self.exception_return();
            }
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        }
        Ok(CpuExit::Continue)
    }

    /// Extend register with optional shift.
    pub(crate) fn extend_reg(&self, rm: u8, option: u8, shift: u32) -> Result<u64, ArmError> {
        let val = self.get_x(rm);

        let extended = match option {
            0b000 => (val as u8) as u64,                // UXTB
            0b001 => (val as u16) as u64,               // UXTH
            0b010 => (val as u32) as u64,               // UXTW
            0b011 => val,                               // UXTX
            0b100 => (val as u8 as i8 as i64) as u64,   // SXTB
            0b101 => (val as u16 as i16 as i64) as u64, // SXTH
            0b110 => (val as u32 as i32 as i64) as u64, // SXTW
            0b111 => val,                               // SXTX
            _ => return Err(ArmError::UndefinedInstruction(0)),
        };

        Ok(extended << shift)
    }

    /// Enable/disable JIT of memory-touching regions (Load/Store via helpers).
    /// Off by default (register-only regions); memory ops otherwise bail.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub fn set_jit_mem(&mut self, on: bool) {
        self.jit.mem = on;
    }

    /// Enable/disable the JIT tier for this CPU instance (default enabled).
    /// Disabling forces pure interpretation — used to obtain a differential
    /// oracle without touching the process-global `RAX_NO_JIT`.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub fn set_jit_enabled(&mut self, on: bool) {
        self.jit.disabled = !on;
    }

    /// Run a compiled region over the current state. FP/SIMD regions take the
    /// V-register-marshaling trampoline; integer-only regions the cheaper one.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_run_region(&mut self, region: &JitRegion) {
        let mut gr = self.jit_marshal_to();
        gr.ctx = self as *mut AArch64Cpu as u64; // mutable ctx for the store helper
        if region.uses_fp {
            region
                .exec
                .run_aarch64_identity_fp(region.entry_offset, &mut gr);
        } else {
            region
                .exec
                .run_aarch64_identity(region.entry_offset, &mut gr);
        }
        self.jit_marshal_from(&gr);
    }

    /// Lift+optimize+lower the region at the current PC. `None` if ineligible
    /// (lift/lower failure, no frontier, entry-is-frontier, clobber-unsafe, or
    /// a relocation slipped through).
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_compile_region(&mut self) -> Option<JitRegion> {
        use crate::smir::ir::Terminator;
        use crate::smir::ir::memory::MemoryError;
        use crate::smir::ir::types::SourceArch;
        use crate::smir::lift::aarch64::Aarch64Lifter;
        use crate::smir::lift::{LiftContext, MemoryReader, SmirLifter};
        use crate::smir::lower::SmirLowerer;
        use crate::smir::lower::aarch64::{Aarch64Lowerer, uses_aarch64_fp_trampoline};
        use crate::smir::lower::runtime::{ExecMem, is_aarch64_native_clobber_safe_excluding};
        use crate::smir::optimize::{OptLevel, optimize_function};

        let entry = self.pc;
        const WINDOW: usize = 512;
        let bytes = self.jit_read_window(entry, WINDOW);
        if bytes.len() < 4 {
            return None;
        }

        struct Win {
            base: u64,
            bytes: Vec<u8>,
        }
        impl MemoryReader for Win {
            fn read(&self, addr: u64, size: usize) -> core::result::Result<Vec<u8>, MemoryError> {
                let off = addr
                    .checked_sub(self.base)
                    .filter(|&o| (o as usize) < self.bytes.len())
                    .ok_or(MemoryError::OutOfBounds { addr })? as usize;
                let n = (self.bytes.len() - off).min(size);
                Ok(self.bytes[off..off + n].to_vec())
            }
        }
        let reader = Win { base: entry, bytes };

        let mut lifter = Aarch64Lifter::new();
        let mut lctx = LiftContext::new(SourceArch::Aarch64);
        let mut func = lifter.lift_function(entry, &reader, &mut lctx).ok()?;

        if std::env::var_os("RAX_JIT_NO_OPT").is_none() {
            optimize_function(&mut func, OptLevel::O2);
        }

        // Frontier terminals become native-exit stubs (resume = block start PC);
        // internal Branch/CondBranch edges stay native (loops, if/else).
        let mut exits: std::collections::HashMap<_, u64> = std::collections::HashMap::new();
        for b in &func.blocks {
            let frontier = matches!(
                &b.terminator,
                Terminator::Trap { .. }
                    | Terminator::Return { .. }
                    | Terminator::IndirectBranch { .. }
                    | Terminator::Switch { .. }
                    | Terminator::Call { .. }
                    | Terminator::Unreachable
            );
            if frontier {
                exits.insert(b.id, b.guest_pc);
            }
        }
        // No frontier ⇒ spin loop (never returns); entry itself a frontier ⇒ no
        // native work. Either way, decline.
        if exits.is_empty() || exits.contains_key(&func.entry) {
            return None;
        }

        let allow_mem = self.jit.mem;
        if !is_aarch64_native_clobber_safe_excluding(&func, &exits, allow_mem) {
            return None;
        }

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.set_native_exits(exits);
        lowerer.set_mem_helpers(allow_mem);
        let res = lowerer.lower_function(&func).ok()?;
        if !res.relocations.is_empty() {
            return None; // self-contained regions only (no external fixups)
        }
        let code = lowerer.finalize().ok()?;
        let exec = ExecMem::new(&code).ok()?;

        let uses_fp = uses_aarch64_fp_trampoline(&func);

        Some(JitRegion {
            exec,
            entry_offset: res.entry_offset,
            uses_fp,
        })
    }
}

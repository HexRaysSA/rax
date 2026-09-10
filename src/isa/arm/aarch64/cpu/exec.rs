//! Integer and data-processing instruction execution

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
    /// Create a new AArch64 CPU.
    pub fn new(config: AArch64Config, memory: Box<dyn ArmMemory>) -> Self {
        let gic = config
            .gic_config
            .as_ref()
            .map(|gc| std::sync::Arc::new(std::sync::Mutex::new(Gic::new(gc.clone()))));
        let gic_irq_line = gic
            .as_ref()
            .and_then(|g| g.lock().ok().and_then(|g| g.irq_line(0)));

        Self {
            x: [0; NUM_GPRS],
            sp_el: [0; NUM_ELS],
            pc: 0,

            nzcv: 0,
            daif: 0xF, // All exceptions masked on reset
            current_el: config.initial_el,
            sp_sel: true, // Use SP_ELx on reset
            pan: false,
            uao: false,
            dit: false,
            ssbs: false,
            tco: false,
            btype: 0,
            il: false,
            ss: false,

            v: [0; NUM_SIMD_REGS],
            fpcr: 0,
            fpsr: 0,

            // SVE: Default VL=128 bits (16 bytes)
            sve_vl: 128,
            sve_p: [0; 16],
            sve_ffr: 0,

            sysregs: SystemRegisters::new(),
            mmu: Mmu::new(),
            gic,
            gic_irq_line,
            timer_levels: (false, false),
            last_fault_level: std::sync::atomic::AtomicU8::new(0),
            fault_log_budget: 64,
            pc_ring: [0; 64],
            pc_ring_idx: 0,
            memory,

            insn_count: 0,
            cycle_count: 0,
            #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
            jit: Aarch64JitState::default(),
            halted: false,
            wfi: false,
            wfe: false,
            event_register: false,
            pending_exceptions: Vec::new(),

            breakpoints: HashSet::new(),
            watchpoints: Vec::new(),

            config,
        }
    }

    /// Get current stack pointer.
    pub fn current_sp(&self) -> u64 {
        if self.sp_sel || self.current_el == 0 {
            if self.current_el == 0 {
                self.sp_el[0]
            } else {
                self.sp_el[self.current_el as usize]
            }
        } else {
            self.sp_el[0]
        }
    }

    /// Read a register encoded in the "Xn|SP" slot: index 31 selects the
    /// current stack pointer rather than XZR.
    pub(crate) fn gpr_or_sp(&self, reg: u8) -> u64 {
        if reg == 31 {
            self.current_sp()
        } else {
            self.get_x(reg)
        }
    }

    // =========================================================================
    // Condition Evaluation
    // =========================================================================

    /// Evaluate condition code.
    pub fn condition_holds(&self, cond: u8) -> bool {
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

    /// Convert translation fault to ArmError.
    pub(crate) fn translation_fault_to_error(
        &self,
        fault: TranslationFault,
        is_write: bool,
    ) -> ArmError {
        use crate::isa::arm::aarch64::mmu::TranslationFaultType;

        let fault_type = match fault.fault_type {
            TranslationFaultType::Translation => MemoryFaultType::Translation,
            TranslationFaultType::Permission => MemoryFaultType::Permission,
            TranslationFaultType::Alignment => MemoryFaultType::Alignment,
            TranslationFaultType::AccessFlag => MemoryFaultType::AccessFlag,
            TranslationFaultType::AddressSize => MemoryFaultType::AddressSize,
            TranslationFaultType::ExternalAbort => MemoryFaultType::External,
        };

        self.last_fault_level
            .store(fault.level, std::sync::atomic::Ordering::Relaxed);

        ArmError::MemoryError(MemoryFaultInfo {
            address: fault.va,
            access: if is_write {
                crate::isa::arm::common::cpu::AccessType::Write
            } else {
                crate::isa::arm::common::cpu::AccessType::Read
            },
            fault_type,
            stage2: fault.stage2,
        })
    }

    /// Shared handle to the GIC (for the platform memory bridge to service
    /// distributor/redistributor MMIO).
    pub fn gic_handle(&self) -> Option<std::sync::Arc<std::sync::Mutex<Gic>>> {
        self.gic.clone()
    }

    /// Recently executed PCs, oldest first (boot debugging).
    pub fn recent_pcs(&self) -> Vec<u64> {
        let mut out = Vec::with_capacity(self.pc_ring.len());
        for i in 0..self.pc_ring.len() {
            let pc = self.pc_ring[(self.pc_ring_idx + i) % self.pc_ring.len()];
            if pc != 0 {
                out.push(pc);
            }
        }
        out
    }

    // =========================================================================
    // Instruction Fetch and Execution
    // =========================================================================

    /// Fetch instruction at PC.
    pub(crate) fn fetch_instruction(&self) -> Result<u32, ArmError> {
        let pa = self.translate_address(self.pc, false, true)?;
        self.memory.fetch_u32(pa).map_err(|e| e.into())
    }

    /// Execute one instruction.
    pub(crate) fn execute_instruction(&mut self) -> Result<CpuExit, ArmError> {
        // Fetch instruction
        let insn = self.fetch_instruction()?;

        // Check breakpoint
        if self.breakpoints.contains(&self.pc) {
            return Ok(CpuExit::Breakpoint(self.pc as u32));
        }

        // Save PC and advance
        let old_pc = self.pc;
        self.pc = self.pc.wrapping_add(4);

        // Clear BTYPE (set by branches)
        let old_btype = self.btype;
        self.btype = 0;

        // Execute
        let result = self.decode_and_execute(insn);

        match result {
            Ok(exit) => {
                self.insn_count += 1;
                self.cycle_count += 1;
                Ok(exit)
            }
            Err(e) => {
                // Restore PC on error
                self.pc = old_pc;
                self.btype = old_btype;
                Err(e)
            }
        }
    }

    /// Decode and execute an instruction.
    pub(crate) fn decode_and_execute(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        // Top-level decode by bits [28:25]
        let op0 = (insn >> 25) & 0xF;

        match op0 {
            // Reserved
            0b0000 => Err(ArmError::UndefinedInstruction(insn)),

            // Unallocated
            0b0001 | 0b0011 => Err(ArmError::UndefinedInstruction(insn)),

            // SVE (Scalable Vector Extension)
            0b0010 => self.exec_sve(insn),

            // Data Processing - Immediate
            0b1000 | 0b1001 => self.exec_dp_imm(insn),

            // Branches, Exception Generating, System
            0b1010 | 0b1011 => self.exec_branch_system(insn),

            // Loads and Stores
            0b0100 | 0b0110 | 0b1100 | 0b1110 => self.exec_load_store(insn),

            // Data Processing - Register
            0b0101 | 0b1101 => self.exec_dp_reg(insn),

            // Data Processing - SIMD and FP
            0b0111 | 0b1111 => self.exec_simd_fp(insn),

            _ => Err(ArmError::UndefinedInstruction(insn)),
        }
    }

    /// Check for pending interrupts.
    pub(crate) fn check_pending_interrupts(&mut self) -> Result<Option<CpuExit>, ArmError> {
        // Check GIC for pending interrupt
        if let Some(ref gic) = self.gic {
            let cpu_id = 0; // Assume single core for now

            if gic
                .lock()
                .map(|g| g.pending_interrupt(cpu_id))
                .unwrap_or(false)
            {
                // Check if IRQ is masked
                let irq_masked = (self.daif & 0x2) != 0;

                if !irq_masked {
                    // Determine target EL
                    let target_el = exception_target_el(
                        ExceptionType::Irq,
                        self.current_el,
                        self.sysregs.hcr_el2,
                        self.sysregs.scr_el3,
                    );

                    return Ok(Some(CpuExit::InterruptPending));
                }
            }
        }

        // Check timer interrupts
        if self.sysregs.cntp_interrupt_pending() {
            let irq_masked = (self.daif & 0x2) != 0;
            if !irq_masked {
                return Ok(Some(CpuExit::InterruptPending));
            }
        }

        Ok(None)
    }

    /// Export the backend-agnostic subset of modeled AArch64 system state.
    pub fn export_sregs(&self) -> Aarch64SystemRegisters {
        Aarch64SystemRegisters {
            sctlr_el1: self.sysregs.el1.sctlr,
            tcr_el1: self.sysregs.el1.tcr,
            ttbr0_el1: self.sysregs.el1.ttbr0,
            ttbr1_el1: self.sysregs.el1.ttbr1,
            mair_el1: self.sysregs.el1.mair,
            vbar_el1: self.sysregs.el1.vbar,
            esr_el1: self.sysregs.el1.esr,
            far_el1: self.sysregs.el1.far,
            elr_el1: self.sysregs.el1.elr,
            spsr_el1: self.sysregs.el1.spsr,
            sp_el0: self.sp_el[0],
            sp_el1: self.sp_el[1],
            tpidr_el0: self.sysregs.tpidr_el0,
            tpidr_el1: self.sysregs.el1.tpidr,
            tpidrro_el0: self.sysregs.tpidrro_el0,
            cntp_ctl_el0: self.sysregs.cntp_ctl_el0 & 0x3,
            cntp_cval_el0: self.sysregs.cntp_cval_el0,
            cntv_ctl_el0: self.sysregs.cntv_ctl_el0 & 0x3,
            cntv_cval_el0: self.sysregs.cntv_cval_el0,
        }
    }

    /// Import the backend-agnostic subset of modeled AArch64 system state.
    pub fn import_sregs(&mut self, sregs: &Aarch64SystemRegisters) {
        self.sysregs.el1.sctlr = sregs.sctlr_el1;
        self.sysregs.el1.tcr = sregs.tcr_el1;
        self.sysregs.el1.ttbr0 = sregs.ttbr0_el1;
        self.sysregs.el1.ttbr1 = sregs.ttbr1_el1;
        self.sysregs.el1.mair = sregs.mair_el1;
        self.sysregs.el1.vbar = sregs.vbar_el1;
        self.sysregs.el1.esr = sregs.esr_el1;
        self.sysregs.el1.far = sregs.far_el1;
        self.sysregs.el1.elr = sregs.elr_el1;
        self.sysregs.el1.spsr = sregs.spsr_el1;
        self.sp_el[0] = sregs.sp_el0;
        self.sp_el[1] = sregs.sp_el1;
        self.sysregs.tpidr_el0 = sregs.tpidr_el0;
        self.sysregs.el1.tpidr = sregs.tpidr_el1;
        self.sysregs.tpidrro_el0 = sregs.tpidrro_el0;
        self.sysregs.cntp_ctl_el0 = sregs.cntp_ctl_el0 & 0x3;
        self.sysregs.cntp_cval_el0 = sregs.cntp_cval_el0;
        self.sysregs.cntv_ctl_el0 = sregs.cntv_ctl_el0 & 0x3;
        self.sysregs.cntv_cval_el0 = sregs.cntv_cval_el0;
        self.update_mmu_config();
    }

    // =========================================================================
    // Instruction Execution Stubs
    // =========================================================================

    /// Execute data processing (immediate) instruction.
    pub(crate) fn exec_dp_imm(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let op0 = (insn >> 23) & 0x7;

        match op0 {
            0b000 | 0b001 => self.exec_pc_rel(insn),
            0b010 => self.exec_add_sub_imm(insn),
            0b011 => self.exec_add_sub_imm_tags(insn),
            0b100 => self.exec_logical_imm(insn),
            0b101 => self.exec_move_wide(insn),
            0b110 => self.exec_bitfield(insn),
            0b111 => self.exec_extract(insn),
            _ => Err(ArmError::UndefinedInstruction(insn)),
        }
    }

    pub(crate) fn exec_ordered_unscaled(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let size = (insn >> 30) & 0x3;
        let opc = (insn >> 22) & 0x3;
        let imm9 = (((insn >> 12) & 0x1FF) as i32) << 23 >> 23;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as u8;
        let base = if rn == 31 {
            let sp = self.current_sp();
            if sp & 0xf != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access: if opc == 0 {
                        crate::isa::arm::common::cpu::AccessType::Write
                    } else {
                        crate::isa::arm::common::cpu::AccessType::Read
                    },
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };
        let address = (base as i64).wrapping_add(imm9 as i64) as u64;

        match opc {
            0b00 => match size {
                0 => self.mem_write_u8(address, self.get_w(rt) as u8)?,
                1 => self.mem_write_u16(address, self.get_w(rt) as u16)?,
                2 => self.mem_write_u32(address, self.get_w(rt))?,
                _ => self.mem_write_u64(address, self.get_x(rt))?,
            },
            0b01 => match size {
                0 => self.set_w(rt, self.mem_read_u8(address)? as u32),
                1 => self.set_w(rt, self.mem_read_u16(address)? as u32),
                2 => self.set_w(rt, self.mem_read_u32(address)?),
                _ => self.set_x(rt, self.mem_read_u64(address)?),
            },
            0b10 => match size {
                0 => self.set_x(rt, self.mem_read_u8(address)? as i8 as i64 as u64),
                1 => self.set_x(rt, self.mem_read_u16(address)? as i16 as i64 as u64),
                2 => self.set_x(rt, self.mem_read_u32(address)? as i32 as i64 as u64),
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            },
            0b11 => match size {
                0 => self.set_w(rt, self.mem_read_u8(address)? as i8 as i32 as u32),
                1 => self.set_w(rt, self.mem_read_u16(address)? as i16 as i32 as u32),
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            },
            _ => unreachable!(),
        }
        Ok(CpuExit::Continue)
    }

    /// FMLAL/FMLSL/FMLAL2/FMLSL2 (FEAT_FHM): widening FP16 fused multiply-add.
    /// Each FP32 result lane accumulates the exact product of two FP16 source
    /// lanes. The non-`2` forms take the lower half of the FP16 lanes, the `2`
    /// forms the upper half. `a` (size<1>) selects add vs subtract.
    pub(crate) fn exec_fmlal(&mut self, insn: u32, indexed: bool) -> Result<CpuExit, ArmError> {
        if (insn >> 31) & 1 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let q = (insn >> 30) & 1;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;
        // Vector form: sub=bit23, "2"=U(bit29), Rm=bits[20:16]. Indexed form:
        // sub=bit13, "2"=bit15, Rm=bits[19:16], index=(H:L:M)=bit11:bit21:bit20.
        let (sub, top, rm, index) = if indexed {
            (
                (insn >> 14) & 1 != 0, // FMLSL/FMLSL2 (op[15:12] bit14)
                (insn >> 15) & 1 != 0, // FMLAL2/FMLSL2 (upper FP16 lanes)
                ((insn >> 16) & 0xF) as usize,
                Some(
                    (((insn >> 11) & 1) << 2 | ((insn >> 21) & 1) << 1 | ((insn >> 20) & 1))
                        as usize,
                ),
            )
        } else {
            (
                (insn >> 23) & 1 != 0,
                (insn >> 29) & 1 != 0,
                ((insn >> 16) & 0x1F) as usize,
                None,
            )
        };
        let elements = if q == 1 { 4 } else { 2 };
        let sel = if top { elements } else { 0 }; // "2" forms read the upper FP16 lanes
        let vn = self.v[rn];
        let vm = self.v[rm];
        let vd = self.v[rd];
        let mut result: u128 = 0;
        for e in 0..elements {
            let lane = e + sel;
            // FMLSL negates the multiplicand (FPNeg op1) before the fused MAC.
            let h1 = (vn >> (16 * lane)) as u16;
            let h1 = if sub {
                fp_neg_bits_with_fpcr(h1 as u64, 16, self.fpcr) as u16
            } else {
                h1
            };
            let h2 = match index {
                Some(ix) => (vm >> (16 * ix)) as u16,
                None => (vm >> (16 * lane)) as u16,
            };
            let h1 = fp16_flush_input_with_fpcr(h1, self.fpcr);
            let h2 = fp16_flush_input_with_fpcr(h2, self.fpcr);
            let nn = Self::fp16_to_f32(h1).to_bits();
            let mm = Self::fp16_to_f32(h2).to_bits();
            let acc_raw = (vd >> (32 * e)) as u64;
            let acc = fp_flush_input_bits_with_fpcr(acc_raw, 32, self.fpcr) as u32;
            let ah_nan_result = if self.fpcr & FPCR_AH != 0 && fp16_is_nan(h1) {
                Some(nn | 0x0040_0000)
            } else if self.fpcr & FPCR_AH != 0 && fp16_is_nan(h2) {
                Some(mm | 0x0040_0000)
            } else if self.fpcr & FPCR_AH != 0 && is_nan32(acc) {
                Some(if is_snan32(acc) {
                    acc | 0x0040_0000
                } else {
                    acc
                })
            } else {
                None
            };
            let r = ah_nan_result.unwrap_or_else(|| {
                fp_muladd_bits_with_fpcr(acc as u64, nn as u64, mm as u64, 32, self.fpcr) as u32
            });
            self.fpsr |= fp_status_fma(4, acc as u64, nn as u64, mm as u64, r as u64)
                | if ah_nan_result.is_some() {
                    0
                } else {
                    fp_fz_input_status(4, acc_raw, self.fpcr)
                };
            result |= (r as u128) << (32 * e);
        }
        // Q==0 leaves the upper 64 bits zero.
        self.v[rd] = result;
        Ok(CpuExit::Continue)
    }

    pub(crate) fn fp16_to_f32(h: u16) -> f32 {
        let sign = ((h >> 15) & 1) as u32;
        let exp = ((h >> 10) & 0x1F) as u32;
        let mant = (h & 0x3FF) as u32;

        let f32_bits = if exp == 0 {
            if mant == 0 {
                sign << 31
            } else {
                let mut m = mant;
                let mut e = 0i32;
                while (m & 0x400) == 0 {
                    m <<= 1;
                    e += 1;
                }
                m &= 0x3FF;
                // A binary16 subnormal has value mant*2^-24; once normalised so
                // the implicit 1 sits at bit 10 (after `e` left shifts) the
                // unbiased exponent is -14-e, i.e. biased (127-14-e).
                let new_exp = (127 - 14 - e) as u32;
                (sign << 31) | (new_exp << 23) | (m << 13)
            }
        } else if exp == 0x1F {
            (sign << 31) | (0xFF << 23) | (mant << 13)
        } else {
            let new_exp = exp + 127 - 15;
            (sign << 31) | (new_exp << 23) | (mant << 13)
        };

        f32::from_bits(f32_bits)
    }

    pub(crate) fn f32_to_fp16(f: f32) -> u16 {
        let bits = f.to_bits();
        let sign = ((bits >> 31) & 1) as u16;
        let exp = ((bits >> 23) & 0xFF) as i32;
        let mant = (bits & 0x7FFFFF) as u32;

        if exp == 0xFF {
            if mant == 0 {
                (sign << 15) | (0x1F << 10)
            } else {
                (sign << 15) | (0x1F << 10) | ((mant >> 13) as u16 & 0x3FF).max(1)
            }
        } else {
            // f32 -> f64 is exact, so a single fp16_round is correctly rounded
            // (round-to-nearest-even, with carry into the exponent and the
            // proper overflow/subnormal thresholds). The prior code truncated
            // the mantissa, which lost the rounding bit.
            fp16_round(f as f64)
        }
    }

    // =========================================================================
    // SVE (Scalable Vector Extension) Execution
    // =========================================================================

    /// Execute SVE instruction.
    /// Read SVE predicate register `i` (the low VL/8 bits are meaningful;
    /// 16 bits at VL=128). Exposed for the differential harness.
    pub fn sve_pred(&self, i: usize) -> u32 {
        self.sve_p[i]
    }

    /// Read the SVE first-fault register. Exposed for the differential harness.
    pub fn sve_ffr(&self) -> u32 {
        self.sve_ffr
    }

    // =========================================================================
    // Instruction Implementations (stubs - to be filled in)
    // =========================================================================

    pub(crate) fn exec_pc_rel(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let op = (insn >> 31) & 1;
        let rd = (insn & 0x1F) as u8;
        let immhi = ((insn >> 5) & 0x7FFFF) as i64;
        let immlo = ((insn >> 29) & 0x3) as i64;
        let imm = (immhi << 2) | immlo;
        let imm = (imm << 43) >> 43; // Sign extend from 21 bits

        // PC was already incremented, use the address of this instruction
        let current_pc = self.pc.wrapping_sub(4);

        let result = if op == 0 {
            // ADR
            (current_pc as i64).wrapping_add(imm) as u64
        } else {
            // ADRP
            let base = current_pc & !0xFFF;
            (base as i64).wrapping_add(imm << 12) as u64
        };

        self.set_x(rd, result);
        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_add_sub_imm(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op = (insn >> 30) & 1; // 0=ADD, 1=SUB
        let s = (insn >> 29) & 1; // Set flags
        let sh = (insn >> 22) & 1; // Shift imm by 12
        let imm12 = ((insn >> 10) & 0xFFF) as u64;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        let imm = if sh != 0 { imm12 << 12 } else { imm12 };

        if sf != 0 {
            // 64-bit
            let rn_val = if rn == 31 {
                self.current_sp()
            } else {
                self.get_x(rn)
            };

            let (result, carry, overflow) = if op == 0 {
                let (r, c) = rn_val.overflowing_add(imm);
                let v = (!(rn_val ^ imm) & (rn_val ^ r)) >> 63 != 0;
                (r, c, v)
            } else {
                let (r, c) = rn_val.overflowing_sub(imm);
                let v = ((rn_val ^ imm) & (rn_val ^ r)) >> 63 != 0;
                (r, !c, v)
            };

            if s != 0 {
                self.update_nz_64(result);
                self.set_c(carry);
                self.set_v(overflow);
            }

            if rd == 31 {
                if s == 0 {
                    self.set_current_sp(result);
                }
            } else {
                self.set_x(rd, result);
            }
        } else {
            // 32-bit
            let rn_val = if rn == 31 {
                self.current_sp() as u32
            } else {
                self.get_w(rn)
            };
            let imm = imm as u32;

            let (result, carry, overflow) = if op == 0 {
                let (r, c) = rn_val.overflowing_add(imm);
                let v = (!(rn_val ^ imm) & (rn_val ^ r)) >> 31 != 0;
                (r, c, v)
            } else {
                let (r, c) = rn_val.overflowing_sub(imm);
                let v = ((rn_val ^ imm) & (rn_val ^ r)) >> 31 != 0;
                (r, !c, v)
            };

            if s != 0 {
                self.update_nz_32(result);
                self.set_c(carry);
                self.set_v(overflow);
            }

            if rd == 31 {
                if s == 0 {
                    self.set_current_sp(result as u64);
                }
            } else {
                self.set_w(rd, result);
            }
        }

        Ok(CpuExit::Continue)
    }

    /// Execute Add/Sub Immediate with Tags (ADDG/SUBG - MTE instructions).
    ///
    /// Encoding:
    /// 31:31 sf (must be 1 for 64-bit)
    /// 30:30 op (0=ADD, 1=SUB)
    /// 29:29 S (must be 0)
    /// 28:23 100011
    /// 22:22 o2 (must be 0)
    /// 21:16 uimm6 (offset in 16-byte granules)
    /// 15:14 op3
    /// 13:10 uimm4 (tag offset)
    /// 9:5   Xn (source register)
    /// 4:0   Xd (destination register)
    pub(crate) fn exec_add_sub_imm_tags(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op = (insn >> 30) & 1; // 0=ADDG, 1=SUBG
        let s = (insn >> 29) & 1;
        let o2 = (insn >> 22) & 1;
        let uimm6 = ((insn >> 16) & 0x3F) as u64;
        let uimm4 = ((insn >> 10) & 0xF) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        if sf == 0 || s != 0 || o2 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // TAG_GRANULE is 16 bytes (LOG2_TAG_GRANULE = 4)
        const TAG_GRANULE: u64 = 16;
        let offset = uimm6 * TAG_GRANULE;

        // Get source operand
        let operand1 = if rn == 31 {
            self.current_sp()
        } else {
            self.get_x(rn)
        };

        // Extract the current allocation tag from address bits [59:56]
        let start_tag = ((operand1 >> 56) & 0xF) as u8;

        // Compute new tag (simplified - in full MTE, this uses GCR_EL1.Exclude)
        // The tag is modified by uimm4, wrapping at 16
        let rtag = if self.config.features.has_mte() {
            // MTE enabled - compute new tag
            (start_tag.wrapping_add(uimm4)) & 0xF
        } else {
            // MTE disabled - tag is 0
            0
        };

        // Compute result address
        let result = if op == 0 {
            // ADDG
            operand1.wrapping_add(offset)
        } else {
            // SUBG
            operand1.wrapping_sub(offset)
        };

        // Insert the new allocation tag into the result address
        // Tags are stored in bits [59:56] (top byte, lower nibble)
        let result = (result & !0x0F00_0000_0000_0000u64) | ((rtag as u64) << 56);

        // Write result
        if rd == 31 {
            self.set_current_sp(result);
        } else {
            self.set_x(rd, result);
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_logical_imm(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let opc = (insn >> 29) & 0x3;
        let n = (insn >> 22) & 1;
        let immr = ((insn >> 16) & 0x3F) as u32;
        let imms = ((insn >> 10) & 0x3F) as u32;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        if sf == 0 && n != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // Decode bitmask immediate
        let imm = decode_bitmask(n != 0, imms, immr, sf != 0)?;

        if sf != 0 {
            // 64-bit
            let rn_val = self.get_x(rn);

            let result = match opc {
                0b00 => rn_val & imm, // AND
                0b01 => rn_val | imm, // ORR
                0b10 => rn_val ^ imm, // EOR
                0b11 => rn_val & imm, // ANDS
                _ => unreachable!(),
            };

            if opc == 0b11 {
                self.update_nz_64(result);
                self.set_c(false);
                self.set_v(false);
            }

            if rd == 31 && opc != 0b11 {
                self.set_current_sp(result);
            } else {
                self.set_x(rd, result);
            }
        } else {
            // 32-bit
            let rn_val = self.get_w(rn);
            let imm = imm as u32;

            let result = match opc {
                0b00 => rn_val & imm,
                0b01 => rn_val | imm,
                0b10 => rn_val ^ imm,
                0b11 => rn_val & imm,
                _ => unreachable!(),
            };

            if opc == 0b11 {
                self.update_nz_32(result);
                self.set_c(false);
                self.set_v(false);
            }

            if rd == 31 && opc != 0b11 {
                self.set_current_sp(result as u64);
            } else {
                self.set_w(rd, result);
            }
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_move_wide(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let opc = (insn >> 29) & 0x3;
        let hw = ((insn >> 21) & 0x3) as u32;
        let imm16 = ((insn >> 5) & 0xFFFF) as u64;
        let rd = (insn & 0x1F) as u8;

        if sf == 0 && hw >= 2 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let shift = hw * 16;

        let result = match opc {
            0b00 => {
                // MOVN
                let val = imm16 << shift;
                if sf != 0 { !val } else { (!val) & 0xFFFF_FFFF }
            }
            0b10 => {
                // MOVZ
                imm16 << shift
            }
            0b11 => {
                // MOVK
                let old = if sf != 0 {
                    self.get_x(rd)
                } else {
                    self.get_w(rd) as u64
                };
                let mask = !(0xFFFFu64 << shift);
                (old & mask) | (imm16 << shift)
            }
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        };

        if sf != 0 {
            self.set_x(rd, result);
        } else {
            self.set_w(rd, result as u32);
        }

        Ok(CpuExit::Continue)
    }

    /// Decode addressing mode for load/store. `scale` is the log2 of the access
    /// size in bytes (used to scale the unsigned/register offsets).
    pub(crate) fn decode_address(
        &self,
        insn: u32,
        rn: u8,
        scale: u32,
        access: crate::isa::arm::common::cpu::AccessType,
    ) -> Result<(u64, bool, u64), ArmError> {
        let base = if rn == 31 {
            let sp = self.current_sp();
            if sp & 0xF != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access,
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };

        // Unsigned offset form: selected by bit 24 alone. Bit 21 is the top
        // bit of imm12 here, NOT a mode selector — gating on it sent every
        // access with an offset >= 0x800 << scale down the indexed path,
        // where the imm12 payload was misread as a post-index writeback.
        if (insn >> 24) & 1 != 0 {
            let imm12 = ((insn >> 10) & 0xFFF) as u64;
            let offset = imm12 << scale;
            return Ok((base.wrapping_add(offset), false, 0));
        }

        // Check addressing mode
        let bit21 = (insn >> 21) & 1;
        let op4 = (insn >> 10) & 0x3;

        match op4 {
            0b00 => {
                // Unscaled immediate
                let imm9 = ((insn >> 12) & 0x1FF) as i32;
                let offset = ((imm9 << 23) >> 23) as i64;
                Ok(((base as i64).wrapping_add(offset) as u64, false, 0))
            }
            0b01 => {
                // Immediate post-indexed
                let imm9 = ((insn >> 12) & 0x1FF) as i32;
                let offset = ((imm9 << 23) >> 23) as i64;
                Ok((base, true, (base as i64).wrapping_add(offset) as u64))
            }
            0b10 if bit21 == 0 => {
                // Unprivileged signed immediate offset
                let imm9 = ((insn >> 12) & 0x1FF) as i32;
                let offset = ((imm9 << 23) >> 23) as i64;
                Ok(((base as i64).wrapping_add(offset) as u64, false, 0))
            }
            0b10 => {
                // Register offset
                let rm = ((insn >> 16) & 0x1F) as u8;
                let option = ((insn >> 13) & 0x7) as u8;
                let s = ((insn >> 12) & 1) != 0;

                let offset = self.extend_reg(rm, option, if s { scale } else { 0 })?;
                Ok((base.wrapping_add(offset), false, 0))
            }
            0b11 => {
                // Immediate pre-indexed
                let imm9 = ((insn >> 12) & 0x1FF) as i32;
                let offset = ((imm9 << 23) >> 23) as i64;
                let addr = (base as i64).wrapping_add(offset) as u64;
                Ok((addr, true, addr))
            }
            _ => unreachable!(),
        }
    }

    // Data processing (register) implementations
    pub(crate) fn exec_logical_shifted(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let opc = (insn >> 29) & 0x3;
        let shift = ((insn >> 22) & 0x3) as u32;
        let n = (insn >> 21) & 1;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let imm6 = ((insn >> 10) & 0x3F) as u32;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        // For 32-bit forms a shift amount with bit 5 set is UNDEFINED.
        if sf == 0 && (imm6 & 0x20) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let operand1 = if sf != 0 {
            self.get_x(rn)
        } else {
            self.get_w(rn) as u64
        };

        let mut operand2 = if sf != 0 {
            self.get_x(rm)
        } else {
            self.get_w(rm) as u64
        };

        // Apply shift at the correct datasize (32 or 64 bits).
        operand2 = if sf != 0 {
            match shift {
                0b00 => operand2 << imm6,                   // LSL
                0b01 => operand2 >> imm6,                   // LSR
                0b10 => ((operand2 as i64) >> imm6) as u64, // ASR
                0b11 => operand2.rotate_right(imm6),        // ROR
                _ => unreachable!(),
            }
        } else {
            let v = operand2 as u32;
            (match shift {
                0b00 => v << imm6,                   // LSL
                0b01 => v >> imm6,                   // LSR
                0b10 => ((v as i32) >> imm6) as u32, // ASR
                0b11 => v.rotate_right(imm6),        // ROR
                _ => unreachable!(),
            }) as u64
        };

        if sf == 0 {
            operand2 &= 0xFFFF_FFFF;
        }

        // Invert if N bit set
        if n != 0 {
            operand2 = !operand2;
            if sf == 0 {
                operand2 &= 0xFFFF_FFFF;
            }
        }

        let result = match opc {
            0b00 => operand1 & operand2, // AND / BIC
            0b01 => operand1 | operand2, // ORR / ORN
            0b10 => operand1 ^ operand2, // EOR / EON
            0b11 => operand1 & operand2, // ANDS / BICS
            _ => unreachable!(),
        };

        if opc == 0b11 {
            if sf != 0 {
                self.update_nz_64(result);
            } else {
                self.update_nz_32(result as u32);
            }
            self.set_c(false);
            self.set_v(false);
        }

        if sf != 0 {
            self.set_x(rd, result);
        } else {
            self.set_w(rd, result as u32);
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_add_sub_shifted_ext(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op = (insn >> 30) & 1;
        let s = (insn >> 29) & 1;
        let extended = (insn >> 21) & 1; // bit 21 distinguishes shifted (0) from extended (1)
        let rm = ((insn >> 16) & 0x1F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        if extended == 0 {
            // Shifted register
            let shift = ((insn >> 22) & 0x3) as u32;
            let imm6 = ((insn >> 10) & 0x3F) as u32;

            // ROR is not a valid shift for add/sub, and 32-bit forms with bit 5
            // of the shift amount set are UNDEFINED.
            if shift == 0b11 || (sf == 0 && (imm6 & 0x20) != 0) {
                return Err(ArmError::UndefinedInstruction(insn));
            }

            let operand1 = if sf != 0 {
                self.get_x(rn)
            } else {
                self.get_w(rn) as u64
            };

            let mut operand2 = if sf != 0 {
                self.get_x(rm)
            } else {
                self.get_w(rm) as u64
            };

            operand2 = match shift {
                0b00 => operand2 << imm6,
                0b01 => {
                    if sf != 0 {
                        operand2 >> imm6
                    } else {
                        // 32-bit LSR: shift the 32-bit value, not the zero-extended u64.
                        ((operand2 as u32) >> imm6) as u64
                    }
                }
                0b10 => {
                    if sf != 0 {
                        ((operand2 as i64) >> imm6) as u64
                    } else {
                        // 32-bit ASR: sign-extend from bit 31 before shifting.
                        (((operand2 as u32 as i32 as i64) >> imm6) as u64)
                    }
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };

            if sf == 0 {
                operand2 &= 0xFFFF_FFFF;
            }

            let (result, carry, overflow) = if op == 0 {
                // ADD
                if sf != 0 {
                    let (r, c) = operand1.overflowing_add(operand2);
                    let v = (!(operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                    (r, c, v)
                } else {
                    let o1 = operand1 as u32;
                    let o2 = operand2 as u32;
                    let (r, c) = o1.overflowing_add(o2);
                    let v = (!(o1 ^ o2) & (o1 ^ r)) >> 31 != 0;
                    (r as u64, c, v)
                }
            } else {
                // SUB
                if sf != 0 {
                    let (r, c) = operand1.overflowing_sub(operand2);
                    let v = ((operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                    (r, !c, v)
                } else {
                    let o1 = operand1 as u32;
                    let o2 = operand2 as u32;
                    let (r, c) = o1.overflowing_sub(o2);
                    let v = ((o1 ^ o2) & (o1 ^ r)) >> 31 != 0;
                    (r as u64, !c, v)
                }
            };

            if s != 0 {
                if sf != 0 {
                    self.update_nz_64(result);
                } else {
                    self.update_nz_32(result as u32);
                }
                self.set_c(carry);
                self.set_v(overflow);
            }

            if sf != 0 {
                self.set_x(rd, result);
            } else {
                self.set_w(rd, result as u32);
            }
        } else {
            // Extended register
            let option = ((insn >> 13) & 0x7) as u8;
            let imm3 = ((insn >> 10) & 0x7) as u32;

            if imm3 > 4 {
                return Err(ArmError::UndefinedInstruction(insn));
            }

            let operand2 = self.extend_reg(rm, option, imm3)?;

            let (result, carry, overflow) = if op == 0 {
                if sf != 0 {
                    let operand1 = if rn == 31 {
                        self.current_sp()
                    } else {
                        self.get_x(rn)
                    };
                    let (r, c) = operand1.overflowing_add(operand2);
                    let v = (!(operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                    (r, c, v)
                } else {
                    let operand1 = if rn == 31 {
                        self.current_sp() as u32
                    } else {
                        self.get_w(rn)
                    };
                    let operand2 = operand2 as u32;
                    let (r, c) = operand1.overflowing_add(operand2);
                    let v = (!(operand1 ^ operand2) & (operand1 ^ r)) >> 31 != 0;
                    (r as u64, c, v)
                }
            } else {
                if sf != 0 {
                    let operand1 = if rn == 31 {
                        self.current_sp()
                    } else {
                        self.get_x(rn)
                    };
                    let (r, c) = operand1.overflowing_sub(operand2);
                    let v = ((operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                    (r, !c, v)
                } else {
                    let operand1 = if rn == 31 {
                        self.current_sp() as u32
                    } else {
                        self.get_w(rn)
                    };
                    let operand2 = operand2 as u32;
                    let (r, c) = operand1.overflowing_sub(operand2);
                    let v = ((operand1 ^ operand2) & (operand1 ^ r)) >> 31 != 0;
                    (r as u64, !c, v)
                }
            };

            if s != 0 {
                if sf != 0 {
                    self.update_nz_64(result);
                } else {
                    self.update_nz_32(result as u32);
                }
                self.set_c(carry);
                self.set_v(overflow);
            }

            if rd == 31 && s == 0 {
                self.set_current_sp(result);
            } else if sf != 0 {
                self.set_x(rd, result);
            } else {
                self.set_w(rd, result as u32);
            }
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_adc_sbc(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op = (insn >> 30) & 1;
        let s = (insn >> 29) & 1;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        // RMIF Xn, #imm6, #mask (FEAT_FlagM): rotate Xn right by imm6 and move
        // the low four bits into the NZCV flags selected by mask.
        if sf == 1 && op == 0 && s == 1 && (insn >> 10) & 0x1F == 0b00001 && (insn >> 4) & 1 == 0 {
            let imm6 = (insn >> 15) & 0x3F;
            let mask = insn & 0xF;
            let val = self.get_x(rn).rotate_right(imm6);
            let mut n = self.get_n();
            let mut z = self.get_z();
            let mut c = self.get_c();
            let mut v = self.get_v();
            if mask & 0b1000 != 0 {
                n = (val >> 3) & 1 == 1;
            }
            if mask & 0b0100 != 0 {
                z = (val >> 2) & 1 == 1;
            }
            if mask & 0b0010 != 0 {
                c = (val >> 1) & 1 == 1;
            }
            if mask & 0b0001 != 0 {
                v = val & 1 == 1;
            }
            self.set_nzcv(n, z, c, v);
            return Ok(CpuExit::Continue);
        }

        // SETF8/SETF16 Wn (FEAT_FlagM): set NZV from a narrow value, C
        // unchanged. N = sign bit, Z = narrow value == 0, V = bit(width) XOR
        // bit(width-1).
        if sf == 0
            && op == 0
            && s == 1
            && (insn >> 10) & 0xF == 0b0010
            && (insn >> 15) & 0x3F == 0
            && insn & 0x1F == 0b01101
        {
            let width = if (insn >> 14) & 1 == 1 { 16 } else { 8 };
            let w = self.get_w(rn);
            let n = (w >> (width - 1)) & 1 == 1;
            let z = w & ((1u32 << width) - 1) == 0;
            let v = ((w >> width) & 1) != ((w >> (width - 1)) & 1);
            let c = self.get_c();
            self.set_nzcv(n, z, c, v);
            return Ok(CpuExit::Continue);
        }

        // ADC/ADCS/SBC/SBCS require bits[15:10] == 0; anything else in this
        // space is unallocated.
        if (insn >> 10) & 0x3F != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let c_in = if self.get_c() { 1u64 } else { 0 };

        if sf != 0 {
            let operand1 = self.get_x(rn);
            let operand2 = self.get_x(rm);

            let (result, carry, overflow) = if op == 0 {
                // ADC
                let (r1, c1) = operand1.overflowing_add(operand2);
                let (r, c2) = r1.overflowing_add(c_in);
                let v = (!(operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                (r, c1 || c2, v)
            } else {
                // SBC
                let not_c = if self.get_c() { 0u64 } else { 1 };
                let (r1, c1) = operand1.overflowing_sub(operand2);
                let (r, c2) = r1.overflowing_sub(not_c);
                let v = ((operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                (r, !(c1 || c2), v)
            };

            if s != 0 {
                self.update_nz_64(result);
                self.set_c(carry);
                self.set_v(overflow);
            }

            self.set_x(rd, result);
        } else {
            let operand1 = self.get_w(rn);
            let operand2 = self.get_w(rm);
            let c_in = c_in as u32;

            let (result, carry, overflow) = if op == 0 {
                let (r1, c1) = operand1.overflowing_add(operand2);
                let (r, c2) = r1.overflowing_add(c_in);
                let v = (!(operand1 ^ operand2) & (operand1 ^ r)) >> 31 != 0;
                (r, c1 || c2, v)
            } else {
                let not_c = if self.get_c() { 0u32 } else { 1 };
                let (r1, c1) = operand1.overflowing_sub(operand2);
                let (r, c2) = r1.overflowing_sub(not_c);
                let v = ((operand1 ^ operand2) & (operand1 ^ r)) >> 31 != 0;
                (r, !(c1 || c2), v)
            };

            if s != 0 {
                self.update_nz_32(result);
                self.set_c(carry);
                self.set_v(overflow);
            }

            self.set_w(rd, result);
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_ccmp_ccmn(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op = (insn >> 30) & 1; // 0=CCMN, 1=CCMP
        let imm_or_reg = (insn >> 11) & 1;
        let rm_imm5 = ((insn >> 16) & 0x1F) as u8;
        let cond = ((insn >> 12) & 0xF) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let nzcv = (insn & 0xF) as u8;

        if ((insn >> 29) & 1) == 0 || ((insn >> 10) & 1) != 0 || ((insn >> 4) & 1) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        if self.condition_holds(cond) {
            let operand2 = if imm_or_reg != 0 {
                rm_imm5 as u64
            } else {
                if sf != 0 {
                    self.get_x(rm_imm5)
                } else {
                    self.get_w(rm_imm5) as u64
                }
            };

            if sf != 0 {
                let operand1 = self.get_x(rn);
                let (result, carry, overflow) = if op == 0 {
                    // CCMN (add)
                    let (r, c) = operand1.overflowing_add(operand2);
                    let v = (!(operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                    (r, c, v)
                } else {
                    // CCMP (sub)
                    let (r, c) = operand1.overflowing_sub(operand2);
                    let v = ((operand1 ^ operand2) & (operand1 ^ r)) >> 63 != 0;
                    (r, !c, v)
                };
                self.update_nz_64(result);
                self.set_c(carry);
                self.set_v(overflow);
            } else {
                let operand1 = self.get_w(rn);
                let operand2 = operand2 as u32;
                let (result, carry, overflow) = if op == 0 {
                    let (r, c) = operand1.overflowing_add(operand2);
                    let v = (!(operand1 ^ operand2) & (operand1 ^ r)) >> 31 != 0;
                    (r, c, v)
                } else {
                    let (r, c) = operand1.overflowing_sub(operand2);
                    let v = ((operand1 ^ operand2) & (operand1 ^ r)) >> 31 != 0;
                    (r, !c, v)
                };
                self.update_nz_32(result);
                self.set_c(carry);
                self.set_v(overflow);
            }
        } else {
            self.nzcv = nzcv;
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_csel(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op = (insn >> 30) & 1;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let cond = ((insn >> 12) & 0xF) as u8;
        let op2 = (insn >> 10) & 0x3;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        if ((insn >> 29) & 1) != 0 || (op2 & 0b10) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let cond_met = self.condition_holds(cond);

        if sf != 0 {
            let operand1 = self.get_x(rn);
            let operand2 = self.get_x(rm);

            let result = if cond_met {
                operand1
            } else {
                match (op, op2) {
                    (0, 0) => operand2,                 // CSEL
                    (0, 1) => operand2.wrapping_add(1), // CSINC
                    (1, 0) => !operand2,                // CSINV
                    (1, 1) => operand2.wrapping_neg(),  // CSNEG
                    _ => unreachable!(),
                }
            };

            self.set_x(rd, result);
        } else {
            let operand1 = self.get_w(rn);
            let operand2 = self.get_w(rm);

            let result = if cond_met {
                operand1
            } else {
                match (op, op2) {
                    (0, 0) => operand2,
                    (0, 1) => operand2.wrapping_add(1),
                    (1, 0) => !operand2,
                    (1, 1) => operand2.wrapping_neg(),
                    _ => unreachable!(),
                }
            };

            self.set_w(rd, result);
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_dp_1src(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let s = (insn >> 29) & 1;
        let opcode2 = (insn >> 16) & 0x1F;
        let opcode = (insn >> 10) & 0x3F;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        if s != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // FEAT_PAuth one-source (opcode2 = 00001). No real key schedule:
        // PAC*/AUT* leave the pointer logically intact (authenticate is the
        // inverse of sign), XPAC strips the auth field. The opcode field
        // (bits[15:10]) selects the variant: 0b000xxx take a modifier in Rn,
        // 0b001xxx are the "Z" forms (modifier 0, require Rn=11111), and
        // 0b0100xx are XPACI/XPACD (require Rn=11111).
        if sf == 1 && opcode2 == 0b00001 {
            match opcode {
                // PACIA/IB/DA/DB, AUTIA/IB/DA/DB Xd, Xn|SP
                0b000000..=0b000111 => {
                    let v = self.get_x(rd);
                    self.set_x(rd, v);
                    return Ok(CpuExit::Continue);
                }
                // PACIZA/.../AUTDZB Xd (Rn must be 11111)
                0b001000..=0b001111 => {
                    if rn != 31 {
                        return Ok(CpuExit::Undefined(insn));
                    }
                    let v = self.get_x(rd);
                    self.set_x(rd, v);
                    return Ok(CpuExit::Continue);
                }
                // XPACI / XPACD Xd (Rn must be 11111)
                0b010000 | 0b010001 => {
                    if rn != 31 {
                        return Ok(CpuExit::Undefined(insn));
                    }
                    let v = strip_pac(self.get_x(rd), opcode & 1 != 0);
                    self.set_x(rd, v);
                    return Ok(CpuExit::Continue);
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            }
        } else if opcode2 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        if sf != 0 {
            let operand = self.get_x(rn);
            let result = match opcode {
                0b000000 => operand.reverse_bits(), // RBIT
                0b000001 => {
                    // REV16
                    ((operand & 0x00ff_00ff_00ff_00ff) << 8)
                        | ((operand & 0xff00_ff00_ff00_ff00) >> 8)
                }
                0b000010 => {
                    // REV32
                    ((operand & 0x0000_00ff) << 24)
                        | ((operand & 0x0000_ff00) << 8)
                        | ((operand & 0x00ff_0000) >> 8)
                        | ((operand & 0xff00_0000) >> 24)
                        | ((operand & 0x0000_00ff_0000_0000) << 24)
                        | ((operand & 0x0000_ff00_0000_0000) << 8)
                        | ((operand & 0x00ff_0000_0000_0000) >> 8)
                        | ((operand & 0xff00_0000_0000_0000) >> 24)
                }
                0b000011 => operand.swap_bytes(), // REV
                0b000100 => u64::from(operand.leading_zeros()), // CLZ
                0b000101 => count_leading_sign(operand, 64), // CLS
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            self.set_x(rd, result);
        } else {
            let operand = self.get_w(rn);
            let result = match opcode {
                0b000000 => operand.reverse_bits(), // RBIT
                0b000001 => {
                    // REV16
                    ((operand & 0x00ff_00ff) << 8) | ((operand & 0xff00_ff00) >> 8)
                }
                0b000010 => operand.swap_bytes(),    // REV
                0b000100 => operand.leading_zeros(), // CLZ
                0b000101 => count_leading_sign(u64::from(operand), 32) as u32, // CLS
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            self.set_w(rd, result);
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_dp_2src(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let s = (insn >> 29) & 1;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let opcode = (insn >> 10) & 0x3F;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        // FEAT_MTE / FEAT_PAuth data-processing (2-source). These all require
        // sf=1 (64-bit). The flag-setting SUBPS aside, the rest leave NZCV.
        if sf == 1 {
            match (s, opcode) {
                // SUBP Xd, Xn|SP, Xm|SP — subtract address tags ignored
                // (bits[63:56] of each operand are sign-extended from bit 55).
                (0, 0b000000) => {
                    let a = sign_extend_56(self.gpr_or_sp(rn));
                    let b = sign_extend_56(self.gpr_or_sp(rm));
                    self.set_x(rd, a.wrapping_sub(b));
                    return Ok(CpuExit::Continue);
                }
                // SUBPS Xd, Xn|SP, Xm|SP — as SUBP, sets NZCV.
                (1, 0b000000) => {
                    let a = sign_extend_56(self.gpr_or_sp(rn));
                    let b = sign_extend_56(self.gpr_or_sp(rm));
                    let (res, n, z, c, v) = sub_with_flags_64(a, b);
                    self.set_nzcv(n, z, c, v);
                    self.set_x(rd, res);
                    return Ok(CpuExit::Continue);
                }
                // IRG Xd|SP, Xn|SP, Xm — insert random (here: deterministic 0)
                // tag, honouring nothing in GCR_EL1. Tag bits are [59:56].
                (0, 0b000100) => {
                    let v = self.gpr_or_sp(rn) & !(0xFu64 << 56);
                    self.set_gpr_or_sp(rd, v);
                    return Ok(CpuExit::Continue);
                }
                // GMI Xd, Xn|SP, Xm — tag mask insert: Xd = Xm | (1 << tag(Xn)).
                (0, 0b000101) => {
                    let tag = (self.gpr_or_sp(rn) >> 56) & 0xF;
                    self.set_x(rd, self.get_x(rm) | (1u64 << tag));
                    return Ok(CpuExit::Continue);
                }
                // PACGA Xd, Xn, Xm|SP — generic pointer-auth MAC in bits[63:32].
                // No real key schedule; produce a deterministic non-zero MAC so
                // the destination is written.
                (0, 0b001100) => {
                    let mac = pacga_stub(self.get_x(rn), self.gpr_or_sp(rm));
                    self.set_x(rd, mac);
                    return Ok(CpuExit::Continue);
                }
                _ => {}
            }
        }

        if s != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        if sf != 0 {
            let operand1 = self.get_x(rn);
            let operand2 = self.get_x(rm);

            let result = match opcode {
                0b000010 => {
                    // UDIV
                    if operand2 == 0 {
                        0
                    } else {
                        operand1 / operand2
                    }
                }
                0b000011 => {
                    // SDIV
                    if operand2 == 0 {
                        0
                    } else {
                        (operand1 as i64).wrapping_div(operand2 as i64) as u64
                    }
                }
                0b001000 => {
                    // LSLV
                    let shift = (operand2 & 0x3F) as u32;
                    operand1 << shift
                }
                0b001001 => {
                    // LSRV
                    let shift = (operand2 & 0x3F) as u32;
                    operand1 >> shift
                }
                0b001010 => {
                    // ASRV
                    let shift = (operand2 & 0x3F) as u32;
                    ((operand1 as i64) >> shift) as u64
                }
                0b001011 => {
                    // RORV
                    let shift = (operand2 & 0x3F) as u32;
                    operand1.rotate_right(shift)
                }
                0b010000 => {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                0b010001 => {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                0b010010 => {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                0b010011 => {
                    // CRC32X
                    crc32(self.get_w(rn) as u64, operand2, 64)
                }
                0b010100 => {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                0b010101 => {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                0b010110 => {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                0b010111 => {
                    // CRC32CX
                    crc32c(self.get_w(rn) as u64, operand2, 64)
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };

            self.set_x(rd, result);
        } else {
            let operand1 = self.get_w(rn);
            let operand2 = self.get_w(rm);

            let result = match opcode {
                0b000010 => {
                    // UDIV
                    if operand2 == 0 {
                        0
                    } else {
                        operand1 / operand2
                    }
                }
                0b000011 => {
                    // SDIV
                    if operand2 == 0 {
                        0
                    } else {
                        (operand1 as i32).wrapping_div(operand2 as i32) as u32
                    }
                }
                0b001000 => {
                    // LSLV
                    let shift = (operand2 & 0x1F) as u32;
                    operand1 << shift
                }
                0b001001 => {
                    // LSRV
                    let shift = (operand2 & 0x1F) as u32;
                    operand1 >> shift
                }
                0b001010 => {
                    // ASRV
                    let shift = (operand2 & 0x1F) as u32;
                    ((operand1 as i32) >> shift) as u32
                }
                0b001011 => {
                    // RORV
                    let shift = (operand2 & 0x1F) as u32;
                    operand1.rotate_right(shift)
                }
                0b010000 => {
                    // CRC32B
                    crc32(operand1 as u64, operand2 as u8 as u64, 8) as u32
                }
                0b010001 => {
                    // CRC32H
                    crc32(operand1 as u64, operand2 as u16 as u64, 16) as u32
                }
                0b010010 => {
                    // CRC32W
                    crc32(operand1 as u64, operand2 as u64, 32) as u32
                }
                0b010100 => {
                    // CRC32CB
                    crc32c(operand1 as u64, operand2 as u8 as u64, 8) as u32
                }
                0b010101 => {
                    // CRC32CH
                    crc32c(operand1 as u64, operand2 as u16 as u64, 16) as u32
                }
                0b010110 => {
                    // CRC32CW
                    crc32c(operand1 as u64, operand2 as u64, 32) as u32
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };

            self.set_w(rd, result);
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_dp_3src(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op54 = (insn >> 29) & 0x3;
        let op31 = (insn >> 21) & 0x7;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let o0 = (insn >> 15) & 1;
        let ra = ((insn >> 10) & 0x1F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        if op54 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        if sf != 0 {
            // 64-bit
            let operand1 = self.get_x(rn);
            let operand2 = self.get_x(rm);
            let addend = self.get_x(ra);

            let result = match (op31, o0) {
                (0b000, 0) => {
                    // MADD
                    addend.wrapping_add(operand1.wrapping_mul(operand2))
                }
                (0b000, 1) => {
                    // MSUB
                    addend.wrapping_sub(operand1.wrapping_mul(operand2))
                }
                (0b001, 0) => {
                    // SMADDL
                    let p = (operand1 as i32 as i64).wrapping_mul(operand2 as i32 as i64);
                    (addend as i64).wrapping_add(p) as u64
                }
                (0b001, 1) => {
                    // SMSUBL
                    let p = (operand1 as i32 as i64).wrapping_mul(operand2 as i32 as i64);
                    (addend as i64).wrapping_sub(p) as u64
                }
                (0b010, 0) => {
                    // SMULH
                    let a = operand1 as i64 as i128;
                    let b = operand2 as i64 as i128;
                    ((a * b) >> 64) as u64
                }
                (0b101, 0) => {
                    // UMADDL
                    let p = (operand1 as u32 as u64).wrapping_mul(operand2 as u32 as u64);
                    addend.wrapping_add(p)
                }
                (0b101, 1) => {
                    // UMSUBL
                    let p = (operand1 as u32 as u64).wrapping_mul(operand2 as u32 as u64);
                    addend.wrapping_sub(p)
                }
                (0b110, 0) => {
                    // UMULH
                    let a = operand1 as u128;
                    let b = operand2 as u128;
                    ((a * b) >> 64) as u64
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };

            self.set_x(rd, result);
        } else {
            // 32-bit
            let operand1 = self.get_w(rn);
            let operand2 = self.get_w(rm);
            let addend = self.get_w(ra);

            let result = match (op31, o0) {
                (0b000, 0) => {
                    // MADD
                    addend.wrapping_add(operand1.wrapping_mul(operand2))
                }
                (0b000, 1) => {
                    // MSUB
                    addend.wrapping_sub(operand1.wrapping_mul(operand2))
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };

            self.set_w(rd, result);
        }

        Ok(CpuExit::Continue)
    }
}

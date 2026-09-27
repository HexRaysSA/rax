//! Load/store, exclusive, atomic, and address-translation execution

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
    // Memory Access
    // =========================================================================

    /// Read byte from memory (with MMU translation).
    pub fn mem_read_u8(&self, va: u64) -> Result<u8, ArmError> {
        let pa = self.translate_address(va, false, false)?;
        self.memory.read_u8(pa).map_err(|e| e.into())
    }

    /// Read halfword from memory.
    pub fn mem_read_u16(&self, va: u64) -> Result<u16, ArmError> {
        let pa = self.translate_address(va, false, false)?;
        self.memory.read_u16(pa).map_err(|e| e.into())
    }

    /// Read word from memory.
    pub fn mem_read_u32(&self, va: u64) -> Result<u32, ArmError> {
        let pa = self.translate_address(va, false, false)?;
        self.memory.read_u32(pa).map_err(|e| e.into())
    }

    /// Read doubleword from memory.
    pub fn mem_read_u64(&self, va: u64) -> Result<u64, ArmError> {
        let pa = self.translate_address(va, false, false)?;
        self.memory.read_u64(pa).map_err(|e| e.into())
    }

    /// Write byte to memory.
    pub fn mem_write_u8(&mut self, va: u64, value: u8) -> Result<(), ArmError> {
        let pa = self.translate_address(va, true, false)?;
        self.memory
            .write_u8(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    /// Write halfword to memory.
    pub fn mem_write_u16(&mut self, va: u64, value: u16) -> Result<(), ArmError> {
        let pa = self.translate_address(va, true, false)?;
        self.memory
            .write_u16(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    /// Write word to memory.
    pub fn mem_write_u32(&mut self, va: u64, value: u32) -> Result<(), ArmError> {
        let pa = self.translate_address(va, true, false)?;
        self.memory
            .write_u32(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    /// Write doubleword to memory.
    pub fn mem_write_u64(&mut self, va: u64, value: u64) -> Result<(), ArmError> {
        let pa = self.translate_address(va, true, false)?;
        self.memory
            .write_u64(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    /// Translate virtual address to physical address, using the privilege level
    /// implied by the current EL (EL0 ⇒ unprivileged, EL1+ ⇒ privileged).
    pub(crate) fn translate_address(
        &self,
        va: u64,
        is_write: bool,
        is_execute: bool,
    ) -> Result<u64, ArmError> {
        self.translate_address_at(va, is_write, is_execute, self.current_el > 0)
    }

    /// Translate as an unprivileged access. PSTATE.UAO lets EL1+ unprivileged
    /// load/store instructions use privileged permissions instead.
    /// Used by LDTR/STTR and the FEAT_LRCPC3 unprivileged pairs
    /// LDTP/STTP/LDTNP/STTNP. (#39)
    pub(crate) fn translate_address_unprivileged(
        &self,
        va: u64,
        is_write: bool,
        is_execute: bool,
    ) -> Result<u64, ArmError> {
        self.translate_address_at(
            va,
            is_write,
            is_execute,
            self.current_el > 0 && self.uao && self.has_uao_ext(),
        )
    }

    pub(crate) fn translate_address_at(
        &self,
        va: u64,
        is_write: bool,
        is_execute: bool,
        privileged: bool,
    ) -> Result<u64, ArmError> {
        // Check alignment for execute
        if is_execute && (va & 3) != 0 {
            return Err(ArmError::MemoryError(MemoryFaultInfo {
                address: va,
                access: if is_write {
                    crate::isa::arm::common::cpu::AccessType::Write
                } else if is_execute {
                    crate::isa::arm::common::cpu::AccessType::InstructionFetch
                } else {
                    crate::isa::arm::common::cpu::AccessType::Read
                },
                fault_type: MemoryFaultType::Alignment,
                stage2: false,
            }));
        }

        // Use MMU if enabled
        match self.mmu.translate(
            va,
            self.memory.as_ref(),
            is_write,
            is_execute,
            privileged,
            self.current_el,
        ) {
            Ok(desc) => Ok(desc.pa),
            Err(fault) => Err(self.translation_fault_to_error(fault, is_write)),
        }
    }

    /// Read a doubleword through unprivileged access translation. See
    /// [`Self::translate_address_unprivileged`]. (#39)
    pub(crate) fn mem_read_u64_unprivileged(&self, va: u64) -> Result<u64, ArmError> {
        let pa = self.translate_address_unprivileged(va, false, false)?;
        self.memory.read_u64(pa).map_err(|e| e.into())
    }

    pub(crate) fn mem_read_u8_unprivileged(&self, va: u64) -> Result<u8, ArmError> {
        let pa = self.translate_address_unprivileged(va, false, false)?;
        self.memory.read_u8(pa).map_err(|e| e.into())
    }

    pub(crate) fn mem_read_u16_unprivileged(&self, va: u64) -> Result<u16, ArmError> {
        let pa = self.translate_address_unprivileged(va, false, false)?;
        self.memory.read_u16(pa).map_err(|e| e.into())
    }

    pub(crate) fn mem_read_u32_unprivileged(&self, va: u64) -> Result<u32, ArmError> {
        let pa = self.translate_address_unprivileged(va, false, false)?;
        self.memory.read_u32(pa).map_err(|e| e.into())
    }

    /// Write a doubleword through unprivileged access translation. See
    /// [`Self::translate_address_unprivileged`]. (#39)
    pub(crate) fn mem_write_u64_unprivileged(
        &mut self,
        va: u64,
        value: u64,
    ) -> Result<(), ArmError> {
        let pa = self.translate_address_unprivileged(va, true, false)?;
        self.memory
            .write_u64(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    pub(crate) fn mem_write_u8_unprivileged(&mut self, va: u64, value: u8) -> Result<(), ArmError> {
        let pa = self.translate_address_unprivileged(va, true, false)?;
        self.memory
            .write_u8(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    pub(crate) fn mem_write_u16_unprivileged(
        &mut self,
        va: u64,
        value: u16,
    ) -> Result<(), ArmError> {
        let pa = self.translate_address_unprivileged(va, true, false)?;
        self.memory
            .write_u16(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    pub(crate) fn mem_write_u32_unprivileged(
        &mut self,
        va: u64,
        value: u32,
    ) -> Result<(), ArmError> {
        let pa = self.translate_address_unprivileged(va, true, false)?;
        self.memory
            .write_u32(pa, value)
            .map_err(|e| -> ArmError { e.into() })?;
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_note_write(va);
        Ok(())
    }

    /// Execute load/store instruction.
    pub(crate) fn exec_load_store(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        // SIMD&FP register load/stores (V=1, bit 26) respect the CPACR FP
        // trap: lazy FP context switching depends on the first FP touch
        // (including vector loads in memcpy) trapping.
        if (insn >> 26) & 1 != 0 {
            let fpen = (self.sysregs.el1.cpacr >> 20) & 0x3;
            if (self.current_el == 0 && fpen != 0x3) || (self.current_el == 1 && (fpen & 1) == 0) {
                return self.take_fp_access_trap();
            }
        }

        // Advanced SIMD load/store multiple structures (LD1-4 / ST1-4).
        // bits[31]=0, bits[29:24] = 001100 (no-offset or post-index variant).
        if (insn >> 31) & 1 == 0 && (insn >> 24) & 0x3F == 0b001100 {
            return self.exec_ldst_structures(insn);
        }
        // Advanced SIMD load/store single structure (LD1-4 element, LD1R-LD4R).
        if (insn >> 31) & 1 == 0 && (insn >> 24) & 0x3F == 0b001101 {
            return self.exec_ldst_single(insn);
        }

        let op0 = (insn >> 28) & 0xF;
        let op1 = (insn >> 26) & 0x1;
        let bits_29_27 = (insn >> 27) & 0x7;
        let bit_24 = (insn >> 24) & 0x1;

        // Load/store exclusive: bits[29:27] = 00x, bit[24] = 0
        if bits_29_27 & 0b110 == 0b000 && bit_24 == 0 && op1 == 0 {
            return self.exec_ldst_exclusive(insn);
        }

        // FEAT_LRCPC3 ordered unscaled load/stores: STLUR* / LDAPUR*.
        // These share top-byte space with MTE's 0xD9 encodings, so route the
        // even bits[23:21] ordered forms before the MTE tag handler below.
        if bits_29_27 == 0b011
            && bit_24 == 1
            && op1 == 0
            && matches!((insn >> 21) & 0x7, 0 | 2 | 4 | 6)
        {
            return self.exec_ordered_unscaled(insn);
        }

        // FEAT_MTE tag load/stores: bits[31:24] = 0xD9. Without tag-capable
        // memory the tag side is a no-op, but the architected data side-
        // effects (granule zeroing, writeback, LDG's register write) are
        // honoured. The 16-byte tag granule is TG.
        if (insn >> 24) & 0xFF == 0xD9 {
            const TG: u64 = 16;
            let opc = (insn >> 22) & 0x3;
            let imm9 = (((insn >> 12) & 0x1FF) as i32) << 23 >> 23;
            let op2 = (insn >> 10) & 0x3;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let rt = (insn & 0x1F) as u8;
            let base = if rn == 31 {
                let sp = self.current_sp();
                if sp & 0xF != 0 {
                    return Err(ArmError::MemoryError(MemoryFaultInfo {
                        address: sp,
                        access: if op2 == 0b00 && (opc == 0b01 || opc == 0b11) {
                            crate::isa::arm::common::cpu::AccessType::Read
                        } else {
                            crate::isa::arm::common::cpu::AccessType::Write
                        },
                        fault_type: MemoryFaultType::Alignment,
                        stage2: false,
                    }));
                }
                sp
            } else {
                self.get_x(rn)
            };
            let off = (imm9 as i64).wrapping_mul(TG as i64);

            // MCSETTAGARRAY/MCGETTAGARRAY use implementation-defined array
            // chunking. In the flat tagless memory model, process one aligned
            // tag granule: writes only advance the base, reads return zero tag
            // data and advance the base unless writeback overlaps the target.
            if op2 == 0b00 && imm9 == 0 && ((insn >> 10) & 0xfff) == 0x800 {
                match opc {
                    0b10 => {
                        let addr = base & !(TG - 1);
                        self.set_gpr_or_sp(rn, addr.wrapping_add(TG));
                        return Ok(CpuExit::Continue);
                    }
                    0b11 => {
                        if rt != 31 {
                            self.set_x(rt, 0);
                        }
                        if rn != rt {
                            let addr = base & !(TG - 1);
                            self.set_gpr_or_sp(rn, addr.wrapping_add(TG));
                        }
                        return Ok(CpuExit::Continue);
                    }
                    _ => {}
                }
            }

            // op2==00 contains LDG and unallocated zeroing/bulk tag forms.
            if op2 == 0b00 {
                if opc != 0b01 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                // LDG Xt, [Xn, #imm]: load the allocation tag for the
                // address into Xt's tag field. No tag memory: tag 0.
                let v = self.get_x(rt) & !(0xFu64 << 56);
                self.set_x(rt, v);
                return Ok(CpuExit::Continue);
            }

            // Indexed forms: op2 01=post-index, 10=signed-offset, 11=pre-index.
            let addr = if op2 == 0b01 {
                base
            } else {
                (base as i64).wrapping_add(off) as u64
            } & !(TG - 1);
            // STG (00) / ST2G (10): tag-only stores, no data effect.
            // STZG (01) / STZ2G (11): also zero the granule(s).
            if opc == 0b01 || opc == 0b11 {
                let granules = if opc == 0b11 { 2 } else { 1 };
                for g in 0..granules {
                    for o in (0..TG).step_by(8) {
                        self.mem_write_u64(addr + g * TG + o, 0)?;
                    }
                }
            }
            if op2 == 0b01 || op2 == 0b11 {
                let nb = (base as i64).wrapping_add(off) as u64;
                self.set_gpr_or_sp(rn, nb);
            }
            return Ok(CpuExit::Continue);
        }

        // Load register (literal), integer and SIMD&FP forms:
        // bits[29:27] = 01x, bits[25:24] = 00.
        if bits_29_27 & 0b110 == 0b010 && (insn >> 24) & 0x3 == 0 {
            return self.exec_ldr_literal(insn);
        }

        // Load/store pair: bits[29:27] = 10x (post-index, offset, pre-index)
        // bit[28] = 0 distinguishes pair from single register
        if bits_29_27 & 0b110 == 0b100 {
            return self.exec_ldst_pair(insn);
        }

        // Load/store single register: bits[29:27] = 11x
        if bits_29_27 & 0b110 == 0b110 {
            return self.exec_ldst_reg(insn);
        }

        // Fallback to single register for any remaining cases
        self.exec_ldst_reg(insn)
    }

    // Load/Store implementations
    /// Execute Load/Store Exclusive instructions (LDXR, STXR, LDAXR, STLXR, etc.)
    ///
    /// Encoding (from ASL):
    /// 31:30 size (00=8-bit, 01=16-bit, 10=32-bit, 11=64-bit)
    /// 29:24 001000
    /// 23:23 o2 (pair indicator)
    /// 22:22 L (0=store, 1=load)
    /// 21:21 o1
    /// 20:16 Rs (status register for store)
    /// 15:15 o0 (1=acquire/release semantics)
    /// 14:10 Rt2 (for pair)
    /// 9:5   Rn (base register)
    /// 4:0   Rt (data register)
    pub(crate) fn exec_ldst_exclusive(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let size = (insn >> 30) & 0x3;
        let o2 = (insn >> 23) & 0x1; // 1 = pair
        let l = (insn >> 22) & 0x1; // 1 = load, 0 = store
        let o1 = (insn >> 21) & 0x1;
        let rs = ((insn >> 16) & 0x1F) as u8;
        let o0 = (insn >> 15) & 0x1; // 1 = acquire/release
        let rt2 = ((insn >> 10) & 0x1F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as u8;

        // CAS/CASA/CASL/CASAL (FEAT_LSE): o2==1 (bit23) and o1==1 (bit21).
        // A single compare-and-swap RMW (no exclusive monitor needed).
        if o2 == 1 && o1 == 1 {
            if rt2 != 31 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let bits = 8u32 << size;
            let m = elem_mask(bits);
            let addr = if rn == 31 {
                let sp = self.current_sp();
                if sp & 0xF != 0 {
                    return Err(ArmError::MemoryError(MemoryFaultInfo {
                        address: sp,
                        access: crate::isa::arm::common::cpu::AccessType::Write,
                        fault_type: MemoryFaultType::Alignment,
                        stage2: false,
                    }));
                }
                sp
            } else {
                self.get_x(rn)
            };
            let old = match size {
                0 => self.mem_read_u8(addr)? as u64,
                1 => self.mem_read_u16(addr)? as u64,
                2 => self.mem_read_u32(addr)? as u64,
                _ => self.mem_read_u64(addr)?,
            };
            let compare = self.get_x(rs) & m;
            if (old & m) == compare {
                let newval = self.get_x(rt) & m;
                match size {
                    0 => self.mem_write_u8(addr, newval as u8)?,
                    1 => self.mem_write_u16(addr, newval as u16)?,
                    2 => self.mem_write_u32(addr, newval as u32)?,
                    _ => self.mem_write_u64(addr, newval)?,
                }
            }
            if size == 3 {
                self.set_x(rs, old);
            } else {
                self.set_w(rs, old as u32);
            }
            return Ok(CpuExit::Continue);
        }

        // CASP/CASPA/CASPL/CASPAL (FEAT_LSE): compare-and-swap pair.
        // Encoding: 0 sz 001000 0 L 1 Rs o0 11111 Rn Rt (bit31==0, o2==0, o1==1).
        // sz==0 -> 32-bit pair, sz==1 -> 64-bit pair. Rs/Rt must be even.
        if o2 == 0 && o1 == 1 && (insn >> 31) & 1 == 0 {
            if rt2 != 31 || rs == 31 || rt == 31 || (rs & 1) != 0 || (rt & 1) != 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let sz = (insn >> 30) & 1; // 0 = 32-bit pair, 1 = 64-bit pair
            let addr = if rn == 31 {
                let sp = self.current_sp();
                if sp & 0xF != 0 {
                    return Err(ArmError::MemoryError(MemoryFaultInfo {
                        address: sp,
                        access: crate::isa::arm::common::cpu::AccessType::Write,
                        fault_type: MemoryFaultType::Alignment,
                        stage2: false,
                    }));
                }
                sp
            } else {
                self.get_x(rn)
            };
            if sz == 1 && (addr & 0xF) != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: addr,
                    access: crate::isa::arm::common::cpu::AccessType::Write,
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            let s = rs as usize;
            let t = rt as usize;
            if sz == 0 {
                // 32-bit pair: low element at addr, high element at addr+4.
                let hi_addr = addr.wrapping_add(4);
                let lo = self.mem_read_u32(addr)?;
                let hi = self.mem_read_u32(hi_addr)?;
                let s1 = self.get_x(rs) as u32; // compare low
                let s2 = self.get_x((s + 1) as u8) as u32; // compare high
                if lo == s1 && hi == s2 {
                    let t1 = self.get_x(rt) as u32;
                    let t2 = self.get_x((t + 1) as u8) as u32;
                    self.mem_write_u32(addr, t1)?;
                    self.mem_write_u32(hi_addr, t2)?;
                }
                self.set_w(rs, lo);
                self.set_w((s + 1) as u8, hi);
            } else {
                // 64-bit pair: low element at addr, high element at addr+8.
                let hi_addr = addr.wrapping_add(8);
                let lo = self.mem_read_u64(addr)?;
                let hi = self.mem_read_u64(hi_addr)?;
                let s1 = self.get_x(rs);
                let s2 = self.get_x((s + 1) as u8);
                if lo == s1 && hi == s2 {
                    let t1 = self.get_x(rt);
                    let t2 = self.get_x((t + 1) as u8);
                    self.mem_write_u64(addr, t1)?;
                    self.mem_write_u64(hi_addr, t2)?;
                }
                self.set_x(rs, lo);
                self.set_x((s + 1) as u8, hi);
            }
            return Ok(CpuExit::Continue);
        }

        // LDAR/STLR (and the LDARB/LDARH/STLRB/STLRH byte/halfword forms,
        // plus the LDLAR/STLLR LORegion variants): ordered but NOT exclusive
        // — plain accesses with acquire/release semantics. The Rs/Rt2 fields
        // are ignored here and must not create a status/pair operand or consult
        // the exclusive monitor: a spin-unlock's STLRB would otherwise be
        // silently dropped.
        if o2 == 1 && o1 == 0 {
            let address = if rn == 31 {
                let sp = self.current_sp();
                if sp & 0xF != 0 {
                    return Err(ArmError::MemoryError(MemoryFaultInfo {
                        address: sp,
                        access: if l == 1 {
                            crate::isa::arm::common::cpu::AccessType::Read
                        } else {
                            crate::isa::arm::common::cpu::AccessType::Write
                        },
                        fault_type: MemoryFaultType::Alignment,
                        stage2: false,
                    }));
                }
                sp
            } else {
                self.get_x(rn)
            };
            let pa = self.translate_address(address, l == 0, false)?;
            if l == 1 {
                match size {
                    0 => {
                        let val = self.memory.read_u8(pa)?;
                        self.set_w(rt, val as u32);
                    }
                    1 => {
                        let val = self.memory.read_u16(pa)?;
                        self.set_w(rt, val as u32);
                    }
                    2 => {
                        let val = self.memory.read_u32(pa)?;
                        self.set_w(rt, val);
                    }
                    _ => {
                        let val = self.memory.read_u64(pa)?;
                        self.set_x(rt, val);
                    }
                }
            } else {
                let val = if rt == 31 { 0 } else { self.get_x(rt) };
                match size {
                    0 => self.memory.write_u8(pa, val as u8)?,
                    1 => self.memory.write_u16(pa, val as u16)?,
                    2 => self.memory.write_u32(pa, val as u32)?,
                    _ => self.memory.write_u64(pa, val)?,
                }
            }
            return Ok(CpuExit::Continue);
        }

        // Pair exclusive ops (LDXP/STXP/LDAXP/STLXP) are flagged by o1 (bit21);
        // single LDXR/STXR have o1==0.
        let is_pair = o1 == 1;
        let is_load = l == 1;
        let is_ordered = o0 == 1; // acquire/release semantics (LDAXR/STLXR)

        // Element size in bytes
        let elsize = 1usize << size; // 1, 2, 4, or 8 bytes
        let datasize = if is_pair { elsize * 2 } else { elsize };

        // Get address from base register
        let address = if rn == 31 {
            // SP - check alignment
            let sp = self.current_sp();
            // SP must be aligned to 16 bytes for stack access
            if sp & 0xF != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access: crate::isa::arm::common::cpu::AccessType::Read,
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };

        // Translate address (for physical memory access)
        let pa = self.translate_address(address, !is_load, false)?;

        if is_load {
            // Load exclusive: LDXR, LDAXR, LDXP, LDAXP

            // Set exclusive monitors for this address range
            self.memory.mark_exclusive(pa, datasize as u8);

            if is_pair {
                // Load pair (LDXP, LDAXP)
                if rt == rt2 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                if elsize == 4 {
                    // 32-bit pair - atomic 64-bit load
                    let data = self.memory.read_u64(pa)?;
                    // Little-endian: lower register gets lower bits
                    self.set_w(rt, data as u32);
                    self.set_w(rt2, (data >> 32) as u32);
                } else {
                    // 64-bit pair - two 64-bit loads (128-bit aligned)
                    if pa & 0xF != 0 {
                        return Err(ArmError::MemoryError(MemoryFaultInfo {
                            address,
                            access: crate::isa::arm::common::cpu::AccessType::Read,
                            fault_type: MemoryFaultType::Alignment,
                            stage2: false,
                        }));
                    }
                    let val1 = self.memory.read_u64(pa)?;
                    let val2 = self.memory.read_u64(pa + 8)?;
                    self.set_x(rt, val1);
                    self.set_x(rt2, val2);
                }
            } else {
                // Single register load (LDXR, LDAXR, LDXRB, LDXRH)
                match elsize {
                    1 => {
                        let val = self.memory.read_u8(pa)?;
                        self.set_w(rt, val as u32);
                    }
                    2 => {
                        let val = self.memory.read_u16(pa)?;
                        self.set_w(rt, val as u32);
                    }
                    4 => {
                        let val = self.memory.read_u32(pa)?;
                        self.set_w(rt, val);
                    }
                    8 => {
                        let val = self.memory.read_u64(pa)?;
                        self.set_x(rt, val);
                    }
                    _ => unreachable!(),
                }
            }

            // Memory barrier for acquire semantics
            if is_ordered {
                // LDAXR has acquire semantics - barrier is implicit
                // In our single-threaded emulator, this is a no-op
            }
        } else {
            // Store exclusive: STXR, STLXR, STXP, STLXP

            // Memory barrier for release semantics
            if is_ordered {
                // STLXR has release semantics - barrier is implicit
                // In our single-threaded emulator, this is a no-op
            }

            // Check if exclusive monitors pass
            let exclusive_held = self.memory.check_exclusive(pa, datasize as u8);

            if exclusive_held {
                // Exclusive access succeeded - perform the store
                if is_pair {
                    if elsize == 4 {
                        // 32-bit pair - atomic 64-bit store
                        let val1 = self.get_w(rt) as u64;
                        let val2 = self.get_w(rt2) as u64;
                        let data = val1 | (val2 << 32);
                        self.memory.write_u64(pa, data)?;
                    } else {
                        // 64-bit pair
                        if pa & 0xF != 0 {
                            return Err(ArmError::MemoryError(MemoryFaultInfo {
                                address,
                                access: crate::isa::arm::common::cpu::AccessType::Write,
                                fault_type: MemoryFaultType::Alignment,
                                stage2: false,
                            }));
                        }
                        let val1 = self.get_x(rt);
                        let val2 = self.get_x(rt2);
                        self.memory.write_u64(pa, val1)?;
                        self.memory.write_u64(pa + 8, val2)?;
                    }
                } else {
                    // Single register store
                    match elsize {
                        1 => {
                            let val = self.get_w(rt) as u8;
                            self.memory.write_u8(pa, val)?;
                        }
                        2 => {
                            let val = self.get_w(rt) as u16;
                            self.memory.write_u16(pa, val)?;
                        }
                        4 => {
                            let val = self.get_w(rt);
                            self.memory.write_u32(pa, val)?;
                        }
                        8 => {
                            let val = self.get_x(rt);
                            self.memory.write_u64(pa, val)?;
                        }
                        _ => unreachable!(),
                    }
                }

                // Store succeeded - write 0 to status register
                self.set_w(rs, 0);
            } else {
                // Exclusive access failed - write 1 to status register
                self.set_w(rs, 1);
            }
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_ldr_literal(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let opc = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let imm19 = ((insn >> 5) & 0x7FFFF) as i64;
        let rt = (insn & 0x1F) as u8;

        let offset = ((imm19 << 45) >> 43) as i64;
        let address = ((self.pc as i64).wrapping_sub(4).wrapping_add(offset)) as u64;

        if v != 0 {
            // LDR (literal, SIMD&FP): opc selects S/D/Q; opc=11 unallocated.
            let bytes = match opc {
                0b00 => 4usize,
                0b01 => 8,
                0b10 => 16,
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            let mut buf = [0u8; 16];
            for (i, b) in buf.iter_mut().enumerate().take(bytes) {
                *b = self.mem_read_u8(address + i as u64)?;
            }
            self.v[rt as usize] = u128::from_le_bytes(buf);
            return Ok(CpuExit::Continue);
        }

        match opc {
            0b00 => {
                // LDR (32-bit)
                let value = self.mem_read_u32(address)?;
                self.set_w(rt, value);
            }
            0b01 => {
                // LDR (64-bit)
                let value = self.mem_read_u64(address)?;
                self.set_x(rt, value);
            }
            0b10 => {
                // LDRSW
                let value = self.mem_read_u32(address)? as i32 as i64 as u64;
                self.set_x(rt, value);
            }
            0b11 => {
                // PRFM - prefetch, NOP
                return Ok(CpuExit::Continue);
            }
            _ => unreachable!(),
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_ldst_pair(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let opc = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let mode = (insn >> 23) & 0x3; // 00=no-alloc, 01=post, 10=signed, 11=pre
        let l = (insn >> 22) & 1; // 0=store, 1=load
        let imm7 = ((insn >> 15) & 0x7F) as i32;
        let rt2 = ((insn >> 10) & 0x1F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as u8;

        // Element (per-register) size in bytes and whether LDPSW sign-extends.
        let (bytes, ldpsw) = if v != 0 {
            let b = match opc {
                0b00 => 4usize, // S
                0b01 => 8,      // D
                0b10 => 16,     // Q
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            (b, false)
        } else {
            match opc {
                0b00 => (4usize, false), // 32-bit
                0b01 => (4, true),       // LDPSW (load only)
                0b10 => (8, false),      // 64-bit
                // STTP/LDTP/STTNP/LDTNP (FEAT_LRCPC3 unprivileged pair):
                // privilege-checking aside, plain 64-bit pair semantics.
                0b11 => (8, false),
                _ => unreachable!(),
            }
        };
        if v == 0 && opc == 0b01 && mode == 0b00 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // opc=0b11, V=0 is the FEAT_LRCPC3 unprivileged 64-bit pair (LDTP/STTP/
        // LDTNP/STTNP): its memory accesses are checked at EL0 even when run at
        // EL1, so route them through the unprivileged translation. (#39)
        let unpriv = v == 0 && opc == 0b11;
        if unpriv && !self.config.features.contains(ArmFeatures::RCPC3) {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        // opc=01, V=0 splits by the L bit: L=1 is LDPSW, L=0 is STGP
        // (FEAT_MTE store-allocation-tag pair). STGP stores two 64-bit
        // registers; the tag write is a no-op in our flat memory model, and
        // its immediate is scaled by the 16-byte tag granule (LSL #4).
        // STGP has no no-allocate (STNP-style) form.
        let stgp = v == 0 && opc == 0b01 && l == 0 && mode != 0b00;
        if stgp {
            let off = (((imm7 << 25) >> 25) as i64) * 16;
            let base = if rn == 31 {
                let sp = self.current_sp();
                if sp & 0xF != 0 {
                    return Err(ArmError::MemoryError(MemoryFaultInfo {
                        address: sp,
                        access: crate::isa::arm::common::cpu::AccessType::Write,
                        fault_type: MemoryFaultType::Alignment,
                        stage2: false,
                    }));
                }
                sp
            } else {
                self.get_x(rn)
            };
            let addr = if mode == 0b01 {
                base
            } else {
                (base as i64).wrapping_add(off) as u64
            };
            self.mem_write_u64(addr, self.get_x(rt))?;
            self.mem_write_u64(addr.wrapping_add(8), self.get_x(rt2))?;
            if mode == 0b01 || mode == 0b11 {
                let nb = (base as i64).wrapping_add(off) as u64;
                if rn == 31 {
                    self.set_current_sp(nb);
                } else {
                    self.set_x(rn, nb);
                }
            }
            return Ok(CpuExit::Continue);
        }
        if ldpsw && l == 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        if l != 0 && rt == rt2 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let offset = (((imm7 << 25) >> 25) as i64) * (bytes as i64);
        let wback = mode == 0b01 || mode == 0b11;
        let postindex = mode == 0b01;

        let base = if rn == 31 {
            let sp = self.current_sp();
            if sp & 0xF != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access: if l != 0 {
                        crate::isa::arm::common::cpu::AccessType::Read
                    } else {
                        crate::isa::arm::common::cpu::AccessType::Write
                    },
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };
        let address = if postindex {
            base
        } else {
            (base as i64).wrapping_add(offset) as u64
        };
        let addr2 = address.wrapping_add(bytes as u64);

        if v != 0 {
            if l != 0 {
                let mut b1 = [0u8; 16];
                let mut b2 = [0u8; 16];
                for i in 0..bytes {
                    b1[i] = self.mem_read_u8(address + i as u64)?;
                    b2[i] = self.mem_read_u8(addr2 + i as u64)?;
                }
                self.v[rt as usize] = u128::from_le_bytes(b1);
                self.v[rt2 as usize] = u128::from_le_bytes(b2);
            } else {
                let v1 = self.v[rt as usize].to_le_bytes();
                let v2 = self.v[rt2 as usize].to_le_bytes();
                for i in 0..bytes {
                    self.mem_write_u8(address + i as u64, v1[i])?;
                    self.mem_write_u8(addr2 + i as u64, v2[i])?;
                }
            }
        } else if bytes == 4 {
            if l != 0 {
                let val1 = self.mem_read_u32(address)?;
                let val2 = self.mem_read_u32(addr2)?;
                if ldpsw {
                    self.set_x(rt, val1 as i32 as i64 as u64);
                    self.set_x(rt2, val2 as i32 as i64 as u64);
                } else {
                    self.set_w(rt, val1);
                    self.set_w(rt2, val2);
                }
            } else {
                self.mem_write_u32(address, self.get_w(rt))?;
                self.mem_write_u32(addr2, self.get_w(rt2))?;
            }
        } else if l != 0 {
            let (v1, v2) = if unpriv {
                (
                    self.mem_read_u64_unprivileged(address)?,
                    self.mem_read_u64_unprivileged(addr2)?,
                )
            } else {
                (self.mem_read_u64(address)?, self.mem_read_u64(addr2)?)
            };
            self.set_x(rt, v1);
            self.set_x(rt2, v2);
        } else if unpriv {
            self.mem_write_u64_unprivileged(address, self.get_x(rt))?;
            self.mem_write_u64_unprivileged(addr2, self.get_x(rt2))?;
        } else {
            self.mem_write_u64(address, self.get_x(rt))?;
            self.mem_write_u64(addr2, self.get_x(rt2))?;
        }

        let suppress_load_wback = l != 0 && v == 0 && rn != 31 && (rn == rt || rn == rt2);
        if wback && !suppress_load_wback {
            let new_base = (base as i64).wrapping_add(offset) as u64;
            if rn == 31 {
                self.set_current_sp(new_base);
            } else {
                self.set_x(rn, new_base);
            }
        }

        Ok(CpuExit::Continue)
    }

    /// Advanced SIMD load/store single structure: one element to/from a lane of
    /// `selem` consecutive registers (LD1-LD4 by element), and the replicating
    /// loads LD1R-LD4R (broadcast one element across all lanes).
    pub(crate) fn exec_ldst_single(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let q = (insn >> 30) & 1;
        let post = (insn >> 23) & 1;
        let l = (insn >> 22) & 1;
        let r = (insn >> 21) & 1;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let opcode = (insn >> 13) & 0x7;
        let s_bit = (insn >> 12) & 1;
        let size = (insn >> 10) & 0x3;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as usize;

        // No-offset form (post==0): the Rm field (bits[20:16]) is reserved and
        // must be 0. A non-zero Rm here is an unallocated encoding that must
        // trap rather than execute a memory access.
        if post == 0 && rm != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let scale = opcode >> 1; // bits[15:14]
        let selem = (((opcode & 1) << 1) | r) as usize + 1;

        let (esize, index, replicate) = match scale {
            0b00 => (8u32, ((q << 3) | (s_bit << 2) | size) as usize, false),
            0b01 => {
                if size & 1 != 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                (16, ((q << 2) | (s_bit << 1) | (size >> 1)) as usize, false)
            }
            0b10 => {
                if size & 2 != 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                if size & 1 == 0 {
                    (32, ((q << 1) | s_bit) as usize, false)
                } else {
                    if s_bit != 0 {
                        return Err(ArmError::UndefinedInstruction(insn));
                    }
                    (64, q as usize, false)
                }
            }
            _ => {
                // Replicate (LD1R-LD4R): load-only, S must be 0.
                if l == 0 || s_bit != 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                (8u32 << size, 0usize, true)
            }
        };
        let ebytes = (esize / 8) as u64;
        let datasize = if q == 1 { 16usize } else { 8 };
        let emask = elem_mask_u128(esize);

        let base = if rn == 31 {
            let sp = self.current_sp();
            if sp & 0xF != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access: if l != 0 {
                        crate::isa::arm::common::cpu::AccessType::Read
                    } else {
                        crate::isa::arm::common::cpu::AccessType::Write
                    },
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };
        let mut addr = base;

        for sct in 0..selem {
            let reg = (rt + sct) % 32;
            if replicate {
                let mut bytes = [0u8; 8];
                for (b, slot) in bytes.iter_mut().enumerate().take(ebytes as usize) {
                    *slot = self.mem_read_u8(addr + b as u64)?;
                }
                let val = u64::from_le_bytes(bytes) as u128 & emask;
                let elements = datasize / ebytes as usize;
                let mut result = 0u128;
                for e in 0..elements {
                    result |= val << (e * esize as usize);
                }
                self.v[reg] = result;
            } else {
                let shift = index * esize as usize;
                if l != 0 {
                    let mut bytes = [0u8; 8];
                    for (b, slot) in bytes.iter_mut().enumerate().take(ebytes as usize) {
                        *slot = self.mem_read_u8(addr + b as u64)?;
                    }
                    let val = u64::from_le_bytes(bytes) as u128 & emask;
                    self.v[reg] = (self.v[reg] & !(emask << shift)) | (val << shift);
                } else {
                    let val = (self.v[reg] >> shift) & emask;
                    for b in 0..ebytes as usize {
                        self.mem_write_u8(addr + b as u64, (val >> (b * 8)) as u8)?;
                    }
                }
            }
            addr += ebytes;
        }

        if post != 0 {
            let inc = if rm == 31 {
                selem as u64 * ebytes
            } else {
                self.get_x(rm)
            };
            let new = base.wrapping_add(inc);
            if rn == 31 {
                self.set_current_sp(new);
            } else {
                self.set_x(rn, new);
            }
        }
        Ok(CpuExit::Continue)
    }

    /// Advanced SIMD load/store multiple structures: LD1/ST1 (1-4 registers),
    /// LD2/ST2, LD3/ST3, LD4/ST4 (de-interleaving). Contiguous, optional
    /// post-index writeback.
    pub(crate) fn exec_ldst_structures(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let q = (insn >> 30) & 1;
        let post = (insn >> 23) & 1;
        let l = (insn >> 22) & 1;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let opcode = (insn >> 12) & 0xF;
        let size = (insn >> 10) & 0x3;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as usize;

        // No-offset form (post==0): bits[20:16] are reserved and must be 0.
        if post == 0 && rm != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // (rpt, selem): number of register groups and structure size.
        let (rpt, selem): (usize, usize) = match opcode {
            0b0000 => (1, 4), // LD4/ST4
            0b0010 => (4, 1), // LD1 x4
            0b0100 => (1, 3), // LD3/ST3
            0b0110 => (3, 1), // LD1 x3
            0b0111 => (1, 1), // LD1 x1
            0b1000 => (1, 2), // LD2/ST2
            0b1010 => (2, 1), // LD1 x2
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        };
        // A single 64-bit element (1D, size=11 with Q=0) is only valid when the
        // structure spans a single register per group.
        if size == 0b11 && q == 0 && selem != 1 && rpt == 1 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let esize = 8u32 << size; // bits
        let ebytes = (esize / 8) as u64;
        let datasize = if q == 1 { 16usize } else { 8 };
        let elements = datasize / ebytes as usize;
        let nregs = rpt * selem;

        let base = if rn == 31 {
            let sp = self.current_sp();
            if sp & 0xF != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access: if l != 0 {
                        crate::isa::arm::common::cpu::AccessType::Read
                    } else {
                        crate::isa::arm::common::cpu::AccessType::Write
                    },
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };
        let mut addr = base;

        // Loads rewrite each touched register fully (upper bits zeroed for Q=0).
        if l != 0 {
            for i in 0..nregs {
                self.v[(rt + i) % 32] = 0;
            }
        }
        let emask = elem_mask_u128(esize);
        for r in 0..rpt {
            for e in 0..elements {
                for sct in 0..selem {
                    let reg = (rt + r * selem + sct) % 32;
                    let shift = e * esize as usize;
                    if l != 0 {
                        let mut bytes = [0u8; 8];
                        for (b, slot) in bytes.iter_mut().enumerate().take(ebytes as usize) {
                            *slot = self.mem_read_u8(addr.wrapping_add(b as u64))?;
                        }
                        let val = u64::from_le_bytes(bytes) as u128 & emask;
                        self.v[reg] = (self.v[reg] & !(emask << shift)) | (val << shift);
                    } else {
                        let val = (self.v[reg] >> shift) & emask;
                        for b in 0..ebytes as usize {
                            self.mem_write_u8(addr.wrapping_add(b as u64), (val >> (b * 8)) as u8)?;
                        }
                    }
                    addr = addr.wrapping_add(ebytes);
                }
            }
        }

        if post != 0 {
            let inc = if rm == 31 {
                (nregs * elements) as u64 * ebytes
            } else {
                self.get_x(rm)
            };
            let new = base.wrapping_add(inc);
            if rn == 31 {
                self.set_current_sp(new);
            } else {
                self.set_x(rn, new);
            }
        }
        Ok(CpuExit::Continue)
    }

    /// Atomic memory operations (FEAT_LSE): LDADD/LDCLR/LDEOR/LDSET/LDSMAX/
    /// LDSMIN/LDUMAX/LDUMIN and SWP. Single-core, so the load-op-store is just
    /// sequential. Rt receives the pre-operation value (discarded if Rt==31).
    pub(crate) fn exec_atomic_memop(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let size = (insn >> 30) & 0x3;
        let rs = ((insn >> 16) & 0x1F) as u8;
        let o3 = (insn >> 15) & 1;
        let opc = (insn >> 12) & 0x7;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as u8;
        let bits = 8u32 << size;
        let m = elem_mask(bits);

        let addr = if rn == 31 {
            let sp = self.current_sp();
            if sp & 0xf != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access: crate::isa::arm::common::cpu::AccessType::Read,
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };
        let old = match size {
            0 => self.mem_read_u8(addr)? as u64,
            1 => self.mem_read_u16(addr)? as u64,
            2 => self.mem_read_u32(addr)? as u64,
            _ => self.mem_read_u64(addr)?,
        };
        let operand = self.get_x(rs) & m;

        let new = if o3 == 1 {
            if opc == 0 {
                operand // SWP
            } else if opc == 0b100 && rs == 31 && (insn >> 23) & 1 == 1 && (insn >> 22) & 1 == 0 {
                // LDAPR/LDAPRB/LDAPRH (FEAT_LRCPC): load-acquire RCpc. In a
                // single-threaded model this is a plain load.
                if size == 3 {
                    self.set_x(rt, old);
                } else {
                    self.set_w(rt, old as u32);
                }
                return Ok(CpuExit::Continue);
            } else {
                return Err(ArmError::UndefinedInstruction(insn));
            }
        } else {
            match opc {
                0b000 => old.wrapping_add(operand), // LDADD
                0b001 => old & !operand,            // LDCLR
                0b010 => old ^ operand,             // LDEOR
                0b011 => old | operand,             // LDSET
                0b100 => (sext_elem(old, bits).max(sext_elem(operand, bits)) as u64) & m, // LDSMAX
                0b101 => (sext_elem(old, bits).min(sext_elem(operand, bits)) as u64) & m, // LDSMIN
                0b110 => (old & m).max(operand & m), // LDUMAX
                0b111 => (old & m).min(operand & m), // LDUMIN
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            }
        };
        let new = new & m;
        match size {
            0 => self.mem_write_u8(addr, new as u8)?,
            1 => self.mem_write_u16(addr, new as u16)?,
            2 => self.mem_write_u32(addr, new as u32)?,
            _ => self.mem_write_u64(addr, new)?,
        }
        if rt != 31 {
            if size == 3 {
                self.set_x(rt, old);
            } else {
                self.set_w(rt, old as u32);
            }
        }
        Ok(CpuExit::Continue)
    }

    /// `LDRAA`/`LDRAB Xt, [Xn|SP, #simm]{!}`: authenticate the base with
    /// data key A (M=0) or B (M=1) and a zero modifier, add the scaled
    /// 10-bit offset (`S:imm9 << 3`), load 64 bits, and with W=1 write the
    /// address back. UNDEFINED without FEAT_PAuth. The implementation's
    /// PAC algorithm leaves pointers unchanged (see `exec_br_reg_pauth`),
    /// so the authenticated base is the base.
    fn exec_ldraa(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if !self.config.features.contains(ArmFeatures::PACA) {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let s = (insn >> 22) & 1;
        let imm9 = (insn >> 12) & 0x1FF;
        let wback = (insn >> 11) & 1 == 1;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as u8;
        let s10 = ((s << 9) | imm9) as i32;
        let offset = (((s10 << 22) >> 22) as i64) << 3;
        let base = if rn == 31 {
            let sp = self.current_sp();
            if sp & 0xF != 0 {
                return Err(ArmError::MemoryError(MemoryFaultInfo {
                    address: sp,
                    access: crate::isa::arm::common::cpu::AccessType::Read,
                    fault_type: MemoryFaultType::Alignment,
                    stage2: false,
                }));
            }
            sp
        } else {
            self.get_x(rn)
        };
        let address = (base as i64).wrapping_add(offset) as u64;
        let data = self.mem_read_u64(address)?;
        self.set_x(rt, data);
        if wback {
            if rn == 31 {
                self.set_current_sp(address);
            } else {
                self.set_x(rn, address);
            }
        }
        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_ldst_reg(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let size = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let opc = (insn >> 22) & 0x3;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rt = (insn & 0x1F) as u8;

        // Atomic memory operations (FEAT_LSE): bit24=0, bit21=1, bits[11:10]=00.
        if v == 0 && (insn >> 24) & 1 == 0 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3 == 0 {
            return self.exec_atomic_memop(insn);
        }

        // Load register (pac): LDRAA/LDRAB, size=11, bit24=0, bit21=1,
        // bits[11:10]=W1.
        if v == 0
            && size == 0b11
            && (insn >> 24) & 1 == 0
            && (insn >> 21) & 1 == 1
            && (insn >> 10) & 1 == 1
        {
            return self.exec_ldraa(insn);
        }

        if v != 0 {
            // SIMD/FP load/store: access size is 1 << ((opc<1>:size)).
            let scale = (((opc >> 1) & 1) << 2) | size;
            if scale > 4 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let bit24 = (insn >> 24) & 1;
            let bit21 = (insn >> 21) & 1;
            let op2 = (insn >> 10) & 0x3;
            if bit24 == 0 && bit21 == 0 && op2 == 0b10 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            // Register-offset form: the extend option must have bit 1 set
            // (UXTW/LSL/SXTW/SXTX); other options are unallocated.
            if bit24 == 0 && bit21 == 1 && op2 == 0b10 {
                let option = (insn >> 13) & 0x7;
                if option & 0b010 == 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
            }
            let access = 1usize << scale;
            let is_load = (opc & 1) == 1;
            let (address, wback, wback_value) = self.decode_address(
                insn,
                rn,
                scale,
                if is_load {
                    crate::isa::arm::common::cpu::AccessType::Read
                } else {
                    crate::isa::arm::common::cpu::AccessType::Write
                },
            )?;
            if is_load {
                let mut bytes = [0u8; 16];
                for (i, b) in bytes.iter_mut().enumerate().take(access) {
                    *b = self.mem_read_u8(address + i as u64)?;
                }
                self.v[rt as usize] = u128::from_le_bytes(bytes);
            } else {
                let val = self.v[rt as usize].to_le_bytes();
                for (i, b) in val.iter().enumerate().take(access) {
                    self.mem_write_u8(address + i as u64, *b)?;
                }
            }
            if wback {
                if rn == 31 {
                    self.set_current_sp(wback_value);
                } else {
                    self.set_x(rn, wback_value);
                }
            }
            return Ok(CpuExit::Continue);
        }

        let bit24 = (insn >> 24) & 1;
        let bit21 = (insn >> 21) & 1;
        let op2 = (insn >> 10) & 0x3;
        if size == 0b11 && opc >= 0b10 {
            let is_unsigned_offset = bit24 == 1;
            let is_signed_offset = bit24 == 0 && bit21 == 0 && op2 == 0b00;
            let is_register_offset = bit24 == 0 && bit21 == 1 && op2 == 0b10;

            if opc == 0b10 && (is_unsigned_offset || is_signed_offset || is_register_offset) {
                if is_register_offset {
                    let option = ((insn >> 13) & 0x7) as u8;
                    if option & 0b010 == 0 {
                        return Err(ArmError::UndefinedInstruction(insn));
                    }
                }
                return Ok(CpuExit::Continue);
            }

            return Err(ArmError::UndefinedInstruction(insn));
        }
        if size == 0b10 && opc == 0b11 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        if bit24 == 0 && bit21 == 1 && op2 == 0b10 {
            let option = ((insn >> 13) & 0x7) as u8;
            if option & 0b010 == 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
        }

        // Determine addressing mode
        let unprivileged = bit24 == 0 && bit21 == 0 && op2 == 0b10;
        let is_load = (opc & 1) != 0 || opc == 0b10;
        let is_signed = opc >= 0b10;
        let (address, wback, wback_value) = self.decode_address(
            insn,
            rn,
            size,
            if is_load {
                crate::isa::arm::common::cpu::AccessType::Read
            } else {
                crate::isa::arm::common::cpu::AccessType::Write
            },
        )?;

        if is_load {
            let value = match size {
                0b00 => {
                    let v = if unprivileged {
                        self.mem_read_u8_unprivileged(address)?
                    } else {
                        self.mem_read_u8(address)?
                    };
                    if is_signed && opc == 0b11 {
                        v as i8 as i64 as u64
                    } else if is_signed {
                        v as i8 as i32 as u64
                    } else {
                        v as u64
                    }
                }
                0b01 => {
                    let v = if unprivileged {
                        self.mem_read_u16_unprivileged(address)?
                    } else {
                        self.mem_read_u16(address)?
                    };
                    if is_signed && opc == 0b11 {
                        v as i16 as i64 as u64
                    } else if is_signed {
                        v as i16 as i32 as u64
                    } else {
                        v as u64
                    }
                }
                0b10 => {
                    let v = if unprivileged {
                        self.mem_read_u32_unprivileged(address)?
                    } else {
                        self.mem_read_u32(address)?
                    };
                    if is_signed {
                        v as i32 as i64 as u64
                    } else {
                        v as u64
                    }
                }
                0b11 => {
                    if unprivileged {
                        self.mem_read_u64_unprivileged(address)?
                    } else {
                        self.mem_read_u64(address)?
                    }
                }
                _ => unreachable!(),
            };

            if size == 0b11 || (is_signed && opc == 0b10) {
                self.set_x(rt, value);
            } else {
                self.set_w(rt, value as u32);
            }
        } else {
            // Store
            match size {
                0b00 => {
                    if unprivileged {
                        self.mem_write_u8_unprivileged(address, self.get_w(rt) as u8)?
                    } else {
                        self.mem_write_u8(address, self.get_w(rt) as u8)?
                    }
                }
                0b01 => {
                    if unprivileged {
                        self.mem_write_u16_unprivileged(address, self.get_w(rt) as u16)?
                    } else {
                        self.mem_write_u16(address, self.get_w(rt) as u16)?
                    }
                }
                0b10 => {
                    if unprivileged {
                        self.mem_write_u32_unprivileged(address, self.get_w(rt))?
                    } else {
                        self.mem_write_u32(address, self.get_w(rt))?
                    }
                }
                0b11 => {
                    if unprivileged {
                        self.mem_write_u64_unprivileged(address, self.get_x(rt))?
                    } else {
                        self.mem_write_u64(address, self.get_x(rt))?
                    }
                }
                _ => unreachable!(),
            }
        }

        // Writeback
        let suppress_load_wback = is_load && rn != 31 && rn == rt;
        if wback && !suppress_load_wback {
            if rn == 31 {
                self.set_current_sp(wback_value);
            } else {
                self.set_x(rn, wback_value);
            }
        }

        Ok(CpuExit::Continue)
    }
}

//! Load/store, load/store-multiple execution

use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{
    ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr, add_with_carry, compute_n_flag,
    compute_z_flag, condition_passed, expand_imm_c, shift_c, sign_extend,
};
use crate::isa::arm::aarch32::instructions::*;
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

impl<'a, M: ArmMemory> Executor<'a, M> {
    /// Table Branch Byte (TBB) - Thumb-2.
    ///
    /// TBB [Rn, Rm]
    ///
    /// Reads a byte from memory[Rn + Rm] and branches forward by 2*byte.
    pub(crate) fn exec_tbb(&mut self, insn: &DecodedInsn) -> ExecResult {
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
    pub(crate) fn exec_tbh(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_ldr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (t, address, writeback) = match self.decode_ldst_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        match self.mem.read_word(address) {
            Ok(data) => {
                if let Some((n, addr)) = writeback {
                    self.cpu.regs[n] = addr;
                }
                if t == 15 {
                    // LDR pc is an interworking branch (ARMv5+): bit0 of the
                    // loaded value selects ARM (0) or Thumb (1).
                    self.cpu.cpsr.t = (data & 1) != 0;
                    ExecResult::Branch(data & !1)
                } else {
                    self.set_reg(t, data)
                }
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    pub(crate) fn exec_ldrb(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_ldrh(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_ldrsb(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_ldrsh(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_str(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_strb(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_strh(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_ldrd(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_strd(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    /// LDA, LDAB, LDAH (ARMv8): a load-acquire of `size` bytes from [Rn]
    /// into Rt, zero-extended; the address must be aligned to the size
    /// (`MemO`). Rt or Rn being PC is CONSTRAINED UNPREDICTABLE: UNDEFINED.
    pub(crate) fn exec_lda(&mut self, insn: &DecodedInsn, size: u32) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        if t == 15 || n == 15 {
            return ExecResult::Undefined;
        }
        let address = self.reg(n);
        if address % size != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }
        let value = match size {
            1 => self.mem.read_byte(address).map(u32::from),
            2 => self.mem.read_halfword(address).map(u32::from),
            _ => self.mem.read_word(address),
        };
        match value {
            Ok(v) => {
                self.cpu.regs[t] = v;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    /// STL, STLB, STLH (ARMv8): a store-release of Rt's low `size` bytes
    /// to [Rn], which must be aligned to the size.
    pub(crate) fn exec_stl(&mut self, insn: &DecodedInsn, size: u32) -> ExecResult {
        let t = (insn.raw & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        if t == 15 || n == 15 {
            return ExecResult::Undefined;
        }
        let address = self.reg(n);
        if address % size != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }
        let value = self.reg(t);
        let stored = match size {
            1 => self.mem.write_byte(address, value as u8),
            2 => self.mem.write_halfword(address, value as u16),
            _ => self.mem.write_word(address, value),
        };
        match stored {
            Ok(()) => ExecResult::Continue,
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    pub(crate) fn exec_ldrex(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);
        if address % 4 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }

        self.exclusive_monitor.mark_exclusive(address, 4);

        match self.mem.read_word(address) {
            Ok(data) => {
                self.cpu.regs[t] = data;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    pub(crate) fn exec_strex(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let t = (insn.raw & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);
        if address % 4 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }

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

    /// LDREXD: doubleword exclusive load into an even/odd register pair.
    pub(crate) fn exec_ldrexd(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        if t & 1 != 0 || t == 14 {
            return ExecResult::Undefined;
        }
        let address = self.reg(n);
        if address % 8 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }

        self.exclusive_monitor.mark_exclusive(address, 8);

        let lo = match self.mem.read_word(address) {
            Ok(d) => d,
            Err(e) => return ExecResult::MemoryFault(e),
        };
        let hi = match self.mem.read_word(address.wrapping_add(4)) {
            Ok(d) => d,
            Err(e) => return ExecResult::MemoryFault(e),
        };
        self.cpu.regs[t] = lo;
        self.cpu.regs[t + 1] = hi;
        ExecResult::Continue
    }

    /// STREXD: doubleword exclusive store from an even/odd register pair.
    pub(crate) fn exec_strexd(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let t = (insn.raw & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        if t & 1 != 0 || t == 14 {
            return ExecResult::Undefined;
        }
        let address = self.reg(n);
        if address % 8 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }

        if self.exclusive_monitor.check_and_clear(address, 8) {
            if let Err(e) = self.mem.write_word(address, self.reg(t)) {
                return ExecResult::MemoryFault(e);
            }
            if let Err(e) = self
                .mem
                .write_word(address.wrapping_add(4), self.reg(t + 1))
            {
                return ExecResult::MemoryFault(e);
            }
            self.cpu.regs[d] = 0; // Success
        } else {
            self.cpu.regs[d] = 1; // Failure
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_ldrexb(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_strexb(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_ldrexh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);
        if address % 2 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }

        self.exclusive_monitor.mark_exclusive(address, 2);

        match self.mem.read_halfword(address) {
            Ok(data) => {
                self.cpu.regs[t] = data as u32;
                ExecResult::Continue
            }
            Err(e) => ExecResult::MemoryFault(e),
        }
    }

    pub(crate) fn exec_strexh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let t = (insn.raw & 0xF) as usize;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let address = self.reg(n);
        if address % 2 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(address));
        }

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

    // =========================================================================
    // Load/Store Multiple
    // =========================================================================

    /// Unified LDM/STM for all four addressing modes (IA/IB/DA/DB), A32 and T32.
    /// The lowest-numbered register always maps to the lowest address.
    pub(crate) fn exec_ldm_stm(
        &mut self,
        insn: &DecodedInsn,
        is_load: bool,
        p: bool,
        u: bool,
    ) -> ExecResult {
        let (n, reglist, wback) = match self.decode_ldstm_operands(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };
        let count = reglist.count_ones();
        let base = self.reg(n);
        let low = if u {
            if p { base.wrapping_add(4) } else { base }
        } else if p {
            base.wrapping_sub(count * 4)
        } else {
            base.wrapping_sub(count * 4).wrapping_add(4)
        };
        let wb_val = if u {
            base.wrapping_add(count * 4)
        } else {
            base.wrapping_sub(count * 4)
        };

        // A32 S bit (the `^` forms): without PC in an LDM list it selects the
        // USER bank for the transfer; an LDM with PC additionally restores
        // CPSR from the current SPSR (exception return).
        let s_bit = Self::a32_s_bit(insn);
        let exception_return = s_bit && is_load && reglist & 0x8000 != 0;
        let user_bank = s_bit && !exception_return && !self.cpu.is_user_or_system();

        let mut addr = low;
        let mut branch_target = None;
        for i in 0..16 {
            if reglist & (1 << i) == 0 {
                continue;
            }
            if is_load {
                match self.mem.read_word(addr) {
                    Ok(d) => {
                        if i == 15 {
                            branch_target = Some(d);
                        } else if user_bank {
                            self.write_user_bank_reg(i, d);
                        } else {
                            self.cpu.regs[i] = d;
                        }
                    }
                    Err(e) => return ExecResult::MemoryFault(e),
                }
            } else {
                let val = if i == 15 {
                    self.cpu.get_pc()
                } else if user_bank {
                    self.read_user_bank_reg(i)
                } else {
                    self.reg(i)
                };
                if let Err(e) = self.mem.write_word(addr, val) {
                    return ExecResult::MemoryFault(e);
                }
            }
            addr = addr.wrapping_add(4);
        }

        // Writeback (suppressed for LDM when the base is in the loaded list).
        if wback && !(is_load && reglist & (1 << n) != 0) {
            self.cpu.regs[n] = wb_val;
        }

        if exception_return {
            let spsr = self.current_spsr_bits();
            self.write_cpsr_all(spsr);
        }

        if let Some(target) = branch_target {
            if exception_return {
                // CPSR (incl. T) was restored from SPSR; PC is the saved value.
                ExecResult::Branch(target)
            } else {
                // LDM {pc} is an interworking branch (ARMv5+): bit0 selects the
                // instruction set.
                self.cpu.cpsr.t = (target & 1) != 0;
                ExecResult::Branch(target & !1)
            }
        } else {
            ExecResult::Continue
        }
    }

    #[allow(dead_code)]
    pub(crate) fn exec_ldm(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_ldmdb(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_stm(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_stmdb(&mut self, insn: &DecodedInsn) -> ExecResult {
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

    pub(crate) fn exec_push(&mut self, insn: &DecodedInsn) -> ExecResult {
        let reglist = match self.decode_reglist(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let count = reglist.count_ones();
        let mut address = self.cpu.regs[13].wrapping_sub(count * 4);
        let start_address = address;
        let user_bank = Self::a32_s_bit(insn) && !self.cpu.is_user_or_system();

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                let val = if user_bank {
                    self.read_user_bank_reg(i)
                } else {
                    self.reg(i)
                };
                match self.mem.write_word(address, val) {
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

    pub(crate) fn exec_pop(&mut self, insn: &DecodedInsn) -> ExecResult {
        let reglist = match self.decode_reglist(insn) {
            Some(v) => v,
            None => return ExecResult::Undefined,
        };

        let mut address = self.cpu.regs[13];
        let mut branch_target = None;
        let s_bit = Self::a32_s_bit(insn);
        let exception_return = s_bit && (reglist & 0x8000) != 0 && !self.cpu.is_user_or_system();
        let user_bank = s_bit && !exception_return && !self.cpu.is_user_or_system();

        for i in 0..16 {
            if (reglist & (1 << i)) != 0 {
                match self.mem.read_word(address) {
                    Ok(data) => {
                        if i == 15 {
                            branch_target = Some(data);
                        } else if user_bank {
                            self.write_user_bank_reg(i, data);
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

        // A32 `LDM sp!, {..., pc}^` (the S-bit form, e.g. an IRQ handler's
        // exception-return `e8fd900f`) is decoded here as a POP. With PC in the
        // list and the S bit set, it additionally restores CPSR from the
        // current mode's SPSR — without this the CPU stays in the handler's
        // mode (e.g. IRQ) on return, corrupting the resumed context.
        if let Some(target) = branch_target {
            if exception_return {
                // CPSR (including the T bit) is restored from SPSR; PC is the
                // loaded value verbatim.
                let spsr = self.current_spsr_bits();
                self.write_cpsr_all(spsr);
                ExecResult::Branch(target)
            } else {
                // POP {pc} is an interworking branch (ARMv5+): the loaded PC's
                // bit0 selects ARM (0) or Thumb (1). Set the state explicitly so
                // a Thumb→ARM return (bit0 = 0) actually leaves Thumb.
                self.cpu.cpsr.t = (target & 1) != 0;
                ExecResult::Branch(target & !1)
            }
        } else {
            ExecResult::Continue
        }
    }

    /// SWP/SWPB: atomic swap (ARMv6-deprecated but still used).
    pub(crate) fn exec_swp(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let byte = (raw >> 22) & 1 == 1;
        let n = ((raw >> 16) & 0xF) as usize;
        let d = ((raw >> 12) & 0xF) as usize;
        let m = (raw & 0xF) as usize;
        let addr = self.cpu.regs[n];
        if byte {
            let old = match self.mem.read_byte(addr) {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            if let Err(e) = self.mem.write_byte(addr, self.cpu.regs[m] as u8) {
                return ExecResult::MemoryFault(e);
            }
            self.cpu.regs[d] = old as u32;
        } else {
            let old = match self.mem.read_word(addr) {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            if let Err(e) = self.mem.write_word(addr, self.cpu.regs[m]) {
                return ExecResult::MemoryFault(e);
            }
            self.cpu.regs[d] = old;
        }
        ExecResult::Continue
    }
}

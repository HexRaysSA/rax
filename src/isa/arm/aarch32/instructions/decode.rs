//! Instruction sub-decoding helpers

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
    /// Thumb (T16/T32) data-processing operand decode using the decoded operands.
    pub(crate) fn decode_dp_operands_thumb(&mut self, insn: &DecodedInsn) -> (usize, usize, u32) {
        use crate::isa::arm::decoder::Operand;
        let (operand2, carry) = match insn.operands.last() {
            Some(Operand::Imm(imm)) => {
                let v = imm.value as u32;
                (v, self.thumb_imm_carry(insn, v))
            }
            Some(Operand::Reg(r)) => (self.reg(r.num as usize), self.cpu.cpsr.c),
            Some(Operand::ShiftedReg(sr)) => {
                let amount = match sr.amount {
                    crate::isa::arm::decoder::ShiftAmount::Immediate(amount) => u32::from(amount),
                    crate::isa::arm::decoder::ShiftAmount::Register(reg) => {
                        self.reg(reg.num as usize) & 0xff
                    }
                };
                shift_c(
                    self.reg(sr.reg.num as usize),
                    sr.shift_type,
                    amount,
                    self.cpu.cpsr.c,
                )
            }
            _ => (0, self.cpu.cpsr.c),
        };
        self.cpu.carry_out = carry;

        // Leading register operands (those before operand2).
        let nlead = insn.operands.len().saturating_sub(1);
        let mut lead = [0usize; 2];
        let mut cnt = 0;
        for o in &insn.operands[..nlead] {
            if let Operand::Reg(r) = o {
                if cnt < 2 {
                    lead[cnt] = r.num as usize;
                    cnt += 1;
                }
            }
        }
        let is_test = matches!(
            insn.mnemonic,
            Mnemonic::CMP | Mnemonic::CMN | Mnemonic::TST | Mnemonic::TEQ
        );
        let (d, n) = match cnt {
            2 => (lead[0], lead[1]),
            1 => {
                if is_test {
                    (15, lead[0])
                } else {
                    (lead[0], 0)
                }
            }
            _ => (0, 0),
        };
        (d, n, operand2)
    }

    /// Decode data processing operands: (Rd, Rn, operand2)
    pub(crate) fn decode_dp_operands(&mut self, insn: &DecodedInsn) -> (usize, usize, u32) {
        if insn.state.is_thumb() {
            return self.decode_dp_operands_thumb(insn);
        }
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
    pub(crate) fn decode_shift_operands(&self, insn: &DecodedInsn) -> (usize, usize, u32) {
        if insn.state.is_thumb() {
            use crate::isa::arm::decoder::Operand;
            let (regs, _) = Self::thumb_reg_ops(insn, 2);
            let d = regs[0];
            let m = regs[1];
            let amount = match insn.operands.last() {
                Some(Operand::Imm(imm)) => imm.value as u32,
                // Register-controlled shift (e.g. T16 LSLS Rdn, Rm).
                Some(Operand::Reg(r)) => self.reg(r.num as usize) & 0xFF,
                _ => 0,
            };
            return (d, m, amount);
        }
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let m = (insn.raw & 0xF) as usize;

        let shift_amount = if (insn.raw >> 4) & 1 != 0 {
            let s = ((insn.raw >> 8) & 0xF) as usize;
            self.reg(s) & 0xFF
        } else {
            let imm5 = ((insn.raw >> 7) & 0x1F) as u32;
            if imm5 == 0 { 32 } else { imm5 }
        };

        (d, m, shift_amount)
    }

    /// Decode multiply operands: (Rd, Rn, Rm)
    pub(crate) fn decode_mul_operands(&self, insn: &DecodedInsn) -> (usize, usize, usize) {
        if insn.state.is_thumb() {
            let (r, _) = Self::thumb_reg_ops(insn, 3);
            return (r[0], r[1], r[2]);
        }
        let d = ((insn.raw >> 16) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;
        (d, n, m)
    }

    /// Decode MLA operands: (Rd, Rn, Rm, Ra)
    pub(crate) fn decode_mla_operands(&self, insn: &DecodedInsn) -> (usize, usize, usize, usize) {
        if insn.state.is_thumb() {
            let (r, _) = Self::thumb_reg_ops(insn, 4);
            return (r[0], r[1], r[2], r[3]);
        }
        let d = ((insn.raw >> 16) & 0xF) as usize;
        let a = ((insn.raw >> 12) & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        (d, n, m, a)
    }

    /// Decode long multiply operands: (RdLo, RdHi, Rn, Rm)
    pub(crate) fn decode_mull_operands(&self, insn: &DecodedInsn) -> (usize, usize, usize, usize) {
        if insn.state.is_thumb() {
            let (r, _) = Self::thumb_reg_ops(insn, 4);
            return (r[0], r[1], r[2], r[3]);
        }
        let dhi = ((insn.raw >> 16) & 0xF) as usize;
        let dlo = ((insn.raw >> 12) & 0xF) as usize;
        let m = ((insn.raw >> 8) & 0xF) as usize;
        let n = (insn.raw & 0xF) as usize;
        (dlo, dhi, n, m)
    }

    /// Decode branch target from instruction.
    pub(crate) fn decode_branch_target(&self, insn: &DecodedInsn) -> Option<u32> {
        if let Some(off) = insn.operands.iter().find_map(|o| match o {
            crate::isa::arm::decoder::Operand::Label(l) => Some(*l),
            _ => None,
        }) {
            let base = if insn.state.is_thumb() {
                // Thumb B/BL/BLX/BCC offsets are relative to PC+4.
                self.cpu.regs[15].wrapping_add(4)
            } else {
                // A32 B/BL/BLX offsets are relative to PC+8. BLX immediate
                // needs the decoded Label operand because bit 24 is H, not L.
                self.cpu.get_pc()
            };
            return Some((base as i64).wrapping_add(off) as u32);
        }

        if insn.state.is_thumb() {
            return None;
        }

        // ARM B/BL: 24-bit signed offset scaled by 4, relative to PC+8.
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
    pub(crate) fn decode_reg_operand(&self, insn: &DecodedInsn, pos: usize) -> Option<usize> {
        if pos < insn.operands.len() {
            match &insn.operands[pos] {
                crate::isa::arm::decoder::Operand::Reg(reg) => Some(reg.num as usize),
                _ => None,
            }
        } else {
            Some((insn.raw & 0xF) as usize)
        }
    }

    /// Decode load/store operands for word/byte: (Rt, address, writeback)
    /// Compute (Rt, address, writeback) from the decoded operands (Thumb path):
    /// the first Reg operand is Rt and the Mem operand gives base/offset/mode.
    pub(crate) fn decode_mem_thumb(
        &self,
        insn: &DecodedInsn,
    ) -> Option<(usize, u32, Option<(usize, u32)>)> {
        use crate::isa::arm::decoder::{AddressingMode, MemOffset, Operand};
        let t = insn.operands.iter().find_map(|o| match o {
            Operand::Reg(r) => Some(crate::isa::arm::aarch32::cpu::aarch32_reg_index(
                r.num as usize,
            )),
            _ => None,
        })?;
        // Thumb LDR (literal): `LDR Rt, [PC, #imm]` is decoded as a Label
        // operand holding the byte offset. The base is Align(PC+4, 4).
        if let Some(off) = insn.operands.iter().find_map(|o| match o {
            Operand::Label(l) => Some(*l),
            _ => None,
        }) {
            let base = self.cpu.regs[15].wrapping_add(4) & !0x3;
            let address = base.wrapping_add(off as u32);
            return Some((t, address, None));
        }
        let mem = insn.operands.iter().find_map(|o| match o {
            Operand::Mem(m) => Some(m),
            _ => None,
        })?;
        // T32 LDR/LDRB/LDRH/LDRSB/LDRSH/LDRD literal forms carry Rn=PC in a
        // Mem operand (unlike T16 LDR literal's Label operand). Their base is
        // Align(current instruction address + 4, 4), not the unaligned PC
        // `reg(15)` reads.
        if mem.base.num == 15
            && mem.mode == AddressingMode::Offset
            && matches!(
                insn.mnemonic,
                crate::isa::arm::decoder::Mnemonic::LDR
                    | crate::isa::arm::decoder::Mnemonic::LDRB
                    | crate::isa::arm::decoder::Mnemonic::LDRH
                    | crate::isa::arm::decoder::Mnemonic::LDRSB
                    | crate::isa::arm::decoder::Mnemonic::LDRSH
                    | crate::isa::arm::decoder::Mnemonic::LDP
            )
        {
            let MemOffset::Imm(offset) = mem.offset else {
                return None;
            };
            let base = self.cpu.regs[15].wrapping_add(4) & !0x3;
            return Some((t, base.wrapping_add(offset as u32), None));
        }
        let n = mem.base.num as usize;
        let base = self.reg(n);
        let offset: i64 = match &mem.offset {
            MemOffset::None => 0,
            MemOffset::Imm(i) => *i,
            MemOffset::Reg(r) => self.reg(r.num as usize) as i64,
            MemOffset::ShiftedReg(sr) => {
                let amount = sr.immediate_amount()?;
                shift_c(
                    self.reg(sr.reg.num as usize),
                    sr.shift_type,
                    u32::from(amount),
                    false,
                )
                .0 as i64
            }
            MemOffset::ExtendedReg(_) => return None,
        };
        let offset_addr = (base as i64).wrapping_add(offset) as u32;
        let (address, wb_addr) = match mem.mode {
            AddressingMode::Offset => (offset_addr, None),
            AddressingMode::PreIndex => (offset_addr, Some(offset_addr)),
            AddressingMode::PostIndex => (base, Some(offset_addr)),
        };
        Some((t, address, wb_addr.filter(|_| n != 15).map(|a| (n, a))))
    }

    pub(crate) fn decode_ldst_operands(
        &self,
        insn: &DecodedInsn,
    ) -> Option<(usize, u32, Option<(usize, u32)>)> {
        if insn.state.is_thumb() {
            return self.decode_mem_thumb(insn);
        }
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
    pub(crate) fn decode_ldst_halfword_operands(
        &self,
        insn: &DecodedInsn,
    ) -> Option<(usize, u32, Option<(usize, u32)>)> {
        if insn.state.is_thumb() {
            return self.decode_mem_thumb(insn);
        }
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
    pub(crate) fn decode_ldstm_operands(&self, insn: &DecodedInsn) -> Option<(usize, u16, bool)> {
        if insn.state.is_thumb() {
            use crate::isa::arm::decoder::Operand;
            let n = insn.operands.iter().find_map(|o| match o {
                Operand::Reg(r) => Some(r.num as usize),
                _ => None,
            })?;
            let reglist = insn.operands.iter().find_map(|o| match o {
                Operand::RegList(rl) => Some(rl.mask),
                _ => None,
            })?;
            // T16 LDM/STM always write back; T32 has an explicit W bit (bit21).
            let wback = if insn.state == crate::isa::arm::ExecutionState::Thumb2 {
                (insn.raw >> 21) & 1 != 0
            } else {
                true
            };
            return Some((n, reglist, wback));
        }
        let w = (insn.raw >> 21) & 1;
        let n = ((insn.raw >> 16) & 0xF) as usize;
        let reglist = (insn.raw & 0xFFFF) as u16;
        Some((n, reglist, w != 0))
    }

    /// Decode register list for PUSH/POP.
    pub(crate) fn decode_reglist(&self, insn: &DecodedInsn) -> Option<u16> {
        // Prefer the decoded register-list operand: for 16-bit Thumb PUSH/POP
        // the raw word's high bits are opcode, not list bits (e.g. POP
        // {r2,r3,r4} = 0xbc1c, whose bit15 would wrongly read as PC).
        if let Some(mask) = insn.operands.iter().find_map(|o| match o {
            crate::isa::arm::decoder::Operand::RegList(rl) => Some(rl.mask),
            _ => None,
        }) {
            return Some(mask as u16);
        }
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
    decoder: &crate::isa::arm::decoder::Decoder,
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
        let advance_it = executor.cpu.cpsr.t && executor.cpu.cpsr.in_it_block();
        let result = executor.execute(&insn);
        instructions_executed += 1;

        match result {
            ExecResult::Continue => {
                // Advance PC
                executor.cpu.regs[15] = executor.cpu.regs[15].wrapping_add(insn.size as u32);
                if advance_it {
                    executor.cpu.cpsr.advance_it_state();
                }
            }
            ExecResult::Branch(target) => {
                executor.cpu.regs[15] = target;
                if advance_it {
                    executor.cpu.cpsr.advance_it_state();
                }
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

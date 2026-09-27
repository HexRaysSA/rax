//! 16-bit Thumb instructions (Armv7-M ARM, DDI 0403E.e, A5.2).

use super::Fault;
use super::alu::{self, Shift};
use crate::isa::arm::common::cpu::CpuExit;
use crate::isa::arm::cortex_m::cpu::CortexMCpu;

impl CortexMCpu {
    /// Dispatches a 16-bit instruction (Table A5-1).
    pub(super) fn execute16(&mut self, hw: u16) -> Result<CpuExit, Fault> {
        let insn = u32::from(hw);
        match insn >> 10 {
            0b000000..=0b001111 => self.t16_shift_add_sub_mov_cmp(insn)?,
            0b010000 => self.t16_data_processing(insn)?,
            0b010001 => self.t16_special_data_branch(insn)?,
            0b010010 | 0b010011 => {
                // LDR (literal) T1.
                let address = self.pc_aligned().wrapping_add((insn & 0xFF) << 2);
                let value = self.mem_u(address, 4)?;
                self.set_r((insn >> 8) & 7, value);
            }
            0b010100..=0b100111 => self.t16_load_store(insn)?,
            0b101000 | 0b101001 => {
                // ADR T1.
                let value = self.pc_aligned().wrapping_add((insn & 0xFF) << 2);
                self.set_r((insn >> 8) & 7, value);
            }
            0b101010 | 0b101011 => {
                // ADD (SP plus immediate) T1.
                let value = self.r(13).wrapping_add((insn & 0xFF) << 2);
                self.set_r((insn >> 8) & 7, value);
            }
            0b101100..=0b101111 => return self.t16_misc(insn),
            0b110000 | 0b110001 => self.t16_stm(insn)?,
            0b110010 | 0b110011 => self.t16_ldm(insn)?,
            0b110100..=0b110111 => return self.t16_cond_branch_svc(insn),
            0b111000 | 0b111001 => {
                // B T2.
                self.require_last_in_it(insn)?;
                let imm32 = (((insn & 0x7FF) << 21) as i32 >> 20) as u32;
                self.branch_write_pc(self.r(15).wrapping_add(imm32));
            }
            _ => return Err(Fault::Undefined(insn)),
        }
        Ok(CpuExit::Continue)
    }

    /// Shift (immediate), add, subtract, move, and compare (A5.2.1).
    fn t16_shift_add_sub_mov_cmp(&mut self, insn: u32) -> Result<(), Fault> {
        let setflags = !self.in_it_block();
        let op = (insn >> 9) & 0x1F;
        let (d, n, m) = (insn & 7, (insn >> 3) & 7, (insn >> 6) & 7);
        let dn = (insn >> 8) & 7;
        let imm8 = insn & 0xFF;
        match op {
            0b00000..=0b01011 => {
                let imm5 = (insn >> 6) & 0x1F;
                if op >> 2 == 0 && imm5 == 0 {
                    // MOV (register) T2: MOVS, not permitted in an IT block.
                    self.require_outside_it(insn)?;
                    let result = self.r(n);
                    self.set_r(d, result);
                    self.update_nz(result);
                    return Ok(());
                }
                let (shift, amount) = alu::decode_imm_shift(op >> 2, imm5);
                let (result, carry) = alu::shift_c(self.r(n), shift, amount, self.flag_c());
                self.set_r(d, result);
                if setflags {
                    self.set_nzc(result, carry);
                }
            }
            0b01100..=0b01111 => {
                let operand = if op & 2 == 0 { self.r(m) } else { m };
                let (result, carry, overflow) = if op & 1 == 0 {
                    alu::add_with_carry(self.r(n), operand, false)
                } else {
                    alu::add_with_carry(self.r(n), !operand, true)
                };
                self.set_r(d, result);
                if setflags {
                    self.set_nzcv(result, carry, overflow);
                }
            }
            0b10000..=0b10011 => {
                // MOV (immediate) T1: the carry is unchanged.
                self.set_r(dn, imm8);
                if setflags {
                    self.update_nz(imm8);
                }
            }
            0b10100..=0b10111 => {
                let (result, carry, overflow) = alu::add_with_carry(self.r(dn), !imm8, true);
                self.set_nzcv(result, carry, overflow);
            }
            _ => {
                let (result, carry, overflow) = if op >> 2 == 0b110 {
                    alu::add_with_carry(self.r(dn), imm8, false)
                } else {
                    alu::add_with_carry(self.r(dn), !imm8, true)
                };
                self.set_r(dn, result);
                if setflags {
                    self.set_nzcv(result, carry, overflow);
                }
            }
        }
        Ok(())
    }

    /// Data processing (A5.2.2).
    fn t16_data_processing(&mut self, insn: u32) -> Result<(), Fault> {
        let setflags = !self.in_it_block();
        let dn = insn & 7;
        let m = (insn >> 3) & 7;
        let a = self.r(dn);
        let b = self.r(m);
        let c = self.flag_c();
        match (insn >> 6) & 0xF {
            op @ (0b0000 | 0b0001 | 0b1100 | 0b1110 | 0b1111) => {
                let result = match op {
                    0b0000 => a & b,
                    0b0001 => a ^ b,
                    0b1100 => a | b,
                    0b1110 => a & !b,
                    _ => !b,
                };
                self.set_r(dn, result);
                if setflags {
                    self.update_nz(result);
                }
            }
            op @ (0b0010 | 0b0011 | 0b0100 | 0b0111) => {
                let shift = match op {
                    0b0010 => Shift::Lsl,
                    0b0011 => Shift::Lsr,
                    0b0100 => Shift::Asr,
                    _ => Shift::Ror,
                };
                let (result, carry) = alu::shift_c(a, shift, b & 0xFF, c);
                self.set_r(dn, result);
                if setflags {
                    self.set_nzc(result, carry);
                }
            }
            op @ (0b0101 | 0b0110) => {
                let (result, carry, overflow) = if op == 0b0101 {
                    alu::add_with_carry(a, b, c)
                } else {
                    alu::add_with_carry(a, !b, c)
                };
                self.set_r(dn, result);
                if setflags {
                    self.set_nzcv(result, carry, overflow);
                }
            }
            0b1000 => self.update_nz(a & b),
            0b1001 => {
                // RSB (immediate) T1: Rd = 0 - Rn.
                let (result, carry, overflow) = alu::add_with_carry(!b, 0, true);
                self.set_r(dn, result);
                if setflags {
                    self.set_nzcv(result, carry, overflow);
                }
            }
            0b1010 => {
                let (result, carry, overflow) = alu::add_with_carry(a, !b, true);
                self.set_nzcv(result, carry, overflow);
            }
            0b1011 => {
                let (result, carry, overflow) = alu::add_with_carry(a, b, false);
                self.set_nzcv(result, carry, overflow);
            }
            _ => {
                // MUL T1: C and V are unchanged.
                let result = a.wrapping_mul(b);
                self.set_r(dn, result);
                if setflags {
                    self.update_nz(result);
                }
            }
        }
        Ok(())
    }

    /// Special data instructions and branch and exchange (A5.2.3).
    fn t16_special_data_branch(&mut self, insn: u32) -> Result<(), Fault> {
        let m = (insn >> 3) & 0xF;
        let dn = ((insn >> 4) & 8) | (insn & 7);
        match (insn >> 6) & 0xF {
            0b0000..=0b0011 => {
                // ADD (register) T2, including the SP forms.
                if dn == 15 && m == 15 {
                    return Err(Fault::Undefined(insn));
                }
                let result = self.r(dn).wrapping_add(self.r(m));
                if dn == 15 {
                    self.require_last_in_it(insn)?;
                    self.branch_write_pc(result);
                } else {
                    self.set_r(dn, result);
                }
            }
            0b0100 => return Err(Fault::Undefined(insn)),
            0b0101..=0b0111 => {
                // CMP (register) T2.
                if (dn < 8 && m < 8) || dn == 15 || m == 15 {
                    return Err(Fault::Undefined(insn));
                }
                let (result, carry, overflow) = alu::add_with_carry(self.r(dn), !self.r(m), true);
                self.set_nzcv(result, carry, overflow);
            }
            0b1000..=0b1011 => {
                // MOV (register) T1.
                let result = self.r(m);
                if dn == 15 {
                    self.require_last_in_it(insn)?;
                    self.branch_write_pc(result);
                } else {
                    self.set_r(dn, result);
                }
            }
            op => {
                if insn & 7 != 0 {
                    return Err(Fault::Undefined(insn));
                }
                self.require_last_in_it(insn)?;
                let target = self.r(m);
                if op & 0b0010 == 0 {
                    self.bx_write_pc(target)?;
                } else {
                    // BLX (register).
                    if m == 15 {
                        return Err(Fault::Undefined(insn));
                    }
                    self.lr = self.insn_addr.wrapping_add(2) | 1;
                    self.blx_write_pc(target);
                }
            }
        }
        Ok(())
    }

    /// Load/store single data item (A5.2.4).
    fn t16_load_store(&mut self, insn: u32) -> Result<(), Fault> {
        let t = insn & 7;
        let n = (insn >> 3) & 7;
        let op_a = insn >> 12;
        let op_b = (insn >> 9) & 7;
        let imm5 = (insn >> 6) & 0x1F;
        match op_a {
            0b0101 => {
                let address = self.r(n).wrapping_add(self.r((insn >> 6) & 7));
                match op_b {
                    0b000 => self.set_mem_u(address, 4, self.r(t))?,
                    0b001 => self.set_mem_u(address, 2, self.r(t))?,
                    0b010 => self.set_mem_u(address, 1, self.r(t))?,
                    0b011 => {
                        let value = self.mem_u(address, 1)? as u8 as i8 as u32;
                        self.set_r(t, value);
                    }
                    0b100 => {
                        let value = self.mem_u(address, 4)?;
                        self.set_r(t, value);
                    }
                    0b101 => {
                        let value = self.mem_u(address, 2)?;
                        self.set_r(t, value);
                    }
                    0b110 => {
                        let value = self.mem_u(address, 1)?;
                        self.set_r(t, value);
                    }
                    _ => {
                        let value = self.mem_u(address, 2)? as u16 as i16 as u32;
                        self.set_r(t, value);
                    }
                }
            }
            _ => {
                let (address, t, size) = match op_a {
                    0b0110 => (self.r(n).wrapping_add(imm5 << 2), t, 4),
                    0b0111 => (self.r(n).wrapping_add(imm5), t, 1),
                    0b1000 => (self.r(n).wrapping_add(imm5 << 1), t, 2),
                    _ => (
                        self.r(13).wrapping_add((insn & 0xFF) << 2),
                        (insn >> 8) & 7,
                        4,
                    ),
                };
                if op_b & 0b100 == 0 {
                    self.set_mem_u(address, size, self.r(t))?;
                } else {
                    let value = self.mem_u(address, size)?;
                    self.set_r(t, value);
                }
            }
        }
        Ok(())
    }

    /// Miscellaneous 16-bit instructions (A5.2.5, Table A5-6).
    fn t16_misc(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let op = (insn >> 5) & 0x7F;
        let (d, m) = (insn & 7, (insn >> 3) & 7);
        match op {
            0b0110011 => {
                // CPS.
                let (disable, affect_pri, affect_fault) =
                    (insn & 0x10 != 0, insn & 2 != 0, insn & 1 != 0);
                if insn & 0xC != 0 || (!affect_pri && !affect_fault) {
                    return Err(Fault::Undefined(insn));
                }
                self.require_outside_it(insn)?;
                if self.privileged() {
                    if affect_pri {
                        self.primask = disable;
                    }
                    if affect_fault {
                        if !disable {
                            self.faultmask = false;
                        } else if self.execution_priority() > -1 {
                            self.faultmask = true;
                        }
                    }
                }
            }
            0b0000000..=0b0000011 => {
                let value = self.r(13).wrapping_add((insn & 0x7F) << 2);
                self.set_r(13, value);
            }
            0b0000100..=0b0000111 => {
                let value = self.r(13).wrapping_sub((insn & 0x7F) << 2);
                self.set_r(13, value);
            }
            0b0001000..=0b0001111
            | 0b0011000..=0b0011111
            | 0b1001000..=0b1001111
            | 0b1011000..=0b1011111 => {
                // CBZ, CBNZ.
                if !self.has_thumb2() {
                    return Err(Fault::Undefined(insn));
                }
                self.require_outside_it(insn)?;
                // imm32 = i:imm5:'0' (i is bit 9, imm5 bits [7:3]).
                let imm32 = ((insn >> 2) & 0x3E) | ((insn >> 3) & 0x40);
                let nonzero = insn & 0x800 != 0;
                if nonzero != (self.r(d) == 0) {
                    self.branch_write_pc(self.r(15).wrapping_add(imm32));
                }
            }
            0b0010000..=0b0010111 => {
                let value = self.r(m);
                let result = match (op >> 1) & 3 {
                    0 => value as u16 as i16 as u32,
                    1 => value as u8 as i8 as u32,
                    2 => value & 0xFFFF,
                    _ => value & 0xFF,
                };
                self.set_r(d, result);
            }
            0b0100000..=0b0101111 => {
                let registers = (insn & 0xFF) | ((insn & 0x100) << 6);
                self.push(registers, insn)?;
            }
            0b1010000..=0b1010011 | 0b1010110..=0b1010111 => {
                let value = self.r(m);
                let result = match (op >> 1) & 3 {
                    0 => value.swap_bytes(),
                    1 => alu::rev16(value),
                    _ => alu::revsh(value),
                };
                self.set_r(d, result);
            }
            0b1100000..=0b1101111 => {
                let registers = (insn & 0xFF) | ((insn & 0x100) << 7);
                self.pop(registers, insn)?;
            }
            0b1111000..=0b1111111 => return self.t16_it_hints(insn),
            _ => return Err(Fault::Undefined(insn)),
        }
        Ok(CpuExit::Continue)
    }

    /// If-Then, and hints (Table A5-7).
    fn t16_it_hints(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let (first_cond, mask) = ((insn >> 4) & 0xF, insn & 0xF);
        if mask != 0 {
            if !self.has_thumb2()
                || first_cond == 0xF
                || (first_cond == 0xE && mask.count_ones() != 1)
            {
                return Err(Fault::Undefined(insn));
            }
            self.require_outside_it(insn)?;
            self.set_it_state((first_cond << 4) | mask);
            return Ok(CpuExit::Continue);
        }
        Ok(self.hint(first_cond))
    }

    /// PUSH: `registers` holds bit 14 for LR.
    pub(super) fn push(&mut self, registers: u32, insn: u32) -> Result<(), Fault> {
        if registers == 0 {
            return Err(Fault::Undefined(insn));
        }
        let sp = self.r(13).wrapping_sub(4 * registers.count_ones());
        let mut address = sp;
        for i in 0..15 {
            if registers & (1 << i) != 0 {
                self.set_mem_a(address, 4, self.r(i))?;
                address = address.wrapping_add(4);
            }
        }
        self.set_r(13, sp);
        Ok(())
    }

    /// POP (A7.7.99): the SP is updated before a PC load, so an exception
    /// return unstacks from the new SP.
    pub(super) fn pop(&mut self, registers: u32, insn: u32) -> Result<(), Fault> {
        if registers == 0 || registers & 0xC000 == 0xC000 {
            return Err(Fault::Undefined(insn));
        }
        if registers & 0x8000 != 0 {
            self.require_last_in_it(insn)?;
        }
        let mut address = self.r(13);
        let mut values = [0u32; 16];
        for (i, value) in values.iter_mut().enumerate() {
            if registers & (1 << i) != 0 {
                *value = self.mem_a(address, 4)?;
                address = address.wrapping_add(4);
            }
        }
        self.set_r(13, self.r(13).wrapping_add(4 * registers.count_ones()));
        for (i, value) in values.iter().enumerate().take(15) {
            if registers & (1 << i) != 0 {
                self.set_r(i as u32, *value);
            }
        }
        if registers & 0x8000 != 0 {
            self.bx_write_pc(values[15])?;
        }
        Ok(())
    }

    /// STM T1: always writes back.
    fn t16_stm(&mut self, insn: u32) -> Result<(), Fault> {
        let n = (insn >> 8) & 7;
        let registers = insn & 0xFF;
        if registers == 0 {
            return Err(Fault::Undefined(insn));
        }
        let base = self.r(n);
        let mut address = base;
        for i in 0..8 {
            if registers & (1 << i) != 0 {
                self.set_mem_a(address, 4, self.r(i))?;
                address = address.wrapping_add(4);
            }
        }
        self.set_r(n, address);
        Ok(())
    }

    /// LDM T1: writes back unless the base is in the list.
    fn t16_ldm(&mut self, insn: u32) -> Result<(), Fault> {
        let n = (insn >> 8) & 7;
        let registers = insn & 0xFF;
        if registers == 0 {
            return Err(Fault::Undefined(insn));
        }
        let mut address = self.r(n);
        let mut values = [0u32; 8];
        for (i, value) in values.iter_mut().enumerate() {
            if registers & (1 << i) != 0 {
                *value = self.mem_a(address, 4)?;
                address = address.wrapping_add(4);
            }
        }
        if registers & (1 << n) == 0 {
            self.set_r(n, address);
        }
        for (i, value) in values.iter().enumerate() {
            if registers & (1 << i) != 0 {
                self.set_r(i as u32, *value);
            }
        }
        Ok(())
    }

    /// Conditional branch, and Supervisor Call (A5.2.6).
    fn t16_cond_branch_svc(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let cond = (insn >> 8) & 0xF;
        match cond {
            0b1110 => Err(Fault::Undefined(insn)),
            0b1111 => Ok(CpuExit::Svc(insn & 0xFF)),
            _ => {
                self.require_outside_it(insn)?;
                if self.condition_passed(cond) {
                    let imm32 = (((insn & 0xFF) << 24) as i32 >> 23) as u32;
                    self.branch_write_pc(self.r(15).wrapping_add(imm32));
                }
                Ok(CpuExit::Continue)
            }
        }
    }
}

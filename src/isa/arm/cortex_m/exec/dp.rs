//! 32-bit data-processing instructions (Armv7-M ARM, DDI 0403E.e, A5.3.1,
//! A5.3.3, A5.3.11 to A5.3.15). Register choices the manual makes
//! UNPREDICTABLE are treated as UNDEFINED.

use super::Fault;
use super::alu::{self, Shift};
use crate::isa::arm::common::cpu::CpuExit;
use crate::isa::arm::cortex_m::cpu::CortexMCpu;

/// SP or PC: UNPREDICTABLE as most operands.
fn bad(r: u32) -> bool {
    r == 13 || r == 15
}

/// The data-processing operation of A5.3.1 / A5.3.11 (`op` field).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DpOp {
    And,
    Bic,
    Orr,
    Orn,
    Eor,
    Add,
    Adc,
    Sbc,
    Sub,
    Rsb,
}

impl CortexMCpu {
    /// Shared tail of the modified-immediate and shifted-register forms:
    /// `operand` is the second operand and `carry` the shifter carry out.
    #[allow(clippy::too_many_arguments)]
    fn dp_common(
        &mut self,
        insn: u32,
        op: u32,
        s: bool,
        n: u32,
        d: u32,
        operand: u32,
        carry: bool,
        operand_reg: Option<u32>,
    ) -> Result<CpuExit, Fault> {
        let m_bad = operand_reg.is_some_and(bad);
        let kind = match op {
            0b0000 => DpOp::And,
            0b0001 => DpOp::Bic,
            0b0010 => DpOp::Orr,
            0b0011 => DpOp::Orn,
            0b0100 => DpOp::Eor,
            0b1000 => DpOp::Add,
            0b1010 => DpOp::Adc,
            0b1011 => DpOp::Sbc,
            0b1101 => DpOp::Sub,
            0b1110 => DpOp::Rsb,
            _ => return Err(Fault::Undefined(insn)),
        };
        let compare = d == 15 && matches!(kind, DpOp::And | DpOp::Eor | DpOp::Add | DpOp::Sub);
        if d == 15 && !compare {
            return Err(Fault::Undefined(insn));
        }
        if compare && !s {
            return Err(Fault::Undefined(insn));
        }
        let move_form = n == 15 && matches!(kind, DpOp::Orr | DpOp::Orn);
        let sp_form = n == 13 && matches!(kind, DpOp::Add | DpOp::Sub);
        let invalid = match kind {
            DpOp::Add | DpOp::Sub => {
                n == 15 || m_bad || (d == 13 && !sp_form) || (compare && n == 15)
            }
            DpOp::Orr | DpOp::Orn if move_form => {
                // MOV/MVN; the shifted-register MOV has its own entry.
                bad(d) || m_bad
            }
            _ => (bad(d) && !compare) || bad(n) || m_bad,
        };
        if invalid {
            return Err(Fault::Undefined(insn));
        }
        let a = if move_form { 0 } else { self.r(n) };
        let c = self.flag_c();
        let (result, carry, overflow, logical) = match kind {
            DpOp::And => (a & operand, carry, false, true),
            DpOp::Bic => (a & !operand, carry, false, true),
            DpOp::Orr => (a | operand, carry, false, true),
            DpOp::Orn => (a | !operand, carry, false, true),
            DpOp::Eor => (a ^ operand, carry, false, true),
            DpOp::Add => {
                let (r, c, v) = alu::add_with_carry(a, operand, false);
                (r, c, v, false)
            }
            DpOp::Adc => {
                let (r, c, v) = alu::add_with_carry(a, operand, c);
                (r, c, v, false)
            }
            DpOp::Sbc => {
                let (r, c, v) = alu::add_with_carry(a, !operand, c);
                (r, c, v, false)
            }
            DpOp::Sub => {
                let (r, c, v) = alu::add_with_carry(a, !operand, true);
                (r, c, v, false)
            }
            DpOp::Rsb => {
                let (r, c, v) = alu::add_with_carry(!a, operand, true);
                (r, c, v, false)
            }
        };
        if !compare {
            self.set_r(d, result);
        }
        if s {
            if logical {
                self.set_nzc(result, carry);
            } else {
                self.set_nzcv(result, carry, overflow);
            }
        }
        Ok(CpuExit::Continue)
    }

    /// Data processing (modified immediate), A5.3.1.
    pub(super) fn dp_modified_immediate(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op = (hw1 >> 5) & 0xF;
        let s = hw1 & 0x10 != 0;
        let n = hw1 & 0xF;
        let d = (insn >> 8) & 0xF;
        let imm12 = ((hw1 & 0x400) << 1) | ((insn >> 4) & 0x700) | (insn & 0xFF);
        let (imm32, carry) =
            alu::thumb_expand_imm_c(imm12, self.flag_c()).ok_or(Fault::Undefined(insn))?;
        self.dp_common(insn, op, s, n, d, imm32, carry, None)
    }

    /// Data processing (shifted register), A5.3.11.
    pub(super) fn dp_shifted_register(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op = (hw1 >> 5) & 0xF;
        let s = hw1 & 0x10 != 0;
        let n = hw1 & 0xF;
        let d = (insn >> 8) & 0xF;
        let m = insn & 0xF;
        let ty = (insn >> 4) & 3;
        let imm5 = ((insn >> 10) & 0x1C) | ((insn >> 6) & 3);
        if insn & 0x8000 != 0 {
            return Err(Fault::Undefined(insn));
        }
        if op == 0b0110 {
            return self.pkh(insn, s, n, d, m, ty, imm5);
        }
        if op == 0b0010 && n == 15 {
            return self.move_shift_immediate(insn, s, d, m, ty, imm5);
        }
        let (shift, amount) = alu::decode_imm_shift(ty, imm5);
        if n == 13
            && d == 13
            && matches!(op, 0b1000 | 0b1101)
            && (shift != Shift::Lsl || amount > 3)
        {
            return Err(Fault::Undefined(insn));
        }
        let (operand, carry) = alu::shift_c(self.r(m), shift, amount, self.flag_c());
        self.dp_common(insn, op, s, n, d, operand, carry, Some(m))
    }

    /// MOV (register) T3 and the immediate shifts (Table A5-23).
    fn move_shift_immediate(
        &mut self,
        insn: u32,
        s: bool,
        d: u32,
        m: u32,
        ty: u32,
        imm5: u32,
    ) -> Result<CpuExit, Fault> {
        let plain_move = ty == 0 && imm5 == 0;
        let invalid = if plain_move && !s {
            d == 15 || m == 15 || (d == 13 && m == 13)
        } else {
            bad(d) || bad(m)
        };
        if invalid {
            return Err(Fault::Undefined(insn));
        }
        let (shift, amount) = alu::decode_imm_shift(ty, imm5);
        let (result, carry) = alu::shift_c(self.r(m), shift, amount, self.flag_c());
        self.set_r(d, result);
        if s {
            self.set_nzc(result, carry);
        }
        Ok(CpuExit::Continue)
    }

    /// PKHBT, PKHTB (Armv7E-M).
    #[allow(clippy::too_many_arguments)]
    fn pkh(
        &mut self,
        insn: u32,
        s: bool,
        n: u32,
        d: u32,
        m: u32,
        ty: u32,
        imm5: u32,
    ) -> Result<CpuExit, Fault> {
        if !self.has_dsp() || s || ty & 1 != 0 || bad(d) || bad(n) || bad(m) {
            return Err(Fault::Undefined(insn));
        }
        let tb = ty & 2 != 0;
        let (shift, amount) = alu::decode_imm_shift(ty, imm5);
        let operand = alu::shift(self.r(m), shift, amount, self.flag_c());
        let rn = self.r(n);
        let result = if tb {
            (rn & 0xFFFF_0000) | (operand & 0xFFFF)
        } else {
            (operand & 0xFFFF_0000) | (rn & 0xFFFF)
        };
        self.set_r(d, result);
        Ok(CpuExit::Continue)
    }

    /// Data processing (plain binary immediate), A5.3.3.
    pub(super) fn dp_plain_immediate(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op = (hw1 >> 4) & 0x1F;
        let n = hw1 & 0xF;
        let d = (insn >> 8) & 0xF;
        let imm12 = ((hw1 & 0x400) << 1) | ((insn >> 4) & 0x700) | (insn & 0xFF);
        let imm5 = ((insn >> 10) & 0x1C) | ((insn >> 6) & 3);
        let low5 = insn & 0x1F;
        let undefined = Err(Fault::Undefined(insn));
        match op {
            0b00000 | 0b01010 => {
                // ADDW / SUBW, ADR (T3 / T2).
                let sub = op == 0b01010;
                if d == 15 || (d == 13 && n != 13) {
                    return undefined;
                }
                let base = if n == 15 {
                    self.pc_aligned()
                } else {
                    self.r(n)
                };
                let result = if sub {
                    base.wrapping_sub(imm12)
                } else {
                    base.wrapping_add(imm12)
                };
                self.set_r(d, result);
            }
            0b00100 | 0b01100 => {
                // MOVW / MOVT.
                if bad(d) {
                    return undefined;
                }
                let imm16 = ((hw1 & 0xF) << 12) | imm12;
                let result = if op == 0b00100 {
                    imm16
                } else {
                    (imm16 << 16) | (self.r(d) & 0xFFFF)
                };
                self.set_r(d, result);
            }
            0b10000 | 0b10010 | 0b11000 | 0b11010 => {
                if bad(d) || bad(n) || insn & 0x20 != 0 {
                    return undefined;
                }
                let signed = op & 0b01000 == 0;
                let sh = op & 0b00010 != 0;
                if sh && imm5 == 0 {
                    return self.saturate16(insn, signed, n, d);
                }
                let (shift, amount) = alu::decode_imm_shift(if sh { 2 } else { 0 }, imm5);
                let operand = alu::shift(self.r(n), shift, amount, self.flag_c()) as i32;
                let (result, saturated) = if signed {
                    alu::signed_sat_q(i64::from(operand), low5 + 1)
                } else {
                    alu::unsigned_sat_q(i64::from(operand), low5)
                };
                self.set_r(d, result);
                if saturated {
                    self.set_q_flag();
                }
            }
            0b10100 | 0b11100 => {
                // SBFX / UBFX.
                let msbit = imm5 + low5;
                if bad(d) || bad(n) || msbit > 31 || insn & 0x20 != 0 {
                    return undefined;
                }
                let width = low5 + 1;
                let field = self.r(n) >> imm5;
                let result = if width == 32 {
                    field
                } else if op == 0b10100 {
                    (((field << (32 - width)) as i32) >> (32 - width)) as u32
                } else {
                    field & ((1 << width) - 1)
                };
                self.set_r(d, result);
            }
            0b10110 => {
                // BFI / BFC.
                let (lsbit, msbit) = (imm5, low5);
                if bad(d) || n == 13 || msbit < lsbit || insn & 0x20 != 0 {
                    return undefined;
                }
                let width = msbit - lsbit + 1;
                let mask = if width == 32 {
                    u32::MAX
                } else {
                    ((1u32 << width) - 1) << lsbit
                };
                let source = if n == 15 { 0 } else { self.r(n) << lsbit };
                let result = (self.r(d) & !mask) | (source & mask);
                self.set_r(d, result);
            }
            _ => return undefined,
        }
        Ok(CpuExit::Continue)
    }

    /// SSAT16 / USAT16 (Armv7E-M).
    fn saturate16(&mut self, insn: u32, signed: bool, n: u32, d: u32) -> Result<CpuExit, Fault> {
        if !self.has_dsp() || insn & 0x30 != 0 {
            return Err(Fault::Undefined(insn));
        }
        let sat = insn & 0xF;
        let value = self.r(n);
        let mut result = 0;
        let mut saturated = false;
        for lane in 0..2 {
            let half = (value >> (16 * lane)) as u16 as i16 as i64;
            let (r, s) = if signed {
                alu::signed_sat_q(half, sat + 1)
            } else {
                alu::unsigned_sat_q(half, sat)
            };
            result |= (r & 0xFFFF) << (16 * lane);
            saturated |= s;
        }
        self.set_r(d, result);
        if saturated {
            self.set_q_flag();
        }
        Ok(CpuExit::Continue)
    }

    /// Data processing (register), A5.3.12.
    pub(super) fn dp_register(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        if (insn >> 12) & 0xF != 0xF {
            return Err(Fault::Undefined(insn));
        }
        let hw1 = insn >> 16;
        let op1 = (hw1 >> 4) & 0xF;
        let op2 = (insn >> 4) & 0xF;
        let n = hw1 & 0xF;
        let d = (insn >> 8) & 0xF;
        let m = insn & 0xF;
        if op1 < 8 && op2 == 0 {
            // LSL/LSR/ASR/ROR (register).
            if bad(d) || bad(n) || bad(m) {
                return Err(Fault::Undefined(insn));
            }
            let shift = Shift::from_type(op1 >> 1);
            let (result, carry) = alu::shift_c(self.r(n), shift, self.r(m) & 0xFF, self.flag_c());
            self.set_r(d, result);
            if op1 & 1 != 0 {
                self.set_nzc(result, carry);
            }
            return Ok(CpuExit::Continue);
        }
        if op1 < 6 && op2 & 0b1000 != 0 {
            return self.extend(insn, op1, op2, n, d, m);
        }
        if op1 & 0b1000 != 0 && op2 & 0b1100 == 0 {
            return self.parallel(insn, true, op1 & 7, op2 & 3, n, d, m);
        }
        if op1 & 0b1000 != 0 && op2 & 0b1100 == 0b0100 {
            return self.parallel(insn, false, op1 & 7, op2 & 3, n, d, m);
        }
        if op1 & 0b1100 == 0b1000 && op2 & 0b1100 == 0b1000 {
            return self.misc_operations(insn, op1 & 3, op2 & 3, n, d, m);
        }
        Err(Fault::Undefined(insn))
    }

    /// SXT*, UXT* and the extend-and-add forms.
    fn extend(
        &mut self,
        insn: u32,
        op1: u32,
        op2: u32,
        n: u32,
        d: u32,
        m: u32,
    ) -> Result<CpuExit, Fault> {
        let add = n != 15;
        let dual = op1 & 0b0110 == 0b0010;
        if op2 & 0b0100 != 0 || bad(d) || bad(m) || n == 13 || ((add || dual) && !self.has_dsp()) {
            return Err(Fault::Undefined(insn));
        }
        let rotated = self.r(m).rotate_right((op2 & 3) * 8);
        let base = if add { self.r(n) } else { 0 };
        let result = match op1 {
            0b0000 => base.wrapping_add(rotated as u16 as i16 as u32),
            0b0001 => base.wrapping_add(rotated & 0xFFFF),
            0b0100 => base.wrapping_add(rotated as u8 as i8 as u32),
            0b0101 => base.wrapping_add(rotated & 0xFF),
            _ => {
                let signed = op1 == 0b0010;
                let lane = |byte: u32| -> u32 {
                    let b = (rotated >> byte) & 0xFF;
                    if signed { b as u8 as i8 as u32 } else { b }
                };
                let lo = (base & 0xFFFF).wrapping_add(lane(0)) & 0xFFFF;
                let hi = (base >> 16).wrapping_add(lane(16)) & 0xFFFF;
                (hi << 16) | lo
            }
        };
        self.set_r(d, result);
        Ok(CpuExit::Continue)
    }

    /// Parallel addition and subtraction (A5.3.13, A5.3.14): `op` selects
    /// ADD16/ASX/SAX/SUB16/ADD8/SUB8, `kind` modular (with GE), saturating,
    /// or halving.
    #[allow(clippy::too_many_arguments)]
    fn parallel(
        &mut self,
        insn: u32,
        signed: bool,
        op: u32,
        kind: u32,
        n: u32,
        d: u32,
        m: u32,
    ) -> Result<CpuExit, Fault> {
        if !self.has_dsp() || kind == 3 || op == 0b011 || op == 0b111 || bad(d) || bad(n) || bad(m)
        {
            return Err(Fault::Undefined(insn));
        }
        let (a, b) = (self.r(n), self.r(m));
        let bytes = op == 0b000 || op == 0b100;
        let width = if bytes { 8 } else { 16 };
        let lanes = 32 / width;
        let lane = |x: u32, i: u32| -> i64 {
            let v = (x >> (i * width)) & ((1 << width) - 1);
            if signed {
                ((v << (32 - width)) as i32 >> (32 - width)) as i64
            } else {
                i64::from(v)
            }
        };
        let mut result = 0u32;
        let mut ge = 0u32;
        for i in 0..lanes {
            // Lane `i` of the result: for ASX/SAX the lanes cross.
            let (x, y, subtract) = match op {
                0b001 | 0b000 => (lane(a, i), lane(b, i), false),
                0b101 | 0b100 => (lane(a, i), lane(b, i), true),
                0b010 => (lane(a, i), lane(b, 1 - i), i == 0),
                _ => (lane(a, i), lane(b, 1 - i), i == 1),
            };
            let value = if subtract { x - y } else { x + y };
            let (bits, ge_set) = match kind {
                0 => {
                    let ge_set = if signed || subtract {
                        value >= 0
                    } else {
                        value >= 1 << width
                    };
                    (value as u32, ge_set)
                }
                1 => {
                    let (r, _) = if signed {
                        alu::signed_sat_q(value, width)
                    } else {
                        alu::unsigned_sat_q(value, width)
                    };
                    (r, false)
                }
                _ => ((value >> 1) as u32, false),
            };
            result |= (bits & ((1 << width) - 1)) << (i * width);
            if ge_set {
                ge |= if bytes { 1 << i } else { 0b11 << (2 * i) };
            }
        }
        self.set_r(d, result);
        if kind == 0 {
            self.set_ge(ge);
        }
        Ok(CpuExit::Continue)
    }

    /// Miscellaneous operations (A5.3.15).
    fn misc_operations(
        &mut self,
        insn: u32,
        op1: u32,
        op2: u32,
        n: u32,
        d: u32,
        m: u32,
    ) -> Result<CpuExit, Fault> {
        if bad(d) || bad(n) || bad(m) {
            return Err(Fault::Undefined(insn));
        }
        let (rn, rm) = (self.r(n), self.r(m));
        let result = match (op1, op2) {
            (0b00, _) => {
                if !self.has_dsp() {
                    return Err(Fault::Undefined(insn));
                }
                // QADD, QDADD, QSUB, QDSUB: Rm op (2 x) Rn.
                let mut saturated = false;
                let mut addend = i64::from(rn as i32);
                if op2 & 1 != 0 {
                    let (doubled, sat) = alu::signed_sat_q(2 * addend, 32);
                    saturated |= sat;
                    addend = i64::from(doubled as i32);
                }
                let value = if op2 & 2 == 0 {
                    i64::from(rm as i32) + addend
                } else {
                    i64::from(rm as i32) - addend
                };
                let (result, sat) = alu::signed_sat_q(value, 32);
                if saturated || sat {
                    self.set_q_flag();
                }
                result
            }
            (0b01, _) | (0b11, 0b00) => {
                // Rm is encoded in both register fields.
                if n != m {
                    return Err(Fault::Undefined(insn));
                }
                match (op1, op2) {
                    (0b01, 0b00) => rm.swap_bytes(),
                    (0b01, 0b01) => alu::rev16(rm),
                    (0b01, 0b10) => rm.reverse_bits(),
                    (0b01, _) => alu::revsh(rm),
                    _ => rm.leading_zeros(),
                }
            }
            (0b10, 0b00) => {
                if !self.has_dsp() {
                    return Err(Fault::Undefined(insn));
                }
                let ge = self.ge();
                (0..4).fold(0, |acc, i| {
                    let source = if ge & (1 << i) != 0 { rn } else { rm };
                    acc | (source & (0xFF << (8 * i)))
                })
            }
            _ => return Err(Fault::Undefined(insn)),
        };
        self.set_r(d, result);
        Ok(CpuExit::Continue)
    }
}

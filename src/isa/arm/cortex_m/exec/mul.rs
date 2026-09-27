//! Multiply, multiply-accumulate, and divide (Armv7-M ARM, DDI 0403E.e,
//! A5.3.16 and A5.3.17). Register choices the manual makes UNPREDICTABLE
//! are treated as UNDEFINED.

use super::Fault;
use crate::isa::arm::common::cpu::CpuExit;
use crate::isa::arm::cortex_m::cpu::CortexMCpu;

fn bad(r: u32) -> bool {
    r == 13 || r == 15
}

/// The signed low (`top == false`) or high halfword of `x`.
fn half(x: u32, top: bool) -> i64 {
    i64::from(if top { (x >> 16) as i16 } else { x as i16 })
}

/// Whether a result wider than 32 bits differs from its low word read as
/// signed (the Q-flag test of the saturating accumulates).
fn overflows32(result: i64) -> bool {
    result != i64::from(result as i32)
}

impl CortexMCpu {
    /// Multiply, multiply accumulate, and absolute difference (A5.3.16).
    pub(super) fn multiply(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op1 = (hw1 >> 4) & 7;
        let op2 = (insn >> 4) & 3;
        let a = (insn >> 12) & 0xF;
        let d = (insn >> 8) & 0xF;
        let n = hw1 & 0xF;
        let m = insn & 0xF;
        let undefined = Err(Fault::Undefined(insn));
        if insn & 0xC0 != 0 || bad(d) || bad(n) || bad(m) || a == 13 {
            return undefined;
        }
        let accumulate = a != 15;
        if op1 != 0 && !self.has_dsp() {
            return undefined;
        }
        let (rn, rm) = (self.r(n), self.r(m));
        let acc = if accumulate { self.r(a) } else { 0 };
        let result = match (op1, op2) {
            (0b000, 0b00) => acc.wrapping_add(rn.wrapping_mul(rm)),
            (0b000, 0b01) => {
                if !accumulate {
                    return undefined;
                }
                acc.wrapping_sub(rn.wrapping_mul(rm))
            }
            (0b001, _) => {
                // SMLA<x><y>, SMUL<x><y>: N is bit 5, M bit 4.
                let product = half(rn, op2 & 2 != 0) * half(rm, op2 & 1 != 0);
                let result = product + i64::from(acc as i32);
                if accumulate && overflows32(result) {
                    self.set_q_flag();
                }
                result as u32
            }
            (0b010 | 0b100, 0b00 | 0b01) => {
                // SMLAD{X}, SMUAD{X}, SMLSD{X}, SMUSD{X}.
                let operand = if op2 & 1 != 0 {
                    rm.rotate_right(16)
                } else {
                    rm
                };
                let product1 = half(rn, false) * half(operand, false);
                let product2 = half(rn, true) * half(operand, true);
                let sum = if op1 == 0b010 {
                    product1 + product2
                } else {
                    product1 - product2
                };
                let result = sum + i64::from(acc as i32);
                if overflows32(result) {
                    self.set_q_flag();
                }
                result as u32
            }
            (0b011, 0b00 | 0b01) => {
                // SMLAW<y>, SMULW<y>.
                let product = i64::from(rn as i32) * half(rm, op2 & 1 != 0);
                let result = product + (i64::from(acc as i32) << 16);
                let high = result >> 16;
                if accumulate && overflows32(high) {
                    self.set_q_flag();
                }
                high as u32
            }
            (0b101 | 0b110, 0b00 | 0b01) => {
                // SMMLA{R}, SMMUL{R}, SMMLS{R}.
                if op1 == 0b110 && !accumulate {
                    return undefined;
                }
                let product = i64::from(rn as i32) * i64::from(rm as i32);
                let base = i64::from(acc as i32) << 32;
                let mut result = if op1 == 0b101 {
                    base.wrapping_add(product)
                } else {
                    base.wrapping_sub(product)
                };
                if op2 & 1 != 0 {
                    result = result.wrapping_add(0x8000_0000);
                }
                (result >> 32) as u32
            }
            (0b111, 0b00) => {
                // USAD8, USADA8.
                let sum: u32 = (0..4)
                    .map(|i| {
                        let x = (rn >> (8 * i)) & 0xFF;
                        let y = (rm >> (8 * i)) & 0xFF;
                        x.abs_diff(y)
                    })
                    .sum();
                acc.wrapping_add(sum)
            }
            _ => return undefined,
        };
        self.set_r(d, result);
        Ok(CpuExit::Continue)
    }

    /// Long multiply, long multiply accumulate, and divide (A5.3.17).
    pub(super) fn long_multiply_divide(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op1 = (hw1 >> 4) & 7;
        let op2 = (insn >> 4) & 0xF;
        let lo = (insn >> 12) & 0xF;
        let hi = (insn >> 8) & 0xF;
        let n = hw1 & 0xF;
        let m = insn & 0xF;
        let undefined = Err(Fault::Undefined(insn));
        if bad(n) || bad(m) {
            return undefined;
        }
        if matches!((op1, op2), (0b001 | 0b011, 0b1111)) {
            // SDIV, UDIV: Rd is bits [11:8]; bits [15:12] are 0b1111.
            let d = hi;
            if lo != 0xF || bad(d) {
                return undefined;
            }
            let (rn, rm) = (self.r(n), self.r(m));
            let result = if rm == 0 {
                if self.scb().div_by_zero_trap() {
                    return Err(Fault::DivideByZero);
                }
                0
            } else if op1 == 0b001 {
                // RoundTowardsZero; 0x80000000 / -1 wraps to 0x80000000.
                (i64::from(rn as i32) / i64::from(rm as i32)) as u32
            } else {
                rn / rm
            };
            self.set_r(d, result);
            return Ok(CpuExit::Continue);
        }
        if bad(lo) || bad(hi) || lo == hi {
            return undefined;
        }
        let dsp = match (op1, op2) {
            (0b000 | 0b010 | 0b100 | 0b110, 0b0000) => false,
            (0b100, 0b1000..=0b1011 | 0b1100 | 0b1101)
            | (0b101, 0b1100 | 0b1101)
            | (0b110, 0b0110) => true,
            _ => return undefined,
        };
        if dsp && !self.has_dsp() {
            return undefined;
        }
        let (rn, rm) = (self.r(n), self.r(m));
        let acc = (u64::from(self.r(hi)) << 32) | u64::from(self.r(lo));
        let result: u64 = match (op1, op2) {
            (0b000, _) => (i64::from(rn as i32) * i64::from(rm as i32)) as u64,
            (0b010, _) => u64::from(rn) * u64::from(rm),
            (0b100, 0b0000) => {
                ((i64::from(rn as i32) * i64::from(rm as i32)) as u64).wrapping_add(acc)
            }
            (0b110, 0b0000) => (u64::from(rn) * u64::from(rm)).wrapping_add(acc),
            (0b110, _) => {
                u64::from(rn) * u64::from(rm) + u64::from(self.r(hi)) + u64::from(self.r(lo))
            }
            (0b100, 0b1000..=0b1011) => {
                // SMLAL<x><y>: N is bit 5, M bit 4.
                let product = half(rn, op2 & 2 != 0) * half(rm, op2 & 1 != 0);
                (product as u64).wrapping_add(acc)
            }
            _ => {
                // SMLALD{X}, SMLSLD{X}.
                let operand = if op2 & 1 != 0 {
                    rm.rotate_right(16)
                } else {
                    rm
                };
                let product1 = half(rn, false) * half(operand, false);
                let product2 = half(rn, true) * half(operand, true);
                let sum = if op1 == 0b100 {
                    product1 + product2
                } else {
                    product1 - product2
                };
                (sum as u64).wrapping_add(acc)
            }
        };
        self.set_r(lo, result as u32);
        self.set_r(hi, (result >> 32) as u32);
        Ok(CpuExit::Continue)
    }
}

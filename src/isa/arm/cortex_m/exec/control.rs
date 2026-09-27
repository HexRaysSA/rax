//! Branches, hints, barriers, and the special-register moves (Armv7-M ARM,
//! DDI 0403E.e, A5.3.4 and B5.2).

use super::Fault;
use crate::isa::arm::common::cpu::CpuExit;
use crate::isa::arm::cortex_m::cpu::CortexMCpu;

/// The special-register numbers `MRS` and `MSR` accept (B5.1.1, Table
/// B5-1): the xPSR views, MSP, PSP, PRIMASK, BASEPRI, BASEPRI_MAX,
/// FAULTMASK, and CONTROL.
fn valid_sysm(sysm: u32) -> bool {
    matches!(sysm, 0..=3 | 5..=9 | 16..=20)
}

impl CortexMCpu {
    /// Branches and miscellaneous control (A5.3.4, Table A5-13).
    pub(super) fn branches_misc(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op = (hw1 >> 4) & 0x7F;
        let op1 = (insn >> 12) & 7;
        if !self.has_thumb2()
            && !(op1 & 0b101 == 0b101 || (op1 & 0b101 == 0 && op & 0b0111000 == 0b0111000))
        {
            // Armv6-M keeps BL, MSR, MRS, the barriers, and UDF.
            return Err(Fault::Undefined(insn));
        }
        match op1 {
            0b000 | 0b010 => {
                if op & 0b0111000 != 0b0111000 {
                    return self.branch_conditional(insn);
                }
                match op {
                    0b0111000 | 0b0111001 => self.msr(insn)?,
                    0b0111010 => {
                        if (insn >> 8) & 7 != 0 {
                            return Err(Fault::Undefined(insn));
                        }
                        let hint = insn & 0xFF;
                        return Ok(match hint {
                            // NOP, YIELD, WFE, WFI, SEV.
                            0..=4 => self.hint(hint),
                            // CSDB, DBG, and the unallocated hints.
                            _ => CpuExit::Continue,
                        });
                    }
                    0b0111011 => match (insn >> 4) & 0xF {
                        // CLREX.
                        0b0010 => self.memory.clear_exclusive(),
                        // DSB (and SSBB, PSSBB), DMB, ISB: memory is
                        // sequentially consistent here.
                        0b0100..=0b0110 => {}
                        _ => return Err(Fault::Undefined(insn)),
                    },
                    0b0111110 | 0b0111111 => self.mrs(insn)?,
                    _ => return Err(Fault::Undefined(insn)),
                }
            }
            0b001 | 0b011 => {
                // B T4.
                self.require_last_in_it(insn)?;
                let target = self.r(15).wrapping_add(branch_offset24(insn));
                self.branch_write_pc(target);
            }
            0b101 | 0b111 => {
                // BL.
                self.require_last_in_it(insn)?;
                let target = self.r(15).wrapping_add(branch_offset24(insn));
                self.lr = self.r(15) | 1;
                self.branch_write_pc(target);
            }
            _ => return Err(Fault::Undefined(insn)),
        }
        Ok(CpuExit::Continue)
    }

    /// B T3: `S:J2:J1:imm6:imm11:'0'`.
    fn branch_conditional(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        self.require_outside_it(insn)?;
        let hw1 = insn >> 16;
        let cond = (hw1 >> 6) & 0xF;
        let s = (hw1 >> 10) & 1;
        let j1 = (insn >> 13) & 1;
        let j2 = (insn >> 11) & 1;
        let imm =
            (s << 20) | (j2 << 19) | (j1 << 18) | ((hw1 & 0x3F) << 12) | ((insn & 0x7FF) << 1);
        let offset = ((imm << 11) as i32 >> 11) as u32;
        if self.condition_passed(cond) {
            self.branch_write_pc(self.r(15).wrapping_add(offset));
        }
        Ok(CpuExit::Continue)
    }

    /// NOP, YIELD, WFE, WFI, SEV (A7.7.x); other hints execute as NOPs.
    pub(super) fn hint(&mut self, hint: u32) -> CpuExit {
        match hint {
            2 => {
                if self.event_register {
                    self.event_register = false;
                    CpuExit::Continue
                } else {
                    self.sleeping = true;
                    CpuExit::Wfe
                }
            }
            3 => {
                self.sleeping = true;
                CpuExit::Wfi
            }
            4 => {
                // SEV signals this processor too.
                self.event_register = true;
                CpuExit::Continue
            }
            _ => CpuExit::Continue,
        }
    }

    /// MRS (B5.2.2).
    fn mrs(&mut self, insn: u32) -> Result<(), Fault> {
        let d = (insn >> 8) & 0xF;
        let sysm = insn & 0xFF;
        if d == 13 || d == 15 || !valid_sysm(sysm) {
            return Err(Fault::Undefined(insn));
        }
        let privileged = self.privileged();
        let value = match sysm >> 3 {
            0 => {
                let mut value = 0;
                if sysm & 1 != 0 {
                    value |= self.xpsr & 0x1FF;
                }
                // EPSR reads as zero.
                if sysm & 4 == 0 {
                    value |= self.xpsr & 0xF800_0000;
                    if self.has_dsp() {
                        value |= self.xpsr & 0x000F_0000;
                    }
                }
                value
            }
            1 if !privileged => 0,
            1 => {
                if sysm & 7 == 0 {
                    self.sp_main
                } else {
                    self.sp_process
                }
            }
            _ => match sysm & 7 {
                0 if privileged => u32::from(self.primask),
                1 | 2 if privileged => u32::from(self.basepri),
                3 if privileged => u32::from(self.faultmask),
                4 => u32::from(self.control & 3),
                _ => 0,
            },
        };
        self.set_r(d, value);
        Ok(())
    }

    /// MSR (register) (B5.2.3).
    fn msr(&mut self, insn: u32) -> Result<(), Fault> {
        let n = (insn >> 16) & 0xF;
        let mask = (insn >> 10) & 3;
        let sysm = insn & 0xFF;
        if n == 13
            || n == 15
            || !valid_sysm(sysm)
            || mask == 0
            || (mask != 0b10 && sysm > 3)
            || (mask & 1 != 0 && !self.has_dsp())
        {
            return Err(Fault::Undefined(insn));
        }
        let value = self.r(n);
        let privileged = self.privileged();
        match sysm >> 3 {
            0 => {
                // Writes to IPSR and EPSR are ignored.
                if sysm & 4 == 0 {
                    if mask & 1 != 0 {
                        self.xpsr = (self.xpsr & !0x000F_0000) | (value & 0x000F_0000);
                    }
                    if mask & 2 != 0 {
                        self.xpsr = (self.xpsr & !0xF800_0000) | (value & 0xF800_0000);
                    }
                }
            }
            1 if privileged => {
                if sysm & 7 == 0 {
                    self.sp_main = value & !3;
                } else {
                    self.sp_process = value & !3;
                }
            }
            1 => {}
            _ if !privileged => {}
            _ => match sysm & 7 {
                0 => self.primask = value & 1 != 0,
                1 => self.basepri = value as u8,
                2 => {
                    let new = value as u8;
                    if new != 0 && (new < self.basepri || self.basepri == 0) {
                        self.basepri = new;
                    }
                }
                3 => {
                    if self.execution_priority() > -1 {
                        self.faultmask = value & 1 != 0;
                    }
                }
                _ => {
                    // CONTROL: nPRIV always, SPSEL in Thread mode only; FPCA
                    // needs the Floating-point Extension.
                    self.control = (self.control & !1) | (value as u8 & 1);
                    if self.thread_mode {
                        self.control = (self.control & !2) | (value as u8 & 2);
                    }
                }
            },
        }
        Ok(())
    }
}

/// B T4 / BL offset: `S:I1:I2:imm10:imm11:'0'` with `I = NOT(J XOR S)`.
fn branch_offset24(insn: u32) -> u32 {
    let hw1 = insn >> 16;
    let s = (hw1 >> 10) & 1;
    let j1 = (insn >> 13) & 1;
    let j2 = (insn >> 11) & 1;
    let i1 = !(j1 ^ s) & 1;
    let i2 = !(j2 ^ s) & 1;
    let imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((insn & 0x7FF) << 1);
    ((imm << 7) as i32 >> 7) as u32
}

//! The Floating-point Extension (FPv5-D16, the Cortex-M7's), in part: the
//! extension register loads and stores (VLDR, VSTR, VLDM, VSTM, VPUSH,
//! VPOP), the transfers between core and extension registers (VMOV of one
//! or two core registers, of a 32-bit scalar; VMRS, VMSR) and VMOV between
//! extension registers or of an immediate. The other data-processing
//! instructions (VADD to VCVT) and the FPv5 additions (VSEL, VMAXNM, VRINT,
//! VCVTA) are not implemented and report UNDEFINED.
//!
//! Encodings: Armv7-M Architecture Reference Manual (DDI 0403E.e), A6.4
//! "Floating-point instruction encoding" and the A7.7 instruction pages.

use super::Fault;
use crate::isa::arm::common::cpu::CpuExit;
use crate::isa::arm::cortex_m::cpu::CortexMCpu;
use crate::isa::arm::cortex_m::ppb::{FPCCR_ASPEN, FPDSCR_MASK};

/// CONTROL.FPCA: the FP context is active.
pub(in crate::isa::arm::cortex_m) const CONTROL_FPCA: u8 = 1 << 2;
/// The FPSCR bits of the M profile: N, Z, C, V, AHP, DN, FZ, RMode and the
/// cumulative exception flags.
pub(in crate::isa::arm::cortex_m) const FPSCR_MASK: u32 = 0xF7C0_009F;
/// Single-precision registers.
const S_REGS: u32 = 32;
/// Double-precision registers of FPv5-D16.
const D_REGS: u32 = 16;

impl CortexMCpu {
    /// A coprocessor instruction (A5.3.18): the FPU's (CP10 and CP11) when
    /// it is present and CPACR gives access, else NOCP.
    pub(super) fn coprocessor(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let coproc = (insn >> 8) & 0xF;
        if self.vfp.is_none() || coproc & 0b1110 != 0b1010 || !self.fp_access() {
            return Err(Fault::NoCoprocessor(insn));
        }
        // 0b1111 in bits 31:28: the FPv5 additions.
        if insn >> 28 != 0b1110 {
            return Err(Fault::Undefined(insn));
        }
        self.fp_check();
        match (insn >> 24) & 0xF {
            0b1100 | 0b1101 => self.fp_load_store(insn),
            0b1110 if insn & (1 << 4) == 0 => self.fp_data_processing(insn),
            0b1110 => self.fp_transfer(insn),
            _ => Err(Fault::Undefined(insn)),
        }
    }

    /// CPACR.CP10: full access, or privileged access only.
    fn fp_access(&self) -> bool {
        match (self.ppb.cpacr >> 20) & 3 {
            0b11 => true,
            0b01 => self.privileged(),
            _ => false,
        }
    }

    /// `ExecuteFPCheck()` (B1.5.7): with FPCCR.ASPEN, the first FP
    /// instruction of a context sets CONTROL.FPCA and takes the FPSCR
    /// defaults of FPDSCR.
    fn fp_check(&mut self) {
        if self.ppb.fpccr & FPCCR_ASPEN != 0 && self.control & CONTROL_FPCA == 0 {
            self.control |= CONTROL_FPCA;
            let defaults = self.ppb.fpdscr & FPDSCR_MASK;
            let vfp = self.vfp_mut();
            let fpscr = vfp.read_fpscr();
            vfp.write_fpscr((fpscr & !FPDSCR_MASK) | defaults);
        }
    }

    fn vfp_mut(&mut self) -> &mut crate::isa::arm::aarch32::vfp::VfpState {
        self.vfp
            .as_mut()
            .expect("FP instructions run only with the FPU")
    }

    fn s(&self, n: u32) -> u32 {
        self.vfp.as_ref().map_or(0, |v| v.read_s_bits(n as u8))
    }

    fn set_s(&mut self, n: u32, value: u32) {
        self.vfp_mut().write_s_bits(n as u8, value);
    }

    fn d(&self, n: u32) -> u64 {
        self.vfp.as_ref().map_or(0, |v| v.read_d_bits(n as u8))
    }

    fn set_d(&mut self, n: u32, value: u64) {
        self.vfp_mut().write_d_bits(n as u8, value);
    }

    /// The first register of a single (`Vd:D`) or double (`D:Vd`) operand,
    /// from its 4-bit field and its extra bit.
    fn fp_register(double: bool, field: u32, extra: u32) -> u32 {
        if double {
            (extra << 4) | field
        } else {
            (field << 1) | extra
        }
    }

    /// Extension register loads and stores, and the 64-bit transfers
    /// (A6.5, A6.6): `1110 110P UDWL Rn | Vd 101s imm8`.
    fn fp_load_store(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let p = insn & (1 << 24) != 0;
        let u = insn & (1 << 23) != 0;
        let w = insn & (1 << 21) != 0;
        let load = insn & (1 << 20) != 0;
        if !p && !u && !w {
            return self.fp_transfer64(insn);
        }
        let rn = (insn >> 16) & 0xF;
        let double = insn & (1 << 8) != 0;
        let imm8 = insn & 0xFF;
        let first = Self::fp_register(double, (insn >> 12) & 0xF, (insn >> 22) & 1);

        if p && !w {
            // VLDR, VSTR (A7.7.250, A7.7.272): PC-relative through Align(PC, 4).
            if double && first >= D_REGS {
                return Err(Fault::Undefined(insn));
            }
            let base = if rn == 15 {
                self.pc_aligned()
            } else {
                self.r(rn)
            };
            let address = if u {
                base.wrapping_add(imm8 * 4)
            } else {
                base.wrapping_sub(imm8 * 4)
            };
            match (double, load) {
                (true, true) => {
                    let low = self.mem_a(address, 4)?;
                    let high = self.mem_a(address.wrapping_add(4), 4)?;
                    self.set_d(first, u64::from(low) | (u64::from(high) << 32));
                }
                (true, false) => {
                    let value = self.d(first);
                    self.set_mem_a(address, 4, value as u32)?;
                    self.set_mem_a(address.wrapping_add(4), 4, (value >> 32) as u32)?;
                }
                (false, true) => {
                    let value = self.mem_a(address, 4)?;
                    self.set_s(first, value);
                }
                (false, false) => self.set_mem_a(address, 4, self.s(first))?,
            }
            return Ok(CpuExit::Continue);
        }

        // VLDM, VSTM (A7.7.249, A7.7.271), VPUSH and VPOP among them:
        // increment after (P=0, U=1) or decrement before with writeback
        // (P=1, U=0, W=1). An odd imm8 for doubles (FLDMX, FSTMX) moves
        // imm8 / 2 registers and writes back imm8 words.
        if p == u || (rn == 15 && w) {
            return Err(Fault::Undefined(insn));
        }
        let registers = if double { imm8 / 2 } else { imm8 };
        let limit = if double { D_REGS } else { S_REGS };
        if registers == 0 || first + registers > limit {
            return Err(Fault::Undefined(insn));
        }
        let words = if double { 2 * registers } else { registers };
        let base = self.r(rn);
        let start = if u { base } else { base.wrapping_sub(imm8 * 4) };
        if load {
            // all the words first: a fault leaves the registers unchanged
            let mut values = [0u32; 32];
            for (i, value) in values.iter_mut().enumerate().take(words as usize) {
                *value = self.mem_a(start.wrapping_add(4 * i as u32), 4)?;
            }
            for i in 0..registers {
                if double {
                    let (low, high) = (values[2 * i as usize], values[2 * i as usize + 1]);
                    self.set_d(first + i, u64::from(low) | (u64::from(high) << 32));
                } else {
                    self.set_s(first + i, values[i as usize]);
                }
            }
        } else {
            for i in 0..registers {
                if double {
                    let value = self.d(first + i);
                    let address = start.wrapping_add(8 * i);
                    self.set_mem_a(address, 4, value as u32)?;
                    self.set_mem_a(address.wrapping_add(4), 4, (value >> 32) as u32)?;
                } else {
                    self.set_mem_a(start.wrapping_add(4 * i), 4, self.s(first + i))?;
                }
            }
        }
        if w {
            let written = if u {
                base.wrapping_add(imm8 * 4)
            } else {
                start
            };
            self.set_r(rn, written);
        }
        Ok(CpuExit::Continue)
    }

    /// VMOV between two core registers and a double, or two singles
    /// (A7.7.244, A7.7.245): `1110 1100 010L Rt2 | Rt 101s 00M1 Vm`.
    fn fp_transfer64(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let to_core = insn & (1 << 20) != 0;
        let rt2 = (insn >> 16) & 0xF;
        let rt = (insn >> 12) & 0xF;
        let double = insn & (1 << 8) != 0;
        let m = Self::fp_register(double, insn & 0xF, (insn >> 5) & 1);
        let bad_core = |r: u32| r == 13 || r == 15;
        if insn & 0xD0 != 0x10
            || bad_core(rt)
            || bad_core(rt2)
            || (to_core && rt == rt2)
            || (double && m >= D_REGS)
            || (!double && m == S_REGS - 1)
        {
            return Err(Fault::Undefined(insn));
        }
        match (double, to_core) {
            (true, true) => {
                let value = self.d(m);
                self.set_r(rt, value as u32);
                self.set_r(rt2, (value >> 32) as u32);
            }
            (true, false) => {
                let value = u64::from(self.r(rt)) | (u64::from(self.r(rt2)) << 32);
                self.set_d(m, value);
            }
            (false, true) => {
                let (low, high) = (self.s(m), self.s(m + 1));
                self.set_r(rt, low);
                self.set_r(rt2, high);
            }
            (false, false) => {
                let (low, high) = (self.r(rt), self.r(rt2));
                self.set_s(m, low);
                self.set_s(m + 1, high);
            }
        }
        Ok(CpuExit::Continue)
    }

    /// The 8-, 16- and 32-bit transfers (A6.7): VMOV between a core register
    /// and a single or a 32-bit scalar, VMRS, VMSR.
    fn fp_transfer(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let to_core = insn & (1 << 20) != 0;
        let c = insn & (1 << 8) != 0;
        let a = (insn >> 21) & 7;
        let rt = (insn >> 12) & 0xF;
        let bad_core = rt == 13 || rt == 15;
        match (c, a) {
            // VMOV between a core register and a single (A7.7.243):
            // `1110 1110 000L Vn | Rt 1010 N001 0000`.
            (false, 0b000) => {
                let n = Self::fp_register(false, (insn >> 16) & 0xF, (insn >> 7) & 1);
                if insn & 0x7F != 0x10 || bad_core {
                    return Err(Fault::Undefined(insn));
                }
                if to_core {
                    self.set_r(rt, self.s(n));
                } else {
                    self.set_s(n, self.r(rt));
                }
            }
            // VMRS, VMSR (A7.7.247, A7.7.248): FPSCR only on the M profile;
            // VMRS to R15 copies its flags to APSR.
            (false, 0b111) => {
                if (insn >> 16) & 0xF != 1 || insn & 0xFF != 0x10 {
                    return Err(Fault::Undefined(insn));
                }
                let fpscr = self.vfp_mut().read_fpscr();
                match (to_core, rt) {
                    (true, 15) => self.xpsr = (self.xpsr & !0xF000_0000) | (fpscr & 0xF000_0000),
                    (true, 13) => return Err(Fault::Undefined(insn)),
                    (true, _) => self.set_r(rt, fpscr),
                    (false, _) if bad_core => return Err(Fault::Undefined(insn)),
                    (false, _) => {
                        let value = self.r(rt) & FPSCR_MASK;
                        self.vfp_mut().write_fpscr(value);
                    }
                }
            }
            // VMOV between a core register and a 32-bit scalar (A7.7.241,
            // A7.7.242): `1110 1110 00xL Vd | Rt 1011 D001 0000`, x the
            // word; the 8- and 16-bit forms need Advanced SIMD.
            (true, 0b000 | 0b001) => {
                let d = Self::fp_register(true, (insn >> 16) & 0xF, (insn >> 7) & 1);
                if insn & 0x7F != 0x10 || bad_core || d >= D_REGS {
                    return Err(Fault::Undefined(insn));
                }
                let shift = 32 * (a & 1);
                let value = self.d(d);
                if to_core {
                    self.set_r(rt, (value >> shift) as u32);
                } else {
                    let word = u64::from(self.r(rt)) << shift;
                    self.set_d(d, (value & !(u64::from(u32::MAX) << shift)) | word);
                }
            }
            _ => return Err(Fault::Undefined(insn)),
        }
        Ok(CpuExit::Continue)
    }

    /// FP data processing (A6.4): only VMOV (register) and VMOV (immediate)
    /// are implemented, `1110 1110 1D11 imm4H/opc2 | Vd 101s opc3 M 0 imm4L/Vm`.
    fn fp_data_processing(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        // opc1 (bits 23:20) without D (bit 22)
        let opc1 = (insn >> 20) & 0b1011;
        let opc2 = (insn >> 16) & 0xF;
        let opc3 = (insn >> 6) & 3;
        let double = insn & (1 << 8) != 0;
        let d = Self::fp_register(double, (insn >> 12) & 0xF, (insn >> 22) & 1);
        if opc1 != 0b1011 || (double && d >= D_REGS) {
            return Err(Fault::Undefined(insn));
        }
        if opc3 & 1 == 0 {
            // VMOV (immediate) (A7.7.239): VFPExpandImm of imm4H:imm4L; bits
            // 7 and 5 are zero.
            if insn & 0xA0 != 0 {
                return Err(Fault::Undefined(insn));
            }
            let imm8 = (opc2 << 4) | (insn & 0xF);
            if double {
                self.set_d(d, expand_imm64(imm8));
            } else {
                self.set_s(d, expand_imm32(imm8));
            }
            return Ok(CpuExit::Continue);
        }
        if opc3 != 0b01 || opc2 != 0 {
            return Err(Fault::Undefined(insn));
        }
        // VMOV (register) (A7.7.240).
        let m = Self::fp_register(double, insn & 0xF, (insn >> 5) & 1);
        if double {
            if m >= D_REGS {
                return Err(Fault::Undefined(insn));
            }
            self.set_d(d, self.d(m));
        } else {
            self.set_s(d, self.s(m));
        }
        Ok(CpuExit::Continue)
    }
}

/// `VFPExpandImm(imm8, 32)`: sign imm8<7>, exponent NOT(imm8<6>) then
/// imm8<6> five times then imm8<5:4>, fraction imm8<3:0> then 19 zeros.
fn expand_imm32(imm8: u32) -> u32 {
    let b6 = (imm8 >> 6) & 1;
    ((imm8 >> 7) << 31)
        | ((b6 ^ 1) << 30)
        | ((b6 * 0b1_1111) << 25)
        | (((imm8 >> 4) & 3) << 23)
        | ((imm8 & 0xF) << 19)
}

/// `VFPExpandImm(imm8, 64)`: sign imm8<7>, exponent NOT(imm8<6>) then
/// imm8<6> eight times then imm8<5:4>, fraction imm8<3:0> then 48 zeros.
fn expand_imm64(imm8: u32) -> u64 {
    let imm8 = u64::from(imm8);
    let b6 = (imm8 >> 6) & 1;
    ((imm8 >> 7) << 63)
        | ((b6 ^ 1) << 62)
        | ((b6 * 0xFF) << 54)
        | (((imm8 >> 4) & 3) << 52)
        | ((imm8 & 0xF) << 48)
}

#[cfg(test)]
#[path = "fp_tests.rs"]
mod tests;

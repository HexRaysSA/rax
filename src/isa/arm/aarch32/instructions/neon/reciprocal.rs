//! A32 reciprocal estimate and refinement instruction execution.
use super::*;
use crate::isa::arm::aarch32::vfp::{
    vrecpe_f16_bits, vrecpe_f32, vrecps_f16_bits, vrecps_f32, vrsqrte_f16_bits, vrsqrte_f32,
    vrsqrts_f16_bits, vrsqrts_f32,
};
use crate::smir::interpret::SmirInterpreter;
impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(crate) fn exec_neon_recip_estimate(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 23) != 0b111100111
            || ((insn.raw >> 20) & 0x3) != 0b11
            || ((insn.raw >> 16) & 0x3) != 0b11
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let size = (insn.raw >> 18) & 0x3;
        let fp = match ((insn.raw >> 7) & 0x1F, insn.mnemonic) {
            (0b01000, Mnemonic::VRECPE) | (0b01001, Mnemonic::VRSQRTE) => false,
            (0b01010, Mnemonic::VRECPE) | (0b01011, Mnemonic::VRSQRTE) => true,
            _ => return ExecResult::Undefined,
        };
        if (!fp && size != 0b10) || (fp && !matches!(size, 0b01 | 0b10)) {
            return ExecResult::Undefined;
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = ((insn.raw >> 6) & 1) != 0;
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let m = (m_bit << 4) | vm;
        if q && ((d | m) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || m + regs > 32 {
            return ExecResult::Undefined;
        }

        let mut fpscr = self.standard_simd_fp_controls();
        let ebytes = if fp && size == 0b01 { 2 } else { 4 };
        for reg in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let result = match (insn.mnemonic, fp) {
                    (Mnemonic::VRECPE, false) => {
                        u64::from(Self::neon_unsigned_recip_estimate(elem as u32))
                    }
                    (Mnemonic::VRSQRTE, false) => {
                        u64::from(Self::neon_unsigned_rsqrt_estimate(elem as u32))
                    }
                    (Mnemonic::VRECPE, true) if size == 0b01 => {
                        u64::from(vrecpe_f16_bits(elem as u16, &mut fpscr))
                    }
                    (Mnemonic::VRSQRTE, true) if size == 0b01 => {
                        u64::from(vrsqrte_f16_bits(elem as u16, &mut fpscr))
                    }
                    (Mnemonic::VRECPE, true) => {
                        u64::from(vrecpe_f32(f32::from_bits(elem as u32), &mut fpscr).to_bits())
                    }
                    (Mnemonic::VRSQRTE, true) => {
                        u64::from(vrsqrte_f32(f32::from_bits(elem as u32), &mut fpscr).to_bits())
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        self.cpu.vfp.fpscr = Fpscr::from_bits(self.cpu.vfp.fpscr.bits() | (fpscr.bits() & 0x9f));
        ExecResult::Continue
    }

    pub(crate) fn neon_recip_estimate(value: u32) -> u32 {
        SmirInterpreter::arm_recip_estimate(value)
    }
    pub(crate) fn neon_recip_sqrt_estimate(value: u32) -> u32 {
        SmirInterpreter::arm_recip_sqrt_estimate(value)
    }

    pub(crate) fn neon_unsigned_recip_estimate(op: u32) -> u32 {
        if op & 0x8000_0000 == 0 {
            return u32::MAX;
        }
        let estimate = Self::neon_recip_estimate((op >> 23) & 0x1FF);
        (estimate & 0x1FF) << 23
    }

    pub(crate) fn neon_unsigned_rsqrt_estimate(op: u32) -> u32 {
        if op & 0xC000_0000 == 0 {
            return u32::MAX;
        }
        let estimate = Self::neon_recip_sqrt_estimate((op >> 23) & 0x1FF);
        (estimate & 0x1FF) << 23
    }

    pub(crate) fn exec_neon_recip_step(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 24) & 1) != 0
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 8) & 0xF) != 0b1111
            || ((insn.raw >> 4) & 1) != 1
        {
            return ExecResult::Undefined;
        }

        match (insn.mnemonic, (insn.raw >> 21) & 1) {
            (Mnemonic::VRECPS, 0) | (Mnemonic::VRSQRTS, 1) => {}
            _ => return ExecResult::Undefined,
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = ((insn.raw >> 6) & 1) != 0;
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if q && ((d | n | m) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || n + regs > 32 || m + regs > 32 {
            return ExecResult::Undefined;
        }

        let size = if ((insn.raw >> 20) & 1) == 0 {
            NeonSize::S32
        } else {
            NeonSize::H16
        };
        let ebytes = (size.bits() / 8) as u8;

        let mut fpscr = self.standard_simd_fp_controls();
        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let result = match size {
                    NeonSize::S32 => {
                        let lhs = f32::from_bits(n_elem as u32);
                        let rhs = f32::from_bits(m_elem as u32);
                        let value = if insn.mnemonic == Mnemonic::VRECPS {
                            vrecps_f32(lhs, rhs, &mut fpscr)
                        } else {
                            vrsqrts_f32(lhs, rhs, &mut fpscr)
                        };
                        u64::from(value.to_bits())
                    }
                    NeonSize::H16 => {
                        let value = if insn.mnemonic == Mnemonic::VRECPS {
                            vrecps_f16_bits(n_elem as u16, m_elem as u16, &mut fpscr)
                        } else {
                            vrsqrts_f16_bits(n_elem as u16, m_elem as u16, &mut fpscr)
                        };
                        u64::from(value)
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        self.cpu.vfp.fpscr = Fpscr::from_bits(self.cpu.vfp.fpscr.bits() | (fpscr.bits() & 0x9f));
        ExecResult::Continue
    }
}

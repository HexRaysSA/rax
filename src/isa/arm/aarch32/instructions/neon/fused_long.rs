//! Mixed half-product/single-accumulator vector and indexed execution.
use super::*;
use crate::isa::arm::aarch32::vfp::vfmal_f32_f16_bits;
impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(crate) fn exec_neon_fp16_fused_multiply_long(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if !Self::is_neon_fp16_fused_multiply_long_shape(insn.raw) {
            return ExecResult::Undefined;
        }

        let vector = (insn.raw >> 24) == 0xFC;
        let subtract = if vector {
            ((insn.raw >> 23) & 1) != 0
        } else {
            ((insn.raw >> 20) & 1) != 0
        };
        match (insn.mnemonic, subtract) {
            (Mnemonic::VFMAL, false) | (Mnemonic::VFMLS, true) => {}
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
        if q && (d & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 {
            return ExecResult::Undefined;
        }

        let n = if q {
            (n_bit << 4) | vn
        } else {
            (vn << 1) | n_bit
        };
        let m = if vector {
            if q {
                (m_bit << 4) | vm
            } else {
                (vm << 1) | m_bit
            }
        } else if q {
            vm & 0x7
        } else {
            ((vm & 0x7) << 1) | m_bit
        };
        if n >= 32 || m >= 32 {
            return ExecResult::Undefined;
        }

        let index = if !vector {
            Some(if q { (m_bit << 1) | (vm >> 3) } else { vm >> 3 })
        } else {
            None
        };
        let scalar = index.map(|lane| {
            if q {
                self.neon_read_d_elem_u64(m, lane, 2) as u16
            } else {
                ((self.cpu.vfp.read_s_bits(m) >> (lane * 16)) & 0xFFFF) as u16
            }
        });

        let mut fpscr = self.standard_simd_fp_controls();
        let operand1 = if q {
            self.cpu.vfp.read_d_bits(n)
        } else {
            u64::from(self.cpu.vfp.read_s_bits(n))
        };
        let operand2 = if scalar.is_some() {
            0
        } else if q {
            self.cpu.vfp.read_d_bits(m)
        } else {
            u64::from(self.cpu.vfp.read_s_bits(m))
        };
        for reg in 0..regs {
            let acc = self.cpu.vfp.read_d_bits(d + reg);
            let mut out = 0u64;
            for lane in 0..2 {
                let source_lane = if q { 2 * reg + lane } else { lane };
                let shift = source_lane * 16;
                let mut lhs = ((operand1 >> shift) & 0xFFFF) as u16;
                let rhs = scalar.unwrap_or_else(|| ((operand2 >> shift) & 0xFFFF) as u16);
                if subtract {
                    lhs ^= 0x8000;
                }
                let acc_lane = (acc >> (lane * 32)) as u32;
                let result = vfmal_f32_f16_bits(acc_lane, lhs, rhs, &mut fpscr);
                out |= u64::from(result) << (lane * 32);
            }
            self.cpu.vfp.write_d_bits(d + reg, out);
        }

        self.cpu.vfp.fpscr = Fpscr::from_bits(self.cpu.vfp.fpscr.bits() | (fpscr.bits() & 0x9f));
        ExecResult::Continue
    }
}

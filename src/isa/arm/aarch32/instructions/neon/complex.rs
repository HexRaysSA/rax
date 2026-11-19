//! Complex addition and fused multiply-accumulate using StandardFPCR.
use super::*;
use crate::isa::arm::decoder::Aarch32Decoder;

impl<M: ArmMemory> Executor<'_, M> {
    pub(crate) fn exec_neon_complex(&mut self, insn: &DecodedInsn) -> ExecResult {
        let Some(Ok(fields)) = Aarch32Decoder::complex_simd_fields(insn.raw) else {
            return ExecResult::Undefined;
        };
        if fields.mnemonic != insn.mnemonic {
            return ExecResult::Undefined;
        }

        let bits = fields.element_bits;
        let mask = (1u64 << bits) - 1;
        let sign = 1u64 << (bits - 1);
        let element = |word: u64, lane: u8| (word >> (bits * lane)) & mask;
        let scalar = fields.index.map(|index| {
            let word = self.cpu.vfp.read_d_bits(fields.m);
            (element(word, index * 2), element(word, index * 2 + 1))
        });
        let mut fpscr = self.standard_simd_fp_controls();
        for register in 0..fields.registers {
            let lhs = self.cpu.vfp.read_d_bits(fields.n + register);
            let dst = self.cpu.vfp.read_d_bits(fields.d + register);
            let rhs = if scalar.is_some() {
                0
            } else {
                self.cpu.vfp.read_d_bits(fields.m + register)
            };
            let mut out = 0;
            for lane in (0..64 / bits).step_by(2) {
                let (real, imaginary) =
                    scalar.unwrap_or_else(|| (element(rhs, lane), element(rhs, lane + 1)));
                let rotated = match fields.rotation {
                    0 => [real, imaginary],
                    1 => [imaginary ^ sign, real],
                    2 => [real ^ sign, imaginary ^ sign],
                    _ => [imaginary, real ^ sign],
                };
                let multiplier = element(lhs, lane + (fields.rotation & 1));
                for (offset, rhs) in (0..2).zip(rotated) {
                    let lane = lane + offset;
                    let result = if fields.mnemonic == Mnemonic::VCADD {
                        add(bits, element(lhs, lane), rhs, &mut fpscr)
                    } else {
                        fused(bits, element(dst, lane), multiplier, rhs, &mut fpscr)
                    };
                    out |= result << (bits * lane);
                }
            }
            self.cpu.vfp.write_d_bits(fields.d + register, out);
        }
        self.cpu.vfp.fpscr = Fpscr::from_bits(self.cpu.vfp.fpscr.bits() | (fpscr.bits() & 0x9f));
        ExecResult::Continue
    }
}

fn add(bits: u8, lhs: u64, rhs: u64, fpscr: &mut Fpscr) -> u64 {
    if bits == 16 {
        u64::from(vadd_f16_bits(lhs as u16, rhs as u16, fpscr))
    } else {
        u64::from(
            vadd_f32(
                f32::from_bits(lhs as u32),
                f32::from_bits(rhs as u32),
                fpscr,
            )
            .to_bits(),
        )
    }
}

fn fused(bits: u8, acc: u64, lhs: u64, rhs: u64, fpscr: &mut Fpscr) -> u64 {
    if bits == 16 {
        u64::from(vfma_f16_bits(acc as u16, lhs as u16, rhs as u16, fpscr))
    } else {
        u64::from(
            vfma_f32(
                f32::from_bits(acc as u32),
                f32::from_bits(lhs as u32),
                f32::from_bits(rhs as u32),
                fpscr,
            )
            .to_bits(),
        )
    }
}

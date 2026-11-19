//! Four byte products accumulated modulo 2^32 in each destination lane.
use super::*;
use crate::isa::arm::decoder::Aarch32Decoder;

impl<M: ArmMemory> Executor<'_, M> {
    pub(crate) fn exec_neon_dot_product(&mut self, insn: &DecodedInsn) -> ExecResult {
        let Some(Ok(fields)) = Aarch32Decoder::dot_product_fields(insn.raw) else {
            return ExecResult::Undefined;
        };
        if fields.mnemonic != insn.mnemonic {
            return ExecResult::Undefined;
        }

        let signed = fields.mnemonic == Mnemonic::VSDOT;
        // Capture the indexed source before either half of Qd can overwrite it.
        let indexed = fields
            .index
            .map(|index| (self.cpu.vfp.read_d_bits(fields.m) >> (32 * index)) as u32);
        let extend = |byte: u8| {
            if signed {
                i32::from(byte as i8)
            } else {
                i32::from(byte)
            }
        };
        for register in 0..fields.registers {
            let lhs = self.cpu.vfp.read_d_bits(fields.n + register);
            let dst = self.cpu.vfp.read_d_bits(fields.d + register);
            let rhs = if indexed.is_none() {
                self.cpu.vfp.read_d_bits(fields.m + register)
            } else {
                0
            };
            let mut result = 0;
            for shift in [0, 32] {
                let left = ((lhs >> shift) as u32).to_le_bytes();
                let right = indexed.unwrap_or((rhs >> shift) as u32).to_le_bytes();
                let products = left
                    .into_iter()
                    .zip(right)
                    .map(|(a, b)| extend(a) * extend(b))
                    .sum::<i32>();
                let lane = ((dst >> shift) as u32).wrapping_add_signed(products);
                result |= u64::from(lane) << shift;
            }
            self.cpu.vfp.write_d_bits(fields.d + register, result);
        }
        ExecResult::Continue
    }
}

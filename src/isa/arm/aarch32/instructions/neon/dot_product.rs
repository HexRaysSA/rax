//! AdvSIMD byte products accumulated modulo 2^32 in each destination lane.
use super::*;
use crate::isa::arm::common::int8;
use crate::isa::arm::decoder::Aarch32Decoder;
use crate::isa::arm::decoder::aarch32::ProductShape;

impl<M: ArmMemory> Executor<'_, M> {
    pub(crate) fn exec_neon_int8_product(&mut self, insn: &DecodedInsn) -> ExecResult {
        let Some(Ok(fields)) = Aarch32Decoder::int8_product_fields(insn.raw) else {
            return ExecResult::Undefined;
        };
        if fields.mnemonic != insn.mnemonic {
            return ExecResult::Undefined;
        }

        let signed = match fields.mnemonic {
            Mnemonic::VSDOT | Mnemonic::VSMMLA => (true, true),
            Mnemonic::VSUDOT => (true, false),
            Mnemonic::VUSDOT | Mnemonic::VUSMMLA => (false, true),
            _ => (false, false),
        };
        let ProductShape::Dot { registers, index } = fields.shape else {
            let read = |reg| {
                let (low, high) = self.cpu.vfp.read_q(reg);
                u128::from(low) | (u128::from(high) << 64)
            };
            let result = int8::matrix_accumulate(
                read(fields.d >> 1),
                read(fields.n >> 1),
                read(fields.m >> 1),
                signed,
            );
            self.cpu
                .vfp
                .write_q(fields.d >> 1, result as u64, (result >> 64) as u64);
            return ExecResult::Continue;
        };
        // Capture the indexed source before either half of Qd can overwrite it.
        let indexed =
            index.map(|index| (self.cpu.vfp.read_d_bits(fields.m) >> (32 * index)) as u32);
        for register in 0..registers {
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
                let products = int8::dot(left, right, signed);
                let lane = ((dst >> shift) as u32).wrapping_add_signed(products);
                result |= u64::from(lane) << shift;
            }
            self.cpu.vfp.write_d_bits(fields.d + register, result);
        }
        ExecResult::Continue
    }
}

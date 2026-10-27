//! Raw FP16 register packing/extraction; no floating-point arithmetic/status effects.
use super::*;
use crate::isa::arm::decoder::Aarch32Decoder;
impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(crate) fn exec_half_register_move(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !Aarch32Decoder::decode_vfp_half_register(insn.raw).is_some_and(|decoded| {
            decoded.mnemonic == insn.mnemonic && decoded.mnemonic != Mnemonic::UNDEFINED
        }) {
            return ExecResult::Undefined;
        }
        if self.cpu.cpsr.t && self.cpu.cpsr.in_it_block() {
            return ExecResult::Undefined;
        }
        if insn.mnemonic != Mnemonic::VMOV_F16_CORE && self.cpu.vfp.fpscr.bits() & 0x00370000 != 0 {
            return ExecResult::Undefined;
        }
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if insn.mnemonic == Mnemonic::VMOV_F16_CORE {
            let t = ((insn.raw >> 12) & 15) as usize;
            let n = ((((insn.raw >> 16) & 15) << 1) | ((insn.raw >> 7) & 1)) as u8;
            if insn.raw & (1 << 20) != 0 {
                self.cpu.regs[t] = self.cpu.vfp.read_s_bits(n) & 0xffff;
            } else {
                self.cpu.vfp.write_s_bits(n, self.cpu.regs[t] & 0xffff);
            }
        } else {
            let d = ((((insn.raw >> 12) & 15) << 1) | ((insn.raw >> 22) & 1)) as u8;
            let m = (((insn.raw & 15) << 1) | ((insn.raw >> 5) & 1)) as u8;
            let source = self.cpu.vfp.read_s_bits(m);
            let original = self.cpu.vfp.read_s_bits(d);
            let value = if insn.mnemonic == Mnemonic::VMOVX_F16 {
                source >> 16
            } else {
                (source << 16) | (original & 0xffff)
            };
            self.cpu.vfp.write_s_bits(d, value);
        }
        ExecResult::Continue
    }
}

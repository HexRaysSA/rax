//! A32 scalar fixed, SIMD integer/fixed and half/double precision conversion.
use super::*;
use crate::isa::arm::aarch32::vfp::{vcvt_f16_bits_f64, vcvt_f64_f16_bits_with_fpscr};
use crate::isa::arm::decoder::Aarch32Decoder;
use crate::smir::interpret::SmirInterpreter;
fn fixed_element(
    raw: u64,
    fp_bits: u32,
    integer_bits: u32,
    fractional_bits: u32,
    signed: bool,
    to_fixed: bool,
    fpscr: &mut Fpscr,
) -> u64 {
    let (result, status) = SmirInterpreter::arm_eval_a32_fixed_conversion(
        raw,
        fp_bits,
        integer_bits,
        fractional_bits,
        signed,
        to_fixed,
        fpscr.bits(),
    );
    *fpscr = Fpscr::from_bits(fpscr.bits() | status);
    result
}
impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(crate) fn exec_scalar_fixed_convert(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some(fields) = Aarch32Decoder::scalar_fixed_fields(insn.raw) else {
            return ExecResult::Undefined;
        };
        if fields.mnemonic == Mnemonic::UNDEFINED || fields.mnemonic != insn.mnemonic {
            return ExecResult::Undefined;
        }
        let raw = if fields.fp_bits == 64 {
            self.cpu.vfp.read_d_bits(fields.d)
        } else {
            u64::from(self.cpu.vfp.read_s_bits(fields.d))
        };
        let mut result = fixed_element(
            raw,
            fields.fp_bits,
            fields.integer_bits,
            fields.fractional_bits,
            fields.signed,
            fields.to_fixed,
            &mut self.cpu.vfp.fpscr,
        );
        if fields.to_fixed && fields.signed {
            result = if fields.integer_bits == 16 {
                result as i16 as i64 as u64
            } else {
                result as i32 as i64 as u64
            };
        }
        if fields.fp_bits == 64 {
            self.cpu.vfp.write_d_bits(fields.d, result);
        } else {
            self.cpu.vfp.write_s_bits(fields.d, result as u32);
        }
        ExecResult::Continue
    }
    pub(crate) fn exec_neon_fp_convert(&mut self, insn: &DecodedInsn) -> ExecResult {
        self.exec_neon_integer_conversion(insn, false)
    }
    pub(crate) fn exec_neon_fp_fixed_convert(&mut self, insn: &DecodedInsn) -> ExecResult {
        self.exec_neon_integer_conversion(insn, true)
    }
    fn exec_neon_integer_conversion(&mut self, insn: &DecodedInsn, fixed: bool) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let fields = if fixed {
            Aarch32Decoder::vector_fixed_fields(insn.raw)
        } else {
            Aarch32Decoder::vector_integer_fields(insn.raw)
        };
        let Some(fields) = fields else {
            return ExecResult::Undefined;
        };
        if fields.mnemonic == Mnemonic::UNDEFINED || fields.mnemonic != insn.mnemonic {
            return ExecResult::Undefined;
        }
        let ebytes = (fields.fp_bits / 8) as u8;
        let mut fpscr = self.standard_simd_fp_controls();
        for reg in 0..fields.regs {
            let source = self.neon_read_vector_elements_u64(fields.m + reg, 1, ebytes);
            let result: Vec<_> = source
                .into_iter()
                .map(|raw| {
                    fixed_element(
                        raw,
                        fields.fp_bits,
                        fields.integer_bits,
                        fields.fractional_bits,
                        fields.signed,
                        fields.to_fixed,
                        &mut fpscr,
                    )
                })
                .collect();
            self.neon_write_vector_elements_u64(fields.d + reg, 1, ebytes, &result);
        }
        self.cpu.vfp.fpscr = Fpscr::from_bits(self.cpu.vfp.fpscr.bits() | (fpscr.bits() & 0x9f));
        ExecResult::Continue
    }
    pub(crate) fn exec_half_double_precision_convert(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if !Aarch32Decoder::decode_vfp_data_processing(insn.raw)
            .is_some_and(|decoded| decoded.mnemonic == insn.mnemonic)
        {
            return ExecResult::Undefined;
        }
        let widen = matches!(
            insn.mnemonic,
            Mnemonic::VCVTB_F64_F16 | Mnemonic::VCVTT_F64_F16
        );
        let high = matches!(
            insn.mnemonic,
            Mnemonic::VCVTT_F64_F16 | Mnemonic::VCVTT_F16_F64
        );
        let shift = if high { 16 } else { 0 };
        let vd = ((insn.raw >> 12) & 15) as u8;
        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vm = (insn.raw & 15) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        if widen {
            let bits = (self.cpu.vfp.read_s_bits((vm << 1) | m_bit) >> shift) as u16;
            let result = vcvt_f64_f16_bits_with_fpscr(bits, &mut self.cpu.vfp.fpscr);
            self.cpu.vfp.write_d((d_bit << 4) | vd, result);
        } else {
            let source = self.cpu.vfp.read_d((m_bit << 4) | vm);
            let result = vcvt_f16_bits_f64(source, &mut self.cpu.vfp.fpscr);
            let d = (vd << 1) | d_bit;
            let original = self.cpu.vfp.read_s_bits(d);
            self.cpu.vfp.write_s_bits(
                d,
                (original & !(0xffff << shift)) | (u32::from(result) << shift),
            );
        }
        ExecResult::Continue
    }
}

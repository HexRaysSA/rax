//! Legacy Advanced SIMD selection/comparison under StandardFPSCRValue.
use super::*;
use crate::smir::interpret::SmirInterpreter;

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(crate) fn exec_neon_fp_minmax(&mut self, insn: &DecodedInsn) -> ExecResult {
        self.with_standard_fp_controls(|executor| executor.exec_neon_fp_minmax_inner(insn))
    }
    fn exec_neon_fp_minmax_inner(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let number = matches!(
            insn.mnemonic,
            Mnemonic::VMAXNM_F16
                | Mnemonic::VMAXNM_F32
                | Mnemonic::VMINNM_F16
                | Mnemonic::VMINNM_F32
        );
        let decoded = if number {
            crate::isa::arm::decoder::Aarch32Decoder::decode_neon_fp_number_minmax(insn.raw)
        } else {
            crate::isa::arm::decoder::Aarch32Decoder::decode_neon_fp_minmax(insn.raw)
        };
        if !decoded.is_some_and(|decoded| decoded.mnemonic == insn.mnemonic) {
            return ExecResult::Undefined;
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

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let fpscr = &mut self.cpu.vfp.fpscr;
                let result = match size {
                    NeonSize::S32 => {
                        let n_val = f32::from_bits(n_elem as u32);
                        let m_val = f32::from_bits(m_elem as u32);
                        (match insn.mnemonic {
                            Mnemonic::VMAX => Self::neon_fpmax_f32_bits(n_val, m_val, fpscr),
                            Mnemonic::VMAXNM_F32 => vmaxnm_f32(n_val, m_val, fpscr).to_bits(),
                            Mnemonic::VMINNM_F32 => vminnm_f32(n_val, m_val, fpscr).to_bits(),
                            Mnemonic::VMIN => Self::neon_fpmin_f32_bits(n_val, m_val, fpscr),
                            _ => return ExecResult::Undefined,
                        }) as u64
                    }
                    NeonSize::H16 if number => {
                        u64::from(if insn.mnemonic == Mnemonic::VMAXNM_F16 {
                            vmaxnm_f16_bits(n_elem as u16, m_elem as u16, fpscr)
                        } else {
                            vminnm_f16_bits(n_elem as u16, m_elem as u16, fpscr)
                        })
                    }
                    NeonSize::H16 => {
                        let maximum = match insn.mnemonic {
                            Mnemonic::VMAX => true,
                            Mnemonic::VMIN => false,
                            _ => return ExecResult::Undefined,
                        };
                        u64::from(Self::neon_fp_minmax_f16_bits(
                            n_elem as u16,
                            m_elem as u16,
                            maximum,
                            &mut self.cpu.vfp.fpscr,
                        ))
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }
    pub(crate) fn exec_neon_fp_compare(&mut self, insn: &DecodedInsn) -> ExecResult {
        self.with_standard_fp_controls(|executor| executor.exec_neon_fp_compare_inner(insn))
    }
    fn exec_neon_fp_compare_inner(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 8) & 0xF) != 0b1110
        {
            return ExecResult::Undefined;
        }

        let bit24 = (insn.raw >> 24) & 1;
        let bit21 = (insn.raw >> 21) & 1;
        let bit20 = (insn.raw >> 20) & 1;
        let absolute = ((insn.raw >> 4) & 1) != 0;
        match (insn.mnemonic, absolute, bit24, bit21, bit20) {
            (Mnemonic::VCEQ, false, 0, 0, 0 | 1)
            | (Mnemonic::VCGE, false, 1, 0, 0 | 1)
            | (Mnemonic::VCGT, false, 1, 1, 0 | 1)
            | (Mnemonic::VACGE, true, 1, 0, 0 | 1)
            | (Mnemonic::VACGT, true, 1, 1, 0 | 1) => {}
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

        let size = if bit20 == 0 {
            NeonSize::S32
        } else {
            NeonSize::H16
        };
        let ebytes = (size.bits() / 8) as u8;
        let true_mask = if size == NeonSize::S32 {
            u64::from(u32::MAX)
        } else {
            u64::from(u16::MAX)
        };

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let control = self.cpu.vfp.fpscr.bits();
                let (nzcv, status) = match size {
                    NeonSize::H16 => {
                        let mask = if absolute { 0x7fff } else { 0xffff };
                        SmirInterpreter::arm_eval_half_compare(
                            n_elem as u16 & mask,
                            m_elem as u16 & mask,
                            insn.mnemonic != Mnemonic::VCEQ,
                            control,
                        )
                    }
                    NeonSize::S32 => {
                        let mask = if absolute { 0x7fffffff } else { 0xffffffff };
                        SmirInterpreter::arm_eval_compare(
                            u64::from(n_elem as u32 & mask),
                            u64::from(m_elem as u32 & mask),
                            false,
                            insn.mnemonic != Mnemonic::VCEQ,
                            control,
                        )
                    }
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.fpscr = Fpscr::from_bits(self.cpu.vfp.fpscr.bits() | status);
                let condition = match insn.mnemonic {
                    Mnemonic::VCEQ => nzcv == 6 << 28,
                    Mnemonic::VCGT | Mnemonic::VACGT => nzcv == 2 << 28,
                    Mnemonic::VCGE | Mnemonic::VACGE => nzcv == 2 << 28 || nzcv == 6 << 28,
                    _ => return ExecResult::Undefined,
                };
                out.push(if condition { true_mask } else { 0 });
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }
    pub(crate) fn neon_fpmax_f32_bits(a: f32, b: f32, fpscr: &mut Fpscr) -> u32 {
        let (bits, status) = SmirInterpreter::arm_eval_minmax(
            a.to_bits() as u64,
            b.to_bits() as u64,
            false,
            true,
            false,
            fpscr.bits(),
        );
        *fpscr = Fpscr::from_bits(fpscr.bits() | status);
        bits as u32
    }
    pub(crate) fn neon_fpmin_f32_bits(a: f32, b: f32, fpscr: &mut Fpscr) -> u32 {
        let (bits, status) = SmirInterpreter::arm_eval_minmax(
            a.to_bits() as u64,
            b.to_bits() as u64,
            false,
            false,
            false,
            fpscr.bits(),
        );
        *fpscr = Fpscr::from_bits(fpscr.bits() | status);
        bits as u32
    }
    pub(crate) fn exec_neon_fp_absdiff(&mut self, insn: &DecodedInsn) -> ExecResult {
        self.with_standard_fp_controls(|executor| executor.exec_neon_fp_absdiff_inner(insn))
    }
    fn exec_neon_fp_absdiff_inner(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 24) != 0xF3
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 21) & 1) != 1
            || ((insn.raw >> 8) & 0xF) != 0b1101
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
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

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let result = match size {
                    NeonSize::S32 => {
                        let n_val = f32::from_bits(n_elem as u32);
                        let m_val = f32::from_bits(m_elem as u32);
                        vsub_f32(n_val, m_val, &mut self.cpu.vfp.fpscr)
                            .abs()
                            .to_bits() as u64
                    }
                    NeonSize::H16 => u64::from(
                        vsub_f16_bits(n_elem as u16, m_elem as u16, &mut self.cpu.vfp.fpscr)
                            & 0x7fff,
                    ),
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }
}

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(super) fn neon_fp_minmax_f16_bits(a: u16, b: u16, maximum: bool, fpscr: &mut Fpscr) -> u16 {
        let (bits, status) =
            SmirInterpreter::arm_eval_half_minmax(a, b, maximum, false, fpscr.bits());
        *fpscr = Fpscr::from_bits(fpscr.bits() | status);
        bits
    }
}

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(crate) fn exec_neon_compare_zero(&mut self, insn: &DecodedInsn) -> ExecResult {
        if ((insn.raw >> 8) & 7) >= 4 {
            self.with_standard_fp_controls(|executor| executor.exec_neon_compare_zero_inner(insn))
        } else {
            self.exec_neon_compare_zero_inner(insn)
        }
    }
    fn exec_neon_compare_zero_inner(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 23) != 0b111100111
            || ((insn.raw >> 20) & 0x3) != 0b11
            || ((insn.raw >> 16) & 0x3) != 0b01
            || !matches!((insn.raw >> 10) & 0x3, 0 | 1)
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let op = (insn.raw >> 7) & 0x7;
        let fp = ((insn.raw >> 8) & 0x7) >= 0b100;
        match (insn.mnemonic, op) {
            (Mnemonic::VCGT, 0b000)
            | (Mnemonic::VCGE, 0b001)
            | (Mnemonic::VCEQ, 0b010)
            | (Mnemonic::VCLE, 0b011)
            | (Mnemonic::VCLT, 0b100) => {}
            _ => return ExecResult::Undefined,
        }

        let size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        if fp && !matches!(size, NeonSize::H16 | NeonSize::S32) {
            return ExecResult::Undefined;
        }
        let ebytes = (size.bits() / 8) as u8;
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

        let true_mask = if size.bits() == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << size.bits()) - 1
        };
        for reg in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let condition = if fp {
                    let control = self.cpu.vfp.fpscr.bits();
                    let (nzcv, status) = match size {
                        NeonSize::H16 => SmirInterpreter::arm_eval_half_compare(
                            elem as u16,
                            0,
                            insn.mnemonic != Mnemonic::VCEQ,
                            control,
                        ),
                        NeonSize::S32 => SmirInterpreter::arm_eval_compare(
                            elem,
                            0,
                            false,
                            insn.mnemonic != Mnemonic::VCEQ,
                            control,
                        ),
                        _ => return ExecResult::Undefined,
                    };
                    self.cpu.vfp.fpscr = Fpscr::from_bits(self.cpu.vfp.fpscr.bits() | status);
                    match insn.mnemonic {
                        Mnemonic::VCEQ => nzcv == 6 << 28,
                        Mnemonic::VCGT => nzcv == 2 << 28,
                        Mnemonic::VCGE => matches!(nzcv, 0x20000000 | 0x60000000),
                        Mnemonic::VCLT => nzcv == 8 << 28,
                        Mnemonic::VCLE => matches!(nzcv, 0x80000000 | 0x60000000),
                        _ => return ExecResult::Undefined,
                    }
                } else {
                    let value = Self::neon_sign_extend_elem_u64(elem, size.bits());
                    match insn.mnemonic {
                        Mnemonic::VCGT => value > 0,
                        Mnemonic::VCGE => value >= 0,
                        Mnemonic::VCEQ => value == 0,
                        Mnemonic::VCLE => value <= 0,
                        Mnemonic::VCLT => value < 0,
                        _ => return ExecResult::Undefined,
                    }
                };
                out.push(if condition { true_mask } else { 0 });
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }
}

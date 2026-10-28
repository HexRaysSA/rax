//! fp.rs

use crate::isa::arm::aarch64::cpu::simd::*;
use crate::isa::arm::aarch64::cpu::*;
use std::collections::HashSet;
use std::fmt::Debug;

use crate::isa::arm::aarch64::exceptions::{
    ExceptionType, SyndromeRegister, build_spsr, exception_target_el, parse_spsr, vector_offset,
};
use crate::isa::arm::aarch64::gic::{Gic, GicConfig};
use crate::isa::arm::aarch64::mmu::{Mmu, MmuConfig, TranslationFault, TranslationGranule};
use crate::isa::arm::aarch64::sysregs::SystemRegisters;
use crate::isa::arm::aarch64::{NUM_ELS, NUM_GPRS, NUM_SIMD_REGS, sctlr};

use crate::isa::arm::common::cpu::{
    ArmCpu, ArmError, ArmException, ArmProfile, ArmVersion, CpuExit, MemoryFaultInfo,
    MemoryFaultType, ProcessorState, WatchpointKind,
};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::ArmMemory;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::vcpu::Aarch64SystemRegisters;

impl AArch64Cpu {
    /// Execute SIMD/FP instruction.
    pub(crate) fn exec_simd_fp(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        self.check_fp_access(crate::isa::arm::common::fp_access::FpAccessClass::Data)?;

        // Decode SIMD/FP instruction groups
        // Bits [28:25] = 0111 or 1111 for SIMD/FP
        // Bits [31:30] and [24:21] determine the specific group

        let op0 = (insn >> 28) & 0xF;
        let op1 = (insn >> 23) & 0x3;
        let op2 = (insn >> 19) & 0xF;
        let op3 = (insn >> 10) & 0x1FF;

        // Scalar FP data processing (three source): FMADD/FMSUB/FNMADD/FNMSUB.
        // bits[31:24] = 0001_1111
        if (insn >> 24) & 0xFF == 0b00011111 {
            let fp_type = (insn >> 22) & 0x3;
            let o1 = (insn >> 21) & 1;
            let rm = ((insn >> 16) & 0x1F) as usize;
            let o0 = (insn >> 15) & 1;
            let ra = ((insn >> 10) & 0x1F) as usize;
            let rn = ((insn >> 5) & 0x1F) as usize;
            let rd = (insn & 0x1F) as usize;
            match fp_type {
                0b00 | 0b01 | 0b11 => {
                    // Route through the canonicalising fused multiply-add. ARM
                    // negates the product (FMSUB/FNMADD) and/or the addend
                    // (FNMADD/FNMSUB) before FPMulAdd, which also flips the
                    // propagated NaN sign.
                    let eb: u32 = match fp_type {
                        0b00 => 32,
                        0b01 => 64,
                        _ => 16,
                    };
                    let m_mask: u64 = if eb == 64 { u64::MAX } else { (1u64 << eb) - 1 };
                    let n = self.v[rn] as u64 & m_mask;
                    let m = self.v[rm] as u64 & m_mask;
                    let a = self.v[ra] as u64 & m_mask;
                    let (nn, aa) = match (o1, o0) {
                        (0, 0) => (n, a),                                       // FMADD
                        (0, 1) => (fp_neg_bits_with_fpcr(n, eb, self.fpcr), a), // FMSUB
                        (1, 0) => (
                            fp_neg_bits_with_fpcr(n, eb, self.fpcr),
                            fp_neg_bits_with_fpcr(a, eb, self.fpcr),
                        ), // FNMADD
                        _ => (n, fp_neg_bits_with_fpcr(a, eb, self.fpcr)),      // FNMSUB
                    };
                    let r = fp_muladd_bits_with_fpcr(aa, nn, m, eb, self.fpcr);
                    self.fpsr |=
                        fp_status_fma_with_fpcr((eb / 8) as usize, aa, nn, m, r, self.fpcr);
                    self.v[rd] = (r & m_mask) as u128;
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            }
            return Ok(CpuExit::Continue);
        }

        // Scalar FP immediate (FMOV Sd/Dd/Hd, #imm): 00011110 ptype 1 imm8 100
        // 00000 Rd. imm8=bits[20:13]; the 8-bit float immediate expands per the
        // element size (h/s/d). Writes the low element and zeroes the upper bits.
        if (insn >> 24) & 0xFF == 0b00011110
            && (insn >> 21) & 1 == 1
            && (insn >> 10) & 0x7 == 0b100
            && (insn >> 5) & 0x1F == 0
        {
            let ptype = (insn >> 22) & 0x3;
            let esize = match ptype {
                0b00 => 4usize,
                0b01 => 8,
                0b11 => 2,
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            let imm8 = ((insn >> 13) & 0xFF) as u8;
            let rd = (insn & 0x1F) as usize;
            self.v[rd] = vfp_expand_imm(imm8, esize) as u128;
            return Ok(CpuExit::Continue);
        }

        // Scalar FP data processing (two source)
        // bits[31:24] = 0001_1110
        // bits[23:22] = type (size)
        // bit[21] = 1
        // bits[15:12] = opcode
        // bits[11:10] = 10
        if (insn >> 24) & 0xFF == 0b00011110 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3 == 0b10
        {
            let fp_type = (insn >> 22) & 0x3;
            let opcode = (insn >> 12) & 0xF;
            let rm = ((insn >> 16) & 0x1F) as u8;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let rd = (insn & 0x1F) as u8;

            // FMUL/FDIV/FADD/FSUB/FMAX/FMIN/FMAXNM/FMINNM via the canonicalising
            // helper; FNMUL = FPNeg(FPMul) flips the product's (incl. NaN) sign.
            let kind = match opcode {
                0b0000 | 0b1000 => FpKind::Mul,
                0b0001 => FpKind::Div,
                0b0010 => FpKind::Add,
                0b0011 => FpKind::Sub,
                0b0100 => FpKind::Max,
                0b0101 => FpKind::Min,
                0b0110 => FpKind::MaxNm,
                0b0111 => FpKind::MinNm,
                _ => return Err(ArmError::Unimplemented(format!("FP opcode {}", opcode))),
            };
            let nmul = opcode == 0b1000;
            match fp_type {
                0b00 => {
                    let (n, m) = (self.v[rn as usize] as u32, self.v[rm as usize] as u32);
                    let mut r = fp_three_same_f32_with_fpcr(kind, n, m, 0, self.fpcr);
                    self.fpsr |=
                        fp_status_binop_with_fpcr(4, kind, n as u64, m as u64, r as u64, self.fpcr);
                    if nmul {
                        r = fp_neg_bits_with_fpcr(r as u64, 32, self.fpcr) as u32;
                    }
                    self.v[rd as usize] = r as u128;
                }
                0b01 => {
                    let (n, m) = (self.v[rn as usize] as u64, self.v[rm as usize] as u64);
                    let mut r = fp_three_same_f64_with_fpcr(kind, n, m, 0, self.fpcr);
                    self.fpsr |= fp_status_binop_with_fpcr(8, kind, n, m, r, self.fpcr);
                    if nmul {
                        r = fp_neg_bits_with_fpcr(r, 64, self.fpcr);
                    }
                    self.v[rd as usize] = r as u128;
                }
                0b11 => {
                    let (n, m) = (self.v[rn as usize] as u16, self.v[rm as usize] as u16);
                    let mut r = sve_fp16_binop_with_fpcr(kind, n, m, self.fpcr);
                    self.fpsr |=
                        fp_status_binop_with_fpcr(2, kind, n as u64, m as u64, r as u64, self.fpcr);
                    if nmul {
                        r = fp_neg_bits_with_fpcr(r as u64, 16, self.fpcr) as u16;
                    }
                    self.v[rd as usize] = r as u128;
                }
                _ => return Err(ArmError::Unimplemented("FP16/reserved".to_string())),
            }
            return Ok(CpuExit::Continue);
        }

        // Scalar FP data processing (one source)
        // bits[31:24] = 0001_1110
        // bits[23:22] = type (size)
        // bit[21] = 1
        // bits[20:15] = opcode
        // bits[14:10] = 10000
        if (insn >> 24) & 0xFF == 0b00011110
            && (insn >> 21) & 1 == 1
            && (insn >> 10) & 0x1F == 0b10000
        {
            let fp_type = (insn >> 22) & 0x3;
            let opcode = (insn >> 15) & 0x1F;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let rd = (insn & 0x1F) as u8;

            // BFCVT Hd, Sn (FEAT_BF16): single-precision -> bfloat16, RNE.
            // Encoded as ptype=01, opcode bits[20:15]=000110 (bits[19:15]=00110).
            if fp_type == 0b01 && opcode == 0b00110 {
                let x = self.v[rn as usize] as u32;
                let bf = f32_to_bf16_with_fpcr(x, self.fpcr);
                self.fpsr |= fp_status_bfcvt_with_fpcr(x, bf, self.fpcr);
                self.v[rd as usize] = bf as u128;
                return Ok(CpuExit::Continue);
            }

            // FCVT (precision change between h/s/d): opcode 0b001xx, bits[16:15]
            // (=opcode&3) select the destination precision (00=s,01=d,11=h),
            // ptype the source. Round-to-nearest-even; NaN via FPConvertNaN.
            if matches!(opcode, 0b00100 | 0b00101 | 0b00111) {
                let dst = opcode & 0x3;
                if dst == fp_type {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let src_prec = match fp_type {
                    0b00 => 4usize,
                    0b01 => 8,
                    0b11 => 2,
                    _ => return Err(ArmError::UndefinedInstruction(insn)),
                };
                let dst_prec = match dst {
                    0b00 => 4usize,
                    0b01 => 8,
                    _ => 2,
                };
                let s = self.v[rn as usize] as u64;
                let r = fp_cvt_elem(s, src_prec, dst_prec, false, self.fpcr);
                self.fpsr |= fp_status_cvt_precision_with_fpcr(s, src_prec, dst_prec, r, self.fpcr);
                self.v[rd as usize] = r as u128;
                return Ok(CpuExit::Continue);
            }

            // FRINT32Z/X (opcode bits[19:15]=10000/10001) and FRINT64Z/X
            // (10010/10011): scalar FEAT_FRINTTS, f32 (ptype 00) / f64 (ptype 01).
            if matches!(opcode, 0b10000 | 0b10001 | 0b10010 | 0b10011) {
                let intsize = if opcode & 0b10 == 0 { 32 } else { 64 };
                let z = opcode & 1 == 0;
                self.v[rd as usize] = match fp_type {
                    0b00 => {
                        let a = self.v[rn as usize] as u32;
                        let r = frint_ts_f32_with_fpcr(a, intsize, z, self.fpcr);
                        self.fpsr |= fp_status_frint_ts_f32_with_fpcr(a, intsize, z, self.fpcr);
                        r as u128
                    }
                    0b01 => {
                        let a = self.v[rn as usize] as u64;
                        let r = frint_ts_f64_with_fpcr(a, intsize, z, self.fpcr);
                        self.fpsr |= fp_status_frint_ts_f64_with_fpcr(a, intsize, z, self.fpcr);
                        r as u128
                    }
                    _ => return Err(ArmError::UndefinedInstruction(insn)),
                };
                return Ok(CpuExit::Continue);
            }

            // FMOV is a plain copy; the FRINT/FABS/FNEG/FSQRT ops share the
            // verified two-reg FP element helpers (correct rounding modes).
            let kind = match opcode {
                0b00000 => None, // FMOV
                0b00001 => Some(TwoRegFp::Fabs),
                0b00010 => Some(TwoRegFp::Fneg),
                0b00011 => Some(TwoRegFp::Fsqrt),
                0b01000 => Some(TwoRegFp::RintN),
                0b01001 => Some(TwoRegFp::RintP),
                0b01010 => Some(TwoRegFp::RintM),
                0b01011 => Some(TwoRegFp::RintZ),
                0b01100 => Some(TwoRegFp::RintA),
                0b01110 => Some(TwoRegFp::RintX),
                0b01111 => Some(TwoRegFp::RintI),
                // 0b001xx with bit2 set are FCVT (precision change) -> handled by
                // the dedicated FCVT block; anything else is unallocated here.
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            match fp_type {
                0b00 => {
                    let a = self.v[rn as usize] as u32;
                    let r = match kind {
                        None => a,
                        Some(k) => fp_two_reg_f32_with_fpcr(k, a, self.fpcr),
                    };
                    self.fpsr |= fp_status_unop_with_fpcr(4, kind, a as u64, r as u64, self.fpcr);
                    self.v[rd as usize] = r as u128;
                }
                0b01 => {
                    let a = self.v[rn as usize] as u64;
                    let r = match kind {
                        None => a,
                        Some(k) => fp_two_reg_f64_with_fpcr(k, a, self.fpcr),
                    };
                    self.fpsr |= fp_status_unop_with_fpcr(8, kind, a, r, self.fpcr);
                    self.v[rd as usize] = r as u128;
                }
                0b11 => {
                    let a = self.v[rn as usize] as u16;
                    let r: u16 = match kind {
                        None => a, // FMOV
                        Some(TwoRegFp::Fabs) => {
                            fp_abs_bits_with_fpcr(a as u64, 16, self.fpcr) as u16
                        }
                        Some(TwoRegFp::Fneg) => {
                            fp_neg_bits_with_fpcr(a as u64, 16, self.fpcr) as u16
                        }
                        Some(TwoRegFp::Fsqrt) => fp16_sqrt_with_fpcr(a, self.fpcr),
                        Some(TwoRegFp::RintN) => fp16_frint_fixed_with_fpcr(a, 0, self.fpcr),
                        Some(TwoRegFp::RintX) | Some(TwoRegFp::RintI) => {
                            fp16_frint_with_fpcr(a, self.fpcr)
                        }
                        Some(TwoRegFp::RintM) => fp16_frint_fixed_with_fpcr(a, 1, self.fpcr),
                        Some(TwoRegFp::RintP) => fp16_frint_fixed_with_fpcr(a, 2, self.fpcr),
                        Some(TwoRegFp::RintZ) => fp16_frint_fixed_with_fpcr(a, 3, self.fpcr),
                        Some(TwoRegFp::RintA) => fp16_frint_fixed_with_fpcr(a, 4, self.fpcr),
                        _ => return Err(ArmError::UndefinedInstruction(insn)),
                    };
                    self.fpsr |= fp_status_unop_with_fpcr(2, kind, a as u64, r as u64, self.fpcr);
                    self.v[rd as usize] = r as u128;
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            }
            return Ok(CpuExit::Continue);
        }

        // FP compare
        // bits[31:24] = 0001_1110
        // bits[23:22] = type
        // bit[21] = 1
        // bits[15:14] = 00
        // bits[13:10] = 1000
        // bits[4:3] = opc
        // bits[2:0] = 0xx
        if (insn >> 24) & 0xFF == 0b00011110
            && (insn >> 21) & 1 == 1
            && (insn >> 14) & 0x3 == 0
            && (insn >> 10) & 0xF == 0b1000
            && (insn & 0x7) == 0
        {
            let fp_type = (insn >> 22) & 0x3;
            let rm = ((insn >> 16) & 0x1F) as u8;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let opc = (insn >> 3) & 0x3;
            let cmp_with_zero = (insn & 0x8) != 0;
            let signal_all_nans = (insn & 0x10) != 0;

            match fp_type {
                0b00 => {
                    // Single precision
                    let raw1_bits = self.v[rn as usize] as u32;
                    let op1_bits = fp32_flush_input_with_fpcr(raw1_bits, self.fpcr);
                    let op1 = f32::from_bits(op1_bits);
                    let raw2_bits = self.v[rm as usize] as u32;
                    let op2_bits = if cmp_with_zero {
                        0
                    } else {
                        fp32_flush_input_with_fpcr(raw2_bits, self.fpcr)
                    };
                    let op2 = if cmp_with_zero {
                        0.0f32
                    } else {
                        f32::from_bits(op2_bits)
                    };

                    let (n, z, c, v) = if op1.is_nan() || op2.is_nan() {
                        if signal_all_nans || is_snan32(op1_bits) || is_snan32(op2_bits) {
                            self.fpsr |= FPSR_IOC;
                        }
                        (false, false, true, true)
                    } else if op1 == op2 {
                        (false, true, true, false)
                    } else if op1 < op2 {
                        (true, false, false, false)
                    } else {
                        (false, false, true, false)
                    };

                    if self.fpcr & FPCR_AH == 0
                        || !(is_nan32(raw1_bits) || !cmp_with_zero && is_nan32(raw2_bits))
                    {
                        self.fpsr |= fp_fz_input_status(4, raw1_bits as u64, self.fpcr)
                            | if cmp_with_zero {
                                0
                            } else {
                                fp_fz_input_status(4, raw2_bits as u64, self.fpcr)
                            };
                    }
                    self.set_n(n);
                    self.set_z(z);
                    self.set_c(c);
                    self.set_v(v);
                }
                0b01 => {
                    // Double precision
                    let raw1_bits = self.v[rn as usize] as u64;
                    let op1_bits = fp64_flush_input_with_fpcr(raw1_bits, self.fpcr);
                    let op1 = f64::from_bits(op1_bits);
                    let raw2_bits = self.v[rm as usize] as u64;
                    let op2_bits = if cmp_with_zero {
                        0
                    } else {
                        fp64_flush_input_with_fpcr(raw2_bits, self.fpcr)
                    };
                    let op2 = if cmp_with_zero {
                        0.0f64
                    } else {
                        f64::from_bits(op2_bits)
                    };

                    let (n, z, c, v) = if op1.is_nan() || op2.is_nan() {
                        if signal_all_nans || is_snan64(op1_bits) || is_snan64(op2_bits) {
                            self.fpsr |= FPSR_IOC;
                        }
                        (false, false, true, true)
                    } else if op1 == op2 {
                        (false, true, true, false)
                    } else if op1 < op2 {
                        (true, false, false, false)
                    } else {
                        (false, false, true, false)
                    };

                    if self.fpcr & FPCR_AH == 0
                        || !(is_nan64(raw1_bits) || !cmp_with_zero && is_nan64(raw2_bits))
                    {
                        self.fpsr |= fp_fz_input_status(8, raw1_bits, self.fpcr)
                            | if cmp_with_zero {
                                0
                            } else {
                                fp_fz_input_status(8, raw2_bits, self.fpcr)
                            };
                    }
                    self.set_n(n);
                    self.set_z(z);
                    self.set_c(c);
                    self.set_v(v);
                }
                0b11 => {
                    // Half precision (compared exactly via f64).
                    let op1_bits =
                        fp16_flush_input_with_fpcr(self.v[rn as usize] as u16, self.fpcr);
                    let op1 = fp16_to_f64(op1_bits);
                    let op2_bits = if cmp_with_zero {
                        0
                    } else {
                        fp16_flush_input_with_fpcr(self.v[rm as usize] as u16, self.fpcr)
                    };
                    let op2 = if cmp_with_zero {
                        0.0f64
                    } else {
                        fp16_to_f64(op2_bits)
                    };
                    let (n, z, c, v) = if op1.is_nan() || op2.is_nan() {
                        if signal_all_nans || fp16_is_snan(op1_bits) || fp16_is_snan(op2_bits) {
                            self.fpsr |= FPSR_IOC;
                        }
                        (false, false, true, true)
                    } else if op1 == op2 {
                        (false, true, true, false)
                    } else if op1 < op2 {
                        (true, false, false, false)
                    } else {
                        (false, false, true, false)
                    };
                    self.set_n(n);
                    self.set_z(z);
                    self.set_c(c);
                    self.set_v(v);
                }
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            }
            return Ok(CpuExit::Continue);
        }

        // Floating-point conditional compare (FCCMP / FCCMPE)
        // bits[31:24]=0001_1110, bit21=1, bits[11:10]=01
        if (insn >> 24) & 0xFF == 0b00011110 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3 == 0b01
        {
            let fp_type = (insn >> 22) & 0x3;
            let rm = ((insn >> 16) & 0x1F) as usize;
            let cond = ((insn >> 12) & 0xF) as u8;
            let rn = ((insn >> 5) & 0x1F) as usize;
            let nzcv_imm = (insn & 0xF) as u8;
            let signal_all_nans = ((insn >> 4) & 1) != 0;

            let to_f64 = |bits: u128| -> Option<f64> {
                Some(match fp_type {
                    0b00 => {
                        f32::from_bits(fp32_flush_input_with_fpcr(bits as u32, self.fpcr)) as f64
                    }
                    0b01 => f64::from_bits(fp64_flush_input_with_fpcr(bits as u64, self.fpcr)),
                    0b11 => fp16_to_f64(fp16_flush_input_with_fpcr(bits as u16, self.fpcr)),
                    _ => return None,
                })
            };
            let (a, b) = match (to_f64(self.v[rn]), to_f64(self.v[rm])) {
                (Some(a), Some(b)) => (a, b),
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };

            if self.condition_holds(cond) {
                let ah_nan = self.fpcr & FPCR_AH != 0
                    && match fp_type {
                        0b00 => is_nan32(self.v[rn] as u32) || is_nan32(self.v[rm] as u32),
                        0b01 => is_nan64(self.v[rn] as u64) || is_nan64(self.v[rm] as u64),
                        0b11 => fp16_is_nan(self.v[rn] as u16) || fp16_is_nan(self.v[rm] as u16),
                        _ => false,
                    };
                self.fpsr |= if ah_nan {
                    0
                } else {
                    match fp_type {
                        0b00 => {
                            fp_fz_input_status(4, self.v[rn] as u64, self.fpcr)
                                | fp_fz_input_status(4, self.v[rm] as u64, self.fpcr)
                        }
                        0b01 => {
                            fp_fz_input_status(8, self.v[rn] as u64, self.fpcr)
                                | fp_fz_input_status(8, self.v[rm] as u64, self.fpcr)
                        }
                        _ => 0,
                    }
                };
                let invalid = match fp_type {
                    0b00 => {
                        let an = self.v[rn] as u32;
                        let bm = self.v[rm] as u32;
                        (is_nan32(an) || is_nan32(bm))
                            && (signal_all_nans || is_snan32(an) || is_snan32(bm))
                    }
                    0b01 => {
                        let an = self.v[rn] as u64;
                        let bm = self.v[rm] as u64;
                        (is_nan64(an) || is_nan64(bm))
                            && (signal_all_nans || is_snan64(an) || is_snan64(bm))
                    }
                    0b11 => {
                        let an = self.v[rn] as u16;
                        let bm = self.v[rm] as u16;
                        (fp16_is_nan(an) || fp16_is_nan(bm))
                            && (signal_all_nans || fp16_is_snan(an) || fp16_is_snan(bm))
                    }
                    _ => false,
                };
                if invalid {
                    self.fpsr |= FPSR_IOC;
                }
                let (n, z, c, v) = if a.is_nan() || b.is_nan() {
                    (false, false, true, true)
                } else if a == b {
                    (false, true, true, false)
                } else if a < b {
                    (true, false, false, false)
                } else {
                    (false, false, true, false)
                };
                self.set_nzcv(n, z, c, v);
            } else {
                self.set_n(nzcv_imm & 0b1000 != 0);
                self.set_z(nzcv_imm & 0b0100 != 0);
                self.set_c(nzcv_imm & 0b0010 != 0);
                self.set_v(nzcv_imm & 0b0001 != 0);
            }
            return Ok(CpuExit::Continue);
        }

        // Floating-point conditional select (FCSEL)
        // bits[31:24]=0001_1110, bit21=1, bits[11:10]=11
        if (insn >> 24) & 0xFF == 0b00011110 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3 == 0b11
        {
            let fp_type = (insn >> 22) & 0x3;
            let rm = ((insn >> 16) & 0x1F) as usize;
            let cond = ((insn >> 12) & 0xF) as u8;
            let rn = ((insn >> 5) & 0x1F) as usize;
            let rd = (insn & 0x1F) as usize;

            let width: u32 = match fp_type {
                0b00 => 32,
                0b01 => 64,
                0b11 => 16,
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            let src = if self.condition_holds(cond) {
                self.v[rn]
            } else {
                self.v[rm]
            };
            let mask = (1u128 << width) - 1;
            self.v[rd] = src & mask; // scalar result, upper bits zeroed
            return Ok(CpuExit::Continue);
        }

        // FMOV (general) - move between FP and general registers
        // bits[31] = sf
        // bits[30:24] = 0011110
        // bits[23:22] = type
        // bit[21] = 1
        // bits[20:19] = rmode
        // bits[18:16] = opcode
        // bits[15:10] = 000000
        if (insn >> 24) & 0x7F == 0b0011110
            && (insn >> 21) & 1 == 1
            && (insn >> 10) & 0x3F == 0
            && (insn >> 16) & 0x7 >= 0b110
        {
            let sf = (insn >> 31) & 1;
            let fp_type = (insn >> 22) & 0x3;
            let rmode = (insn >> 19) & 0x3;
            let opcode = (insn >> 16) & 0x7;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let rd = (insn & 0x1F) as u8;

            match (sf, fp_type, rmode, opcode) {
                // FMOV Wd, Sn
                (0, 0b00, 0b00, 0b110) => {
                    let val = self.v[rn as usize] as u32;
                    self.set_w(rd, val);
                }
                // FMOV Sd, Wn
                (0, 0b00, 0b00, 0b111) => {
                    let val = self.get_w(rn);
                    self.v[rd as usize] = val as u128;
                }
                // FMOV Xd, Dn
                (1, 0b01, 0b00, 0b110) => {
                    let val = self.v[rn as usize] as u64;
                    self.set_x(rd, val);
                }
                // FMOV Dn, Xn
                (1, 0b01, 0b00, 0b111) => {
                    let val = self.get_x(rn);
                    self.v[rd as usize] = val as u128;
                }
                // FMOV Xd, Vn.D[1]
                (1, 0b10, 0b01, 0b110) => {
                    let val = (self.v[rn as usize] >> 64) as u64;
                    self.set_x(rd, val);
                }
                // FMOV Vd.D[1], Xn
                (1, 0b10, 0b01, 0b111) => {
                    let val = self.get_x(rn);
                    let lower = self.v[rd as usize] as u64;
                    self.v[rd as usize] = ((val as u128) << 64) | (lower as u128);
                }
                // FMOV Wd, Hn / FMOV Xd, Hn (FEAT_FP16): zero-extend the 16 bits.
                (_, 0b11, 0b00, 0b110) => {
                    let val = self.v[rn as usize] as u16 as u64;
                    if sf == 1 {
                        self.set_x(rd, val);
                    } else {
                        self.set_w(rd, val as u32);
                    }
                }
                // FMOV Hd, Wn / FMOV Hd, Xn (FEAT_FP16): low 16 bits -> Hd.
                (_, 0b11, 0b00, 0b111) => {
                    let val = if sf == 1 {
                        self.get_x(rn)
                    } else {
                        self.get_w(rn) as u64
                    };
                    self.v[rd as usize] = (val & 0xFFFF) as u128;
                }
                // FJCVTZS Wd, Dn (FEAT_JSCVT): JS double->int32 (round toward
                // zero, modulo 2^32). Z=1 iff exact (finite, integral, in range);
                // N=C=V=0.
                (0, 0b01, 0b11, 0b110) => {
                    let bits = self.v[rn as usize] as u64;
                    let x = f64::from_bits(bits);
                    let (res, exact): (i32, bool) = if !x.is_finite() {
                        (0, false)
                    } else {
                        let t = x.trunc();
                        // JS ToInt32: reduce trunc(x) modulo 2^32 to a signed 32-bit.
                        let m = t.rem_euclid(4294967296.0); // [0, 2^32)
                        let r = if m >= 2147483648.0 {
                            (m - 4294967296.0) as i64
                        } else {
                            m as i64
                        } as i32;
                        // -0.0 is "inexact" for JavaScript (qemu helper_fjcvtzs).
                        let neg_zero = x == 0.0 && x.is_sign_negative();
                        (r, x == r as f64 && !neg_zero)
                    };
                    self.set_w(rd, res as u32);
                    self.set_nzcv(false, exact, false, false);
                    self.fpsr |= fp_status_fjcvtzs_with_fpcr(bits, self.fpcr);
                }
                _ => {
                    return Err(ArmError::Unimplemented(format!(
                        "FMOV general variant sf={} type={} rmode={} op={}",
                        sf, fp_type, rmode, opcode
                    )));
                }
            }
            return Ok(CpuExit::Continue);
        }

        // FCVT - floating-point convert precision
        // bits[31:24] = 0001_1110
        // bits[23:22] = type (source)
        // bit[21] = 1
        // bits[20:17] = 0001
        // bits[16:15] = opc (dest)
        // bits[14:10] = 10000
        if (insn >> 24) & 0xFF == 0b00011110
            && (insn >> 21) & 1 == 1
            && (insn >> 17) & 0xF == 0b0001
            && (insn >> 10) & 0x1F == 0b10000
        {
            let src_type = (insn >> 22) & 0x3;
            let dst_type = (insn >> 15) & 0x3;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let rd = (insn & 0x1F) as u8;

            match (src_type, dst_type) {
                // FCVT Dd, Sn (single to double)
                (0b00, 0b01) => {
                    let val = f32::from_bits(self.v[rn as usize] as u32);
                    let result = val as f64;
                    self.v[rd as usize] = result.to_bits() as u128;
                }
                // FCVT Sd, Dn (double to single)
                (0b01, 0b00) => {
                    let val = f64::from_bits(self.v[rn as usize] as u64);
                    self.v[rd as usize] = f64_to_f32_bits_with_fpcr(val, self.fpcr) as u128;
                }
                _ => {
                    return Err(ArmError::Unimplemented(format!(
                        "FCVT variant src={} dst={}",
                        src_type, dst_type
                    )));
                }
            }
            return Ok(CpuExit::Continue);
        }

        // Fixed-point conversion between FP and GPR (scalar): sf 0 0 11110 ptype
        // 0 rmode opcode scale Rn Rd, bit21==0. scale=bits[15:10], fbits=64-scale.
        // SCVTF/UCVTF (opcode 010/011, GPR int -> FP scaled by 2^-fbits) and
        // FCVTZS/FCVTZU (opcode 000/001, FP -> GPR int = trunc(FP * 2^fbits)).
        if (insn >> 24) & 0x7F == 0b0011110
            && (insn >> 21) & 1 == 0
            && matches!((insn >> 16) & 0x7, 0b000 | 0b001 | 0b010 | 0b011)
        {
            let sf = (insn >> 31) & 1;
            let ptype = (insn >> 22) & 0x3;
            let opcode = (insn >> 16) & 0x7;
            let scale = (insn >> 10) & 0x3F;
            let fbits = 64 - scale as i32;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let rd = (insn & 0x1F) as u8;
            // 32-bit forms only support fbits 1..=32: scale<5> must be 1.
            // The rmode field must also be fixed (11 for FCVTZ*, 00 for *CVTF).
            if sf == 0 && (scale >> 5) & 1 == 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let rmode = (insn >> 19) & 0x3;
            let want_rmode = if opcode >= 0b010 { 0b00 } else { 0b11 };
            if rmode != want_rmode || ptype == 0b10 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            if opcode == 0b010 || opcode == 0b011 {
                // GPR int -> FP, value = int / 2^fbits (the 2^-fbits scale is an
                // exact power of two, so a single FPRound of the integer suffices).
                let signed = opcode == 0b010;
                let (negative, raw_int) = if signed {
                    if sf == 1 {
                        let x = self.get_x(rn) as i64;
                        (x < 0, (x as i128).unsigned_abs())
                    } else {
                        let x = self.get_w(rn) as i32;
                        (x < 0, (x as i128).unsigned_abs())
                    }
                } else if sf == 1 {
                    (false, self.get_x(rn) as u128)
                } else {
                    (false, self.get_w(rn) as u128)
                };
                let (r, status): (u64, u32) = match ptype {
                    0b00 => {
                        let r = scaled_int_to_fp32_bits_with_fpcr(
                            raw_int,
                            negative,
                            fbits as u32,
                            self.fpcr,
                        );
                        (
                            r as u64,
                            fp_status_scaled_int_to_fp(raw_int, fbits as u32, 4, r as u64),
                        )
                    }
                    0b01 => {
                        let r = scaled_int_to_fp64_bits_with_fpcr(
                            raw_int,
                            negative,
                            fbits as u32,
                            self.fpcr,
                        );
                        (r, fp_status_scaled_int_to_fp(raw_int, fbits as u32, 8, r))
                    }
                    0b11 => {
                        let raw_r = scaled_int_to_fp16_bits_with_fpcr(
                            raw_int,
                            negative,
                            fbits as u32,
                            self.fpcr,
                        );
                        let status =
                            fp_status_scaled_int_to_fp(raw_int, fbits as u32, 2, raw_r as u64);
                        let (r, status) = fp16_int_to_fp_output_status_with_fpcr(
                            raw_int, raw_r, status, self.fpcr,
                        );
                        (r as u64, status)
                    }
                    _ => return Err(ArmError::UndefinedInstruction(insn)),
                };
                self.fpsr |= status;
                self.v[rd as usize] = r as u128;
                return Ok(CpuExit::Continue);
            }
            // FP -> GPR int, truncating toward zero: int = sat(trunc(FP * 2^fbits)).
            let signed = (opcode & 1) == 0;
            let input_status = match ptype {
                0b00 => fp_fz_input_status(4, self.v[rn as usize] as u64, self.fpcr),
                0b01 => fp_fz_input_status(8, self.v[rn as usize] as u64, self.fpcr),
                _ => 0,
            };
            let fval: f64 = match ptype {
                0b00 => f32::from_bits(fp32_flush_input_with_fpcr(
                    self.v[rn as usize] as u32,
                    self.fpcr,
                )) as f64,
                0b01 => f64::from_bits(fp64_flush_input_with_fpcr(
                    self.v[rn as usize] as u64,
                    self.fpcr,
                )),
                0b11 => fp16_to_f64(fp16_flush_input_with_fpcr(
                    self.v[rn as usize] as u16,
                    self.fpcr,
                )),
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            let scaled = fval * 2f64.powi(fbits);
            self.fpsr |= fp_status_merge_input_status(
                fp_to_int_status(scaled, signed, if sf == 1 { 64 } else { 32 }),
                input_status,
                self.fpcr,
            );
            let res: u64 = match (sf == 1, signed) {
                (true, true) => scaled as i64 as u64,
                (true, false) => scaled as u64,
                (false, true) => (scaled as i32) as u32 as u64,
                (false, false) => (scaled as u32) as u64,
            };
            if sf == 1 {
                self.set_x(rd, res);
            } else {
                self.set_w(rd, res as u32);
            }
            return Ok(CpuExit::Continue);
        }

        // Conversion between floating-point and integer (scalar, GPR-involved):
        // sf 0 0 11110 ptype 1 rmode opcode 000000 Rn Rd. rmode=bits[20:19],
        // opcode=bits[18:16]. FMOV (opcode 11x) is handled above; here are the
        // FP<->int conversions: SCVTF/UCVTF (opcode 010/011, int->FP) and
        // FCVTNS/NU/PS/PU/MS/MU/ZS/ZU/AS/AU (FP->int, rounding from rmode, or
        // ties-away for opcode 100/101).
        if (insn >> 24) & 0x7F == 0b0011110 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3F == 0 {
            let sf = (insn >> 31) & 1;
            let ptype = (insn >> 22) & 0x3;
            let rmode = (insn >> 19) & 0x3;
            let opcode = (insn >> 16) & 0x7;
            let rn = ((insn >> 5) & 0x1F) as u8;
            let rd = (insn & 0x1F) as u8;
            if opcode >= 0b110 {
                // FMOV (general) is handled earlier; anything else is unallocated.
                return Err(ArmError::UndefinedInstruction(insn));
            }
            if opcode == 0b010 || opcode == 0b011 {
                if rmode != 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                // SCVTF / UCVTF: integer (GPR) -> floating-point.
                let signed = opcode == 0b010;
                let iv = if sf == 1 {
                    self.get_x(rn)
                } else {
                    self.get_w(rn) as u64
                };
                let (negative, raw_int) = if signed {
                    if sf == 1 {
                        let x = iv as i64;
                        (x < 0, (x as i128).unsigned_abs())
                    } else {
                        let x = iv as u32 as i32;
                        (x < 0, (x as i128).unsigned_abs())
                    }
                } else if sf == 1 {
                    (false, iv as u128)
                } else {
                    (false, (iv as u32) as u128)
                };
                let (r, status): (u64, u32) = match ptype {
                    0b00 => {
                        let r = int_to_fp32_bits_with_fpcr(raw_int, negative, self.fpcr);
                        (r as u64, fp_status_int_to_fp_scaled(raw_int, 4, r as u64))
                    }
                    0b01 => {
                        let r = int_to_fp64_bits_with_fpcr(raw_int, negative, self.fpcr);
                        (r, fp_status_int_to_fp_scaled(raw_int, 8, r))
                    }
                    0b11 => {
                        let raw_r = int_to_fp16_bits_with_fpcr(raw_int, negative, self.fpcr);
                        let status = fp_status_int_to_fp_scaled(raw_int, 2, raw_r as u64);
                        let (r, status) = fp16_int_to_fp_output_status_with_fpcr(
                            raw_int, raw_r, status, self.fpcr,
                        );
                        (r as u64, status)
                    }
                    _ => return Err(ArmError::UndefinedInstruction(insn)),
                };
                self.fpsr |= status;
                self.v[rd as usize] = r as u128;
                return Ok(CpuExit::Continue);
            }
            if opcode >= 0b100 && rmode != 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            // FP -> integer. signed = even opcode; rounding from rmode (or
            // ties-away for FCVTA* opcode 100/101).
            let signed = (opcode & 1) == 0;
            let input_status = match ptype {
                0b00 => fp_fz_input_status(4, self.v[rn as usize] as u64, self.fpcr),
                0b01 => fp_fz_input_status(8, self.v[rn as usize] as u64, self.fpcr),
                _ => 0,
            };
            let fval: f64 = match ptype {
                0b00 => f32::from_bits(fp32_flush_input_with_fpcr(
                    self.v[rn as usize] as u32,
                    self.fpcr,
                )) as f64,
                0b01 => f64::from_bits(fp64_flush_input_with_fpcr(
                    self.v[rn as usize] as u64,
                    self.fpcr,
                )),
                0b11 => fp16_to_f64(fp16_flush_input_with_fpcr(
                    self.v[rn as usize] as u16,
                    self.fpcr,
                )),
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            let rounded = if opcode >= 0b100 {
                fval.round() // FCVTAS/FCVTAU: round to nearest, ties away
            } else {
                match rmode {
                    0b00 => fval.round_ties_even(),
                    0b01 => fval.ceil(),
                    0b10 => fval.floor(),
                    _ => fval.trunc(),
                }
            };
            self.fpsr |= fp_status_merge_input_status(
                fp_to_int_rounded_status(fval, rounded, signed, if sf == 1 { 64 } else { 32 }),
                input_status,
                self.fpcr,
            );
            // Saturate into the sf-width signed/unsigned range; NaN -> 0 (Rust's
            // float-to-int `as` already truncates/saturates/maps NaN to 0, and the
            // input is already integral).
            let res: u64 = match (sf == 1, signed) {
                (true, true) => rounded as i64 as u64,
                (true, false) => rounded as u64,
                (false, true) => (rounded as i32) as u32 as u64,
                (false, false) => (rounded as u32) as u64,
            };
            if sf == 1 {
                self.set_x(rd, res);
            } else {
                self.set_w(rd, res as u32);
            }
            return Ok(CpuExit::Continue);
        }

        // (FADD/FADDP FP16 fall through to the unified three-same FP16 handler
        // below; the previous dedicated add handler rounded incorrectly.)

        // SM3/SM4 crypto (bits[31:24]=0xCE). This MUST precede every Advanced
        // SIMD dispatch below: 0xCE has bits[28:24]=01110 and bit22=1/bit10=1,
        // so e.g. SM3SS1 would otherwise be captured by the FP16 three-same
        // group and executed as FMLA.
        if (insn >> 24) & 0xFF == 0xCE {
            return self.exec_crypto(insn);
        }

        // Advanced SIMD copy (DUP element/general, INS element/general, SMOV,
        // UMOV). Identified by bits[23:21]==000 (bit22==0 distinguishes it from
        // the FP16 three-same group, which has bit22==1). Must precede FP16.
        // Encoding: 0_Q_op_01110000_imm5_0_imm4_1_Rn_Rd
        // op_bits 11110 (top 0x5E) is the scalar form: DUP <V><d>,<Vn>.<T>[i]
        // (a.k.a. MOV), handled inside exec_simd_copy.
        if matches!((insn >> 24) & 0x1F, 0b01110 | 0b11110)
            && (insn >> 21) & 0x7 == 0
            && (insn >> 15) & 1 == 0
            && (insn >> 10) & 1 == 1
        {
            return self.exec_simd_copy(insn);
        }

        // Advanced SIMD three-same FP16 (vector and scalar)
        // FP16 uses bit[21]=0 (unlike regular three-same which has bit[21]=1)
        // Various FP16 ops use different bits[23:22] values:
        //   - FADD/FSUB/etc: bits[23:22]=11
        //   - FDIV/FRECPS/FRSQRTS: bits[23:22]=01
        let op_bits = (insn >> 24) & 0x1F;
        if (op_bits == 0b01110 || op_bits == 0b11110)
            && (insn >> 22) & 1 == 1       // bit[22]=1 for FP16 three-same
            && (insn >> 21) & 1 == 0       // bit[21]=0 for FP16 three-same
            && (insn >> 14) & 0x3 == 0b00  // bits[15:14]=00 for FP16 three-same
            && (insn >> 10) & 1 == 1
        {
            return self.exec_simd_fp16_three_same(insn);
        }

        // Advanced SIMD three-same (vector and scalar)
        // Vector encoding: 0_Q_U_01110_size_1_Rm_opcode_1_Rn_Rd (bits[28:24]=01110)
        // Scalar encoding: 0_1_U_11110_size_1_Rm_opcode_1_Rn_Rd (bits[28:24]=11110)
        let op_bits = (insn >> 24) & 0x1F;
        if (op_bits == 0b01110 || op_bits == 0b11110)
            && (insn >> 21) & 1 == 1
            && (insn >> 10) & 1 == 1
        {
            return self.exec_simd_three_same(insn);
        }

        // BFCVTN/BFCVTN2 (FEAT_BF16): f32 -> bf16 narrowing. Same two-reg-misc
        // slot as FCVTN (opcode 10110) but selected by size==10 (FCVTN uses
        // size 0x). Intercept before the generic two-reg-misc handler.
        if op_bits == 0b01110
            && (insn >> 29) & 1 == 0
            && (insn >> 22) & 0x3 == 0b10
            && (insn >> 17) & 0x1F == 0b10000
            && (insn >> 12) & 0x1F == 0b10110
            && (insn >> 10) & 0x3 == 0b10
        {
            return self.exec_simd_bfcvtn(insn);
        }

        // Advanced SIMD two-reg misc (vector and scalar)
        // Vector encoding: 0_Q_U_01110_size_10000_opcode_10_Rn_Rd (bits[28:24]=01110)
        // Scalar encoding: 0_1_U_11110_size_10000_opcode_10_Rn_Rd (bits[28:24]=11110)
        if (op_bits == 0b01110 || op_bits == 0b11110)
            && (insn >> 17) & 0x1F == 0b10000
            && (insn >> 10) & 0x3 == 0b10
        {
            return self.exec_simd_two_reg(insn);
        }

        // Advanced SIMD two-reg misc FP16 (vector and scalar)
        // Encoding pattern: bits[21:19]=111 distinguishes FP16 from normal two-reg misc
        // Vector: 0_Q_U_01110_size_111_opcode_10_Rn_Rd
        // Scalar: 0_1_U_11110_size_111_opcode_10_Rn_Rd
        if (op_bits == 0b01110 || op_bits == 0b11110)
            && (insn >> 19) & 0x7 == 0b111  // FP16 distinguishing bits
            && (insn >> 10) & 0x3 == 0b10
        {
            return self.exec_simd_fp16_two_reg(insn);
        }

        // Scalar three-different: SQDMULL/SQDMLAL/SQDMLSL <Dd>,<Sn>,<Sm> (and the
        // S<-H form). Top 0x5E (op_bits==11110), bit21==1, bits[11:10]==00,
        // opcode 1101/1001/1011. Signed doubling widening multiply, then
        // (optionally) a saturating accumulate; one element, rest zeroed.
        if op_bits == 0b11110 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3 == 0b00 {
            if (insn >> 31) != 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let size = (insn >> 22) & 0x3;
            let opcode = (insn >> 12) & 0xF;
            let (accum, subtract) = match opcode {
                0b1101 => (false, false), // SQDMULL
                0b1001 => (true, false),  // SQDMLAL
                0b1011 => (true, true),   // SQDMLSL
                _ => return Err(ArmError::UndefinedInstruction(insn)),
            };
            if size != 0b01 && size != 0b10 {
                return Err(ArmError::UndefinedInstruction(insn)); // src H or S only
            }
            let bits = 8u32 << size; // narrow source element size
            let dbits = 2 * bits;
            let rm = ((insn >> 16) & 0x1F) as usize;
            let rn = ((insn >> 5) & 0x1F) as usize;
            let rd = (insn & 0x1F) as usize;
            let nv = sext_elem(self.v[rn] as u64 & elem_mask(bits), bits);
            let mv = sext_elem(self.v[rm] as u64 & elem_mask(bits), bits);
            let dmin = -(1i128 << (dbits - 1));
            let dmax = (1i128 << (dbits - 1)) - 1;
            let raw_prod = 2 * nv * mv;
            let prod_saturated = raw_prod < dmin || raw_prod > dmax;
            let prod = raw_prod.clamp(dmin, dmax);
            let (r, acc_saturated) = if accum {
                let d = sext_elem(self.v[rd] as u64 & elem_mask(dbits), dbits);
                sat_signed_q(d + if subtract { -prod } else { prod }, dbits)
            } else {
                (prod as u64 & elem_mask(dbits), false)
            };
            if prod_saturated || acc_saturated {
                self.fpsr |= FPSR_QC;
            }
            self.v[rd] = (r as u128) & elem_mask_u128(dbits);
            return Ok(CpuExit::Continue);
        }

        // Advanced SIMD three different (disparate) - widening/narrowing operations
        // Encoding: 0_Q_U_01110_size_1_Rm_opcode_00_Rn_Rd
        // bits[28:24]=01110, bit[21]=1, bits[11:10]=00
        if op_bits == 0b01110 && (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3 == 0b00 {
            return self.exec_simd_three_different(insn);
        }

        // SDOT/UDOT (FEAT_DotProd, bits[15:10]=100101) and USDOT (FEAT_I8MM,
        // U==0, bits[15:10]=100111): 8-bit -> 32-bit dot product, bit21==0.
        if op_bits == 0b01110 && (insn >> 21) & 1 == 0 {
            let lo6 = (insn >> 10) & 0x3F;
            if lo6 == 0b100101 {
                if (insn >> 22) & 0x3 != 0b10 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let signed = (insn >> 29) & 1 == 0; // SDOT (U=0) / UDOT (U=1)
                return self.exec_simd_dot(insn, signed, signed);
            }
            if lo6 == 0b100111 && (insn >> 29) & 1 == 0 {
                if (insn >> 22) & 0x3 != 0b10 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                // USDOT: Vn unsigned, Vm signed.
                return self.exec_simd_dot(insn, false, true);
            }
        }

        // Three-same-extra (bit21==0): SQRDMLAH/SQRDMLSH (FEAT_RDM, bits[15:10]==
        // 100001/100011, vector + scalar) and SMMLA/UMMLA/USMMLA (FEAT_I8MM,
        // bits[15:10]==101001/101011, vector only).
        if (op_bits == 0b01110 || op_bits == 0b11110) && (insn >> 21) & 1 == 0 {
            let lo6 = (insn >> 10) & 0x3F;
            if matches!(lo6, 0b100001 | 0b100011 | 0b101001 | 0b101011) {
                return self.exec_simd_three_same_extra(insn);
            }
        }

        // FCMLA (vector): 0_Q_1_01110_size_0_Rm_110_rot_1_Rn_Rd
        //   bits[15:13]=110, bit10=1, rot=bits[12:11].
        // FCADD: 0_Q_1_01110_size_0_Rm_111_rot_01_Rn_Rd
        //   bits[15:13]=111, bits[11:10]=01, rot=bit12.
        if op_bits == 0b01110 && (insn >> 29) & 1 == 1 && (insn >> 21) & 1 == 0 {
            if (insn >> 13) & 0x7 == 0b110 && (insn >> 10) & 1 == 1 {
                return self.exec_simd_complex(insn, true);
            }
            if (insn >> 13) & 0x7 == 0b111 && (insn >> 10) & 0x3 == 0b01 {
                return self.exec_simd_complex(insn, false);
            }
            // BF16 three-same-extra: BFDOT/BFMLAL (bits[15:10]=111111) and
            // BFMMLA (bits[15:10]=111011), sub-selected by size bits[23:22].
            let lo6 = (insn >> 10) & 0x3F;
            let size = (insn >> 22) & 0x3;
            if lo6 == 0b111111 {
                if size == 0b01 {
                    return self.exec_simd_bfdot(insn, false); // BFDOT vector
                }
                if size == 0b11 {
                    return self.exec_simd_bfmlal(insn, false); // BFMLALB/T vector
                }
                return Err(ArmError::UndefinedInstruction(insn));
            }
            if lo6 == 0b111011 {
                if (insn >> 30) & 1 == 1 && size == 0b01 {
                    return self.exec_simd_bfmmla(insn); // BFMMLA
                }
                return Err(ArmError::UndefinedInstruction(insn));
            }
        }

        // Cryptographic AES/SHA operations
        // AES: 0100 1110 00 1 01000 0 opcode 10 Rn Rd (bits[31:24]=0x4E)
        // SHA two-reg: 0101 1110 00 1 01000 0 opcode 10 Rn Rd (bits[31:24]=0x5E)
        // The bits[21:17]==10100 marker distinguishes AES/SHA two-register crypto
        // from across-lanes (11000) and two-reg-misc (10000), which share the
        // same bits[31:24] for Q==1.
        if ((insn >> 24) & 0xFF == 0x4E || (insn >> 24) & 0xFF == 0x5E)
            && (insn >> 17) & 0x1F == 0b10100
            && (insn >> 10) & 0x3 == 0b10
        {
            return self.exec_crypto(insn);
        }

        // SHA/SM3/SM4 three-register operations
        // SHA three-reg: 0101 1110 000 Rm 0 opcode 00 Rn Rd (bits[31:24]=0x5E, bits[11:10]=00)
        // SM3/SM4: various encodings with bits[31:24]=0xCE
        if (insn >> 24) & 0xFF == 0x5E && (insn >> 21) & 7 == 0 && (insn >> 10) & 0x3 == 0b00 {
            return self.exec_crypto(insn);
        }

        // Advanced SIMD across lanes (reduction operations like ADDV, SADDLV, etc.)
        // Encoding: 0_Q_U_01110_size_11000_opcode_10_Rn_Rd
        if op_bits == 0b01110 && (insn >> 17) & 0x1F == 0b11000 && (insn >> 10) & 0x3 == 0b10 {
            return self.exec_simd_across_lanes(insn);
        }

        // AdvSIMD scalar pairwise (ADDP/FADDP/FMAXP/FMINP/FMAXNMP/FMINNMP to a
        // scalar): top 0x5E/0x7E, bits[21:17]==11000, bits[11:10]==10.
        if op_bits == 0b11110 && (insn >> 17) & 0x1F == 0b11000 && (insn >> 10) & 0x3 == 0b10 {
            return self.exec_simd_scalar_pairwise(insn);
        }

        // FCMLA by element: 0_Q_1_01111_size_L_M_Rm_0_rot_1_H_0_Rn_Rd. Must
        // precede the generic indexed dispatch below, since its opcode field
        // bits[15:12]=0_rot_1 overlaps FMLA/FMLS-by-element. Discriminated by
        // U==1, bit15==0, bit12==1, bit10==0.
        if op_bits == 0b01111
            && (insn >> 29) & 1 == 1
            && (insn >> 15) & 1 == 0
            && (insn >> 12) & 1 == 1
            && (insn >> 10) & 1 == 0
        {
            return self.exec_simd_complex_indexed(insn);
        }

        // U=0 by-element group with opcode bits[15:12]==1111, bit10==0: the
        // FEAT_I8MM / FEAT_BF16 by-element instructions, sub-selected by the
        // size field bits[23:22]: 00=SUDOT, 01=BFDOT, 10=USDOT, 11=BFMLALB/T.
        // Must precede the generic indexed dispatch below.
        if op_bits == 0b01111
            && (insn >> 29) & 1 == 0
            && (insn >> 12) & 0xF == 0b1111
            && (insn >> 10) & 1 == 0
        {
            match (insn >> 22) & 0x3 {
                0b00 => return self.exec_simd_dot_indexed_mixed(insn, true, false), // SUDOT: Vn signed, Vm unsigned
                0b10 => return self.exec_simd_dot_indexed_mixed(insn, false, true), // USDOT: Vn unsigned, Vm signed
                0b01 => return self.exec_simd_bfdot(insn, true), // BFDOT by element
                0b11 => return self.exec_simd_bfmlal(insn, true), // BFMLALB/T by element
                _ => {}
            }
        }

        // FEAT_FP8FMA FMLALB/FMLALT (by element): 0 Q 0 01111 11 idx Rm 0000
        // idx 0 Rn Rd. FP8 (E5M2: an exact f16 with the mantissa truncated to
        // 2 bits, so widening is a left shift) multiplied into f16 lanes;
        // Q selects bottom (0) / top (1) source bytes.
        if op_bits == 0b01111
            && (insn >> 29) & 1 == 0
            && (insn >> 22) & 0x3 == 0b11
            && (insn >> 12) & 0xF == 0b0000
            && (insn >> 10) & 1 == 0
        {
            if (insn >> 31) != 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            if self.config.version < ArmVersion::V9_4A {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let top = (insn >> 30) & 1 == 1;
            let rm = ((insn >> 16) & 0xF) as usize;
            let rn = ((insn >> 5) & 0x1F) as usize;
            let rd = (insn & 0x1F) as usize;
            let idx = ((((insn >> 11) & 1) << 3)
                | (((insn >> 21) & 1) << 2)
                | (((insn >> 20) & 1) << 1)
                | ((insn >> 10) & 1)) as usize;
            let f8_to_f16 = |b: u8| (b as u16) << 8;
            let n = self.v[rn].to_le_bytes();
            let m = self.v[rm].to_le_bytes();
            let mut d = self.v[rd].to_le_bytes();
            let mb = f8_to_f16(m[idx & 0xF]);
            for i in 0..8 {
                let nb = f8_to_f16(n[2 * i + usize::from(top)]);
                let prod = fp16_mul(nb, mb);
                let cur = u16::from_le_bytes([d[2 * i], d[2 * i + 1]]);
                let r = fp16_add(cur, prod);
                d[2 * i..2 * i + 2].copy_from_slice(&r.to_le_bytes());
            }
            self.v[rd] = u128::from_le_bytes(d);
            return Ok(CpuExit::Continue);
        }

        // FEAT_FHM FMLAL/FMLSL/FMLAL2/FMLSL2 by element: 0Q U 01111 10 L M Rm
        // (top:sub:00) H 0 Rn Rd. sz==10, bits[13:12]==00, and bit15==U (which
        // distinguishes them from the integer MUL/MLAL-by-element forms that
        // share bits[13:12]==00). Must precede the generic indexed dispatch.
        if op_bits == 0b01111
            && (insn >> 22) & 0x3 == 0b10
            && (insn >> 12) & 0x3 == 0
            && (insn >> 10) & 1 == 0
            && (insn >> 15) & 1 == (insn >> 29) & 1
        {
            return self.exec_fmlal(insn, true);
        }

        // Advanced SIMD vector x indexed element
        // Encoding: 0_Q_U_01111_size_L_M_Rm_opcode_H_0_Rn_Rd  (bit10 = 0)
        if (op_bits == 0b01111 || op_bits == 0b11111) && (insn >> 10) & 1 == 0 {
            return self.exec_simd_indexed(insn);
        }

        // Advanced SIMD modified immediate (MOVI/MVNI/ORR/BIC/FMOV vector)
        // Encoding: 0_Q_op_0111100000_abc_cmode_o2_1_defgh_Rd
        if (insn >> 19) & 0x3FF == 0b0111100000 && (insn >> 10) & 1 == 1 {
            return self.exec_simd_modified_imm(insn);
        }

        // Advanced SIMD shift by immediate (vector: bits[28:23]==011110; scalar:
        // bits[28:23]==111110). bit[10]==1. Both route to exec_simd_shift_imm,
        // which detects scalar via the top byte (0x5F/0x7F).
        if matches!((insn >> 23) & 0x3F, 0b011110 | 0b111110) && (insn >> 10) & 1 == 1 {
            return self.exec_simd_shift_imm(insn);
        }

        // Advanced SIMD permute (ZIP, UZP, TRN)
        // Encoding: 0_Q_0_01110_size_0_Rm_0_opcode_10_Rn_Rd
        if op_bits == 0b01110
            && (insn >> 29) & 1 == 0
            && (insn >> 21) & 1 == 0
            && (insn >> 15) & 1 == 0
            && (insn >> 10) & 0x3 == 0b10
        {
            return self.exec_simd_permute(insn);
        }

        // Advanced SIMD table lookup (TBL, TBX)
        // Encoding: 0_Q_0_01110_00_0_Rm_0_len_op_00_Rn_Rd
        if op_bits == 0b01110
            && (insn >> 29) & 1 == 0
            && (insn >> 22) & 0x3 == 0b00
            && (insn >> 21) & 1 == 0
            && (insn >> 10) & 0x3 == 0b00
        {
            return self.exec_simd_table(insn);
        }

        // Advanced SIMD extract (EXT)
        // Encoding: 0_Q_10_1110_00_0_Rm_0_imm4_0_Rn_Rd
        if op_bits == 0b01110
            && (insn >> 29) & 1 == 1
            && (insn >> 22) & 0x3 == 0b00
            && (insn >> 15) & 1 == 0
        {
            return self.exec_simd_extract(insn);
        }

        // If we get here, it's an unimplemented SIMD/FP instruction
        Err(ArmError::Unimplemented(format!(
            "SIMD/FP insn 0x{:08x}",
            insn
        )))
    }

    /// Execute SIMD FP add (binary uniform add).
    pub(crate) fn exec_simd_fp_add_uniform(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let q = (insn >> 30) & 1;
        let pair = ((insn >> 29) & 1) != 0;
        let size = (insn >> 22) & 0x3;
        let rm = ((insn >> 16) & 0x1F) as usize;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        let esize = if size & 1 == 0 { 4 } else { 8 };
        let datasize = if q == 1 { 16 } else { 8 };
        let elements = datasize / esize;

        let src1 = self.v[rn].to_le_bytes();
        let src2 = self.v[rm].to_le_bytes();
        let mut dst = [0u8; 16];
        let mut concat = [0u8; 32];

        if pair {
            concat[..datasize].copy_from_slice(&src1[..datasize]);
            concat[datasize..datasize * 2].copy_from_slice(&src2[..datasize]);
        }

        for e in 0..elements {
            let out_off = e * esize;
            if esize == 4 {
                let (a, b) = if pair {
                    let idx1 = 2 * e;
                    let idx2 = idx1 + 1;
                    let a_off = idx1 * esize;
                    let b_off = idx2 * esize;
                    (
                        f32::from_le_bytes([
                            concat[a_off],
                            concat[a_off + 1],
                            concat[a_off + 2],
                            concat[a_off + 3],
                        ]),
                        f32::from_le_bytes([
                            concat[b_off],
                            concat[b_off + 1],
                            concat[b_off + 2],
                            concat[b_off + 3],
                        ]),
                    )
                } else {
                    let a_off = e * esize;
                    let b_off = e * esize;
                    (
                        f32::from_le_bytes([
                            src1[a_off],
                            src1[a_off + 1],
                            src1[a_off + 2],
                            src1[a_off + 3],
                        ]),
                        f32::from_le_bytes([
                            src2[b_off],
                            src2[b_off + 1],
                            src2[b_off + 2],
                            src2[b_off + 3],
                        ]),
                    )
                };

                let result = a + b;
                let bytes = result.to_le_bytes();
                dst[out_off..out_off + 4].copy_from_slice(&bytes);
            } else {
                let (a, b) = if pair {
                    let idx1 = 2 * e;
                    let idx2 = idx1 + 1;
                    let a_off = idx1 * esize;
                    let b_off = idx2 * esize;
                    (
                        f64::from_le_bytes([
                            concat[a_off],
                            concat[a_off + 1],
                            concat[a_off + 2],
                            concat[a_off + 3],
                            concat[a_off + 4],
                            concat[a_off + 5],
                            concat[a_off + 6],
                            concat[a_off + 7],
                        ]),
                        f64::from_le_bytes([
                            concat[b_off],
                            concat[b_off + 1],
                            concat[b_off + 2],
                            concat[b_off + 3],
                            concat[b_off + 4],
                            concat[b_off + 5],
                            concat[b_off + 6],
                            concat[b_off + 7],
                        ]),
                    )
                } else {
                    let a_off = e * esize;
                    let b_off = e * esize;
                    (
                        f64::from_le_bytes([
                            src1[a_off],
                            src1[a_off + 1],
                            src1[a_off + 2],
                            src1[a_off + 3],
                            src1[a_off + 4],
                            src1[a_off + 5],
                            src1[a_off + 6],
                            src1[a_off + 7],
                        ]),
                        f64::from_le_bytes([
                            src2[b_off],
                            src2[b_off + 1],
                            src2[b_off + 2],
                            src2[b_off + 3],
                            src2[b_off + 4],
                            src2[b_off + 5],
                            src2[b_off + 6],
                            src2[b_off + 7],
                        ]),
                    )
                };

                let result = a + b;
                let bytes = result.to_le_bytes();
                dst[out_off..out_off + 8].copy_from_slice(&bytes);
            }
        }

        self.v[rd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }

    /// Execute SIMD FP16 three-same register instructions.
    pub(crate) fn exec_simd_fp16_three_same(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let a = (insn >> 23) & 1; // Selects between two groups of operations
        let rm = ((insn >> 16) & 0x1F) as usize;
        let opcode = (insn >> 11) & 0x7; // 3 bits for FP16
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        // For scalar (bit28=1) only the low halfword is processed.
        let is_scalar = ((insn >> 28) & 1) == 1;
        let datasize = if is_scalar {
            2
        } else if q == 1 {
            16
        } else {
            8
        };
        let elements = datasize / 2;

        // The scalar three-same FP16 group is a subset: only FMULX, FCMEQ,
        // FRECPS, FRSQRTS, FCMGE, FACGE, FABD, FCMGT and FACGT have scalar
        // encodings. The element-wise arithmetic (FADD/FSUB/FMUL/FMAX/FMIN/
        // FMAXNM/FMINNM/FDIV), the fused FMLA/FMLS and the pairwise forms do
        // not, so reject them in scalar context.
        if is_scalar
            && !matches!(
                (u, a, opcode),
                (0, 0, 0b011)
                    | (0, 0, 0b100)
                    | (0, 0, 0b111)
                    | (0, 1, 0b111)
                    | (1, 0, 0b100)
                    | (1, 0, 0b101)
                    | (1, 1, 0b010)
                    | (1, 1, 0b100)
                    | (1, 1, 0b101)
            )
        {
            return Ok(CpuExit::Undefined(insn));
        }

        // Classify the operation. `Bin` is a per-lane binary op; `Mla`/`Mls`
        // are the fused multiply-accumulate forms (they read the destination);
        // `Pair` is a pairwise-reduction op. See the Arm "Advanced SIMD
        // three-same (FP16)" table indexed by (U, a=bit23, opcode=bits[13:11]).
        enum Fp16Op {
            Bin(fn(u16, u16) -> u16),
            Pair(fn(u16, u16) -> u16),
            Mla,
            Mls,
        }
        let op = match (u, a, opcode) {
            // U=0
            (0, 0, 0b000) => Fp16Op::Bin(fp16_maxnm),
            (0, 1, 0b000) => Fp16Op::Bin(fp16_minnm),
            (0, 0, 0b001) => Fp16Op::Mla,
            (0, 1, 0b001) => Fp16Op::Mls,
            (0, 0, 0b010) => Fp16Op::Bin(fp16_add),
            (0, 1, 0b010) => Fp16Op::Bin(fp16_sub),
            (0, 0, 0b011) => Fp16Op::Bin(fp16_mulx),
            (0, 0, 0b100) => Fp16Op::Bin(|x, y| fp16_cmp(x, y, 0)), // FCMEQ
            (0, 0, 0b110) => Fp16Op::Bin(fp16_max),
            (0, 1, 0b110) => Fp16Op::Bin(fp16_min),
            (0, 0, 0b111) => Fp16Op::Bin(fp16_recps),
            (0, 1, 0b111) => Fp16Op::Bin(fp16_rsqrts),
            // U=1
            (1, 0, 0b000) => Fp16Op::Pair(fp16_maxnm),
            (1, 1, 0b000) => Fp16Op::Pair(fp16_minnm),
            (1, 0, 0b010) => Fp16Op::Pair(fp16_add),
            (1, 1, 0b010) => Fp16Op::Bin(fp16_abd),
            (1, 0, 0b011) => Fp16Op::Bin(fp16_mul),
            (1, 0, 0b100) => Fp16Op::Bin(|x, y| fp16_cmp(x, y, 1)), // FCMGE
            (1, 1, 0b100) => Fp16Op::Bin(|x, y| fp16_cmp(x, y, 2)), // FCMGT
            (1, 0, 0b101) => Fp16Op::Bin(|x, y| fp16_cmp(x, y, 3)), // FACGE
            (1, 1, 0b101) => Fp16Op::Bin(|x, y| fp16_cmp(x, y, 4)), // FACGT
            (1, 0, 0b110) => Fp16Op::Pair(fp16_max),
            (1, 1, 0b110) => Fp16Op::Pair(fp16_min),
            (1, 0, 0b111) => Fp16Op::Bin(fp16_div),
            _ => return Ok(CpuExit::Undefined(insn)),
        };

        let lane = |v: u128, e: usize| -> u16 { (v >> (e * 16)) as u16 };
        let src1 = self.v[rn];
        let src2 = self.v[rm];
        let acc = self.v[rd];
        let mut dst = 0u128;

        match op {
            Fp16Op::Bin(f) => {
                for e in 0..elements {
                    let n = lane(src1, e);
                    let m = lane(src2, e);
                    let r = match (u, a, opcode) {
                        (0, 0, 0b010) => sve_fp16_binop_with_fpcr(FpKind::Add, n, m, self.fpcr),
                        (0, 1, 0b010) => sve_fp16_binop_with_fpcr(FpKind::Sub, n, m, self.fpcr),
                        (1, 1, 0b010) => sve_fp16_binop_with_fpcr(FpKind::Abd, n, m, self.fpcr),
                        (1, 0, 0b011) => sve_fp16_binop_with_fpcr(FpKind::Mul, n, m, self.fpcr),
                        (1, 0, 0b111) => sve_fp16_binop_with_fpcr(FpKind::Div, n, m, self.fpcr),
                        (0, 0, 0b111) => fp16_recps_with_fpcr(n, m, self.fpcr),
                        (0, 1, 0b111) => fp16_rsqrts_with_fpcr(n, m, self.fpcr),
                        (0, 0, 0b011) => sve_fp16_binop_with_fpcr(FpKind::Mulx, n, m, self.fpcr),
                        (0, 0, 0b100) => fp16_cmp_with_fpcr(n, m, 0, self.fpcr),
                        (1, 0, 0b100) => fp16_cmp_with_fpcr(n, m, 1, self.fpcr),
                        (1, 1, 0b100) => fp16_cmp_with_fpcr(n, m, 2, self.fpcr),
                        (1, 0, 0b101) => fp16_cmp_with_fpcr(n, m, 3, self.fpcr),
                        (1, 1, 0b101) => fp16_cmp_with_fpcr(n, m, 4, self.fpcr),
                        (0, 0, 0b000) => sve_fp16_binop_with_fpcr(FpKind::MaxNm, n, m, self.fpcr),
                        (0, 1, 0b000) => sve_fp16_binop_with_fpcr(FpKind::MinNm, n, m, self.fpcr),
                        (0, 0, 0b110) => sve_fp16_binop_with_fpcr(FpKind::Max, n, m, self.fpcr),
                        (0, 1, 0b110) => sve_fp16_binop_with_fpcr(FpKind::Min, n, m, self.fpcr),
                        _ => f(n, m),
                    };
                    self.fpsr |= fp16_three_same_status_with_fpcr(u, a, opcode, n, m, r, self.fpcr);
                    dst |= (r as u128) << (e * 16);
                }
            }
            Fp16Op::Mla => {
                for e in 0..elements {
                    let aa = lane(acc, e);
                    let n = lane(src1, e);
                    let m = lane(src2, e);
                    let r = fp_muladd_bits_with_fpcr(aa as u64, n as u64, m as u64, 16, self.fpcr)
                        as u16;
                    self.fpsr |= fp_status_fma_with_fpcr(
                        2, aa as u64, n as u64, m as u64, r as u64, self.fpcr,
                    );
                    dst |= (r as u128) << (e * 16);
                }
            }
            Fp16Op::Mls => {
                for e in 0..elements {
                    let aa = lane(acc, e);
                    let n = lane(src1, e);
                    let m = lane(src2, e);
                    let neg_n = fp_neg_bits_with_fpcr(n as u64, 16, self.fpcr);
                    let r =
                        fp_muladd_bits_with_fpcr(aa as u64, neg_n, m as u64, 16, self.fpcr) as u16;
                    self.fpsr |=
                        fp_status_fma_with_fpcr(2, aa as u64, neg_n, m as u64, r as u64, self.fpcr);
                    dst |= (r as u128) << (e * 16);
                }
            }
            Fp16Op::Pair(f) => {
                // Pairwise: the lower half of the result comes from adjacent
                // pairs of Vn, the upper half from adjacent pairs of Vm.
                let pairs = elements / 2;
                for i in 0..pairs {
                    let n = lane(src1, 2 * i);
                    let m = lane(src1, 2 * i + 1);
                    let r = match (u, a, opcode) {
                        (1, 0, 0b010) => sve_fp16_binop_with_fpcr(FpKind::Add, n, m, self.fpcr),
                        (1, 0, 0b000) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::MaxNmp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        (1, 1, 0b000) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::MinNmp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        (1, 0, 0b110) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::Maxp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        (1, 1, 0b110) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::Minp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        _ => f(n, m),
                    };
                    self.fpsr |= fp16_three_same_status_with_fpcr(u, a, opcode, n, m, r, self.fpcr);
                    dst |= (r as u128) << (i * 16);
                }
                for i in 0..pairs {
                    let n = lane(src2, 2 * i);
                    let m = lane(src2, 2 * i + 1);
                    let r = match (u, a, opcode) {
                        (1, 0, 0b010) => sve_fp16_binop_with_fpcr(FpKind::Add, n, m, self.fpcr),
                        (1, 0, 0b000) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::MaxNmp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        (1, 1, 0b000) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::MinNmp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        (1, 0, 0b110) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::Maxp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        (1, 1, 0b110) => sve_fp_pairwise_reduce_combine_with_fpcr(
                            FpKind::Minp,
                            2,
                            n as u64,
                            m as u64,
                            self.fpcr,
                        ) as u16,
                        _ => f(n, m),
                    };
                    self.fpsr |= fp16_three_same_status_with_fpcr(u, a, opcode, n, m, r, self.fpcr);
                    dst |= (r as u128) << ((pairs + i) * 16);
                }
            }
        }

        self.v[rd] = dst;
        Ok(CpuExit::Continue)
    }

    /// Execute SIMD FP16 two-reg misc instructions.
    pub(crate) fn exec_simd_fp16_two_reg(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let a = (insn >> 23) & 1; // bit23 sub-group selector (the FP16 "sz" low bit)
        let opcode = (insn >> 12) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        // For scalar, bit[28]=1
        let is_scalar = ((insn >> 28) & 1) == 1;
        let datasize = if is_scalar {
            2
        } else if q == 1 {
            16
        } else {
            8
        };
        let elements = datasize / 2;

        // Validity: FABS/FNEG (01111), FRINT* (11000/11001) and the vector FSQRT
        // (U=1, 11111) have no SIMD-scalar encoding — their scalar variants live
        // in the floating-point data-processing groups. FRECPX (U=0, 11111) is
        // scalar-only and has no vector form. Reject the mismatched cases.
        if is_scalar {
            if opcode == 0b01111
                || opcode == 0b11000
                || opcode == 0b11001
                || (opcode == 0b11111 && u == 1)
            {
                return Ok(CpuExit::Undefined(insn));
            }
        } else if opcode == 0b11111 && u == 0 {
            return Ok(CpuExit::Undefined(insn));
        }

        let lane = |v: u128, e: usize| -> u16 { (v >> (e * 16)) as u16 };
        let src = self.v[rn];
        let mut dst = 0u128;

        for e in 0..elements {
            let s = lane(src, e);
            // Decode by (U, a=bit23, opcode=bits[16:12]) per the Arm "Advanced
            // SIMD two-register miscellaneous (FP16)" table. FCVT* produce a
            // 16-bit integer lane; SCVTF/UCVTF consume one; the rest are FP16.
            let r: u16 = match (u, a, opcode) {
                // Sign manipulation.
                (0, 1, 0b01111) => fp_abs_bits_with_fpcr(s as u64, 16, self.fpcr) as u16, // FABS
                (1, 1, 0b01111) => fp_neg_bits_with_fpcr(s as u64, 16, self.fpcr) as u16, // FNEG
                // Square root and reciprocal-family estimates.
                (1, 1, 0b11111) => fp16_sqrt_with_fpcr(s, self.fpcr), // FSQRT
                (0, 1, 0b11111) => fp16_recpx(fp16_flush_input_with_fpcr(s, self.fpcr)), // FRECPX
                (0, 1, 0b11101) => {
                    let raw =
                        fp16_recpe(fp_estimate_input_with_fpcr(s as u64, 16, self.fpcr) as u16);
                    fp16_flush_output_with_fpcr(raw, self.fpcr)
                } // FRECPE
                (1, 1, 0b11101) => {
                    let raw = fp16_rsqrte_with_fpcr(
                        fp_estimate_input_with_fpcr(s as u64, 16, self.fpcr) as u16,
                        self.fpcr,
                    );
                    fp16_flush_output_with_fpcr(raw, self.fpcr)
                } // FRSQRTE
                // Compare against zero.
                (0, 1, 0b01100) => fp16_cmp0_with_fpcr(s, 0, self.fpcr), // FCMGT #0
                (0, 1, 0b01101) => fp16_cmp0_with_fpcr(s, 2, self.fpcr), // FCMEQ #0
                (0, 1, 0b01110) => fp16_cmp0_with_fpcr(s, 4, self.fpcr), // FCMLT #0
                (1, 1, 0b01100) => fp16_cmp0_with_fpcr(s, 1, self.fpcr), // FCMGE #0
                (1, 1, 0b01101) => fp16_cmp0_with_fpcr(s, 3, self.fpcr), // FCMLE #0
                // Round to integral.
                (0, 0, 0b11000) => fp16_frint_fixed_with_fpcr(s, 0, self.fpcr), // FRINTN
                (0, 0, 0b11001) => fp16_frint_fixed_with_fpcr(s, 1, self.fpcr), // FRINTM
                (0, 1, 0b11000) => fp16_frint_fixed_with_fpcr(s, 2, self.fpcr), // FRINTP
                (0, 1, 0b11001) => fp16_frint_fixed_with_fpcr(s, 3, self.fpcr), // FRINTZ
                (1, 0, 0b11000) => fp16_frint_fixed_with_fpcr(s, 4, self.fpcr), // FRINTA
                (1, 0, 0b11001) => fp16_frint_with_fpcr(s, self.fpcr),          // FRINTX
                (1, 1, 0b11001) => fp16_frint_with_fpcr(s, self.fpcr),          // FRINTI
                // Floating-point to integer (signed).
                (0, 0, 0b11010) => fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), true, 0), // FCVTNS
                (0, 0, 0b11011) => fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), true, 1), // FCVTMS
                (0, 0, 0b11100) => fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), true, 4), // FCVTAS
                (0, 1, 0b11010) => fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), true, 2), // FCVTPS
                (0, 1, 0b11011) => fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), true, 3), // FCVTZS
                // Floating-point to integer (unsigned).
                (1, 0, 0b11010) => {
                    fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), false, 0)
                } // FCVTNU
                (1, 0, 0b11011) => {
                    fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), false, 1)
                } // FCVTMU
                (1, 0, 0b11100) => {
                    fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), false, 4)
                } // FCVTAU
                (1, 1, 0b11010) => {
                    fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), false, 2)
                } // FCVTPU
                (1, 1, 0b11011) => {
                    fp16_to_int16(fp16_flush_input_with_fpcr(s, self.fpcr), false, 3)
                } // FCVTZU
                // Integer to floating-point.
                (0, 0, 0b11101) => {
                    let x = s as i16;
                    let raw =
                        int_to_fp16_bits_with_fpcr((x as i128).unsigned_abs(), x < 0, self.fpcr);
                    fp16_flush_output_with_fpcr(raw, self.fpcr)
                } // SCVTF
                (1, 0, 0b11101) => {
                    let raw = int_to_fp16_bits_with_fpcr(s as u128, false, self.fpcr);
                    fp16_flush_output_with_fpcr(raw, self.fpcr)
                } // UCVTF
                _ => return Ok(CpuExit::Undefined(insn)),
            };
            self.fpsr |= fp16_two_reg_status_with_fpcr(u, a, opcode, s, r, self.fpcr);
            dst |= (r as u128) << (e * 16);
        }

        self.v[rd] = dst;
        Ok(CpuExit::Continue)
    }

    /// Execute an Advanced SIMD three-same floating-point instruction.
    pub(crate) fn exec_simd_three_same_fp(
        &mut self,
        insn: u32,
        scalar: bool,
    ) -> Result<CpuExit, ArmError> {
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let size = (insn >> 22) & 0x3;
        let opcode = (insn >> 11) & 0x1F;
        let rm = ((insn >> 16) & 0x1F) as usize;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        let sz = size & 1; // 0 => f32, 1 => f64
        let a_bit = (size >> 1) & 1;

        if scalar {
            // The scalar AdvSIMD FP three-same table only defines compare/step
            // operations, FMULX, and FABD. Ordinary arithmetic,
            // FMA, min/max, pairwise, and FDIV forms are vector-only here.
            let legal_scalar = matches!(
                (u, a_bit, opcode, sz),
                (0, 0, 0b11011, _) // FMULX
                    | (0, 0, 0b11100, _) // FCMEQ
                    | (0, 0, 0b11111, _) // FRECPS
                    | (0, 1, 0b11111, _) // FRSQRTS
                    | (1, 0, 0b11100, _) // FCMGE
                    | (1, 0, 0b11101, _) // FACGE
                    | (1, 1, 0b11010, _) // FABD
                    | (1, 1, 0b11100, _) // FCMGT
                    | (1, 1, 0b11101, _) // FACGT
            );
            if !legal_scalar {
                return Err(ArmError::UndefinedInstruction(insn));
            }
        }

        // FEAT_FHM: FMLAL/FMLSL (U==0, opcode 0b11101) and FMLAL2/FMLSL2
        // (U==1, opcode 0b11001) widen FP16 lanes into FP32 accumulator lanes.
        // These are only defined for the vector (non-scalar) form.
        if !scalar && ((u == 0 && opcode == 0b11101) || (u == 1 && opcode == 0b11001)) {
            if size & 1 != 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            return self.exec_fmlal(insn, false);
        }

        let kind = match fp_three_same_decode(u, a_bit, opcode) {
            Some(k) => k,
            None => return Err(ArmError::UndefinedInstruction(insn)),
        };
        let esize = if sz == 0 { 4usize } else { 8 };

        // A 64-bit vector cannot hold a single f64 element (needs 2D / Q==1).
        if sz == 1 && q == 0 && !scalar {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let datasize = if scalar {
            esize
        } else if q == 1 {
            16
        } else {
            8
        };
        let elements = datasize / esize;

        let pairwise = matches!(
            kind,
            FpKind::Addp | FpKind::Maxp | FpKind::Minp | FpKind::MaxNmp | FpKind::MinNmp
        );

        let src1 = self.v[rn].to_le_bytes();
        let src2 = self.v[rm].to_le_bytes();
        let old_d = self.v[rd].to_le_bytes();
        let mut dst = [0u8; 16];

        let mut concat = [0u8; 32];
        if pairwise {
            concat[..datasize].copy_from_slice(&src1[..datasize]);
            concat[datasize..datasize * 2].copy_from_slice(&src2[..datasize]);
        }

        for e in 0..elements {
            let off = e * esize;
            let (a, b) = if pairwise {
                (
                    read_elem(&concat, (2 * e) * esize, esize),
                    read_elem(&concat, (2 * e + 1) * esize, esize),
                )
            } else {
                (read_elem(&src1, off, esize), read_elem(&src2, off, esize))
            };
            let d = read_elem(&old_d, off, esize);
            let res = if pairwise {
                sve_fp_pairwise_reduce_combine_with_fpcr(kind, esize, a, b, self.fpcr)
            } else if sz == 0 {
                fp_three_same_f32_with_fpcr(kind, a as u32, b as u32, d as u32, self.fpcr) as u64
            } else {
                fp_three_same_f64_with_fpcr(kind, a, b, d, self.fpcr)
            };
            self.fpsr |= if pairwise {
                fp_pairwise_reduce_status_with_fpcr(esize, kind, a, b, res, self.fpcr)
            } else {
                fp_three_same_status_with_fpcr(esize, kind, a, b, d, res, self.fpcr)
            };
            write_elem(&mut dst, off, esize, res);
        }

        self.v[rd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }

    /// Deterministic FP two-register-misc ops (FABS/FNEG/FSQRT, FRINT*, FCVT* to
    /// integer, SCVTF/UCVTF, FCMxx #0). Returns `None` for the estimate ops and
    /// FP narrow/long forms so the caller can fall through.
    pub(crate) fn exec_simd_two_reg_fp(&mut self, insn: u32) -> Option<Result<CpuExit, ArmError>> {
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let sz_hi = (insn >> 23) & 1;
        let sz = (insn >> 22) & 1; // 0 => f32, 1 => f64
        let opcode = (insn >> 12) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;
        let scalar = ((insn >> 24) & 0x1F) == 0b11110;

        // FRINT32X/Z (opcode 11110) and FRINT64X/Z (opcode 11111), sz_hi==0.
        // U selects X(round per mode)/Z(toward zero); bit22 selects f32/f64.
        if sz_hi == 0 && (opcode == 0b11110 || opcode == 0b11111) {
            let intsize = if opcode == 0b11110 { 32 } else { 64 };
            let z = u == 0;
            let esize = if sz == 0 { 4usize } else { 8 };
            if sz == 1 && q == 0 && !scalar {
                return Some(Err(ArmError::UndefinedInstruction(insn)));
            }
            let datasize = if scalar {
                esize
            } else if q == 1 {
                16
            } else {
                8
            };
            let src = self.v[rn].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..(datasize / esize) {
                let off = e * esize;
                let a = read_elem(&src, off, esize);
                let r = if esize == 4 {
                    frint_ts_f32_with_fpcr(a as u32, intsize, z, self.fpcr) as u64
                } else {
                    frint_ts_f64_with_fpcr(a, intsize, z, self.fpcr)
                };
                self.fpsr |= if esize == 4 {
                    fp_status_frint_ts_f32_with_fpcr(a as u32, intsize, z, self.fpcr)
                } else {
                    fp_status_frint_ts_f64_with_fpcr(a, intsize, z, self.fpcr)
                };
                write_elem(&mut dst, off, esize, r);
            }
            self.v[rd] = u128::from_le_bytes(dst);
            return Some(Ok(CpuExit::Continue));
        }

        // FCVTL/FCVTL2 (opcode 10111, U=0), FCVTN/FCVTN2 (10110, U=0) and
        // FCVTXN/FCVTXN2 (10110, U=1): FP convert long/narrow. sz(bit22) selects
        // the f16<->f32 (0) vs f32<->f64 (1) pair. (BFCVTN size==10 is handled
        // before reaching here.)
        if opcode == 0b10110 || opcode == 0b10111 {
            let long = opcode == 0b10111;
            let round_odd = !long && u == 1; // FCVTXN
            if round_odd && sz == 0 {
                return Some(Err(ArmError::UndefinedInstruction(insn)));
            }
            let part = q as usize; // FCVTL2/FCVTN2 use the upper half
            if long {
                // Widen: f16->f32 (sz=0) or f32->f64 (sz=1). The source 64-bit
                // half holds 8/sp elements (4 h or 2 s).
                let (sp, dp) = if sz == 0 { (2usize, 4usize) } else { (4, 8) };
                let nelem = 8 / sp;
                let src = self.v[rn].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..nelem {
                    let s = read_elem(&src, part * 8 + e * sp, sp);
                    let r = fp_cvt_elem(s, sp, dp, false, self.fpcr);
                    self.fpsr |= fp_status_cvt_precision_with_fpcr(s, sp, dp, r, self.fpcr);
                    write_elem(&mut dst, e * dp, dp, r);
                }
                self.v[rd] = u128::from_le_bytes(dst);
            } else {
                // Narrow: f32->f16 (sz=0) or f64->f32 (sz=1, or FCVTX round-odd).
                // The full 128-bit source holds 16/sp elements (4 s or 2 d).
                let (sp, dp) = if sz == 0 { (4usize, 2usize) } else { (8, 4) };
                let nelem = if scalar { 1 } else { 16 / sp };
                let src = self.v[rn].to_le_bytes();
                let mut dst = if scalar || part == 0 {
                    [0u8; 16]
                } else {
                    self.v[rd].to_le_bytes()
                };
                let base = if scalar { 0 } else { part * 8 };
                for e in 0..nelem {
                    let s = read_elem(&src, e * sp, sp);
                    let r = fp_cvt_elem(s, sp, dp, round_odd, self.fpcr);
                    self.fpsr |= fp_status_cvt_precision_with_fpcr_rounding(
                        s, sp, dp, r, round_odd, self.fpcr,
                    );
                    write_elem(&mut dst, base + e * dp, dp, r);
                }
                self.v[rd] = u128::from_le_bytes(dst);
            }
            return Some(Ok(CpuExit::Continue));
        }

        // SCVTF / UCVTF take an integer source, so they bypass the float helper.
        let cvtf = match (u, sz_hi, opcode) {
            (0, 0, 0b11101) => Some(false), // SCVTF
            (1, 0, 0b11101) => Some(true),  // UCVTF
            _ => None,
        };
        let kind = match (u, sz_hi, opcode) {
            (0, 1, 0b01111) => Some(TwoRegFp::Fabs),
            (1, 1, 0b01111) => Some(TwoRegFp::Fneg),
            (1, 1, 0b11111) => Some(TwoRegFp::Fsqrt),
            (0, 0, 0b11000) => Some(TwoRegFp::RintN),
            (0, 1, 0b11000) => Some(TwoRegFp::RintP),
            (1, 0, 0b11000) => Some(TwoRegFp::RintA),
            (0, 0, 0b11001) => Some(TwoRegFp::RintM),
            (0, 1, 0b11001) => Some(TwoRegFp::RintZ),
            (1, 0, 0b11001) => Some(TwoRegFp::RintX),
            (1, 1, 0b11001) => Some(TwoRegFp::RintI),
            (0, 0, 0b11010) => Some(TwoRegFp::CvtNS),
            (0, 1, 0b11010) => Some(TwoRegFp::CvtPS),
            (1, 0, 0b11010) => Some(TwoRegFp::CvtNU),
            (1, 1, 0b11010) => Some(TwoRegFp::CvtPU),
            (0, 0, 0b11011) => Some(TwoRegFp::CvtMS),
            (0, 1, 0b11011) => Some(TwoRegFp::CvtZS),
            (1, 0, 0b11011) => Some(TwoRegFp::CvtMU),
            (1, 1, 0b11011) => Some(TwoRegFp::CvtZU),
            (0, 0, 0b11100) => Some(TwoRegFp::CvtAS),
            (1, 0, 0b11100) => Some(TwoRegFp::CvtAU),
            (0, 1, 0b01100) => Some(TwoRegFp::CmGt),
            (1, 1, 0b01100) => Some(TwoRegFp::CmGe),
            (0, 1, 0b01101) => Some(TwoRegFp::CmEq),
            (1, 1, 0b01101) => Some(TwoRegFp::CmLe),
            (0, 1, 0b01110) => Some(TwoRegFp::CmLt),
            _ => None,
        };
        // URECPE (U=0) / URSQRTE (U=1): unsigned 32-bit integer estimates,
        // sz_hi=1, opcode 11100.
        if (insn >> 23) & 1 == 1 && opcode == 0b11100 {
            if sz != 0 {
                return Some(Err(ArmError::UndefinedInstruction(insn)));
            }
            let datasize = if scalar {
                4usize
            } else if q == 1 {
                16
            } else {
                8
            };
            let elements = datasize / 4;
            let src = self.v[rn].to_le_bytes();
            let mut dst = [0u8; 16];
            let is_rsqrt = (insn >> 29) & 1 == 1;
            for e in 0..elements {
                let off = e * 4;
                let a = read_elem(&src, off, 4) as u32;
                let r = if is_rsqrt {
                    unsigned_rsqrt_estimate(a)
                } else {
                    unsigned_recip_estimate(a)
                };
                write_elem(&mut dst, off, 4, r as u64);
            }
            self.v[rd] = u128::from_le_bytes(dst);
            return Some(Ok(CpuExit::Continue));
        }

        // FRECPE (U=0) / FRSQRTE (U=1): estimate ops, sz_hi=1, opcode 11101.
        if (insn >> 23) & 1 == 1 && opcode == 0b11101 {
            let is_rsqrt = (insn >> 29) & 1 == 1;
            if sz == 1 && q == 0 && !scalar {
                return Some(Err(ArmError::UndefinedInstruction(insn)));
            }
            let esize = if sz == 0 { 4usize } else { 8 };
            let datasize = if scalar {
                esize
            } else if q == 1 {
                16
            } else {
                8
            };
            let elements = datasize / esize;
            let src = self.v[rn].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..elements {
                let off = e * esize;
                let raw = read_elem(&src, off, esize);
                let a = fp_estimate_input_with_fpcr(raw, (esize * 8) as u32, self.fpcr);
                let r = match (is_rsqrt, sz == 0) {
                    (false, true) => fp_recip_estimate_f32(a as u32) as u64,
                    (false, false) => fp_recip_estimate_f64(a),
                    (true, true) => fp_rsqrt_estimate_f32_with_fpcr(a as u32, self.fpcr) as u64,
                    (true, false) => fp_rsqrt_estimate_f64_with_fpcr(a, self.fpcr),
                };
                self.fpsr |= fp_status_estimate_with_fpcr(esize, is_rsqrt, raw, r, self.fpcr);
                write_elem(&mut dst, off, esize, r);
            }
            self.v[rd] = u128::from_le_bytes(dst);
            return Some(Ok(CpuExit::Continue));
        }

        // FRECPX (reciprocal exponent): sz_hi=1, opcode 11111, U=0. Scalar-only
        // in AArch64 (no vector form), so only lane 0 is written and the rest of
        // the register is zeroed.
        if (insn >> 23) & 1 == 1 && opcode == 0b11111 && u == 0 {
            if !scalar {
                return Some(Err(ArmError::UndefinedInstruction(insn)));
            }
            let esize = if sz == 0 { 4usize } else { 8 };
            let raw = read_elem(&self.v[rn].to_le_bytes(), 0, esize);
            let a = fp_flush_input_bits_with_fpcr(raw, (esize * 8) as u32, self.fpcr);
            let mut dst = [0u8; 16];
            let r = sve_fp_recpx(esize, a);
            if fp_is_snan_bits(esize, a) {
                self.fpsr |= FPSR_IOC;
            }
            if self.fpcr & FPCR_AH == 0 {
                self.fpsr |= fp_fz_input_status(esize, raw, self.fpcr);
            }
            write_elem(&mut dst, 0, esize, r);
            self.v[rd] = u128::from_le_bytes(dst);
            return Some(Ok(CpuExit::Continue));
        }

        if kind.is_none() && cvtf.is_none() {
            return None;
        }

        if sz == 1 && q == 0 && !scalar {
            return Some(Err(ArmError::UndefinedInstruction(insn)));
        }
        let esize = if sz == 0 { 4usize } else { 8 };
        let datasize = if scalar {
            esize
        } else if q == 1 {
            16
        } else {
            8
        };
        let elements = datasize / esize;
        let src = self.v[rn].to_le_bytes();
        let mut dst = [0u8; 16];
        for e in 0..elements {
            let off = e * esize;
            let a = read_elem(&src, off, esize);
            let r = if let Some(unsigned) = cvtf {
                let (negative, raw_int) = if unsigned {
                    if sz == 0 {
                        (false, (a as u32) as u128)
                    } else {
                        (false, a as u128)
                    }
                } else if sz == 0 {
                    let x = a as u32 as i32;
                    (x < 0, (x as i128).unsigned_abs())
                } else {
                    let x = a as i64;
                    (x < 0, (x as i128).unsigned_abs())
                };
                let r = if sz == 0 {
                    int_to_fp32_bits_with_fpcr(raw_int, negative, self.fpcr) as u64
                } else {
                    int_to_fp64_bits_with_fpcr(raw_int, negative, self.fpcr)
                };
                self.fpsr |= fp_status_int_to_fp_scaled(raw_int, esize, r);
                r
            } else if sz == 0 {
                fp_two_reg_f32_with_fpcr(kind.unwrap(), a as u32, self.fpcr) as u64
            } else {
                fp_two_reg_f64_with_fpcr(kind.unwrap(), a, self.fpcr)
            };
            if let Some(kind) = kind {
                self.fpsr |= fp_status_unop_with_fpcr(esize, Some(kind), a, r, self.fpcr);
                self.fpsr |= fp_status_fp_to_int_unop_with_fpcr(esize, kind, a, self.fpcr);
            }
            write_elem(&mut dst, off, esize, r);
        }
        self.v[rd] = u128::from_le_bytes(dst);
        Some(Ok(CpuExit::Continue))
    }
}

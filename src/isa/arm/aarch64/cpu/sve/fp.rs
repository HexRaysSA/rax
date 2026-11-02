//! fp.rs

use crate::isa::arm::aarch64::cpu::*;
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
    pub(crate) fn exec_sve_fp_pred(
        &mut self,
        insn: u32,
        zd: usize,
        zn: usize,
        zm: usize,
        pg: usize,
        esize: usize,
    ) -> Result<CpuExit, ArmError> {
        // FEAT_SVE_B16B16 bf16 arithmetic (BFADD/BFSUB/BFMUL/BFMAX/BFMIN/
        // BFMAXNM/BFMINNM, BFMLA/BFMLS, indexed BFMUL/BFMLA/BFMLS, BFCLAMP).
        // These use the size==00 encoding slots, distinct from the f16/f32/f64
        // ops handled below, so intercept them first.
        if let Some(r) = self.try_exec_sve_bf16(insn) {
            return r;
        }

        // SVE unpredicated FADD/FSUB/FMUL (vectors): 0x65, bit21==0,
        // bits[15:12]==0000, opc=bits[11:10]. Size 00 is BF16 and is handled
        // above by the optional FEAT_SVE_B16B16 path.
        if (insn >> 24) & 0xFF == 0b01100101
            && (insn >> 21) & 1 == 0
            && (insn >> 12) & 0xF == 0
            && (insn >> 10) & 0x3 != 0b11
        {
            let kind = match (insn >> 10) & 0x3 {
                0b00 => FpKind::Add,
                0b01 => FpKind::Sub,
                0b10 => FpKind::Mul,
                _ => unreachable!(),
            };
            if esize < 2 {
                return Ok(CpuExit::Undefined(insn));
            }
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zm].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..(16 / esize) {
                let off = e * esize;
                let a = read_elem(&n, off, esize);
                let b = read_elem(&m, off, esize);
                let r = match esize {
                    2 => sve_fp16_binop_with_fpcr(kind, a as u16, b as u16, self.fpcr) as u64,
                    4 => fp_three_same_f32_with_fpcr(kind, a as u32, b as u32, 0, self.fpcr) as u64,
                    8 => fp_three_same_f64_with_fpcr(kind, a, b, 0, self.fpcr),
                    _ => return Ok(CpuExit::Undefined(insn)),
                };
                self.fpsr |= fp_three_same_status_with_fpcr(esize, kind, a, b, 0, r, self.fpcr);
                write_elem(&mut dst, off, esize, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE BFDOT (bf16 dot product, round-to-odd): 0x64, bits[23:22]==01,
        // bit21==1, bits[15:10]==100000 (zzzz) or 010000 (zzxw indexed). Each
        // f32 lane sums two bf16 products; the indexed form broadcasts Zm's
        // 32-bit group at `index` (bits[20:19], Zm in bits[18:16]).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 22) & 0x3 == 0b01
            && (insn >> 21) & 1 == 1
            && matches!((insn >> 10) & 0x3F, 0b100000 | 0b010000)
        {
            let indexed = (insn >> 10) & 0x3F == 0b010000;
            let (m, a) = (
                if indexed {
                    self.v[((insn >> 16) & 0x7) as usize]
                } else {
                    self.v[zm]
                },
                self.v[zd],
            );
            let n = self.v[zn];
            let m_idx = if indexed {
                (m >> (((insn >> 19) & 0x3) * 32)) as u32
            } else {
                0
            };
            let mut r = 0u128;
            for e in 0..4 {
                let m_pair = if indexed {
                    m_idx
                } else {
                    (m >> (e * 32)) as u32
                };
                let res = bf16_dot_result_with_fpcr(
                    sve_bfdot_lane((a >> (e * 32)) as u32, (n >> (e * 32)) as u32, m_pair),
                    self.fpcr,
                );
                r |= (res as u128) << (e * 32);
            }
            self.v[zd] = r;
            return Ok(CpuExit::Continue);
        }

        // SVE2.1 FDOT (FP 2-way dot product, f16 -> f32): 0x64, bits[23:22]==00,
        // bit21==1, bits[15:10]==100000 (zzzz) or 010000 (zzxz indexed). Each f32
        // lane sums two f16 products (single-rounded) into the accumulator; the
        // indexed form broadcasts Zm's 32-bit group at index=bits[20:19]
        // (Zm=bits[18:16]).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 22) & 0x3 == 0b00
            && (insn >> 21) & 1 == 1
            && matches!((insn >> 10) & 0x3F, 0b100000 | 0b010000)
        {
            if !self.config.features.contains(ArmFeatures::SVE2P1) {
                return Ok(CpuExit::Undefined(insn));
            }
            let indexed = (insn >> 10) & 0x3F == 0b010000;
            let n = self.v[zn];
            let (m, a) = if indexed {
                (self.v[((insn >> 16) & 0x7) as usize], self.v[zd])
            } else {
                (self.v[zm], self.v[zd])
            };
            let m_idx = if indexed {
                (m >> (((insn >> 19) & 0x3) * 32)) as u32
            } else {
                0
            };
            let mut r = 0u128;
            for e in 0..4 {
                let m_pair = if indexed {
                    m_idx
                } else {
                    (m >> (e * 32)) as u32
                };
                let res = f16_dotadd((a >> (e * 32)) as u32, (n >> (e * 32)) as u32, m_pair);
                r |= (res as u128) << (e * 32);
            }
            self.v[zd] = r;
            return Ok(CpuExit::Continue);
        }

        // SVE2 FMLAL/FMLSL (f16) and BFMLALB/T, BFMLSLB/T (bf16) widening fused
        // multiply-add into f32: 0x64, bit21==1, bits[15:11]==10000 (add) or
        // 10100 (sub); bit10 picks the odd(T)/even(B) lane. bits[23:22] selects
        // the source format: 10=f16, 11=bf16 (the bf16 subtract form BFMLSL is
        // FEAT_SVE2p1). The narrow inputs are widened to f32 (bf16 by a 16-bit
        // left shift, f16 by the standard widening) and accumulated with a
        // single ARM-correct fused multiply-add (processing the addend NaN
        // first); FMLSL/BFMLSL negate the Zn input (the FPCR.AH=0 form,
        // matching the oracle).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 21) & 1 == 1
            && matches!((insn >> 22) & 0x3, 0b10 | 0b11)
            && matches!((insn >> 11) & 0x1F, 0b10000 | 0b10100)
        {
            let bf = (insn >> 22) & 0x3 == 0b11;
            let sub = (insn >> 13) & 1 == 1;
            if bf && sub && !self.config.features.contains(ArmFeatures::SVE2P1) {
                return Ok(CpuExit::Undefined(insn));
            }
            let top = (insn >> 10) & 1 == 1;
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zm].to_le_bytes();
            let acc = self.v[zd].to_le_bytes();
            let fpcr = self.fpcr;
            let widen = |b: u16| -> u32 {
                if bf {
                    (b as u32) << 16
                } else {
                    let b = fp16_flush_input_with_fpcr(b, fpcr);
                    Self::fp16_to_f32(b).to_bits()
                }
            };
            let mut dst = acc;
            for j in 0..4 {
                let h_off = (2 * j + top as usize) * 2;
                let nbits = read_elem(&n, h_off, 2) as u16;
                let nbits = if sub {
                    fp_neg_bits_with_fpcr(nbits as u64, 16, self.fpcr) as u16
                } else {
                    nbits
                };
                let nn_raw = widen(nbits) as u64;
                let mm_raw = widen(read_elem(&m, h_off, 2) as u16) as u64;
                let aa_raw = read_elem(&acc, j * 4, 4);
                let nn = if bf {
                    bfmlal_f32_input_with_fpcr(nn_raw as u32, self.fpcr)
                } else {
                    fp_flush_input_bits_with_fpcr(nn_raw, 32, self.fpcr) as u32
                };
                let mm = if bf {
                    bfmlal_f32_input_with_fpcr(mm_raw as u32, self.fpcr)
                } else {
                    fp_flush_input_bits_with_fpcr(mm_raw, 32, self.fpcr) as u32
                };
                let aa = if bf {
                    bfmlal_f32_input_with_fpcr(aa_raw as u32, self.fpcr)
                } else {
                    fp_flush_input_bits_with_fpcr(aa_raw, 32, self.fpcr) as u32
                };
                let ah_nan_result = if !bf && self.fpcr & FPCR_AH != 0 {
                    fmlal_ah_result(aa_raw as u32, nn_raw as u32, mm_raw as u32, self.fpcr)
                } else {
                    None
                };
                let r = if bf {
                    bfmlal_ah_result(aa_raw as u32, nn_raw as u32, mm_raw as u32, self.fpcr)
                } else {
                    ah_nan_result
                }
                .or_else(|| {
                    fmlal_default_invalid_result(aa as u32, nn as u32, mm as u32, self.fpcr)
                })
                .unwrap_or_else(|| {
                    fp_muladd_bits_with_fpcr(aa as u64, nn as u64, mm as u64, 32, self.fpcr) as u32
                });
                let mut status = if bf && self.fpcr & FPCR_AH != 0 {
                    0
                } else {
                    fp_status_fma(4, aa as u64, nn as u64, mm as u64, r as u64)
                };
                if !(bf && self.fpcr & FPCR_AH != 0)
                    && bf
                    && fp_fz_fma_output(4, aa as u64, nn as u64, mm as u64, r as u64, self.fpcr)
                        .is_some()
                {
                    status &= !FPSR_IXC;
                }
                let input_status = if bf {
                    bfmlal_f32_input_status(aa_raw, self.fpcr)
                        | bfmlal_f32_input_status(nn_raw, self.fpcr)
                        | bfmlal_f32_input_status(mm_raw, self.fpcr)
                } else if ah_nan_result.is_some() {
                    0
                } else {
                    fp_fz_input_status(4, aa_raw, self.fpcr)
                        | fp_fz_input_status(4, nn_raw, self.fpcr)
                        | fp_fz_input_status(4, mm_raw, self.fpcr)
                };
                self.fpsr |= status | input_status;
                write_elem(&mut dst, j * 4, 4, r as u64);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE2 FMLAL/FMLSL (f16) and BFMLALB/T, BFMLSLB/T (bf16) by indexed
        // element: 0x64, bit21==1, bits[23:22]==10(f16)/11(bf16),
        // bits[15:14]==01, bit12==0. sub=bit13, T=bit10, Zm=bits[18:16],
        // index=(bits[20:19]<<1)|bit11. Like the non-indexed form but Zm.h[index]
        // is the broadcast second factor; the FMA uses the ARM-correct
        // float32_muladd (addend NaN processed first).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 21) & 1 == 1
            && matches!((insn >> 22) & 0x3, 0b10 | 0b11)
            && (insn >> 14) & 0x3 == 0b01
            && (insn >> 12) & 1 == 0
        {
            let bf = (insn >> 22) & 0x3 == 0b11;
            let sub = (insn >> 13) & 1 == 1; // FMLSL / BFMLSL
            if bf && sub && !self.config.features.contains(ArmFeatures::SVE2P1) {
                return Ok(CpuExit::Undefined(insn));
            }
            let top = (insn >> 10) & 1 == 1; // odd half of Zn
            let index = ((((insn >> 19) & 0x3) << 1) | ((insn >> 11) & 1)) as usize;
            let zmr = ((insn >> 16) & 0x7) as usize;
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zmr].to_le_bytes();
            let acc = self.v[zd].to_le_bytes();
            let fpcr = self.fpcr;
            let widen = |b: u16| -> u32 {
                if bf {
                    (b as u32) << 16
                } else {
                    let b = fp16_flush_input_with_fpcr(b, fpcr);
                    Self::fp16_to_f32(b).to_bits()
                }
            };
            let mm_raw = widen(read_elem(&m, index * 2, 2) as u16) as u64;
            let mm = if bf {
                bfmlal_f32_input_with_fpcr(mm_raw as u32, self.fpcr)
            } else {
                fp_flush_input_bits_with_fpcr(mm_raw, 32, self.fpcr) as u32
            }; // Zm.h[index]
            let mut dst = acc;
            for j in 0..4 {
                let h_off = (2 * j + top as usize) * 2;
                let nbits = read_elem(&n, h_off, 2) as u16;
                let nbits = if sub {
                    fp_neg_bits_with_fpcr(nbits as u64, 16, self.fpcr) as u16
                } else {
                    nbits
                };
                let nn_raw = widen(nbits) as u64;
                let aa_raw = read_elem(&acc, j * 4, 4);
                let nn = if bf {
                    bfmlal_f32_input_with_fpcr(nn_raw as u32, self.fpcr)
                } else {
                    fp_flush_input_bits_with_fpcr(nn_raw, 32, self.fpcr) as u32
                };
                let aa = if bf {
                    bfmlal_f32_input_with_fpcr(aa_raw as u32, self.fpcr)
                } else {
                    fp_flush_input_bits_with_fpcr(aa_raw, 32, self.fpcr) as u32
                };
                let ah_nan_result = if !bf && self.fpcr & FPCR_AH != 0 {
                    fmlal_ah_result(aa_raw as u32, nn_raw as u32, mm_raw as u32, self.fpcr)
                } else {
                    None
                };
                let r = if bf {
                    bfmlal_ah_result(aa_raw as u32, nn_raw as u32, mm_raw as u32, self.fpcr)
                } else {
                    ah_nan_result
                }
                .or_else(|| {
                    fmlal_default_invalid_result(aa as u32, nn as u32, mm as u32, self.fpcr)
                })
                .unwrap_or_else(|| {
                    fp_muladd_bits_with_fpcr(aa as u64, nn as u64, mm as u64, 32, self.fpcr) as u32
                });
                let mut status = if bf && self.fpcr & FPCR_AH != 0 {
                    0
                } else {
                    fp_status_fma(4, aa as u64, nn as u64, mm as u64, r as u64)
                };
                if !(bf && self.fpcr & FPCR_AH != 0)
                    && bf
                    && fp_fz_fma_output(4, aa as u64, nn as u64, mm as u64, r as u64, self.fpcr)
                        .is_some()
                {
                    status &= !FPSR_IXC;
                }
                let input_status = if bf {
                    bfmlal_f32_input_status(aa_raw, self.fpcr)
                        | bfmlal_f32_input_status(nn_raw, self.fpcr)
                        | bfmlal_f32_input_status(mm_raw, self.fpcr)
                } else if ah_nan_result.is_some() {
                    0
                } else {
                    fp_fz_input_status(4, aa_raw, self.fpcr)
                        | fp_fz_input_status(4, nn_raw, self.fpcr)
                        | fp_fz_input_status(4, mm_raw, self.fpcr)
                };
                self.fpsr |= status | input_status;
                write_elem(&mut dst, j * 4, 4, r as u64);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE FMMLA / BFMMLA (FP matrix multiply-accumulate): 0x64, bit21==1,
        // bits[15:10]==111001. bits[23:22]: 01=BFMMLA, 10=FMMLA.s, 11=FMMLA.d.
        // The 2x2 f32 tile is N(row i) . M(row j) with plain (non-fused) mul/add.
        // FMMLA.d needs a 256-bit segment (VL >= 4*8 bytes), so at VL=128 it is
        // an unallocated encoding. BFMMLA reuses the NEON path (same semantics).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 21) & 1 == 1
            && (insn >> 10) & 0x3F == 0b111001
        {
            match (insn >> 22) & 0x3 {
                0b01 => return self.exec_simd_bfmmla(insn),
                0b10 => {
                    if !self.config.features.contains(ArmFeatures::SVE_F32MM) {
                        return Ok(CpuExit::Undefined(insn));
                    }
                    let (n, m, a) = (self.v[zn], self.v[zm], self.v[zd]);
                    let f = |v: u128, i: u32| f32::from_bits((v >> (i * 32)) as u32);
                    let (n00, n01, n10, n11) = (f(n, 0), f(n, 1), f(n, 2), f(n, 3));
                    let (m00, m01, m10, m11) = (f(m, 0), f(m, 1), f(m, 2), f(m, 3));
                    let d = [
                        f(a, 0) + (n00 * m00 + n01 * m01),
                        f(a, 1) + (n00 * m10 + n01 * m11),
                        f(a, 2) + (n10 * m00 + n11 * m01),
                        f(a, 3) + (n10 * m10 + n11 * m11),
                    ];
                    let mut r = 0u128;
                    for (i, v) in d.iter().enumerate() {
                        r |= (v.to_bits() as u128) << (i * 32);
                    }
                    self.v[zd] = r;
                    return Ok(CpuExit::Continue);
                }
                // FMMLA.d (esz=3): VL=128 < 4*8 bytes, so it is unallocated.
                _ => return Ok(CpuExit::Undefined(insn)),
            }
        }

        // SVE FCADD (FP complex add, predicated): 0x64, bits[21:17]==00000,
        // bits[15:13]==100. rot=bit16 (0=90,1=270). Per complex pair, merging:
        // re = Zdn_re + (rot? Zm_im : -Zm_im); im = Zdn_im + (rot? -Zm_re : Zm_re).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 17) & 0x1F == 0
            && (insn >> 13) & 0x7 == 0b100
        {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let bits = 8u32 << size;
            let esz = (bits / 8) as usize;
            let rot = (insn >> 16) & 1;
            let (dn, zmv) = (self.v[zd], self.v[zn]); // Zdn, Zm
            let pred = self.sve_p[pg];
            let mask = elem_mask(bits) as u128;
            let elem = |v: u128, idx: usize| ((v >> (idx * bits as usize)) & mask) as u64;
            let mut result = dn;
            for e in 0..(16 / (2 * esz)) {
                let (re, im) = (2 * e, 2 * e + 1);
                let (add_re, add_im) = if rot == 0 {
                    (
                        fp_neg_bits_with_fpcr(elem(zmv, im), bits, self.fpcr),
                        elem(zmv, re),
                    )
                } else {
                    (
                        elem(zmv, im),
                        fp_neg_bits_with_fpcr(elem(zmv, re), bits, self.fpcr),
                    )
                };
                if (pred >> (re * esz)) & 1 == 1 {
                    let lhs = elem(dn, re);
                    let r = fp_add_bits_with_fpcr(lhs, add_re, bits, self.fpcr);
                    self.fpsr |=
                        fp_status_binop_with_fpcr(esz, FpKind::Add, lhs, add_re, r, self.fpcr);
                    result = (result & !(mask << (re * bits as usize)))
                        | ((r as u128 & mask) << (re * bits as usize));
                }
                if (pred >> (im * esz)) & 1 == 1 {
                    let lhs = elem(dn, im);
                    let r = fp_add_bits_with_fpcr(lhs, add_im, bits, self.fpcr);
                    self.fpsr |=
                        fp_status_binop_with_fpcr(esz, FpKind::Add, lhs, add_im, r, self.fpcr);
                    result = (result & !(mask << (im * bits as usize)))
                        | ((r as u128 & mask) << (im * bits as usize));
                }
            }
            self.v[zd] = result;
            return Ok(CpuExit::Continue);
        }

        // SVE FCMLA (FP complex multiply-add, predicated): 0x64, bit21==0,
        // bit15==0. rot=bits[14:13]; Zn=bits[9:5], Zm=bits[20:16], Zda=Zd. Per
        // complex pair, merging, same operand selection as NEON FCMLA.
        if (insn >> 24) & 0xFF == 0b01100100 && (insn >> 21) & 1 == 0 && (insn >> 15) & 1 == 0 {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let bits = 8u32 << size;
            let esz = (bits / 8) as usize;
            let rot = (insn >> 13) & 0x3;
            let (n, mv, acc) = (self.v[zn], self.v[zm], self.v[zd]);
            let pred = self.sve_p[pg];
            let mask = elem_mask(bits) as u128;
            let elem = |v: u128, idx: usize| ((v >> (idx * bits as usize)) & mask) as u64;
            let mut result = acc;
            for e in 0..(16 / (2 * esz)) {
                let (re, im) = (2 * e, 2 * e + 1);
                let (a_re_raw, a_im_raw) = (elem(n, re), elem(n, im));
                let (b_re_raw, b_im_raw) = (elem(mv, re), elem(mv, im));
                let (a_re, a_im) = (
                    fp_flush_input_bits_with_fpcr(a_re_raw, bits, self.fpcr),
                    fp_flush_input_bits_with_fpcr(a_im_raw, bits, self.fpcr),
                );
                let (b_re, b_im) = (
                    fp_flush_input_bits_with_fpcr(b_re_raw, bits, self.fpcr),
                    fp_flush_input_bits_with_fpcr(b_im_raw, bits, self.fpcr),
                );
                let (xr, yr, xi, yi) = match rot {
                    0b00 => (a_re, b_re, a_re, b_im),
                    0b01 => (
                        a_im,
                        fp_neg_bits_with_fpcr(b_im, bits, self.fpcr),
                        a_im,
                        b_re,
                    ),
                    0b10 => (
                        a_re,
                        fp_neg_bits_with_fpcr(b_re, bits, self.fpcr),
                        a_re,
                        fp_neg_bits_with_fpcr(b_im, bits, self.fpcr),
                    ),
                    _ => (
                        a_im,
                        b_im,
                        a_im,
                        fp_neg_bits_with_fpcr(b_re, bits, self.fpcr),
                    ),
                };
                let (xr_raw, yr_raw, xi_raw, yi_raw) = match rot {
                    0b00 => (a_re_raw, b_re_raw, a_re_raw, b_im_raw),
                    0b01 => (
                        a_im_raw,
                        fp_neg_bits_with_fpcr(b_im_raw, bits, self.fpcr),
                        a_im_raw,
                        b_re_raw,
                    ),
                    0b10 => (
                        a_re_raw,
                        fp_neg_bits_with_fpcr(b_re_raw, bits, self.fpcr),
                        a_re_raw,
                        fp_neg_bits_with_fpcr(b_im_raw, bits, self.fpcr),
                    ),
                    _ => (
                        a_im_raw,
                        b_im_raw,
                        a_im_raw,
                        fp_neg_bits_with_fpcr(b_re_raw, bits, self.fpcr),
                    ),
                };
                if (pred >> (re * esz)) & 1 == 1 {
                    let aa_raw = elem(acc, re);
                    let aa = fp_flush_input_bits_with_fpcr(aa_raw, bits, self.fpcr);
                    let r = fp_fcmla_muladd_bits_with_fpcr(aa, xr, yr, bits, self.fpcr);
                    self.fpsr |= fp_status_fma_with_fpcr(esz, aa_raw, xr_raw, yr_raw, r, self.fpcr);
                    result = (result & !(mask << (re * bits as usize)))
                        | ((r as u128 & mask) << (re * bits as usize));
                }
                if (pred >> (im * esz)) & 1 == 1 {
                    let aa_raw = elem(acc, im);
                    let aa = fp_flush_input_bits_with_fpcr(aa_raw, bits, self.fpcr);
                    let r = fp_fcmla_muladd_bits_with_fpcr(aa, xi, yi, bits, self.fpcr);
                    self.fpsr |= fp_status_fma_with_fpcr(esz, aa_raw, xi_raw, yi_raw, r, self.fpcr);
                    result = (result & !(mask << (im * bits as usize)))
                        | ((r as u128 & mask) << (im * bits as usize));
                }
            }
            self.v[zd] = result;
            return Ok(CpuExit::Continue);
        }

        // SVE FP multiply / multiply-add by indexed element: 0x64, bit21==1,
        // bits[15:11]==00000 (FMLA=000000 / FMLS=000001) or bits[15:10]==001000
        // (FMUL). The indexed Zm element is broadcast. Size: bit23==0 -> .h
        // (fp16, bit22 is the index MSB), bits[23:22]==10 -> .s, ==11 -> .d.
        // FMLA/FMLS are fused; FMUL is a plain multiply (unpredicated).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 21) & 1 == 1
            && ((insn >> 11) & 0x1F == 0b00000 || (insn >> 10) & 0x3F == 0b001000)
        {
            let (esz, index, zmr): (usize, usize, usize) = if (insn >> 23) & 1 == 0 {
                // .h: index = bit22:bits[20:19], Zm = bits[18:16].
                let idx = (((insn >> 22) & 1) << 2) | ((insn >> 19) & 0x3);
                (2, idx as usize, ((insn >> 16) & 0x7) as usize)
            } else if (insn >> 22) & 1 == 0 {
                (
                    4,
                    ((insn >> 19) & 0x3) as usize,
                    ((insn >> 16) & 0x7) as usize,
                )
            } else {
                (
                    8,
                    ((insn >> 20) & 1) as usize,
                    ((insn >> 16) & 0xF) as usize,
                )
            };
            let ebits = (esz * 8) as u32;
            let is_fmul = (insn >> 10) & 0x3F == 0b001000;
            let is_fmls = !is_fmul && (insn >> 10) & 1 == 1;
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zmr].to_le_bytes();
            let acc = self.v[zd].to_le_bytes();
            let mm = read_elem(&m, index * esz, esz); // Zm[index]
            let mut dst = acc;
            for e in 0..(16 / esz) {
                let off = e * esz;
                let ne = read_elem(&n, off, esz);
                let (r, status) = if is_fmul {
                    let r = match esz {
                        2 => sve_fp16_binop_with_fpcr(FpKind::Mul, ne as u16, mm as u16, self.fpcr)
                            as u64,
                        4 => fp_three_same_f32_with_fpcr(
                            FpKind::Mul,
                            ne as u32,
                            mm as u32,
                            0,
                            self.fpcr,
                        ) as u64,
                        _ => fp_three_same_f64_with_fpcr(FpKind::Mul, ne, mm, 0, self.fpcr),
                    };
                    (
                        r,
                        fp_status_binop_with_fpcr(esz, FpKind::Mul, ne, mm, r, self.fpcr),
                    )
                } else {
                    let aa_raw = read_elem(&acc, off, esz);
                    let ne_raw = ne;
                    let mm_raw = mm;
                    let (aa, ne, mm) = (
                        fp_flush_input_bits_with_fpcr(aa_raw, ebits, self.fpcr),
                        fp_flush_input_bits_with_fpcr(ne, ebits, self.fpcr),
                        fp_flush_input_bits_with_fpcr(mm, ebits, self.fpcr),
                    );
                    let nn = if is_fmls {
                        fp_neg_bits_with_fpcr(ne, ebits, self.fpcr)
                    } else {
                        ne
                    };
                    let nn_raw = if is_fmls {
                        fp_neg_bits_with_fpcr(ne_raw, ebits, self.fpcr)
                    } else {
                        ne_raw
                    };
                    let r = fp_muladd_bits_with_fpcr(aa, nn, mm, ebits, self.fpcr);
                    let status = fp_status_fma_with_fpcr(esz, aa_raw, nn_raw, mm_raw, r, self.fpcr);
                    (r, fp_status_sve_underflow(esz, r, status))
                };
                self.fpsr |= status;
                write_elem(&mut dst, off, esz, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE FCMLA by indexed element: 0x64, bit21==1, bits[15:12]==0001.
        // rot=bits[11:10]; the indexed Zm complex pair (2*index) is broadcast.
        // Unpredicated, fused. .h: index=bits[20:19], Zm=bits[18:16]; .s:
        // index=bit20, Zm=bits[19:16]. Same flip/negate math as FCMLA.
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 21) & 1 == 1
            && (insn >> 12) & 0xF == 0b0001
        {
            let size = (insn >> 22) & 0x3;
            if size < 2 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esize = 1usize << (size - 1); // .h=2, .s=4
            let bits = (esize * 8) as u32;
            let mask = elem_mask(bits) as u128;
            let rot = (insn >> 10) & 0x3;
            let flip = rot & 1;
            let negf_imag = (rot >> 1) & 1;
            let negf_real = flip ^ negf_imag;
            let (index, zmr) = if size == 2 {
                (((insn >> 19) & 0x3) as usize, ((insn >> 16) & 0x7) as usize)
            } else {
                (((insn >> 20) & 1) as usize, ((insn >> 16) & 0xF) as usize)
            };
            let (n, mv, acc) = (self.v[zn], self.v[zmr], self.v[zd]);
            let elem = |v: u128, e: usize| ((v >> (e * bits as usize)) & mask) as u64;
            let (mr_raw, mi_raw) = (elem(mv, 2 * index), elem(mv, 2 * index + 1));
            let (mr, mi) = (
                fp_flush_input_bits_with_fpcr(mr_raw, bits, self.fpcr),
                fp_flush_input_bits_with_fpcr(mi_raw, bits, self.fpcr),
            );
            let e1b = if flip == 1 { mi } else { mr };
            let e3b = if flip == 1 { mr } else { mi };
            let e1b_raw = if flip == 1 { mi_raw } else { mr_raw };
            let e3b_raw = if flip == 1 { mr_raw } else { mi_raw };
            let e1 = if negf_real == 1 {
                fp_neg_bits_with_fpcr(e1b, bits, self.fpcr)
            } else {
                e1b
            };
            let e3 = if negf_imag == 1 {
                fp_neg_bits_with_fpcr(e3b, bits, self.fpcr)
            } else {
                e3b
            };
            let e1_raw = if negf_real == 1 {
                fp_neg_bits_with_fpcr(e1b_raw, bits, self.fpcr)
            } else {
                e1b_raw
            };
            let e3_raw = if negf_imag == 1 {
                fp_neg_bits_with_fpcr(e3b_raw, bits, self.fpcr)
            } else {
                e3b_raw
            };
            let mut result = acc;
            for p in 0..((16 / esize) / 2) {
                let (re, im) = (2 * p, 2 * p + 1);
                let e2_raw = if flip == 1 { elem(n, im) } else { elem(n, re) };
                let e2 = fp_flush_input_bits_with_fpcr(e2_raw, bits, self.fpcr);
                let ar_raw = elem(acc, re);
                let ai_raw = elem(acc, im);
                let ar = fp_flush_input_bits_with_fpcr(ar_raw, bits, self.fpcr);
                let ai = fp_flush_input_bits_with_fpcr(ai_raw, bits, self.fpcr);
                let dr = fp_fcmla_muladd_bits_with_fpcr(ar, e2, e1, bits, self.fpcr);
                let di = fp_fcmla_muladd_bits_with_fpcr(ai, e2, e3, bits, self.fpcr);
                self.fpsr |= fp_status_fma_with_fpcr(esize, ar_raw, e2_raw, e1_raw, dr, self.fpcr);
                self.fpsr |= fp_status_fma_with_fpcr(esize, ai_raw, e2_raw, e3_raw, di, self.fpcr);
                result = (result & !(mask << (re * bits as usize)))
                    | ((dr as u128 & mask) << (re * bits as usize));
                result = (result & !(mask << (im * bits as usize)))
                    | ((di as u128 & mask) << (im * bits as usize));
            }
            self.v[zd] = result;
            return Ok(CpuExit::Continue);
        }

        // SVE predicated FP fused multiply-add: 0x65, bit21==1. bits[14:13]
        // select FMLA(00)/FMLS(01)/FNMLA(10)/FNMLS(11); bit15 picks the form
        // (0: Zd is the addend Za, multiplicands Zn/Zm; 1: Zd is a multiplicand
        // Zdn with addend Za). neg_prod=bit13^bit14, neg_addend=bit14 (FPCR.AH=0
        // negates via the sign bit). Single fused multiply-add; merging.
        if (insn >> 24) & 0xFF == 0b01100101 && (insn >> 21) & 1 == 1 {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let ebits = (esz * 8) as u32;
            let op3 = (insn >> 13) & 0x7;
            let neg_prod = ((insn >> 13) & 1) ^ ((insn >> 14) & 1) == 1;
            let neg_add = (insn >> 14) & 1 == 1;
            let rm = ((insn >> 16) & 0x1F) as usize;
            let r95 = ((insn >> 5) & 0x1F) as usize;
            // mad form (bit15==1): Zdn=zd is a multiplicand, Zm=bits[9:5],
            // addend=bits[20:16]. else: Zn=bits[9:5], Zm=bits[20:16], addend=Za=zd.
            let (n_reg, m_reg, a_reg) = if (insn >> 15) & 1 == 1 {
                (zd, r95, rm)
            } else {
                (r95, rm, zd)
            };
            let pred = self.sve_p[pg];
            let nb = self.v[n_reg].to_le_bytes();
            let mb = self.v[m_reg].to_le_bytes();
            let ab = self.v[a_reg].to_le_bytes();
            let mut dst = self.v[zd].to_le_bytes();
            for e in 0..(16 / esz) {
                let off = e * esz;
                if (pred >> off) & 1 == 0 {
                    continue;
                }
                let a_raw = read_elem(&ab, off, esz);
                let n_raw = read_elem(&nb, off, esz);
                let m_raw = read_elem(&mb, off, esz);
                let mut a = a_raw;
                let mut n = n_raw;
                let mut m = m_raw;
                if matches!(op3, 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7) {
                    n = fp_flush_input_bits_with_fpcr(n, ebits, self.fpcr);
                    m = fp_flush_input_bits_with_fpcr(m, ebits, self.fpcr);
                    a = fp_flush_input_bits_with_fpcr(a, ebits, self.fpcr);
                }
                let mut a_status = a_raw;
                let mut n_status = n_raw;
                if neg_prod {
                    n = fp_neg_bits_with_fpcr(n, ebits, self.fpcr);
                    n_status = fp_neg_bits_with_fpcr(n_status, ebits, self.fpcr);
                }
                if neg_add {
                    a = fp_neg_bits_with_fpcr(a, ebits, self.fpcr);
                    a_status = fp_neg_bits_with_fpcr(a_status, ebits, self.fpcr);
                }
                let r = fp_muladd_bits_with_fpcr(a, n, m, ebits, self.fpcr);
                let status = fp_status_fma_with_fpcr(esz, a_status, n_status, m_raw, r, self.fpcr);
                self.fpsr |= fp_status_sve_underflow(esz, r, status);
                write_elem(&mut dst, off, esz, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE FRECPE / FRSQRTE (reciprocal / reciprocal-sqrt estimate,
        // unpredicated): 0x65, bits[21:16]==001110 (FRECPE) / 001111 (FRSQRTE),
        // bits[15:10]==001100. Reuses the FP estimate helpers.
        if (insn >> 24) & 0xFF == 0b01100101
            && matches!((insn >> 16) & 0x3F, 0b001110 | 0b001111)
            && (insn >> 10) & 0x3F == 0b001100
        {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let rsqrt = (insn >> 16) & 1 == 1;
            let n = self.v[zn].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..(16 / esz) {
                let off = e * esz;
                let raw = read_elem(&n, off, esz);
                let x = fp_estimate_input_with_fpcr(raw, (esz * 8) as u32, self.fpcr);
                let r = match esz {
                    2 => {
                        (if rsqrt {
                            fp16_rsqrte_with_fpcr(x as u16, self.fpcr)
                        } else {
                            fp16_recpe(x as u16)
                        }) as u64
                    }
                    4 => {
                        (if rsqrt {
                            fp_rsqrt_estimate_f32_with_fpcr(x as u32, self.fpcr)
                        } else {
                            fp_recip_estimate_f32(x as u32)
                        }) as u64
                    }
                    _ => {
                        if rsqrt {
                            fp_rsqrt_estimate_f64_with_fpcr(x, self.fpcr)
                        } else {
                            fp_recip_estimate_f64(x)
                        }
                    }
                };
                self.fpsr |= fp_status_estimate_with_fpcr(esz, rsqrt, raw, r, self.fpcr);
                write_elem(&mut dst, off, esz, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE FP compare (register) -> predicate: 0x65, bit21==0, the condition
        // is (bits[15:13], bit4): FCMGE/FCMGT/FCMEQ/FCMNE/FCMUO/FACGE/FACGT.
        // Zeroing under Pg; sets NZCV via PredTest(Pg).
        if (insn >> 24) & 0xFF == 0b01100101
            && (insn >> 21) & 1 == 0
            && matches!(
                ((insn >> 13) & 0x7, (insn >> 4) & 1),
                (0b010, 0)
                    | (0b010, 1)
                    | (0b011, 0)
                    | (0b011, 1)
                    | (0b110, 0)
                    | (0b110, 1)
                    | (0b111, 1)
            )
        {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let cc = ((insn >> 13) & 0x7, (insn >> 4) & 1);
            let pred = self.sve_p[pg];
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zm].to_le_bytes();
            let mut pd = 0u32;
            for e in 0..(16 / esz) {
                let off = e * esz;
                if (pred >> off) & 1 == 1 {
                    let a = read_elem(&n, off, esz);
                    let b = read_elem(&m, off, esz);
                    if fp_is_snan_bits(esz, a)
                        || fp_is_snan_bits(esz, b)
                        || ((cc.0 == 0b010 || (cc.1 == 1 && matches!(cc.0, 0b110 | 0b111)))
                            && (fp_is_nan_bits(esz, a) || fp_is_nan_bits(esz, b)))
                    {
                        self.fpsr |= FPSR_IOC;
                    }
                    self.fpsr |= fp_fz_input_status(esz, a, self.fpcr)
                        | fp_fz_input_status(esz, b, self.fpcr);
                    let a = fp_flush_input_bits_with_fpcr(a, (esz * 8) as u32, self.fpcr);
                    let b = fp_flush_input_bits_with_fpcr(b, (esz * 8) as u32, self.fpcr);
                    if sve_fp_compare(esz, cc, a, b) {
                        pd |= 1 << off;
                    }
                }
            }
            // FP compares write only the predicate; they do not set NZCV.
            self.sve_p[(insn & 0xF) as usize] = pd;
            return Ok(CpuExit::Continue);
        }

        // SVE FP compare with zero -> predicate: 0x65, bits[21:18]==0100,
        // bits[15:13]==001. bits[17:16] select GE/GT (00), LT/LE (01), EQ/NE
        // (10); bit4 picks within. Zeroing; sets NZCV via PredTest(Pg).
        if (insn >> 24) & 0xFF == 0b01100101
            && (insn >> 18) & 0xF == 0b0100
            && (insn >> 13) & 0x7 == 0b001
        {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let sub = (insn >> 16) & 0x3;
            let bit4 = (insn >> 4) & 1;
            // Valid: GE/GT (00,0/1), LT/LE (01,0/1), EQ (10,0), NE (11,0).
            // (10,1) and (11,1) are unallocated and fault on hardware.
            if (sub == 0b10 || sub == 0b11) && bit4 == 1 {
                return Ok(CpuExit::Undefined(insn));
            }
            let pred = self.sve_p[pg];
            let n = self.v[zn].to_le_bytes();
            let mut pd = 0u32;
            for e in 0..(16 / esz) {
                let off = e * esz;
                if (pred >> off) & 1 == 1 {
                    let a = read_elem(&n, off, esz);
                    if fp_is_snan_bits(esz, a) || (sub <= 0b01 && fp_is_nan_bits(esz, a)) {
                        self.fpsr |= FPSR_IOC;
                    }
                    self.fpsr |= fp_fz_input_status(esz, a, self.fpcr);
                    let a = fp_flush_input_bits_with_fpcr(a, (esz * 8) as u32, self.fpcr);
                    if sve_fp_compare_zero(esz, sub, bit4, a) {
                        pd |= 1 << off;
                    }
                }
            }
            // FP compares write only the predicate; they do not set NZCV.
            self.sve_p[(insn & 0xF) as usize] = pd;
            return Ok(CpuExit::Continue);
        }

        // SVE FRECPS / FRSQRTS (reciprocal / reciprocal-sqrt step, unpredicated):
        // 0x65, bit21==0, bits[15:10]==000110 (FRECPS) / 000111 (FRSQRTS).
        // Fused step with the inf*0 special (2.0 / 1.5).
        if (insn >> 24) & 0xFF == 0b01100101
            && (insn >> 21) & 1 == 0
            && matches!((insn >> 10) & 0x3F, 0b000110 | 0b000111)
        {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let rsqrt = (insn >> 10) & 1 == 1;
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zm].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..(16 / esz) {
                let off = e * esz;
                let (x, y) = (read_elem(&n, off, esz), read_elem(&m, off, esz));
                let r = match (rsqrt, esz) {
                    (true, 2) => fp16_rsqrts_with_fpcr(x as u16, y as u16, self.fpcr) as u64,
                    (false, 2) => fp16_recps_with_fpcr(x as u16, y as u16, self.fpcr) as u64,
                    (true, 4) => fp_three_same_f32_with_fpcr(
                        FpKind::Rsqrts,
                        x as u32,
                        y as u32,
                        0,
                        self.fpcr,
                    ) as u64,
                    (false, 4) => {
                        fp_three_same_f32_with_fpcr(FpKind::Recps, x as u32, y as u32, 0, self.fpcr)
                            as u64
                    }
                    (true, _) => fp_three_same_f64_with_fpcr(FpKind::Rsqrts, x, y, 0, self.fpcr),
                    (false, _) => fp_three_same_f64_with_fpcr(FpKind::Recps, x, y, 0, self.fpcr),
                };
                self.fpsr |= fp_status_recps_rsqrts_with_fpcr(esz, rsqrt, x, y, r, self.fpcr);
                write_elem(&mut dst, off, esz, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE FTSMUL (trigonometric starting value): 0x65, bit21==0,
        // bits[15:10]==000011. result = Zn[e]^2 with sign from Zm[e] bit0.
        if (insn >> 24) & 0xFF == 0b01100101
            && (insn >> 21) & 1 == 0
            && (insn >> 10) & 0x3F == 0b000011
        {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zm].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..(16 / esz) {
                let off = e * esz;
                let raw_x = read_elem(&n, off, esz);
                let x = fp_flush_input_bits_with_fpcr(raw_x, (esz * 8) as u32, self.fpcr);
                let sgn = read_elem(&m, off, esz) & 1;
                let r = sve_ftsmul(esz, x, sgn, self.fpcr);
                let status = if fp_is_snan_bits(esz, x) {
                    FPSR_IOC
                } else if esz == 8 {
                    if fp_is_nan_bits(esz, x) || fp_is_inf_bits(esz, x) || fp_is_zero_bits(esz, x) {
                        0
                    } else if fp64_is_inf(r) {
                        FPSR_OFC | FPSR_IXC
                    } else if fp64_is_tiny(r) || fp64_is_zero(r) {
                        FPSR_UFC | FPSR_IXC
                    } else if fp64_mul_exact(x, x) {
                        0
                    } else {
                        FPSR_IXC
                    }
                } else {
                    let exact = sve_fp_to_f64(esz, x) * sve_fp_to_f64(esz, x);
                    let signed_exact = if sgn != 0 { -exact } else { exact };
                    fp_status_from_exact_f64(esz, signed_exact, r)
                };
                self.fpsr |= crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(
                    esz, r, status, self.fpcr,
                ) | fp_fz_input_status(esz, raw_x, self.fpcr);
                write_elem(&mut dst, off, esz, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE FTMAD (trigonometric multiply-add coefficient): 0x65,
        // bits[21:19]==010, bits[15:10]==100000. Destructive: Zdn = fused(Zdn,
        // |Zm|, coeff[imm + 8*(Zm<0)]); Zm is at bits[9:5], imm at bits[18:16].
        if (insn >> 24) & 0xFF == 0b01100101
            && (insn >> 19) & 0x7 == 0b010
            && (insn >> 10) & 0x3F == 0b100000
        {
            let size = (insn >> 22) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let imm = ((insn >> 16) & 0x7) as usize;
            let dn = self.v[zd].to_le_bytes(); // Zdn
            let m = self.v[zn].to_le_bytes(); // Zm at bits[9:5]
            let mut dst = [0u8; 16];
            for e in 0..(16 / esz) {
                let off = e * esz;
                let nn = read_elem(&dn, off, esz);
                let mm = read_elem(&m, off, esz);
                let r = sve_ftmad(esz, nn, mm, imm, self.fpcr);
                let neg = match esz {
                    2 => mm & 0x8000 != 0,
                    4 => mm & 0x8000_0000 != 0,
                    _ => mm & 0x8000_0000_0000_0000 != 0,
                };
                let m_abs = mm & elem_mask((esz * 8 - 1) as u32);
                let coeff = match esz {
                    2 => FTMAD_COEFF_H[imm + if neg { 8 } else { 0 }] as u64,
                    4 => FTMAD_COEFF_S[imm + if neg { 8 } else { 0 }] as u64,
                    _ => FTMAD_COEFF_D[imm + if neg { 8 } else { 0 }],
                };
                self.fpsr |= fp_status_fma_with_fpcr(esz, coeff, nn, m_abs, r, self.fpcr);
                write_elem(&mut dst, off, esz, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE2.1 FCLAMP (FP clamp): 0x64, bit21==1, bits[15:10]==001001.
        // Zd = fminnum(fmaxnum(Zn, Zd), Zm) per element (Zd is the clamped
        // value). Must precede the reduce/unary dispatch (which keys on
        // bits[15:13], that FCLAMP's 001001 would otherwise hit as 001).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 21) & 1 == 1
            && (insn >> 10) & 0x3F == 0b001001
        {
            if !self.config.features.contains(ArmFeatures::SVE2P1) {
                return Ok(CpuExit::Undefined(insn));
            }
            let n = self.v[zn].to_le_bytes();
            let m = self.v[zm].to_le_bytes();
            let d = self.v[zd].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..(16 / esize) {
                let off = e * esize;
                let lo = sve_fp_combine(
                    FpKind::MaxNm,
                    esize,
                    read_elem(&n, off, esize),
                    read_elem(&d, off, esize),
                );
                let r = sve_fp_combine(FpKind::MinNm, esize, lo, read_elem(&m, off, esize));
                write_elem(&mut dst, off, esize, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // SVE2.1 FP quadword reductions (FADDQV/FMAXNMQV/FMINNMQV/FMAXQV/
        // FMINQV): 0x64, bits[21:19]==010, bits[15:13]==101. opc=bits[18:16].
        // Each element position is reduced across the 128-bit segments seeded
        // with the op identity; at VL=128 an active lane is combined with the
        // identity (so FADD normalises -0.0/quiets NaN) and an inactive lane is
        // the raw identity. Must precede the unary dispatch (bits[15:13]==101).
        if (insn >> 24) & 0xFF == 0b01100100
            && (insn >> 19) & 0x7 == 0b010
            && (insn >> 13) & 0x7 == 0b101
        {
            if !self.config.features.contains(ArmFeatures::SVE2P1) {
                return Ok(CpuExit::Undefined(insn));
            }
            let kind = match (insn >> 16) & 0x7 {
                0b000 => FpKind::Add,
                0b100 => FpKind::MaxNm,
                0b101 => FpKind::MinNm,
                0b110 => FpKind::Max,
                0b111 => FpKind::Min,
                _ => return Ok(CpuExit::Undefined(insn)),
            };
            // At VL=128 each element position reduces a single-element column,
            // so an active lane is the raw Zn element (no combine with the
            // identity -> -0.0 and NaN payloads are preserved, matching hw); an
            // inactive lane is the op identity (the empty reduction).
            let ident = sve_fp_identity(kind, esize);
            let pred = self.sve_p[pg];
            let src = self.v[zn].to_le_bytes();
            let mut dst = [0u8; 16];
            for e in 0..(16 / esize) {
                let off = e * esize;
                let v = if (pred >> off) & 1 == 1 {
                    read_elem(&src, off, esize)
                } else {
                    ident
                };
                write_elem(&mut dst, off, esize, v);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }

        // FP fast reductions / FADDA live at bits[15:13]==001; FP unary at
        // bits[15:13]==101; predicated binary arith at bits[15:13]==100.
        match (insn >> 13) & 0x7 {
            0b001 => return self.exec_sve_fp_reduce(insn, esize),
            0b101 => return self.exec_sve_fp_unary(insn, zd, zn, pg, esize),
            0b100 => {}
            _ => return Ok(CpuExit::Undefined(insn)),
        }

        if (insn >> 24) & 0xFF == 0b01100100 && (insn >> 19) & 0x7 != 0b010 {
            return Ok(CpuExit::Undefined(insn));
        }

        // FP pairwise (FADDP/FMAXNMP/FMINNMP/FMAXP/FMINP): 0x64, bits[21:19]==010.
        // Interleaves the pairwise results of Zdn and Zm (even = Zdn pair, odd =
        // Zm pair), merged into Zdn under Pg. opc=bits[18:16].
        if (insn >> 24) & 0xFF == 0b01100100 && (insn >> 19) & 0x7 == 0b010 {
            // FP pairwise (FADDP/FMAXNMP/FMINNMP/FMAXP/FMINP) is only defined for
            // H/S/D elements, so size==00 is reserved, and only opc values 000,
            // 100, 101, 110, 111 are allocated. Reject the reserved size and the
            // reserved opc values (001/010/011) instead of executing them.
            if (insn >> 22) & 0x3 == 0b00 {
                return Ok(CpuExit::Undefined(insn));
            }
            let kind = match (insn >> 16) & 0x7 {
                0b000 => FpKind::Add,
                0b100 => FpKind::MaxNm,
                0b101 => FpKind::MinNm,
                0b110 => FpKind::Max,
                0b111 => FpKind::Min,
                _ => return Ok(CpuExit::Undefined(insn)),
            };
            let pred = self.sve_p[pg];
            let elements = 16 / esize;
            let h = elements / 2;
            let dn = self.v[zd].to_le_bytes(); // Zdn
            let m = self.v[zn].to_le_bytes(); // Zm
            let mut res = [0u8; 16];
            for p in 0..h {
                let even_off = 2 * p * esize;
                let odd_off = (2 * p + 1) * esize;
                let dn0 = read_elem(&dn, even_off, esize);
                let dn1 = read_elem(&dn, odd_off, esize);
                let m0 = read_elem(&m, even_off, esize);
                let m1 = read_elem(&m, odd_off, esize);
                let dnv =
                    sve_fp_pairwise_reduce_combine_with_fpcr(kind, esize, dn0, dn1, self.fpcr);
                let mv = sve_fp_pairwise_reduce_combine_with_fpcr(kind, esize, m0, m1, self.fpcr);
                if (pred >> even_off) & 1 == 1 {
                    self.fpsr |=
                        fp_pairwise_reduce_status_with_fpcr(esize, kind, dn0, dn1, dnv, self.fpcr);
                }
                if (pred >> odd_off) & 1 == 1 {
                    self.fpsr |=
                        fp_pairwise_reduce_status_with_fpcr(esize, kind, m0, m1, mv, self.fpcr);
                }
                write_elem(&mut res, even_off, esize, dnv);
                write_elem(&mut res, odd_off, esize, mv);
            }
            let mut dst = dn;
            for e in 0..elements {
                if (pred >> (e * esize)) & 1 == 1 {
                    write_elem(
                        &mut dst,
                        e * esize,
                        esize,
                        read_elem(&res, e * esize, esize),
                    );
                }
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }
        let opc5 = (insn >> 16) & 0x1F;
        // FSCALE (opc5==01001): Zdn = Zdn * 2^(signed Zm element), merging. The
        // Zm element is a signed integer exponent, not a float.
        if opc5 == 0b01001 {
            if (insn >> 22) & 0x3 == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let pred = self.sve_p[pg];
            let a = self.v[zd].to_le_bytes(); // Zdn
            let b = self.v[zn].to_le_bytes(); // Zm
            let mut dst = a;
            let ibits = (esize * 8) as u32;
            for e in 0..(16 / esize) {
                let off = e * esize;
                if (pred >> off) & 1 == 0 {
                    continue;
                }
                let raw_x = read_elem(&a, off, esize);
                let x = fp_flush_input_bits_with_fpcr(raw_x, ibits, self.fpcr);
                let n = sext_elem(read_elem(&b, off, esize), ibits) as i64;
                let r = sve_fscale(esize, x, n, self.fpcr);
                let status = fp_status_fscale(esize, x, n, r);
                let input_status = fp_fz_input_status(esize, raw_x, self.fpcr);
                self.fpsr |= if self.fpcr & FPCR_AH != 0
                    && input_status != 0
                    && status == (FPSR_UFC | FPSR_IXC)
                {
                    input_status
                } else {
                    status | input_status
                };
                write_elem(&mut dst, off, esize, r);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }
        let (kind, swap) = match opc5 {
            0b00000 => (FpKind::Add, false),
            0b00001 => (FpKind::Sub, false),
            0b00010 => (FpKind::Mul, false),
            0b00011 => (FpKind::Sub, true), // FSUBR
            0b00100 => (FpKind::MaxNm, false),
            0b00101 => (FpKind::MinNm, false),
            0b00110 => (FpKind::Max, false),
            0b00111 => (FpKind::Min, false),
            0b01000 => (FpKind::Abd, false),
            0b01010 => (FpKind::Mulx, false), // FMULX
            0b01100 => (FpKind::Div, true),   // FDIVR
            0b01101 => (FpKind::Div, false),
            0b11000 => (FpKind::Add, false),   // FADD #0.5/#1.0
            0b11001 => (FpKind::Sub, false),   // FSUB #0.5/#1.0
            0b11010 => (FpKind::Mul, false),   // FMUL #0.5/#1.0
            0b11011 => (FpKind::Sub, true),    // FSUBR #0.5/#1.0
            0b11100 => (FpKind::MaxNm, false), // FMAXNM #0.0/#1.0
            0b11101 => (FpKind::MinNm, false), // FMINNM #0.0/#1.0
            0b11110 => (FpKind::Max, false),   // FMAX #0.0/#1.0
            0b11111 => (FpKind::Min, false),   // FMIN #0.0/#1.0
            _ => return Ok(CpuExit::Undefined(insn)),
        };
        let immediate_scalar = opc5 >= 0b11000;
        let scalar = if immediate_scalar {
            let one = (insn >> 5) & 1 == 1;
            let zero = opc5 >= 0b11100 && !one;
            Some(match (esize, zero, one) {
                (2, true, _) => 0,
                (2, false, false) => 0x3800,
                (2, false, true) => 0x3c00,
                (4, true, _) => 0,
                (4, false, false) => 0x3f00_0000,
                (4, false, true) => 0x3f80_0000,
                (8, true, _) => 0,
                (8, false, false) => 0x3fe0_0000_0000_0000,
                (8, false, true) => 0x3ff0_0000_0000_0000,
                _ => return Ok(CpuExit::Undefined(insn)),
            })
        } else {
            None
        };
        let pred = self.sve_p[pg];
        let elements = 16 / esize;
        let a_reg = self.v[zd].to_le_bytes(); // Zdn (first source, dest)
        let b_reg = self.v[zn].to_le_bytes(); // Zm (second source)
        let mut dst = a_reg;
        for e in 0..elements {
            if (pred >> (e * esize)) & 1 == 0 {
                continue;
            }
            let off = e * esize;
            let a = read_elem(&a_reg, off, esize);
            let b = scalar.unwrap_or_else(|| read_elem(&b_reg, off, esize));
            let (x, y) = if swap { (b, a) } else { (a, b) };
            let mut r = match esize {
                2 => sve_fp16_binop_with_fpcr(kind, x as u16, y as u16, self.fpcr) as u64,
                4 => fp_three_same_f32_with_fpcr(kind, x as u32, y as u32, 0, self.fpcr) as u64,
                8 => fp_three_same_f64_with_fpcr(kind, x, y, 0, self.fpcr),
                _ => return Ok(CpuExit::Undefined(insn)),
            };
            if self.fpcr & FPCR_AH != 0
                && immediate_scalar
                && kind == FpKind::Min
                && scalar == Some(0)
                && fp_is_zero_bits(esize, x)
            {
                r = 0;
            }
            let status = fp_three_same_status_with_fpcr(esize, kind, x, y, 0, r, self.fpcr);
            self.fpsr |= if kind == FpKind::Mulx {
                fp_status_sve_underflow(esize, r, status)
            } else {
                status
            };
            write_elem(&mut dst, off, esize, r);
        }
        self.v[zd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }

    /// Execute SVE FP reduction to a scalar in Vd: the "fast" tree reductions
    /// FADDV/FMAXNMV/FMINNMV/FMAXV/FMINV (opc=bits[18:16]) and the strictly
    /// ordered FADDA (bits[20:16]==11000). Pg is byte-granular.
    pub(crate) fn exec_sve_fp_reduce(
        &mut self,
        insn: u32,
        esize: usize,
    ) -> Result<CpuExit, ArmError> {
        if esize < 2 {
            return Ok(CpuExit::Undefined(insn));
        }
        let pg = ((insn >> 10) & 0x7) as usize;
        let zn = ((insn >> 5) & 0x1F) as usize;
        let vd = (insn & 0x1F) as usize;
        let pred = self.sve_p[pg];
        let elements = 16 / esize;
        let mask = elem_mask((esize * 8) as u32) as u128;
        // FADDA: strict left-to-right accumulate seeded by Vdn[0]; skip inactive.
        if (insn >> 16) & 0x1F == 0b11000 {
            let m_reg = self.v[zn].to_le_bytes(); // Zm
            let vd_bytes = self.v[vd].to_le_bytes();
            let mut acc = read_elem(&vd_bytes, 0, esize);
            for e in 0..elements {
                if (pred >> (e * esize)) & 1 == 1 {
                    let x = read_elem(&m_reg, e * esize, esize);
                    let r = sve_fp_combine_with_fpcr(FpKind::Add, esize, acc, x, self.fpcr);
                    self.fpsr |=
                        fp_status_binop_with_fpcr(esize, FpKind::Add, acc, x, r, self.fpcr);
                    acc = r;
                }
            }
            self.v[vd] = (acc as u128) & mask;
            return Ok(CpuExit::Continue);
        }
        let kind = match (insn >> 16) & 0x7 {
            0b000 => FpKind::Add,   // FADDV
            0b100 => FpKind::MaxNm, // FMAXNMV
            0b101 => FpKind::MinNm, // FMINNMV
            0b110 => FpKind::Max,   // FMAXV
            0b111 => FpKind::Min,   // FMINV
            _ => return Ok(CpuExit::Undefined(insn)),
        };
        let ident = sve_fp_identity(kind, esize);
        let src = self.v[zn].to_le_bytes();
        let buf: Vec<u64> = (0..elements)
            .map(|e| {
                if (pred >> (e * esize)) & 1 == 1 {
                    read_elem(&src, e * esize, esize)
                } else {
                    ident
                }
            })
            .collect();
        let (r, status) = sve_fp_tree_reduce_status(&buf, kind, esize, self.fpcr);
        self.fpsr |= status;
        self.v[vd] = (r as u128) & mask;
        Ok(CpuExit::Continue)
    }

    /// Execute SVE predicated FP unary (merging): FSQRT, FRECPX and FRINT*
    /// (bits[20:16] selects the op). Inactive lanes keep their prior Zd value.
    pub(crate) fn exec_sve_fp_unary(
        &mut self,
        insn: u32,
        zd: usize,
        zn: usize,
        pg: usize,
        esize: usize,
    ) -> Result<CpuExit, ArmError> {
        // FCVT (FP precision conversion): 0x65, bits[21:18]==0010. bits[23:22]
        // (opc) and bits[17:16] (opc2) select the src/dst float widths, NOT the
        // element size, so it bypasses the size-derived esize path entirely. The
        // 0x65 gate excludes the 0x64 FCVTNT/FCVTLT/FCVTXNT top/bottom variants.
        if (insn >> 24) & 0xFF == 0b01100101 && (insn >> 18) & 0xF == 0b0010 {
            return self.exec_sve_fcvt(insn, zd, zn, pg);
        }
        // FLOGB (find exponent): 0x65, bits[23:19]==0b00011, size in bits[18:17].
        // The element size is not bits[23:22] (those are 0), so it is computed
        // locally. Result is floor(log2|x|) as a signed integer, merging.
        if (insn >> 24) & 0xFF == 0b01100101 && (insn >> 19) & 0x1F == 0b00011 {
            let size = (insn >> 17) & 0x3;
            if size == 0 {
                return Ok(CpuExit::Undefined(insn));
            }
            let esz = 1usize << size;
            let pred = self.sve_p[pg];
            let src = self.v[zn].to_le_bytes();
            let mut dst = self.v[zd].to_le_bytes();
            let elements = 16 / esz;
            for e in 0..elements {
                let off = e * esz;
                if (pred >> off) & 1 == 0 {
                    continue;
                }
                let raw = read_elem(&src, off, esz);
                let x = fp_flush_input_bits_with_fpcr(raw, (esz * 8) as u32, self.fpcr);
                if fp_is_zero_bits(esz, x) || fp_is_nan_bits(esz, x) {
                    self.fpsr |= FPSR_IOC;
                }
                self.fpsr |= fp_fz_input_status(esz, raw, self.fpcr);
                let r = sve_flogb(esz, x);
                write_elem(&mut dst, off, esz, r as u64);
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }
        // FP<->int conversions: 0x65, bits[21:19]==011 (FCVTZS/FCVTZU, FP->int)
        // or ==010 (SCVTF/UCVTF, int->FP). bits[23:22]/bits[18:17] pick the
        // widths and bit16 the signedness, so this also bypasses the esize path.
        // FLOGB (bits[23:22]==00) is intercepted above before reaching here.
        if (insn >> 24) & 0xFF == 0b01100101
            && ((insn >> 19) & 0x7 == 0b011 || (insn >> 19) & 0x7 == 0b010)
        {
            return self.exec_sve_fp_int_cvt(insn, zd, zn, pg);
        }
        // FCVTNT/FCVTXNT (narrow, top) and FCVTLT (long, top): 0x64,
        // bits[21:18]==0010. The wider element is the container; for narrowing
        // the converted result goes to the top (odd) half (bottom preserved),
        // for widening the source is read from the top (odd) half. FCVTXNT uses
        // round-to-odd. Predication is at the container (wider) granularity.
        if (insn >> 24) & 0xFF == 0b01100100 && (insn >> 18) & 0xF == 0b0010 {
            let opc = (insn >> 22) & 0x3;
            let opc2 = (insn >> 16) & 0x3;
            // (src,dst,round_odd,narrow,bf): bf marks the bf16 destination
            // (BFCVTNT), distinguished from FCVTNT s->h only by opc2 (10 vs 00).
            let (src_sz, dst_sz, round_odd, narrow, bf): (usize, usize, bool, bool, bool) =
                match (opc, opc2) {
                    (0b00, 0b10) => (8, 4, true, true, false),  // FCVTXNT d->s
                    (0b10, 0b00) => (4, 2, false, true, false), // FCVTNT  s->h
                    (0b10, 0b10) => (4, 2, false, true, true),  // BFCVTNT s->bf16
                    (0b11, 0b10) => (8, 4, false, true, false), // FCVTNT  d->s
                    (0b10, 0b01) => (2, 4, false, false, false), // FCVTLT h->s
                    (0b11, 0b11) => (4, 8, false, false, false), // FCVTLT s->d
                    _ => return Ok(CpuExit::Undefined(insn)),
                };
            let cont = src_sz.max(dst_sz);
            let elements = 16 / cont;
            let pred = self.sve_p[pg];
            let operand = self.v[zn].to_le_bytes();
            let mut dst = self.v[zd].to_le_bytes();
            for c in 0..elements {
                let coff = c * cont;
                if (pred >> coff) & 1 == 0 {
                    continue;
                }
                let convert = |x: u64| -> u64 {
                    if bf {
                        f32_to_bf16_with_fpcr(x as u32, self.fpcr) as u64
                    } else {
                        fp_cvt_elem(x, src_sz, dst_sz, round_odd, self.fpcr)
                    }
                };
                if narrow {
                    let x = read_elem(&operand, coff, src_sz);
                    let res = convert(x);
                    self.fpsr |= if bf {
                        fp_status_bfcvt_with_fpcr(x as u32, res as u16, self.fpcr)
                    } else {
                        fp_status_cvt_precision_with_fpcr_rounding(
                            x, src_sz, dst_sz, res, round_odd, self.fpcr,
                        )
                    };
                    write_elem(&mut dst, coff + dst_sz, dst_sz, res); // top half
                } else {
                    let x = read_elem(&operand, coff + src_sz, src_sz); // top half
                    let res = convert(x);
                    self.fpsr |=
                        fp_status_cvt_precision_with_fpcr(x, src_sz, dst_sz, res, self.fpcr);
                    write_elem(&mut dst, coff, dst_sz, res);
                }
            }
            self.v[zd] = u128::from_le_bytes(dst);
            return Ok(CpuExit::Continue);
        }
        if esize < 2 {
            return Ok(CpuExit::Undefined(insn));
        }
        let b20_16 = (insn >> 16) & 0x1F;
        if !matches!(
            b20_16,
            0b00000..=0b00100 | 0b00110 | 0b00111 | 0b01100 | 0b01101
        ) {
            return Ok(CpuExit::Undefined(insn));
        }
        // FRINT* rounding -> (TwoRegFp variant, fp16 mode).
        let rint = |m: u32| -> Option<(TwoRegFp, u8)> {
            Some(match m {
                0b000 => (TwoRegFp::RintN, 0),
                0b001 => (TwoRegFp::RintP, 2),
                0b010 => (TwoRegFp::RintM, 1),
                0b011 => (TwoRegFp::RintZ, 3),
                0b100 => (TwoRegFp::RintA, 4),
                0b110 => (TwoRegFp::RintX, 0),
                0b111 => (TwoRegFp::RintI, 0),
                _ => return None,
            })
        };
        let pred = self.sve_p[pg];
        let elements = 16 / esize;
        let src = self.v[zn].to_le_bytes();
        let mut dst = self.v[zd].to_le_bytes(); // merging: start from Zd
        for e in 0..elements {
            if (pred >> (e * esize)) & 1 == 0 {
                continue;
            }
            let off = e * esize;
            let lane = read_elem(&src, off, esize);
            let (r, status) = match b20_16 {
                0b01101 => {
                    let kind = TwoRegFp::Fsqrt;
                    let r = match esize {
                        2 => fp16_sqrt_with_fpcr(lane as u16, self.fpcr) as u64,
                        4 => fp_two_reg_f32_with_fpcr(kind, lane as u32, self.fpcr) as u64,
                        _ => fp_two_reg_f64_with_fpcr(kind, lane, self.fpcr),
                    };
                    (
                        r,
                        fp_status_unop_with_fpcr(esize, Some(kind), lane, r, self.fpcr),
                    )
                }
                0b01100 => {
                    let a = fp_flush_input_bits_with_fpcr(lane, (esize * 8) as u32, self.fpcr);
                    let mut status = if fp_is_snan_bits(esize, a) {
                        FPSR_IOC
                    } else {
                        0
                    };
                    if self.fpcr & FPCR_AH == 0 {
                        status |= fp_fz_input_status(esize, lane, self.fpcr);
                    }
                    (sve_fp_recpx(esize, a), status)
                }
                m if m < 0b01000 => {
                    let Some((trk, fp16m)) = rint(m) else {
                        return Ok(CpuExit::Undefined(insn));
                    };
                    let r = match esize {
                        2 if matches!(trk, TwoRegFp::RintX | TwoRegFp::RintI) => {
                            fp16_frint_with_fpcr(lane as u16, self.fpcr) as u64
                        }
                        2 => fp16_frint_fixed_with_fpcr(lane as u16, fp16m, self.fpcr) as u64,
                        4 => fp_two_reg_f32_with_fpcr(trk, lane as u32, self.fpcr) as u64,
                        _ => fp_two_reg_f64_with_fpcr(trk, lane, self.fpcr),
                    };
                    (
                        r,
                        fp_status_unop_with_fpcr(esize, Some(trk), lane, r, self.fpcr),
                    )
                }
                _ => return Ok(CpuExit::Undefined(insn)),
            };
            self.fpsr |= status;
            write_elem(&mut dst, off, esize, r);
        }
        self.v[zd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }

    /// Execute SVE FCVTZS/FCVTZU (FP -> integer, round toward zero, saturating)
    /// and SCVTF/UCVTF (integer -> FP, round to nearest even). The per-element
    /// container is the larger of the FP and integer widths; the source occupies
    /// the low bits of its container and the result is zero-extended back.
    /// Predication is byte-granular at the container size and merges.
    pub(crate) fn exec_sve_fp_int_cvt(
        &mut self,
        insn: u32,
        zd: usize,
        zn: usize,
        pg: usize,
    ) -> Result<CpuExit, ArmError> {
        let opc = (insn >> 22) & 0x3;
        let opc2 = (insn >> 17) & 0x3;
        let signed = (insn >> 16) & 1 == 0; // int_U: 0=signed, 1=unsigned
        let to_int = (insn >> 19) & 0x7 == 0b011; // FCVTZ; else SCVTF/UCVTF
        let (fp_sz, int_sz): (usize, usize) = match (opc, opc2) {
            (0b01, 0b01) => (2, 2), // fp16 <-> int16
            (0b01, 0b10) => (2, 4), // fp16 <-> int32
            (0b01, 0b11) => (2, 8), // fp16 <-> int64
            (0b10, 0b10) => (4, 4), // f32  <-> int32
            (0b11, 0b00) => (8, 4), // f64  <-> int32
            (0b11, 0b10) => (4, 8), // f32  <-> int64
            (0b11, 0b11) => (8, 8), // f64  <-> int64
            _ => return Ok(CpuExit::Undefined(insn)),
        };
        let cont = fp_sz.max(int_sz);
        let elements = 16 / cont;
        let pred = self.sve_p[pg];
        let operand = self.v[zn].to_le_bytes();
        let mut dst = self.v[zd].to_le_bytes(); // merging: start from Zd
        for e in 0..elements {
            let off = e * cont;
            if (pred >> off) & 1 == 0 {
                continue;
            }
            let res = if to_int {
                let raw = read_elem(&operand, off, fp_sz);
                let x = fp_flush_input_bits_with_fpcr(raw, (fp_sz * 8) as u32, self.fpcr);
                let res = sve_fcvtz(fp_sz, int_sz, signed, x);
                let status = fp_to_int_status(sve_fp_to_f64(fp_sz, x), signed, (int_sz * 8) as u32);
                let input_status = fp_fz_input_status(fp_sz, raw, self.fpcr);
                self.fpsr |= fp_status_merge_input_status(status, input_status, self.fpcr);
                res
            } else {
                let x = read_elem(&operand, off, int_sz);
                let res = sve_cvtf(int_sz, fp_sz, signed, x, self.fpcr);
                let raw_int = if signed {
                    match int_sz {
                        2 => (x as u16 as i16 as i128).unsigned_abs(),
                        4 => (x as u32 as i32 as i128).unsigned_abs(),
                        _ => (x as i64 as i128).unsigned_abs(),
                    }
                } else {
                    match int_sz {
                        2 => (x as u16) as u128,
                        4 => (x as u32) as u128,
                        _ => x as u128,
                    }
                };
                self.fpsr |= fp_status_int_to_fp_scaled(raw_int, fp_sz, res);
                res
            };
            write_elem(&mut dst, off, cont, res);
        }
        self.v[zd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }
}

//! permute.rs

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
use crate::isa::arm::common::int8;
use crate::isa::arm::common::memory::ArmMemory;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::vcpu::Aarch64SystemRegisters;

impl AArch64Cpu {
    /// Execute the AdvSIMD "three-same-extra" (bit21==0) ops: SQRDMLAH/SQRDMLSH
    /// (FEAT_RDM; vector + scalar) and SMMLA/UMMLA/USMMLA (FEAT_I8MM int8 2x2
    /// matrix multiply-accumulate; .4s,.16b,.16b, Q==1 only).
    pub(crate) fn exec_simd_three_same_extra(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) & 1 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let op_bits = (insn >> 24) & 0x1F;
        let scalar = op_bits == 0b11110;
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let size = (insn >> 22) & 0x3;
        let lo6 = (insn >> 10) & 0x3F;
        let rm = ((insn >> 16) & 0x1F) as usize;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        if lo6 == 0b101001 || lo6 == 0b101011 {
            // SMMLA(U=0)/UMMLA(U=1)/USMMLA(U=0,101011) int8 2x2 matrix MAC.
            if scalar || q == 0 || size != 0b10 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let signed = if lo6 == 0b101011 {
                (false, true) // USMMLA: Vn unsigned, Vm signed
            } else if u == 1 {
                (false, false) // UMMLA
            } else {
                (true, true) // SMMLA
            };
            self.v[rd] = int8::matrix_accumulate(self.v[rd], self.v[rn], self.v[rm], signed);
            return Ok(CpuExit::Continue);
        }

        // SQRDMLAH (100001) / SQRDMLSH (100011): U==1, 16- or 32-bit elements.
        if u != 1 || size == 0b00 || size == 0b11 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let sub = lo6 == 0b100011;
        let bits = 8u32 << size;
        let esize = (bits / 8) as usize;
        let elements = if scalar {
            1
        } else if q == 1 {
            16 / esize
        } else {
            8 / esize
        };
        let n = self.v[rn].to_le_bytes();
        let m = self.v[rm].to_le_bytes();
        let a = self.v[rd].to_le_bytes();
        let mut dst = [0u8; 16];
        for e in 0..elements {
            let off = e * esize;
            let prod = sext_elem(read_elem(&n, off, esize), bits)
                * sext_elem(read_elem(&m, off, esize), bits);
            let prod = if sub { -prod } else { prod };
            let rounded = (prod * 2 + (1i128 << (bits - 1))) >> bits;
            let acc = sext_elem(read_elem(&a, off, esize), bits);
            let (r, saturated) = sat_signed_q(acc + rounded, bits);
            if saturated {
                self.fpsr |= FPSR_QC;
            }
            write_elem(&mut dst, off, esize, r);
        }
        self.v[rd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }

    /// Execute SIMD across lanes (reduction operations).
    pub(crate) fn exec_simd_across_lanes(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) & 1 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let size = (insn >> 22) & 0x3;
        let opcode = (insn >> 12) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        // ---- Floating-point reductions: FMAXNMV/FMINNMV (0b01100),
        //      FMAXV/FMINV (0b01111). U==1, f32 lanes only. bit23 picks min. ----
        if opcode == 0b01100 || opcode == 0b01111 {
            // FP max/min across lanes: f32 (U==1, 4S) or FP16 (U==0, .4h/.8h).
            // bit23 (size high) selects min; opcode 01100=NM variant. Reduced via
            // the ARM-correct combine (NaN propagation, sign-of-zero, sNaN quiet).
            let nm = opcode == 0b01100;
            let is_min = (size >> 1) & 1 == 1;
            let kind = match (nm, is_min) {
                (false, false) => FpKind::Max,
                (false, true) => FpKind::Min,
                (true, false) => FpKind::MaxNm,
                (true, true) => FpKind::MinNm,
            };
            let vn = self.v[rn];
            // ARM Reduce() is a recursive split-in-half tree (sve_fp_tree_reduce),
            // NOT a sequential fold — the order is observable when a NaN is
            // present (sNaN propagation / which numeric lane survives).
            let (esize, nlanes) = if u == 1 {
                if size & 1 != 0 || q == 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                (4usize, 4usize) // f32, 4S
            } else {
                (2usize, if q == 1 { 8 } else { 4 }) // FP16, .8h/.4h
            };
            let buf: Vec<u64> = (0..nlanes)
                .map(|e| (vn >> (e * esize * 8)) as u64 & elem_mask((esize * 8) as u32))
                .collect();
            let (r, status) = sve_fp_tree_reduce_status(&buf, kind, esize, self.fpcr);
            self.fpsr |= status;
            self.v[rd] = (r & elem_mask((esize * 8) as u32)) as u128;
            return Ok(CpuExit::Continue);
        }

        let bits = 8u32 << size;
        let esize = (bits / 8) as usize;
        let datasize = if q == 1 { 16 } else { 8 };
        let elements = datasize / esize;
        let src = self.v[rn].to_le_bytes();

        // Reductions are defined for 8B/16B/4H/8H and (Q==1) 4S; never 64-bit,
        // and 8B/4H also exclude the single-element degenerate cases.
        let valid_size = match size {
            0b00 => true,   // 8B / 16B
            0b01 => true,   // 4H / 8H
            0b10 => q == 1, // 4S only
            _ => false,
        };
        if !valid_size {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let (result, result_bits): (u64, u32) = match opcode {
            0b11011 => {
                // ADDV
                let mut acc = 0u64;
                for e in 0..elements {
                    acc = acc.wrapping_add(read_elem(&src, e * esize, esize));
                }
                (acc & elem_mask(bits), bits)
            }
            0b00011 => {
                // SADDLV (U=0) / UADDLV (U=1) -- widening sum across lanes.
                let mut acc = 0i128;
                for e in 0..elements {
                    let v = read_elem(&src, e * esize, esize);
                    acc += if u == 0 {
                        sext_elem(v, bits)
                    } else {
                        uext_elem(v, bits) as i128
                    };
                }
                ((acc as u64) & elem_mask(2 * bits), 2 * bits)
            }
            0b01010 => {
                // SMAXV (U=0) / UMAXV (U=1)
                let mut acc = read_elem(&src, 0, esize);
                for e in 1..elements {
                    let v = read_elem(&src, e * esize, esize);
                    acc = if u == 0 {
                        if sext_elem(v, bits) > sext_elem(acc, bits) {
                            v
                        } else {
                            acc
                        }
                    } else if uext_elem(v, bits) > uext_elem(acc, bits) {
                        v
                    } else {
                        acc
                    };
                }
                (acc & elem_mask(bits), bits)
            }
            0b11010 => {
                // SMINV (U=0) / UMINV (U=1)
                let mut acc = read_elem(&src, 0, esize);
                for e in 1..elements {
                    let v = read_elem(&src, e * esize, esize);
                    acc = if u == 0 {
                        if sext_elem(v, bits) < sext_elem(acc, bits) {
                            v
                        } else {
                            acc
                        }
                    } else if uext_elem(v, bits) < uext_elem(acc, bits) {
                        v
                    } else {
                        acc
                    };
                }
                (acc & elem_mask(bits), bits)
            }
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        };

        self.v[rd] = (result as u128) & elem_mask_u128(result_bits);
        Ok(CpuExit::Continue)
    }

    /// AdvSIMD scalar pairwise: reduce the two elements of a vector to a scalar.
    /// ADDP (int, D only); FADDP/FMAXP/FMINP/FMAXNMP/FMINNMP for f16 (U=0),
    /// f32 (U=1, bit22=0) or f64 (U=1, bit22=1). bit23 selects min for the
    /// max/min forms. Writes lane 0, zeroing the rest.
    pub(crate) fn exec_simd_scalar_pairwise(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let u = (insn >> 29) & 1;
        let size = (insn >> 22) & 0x3;
        let opcode = (insn >> 12) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;
        let vn = self.v[rn];

        if opcode == 0b11011 {
            // ADDP (scalar, .2d -> Dd).
            if u != 0 || size != 0b11 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            self.v[rd] = (vn as u64).wrapping_add((vn >> 64) as u64) as u128;
            return Ok(CpuExit::Continue);
        }

        let (faddp, nm) = match opcode {
            0b01101 => (true, false),  // FADDP
            0b01100 => (false, true),  // FMAXNMP / FMINNMP
            0b01111 => (false, false), // FMAXP / FMINP
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        };
        let min = (size >> 1) & 1 == 1;
        if u == 0 && (size & 1) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let esize = if u == 0 {
            2usize // FP16
        } else if size & 1 == 0 {
            4 // f32
        } else {
            8 // f64
        };
        let kind = if faddp {
            FpKind::Add
        } else {
            match (nm, min) {
                (false, false) => FpKind::Max,
                (false, true) => FpKind::Min,
                (true, false) => FpKind::MaxNm,
                (true, true) => FpKind::MinNm,
            }
        };
        let mask = elem_mask((esize * 8) as u32);
        let e0 = vn as u64 & mask;
        let e1 = (vn >> (esize * 8)) as u64 & mask;
        let r = sve_fp_pairwise_reduce_combine_with_fpcr(kind, esize, e0, e1, self.fpcr);
        self.fpsr |= fp_pairwise_reduce_status_with_fpcr(esize, kind, e0, e1, r, self.fpcr);
        self.v[rd] = (r & mask) as u128;
        Ok(CpuExit::Continue)
    }

    /// Execute the Advanced SIMD "copy" group: DUP (element/general), INS
    /// (element/general), SMOV, UMOV. Element size and lane index come from the
    /// `imm5` field (lowest set bit selects the size).
    pub(crate) fn exec_simd_copy(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) & 1 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let q = (insn >> 30) & 1;
        let op = (insn >> 29) & 1;
        let scalar = (insn >> 24) & 0x1F == 0b11110; // DUP <V><d>,<Vn>.<T>[i] (MOV)
        let imm5 = (insn >> 16) & 0x1F;
        let imm4 = (insn >> 11) & 0xF;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        let size = if imm5 & 1 != 0 {
            0u32
        } else if imm5 & 2 != 0 {
            1
        } else if imm5 & 4 != 0 {
            2
        } else if imm5 & 8 != 0 {
            3
        } else {
            return Err(ArmError::UndefinedInstruction(insn));
        };
        let esize = 8u32 << size; // element size in bits
        let shift = esize as usize;
        let index = (imm5 >> (size + 1)) as usize;
        let emask = elem_mask_u128(esize);

        if scalar && (op != 0 || imm4 != 0b0000) {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        if op == 1 {
            // INS (element): Vd[index] = Vn[src_index]. INS is a 128-bit-only
            // operation; the Q==0 encoding is unallocated and must trap.
            if q == 0 {
                return Err(ArmError::UndefinedInstruction(insn));
            }
            let src_index = (imm4 >> size) as usize;
            let vn = self.v[rn as usize];
            let elem = (vn >> (src_index * shift)) & emask;
            let mut vd = self.v[rd as usize];
            vd &= !(emask << (index * shift));
            vd |= elem << (index * shift);
            self.v[rd as usize] = vd;
            return Ok(CpuExit::Continue);
        }

        match imm4 {
            0b0000 => {
                // DUP (element): broadcast Vn[index]. The scalar form (MOV
                // <V><d>,<Vn>.<T>[i]) extracts a single element into lane 0.
                if !scalar && size == 3 && q == 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let vn = self.v[rn as usize];
                let elem = (vn >> (index * shift)) & emask;
                if scalar {
                    self.v[rd as usize] = elem;
                } else {
                    let datasize = if q == 1 { 128 } else { 64 };
                    let mut result = 0u128;
                    let mut p = 0;
                    while p < datasize {
                        result |= elem << p;
                        p += shift;
                    }
                    self.v[rd as usize] = result;
                }
            }
            0b0001 => {
                // DUP (general): broadcast Xn/Wn.
                if size == 3 && q == 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let v = (self.get_x(rn) as u128) & emask;
                let datasize = if q == 1 { 128 } else { 64 };
                let mut result = 0u128;
                let mut p = 0;
                while p < datasize {
                    result |= v << p;
                    p += shift;
                }
                self.v[rd as usize] = result;
            }
            0b0011 => {
                // INS (general): Vd[index] = Xn/Wn. INS is 128-bit-only; the
                // Q==0 encoding is unallocated and must trap.
                if q == 0 {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let v = (self.get_x(rn) as u128) & emask;
                let mut vd = self.v[rd as usize];
                vd &= !(emask << (index * shift));
                vd |= v << (index * shift);
                self.v[rd as usize] = vd;
            }
            0b0101 => {
                // SMOV: GPR = sign-extended Vn[index]. Valid: B/H -> W or X,
                // S -> X only; never D.
                if size == 3 || (size == 2 && q == 0) {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let vn = self.v[rn as usize];
                let elem = ((vn >> (index * shift)) & emask) as u64;
                let signed = sext_elem(elem, esize) as u64;
                if q == 1 {
                    self.set_x(rd, signed);
                } else {
                    self.set_w(rd, signed as u32);
                }
            }
            0b0111 => {
                // UMOV: GPR = zero-extended Vn[index]. Valid: B/H/S -> W,
                // D -> X only.
                let valid = (size <= 2 && q == 0) || (size == 3 && q == 1);
                if !valid {
                    return Err(ArmError::UndefinedInstruction(insn));
                }
                let vn = self.v[rn as usize];
                let elem = ((vn >> (index * shift)) & emask) as u64;
                if q == 1 {
                    self.set_x(rd, elem);
                } else {
                    self.set_w(rd, elem as u32);
                }
            }
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        }
        Ok(CpuExit::Continue)
    }

    /// Execute SIMD permute operations (ZIP, UZP, TRN).
    pub(crate) fn exec_simd_permute(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let q = (insn >> 30) & 1;
        let size = (insn >> 22) & 0x3;
        let rm = ((insn >> 16) & 0x1F) as usize;
        let opcode = (insn >> 12) & 0x7;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        // 64-bit elements need the 2D (Q==1) arrangement; "1D" is RESERVED.
        if size == 0b11 && q == 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let esize = 1usize << size;
        let datasize = if q == 1 { 16 } else { 8 };
        let elements = datasize / esize;

        let src1 = self.v[rn].to_le_bytes();
        let src2 = self.v[rm].to_le_bytes();
        let mut dst = [0u8; 16];

        match opcode {
            0b001 => {
                // UZP1 - unzip, lower halves
                for e in 0..elements {
                    let src_idx = e * 2;
                    let dst_off = e * esize;
                    if src_idx < elements {
                        let src_off = src_idx * esize;
                        dst[dst_off..dst_off + esize]
                            .copy_from_slice(&src1[src_off..src_off + esize]);
                    } else {
                        let src_off = (src_idx - elements) * esize;
                        dst[dst_off..dst_off + esize]
                            .copy_from_slice(&src2[src_off..src_off + esize]);
                    }
                }
            }
            0b010 => {
                // TRN1 - transpose, lower halves
                for e in 0..(elements / 2) {
                    let dst_off1 = (e * 2) * esize;
                    let dst_off2 = (e * 2 + 1) * esize;
                    let src_off = (e * 2) * esize;
                    dst[dst_off1..dst_off1 + esize]
                        .copy_from_slice(&src1[src_off..src_off + esize]);
                    dst[dst_off2..dst_off2 + esize]
                        .copy_from_slice(&src2[src_off..src_off + esize]);
                }
            }
            0b011 => {
                // ZIP1 - zip, lower halves
                for e in 0..(elements / 2) {
                    let dst_off1 = (e * 2) * esize;
                    let dst_off2 = (e * 2 + 1) * esize;
                    let src_off = e * esize;
                    dst[dst_off1..dst_off1 + esize]
                        .copy_from_slice(&src1[src_off..src_off + esize]);
                    dst[dst_off2..dst_off2 + esize]
                        .copy_from_slice(&src2[src_off..src_off + esize]);
                }
            }
            0b101 => {
                // UZP2 - unzip, upper halves
                for e in 0..elements {
                    let src_idx = e * 2 + 1;
                    let dst_off = e * esize;
                    if src_idx < elements {
                        let src_off = src_idx * esize;
                        dst[dst_off..dst_off + esize]
                            .copy_from_slice(&src1[src_off..src_off + esize]);
                    } else {
                        let src_off = (src_idx - elements) * esize;
                        dst[dst_off..dst_off + esize]
                            .copy_from_slice(&src2[src_off..src_off + esize]);
                    }
                }
            }
            0b110 => {
                // TRN2 - transpose, upper halves
                for e in 0..(elements / 2) {
                    let dst_off1 = (e * 2) * esize;
                    let dst_off2 = (e * 2 + 1) * esize;
                    let src_off = (e * 2 + 1) * esize;
                    dst[dst_off1..dst_off1 + esize]
                        .copy_from_slice(&src1[src_off..src_off + esize]);
                    dst[dst_off2..dst_off2 + esize]
                        .copy_from_slice(&src2[src_off..src_off + esize]);
                }
            }
            0b111 => {
                // ZIP2 - zip, upper halves
                let half = elements / 2;
                for e in 0..half {
                    let dst_off1 = (e * 2) * esize;
                    let dst_off2 = (e * 2 + 1) * esize;
                    let src_off = (half + e) * esize;
                    dst[dst_off1..dst_off1 + esize]
                        .copy_from_slice(&src1[src_off..src_off + esize]);
                    dst[dst_off2..dst_off2 + esize]
                        .copy_from_slice(&src2[src_off..src_off + esize]);
                }
            }
            _ => return Ok(CpuExit::Undefined(insn)),
        }

        self.v[rd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }

    /// Execute SIMD extract (EXT).
    pub(crate) fn exec_simd_extract(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 31) != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let q = (insn >> 30) & 1;
        let rm = ((insn >> 16) & 0x1F) as usize;
        let imm4 = ((insn >> 11) & 0xF) as usize;
        let rn = ((insn >> 5) & 0x1F) as usize;
        let rd = (insn & 0x1F) as usize;

        let datasize = if q == 1 { 16 } else { 8 };

        // imm4 with bit 3 set is UNDEFINED for the 64-bit (Q==0) form.
        if q == 0 && imm4 >= 8 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // Concatenate the low `datasize` bytes of Vn:Vm and extract `datasize`
        // bytes starting at byte `imm4`.
        let src1 = self.v[rn].to_le_bytes();
        let src2 = self.v[rm].to_le_bytes();
        let mut concat = [0u8; 32];
        concat[..datasize].copy_from_slice(&src1[..datasize]);
        concat[datasize..2 * datasize].copy_from_slice(&src2[..datasize]);

        let mut dst = [0u8; 16];
        for i in 0..datasize {
            dst[i] = concat[imm4 + i];
        }

        self.v[rd] = u128::from_le_bytes(dst);
        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_extract(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let opc = (insn >> 29) & 0x3;
        let n = (insn >> 22) & 1;
        let rm = ((insn >> 16) & 0x1F) as u8;
        let imms = ((insn >> 10) & 0x3F) as u32;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        let datasize = if sf != 0 { 64u32 } else { 32 };
        if opc != 0 || (sf == 0 && (n != 0 || imms >= 32)) || (sf != 0 && n == 0) {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        let lsb = imms;

        let operand1 = if sf != 0 {
            self.get_x(rn)
        } else {
            self.get_w(rn) as u64
        };

        let operand2 = if sf != 0 {
            self.get_x(rm)
        } else {
            self.get_w(rm) as u64
        };

        let result = if lsb == 0 {
            operand2
        } else {
            (operand1 << (datasize - lsb)) | (operand2 >> lsb)
        };

        if sf != 0 {
            self.set_x(rd, result);
        } else {
            self.set_w(rd, result as u32);
        }

        Ok(CpuExit::Continue)
    }
}

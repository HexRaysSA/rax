//! core.rs

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
    pub(crate) fn exec_sve(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        self.check_fp_instruction(insn)?;
        if super::admission::reserved(insn) {
            return Ok(CpuExit::Undefined(insn));
        }
        self.check_sve_access(insn)?;
        let top = (insn >> 24) & 0xff;
        let has_sve2p1 = self.config.features.contains(ArmFeatures::SVE2P1);

        // Extract primary classification bits
        let op0 = (insn >> 29) & 0x7;
        let op1 = (insn >> 23) & 0x3;
        let op2 = (insn >> 17) & 0x1F;
        let op3 = (insn >> 10) & 0x3F;

        // Common register fields
        let zd = (insn & 0x1F) as usize;
        let zn = ((insn >> 5) & 0x1F) as usize;
        let zm = ((insn >> 16) & 0x1F) as usize;
        let pg = ((insn >> 10) & 0x7) as usize;
        let size = (insn >> 22) & 0x3;

        // Element size in bytes
        let esize = 1usize << size; // 1, 2, 4, or 8 bytes

        match op0 {
            // EXT (destructive): 0x05, bits[23:21]==001, bits[15:13]==000.
            // Zdn.B = (Zm:Zdn) extracted at byte offset imm8 (imm8h:imm8l).
            // Must precede the int_unpred arm below (which shares bit21==1 &&
            // bits[15:13]==000 but does not check the op byte). At VL=128 there
            // are 16 byte-elements; if imm8>=16 the offset wraps to 0.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 0x7 == 0b001
                    && (insn >> 13) & 0x7 == 0b000 =>
            {
                let imm8 = (((insn >> 16) & 0x1F) << 3) | ((insn >> 10) & 0x7);
                let low = self.v[zd]; // operand1 (Zdn) = low half of concat
                let high = self.v[zn]; // operand2 (Zm)  = high half of concat
                let pos = if imm8 >= 16 { 0 } else { imm8 };
                let s = pos * 8; // byte offset -> bit offset (0..=120)
                self.v[zd] = if s == 0 {
                    low
                } else {
                    (low >> s) | (high << (128 - s))
                };
                Ok(CpuExit::Continue)
            }

            // SVE2.1 DUPQ (broadcast indexed element within each 128-bit
            // segment): 0x05, bits[23:22]==00, bit21==1, bits[15:10]==001001. The
            // element size and segment index are packed into the tsz field
            // bits[20:16] (lowest set bit selects esize; the index is above it).
            // At VL=128 there is one segment, so Zn[index] fills every lane.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 22) & 0x3 == 0b00
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001001 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let tsz = (insn >> 16) & 0x1F;
                if tsz == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let size = tsz.trailing_zeros() as usize;
                let esz = 1usize << size;
                let index = (tsz >> (size + 1)) as usize;
                if esz == 16 {
                    self.v[zd] = if index == 0 { self.v[zn] } else { 0 };
                    return Ok(CpuExit::Continue);
                }
                let nsegelt = 16 / esz;
                let src = self.v[zn].to_le_bytes();
                let val = if index < nsegelt {
                    read_elem(&src, index * esz, esz)
                } else {
                    0
                };
                let mut dst = [0u8; 16];
                for e in 0..nsegelt {
                    write_elem(&mut dst, e * esz, esz, val);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2.1 EXTQ (extract within each 128-bit segment): 0x05,
            // bits[23:20]==0110, bits[15:10]==001001. imm4=bits[19:16] is a byte
            // offset (0..15). Destructive: the concatenation (Zm:Zdn) of the
            // 128-bit segment is shifted right imm bytes; at VL=128 this matches
            // EXT with a 4-bit immediate (Zdn=Zd field, Zm=Zn field).
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 20) & 0xF == 0b0110
                    && (insn >> 10) & 0x3F == 0b001001 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let imm = ((insn >> 16) & 0xF) as usize; // bytes
                let low = self.v[zd]; // Zdn
                let high = self.v[zn]; // Zm
                let s = imm * 8;
                self.v[zd] = if s == 0 {
                    low
                } else {
                    (low >> s) | (high << (128 - s))
                };
                Ok(CpuExit::Continue)
            }

            // SVE2.1 REVD (reverse 64-bit doublewords within each 128-bit
            // segment, predicated/merging): 0x05, bits[23:16]==0b00101110,
            // bits[15:13]==100. Pg=bits[12:10]; the swap of a 128-bit segment is
            // governed by the predicate bit of its low doubleword. At VL=128 the
            // single segment swaps its two 64-bit halves iff predicate bit 0 set.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 16) & 0xFF == 0b00101110
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let pg = ((insn >> 10) & 0x7) as usize;
                let pred = self.sve_p[pg];
                if pred & 1 == 1 {
                    let v = self.v[zn];
                    self.v[zd] = (v >> 64) | (v << 64);
                }
                // inactive low-doubleword -> merge (Zd unchanged)
                Ok(CpuExit::Continue)
            }

            // SVE2.1 PMOV (move a bit-plane between a vector and a predicate):
            // 0x05, bits[21:19]==101, bits[15:10]==001110. bit16 selects the
            // direction (0: Zn -> Pd, 1: Pn -> Zd). The element size and bit-plane
            // index are tsz-encoded in bits[23:22]:bits[18:17]. Per qemu pmov_pv/
            // pmov_vp, predicate bit e*esize maps to vector bit elements*idx+e
            // (elements = 16/esize). The vp form zeroes Zd only when idx==0 (else
            // it merges the selected plane).
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 19) & 0x7 == 0b101
                    && (insn >> 10) & 0x3F == 0b001110 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let sh = (insn >> 22) & 0x3;
                let sl = (insn >> 17) & 0x3;
                let (esz, idx): (usize, usize) = if sh == 0b00 && sl == 0b01 {
                    (0, 0)
                } else if sh == 0b00 && sl & 0b10 == 0b10 {
                    (1, (sl & 1) as usize)
                } else if sh == 0b01 {
                    (2, sl as usize)
                } else if sh & 0b10 == 0b10 {
                    (3, ((((sh & 1) << 2) | sl) as usize))
                } else {
                    return Ok(CpuExit::Undefined(insn));
                };
                let esize = 1usize << esz;
                let elements = 16 / esize;
                if (insn >> 16) & 1 == 0 {
                    // PMOV Pd.T, Zn[idx]: Zn -> Pd.
                    let pd = (insn & 0xF) as usize;
                    let z = self.v[((insn >> 5) & 0x1F) as usize];
                    let mut p = 0u32;
                    for e in 0..elements {
                        let bit = (z >> (elements * idx + e)) & 1;
                        p |= (bit as u32) << (e * esize);
                    }
                    self.sve_p[pd] = p;
                } else {
                    // PMOV Zd[idx], Pn.T: Pn -> Zd.
                    let zd = (insn & 0x1F) as usize;
                    let p = self.sve_p[((insn >> 5) & 0xF) as usize];
                    let mut z = if idx == 0 { 0u128 } else { self.v[zd] };
                    for e in 0..elements {
                        let pos = elements * idx + e;
                        let bit = ((p >> (e * esize)) & 1) as u128;
                        z = (z & !(1u128 << pos)) | (bit << pos);
                    }
                    self.v[zd] = z;
                }
                Ok(CpuExit::Continue)
            }

            // Unpredicated integer add/subtract (ADD/SUB/SQADD/UQADD/SQSUB/
            // UQSUB): bit21==1, bits[15:13]==000. Size is the full bits[23:22],
            // so this must NOT be gated on op1 (which folds size's high bit).
            0b000 if (insn >> 21) & 1 == 1 && (insn >> 13) & 0x7 == 0b000 => {
                self.exec_sve_int_unpred(insn, zd, zn, zm, esize)
            }

            // TBL (table lookup, single table): 0x05, bit21==1,
            // bits[15:10]==001100. Shares bits[15:10] with the unpredicated
            // logical arm below (0x04) so it MUST precede it and gate on 0x05.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001100 =>
            {
                self.exec_sve_tbl(zd, zn, zm, esize)
            }

            // TBX (table lookup, keep destination for out-of-range): 0x05,
            // bit21==1, bits[15:10]==001011. Like TBL but unmatched indices
            // preserve the existing Zd element instead of zeroing it.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001011 =>
            {
                self.exec_sve_tbx(zd, zn, zm, esize)
            }

            // SVE2.1 TBXQ (per-128-bit-segment table lookup, keep destination):
            // 0x05, bit21==1, bits[15:10]==001101. At VL=128 (one segment) this
            // is identical to TBX over the whole register.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001101 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                self.exec_sve_tbx(zd, zn, zm, esize)
            }

            // TBL2 (two-register table lookup): 0x05, bit21==1,
            // bits[15:10]==001010. The tables are {Zn, Zn+1}; out-of-range
            // indices yield 0.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001010 =>
            {
                let t0 = self.v[zn].to_le_bytes();
                let t1 = self.v[(zn + 1) % 32].to_le_bytes();
                let idx = self.v[zm].to_le_bytes();
                let n = 16 / esize;
                let mut dst = [0u8; 16];
                for e in 0..n {
                    let off = e * esize;
                    let i = read_elem(&idx, off, esize) as usize;
                    let val = if i < n {
                        read_elem(&t0, i * esize, esize)
                    } else if i < 2 * n {
                        read_elem(&t1, (i - n) * esize, esize)
                    } else {
                        0
                    };
                    write_elem(&mut dst, off, esize, val);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // Predicate ZIP/UZP/TRN (ZIP1_p..TRN2_p): 0x05, bits[21:20]==10,
            // bits[15:13]==010. opc=bits[12:10]. Permutes the esize-bit chunks
            // of the byte-granular predicates Pn (bits[8:5]) and Pm (bits[19:16]).
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 20) & 0x3 == 0b10
                    && (insn >> 13) & 0x7 == 0b010 =>
            {
                if (insn & ((1 << 9) | (1 << 4))) != 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let opc = (insn >> 10) & 0x7;
                let esize = 1usize << ((insn >> 22) & 0x3);
                let n = 16 / esize;
                let cmask = (1u32 << esize) - 1;
                let pn = self.sve_p[((insn >> 5) & 0xF) as usize];
                let pm = self.sve_p[((insn >> 16) & 0xF) as usize];
                let chunk = |p: u32, i: usize| (p >> (i * esize)) & cmask;
                let mut out = 0u32;
                let h = n / 2;
                for i in 0..h {
                    let (lo, hi) = match opc {
                        0b000 => (chunk(pn, i), chunk(pm, i)),                 // ZIP1
                        0b001 => (chunk(pn, h + i), chunk(pm, h + i)),         // ZIP2
                        0b100 => (chunk(pn, 2 * i), chunk(pm, 2 * i)),         // TRN1
                        0b101 => (chunk(pn, 2 * i + 1), chunk(pm, 2 * i + 1)), // TRN2
                        _ => (0, 0),
                    };
                    if matches!(opc, 0b000 | 0b001 | 0b100 | 0b101) {
                        out |= lo << (2 * i * esize);
                        out |= hi << ((2 * i + 1) * esize);
                    }
                }
                if opc == 0b010 || opc == 0b011 {
                    let odd = opc == 0b011; // UZP2 takes odd elements
                    for i in 0..n {
                        let v = if i < h {
                            chunk(pn, 2 * i + odd as usize)
                        } else {
                            chunk(pm, 2 * (i - h) + odd as usize)
                        };
                        out |= v << (i * esize);
                    }
                } else if opc > 0b101 {
                    return Ok(CpuExit::Undefined(insn));
                }
                self.sve_p[(insn & 0xF) as usize] = out;
                Ok(CpuExit::Continue)
            }

            // Predicate REV (REV_p): 0x05, bits[21:16]==110100, bits[15:10]==
            // 010000. Reverse the esize-bit chunks of the predicate Pn.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 16) & 0x3F == 0b110100
                    && (insn >> 10) & 0x3F == 0b010000 =>
            {
                if (insn & ((1 << 9) | (1 << 4))) != 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let esize = 1usize << ((insn >> 22) & 0x3);
                let n = 16 / esize;
                let cmask = (1u32 << esize) - 1;
                let pn = self.sve_p[((insn >> 5) & 0xF) as usize];
                let mut out = 0u32;
                for i in 0..n {
                    out |= ((pn >> ((n - 1 - i) * esize)) & cmask) << (i * esize);
                }
                self.sve_p[(insn & 0xF) as usize] = out;
                Ok(CpuExit::Continue)
            }

            // PUNPKLO/PUNPKHI (predicate unpack): 0x05, bits[23:20]==0011,
            // bits[19:17]==000, bits[15:10]==010000. Each of the low (lo) / high
            // (hi, bit16) 8 source predicate bits expands to bit 2i of the dest.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 22) & 0x3 == 0
                    && (insn >> 20) & 0x3 == 0b11
                    && (insn >> 17) & 0x7 == 0
                    && (insn >> 10) & 0x3F == 0b010000 =>
            {
                let hi = (insn >> 16) & 1 == 1;
                let pn = self.sve_p[((insn >> 5) & 0xF) as usize];
                let pd = (insn & 0xF) as usize;
                let base = if hi { 8 } else { 0 };
                let mut out = 0u32;
                for i in 0..8 {
                    if (pn >> (base + i)) & 1 == 1 {
                        out |= 1 << (2 * i);
                    }
                }
                self.sve_p[pd] = out;
                Ok(CpuExit::Continue)
            }

            // DUP (indexed broadcast) Zd.T, Zn.T[index]: 0x05, bit21==1,
            // bits[15:10]==001000. esize and index come from the tsz:imm2 field
            // (lowest set bit of tsz selects esize).
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001000 =>
            {
                self.exec_sve_dup_indexed(insn, zn, zd)
            }

            // COMPACT (pack active elements down): 0x05, bit23==1,
            // bits[21:16]==100001, bits[15:13]==100. S/D elements only.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 23) & 1 == 1
                    && (insn >> 16) & 0x3F == 0b100001
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                self.exec_sve_compact(insn, zd, zn, pg)
            }

            // SVE2 SPLICE (constructive): 0x05, bits[21:16]==101101,
            // bits[15:13]==100. Sources are the consecutive pair {Zn, Zn+1}.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 16) & 0x3F == 0b101101
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                self.exec_sve_splice_pair(insn, zd, zn, pg)
            }

            // SPLICE (destructive): 0x05, bits[21:16]==101100, bits[15:13]==100.
            // Zdn's active span is packed low, the rest filled from Zm.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 16) & 0x3F == 0b101100
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                self.exec_sve_splice(insn, zd, zn, pg)
            }

            // Unpredicated bitwise logical (AND/ORR/EOR/BIC): bits[15:10]=001100.
            0b000 if (insn >> 21) & 1 == 1 && (insn >> 10) & 0x3F == 0b001100 => {
                self.exec_sve_logical_unpred(insn, zd, zn, zm)
            }

            // SVE2 unpredicated multiply: 0x04, bit21==1, bits[15:12]==0110,
            // bits[11:10] opc (00=MUL, 01=PMUL byte-only, 10=SMULH, 11=UMULH).
            // The 0x05 sibling of bits[15:12]==0110 is ZIP/UZP/TRN, so this MUST
            // gate on the op byte. PMUL is defined for byte elements only.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 12) & 0xF == 0b0110
                    && ((insn >> 10) & 0x3 != 0b01 || esize == 1) =>
            {
                let opc = (insn >> 10) & 0x3;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let elements = 16 / esize;
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..elements {
                    let off = e * esize;
                    let x = read_elem(&a, off, esize);
                    let y = read_elem(&b, off, esize);
                    let r = match opc {
                        0b00 => x.wrapping_mul(y) & mask,
                        0b01 => poly_mul_8(x, y), // PMUL.B (carry-less)
                        0b10 => ((sext_elem(x, bits) * sext_elem(y, bits)) >> bits) as u64 & mask,
                        _ => ((uext_elem(x, bits) * uext_elem(y, bits)) >> bits) as u64 & mask,
                    };
                    write_elem(&mut dst, off, esize, r);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 bitwise ternary (whole-register): 0x04, bit21==1,
            // bits[15:11]==00111. Zdn=bits[4:0], Zk=bits[9:5], Zm=bits[20:16];
            // opc=bits[23:22], o2=bit10 select the operation.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 11) & 0x1F == 0b00111 =>
            {
                let opc = (insn >> 22) & 0x3;
                let o2 = (insn >> 10) & 1;
                let dn = self.v[zd]; // Zdn (first source + destination)
                let k = self.v[zn]; // Zk (select mask)
                let m = self.v[zm]; // Zm (second source)
                self.v[zd] = match (opc, o2) {
                    (0b00, 0) => dn ^ m ^ k,             // EOR3
                    (0b01, 0) => dn ^ (m & !k),          // BCAX
                    (0b00, 1) => (dn & k) | (m & !k),    // BSL
                    (0b01, 1) => (!dn & k) | (m & !k),   // BSL1N
                    (0b10, 1) => (dn & k) | (!m & !k),   // BSL2N
                    (0b11, 1) => !((dn & k) | (m & !k)), // NBSL
                    _ => return Ok(CpuExit::Undefined(insn)),
                };
                Ok(CpuExit::Continue)
            }

            // SVE FEXPA (exponential accelerator): 0x04, bit21==1,
            // bits[20:16]==00000, bits[15:10]==101110. Unpredicated table lookup.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 16) & 0x1F == 0b00000
                    && (insn >> 10) & 0x3F == 0b101110 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let esz = 1usize << size;
                let n = self.v[zn].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..(16 / esz) {
                    let off = e * esz;
                    write_elem(&mut dst, off, esz, sve_fexpa(esz, read_elem(&n, off, esz)));
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE REVB/REVH/REVW/RBIT (predicated, merging): 0x05, bit21==1,
            // bits[20:18]==001, bits[15:13]==100. bits[17:16]: 00=REVB (reverse
            // bytes within each element), 01=REVH (halfwords), 10=REVW (words),
            // 11=RBIT (bits). @rd_pg_rn.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 18) & 0x7 == 0b001
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                let op = (insn >> 16) & 0x3;
                let unit = match op {
                    0b00 => 1usize,          // REVB
                    0b01 if esize >= 4 => 2, // REVH (S/D)
                    0b10 if esize == 8 => 4, // REVW (D)
                    0b11 => 0,               // RBIT
                    _ => return Ok(CpuExit::Undefined(insn)),
                };
                if op == 0b00 && esize < 2 {
                    return Ok(CpuExit::Undefined(insn)); // REVB.b is reserved
                }
                let pg = ((insn >> 10) & 0x7) as usize;
                let rn = ((insn >> 5) & 0x1F) as usize;
                let pred = self.sve_p[pg];
                let mask = elem_mask((esize * 8) as u32);
                let src = self.v[rn].to_le_bytes();
                let mut dst = self.v[zd].to_le_bytes();
                for e in 0..(16 / esize) {
                    let off = e * esize;
                    if (pred >> off) & 1 == 0 {
                        continue;
                    }
                    let v = read_elem(&src, off, esize);
                    let r = if op == 0b11 {
                        (v & mask).reverse_bits() >> (64 - esize * 8)
                    } else {
                        reverse_chunks(v, esize, unit) & mask
                    };
                    write_elem(&mut dst, off, esize, r);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE INSR (insert scalar, shifting the vector up one element): 0x05,
            // bit21==1, bits[15:10]==001110, bits[20:16]==00100 (GPR) or 10100
            // (SIMD scalar). New Zdn = [scalar, Zdn[0..N-1]].
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001110
                    && matches!((insn >> 16) & 0x1F, 0b00100 | 0b10100) =>
            {
                let insr_f = (insn >> 20) & 1 == 1; // SIMD&FP scalar form
                let rmf = ((insn >> 5) & 0x1F) as usize;
                let esbits = esize * 8;
                let smask: u128 = (1u128 << esbits) - 1;
                let scalar = if insr_f {
                    self.v[rmf] & smask
                } else {
                    (self.get_x(rmf as u8) as u128) & smask
                };
                self.v[zd] = (self.v[zd] << esbits) | scalar;
                Ok(CpuExit::Continue)
            }

            // SVE CLASTA/CLASTB to vector or SIMD&FP scalar: 0x05,
            // bits[21:17]==10100 (vector) / 10101 (scalar), bit16=A(0)/B(1),
            // bits[15:13]==100. The element at (CLASTB) / after (CLASTA) the last
            // active lane of Zm is broadcast to Zdn (vector) or written to Vd
            // (scalar); with no active lane the destination is unchanged.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && matches!((insn >> 17) & 0x1F, 0b10100 | 0b10101)
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                let scalar_form = (insn >> 17) & 1 == 1;
                let before = (insn >> 16) & 1 == 1; // CLASTB
                let pg = ((insn >> 10) & 0x7) as usize;
                let src_reg = ((insn >> 5) & 0x1F) as usize;
                let n = 16 / esize;
                let pred = self.sve_p[pg];
                let mask = elem_mask((esize * 8) as u32);
                let src = self.v[src_reg].to_le_bytes();
                let mut last: i32 = -1;
                for e in (0..n).rev() {
                    if (pred >> (e * esize)) & 1 == 1 {
                        last = e as i32;
                        break;
                    }
                }
                let selected = if last >= 0 {
                    let idx = if before {
                        last as usize
                    } else {
                        let i = (last + 1) as usize;
                        if i >= n { 0 } else { i }
                    };
                    Some(read_elem(&src, idx * esize, esize) & mask)
                } else {
                    None
                };
                if scalar_form {
                    // Writing to a SIMD&FP scalar always zeroes the upper bits;
                    // with no active element the prior low element is preserved.
                    let val = selected.unwrap_or((self.v[zd] as u64) & mask);
                    self.v[zd] = val as u128;
                } else if let Some(val) = selected {
                    // Vector form: broadcast; unchanged if no active element.
                    let mut out = 0u128;
                    for e in 0..n {
                        out |= (val as u128) << (e * esize * 8);
                    }
                    self.v[zd] = out;
                }
                Ok(CpuExit::Continue)
            }

            // SVE FCPY (copy FP immediate into Pg-active lanes, merging): 0x05,
            // bits[21:20]==01, bits[15:13]==110. Pg is 4-bit (bits[19:16]).
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 20) & 0x3 == 0b01
                    && (insn >> 13) & 0x7 == 0b110 =>
            {
                if esize < 2 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let pg = ((insn >> 16) & 0xF) as usize;
                let imm8 = ((insn >> 5) & 0xFF) as u8;
                let val = vfp_expand_imm(imm8, esize);
                let pred = self.sve_p[pg];
                let mut dst = self.v[zd].to_le_bytes();
                for e in 0..(16 / esize) {
                    let off = e * esize;
                    if (pred >> off) & 1 == 1 {
                        write_elem(&mut dst, off, esize, val);
                    }
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE ORR/EOR/AND with a logical immediate: bits[21:18]==0000,
            // opc=bits[23:22]. The N:immr:imms field decodes a 64-bit mask
            // broadcast to every doubleword lane.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 18) & 0xF == 0
                    && (insn >> 22) & 0x3 != 0b11 =>
            {
                let n = (insn >> 17) & 1 == 1;
                let immr = (insn >> 11) & 0x3F;
                let imms = (insn >> 5) & 0x3F;
                match decode_bitmask(n, imms, immr, true) {
                    Ok(mask) => {
                        let imm = (mask as u128) | ((mask as u128) << 64);
                        self.v[zd] = match (insn >> 22) & 0x3 {
                            0b00 => self.v[zd] | imm,
                            0b01 => self.v[zd] ^ imm,
                            _ => self.v[zd] & imm,
                        };
                        Ok(CpuExit::Continue)
                    }
                    Err(_) => Ok(CpuExit::Undefined(insn)),
                }
            }

            // SVE DUPM (broadcast logical-immediate mask): 0x05, bits[23:18]==
            // 110000. The N:immr:imms field decodes a 64-bit mask broadcast to
            // every doubleword lane.
            0b000 if (insn >> 24) & 0xFF == 0b00000101 && (insn >> 18) & 0x3F == 0b110000 => {
                let n = (insn >> 17) & 1 == 1;
                let immr = (insn >> 11) & 0x3F;
                let imms = (insn >> 5) & 0x3F;
                match decode_bitmask(n, imms, immr, true) {
                    Ok(imm) => {
                        self.v[zd] = (imm as u128) | ((imm as u128) << 64);
                        Ok(CpuExit::Continue)
                    }
                    Err(_) => Ok(CpuExit::Undefined(insn)),
                }
            }

            // SVE UNPK (SUNPKHI/LO, UUNPKHI/LO): 0x05, bits[21:18]==1100,
            // bits[15:10]==001110. Unpack the low (h=0) or high (h=1) half of
            // Zn, sign- (u=0) or zero- (u=1) extending each half-width element.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 18) & 0xF == 0b1100
                    && (insn >> 10) & 0x3F == 0b001110 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let mask = elem_mask((d_esize * 8) as u32);
                let unsigned = (insn >> 17) & 1 == 1;
                let hi = (insn >> 16) & 1 == 1;
                let src = self.v[zn].to_le_bytes();
                let n_dst = 16 / d_esize;
                let mut dst = [0u8; 16];
                for e in 0..n_dst {
                    let src_idx = (if hi { n_dst } else { 0 }) + e;
                    let sv = read_elem(&src, src_idx * s_esize, s_esize);
                    let r = if unsigned {
                        uext_elem(sv, s_bits) as u64
                    } else {
                        sext_elem(sv, s_bits) as u64
                    };
                    write_elem(&mut dst, e * d_esize, d_esize, r & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE FTSSEL (trigonometric select coefficient): 0x04, bit21==1,
            // bits[15:10]==101100. Per lane: result = Zm[e]&1 ? 1.0 : Zn[e];
            // then if Zm[e]&2 negate. Unpredicated; Zn=bits[9:5], Zm=bits[20:16].
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b101100 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let esize = 1usize << size;
                let one: u64 = match esize {
                    2 => 0x3C00,
                    4 => 0x3F80_0000,
                    _ => 0x3FF0_0000_0000_0000,
                };
                let signbit: u64 = 1 << (esize * 8 - 1);
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..(16 / esize) {
                    let off = e * esize;
                    let mm = read_elem(&m, off, esize);
                    let mut nn = read_elem(&n, off, esize);
                    if mm & 1 != 0 {
                        nn = one;
                    }
                    if mm & 2 != 0 {
                        nn ^= signbit;
                    }
                    write_elem(&mut dst, off, esize, nn);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 XAR (exclusive-or and rotate right by immediate): 0x04,
            // bit21==1, bits[15:10]==001101. Zdn=bits[4:0], Zm=bits[9:5]; the
            // tsz:imm3 field gives the element size and rotate amount (1..bits).
            // Destructive: Zdn = ROR(Zdn ^ Zm, amount) per element.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b001101 =>
            {
                let tsz = (((insn >> 22) & 0x3) << 2) | ((insn >> 19) & 0x3);
                if tsz == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let bits: u32 = if tsz & 0b1000 != 0 {
                    64
                } else if tsz & 0b0100 != 0 {
                    32
                } else if tsz & 0b0010 != 0 {
                    16
                } else {
                    8
                };
                let esize = (bits / 8) as usize;
                let tszimm = (tsz << 3) | ((insn >> 16) & 0x7);
                let amount = (2 * bits - tszimm) % bits; // 1..bits, bits == identity
                let a = self.v[zd].to_le_bytes();
                let b = self.v[zn].to_le_bytes();
                let mask = elem_mask(bits);
                let mut dst = [0u8; 16];
                for e in 0..(16 / esize) {
                    let off = e * esize;
                    let x = (read_elem(&a, off, esize) ^ read_elem(&b, off, esize)) & mask;
                    let r = if amount == 0 {
                        x
                    } else {
                        ((x >> amount) | (x << (bits - amount))) & mask
                    };
                    write_elem(&mut dst, off, esize, r);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 SQDMULH/SQRDMULH (unpredicated saturating doubling multiply
            // high): 0x04, bit21==1, bits[15:11]==01110. R=bit10 adds rounding.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 11) & 0x1F == 0b01110 =>
            {
                let round = (insn >> 10) & 1 == 1;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let elements = 16 / esize;
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                let hi = (1i128 << (bits - 1)) - 1;
                let lo = -(1i128 << (bits - 1));
                for e in 0..elements {
                    let off = e * esize;
                    let prod = sext_elem(read_elem(&a, off, esize), bits)
                        * sext_elem(read_elem(&b, off, esize), bits);
                    let high = if round {
                        (prod + (1i128 << (bits - 2))) >> (bits - 1)
                    } else {
                        prod >> (bits - 1)
                    };
                    write_elem(&mut dst, off, esize, high.clamp(lo, hi) as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE element count / inc-dec / stack allocation (0x04). The stack
            // forms (ADDVL/ADDPL/RDVL, bits[15:11]==01010) share bits[15:13]==010
            // with INDEX but differ at bit12; the count forms have bits[15:14]==11.
            // Routed before INDEX so the stack forms are not mis-decoded.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (((insn >> 11) & 0x1F == 0b01010)
                        || matches!((insn >> 12) & 0xF, 0b1100 | 0b1110 | 0b1111)) =>
            {
                self.exec_sve_elem_count(insn)
            }

            // INDEX (immediate/scalar variants): bit21==1, bits[15:13]==010.
            0b000 if (insn >> 21) & 1 == 1 && (insn >> 13) & 0x7 == 0b010 => {
                self.exec_sve_index(insn, zd, esize)
            }

            // ZIP/UZP/TRN (unpredicated permute): 0x05, bit21==1, bits[15:13]==011.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x7 == 0b011 =>
            {
                self.exec_sve_zip_uzp_trn(insn, zd, zn, zm, esize)
            }

            // SEL Zd.T, Pg, Zn, Zm: 0x05, bit21==1, bits[15:14]==11. Per-element
            // merge governed by the 4-bit predicate Pg (bits[13:10]).
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 14) & 0x3 == 0b11 =>
            {
                let pg = ((insn >> 10) & 0xF) as usize;
                let pred = self.sve_p[pg];
                let elements = 16 / esize;
                let n_reg = self.v[zn].to_le_bytes();
                let m_reg = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..elements {
                    let off = e * esize;
                    let src = if (pred >> (e * esize)) & 1 == 1 {
                        &n_reg
                    } else {
                        &m_reg
                    };
                    write_elem(&mut dst, off, esize, read_elem(src, off, esize));
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // REV Zd.T, Zn.T (reverse all elements): 0x05, bits[20:16]==11000,
            // bits[15:10]==001110.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 16) & 0x1F == 0b11000
                    && (insn >> 10) & 0x3F == 0b001110 =>
            {
                let n = 16 / esize;
                let a = self.v[zn].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..n {
                    write_elem(
                        &mut dst,
                        e * esize,
                        esize,
                        read_elem(&a, (n - 1 - e) * esize, esize),
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // CPY/MOV (predicated copy of immediate / scalar GPR / SIMD scalar),
            // all in the 0x05 space.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 20) & 0x3 == 0b01
                    && (insn >> 15) & 1 == 0 =>
            {
                self.exec_sve_cpy(insn, esize, 0) // CPY immediate
            }
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 16) & 0x3F == 0b101000
                    && (insn >> 13) & 0x7 == 0b101 =>
            {
                self.exec_sve_cpy(insn, esize, 1) // CPY scalar GPR
            }
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 16) & 0x3F == 0b100000
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                self.exec_sve_cpy(insn, esize, 2) // CPY SIMD scalar
            }

            // LASTA/LASTB to SIMD&FP scalar: 0x05, bits[21:17]==10001,
            // bit16: 0=A (after), 1=B (before), bits[15:13]==100.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 17) & 0x1F == 0b10001
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                self.exec_sve_last_scalar(insn, esize)
            }

            // LASTA/LASTB/CLASTA/CLASTB -> GPR: 0x05, bits[15:13]==101, bit21==1,
            // bits[19:17]==000. bit20: 0=LAST, 1=CLAST; bit16: 0=A (after), 1=B.
            0b000
                if (insn >> 24) & 0xFF == 0b00000101
                    && (insn >> 13) & 0x7 == 0b101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 17) & 0x7 == 0b000 =>
            {
                self.exec_sve_lastx(insn, esize)
            }

            // ADR (vector address generation): 0x04, bit21==1, bits[15:12]==1010.
            // Zd[e] = Zn[e] + offset(Zm[e]) * 2^msz. bits[23:22] selects the
            // form: 00=D+SXTW(Zm<31:0>), 01=D+UXTW(Zm<31:0>), 10=S packed,
            // 11=D packed. msz = bits[11:10].
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 12) & 0xF == 0b1010 =>
            {
                let mode = (insn >> 22) & 0x3;
                let msz = (insn >> 10) & 0x3;
                let esize = if mode == 0b10 { 4 } else { 8 };
                let elements = 16 / esize;
                let m = elem_mask((esize * 8) as u32);
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..elements {
                    let off = e * esize;
                    let base = read_elem(&a, off, esize);
                    let zmv = read_elem(&b, off, esize);
                    let offset = match mode {
                        0b00 => (zmv as u32 as i32 as i64 as u64) << msz, // SXTW
                        0b01 => (zmv as u32 as u64) << msz,               // UXTW
                        _ => zmv << msz,                                  // packed S/D
                    };
                    write_elem(&mut dst, off, esize, base.wrapping_add(offset) & m);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // MOVPRFX Zd, Zn (unpredicated whole-register copy): 0x04,
            // bits[23:16]==00100000, bits[15:10]==101111. Standalone it is a
            // plain vector move.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 16) & 0xFF == 0b00100000
                    && (insn >> 10) & 0x3F == 0b101111 =>
            {
                self.v[zd] = self.v[zn];
                Ok(CpuExit::Continue)
            }

            // MOVPRFX Zd.T, Pg/M-or-Z, Zn.T (predicated copy): 0x04,
            // bits[21:18]==0100, bit17==0, bits[15:13]==001. Active lanes copy
            // Zn; inactive lanes merge (M=1, keep Zd) or zero (M=0). Must precede
            // the integer-reduction arm, which shares bit21==0 && bits[15:13]==001.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 18) & 0xF == 0b0100
                    && (insn >> 17) & 1 == 0
                    && (insn >> 13) & 0x7 == 0b001 =>
            {
                let merging = (insn >> 16) & 1 == 1;
                let pred = self.sve_p[pg];
                let elements = 16 / esize;
                let n_reg = self.v[zn].to_le_bytes();
                let mut dst = self.v[zd].to_le_bytes(); // merging base = prior Zd
                for e in 0..elements {
                    let off = e * esize;
                    if (pred >> off) & 1 == 1 {
                        write_elem(&mut dst, off, esize, read_elem(&n_reg, off, esize));
                    } else if !merging {
                        write_elem(&mut dst, off, esize, 0);
                    }
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2.1 integer quadword reductions (ADDQV/SMAXQV/UMAXQV/SMINQV/
            // UMINQV/ANDQV/ORQV/EORQV): 0x04, bit21==0, bits[15:13]==001, and
            // bit18==1 (the QV opcodes set the high bit of bits[18:16], unlike the
            // scalar reductions below). Reduces each element position across the
            // 128-bit segments into a single quadword in Vd. Must precede the
            // scalar-reduction arm, which shares bit21==0 && bits[15:13]==001.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 13) & 0x7 == 0b001
                    && (insn >> 18) & 1 == 1 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                self.exec_sve_qv_reduce_int(insn, esize)
            }

            // Integer reductions to a scalar (SADDV/UADDV/SMAXV/.../ANDV/ORV/
            // EORV): bit21==0, bits[15:13]==001.
            0b000 if (insn >> 21) & 1 == 0 && (insn >> 13) & 0x7 == 0b001 => {
                self.exec_sve_int_reduce(insn, esize)
            }

            // Predicated shift by vector (ASR/LSR/LSL Zdn, Pg/M, Zdn, Zm):
            // bits[15:13]==100, bits[21:19]==010.
            0b000
                if (insn >> 13) & 0x7 == 0b100
                    && (insn >> 19) & 0x7 == 0b010
                    && (insn >> 21) & 1 == 0 =>
            {
                self.exec_sve_shift_pred(insn, zd, zn, pg, esize)
            }

            // Predicated shift by wide elements (ASR/LSR/LSL Zdn, Pg/M, Zdn,
            // Zm.D): byte/half/word lanes use the 64-bit Zm element that covers
            // the lane as the shift amount; doubleword lanes are unallocated.
            0b000
                if top == 0b0000_0100
                    && (insn >> 13) & 0x7 == 0b100
                    && (insn >> 19) & 0x7 == 0b011
                    && matches!((insn >> 16) & 0x7, 0b000 | 0b001 | 0b011) =>
            {
                self.exec_sve_shift_wide_pred(insn, zd, zn, pg, esize)
            }

            // Unpredicated shift by wide elements (ASR/LSR/LSL Zd, Zn, Zm.D).
            0b000
                if top == 0b0000_0100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x7 == 0b100
                    && matches!((insn >> 10) & 0x7, 0b000 | 0b001 | 0b011) =>
            {
                self.exec_sve_shift_wide_unpred(insn, zd, zn, zm, esize)
            }

            // Unpredicated shift by immediate (ASR/LSR/LSL Zd, Zn, #imm).
            0b000
                if top == 0b0000_0100
                    && (insn >> 21) & 1 == 1
                    && matches!((insn >> 10) & 0x3F, 0b100100 | 0b100101 | 0b100111) =>
            {
                self.exec_sve_shift_imm_unpred(insn)
            }

            // Predicated shift by immediate: bits[15:13]==100, bits[21:20]==00
            // (bits[21:19] 000 => ASR/LSR/LSL/ASRD/SQSHL/UQSHL, 001 => SRSHR/
            // URSHR/SQSHLU).
            0b000 if (insn >> 13) & 0x7 == 0b100 && (insn >> 20) & 0x3 == 0b00 => {
                self.exec_sve_shift_imm(insn)
            }

            // SVE predicated integer/FP unary (merging): 0x04, bits[15:13]==101,
            // bits[21:19] in {010,011}. opc=bits[21:16] selects SXTB/H/W, UXTB/
            // H/W, ABS, NEG, CLS, CLZ, CNT, CNOT, FABS, FNEG, NOT.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 13) & 0x7 == 0b101
                    && matches!((insn >> 19) & 0x7, 0b010 | 0b011) =>
            {
                let opc = (insn >> 16) & 0x3F;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let signbit = 1u64 << (bits - 1);
                let pred = self.sve_p[pg];
                let src = self.v[zn].to_le_bytes();
                let mut dst = self.v[zd].to_le_bytes();
                // Validity: the extend width must be smaller than the element.
                // Checked up front — an unallocated size is UNDEF even when
                // the governing predicate has no active elements.
                let ext_ok = |w: u32| bits > w;
                let opc_valid = match opc {
                    0b010000 | 0b010001 => ext_ok(8),
                    0b010010 | 0b010011 => ext_ok(16),
                    0b010100 | 0b010101 => ext_ok(32),
                    0b010110..=0b011011 | 0b011110 => true,
                    0b011100 | 0b011101 => esize >= 2,
                    _ => false,
                };
                if !opc_valid {
                    return Ok(CpuExit::Undefined(insn));
                }
                for e in 0..(16 / esize) {
                    let off = e * esize;
                    if (pred >> off) & 1 == 0 {
                        continue;
                    }
                    let v = read_elem(&src, off, esize);
                    let r: u64 = match opc {
                        0b010000 if ext_ok(8) => sext_elem(v, 8) as u64 & mask, // SXTB
                        0b010001 if ext_ok(8) => v & 0xFF,                      // UXTB
                        0b010010 if ext_ok(16) => sext_elem(v, 16) as u64 & mask, // SXTH
                        0b010011 if ext_ok(16) => v & 0xFFFF,                   // UXTH
                        0b010100 if ext_ok(32) => sext_elem(v, 32) as u64 & mask, // SXTW
                        0b010101 if ext_ok(32) => v & 0xFFFF_FFFF,              // UXTW
                        0b010110 => sext_elem(v, bits).unsigned_abs() as u64 & mask, // ABS
                        0b010111 => (-sext_elem(v, bits)) as u64 & mask,        // NEG
                        0b011000 => count_leading_sign(v, bits),                // CLS
                        0b011001 => count_leading_zeros_elem(v, bits),          // CLZ
                        0b011010 => (v & mask).count_ones() as u64,             // CNT
                        0b011011 => u64::from(v & mask == 0),                   // CNOT
                        0b011100 if esize >= 2 => fp_abs_bits_with_fpcr(v, bits, self.fpcr), // FABS
                        0b011101 if esize >= 2 => fp_neg_bits_with_fpcr(v, bits, self.fpcr), // FNEG
                        0b011110 => !v & mask,                                  // NOT
                        _ => return Ok(CpuExit::Undefined(insn)),
                    };
                    write_elem(&mut dst, off, esize, r);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE predicated integer multiply-add: 0x04, bit21==0, bits[15:13]
            // ==010 (MLA: d=Za+Zn*Zm), 011 (MLS: d=Za-Zn*Zm), 110 (MAD:
            // d=Za+Zdn*Zm), 111 (MSB: d=Za-Zdn*Zm). Low-half integer multiply,
            // merging. MLA/MLS keep Za in Zd; MAD/MSB keep a multiplicand in Zd.
            0b000
                if (insn >> 24) & 0xFF == 0b00000100
                    && (insn >> 21) & 1 == 0
                    && matches!((insn >> 13) & 0x7, 0b010 | 0b011 | 0b110 | 0b111) =>
            {
                let op3 = (insn >> 13) & 0x7;
                let sub = op3 & 1 == 1; // MLS/MSB
                let mad = op3 & 0x4 != 0; // MAD/MSB (Zdn is a multiplicand)
                let rm = ((insn >> 16) & 0x1F) as usize;
                let r95 = ((insn >> 5) & 0x1F) as usize;
                let (f1, f2, ar) = if mad { (zd, rm, r95) } else { (r95, rm, zd) };
                let pred = self.sve_p[pg];
                let mask = elem_mask((esize * 8) as u32);
                let fb1 = self.v[f1].to_le_bytes();
                let fb2 = self.v[f2].to_le_bytes();
                let ab = self.v[ar].to_le_bytes();
                let mut dst = self.v[zd].to_le_bytes();
                for e in 0..(16 / esize) {
                    let off = e * esize;
                    if (pred >> off) & 1 == 0 {
                        continue;
                    }
                    let prod =
                        read_elem(&fb1, off, esize).wrapping_mul(read_elem(&fb2, off, esize));
                    let a = read_elem(&ab, off, esize);
                    let r = if sub {
                        a.wrapping_sub(prod)
                    } else {
                        a.wrapping_add(prod)
                    } & mask;
                    write_elem(&mut dst, off, esize, r);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // Integer predicated binary operations
            0b000 if (op1 & 0x2) == 0 && (op2 & 0x10) == 0 => {
                self.exec_sve_int_pred(insn, zd, zn, zm, pg, esize)
            }

            // Unpredicated arithmetic
            0b000 if op1 == 0b01 => self.exec_sve_int_unpred(insn, zd, zn, zm, esize),

            // SVE2.1 PSEL (predicate select): 0x25, bit21==1, bits[15:14]==01,
            // bit9==0, bit4==0. Pd = Pn if the Pm element at (Wv+imm) mod
            // elements is active, else Pd is all-false. The element size and imm
            // are tsz-encoded in bits[23:18]; Wv = W(bits[17:16]+12).
            0b001
                if (insn >> 24) & 0xFF == 0b00100101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 14) & 0x3 == 0b01
                    && (insn >> 9) & 1 == 0
                    && (insn >> 4) & 1 == 0 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let b2322 = (insn >> 22) & 0x3;
                let b20 = (insn >> 20) & 1;
                let b19 = (insn >> 19) & 1;
                let b18 = (insn >> 18) & 1;
                let (esz, imm): (usize, u64) = if b18 == 1 {
                    (0, ((b2322 << 2) | ((insn >> 19) & 0x3)) as u64)
                } else if b19 == 1 {
                    (1, ((b2322 << 1) | b20) as u64)
                } else if b20 == 1 {
                    (2, b2322 as u64)
                } else if (insn >> 22) & 1 == 1 {
                    (3, ((insn >> 23) & 1) as u64)
                } else {
                    return Ok(CpuExit::Undefined(insn));
                };
                let esize = 1usize << esz;
                let elements = (16 / esize) as u64;
                let rv = 12 + ((insn >> 16) & 0x3) as u8;
                let wv = self.get_x(rv) & 0xFFFF_FFFF;
                let idx = (wv.wrapping_add(imm)) % elements;
                let pm = ((insn >> 5) & 0xF) as usize;
                let pn = ((insn >> 10) & 0xF) as usize;
                let pd = (insn & 0xF) as usize;
                let active = (self.sve_p[pm] >> (idx as usize * esize)) & 1 == 1;
                self.sve_p[pd] = if active { self.sve_p[pn] } else { 0 };
                Ok(CpuExit::Continue)
            }

            // SVE2.1 PEXT (extract a predicate from a predicate-as-counter):
            // 0x25, bit21==1, bits[20:16]==00000, bits[15:12]==0111, bit4==1.
            // PEXT_1 (bits[11:10]==00, imm=bits[9:8]) writes one predicate;
            // PEXT_2 (bits[11:9]==010, imm=bit8) writes the pair {Pd, Pd+1}. The
            // counter source is PN(8+bits[7:5]). Decodes the counter (qemu
            // decode_counter/CounterToPredicate) into the `part`-th VL-sized chunk.
            0b001
                if (insn >> 24) & 0xFF == 0b00100101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 16) & 0x1F == 0b00000
                    && (insn >> 12) & 0xF == 0b0111
                    && (insn >> 4) & 1 == 1 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let v_esz = ((insn >> 22) & 0x3) as usize;
                let (n, imm) = if (insn >> 10) & 0x3 == 0b00 {
                    (1usize, ((insn >> 8) & 0x3) as usize) // PEXT_1
                } else if (insn >> 9) & 0x7 == 0b010 {
                    (2usize, ((insn >> 8) & 1) as usize) // PEXT_2
                } else {
                    return Ok(CpuExit::Undefined(insn));
                };
                let png = self.sve_p[(8 + ((insn >> 5) & 0x7)) as usize] & 0xFFFF;
                let rd_base = (insn & 0xF) as usize;
                const VL_BYTES: usize = 16; // VL=128 -> 16-byte vector, 16-bit predicate
                const PRED_MASKS: [u32; 5] = [0xFFFF, 0x5555, 0x1111, 0x0101, 0x0001];
                // decode_counter (predicate-as-counter -> element count/invert/stride)
                let (count, lg2_stride, invert) = if png & 0xF != 0 {
                    let p_esz = png.trailing_zeros() as usize;
                    let mut count = (png & ((VL_BYTES as u32) * 8 - 1)) as usize; // pow2ceil(16)<<3 -1 = 127
                    count >>= p_esz + 1;
                    let invert = (png >> 15) & 1 == 1;
                    let mut stride = 0usize;
                    if p_esz != v_esz {
                        if p_esz < v_esz {
                            let shift = v_esz - p_esz;
                            let trunc = count >> shift;
                            count = trunc + (count != (trunc << shift)) as usize;
                        } else {
                            let shift = p_esz - v_esz;
                            count <<= shift;
                            stride = shift;
                        }
                    }
                    (count, stride, invert)
                } else {
                    (0, 0, false)
                };
                let esz_mask = PRED_MASKS[v_esz + lg2_stride];
                let oprbits = VL_BYTES; // 16 predicate bit-positions at VL=128
                for i in 0..n {
                    let rd = (rd_base + i) % 16;
                    let part = imm * n + i;
                    let b_count = ((count << v_esz) as i64) - (VL_BYTES * part) as i64;
                    let pd = if invert {
                        if b_count <= 0 {
                            esz_mask // whilel(all)
                        } else if (b_count as usize) < oprbits {
                            // whileg: last (oprbits - b_count) positions active
                            let inv = b_count as usize;
                            esz_mask & !((1u32 << inv) - 1) & ((1u32 << oprbits) - 1)
                        } else {
                            0
                        }
                    } else if b_count > 0 {
                        // whilel: first min(b_count, oprbits) positions active
                        let c = (b_count as usize).min(oprbits);
                        esz_mask & ((1u32 << c) - 1)
                    } else {
                        0
                    };
                    self.sve_p[rd] = pd;
                }
                Ok(CpuExit::Continue)
            }

            // Predicate operations (WHILE, PTRUE, etc.)
            0b001 => self.exec_sve_pred_ops(insn),

            // DUP/MOV/INDEX
            0b000 if op1 == 0b10 || op1 == 0b11 => self.exec_sve_permute(insn, zd, zn, zm, esize),

            // FP predicated operations
            0b011 => self.exec_sve_fp_pred(insn, zd, zn, zm, pg, esize),

            // SVE2 integer add/subtract long/wide and abs-diff long: 0x45,
            // bit21==0, bits[15:13] selects the group — 000 = add/sub LONG (both
            // operands widened from half-width), 001 = ABS-DIFF long (|a-b|,
            // S=bit12 must be 1), 010 = add/sub WIDE (Zn already full width, Zm
            // widened). T (bit10) picks odd/even half-width source elements;
            // U (bit11) unsigned widening; S (bit12) subtract. size=00 reserved.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && matches!((insn >> 13) & 0x7, 0b000 | 0b001 | 0b010) =>
            {
                let group = (insn >> 13) & 0x7;
                let size = (insn >> 22) & 0x3;
                if size == 0 || (group == 0b001 && (insn >> 12) & 1 == 0) {
                    return Ok(CpuExit::Undefined(insn));
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let sub = (insn >> 12) & 1 == 1;
                let unsigned = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let elements = 16 / d_esize;
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                let mask = elem_mask((d_esize * 8) as u32);
                let widen = |x: u64| -> i128 {
                    if unsigned {
                        uext_elem(x, s_bits) as i128
                    } else {
                        sext_elem(x, s_bits)
                    }
                };
                for d in 0..elements {
                    let s_off = (2 * d + top as usize) * s_esize;
                    let vm = widen(read_elem(&b, s_off, s_esize));
                    let r: i128 = match group {
                        0b000 => {
                            let vn = widen(read_elem(&a, s_off, s_esize));
                            if sub { vn - vm } else { vn + vm }
                        }
                        0b001 => (widen(read_elem(&a, s_off, s_esize)) - vm).abs(),
                        _ => {
                            let vn = read_elem(&a, d * d_esize, d_esize) as i128;
                            if sub { vn - vm } else { vn + vm }
                        }
                    };
                    write_elem(&mut dst, d * d_esize, d_esize, (r as u64) & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 integer add/subtract interleaved long (SADDLBT/SSUBLBT/
            // SSUBLTB): 0x45, bit21==0, bits[15:12]==1000. Signed widening where
            // the two narrow source halves come from DIFFERENT positions:
            // bits[11:10]==00 SADDLBT (Zn bottom + Zm top), 10 SSUBLBT (Zn bottom
            // - Zm top), 11 SSUBLTB (Zn top - Zm bottom); 01 unallocated. size=00
            // reserved. Mirrors qemu's saddl/ssubl helper with sel={2,2,1}.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 12) & 0xF == 0b1000 =>
            {
                let size = (insn >> 22) & 0x3;
                let op = (insn >> 10) & 0x3;
                if size == 0 || op == 0b01 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let sub = op != 0b00;
                // (seln, selm): which narrow half of Zn/Zm (0=bottom, 1=top).
                let (seln, selm) = if op == 0b11 {
                    (1usize, 0usize)
                } else {
                    (0usize, 1usize)
                };
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let elements = 16 / d_esize;
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                let mask = elem_mask((d_esize * 8) as u32);
                for d in 0..elements {
                    let n_off = (2 * d + seln) * s_esize;
                    let m_off = (2 * d + selm) * s_esize;
                    let vn = sext_elem(read_elem(&a, n_off, s_esize), s_bits);
                    let vm = sext_elem(read_elem(&b, m_off, s_esize), s_bits);
                    let r = if sub { vn - vm } else { vn + vm };
                    write_elem(&mut dst, d * d_esize, d_esize, (r as u64) & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2.1 SCLAMP/UCLAMP (signed/unsigned clamp): 0x44, bit21==0,
            // bits[15:11]==11000. bit10=U. Zd = min(max(Zd, Zn), Zm) per element
            // (Zd is both the clamped value and the destination).
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b11000 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let unsigned = (insn >> 10) & 1 == 1;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let d = self.v[zd].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..(16 / esize) {
                    let off = e * esize;
                    let (dv, nv, mv) = (
                        read_elem(&d, off, esize),
                        read_elem(&n, off, esize),
                        read_elem(&m, off, esize),
                    );
                    let r = if unsigned {
                        uext_elem(dv, bits)
                            .max(uext_elem(nv, bits))
                            .min(uext_elem(mv, bits)) as u64
                    } else {
                        sext_elem(dv, bits)
                            .max(sext_elem(nv, bits))
                            .min(sext_elem(mv, bits)) as u64
                    };
                    write_elem(&mut dst, off, esize, r & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2.1 quadword permutes ZIPQ1/ZIPQ2/UZPQ1/UZPQ2/TBLQ: 0x44,
            // bit21==0, bits[15:13]==111. opc=bits[12:10] (000/001 ZIP, 010/011
            // UZP, 110 TBLQ). These permute within each 128-bit segment; at VL=128
            // (a single segment) they coincide with the non-quadword ZIP/UZP/TBL
            // over the whole register. (TBXQ lives in the 0x05 space, handled
            // separately.)
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 13) & 0x7 == 0b111 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let opc = (insn >> 10) & 0x7;
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let nelt = 16 / esize;
                let half = nelt / 2;
                let mut dst = [0u8; 16];
                match opc {
                    0b000 | 0b001 => {
                        // ZIPQ1 (low half) / ZIPQ2 (high half): interleave Zn,Zm.
                        let base = if opc == 0b001 { half } else { 0 };
                        for i in 0..half {
                            write_elem(
                                &mut dst,
                                (2 * i) * esize,
                                esize,
                                read_elem(&n, (base + i) * esize, esize),
                            );
                            write_elem(
                                &mut dst,
                                (2 * i + 1) * esize,
                                esize,
                                read_elem(&m, (base + i) * esize, esize),
                            );
                        }
                    }
                    0b010 | 0b011 => {
                        // UZPQ1 (even) / UZPQ2 (odd): deinterleave Zn:Zm.
                        let start = (opc & 1) as usize; // 0 even, 1 odd
                        for i in 0..nelt {
                            let src_idx = 2 * i + start;
                            let v = if src_idx < nelt {
                                read_elem(&n, src_idx * esize, esize)
                            } else {
                                read_elem(&m, (src_idx - nelt) * esize, esize)
                            };
                            write_elem(&mut dst, i * esize, esize, v);
                        }
                    }
                    0b110 => {
                        // TBLQ: per-segment table lookup of Zn indexed by Zm,
                        // zero-filling out-of-range indices.
                        for i in 0..nelt {
                            let idx = read_elem(&m, i * esize, esize) as usize;
                            let v = if idx < nelt {
                                read_elem(&n, idx * esize, esize)
                            } else {
                                0
                            };
                            write_elem(&mut dst, i * esize, esize, v);
                        }
                    }
                    _ => return Ok(CpuExit::Undefined(insn)),
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 shift right and accumulate: 0x45, bit21==0, bits[15:12]==1110.
            // SSRA/USRA (R=bit11=0) and SRSRA/URSRA (R=1); U=bit10 signedness.
            // Same-size (tsz=tszh:tszl 4 bits); shift = 2*esize - tsz:imm3.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 12) & 0xF == 0b1110 =>
            {
                let tsize = (((insn >> 22) & 0x3) << 2) | ((insn >> 19) & 0x3);
                if tsize == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let bits = 8 << (31 - tsize.leading_zeros());
                let esize = (bits / 8) as usize;
                let amount = 2 * bits - ((tsize << 3) | ((insn >> 16) & 0x7));
                let round = (insn >> 11) & 1 == 1;
                let unsigned = (insn >> 10) & 1 == 1;
                let mask = elem_mask(bits);
                let elements = 16 / esize;
                let acc = self.v[zd].to_le_bytes();
                let n = self.v[zn].to_le_bytes();
                let mut dst = acc;
                for e in 0..elements {
                    let off = e * esize;
                    let x = read_elem(&n, off, esize);
                    let v: i128 = if unsigned {
                        uext_elem(x, bits) as i128
                    } else {
                        sext_elem(x, bits)
                    };
                    let shifted = if round {
                        (v + (1i128 << (amount - 1))) >> amount
                    } else {
                        v >> amount
                    };
                    let cur = read_elem(&acc, off, esize) as i128;
                    write_elem(&mut dst, off, esize, (cur + shifted) as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 shift and insert: 0x45, bit21==0, bits[15:11]==11110. op=bit10
            // selects SLI (shift left, preserve low bits) vs SRI (shift right,
            // preserve high bits). Same-size tsz decode.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b11110 =>
            {
                let tsize = (((insn >> 22) & 0x3) << 2) | ((insn >> 19) & 0x3);
                if tsize == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let bits = 8 << (31 - tsize.leading_zeros());
                let esize = (bits / 8) as usize;
                let tszimm = (tsize << 3) | ((insn >> 16) & 0x7);
                let sli = (insn >> 10) & 1 == 1;
                let amount = if sli {
                    tszimm - bits
                } else {
                    2 * bits - tszimm
                };
                let mask = elem_mask(bits);
                let elements = 16 / esize;
                let dn = self.v[zd].to_le_bytes();
                let n = self.v[zn].to_le_bytes();
                let mut dst = dn;
                for e in 0..elements {
                    let off = e * esize;
                    let x = read_elem(&n, off, esize);
                    let d = read_elem(&dn, off, esize);
                    let r = if sli {
                        let keep = (1u64 << amount) - 1; // low `amount` dest bits preserved
                        ((x << amount) & mask) | (d & keep)
                    } else {
                        // SRI shift is 1..=esize; a full-width shift yields 0 (a
                        // u64 `>> bits` would otherwise wrap when bits==64).
                        let shifted = if amount >= bits {
                            0
                        } else {
                            (x >> amount) & mask
                        };
                        let keep = mask & !((1u64 << (bits - amount)).wrapping_sub(1)); // high bits
                        shifted | (d & keep)
                    };
                    write_elem(&mut dst, off, esize, r & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 abs-diff accumulate long: 0x45, bit21==0, bits[15:12]==1100.
            // SABALB/T (U=0) / UABALB/T (U=1): Zda += |widen(Zn) - widen(Zm)| over
            // the half-width even (T=0) / odd (T=1) source elements.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 12) & 0xF == 0b1100 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let mask = elem_mask((d_esize * 8) as u32);
                let unsigned = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let elements = 16 / d_esize;
                let acc = self.v[zd].to_le_bytes();
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = acc;
                let widen = |x: u64| -> i128 {
                    if unsigned {
                        uext_elem(x, s_bits) as i128
                    } else {
                        sext_elem(x, s_bits)
                    }
                };
                for d in 0..elements {
                    let off = (2 * d + top as usize) * s_esize;
                    let diff = (widen(read_elem(&a, off, s_esize))
                        - widen(read_elem(&b, off, s_esize)))
                    .abs();
                    let cur = read_elem(&acc, d * d_esize, d_esize) as i128;
                    write_elem(&mut dst, d * d_esize, d_esize, (cur + diff) as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 SABA/UABA (abs-diff accumulate, same width): 0x45, bit21==0,
            // bits[15:11]==11111, bit10 selects UABA(1)/SABA(0). The destination
            // accumulates the per-element absolute difference at full width.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b11111 =>
            {
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let unsigned = (insn >> 10) & 1 == 1;
                let elements = 16 / esize;
                let acc = self.v[zd].to_le_bytes();
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = acc;
                for e in 0..elements {
                    let off = e * esize;
                    let (av, bv) = if unsigned {
                        (
                            uext_elem(read_elem(&a, off, esize), bits) as i128,
                            uext_elem(read_elem(&b, off, esize), bits) as i128,
                        )
                    } else {
                        (
                            sext_elem(read_elem(&a, off, esize), bits),
                            sext_elem(read_elem(&b, off, esize), bits),
                        )
                    };
                    let diff = (av - bv).abs() as u64 & mask;
                    let cur = read_elem(&acc, off, esize);
                    write_elem(&mut dst, off, esize, cur.wrapping_add(diff) & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 bit permute (BEXT/BDEP/BGRP): 0x45, bit21==0, bits[15:12]==1011.
            // opc=bits[11:10]: 00=BEXT (gather Zn bits at Zm's set bits to the
            // bottom, like PEXT), 01=BDEP (scatter Zn's low bits to Zm's set bits,
            // like PDEP), 10=BGRP (Zm-selected bits to the bottom, rest on top).
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 12) & 0xF == 0b1011 =>
            {
                let opc = (insn >> 10) & 0x3;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let elements = 16 / esize;
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..elements {
                    let off = e * esize;
                    let zn_e = read_elem(&a, off, esize);
                    let zm_e = read_elem(&b, off, esize);
                    let r = match opc {
                        0b00 => {
                            let mut r = 0u64;
                            let mut k = 0;
                            for i in 0..bits {
                                if (zm_e >> i) & 1 == 1 {
                                    r |= ((zn_e >> i) & 1) << k;
                                    k += 1;
                                }
                            }
                            r
                        }
                        0b01 => {
                            let mut r = 0u64;
                            let mut k = 0;
                            for i in 0..bits {
                                if (zm_e >> i) & 1 == 1 {
                                    r |= ((zn_e >> k) & 1) << i;
                                    k += 1;
                                }
                            }
                            r
                        }
                        0b10 => {
                            let (mut low, mut lk, mut high, mut hk) = (0u64, 0u32, 0u64, 0u32);
                            for i in 0..bits {
                                let bit = (zn_e >> i) & 1;
                                if (zm_e >> i) & 1 == 1 {
                                    low |= bit << lk;
                                    lk += 1;
                                } else {
                                    high |= bit << hk;
                                    hk += 1;
                                }
                            }
                            // When every mask bit is set, `lk` reaches `bits`
                            // (up to 64) and `high` stays 0; guard the shift so
                            // an all-ones 64-bit mask element cannot overflow.
                            low | high.checked_shl(lk).unwrap_or(0)
                        }
                        _ => return Ok(CpuExit::Undefined(insn)),
                    };
                    write_elem(&mut dst, off, esize, r & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 shift left long: 010001010 tszh 0 tszl imm3 1010 U T Zn Zd.
            // Widens the half-width source elements (signed U=0 / unsigned U=1,
            // even T=0 / odd T=1) and shifts them left. src esize from highest
            // set bit of tsz, dst 2x; shift = tsz:imm3 - src_bits.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 23) & 1 == 0
                    && (insn >> 21) & 1 == 0
                    && (insn >> 12) & 0xF == 0b1010 =>
            {
                let tsize = (((insn >> 22) & 1) << 2) | ((insn >> 19) & 0x3);
                if tsize == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let src_esize = 1usize << (31 - tsize.leading_zeros());
                let dst_esize = src_esize * 2;
                let src_bits = (src_esize * 8) as u32;
                let dst_bits = (dst_esize * 8) as u32;
                let dmask = elem_mask(dst_bits);
                let amount = ((tsize << 3) | ((insn >> 16) & 0x7)) - src_bits;
                let unsigned = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let n_dst = 16 / dst_esize;
                let a = self.v[zn].to_le_bytes();
                let mut dst = [0u8; 16];
                for d in 0..n_dst {
                    let x = read_elem(&a, (2 * d + top as usize) * src_esize, src_esize);
                    let widened: u128 = if unsigned {
                        uext_elem(x, src_bits)
                    } else {
                        sext_elem(x, src_bits) as u128
                    };
                    write_elem(
                        &mut dst,
                        d * dst_esize,
                        dst_esize,
                        (widened << amount) as u64 & dmask,
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 integer multiply long: 0x45, bit21==0, bits[15:13]==011.
            // (op=bit12, U=bit11): (1,0)=SMULLB/T, (1,1)=UMULLB/T, (0,0)=
            // SQDMULLB/T (saturating doubling), (0,1)=PMULLB/T (polynomial).
            // Source elements are half-width; T picks odd/even. size=00 reserved;
            // PMULL is only defined for the H form (size=01) in base SVE2.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 13) & 0x7 == 0b011 =>
            {
                let size = (insn >> 22) & 0x3;
                let op = (insn >> 12) & 1;
                let unsigned = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let is_pmull = op == 0 && unsigned;
                // SMULL/UMULL/SQDMULL need a half-width source so size==0 is
                // reserved; PMULL is valid for .q (size==0, 64->128), .h
                // (size==01, 8->16) and .d (size==11, 32->64) but not size==10.
                if (size == 0 && !is_pmull) || (is_pmull && size == 2) {
                    return Ok(CpuExit::Undefined(insn));
                }
                if is_pmull && size == 0 {
                    // PMULLB/T .q <- .d: 64x64 -> 128 carryless. T selects the
                    // odd (high) 64-bit lane of the segment, B the even (low).
                    let lane = top as usize;
                    let xn = (self.v[zn] >> (lane * 64)) as u64;
                    let xm = (self.v[zm] >> (lane * 64)) as u64;
                    self.v[zd] = poly_mul_64(xn, xm);
                    return Ok(CpuExit::Continue);
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let d_bits = (d_esize * 8) as u32;
                let elements = 16 / d_esize;
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                let mask = elem_mask(d_bits);
                for d in 0..elements {
                    let off = (2 * d + top as usize) * s_esize;
                    let xn = read_elem(&a, off, s_esize);
                    let xm = read_elem(&b, off, s_esize);
                    let r: u64 = match (op, unsigned) {
                        (1, false) => (sext_elem(xn, s_bits) * sext_elem(xm, s_bits)) as u64 & mask,
                        (1, true) => (uext_elem(xn, s_bits) * uext_elem(xm, s_bits)) as u64 & mask,
                        (0, false) => {
                            let prod = 2i128 * sext_elem(xn, s_bits) * sext_elem(xm, s_bits);
                            let hi = (1i128 << (d_bits - 1)) - 1;
                            let lo = -(1i128 << (d_bits - 1));
                            prod.clamp(lo, hi) as u64 & mask
                        }
                        _ => poly_mul_wide(xn, xm, s_bits) & mask,
                    };
                    write_elem(&mut dst, d * d_esize, d_esize, r);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 complex integer add (CADD/SQCADD): 0x45, bits[21:17]==00000,
            // bits[15:11]==11011. Treats element pairs as (real, imag); adds Zm
            // rotated by 90 (rot=0) or 270 (rot=1) degrees into Zdn. op=bit16
            // selects the saturating form (SQCADD).
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 17) & 0x1F == 0
                    && (insn >> 11) & 0x1F == 0b11011 =>
            {
                let size = (insn >> 22) & 0x3;
                let esize = 1usize << size;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let sat = (insn >> 16) & 1 == 1;
                let rot = (insn >> 10) & 1;
                let dn = self.v[zd].to_le_bytes(); // Zdn
                let m = self.v[zn].to_le_bytes(); // Zm (bits[9:5])
                let mut dst = dn;
                let pairs = (16 / esize) / 2;
                let hi = (1i128 << (bits - 1)) - 1;
                let lo = -(1i128 << (bits - 1));
                let clamp = |v: i128| if sat { v.clamp(lo, hi) } else { v };
                for p in 0..pairs {
                    let (re, im) = (2 * p * esize, (2 * p + 1) * esize);
                    let dn_re = sext_elem(read_elem(&dn, re, esize), bits);
                    let dn_im = sext_elem(read_elem(&dn, im, esize), bits);
                    let m_re = sext_elem(read_elem(&m, re, esize), bits);
                    let m_im = sext_elem(read_elem(&m, im, esize), bits);
                    let (r_re, r_im) = if rot == 0 {
                        (dn_re - m_im, dn_im + m_re) // rotate Zm by 90 degrees
                    } else {
                        (dn_re + m_im, dn_im - m_re) // rotate Zm by 270 degrees
                    };
                    write_elem(&mut dst, re, esize, clamp(r_re) as u64 & mask);
                    write_elem(&mut dst, im, esize, clamp(r_im) as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 shift right narrow: 010001010 tszh 1 tszl imm3 00 op U R T.
            // (op,U): (0,1)=SHRN/RSHRN, (0,0)=SQSHRUN, (1,0)=SQSHRN, (1,1)=UQSHRN
            // (R=bit11 adds rounding). dst esize from highest set bit of tsz, src
            // 2x; shift amount = 2*dst_bits - (tsz:imm3).
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 23) & 1 == 0
                    && (insn >> 21) & 1 == 1
                    && (insn >> 14) & 0x3 == 0 =>
            {
                let tsize = (((insn >> 22) & 1) << 2) | ((insn >> 19) & 0x3);
                if tsize == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let dst_esize = 1usize << (31 - tsize.leading_zeros());
                let src_esize = dst_esize * 2;
                let dst_bits = (dst_esize * 8) as u32;
                let src_bits = (src_esize * 8) as u32;
                let dmask = elem_mask(dst_bits);
                let tszimm = (tsize << 3) | ((insn >> 16) & 0x7);
                let amount = src_bits - tszimm; // 1..=dst_bits
                let op = (insn >> 13) & 1;
                let u = (insn >> 12) & 1;
                let round = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let n_src = 16 / src_esize;
                let a = self.v[zn].to_le_bytes();
                let mut dst = if top {
                    self.v[zd].to_le_bytes()
                } else {
                    [0u8; 16]
                };
                for d in 0..n_src {
                    let x = read_elem(&a, d * src_esize, src_esize);
                    let narrow: u64 = match (op, u) {
                        (0, 1) => {
                            let v = uext_elem(x, src_bits);
                            let r = if round {
                                (v + (1u128 << (amount - 1))) >> amount
                            } else {
                                v >> amount
                            };
                            r as u64 & dmask
                        }
                        (0, 0) => {
                            let v = sext_elem(x, src_bits);
                            let r = if round {
                                (v + (1i128 << (amount - 1))) >> amount
                            } else {
                                v >> amount
                            };
                            r.clamp(0, dmask as i128) as u64
                        }
                        (1, 0) => {
                            let v = sext_elem(x, src_bits);
                            let r = if round {
                                (v + (1i128 << (amount - 1))) >> amount
                            } else {
                                v >> amount
                            };
                            let hi = (1i128 << (dst_bits - 1)) - 1;
                            let lo = -(1i128 << (dst_bits - 1));
                            r.clamp(lo, hi) as u64 & dmask
                        }
                        _ => {
                            let v = uext_elem(x, src_bits);
                            let r = if round {
                                (v + (1u128 << (amount - 1))) >> amount
                            } else {
                                v >> amount
                            };
                            r.min(dmask as u128) as u64
                        }
                    };
                    write_elem(
                        &mut dst,
                        (2 * d + top as usize) * dst_esize,
                        dst_esize,
                        narrow,
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2.1 multi-vector saturating extract narrow SQCVTN/UQCVTN/
            // SQCVTUN (.s pair -> .h): 0x45, bits[23:22]==00, bit21==1,
            // bits[20:16]==10001, bits[15:13]==010. op=bits[12:10] (000 SQCVTN
            // signed->signed, 010 UQCVTN unsigned->unsigned, 100 SQCVTUN
            // signed->unsigned). Reads the register pair {Zn, Zn+1} and
            // interleaves: Zd.h[2i]=sat(Zn.s[i]), Zd.h[2i+1]=sat(Zn+1.s[i]).
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 22) & 0x3 == 0b00
                    && (insn >> 21) & 1 == 1
                    && (insn >> 16) & 0x1F == 0b10001
                    && (insn >> 13) & 0x7 == 0b010 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let (signed_in, signed_out) = match (insn >> 10) & 0x7 {
                    0b000 => (true, true),   // SQCVTN
                    0b010 => (false, false), // UQCVTN
                    0b100 => (true, false),  // SQCVTUN
                    _ => return Ok(CpuExit::Undefined(insn)),
                };
                let zn = ((insn >> 5) & 0x1F) as usize;
                let s0 = self.v[zn].to_le_bytes();
                let s1 = self.v[(zn + 1) % 32].to_le_bytes();
                let mut dst = [0u8; 16];
                let narrow = |bytes: &[u8; 16], i: usize| -> u64 {
                    let v = read_elem(bytes, i * 4, 4);
                    let w = if signed_in {
                        sext_elem(v, 32)
                    } else {
                        uext_elem(v, 32) as i128
                    };
                    if signed_out {
                        sat_signed(w, 16)
                    } else {
                        sat_unsigned(w, 16)
                    }
                };
                for i in 0..4 {
                    write_elem(&mut dst, (2 * i) * 2, 2, narrow(&s0, i));
                    write_elem(&mut dst, (2 * i + 1) * 2, 2, narrow(&s1, i));
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 saturating extract narrow: 010001010 tszh 1 tszl 000010 vv T.
            // (bit12,bit11): 00=SQXTN (signed->signed sat), 01=UQXTN (unsigned->
            // unsigned sat), 10=SQXTUN (signed->unsigned sat). The dest element
            // size comes from the highest set bit of tsz=tszh:tszl, source 2x.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 23) & 1 == 0
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x3F == 0b000010 =>
            {
                let tsz = (((insn >> 22) & 1) << 2) | ((insn >> 19) & 0x3);
                // Only the one-hot tsz values 0b001/0b010/0b100 are allocated;
                // 0b000 and the non-one-hot 0b011/0b101/0b110/0b111 are reserved.
                if !tsz.is_power_of_two() {
                    return Ok(CpuExit::Undefined(insn));
                }
                // Only variants 0b00 (SQXTN), 0b01 (UQXTN), 0b10 (SQXTUN) are
                // defined; 0b11 is reserved and must trap.
                let variant = (insn >> 11) & 0x3;
                if variant == 0b11 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let hsb = 31 - tsz.leading_zeros();
                let dst_esize = 1usize << hsb;
                let src_esize = dst_esize * 2;
                let dst_bits = (dst_esize * 8) as u32;
                let src_bits = (src_esize * 8) as u32;
                let dmask = elem_mask(dst_bits);
                let top = (insn >> 10) & 1 == 1;
                let n_src = 16 / src_esize;
                let a = self.v[zn].to_le_bytes();
                let mut dst = if top {
                    self.v[zd].to_le_bytes()
                } else {
                    [0u8; 16]
                };
                for d in 0..n_src {
                    let x = read_elem(&a, d * src_esize, src_esize);
                    let narrow: u64 = match variant {
                        0b00 => {
                            let v = sext_elem(x, src_bits);
                            let hi = (1i128 << (dst_bits - 1)) - 1;
                            let lo = -(1i128 << (dst_bits - 1));
                            v.clamp(lo, hi) as u64 & dmask
                        }
                        0b01 => uext_elem(x, src_bits).min(dmask as u128) as u64,
                        _ => sext_elem(x, src_bits).clamp(0, dmask as i128) as u64,
                    };
                    write_elem(
                        &mut dst,
                        (2 * d + top as usize) * dst_esize,
                        dst_esize,
                        narrow,
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 add/subtract high narrow: 0x45, bit21==1, bits[15:13]==011.
            // ADDHN/SUBHN (S=bit12) with optional rounding (R=bit11). The result
            // is the high half of the (full-width) sum/difference, written to the
            // even (T=0, bottom, other half zeroed) or odd (T=1, top, other half
            // preserved) narrow elements. size=00 reserved.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x7 == 0b011 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let src_esize = 1usize << size;
                let dst_esize = src_esize / 2;
                let src_mask = elem_mask((src_esize * 8) as u32);
                let dst_bits = (dst_esize * 8) as u32;
                let dst_mask = elem_mask(dst_bits);
                let sub = (insn >> 12) & 1 == 1;
                let round = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let n_src = 16 / src_esize;
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = if top {
                    self.v[zd].to_le_bytes()
                } else {
                    [0u8; 16]
                };
                for d in 0..n_src {
                    let xn = read_elem(&a, d * src_esize, src_esize);
                    let xm = read_elem(&b, d * src_esize, src_esize);
                    let sum = if sub {
                        xn.wrapping_sub(xm)
                    } else {
                        xn.wrapping_add(xm)
                    };
                    let rounded = if round {
                        sum.wrapping_add(1u64 << (dst_bits - 1))
                    } else {
                        sum
                    } & src_mask;
                    let narrow = (rounded >> dst_bits) & dst_mask;
                    write_elem(
                        &mut dst,
                        (2 * d + top as usize) * dst_esize,
                        dst_esize,
                        narrow,
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 integer multiply-add long: 0x44, bit21==0, bits[15:13]==010.
            // S?MLALB/T (S=0) and S?MLSLB/T (S=1); U widening sign; T odd/even.
            // Zda (the destination, bits[4:0]) accumulates widen(Zn)*widen(Zm).
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 13) & 0x7 == 0b010 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let mask = elem_mask((d_esize * 8) as u32);
                let sub = (insn >> 12) & 1 == 1;
                let unsigned = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let elements = 16 / d_esize;
                let acc = self.v[zd].to_le_bytes();
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = acc;
                for d in 0..elements {
                    let off = (2 * d + top as usize) * s_esize;
                    let xn = read_elem(&a, off, s_esize);
                    let xm = read_elem(&b, off, s_esize);
                    let prod: i128 = if unsigned {
                        (uext_elem(xn, s_bits) * uext_elem(xm, s_bits)) as i128
                    } else {
                        sext_elem(xn, s_bits) * sext_elem(xm, s_bits)
                    };
                    let cur = read_elem(&acc, d * d_esize, d_esize) as i128;
                    let r = if sub { cur - prod } else { cur + prod };
                    write_elem(&mut dst, d * d_esize, d_esize, (r as u64) & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 saturating doubling multiply-add long: 0x44, bit21==0,
            // bits[15:12]==0110. SQDMLALB/T (S=0) / SQDMLSLB/T (S=1). The doubled
            // signed product is saturated, then the accumulate is saturated.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 12) & 0xF == 0b0110 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let d_bits = (d_esize * 8) as u32;
                let mask = elem_mask(d_bits);
                let sub = (insn >> 11) & 1 == 1;
                let top = (insn >> 10) & 1 == 1;
                let elements = 16 / d_esize;
                let hi = (1i128 << (d_bits - 1)) - 1;
                let lo = -(1i128 << (d_bits - 1));
                let acc = self.v[zd].to_le_bytes();
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = acc;
                for d in 0..elements {
                    let off = (2 * d + top as usize) * s_esize;
                    let prod = 2i128
                        * sext_elem(read_elem(&a, off, s_esize), s_bits)
                        * sext_elem(read_elem(&b, off, s_esize), s_bits);
                    let sat = prod.clamp(lo, hi);
                    let cur = sext_elem(read_elem(&acc, d * d_esize, d_esize), d_bits);
                    let r = if sub { cur - sat } else { cur + sat };
                    write_elem(
                        &mut dst,
                        d * d_esize,
                        d_esize,
                        (r.clamp(lo, hi) as u64) & mask,
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 saturating doubling multiply-add long (interleaved):
            // SQDMLALBT/SQDMLSLBT. 0x44, bit21==0, bits[15:11]==00001, bit10=S
            // (0=add, 1=sub). The two narrow sources come from DIFFERENT halves
            // (Zn bottom * Zm top, sel=2), unlike the B/T forms above; the doubled
            // product saturates, then the accumulate saturates. size=00 reserved.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b00001 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let d_bits = (d_esize * 8) as u32;
                let mask = elem_mask(d_bits);
                let sub = (insn >> 10) & 1 == 1;
                let elements = 16 / d_esize;
                let hi = (1i128 << (d_bits - 1)) - 1;
                let lo = -(1i128 << (d_bits - 1));
                let acc = self.v[zd].to_le_bytes();
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = acc;
                for d in 0..elements {
                    let n_off = (2 * d) * s_esize; // Zn bottom
                    let m_off = (2 * d + 1) * s_esize; // Zm top
                    let prod = 2i128
                        * sext_elem(read_elem(&a, n_off, s_esize), s_bits)
                        * sext_elem(read_elem(&b, m_off, s_esize), s_bits);
                    let sat = prod.clamp(lo, hi);
                    let cur = sext_elem(read_elem(&acc, d * d_esize, d_esize), d_bits);
                    let r = if sub { cur - sat } else { cur + sat };
                    write_elem(
                        &mut dst,
                        d * d_esize,
                        d_esize,
                        (r.clamp(lo, hi) as u64) & mask,
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 SADALP/UADALP (add long pairwise, accumulate): 0x44,
            // bits[21:17]==00010, bits[15:13]==101. U=bit16. Each (active)
            // destination element gains the widened sum of a pair of half-width
            // source elements; inactive lanes keep the prior accumulator.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 17) & 0x1F == 0b00010
                    && (insn >> 13) & 0x7 == 0b101 =>
            {
                let size = (insn >> 22) & 0x3;
                if size == 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let d_esize = 1usize << size;
                let s_esize = d_esize / 2;
                let s_bits = (s_esize * 8) as u32;
                let mask = elem_mask((d_esize * 8) as u32);
                let unsigned = (insn >> 16) & 1 == 1;
                let pred = self.sve_p[pg];
                let elements = 16 / d_esize;
                let acc = self.v[zd].to_le_bytes();
                let n = self.v[zn].to_le_bytes();
                let mut dst = acc;
                let widen = |x: u64| -> i128 {
                    if unsigned {
                        uext_elem(x, s_bits) as i128
                    } else {
                        sext_elem(x, s_bits)
                    }
                };
                for d in 0..elements {
                    if (pred >> (d * d_esize)) & 1 == 0 {
                        continue;
                    }
                    let pair = widen(read_elem(&n, 2 * d * s_esize, s_esize))
                        + widen(read_elem(&n, (2 * d + 1) * s_esize, s_esize));
                    let cur = read_elem(&acc, d * d_esize, d_esize) as i128;
                    write_elem(&mut dst, d * d_esize, d_esize, (cur + pair) as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 predicated integer pairwise: 0x44, bits[21:19]==010,
            // bits[15:13]==101. opc=bits[18:17] (00=ADDP, 10=MAXP, 11=MINP),
            // U=bit16. The pairwise results of Zdn and Zm are INTERLEAVED (even
            // output = Zdn pair, odd = Zm pair); merged into Zdn under Pg.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 19) & 0x7 == 0b010
                    && (insn >> 13) & 0x7 == 0b101 =>
            {
                let opc = (insn >> 17) & 0x3;
                let unsigned = (insn >> 16) & 1 == 1;
                // Only (opc,U) in {(00,1)=ADDP, (10,0)=SMAXP, (10,1)=UMAXP,
                // (11,0)=SMINP, (11,1)=UMINP} are allocated; (00,0), (01,0) and
                // (01,1) are reserved and must trap rather than execute.
                if !matches!((opc, unsigned), (0b00, true) | (0b10, _) | (0b11, _)) {
                    return Ok(CpuExit::Undefined(insn));
                }
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let elements = 16 / esize;
                let h = elements / 2;
                let pred = self.sve_p[pg];
                let dn = self.v[zd].to_le_bytes(); // Zdn
                let m = self.v[zn].to_le_bytes(); // Zm
                let op = |a: u64, b: u64| -> u64 {
                    match opc {
                        0b00 => a.wrapping_add(b) & mask,
                        0b10 if unsigned => a.max(b),
                        0b10 => (sext_elem(a, bits).max(sext_elem(b, bits)) as u64) & mask,
                        _ if unsigned => a.min(b),
                        _ => (sext_elem(a, bits).min(sext_elem(b, bits)) as u64) & mask,
                    }
                };
                let mut res = [0u8; 16];
                for p in 0..h {
                    let dnv = op(
                        read_elem(&dn, 2 * p * esize, esize),
                        read_elem(&dn, (2 * p + 1) * esize, esize),
                    );
                    let mv = op(
                        read_elem(&m, 2 * p * esize, esize),
                        read_elem(&m, (2 * p + 1) * esize, esize),
                    );
                    write_elem(&mut res, 2 * p * esize, esize, dnv);
                    write_elem(&mut res, (2 * p + 1) * esize, esize, mv);
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
                Ok(CpuExit::Continue)
            }

            // SVE2 SQRDMLAH/SQRDMLSH (saturating rounding doubling multiply-add):
            // 0x44, bit21==0, bits[15:11]==01110. S=bit10 selects subtract. The
            // rounded doubling-high is unsaturated; only the accumulate saturates.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b01110 =>
            {
                let sub = (insn >> 10) & 1 == 1;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let elements = 16 / esize;
                let acc = self.v[zd].to_le_bytes();
                let a = self.v[zn].to_le_bytes();
                let b = self.v[zm].to_le_bytes();
                let mut dst = acc;
                let hi = (1i128 << (bits - 1)) - 1;
                let lo = -(1i128 << (bits - 1));
                for e in 0..elements {
                    let off = e * esize;
                    let prod = sext_elem(read_elem(&a, off, esize), bits)
                        * sext_elem(read_elem(&b, off, esize), bits);
                    // The Zm factor is negated BEFORE the rounding bias is added
                    // (matching qemu), so the rounding of SQRDMLSH is applied to
                    // -prod rather than negating the rounded SQRDMLAH result —
                    // the two differ at exact rounding ties.
                    let p = if sub { -prod } else { prod };
                    let sdrh = (p + (1i128 << (bits - 2))) >> (bits - 1);
                    let cur = sext_elem(read_elem(&acc, off, esize), bits);
                    write_elem(
                        &mut dst,
                        off,
                        esize,
                        (cur + sdrh).clamp(lo, hi) as u64 & mask,
                    );
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 CDOT (complex integer dot product): 0x44, bit21==0,
            // bits[15:12]==0001. rot=bits[11:10]. Each destination element
            // accumulates two complex products of half-width signed elements
            // (.s from int8, .d from int16): real += r*a, then += i*b*(+/-1).
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 12) & 0xF == 0b0001 =>
            {
                let size = (insn >> 22) & 0x3;
                if size < 2 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let esize = 1usize << size; // 4 (.s) or 8 (.d)
                let nb = esize / 4; // narrow element bytes (1 or 2)
                let nbits = (nb * 8) as u32;
                let dbits = (esize * 8) as u32;
                let mask = elem_mask(dbits);
                let rot = (insn >> 10) & 0x3;
                let sel_a = (rot & 1) as usize;
                let sel_b = sel_a ^ 1;
                let sub_i: i128 = if rot == 0 || rot == 3 { -1 } else { 1 };
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let a = self.v[zd].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..(16 / esize) {
                    let mut acc = sext_elem(read_elem(&a, e * esize, esize), dbits);
                    for i in 0..2 {
                        let base = e * esize + i * 2 * nb;
                        let e1r = sext_elem(read_elem(&n, base, nb), nbits);
                        let e1i = sext_elem(read_elem(&n, base + nb, nb), nbits);
                        let e2a = sext_elem(read_elem(&m, base + nb * sel_a, nb), nbits);
                        let e2b = sext_elem(read_elem(&m, base + nb * sel_b, nb), nbits);
                        acc += e1r * e2a + e1i * e2b * sub_i;
                    }
                    write_elem(&mut dst, e * esize, esize, acc as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 CDOT by indexed element: 0x44, bit21==1, bits[15:12]==0100.
            // Like CDOT but the Zm complex element is taken from a fixed index
            // within the 128-bit segment and shared across the segment. .s:
            // index=bits[20:19], Zm=bits[18:16]; .d: index=bit20, Zm=bits[19:16].
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 12) & 0xF == 0b0100 =>
            {
                let size = (insn >> 22) & 0x3;
                if size < 2 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let esize = 1usize << size;
                let nb = esize / 4;
                let nbits = (nb * 8) as u32;
                let dbits = (esize * 8) as u32;
                let mask = elem_mask(dbits);
                let rot = (insn >> 10) & 0x3;
                let sel_a = (rot & 1) as usize;
                let sel_b = sel_a ^ 1;
                let sub_i: i128 = if rot == 0 || rot == 3 { -1 } else { 1 };
                let (index, zmr) = if size == 2 {
                    (((insn >> 19) & 0x3) as usize, ((insn >> 16) & 0x7) as usize)
                } else {
                    (((insn >> 20) & 1) as usize, ((insn >> 16) & 0xF) as usize)
                };
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zmr].to_le_bytes();
                let a = self.v[zd].to_le_bytes();
                let m_base = index * esize;
                let mut dst = [0u8; 16];
                for e in 0..(16 / esize) {
                    let mut acc = sext_elem(read_elem(&a, e * esize, esize), dbits);
                    let nbase = e * esize;
                    for i in 0..2 {
                        let e1r = sext_elem(read_elem(&n, nbase + i * 2 * nb, nb), nbits);
                        let e1i = sext_elem(read_elem(&n, nbase + i * 2 * nb + nb, nb), nbits);
                        let e2a =
                            sext_elem(read_elem(&m, m_base + i * 2 * nb + nb * sel_a, nb), nbits);
                        let e2b =
                            sext_elem(read_elem(&m, m_base + i * 2 * nb + nb * sel_b, nb), nbits);
                        acc += e1r * e2a + e1i * e2b * sub_i;
                    }
                    write_elem(&mut dst, e * esize, esize, acc as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE integer dot product (vector): 0x44, bit21==0, with bit23==1
            // and bits[15:11]==00000 (SDOT/UDOT, u=bit10) or bits[23:22]==10 and
            // bits[15:10]==011110 (USDOT).
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (((insn >> 23) & 1 == 1 && (insn >> 11) & 0x1F == 0b00000)
                        || ((insn >> 22) & 0x3 == 0b10 && (insn >> 10) & 0x3F == 0b011110)) =>
            {
                self.exec_sve_dot(insn)
            }

            // SVE integer dot product (indexed): 0x44, bit21==1,
            // bits[15:10] in {SDOT, UDOT, USDOT, SUDOT}.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 1
                    && matches!(
                        (insn >> 10) & 0x3F,
                        0b000000 | 0b000001 | 0b000110 | 0b000111
                    ) =>
            {
                self.exec_sve_dot(insn)
            }

            // SVE2.1 two-way integer dot product SDOT/UDOT (.s <- .h): 0x44,
            // bit21==0, bits[15:11]==11001 (bit10=U). Each .s lane accumulates two
            // 16-bit products. bits[23:22]==00 is the vector form; ==10 is the
            // indexed form (index=bits[20:19], Zm=bits[18:16]) broadcasting the
            // index-th .h pair within the 128-bit segment.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b11001 =>
            {
                if !has_sve2p1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let signed = (insn >> 10) & 1 == 0;
                let indexed = (insn >> 22) & 0x3 == 0b10;
                let zd = (insn & 0x1F) as usize;
                let zn = ((insn >> 5) & 0x1F) as usize;
                let (zm, index) = if indexed {
                    (((insn >> 16) & 0x7) as usize, ((insn >> 19) & 0x3) as usize)
                } else {
                    (((insn >> 16) & 0x1F) as usize, 0)
                };
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let a = self.v[zd].to_le_bytes();
                let ext = |b: &[u8; 16], off: usize| -> i64 {
                    if signed {
                        sext_elem(read_elem(b, off, 2), 16) as i64
                    } else {
                        uext_elem(read_elem(b, off, 2), 16) as i64
                    }
                };
                let mut dst = [0u8; 16];
                for i in 0..4 {
                    let mut acc = read_elem(&a, i * 4, 4) as u32 as i64;
                    for k in 0..2 {
                        let n_off = i * 4 + k * 2;
                        let m_off = if indexed { (index * 2 + k) * 2 } else { n_off };
                        acc = acc.wrapping_add(ext(&n, n_off) * ext(&m, m_off));
                    }
                    write_elem(&mut dst, i * 4, 4, acc as u32 as u64);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 predicated integer ALU (saturating/rounding shifts, halving
            // add/sub, saturating add/sub, SQABS/SQNEG): 0x44, bit21==0,
            // bits[15:13]==100, or bits[15:13]==101 with bits[21:19]==001. The
            // pairwise group (bits[15:13]==101, bits[21:19]==010) is handled by
            // its own arm and excluded here.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && ((insn >> 13) & 0x7 == 0b100
                        || ((insn >> 13) & 0x7 == 0b101 && (insn >> 19) & 0x7 == 0b001)
                        || ((insn >> 13) & 0x7 == 0b101
                            && (insn >> 19) & 0x7 == 0b000
                            && matches!((insn >> 16) & 0x7, 0b000 | 0b001))) =>
            {
                self.exec_sve2_pred_alu(insn)
            }

            // SVE2 complex integer multiply-add (CMLA/SQRDCMLAH): 0x44, bit21==0,
            // bits[15:13]==001. op=bit12 picks the saturating-rounding-doubling
            // SQRDCMLAH; rot=bits[11:10] is the 0/90/180/270 rotation. Each
            // complex pair accumulates one selected-component product.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 0
                    && (insn >> 13) & 0x7 == 0b001 =>
            {
                let size = (insn >> 22) & 0x3;
                let esize = 1usize << size;
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let sat = (insn >> 12) & 1 == 1;
                let rot = (insn >> 10) & 0x3;
                let acc = self.v[zd].to_le_bytes();
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let mut dst = acc;
                let hi = (1i128 << (bits - 1)) - 1;
                let lo = -(1i128 << (bits - 1));
                let pairs = (16 / esize) / 2;
                for p in 0..pairs {
                    let (re, im) = (2 * p * esize, (2 * p + 1) * esize);
                    let n_re = sext_elem(read_elem(&n, re, esize), bits);
                    let n_im = sext_elem(read_elem(&n, im, esize), bits);
                    let m_re = sext_elem(read_elem(&m, re, esize), bits);
                    let m_im = sext_elem(read_elem(&m, im, esize), bits);
                    let acc_re = sext_elem(read_elem(&acc, re, esize), bits);
                    let acc_im = sext_elem(read_elem(&acc, im, esize), bits);
                    let zn_sel = if rot == 0 || rot == 2 { n_re } else { n_im };
                    // The signed Zm factor for the real/imag accumulation.
                    let (mfr, mfi): (i128, i128) = match rot {
                        0 => (m_re, m_im),
                        1 => (-m_im, m_re),
                        2 => (-m_re, -m_im),
                        _ => (m_im, -m_re),
                    };
                    let (r_re, r_im) = if sat {
                        // SignedDoublingRoundingHigh: (2*prod + 2^(bits-1)) >> bits,
                        // rewritten as (prod + 2^(bits-2)) >> (bits-1) to avoid the
                        // doubled product overflowing i128 at the 64-bit size. As in
                        // NEON SQRDMLAH the rounded high part is NOT saturated; only
                        // the final accumulate is.
                        let sdrh = |prod: i128| (prod + (1i128 << (bits - 2))) >> (bits - 1);
                        (
                            (acc_re + sdrh(zn_sel * mfr)).clamp(lo, hi),
                            (acc_im + sdrh(zn_sel * mfi)).clamp(lo, hi),
                        )
                    } else {
                        (acc_re + zn_sel * mfr, acc_im + zn_sel * mfi)
                    };
                    write_elem(&mut dst, re, esize, r_re as u64 & mask);
                    write_elem(&mut dst, im, esize, r_im as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 integer multiply / multiply-add (indexed): 0x44, bit21==1.
            // The second factor is a single element Zm[index] broadcast to every
            // lane; the (index, Zm) packing depends on the element size.
            // bits[15:10] selects MUL/SQDMULH/SQRDMULH (1111xx), MLA/MLS
            // (00001x) or SQRDMLAH/SQRDMLSH (00010x). Widening and complex
            // indexed forms have their own dispatch arms below.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 1
                    && matches!(
                        (insn >> 10) & 0x3F,
                        0b111110 | 0b111100 | 0b111101 | 0b000010 | 0b000011 | 0b000100 | 0b000101
                    ) =>
            {
                self.exec_sve2_mul_indexed(insn, zn, zd)
            }

            // SVE2 widening multiply-add long by indexed element: 0x44, bit21==1.
            // bits[15:12] selects S/U MULL/MLAL/MLSL and SQDMULL/SQDMLAL/SQDMLSL;
            // the narrow source is half the destination width and bit10 (T) picks
            // the odd/even narrow lane. Distinct op fields from the same-width
            // indexed group above (1111xx / 0000xx), so no overlap.
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 1
                    && matches!(
                        (insn >> 12) & 0xF,
                        0b1000
                            | 0b1001
                            | 0b1010
                            | 0b1011
                            | 0b1100
                            | 0b1101
                            | 0b1110
                            | 0b0010
                            | 0b0011
                    ) =>
            {
                self.exec_sve2_mull_indexed(insn, zn, zd)
            }

            // SVE2 CMLA / SQRDCMLAH by indexed element: 0x44, bit21==1,
            // bits[15:13]==011. bit12 picks SQRDCMLAH (saturating-rounding-
            // doubling) over plain CMLA. rot=bits[11:10]; the indexed Zm complex
            // pair (at 2*index) is broadcast. .h: index=bits[20:19],
            // Zm=bits[18:16]; .s: index=bit20, Zm=bits[19:16]. For SQRDCMLAH the
            // doubled-rounded high product is accumulated then saturated, exactly
            // as the non-indexed SQRDCMLAH (qemu sve2_sqrdcmlah_idx).
            0b010
                if (insn >> 24) & 0xFF == 0b01000100
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x7 == 0b011 =>
            {
                let size = (insn >> 22) & 0x3;
                if size < 2 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let sat = (insn >> 12) & 1 == 1;
                let esize = 1usize << (size - 1); // .h=2, .s=4
                let bits = (esize * 8) as u32;
                let mask = elem_mask(bits);
                let hi = (1i128 << (bits - 1)) - 1;
                let lo = -(1i128 << (bits - 1));
                let sdrh = |prod: i128| (prod + (1i128 << (bits - 2))) >> (bits - 1);
                let rot = (insn >> 10) & 0x3;
                let sel_a = (rot & 1) as usize;
                let sel_b = sel_a ^ 1;
                let sub_r: i128 = if rot == 1 || rot == 2 { -1 } else { 1 };
                let sub_i: i128 = if rot >= 2 { -1 } else { 1 };
                let (index, zm) = if size == 2 {
                    (((insn >> 19) & 0x3) as usize, ((insn >> 16) & 0x7) as usize)
                } else {
                    (((insn >> 20) & 1) as usize, ((insn >> 16) & 0xF) as usize)
                };
                let idx = index * 2;
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let a = self.v[zd].to_le_bytes();
                let e2a = sext_elem(read_elem(&m, (idx + sel_a) * esize, esize), bits);
                let e2b = sext_elem(read_elem(&m, (idx + sel_b) * esize, esize), bits);
                let mut dst = [0u8; 16];
                for p in 0..((16 / esize) / 2) {
                    let (re, im) = (2 * p, 2 * p + 1);
                    let e1 = sext_elem(read_elem(&n, (re + sel_a) * esize, esize), bits);
                    let ar = sext_elem(read_elem(&a, re * esize, esize), bits);
                    let ai = sext_elem(read_elem(&a, im * esize, esize), bits);
                    let (r_re, r_im) = if sat {
                        (
                            (ar + sdrh(e1 * e2a * sub_r)).clamp(lo, hi),
                            (ai + sdrh(e1 * e2b * sub_i)).clamp(lo, hi),
                        )
                    } else {
                        (ar + e1 * e2a * sub_r, ai + e1 * e2b * sub_i)
                    };
                    write_elem(&mut dst, re * esize, esize, r_re as u64 & mask);
                    write_elem(&mut dst, im * esize, esize, r_im as u64 & mask);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 MATCH / NMATCH (character match -> predicate): 0x45, bit21==1,
            // bits[15:13]==100. For each Pg-active Zn element the result bit is
            // set if that element value equals any Zm element in the same
            // 128-bit segment (MATCH) or none of them (NMATCH, bit4==1). The
            // result is zeroing and sets NZCV via PredTest(Pg). size b/h only.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x7 == 0b100 =>
            {
                let size = (insn >> 22) & 0x3;
                if size > 1 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let esize = 1usize << size;
                let elements = 16 / esize;
                let nmatch = (insn >> 4) & 1 == 1;
                let pg = ((insn >> 10) & 0x7) as usize;
                let pd = (insn & 0xF) as usize;
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let gov = self.sve_p[pg];
                let mut result = 0u32;
                for e in 0..elements {
                    let off = e * esize;
                    if (gov >> off) & 1 == 0 {
                        continue; // zeroing predication
                    }
                    let ne = read_elem(&n, off, esize);
                    let matched = (0..elements).any(|j| read_elem(&m, j * esize, esize) == ne);
                    if matched ^ nmatch {
                        result |= 1 << off;
                    }
                }
                self.sve_p[pd] = result;
                let (nf, zf, cf, vf) = pred_test(gov, result, elements, esize);
                self.set_n(nf);
                self.set_z(zf);
                self.set_c(cf);
                self.set_v(vf);
                Ok(CpuExit::Continue)
            }

            // SVE2 HISTSEG (histogram segment): 0x45, bit21==1,
            // bits[15:10]==101000, size==b. Each result byte is the number of Zm
            // bytes (in the 128-bit segment) equal to the corresponding Zn byte.
            // Unpredicated.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 10) & 0x3F == 0b101000 =>
            {
                if (insn >> 22) & 0x3 != 0 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                for e in 0..16 {
                    dst[e] = m.iter().filter(|&&b| b == n[e]).count() as u8;
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 HISTCNT (histogram count): 0x45, bit21==1, bits[15:13]==110,
            // size s/d. For each Pg-active element i, the result is the number of
            // active elements j<=i whose Zm value equals Zn[i]; inactive lanes
            // are zeroed.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x7 == 0b110 =>
            {
                let size = (insn >> 22) & 0x3;
                if size < 2 {
                    return Ok(CpuExit::Undefined(insn));
                }
                let esize = 1usize << size;
                let elements = 16 / esize;
                let pg = ((insn >> 10) & 0x7) as usize;
                let gov = self.sve_p[pg];
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let mut dst = [0u8; 16];
                for i in 0..elements {
                    let off_i = i * esize;
                    if (gov >> off_i) & 1 == 0 {
                        continue; // zeroing
                    }
                    let nn = read_elem(&n, off_i, esize);
                    let mut count = 0u64;
                    for j in 0..=i {
                        let off_j = j * esize;
                        if (gov >> off_j) & 1 == 1 && read_elem(&m, off_j, esize) == nn {
                            count += 1;
                        }
                    }
                    write_elem(&mut dst, off_i, esize, count);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE2 crypto (AES / SM4 / SHA3-RAX1): 0x45, bit21==1,
            // bits[15:13]==111. At VL=128 each op acts on the single 128-bit
            // segment, identical to its NEON counterpart.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 1
                    && (insn >> 13) & 0x7 == 0b111 =>
            {
                self.exec_sve2_crypto(insn)
            }

            // SVE2 ADCLB/ADCLT/SBCLB/SBCLT (long add/subtract with carry): 0x45,
            // bit21==0, bits[15:11]==11010. The carry-in is bit `esize` of each
            // Zm element; bit23 inverts the Zn operand (SBCL = add of the one's
            // complement); bit22 selects .d (1) / .s (0); bit10 (T) the odd/even
            // Zn half. Zda holds the low half; the full sum (with carry-out) is
            // written across the doubled container.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b11010 =>
            {
                let d_form = (insn >> 22) & 1 == 1;
                let top = ((insn >> 10) & 1) as u32;
                let inv = (insn >> 23) & 1 == 1;
                if d_form {
                    let e1 = self.v[zd] as u64;
                    let mut e2 = (self.v[zn] >> (top * 64)) as u64;
                    if inv {
                        e2 = !e2;
                    }
                    let c = ((self.v[zm] >> 64) & 1) as u64;
                    self.v[zd] = (e1 as u128) + (e2 as u128) + (c as u128);
                } else {
                    let mut dst = 0u128;
                    for i in 0..2 {
                        let e1 = (self.v[zd] >> (i * 64)) as u32;
                        let mut e2 = ((self.v[zn] >> (i * 64)) >> (top * 32)) as u32;
                        if inv {
                            e2 = !e2;
                        }
                        let c = ((self.v[zm] >> (i * 64 + 32)) & 1) as u32;
                        let sum = e1 as u64 + e2 as u64 + c as u64; // 33-bit, holds carry-out
                        dst |= (sum as u128) << (i * 64);
                    }
                    self.v[zd] = dst;
                }
                Ok(CpuExit::Continue)
            }

            // SVE2 EORBT/EORTB (interleaving exclusive OR): 0x45, bit21==0,
            // bits[15:11]==10010, bit10 selects EORTB(1)/EORBT(0). EORBT writes
            // the even result lanes as Zn_even ^ Zm_odd (odd lanes keep the prior
            // Zd); EORTB writes the odd lanes as Zn_odd ^ Zm_even.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 11) & 0x1F == 0b10010 =>
            {
                let esize = 1usize << ((insn >> 22) & 0x3);
                let tb = (insn >> 10) & 1 == 1; // EORTB
                let (sel1, sel2) = if tb {
                    (1usize, 0usize)
                } else {
                    (0usize, 1usize)
                };
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let mut dst = self.v[zd].to_le_bytes(); // keep prior Zd in unwritten lanes
                for p in 0..((16 / esize) / 2) {
                    let base = 2 * p * esize;
                    let nn = read_elem(&n, base + sel1 * esize, esize);
                    let mm = read_elem(&m, base + sel2 * esize, esize);
                    write_elem(&mut dst, base + sel1 * esize, esize, nn ^ mm);
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // SVE I8MM integer matrix multiply-accumulate (SMMLA/UMMLA/USMMLA):
            // 0x45, bit21==0, bits[15:10]==100110. bit23 = Zn unsigned, bit22 =
            // Zm unsigned (the signed-by-unsigned pair is unallocated). Computes
            // a 2x2 int32 tile: Zda += Zn(2x8 int8) * Zm(2x8 int8)^T, each entry
            // an 8-element dot product accumulated mod 2^32.
            0b010
                if (insn >> 24) & 0xFF == 0b01000101
                    && (insn >> 21) & 1 == 0
                    && (insn >> 10) & 0x3F == 0b100110 =>
            {
                let n_uns = (insn >> 23) & 1 == 1;
                let m_uns = (insn >> 22) & 1 == 1;
                if !n_uns && m_uns {
                    return Ok(CpuExit::Undefined(insn)); // signed-by-unsigned: unallocated
                }
                let n = self.v[zn].to_le_bytes();
                let m = self.v[zm].to_le_bytes();
                let acc = self.v[zd].to_le_bytes();
                let dot = |nrow: usize, mrow: usize| -> u32 {
                    let mut s = 0i64;
                    for k in 0..8 {
                        let nv = n[nrow * 8 + k];
                        let mv = m[mrow * 8 + k];
                        let np = if n_uns { nv as i64 } else { nv as i8 as i64 };
                        let mp = if m_uns { mv as i64 } else { mv as i8 as i64 };
                        s = s.wrapping_add(np * mp);
                    }
                    s as u32
                };
                let mut dst = [0u8; 16];
                for (idx, &(nr, mr)) in [(0, 0), (0, 1), (1, 0), (1, 1)].iter().enumerate() {
                    let a = u32::from_le_bytes(acc[idx * 4..idx * 4 + 4].try_into().unwrap());
                    let r = a.wrapping_add(dot(nr, mr));
                    dst[idx * 4..idx * 4 + 4].copy_from_slice(&r.to_le_bytes());
                }
                self.v[zd] = u128::from_le_bytes(dst);
                Ok(CpuExit::Continue)
            }

            // Load/Store
            0b100 | 0b101 | 0b110 | 0b111 => self.exec_sve_ldst(insn),

            _ => Err(ArmError::Unimplemented(format!(
                "SVE op0={:03b} op1={:02b}",
                op0, op1
            ))),
        }
    }
}

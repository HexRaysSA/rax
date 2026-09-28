//! misc.rs

use crate::error::{Error, Result};
use crate::isa::x86_64::decode::dispatch::evex::*;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::{execute, flags};

impl X86_64Vcpu {
    /// Execute EVEX-encoded instruction.
    /// mm: opcode map (1=0F, 2=0F38, 3=0F3A)
    pub(in crate::isa::x86_64) fn execute_evex(
        &mut self,
        ctx: &mut InsnContext,
        mm: u8,
    ) -> Result<Option<VcpuExit>> {
        let opcode = ctx.consume_u8()?;
        if mm != 4 {
            ctx.rip_relative_offset =
                crate::isa::x86_64::decode::dispatch::immediate_len(mm, opcode);
        }

        // Record precise opcode key for profiling
        #[cfg(feature = "profiling")]
        crate::observability::profiling::set_current_opcode_key(
            crate::observability::profiling::OpcodeKey::Evex { map: mm, opcode },
        );

        match mm {
            1 => self.execute_evex_0f(ctx, opcode),
            2 => self.execute_evex_0f38(ctx, opcode),
            3 => self.execute_evex_0f3a(ctx, opcode),
            4 if self.apx_enabled() => self.execute_evex_map4_apx(ctx, opcode),
            4 => self.inject_undefined_instruction(),
            5 => self.execute_evex_map5(ctx, opcode),
            6 => self.execute_evex_map6(ctx, opcode),
            _ => self.inject_undefined_instruction(),
        }
    }

    /// Resolve the full 0-31 vector register index for an EVEX r/m register operand.
    /// rm (3 bits) extended by EVEX.B (bit 3) and EVEX.X (bit 4, V' for reg-reg).
    #[inline]
    pub(crate) fn evex_rm_vec_reg(evex: &crate::isa::x86_64::cpu::EvexPrefix, rm: u8) -> usize {
        // rm is the raw 3-bit ModRM.rm field; the r/m vector register's high bits
        // come solely from EVEX.B (bit 3) and EVEX.X (bit 4, V' for reg-reg). Mask
        // to 3 bits defensively so a caller that passes a REX-extended rm (e.g. a
        // stray legacy REX before the EVEX prefix) can never push the index past
        // 31 and read regs.zmm_ext out of bounds.
        let rm = rm & 0x07;
        let base = if !evex.b { rm + 8 } else { rm };
        let base = if !evex.x { base + 16 } else { base };
        base as usize
    }

    /// Compute the active-element opmask for an EVEX op.
    /// k0 (aaa == 0) means "no masking": all elements active.
    #[inline]
    pub(crate) fn evex_kmask(
        evex: &crate::isa::x86_64::cpu::EvexPrefix,
        k: &[u64],
        num_elems: usize,
    ) -> u64 {
        let full = if num_elems >= 64 {
            u64::MAX
        } else {
            (1u64 << num_elems) - 1
        };
        if evex.aaa == 0 {
            full
        } else {
            k[evex.aaa as usize] & full
        }
    }

    pub(crate) fn zero_zmm_upper_from_128(&mut self, zmm: usize) {
        if zmm < 16 {
            self.regs.ymm_high[zmm] = [0; 2];
            self.regs.zmm_high[zmm] = [0; 4];
        } else {
            self.regs.zmm_ext[zmm - 16][2..].fill(0);
        }
    }

    pub(crate) fn x86_min_f32(a: f32, b: f32) -> f32 {
        if (a == 0.0 && b == 0.0) || a.is_nan() || b.is_nan() {
            b
        } else if a < b {
            a
        } else {
            b
        }
    }

    pub(crate) fn x86_min_f64(a: f64, b: f64) -> f64 {
        if (a == 0.0 && b == 0.0) || a.is_nan() || b.is_nan() {
            b
        } else if a < b {
            a
        } else {
            b
        }
    }

    pub(crate) fn x86_max_f32(a: f32, b: f32) -> f32 {
        if (a == 0.0 && b == 0.0) || a.is_nan() || b.is_nan() {
            b
        } else if a > b {
            a
        } else {
            b
        }
    }

    pub(crate) fn x86_max_f64(a: f64, b: f64) -> f64 {
        if (a == 0.0 && b == 0.0) || a.is_nan() || b.is_nan() {
            b
        } else if a > b {
            a
        } else {
            b
        }
    }

    // ZMM register helper functions

    pub(crate) fn get_zmm_data(&self, zmm: usize, vl: usize) -> [u8; 64] {
        let mut data = [0u8; 64];
        if zmm < 16 {
            data[0..8].copy_from_slice(&self.regs.xmm[zmm][0].to_le_bytes());
            data[8..16].copy_from_slice(&self.regs.xmm[zmm][1].to_le_bytes());
            if vl > 16 {
                data[16..24].copy_from_slice(&self.regs.ymm_high[zmm][0].to_le_bytes());
                data[24..32].copy_from_slice(&self.regs.ymm_high[zmm][1].to_le_bytes());
            }
            if vl > 32 {
                data[32..40].copy_from_slice(&self.regs.zmm_high[zmm][0].to_le_bytes());
                data[40..48].copy_from_slice(&self.regs.zmm_high[zmm][1].to_le_bytes());
                data[48..56].copy_from_slice(&self.regs.zmm_high[zmm][2].to_le_bytes());
                data[56..64].copy_from_slice(&self.regs.zmm_high[zmm][3].to_le_bytes());
            }
        } else {
            let idx = zmm - 16;
            for i in 0..(vl / 8) {
                let start = i * 8;
                data[start..start + 8].copy_from_slice(&self.regs.zmm_ext[idx][i].to_le_bytes());
            }
        }
        data
    }

    pub(crate) fn load_zmm_data(&mut self, addr: u64, vl: usize) -> Result<[u8; 64]> {
        let mut data = [0u8; 64];
        for i in 0..(vl / 8) {
            let val = self.read_mem(addr + (i * 8) as u64, 8)?;
            let start = i * 8;
            data[start..start + 8].copy_from_slice(&val.to_le_bytes());
        }
        Ok(data)
    }

    pub(crate) fn set_zmm_data(&mut self, zmm: usize, data: &[u8], vl: usize) {
        // Helper to read u64 from data with zero-padding for short slices
        let read_u64 = |offset: usize| -> u64 {
            let mut bytes = [0u8; 8];
            let end = (offset + 8).min(data.len());
            if offset < data.len() {
                bytes[..end - offset].copy_from_slice(&data[offset..end]);
            }
            u64::from_le_bytes(bytes)
        };

        if zmm < 16 {
            self.regs.xmm[zmm][0] = read_u64(0);
            if vl > 8 {
                self.regs.xmm[zmm][1] = read_u64(8);
            } else {
                self.regs.xmm[zmm][1] = 0;
            }
            if vl > 16 {
                self.regs.ymm_high[zmm][0] = read_u64(16);
                self.regs.ymm_high[zmm][1] = read_u64(24);
            } else {
                self.regs.ymm_high[zmm] = [0; 2];
            }
            if vl > 32 {
                self.regs.zmm_high[zmm][0] = read_u64(32);
                self.regs.zmm_high[zmm][1] = read_u64(40);
                self.regs.zmm_high[zmm][2] = read_u64(48);
                self.regs.zmm_high[zmm][3] = read_u64(56);
            } else {
                self.regs.zmm_high[zmm] = [0; 4];
            }
        } else {
            let idx = zmm - 16;
            for i in 0..8 {
                self.regs.zmm_ext[idx][i] = if i < vl / 8 { read_u64(i * 8) } else { 0 };
            }
        }
    }

    // ============================================================================
    // AVX10.1 VNNI Instruction Implementations
    // ============================================================================

    /// VPDPBUSD/VPDPBUSDS - Multiply and Add Unsigned and Signed Bytes
    pub(crate) fn execute_vpdpbusd(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        // Destination/accumulator register
        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        // Source1 from vvvv (first multiplicand)
        let zmm_src1 = ctx.evex_vvvv() as usize;

        // Vector length from L'L
        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;
        let addr = if is_memory {
            let scale = if evex.broadcast { 4 } else { vl };
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
        } else {
            addr
        };

        // Load source2
        let src2 = if is_memory {
            if evex.broadcast {
                let elem = self.read_mem(addr, 4)?.to_le_bytes();
                let mut data = [0u8; 64];
                for lane in 0..num_dwords {
                    let base = lane * 4;
                    data[base..base + 4].copy_from_slice(&elem[..4]);
                }
                data
            } else {
                self.load_zmm_data(addr, vl)?
            }
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);
        let mask = Self::evex_kmask(&evex, &self.regs.k, num_dwords);

        // Process each dword
        for i in 0..num_dwords {
            let base = i * 4;
            if (mask >> i) & 1 == 0 {
                if evex.z {
                    dst[base..base + 4].fill(0);
                }
                continue;
            }
            // Each dword contains 4 bytes
            let mut sum =
                i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            for j in 0..4 {
                let a = src1[base + j] as u8 as i32; // unsigned byte
                let b = src2[base + j] as i8 as i32; // signed byte
                sum += (a * b) as i64;
            }

            let result = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VPDPWSSD/VPDPWSSDS - Multiply and Add Signed Word Integers
    pub(crate) fn execute_vpdpwssd(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;
        let addr = if is_memory {
            let scale = if evex.broadcast { 4 } else { vl };
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
        } else {
            addr
        };

        let src2 = if is_memory {
            if evex.broadcast {
                let elem = self.read_mem(addr, 4)?.to_le_bytes();
                let mut data = [0u8; 64];
                for lane in 0..num_dwords {
                    let base = lane * 4;
                    data[base..base + 4].copy_from_slice(&elem[..4]);
                }
                data
            } else {
                self.load_zmm_data(addr, vl)?
            }
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);
        let mask = Self::evex_kmask(&evex, &self.regs.k, num_dwords);

        for i in 0..num_dwords {
            let base = i * 4;
            if (mask >> i) & 1 == 0 {
                if evex.z {
                    dst[base..base + 4].fill(0);
                }
                continue;
            }
            let mut sum =
                i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            // Two pairs of signed words per dword
            let a0 = i16::from_le_bytes([src1[base], src1[base + 1]]) as i32;
            let b0 = i16::from_le_bytes([src2[base], src2[base + 1]]) as i32;
            let a1 = i16::from_le_bytes([src1[base + 2], src1[base + 3]]) as i32;
            let b1 = i16::from_le_bytes([src2[base + 2], src2[base + 3]]) as i32;

            sum += (a0 * b0 + a1 * b1) as i64;

            let result = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX10.1 IFMA Instruction Implementations
    // ============================================================================

    /// VPMADD52LUQ/VPMADD52HUQ - Packed Multiply of Unsigned 52-bit and Add
    pub(crate) fn execute_vpmadd52(
        &mut self,
        ctx: &mut InsnContext,
        high: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_qwords = vl / 8;
        let addr = if is_memory {
            let scale = if evex.broadcast { 8 } else { vl };
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
        } else {
            addr
        };

        let src2 = if is_memory {
            if evex.broadcast {
                let elem = self.read_mem(addr, 8)?.to_le_bytes();
                let mut data = [0u8; 64];
                for lane in 0..num_qwords {
                    let base = lane * 8;
                    data[base..base + 8].copy_from_slice(&elem[..8]);
                }
                data
            } else {
                self.load_zmm_data(addr, vl)?
            }
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);
        let mask = Self::evex_kmask(&evex, &self.regs.k, num_qwords);

        for i in 0..num_qwords {
            let base = i * 8;
            if (mask >> i) & 1 == 0 {
                if evex.z {
                    dst[base..base + 8].fill(0);
                }
                continue;
            }
            let a = u64::from_le_bytes([
                src1[base],
                src1[base + 1],
                src1[base + 2],
                src1[base + 3],
                src1[base + 4],
                src1[base + 5],
                src1[base + 6],
                src1[base + 7],
            ]) & 0x000F_FFFF_FFFF_FFFF; // 52-bit mask

            let b = u64::from_le_bytes([
                src2[base],
                src2[base + 1],
                src2[base + 2],
                src2[base + 3],
                src2[base + 4],
                src2[base + 5],
                src2[base + 6],
                src2[base + 7],
            ]) & 0x000F_FFFF_FFFF_FFFF;

            let d = u64::from_le_bytes([
                dst[base],
                dst[base + 1],
                dst[base + 2],
                dst[base + 3],
                dst[base + 4],
                dst[base + 5],
                dst[base + 6],
                dst[base + 7],
            ]);

            // 52x52 multiplication gives 104-bit result
            let product = (a as u128) * (b as u128);
            let result = if high {
                // High 52 bits of 104-bit product, added to dest
                d.wrapping_add(((product >> 52) & 0x000F_FFFF_FFFF_FFFF) as u64)
            } else {
                // Low 52 bits of 104-bit product, added to dest
                d.wrapping_add((product & 0x000F_FFFF_FFFF_FFFF) as u64)
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 8].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX10.1 VBMI Instruction Implementations
    // ============================================================================

    /// VPERMB - Permute Packed Bytes Elements
    pub(crate) fn execute_vpermb(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_idx = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };
        let addr = if is_memory {
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, vl)
        } else {
            addr
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src, vl)
        };

        let idx = self.get_zmm_data(zmm_idx, vl);
        let dest_old = self.get_zmm_data(zmm_dst, vl);
        let mask = Self::evex_kmask(&evex, &self.regs.k, vl);
        let mut dst = [0u8; 64];

        for i in 0..vl {
            if (mask >> i) & 1 != 0 {
                let index = (idx[i] as usize) % vl;
                dst[i] = src[index];
            } else if !evex.z {
                dst[i] = dest_old[i];
            }
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX10.1 BITALG Instruction Implementations
    // ============================================================================

    /// VPSHUFBITQMB - Shuffle Bits from Quadword Elements Using Byte Indexes into Mask
    pub(crate) fn execute_vpshufbitqmb(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let k_dst = reg as usize & 0x7;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };
        let addr = if is_memory {
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, vl)
        } else {
            addr
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let writemask = Self::evex_kmask(&evex, &self.regs.k, vl);
        let mut result: u64 = 0;

        // Process each qword
        for qword_idx in 0..(vl / 8) {
            let qword_base = qword_idx * 8;
            let mut qword = 0u64;
            for i in 0..8 {
                qword |= (src1[qword_base + i] as u64) << (i * 8);
            }

            // Each byte in src2 selects a bit from the corresponding qword
            for byte_idx in 0..8 {
                let bit_index = src2[qword_base + byte_idx] & 0x3F; // 6-bit index
                let bit = (qword >> bit_index) & 1;
                result |= bit << (qword_idx * 8 + byte_idx);
            }
        }

        self.regs.k[k_dst] = result & writemask;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX10.1 BF16 Instruction Implementations
    // ============================================================================

    /// VDPBF16PS - Dot Product of BF16 Pairs Accumulated into FP32
    pub(crate) fn execute_vdpbf16ps(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_floats = vl / 4;
        let addr = if is_memory {
            let scale = if evex.broadcast { 4 } else { vl };
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, scale)
        } else {
            addr
        };

        let src2 = if is_memory {
            if evex.broadcast {
                let elem = self.read_mem(addr, 4)?.to_le_bytes();
                let mut data = [0u8; 64];
                for lane in 0..num_floats {
                    let base = lane * 4;
                    data[base..base + 4].copy_from_slice(&elem[..4]);
                }
                data
            } else {
                self.load_zmm_data(addr, vl)?
            }
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);
        let mask = Self::evex_kmask(&evex, &self.regs.k, num_floats);

        for i in 0..num_floats {
            let base = i * 4;
            if (mask >> i) & 1 == 0 {
                if evex.z {
                    dst[base..base + 4].fill(0);
                }
                continue;
            }
            let acc_bits =
                u32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]);
            let acc = f32::from_bits(ftz_f32_bits(acc_bits));

            // Two BF16 values per dword.
            let a0 = bf16_to_f32(u16::from_le_bytes([src1[base], src1[base + 1]]));
            let b0 = bf16_to_f32(u16::from_le_bytes([src2[base], src2[base + 1]]));
            let a1 = bf16_to_f32(u16::from_le_bytes([src1[base + 2], src1[base + 3]]));
            let b1 = bf16_to_f32(u16::from_le_bytes([src2[base + 2], src2[base + 3]]));

            let result = acc + a0 * b0 + a1 * b1;
            let bytes = ftz_f32_bits(result.to_bits()).to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VCVTNEPS2BF16 - Convert Packed Single-Precision to BF16
    pub(crate) fn execute_vcvtneps2bf16(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };
        let addr = if is_memory {
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, vl)
        } else {
            addr
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src, vl)
        };

        let dst_vl = vl / 2; // Output is half the size
        let num_floats = vl / 4;
        let mask = Self::evex_kmask(&evex, &self.regs.k, num_floats);
        let mut dst = if evex.z {
            [0u8; 64]
        } else {
            self.get_zmm_data(zmm_dst, dst_vl)
        };

        for i in 0..num_floats {
            if (mask >> i) & 1 == 0 {
                continue;
            }
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src[src_base],
                src[src_base + 1],
                src[src_base + 2],
                src[src_base + 3],
            ]);
            let bf16 = f32_to_bf16(f);
            let dst_base = i * 2;
            let bytes = bf16.to_le_bytes();
            dst[dst_base..dst_base + 2].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..dst_vl], dst_vl);

        // Always zero upper bits for this conversion
        if zmm_dst < 16 {
            if dst_vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VCVTNE2PS2BF16 - Convert Two Packed Single-Precision to BF16
    pub(crate) fn execute_vcvtne2ps2bf16(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };
        let addr = if is_memory {
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, vl)
        } else {
            addr
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);

        let num_floats = vl / 4;
        let out_elems = vl / 2;
        let mask = Self::evex_kmask(&evex, &self.regs.k, out_elems);
        let mut dst = if evex.z {
            [0u8; 64]
        } else {
            self.get_zmm_data(zmm_dst, vl)
        };

        // First half from src2
        for i in 0..num_floats {
            if (mask >> i) & 1 == 0 {
                continue;
            }
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src2[src_base],
                src2[src_base + 1],
                src2[src_base + 2],
                src2[src_base + 3],
            ]);
            let bf16 = f32_to_bf16(f);
            let dst_base = i * 2;
            let bytes = bf16.to_le_bytes();
            dst[dst_base..dst_base + 2].copy_from_slice(&bytes);
        }

        // Second half from src1
        for i in 0..num_floats {
            let out_lane = num_floats + i;
            if (mask >> out_lane) & 1 == 0 {
                continue;
            }
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src1[src_base],
                src1[src_base + 1],
                src1[src_base + 2],
                src1[src_base + 3],
            ]);
            let bf16 = f32_to_bf16(f);
            let dst_base = (vl / 2) + i * 2;
            let bytes = bf16.to_le_bytes();
            dst[dst_base..dst_base + 2].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX-512 VDBPSADBW Instruction Implementation
    // ============================================================================

    /// VDBPSADBW - Double Block Packed Sum-Absolute-Differences
    pub(crate) fn execute_vdbpsadbw(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let modrm_start = ctx.cursor;
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };
        let addr = if is_memory {
            execute::simd::evex_scaled_disp8_addr(ctx, modrm_start, addr, vl)
        } else {
            addr
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut tmp1 = [0u8; 64];
        let mut raw = [0u8; 64];

        for lane_base in (0..vl).step_by(16) {
            for dword in 0..4 {
                let sel = ((imm8 >> (dword * 2)) & 0x03) as usize;
                let src_base = lane_base + sel * 4;
                let dst_base = lane_base + dword * 4;
                tmp1[dst_base..dst_base + 4].copy_from_slice(&src2[src_base..src_base + 4]);
            }
        }

        let sad4 = |a_base: usize, b_base: usize| -> u16 {
            let mut sad = 0u16;
            for byte in 0..4 {
                let a = src1[a_base + byte] as i16;
                let b = tmp1[b_base + byte] as i16;
                sad += (a - b).unsigned_abs();
            }
            sad
        };

        for block_base in (0..vl).step_by(8) {
            let results = [
                sad4(block_base, block_base),
                sad4(block_base, block_base + 1),
                sad4(block_base + 4, block_base + 2),
                sad4(block_base + 4, block_base + 3),
            ];
            for (idx, sad) in results.iter().enumerate() {
                let dst_offset = block_base + idx * 2;
                raw[dst_offset..dst_offset + 2].copy_from_slice(&sad.to_le_bytes());
            }
        }

        let mask = Self::evex_kmask(&evex, &self.regs.k, vl / 2);
        let mut dst = if evex.z {
            [0u8; 64]
        } else {
            self.get_zmm_data(zmm_dst, vl)
        };
        for word in 0..(vl / 2) {
            if (mask >> word) & 1 != 0 {
                let base = word * 2;
                dst[base..base + 2].copy_from_slice(&raw[base..base + 2]);
            }
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX10.2 VMINMAX Instruction Implementations
    // ============================================================================

    /// VMINMAXPS - Minimum/Maximum of Packed Single-Precision Floats
    pub(crate) fn execute_vminmax_ps(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = [0u8; 64];

        let num_elems = vl / 4;
        let is_min = (imm8 & 0x1) == 0;

        for i in 0..num_elems {
            let base = i * 4;
            let a =
                f32::from_le_bytes([src1[base], src1[base + 1], src1[base + 2], src1[base + 3]]);
            let b =
                f32::from_le_bytes([src2[base], src2[base + 1], src2[base + 2], src2[base + 3]]);

            let result = if is_min { a.min(b) } else { a.max(b) };
            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VMINMAXPD - Minimum/Maximum of Packed Double-Precision Floats
    pub(crate) fn execute_vminmax_pd(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = [0u8; 64];

        let num_elems = vl / 8;
        let is_min = (imm8 & 0x1) == 0;

        for i in 0..num_elems {
            let base = i * 8;
            let a = f64::from_le_bytes([
                src1[base],
                src1[base + 1],
                src1[base + 2],
                src1[base + 3],
                src1[base + 4],
                src1[base + 5],
                src1[base + 6],
                src1[base + 7],
            ]);
            let b = f64::from_le_bytes([
                src2[base],
                src2[base + 1],
                src2[base + 2],
                src2[base + 3],
                src2[base + 4],
                src2[base + 5],
                src2[base + 6],
                src2[base + 7],
            ]);

            let result = if is_min { a.min(b) } else { a.max(b) };
            let bytes = result.to_le_bytes();
            dst[base..base + 8].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VMINMAXSS - Minimum/Maximum of Scalar Single-Precision Float
    pub(crate) fn execute_vminmax_ss(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let b_val = if is_memory {
            let bytes = self.load_zmm_data(addr, 4)?;
            f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            let src2 = self.get_zmm_data(zmm_src2, 16);
            f32::from_le_bytes([src2[0], src2[1], src2[2], src2[3]])
        };

        let src1 = self.get_zmm_data(zmm_src1, 16);
        let a_val = f32::from_le_bytes([src1[0], src1[1], src1[2], src1[3]]);

        let is_min = (imm8 & 0x1) == 0;
        let result = if is_min {
            a_val.min(b_val)
        } else {
            a_val.max(b_val)
        };

        // Copy src1 to dst, then overwrite lowest element
        let mut dst = self.get_zmm_data(zmm_src1, 16);
        let bytes = result.to_le_bytes();
        dst[0..4].copy_from_slice(&bytes);

        self.set_zmm_data(zmm_dst, &dst[..16], 16);

        // Zero upper bits
        if zmm_dst < 16 {
            self.regs.ymm_high[zmm_dst][0] = 0;
            self.regs.ymm_high[zmm_dst][1] = 0;
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VMINMAXSD - Minimum/Maximum of Scalar Double-Precision Float
    pub(crate) fn execute_vminmax_sd(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let b_val = if is_memory {
            let bytes = self.load_zmm_data(addr, 8)?;
            f64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            let src2 = self.get_zmm_data(zmm_src2, 16);
            f64::from_le_bytes([
                src2[0], src2[1], src2[2], src2[3], src2[4], src2[5], src2[6], src2[7],
            ])
        };

        let src1 = self.get_zmm_data(zmm_src1, 16);
        let a_val = f64::from_le_bytes([
            src1[0], src1[1], src1[2], src1[3], src1[4], src1[5], src1[6], src1[7],
        ]);

        let is_min = (imm8 & 0x1) == 0;
        let result = if is_min {
            a_val.min(b_val)
        } else {
            a_val.max(b_val)
        };

        // Copy src1 to dst, then overwrite lowest element
        let mut dst = self.get_zmm_data(zmm_src1, 16);
        let bytes = result.to_le_bytes();
        dst[0..8].copy_from_slice(&bytes);

        self.set_zmm_data(zmm_dst, &dst[..16], 16);

        // Zero upper bits
        if zmm_dst < 16 {
            self.regs.ymm_high[zmm_dst][0] = 0;
            self.regs.ymm_high[zmm_dst][1] = 0;
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX10.2 Media Acceleration Instruction Implementations
    // ============================================================================

    /// VPDPBSSD/VPDPBSSDS - Multiply and Add Signed Byte Integers
    pub(crate) fn execute_vpdpbssd(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum =
                i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            for j in 0..4 {
                let a = src1[base + j] as i8 as i32; // signed byte
                let b = src2[base + j] as i8 as i32; // signed byte
                sum += (a * b) as i64;
            }

            let result = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VPDPBSUD/VPDPBSUDS - Multiply and Add Signed/Unsigned Byte Integers
    pub(crate) fn execute_vpdpbsud(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum =
                i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            for j in 0..4 {
                let a = src1[base + j] as i8 as i32; // signed byte
                let b = src2[base + j] as u8 as i32; // unsigned byte
                sum += (a * b) as i64;
            }

            let result = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VPDPBUUD/VPDPBUUDS - Multiply and Add Unsigned Byte Integers
    pub(crate) fn execute_vpdpbuud(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum =
                u32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as u64;

            for j in 0..4 {
                let a = src1[base + j] as u32; // unsigned byte
                let b = src2[base + j] as u32; // unsigned byte
                sum += (a * b) as u64;
            }

            let result = if saturate {
                sum.min(u32::MAX as u64) as u32
            } else {
                sum as u32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VPDPWSUD/VPDPWSUDS - Multiply and Add Signed/Unsigned Word Integers
    pub(crate) fn execute_vpdpwsud(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum =
                i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            // Two pairs of words per dword
            let a0 = i16::from_le_bytes([src1[base], src1[base + 1]]) as i32; // signed
            let b0 = u16::from_le_bytes([src2[base], src2[base + 1]]) as i32; // unsigned
            let a1 = i16::from_le_bytes([src1[base + 2], src1[base + 3]]) as i32; // signed
            let b1 = u16::from_le_bytes([src2[base + 2], src2[base + 3]]) as i32; // unsigned

            sum += (a0 * b0 + a1 * b1) as i64;

            let result = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VPDPWUSD/VPDPWUSDS - Multiply and Add Unsigned/Signed Word Integers
    pub(crate) fn execute_vpdpwusd(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum =
                i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            // Two pairs of words per dword
            let a0 = u16::from_le_bytes([src1[base], src1[base + 1]]) as i32; // unsigned
            let b0 = i16::from_le_bytes([src2[base], src2[base + 1]]) as i32; // signed
            let a1 = u16::from_le_bytes([src1[base + 2], src1[base + 3]]) as i32; // unsigned
            let b1 = i16::from_le_bytes([src2[base + 2], src2[base + 3]]) as i32; // signed

            sum += (a0 * b0 + a1 * b1) as i64;

            let result = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VPDPWUUD/VPDPWUUDS - Multiply and Add Unsigned Word Integers
    pub(crate) fn execute_vpdpwuud(
        &mut self,
        ctx: &mut InsnContext,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = ctx.evex_vvvv() as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = Self::evex_rm_vec_reg(&evex, rm);
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum =
                u32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as u64;

            // Two pairs of words per dword
            let a0 = u16::from_le_bytes([src1[base], src1[base + 1]]) as u32; // unsigned
            let b0 = u16::from_le_bytes([src2[base], src2[base + 1]]) as u32; // unsigned
            let a1 = u16::from_le_bytes([src1[base + 2], src1[base + 3]]) as u32; // unsigned
            let b1 = u16::from_le_bytes([src2[base + 2], src2[base + 3]]) as u32; // unsigned

            sum += (a0 * b0 + a1 * b1) as u64;

            let result = if saturate {
                sum.min(u32::MAX as u64) as u32
            } else {
                sum as u32
            };

            let bytes = result.to_le_bytes();
            dst[base..base + 4].copy_from_slice(&bytes);
        }

        self.set_zmm_data(zmm_dst, &dst[..vl], vl);

        if vl < 64 && zmm_dst < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_dst][0] = 0;
                self.regs.ymm_high[zmm_dst][1] = 0;
            }
            self.regs.zmm_high[zmm_dst] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(crate) fn inject_invalid_opcode(&mut self) -> Result<Option<VcpuExit>> {
        self.inject_exception(6, None)?;
        Ok(None)
    }

    /// Helper: perform shift operation
    pub(crate) fn perform_shift(&self, src: u64, count: u64, shift_type: u8, op_size: u8) -> u64 {
        if count == 0 {
            return src;
        }

        let width = op_size as u32 * 8;
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        let src = src & mask;

        match shift_type {
            0 => {
                let count = (count as u32) % width;
                if count == 0 {
                    return src;
                }
                ((src << count) | (src >> (width - count))) & mask
            }
            1 => {
                let count = (count as u32) % width;
                if count == 0 {
                    return src;
                }
                ((src >> count) | (src << (width - count))) & mask
            }
            2 => {
                // RCL
                let count = (count as u32) % (width + 1);
                if count == 0 {
                    return src;
                }

                let mut result = src;
                let mut carry = (self.regs.rflags & flags::bits::CF) != 0;
                for _ in 0..count {
                    let msb = (result >> (width - 1)) & 1 != 0;
                    result = ((result << 1) | carry as u64) & mask;
                    carry = msb;
                }
                result
            }
            3 => {
                // RCR
                let count = (count as u32) % (width + 1);
                if count == 0 {
                    return src;
                }

                let mut result = src;
                let mut carry = (self.regs.rflags & flags::bits::CF) != 0;
                for _ in 0..count {
                    let lsb = result & 1 != 0;
                    result = (result >> 1) | ((carry as u64) << (width - 1));
                    carry = lsb;
                }
                result & mask
            }
            4 | 6 => (src << count) & mask, // SHL/SAL
            5 => src >> count,              // SHR
            7 => {
                // SAR - arithmetic shift right
                if count as u32 >= width {
                    return if (src & (1u64 << (width - 1))) != 0 {
                        mask
                    } else {
                        0
                    };
                }
                match op_size {
                    1 => ((src as i8) >> count) as u8 as u64,
                    2 => ((src as i16) >> count) as u16 as u64,
                    4 => ((src as i32) >> count) as u32 as u64,
                    8 => ((src as i64) >> count) as u64,
                    _ => src,
                }
            }
            _ => src,
        }
    }

    /// Update flags for ALU operations
    pub(crate) fn update_flags_alu(
        &mut self,
        result: u64,
        src1: u64,
        src2: u64,
        op_size: u8,
        alu_op: ApxAluOp,
    ) {
        let sign_bit: u64 = match op_size {
            1 => 0x80,
            2 => 0x8000,
            4 => 0x8000_0000,
            8 => 0x8000_0000_0000_0000,
            _ => 0x8000_0000,
        };
        let max_val: u64 = match op_size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            8 => u64::MAX,
            _ => 0xFFFF_FFFF,
        };

        let masked_result = result & max_val;

        // ZF - zero flag
        let zf = masked_result == 0;
        // SF - sign flag
        let sf = (masked_result & sign_bit) != 0;
        // PF - parity flag (low byte)
        let pf = (result as u8).count_ones() % 2 == 0;

        // CF and OF depend on operation
        let (cf, of) = match alu_op {
            ApxAluOp::Add | ApxAluOp::Adc => {
                let cf = result > max_val || result < src1;
                let of = ((!(src1 ^ src2)) & (src1 ^ result) & sign_bit) != 0;
                (cf, of)
            }
            ApxAluOp::Sub | ApxAluOp::Sbb => {
                let cf = src1 < src2;
                let of = ((src1 ^ src2) & (src1 ^ result) & sign_bit) != 0;
                (cf, of)
            }
            ApxAluOp::And | ApxAluOp::Or | ApxAluOp::Xor => {
                (false, false) // Logical ops clear CF and OF
            }
        };

        // Update RFLAGS
        let mut flags = self.regs.rflags;
        flags &= !(0x8D5); // Clear CF, PF, ZF, SF, OF
        if cf {
            flags |= 0x001;
        }
        if pf {
            flags |= 0x004;
        }
        if zf {
            flags |= 0x040;
        }
        if sf {
            flags |= 0x080;
        }
        if of {
            flags |= 0x800;
        }
        self.regs.rflags = flags;
        self.clear_lazy_flags();
    }

    /// Update flags for shift operations
    pub(crate) fn update_flags_shift(
        &mut self,
        result: u64,
        src: u64,
        count: u64,
        shift_type: u8,
        op_size: u8,
    ) {
        let sign_bit: u64 = match op_size {
            1 => 0x80,
            2 => 0x8000,
            4 => 0x8000_0000,
            8 => 0x8000_0000_0000_0000,
            _ => 0x8000_0000,
        };
        let max_val: u64 = match op_size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            8 => u64::MAX,
            _ => 0xFFFF_FFFF,
        };

        let masked_result = result & max_val;

        let bits = op_size as u64 * 8;
        if shift_type <= 3 {
            let rotate_count = if shift_type <= 1 {
                count % bits
            } else {
                count % (bits + 1)
            };
            if rotate_count == 0 {
                return;
            }

            let cf = match shift_type {
                0 => (masked_result & 1) != 0,                // ROL
                1 => (masked_result & sign_bit) != 0,         // ROR
                2 => (src >> (bits - rotate_count)) & 1 != 0, // RCL
                3 => (src >> (rotate_count - 1)) & 1 != 0,    // RCR
                _ => unreachable!(),
            };
            let of = if count == 1 {
                match shift_type {
                    0 => ((masked_result >> (bits - 1)) ^ masked_result) & 1 != 0,
                    1 | 3 => {
                        ((masked_result >> (bits - 1)) ^ (masked_result >> (bits - 2))) & 1 != 0
                    }
                    2 => ((masked_result & sign_bit) != 0) ^ cf,
                    _ => unreachable!(),
                }
            } else {
                (self.regs.rflags & flags::bits::OF) != 0
            };

            if cf {
                self.regs.rflags |= flags::bits::CF;
            } else {
                self.regs.rflags &= !flags::bits::CF;
            }
            if of {
                self.regs.rflags |= flags::bits::OF;
            } else {
                self.regs.rflags &= !flags::bits::OF;
            }
            self.clear_lazy_flags();
            return;
        }

        // ZF, SF, PF from result
        let zf = masked_result == 0;
        let sf = (masked_result & sign_bit) != 0;
        let pf = (result as u8).count_ones() % 2 == 0;

        // CF depends on shift type and direction
        let cf = match shift_type {
            4 | 6 => count <= bits && (src >> (bits - count)) & 1 != 0,
            5 => count <= bits && (src >> (count - 1)) & 1 != 0,
            7 => {
                if count <= bits {
                    (src >> (count - 1)) & 1 != 0
                } else {
                    (src >> (bits - 1)) & 1 != 0
                }
            }
            _ => unreachable!(),
        };

        // OF is only defined for count=1
        let of = if count == 1 {
            match shift_type {
                4 | 6 => (masked_result & sign_bit) != (src & sign_bit), // SHL: sign change
                5 => (src & sign_bit) != 0,                              // SHR: old sign
                7 => false,                                              // SAR: always 0
                _ => unreachable!(),
            }
        } else {
            false // Undefined for count > 1, we clear it
        };

        let mut flags = self.regs.rflags;
        // AF is architecturally undefined for shifts. Preserve its incoming
        // value as the deterministic policy shared by the legacy executor,
        // SMIR interpreter, and native JIT status merge.
        flags &= !0x8C5;
        if cf {
            flags |= 0x001;
        }
        if pf {
            flags |= 0x004;
        }
        if zf {
            flags |= 0x040;
        }
        if sf {
            flags |= 0x080;
        }
        if of {
            flags |= 0x800;
        }
        self.regs.rflags = flags;
        self.clear_lazy_flags();
    }
}

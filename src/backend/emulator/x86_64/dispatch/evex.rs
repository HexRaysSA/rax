//! EVEX-encoded (AVX-512) instruction dispatch.
//!
//! EVEX prefix format (after 0x62):
//! - P0: R X B R' 0 m m m
//! - P1: W v v v v 1 p p
//! - P2: z L' L b V' a a a
//!
//! mm field (opcode map):
//! - 1: 0F (two-byte opcode)
//! - 2: 0F 38 (three-byte opcode)
//! - 3: 0F 3A (three-byte opcode with immediate)
//! - 5: MAP5 (AVX-512 FP16)
//! - 6: MAP6 (AVX-512 FP16)

use crate::cpu::VcpuExit;
use crate::error::{Error, Result};

use super::super::cpu::{InsnContext, X86_64Vcpu};
use super::super::insn;

impl X86_64Vcpu {
    /// Execute EVEX-encoded instruction.
    /// mm: opcode map (1=0F, 2=0F38, 3=0F3A)
    pub(in crate::backend::emulator::x86_64) fn execute_evex(
        &mut self,
        ctx: &mut InsnContext,
        mm: u8,
    ) -> Result<Option<VcpuExit>> {
        let opcode = ctx.consume_u8()?;

        // Record precise opcode key for profiling
        #[cfg(feature = "profiling")]
        crate::profiling::set_current_opcode_key(crate::profiling::OpcodeKey::Evex {
            map: mm,
            opcode,
        });

        match mm {
            1 => self.execute_evex_0f(ctx, opcode),
            2 => self.execute_evex_0f38(ctx, opcode),
            3 => self.execute_evex_0f3a(ctx, opcode),
            5 => self.execute_evex_map5(ctx, opcode),
            _ => Err(Error::Emulator(format!(
                "Invalid EVEX mm field {} at RIP={:#x}",
                mm, self.regs.rip
            ))),
        }
    }

    /// EVEX 0F opcode map (mm=1)
    fn execute_evex_0f(&mut self, ctx: &mut InsnContext, opcode: u8) -> Result<Option<VcpuExit>> {
        let evex = ctx
            .evex
            .ok_or_else(|| Error::Emulator("EVEX context missing".to_string()))?;

        match opcode {
            // VMOVUPS/VMOVAPS load (0x10/0x28)
            0x10 | 0x28 if evex.pp == 0 => self.execute_evex_mov_load(ctx, opcode == 0x28),
            // VMOVUPD/VMOVAPD load (0x10/0x28 with 66 prefix)
            0x10 | 0x28 if evex.pp == 1 => self.execute_evex_mov_load(ctx, opcode == 0x28),
            // VMOVUPS/VMOVAPS store (0x11/0x29)
            0x11 | 0x29 if evex.pp == 0 => self.execute_evex_mov_store(ctx, opcode == 0x29),
            // VMOVUPD/VMOVAPD store (0x11/0x29 with 66 prefix)
            0x11 | 0x29 if evex.pp == 1 => self.execute_evex_mov_store(ctx, opcode == 0x29),
            // VADDPS/VADDPD (0x58)
            0x58 => self.execute_evex_fp_arith(ctx, |a, b| a + b),
            // VMULPS/VMULPD (0x59)
            0x59 => self.execute_evex_fp_arith(ctx, |a, b| a * b),
            // VSUBPS/VSUBPD (0x5C)
            0x5C => self.execute_evex_fp_arith(ctx, |a, b| a - b),
            // VDIVPS/VDIVPD (0x5E)
            0x5E => self.execute_evex_fp_arith(ctx, |a, b| a / b),
            // VXORPS/VXORPD (0x57)
            0x57 => self.execute_evex_bitwise_xor(ctx),
            _ => Err(Error::Emulator(format!(
                "Unimplemented EVEX.0F opcode {:#04x} at RIP={:#x}",
                opcode, self.regs.rip
            ))),
        }
    }

    /// EVEX move load (VMOVAPS/VMOVUPS, VMOVAPD/VMOVUPD)
    fn execute_evex_mov_load(
        &mut self,
        ctx: &mut InsnContext,
        aligned: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        // Calculate full destination register (5 bits for ZMM16-31)
        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        // Vector length from L'L
        let vl = match evex.ll {
            0 => 16, // 128-bit (XMM)
            1 => 32, // 256-bit (YMM)
            2 => 64, // 512-bit (ZMM)
            _ => 64,
        };

        if is_memory {
            // Check alignment for VMOVAPS/VMOVAPD
            if aligned && (addr % vl as u64) != 0 {
                return Err(Error::Emulator(format!(
                    "VMOVAPS: unaligned memory access at {:#x}",
                    addr
                )));
            }
            // Load from memory to ZMM register
            self.load_zmm_from_mem(zmm_dst, addr, vl)?;
        } else {
            // Register to register move
            let zmm_src = if !evex.b { rm + 8 } else { rm };
            let zmm_src = zmm_src as usize; // ZMM16-31 not encoded in rm for reg-reg
            self.copy_zmm(zmm_dst, zmm_src, vl);
        }

        // Zero upper bits if not 512-bit
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

    /// EVEX move store (VMOVAPS/VMOVUPS, VMOVAPD/VMOVUPD)
    fn execute_evex_mov_store(
        &mut self,
        ctx: &mut InsnContext,
        aligned: bool,
    ) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        // Source register
        let zmm_src = if !evex.r { reg + 8 } else { reg };
        let zmm_src = if !evex.r_prime { zmm_src + 16 } else { zmm_src } as usize;

        // Vector length from L'L
        let vl = match evex.ll {
            0 => 16, // 128-bit (XMM)
            1 => 32, // 256-bit (YMM)
            2 => 64, // 512-bit (ZMM)
            _ => 64,
        };

        if is_memory {
            // Check alignment for VMOVAPS/VMOVAPD
            if aligned && (addr % vl as u64) != 0 {
                return Err(Error::Emulator(format!(
                    "VMOVAPS: unaligned memory access at {:#x}",
                    addr
                )));
            }
            // Store ZMM register to memory
            self.store_zmm_to_mem(zmm_src, addr, vl)?;
        } else {
            // Register to register move (destination is rm)
            let zmm_dst = if !evex.b { rm + 8 } else { rm } as usize;
            self.copy_zmm(zmm_dst, zmm_src, vl);

            // Zero upper bits if not 512-bit
            if vl < 64 && zmm_dst < 16 {
                if vl <= 16 {
                    self.regs.ymm_high[zmm_dst][0] = 0;
                    self.regs.ymm_high[zmm_dst][1] = 0;
                }
                self.regs.zmm_high[zmm_dst] = [0; 4];
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// EVEX floating-point arithmetic (VADDPS/PD, VMULPS/PD, VSUBPS/PD, VDIVPS/PD)
    fn execute_evex_fp_arith<F>(&mut self, ctx: &mut InsnContext, op: F) -> Result<Option<VcpuExit>>
    where
        F: Fn(f32, f32) -> f32,
    {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        // Destination register (5 bits)
        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        // Source1 from vvvv
        let zmm_src1 = evex.vvvv as usize;

        // Vector length from L'L
        let vl = match evex.ll {
            0 => 16, // 128-bit
            1 => 32, // 256-bit
            2 => 64, // 512-bit
            _ => 64,
        };

        // Number of f32 elements
        let num_elems = vl / 4;

        // Load source2
        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        // Get source1
        let src1 = self.get_zmm_data(zmm_src1, vl);

        // Perform operation
        let mut result = [0u8; 64];
        for i in 0..num_elems {
            let a = f32::from_le_bytes([
                src1[i * 4],
                src1[i * 4 + 1],
                src1[i * 4 + 2],
                src1[i * 4 + 3],
            ]);
            let b = f32::from_le_bytes([
                src2[i * 4],
                src2[i * 4 + 1],
                src2[i * 4 + 2],
                src2[i * 4 + 3],
            ]);
            let r = op(a, b);
            let bytes = r.to_le_bytes();
            result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        // Store result
        self.set_zmm_data(zmm_dst, &result[..vl], vl);

        // Zero upper bits if not 512-bit (for ZMM0-15)
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

    /// EVEX bitwise XOR (VXORPS, VXORPD)
    fn execute_evex_bitwise_xor(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        // Destination register (5 bits)
        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        // Source1 from vvvv (inverted)
        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        // Vector length from L'L
        let vl = match evex.ll {
            0 => 16, // 128-bit
            1 => 32, // 256-bit
            2 => 64, // 512-bit
            _ => 64,
        };

        // Load source2
        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        // Get source1
        let src1 = self.get_zmm_data(zmm_src1, vl);

        // Perform bitwise XOR
        let mut result = [0u8; 64];
        for i in 0..vl {
            result[i] = src1[i] ^ src2[i];
        }

        // Store result
        self.set_zmm_data(zmm_dst, &result[..vl], vl);

        // Zero upper bits if not 512-bit (for ZMM0-15)
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

    // ZMM register helper functions

    fn load_zmm_from_mem(&mut self, zmm: usize, addr: u64, vl: usize) -> Result<()> {
        if zmm < 16 {
            // ZMM0-15: load into xmm + ymm_high + zmm_high
            self.regs.xmm[zmm][0] = self.read_mem(addr, 8)?;
            self.regs.xmm[zmm][1] = self.read_mem(addr + 8, 8)?;
            if vl > 16 {
                self.regs.ymm_high[zmm][0] = self.read_mem(addr + 16, 8)?;
                self.regs.ymm_high[zmm][1] = self.read_mem(addr + 24, 8)?;
            }
            if vl > 32 {
                self.regs.zmm_high[zmm][0] = self.read_mem(addr + 32, 8)?;
                self.regs.zmm_high[zmm][1] = self.read_mem(addr + 40, 8)?;
                self.regs.zmm_high[zmm][2] = self.read_mem(addr + 48, 8)?;
                self.regs.zmm_high[zmm][3] = self.read_mem(addr + 56, 8)?;
            }
        } else {
            // ZMM16-31: load into zmm_ext
            let idx = zmm - 16;
            for i in 0..(vl / 8) {
                self.regs.zmm_ext[idx][i] = self.read_mem(addr + (i * 8) as u64, 8)?;
            }
        }
        Ok(())
    }

    fn store_zmm_to_mem(&mut self, zmm: usize, addr: u64, vl: usize) -> Result<()> {
        if zmm < 16 {
            self.write_mem(addr, self.regs.xmm[zmm][0], 8)?;
            self.write_mem(addr + 8, self.regs.xmm[zmm][1], 8)?;
            if vl > 16 {
                self.write_mem(addr + 16, self.regs.ymm_high[zmm][0], 8)?;
                self.write_mem(addr + 24, self.regs.ymm_high[zmm][1], 8)?;
            }
            if vl > 32 {
                self.write_mem(addr + 32, self.regs.zmm_high[zmm][0], 8)?;
                self.write_mem(addr + 40, self.regs.zmm_high[zmm][1], 8)?;
                self.write_mem(addr + 48, self.regs.zmm_high[zmm][2], 8)?;
                self.write_mem(addr + 56, self.regs.zmm_high[zmm][3], 8)?;
            }
        } else {
            let idx = zmm - 16;
            for i in 0..(vl / 8) {
                self.write_mem(addr + (i * 8) as u64, self.regs.zmm_ext[idx][i], 8)?;
            }
        }
        Ok(())
    }

    fn copy_zmm(&mut self, dst: usize, src: usize, vl: usize) {
        if dst < 16 && src < 16 {
            self.regs.xmm[dst] = self.regs.xmm[src];
            if vl > 16 {
                self.regs.ymm_high[dst] = self.regs.ymm_high[src];
            }
            if vl > 32 {
                self.regs.zmm_high[dst] = self.regs.zmm_high[src];
            }
        } else if dst >= 16 && src >= 16 {
            let d = dst - 16;
            let s = src - 16;
            for i in 0..(vl / 8) {
                self.regs.zmm_ext[d][i] = self.regs.zmm_ext[s][i];
            }
        } else if dst < 16 && src >= 16 {
            let s = src - 16;
            self.regs.xmm[dst][0] = self.regs.zmm_ext[s][0];
            self.regs.xmm[dst][1] = self.regs.zmm_ext[s][1];
            if vl > 16 {
                self.regs.ymm_high[dst][0] = self.regs.zmm_ext[s][2];
                self.regs.ymm_high[dst][1] = self.regs.zmm_ext[s][3];
            }
            if vl > 32 {
                self.regs.zmm_high[dst][0] = self.regs.zmm_ext[s][4];
                self.regs.zmm_high[dst][1] = self.regs.zmm_ext[s][5];
                self.regs.zmm_high[dst][2] = self.regs.zmm_ext[s][6];
                self.regs.zmm_high[dst][3] = self.regs.zmm_ext[s][7];
            }
        } else {
            // dst >= 16 && src < 16
            let d = dst - 16;
            self.regs.zmm_ext[d][0] = self.regs.xmm[src][0];
            self.regs.zmm_ext[d][1] = self.regs.xmm[src][1];
            if vl > 16 {
                self.regs.zmm_ext[d][2] = self.regs.ymm_high[src][0];
                self.regs.zmm_ext[d][3] = self.regs.ymm_high[src][1];
            }
            if vl > 32 {
                self.regs.zmm_ext[d][4] = self.regs.zmm_high[src][0];
                self.regs.zmm_ext[d][5] = self.regs.zmm_high[src][1];
                self.regs.zmm_ext[d][6] = self.regs.zmm_high[src][2];
                self.regs.zmm_ext[d][7] = self.regs.zmm_high[src][3];
            }
        }
    }

    fn get_zmm_data(&self, zmm: usize, vl: usize) -> [u8; 64] {
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

    fn load_zmm_data(&mut self, addr: u64, vl: usize) -> Result<[u8; 64]> {
        let mut data = [0u8; 64];
        for i in 0..(vl / 8) {
            let val = self.read_mem(addr + (i * 8) as u64, 8)?;
            let start = i * 8;
            data[start..start + 8].copy_from_slice(&val.to_le_bytes());
        }
        Ok(data)
    }

    fn set_zmm_data(&mut self, zmm: usize, data: &[u8], vl: usize) {
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
            }
            if vl > 32 {
                self.regs.zmm_high[zmm][0] = read_u64(32);
                self.regs.zmm_high[zmm][1] = read_u64(40);
                self.regs.zmm_high[zmm][2] = read_u64(48);
                self.regs.zmm_high[zmm][3] = read_u64(56);
            }
        } else {
            let idx = zmm - 16;
            for i in 0..(vl / 8) {
                self.regs.zmm_ext[idx][i] = read_u64(i * 8);
            }
        }
    }

    /// EVEX 0F38 opcode map (mm=2)
    fn execute_evex_0f38(&mut self, ctx: &mut InsnContext, opcode: u8) -> Result<Option<VcpuExit>> {
        let evex = ctx
            .evex
            .ok_or_else(|| Error::Emulator("EVEX context missing".to_string()))?;

        match opcode {
            // VPMULLD/VPMULLQ (0x40)
            // W=0: VPMULLD (32-bit elements)
            // W=1: VPMULLQ (64-bit elements)
            0x40 if evex.pp == 1 => {
                if evex.w {
                    insn::simd::vpmullq(self, ctx)
                } else {
                    insn::simd::vpmulld_evex(self, ctx)
                }
            }
            // VEXPANDPS/VEXPANDPD (0x88)
            0x88 if evex.pp == 1 => {
                if evex.w {
                    insn::simd::vexpand_evex(self, ctx, 8, "VEXPANDPD")
                } else {
                    insn::simd::vexpand_evex(self, ctx, 4, "VEXPANDPS")
                }
            }
            // VPEXPANDD/VPEXPANDQ (0x89)
            0x89 if evex.pp == 1 => {
                if evex.w {
                    insn::simd::vexpand_evex(self, ctx, 8, "VPEXPANDQ")
                } else {
                    insn::simd::vexpand_evex(self, ctx, 4, "VPEXPANDD")
                }
            }
            // VCOMPRESSPS/VCOMPRESSPD (0x8A)
            0x8A if evex.pp == 1 => {
                if evex.w {
                    insn::simd::vcompress_evex(self, ctx, 8, "VCOMPRESSPD")
                } else {
                    insn::simd::vcompress_evex(self, ctx, 4, "VCOMPRESSPS")
                }
            }
            // VPCOMPRESSD/VPCOMPRESSQ (0x8B)
            0x8B if evex.pp == 1 => {
                if evex.w {
                    insn::simd::vcompress_evex(self, ctx, 8, "VPCOMPRESSQ")
                } else {
                    insn::simd::vcompress_evex(self, ctx, 4, "VPCOMPRESSD")
                }
            }

            // ============================================================================
            // AVX10.1 VNNI Instructions
            // ============================================================================

            // VPDPBUSD (0x50) - Multiply and Add Unsigned and Signed Bytes
            0x50 if evex.pp == 1 => self.execute_vpdpbusd(ctx, false),
            // VPDPBUSDS (0x51) - Multiply and Add Unsigned and Signed Bytes with Saturation
            0x51 if evex.pp == 1 => self.execute_vpdpbusd(ctx, true),
            // VPDPWSSD (0x52) - Multiply and Add Signed Word Integers
            0x52 if evex.pp == 1 && !evex.w => self.execute_vpdpwssd(ctx, false),
            // VPDPWSSDS (0x53) - Multiply and Add Signed Word Integers with Saturation
            0x53 if evex.pp == 1 => self.execute_vpdpwssd(ctx, true),

            // ============================================================================
            // AVX10.1 IFMA Instructions
            // ============================================================================

            // VPMADD52LUQ (0xB4) - Packed Multiply of Unsigned 52-bit and Add Low Qword
            0xB4 if evex.pp == 1 && evex.w => self.execute_vpmadd52(ctx, false),
            // VPMADD52HUQ (0xB5) - Packed Multiply of Unsigned 52-bit and Add High Qword
            0xB5 if evex.pp == 1 && evex.w => self.execute_vpmadd52(ctx, true),

            // ============================================================================
            // AVX10.1 VPOPCNTDQ Instructions
            // ============================================================================

            // VPOPCNTB/W (0x54) - Population count for packed bytes/words
            0x54 if evex.pp == 1 => {
                if evex.w {
                    self.execute_vpopcnt(ctx, 2) // VPOPCNTW
                } else {
                    self.execute_vpopcnt(ctx, 1) // VPOPCNTB
                }
            }
            // VPOPCNTD/Q (0x55) - Population count for packed dwords/qwords
            0x55 if evex.pp == 1 => {
                if evex.w {
                    self.execute_vpopcnt(ctx, 8) // VPOPCNTQ
                } else {
                    self.execute_vpopcnt(ctx, 4) // VPOPCNTD
                }
            }

            // ============================================================================
            // AVX10.1 VBMI Instructions
            // ============================================================================

            // VPERMB (0x8D) - Permute Packed Bytes Elements
            0x8D if evex.pp == 1 && !evex.w => self.execute_vpermb(ctx),
            // VPERMI2B (0x75) - Full Permute of Bytes from Two Tables Overwriting Index
            0x75 if evex.pp == 1 && !evex.w => self.execute_vpermi2b(ctx),
            // VPERMT2B (0x7D) - Full Permute of Bytes from Two Tables Overwriting Table
            0x7D if evex.pp == 1 && !evex.w => self.execute_vpermt2b(ctx),

            // ============================================================================
            // AVX10.1 BITALG Instructions
            // ============================================================================

            // VPSHUFBITQMB (0x8F) - Shuffle Bits from Quadword Elements Using Byte Indexes into Mask
            0x8F if evex.pp == 1 && !evex.w => self.execute_vpshufbitqmb(ctx),

            // ============================================================================
            // AVX10.1 BF16 Instructions
            // ============================================================================

            // VDPBF16PS (0x52) - Dot Product of BF16 Pairs Accumulated into FP32
            0x52 if evex.pp == 2 && !evex.w => self.execute_vdpbf16ps(ctx),
            // VCVTNEPS2BF16 (0x72) - Convert Packed Single to BF16
            0x72 if evex.pp == 2 && !evex.w => self.execute_vcvtneps2bf16(ctx),
            // VCVTNE2PS2BF16 (0x72) - Convert Two Packed Single to BF16
            0x72 if evex.pp == 3 && !evex.w => self.execute_vcvtne2ps2bf16(ctx),

            // ============================================================================
            // AVX10.2 Saturation Conversion Instructions
            // ============================================================================

            // VCVTTPS2IBS (0x68) - Convert with Truncation Packed Single to Signed Byte with Saturation
            0x68 if evex.pp == 0 && !evex.w => self.execute_vcvttps2ibs(ctx),
            // VCVTTPS2IUBS (0x6A) - Convert with Truncation Packed Single to Unsigned Byte with Saturation
            0x6A if evex.pp == 0 && !evex.w => self.execute_vcvttps2iubs(ctx),
            // VCVTTPD2QQS (0x6D) - Convert with Truncation Packed Double to Signed Qword with Saturation
            0x6D if evex.pp == 1 && evex.w => self.execute_vcvttpd2qqs(ctx),
            // VCVTTPD2UQQS (0x6C) - Convert with Truncation Packed Double to Unsigned Qword with Saturation
            0x6C if evex.pp == 1 && evex.w => self.execute_vcvttpd2uqqs(ctx),

            // ============================================================================
            // AVX10.2 Media Acceleration Instructions (VPDPB*/VPDPW*)
            // ============================================================================

            // VPDPBSSD (0x50) - Multiply and Add Signed Byte Integers
            0x50 if evex.pp == 2 && !evex.w => self.execute_vpdpbssd(ctx, false),
            // VPDPBSSDS (0x51) - Multiply and Add Signed Byte Integers with Saturation
            0x51 if evex.pp == 2 && !evex.w => self.execute_vpdpbssd(ctx, true),
            // VPDPBSUD (0x50) - Multiply and Add Signed/Unsigned Byte Integers
            0x50 if evex.pp == 2 && evex.w => self.execute_vpdpbsud(ctx, false),
            // VPDPBSUDS (0x51) - Multiply and Add Signed/Unsigned Byte Integers with Saturation
            0x51 if evex.pp == 2 && evex.w => self.execute_vpdpbsud(ctx, true),
            // VPDPBUUD (0x50) - Multiply and Add Unsigned Byte Integers
            0x50 if evex.pp == 0 && evex.w => self.execute_vpdpbuud(ctx, false),
            // VPDPBUUDS (0x51) - Multiply and Add Unsigned Byte Integers with Saturation
            0x51 if evex.pp == 0 && evex.w => self.execute_vpdpbuud(ctx, true),
            // VPDPWSUD (0xD2) - Multiply and Add Signed/Unsigned Word Integers
            0xD2 if evex.pp == 2 && !evex.w => self.execute_vpdpwsud(ctx, false),
            // VPDPWSUDS (0xD3) - Multiply and Add Signed/Unsigned Word Integers with Saturation
            0xD3 if evex.pp == 2 && !evex.w => self.execute_vpdpwsud(ctx, true),
            // VPDPWUSD (0xD2) - Multiply and Add Unsigned/Signed Word Integers
            0xD2 if evex.pp == 1 && !evex.w => self.execute_vpdpwusd(ctx, false),
            // VPDPWUSDS (0xD3) - Multiply and Add Unsigned/Signed Word Integers with Saturation
            0xD3 if evex.pp == 1 && !evex.w => self.execute_vpdpwusd(ctx, true),
            // VPDPWUUD (0xD2) - Multiply and Add Unsigned Word Integers
            0xD2 if evex.pp == 0 && !evex.w => self.execute_vpdpwuud(ctx, false),
            // VPDPWUUDS (0xD3) - Multiply and Add Unsigned Word Integers with Saturation
            0xD3 if evex.pp == 0 && !evex.w => self.execute_vpdpwuud(ctx, true),

            _ => Err(Error::Emulator(format!(
                "Unimplemented EVEX.0F38 opcode {:#04x} (W={}) at RIP={:#x}",
                opcode, evex.w as u8, self.regs.rip
            ))),
        }
    }

    /// EVEX 0F3A opcode map (mm=3)
    fn execute_evex_0f3a(&mut self, ctx: &mut InsnContext, opcode: u8) -> Result<Option<VcpuExit>> {
        let evex = ctx
            .evex
            .ok_or_else(|| Error::Emulator("EVEX context missing".to_string()))?;

        match opcode {
            // ============================================================================
            // AVX10.2 VMPSADBW Instruction
            // ============================================================================

            // VMPSADBW (0x42) - Compute Multiple Packed Sums of Absolute Difference
            0x42 if evex.pp == 1 => self.execute_vmpsadbw(ctx),

            // ============================================================================
            // AVX10.2 VMINMAX Instructions
            // ============================================================================

            // VMINMAXPS (0x52) - Minimum/Maximum of Packed Single-Precision Floats
            0x52 if evex.pp == 0 && !evex.w => self.execute_vminmax_ps(ctx),
            // VMINMAXPD (0x52) - Minimum/Maximum of Packed Double-Precision Floats
            0x52 if evex.pp == 1 && evex.w => self.execute_vminmax_pd(ctx),
            // VMINMAXSS (0x53) - Minimum/Maximum of Scalar Single-Precision Float
            0x53 if evex.pp == 0 && !evex.w => self.execute_vminmax_ss(ctx),
            // VMINMAXSD (0x53) - Minimum/Maximum of Scalar Double-Precision Float
            0x53 if evex.pp == 1 && evex.w => self.execute_vminmax_sd(ctx),

            _ => Err(Error::Emulator(format!(
                "Unimplemented EVEX.0F3A opcode {:#04x} at RIP={:#x}",
                opcode, self.regs.rip
            ))),
        }
    }

    /// EVEX MAP5 opcode map (mm=5) - AVX-512 FP16 instructions
    fn execute_evex_map5(&mut self, ctx: &mut InsnContext, opcode: u8) -> Result<Option<VcpuExit>> {
        let evex = ctx
            .evex
            .ok_or_else(|| Error::Emulator("EVEX context missing".to_string()))?;

        // MAP5 instructions are FP16 (half-precision) arithmetic
        // pp=0 (NP), W=0 for packed FP16
        match opcode {
            // VADDPH (0x58)
            0x58 if evex.pp == 0 => self.execute_evex_fp16_arith(ctx, |a, b| a + b),
            // VMULPH (0x59)
            0x59 if evex.pp == 0 => self.execute_evex_fp16_arith(ctx, |a, b| a * b),
            // VSUBPH (0x5C)
            0x5C if evex.pp == 0 => self.execute_evex_fp16_arith(ctx, |a, b| a - b),
            // VDIVPH (0x5E)
            0x5E if evex.pp == 0 => self.execute_evex_fp16_arith(ctx, |a, b| a / b),
            _ => Err(Error::Emulator(format!(
                "Unimplemented EVEX.MAP5 opcode {:#04x} (pp={}) at RIP={:#x}",
                opcode, evex.pp, self.regs.rip
            ))),
        }
    }

    /// EVEX FP16 (half-precision) arithmetic (VADDPH, VSUBPH, VMULPH, VDIVPH)
    fn execute_evex_fp16_arith<F>(
        &mut self,
        ctx: &mut InsnContext,
        op: F,
    ) -> Result<Option<VcpuExit>>
    where
        F: Fn(f32, f32) -> f32,
    {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        // Destination register (5 bits)
        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        // Source1 from vvvv (inverted)
        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        // Vector length from L'L
        let vl = match evex.ll {
            0 => 16, // 128-bit (8 FP16 values)
            1 => 32, // 256-bit (16 FP16 values)
            2 => 64, // 512-bit (32 FP16 values)
            _ => 64,
        };

        // Number of FP16 elements (2 bytes each)
        let num_elems = vl / 2;

        // Load source2
        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        // Get source1
        let src1 = self.get_zmm_data(zmm_src1, vl);

        // Perform operation on each FP16 element
        let mut result = [0u8; 64];
        for i in 0..num_elems {
            // Convert FP16 to f32, perform operation, convert back to FP16
            let a_fp16 = u16::from_le_bytes([src1[i * 2], src1[i * 2 + 1]]);
            let b_fp16 = u16::from_le_bytes([src2[i * 2], src2[i * 2 + 1]]);
            let a = fp16_to_f32(a_fp16);
            let b = fp16_to_f32(b_fp16);
            let r = op(a, b);
            let r_fp16 = f32_to_fp16(r);
            let bytes = r_fp16.to_le_bytes();
            result[i * 2..i * 2 + 2].copy_from_slice(&bytes);
        }

        // Store result
        self.set_zmm_data(zmm_dst, &result[..vl], vl);

        // Zero upper bits if not 512-bit (for ZMM0-15)
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
    // AVX10.1 VNNI Instruction Implementations
    // ============================================================================

    /// VPDPBUSD/VPDPBUSDS - Multiply and Add Unsigned and Signed Bytes
    fn execute_vpdpbusd(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        // Destination/accumulator register
        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        // Source1 from vvvv (first multiplicand)
        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        // Vector length from L'L
        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_dwords = vl / 4;

        // Load source2
        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        // Process each dword
        for i in 0..num_dwords {
            let base = i * 4;
            // Each dword contains 4 bytes
            let mut sum = i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            for j in 0..4 {
                let a = src1[base + j] as u8 as i32;  // unsigned byte
                let b = src2[base + j] as i8 as i32;  // signed byte
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
    fn execute_vpdpwssd(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

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
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum = i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

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
    fn execute_vpmadd52(&mut self, ctx: &mut InsnContext, high: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_qwords = vl / 8;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_qwords {
            let base = i * 8;
            let a = u64::from_le_bytes([
                src1[base], src1[base + 1], src1[base + 2], src1[base + 3],
                src1[base + 4], src1[base + 5], src1[base + 6], src1[base + 7],
            ]) & 0x000F_FFFF_FFFF_FFFF; // 52-bit mask

            let b = u64::from_le_bytes([
                src2[base], src2[base + 1], src2[base + 2], src2[base + 3],
                src2[base + 4], src2[base + 5], src2[base + 6], src2[base + 7],
            ]) & 0x000F_FFFF_FFFF_FFFF;

            let d = u64::from_le_bytes([
                dst[base], dst[base + 1], dst[base + 2], dst[base + 3],
                dst[base + 4], dst[base + 5], dst[base + 6], dst[base + 7],
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
    // AVX10.1 VPOPCNTDQ Instruction Implementations
    // ============================================================================

    /// VPOPCNTB/W/D/Q - Population count for packed elements
    fn execute_vpopcnt(&mut self, ctx: &mut InsnContext, elem_size: usize) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src, vl)
        };

        let mut dst = [0u8; 64];
        let num_elems = vl / elem_size;

        for i in 0..num_elems {
            let base = i * elem_size;
            let mut count = 0u64;

            for j in 0..elem_size {
                count += src[base + j].count_ones() as u64;
            }

            match elem_size {
                1 => dst[base] = count as u8,
                2 => {
                    let bytes = (count as u16).to_le_bytes();
                    dst[base..base + 2].copy_from_slice(&bytes);
                }
                4 => {
                    let bytes = (count as u32).to_le_bytes();
                    dst[base..base + 4].copy_from_slice(&bytes);
                }
                8 => {
                    let bytes = count.to_le_bytes();
                    dst[base..base + 8].copy_from_slice(&bytes);
                }
                _ => {}
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
    // AVX10.1 VBMI Instruction Implementations
    // ============================================================================

    /// VPERMB - Permute Packed Bytes Elements
    fn execute_vpermb(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_idx = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src, vl)
        };

        let idx = self.get_zmm_data(zmm_idx, vl);
        let mut dst = [0u8; 64];

        for i in 0..vl {
            let index = (idx[i] as usize) % vl;
            dst[i] = src[index];
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

    /// VPERMI2B - Full Permute of Bytes from Two Tables Overwriting Index
    fn execute_vpermi2b(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_idx = if !evex.r { reg + 8 } else { reg };
        let zmm_idx = if !evex.r_prime { zmm_idx + 16 } else { zmm_idx } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let idx = self.get_zmm_data(zmm_idx, vl);

        let mut dst = [0u8; 64];
        let table_size = vl * 2;

        for i in 0..vl {
            let index = (idx[i] as usize) % table_size;
            dst[i] = if index < vl { src1[index] } else { src2[index - vl] };
        }

        self.set_zmm_data(zmm_idx, &dst[..vl], vl);

        if vl < 64 && zmm_idx < 16 {
            if vl <= 16 {
                self.regs.ymm_high[zmm_idx][0] = 0;
                self.regs.ymm_high[zmm_idx][1] = 0;
            }
            self.regs.zmm_high[zmm_idx] = [0; 4];
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VPERMT2B - Full Permute of Bytes from Two Tables Overwriting Table
    fn execute_vpermt2b(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_idx = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_dst, vl);
        let idx = self.get_zmm_data(zmm_idx, vl);

        let mut dst = [0u8; 64];
        let table_size = vl * 2;

        for i in 0..vl {
            let index = (idx[i] as usize) % table_size;
            dst[i] = if index < vl { src1[index] } else { src2[index - vl] };
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
    fn execute_vpshufbitqmb(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let k_dst = reg as usize & 0x7;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
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

        self.regs.k[k_dst] = result;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    // ============================================================================
    // AVX10.1 BF16 Instruction Implementations
    // ============================================================================

    /// VDPBF16PS - Dot Product of BF16 Pairs Accumulated into FP32
    fn execute_vdpbf16ps(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let num_floats = vl / 4;

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_floats {
            let base = i * 4;
            // Read accumulator as f32
            let acc = f32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]);

            // Two BF16 values per dword
            let a0 = bf16_to_f32(u16::from_le_bytes([src1[base], src1[base + 1]]));
            let b0 = bf16_to_f32(u16::from_le_bytes([src2[base], src2[base + 1]]));
            let a1 = bf16_to_f32(u16::from_le_bytes([src1[base + 2], src1[base + 3]]));
            let b1 = bf16_to_f32(u16::from_le_bytes([src2[base + 2], src2[base + 3]]));

            let result = acc + a0 * b0 + a1 * b1;
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

    /// VCVTNEPS2BF16 - Convert Packed Single-Precision to BF16
    fn execute_vcvtneps2bf16(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src, vl)
        };

        let num_floats = vl / 4;
        let dst_vl = vl / 2; // Output is half the size
        let mut dst = [0u8; 64];

        for i in 0..num_floats {
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src[src_base], src[src_base + 1], src[src_base + 2], src[src_base + 3],
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
    fn execute_vcvtne2ps2bf16(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);

        let num_floats = vl / 4;
        let mut dst = [0u8; 64];

        // First half from src2
        for i in 0..num_floats {
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src2[src_base], src2[src_base + 1], src2[src_base + 2], src2[src_base + 3],
            ]);
            let bf16 = f32_to_bf16(f);
            let dst_base = i * 2;
            let bytes = bf16.to_le_bytes();
            dst[dst_base..dst_base + 2].copy_from_slice(&bytes);
        }

        // Second half from src1
        for i in 0..num_floats {
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src1[src_base], src1[src_base + 1], src1[src_base + 2], src1[src_base + 3],
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
    // AVX10.2 VMPSADBW Instruction Implementation
    // ============================================================================

    /// VMPSADBW - Compute Multiple Packed Sums of Absolute Difference
    fn execute_vmpsadbw(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = [0u8; 64];

        // Process 128-bit lanes
        // imm8 encoding: bits [2:0] select src1 offset, bits [5:3] select src2 offset
        // Each lane uses the same block selection from imm8
        let num_lanes = vl / 16;
        let src1_blk = (imm8 & 0x3) as usize;  // bits [1:0]
        let src2_blk = ((imm8 >> 2) & 0x3) as usize;  // bits [3:2]

        for lane in 0..num_lanes {
            let lane_base = lane * 16;

            // Source block offsets within the lane
            let src1_offset = lane_base + (src1_blk * 4);

            // Calculate 8 SAD values per lane
            for i in 0..8 {
                let mut sad: u16 = 0;
                // src2 uses a sliding window of 4 consecutive bytes starting at blk2*4 + i
                let src2_start = lane_base + (src2_blk * 4) + i;
                for j in 0..4 {
                    let a = src1[src1_offset + j] as i16;
                    let b_idx = src2_start + j;
                    // Handle wrap-around within lane
                    let b = if b_idx < lane_base + 16 {
                        src2[b_idx] as i16
                    } else {
                        0  // Zero-pad beyond lane boundary
                    };
                    sad += (a - b).unsigned_abs();
                }
                let dst_offset = lane_base + i * 2;
                let bytes = sad.to_le_bytes();
                dst[dst_offset..dst_offset + 2].copy_from_slice(&bytes);
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
    fn execute_vminmax_ps(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = [0u8; 64];

        let num_elems = vl / 4;
        let is_min = (imm8 & 0x1) == 0;

        for i in 0..num_elems {
            let base = i * 4;
            let a = f32::from_le_bytes([src1[base], src1[base + 1], src1[base + 2], src1[base + 3]]);
            let b = f32::from_le_bytes([src2[base], src2[base + 1], src2[base + 2], src2[base + 3]]);

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
    fn execute_vminmax_pd(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src2 = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = [0u8; 64];

        let num_elems = vl / 8;
        let is_min = (imm8 & 0x1) == 0;

        for i in 0..num_elems {
            let base = i * 8;
            let a = f64::from_le_bytes([
                src1[base], src1[base + 1], src1[base + 2], src1[base + 3],
                src1[base + 4], src1[base + 5], src1[base + 6], src1[base + 7],
            ]);
            let b = f64::from_le_bytes([
                src2[base], src2[base + 1], src2[base + 2], src2[base + 3],
                src2[base + 4], src2[base + 5], src2[base + 6], src2[base + 7],
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
    fn execute_vminmax_ss(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let b_val = if is_memory {
            let bytes = self.load_zmm_data(addr, 4)?;
            f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            let src2 = self.get_zmm_data(zmm_src2, 16);
            f32::from_le_bytes([src2[0], src2[1], src2[2], src2[3]])
        };

        let src1 = self.get_zmm_data(zmm_src1, 16);
        let a_val = f32::from_le_bytes([src1[0], src1[1], src1[2], src1[3]]);

        let is_min = (imm8 & 0x1) == 0;
        let result = if is_min { a_val.min(b_val) } else { a_val.max(b_val) };

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
    fn execute_vminmax_sd(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

        let b_val = if is_memory {
            let bytes = self.load_zmm_data(addr, 8)?;
            f64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        } else {
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            let src2 = self.get_zmm_data(zmm_src2, 16);
            f64::from_le_bytes([
                src2[0], src2[1], src2[2], src2[3],
                src2[4], src2[5], src2[6], src2[7],
            ])
        };

        let src1 = self.get_zmm_data(zmm_src1, 16);
        let a_val = f64::from_le_bytes([
            src1[0], src1[1], src1[2], src1[3],
            src1[4], src1[5], src1[6], src1[7],
        ]);

        let is_min = (imm8 & 0x1) == 0;
        let result = if is_min { a_val.min(b_val) } else { a_val.max(b_val) };

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
    // AVX10.2 Saturation Conversion Instruction Implementations
    // ============================================================================

    /// VCVTTPS2IBS - Convert with Truncation Packed Single to Signed Byte with Saturation
    fn execute_vcvttps2ibs(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src, vl)
        };

        let num_floats = vl / 4;
        let dst_vl = vl / 4; // Output is 1/4 the size
        let mut dst = [0u8; 64];

        for i in 0..num_floats {
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src[src_base], src[src_base + 1], src[src_base + 2], src[src_base + 3],
            ]);
            // Truncate and saturate to i8
            let val = f.trunc() as i32;
            let saturated = val.clamp(i8::MIN as i32, i8::MAX as i32) as i8;
            dst[i] = saturated as u8;
        }

        self.set_zmm_data(zmm_dst, &dst[..dst_vl], dst_vl);

        // Zero upper bits
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

    /// VCVTTPS2IUBS - Convert with Truncation Packed Single to Unsigned Byte with Saturation
    fn execute_vcvttps2iubs(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src, vl)
        };

        let num_floats = vl / 4;
        let dst_vl = vl / 4;
        let mut dst = [0u8; 64];

        for i in 0..num_floats {
            let src_base = i * 4;
            let f = f32::from_le_bytes([
                src[src_base], src[src_base + 1], src[src_base + 2], src[src_base + 3],
            ]);
            // Truncate and saturate to u8
            let val = f.trunc() as i32;
            let saturated = val.clamp(0, u8::MAX as i32) as u8;
            dst[i] = saturated;
        }

        self.set_zmm_data(zmm_dst, &dst[..dst_vl], dst_vl);

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

    /// VCVTTPD2QQS - Convert with Truncation Packed Double to Signed Qword with Saturation
    fn execute_vcvttpd2qqs(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src, vl)
        };

        let num_doubles = vl / 8;
        let mut dst = [0u8; 64];

        for i in 0..num_doubles {
            let base = i * 8;
            let f = f64::from_le_bytes([
                src[base], src[base + 1], src[base + 2], src[base + 3],
                src[base + 4], src[base + 5], src[base + 6], src[base + 7],
            ]);
            // Truncate and saturate to i64
            let val = f.trunc();
            let saturated = if val >= i64::MAX as f64 {
                i64::MAX
            } else if val <= i64::MIN as f64 {
                i64::MIN
            } else {
                val as i64
            };
            let bytes = saturated.to_le_bytes();
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

    /// VCVTTPD2UQQS - Convert with Truncation Packed Double to Unsigned Qword with Saturation
    fn execute_vcvttpd2uqqs(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let vl = match evex.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };

        let src = if is_memory {
            self.load_zmm_data(addr, vl)?
        } else {
            let zmm_src = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src, vl)
        };

        let num_doubles = vl / 8;
        let mut dst = [0u8; 64];

        for i in 0..num_doubles {
            let base = i * 8;
            let f = f64::from_le_bytes([
                src[base], src[base + 1], src[base + 2], src[base + 3],
                src[base + 4], src[base + 5], src[base + 6], src[base + 7],
            ]);
            // Truncate and saturate to u64
            let val = f.trunc();
            let saturated = if val >= u64::MAX as f64 {
                u64::MAX
            } else if val < 0.0 {
                0
            } else {
                val as u64
            };
            let bytes = saturated.to_le_bytes();
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
    // AVX10.2 Media Acceleration Instruction Implementations
    // ============================================================================

    /// VPDPBSSD/VPDPBSSDS - Multiply and Add Signed Byte Integers
    fn execute_vpdpbssd(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

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
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum = i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            for j in 0..4 {
                let a = src1[base + j] as i8 as i32;  // signed byte
                let b = src2[base + j] as i8 as i32;  // signed byte
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
    fn execute_vpdpbsud(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

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
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum = i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            for j in 0..4 {
                let a = src1[base + j] as i8 as i32;   // signed byte
                let b = src2[base + j] as u8 as i32;  // unsigned byte
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
    fn execute_vpdpbuud(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

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
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum = u32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as u64;

            for j in 0..4 {
                let a = src1[base + j] as u32;  // unsigned byte
                let b = src2[base + j] as u32;  // unsigned byte
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
    fn execute_vpdpwsud(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

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
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum = i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            // Two pairs of words per dword
            let a0 = i16::from_le_bytes([src1[base], src1[base + 1]]) as i32;       // signed
            let b0 = u16::from_le_bytes([src2[base], src2[base + 1]]) as i32;       // unsigned
            let a1 = i16::from_le_bytes([src1[base + 2], src1[base + 3]]) as i32;   // signed
            let b1 = u16::from_le_bytes([src2[base + 2], src2[base + 3]]) as i32;   // unsigned

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
    fn execute_vpdpwusd(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

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
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum = i32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as i64;

            // Two pairs of words per dword
            let a0 = u16::from_le_bytes([src1[base], src1[base + 1]]) as i32;       // unsigned
            let b0 = i16::from_le_bytes([src2[base], src2[base + 1]]) as i32;       // signed
            let a1 = u16::from_le_bytes([src1[base + 2], src1[base + 3]]) as i32;   // unsigned
            let b1 = i16::from_le_bytes([src2[base + 2], src2[base + 3]]) as i32;   // signed

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
    fn execute_vpdpwuud(&mut self, ctx: &mut InsnContext, saturate: bool) -> Result<Option<VcpuExit>> {
        let evex = ctx.evex.unwrap();
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;

        let zmm_dst = if !evex.r { reg + 8 } else { reg };
        let zmm_dst = if !evex.r_prime { zmm_dst + 16 } else { zmm_dst } as usize;

        let zmm_src1 = (evex.vvvv ^ 0xF) as usize;

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
            let zmm_src2 = if !evex.b { rm + 8 } else { rm } as usize;
            self.get_zmm_data(zmm_src2, vl)
        };

        let src1 = self.get_zmm_data(zmm_src1, vl);
        let mut dst = self.get_zmm_data(zmm_dst, vl);

        for i in 0..num_dwords {
            let base = i * 4;
            let mut sum = u32::from_le_bytes([dst[base], dst[base + 1], dst[base + 2], dst[base + 3]]) as u64;

            // Two pairs of words per dword
            let a0 = u16::from_le_bytes([src1[base], src1[base + 1]]) as u32;       // unsigned
            let b0 = u16::from_le_bytes([src2[base], src2[base + 1]]) as u32;       // unsigned
            let a1 = u16::from_le_bytes([src1[base + 2], src1[base + 3]]) as u32;   // unsigned
            let b1 = u16::from_le_bytes([src2[base + 2], src2[base + 3]]) as u32;   // unsigned

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
}

/// Convert IEEE 754 half-precision (FP16) to single-precision (f32)
fn fp16_to_f32(h: u16) -> f32 {
    let sign = ((h >> 15) & 1) as u32;
    let exp = ((h >> 10) & 0x1F) as u32;
    let mant = (h & 0x3FF) as u32;

    let f32_bits = if exp == 0 {
        if mant == 0 {
            // Zero (preserve sign)
            sign << 31
        } else {
            // Denormalized number - normalize it
            let mut m = mant;
            let mut e = 0i32;
            while (m & 0x400) == 0 {
                m <<= 1;
                e += 1;
            }
            m &= 0x3FF; // Remove implicit bit
            let new_exp = (127 - 15 - e) as u32;
            (sign << 31) | (new_exp << 23) | (m << 13)
        }
    } else if exp == 0x1F {
        // Infinity or NaN
        (sign << 31) | (0xFF << 23) | (mant << 13)
    } else {
        // Normalized number
        // FP16 exponent bias is 15, f32 is 127
        let new_exp = exp + 127 - 15;
        (sign << 31) | (new_exp << 23) | (mant << 13)
    };

    f32::from_bits(f32_bits)
}

/// Convert single-precision (f32) to IEEE 754 half-precision (FP16)
fn f32_to_fp16(f: f32) -> u16 {
    let bits = f.to_bits();
    let sign = ((bits >> 31) & 1) as u16;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let mant = (bits & 0x7FFFFF) as u32;

    if exp == 0xFF {
        // Infinity or NaN
        if mant == 0 {
            // Infinity
            (sign << 15) | (0x1F << 10)
        } else {
            // NaN - preserve some mantissa bits
            (sign << 15) | (0x1F << 10) | ((mant >> 13) as u16 & 0x3FF).max(1)
        }
    } else if exp == 0 {
        // Zero or denormalized f32 (becomes zero in FP16)
        sign << 15
    } else {
        // Normalized number
        let new_exp = exp - 127 + 15;
        if new_exp >= 0x1F {
            // Overflow - return infinity
            (sign << 15) | (0x1F << 10)
        } else if new_exp <= 0 {
            // Underflow - return zero or denormalized
            if new_exp < -10 {
                // Too small, return zero
                sign << 15
            } else {
                // Denormalized
                let shift = 1 - new_exp;
                let m = (0x800000 | mant) >> (13 + shift);
                (sign << 15) | (m as u16 & 0x3FF)
            }
        } else {
            // Normal case
            let new_mant = (mant >> 13) as u16;
            (sign << 15) | ((new_exp as u16) << 10) | (new_mant & 0x3FF)
        }
    }
}

/// Convert BFloat16 (BF16) to single-precision (f32)
fn bf16_to_f32(bf: u16) -> f32 {
    // BF16 is simply the upper 16 bits of f32
    f32::from_bits((bf as u32) << 16)
}

/// Convert single-precision (f32) to BFloat16 (BF16)
fn f32_to_bf16(f: f32) -> u16 {
    // BF16 is the upper 16 bits of f32 with round-to-nearest-even
    let bits = f.to_bits();

    // Check for NaN and preserve signaling NaN
    if (bits & 0x7FFFFFFF) > 0x7F800000 {
        // NaN - ensure we keep a non-zero mantissa
        return ((bits >> 16) as u16) | 0x0040;
    }

    // Round to nearest even
    let rounding_bias = 0x7FFF + ((bits >> 16) & 1);
    ((bits.wrapping_add(rounding_bias)) >> 16) as u16
}

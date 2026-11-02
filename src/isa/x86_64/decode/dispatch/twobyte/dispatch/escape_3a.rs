//! Two-byte opcode instruction implementation for x86_64 emulator.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use super::super::super::{x86_dppd_lane_result_bits, x86_dpps_lane_result_bits};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute;
use crate::isa::x86_64::execute::crypto::aes;
use crate::isa::x86_64::execute::crypto::sha;
use crate::isa::x86_64::execute::simd::pcmpxstrx;

impl X86_64Vcpu {
    #[inline(always)]
    pub(in crate::isa::x86_64) fn execute_0f3a(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        let opcode3 = ctx.consume_u8()?;
        // Every legacy 0F3A instruction has a trailing imm8.
        ctx.rip_relative_offset = super::super::super::immediate_len(0x3, opcode3);
        if self.reject_rex2_for_legacy_simd(ctx)? {
            return Ok(None);
        }

        // Record precise opcode key for profiling
        #[cfg(feature = "profiling")]
        crate::observability::profiling::set_current_opcode_key(
            crate::observability::profiling::OpcodeKey::ThreeByte3A(opcode3),
        );

        match opcode3 {
            // ROUNDPS - Round Packed Single Precision Floating-Point Values (0x08)
            0x08 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };

                // Round mode from imm8[1:0]: 0=nearest-even, 1=floor, 2=ceil, 3=truncate.
                // Mode 0 is round-to-nearest with ties to EVEN (banker's rounding),
                // NOT Rust's `f32::round` which rounds half AWAY from zero.
                let round_mode = if (imm8 & 0x04) != 0 {
                    ((self.mxcsr >> 13) & 0x03) as u8
                } else {
                    imm8 & 0x03
                };
                let round_fn = |v: f32| -> f32 {
                    match round_mode {
                        0 => v.round_ties_even(),
                        1 => v.floor(),
                        2 => v.ceil(),
                        3 => v.trunc(),
                        _ => v,
                    }
                };

                let s0 = f32::from_bits(src_lo as u32);
                let s1 = f32::from_bits((src_lo >> 32) as u32);
                let s2 = f32::from_bits(src_hi as u32);
                let s3 = f32::from_bits((src_hi >> 32) as u32);

                let r0 = round_fn(s0).to_bits();
                let r1 = round_fn(s1).to_bits();
                let r2 = round_fn(s2).to_bits();
                let r3 = round_fn(s3).to_bits();

                self.regs.xmm[xmm_dst][0] = (r0 as u64) | ((r1 as u64) << 32);
                self.regs.xmm[xmm_dst][1] = (r2 as u64) | ((r3 as u64) << 32);
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // ROUNDPD - Round Packed Double Precision Floating-Point Values (0x09)
            0x09 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };

                let round_mode = if (imm8 & 0x04) != 0 {
                    ((self.mxcsr >> 13) & 0x03) as u8
                } else {
                    imm8 & 0x03
                };
                let round_fn = |v: f64| -> f64 {
                    match round_mode {
                        0 => v.round_ties_even(),
                        1 => v.floor(),
                        2 => v.ceil(),
                        3 => v.trunc(),
                        _ => v,
                    }
                };

                let s0 = f64::from_bits(src_lo);
                let s1 = f64::from_bits(src_hi);

                self.regs.xmm[xmm_dst][0] = round_fn(s0).to_bits();
                self.regs.xmm[xmm_dst][1] = round_fn(s1).to_bits();
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // ROUNDSS - Round Scalar Single Precision Floating-Point (0x0A)
            0x0A => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let src = if is_memory {
                    self.read_mem(addr, 4)? as u32
                } else {
                    self.regs.xmm[rm as usize][0] as u32
                };

                let round_mode = if (imm8 & 0x04) != 0 {
                    ((self.mxcsr >> 13) & 0x03) as u8
                } else {
                    imm8 & 0x03
                };
                let v = f32::from_bits(src);
                let result = match round_mode {
                    0 => v.round_ties_even(),
                    1 => v.floor(),
                    2 => v.ceil(),
                    3 => v.trunc(),
                    _ => v,
                };

                // Only update the low 32 bits, keep the rest
                self.regs.xmm[xmm_dst][0] =
                    (self.regs.xmm[xmm_dst][0] & 0xFFFF_FFFF_0000_0000) | (result.to_bits() as u64);
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // ROUNDSD - Round Scalar Double Precision Floating-Point (0x0B)
            0x0B => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let src = if is_memory {
                    self.read_mem(addr, 8)?
                } else {
                    self.regs.xmm[rm as usize][0]
                };

                let round_mode = if (imm8 & 0x04) != 0 {
                    ((self.mxcsr >> 13) & 0x03) as u8
                } else {
                    imm8 & 0x03
                };
                let v = f64::from_bits(src);
                let result = match round_mode {
                    0 => v.round_ties_even(),
                    1 => v.floor(),
                    2 => v.ceil(),
                    3 => v.trunc(),
                    _ => v,
                };

                // Only update the low 64 bits, keep xmm[1] unchanged
                self.regs.xmm[xmm_dst][0] = result.to_bits();
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // BLENDPS - Blend Packed Single Precision Floating-Point Values (0x0C)
            0x0C => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm_dst][0];
                let dst_hi = self.regs.xmm[xmm_dst][1];

                // Each bit in imm8[3:0] selects src (1) or dst (0) for each 32-bit element
                let r0 = if imm8 & 0x01 != 0 {
                    src_lo & 0xFFFF_FFFF
                } else {
                    dst_lo & 0xFFFF_FFFF
                };
                let r1 = if imm8 & 0x02 != 0 {
                    src_lo & 0xFFFF_FFFF_0000_0000
                } else {
                    dst_lo & 0xFFFF_FFFF_0000_0000
                };
                let r2 = if imm8 & 0x04 != 0 {
                    src_hi & 0xFFFF_FFFF
                } else {
                    dst_hi & 0xFFFF_FFFF
                };
                let r3 = if imm8 & 0x08 != 0 {
                    src_hi & 0xFFFF_FFFF_0000_0000
                } else {
                    dst_hi & 0xFFFF_FFFF_0000_0000
                };

                self.regs.xmm[xmm_dst][0] = r0 | r1;
                self.regs.xmm[xmm_dst][1] = r2 | r3;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // BLENDPD - Blend Packed Double Precision Floating-Point Values (0x0D)
            0x0D => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm_dst][0];
                let dst_hi = self.regs.xmm[xmm_dst][1];

                // imm8[0] selects low qword, imm8[1] selects high qword
                self.regs.xmm[xmm_dst][0] = if imm8 & 0x01 != 0 { src_lo } else { dst_lo };
                self.regs.xmm[xmm_dst][1] = if imm8 & 0x02 != 0 { src_hi } else { dst_hi };
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PBLENDW - Blend Packed Words (0x0E)
            0x0E => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm_dst][0];
                let dst_hi = self.regs.xmm[xmm_dst][1];

                // Each bit in imm8 selects one of 8 words
                let mut result_lo = 0u64;
                let mut result_hi = 0u64;
                for i in 0..4 {
                    let mask = 0xFFFFu64 << (i * 16);
                    if imm8 & (1 << i) != 0 {
                        result_lo |= src_lo & mask;
                    } else {
                        result_lo |= dst_lo & mask;
                    }
                }
                for i in 0..4 {
                    let mask = 0xFFFFu64 << (i * 16);
                    if imm8 & (1 << (i + 4)) != 0 {
                        result_hi |= src_hi & mask;
                    } else {
                        result_hi |= dst_hi & mask;
                    }
                }
                self.regs.xmm[xmm_dst][0] = result_lo;
                self.regs.xmm[xmm_dst][1] = result_hi;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PALIGNR - Packed Align Right (0x0F)
            0x0F => {
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;

                if ctx.operand_size_override {
                    // XMM version: concatenate dst:src (256 bits), shift right by imm8 bytes.
                    let xmm_dst = reg as usize;
                    let (src_lo, src_hi) = if is_memory {
                        (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                    } else {
                        (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                    };
                    let dst_lo = self.regs.xmm[xmm_dst][0];
                    let dst_hi = self.regs.xmm[xmm_dst][1];

                    let shift = (imm8 as usize) * 8;
                    if shift >= 256 {
                        self.regs.xmm[xmm_dst][0] = 0;
                        self.regs.xmm[xmm_dst][1] = 0;
                    } else if shift == 0 {
                        self.regs.xmm[xmm_dst][0] = src_lo;
                        self.regs.xmm[xmm_dst][1] = src_hi;
                    } else if shift >= 128 {
                        // Shift only uses dst bits
                        let s = shift - 128;
                        if s >= 64 {
                            self.regs.xmm[xmm_dst][0] = dst_hi >> (s - 64);
                            self.regs.xmm[xmm_dst][1] = 0;
                        } else if s > 0 {
                            self.regs.xmm[xmm_dst][0] = (dst_lo >> s) | (dst_hi << (64 - s));
                            self.regs.xmm[xmm_dst][1] = dst_hi >> s;
                        } else {
                            self.regs.xmm[xmm_dst][0] = dst_lo;
                            self.regs.xmm[xmm_dst][1] = dst_hi;
                        }
                    } else if shift >= 64 {
                        // Crosses from src to dst
                        let s = shift - 64;
                        if s > 0 {
                            self.regs.xmm[xmm_dst][0] = (src_hi >> s) | (dst_lo << (64 - s));
                            self.regs.xmm[xmm_dst][1] = (dst_lo >> s) | (dst_hi << (64 - s));
                        } else {
                            self.regs.xmm[xmm_dst][0] = src_hi;
                            self.regs.xmm[xmm_dst][1] = dst_lo;
                        }
                    } else if shift > 0 {
                        // Shift within src part
                        self.regs.xmm[xmm_dst][0] = (src_lo >> shift) | (src_hi << (64 - shift));
                        self.regs.xmm[xmm_dst][1] = (src_hi >> shift) | (dst_lo << (64 - shift));
                    }
                } else {
                    // MMX version: concatenate dst:src (128 bits), shift right by imm8 bytes
                    let mm_dst = reg as usize & 0x7;
                    let src = if is_memory {
                        self.read_mem(addr, 8)?
                    } else {
                        self.regs.mm[rm as usize & 0x7]
                    };
                    let dst = self.regs.mm[mm_dst];

                    let shift = (imm8 as usize) * 8;
                    if shift >= 128 {
                        self.regs.mm[mm_dst] = 0;
                    } else if shift == 0 {
                        self.regs.mm[mm_dst] = src;
                    } else if shift >= 64 {
                        self.regs.mm[mm_dst] = dst >> (shift - 64);
                    } else if shift > 0 {
                        self.regs.mm[mm_dst] = (src >> shift) | (dst << (64 - shift));
                    }
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PEXTRB - Extract Byte (0x14)
            0x14 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_src = reg as usize;
                let idx = (imm8 & 0x0F) as usize;

                // Get byte from XMM register
                let byte = if idx < 8 {
                    ((self.regs.xmm[xmm_src][0] >> (idx * 8)) & 0xFF) as u8
                } else {
                    ((self.regs.xmm[xmm_src][1] >> ((idx - 8) * 8)) & 0xFF) as u8
                };

                if is_memory {
                    self.write_mem(addr, byte as u64, 1)?;
                } else {
                    // Zero-extend to 32/64 bit register
                    let dest_size = if ctx.rex_w() { 8 } else { 4 };
                    self.set_reg(rm, byte as u64, dest_size);
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PEXTRW - Extract Word (0x15) - note: this is actually in 0F C5, but 0F 3A 15 also exists
            0x15 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_src = reg as usize;
                let idx = (imm8 & 0x07) as usize;

                let word = if idx < 4 {
                    ((self.regs.xmm[xmm_src][0] >> (idx * 16)) & 0xFFFF) as u16
                } else {
                    ((self.regs.xmm[xmm_src][1] >> ((idx - 4) * 16)) & 0xFFFF) as u16
                };

                if is_memory {
                    self.write_mem(addr, word as u64, 2)?;
                } else {
                    let dest_size = if ctx.rex_w() { 8 } else { 4 };
                    self.set_reg(rm, word as u64, dest_size);
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PEXTRD/PEXTRQ - Extract Dword/Qword (0x16)
            0x16 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_src = reg as usize;

                if ctx.rex_w() {
                    // PEXTRQ - extract qword
                    let idx = (imm8 & 0x01) as usize;
                    let value = self.regs.xmm[xmm_src][idx];
                    if is_memory {
                        self.write_mem(addr, value, 8)?;
                    } else {
                        self.set_reg(rm, value, 8);
                    }
                } else {
                    // PEXTRD - extract dword
                    let idx = (imm8 & 0x03) as usize;
                    let value = if idx < 2 {
                        ((self.regs.xmm[xmm_src][0] >> (idx * 32)) & 0xFFFF_FFFF) as u32
                    } else {
                        ((self.regs.xmm[xmm_src][1] >> ((idx - 2) * 32)) & 0xFFFF_FFFF) as u32
                    };
                    if is_memory {
                        self.write_mem(addr, value as u64, 4)?;
                    } else {
                        self.set_reg(rm, value as u64, 4);
                    }
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // EXTRACTPS - Extract Packed Single Precision Floating-Point (0x17)
            0x17 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_src = reg as usize;
                let idx = (imm8 & 0x03) as usize;

                let value = if idx < 2 {
                    ((self.regs.xmm[xmm_src][0] >> (idx * 32)) & 0xFFFF_FFFF) as u32
                } else {
                    ((self.regs.xmm[xmm_src][1] >> ((idx - 2) * 32)) & 0xFFFF_FFFF) as u32
                };

                if is_memory {
                    self.write_mem(addr, value as u64, 4)?;
                } else {
                    self.set_reg(rm, value as u64, 4);
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PINSRB - Insert Byte (0x20)
            0x20 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let idx = (imm8 & 0x0F) as usize;

                let byte = if is_memory {
                    self.read_mem(addr, 1)? as u8
                } else {
                    self.get_reg(rm, 1) as u8
                };

                // Insert byte at position idx
                if idx < 8 {
                    let mask = !(0xFFu64 << (idx * 8));
                    self.regs.xmm[xmm_dst][0] =
                        (self.regs.xmm[xmm_dst][0] & mask) | ((byte as u64) << (idx * 8));
                } else {
                    let pos = idx - 8;
                    let mask = !(0xFFu64 << (pos * 8));
                    self.regs.xmm[xmm_dst][1] =
                        (self.regs.xmm[xmm_dst][1] & mask) | ((byte as u64) << (pos * 8));
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // INSERTPS - Insert Packed Single Precision Floating-Point (0x21)
            0x21 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;

                // imm8[7:6] = count_s (source element select for register source)
                // imm8[5:4] = count_d (destination element)
                // imm8[3:0] = zmask (zero mask)
                let count_s = ((imm8 >> 6) & 0x03) as usize;
                let count_d = ((imm8 >> 4) & 0x03) as usize;
                let zmask = imm8 & 0x0F;

                // Get source value
                let src_val = if is_memory {
                    self.read_mem(addr, 4)? as u32
                } else {
                    let xmm_src = rm as usize;
                    if count_s < 2 {
                        ((self.regs.xmm[xmm_src][0] >> (count_s * 32)) & 0xFFFF_FFFF) as u32
                    } else {
                        ((self.regs.xmm[xmm_src][1] >> ((count_s - 2) * 32)) & 0xFFFF_FFFF) as u32
                    }
                };

                // Insert into destination position
                if count_d < 2 {
                    let mask = !(0xFFFF_FFFFu64 << (count_d * 32));
                    self.regs.xmm[xmm_dst][0] =
                        (self.regs.xmm[xmm_dst][0] & mask) | ((src_val as u64) << (count_d * 32));
                } else {
                    let pos = count_d - 2;
                    let mask = !(0xFFFF_FFFFu64 << (pos * 32));
                    self.regs.xmm[xmm_dst][1] =
                        (self.regs.xmm[xmm_dst][1] & mask) | ((src_val as u64) << (pos * 32));
                }

                // Apply zero mask
                for i in 0..4 {
                    if zmask & (1 << i) != 0 {
                        if i < 2 {
                            self.regs.xmm[xmm_dst][0] &= !(0xFFFF_FFFFu64 << (i * 32));
                        } else {
                            self.regs.xmm[xmm_dst][1] &= !(0xFFFF_FFFFu64 << ((i - 2) * 32));
                        }
                    }
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PINSRD/PINSRQ - Insert Dword/Qword (0x22)
            0x22 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;

                if ctx.rex_w() {
                    // PINSRQ - insert qword
                    let idx = (imm8 & 0x01) as usize;
                    let value = if is_memory {
                        self.read_mem(addr, 8)?
                    } else {
                        self.get_reg(rm, 8)
                    };
                    self.regs.xmm[xmm_dst][idx] = value;
                } else {
                    // PINSRD - insert dword
                    let idx = (imm8 & 0x03) as usize;
                    let value = if is_memory {
                        self.read_mem(addr, 4)? as u32
                    } else {
                        self.get_reg(rm, 4) as u32
                    };

                    if idx < 2 {
                        let mask = !(0xFFFF_FFFFu64 << (idx * 32));
                        self.regs.xmm[xmm_dst][0] =
                            (self.regs.xmm[xmm_dst][0] & mask) | ((value as u64) << (idx * 32));
                    } else {
                        let pos = idx - 2;
                        let mask = !(0xFFFF_FFFFu64 << (pos * 32));
                        self.regs.xmm[xmm_dst][1] =
                            (self.regs.xmm[xmm_dst][1] & mask) | ((value as u64) << (pos * 32));
                    }
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // DPPS - Dot Product of Packed Single Precision Floating-Point (0x40)
            0x40 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm_dst][0];
                let dst_hi = self.regs.xmm[xmm_dst][1];

                // imm8[7:4] = input mask, imm8[3:0] = output mask
                let in_mask = (imm8 >> 4) & 0x0F;
                let out_mask = imm8 & 0x0F;

                // Store result with output mask
                let dst = [
                    dst_lo as u32,
                    (dst_lo >> 32) as u32,
                    dst_hi as u32,
                    (dst_hi >> 32) as u32,
                ];
                let src = [
                    src_lo as u32,
                    (src_lo >> 32) as u32,
                    src_hi as u32,
                    (src_hi >> 32) as u32,
                ];
                let r0 = if out_mask & 0x01 != 0 {
                    x86_dpps_lane_result_bits(dst, src, in_mask, 0)
                } else {
                    0
                };
                let r1 = if out_mask & 0x02 != 0 {
                    x86_dpps_lane_result_bits(dst, src, in_mask, 1)
                } else {
                    0
                };
                let r2 = if out_mask & 0x04 != 0 {
                    x86_dpps_lane_result_bits(dst, src, in_mask, 2)
                } else {
                    0
                };
                let r3 = if out_mask & 0x08 != 0 {
                    x86_dpps_lane_result_bits(dst, src, in_mask, 3)
                } else {
                    0
                };

                self.regs.xmm[xmm_dst][0] = (r0 as u64) | ((r1 as u64) << 32);
                self.regs.xmm[xmm_dst][1] = (r2 as u64) | ((r3 as u64) << 32);
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // DPPD - Dot Product of Packed Double Precision Floating-Point (0x41)
            0x41 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm_dst][0];
                let dst_hi = self.regs.xmm[xmm_dst][1];

                // imm8[5:4] = input mask, imm8[1:0] = output mask
                let in_mask = (imm8 >> 4) & 0x03;
                let out_mask = imm8 & 0x03;

                let dst = [dst_lo, dst_hi];
                let src = [src_lo, src_hi];
                self.regs.xmm[xmm_dst][0] = if out_mask & 0x01 != 0 {
                    x86_dppd_lane_result_bits(dst, src, in_mask, 0)
                } else {
                    0
                };
                self.regs.xmm[xmm_dst][1] = if out_mask & 0x02 != 0 {
                    x86_dppd_lane_result_bits(dst, src, in_mask, 1)
                } else {
                    0
                };
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // MPSADBW - Multiple Sum of Absolute Differences (0x42)
            0x42 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm_dst][0];
                let dst_hi = self.regs.xmm[xmm_dst][1];

                // imm8[1:0] selects source block offset (0, 4, 8, or 12 bytes)
                // imm8[2] selects destination block offset (0 or 4 bytes)
                let src_offset = ((imm8 & 0x03) * 4) as usize;
                let dst_offset = if imm8 & 0x04 != 0 { 4 } else { 0 };

                // Get source bytes (need 4 consecutive bytes starting at src_offset)
                let get_src_byte = |idx: usize| -> u8 {
                    let actual_idx = src_offset + idx;
                    if actual_idx < 8 {
                        ((src_lo >> (actual_idx * 8)) & 0xFF) as u8
                    } else {
                        ((src_hi >> ((actual_idx - 8) * 8)) & 0xFF) as u8
                    }
                };

                // Get destination bytes
                let get_dst_byte = |idx: usize| -> u8 {
                    if idx < 8 {
                        ((dst_lo >> (idx * 8)) & 0xFF) as u8
                    } else {
                        ((dst_hi >> ((idx - 8) * 8)) & 0xFF) as u8
                    }
                };

                // Compute 8 SADs
                let mut results = [0u16; 8];
                for i in 0..8 {
                    let mut sad = 0u16;
                    for j in 0..4 {
                        let s = get_src_byte(j) as i16;
                        let d = get_dst_byte(dst_offset + i + j) as i16;
                        sad += (s - d).unsigned_abs();
                    }
                    results[i] = sad;
                }

                self.regs.xmm[xmm_dst][0] = (results[0] as u64)
                    | ((results[1] as u64) << 16)
                    | ((results[2] as u64) << 32)
                    | ((results[3] as u64) << 48);
                self.regs.xmm[xmm_dst][1] = (results[4] as u64)
                    | ((results[5] as u64) << 16)
                    | ((results[6] as u64) << 32)
                    | ((results[7] as u64) << 48);
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PCLMULQDQ - Carry-Less Multiplication Quadword (0x44)
            0x44 => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm_dst][0];
                let dst_hi = self.regs.xmm[xmm_dst][1];

                // imm8[0] selects which qword from dst, imm8[4] selects which qword from src
                let a = if imm8 & 0x01 != 0 { dst_hi } else { dst_lo };
                let b = if imm8 & 0x10 != 0 { src_hi } else { src_lo };

                // Carry-less multiplication (XOR instead of add in polynomial multiplication)
                let mut result_lo = 0u64;
                let mut result_hi = 0u64;

                for i in 0..64 {
                    if (b >> i) & 1 != 0 {
                        // XOR a shifted left by i
                        if i == 0 {
                            result_lo ^= a;
                        } else {
                            result_lo ^= a << i;
                            result_hi ^= a >> (64 - i);
                        }
                    }
                }

                self.regs.xmm[xmm_dst][0] = result_lo;
                self.regs.xmm[xmm_dst][1] = result_hi;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PCMPESTRM - Packed Compare Explicit Length Strings, Return Mask (0x60)
            0x60 => {
                if !ctx.operand_size_override || ctx.rep_prefix.is_some() {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm1 = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm1][0];
                let dst_hi = self.regs.xmm[xmm1][1];

                // Without REX.W, explicit lengths are signed EAX/EDX values.
                // REX.W selects signed RAX/RDX values before absolute-value
                // saturation to the byte/word element count.
                let (len1, len2) = if ctx.rex_w() {
                    (self.regs.rax as i64, self.regs.rdx as i64)
                } else {
                    (
                        self.regs.rax as u32 as i32 as i64,
                        self.regs.rdx as u32 as i32 as i64,
                    )
                };

                // Perform string comparison and return mask in XMM0
                let result = self.pcmpxstrx(dst_lo, dst_hi, src_lo, src_hi, len1, len2, imm8, true);
                self.regs.xmm[0][0] = result as u64;
                self.regs.xmm[0][1] = (result >> 64) as u64;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PCMPESTRI - Packed Compare Explicit Length Strings, Return Index (0x61)
            0x61 => {
                if !ctx.operand_size_override || ctx.rep_prefix.is_some() {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm1 = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm1][0];
                let dst_hi = self.regs.xmm[xmm1][1];

                let (len1, len2) = if ctx.rex_w() {
                    (self.regs.rax as i64, self.regs.rdx as i64)
                } else {
                    (
                        self.regs.rax as u32 as i32 as i64,
                        self.regs.rdx as u32 as i32 as i64,
                    )
                };

                let result =
                    self.pcmpxstrx(dst_lo, dst_hi, src_lo, src_hi, len1, len2, imm8, false);
                self.regs.rcx = result as u64;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PCMPISTRM - Packed Compare Implicit Length Strings, Return Mask (0x62)
            0x62 => {
                if !ctx.operand_size_override || ctx.rep_prefix.is_some() {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm1 = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm1][0];
                let dst_hi = self.regs.xmm[xmm1][1];

                // Implicit length - find null terminator
                let len1 = self.find_null_terminator(dst_lo, dst_hi, imm8);
                let len2 = self.find_null_terminator(src_lo, src_hi, imm8);

                let result = self.pcmpxstrx(dst_lo, dst_hi, src_lo, src_hi, len1, len2, imm8, true);
                self.regs.xmm[0][0] = result as u64;
                self.regs.xmm[0][1] = (result >> 64) as u64;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // PCMPISTRI - Packed Compare Implicit Length Strings, Return Index (0x63)
            0x63 => {
                if !ctx.operand_size_override || ctx.rep_prefix.is_some() {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm1 = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let dst_lo = self.regs.xmm[xmm1][0];
                let dst_hi = self.regs.xmm[xmm1][1];

                let len1 = self.find_null_terminator(dst_lo, dst_hi, imm8);
                let len2 = self.find_null_terminator(src_lo, src_hi, imm8);

                let result =
                    self.pcmpxstrx(dst_lo, dst_hi, src_lo, src_hi, len1, len2, imm8, false);

                self.regs.rcx = result as u64;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // SHA1RNDS4 - Perform Four Rounds of SHA1 Operation (0xCC)
            0xCC => {
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let Some((src2_lo, src2_hi)) = sha::read_xmm_m128(self, rm, is_memory, addr)?
                else {
                    return Ok(None);
                };
                let src1_lo = self.regs.xmm[xmm_dst][0];
                let src1_hi = self.regs.xmm[xmm_dst][1];
                let (result_lo, result_hi) =
                    sha::sha1rnds4(src1_lo, src1_hi, src2_lo, src2_hi, imm8);
                self.regs.xmm[xmm_dst][0] = result_lo;
                self.regs.xmm[xmm_dst][1] = result_hi;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // AESKEYGENASSIST - AES Key Generation Assist (0xDF)
            // DEST[31:0] := SubWord(X1)
            // DEST[63:32] := RotWord(SubWord(X1)) XOR RCON
            // DEST[95:64] := SubWord(X3)
            // DEST[127:96] := RotWord(SubWord(X3)) XOR RCON
            0xDF => {
                if !ctx.operand_size_override {
                    return self.inject_undefined_instruction();
                }
                let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
                let imm8 = ctx.consume_u8()?;
                let xmm_dst = reg as usize;
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };

                let (result_lo, result_hi) = aes::aeskeygenassist(src_lo, src_hi, imm8);
                self.regs.xmm[xmm_dst][0] = result_lo;
                self.regs.xmm[xmm_dst][1] = result_hi;
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // GFNI affine transforms (66 0F 3A CE/CF /r ib)
            0xCE => execute::simd::gf2p8affineqb(self, ctx),
            0xCF => execute::simd::gf2p8affineinvqb(self, ctx),

            _ => self.inject_undefined_instruction(),
        }
    }

    /// Return the implicit packed-string length selected by the immediate.
    fn find_null_terminator(&self, lo: u64, hi: u64, imm8: u8) -> i64 {
        pcmpxstrx::find_null_terminator(lo, hi, imm8)
    }

    /// Evaluate a packed-string comparison and commit its six defined status
    /// flags. DF and every non-status RFLAGS bit are preserved.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::isa::x86_64) fn pcmpxstrx(
        &mut self,
        first_lo: u64,
        first_hi: u64,
        second_lo: u64,
        second_hi: u64,
        len1: i64,
        len2: i64,
        imm8: u8,
        return_mask: bool,
    ) -> u128 {
        let result = pcmpxstrx::evaluate(
            first_lo,
            first_hi,
            second_lo,
            second_hi,
            len1,
            len2,
            imm8,
            return_mask,
        );

        self.clear_lazy_flags();
        use crate::isa::x86_64::flags::bits;
        self.regs.rflags &= !(bits::CF | bits::ZF | bits::SF | bits::OF | bits::AF | bits::PF);
        if result.cf {
            self.regs.rflags |= bits::CF;
        }
        if result.zf {
            self.regs.rflags |= bits::ZF;
        }
        if result.sf {
            self.regs.rflags |= bits::SF;
        }
        if result.of {
            self.regs.rflags |= bits::OF;
        }

        result.value
    }
}

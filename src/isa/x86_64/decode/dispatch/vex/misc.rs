//! VEX instruction implementation for x86_64 emulator.

use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute;
use crate::isa::x86_64::flags;
use crate::isa::x86_64::mxcsr_value_is_valid;

impl X86_64Vcpu {
    fn kmask_bits(size_bits: u8) -> u64 {
        match size_bits {
            8 => 0xFF,
            16 => 0xFFFF,
            32 => 0xFFFF_FFFF,
            64 => !0u64,
            _ => unreachable!(),
        }
    }

    pub(in crate::isa::x86_64) fn execute_vex_movmskp(
        &mut self,
        ctx: &mut InsnContext,
        vex_pp: u8,
        vex_l: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, _, _) = self.decode_modrm(ctx)?;
        if is_memory {
            return self.inject_undefined_instruction();
        }

        let xmm_src = rm as usize;
        let mut result = 0u64;

        if vex_pp == 0 {
            // VMOVMSKPS: extract sign bits of singles
            let lo = self.regs.xmm[xmm_src][0];
            let hi = self.regs.xmm[xmm_src][1];

            result |= ((lo >> 31) & 1) as u64;
            result |= ((lo >> 63) & 1) << 1;
            result |= ((hi >> 31) & 1) << 2;
            result |= ((hi >> 63) & 1) << 3;

            if vex_l == 1 {
                let hi2 = self.regs.ymm_high[xmm_src][0];
                let hi3 = self.regs.ymm_high[xmm_src][1];

                result |= ((hi2 >> 31) & 1) << 4;
                result |= ((hi2 >> 63) & 1) << 5;
                result |= ((hi3 >> 31) & 1) << 6;
                result |= ((hi3 >> 63) & 1) << 7;
            }
        } else {
            // VMOVMSKPD: extract sign bits of doubles
            let lo = self.regs.xmm[xmm_src][0];
            let hi = self.regs.xmm[xmm_src][1];

            result |= ((lo >> 63) & 1) as u64;
            result |= ((hi >> 63) & 1) << 1;

            if vex_l == 1 {
                let hi2 = self.regs.ymm_high[xmm_src][0];
                let hi3 = self.regs.ymm_high[xmm_src][1];

                result |= ((hi2 >> 63) & 1) << 2;
                result |= ((hi3 >> 63) & 1) << 3;
            }
        }

        self.set_reg(reg, result, 4);

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_pmovmskb(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        if vvvv != 0 {
            return self.inject_undefined_instruction();
        }
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let xmm_src = rm as usize;
        let mut result = 0u64;

        if vex_l == 0 {
            let mut bytes = [0u8; 16];
            if is_memory {
                for i in 0..16 {
                    bytes[i] = self.read_mem(addr + i as u64, 1)? as u8;
                }
            } else {
                bytes[0..8].copy_from_slice(&self.regs.xmm[xmm_src][0].to_le_bytes());
                bytes[8..16].copy_from_slice(&self.regs.xmm[xmm_src][1].to_le_bytes());
            }
            for i in 0..16 {
                if (bytes[i] & 0x80) != 0 {
                    result |= 1u64 << i;
                }
            }
        } else {
            let mut bytes = [0u8; 32];
            if is_memory {
                for i in 0..32 {
                    bytes[i] = self.read_mem(addr + i as u64, 1)? as u8;
                }
            } else {
                bytes[0..8].copy_from_slice(&self.regs.xmm[xmm_src][0].to_le_bytes());
                bytes[8..16].copy_from_slice(&self.regs.xmm[xmm_src][1].to_le_bytes());
                bytes[16..24].copy_from_slice(&self.regs.ymm_high[xmm_src][0].to_le_bytes());
                bytes[24..32].copy_from_slice(&self.regs.ymm_high[xmm_src][1].to_le_bytes());
            }
            for i in 0..32 {
                if (bytes[i] & 0x80) != 0 {
                    result |= 1u64 << i;
                }
            }
        }

        self.set_reg(reg, result, 4);
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_pmaskmov(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vex_w: u8,
        vvvv: u8,
        opcode: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        if !is_memory {
            return self.inject_undefined_instruction();
        }
        let mask_reg = vvvv as usize;
        let elem_size = if vex_w == 0 { 4 } else { 8 };

        if opcode == 0x8C {
            // Load form: reg = dest, vvvv = mask, rm = memory
            let xmm_dst = reg as usize;
            if elem_size == 4 {
                let mut lo = 0u64;
                let mut hi = 0u64;
                for i in 0..2 {
                    let mask = (self.regs.xmm[mask_reg][0] >> (i * 32)) as u32;
                    let val = if (mask & 0x8000_0000) != 0 {
                        self.read_mem(addr + (i * 4) as u64, 4)? as u32
                    } else {
                        0
                    };
                    lo |= (val as u64) << (i * 32);
                }
                for i in 0..2 {
                    let mask = (self.regs.xmm[mask_reg][1] >> (i * 32)) as u32;
                    let val = if (mask & 0x8000_0000) != 0 {
                        self.read_mem(addr + ((i + 2) * 4) as u64, 4)? as u32
                    } else {
                        0
                    };
                    hi |= (val as u64) << (i * 32);
                }
                self.regs.xmm[xmm_dst][0] = lo;
                self.regs.xmm[xmm_dst][1] = hi;

                if vex_l == 1 {
                    let mut hi2 = 0u64;
                    let mut hi3 = 0u64;
                    for i in 0..2 {
                        let mask = (self.regs.ymm_high[mask_reg][0] >> (i * 32)) as u32;
                        let val = if (mask & 0x8000_0000) != 0 {
                            self.read_mem(addr + ((i + 4) * 4) as u64, 4)? as u32
                        } else {
                            0
                        };
                        hi2 |= (val as u64) << (i * 32);
                    }
                    for i in 0..2 {
                        let mask = (self.regs.ymm_high[mask_reg][1] >> (i * 32)) as u32;
                        let val = if (mask & 0x8000_0000) != 0 {
                            self.read_mem(addr + ((i + 6) * 4) as u64, 4)? as u32
                        } else {
                            0
                        };
                        hi3 |= (val as u64) << (i * 32);
                    }
                    self.regs.ymm_high[xmm_dst][0] = hi2;
                    self.regs.ymm_high[xmm_dst][1] = hi3;
                } else {
                    self.regs.ymm_high[xmm_dst][0] = 0;
                    self.regs.ymm_high[xmm_dst][1] = 0;
                }
            } else {
                let mut lo = 0u64;
                let mut hi = 0u64;
                for i in 0..2 {
                    let mask = self.regs.xmm[mask_reg][i] >> 63;
                    let val = if mask != 0 {
                        self.read_mem(addr + (i * 8) as u64, 8)?
                    } else {
                        0
                    };
                    if i == 0 {
                        lo = val;
                    } else {
                        hi = val;
                    }
                }
                self.regs.xmm[xmm_dst][0] = lo;
                self.regs.xmm[xmm_dst][1] = hi;

                if vex_l == 1 {
                    let mut hi2 = 0u64;
                    let mut hi3 = 0u64;
                    for i in 0..2 {
                        let mask = self.regs.ymm_high[mask_reg][i] >> 63;
                        let val = if mask != 0 {
                            self.read_mem(addr + ((i + 2) * 8) as u64, 8)?
                        } else {
                            0
                        };
                        if i == 0 {
                            hi2 = val;
                        } else {
                            hi3 = val;
                        }
                    }
                    self.regs.ymm_high[xmm_dst][0] = hi2;
                    self.regs.ymm_high[xmm_dst][1] = hi3;
                } else {
                    self.regs.ymm_high[xmm_dst][0] = 0;
                    self.regs.ymm_high[xmm_dst][1] = 0;
                }
            }
        } else {
            // Store form: rm = memory dest, reg = source, vvvv = mask
            let xmm_src = reg as usize;
            if elem_size == 4 {
                for i in 0..2 {
                    let mask = (self.regs.xmm[mask_reg][0] >> (i * 32)) as u32;
                    if (mask & 0x8000_0000) != 0 {
                        let val = (self.regs.xmm[xmm_src][0] >> (i * 32)) as u32;
                        self.write_mem(addr + (i * 4) as u64, val as u64, 4)?;
                    }
                }
                for i in 0..2 {
                    let mask = (self.regs.xmm[mask_reg][1] >> (i * 32)) as u32;
                    if (mask & 0x8000_0000) != 0 {
                        let val = (self.regs.xmm[xmm_src][1] >> (i * 32)) as u32;
                        self.write_mem(addr + ((i + 2) * 4) as u64, val as u64, 4)?;
                    }
                }
                if vex_l == 1 {
                    for i in 0..2 {
                        let mask = (self.regs.ymm_high[mask_reg][0] >> (i * 32)) as u32;
                        if (mask & 0x8000_0000) != 0 {
                            let val = (self.regs.ymm_high[xmm_src][0] >> (i * 32)) as u32;
                            self.write_mem(addr + ((i + 4) * 4) as u64, val as u64, 4)?;
                        }
                    }
                    for i in 0..2 {
                        let mask = (self.regs.ymm_high[mask_reg][1] >> (i * 32)) as u32;
                        if (mask & 0x8000_0000) != 0 {
                            let val = (self.regs.ymm_high[xmm_src][1] >> (i * 32)) as u32;
                            self.write_mem(addr + ((i + 6) * 4) as u64, val as u64, 4)?;
                        }
                    }
                }
            } else {
                for i in 0..2 {
                    let mask = self.regs.xmm[mask_reg][i] >> 63;
                    if mask != 0 {
                        let val = self.regs.xmm[xmm_src][i];
                        self.write_mem(addr + (i * 8) as u64, val, 8)?;
                    }
                }
                if vex_l == 1 {
                    for i in 0..2 {
                        let mask = self.regs.ymm_high[mask_reg][i] >> 63;
                        if mask != 0 {
                            let val = self.regs.ymm_high[xmm_src][i];
                            self.write_mem(addr + ((i + 2) * 8) as u64, val, 8)?;
                        }
                    }
                }
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_maskmov_fp(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
        opcode: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        if !is_memory {
            return self.inject_undefined_instruction();
        }
        let mask_reg = vvvv as usize;
        let is_ps = opcode == 0x2C || opcode == 0x2E;
        let is_load = opcode == 0x2C || opcode == 0x2D;

        if is_ps {
            let count = if vex_l == 1 { 8 } else { 4 };
            let mut mask = [0u32; 8];
            let mask_lo = self.regs.xmm[mask_reg][0];
            let mask_hi = self.regs.xmm[mask_reg][1];
            mask[0] = mask_lo as u32;
            mask[1] = (mask_lo >> 32) as u32;
            mask[2] = mask_hi as u32;
            mask[3] = (mask_hi >> 32) as u32;
            if vex_l == 1 {
                let mask_hi2 = self.regs.ymm_high[mask_reg][0];
                let mask_hi3 = self.regs.ymm_high[mask_reg][1];
                mask[4] = mask_hi2 as u32;
                mask[5] = (mask_hi2 >> 32) as u32;
                mask[6] = mask_hi3 as u32;
                mask[7] = (mask_hi3 >> 32) as u32;
            }

            if is_load {
                let mut dst = [0u32; 8];
                for i in 0..count {
                    if (mask[i] & 0x8000_0000) != 0 {
                        dst[i] = self.read_mem(addr + (i * 4) as u64, 4)? as u32;
                    }
                }
                let xmm_dst = reg as usize;
                self.regs.xmm[xmm_dst][0] = (dst[0] as u64) | ((dst[1] as u64) << 32);
                self.regs.xmm[xmm_dst][1] = (dst[2] as u64) | ((dst[3] as u64) << 32);
                if vex_l == 1 {
                    self.regs.ymm_high[xmm_dst][0] = (dst[4] as u64) | ((dst[5] as u64) << 32);
                    self.regs.ymm_high[xmm_dst][1] = (dst[6] as u64) | ((dst[7] as u64) << 32);
                } else {
                    self.regs.ymm_high[xmm_dst][0] = 0;
                    self.regs.ymm_high[xmm_dst][1] = 0;
                }
            } else {
                let xmm_src = reg as usize;
                let mut src = [0u32; 8];
                let lo = self.regs.xmm[xmm_src][0];
                let hi = self.regs.xmm[xmm_src][1];
                src[0] = lo as u32;
                src[1] = (lo >> 32) as u32;
                src[2] = hi as u32;
                src[3] = (hi >> 32) as u32;
                if vex_l == 1 {
                    let hi2 = self.regs.ymm_high[xmm_src][0];
                    let hi3 = self.regs.ymm_high[xmm_src][1];
                    src[4] = hi2 as u32;
                    src[5] = (hi2 >> 32) as u32;
                    src[6] = hi3 as u32;
                    src[7] = (hi3 >> 32) as u32;
                }
                for i in 0..count {
                    if (mask[i] & 0x8000_0000) != 0 {
                        self.write_mem(addr + (i * 4) as u64, src[i] as u64, 4)?;
                    }
                }
            }
        } else {
            let count = if vex_l == 1 { 4 } else { 2 };
            let mut mask = [0u64; 4];
            mask[0] = self.regs.xmm[mask_reg][0];
            mask[1] = self.regs.xmm[mask_reg][1];
            if vex_l == 1 {
                mask[2] = self.regs.ymm_high[mask_reg][0];
                mask[3] = self.regs.ymm_high[mask_reg][1];
            }

            if is_load {
                let mut dst = [0u64; 4];
                for i in 0..count {
                    if (mask[i] >> 63) != 0 {
                        dst[i] = self.read_mem(addr + (i * 8) as u64, 8)?;
                    }
                }
                let xmm_dst = reg as usize;
                self.regs.xmm[xmm_dst][0] = dst[0];
                self.regs.xmm[xmm_dst][1] = dst[1];
                if vex_l == 1 {
                    self.regs.ymm_high[xmm_dst][0] = dst[2];
                    self.regs.ymm_high[xmm_dst][1] = dst[3];
                } else {
                    self.regs.ymm_high[xmm_dst][0] = 0;
                    self.regs.ymm_high[xmm_dst][1] = 0;
                }
            } else {
                let xmm_src = reg as usize;
                let mut src = [0u64; 4];
                src[0] = self.regs.xmm[xmm_src][0];
                src[1] = self.regs.xmm[xmm_src][1];
                if vex_l == 1 {
                    src[2] = self.regs.ymm_high[xmm_src][0];
                    src[3] = self.regs.ymm_high[xmm_src][1];
                }
                for i in 0..count {
                    if (mask[i] >> 63) != 0 {
                        self.write_mem(addr + (i * 8) as u64, src[i], 8)?;
                    }
                }
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX reciprocal square root: VRSQRTPS, VRSQRTSS
    pub(in crate::isa::x86_64) fn execute_vex_rsqrt(
        &mut self,
        ctx: &mut InsnContext,
        vex_pp: u8,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let xmm_dst = reg as usize;

        if vex_pp == 2 {
            // VRSQRTSS: scalar single
            let xmm_src1 = vvvv as usize;
            let src = if is_memory {
                f32::from_bits(self.read_mem(addr, 4)? as u32)
            } else {
                f32::from_bits(self.regs.xmm[rm as usize][0] as u32)
            };
            let result = rsqrt_scalar_f32(src.to_bits()) as u64;
            self.regs.xmm[xmm_dst][0] = (self.regs.xmm[xmm_src1][0] & !0xFFFFFFFF) | result;
            self.regs.xmm[xmm_dst][1] = self.regs.xmm[xmm_src1][1];
            self.regs.ymm_high[xmm_dst][0] = 0;
            self.regs.ymm_high[xmm_dst][1] = 0;
        } else {
            // VRSQRTPS: packed singles
            if vex_l == 0 {
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                self.regs.xmm[xmm_dst][0] = rsqrt_packed_f32(src_lo);
                self.regs.xmm[xmm_dst][1] = rsqrt_packed_f32(src_hi);
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            } else {
                let (src0, src1, src2, src3) = if is_memory {
                    (
                        self.read_mem(addr, 8)?,
                        self.read_mem(addr + 8, 8)?,
                        self.read_mem(addr + 16, 8)?,
                        self.read_mem(addr + 24, 8)?,
                    )
                } else {
                    (
                        self.regs.xmm[rm as usize][0],
                        self.regs.xmm[rm as usize][1],
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                self.regs.xmm[xmm_dst][0] = rsqrt_packed_f32(src0);
                self.regs.xmm[xmm_dst][1] = rsqrt_packed_f32(src1);
                self.regs.ymm_high[xmm_dst][0] = rsqrt_packed_f32(src2);
                self.regs.ymm_high[xmm_dst][1] = rsqrt_packed_f32(src3);
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX reciprocal: VRCPPS, VRCPSS
    pub(in crate::isa::x86_64) fn execute_vex_rcp(
        &mut self,
        ctx: &mut InsnContext,
        vex_pp: u8,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let xmm_dst = reg as usize;

        if vex_pp == 2 {
            // VRCPSS: scalar single
            let xmm_src1 = vvvv as usize;
            let src = if is_memory {
                f32::from_bits(self.read_mem(addr, 4)? as u32)
            } else {
                f32::from_bits(self.regs.xmm[rm as usize][0] as u32)
            };
            let result = rcp_scalar_f32(src.to_bits()) as u64;
            self.regs.xmm[xmm_dst][0] = (self.regs.xmm[xmm_src1][0] & !0xFFFFFFFF) | result;
            self.regs.xmm[xmm_dst][1] = self.regs.xmm[xmm_src1][1];
            self.regs.ymm_high[xmm_dst][0] = 0;
            self.regs.ymm_high[xmm_dst][1] = 0;
        } else {
            // VRCPPS: packed singles
            if vex_l == 0 {
                let (src_lo, src_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                self.regs.xmm[xmm_dst][0] = rcp_packed_f32(src_lo);
                self.regs.xmm[xmm_dst][1] = rcp_packed_f32(src_hi);
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            } else {
                let (src0, src1, src2, src3) = if is_memory {
                    (
                        self.read_mem(addr, 8)?,
                        self.read_mem(addr + 8, 8)?,
                        self.read_mem(addr + 16, 8)?,
                        self.read_mem(addr + 24, 8)?,
                    )
                } else {
                    (
                        self.regs.xmm[rm as usize][0],
                        self.regs.xmm[rm as usize][1],
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                self.regs.xmm[xmm_dst][0] = rcp_packed_f32(src0);
                self.regs.xmm[xmm_dst][1] = rcp_packed_f32(src1);
                self.regs.ymm_high[xmm_dst][0] = rcp_packed_f32(src2);
                self.regs.ymm_high[xmm_dst][1] = rcp_packed_f32(src3);
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX zero: VZEROUPPER, VZEROALL
    pub(in crate::isa::x86_64) fn execute_vex_vzero(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
    ) -> Result<Option<VcpuExit>> {
        if vex_l == 0 {
            // VZEROUPPER: zero upper 128 bits of all YMM registers
            for i in 0..16 {
                self.regs.ymm_high[i][0] = 0;
                self.regs.ymm_high[i][1] = 0;
            }
        } else {
            // VZEROALL: zero all YMM registers
            for i in 0..16 {
                self.regs.xmm[i][0] = 0;
                self.regs.xmm[i][1] = 0;
                self.regs.ymm_high[i][0] = 0;
                self.regs.ymm_high[i][1] = 0;
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX MXCSR: VLDMXCSR, VSTMXCSR
    pub(in crate::isa::x86_64) fn execute_vex_ldst_mxcsr(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        let modrm = ctx.peek_u8()?;
        let reg_op = (modrm >> 3) & 0x07;
        let (_, _, is_memory, addr, _) = self.decode_modrm(ctx)?;

        if !is_memory {
            return self.inject_undefined_instruction();
        }

        match reg_op {
            2 => {
                if !self.require_cr0_ts_clear_for_nm()? {
                    return Ok(None);
                }
                // VLDMXCSR: load MXCSR from memory
                let value = self.read_mem(addr, 4)? as u32;
                if !mxcsr_value_is_valid(value) {
                    self.inject_exception(13, Some(0))?;
                    return Ok(None);
                }
                self.mxcsr = value;
            }
            3 => {
                if !self.require_cr0_ts_clear_for_nm()? {
                    return Ok(None);
                }
                // VSTMXCSR: store MXCSR to memory
                self.write_mem(addr, self.mxcsr as u64, 4)?;
            }
            _ => {
                return self.inject_undefined_instruction();
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX add-subtract: VADDSUBPS, VADDSUBPD
    pub(in crate::isa::x86_64) fn execute_vex_addsubp(
        &mut self,
        ctx: &mut InsnContext,
        vex_pp: u8,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let xmm_dst = reg as usize;
        let xmm_src1 = vvvv as usize;

        let (src2_lo, src2_hi) = if is_memory {
            (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
        } else {
            (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
        };
        let src1_lo = self.regs.xmm[xmm_src1][0];
        let src1_hi = self.regs.xmm[xmm_src1][1];

        if vex_pp == 3 {
            // VADDSUBPS: alternating sub/add for singles
            // dst[0] = src1[0] - src2[0], dst[1] = src1[1] + src2[1], etc.
            let addsub_ps = |a: u64, b: u64| -> u64 {
                let a0 = f32::from_bits(a as u32);
                let a1 = f32::from_bits((a >> 32) as u32);
                let b0 = f32::from_bits(b as u32);
                let b1 = f32::from_bits((b >> 32) as u32);
                let r0 = (a0 - b0).to_bits() as u64;
                let r1 = (a1 + b1).to_bits() as u64;
                r0 | (r1 << 32)
            };

            self.regs.xmm[xmm_dst][0] = addsub_ps(src1_lo, src2_lo);
            self.regs.xmm[xmm_dst][1] = addsub_ps(src1_hi, src2_hi);

            if vex_l == 1 {
                let (src2_hi2, src2_hi3) = if is_memory {
                    (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                } else {
                    (
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                self.regs.ymm_high[xmm_dst][0] = addsub_ps(src1_hi2, src2_hi2);
                self.regs.ymm_high[xmm_dst][1] = addsub_ps(src1_hi3, src2_hi3);
            } else {
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
        } else {
            // VADDSUBPD: alternating sub/add for doubles
            // dst[0] = src1[0] - src2[0], dst[1] = src1[1] + src2[1]
            let a0 = f64::from_bits(src1_lo);
            let a1 = f64::from_bits(src1_hi);
            let b0 = f64::from_bits(src2_lo);
            let b1 = f64::from_bits(src2_hi);
            self.regs.xmm[xmm_dst][0] = (a0 - b0).to_bits();
            self.regs.xmm[xmm_dst][1] = (a1 + b1).to_bits();

            if vex_l == 1 {
                let (src2_hi2, src2_hi3) = if is_memory {
                    (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                } else {
                    (
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                let a2 = f64::from_bits(src1_hi2);
                let a3 = f64::from_bits(src1_hi3);
                let b2 = f64::from_bits(src2_hi2);
                let b3 = f64::from_bits(src2_hi3);
                self.regs.ymm_high[xmm_dst][0] = (a2 - b2).to_bits();
                self.regs.ymm_high[xmm_dst][1] = (a3 + b3).to_bits();
            } else {
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX horizontal add: VHADDPS, VHADDPD
    pub(in crate::isa::x86_64) fn execute_vex_haddp(
        &mut self,
        ctx: &mut InsnContext,
        vex_pp: u8,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let xmm_dst = reg as usize;
        let xmm_src1 = vvvv as usize;

        let (src2_lo, src2_hi) = if is_memory {
            (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
        } else {
            (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
        };
        let src1_lo = self.regs.xmm[xmm_src1][0];
        let src1_hi = self.regs.xmm[xmm_src1][1];

        if vex_pp == 3 {
            // VHADDPS: horizontal add for singles
            // dst[0] = src1[0] + src1[1], dst[1] = src1[2] + src1[3]
            // dst[2] = src2[0] + src2[1], dst[3] = src2[2] + src2[3]
            let hadd_ps = |lo: u64, hi: u64| -> u64 {
                let s0 = f32::from_bits(lo as u32);
                let s1 = f32::from_bits((lo >> 32) as u32);
                let s2 = f32::from_bits(hi as u32);
                let s3 = f32::from_bits((hi >> 32) as u32);
                let r0 = (s0 + s1).to_bits() as u64;
                let r1 = (s2 + s3).to_bits() as u64;
                r0 | (r1 << 32)
            };

            self.regs.xmm[xmm_dst][0] = hadd_ps(src1_lo, src1_hi);
            self.regs.xmm[xmm_dst][1] = hadd_ps(src2_lo, src2_hi);

            if vex_l == 1 {
                let (src2_hi2, src2_hi3) = if is_memory {
                    (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                } else {
                    (
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                self.regs.ymm_high[xmm_dst][0] = hadd_ps(src1_hi2, src1_hi3);
                self.regs.ymm_high[xmm_dst][1] = hadd_ps(src2_hi2, src2_hi3);
            } else {
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
        } else {
            // VHADDPD: horizontal add for doubles
            // dst[0] = src1[0] + src1[1], dst[1] = src2[0] + src2[1]
            let a0 = f64::from_bits(src1_lo);
            let a1 = f64::from_bits(src1_hi);
            let b0 = f64::from_bits(src2_lo);
            let b1 = f64::from_bits(src2_hi);
            self.regs.xmm[xmm_dst][0] = (a0 + a1).to_bits();
            self.regs.xmm[xmm_dst][1] = (b0 + b1).to_bits();

            if vex_l == 1 {
                let (src2_hi2, src2_hi3) = if is_memory {
                    (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                } else {
                    (
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                let a2 = f64::from_bits(src1_hi2);
                let a3 = f64::from_bits(src1_hi3);
                let b2 = f64::from_bits(src2_hi2);
                let b3 = f64::from_bits(src2_hi3);
                self.regs.ymm_high[xmm_dst][0] = (a2 + a3).to_bits();
                self.regs.ymm_high[xmm_dst][1] = (b2 + b3).to_bits();
            } else {
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX horizontal subtract: VHSUBPS, VHSUBPD
    pub(in crate::isa::x86_64) fn execute_vex_hsubp(
        &mut self,
        ctx: &mut InsnContext,
        vex_pp: u8,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let xmm_dst = reg as usize;
        let xmm_src1 = vvvv as usize;

        let (src2_lo, src2_hi) = if is_memory {
            (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
        } else {
            (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
        };
        let src1_lo = self.regs.xmm[xmm_src1][0];
        let src1_hi = self.regs.xmm[xmm_src1][1];

        if vex_pp == 3 {
            // VHSUBPS: horizontal subtract for singles
            let hsub_ps = |lo: u64, hi: u64| -> u64 {
                let s0 = f32::from_bits(lo as u32);
                let s1 = f32::from_bits((lo >> 32) as u32);
                let s2 = f32::from_bits(hi as u32);
                let s3 = f32::from_bits((hi >> 32) as u32);
                let r0 = (s0 - s1).to_bits() as u64;
                let r1 = (s2 - s3).to_bits() as u64;
                r0 | (r1 << 32)
            };

            self.regs.xmm[xmm_dst][0] = hsub_ps(src1_lo, src1_hi);
            self.regs.xmm[xmm_dst][1] = hsub_ps(src2_lo, src2_hi);

            if vex_l == 1 {
                let (src2_hi2, src2_hi3) = if is_memory {
                    (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                } else {
                    (
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                self.regs.ymm_high[xmm_dst][0] = hsub_ps(src1_hi2, src1_hi3);
                self.regs.ymm_high[xmm_dst][1] = hsub_ps(src2_hi2, src2_hi3);
            } else {
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
        } else {
            // VHSUBPD: horizontal subtract for doubles
            let a0 = f64::from_bits(src1_lo);
            let a1 = f64::from_bits(src1_hi);
            let b0 = f64::from_bits(src2_lo);
            let b1 = f64::from_bits(src2_hi);
            self.regs.xmm[xmm_dst][0] = (a0 - a1).to_bits();
            self.regs.xmm[xmm_dst][1] = (b0 - b1).to_bits();

            if vex_l == 1 {
                let (src2_hi2, src2_hi3) = if is_memory {
                    (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                } else {
                    (
                        self.regs.ymm_high[rm as usize][0],
                        self.regs.ymm_high[rm as usize][1],
                    )
                };
                let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                let a2 = f64::from_bits(src1_hi2);
                let a3 = f64::from_bits(src1_hi3);
                let b2 = f64::from_bits(src2_hi2);
                let b3 = f64::from_bits(src2_hi3);
                self.regs.ymm_high[xmm_dst][0] = (a2 - a3).to_bits();
                self.regs.ymm_high[xmm_dst][1] = (b2 - b3).to_bits();
            } else {
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// VEX-encoded shuffle: VPSHUFD/VPSHUFHW/VPSHUFLW
    pub(in crate::isa::x86_64) fn execute_vex_cmp(
        &mut self,
        ctx: &mut InsnContext,
        vex_pp: u8,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;
        let xmm_dst = reg as usize;
        let xmm_src1 = vvvv as usize;

        match vex_pp {
            0 => {
                // VCMPPS - packed single
                let (src2_lo, src2_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let src1_lo = self.regs.xmm[xmm_src1][0];
                let src1_hi = self.regs.xmm[xmm_src1][1];

                let r0 = if self.cmp_predicate_f32(
                    f32::from_bits(src1_lo as u32),
                    f32::from_bits(src2_lo as u32),
                    imm8,
                ) {
                    0xFFFFFFFFu32
                } else {
                    0
                };
                let r1 = if self.cmp_predicate_f32(
                    f32::from_bits((src1_lo >> 32) as u32),
                    f32::from_bits((src2_lo >> 32) as u32),
                    imm8,
                ) {
                    0xFFFFFFFFu32
                } else {
                    0
                };
                let r2 = if self.cmp_predicate_f32(
                    f32::from_bits(src1_hi as u32),
                    f32::from_bits(src2_hi as u32),
                    imm8,
                ) {
                    0xFFFFFFFFu32
                } else {
                    0
                };
                let r3 = if self.cmp_predicate_f32(
                    f32::from_bits((src1_hi >> 32) as u32),
                    f32::from_bits((src2_hi >> 32) as u32),
                    imm8,
                ) {
                    0xFFFFFFFFu32
                } else {
                    0
                };
                self.regs.xmm[xmm_dst][0] = r0 as u64 | ((r1 as u64) << 32);
                self.regs.xmm[xmm_dst][1] = r2 as u64 | ((r3 as u64) << 32);

                if vex_l == 1 {
                    let (src2_hi2, src2_hi3) = if is_memory {
                        (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                    } else {
                        (
                            self.regs.ymm_high[rm as usize][0],
                            self.regs.ymm_high[rm as usize][1],
                        )
                    };
                    let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                    let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                    let r4 = if self.cmp_predicate_f32(
                        f32::from_bits(src1_hi2 as u32),
                        f32::from_bits(src2_hi2 as u32),
                        imm8,
                    ) {
                        0xFFFFFFFFu32
                    } else {
                        0
                    };
                    let r5 = if self.cmp_predicate_f32(
                        f32::from_bits((src1_hi2 >> 32) as u32),
                        f32::from_bits((src2_hi2 >> 32) as u32),
                        imm8,
                    ) {
                        0xFFFFFFFFu32
                    } else {
                        0
                    };
                    let r6 = if self.cmp_predicate_f32(
                        f32::from_bits(src1_hi3 as u32),
                        f32::from_bits(src2_hi3 as u32),
                        imm8,
                    ) {
                        0xFFFFFFFFu32
                    } else {
                        0
                    };
                    let r7 = if self.cmp_predicate_f32(
                        f32::from_bits((src1_hi3 >> 32) as u32),
                        f32::from_bits((src2_hi3 >> 32) as u32),
                        imm8,
                    ) {
                        0xFFFFFFFFu32
                    } else {
                        0
                    };
                    self.regs.ymm_high[xmm_dst][0] = r4 as u64 | ((r5 as u64) << 32);
                    self.regs.ymm_high[xmm_dst][1] = r6 as u64 | ((r7 as u64) << 32);
                } else {
                    self.regs.ymm_high[xmm_dst][0] = 0;
                    self.regs.ymm_high[xmm_dst][1] = 0;
                }
            }
            1 => {
                // VCMPPD - packed double
                let (src2_lo, src2_hi) = if is_memory {
                    (self.read_mem(addr, 8)?, self.read_mem(addr + 8, 8)?)
                } else {
                    (self.regs.xmm[rm as usize][0], self.regs.xmm[rm as usize][1])
                };
                let src1_lo = self.regs.xmm[xmm_src1][0];
                let src1_hi = self.regs.xmm[xmm_src1][1];

                let r0 = if self.cmp_predicate_f64(
                    f64::from_bits(src1_lo),
                    f64::from_bits(src2_lo),
                    imm8,
                ) {
                    !0u64
                } else {
                    0
                };
                let r1 = if self.cmp_predicate_f64(
                    f64::from_bits(src1_hi),
                    f64::from_bits(src2_hi),
                    imm8,
                ) {
                    !0u64
                } else {
                    0
                };
                self.regs.xmm[xmm_dst][0] = r0;
                self.regs.xmm[xmm_dst][1] = r1;

                if vex_l == 1 {
                    let (src2_hi2, src2_hi3) = if is_memory {
                        (self.read_mem(addr + 16, 8)?, self.read_mem(addr + 24, 8)?)
                    } else {
                        (
                            self.regs.ymm_high[rm as usize][0],
                            self.regs.ymm_high[rm as usize][1],
                        )
                    };
                    let src1_hi2 = self.regs.ymm_high[xmm_src1][0];
                    let src1_hi3 = self.regs.ymm_high[xmm_src1][1];
                    let r2 = if self.cmp_predicate_f64(
                        f64::from_bits(src1_hi2),
                        f64::from_bits(src2_hi2),
                        imm8,
                    ) {
                        !0u64
                    } else {
                        0
                    };
                    let r3 = if self.cmp_predicate_f64(
                        f64::from_bits(src1_hi3),
                        f64::from_bits(src2_hi3),
                        imm8,
                    ) {
                        !0u64
                    } else {
                        0
                    };
                    self.regs.ymm_high[xmm_dst][0] = r2;
                    self.regs.ymm_high[xmm_dst][1] = r3;
                } else {
                    self.regs.ymm_high[xmm_dst][0] = 0;
                    self.regs.ymm_high[xmm_dst][1] = 0;
                }
            }
            2 => {
                // VCMPSS - scalar single
                let src2 = if is_memory {
                    f32::from_bits(self.read_mem(addr, 4)? as u32)
                } else {
                    f32::from_bits(self.regs.xmm[rm as usize][0] as u32)
                };
                let src1 = f32::from_bits(self.regs.xmm[xmm_src1][0] as u32);
                let result = if self.cmp_predicate_f32(src1, src2, imm8) {
                    0xFFFFFFFFu32
                } else {
                    0
                };
                self.regs.xmm[xmm_dst][0] =
                    (self.regs.xmm[xmm_src1][0] & !0xFFFFFFFF) | result as u64;
                self.regs.xmm[xmm_dst][1] = self.regs.xmm[xmm_src1][1];
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
            3 => {
                // VCMPSD - scalar double
                let src2 = if is_memory {
                    f64::from_bits(self.read_mem(addr, 8)?)
                } else {
                    f64::from_bits(self.regs.xmm[rm as usize][0])
                };
                let src1 = f64::from_bits(self.regs.xmm[xmm_src1][0]);
                let result = if self.cmp_predicate_f64(src1, src2, imm8) {
                    !0u64
                } else {
                    0
                };
                self.regs.xmm[xmm_dst][0] = result;
                self.regs.xmm[xmm_dst][1] = self.regs.xmm[xmm_src1][1];
                self.regs.ymm_high[xmm_dst][0] = 0;
                self.regs.ymm_high[xmm_dst][1] = 0;
            }
            _ => unreachable!(),
        }
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KMOV load: Move mask from k reg or memory to k reg
    /// KMOVB/W/D/Q k1, k2/m8/m16/m32/m64
    pub(in crate::isa::x86_64) fn execute_kmov_load(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
    ) -> Result<Option<VcpuExit>> {
        let modrm = ctx.consume_u8()?;
        let mode = (modrm >> 6) & 0x03;
        if vvvv != 0 || ctx.rex_r() != 0 || (mode == 3 && ctx.rex_b() != 0) {
            return self.inject_undefined_instruction();
        }
        let k_dst = ((modrm >> 3) & 0x07) as usize;
        let rm = modrm & 0x07;

        let value = if mode == 3 {
            // Register to register: source is another k reg
            let k_src = rm as usize;
            self.regs.k[k_src]
        } else {
            // Memory to register
            ctx.cursor -= 1; // Re-decode with modrm
            let (_, _, _, addr, _) = self.decode_modrm(ctx)?;
            let byte_size = (size_bits / 8) as u8;
            self.read_mem(addr, byte_size)?
        };

        // Mask to size
        let mask = Self::kmask_bits(size_bits);
        self.regs.k[k_dst] = value & mask;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KMOV store: Move mask from k reg to memory
    /// KMOVB/W/D/Q m8/m16/m32/m64, k1
    pub(in crate::isa::x86_64) fn execute_kmov_store(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
    ) -> Result<Option<VcpuExit>> {
        if vvvv != 0 {
            return self.inject_undefined_instruction();
        }
        let (reg, _, is_memory, addr, _) = self.decode_modrm(ctx)?;

        if !is_memory {
            return self.inject_undefined_instruction();
        }

        // ModRM.reg selects the source opmask register. decode_modrm extends reg
        // with REX.R / VEX.R, but opmask registers are only k0-k7, so a VEX.R-
        // extended encoding (reg >= 8) would index past the 8-entry regs.k array
        // and could abort a host built with an aborting panic strategy. Reject
        // the invalid encoding with #UD.
        if reg >= 8 {
            self.inject_exception(6, None)?; // #UD = vector 6
            return Ok(None);
        }

        let k_src = reg as usize;
        let value = self.regs.k[k_src];
        let byte_size = (size_bits / 8) as u8;

        self.write_mem(addr, value, byte_size)?;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KMOV from GPR: Move from general purpose register to k reg
    /// KMOVB/W/D k1, r32 or KMOVQ k1, r64
    pub(in crate::isa::x86_64) fn execute_kmov_from_gpr(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
    ) -> Result<Option<VcpuExit>> {
        let modrm = ctx.consume_u8()?;
        let mode = (modrm >> 6) & 0x03;

        if vvvv != 0 || mode != 3 || ctx.rex_r() != 0 {
            return self.inject_undefined_instruction();
        }
        let k_dst = ((modrm >> 3) & 0x07) as usize;
        let rm = modrm & 0x07;

        // Get the GPR value
        let gpr_idx = rm + if ctx.rex_b() != 0 { 8 } else { 0 };
        let value = self.get_reg(gpr_idx, if size_bits == 64 { 8 } else { 4 });

        // Mask to size
        let mask = Self::kmask_bits(size_bits);
        self.regs.k[k_dst] = value & mask;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KMOV to GPR: Move from k reg to general purpose register
    /// KMOVB/W/D r32, k1 or KMOVQ r64, k1
    pub(in crate::isa::x86_64) fn execute_kmov_to_gpr(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
    ) -> Result<Option<VcpuExit>> {
        let modrm = ctx.consume_u8()?;
        let mode = (modrm >> 6) & 0x03;

        if vvvv != 0 || mode != 3 || ctx.rex_b() != 0 {
            return self.inject_undefined_instruction();
        }
        let gpr_reg = ((modrm >> 3) & 0x07) + if ctx.rex_r() != 0 { 8 } else { 0 };
        let k_src = (modrm & 0x07) as usize;

        let value = self.regs.k[k_src];

        // Mask to size and zero-extend to 32 or 64 bits
        let mask = Self::kmask_bits(size_bits);
        let result = value & mask;

        // Write to GPR (32-bit writes zero-extend to 64-bit in 64-bit mode)
        self.set_reg(gpr_reg, result, if size_bits == 64 { 8 } else { 4 });

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// Execute binary mask operation (KAND, KOR, KXOR, KANDN, KXNOR, KADD)
    /// Format: op k1, k2, k3 where k1 = k2 op k3
    pub(in crate::isa::x86_64) fn execute_kmask_binop<F>(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
        op: F,
    ) -> Result<Option<VcpuExit>>
    where
        F: Fn(u64, u64) -> u64,
    {
        let modrm = ctx.consume_u8()?;
        let mode = (modrm >> 6) & 0x03;

        if mode != 3 || ctx.rex_r() != 0 || ctx.rex_b() != 0 {
            return self.inject_undefined_instruction();
        }
        let k_dst = ((modrm >> 3) & 0x07) as usize;
        let k_src2 = (modrm & 0x07) as usize;

        // VEX.vvvv selects the first source opmask register. As in execute_kunpck,
        // vvvv is a 4-bit field (0..=15) but only k0-k7 exist, so a guest can set
        // the high bit (e.g. KANDW with VEX.vvvv=8) to name a non-existent opmask
        // register. Indexing the 8-entry regs.k array with it would panic and, under
        // abort a host process built with an aborting panic strategy. Reject the
        // invalid encoding with #UD.
        if vvvv >= 8 {
            self.inject_exception(6, None)?; // #UD = vector 6
            return Ok(None);
        }

        let k_src1 = vvvv as usize;
        let src1 = self.regs.k[k_src1];
        let src2 = self.regs.k[k_src2];

        // Apply operation
        let result = op(src1, src2);

        // Mask to size
        let mask = Self::kmask_bits(size_bits);
        self.regs.k[k_dst] = result & mask;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// Execute unary mask operation (KNOT)
    /// Format: op k1, k2 where k1 = op(k2)
    pub(in crate::isa::x86_64) fn execute_kmask_unaryop<F>(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
        op: F,
    ) -> Result<Option<VcpuExit>>
    where
        F: Fn(u64) -> u64,
    {
        let modrm = ctx.consume_u8()?;
        let mode = (modrm >> 6) & 0x03;

        if vvvv != 0 || mode != 3 || ctx.rex_r() != 0 || ctx.rex_b() != 0 {
            return self.inject_undefined_instruction();
        }
        let k_dst = ((modrm >> 3) & 0x07) as usize;
        let k_src = (modrm & 0x07) as usize;

        let src = self.regs.k[k_src];

        // Apply operation
        let result = op(src);

        // Mask to size
        let mask = Self::kmask_bits(size_bits);
        self.regs.k[k_dst] = result & mask;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KTESTB/W/D/Q: update ZF from SRC1 & SRC2 and CF from !SRC1 & SRC2.
    pub(in crate::isa::x86_64) fn execute_ktest(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
    ) -> Result<Option<VcpuExit>> {
        if vvvv != 0 {
            return self.inject_undefined_instruction();
        }

        let modrm = ctx.consume_u8()?;
        if (modrm >> 6) != 3 || ctx.rex_r() != 0 || ctx.rex_b() != 0 {
            return self.inject_undefined_instruction();
        }

        let k_src1 = ((modrm >> 3) & 0x07) as usize;
        let k_src2 = (modrm & 0x07) as usize;
        let mask = Self::kmask_bits(size_bits);
        let src1 = self.regs.k[k_src1] & mask;
        let src2 = self.regs.k[k_src2] & mask;

        self.clear_lazy_flags();
        self.regs.rflags &= !(flags::bits::AF
            | flags::bits::OF
            | flags::bits::PF
            | flags::bits::SF
            | flags::bits::ZF
            | flags::bits::CF);
        if (src1 & src2) == 0 {
            self.regs.rflags |= flags::bits::ZF;
        }
        if ((!src1) & src2 & mask) == 0 {
            self.regs.rflags |= flags::bits::CF;
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KORTESTB/W/D/Q: update ZF if SRC1 | SRC2 is zero and CF if it is all ones.
    pub(in crate::isa::x86_64) fn execute_kortest(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
    ) -> Result<Option<VcpuExit>> {
        if vvvv != 0 {
            return self.inject_undefined_instruction();
        }

        let modrm = ctx.consume_u8()?;
        if (modrm >> 6) != 3 || ctx.rex_r() != 0 || ctx.rex_b() != 0 {
            return self.inject_undefined_instruction();
        }

        let k_src1 = ((modrm >> 3) & 0x07) as usize;
        let k_src2 = (modrm & 0x07) as usize;
        let mask = Self::kmask_bits(size_bits);
        let result = (self.regs.k[k_src1] | self.regs.k[k_src2]) & mask;

        self.clear_lazy_flags();
        self.regs.rflags &= !(flags::bits::AF
            | flags::bits::OF
            | flags::bits::PF
            | flags::bits::SF
            | flags::bits::ZF
            | flags::bits::CF);
        if result == 0 {
            self.regs.rflags |= flags::bits::ZF;
        }
        if result == mask {
            self.regs.rflags |= flags::bits::CF;
        }

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KUNPCKBW/WD/DQ: concatenate the low source fields and zero-extend.
    pub(in crate::isa::x86_64) fn execute_kunpck(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        lane_bits: u8,
    ) -> Result<Option<VcpuExit>> {
        let modrm = ctx.consume_u8()?;
        if (modrm >> 6) != 3 || ctx.rex_r() != 0 || ctx.rex_b() != 0 {
            return self.inject_undefined_instruction();
        }

        // VEX.vvvv selects the first source opmask register, but only k0-k7
        // exist. VEX decodes vvvv as a 4-bit field (0..=15), so a guest can set
        // the high bit (e.g. KUNPCKBW `C5 BD 4B C0` decodes vvvv=8) to name a
        // non-existent opmask register. Using it as an index into regs.k (an
        // 8-entry array) would panic and, in an aborting build, turn a guest
        // instruction into a host process abort/DoS. Reject the invalid encoding
        // with #UD instead, matching how other invalid encodings are handled
        // (see movdir.rs / evex.rs). RIP is left on the faulting instruction
        // (it is advanced only on retire below), so #UD points at it correctly.
        if vvvv >= 8 {
            self.inject_exception(6, None)?; // #UD = vector 6
            return Ok(None);
        }

        let k_dst = ((modrm >> 3) & 0x07) as usize;
        let k_src1 = vvvv as usize;
        let k_src2 = (modrm & 0x07) as usize;
        let lane_mask = Self::kmask_bits(lane_bits);
        let result =
            ((self.regs.k[k_src1] & lane_mask) << lane_bits) | (self.regs.k[k_src2] & lane_mask);
        self.regs.k[k_dst] = result;

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    /// KSHIFTL*/KSHIFTR*: shift a mask field by imm8 and zero-extend the result.
    pub(in crate::isa::x86_64) fn execute_kshift(
        &mut self,
        ctx: &mut InsnContext,
        vvvv: u8,
        size_bits: u8,
        left: bool,
    ) -> Result<Option<VcpuExit>> {
        if vvvv != 0 {
            return self.inject_undefined_instruction();
        }

        let modrm = ctx.consume_u8()?;
        if (modrm >> 6) != 3 || ctx.rex_r() != 0 || ctx.rex_b() != 0 {
            return self.inject_undefined_instruction();
        }

        let k_dst = ((modrm >> 3) & 0x07) as usize;
        let k_src = (modrm & 0x07) as usize;
        let count = ctx.consume_u8()?;
        let mask = Self::kmask_bits(size_bits);
        let src = self.regs.k[k_src] & mask;
        self.regs.k[k_dst] = if count >= size_bits {
            0
        } else if left {
            (src << count) & mask
        } else {
            src >> count
        };

        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }
}

fn rcp_packed_f32(v: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        return unsafe { rcp_packed_f32_native(v) };
    }

    let f0 = f32::from_bits(v as u32);
    let f1 = f32::from_bits((v >> 32) as u32);
    let r0 = (1.0f32 / f0).to_bits() as u64;
    let r1 = (1.0f32 / f1).to_bits() as u64;
    r0 | (r1 << 32)
}

fn rsqrt_packed_f32(v: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        return unsafe { rsqrt_packed_f32_native(v) };
    }

    let f0 = f32::from_bits(v as u32);
    let f1 = f32::from_bits((v >> 32) as u32);
    let r0 = (1.0f32 / f0.sqrt()).to_bits() as u64;
    let r1 = (1.0f32 / f1.sqrt()).to_bits() as u64;
    r0 | (r1 << 32)
}

fn rcp_scalar_f32(bits: u32) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        return unsafe { rcp_scalar_f32_native(bits) };
    }

    (1.0f32 / f32::from_bits(bits)).to_bits()
}

fn rsqrt_scalar_f32(bits: u32) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        return unsafe { rsqrt_scalar_f32_native(bits) };
    }

    (1.0f32 / f32::from_bits(bits).sqrt()).to_bits()
}

#[cfg(target_arch = "x86_64")]
unsafe fn rcp_packed_f32_native(bits: u64) -> u64 {
    crate::host::x86_estimate::reciprocal_packed(bits)
}

#[cfg(target_arch = "x86_64")]
unsafe fn rsqrt_packed_f32_native(bits: u64) -> u64 {
    crate::host::x86_estimate::rsqrt_packed(bits)
}

#[cfg(target_arch = "x86_64")]
unsafe fn rcp_scalar_f32_native(bits: u32) -> u32 {
    crate::host::x86_estimate::reciprocal_scalar(u64::from(bits)) as u32
}

#[cfg(target_arch = "x86_64")]
unsafe fn rsqrt_scalar_f32_native(bits: u32) -> u32 {
    crate::host::x86_estimate::rsqrt_scalar(u64::from(bits)) as u32
}

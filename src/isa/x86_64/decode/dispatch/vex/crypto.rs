//! VEX-encoded VAES and VPCLMULQDQ instructions.

use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute::crypto::{aes, clmul};
use crate::isa::x86_64::execute::simd::{affine_byte as gf_affine_byte, gf_inv, gf_mul};

fn read_vex_vec(vcpu: &X86_64Vcpu, reg: usize, vl_bytes: usize) -> [u8; 32] {
    let mut data = [0u8; 32];
    data[0..8].copy_from_slice(&vcpu.regs.xmm[reg][0].to_le_bytes());
    data[8..16].copy_from_slice(&vcpu.regs.xmm[reg][1].to_le_bytes());
    if vl_bytes == 32 {
        data[16..24].copy_from_slice(&vcpu.regs.ymm_high[reg][0].to_le_bytes());
        data[24..32].copy_from_slice(&vcpu.regs.ymm_high[reg][1].to_le_bytes());
    }
    data
}

fn read_vex_mem(vcpu: &mut X86_64Vcpu, addr: u64, vl_bytes: usize) -> Result<[u8; 32]> {
    let mut data = [0u8; 32];
    for off in (0..vl_bytes).step_by(8) {
        data[off..off + 8].copy_from_slice(&vcpu.read_mem(addr + off as u64, 8)?.to_le_bytes());
    }
    Ok(data)
}

fn write_vex_vec(vcpu: &mut X86_64Vcpu, reg: usize, vl_bytes: usize, data: &[u8; 32]) {
    vcpu.regs.xmm[reg][0] = u64::from_le_bytes(data[0..8].try_into().unwrap());
    vcpu.regs.xmm[reg][1] = u64::from_le_bytes(data[8..16].try_into().unwrap());
    if vl_bytes == 32 {
        vcpu.regs.ymm_high[reg][0] = u64::from_le_bytes(data[16..24].try_into().unwrap());
        vcpu.regs.ymm_high[reg][1] = u64::from_le_bytes(data[24..32].try_into().unwrap());
    } else {
        vcpu.regs.ymm_high[reg] = [0; 2];
    }
}

impl X86_64Vcpu {
    pub(in crate::isa::x86_64) fn execute_vex_gf2p8mulb(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let vl_bytes = if vex_l == 0 { 16 } else { 32 };
        let src1 = read_vex_vec(self, vvvv as usize, vl_bytes);
        let src2 = if is_memory {
            read_vex_mem(self, addr, vl_bytes)?
        } else {
            read_vex_vec(self, rm as usize, vl_bytes)
        };

        let mut result = [0u8; 32];
        for i in 0..vl_bytes {
            result[i] = gf_mul(src1[i], src2[i]);
        }

        write_vex_vec(self, reg as usize, vl_bytes, &result);
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_gf2p8affine(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
        inverse: bool,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;
        let vl_bytes = if vex_l == 0 { 16 } else { 32 };
        let qwords = vl_bytes / 8;
        let src1 = read_vex_vec(self, vvvv as usize, vl_bytes);
        let matrix_bytes = if is_memory {
            read_vex_mem(self, addr, vl_bytes)?
        } else {
            read_vex_vec(self, rm as usize, vl_bytes)
        };

        let mut result = [0u8; 32];
        for qword in 0..qwords {
            let base = qword * 8;
            let matrix = &matrix_bytes[base..base + 8];
            for byte in 0..8 {
                let lane = base + byte;
                let input = if inverse {
                    gf_inv(src1[lane])
                } else {
                    src1[lane]
                };
                result[lane] = gf_affine_byte(matrix, input, imm8);
            }
        }

        write_vex_vec(self, reg as usize, vl_bytes, &result);
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_vaes(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
        opcode: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let vl_bytes = if vex_l == 0 { 16 } else { 32 };
        let lanes = vl_bytes / 16;
        let states = read_vex_vec(self, vvvv as usize, vl_bytes);
        let keys = if is_memory {
            read_vex_mem(self, addr, vl_bytes)?
        } else {
            read_vex_vec(self, rm as usize, vl_bytes)
        };

        let mut result = [0u8; 32];
        for lane in 0..lanes {
            let base = lane * 16;
            let state_lo = u64::from_le_bytes(states[base..base + 8].try_into().unwrap());
            let state_hi = u64::from_le_bytes(states[base + 8..base + 16].try_into().unwrap());
            let key_lo = u64::from_le_bytes(keys[base..base + 8].try_into().unwrap());
            let key_hi = u64::from_le_bytes(keys[base + 8..base + 16].try_into().unwrap());
            let (out_lo, out_hi) = match opcode {
                0xDC => aes::aesenc(state_lo, state_hi, key_lo, key_hi),
                0xDD => aes::aesenclast(state_lo, state_hi, key_lo, key_hi),
                0xDE => aes::aesdec(state_lo, state_hi, key_lo, key_hi),
                0xDF => aes::aesdeclast(state_lo, state_hi, key_lo, key_hi),
                _ => {
                    return Err(Error::Emulator(format!(
                        "invalid VEX VAES opcode {opcode:#x}"
                    )));
                }
            };
            result[base..base + 8].copy_from_slice(&out_lo.to_le_bytes());
            result[base + 8..base + 16].copy_from_slice(&out_hi.to_le_bytes());
        }

        write_vex_vec(self, reg as usize, vl_bytes, &result);
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_vpdpbusd(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let vl_bytes = if vex_l == 0 { 16 } else { 32 };
        let dwords = vl_bytes / 4;
        let src1 = read_vex_vec(self, vvvv as usize, vl_bytes);
        let src2 = if is_memory {
            read_vex_mem(self, addr, vl_bytes)?
        } else {
            read_vex_vec(self, rm as usize, vl_bytes)
        };
        let mut result = read_vex_vec(self, reg as usize, vl_bytes);

        for lane in 0..dwords {
            let base = lane * 4;
            let mut sum = i32::from_le_bytes(result[base..base + 4].try_into().unwrap()) as i64;
            for byte in 0..4 {
                let a = src1[base + byte] as i32;
                let b = src2[base + byte] as i8 as i32;
                sum += (a * b) as i64;
            }
            let value = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };
            result[base..base + 4].copy_from_slice(&value.to_le_bytes());
        }

        write_vex_vec(self, reg as usize, vl_bytes, &result);
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_vpdpwssd(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
        saturate: bool,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let vl_bytes = if vex_l == 0 { 16 } else { 32 };
        let dwords = vl_bytes / 4;
        let src1 = read_vex_vec(self, vvvv as usize, vl_bytes);
        let src2 = if is_memory {
            read_vex_mem(self, addr, vl_bytes)?
        } else {
            read_vex_vec(self, rm as usize, vl_bytes)
        };
        let mut result = read_vex_vec(self, reg as usize, vl_bytes);

        for lane in 0..dwords {
            let base = lane * 4;
            let mut sum = i32::from_le_bytes(result[base..base + 4].try_into().unwrap()) as i64;
            let a0 = i16::from_le_bytes(src1[base..base + 2].try_into().unwrap()) as i32;
            let b0 = i16::from_le_bytes(src2[base..base + 2].try_into().unwrap()) as i32;
            let a1 = i16::from_le_bytes(src1[base + 2..base + 4].try_into().unwrap()) as i32;
            let b1 = i16::from_le_bytes(src2[base + 2..base + 4].try_into().unwrap()) as i32;
            sum += (a0 * b0 + a1 * b1) as i64;
            let value = if saturate {
                sum.clamp(i32::MIN as i64, i32::MAX as i64) as i32
            } else {
                sum as i32
            };
            result[base..base + 4].copy_from_slice(&value.to_le_bytes());
        }

        write_vex_vec(self, reg as usize, vl_bytes, &result);
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    pub(in crate::isa::x86_64) fn execute_vex_pclmulqdq(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
    ) -> Result<Option<VcpuExit>> {
        let (reg, rm, is_memory, addr, _) = self.decode_modrm(ctx)?;
        let imm8 = ctx.consume_u8()?;
        let vl_bytes = if vex_l == 0 { 16 } else { 32 };
        let lanes = vl_bytes / 16;
        let src1 = read_vex_vec(self, vvvv as usize, vl_bytes);
        let src2 = if is_memory {
            read_vex_mem(self, addr, vl_bytes)?
        } else {
            read_vex_vec(self, rm as usize, vl_bytes)
        };

        let mut result = [0u8; 32];
        for lane in 0..lanes {
            let base = lane * 16;
            let src1_base = base + if imm8 & 0x01 != 0 { 8 } else { 0 };
            let src2_base = base + if imm8 & 0x10 != 0 { 8 } else { 0 };
            let a = u64::from_le_bytes(src1[src1_base..src1_base + 8].try_into().unwrap());
            let b = u64::from_le_bytes(src2[src2_base..src2_base + 8].try_into().unwrap());
            result[base..base + 16].copy_from_slice(&clmul::qword(a, b));
        }

        write_vex_vec(self, reg as usize, vl_bytes, &result);
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }
}

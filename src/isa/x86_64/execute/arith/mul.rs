//! IMUL instructions.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

use super::super::imul::truncated_product;

/// IMUL r, r/m (0x0F 0xAF)
pub fn imul_r_rm(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let dst = vcpu.get_reg(reg, op_size);

    let src = if is_memory {
        vcpu.read_mem(addr, op_size)?
    } else {
        vcpu.get_reg(rm, op_size)
    };

    let (result, overflow) = truncated_product(dst, src, op_size);
    vcpu.set_reg(reg, result, op_size);
    flags::set_cf_of(&mut vcpu.regs.rflags, overflow, overflow);
    vcpu.clear_lazy_flags();
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// IMUL r, r/m, imm (0x69) - 3-operand with 16/32-bit immediate
pub fn imul_r_rm_imm(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let imm_size = if op_size == 8 { 4 } else { op_size };
    ctx.rip_relative_offset = imm_size as usize;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    let src = if is_memory {
        vcpu.read_mem(addr, op_size)?
    } else {
        vcpu.get_reg(rm, op_size)
    };

    // Immediate is sign-extended to operand size
    let imm = ctx.consume_imm(imm_size)?;
    let imm = if op_size == 8 {
        imm as i32 as i64 as u64
    } else {
        imm
    };

    let (result, overflow) = truncated_product(src, imm, op_size);
    vcpu.set_reg(reg, result, op_size);
    flags::set_cf_of(&mut vcpu.regs.rflags, overflow, overflow);
    vcpu.clear_lazy_flags();
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// IMUL r, r/m, imm8 (0x6B) - 3-operand with 8-bit immediate
pub fn imul_r_rm_imm8(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    ctx.rip_relative_offset = 1;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    let src = if is_memory {
        vcpu.read_mem(addr, op_size)?
    } else {
        vcpu.get_reg(rm, op_size)
    };

    // Immediate is 8-bit, sign-extended to operand size
    let imm = ctx.consume_imm(1)? as i8 as i64 as u64;

    let (result, overflow) = truncated_product(src, imm, op_size);
    vcpu.set_reg(reg, result, op_size);
    flags::set_cf_of(&mut vcpu.regs.rflags, overflow, overflow);
    vcpu.clear_lazy_flags();
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

//! Call and return instructions: CALL, RET, RETF.

use crate::cpu::VcpuExit;
use crate::error::{Error, Result};

use super::super::super::cpu::{InsnContext, X86_64Vcpu};

pub(super) fn validate_far_selector(vcpu: &X86_64Vcpu, selector: u16) -> Result<()> {
    // Real mode (CR0.PE=0): a far selector is a raw segment value (CS.base =
    // selector<<4); there is no descriptor table to validate against.
    if vcpu.sregs.cr0 & 1 == 0 {
        return Ok(());
    }
    if selector == 0 {
        return Err(Error::Emulator("CALL FAR: null selector".to_string()));
    }

    let ti = (selector & 0x4) != 0;
    let index = (selector >> 3) as u64;
    let limit = if ti {
        vcpu.sregs.ldt.limit as u64
    } else {
        vcpu.sregs.gdt.limit as u64
    };

    if limit == 0 {
        return Err(Error::Emulator(
            "CALL FAR: descriptor table not present".to_string(),
        ));
    }

    let end = index * 8 + 7;
    if end > limit {
        return Err(Error::Emulator(
            "CALL FAR: selector outside descriptor table limits".to_string(),
        ));
    }

    Ok(())
}

fn pop_by_size(vcpu: &mut X86_64Vcpu, size: u8) -> Result<u64> {
    match size {
        2 => Ok(vcpu.pop16()? as u64),
        4 => Ok(vcpu.pop32()? as u64),
        8 => vcpu.pop64(),
        _ => Err(Error::Emulator(format!("invalid stack pop size: {}", size))),
    }
}

fn push_by_size(vcpu: &mut X86_64Vcpu, size: u8, value: u64) -> Result<()> {
    match size {
        2 => vcpu.push16(value as u16),
        4 => vcpu.push32(value as u32),
        8 => vcpu.push64(value),
        _ => Err(Error::Emulator(format!(
            "invalid stack push size: {}",
            size
        ))),
    }
}

/// CALL rel32 (0xE8)
pub fn call_rel32(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let disp = ctx.consume_u32()? as i32 as i64;
    let ret_addr = vcpu.regs.rip + ctx.cursor as u64;
    let target = (vcpu.regs.rip as i64 + ctx.cursor as i64 + disp) as u64;
    vcpu.push64(ret_addr)?;
    vcpu.regs.rip = target;
    Ok(None)
}

/// RET (0xC3)
pub fn ret(vcpu: &mut X86_64Vcpu, _ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let ret_addr = vcpu.pop64()?;
    vcpu.regs.rip = ret_addr;
    Ok(None)
}

/// RET imm16 (0xC2)
pub fn ret_imm16(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let imm = ctx.consume_u16()?;
    let ret_addr = vcpu.pop64()?;
    vcpu.regs.rsp = vcpu.regs.rsp.wrapping_add(imm as u64);
    vcpu.regs.rip = ret_addr;
    Ok(None)
}

/// RETF - far return (0xCB)
pub fn retf(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let ret_addr = pop_by_size(vcpu, op_size)?;
    let cs = pop_by_size(vcpu, op_size)? as u16;
    validate_far_selector(vcpu, cs)?;

    let old_cpl = vcpu.sregs.cs.selector & 0x3;
    let new_cpl = cs & 0x3;
    if new_cpl > old_cpl {
        let new_rsp = pop_by_size(vcpu, op_size)?;
        let new_ss = pop_by_size(vcpu, op_size)? as u16;
        vcpu.set_sreg(2, new_ss); // SS is segment register 2
        vcpu.regs.rsp = new_rsp;
    }

    vcpu.regs.rip = ret_addr;
    // Load CS from the real descriptor (falls back to flat segmentation when the
    // descriptor table slot is not a usable present code segment).
    vcpu.load_code_segment_lenient(cs);
    Ok(None)
}

/// RETF imm16 - far return with stack pop (0xCA)
pub fn retf_imm16(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let imm = ctx.consume_u16()?;
    let op_size = ctx.op_size;
    let ret_addr = pop_by_size(vcpu, op_size)?;
    let cs = pop_by_size(vcpu, op_size)? as u16;
    validate_far_selector(vcpu, cs)?;

    let old_cpl = vcpu.sregs.cs.selector & 0x3;
    let new_cpl = cs & 0x3;
    if new_cpl > old_cpl {
        let new_rsp = pop_by_size(vcpu, op_size)?;
        let new_ss = pop_by_size(vcpu, op_size)? as u16;
        vcpu.set_sreg(2, new_ss); // SS is segment register 2
        vcpu.regs.rsp = new_rsp;
    }

    vcpu.regs.rsp = vcpu.regs.rsp.wrapping_add(imm as u64);
    vcpu.regs.rip = ret_addr;
    // Load CS from the real descriptor (lenient: flat fallback for sparse GDT).
    vcpu.load_code_segment_lenient(cs);
    Ok(None)
}

/// CALL FAR ptr16:16/ptr16:32 (0x9A)
/// Far call with immediate pointer - pushes CS:IP then jumps
/// Note: This opcode is invalid in 64-bit mode.
pub fn call_far_ptr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    if vcpu.sregs.cs.l {
        return Err(Error::Emulator(
            "CALL FAR ptr16:16/ptr16:32 is invalid in 64-bit mode".to_string(),
        ));
    }

    let offset = match ctx.op_size {
        2 => ctx.consume_u16()? as u64,
        4 => ctx.consume_u32()? as u64,
        _ => {
            return Err(Error::Emulator(format!(
                "CALL FAR ptr16:16/ptr16:32 invalid operand size: {}",
                ctx.op_size
            )));
        }
    };
    let selector = ctx.consume_u16()?;
    validate_far_selector(vcpu, selector)?;

    // Push return CS:IP
    let old_cs = vcpu.get_sreg(1);
    let ret_addr = vcpu.regs.rip + ctx.cursor as u64;

    push_by_size(vcpu, ctx.op_size, old_cs as u64)?;
    push_by_size(vcpu, ctx.op_size, ret_addr)?;

    // Load new CS:IP from the real descriptor (lenient: flat fallback).
    vcpu.load_code_segment_lenient(selector);
    vcpu.regs.rip = offset;
    Ok(None)
}

/// CALL FAR m16:16/m16:32/m16:64 (0xFF /3)
/// Far call with memory indirect - pushes CS:IP then jumps to address from memory.
/// Offset size follows the operand-size attribute (16/32 in non-64-bit, 16/32/64 in 64-bit).
pub fn call_far_mem(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm_start = ctx.cursor;
    let _modrm = ctx.consume_u8()?;

    // Get memory address
    let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
    ctx.cursor = modrm_start + 1 + extra;

    let offset_size = ctx.op_size;

    // Read offset and selector from memory
    let offset = vcpu.read_mem(addr, offset_size)?;
    let selector = vcpu.mmu.read_u16(addr + offset_size as u64, &vcpu.sregs)?;
    validate_far_selector(vcpu, selector)?;

    // Push return CS:IP
    let old_cs = vcpu.get_sreg(1);
    let ret_addr = vcpu.regs.rip + ctx.cursor as u64;

    push_by_size(vcpu, ctx.op_size, old_cs as u64)?;
    push_by_size(vcpu, ctx.op_size, ret_addr)?;

    // Load new CS:IP from the real descriptor (lenient: flat fallback).
    vcpu.load_code_segment_lenient(selector);
    vcpu.regs.rip = offset;
    Ok(None)
}

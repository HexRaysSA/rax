//! MOVDIRI and MOVDIR64B instructions.

use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};

fn movdir_addr_size(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> u8 {
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0;
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode {
        if ctx.address_size_override { 4 } else { 8 }
    } else {
        let default_16bit = !vcpu.sregs.cs.db;
        let is_16bit = default_16bit ^ ctx.address_size_override;
        if is_16bit { 2 } else { 4 }
    }
}

/// MOVDIRI m32, r32 or MOVDIRI m64, r64 (0F 38 F9 /r)
pub fn movdiri(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    if ctx.operand_size_override {
        // MOVDIRI (NP 0F 38 F9) does not have a valid encoding with a 66 prefix.
        // This is an invalid encoding -> #UD. Inject the fault instead of aborting
        // the VM; don't advance RIP (exception delivery sets RIP to the handler).
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    let op_size = if ctx.rex_w() { 8 } else { 4 };
    movdiri_decoded(vcpu, ctx, 0, op_size)
}

/// Execute a validated APX-promoted MOVDIRI with EVEX register extension.
pub(crate) fn movdiri_apx(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
) -> Result<Option<VcpuExit>> {
    let reg_extension = ctx.evex_dest_reg();
    let op_size = if ctx.evex_w() { 8 } else { 4 };
    movdiri_decoded(vcpu, ctx, reg_extension, op_size)
}

fn movdiri_decoded(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    reg_extension: u8,
    op_size: u8,
) -> Result<Option<VcpuExit>> {
    let (reg, _rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    if !is_memory {
        // MOVDIRI with a register destination (ModRM.mod = 11) is invalid -> #UD.
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    let value = vcpu.get_reg(reg | reg_extension, op_size);
    vcpu.write_mem(addr, value, op_size)?;

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOVDIR64B r16/r32/r64, m512 (66 0F 38 F8 /r)
pub fn movdir64b(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    if !ctx.operand_size_override || ctx.rep_prefix.is_some() || ctx.rex2.is_some() {
        // MOVDIR64B (66 0F 38 F8) requires the 66 prefix. Without it this is not a
        // valid MOVDIR64B encoding; F2/F3 refining-prefix conflicts and legacy
        // REX2 forms are also undefined. Inject #UD instead of aborting the VM;
        // don't advance RIP (exception delivery sets RIP to the handler).
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    movdir64b_decoded(vcpu, ctx, 0)
}

/// Execute a validated APX-promoted MOVDIR64B with EVEX register extension.
pub(crate) fn movdir64b_apx(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
) -> Result<Option<VcpuExit>> {
    let reg_extension = ctx.evex_dest_reg();
    movdir64b_decoded(vcpu, ctx, reg_extension)
}

fn movdir64b_decoded(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    reg_extension: u8,
) -> Result<Option<VcpuExit>> {
    let (reg, _rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    if !is_memory {
        // MOVDIR64B with a register source (ModRM.mod = 11) is invalid -> #UD.
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    let dest_reg = reg | reg_extension;
    let addr_size = movdir_addr_size(vcpu, ctx);
    let dest_addr = match addr_size {
        2 => vcpu.get_reg(dest_reg, 2) as u64,
        4 => vcpu.get_reg(dest_reg, 4) as u64,
        8 => vcpu.get_reg(dest_reg, 8),
        _ => {
            return Err(Error::Emulator(format!(
                "MOVDIR64B invalid address size {}",
                addr_size
            )));
        }
    };

    if dest_addr & 0x3F != 0 {
        // MOVDIR64B requires the destination (memory) operand to be 64-byte aligned.
        // On misalignment the architecture raises #GP(0). Inject the fault instead of
        // aborting the VM; don't advance RIP (exception delivery sets RIP to the handler).
        vcpu.inject_exception(13, Some(0))?; // #GP(0) = vector 13, error code 0
        return Ok(None);
    }

    // The register is an offset into ES without override (SDM Vol. 2B,
    // MOVDIR64B): ES's base outside 64-bit mode, wrapping at 4 GiB.
    let dest_linear = vcpu.segment_linear(vcpu.get_segment_base(Some(0x26)), dest_addr);
    let mut buf = [0u8; 64];
    vcpu.mmu.read(addr, &mut buf, &vcpu.sregs)?;
    vcpu.mmu.write(dest_linear, &buf, &vcpu.sregs)?;

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

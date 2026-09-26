//! MOV instructions (GPR data movement).

use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute::system::{
    X86SegmentLoadTarget, X86SegmentSelectorLoadFault, X86SystemDescriptorFault,
};

#[inline(always)]
fn is_canonical_48(addr: u64) -> bool {
    ((addr as i64) << 16 >> 16) as u64 == addr
}

/// MOV r8, imm8 (0xB0-0xB7)
pub fn mov_r8_imm8(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let reg = (opcode - 0xB0) | ctx.rex_b();
    let imm = ctx.consume_u8()?;
    let has_rex = ctx.rex.is_some();
    vcpu.set_reg8(reg, imm as u64, has_rex);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r16/32/64, imm16/32/64 (0xB8-0xBF)
pub fn mov_r_imm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let reg = (opcode - 0xB8) | ctx.rex_b();
    let imm = ctx.consume_imm(ctx.op_size)?;
    vcpu.set_reg(reg, imm, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Read the absolute offset operand of a `MOV moffs` instruction (its width is
/// the effective address size: 16-bit in real/16-bit mode, 32-bit in 32-bit
/// mode, 64-bit in long mode; toggled by a 0x67 prefix) and add the segment
/// base (DS by default, or an override). In long mode DS.base is 0, so the base
/// add is a no-op there.
fn moffs_addr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<u64> {
    let cs = &vcpu.sregs.cs;
    let off = if cs.l {
        if ctx.address_size_override {
            ctx.consume_u32()? as u64
        } else {
            ctx.consume_u64()?
        }
    } else if cs.db {
        if ctx.address_size_override {
            ctx.consume_u16()? as u64
        } else {
            ctx.consume_u32()? as u64
        }
    } else if ctx.address_size_override {
        ctx.consume_u32()? as u64
    } else {
        ctx.consume_u16()? as u64
    };
    Ok(vcpu.segment_linear(vcpu.get_segment_base(ctx.segment_override), off))
}

/// MOV AL, moffs8 (0xA0) - Load byte from absolute address
pub fn mov_al_moffs(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let addr = moffs_addr(vcpu, ctx)?;
    let value = vcpu.mmu.read_u8(addr, &vcpu.sregs)?;
    vcpu.regs.rax = (vcpu.regs.rax & !0xFF) | (value as u64);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV rAX, moffs (0xA1) - Load word/dword/qword from absolute address
pub fn mov_rax_moffs(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let addr = moffs_addr(vcpu, ctx)?;
    let value = vcpu.read_mem(addr, ctx.op_size)?;
    vcpu.set_reg(0, value, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV moffs8, AL (0xA2) - Store byte to absolute address
pub fn mov_moffs_al(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let addr = moffs_addr(vcpu, ctx)?;
    vcpu.mmu.write_u8(addr, vcpu.regs.rax as u8, &vcpu.sregs)?;
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV moffs, rAX (0xA3) - Store word/dword/qword to absolute address
pub fn mov_moffs_rax(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let addr = moffs_addr(vcpu, ctx)?;
    vcpu.write_mem(addr, vcpu.get_reg(0, ctx.op_size), ctx.op_size)?;
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r/m8, r8 (0x88)
pub fn mov_rm8_r8(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let has_rex = ctx.rex.is_some();
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let value = vcpu.get_reg8(reg, has_rex);

    if is_memory {
        vcpu.mmu.write_u8(addr, value as u8, &vcpu.sregs)?;
    } else {
        vcpu.set_reg8(rm, value, has_rex);
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r/m, r (0x89)
pub fn mov_rm_r(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let value = vcpu.get_reg(reg, op_size);

    if is_memory {
        vcpu.write_mem(addr, value, op_size)?;
    } else {
        vcpu.set_reg(rm, value, op_size);
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r8, r/m8 (0x8A)
pub fn mov_r8_rm8(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let has_rex = ctx.rex.is_some();
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    let value = if is_memory {
        vcpu.mmu.read_u8(addr, &vcpu.sregs)? as u64
    } else {
        vcpu.get_reg8(rm, has_rex)
    };
    vcpu.set_reg8(reg, value, has_rex);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r, r/m (0x8B)
pub fn mov_r_rm(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    let value = if is_memory {
        vcpu.read_mem(addr, op_size)?
    } else {
        vcpu.get_reg(rm, op_size)
    };

    vcpu.set_reg(reg, value, op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r/m, Sreg (0x8C)
pub fn mov_rm_sreg(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let modrm = ctx.peek_u8()?;
    // ModR/M.reg names a segment register, so legacy REX.R and both REX2 R
    // extension bits are ignored. Encodings /6 and /7 name no segment register.
    let sreg = (modrm >> 3) & 7;
    if sreg >= 6 {
        return vcpu.inject_undefined_instruction();
    }
    let (_, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let value = vcpu.get_sreg(sreg);

    if is_memory {
        vcpu.mmu.write_u16(addr, value, &vcpu.sregs)?;
    } else {
        let reg_size = if op_size == 8 {
            8
        } else if op_size == 4 {
            4
        } else {
            2
        };
        vcpu.set_reg(rm, value as u64, reg_size);
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV Sreg, r/m16 or r/m64 (0x8E). Register sources always contribute their
/// low 16 bits; W=1 selects an 8-byte memory read and still loads only bits
/// 15:0. ModR/M.reg is not extended by REX/REX2.
pub fn mov_sreg_rm(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm_start = ctx.cursor;
    let modrm = ctx.peek_u8()?;
    let target = match (modrm >> 3) & 7 {
        0 => X86SegmentLoadTarget::Es,
        2 => X86SegmentLoadTarget::Ss,
        3 => X86SegmentLoadTarget::Ds,
        4 => X86SegmentLoadTarget::Fs,
        5 => X86SegmentLoadTarget::Gs,
        // CS and /6-/7 are invalid before any source-memory access.
        1 | 6 | 7 => return vcpu.inject_undefined_instruction(),
        _ => unreachable!("three-bit segment selector changed"),
    };
    ctx.consume_u8()?;
    let rm = (modrm & 7) | ctx.any_rex_b();
    let value = if modrm >> 6 == 3 {
        vcpu.get_reg(rm, 2) as u16
    } else {
        let (addr, extra, stack_segment) =
            vcpu.decode_modrm_addr_with_stack_segment(ctx, modrm_start)?;
        ctx.cursor = modrm_start + 1 + extra;
        let width = if ctx.any_rex_w() { 8 } else { 2 };
        let canonical_range = addr.checked_add(u64::from(width - 1)).is_some_and(|last| {
            vcpu.sregs.efer & (1 << 10) == 0 || is_canonical_48(addr) && is_canonical_48(last)
        });
        if !canonical_range {
            vcpu.inject_exception(if stack_segment { 12 } else { 13 }, Some(0))?;
            return Ok(None);
        }
        vcpu.read_mem(addr, width)? as u16
    };

    match vcpu.load_segment_selector(target, value, false) {
        Ok(()) => {}
        Err(X86SegmentSelectorLoadFault::Architectural(
            X86SystemDescriptorFault::GeneralProtection { error_code },
        )) => {
            vcpu.inject_exception(13, Some(u64::from(error_code)))?;
            return Ok(None);
        }
        Err(X86SegmentSelectorLoadFault::Architectural(
            X86SystemDescriptorFault::SegmentNotPresent { error_code },
        )) => {
            vcpu.inject_exception(11, Some(u64::from(error_code)))?;
            return Ok(None);
        }
        Err(X86SegmentSelectorLoadFault::StackSegment { error_code }) => {
            vcpu.inject_exception(12, Some(u64::from(error_code)))?;
            return Ok(None);
        }
        Err(X86SegmentSelectorLoadFault::Memory(error)) => return Err(error),
        Err(X86SegmentSelectorLoadFault::NativeDeopt) => {
            unreachable!("direct segment load cannot request native deoptimization")
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn load_pointer_to_segment(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    target: X86SegmentLoadTarget,
) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    if op_size != 2 && op_size != 4 && op_size != 8 {
        return Err(Error::Emulator(format!(
            "invalid far pointer load operand size: {op_size}"
        )));
    }

    let modrm_start = ctx.cursor;
    let modrm = ctx.consume_u8()?;
    if modrm >> 6 == 3 {
        return vcpu.inject_undefined_instruction();
    }
    let reg = ((modrm >> 3) & 7) | ctx.any_rex_r();
    let (addr, extra, stack_segment) =
        vcpu.decode_modrm_addr_with_stack_segment(ctx, modrm_start)?;
    ctx.cursor = modrm_start + 1 + extra;

    let pointer_size = u64::from(op_size) + 2;
    let canonical_range = addr.checked_add(pointer_size - 1).is_some_and(|last| {
        vcpu.sregs.efer & (1 << 10) == 0 || is_canonical_48(addr) && is_canonical_48(last)
    });
    if !canonical_range {
        vcpu.inject_exception(if stack_segment { 12 } else { 13 }, Some(0))?;
        return Ok(None);
    }

    let offset = vcpu.read_mem(addr, op_size)?;
    let selector = vcpu.read_mem(addr + u64::from(op_size), 2)? as u16;
    match vcpu.load_segment_selector(target, selector, false) {
        Ok(()) => {}
        Err(X86SegmentSelectorLoadFault::Architectural(
            X86SystemDescriptorFault::GeneralProtection { error_code },
        )) => {
            vcpu.inject_exception(13, Some(u64::from(error_code)))?;
            return Ok(None);
        }
        Err(X86SegmentSelectorLoadFault::Architectural(
            X86SystemDescriptorFault::SegmentNotPresent { error_code },
        )) => {
            vcpu.inject_exception(11, Some(u64::from(error_code)))?;
            return Ok(None);
        }
        Err(X86SegmentSelectorLoadFault::StackSegment { error_code }) => {
            vcpu.inject_exception(12, Some(u64::from(error_code)))?;
            return Ok(None);
        }
        Err(X86SegmentSelectorLoadFault::Memory(error)) => return Err(error),
        Err(X86SegmentSelectorLoadFault::NativeDeopt) => {
            unreachable!("direct far-pointer segment load cannot request native deoptimization")
        }
    }

    vcpu.set_reg(reg, offset, op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// LES r16/32, m16:16/32 (0xC4) - Load far pointer into ES and GPR.
pub fn les(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    load_pointer_to_segment(vcpu, ctx, X86SegmentLoadTarget::Es)
}

/// LDS r16/32, m16:16/32 (0xC5) - Load far pointer into DS and GPR.
pub fn lds(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    load_pointer_to_segment(vcpu, ctx, X86SegmentLoadTarget::Ds)
}

/// LSS r16/32/64, m16:16/32/64 (0F B2) - Load far pointer into SS and GPR.
pub fn lss(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    load_pointer_to_segment(vcpu, ctx, X86SegmentLoadTarget::Ss)
}

/// LFS r16/32/64, m16:16/32/64 (0F B4) - Load far pointer into FS and GPR.
pub fn lfs(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    load_pointer_to_segment(vcpu, ctx, X86SegmentLoadTarget::Fs)
}

/// LGS r16/32/64, m16:16/32/64 (0F B5) - Load far pointer into GS and GPR.
pub fn lgs(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    load_pointer_to_segment(vcpu, ctx, X86SegmentLoadTarget::Gs)
}

/// MOV r/m8, imm8 (0xC6 /0) or XABORT (0xC6 F8 imm8)
pub fn mov_rm8_imm8(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let has_rex = ctx.rex.is_some();
    let modrm = ctx.peek_u8()?;
    let reg = (modrm >> 3) & 0x07;

    if modrm == 0xf8 {
        // XABORT aborts a transaction; outside a transaction it has no effect.
        // The emulator has no transactional state, so every XABORT is outside.
        ctx.consume_u8()?; // consume ModRM
        let _status = ctx.consume_u8()?; // status code
        vcpu.regs.rip += ctx.cursor as u64;
        return Ok(None);
    }
    if reg != 0 {
        return vcpu.inject_undefined_instruction();
    }

    ctx.rip_relative_offset = 1;
    let (_, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let imm = ctx.consume_u8()?;

    if is_memory {
        vcpu.mmu.write_u8(addr, imm, &vcpu.sregs)?;
    } else {
        vcpu.set_reg8(rm, imm as u64, has_rex);
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r/m, imm (0xC7 /0) or XBEGIN (0xC7 F8 rel16/rel32)
pub fn mov_rm_imm(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm = ctx.peek_u8()?;
    let reg = (modrm >> 3) & 0x07;

    if modrm == 0xf8 {
        // XBEGIN starts a transaction. The emulator has no transactional state,
        // so model the guest-visible forced-abort path and jump to fallback.
        ctx.consume_u8()?; // consume ModRM
        let offset = if ctx.op_size == 2 {
            ctx.consume_u16()? as i16 as i64
        } else {
            // REX.W does not widen XBEGIN's displacement beyond rel32.
            ctx.consume_u32()? as i32 as i64
        };
        let next_rip = vcpu.regs.rip.wrapping_add(ctx.cursor as u64);
        // The rel16 form sign-extends into RIP; it does not truncate the
        // resulting target to 16 bits.
        let fallback = next_rip.wrapping_add_signed(offset);
        if !is_canonical_48(fallback) {
            vcpu.inject_exception(13, Some(0))?;
            return Ok(None);
        }
        vcpu.regs.rax = 0;
        vcpu.regs.rip = fallback;
        return Ok(None);
    }
    if reg != 0 {
        return vcpu.inject_undefined_instruction();
    }

    let op_size = ctx.op_size;
    let imm_size = if op_size == 8 { 4 } else { op_size };
    ctx.rip_relative_offset = imm_size as usize;
    let (_, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    let imm = ctx.consume_imm(imm_size)?;
    let imm = if op_size == 8 {
        imm as i32 as i64 as u64
    } else {
        imm
    };

    // Tolerate MOV r64, imm64 encoded with C7 /0 when the upper dword is sign-extension.
    if op_size == 8 && (modrm >> 6) == 3 && ctx.cursor + 4 <= ctx.bytes_len {
        let sign = if (imm as i64) < 0 { 0xFF } else { 0x00 };
        if ctx.bytes[ctx.cursor..ctx.cursor + 4]
            .iter()
            .all(|b| *b == sign)
        {
            ctx.cursor += 4;
        }
    }

    if is_memory {
        vcpu.write_mem(addr, imm, op_size)?;
    } else {
        vcpu.set_reg(rm, imm, op_size);
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::is_canonical_48;

    #[test]
    fn canonical_48_boundaries_cover_both_sign_extensions() {
        for addr in [0, 0x0000_7FFF_FFFF_FFFF, 0xFFFF_8000_0000_0000, u64::MAX] {
            assert!(is_canonical_48(addr), "{addr:016X}");
        }
        for addr in [0x0000_8000_0000_0000, 0xFFFF_7FFF_FFFF_FFFF] {
            assert!(!is_canonical_48(addr), "{addr:016X}");
        }
    }
}

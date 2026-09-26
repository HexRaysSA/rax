//! Stack instructions: PUSH, POP, PUSHA, POPA.

use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute::system::{
    X86SegmentLoadTarget, X86SegmentSelectorLoadFault, X86SystemDescriptorFault, is_canonical_48,
};

fn long_mode_stack_write_is_canonical(rsp: u64, width: u8) -> bool {
    let address = rsp.wrapping_sub(u64::from(width));
    address
        .checked_add(u64::from(width - 1))
        .is_some_and(|last| is_canonical_48(address) && is_canonical_48(last))
}

fn long_mode_stack_read_is_canonical(rsp: u64, width: u8) -> bool {
    rsp.checked_add(u64::from(width - 1))
        .is_some_and(|last| is_canonical_48(rsp) && is_canonical_48(last))
}

/// PUSH r64 (0x50-0x57)
pub fn push_r64(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let reg = (opcode - 0x50) | ctx.any_rex_b();
    let op_size = stack_op_size(vcpu, ctx);
    let value = vcpu.get_reg(reg, op_size);
    match op_size {
        2 => vcpu.push16(value as u16)?,
        4 => vcpu.push32(value as u32)?,
        8 => vcpu.push64(value)?,
        _ => {
            return Err(Error::Emulator(format!(
                "invalid PUSH r op size: {}",
                op_size
            )));
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

fn segment_op_size(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> u8 {
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0;
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode {
        // Intel defines REX.W/REX2.W as taking precedence over 66H. The
        // default is already 64 bits, so W is observable only for the combined
        // 66+W encoding.
        if ctx.any_rex_w() || !ctx.operand_size_override {
            8
        } else {
            2
        }
    } else {
        let default_16bit = !vcpu.sregs.cs.db;
        let is_16bit = default_16bit ^ ctx.operand_size_override;
        if is_16bit { 2 } else { 4 }
    }
}

pub(crate) fn stack_op_size(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> u8 {
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0;
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode {
        if ctx.operand_size_override && !ctx.any_rex_w() {
            2
        } else {
            8
        }
    } else {
        let default_16bit = !vcpu.sregs.cs.db;
        let is_16bit = default_16bit ^ ctx.operand_size_override;
        if is_16bit { 2 } else { 4 }
    }
}

fn segment_invalid_in_64bit(sreg: u8) -> bool {
    matches!(sreg, 0 | 1 | 2 | 3)
}

fn segment_name(sreg: u8) -> &'static str {
    match sreg {
        0 => "ES",
        1 => "CS",
        2 => "SS",
        3 => "DS",
        4 => "FS",
        5 => "GS",
        _ => "UNKNOWN",
    }
}

/// PUSH Sreg (ES/CS/SS/DS/FS/GS)
pub fn push_sreg(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    sreg: u8,
) -> Result<Option<VcpuExit>> {
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0;
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode && segment_invalid_in_64bit(sreg) {
        // PUSH ES/CS/SS/DS invalid in 64-bit mode - inject #UD
        // Don't advance RIP - exception should point to faulting instruction
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    let op_size = segment_op_size(vcpu, ctx);
    if in_64bit_mode && !long_mode_stack_write_is_canonical(vcpu.regs.rsp, op_size) {
        vcpu.inject_exception(12, Some(0))?;
        return Ok(None);
    }
    let value = vcpu.get_sreg(sreg) as u64;
    match op_size {
        2 => vcpu.push16(value as u16)?,
        4 => vcpu.push_segment32(value as u16)?,
        8 => vcpu.push64(value)?,
        _ => {
            return Err(Error::Emulator(format!(
                "invalid PUSH Sreg size: {}",
                op_size
            )));
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// POP Sreg (ES/SS/DS/FS/GS)
pub fn pop_sreg(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    sreg: u8,
) -> Result<Option<VcpuExit>> {
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0;
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode && segment_invalid_in_64bit(sreg) {
        // POP ES/CS/SS/DS invalid in 64-bit mode - inject #UD
        // Don't advance RIP - exception should point to faulting instruction
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    let target = match sreg {
        0 => X86SegmentLoadTarget::Es,
        2 => X86SegmentLoadTarget::Ss,
        3 => X86SegmentLoadTarget::Ds,
        4 => X86SegmentLoadTarget::Fs,
        5 => X86SegmentLoadTarget::Gs,
        _ => {
            return Err(Error::Emulator(format!(
                "invalid POP segment register: {sreg}"
            )));
        }
    };

    let op_size = segment_op_size(vcpu, ctx);
    if !matches!(op_size, 2 | 4 | 8) {
        return Err(Error::Emulator(format!("invalid POP Sreg size: {op_size}")));
    }
    let stack_offset = vcpu.stack_pointer_offset();
    let stack_address_size = if vcpu.sregs.cs.l {
        8
    } else if vcpu.sregs.ss.db {
        4
    } else {
        2
    };
    let stack_address = if vcpu.sregs.cs.l {
        stack_offset
    } else {
        vcpu.segment_linear(vcpu.sregs.ss.base, stack_offset)
    };
    if in_64bit_mode && !long_mode_stack_read_is_canonical(stack_address, op_size) {
        vcpu.inject_exception(12, Some(0))?;
        return Ok(None);
    }
    let value = vcpu.read_mem(stack_address, op_size)? as u16;

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

    let new_stack_offset = match stack_address_size {
        2 => u64::from((stack_offset as u16).wrapping_add(u16::from(op_size))),
        4 => u64::from((stack_offset as u32).wrapping_add(u32::from(op_size))),
        8 => stack_offset.wrapping_add(u64::from(op_size)),
        _ => unreachable!("x86 stack-address width changed"),
    };
    // POP SS can change SS.B. The stack read and pointer increment both use
    // the pre-instruction stack-address size, so commit without consulting the
    // newly loaded descriptor.
    match stack_address_size {
        2 => {
            vcpu.regs.rsp = (vcpu.regs.rsp & !0xFFFF) | (new_stack_offset & 0xFFFF);
        }
        4 => vcpu.regs.rsp = new_stack_offset & 0xFFFF_FFFF,
        8 => vcpu.regs.rsp = new_stack_offset,
        _ => unreachable!("x86 stack-address width changed"),
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// PUSH imm8 (0x6A)
pub fn push_imm8(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = stack_op_size(vcpu, ctx);
    let imm = ctx.consume_u8()? as i8 as i64 as u64;
    match op_size {
        2 => vcpu.push16(imm as u16)?,
        4 => vcpu.push32(imm as u32)?,
        8 => vcpu.push64(imm)?,
        _ => {
            return Err(Error::Emulator(format!(
                "invalid PUSH imm8 op size: {}",
                op_size
            )));
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// PUSH imm32 (0x68)
pub fn push_imm32(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = stack_op_size(vcpu, ctx);
    let imm = if op_size == 2 {
        ctx.consume_u16()? as i16 as i64 as u64
    } else {
        ctx.consume_u32()? as i32 as i64 as u64
    };
    match op_size {
        2 => vcpu.push16(imm as u16)?,
        4 => vcpu.push32(imm as u32)?,
        8 => vcpu.push64(imm)?,
        _ => {
            return Err(Error::Emulator(format!(
                "invalid PUSH imm32 op size: {}",
                op_size
            )));
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// POP r64 (0x58-0x5F)
pub fn pop_r64(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    opcode: u8,
) -> Result<Option<VcpuExit>> {
    let reg = (opcode - 0x58) | ctx.any_rex_b();
    let op_size = stack_op_size(vcpu, ctx);

    let value = match op_size {
        2 => vcpu.pop16()? as u64,
        4 => vcpu.pop32()? as u64,
        8 => vcpu.pop64()?,
        _ => {
            return Err(Error::Emulator(format!(
                "invalid POP r op size: {}",
                op_size
            )));
        }
    };
    vcpu.set_reg(reg, value, op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// POP r/m64 (0x8F /0)
pub fn pop_rm(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = stack_op_size(vcpu, ctx);

    let modrm_start = ctx.cursor;
    let modrm = ctx.consume_u8()?;
    if ((modrm >> 3) & 0x07) != 0 {
        return vcpu.inject_undefined_instruction();
    }

    let rm = (modrm & 0x07) | ctx.any_rex_b();
    let is_memory = (modrm >> 6) != 3;
    let extra = if is_memory {
        let (_, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
        extra
    } else {
        0
    };

    // Pop value based on operand size
    let value = match op_size {
        2 => vcpu.pop16()? as u64,
        4 => vcpu.pop32()? as u64,
        8 => vcpu.pop64()?,
        _ => {
            return Err(Error::Emulator(format!(
                "invalid POP r/m op size: {}",
                op_size
            )));
        }
    };

    if is_memory {
        let (addr, _) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
        ctx.cursor = modrm_start + 1 + extra;
        vcpu.write_mem(addr, value, op_size)?;
    } else {
        vcpu.set_reg(rm, value, op_size);
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// PUSHA/PUSHAD (0x60) - Push all general-purpose registers
pub fn pusha(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    // Check if we're in 64-bit mode - PUSHA/PUSHAD is invalid in 64-bit mode
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0; // EFER.LMA = bit 10
    let cs_l = vcpu.sregs.cs.l; // CS.L indicates 64-bit code segment

    if in_long_mode && cs_l {
        // PUSHA/PUSHAD invalid in 64-bit mode - inject #UD
        // Don't advance RIP - exception should point to faulting instruction
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    // Determine operand size: 0x66 prefix TOGGLES the default operand size
    // CS.D (db flag) determines default: D=0 means 16-bit default, D=1 means 32-bit default
    // The 0x66 prefix inverts the default
    let default_16bit = !vcpu.sregs.cs.db;
    let is_16bit = default_16bit ^ ctx.operand_size_override;

    // Save original SP/ESP before any pushes
    let original_sp = vcpu.regs.rsp;

    if is_16bit {
        // PUSHA - push 16-bit registers: AX, CX, DX, BX, SP, BP, SI, DI
        let ax = (vcpu.regs.rax & 0xFFFF) as u16;
        let cx = (vcpu.regs.rcx & 0xFFFF) as u16;
        let dx = (vcpu.regs.rdx & 0xFFFF) as u16;
        let bx = (vcpu.regs.rbx & 0xFFFF) as u16;
        let sp = (original_sp & 0xFFFF) as u16;
        let bp = (vcpu.regs.rbp & 0xFFFF) as u16;
        let si = (vcpu.regs.rsi & 0xFFFF) as u16;
        let di = (vcpu.regs.rdi & 0xFFFF) as u16;

        vcpu.push16(ax)?;
        vcpu.push16(cx)?;
        vcpu.push16(dx)?;
        vcpu.push16(bx)?;
        vcpu.push16(sp)?;
        vcpu.push16(bp)?;
        vcpu.push16(si)?;
        vcpu.push16(di)?;
    } else {
        // PUSHAD - push 32-bit registers: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
        let eax = (vcpu.regs.rax & 0xFFFFFFFF) as u32;
        let ecx = (vcpu.regs.rcx & 0xFFFFFFFF) as u32;
        let edx = (vcpu.regs.rdx & 0xFFFFFFFF) as u32;
        let ebx = (vcpu.regs.rbx & 0xFFFFFFFF) as u32;
        let esp = (original_sp & 0xFFFFFFFF) as u32;
        let ebp = (vcpu.regs.rbp & 0xFFFFFFFF) as u32;
        let esi = (vcpu.regs.rsi & 0xFFFFFFFF) as u32;
        let edi = (vcpu.regs.rdi & 0xFFFFFFFF) as u32;

        vcpu.push32(eax)?;
        vcpu.push32(ecx)?;
        vcpu.push32(edx)?;
        vcpu.push32(ebx)?;
        vcpu.push32(esp)?;
        vcpu.push32(ebp)?;
        vcpu.push32(esi)?;
        vcpu.push32(edi)?;
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// POPA/POPAD (0x61) - Pop all general-purpose registers
pub fn popa(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    // Check if we're in 64-bit mode - POPA/POPAD is invalid in 64-bit mode
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0; // EFER.LMA = bit 10
    let cs_l = vcpu.sregs.cs.l; // CS.L indicates 64-bit code segment

    if in_long_mode && cs_l {
        // POPA/POPAD invalid in 64-bit mode - inject #UD
        // Don't advance RIP - exception should point to faulting instruction
        vcpu.inject_exception(6, None)?; // #UD = vector 6
        return Ok(None);
    }

    // Determine operand size: 0x66 prefix TOGGLES the default operand size
    // CS.D (db flag) determines default: D=0 means 16-bit default, D=1 means 32-bit default
    let default_16bit = !vcpu.sregs.cs.db;
    let is_16bit = default_16bit ^ ctx.operand_size_override;

    if is_16bit {
        // POPA - pop 16-bit registers: DI, SI, BP, skip SP, BX, DX, CX, AX
        let di = vcpu.pop16()?;
        let si = vcpu.pop16()?;
        let bp = vcpu.pop16()?;
        let _ = vcpu.pop16()?; // Skip SP value on stack
        let bx = vcpu.pop16()?;
        let dx = vcpu.pop16()?;
        let cx = vcpu.pop16()?;
        let ax = vcpu.pop16()?;

        // Update only the lower 16 bits of registers
        vcpu.regs.rdi = (vcpu.regs.rdi & !0xFFFF) | (di as u64);
        vcpu.regs.rsi = (vcpu.regs.rsi & !0xFFFF) | (si as u64);
        vcpu.regs.rbp = (vcpu.regs.rbp & !0xFFFF) | (bp as u64);
        vcpu.regs.rbx = (vcpu.regs.rbx & !0xFFFF) | (bx as u64);
        vcpu.regs.rdx = (vcpu.regs.rdx & !0xFFFF) | (dx as u64);
        vcpu.regs.rcx = (vcpu.regs.rcx & !0xFFFF) | (cx as u64);
        vcpu.regs.rax = (vcpu.regs.rax & !0xFFFF) | (ax as u64);
    } else {
        // POPAD - pop 32-bit registers: EDI, ESI, EBP, skip ESP, EBX, EDX, ECX, EAX
        let edi = vcpu.pop32()?;
        let esi = vcpu.pop32()?;
        let ebp = vcpu.pop32()?;
        let _ = vcpu.pop32()?; // Skip ESP value on stack
        let ebx = vcpu.pop32()?;
        let edx = vcpu.pop32()?;
        let ecx = vcpu.pop32()?;
        let eax = vcpu.pop32()?;

        vcpu.regs.rdi = edi as u64;
        vcpu.regs.rsi = esi as u64;
        vcpu.regs.rbp = ebp as u64;
        vcpu.regs.rbx = ebx as u64;
        vcpu.regs.rdx = edx as u64;
        vcpu.regs.rcx = ecx as u64;
        vcpu.regs.rax = eax as u64;
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

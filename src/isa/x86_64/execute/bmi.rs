//! BMI1/BMI2 and related bit-manipulation instruction implementations.
//!
//! BMI1: ANDN, BEXTR, BLSI, BLSMSK, BLSR, TZCNT, LZCNT
//! BMI2: BZHI, MULX, PDEP, PEXT, RORX, SARX, SHRX, SHLX
//! TBM: BEXTR, BLCFILL, BLCI, BLCIC, BLCMSK, BLCS, BLSFILL, BLSIC,
//! T1MSKC, TZMSK (AMD)

use super::bmi1::Operation as Bmi1;
use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

// =============================================================================
// BMI1 Instructions
// =============================================================================

/// ANDN - Logical AND NOT (VEX.LZ.0F38 F2 /r)
pub fn andn(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let (dest, rm, memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let other = vcpu.get_reg(vvvv, ctx.op_size);
    let source = bmi1_source(vcpu, ctx, rm, memory, addr)?;
    finish_bmi1(vcpu, ctx, dest, Bmi1::AndNot, source, other)
}

/// BLSI, BLSMSK, BLSR group (VEX.LZ.0F38 F3 /1, /2, /3)
pub fn blsi_blsmsk_blsr(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    vvvv: u8,
) -> Result<Option<VcpuExit>> {
    let group = (ctx.peek_u8()? >> 3) & 7;
    let (_, rm, memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let source = bmi1_source(vcpu, ctx, rm, memory, addr)?;
    let operation = match group {
        1 => Bmi1::ResetLowest,
        2 => Bmi1::MaskThroughLowest,
        3 => Bmi1::IsolateLowest,
        _ => return vcpu.inject_undefined_instruction(),
    };
    finish_bmi1(vcpu, ctx, vvvv, operation, source, 0)
}

/// BEXTR - Bit Field Extract (VEX.LZ.0F38 F7 /r)
pub fn bextr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let (dest, rm, memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let source = bmi1_source(vcpu, ctx, rm, memory, addr)?;
    let control = vcpu.get_reg(vvvv, ctx.op_size);
    finish_bmi1(vcpu, ctx, dest, Bmi1::Extract, source, control)
}

fn bmi1_source(
    vcpu: &mut X86_64Vcpu,
    ctx: &InsnContext,
    register: u8,
    memory: bool,
    address: u64,
) -> Result<u64> {
    if memory {
        vcpu.read_mem(address, ctx.op_size)
    } else {
        Ok(vcpu.get_reg(register, ctx.op_size))
    }
}

fn finish_bmi1(
    vcpu: &mut X86_64Vcpu,
    ctx: &InsnContext,
    destination: u8,
    operation: Bmi1,
    source: u64,
    other: u64,
) -> Result<Option<VcpuExit>> {
    vcpu.materialize_flags();
    let (result, flags) =
        operation.apply(u32::from(ctx.op_size) * 8, source, other, vcpu.regs.rflags);
    vcpu.set_reg(destination, result, ctx.op_size);
    vcpu.regs.rflags = flags;
    vcpu.clear_lazy_flags();
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

// =============================================================================
// BMI2 Instructions
// =============================================================================

/// BZHI - Zero High Bits Starting with Specified Bit Position (VEX.LZ.0F38 F5 /r)
pub fn bzhi(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let index = (vcpu.get_reg(vvvv, ctx.op_size) & 0xFF) as u32;
    let bits = if ctx.op_size == 8 { 64u32 } else { 32u32 };
    let result = if index >= bits {
        src
    } else {
        src & ((1u64 << index) - 1)
    };
    vcpu.set_reg(reg, result, ctx.op_size);
    // SF and ZF based on result, CF = (index >= bits)
    let sf = if ctx.op_size == 8 {
        (result >> 63) & 1
    } else {
        (result >> 31) & 1
    };
    let zf = if result == 0 { 1 } else { 0 };
    let cf = if index >= bits { 1 } else { 0 };
    // BZHI deterministically preserves its undefined PF/AF in the emulator.
    vcpu.materialize_flags();
    vcpu.regs.rflags &= !(flags::bits::SF | flags::bits::ZF | flags::bits::OF | flags::bits::CF);
    if sf != 0 {
        vcpu.regs.rflags |= flags::bits::SF;
    }
    if zf != 0 {
        vcpu.regs.rflags |= flags::bits::ZF;
    }
    if cf != 0 {
        vcpu.regs.rflags |= flags::bits::CF;
    }
    // Flags were written eagerly; drop any stale pending lazy op so the next
    // flag reader (Jcc/SETcc) doesn't clobber these defined flags.
    vcpu.clear_lazy_flags();
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MULX - Unsigned Multiply Without Affecting Flags (VEX.LZ.F2.0F38 F6 /r)
pub fn mulx(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src1 = if ctx.op_size == 8 {
        vcpu.regs.rdx
    } else {
        vcpu.regs.rdx & mask
    };
    let src2 = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let (hi, lo) = if ctx.op_size == 8 {
        let prod = (src1 as u128) * (src2 as u128);
        ((prod >> 64) as u64, prod as u64)
    } else {
        let prod = (src1 as u64) * (src2 as u64);
        ((prod >> 32) as u64 & mask, prod as u64 & mask)
    };
    // Write low first, then high (so high wins if both destinations are the same)
    vcpu.set_reg(vvvv, lo, ctx.op_size);
    vcpu.set_reg(reg, hi, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// PDEP - Parallel Bits Deposit (VEX.LZ.F2.0F38 F5 /r)
pub fn pdep(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = vcpu.get_reg(vvvv, ctx.op_size) & mask;
    let selector = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let mut result = 0u64;
    let mut k = 0u32;
    for i in 0..ctx.op_size * 8 {
        if (selector >> i) & 1 != 0 {
            if (src >> k) & 1 != 0 {
                result |= 1 << i;
            }
            k += 1;
        }
    }
    vcpu.set_reg(reg, result & mask, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// PEXT - Parallel Bits Extract (VEX.LZ.F3.0F38 F5 /r)
pub fn pext(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = vcpu.get_reg(vvvv, ctx.op_size) & mask;
    let selector = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let mut result = 0u64;
    let mut k = 0u32;
    for i in 0..ctx.op_size * 8 {
        if (selector >> i) & 1 != 0 {
            if (src >> i) & 1 != 0 {
                result |= 1 << k;
            }
            k += 1;
        }
    }
    vcpu.set_reg(reg, result & mask, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// RORX - Rotate Right Logical Without Affecting Flags (VEX.LZ.F2.0F3A F0 /r ib)
pub fn rorx(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)?
    } else {
        vcpu.get_reg(rm, ctx.op_size)
    };
    let imm = ctx.consume_u8()?;
    let bits = if ctx.op_size == 8 { 64u32 } else { 32u32 };
    let count_mask = if bits == 64 { 0x3F } else { 0x1F };
    let count = (imm & count_mask) as u32;
    let src = src & mask;
    let result = if count == 0 {
        src
    } else {
        ((src >> count) | (src << (bits - count))) & mask
    };
    vcpu.set_reg(reg, result, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// SARX - Shift Arithmetic Right Without Affecting Flags (VEX.LZ.F3.0F38 F7 /r)
pub fn sarx(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let count_mask = if ctx.op_size == 8 { 0x3F } else { 0x1F };
    let count = (vcpu.get_reg(vvvv, ctx.op_size) & count_mask) as u32;
    let result = if ctx.op_size == 8 {
        ((src as i64) >> count) as u64
    } else {
        (((src as u32 as i32) >> count) as u32) as u64
    };
    vcpu.set_reg(reg, result & mask, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// SHRX - Shift Logical Right Without Affecting Flags (VEX.LZ.F2.0F38 F7 /r)
pub fn shrx(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let count_mask = if ctx.op_size == 8 { 0x3F } else { 0x1F };
    let count = (vcpu.get_reg(vvvv, ctx.op_size) & count_mask) as u32;
    let result = src >> count;
    vcpu.set_reg(reg, result & mask, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// SHLX - Shift Logical Left Without Affecting Flags (VEX.LZ.66.0F38 F7 /r)
pub fn shlx(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, vvvv: u8) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let count_mask = if ctx.op_size == 8 { 0x3F } else { 0x1F };
    let count = (vcpu.get_reg(vvvv, ctx.op_size) & count_mask) as u32;
    let result = src << count;
    vcpu.set_reg(reg, result & mask, ctx.op_size);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

// =============================================================================
// TBM Instructions (AMD)
// =============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::isa::x86_64) enum TbmKind {
    Blcfill,
    Blci,
    Blcic,
    Blcmsk,
    Blcs,
    Blsfill,
    Blsic,
    T1mskc,
    Tzmsk,
}

/// Execute an XOP map-9 scalar TBM operation.
pub fn tbm(
    vcpu: &mut X86_64Vcpu,
    ctx: &mut InsnContext,
    dst: u8,
    kind: TbmKind,
) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        !0u64
    } else {
        0xFFFF_FFFFu64
    };
    let (_, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let src = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let incremented = src.wrapping_add(1) & mask;
    let decremented = src.wrapping_sub(1) & mask;
    let result = match kind {
        TbmKind::Blcfill => src & incremented,
        TbmKind::Blci => src | !incremented,
        TbmKind::Blcic => !src & incremented,
        TbmKind::Blcmsk => src ^ incremented,
        TbmKind::Blcs => src | incremented,
        TbmKind::Blsfill => src | decremented,
        TbmKind::Blsic => !src | decremented,
        TbmKind::T1mskc => !src | incremented,
        TbmKind::Tzmsk => !src & decremented,
    } & mask;
    vcpu.set_reg(dst, result, ctx.op_size);

    let carry = match kind {
        TbmKind::Blsfill | TbmKind::Blsic | TbmKind::Tzmsk => src == 0,
        _ => src == mask,
    };
    vcpu.materialize_flags();
    vcpu.regs.rflags &= !(flags::bits::SF | flags::bits::ZF | flags::bits::OF | flags::bits::CF);
    if carry {
        vcpu.regs.rflags |= flags::bits::CF;
    }
    if result == 0 {
        vcpu.regs.rflags |= flags::bits::ZF;
    }
    if result & (1_u64 << (u32::from(ctx.op_size) * 8 - 1)) != 0 {
        vcpu.regs.rflags |= flags::bits::SF;
    }
    vcpu.clear_lazy_flags();
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// Immediate-control BEXTR (XOP.L0.0A.W{0,1} 10 /r id).
pub fn tbm_bextr_imm(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let mask = if ctx.op_size == 8 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let (dst, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;
    let control = ctx.consume_u32()?;
    let src = if is_memory {
        vcpu.read_mem(addr, ctx.op_size)? & mask
    } else {
        vcpu.get_reg(rm, ctx.op_size) & mask
    };
    let start = control & 0xff;
    let length = (control >> 8) & 0xff;
    let bits = u32::from(ctx.op_size) * 8;
    let result = if start >= bits || length == 0 {
        0
    } else {
        let shifted = src >> start;
        if length >= bits {
            shifted
        } else {
            shifted & ((1_u64 << length) - 1)
        }
    };
    vcpu.set_reg(dst, result, ctx.op_size);
    vcpu.materialize_flags();
    vcpu.regs.rflags &= !(flags::bits::ZF | flags::bits::OF | flags::bits::CF);
    if result == 0 {
        vcpu.regs.rflags |= flags::bits::ZF;
    }
    vcpu.clear_lazy_flags();
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

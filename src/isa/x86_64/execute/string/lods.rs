//! Load string instructions: LODSB, LODSW, LODSD, LODSQ.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use super::{address_size, advance_index, dec_count, index, normalize_count, rep_count};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

/// LODSB (0xAC)
pub fn lodsb(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let is_rep = ctx.rep_prefix.is_some();
    // Source DS:[RSI] honors a segment-override prefix (FS/GS); address size
    // selects SI/CX, ESI/ECX, or RSI/RCX.
    let src_base = vcpu.get_segment_base(ctx.segment_override);
    let addr_size = address_size(vcpu, ctx);
    let count = if is_rep {
        rep_count(vcpu.regs.rcx, addr_size)
    } else {
        1
    };
    if is_rep && count == 0 {
        vcpu.regs.rcx = normalize_count(vcpu.regs.rcx, addr_size);
    }
    for _ in 0..count {
        if is_rep && rep_count(vcpu.regs.rcx, addr_size) == 0 {
            break;
        }
        let src = vcpu.segment_linear(src_base, index(vcpu.regs.rsi, addr_size));
        let val = vcpu.mmu.read_u8(src, &vcpu.sregs)?;
        vcpu.regs.rax = (vcpu.regs.rax & !0xFF) | (val as u64);
        let forward = vcpu.regs.rflags & flags::bits::DF == 0;
        vcpu.regs.rsi = advance_index(vcpu.regs.rsi, 1, forward, addr_size);
        if is_rep {
            vcpu.regs.rcx = dec_count(vcpu.regs.rcx, addr_size);
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// LODSW/LODSD/LODSQ (0xAD)
pub fn lods(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let delta = op_size as u64;
    let is_rep = ctx.rep_prefix.is_some();
    let src_base = vcpu.get_segment_base(ctx.segment_override);
    let addr_size = address_size(vcpu, ctx);
    let count = if is_rep {
        rep_count(vcpu.regs.rcx, addr_size)
    } else {
        1
    };
    if is_rep && count == 0 {
        vcpu.regs.rcx = normalize_count(vcpu.regs.rcx, addr_size);
    }
    for _ in 0..count {
        if is_rep && rep_count(vcpu.regs.rcx, addr_size) == 0 {
            break;
        }
        let src = vcpu.segment_linear(src_base, index(vcpu.regs.rsi, addr_size));
        let val = vcpu.read_mem(src, op_size)?;
        vcpu.set_reg(0, val, op_size);
        let forward = vcpu.regs.rflags & flags::bits::DF == 0;
        vcpu.regs.rsi = advance_index(vcpu.regs.rsi, delta, forward, addr_size);
        if is_rep {
            vcpu.regs.rcx = dec_count(vcpu.regs.rcx, addr_size);
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

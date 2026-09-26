//! Compare string instructions: CMPSB, CMPSW, CMPSD, CMPSQ.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use super::{address_size, advance_index, dec_count, index, normalize_count, rep_count};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

/// CMPSB (0xA6)
pub fn cmpsb(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let is_rep = ctx.rep_prefix.is_some();
    // CMPS compares the segment-overridable source DS:[RSI] (val1) with the
    // fixed ES:[RDI] destination (val2).
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
        let dst = vcpu.segment_linear(
            vcpu.get_segment_base(Some(0x26)),
            index(vcpu.regs.rdi, addr_size),
        );
        let val1 = vcpu.mmu.read_u8(src, &vcpu.sregs)? as u64;
        let val2 = vcpu.mmu.read_u8(dst, &vcpu.sregs)? as u64;
        let result = val1.wrapping_sub(val2);
        flags::update_flags_sub(&mut vcpu.regs.rflags, val1, val2, result, 1);
        vcpu.clear_lazy_flags();
        let forward = vcpu.regs.rflags & flags::bits::DF == 0;
        vcpu.regs.rsi = advance_index(vcpu.regs.rsi, 1, forward, addr_size);
        vcpu.regs.rdi = advance_index(vcpu.regs.rdi, 1, forward, addr_size);
        if is_rep {
            vcpu.regs.rcx = dec_count(vcpu.regs.rcx, addr_size);
            let zf = (vcpu.regs.rflags & flags::bits::ZF) != 0;
            if ctx.rep_prefix == Some(0xF3) && !zf {
                break;
            }
            if ctx.rep_prefix == Some(0xF2) && zf {
                break;
            }
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// CMPSW/CMPSD/CMPSQ (0xA7)
pub fn cmps(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
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
        let dst = vcpu.segment_linear(
            vcpu.get_segment_base(Some(0x26)),
            index(vcpu.regs.rdi, addr_size),
        );
        let val1 = vcpu.read_mem(src, op_size)?;
        let val2 = vcpu.read_mem(dst, op_size)?;
        let result = val1.wrapping_sub(val2);
        flags::update_flags_sub(&mut vcpu.regs.rflags, val1, val2, result, op_size);
        vcpu.clear_lazy_flags();
        let forward = vcpu.regs.rflags & flags::bits::DF == 0;
        vcpu.regs.rsi = advance_index(vcpu.regs.rsi, delta, forward, addr_size);
        vcpu.regs.rdi = advance_index(vcpu.regs.rdi, delta, forward, addr_size);
        if is_rep {
            vcpu.regs.rcx = dec_count(vcpu.regs.rcx, addr_size);
            let zf = (vcpu.regs.rflags & flags::bits::ZF) != 0;
            if ctx.rep_prefix == Some(0xF3) && !zf {
                break;
            }
            if ctx.rep_prefix == Some(0xF2) && zf {
                break;
            }
        }
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

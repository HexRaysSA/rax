//! Scan string instructions: SCASB, SCASW, SCASD, SCASQ.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use super::{address_size, advance_index, dec_count, index, normalize_count, rep_count};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

/// SCASB (0xAE)
pub fn scasb(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let is_rep = ctx.rep_prefix.is_some();
    // SCAS operand is always ES:[RDI] (NOT segment-overridable).
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
        let dst = vcpu.segment_linear(
            vcpu.get_segment_base(Some(0x26)),
            index(vcpu.regs.rdi, addr_size),
        );
        let val = vcpu.mmu.read_u8(dst, &vcpu.sregs)? as u64;
        let al = vcpu.regs.rax & 0xFF;
        let result = al.wrapping_sub(val);
        flags::update_flags_sub(&mut vcpu.regs.rflags, al, val, result, 1);
        vcpu.clear_lazy_flags();
        let forward = vcpu.regs.rflags & flags::bits::DF == 0;
        vcpu.regs.rdi = advance_index(vcpu.regs.rdi, 1, forward, addr_size);
        if is_rep {
            vcpu.regs.rcx = dec_count(vcpu.regs.rcx, addr_size);
            let zf = (vcpu.regs.rflags & flags::bits::ZF) != 0;
            // REPE (0xF3): continue while equal (ZF=1)
            // REPNE (0xF2): continue while not equal (ZF=0)
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

/// SCASW/SCASD/SCASQ (0xAF)
pub fn scas(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let delta = op_size as u64;
    let is_rep = ctx.rep_prefix.is_some();
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
        let dst = vcpu.segment_linear(
            vcpu.get_segment_base(Some(0x26)),
            index(vcpu.regs.rdi, addr_size),
        );
        let val = vcpu.read_mem(dst, op_size)?;
        let rax = vcpu.get_reg(0, op_size);
        let result = rax.wrapping_sub(val);
        flags::update_flags_sub(&mut vcpu.regs.rflags, rax, val, result, op_size);
        vcpu.clear_lazy_flags();
        let forward = vcpu.regs.rflags & flags::bits::DF == 0;
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

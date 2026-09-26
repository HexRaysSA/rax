//! Table lookup translation instruction: XLAT/XLATB.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};

fn xlat_address_size(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> u8 {
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

/// XLAT/XLATB (0xD7) - Table lookup translation
pub fn xlat(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let index = vcpu.regs.rax & 0xFF;
    let offset = match xlat_address_size(vcpu, ctx) {
        2 => ((vcpu.regs.rbx as u16).wrapping_add(index as u16)) as u64,
        4 => ((vcpu.regs.rbx as u32).wrapping_add(index as u32)) as u64,
        8 => vcpu.regs.rbx.wrapping_add(index),
        _ => unreachable!(),
    };
    let addr = vcpu.segment_linear(vcpu.get_segment_base(ctx.segment_override), offset);
    let value = vcpu.read_mem(addr, 1)?;
    vcpu.regs.rax = (vcpu.regs.rax & !0xFF) | (value & 0xFF);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

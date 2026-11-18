//! Conditional move instructions: CMOVcc.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};

const EFER_LMA: u64 = 1 << 10;

/// CMOVcc r, r/m (0x0F 0x40-0x4F) - Conditional Move
pub fn cmovcc(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, cc: u8) -> Result<Option<VcpuExit>> {
    let op_size = ctx.op_size;
    let (reg, rm, is_memory, addr, _) = vcpu.decode_modrm(ctx)?;

    // The memory read can fault even when the destination is unselected.
    let value = if is_memory {
        vcpu.read_mem(addr, op_size)?
    } else {
        vcpu.get_reg(rm, op_size)
    };
    if vcpu.check_condition(cc) {
        vcpu.set_reg(reg, value, op_size);
    } else if op_size == 4 && vcpu.sregs.efer & EFER_LMA != 0 {
        let value = vcpu.get_reg(reg, op_size);
        vcpu.set_reg(reg, value, op_size);
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

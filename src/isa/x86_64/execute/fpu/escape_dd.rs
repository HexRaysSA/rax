//! DD escape - FLD, FST, FSTP, FRSTOR, FNSAVE, FUCOM, FUCOMP, FFREE

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use super::helpers::{fnsave, frstor, set_fpu_compare_flags};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};

/// DD escape - FLD, FST, FSTP, FRSTOR, FNSAVE, FUCOM, FUCOMP, FFREE
pub fn escape_dd(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm = ctx.consume_u8()?;
    let reg = (modrm >> 3) & 7;
    let rm = modrm & 7;
    let is_memory = (modrm >> 6) != 3;

    if is_memory {
        let addr = vcpu.decode_fpu_modrm_addr(ctx, modrm)?;
        match reg {
            0 => {
                // FLD m64
                let val = vcpu.read_f64(addr)?;
                vcpu.fpu.push(val);
            }
            1 => {
                // FISTTP m64int
                let val = vcpu.fpu.pop().trunc() as i64;
                vcpu.write_mem64(addr, val as u64)?;
            }
            2 => {
                // FST m64
                let val = vcpu.fpu.get_st(0);
                vcpu.write_f64(addr, val)?;
            }
            3 => {
                // FSTP m64
                let val = vcpu.fpu.pop();
                vcpu.write_f64(addr, val)?;
            }
            4 => {
                // FRSTOR m94/108byte
                frstor(vcpu, addr)?;
            }
            6 => {
                // FNSAVE m94/108byte
                fnsave(vcpu, addr)?;
            }
            7 => {
                // FNSTSW m16
                vcpu.write_mem16(addr, vcpu.fpu.status_word)?;
            }
            _ => {
                vcpu.inject_exception(6, None)?;
                return Ok(None);
            }
        }
    } else {
        match modrm {
            0xC0..=0xC7 => {
                // FFREE ST(i)
                if !super::require_waiting_x87_available(vcpu)? {
                    return Ok(None);
                }
                let tag_shift = (vcpu.fpu.st_index(rm) as u16) * 2;
                vcpu.fpu.tag_word |= 3 << tag_shift; // Mark as empty
                super::record_x87_data_op(vcpu, 0x05C0 + u16::from(rm));
            }
            0xC8..=0xCF => {
                // Legacy FXCH alias.
                let st0_idx = vcpu.fpu.st_index(0);
                let sti_idx = vcpu.fpu.st_index(rm);
                vcpu.fpu.st.swap(st0_idx, sti_idx);
                let st0_shift = (st0_idx as u16) * 2;
                let sti_shift = (sti_idx as u16) * 2;
                let st0_tag = (vcpu.fpu.tag_word >> st0_shift) & 3;
                let sti_tag = (vcpu.fpu.tag_word >> sti_shift) & 3;
                vcpu.fpu.tag_word &= !((3 << st0_shift) | (3 << sti_shift));
                vcpu.fpu.tag_word |= st0_tag << sti_shift;
                vcpu.fpu.tag_word |= sti_tag << st0_shift;
            }
            0xD0..=0xD7 => {
                // FST ST(i)
                if !super::require_waiting_x87_available(vcpu)? {
                    return Ok(None);
                }
                super::store_x87_register(vcpu, rm, false, 0x05D0 + u16::from(rm));
            }
            0xD8..=0xDF => {
                // FSTP ST(i)
                if !super::require_waiting_x87_available(vcpu)? {
                    return Ok(None);
                }
                super::store_x87_register(vcpu, rm, true, 0x05D8 + u16::from(rm));
            }
            0xE0..=0xE7 => {
                // FUCOM ST(i)
                let st0 = vcpu.fpu.get_st(0);
                let sti = vcpu.fpu.get_st(rm);
                set_fpu_compare_flags(vcpu, st0, sti);
            }
            0xE8..=0xEF => {
                // FUCOMP ST(i)
                let st0 = vcpu.fpu.get_st(0);
                let sti = vcpu.fpu.get_st(rm);
                set_fpu_compare_flags(vcpu, st0, sti);
                vcpu.fpu.pop();
            }
            _ => {
                vcpu.inject_exception(6, None)?;
                return Ok(None);
            }
        }
    }

    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

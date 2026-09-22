//! DF escape - FILD, FIST, FISTP (word/qword), FBLD, FBSTP, FNSTSW AX

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use super::helpers::{bcd_to_f64, f64_to_bcd, fpu_round, set_fcomi_flags};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};

/// DF escape - FILD, FIST, FISTP (word/qword), FBLD, FBSTP, FNSTSW AX
pub fn escape_df(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm = ctx.consume_u8()?;
    let reg = (modrm >> 3) & 7;
    let rm = modrm & 7;
    let is_memory = (modrm >> 6) != 3;

    if is_memory {
        let addr = vcpu.decode_fpu_modrm_addr(ctx, modrm)?;
        match reg {
            0 => {
                // FILD m16int
                let val = vcpu.read_mem16(addr)? as i16 as f64;
                vcpu.fpu.push(val);
            }
            1 => {
                // FISTTP m16int
                let val = vcpu.fpu.pop().trunc() as i16;
                vcpu.write_mem16(addr, val as u16)?;
            }
            2 => {
                // FIST m16int
                let val = fpu_round(vcpu.fpu.control_word, vcpu.fpu.get_st(0)) as i16;
                vcpu.write_mem16(addr, val as u16)?;
            }
            3 => {
                // FISTP m16int
                let val = fpu_round(vcpu.fpu.control_word, vcpu.fpu.pop()) as i16;
                vcpu.write_mem16(addr, val as u16)?;
            }
            4 => {
                // FBLD m80bcd
                let bytes = vcpu.read_bytes(addr, 10)?;
                let val = bcd_to_f64(&bytes);
                vcpu.fpu.push(val);
            }
            5 => {
                // FILD m64int
                let val = vcpu.read_mem64(addr)? as i64 as f64;
                vcpu.fpu.push(val);
            }
            6 => {
                // FBSTP m80bcd
                let val = fpu_round(vcpu.fpu.control_word, vcpu.fpu.pop());
                let bytes = f64_to_bcd(val);
                vcpu.write_bytes(addr, &bytes)?;
            }
            7 => {
                // FISTP m64int
                let val = fpu_round(vcpu.fpu.control_word, vcpu.fpu.pop()) as i64;
                vcpu.write_mem64(addr, val as u64)?;
            }
            _ => unreachable!(),
        }
    } else {
        match modrm {
            0xC0..=0xC7 => {
                // FFREEP ST(i): free ST(i), then pop the x87 stack.
                if !super::require_waiting_x87_available(vcpu)? {
                    return Ok(None);
                }
                let target_tag_shift = (vcpu.fpu.st_index(rm) as u16) * 2;
                let top_tag_shift = (vcpu.fpu.top as u16) * 2;
                vcpu.fpu.tag_word |= 3 << target_tag_shift;
                vcpu.fpu.tag_word |= 3 << top_tag_shift;
                vcpu.fpu.top = vcpu.fpu.top.wrapping_add(1) & 7;
                vcpu.fpu.status_word =
                    (vcpu.fpu.status_word & !0x3800) | ((vcpu.fpu.top as u16) << 11);
                super::record_x87_data_op(vcpu, 0x07C0 + u16::from(rm));
            }
            0xD0..=0xD7 => {
                // Legacy FSTP ST(i) alias.
                if !super::require_waiting_x87_available(vcpu)? {
                    return Ok(None);
                }
                super::store_x87_register(vcpu, rm, true, 0x07D0 + u16::from(rm));
            }
            0xE0 => {
                // FNSTSW AX
                if !super::require_x87_available(vcpu)? {
                    return Ok(None);
                }
                vcpu.regs.rax = (vcpu.regs.rax & !0xFFFF) | vcpu.fpu.status_word as u64;
            }
            0xE8..=0xEF => {
                // FUCOMIP ST(0), ST(i)
                let st0 = vcpu.fpu.get_st(0);
                let sti = vcpu.fpu.get_st(rm);
                set_fcomi_flags(vcpu, st0, sti);
                vcpu.fpu.pop();
            }
            0xF0..=0xF7 => {
                // FCOMIP ST(0), ST(i)
                let st0 = vcpu.fpu.get_st(0);
                let sti = vcpu.fpu.get_st(rm);
                set_fcomi_flags(vcpu, st0, sti);
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

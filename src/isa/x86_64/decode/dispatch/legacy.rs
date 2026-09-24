//! Single-byte opcode dispatch for the x86_64 CPU emulator.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute;

impl X86_64Vcpu {
    /// Main instruction dispatch for single-byte opcodes.
    pub(in crate::isa::x86_64) fn execute(
        &mut self,
        opcode: u8,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        match opcode {
            // INC r16/r32 (0x40-0x47) / DEC r16/r32 (0x48-0x4F). These encodings
            // exist only in 16/32-bit mode; in 64-bit mode the same bytes are REX
            // prefixes (consumed by the decoder). INC/DEC preserve CF.
            0x40..=0x4F => {
                let reg = (opcode & 0x07) | ctx.rex_b();
                let is_dec = opcode >= 0x48;
                let op_size = ctx.op_size;
                let a = self.get_reg(reg, op_size);
                let result = if is_dec {
                    a.wrapping_sub(1)
                } else {
                    a.wrapping_add(1)
                };
                self.set_reg(reg, result, op_size);
                if is_dec {
                    self.set_lazy_dec(a, result, op_size);
                } else {
                    self.set_lazy_inc(a, result, op_size);
                }
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }
            // NOP / PAUSE (F3 90)
            0x90 => {
                if ctx.rex_b() != 0 {
                    execute::data::xchg_rax_r(self, ctx, opcode)
                } else if ctx.rep_prefix == Some(0xF3) {
                    execute::system::pause(self, ctx)
                } else {
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
            }

            // HLT - halt and exit to caller.
            // NOTE: architecturally HLT is privileged (#GP at CPL!=0), but the rax
            // test harness uses HLT as a universal terminator from any CPL (incl.
            // ring 3 after SYSEXIT/SYSRET), so it is intentionally NOT gated here.
            0xF4 => {
                // User mode enforces the architectural CPL 0 requirement.
                if self.user_mode_enabled() && self.sregs.cs.selector & 3 != 0 {
                    self.inject_exception(13, Some(0))?;
                    return Ok(None);
                }
                self.regs.rip += ctx.cursor as u64;
                self.halted = true;
                Ok(Some(VcpuExit::Hlt))
            }

            // Two-byte opcode (0x0F prefix)
            0x0F => self.execute_0f(ctx),

            // Control flow
            0xEB => execute::control::jmp_rel8(self, ctx),
            0xE9 => execute::control::jmp_rel32(self, ctx),
            0xEA => execute::control::jmp_far_ptr(self, ctx),
            0xE8 => execute::control::call_rel32(self, ctx),
            0x9A => execute::control::call_far_ptr(self, ctx),
            0xC3 => execute::control::ret(self, ctx),
            0xC2 => execute::control::ret_imm16(self, ctx),
            0xCA => execute::control::retf_imm16(self, ctx),
            0xCB => execute::control::retf(self, ctx),
            0xCF => execute::control::iret(self, ctx),
            0x70..=0x7F => execute::control::jcc_rel8(self, ctx, opcode & 0x0F),

            // Legacy LES/LDS in compatibility mode, or VEX prefixes otherwise.
            0xC4 => self.execute_les_or_vex3(ctx),
            0xC5 => self.execute_lds_or_vex2(ctx),

            // I/O
            0xE4 => execute::io::in_al_imm8(self, ctx),
            0xE5 => execute::io::in_ax_imm8(self, ctx),
            0xEC => execute::io::in_al_dx(self, ctx),
            0xED => execute::io::in_ax_dx(self, ctx),
            0xE6 => execute::io::out_imm8_al(self, ctx),
            0xE7 => execute::io::out_imm8_ax(self, ctx),
            0xEE => execute::io::out_dx_al(self, ctx),
            0xEF => execute::io::out_dx_ax(self, ctx),

            // String I/O
            0x6C => execute::io::insb(self, ctx),
            0x6D => execute::io::insw(self, ctx),
            0x6E => execute::io::outsb(self, ctx),
            0x6F => execute::io::outsw(self, ctx),

            // Data movement
            0xB0..=0xB7 => execute::data::mov_r8_imm8(self, ctx, opcode),
            0xB8..=0xBF => execute::data::mov_r_imm(self, ctx, opcode),
            0x88 => execute::data::mov_rm8_r8(self, ctx),
            0x89 => execute::data::mov_rm_r(self, ctx),
            0x8A => execute::data::mov_r8_rm8(self, ctx),
            0x8B => execute::data::mov_r_rm(self, ctx),
            0x8C => execute::data::mov_rm_sreg(self, ctx),
            0x8E => execute::data::mov_sreg_rm(self, ctx),
            0x8D => execute::data::lea(self, ctx),
            0x06 => execute::data::push_sreg(self, ctx, 0), // PUSH ES
            0x0E => execute::data::push_sreg(self, ctx, 1), // PUSH CS
            0x16 => execute::data::push_sreg(self, ctx, 2), // PUSH SS
            0x1E => execute::data::push_sreg(self, ctx, 3), // PUSH DS
            0x07 => execute::data::pop_sreg(self, ctx, 0),  // POP ES
            0x17 => execute::data::pop_sreg(self, ctx, 2),  // POP SS
            0x1F => execute::data::pop_sreg(self, ctx, 3),  // POP DS
            // MOV moffs instructions
            0xA0 => execute::data::mov_al_moffs(self, ctx),
            0xA1 if ctx.has_rex2() => execute::control::jmp_abs(self, ctx),
            0xA1 => execute::data::mov_rax_moffs(self, ctx),
            0xA2 => execute::data::mov_moffs_al(self, ctx),
            0xA3 => execute::data::mov_moffs_rax(self, ctx),
            0xC6 => execute::data::mov_rm8_imm8(self, ctx),
            0xC7 => execute::data::mov_rm_imm(self, ctx),
            0x50..=0x57 => execute::data::push_r64(self, ctx, opcode),
            0x58..=0x5F => execute::data::pop_r64(self, ctx, opcode),
            0x8F => self.execute_pop_or_xop(ctx),
            0x6A => execute::data::push_imm8(self, ctx),
            0x68 => execute::data::push_imm32(self, ctx),
            0x86 => execute::data::xchg_r8_rm8(self, ctx),
            0x87 => execute::data::xchg_r_rm(self, ctx),
            0x91..=0x97 => execute::data::xchg_rax_r(self, ctx, opcode),
            0x63 if self.sregs.cs.l => execute::data::movsxd(self, ctx),
            0x63 => execute::data::arpl(self, ctx),

            // Arithmetic
            0x00 => execute::arith::add_rm8_r8(self, ctx),
            0x01 => execute::arith::add_rm_r(self, ctx),
            0x02 => execute::arith::add_r8_rm8(self, ctx),
            0x03 => execute::arith::add_r_rm(self, ctx),
            0x04 => execute::arith::add_al_imm8(self, ctx),
            0x05 => execute::arith::add_rax_imm(self, ctx),
            0x10 => execute::arith::adc_rm8_r8(self, ctx),
            0x11 => execute::arith::adc_rm_r(self, ctx),
            0x12 => execute::arith::adc_r8_rm8(self, ctx),
            0x13 => execute::arith::adc_r_rm(self, ctx),
            0x14 => execute::arith::adc_al_imm8(self, ctx),
            0x15 => execute::arith::adc_rax_imm(self, ctx),
            0x18 => execute::arith::sbb_rm8_r8(self, ctx),
            0x19 => execute::arith::sbb_rm_r(self, ctx),
            0x1A => execute::arith::sbb_r8_rm8(self, ctx),
            0x1B => execute::arith::sbb_r_rm(self, ctx),
            0x1C => execute::arith::sbb_al_imm8(self, ctx),
            0x1D => execute::arith::sbb_rax_imm(self, ctx),
            0x27 => execute::arith::daa(self, ctx),
            0x28 => execute::arith::sub_rm8_r8(self, ctx),
            0x29 => execute::arith::sub_rm_r(self, ctx),
            0x2A => execute::arith::sub_r8_rm8(self, ctx),
            0x2B => execute::arith::sub_r_rm(self, ctx),
            0x2C => execute::arith::sub_al_imm8(self, ctx),
            0x2D => execute::arith::sub_rax_imm(self, ctx),
            0x2F => execute::arith::das(self, ctx),
            0x38 => execute::arith::cmp_rm8_r8(self, ctx),
            0x39 => execute::arith::cmp_rm_r(self, ctx),
            0x3A => execute::arith::cmp_r8_rm8(self, ctx),
            0x3B => execute::arith::cmp_r_rm(self, ctx),
            0x3C => execute::arith::cmp_al_imm8(self, ctx),
            0x3D => execute::arith::cmp_rax_imm(self, ctx),
            0x3F => execute::arith::aas(self, ctx),
            0x80 => execute::arith::group1_rm8_imm8(self, ctx),
            // 0x82 is a legacy alias for 0x80 outside 64-bit mode, but is not a
            // valid long-mode single-byte group-1 opcode.
            0x82 if self.sregs.cs.l => {
                self.inject_exception(6, None)?;
                Ok(None)
            }
            0x82 => execute::arith::group1_rm8_imm8(self, ctx),
            0x81 => execute::arith::group1_rm_imm32(self, ctx),
            0x83 => execute::arith::group1_rm_imm8(self, ctx),
            0x69 => execute::arith::imul_r_rm_imm(self, ctx),
            0x6B => execute::arith::imul_r_rm_imm8(self, ctx),
            0x98 => execute::arith::cbw_cwde_cdqe(self, ctx),
            0x99 => execute::arith::cwd_cdq_cqo(self, ctx),

            // Logic
            0x08 => execute::logic::or_rm8_r8(self, ctx),
            0x09 => execute::logic::or_rm_r(self, ctx),
            0x0A => execute::logic::or_r8_rm8(self, ctx),
            0x0B => execute::logic::or_r_rm(self, ctx),
            0x0C => execute::logic::or_al_imm8(self, ctx),
            0x0D => execute::logic::or_rax_imm(self, ctx),
            0x20 => execute::logic::and_rm8_r8(self, ctx),
            0x21 => execute::logic::and_rm_r(self, ctx),
            0x22 => execute::logic::and_r8_rm8(self, ctx),
            0x23 => execute::logic::and_r_rm(self, ctx),
            0x24 => execute::logic::and_al_imm8(self, ctx),
            0x25 => execute::logic::and_rax_imm(self, ctx),
            0x30 => execute::logic::xor_rm8_r8(self, ctx),
            0x31 => execute::logic::xor_rm_r(self, ctx),
            0x32 => execute::logic::xor_r8_rm8(self, ctx),
            0x33 => execute::logic::xor_r_rm(self, ctx),
            0x34 => execute::logic::xor_al_imm8(self, ctx),
            0x35 => execute::logic::xor_rax_imm(self, ctx),
            0x37 => execute::arith::aaa(self, ctx),
            0x84 => execute::logic::test_rm8_r8(self, ctx),
            0x85 => execute::logic::test_rm_r(self, ctx),
            0xA8 => execute::logic::test_al_imm8(self, ctx),
            0xA9 => execute::logic::test_rax_imm(self, ctx),
            0xF6 => execute::logic::group3_rm8(self, ctx),
            0xF7 => execute::logic::group3_rm(self, ctx),

            // Shifts/Rotates
            0xC0 => execute::shift::group2_rm8_imm8(self, ctx),
            0xC1 => execute::shift::group2_rm_imm8(self, ctx),
            0xD0 => execute::shift::group2_rm8_1(self, ctx),
            0xD1 => execute::shift::group2_rm_1(self, ctx),
            0xD2 => execute::shift::group2_rm8_cl(self, ctx),
            0xD3 => execute::shift::group2_rm_cl(self, ctx),

            // BCD Adjust
            0xD4 => execute::arith::aam(self, ctx),
            0xD5 => execute::arith::aad(self, ctx),

            // System/Flags
            0xFA => execute::system::cli(self, ctx),
            0xFB => execute::system::sti(self, ctx),
            0xF8 => execute::system::clc(self, ctx),
            0xF9 => execute::system::stc(self, ctx),
            0xF5 => execute::system::cmc(self, ctx),
            0xFC => execute::system::cld(self, ctx),
            0xFD => execute::system::std(self, ctx),
            0x9C => execute::system::pushf(self, ctx),
            0x9D => execute::system::popf(self, ctx),
            0x9E => execute::system::sahf(self, ctx),
            0x9F => execute::system::lahf(self, ctx),

            // Loop instructions
            0xE0 => execute::control::loopnz(self, ctx),
            0xE1 => execute::control::loopz(self, ctx),
            0xE2 => execute::control::loop_rel8(self, ctx),
            0xE3 => execute::control::jrcxz(self, ctx),

            // Interrupts
            0xCC => execute::control::int3(self, ctx),
            0xCD => execute::control::int_imm8(self, ctx),
            0xCE => execute::control::into(self, ctx),
            0xF1 => execute::control::icebp(self, ctx),

            // Misc
            0x60 => execute::data::pusha(self, ctx),
            0x61 => execute::data::popa(self, ctx),
            0x62 => execute::data::bound_or_evex(self, ctx),
            0xC8 => execute::data::enter(self, ctx),
            0xC9 => execute::data::leave(self, ctx),
            0xD7 => execute::control::xlat(self, ctx),
            0xFE => execute::control::group4(self, ctx),
            0xFF => execute::control::group5(self, ctx),

            // String operations (handled with REP prefix check)
            0xA4 => execute::string::movsb(self, ctx),
            0xA5 => execute::string::movs(self, ctx),
            0xAA => execute::string::stosb(self, ctx),
            0xAB => execute::string::stos(self, ctx),
            0xAC => execute::string::lodsb(self, ctx),
            0xAD => execute::string::lods(self, ctx),
            0xAE => execute::string::scasb(self, ctx),
            0xAF => execute::string::scas(self, ctx),
            0xA6 => execute::string::cmpsb(self, ctx),
            0xA7 => execute::string::cmps(self, ctx),

            // FWAIT/WAIT - check for pending FPU exceptions (NOP in emulator)
            0x9B => {
                self.regs.rip += ctx.cursor as u64;
                Ok(None)
            }

            // x87 FPU escape opcodes
            0xD8 => execute::fpu::escape_d8(self, ctx),
            0xD9 => execute::fpu::escape_d9(self, ctx),
            0xDA => execute::fpu::escape_da(self, ctx),
            0xDB => execute::fpu::escape_db(self, ctx),
            0xDC => execute::fpu::escape_dc(self, ctx),
            0xDD => execute::fpu::escape_dd(self, ctx),
            0xDE => execute::fpu::escape_de(self, ctx),
            0xDF => execute::fpu::escape_df(self, ctx),

            _ => self.inject_undefined_instruction(),
        }
    }

    fn c4_c5_memory_form(&self, ctx: &InsnContext) -> Result<bool> {
        Ok(!self.sregs.cs.l && (ctx.peek_u8()? >> 6) != 3)
    }

    pub(in crate::isa::x86_64) fn execute_les_or_vex3(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        if self.c4_c5_memory_form(ctx)? {
            execute::data::les(self, ctx)
        } else {
            self.execute_vex3(ctx)
        }
    }

    pub(in crate::isa::x86_64) fn execute_lds_or_vex2(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        if self.c4_c5_memory_form(ctx)? {
            execute::data::lds(self, ctx)
        } else {
            self.execute_vex2(ctx)
        }
    }
}

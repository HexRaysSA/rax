//! VEX.128 packed-string comparisons. Intel SDM 086, Vol. 2B, pp. 4-257,
//! 4-259, 4-270 and 4-272 define the four forms and reserved prefix fields.

use crate::error::Result;
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute::simd::pcmpxstrx;
use crate::vm::vcpu::VcpuExit;

impl X86_64Vcpu {
    pub(in crate::isa::x86_64) fn execute_vex_packed_string(
        &mut self,
        ctx: &mut InsnContext,
        vex_l: u8,
        vvvv: u8,
        opcode: u8,
    ) -> Result<Option<VcpuExit>> {
        // vvvv is already inverted by the VEX decoder. Reject reserved
        // encodings before accessing the ModR/M operand or publishing flags.
        if vex_l != 0 || vvvv != 0 {
            return self.inject_undefined_instruction();
        }
        let (reg, rm, is_memory, address, _) = self.decode_modrm(ctx)?;
        let immediate = ctx.consume_u8()?;
        let first = self.regs.xmm[reg as usize];
        let second = if is_memory {
            [self.read_mem(address, 8)?, self.read_mem(address + 8, 8)?]
        } else {
            self.regs.xmm[rm as usize]
        };
        let (len1, len2) = if opcode < 0x62 {
            if self.sregs.cs.l && ctx.rex_w() {
                (self.regs.rax as i64, self.regs.rdx as i64)
            } else {
                (
                    self.regs.rax as u32 as i32 as i64,
                    self.regs.rdx as u32 as i32 as i64,
                )
            }
        } else {
            (
                pcmpxstrx::find_null_terminator(first[0], first[1], immediate),
                pcmpxstrx::find_null_terminator(second[0], second[1], immediate),
            )
        };
        let mask = opcode & 1 == 0;
        let result = self.pcmpxstrx(
            first[0], first[1], second[0], second[1], len1, len2, immediate, mask,
        );
        if mask {
            self.regs.xmm[0] = [result as u64, (result >> 64) as u64];
            self.regs.ymm_high[0] = [0; 2];
            // Clear explicitly even when XMM0 and YMM0 already equal the
            // result: the common VEX wrapper only detects changed low lanes.
            self.regs.zmm_high[0] = [0; 4];
        } else {
            self.regs.rcx = result as u64;
        }
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }
}

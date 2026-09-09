//! Exact helper-backed scalar ALU memory-source lowering.

use super::*;
use std::collections::HashMap;

enum ImmediateSourceResult {
    Alu(X86ScalarAluImmediate),
    FoldedMove { dst: VReg, zero: bool },
}

impl X86_64Lowerer {
    /// Fuse one exact scalar `Load virtual; ALU/CMP/TEST/IMUL ... virtual` pair into
    /// a fault-precise MMU helper load followed by a native operation using a
    /// caller-owned stack slot. The carrier register is saved twice: one word
    /// preserves its architectural pre-instruction value, while the other
    /// stages the helper result after the call. This covers destructive legacy
    /// forms, APX NDD operand order/aliasing, and compare/test forms without
    /// assigning the SSA temporary to a live guest GPR.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_alu_source(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_alu_source_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (temporary, addr, mem_width) = match &load.kind {
            OpKind::Load {
                dst: temporary @ VReg::Virtual(_),
                addr,
                width,
                sign: SignExtend::Zero,
            } => (*temporary, addr, *width),
            _ => unreachable!("validated scalar memory-source pair starts with Load"),
        };
        let width = mem_width
            .to_op_width()
            .expect("validated scalar memory width has an integer width");
        if let Some(shape) = x86_scalar_alu_immediate_shape(&block.ops[idx + 1]) {
            self.emit_jit_mem_alu_immediate_source(
                load.guest_pc,
                addr,
                ImmediateSourceResult::Alu(shape),
            )?;
            return Ok(Some(consumed));
        }
        if let OpKind::Mov { dst, src, .. } = &block.ops[idx + 1].kind {
            let result = ImmediateSourceResult::FoldedMove {
                dst: *dst,
                zero: src.as_imm() == Some(0),
            };
            self.emit_jit_mem_alu_immediate_source(load.guest_pc, addr, result)?;
            return Ok(Some(consumed));
        }
        let consumer = &block.ops[idx + 1].kind;
        let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
        let carrier = match consumer {
            OpKind::Add { dst, .. }
            | OpKind::Sub { dst, .. }
            | OpKind::Adc { dst, .. }
            | OpKind::Sbb { dst, .. }
            | OpKind::And { dst, .. }
            | OpKind::Or { dst, .. }
            | OpKind::Xor { dst, .. } => *dst,
            OpKind::MulS { dst_lo, .. } => *dst_lo,
            OpKind::Cmp { src1, src2, .. } | OpKind::Test { src1, src2, .. } => {
                match (src1, src2) {
                    (lhs, SrcOperand::Reg(rhs)) if *lhs == temporary => *rhs,
                    (lhs, SrcOperand::Reg(rhs)) if *rhs == temporary => *lhs,
                    (lhs, SrcOperand::Imm(_)) if *lhs == temporary => rax,
                    _ => unreachable!("validated compare/test has one memory temporary"),
                }
            }
            _ => unreachable!("validated scalar memory-source consumer"),
        };
        let carrier_reg = self.get_dst_reg(carrier)?;
        Self::ensure_flag_stack_operands_safe("scalar memory-source", &[carrier_reg])?;

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(carrier_reg);
            emitter.emit_push(carrier_reg);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            Some(carrier),
            None,
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            16,
        )?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            // [rsp] becomes the zero-extended helper result; [rsp+8] retains
            // the complete pre-instruction carrier value for aliases and
            // partial-register destination semantics.
            emitter.emit_mov_mr(PhysReg::Rsp, 0, carrier_reg, OpWidth::W64);
            emitter.emit_mov_rm(carrier_reg, PhysReg::Rsp, 8, OpWidth::W64);
        }

        let finish = |this: &mut Self, restore_flags: bool| {
            if restore_flags {
                this.code.emit_u8(0x9D); // popfq
            }
            let mut emitter = X86Emitter::new(&mut this.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        };

        if let OpKind::MulS {
            dst_lo,
            dst_hi: None,
            src1,
            src2: SrcOperand::Imm(value),
            flags,
            ..
        } = consumer
        {
            debug_assert_eq!(*dst_lo, carrier);
            debug_assert_eq!(*src1, temporary);
            let preserve_flags = *flags == FlagUpdate::None;
            let use_imm8 = match block.ops[idx + 1].x86_hint {
                Some(X86OpHint::ImulImm8) => true,
                Some(X86OpHint::ImulImm32) => false,
                _ => unreachable!("validated immediate memory IMUL hint"),
            };
            if preserve_flags {
                self.code.emit_u8(0x9C); // pushfq
            }
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_imul_rmi_disp(
                carrier_reg,
                PhysReg::Rsp,
                if preserve_flags { 8 } else { 0 },
                DispSize::Auto,
                *value as i32,
                width,
                use_imm8,
            );
            finish(self, preserve_flags);
            return Ok(Some(consumed));
        }

        if let OpKind::MulS {
            dst_lo,
            dst_hi: None,
            src1,
            src2: SrcOperand::Reg(source),
            flags,
            ..
        } = consumer
        {
            debug_assert_eq!(*dst_lo, *src1);
            debug_assert_eq!(*source, temporary);
            let preserve_flags = *flags == FlagUpdate::None;
            if preserve_flags {
                self.code.emit_u8(0x9C); // pushfq
            }
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_imul_rm_disp(
                carrier_reg,
                PhysReg::Rsp,
                if preserve_flags { 8 } else { 0 },
                DispSize::Auto,
                width,
            );
            finish(self, preserve_flags);
            return Ok(Some(consumed));
        }

        let binary = match consumer {
            OpKind::Add {
                dst,
                src1,
                src2,
                flags,
                ..
            } => Some((0x00, 0, *dst, *src1, src2, *flags)),
            OpKind::Or {
                dst,
                src1,
                src2,
                flags,
                ..
            } => Some((0x08, 1, *dst, *src1, src2, *flags)),
            OpKind::Adc {
                dst,
                src1,
                src2,
                flags,
                ..
            } => Some((0x10, 2, *dst, *src1, src2, *flags)),
            OpKind::Sbb {
                dst,
                src1,
                src2,
                flags,
                ..
            } => Some((0x18, 3, *dst, *src1, src2, *flags)),
            OpKind::And {
                dst,
                src1,
                src2,
                flags,
                ..
            } => Some((0x20, 4, *dst, *src1, src2, *flags)),
            OpKind::Sub {
                dst,
                src1,
                src2,
                flags,
                ..
            } => Some((0x28, 5, *dst, *src1, src2, *flags)),
            OpKind::Xor {
                dst,
                src1,
                src2,
                flags,
                ..
            } => Some((0x30, 6, *dst, *src1, src2, *flags)),
            _ => None,
        };

        if let Some((opcode, digit, dst, src1, src2, flags)) = binary {
            debug_assert_eq!(dst, carrier);
            let preserve_flags = flags == FlagUpdate::None;
            if matches!(src2, SrcOperand::Reg(rhs) if *rhs == temporary) {
                if dst != src1 {
                    let src1_reg = self.get_reg(src1)?;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(carrier_reg, src1_reg, width);
                }
                if preserve_flags {
                    self.code.emit_u8(0x9C); // pushfq
                }
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mem_disp(
                    opcode,
                    carrier_reg,
                    PhysReg::Rsp,
                    if preserve_flags { 8 } else { 0 },
                    DispSize::Auto,
                    width,
                    X86AluEncoding::RegRm,
                );
            } else {
                debug_assert_eq!(src1, temporary);
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rm(carrier_reg, PhysReg::Rsp, 0, width);
                }
                if preserve_flags {
                    self.code.emit_u8(0x9C); // pushfq
                }
                match src2 {
                    SrcOperand::Reg(rhs) if *rhs == dst => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_alu_mem_disp(
                            opcode,
                            carrier_reg,
                            PhysReg::Rsp,
                            if preserve_flags { 16 } else { 8 },
                            DispSize::Auto,
                            width,
                            X86AluEncoding::RegRm,
                        );
                    }
                    SrcOperand::Reg(rhs) => {
                        let rhs_reg = self.get_reg(*rhs)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_alu_rr(opcode, carrier_reg, rhs_reg, width);
                    }
                    SrcOperand::Imm(value) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_alu_ri(digit, carrier_reg, *value, width);
                    }
                    _ => unreachable!("validated scalar memory-source operand"),
                }
            }
            finish(self, preserve_flags);
            return Ok(Some(consumed));
        }

        match consumer {
            OpKind::Cmp { src1, src2, .. } => {
                let mut emitter = X86Emitter::new(&mut self.code);
                match (src1, src2) {
                    (lhs, SrcOperand::Reg(_)) if *lhs == temporary => {
                        emitter.emit_alu_mem_disp(
                            0x38,
                            carrier_reg,
                            PhysReg::Rsp,
                            0,
                            DispSize::Auto,
                            width,
                            X86AluEncoding::RmReg,
                        );
                    }
                    (_, SrcOperand::Reg(rhs)) if *rhs == temporary => {
                        emitter.emit_alu_mem_disp(
                            0x38,
                            carrier_reg,
                            PhysReg::Rsp,
                            0,
                            DispSize::Auto,
                            width,
                            X86AluEncoding::RegRm,
                        );
                    }
                    (lhs, SrcOperand::Imm(value)) if *lhs == temporary => {
                        emitter.emit_alu_mi_disp(7, PhysReg::Rsp, 0, DispSize::Auto, *value, width);
                    }
                    _ => unreachable!("validated memory CMP operand order"),
                }
            }
            OpKind::Test { src1, src2, .. } => {
                let mut emitter = X86Emitter::new(&mut self.code);
                match (src1, src2) {
                    (lhs, SrcOperand::Reg(_)) if *lhs == temporary => emitter.emit_test_mr_disp(
                        PhysReg::Rsp,
                        0,
                        DispSize::Auto,
                        carrier_reg,
                        width,
                    ),
                    (_, SrcOperand::Reg(rhs)) if *rhs == temporary => emitter.emit_test_mr_disp(
                        PhysReg::Rsp,
                        0,
                        DispSize::Auto,
                        carrier_reg,
                        width,
                    ),
                    (lhs, SrcOperand::Imm(value)) if *lhs == temporary => {
                        emitter.emit_test_mi_disp(PhysReg::Rsp, 0, DispSize::Auto, *value, width)
                    }
                    _ => unreachable!("validated memory TEST operand order"),
                }
            }
            _ => unreachable!("validated scalar memory-source consumer"),
        }
        finish(self, false);
        Ok(Some(consumed))
    }

    /// Full-width constants use a neutral caller frame. The helper sees the
    /// original address and GPRs before any architectural destination commits.
    #[cfg(feature = "smir-jit")]
    fn emit_jit_mem_alu_immediate_source(
        &mut self,
        guest_pc: u64,
        addr: &Address,
        result: ImmediateSourceResult,
    ) -> Result<(), LowerError> {
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -32);
            emitter.emit_mov_mr(PhysReg::Rsp, 24, PhysReg::Rax, OpWidth::W64);
        }
        self.emit_jit_mem_op(
            guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            MemWidth::B8,
            SignExtend::Zero,
            32,
        )?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, OpWidth::W64);
        }
        let destination = match result {
            ImmediateSourceResult::Alu(shape) => {
                let preserve_flags = shape.flags == FlagUpdate::None;
                if preserve_flags {
                    self.code.emit_u8(0x9C);
                }
                self.emit_scalar_alu_immediate(
                    shape.kind,
                    PhysReg::Rax,
                    shape.value,
                    OpWidth::W64,
                    None,
                    &[],
                )?;
                if preserve_flags {
                    self.code.emit_u8(0x9D);
                }
                shape.dst
            }
            ImmediateSourceResult::FoldedMove { dst, zero } => {
                if zero {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_ri_imm64(PhysReg::Rax, 0);
                }
                Some(dst)
            }
        };
        let mut restore_rax = true;
        if let Some(destination) = destination {
            let index =
                Self::x86_gpr_index(destination).ok_or_else(|| LowerError::InvalidOperand {
                    op: "W64 immediate memory source".to_string(),
                    operand: "destination is not an architectural x86 GPR".to_string(),
                })?;
            if Self::x86_state_backed_gpr(destination) {
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_push(PhysReg::Rdx);
                    emitter.emit_mov_rr(PhysReg::Rdx, PhysReg::Rax, OpWidth::W64);
                }
                self.emit_load_state_ptr_rax();
                self.emit_store_gpr_slot_from_reg(index, PhysReg::Rdx, OpWidth::W64)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                if index == 5 {
                    emitter.emit_mov_mr(PhysReg::Rbp, 0, PhysReg::Rdx, OpWidth::W64);
                }
                emitter.emit_pop(PhysReg::Rdx);
            } else {
                let destination = self.get_dst_reg(destination)?;
                restore_rax = destination != PhysReg::Rax;
                if restore_rax {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(destination, PhysReg::Rax, OpWidth::W64);
                }
            }
        }
        let mut emitter = X86Emitter::new(&mut self.code);
        if restore_rax {
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        }
        emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 32);
        Ok(())
    }
}

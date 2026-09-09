//! Exact helper-backed scalar ALU read-modify-write lowering.

use super::*;
use std::collections::HashMap;

impl X86_64Lowerer {
    /// Fuse the exact fault-precise memory-destination ALU sequence emitted by
    /// the x86 lifter. A 32-byte caller frame retains the original memory
    /// value, store value, arithmetic source, and guest RAX. Both helper calls
    /// therefore observe coherent architectural registers, while the store can
    /// consume its value without assigning either virtual result to a guest GPR.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_alu_rmw(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        if let Some(folded) = crate::smir::lower::runtime::x86_jit_mem_alu_folded_rmw_sequence(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) {
            let load = &block.ops[idx];
            let OpKind::Load { addr, .. } = &load.kind else {
                unreachable!("validated folded scalar RMW starts with Load");
            };
            self.emit_fused_mem_alu_rmw(
                load.guest_pc,
                addr,
                MemWidth::B8,
                OpWidth::W64,
                folded.opcode,
                folded.digit,
                &SrcOperand::Imm(folded.immediate),
                folded.replay,
            )?;
            return Ok(Some(folded.consumed));
        }
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_alu_rmw_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated scalar RMW starts with Load"),
        };
        let width = mem_width
            .to_op_width()
            .expect("validated scalar RMW width has an integer width");
        let (opcode, digit, source) = match &block.ops[idx + 1].kind {
            OpKind::Add { src2, .. } => (0x00, 0, src2),
            OpKind::Or { src2, .. } => (0x08, 1, src2),
            OpKind::Adc { src2, .. } => (0x10, 2, src2),
            OpKind::Sbb { src2, .. } => (0x18, 3, src2),
            OpKind::And { src2, .. } => (0x20, 4, src2),
            OpKind::Sub { src2, .. } => (0x28, 5, src2),
            OpKind::Xor { src2, .. } => (0x30, 6, src2),
            _ => unreachable!("validated scalar RMW consumer"),
        };
        self.emit_fused_mem_alu_rmw(
            load.guest_pc,
            addr,
            mem_width,
            width,
            opcode,
            digit,
            source,
            consumed == 4,
        )?;
        Ok(Some(consumed))
    }

    /// Emit the fault-precise helper-backed memory read-modify-write body
    /// shared by the plain and LOCK-prefixed forms. `replay` regenerates the
    /// architectural flags after a successful store; a caller whose flag result
    /// was proven dead passes `false`.
    #[cfg(feature = "smir-jit")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_fused_mem_alu_rmw(
        &mut self,
        guest_pc: u64,
        addr: &Address,
        mem_width: MemWidth,
        width: OpWidth,
        opcode: u8,
        digit: u8,
        source: &SrcOperand,
        replay: bool,
    ) -> Result<(), LowerError> {
        self.emit_fused_mem_alu_rmw_with_writeback(
            guest_pc, addr, mem_width, width, opcode, digit, source, replay, None,
        )
    }

    /// As [`Self::emit_fused_mem_alu_rmw`], additionally delivering the
    /// pre-operation memory value into an architectural GPR once the store has
    /// retired. `MOV` is flag-neutral, so the optional replay's published flags
    /// survive the write-back.
    #[cfg(feature = "smir-jit")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_fused_mem_alu_rmw_with_writeback(
        &mut self,
        guest_pc: u64,
        addr: &Address,
        mem_width: MemWidth,
        width: OpWidth,
        opcode: u8,
        digit: u8,
        source: &SrcOperand,
        replay: bool,
        writeback: Option<(PhysReg, OpWidth)>,
    ) -> Result<(), LowerError> {
        self.emit_fused_mem_alu_rmw_full(
            guest_pc, addr, mem_width, width, opcode, digit, source, replay, None, writeback,
        )
    }

    /// As [`Self::emit_fused_mem_alu_rmw_with_writeback`], additionally
    /// selecting the unary `INC`/`DEC` flag contract for the post-store replay.
    #[cfg(feature = "smir-jit")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_fused_mem_alu_rmw_full(
        &mut self,
        guest_pc: u64,
        addr: &Address,
        mem_width: MemWidth,
        width: OpWidth,
        opcode: u8,
        digit: u8,
        source: &SrcOperand,
        replay: bool,
        replay_unary: Option<u8>,
        writeback: Option<(PhysReg, OpWidth)>,
    ) -> Result<(), LowerError> {
        self.emit_fused_mem_alu_rmw_swap(
            guest_pc,
            addr,
            mem_width,
            width,
            opcode,
            digit,
            source,
            replay,
            replay_unary,
            writeback,
            false,
        )
    }

    /// As [`Self::emit_fused_mem_alu_rmw_full`], additionally supporting the
    /// `XCHG` form, whose stored element is the source itself rather than an
    /// arithmetic combination and which publishes no flags at all.
    #[cfg(feature = "smir-jit")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_fused_mem_alu_rmw_swap(
        &mut self,
        guest_pc: u64,
        addr: &Address,
        mem_width: MemWidth,
        width: OpWidth,
        opcode: u8,
        digit: u8,
        source: &SrcOperand,
        replay: bool,
        replay_unary: Option<u8>,
        writeback: Option<(PhysReg, OpWidth)>,
        swap: bool,
    ) -> Result<(), LowerError> {
        // Caller-frame layout after the flag-neutral reservation:
        //   [rsp+0]  original zero-extended memory value
        //   [rsp+8]  computed store value
        //   [rsp+16] staged register or non-encodable W64 immediate source
        //   [rsp+24] complete architectural RAX
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -32);
            emitter.emit_mov_mr(PhysReg::Rsp, 24, PhysReg::Rax, OpWidth::W64);
        }
        let source_from_frame = matches!(source, SrcOperand::Reg(_))
            || source
                .as_imm()
                .is_some_and(|value| !scalar_alu_immediate_is_encodable(value, width));
        if let SrcOperand::Reg(source) = source {
            let index = Self::x86_gpr_index(*source)
                .expect("validated scalar RMW register source is an x86 GPR");
            if index <= 15 && !matches!(index, 4 | 5) {
                let source_reg = self.get_reg(*source)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rsp, 16, source_reg, OpWidth::W64);
            } else {
                // RSP, RBP, and APX EGPRs are state-backed rather than identity
                // mapped. Snapshot their coherent GuestRegs slot through saved
                // RAX without exposing host RSP/RBP to guest semantics.
                self.emit_load_state_ptr_rax();
                self.emit_struct_mov(PhysReg::Rax, 0, i32::from(index) * 8, false);
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rsp, 16, PhysReg::Rax, OpWidth::W64);
                emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            }
        } else if source_from_frame {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_ri_imm64(PhysReg::Rax, source.as_imm().expect("validated immediate"));
            emitter.emit_mov_mr(PhysReg::Rsp, 16, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        }

        // The load helper writes to caller [rsp+0]: its own PUSH RAX/PUSHFQ
        // make that slot [rsp+16] while the call-out is active.
        self.emit_jit_mem_op(
            guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        // Compute the store value while preserving the incoming flags. PUSHFQ
        // shifts the staged register source from caller +16 to active +24;
        // ADC/SBB still read the incoming CF because PUSHFQ is flag-neutral.
        if swap {
            // The replacement element is the source itself.
            let mut emitter = X86Emitter::new(&mut self.code);
            match source {
                SrcOperand::Reg(_) => {
                    emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 16, OpWidth::W64)
                }
                SrcOperand::Imm(value) | SrcOperand::Imm64(value) => {
                    emitter.emit_mov_ri_imm64(PhysReg::Rax, *value)
                }
                _ => unreachable!("validated scalar RMW source"),
            }
            emitter.emit_mov_mr(PhysReg::Rsp, 8, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            return self.emit_fused_mem_alu_rmw_tail(guest_pc, addr, mem_width, writeback);
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, width);
        }
        self.code.emit_u8(0x9C); // pushfq
        match source {
            _ if source_from_frame => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mem_disp(
                    opcode,
                    PhysReg::Rax,
                    PhysReg::Rsp,
                    24,
                    DispSize::Auto,
                    width,
                    X86AluEncoding::RegRm,
                );
            }
            SrcOperand::Imm(value) | SrcOperand::Imm64(value) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_ri(digit, PhysReg::Rax, *value, width);
            }
            _ => unreachable!("validated scalar RMW source"),
        }
        self.code.emit_u8(0x9D); // popfq
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(PhysReg::Rsp, 8, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        }

        // The store helper's internal 16-byte spill shifts caller [rsp+8] to
        // active [rsp+24]. A store fault removes the complete caller frame and
        // exits at the current instruction without committing flags or GPRs.
        self.emit_jit_mem_op(
            guest_pc,
            false,
            None,
            None,
            None,
            None,
            Some(24),
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        // Only a successful store reaches the replay. It regenerates the exact
        // architectural flags from the original memory/source operands, then
        // restores RAX and releases the caller frame with flag-neutral MOV/LEA.
        // The three-operation form has no architectural flag update at all
        // (optimization proved it dead), so it skips straight to the restore.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            if replay {
                emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, width);
                match replay_unary {
                    Some(1) => emitter.emit_inc(PhysReg::Rax, width),
                    Some(2) => emitter.emit_dec(PhysReg::Rax, width),
                    Some(_) => unreachable!("validated unary RMW replay tag"),
                    None => match source {
                        _ if source_from_frame => emitter.emit_alu_mem_disp(
                            opcode,
                            PhysReg::Rax,
                            PhysReg::Rsp,
                            16,
                            DispSize::Auto,
                            width,
                            X86AluEncoding::RegRm,
                        ),
                        SrcOperand::Imm(value) | SrcOperand::Imm64(value) => {
                            emitter.emit_alu_ri(digit, PhysReg::Rax, *value, width)
                        }
                        _ => unreachable!("validated scalar RMW replay source"),
                    },
                }
            }
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            if let Some((destination, destination_width)) = writeback {
                emitter.emit_mov_rm(destination, PhysReg::Rsp, 0, destination_width);
            }
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 32);
        }
        Ok(())
    }

    /// Commit a fused read-modify-write whose replacement element is already
    /// staged at caller `[rsp+8]`: run the store helper, restore the scratch
    /// accumulator, deliver the optional architectural write-back, and release
    /// the caller frame. Every instruction here is `MOV`/`LEA`, so a flag image
    /// published earlier survives unchanged.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn emit_fused_mem_alu_rmw_tail(
        &mut self,
        guest_pc: u64,
        addr: &Address,
        mem_width: MemWidth,
        writeback: Option<(PhysReg, OpWidth)>,
    ) -> Result<(), LowerError> {
        self.emit_jit_mem_op(
            guest_pc,
            false,
            None,
            None,
            None,
            None,
            Some(24),
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        if let Some((destination, destination_width)) = writeback {
            emitter.emit_mov_rm(destination, PhysReg::Rsp, 0, destination_width);
        }
        emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 32);
        Ok(())
    }

    /// Fuse the LOCK-prefixed memory read-modify-write emitted by the x86
    /// lifter. The emulator realizes a locked ALU as an ordinary
    /// read-modify-write through the vCPU MMU in both interpreters, so the
    /// fused native form reproduces interpretation exactly.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_atomic_rmw(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_mem_atomic_rmw_sequence(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };
        let source = match sequence.source_reg {
            Some(reg) => SrcOperand::Reg(reg),
            None => SrcOperand::Imm(sequence.source_imm),
        };
        let writeback = match sequence.writeback {
            Some(dst) => Some((self.get_dst_reg(dst)?, sequence.width)),
            None => None,
        };
        self.emit_fused_mem_alu_rmw_swap(
            sequence.guest_pc,
            sequence.addr,
            sequence.mem_width,
            sequence.width,
            sequence.opcode,
            sequence.digit,
            &source,
            sequence.replay,
            sequence.replay_unary,
            writeback,
            sequence.swap,
        )?;
        Ok(Some(sequence.consumed))
    }
}

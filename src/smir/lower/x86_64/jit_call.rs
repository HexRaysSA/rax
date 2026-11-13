//! Fault-precise guest CALL lowering for the lift-through-calls JIT path.

use super::*;

/// Validate the exact terminal encoding used by the 64-bit callout ABI.
///
/// The current direct interpreter treats a legacy `0x66` override as a
/// 16-bit near CALL, while the callout ABI implements an 8-byte return-address
/// push and 64-bit target. Reject that prefix until the direct and lifted width
/// contracts are unified. Malformed provenance fails closed.
fn jit_call_instruction_uses_64_bit_abi(instruction: &X86InstructionBytes) -> bool {
    let bytes = instruction.as_slice();
    let mut cursor = 0usize;
    let mut lock = false;
    loop {
        let Some(&byte) = bytes.get(cursor) else {
            return false;
        };
        match byte {
            0x66 => return false,
            0xF0 => {
                lock = true;
                cursor += 1;
            }
            0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x67 | 0x40..=0x4F => {
                cursor += 1;
            }
            // APX REX2 is a two-byte prefix. Skip its already-decoded payload
            // rather than interpreting payload bits as another prefix/opcode.
            0xD5 => {
                if bytes.get(cursor + 1).is_none() {
                    return false;
                }
                cursor += 2;
            }
            _ => break,
        }
    }
    if lock {
        return false;
    }
    match bytes.get(cursor..).unwrap_or_default() {
        [0xE8, _, _, _, _, ..] => true,
        [0xFF, modrm, ..] => (modrm >> 3) & 7 == 2,
        _ => false,
    }
}

impl X86_64Lowerer {
    /// Recover the guest PC of the terminal CALL from exact instruction
    /// provenance. The continuation is its architectural return address, so
    /// only the instruction ending at that PC is a valid call site.
    pub(crate) fn jit_call_site_pc(
        &self,
        source: BlockId,
        continuation: BlockId,
    ) -> Result<GuestAddr, LowerError> {
        let return_pc =
            *self
                .block_guest_pcs
                .get(&continuation)
                .ok_or_else(|| LowerError::UnsupportedOp {
                    op: "jit-call: continuation guest_pc unknown".to_string(),
                })?;
        let mut candidates =
            self.x86_instruction_bytes
                .iter()
                .filter_map(|(&(block, pc), instruction)| {
                    (block == source
                        && pc.checked_add(instruction.as_slice().len() as u64) == Some(return_pc))
                    .then_some((pc, instruction))
                });
        let (call_pc, instruction) =
            candidates.next().ok_or_else(|| LowerError::UnsupportedOp {
                op: format!(
                    "jit-call: no instruction in {source:?} ends at continuation {return_pc:#x}"
                ),
            })?;
        if candidates.next().is_some() {
            return Err(LowerError::UnsupportedOp {
                op: format!(
                    "jit-call: ambiguous instruction provenance in {source:?} at continuation {return_pc:#x}"
                ),
            });
        }
        if !jit_call_instruction_uses_64_bit_abi(instruction) {
            return Err(LowerError::UnsupportedOp {
                op: format!("jit-call: unsupported terminal encoding at {call_pc:#x}"),
            });
        }
        Ok(call_pc)
    }

    /// Lower a guest `CALL` as a runtime call-out (lift-through-calls). Spills
    /// all guest registers and RFLAGS to `GuestRegs`, then calls `call_fn` with
    /// `(gr_ptr, target_pc, return_pc, call_pc)`. The helper runs the callee in
    /// the interpreter until it returns to `return_pc`.
    ///
    /// A memory-indirect target is read through the guest MMU before the CALL's
    /// stack push. The 8-byte target is held in a fixed 16-byte host-stack slot;
    /// a target-read fault exits at `call_pc` without changing guest RSP. On a
    /// clean target read, the regular callout helper performs the architectural
    /// return-address push and can independently deopt a stack fault at the same
    /// instruction boundary.
    pub(crate) fn emit_jit_call_op(
        &mut self,
        target: &CallTarget,
        continuation: BlockId,
        call_pc: GuestAddr,
    ) -> Result<(), LowerError> {
        let return_pc =
            *self
                .block_guest_pcs
                .get(&continuation)
                .ok_or_else(|| LowerError::UnsupportedOp {
                    op: "jit-call: continuation guest_pc unknown".to_string(),
                })?;

        enum TargetSource {
            Direct(u64),
            Reg(u8),
            Stack,
        }

        let (target_source, caller_stack_bytes) = match target {
            CallTarget::GuestAddr(address) => (TargetSource::Direct(*address), 0i32),
            CallTarget::Indirect(reg) => (TargetSource::Reg(self.jit_arch_enc(*reg)?), 0),
            CallTarget::IndirectMem(addr)
                if self.mem_helpers && addr.is_x86_state_backed_shape() =>
            {
                // Preserve flags and call alignment while reserving one complete
                // 8-byte target plus 8 bytes of padding. emit_jit_mem_op's two
                // pushes place the caller slot at [rsp+16]. Its fault path owns
                // and releases this reservation before returning.
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
                }
                self.emit_jit_mem_op(
                    call_pc,
                    true,
                    None,
                    Some(16),
                    None,
                    None,
                    None,
                    addr,
                    MemWidth::B8,
                    SignExtend::Zero,
                    16,
                )?;
                (TargetSource::Stack, 16)
            }
            CallTarget::X86IndirectMemAddr32(addr)
                if self.mem_helpers && addr.is_x86_addr32_state_backed_shape() =>
            {
                // The target load has the same fault/stack contract as the
                // ordinary memory form, but its effective offset is evaluated
                // modulo 2^32 before an optional FS/GS base is added.
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
                }
                self.emit_jit_mem_op_addr32(
                    call_pc,
                    true,
                    None,
                    Some(16),
                    None,
                    None,
                    None,
                    addr,
                    MemWidth::B8,
                    SignExtend::Zero,
                    16,
                )?;
                (TargetSource::Stack, 16)
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("jit-call target {target:?}"),
                });
            }
        };

        // --- spill: push rax; rax=state ptr; pushfq; spill GPRs + RAX ---
        self.code.emit_u8(0x50);
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x45);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
        self.code.emit_u8(0x9C);
        for enc in [1u8, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            self.emit_struct_mov(PhysReg::Rax, enc, (enc as i32) * 8, true);
        }
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4C);
        self.code.emit_u8(0x24);
        self.code.emit_u8(0x08);
        self.emit_struct_mov(PhysReg::Rax, 1, 0, true);
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x0C);
        self.code.emit_u8(0x24);
        self.emit_struct_mov(PhysReg::Rax, 1, X86_GUEST_RFLAGS_OFFSET, true);

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_call_helpers);

        // SysV args: RDI=GuestRegs, RSI=target, RDX=return PC, RCX=call PC.
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x89);
        self.code.emit_u8(0xC7);
        match target_source {
            TargetSource::Direct(address) => self.emit_movabs(6, address),
            TargetSource::Reg(enc) => {
                self.emit_struct_mov(PhysReg::Rax, 6, (enc as i32) * 8, false)
            }
            TargetSource::Stack => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rsi, PhysReg::Rsp, 16, OpWidth::W64);
            }
        }
        self.emit_movabs(2, return_pc);
        self.emit_movabs(1, call_pc);

        self.emit_host_c_helper_call(X86_GUEST_CALL_FN_OFFSET as u32);
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4D);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x85);
        self.code.emit_u8(0xC0);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x84);
        let jz_pos = self.code.position();
        self.code.emit_u32(0);

        // --- success: restore post-callee state and resume continuation ---
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_call_helpers);
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0xB1);
        self.code.emit_u32(X86_GUEST_RFLAGS_OFFSET as u32);
        self.code.emit_bytes(&[0x48, 0x81, 0x24, 0x24]);
        self.code.emit_i32(-0x44101); // keep host TF/NT/AC clear
        self.code.emit_u8(0x9D);
        self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
        self.emit_reload_all(PhysReg::Rcx);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16 + caller_stack_bytes);
        }
        self.code.emit_u8(0xE9);
        let jmp_off = self.code.position();
        self.code.emit_u32(0);
        self.pending_jumps
            .push((jmp_off, continuation, RelocKind::PcRel32));

        // --- bailout: helper published exit_pc; restore and return ---
        let bail = self.code.position();
        self.code
            .patch_i32(jz_pos, (bail as i64 - (jz_pos as i64 + 4)) as i32);
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_call_helpers);
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0xB1);
        self.code.emit_u32(X86_GUEST_RFLAGS_OFFSET as u32);
        self.code.emit_bytes(&[0x48, 0x81, 0x24, 0x24]);
        self.code.emit_i32(-0x44101); // keep host TF/NT/AC clear
        self.code.emit_u8(0x9D);
        self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
        self.emit_reload_all(PhysReg::Rcx);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16 + caller_stack_bytes);
        }
        self.emit_epilogue_with_ret(None);
        Ok(())
    }
}

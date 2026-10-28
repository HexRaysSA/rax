//! XSETBV provenance validation and state-backed native lowering.

use crate::smir::lower::x86_64::*;

fn x86_xsetbv_shape_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::X86XSetBv {
            selector: VReg::Arch(ArchReg::X86(X86Reg::Rcx)),
            src_low: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            src_high: VReg::Arch(ArchReg::X86(X86Reg::Rdx)),
        }
    ) && op.x86_hint.is_none()
}

/// Derive XSETBV's precise successful handoff PC from exact source provenance.
///
/// Intel SDM revision 092 specifies `NP 0F 01 D1`: 66H/F2H/F3H and LOCK are
/// invalid, while segment, address-size, and REX prefixes are ignored. The
/// x86-64 lifter accepts exactly those ignored prefix bytes (including repeated
/// or reordered ignored prefixes) and emits one unhinted architectural op.
/// Requiring that complete source shape prevents arbitrary metadata from being
/// used solely as a length oracle. If a following instruction is present in
/// the block, its PC must agree with the byte-derived boundary.
///
/// Runtime is O(1) and auxiliary space is O(1): architectural x86 instruction
/// provenance is bounded to 15 bytes.
pub(crate) fn x86_xsetbv_resume_pc(
    block: &SmirBlock,
    op_index: usize,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> Option<GuestAddr> {
    let op = block.ops.get(op_index)?;
    if !x86_xsetbv_shape_valid(op)
        || block
            .ops
            .iter()
            .enumerate()
            .any(|(index, candidate)| index != op_index && candidate.guest_pc == op.guest_pc)
    {
        return None;
    }

    let source = instruction_bytes.get(&(block.id, op.guest_pc))?.as_slice();
    let prefix_len = source.len().checked_sub(3)?;
    if source[prefix_len..] != [0x0F, 0x01, 0xD1]
        || !source[..prefix_len].iter().all(|byte| {
            matches!(
                byte,
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x67 | 0x40..=0x4F
            )
        })
    {
        return None;
    }

    let resume_pc = op.guest_pc.checked_add(source.len() as u64)?;
    if block.ops[op_index + 1..]
        .iter()
        .find(|next| next.guest_pc != op.guest_pc)
        .is_some_and(|next| next.guest_pc != resume_pc)
    {
        return None;
    }
    Some(resume_pc)
}

impl X86_64Lowerer {
    /// Lower XSETBV as a state-backed control update followed by an immediate
    /// native-region handoff. Returning at `resume_pc` is required: changing
    /// XCR0 can enable or disable subsequent vector instructions, so code that
    /// was admitted under the entry state must not continue in the same region.
    /// Invalid state restores every input and returns at the XSETBV PC, letting
    /// the interpreter deliver #UD or #GP(0) with precise restart semantics.
    pub(crate) fn emit_xsetbv(&mut self, op: &SmirOp, resume_pc: u64) -> Result<(), LowerError> {
        let (selector, src_low, src_high) = match &op.kind {
            OpKind::X86XSetBv {
                selector,
                src_low,
                src_high,
            } => (*selector, *src_low, *src_high),
            _ => unreachable!("emit_xsetbv requires X86XSetBv"),
        };
        if self.get_reg(selector)? != PhysReg::Rcx
            || self.get_reg(src_low)? != PhysReg::Rax
            || self.get_reg(src_high)? != PhysReg::Rdx
        {
            return Err(LowerError::InvalidOperand {
                op: "X86XSetBv".to_string(),
                operand: "requires ECX selector and EDX:EAX source".to_string(),
            });
        }

        // [rsp+0]=RDX, [rsp+8]=RCX, [rsp+16]=RAX, [rsp+24]=RFLAGS.
        // The architectural instruction preserves every one of these values on
        // both success and fault, so all scratch computation is stack-backed.
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.code.emit_u8(0x51); // push rcx
        self.code.emit_u8(0x52); // push rdx
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x45);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rax,[rbp+state]

        let mut fault_branches = Vec::new();

        // CR4.OSXSAVE=0 raises #UD before selector/value validation.
        self.code.emit_u8(0xF7);
        self.code.emit_u8(0x80);
        self.code.emit_u32(X86_GUEST_CR4_OFFSET as u32);
        self.code.emit_u32(1 << 18); // test dword [rax+cr4],1<<18
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));

        // In protected mode XSETBV requires CPL=0. Real mode ignores CS.RPL.
        self.code.emit_u8(0xF7);
        self.code.emit_u8(0x80);
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1); // test dword [rax+cr0],CR0.PE
        let privilege_ok = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x83);
        self.code.emit_u8(0xB8);
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0); // cmp qword [rax+cpl],0
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));
        self.patch_rel32_to_current(privilege_ok)?;

        // Only XCR0 (ECX=0) is writable.
        self.code.emit_u8(0x83);
        self.code.emit_u8(0x7C);
        self.code.emit_u8(0x24);
        self.code.emit_u8(0x08);
        self.code.emit_u8(0); // cmp dword [rsp+8],0
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));

        // RCX = zero-extended EDX:EAX candidate, reconstructed from snapshots.
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4C);
        self.code.emit_u8(0x24);
        self.code.emit_u8(0x10); // mov ecx,[rsp+16]
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x14);
        self.code.emit_u8(0x24); // mov edx,[rsp]
        self.code.emit_u8(0x48);
        self.code.emit_u8(0xC1);
        self.code.emit_u8(0xE2);
        self.code.emit_u8(0x20); // shl rdx,32
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x09);
        self.code.emit_u8(0xD1); // or rcx,rdx

        // X87 must remain enabled.
        self.code.emit_u8(0xF6);
        self.code.emit_u8(0xC1);
        self.code.emit_u8(0x01); // test cl,1
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));

        // Supported state is x87/SSE/AVX/AVX-512/PKRU plus APX_F only when the
        // emulator exposes APX. TEST r64,imm32 sign-extends the immediate, and
        // both complements have identical ones in bits 63:32.
        self.code.emit_u8(0x83);
        self.code.emit_u8(0xB8);
        self.code.emit_u32(X86_GUEST_APX_ENABLED_OFFSET as u32);
        self.code.emit_u8(0); // cmp dword [rax+apx_enabled],0
        let no_apx = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_u8(0x48);
        self.code.emit_u8(0xF7);
        self.code.emit_u8(0xC1);
        self.code.emit_u32(!(0x2E7u32 | (1 << 19))); // test rcx,!supported_with_apx
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));
        self.code.emit_u8(0xE9);
        let supported = self.code.position();
        self.code.emit_u32(0);
        self.patch_rel32_to_current(no_apx)?;
        self.code.emit_u8(0x48);
        self.code.emit_u8(0xF7);
        self.code.emit_u8(0xC1);
        self.code.emit_u32(!0x2E7u32); // test rcx,!supported_without_apx
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));
        self.patch_rel32_to_current(supported)?;

        // AVX (bit 2) depends on SSE (bit 1).
        self.code.emit_u8(0xF6);
        self.code.emit_u8(0xC1);
        self.code.emit_u8(0x04); // test cl,4
        let avx_dependency_ok = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_u8(0xF6);
        self.code.emit_u8(0xC1);
        self.code.emit_u8(0x02); // test cl,2
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));
        self.patch_rel32_to_current(avx_dependency_ok)?;

        // AVX-512 bits 7:5 are all-or-none and require SSE+AVX.
        self.code.emit_u8(0x89);
        self.code.emit_u8(0xCA); // mov edx,ecx
        self.code.emit_u8(0x81);
        self.code.emit_u8(0xE2);
        self.code.emit_u32(0xE0); // and edx,0xE0
        let avx512_ok = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_u8(0x81);
        self.code.emit_u8(0xFA);
        self.code.emit_u32(0xE0); // cmp edx,0xE0
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));
        self.code.emit_u8(0x89);
        self.code.emit_u8(0xCA); // mov edx,ecx
        self.code.emit_u8(0x83);
        self.code.emit_u8(0xE2);
        self.code.emit_u8(0x06); // and edx,6
        self.code.emit_u8(0x83);
        self.code.emit_u8(0xFA);
        self.code.emit_u8(0x06); // cmp edx,6
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));
        self.patch_rel32_to_current(avx512_ok)?;

        // Commit XCR0, restore the complete architectural input state, and
        // force a new region at the next instruction under the new policy.
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x89);
        self.code.emit_u8(0x88);
        self.code.emit_u32(X86_GUEST_XCR0_OFFSET as u32); // mov [rax+xcr0],rcx
        self.code.emit_u8(0x5A);
        self.code.emit_u8(0x59);
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9D);
        self.emit_x86_retirement();
        self.emit_native_exit(resume_pc);

        // Every invalid path is non-committing and restarts at XSETBV.
        let fault = self.code.position();
        for branch in fault_branches {
            self.code
                .patch_i32(branch, (fault as i64 - (branch as i64 + 4)) as i32);
        }
        self.code.emit_u8(0x5A);
        self.code.emit_u8(0x59);
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9D);
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }

    pub(crate) fn emit_xsetbv_if_present(
        &mut self,
        block: &SmirBlock,
        op_index: usize,
    ) -> Result<bool, LowerError> {
        if !matches!(block.ops[op_index].kind, OpKind::X86XSetBv { .. }) {
            return Ok(false);
        }
        let resume_pc = x86_xsetbv_resume_pc(block, op_index, &self.x86_instruction_bytes)
            .ok_or_else(|| LowerError::UnsupportedOp {
                op: "X86XSetBv without exact source-derived handoff PC".to_string(),
            })?;
        self.emit_xsetbv(&block.ops[op_index], resume_pc)?;
        Ok(true)
    }
}

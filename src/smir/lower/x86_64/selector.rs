//! Fault-precise, helper-backed selector-store and selector-load lowering.

use crate::smir::ir::ops::{
    OpKind, SmirOp, X86SelectorQueryKind, X86SelectorQueryOp, X86SelectorQuerySource,
    X86SelectorVerifyKind, X86SelectorVerifyOp, X86SelectorVerifySource, X86SystemSelector,
    X86SystemSelectorLoadOp, X86SystemSelectorSource, X86SystemSelectorStoreOp,
    X86SystemSelectorTarget,
};
use crate::smir::ir::types::{Address, ArchReg, MemWidth, OpWidth, SignExtend, VReg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_APX_ENABLED_OFFSET, X86_GUEST_CPL_OFFSET, X86_GUEST_CR0_OFFSET,
    X86_GUEST_CR4_OFFSET, X86_GUEST_CS_L_OFFSET, X86_GUEST_EFER_OFFSET, X86_GUEST_RFLAGS_OFFSET,
    X86_GUEST_SYSTEM_SELECTOR_FN_OFFSET, X86_GUEST_SYSTEM_SELECTOR_LOAD_FN_OFFSET,
    X86_SELECTOR_QUERY_HELPER_APX, X86_SELECTOR_QUERY_HELPER_DST_SHIFT,
    X86_SELECTOR_QUERY_HELPER_LIMIT, X86_SELECTOR_QUERY_HELPER_MEMORY,
    X86_SELECTOR_QUERY_HELPER_TAG, X86_SELECTOR_QUERY_HELPER_WIDTH_SHIFT,
    X86_SELECTOR_VERIFY_HELPER_APX, X86_SELECTOR_VERIFY_HELPER_MEMORY,
    X86_SELECTOR_VERIFY_HELPER_TAG, X86_SELECTOR_VERIFY_HELPER_WRITE, X86_STATE_PTR_AT_RBP,
};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact direct destination emitted by the strict x86 lifter.
/// EGPR destinations and address components necessarily require REX2/APX;
/// REX2 may also encode a legacy register or address.
pub(crate) fn x86_system_selector_store_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
        selector,
        target,
        requires_apx,
    }) = &op.kind
    else {
        return false;
    };
    if op.x86_hint.is_some() {
        return false;
    }

    match target {
        X86SystemSelectorTarget::Register { dst, width } => {
            let Some(index) = (match dst {
                VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
                _ => None,
            }) else {
                return false;
            };
            matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                && (index < 16 || *requires_apx)
        }
        X86SystemSelectorTarget::Memory { addr } => {
            let uses_egpr = addr
                .regs()
                .iter()
                .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
            addr.is_x86_state_backed_shape() && (!uses_egpr || *requires_apx)
        }
        X86SystemSelectorTarget::Stack {
            stack_pointer,
            width,
        } => {
            *stack_pointer == VReg::Arch(ArchReg::X86(crate::smir::ir::types::X86Reg::Rsp))
                && matches!(width, MemWidth::B2 | MemWidth::B8)
                && matches!(selector, X86SystemSelector::Fs | X86SystemSelector::Gs)
        }
    }
}

/// Validate strict long-mode LLDT/LTR, `MOV Sreg,r/m`, and `POP FS/GS` forms
/// admitted by native lowering.
pub(crate) fn x86_system_selector_load_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
        selector,
        source,
        requires_apx,
        next_pc,
        ..
    }) = &op.kind
    else {
        return false;
    };
    let system = matches!(selector, X86SystemSelector::Ldtr | X86SystemSelector::Tr);
    let ordinary = matches!(
        selector,
        X86SystemSelector::Es
            | X86SystemSelector::Ss
            | X86SystemSelector::Ds
            | X86SystemSelector::Fs
            | X86SystemSelector::Gs
    );
    let length_valid = if system {
        matches!(next_pc.checked_sub(op.guest_pc), Some(3..=15))
    } else {
        matches!(next_pc.checked_sub(op.guest_pc), Some(2..=15))
    };
    if !(system || ordinary) || op.x86_hint.is_some() || !length_valid {
        return false;
    }

    match source {
        X86SystemSelectorSource::Register { src } => {
            let Some(index) = (match src {
                VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
                _ => None,
            }) else {
                return false;
            };
            index < 16 || *requires_apx
        }
        X86SystemSelectorSource::Memory { addr, width, .. } => {
            let uses_egpr = addr
                .regs()
                .iter()
                .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
            let width_valid = *width == MemWidth::B2 || ordinary && *width == MemWidth::B8;
            addr.is_x86_state_backed_shape() && (!uses_egpr || *requires_apx) && width_valid
        }
        X86SystemSelectorSource::Stack {
            stack_pointer,
            width,
        } => {
            let minimum_len = 2 + u64::from(*requires_apx) + u64::from(*width == MemWidth::B2);
            *stack_pointer == VReg::Arch(ArchReg::X86(crate::smir::ir::types::X86Reg::Rsp))
                && matches!(width, MemWidth::B2 | MemWidth::B8)
                && matches!(selector, X86SystemSelector::Fs | X86SystemSelector::Gs)
                && next_pc
                    .checked_sub(op.guest_pc)
                    .is_some_and(|length| (minimum_len..=15).contains(&length))
        }
        X86SystemSelectorSource::FarPointer {
            addr,
            dst,
            offset_width,
            ..
        } => {
            let uses_egpr = addr
                .regs()
                .iter()
                .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
            let Some(dst_index) = (match dst {
                VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
                _ => None,
            }) else {
                return false;
            };
            let minimum_len = 3
                + u64::from(*requires_apx)
                + u64::from(*offset_width == OpWidth::W16)
                + u64::from(*offset_width == OpWidth::W64 && !*requires_apx);
            addr.is_x86_state_backed_shape()
                && ((!uses_egpr && dst_index < 16) || *requires_apx)
                && matches!(offset_width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                && matches!(
                    selector,
                    X86SystemSelector::Ss | X86SystemSelector::Fs | X86SystemSelector::Gs
                )
                && next_pc
                    .checked_sub(op.guest_pc)
                    .is_some_and(|length| (minimum_len..=15).contains(&length))
        }
    }
}

/// Validate the exact fixed-r/m16 VERR/VERW form emitted by the strict x86
/// lifter. Every EGPR source or address requires an accompanying REX2/APX tag.
pub(crate) fn x86_selector_verify_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86SelectorVerify(X86SelectorVerifyOp {
        source,
        requires_apx,
        next_pc,
        ..
    }) = &op.kind
    else {
        return false;
    };
    if op.x86_hint.is_some() || !matches!(next_pc.checked_sub(op.guest_pc), Some(3..=15)) {
        return false;
    }

    match source {
        X86SelectorVerifySource::Register { src } => {
            let Some(index) = (match src {
                VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
                _ => None,
            }) else {
                return false;
            };
            index < 16 || *requires_apx
        }
        X86SelectorVerifySource::Memory { addr, .. } => {
            let uses_egpr = addr
                .regs()
                .iter()
                .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
            addr.is_x86_state_backed_shape() && (!uses_egpr || *requires_apx)
        }
    }
}

/// Validate the exact LAR/LSL form emitted by the strict x86 lifter. The
/// destination is conditionally written, so its previous value remains an
/// explicit source in optimizer liveness even for 32-/64-bit forms.
pub(crate) fn x86_selector_query_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86SelectorQuery(X86SelectorQueryOp {
        dst,
        source,
        width,
        requires_apx,
        next_pc,
        ..
    }) = &op.kind
    else {
        return false;
    };
    let minimum_len = if *requires_apx {
        4 + u64::from(*width == OpWidth::W16)
    } else {
        3 + u64::from(*width != OpWidth::W32)
    };
    if op.x86_hint.is_some()
        || !matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        || !next_pc
            .checked_sub(op.guest_pc)
            .is_some_and(|length| (minimum_len..=15).contains(&length))
    {
        return false;
    }
    let Some(dst_index) = (match dst {
        VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
        _ => None,
    }) else {
        return false;
    };
    if dst_index >= 16 && !*requires_apx {
        return false;
    }

    match source {
        X86SelectorQuerySource::Register { src } => {
            let Some(src_index) = (match src {
                VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
                _ => None,
            }) else {
                return false;
            };
            src_index < 16 || *requires_apx
        }
        X86SelectorQuerySource::Memory { addr, .. } => {
            let uses_egpr = addr
                .regs()
                .iter()
                .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
            addr.is_x86_state_backed_shape() && (!uses_egpr || *requires_apx)
        }
    }
}

impl X86_64Lowerer {
    /// Emit APX and selector-specific checks while RAX is the live `GuestRegs`
    /// base. SLDT/STR require protected-mode, VM86, and UMIP checks; PUSH FS/GS
    /// requires EFER.LMA and CS.L; MOV r/m,Sreg has no mode guard. Every REX2
    /// form requires APX, and every failure replays the direct instruction at
    /// its original PC.
    fn emit_x86_system_selector_store_guards(
        &mut self,
        selector: X86SystemSelector,
        requires_apx: bool,
        stack_width: Option<MemWidth>,
    ) -> (Vec<usize>, Vec<usize>) {
        let mut fault_branches = Vec::with_capacity(9);
        let mut commit_branches = Vec::with_capacity(1);

        if requires_apx {
            self.code.emit_bytes(&[0x83, 0xB8]); // cmp dword [rax+apx],0
            self.code.emit_u32(X86_GUEST_APX_ENABLED_OFFSET as u32);
            self.code.emit_u8(0);
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));
        }

        if let Some(width) = stack_width {
            let range_tail = match width {
                MemWidth::B2 => 1,
                MemWidth::B8 => 7,
                _ => unreachable!("validated PUSH-segment width changed"),
            };
            self.code.emit_bytes(&[0x48, 0xF7, 0x80]); // test qword [rax+efer],LMA
            self.code.emit_u32(X86_GUEST_EFER_OFFSET as u32);
            self.code.emit_u32(1 << 10);
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));

            self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cs_l],0
            self.code.emit_u32(X86_GUEST_CS_L_OFFSET as u32);
            self.code.emit_u8(0);
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));

            // Compute the complete post-decrement stack range from the
            // state-backed RSP. Every byte must remain within one canonical
            // 48-bit region, and the range must not wrap through 2^64. These
            // checks precede selector observation and the generic MMU helper;
            // the latter intentionally reports only success/failure and cannot
            // by itself preserve the architectural #SS(0) classification.
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rax, 4 * 8, OpWidth::W64);
                emitter.emit_lea(PhysReg::Rdx, PhysReg::Rdx, -(width.bytes() as i32));
            }
            self.code.emit_bytes(&[
                0x48, 0x89, 0xD1, // mov rcx,rdx
                0x48, 0xC1, 0xE1, 0x10, // shl rcx,16
                0x48, 0xC1, 0xF9, 0x10, // sar rcx,16
                0x48, 0x39, 0xD1, // cmp rcx,rdx
            ]);
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));

            self.code.emit_bytes(&[
                0x48, 0x89, 0xD1, // mov rcx,rdx
                0x48, 0x83, 0xC1, // add rcx,imm8
                range_tail,
            ]);
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::B));
            self.code.emit_bytes(&[
                0x48, 0x89, 0xCA, // mov rdx,rcx
                0x48, 0xC1, 0xE2, 0x10, // shl rdx,16
                0x48, 0xC1, 0xFA, 0x10, // sar rdx,16
                0x48, 0x39, 0xCA, // cmp rdx,rcx
            ]);
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));
        }

        if !matches!(selector, X86SystemSelector::Ldtr | X86SystemSelector::Tr) {
            return (fault_branches, commit_branches);
        }

        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],PE
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));

        self.code.emit_bytes(&[0x48, 0xF7, 0x80]); // test qword [rax+rflags],VM
        self.code.emit_u32(X86_GUEST_RFLAGS_OFFSET as u32);
        self.code
            .emit_u32(crate::isa::x86_64::flags::bits::VM as u32);
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));

        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr4],UMIP
        self.code.emit_u32(X86_GUEST_CR4_OFFSET as u32);
        self.code.emit_u32(1 << 11);
        commit_branches.push(self.emit_jcc_placeholder(X86Cond::E));

        self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cpl],0
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0);
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));

        (fault_branches, commit_branches)
    }

    /// Read the selected guest-visible selector through the owning-vCPU helper
    /// and commit the encoded GPR width, one exact 2-byte ordinary store, or a
    /// fault-precise long-mode stack store. Host selector instructions are
    /// never emitted because they would observe host state rather than the
    /// guest vCPU.
    pub(crate) fn emit_x86_system_selector_store(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86SystemSelectorStore requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_system_selector_store_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86SystemSelectorStore".to_string(),
                operand: "requires an unhinted W16/W32/W64 x86 GPR, state-backed memory, or FS/GS long-mode stack target, with APX for every EGPR"
                    .to_string(),
            });
        }
        let OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
            selector,
            target,
            requires_apx,
        }) = &op.kind
        else {
            unreachable!("validated X86SystemSelectorStore shape changed")
        };
        let memory_target = matches!(
            target,
            X86SystemSelectorTarget::Memory { .. } | X86SystemSelectorTarget::Stack { .. }
        );
        if memory_target && !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "x86 selector-store memory destination requires JIT MMU helpers".to_string(),
            });
        }

        // A memory-writing form owns one aligned 16-byte value slot across its
        // selector and MMU helper calls. The slot does not alter SysV call
        // alignment.
        if memory_target {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }

        // Publish every identity-mapped GPR before borrowing ABI registers.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        let stack_width = match target {
            X86SystemSelectorTarget::Stack { width, .. } => Some(*width),
            _ => None,
        };
        let (fault_branches, commit_branches) =
            self.emit_x86_system_selector_store_guards(*selector, *requires_apx, stack_width);
        for branch in commit_branches {
            self.patch_rel32_to_current(branch)?;
        }

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(
                PhysReg::Rsi,
                match selector {
                    X86SystemSelector::Ldtr => 0,
                    X86SystemSelector::Tr => 1,
                    X86SystemSelector::Es => 2,
                    X86SystemSelector::Cs => 3,
                    X86SystemSelector::Ss => 4,
                    X86SystemSelector::Ds => 5,
                    X86SystemSelector::Fs => 6,
                    X86SystemSelector::Gs => 7,
                },
                OpWidth::W32,
            );
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_SYSTEM_SELECTOR_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);

        match target {
            X86SystemSelectorTarget::Register { dst, width } => {
                let destination = match dst {
                    VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index().unwrap(),
                    _ => unreachable!("validated selector-store destination changed"),
                };
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    // The helper returns the selector in RAX, while the shared
                    // state-slot writer uses RAX as its fixed GuestRegs base.
                    // Preserve the value in RDX and restore that base from RCX
                    // before committing the encoded partial/full GPR width.
                    emitter.emit_mov_rr(PhysReg::Rdx, PhysReg::Rax, OpWidth::W64);
                    emitter.emit_mov_rr(PhysReg::Rax, PhysReg::Rcx, OpWidth::W64);
                }
                self.emit_store_gpr_slot_from_reg(destination, PhysReg::Rdx, *width)?;
                if destination == 5 {
                    self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
                }
                self.emit_reload_all(PhysReg::Rcx);
                self.code.emit_u8(0x9D); // popfq
                self.emit_flag_preserving_stack_pop8();
            }
            X86SystemSelectorTarget::Memory { addr } => {
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    // Two snapshots precede the outer selector slot.
                    emitter.emit_mov_mr(PhysReg::Rsp, 16, PhysReg::Rax, OpWidth::W64);
                }
                self.emit_reload_all(PhysReg::Rcx);
                self.code.emit_u8(0x9D);
                self.emit_flag_preserving_stack_pop8();

                self.emit_jit_mem_op(
                    op.guest_pc,
                    false,
                    None,
                    None,
                    None,
                    None,
                    Some(16),
                    addr,
                    MemWidth::B2,
                    SignExtend::Zero,
                    16,
                )?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
            }
            X86SystemSelectorTarget::Stack {
                stack_pointer,
                width,
            } => {
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    // Two snapshots precede the outer selector slot.
                    emitter.emit_mov_mr(PhysReg::Rsp, 16, PhysReg::Rax, OpWidth::W64);
                }
                self.emit_reload_all(PhysReg::Rcx);
                self.code.emit_u8(0x9D);
                self.emit_flag_preserving_stack_pop8();

                let stack_addr = Address::base_off(*stack_pointer, -(i64::from(width.bytes())));
                self.emit_jit_mem_op(
                    op.guest_pc,
                    false,
                    None,
                    None,
                    None,
                    None,
                    Some(16),
                    &stack_addr,
                    *width,
                    SignExtend::Zero,
                    16,
                )?;

                // The MMU write succeeded. Commit GuestRegs.gpr[RSP] without
                // changing guest flags or any identity-mapped guest GPR.
                self.code.emit_u8(0x50); // push guest RAX
                self.code.emit_u8(0x52); // push guest RDX
                self.emit_load_state_ptr_rax();
                self.emit_struct_mov(PhysReg::Rax, 2, 4 * 8, false);
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_lea(PhysReg::Rdx, PhysReg::Rdx, -(width.bytes() as i32));
                }
                self.emit_struct_mov(PhysReg::Rax, 2, 4 * 8, true);
                self.code.emit_u8(0x5A); // pop guest RDX
                self.code.emit_u8(0x58); // pop guest RAX

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
            }
        }

        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        // Guard failures precede both selector observation and destination
        // commit. Restore the exact pre-instruction image and replay direct.
        for branch in fault_branches {
            self.patch_rel32_to_current(branch)?;
        }
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        if memory_target {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.emit_native_exit(op.guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }

    /// Load LDTR/TR or an ordinary segment register through the owning vCPU's
    /// MMU and descriptor validator. POP FS/GS also commits its RSP increment,
    /// and LSS/LFS/LGS their width-tagged GPR, only after the selector load
    /// succeeds. Every variant exits natively after a successful commit;
    /// LLDT/LTR additionally serialize. Every dynamic guard, source-memory,
    /// descriptor, or implicit descriptor-store fault restores the complete
    /// pre-instruction register/flag image and replays direct at `guest_pc`.
    pub(crate) fn emit_x86_system_selector_load(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86SystemSelectorLoad requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86SystemSelectorLoad requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_system_selector_load_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86SystemSelectorLoad".to_string(),
                operand: "requires an unhinted LLDT/LTR, MOV-Sreg, POP-FS/GS, or LSS/LFS/LGS source; valid widths; APX for every EGPR; and an exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86SystemSelectorLoad(load) = &op.kind else {
            unreachable!("validated X86SystemSelectorLoad shape changed")
        };

        // Publish every identity-mapped GPR before borrowing ABI registers.
        // The two pushes preserve guest flags and maintain SysV call alignment.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        let mut guard_faults = Vec::with_capacity(4);
        if load.requires_apx {
            self.code.emit_bytes(&[0x83, 0xB8]); // cmp dword [rax+apx],0
            self.code.emit_u32(X86_GUEST_APX_ENABLED_OFFSET as u32);
            self.code.emit_u8(0);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
        }
        if matches!(
            load.selector,
            X86SystemSelector::Ldtr | X86SystemSelector::Tr
        ) {
            self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],PE
            self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
            self.code.emit_u32(1);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
            self.code.emit_bytes(&[0x48, 0xF7, 0x80]); // test qword [rax+rflags],VM
            self.code.emit_u32(X86_GUEST_RFLAGS_OFFSET as u32);
            self.code
                .emit_u32(crate::isa::x86_64::flags::bits::VM as u32);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::Ne));
            self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cpl],0
            self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
            self.code.emit_u8(0);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::Ne));
        }
        let stack_width = match &load.source {
            X86SystemSelectorSource::Stack { width, .. } => Some(*width),
            _ => None,
        };
        let far_pointer = match &load.source {
            X86SystemSelectorSource::FarPointer {
                dst, offset_width, ..
            } => Some((*dst, *offset_width)),
            _ => None,
        };
        if far_pointer.is_some() {
            self.code.emit_bytes(&[0x48, 0xF7, 0x80]); // test qword [rax+efer],LMA
            self.code.emit_u32(X86_GUEST_EFER_OFFSET as u32);
            self.code.emit_u32(1 << 10);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
            self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cs_l],0
            self.code.emit_u32(X86_GUEST_CS_L_OFFSET as u32);
            self.code.emit_u8(0);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
        }
        if let Some(width) = stack_width {
            let range_tail = match width {
                MemWidth::B2 => 1,
                MemWidth::B8 => 7,
                _ => unreachable!("validated POP-segment width changed"),
            };
            self.code.emit_bytes(&[0x48, 0xF7, 0x80]); // test qword [rax+efer],LMA
            self.code.emit_u32(X86_GUEST_EFER_OFFSET as u32);
            self.code.emit_u32(1 << 10);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
            self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cs_l],0
            self.code.emit_u32(X86_GUEST_CS_L_OFFSET as u32);
            self.code.emit_u8(0);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));

            // Validate the complete pre-increment source range before the
            // helper can observe memory. This preserves #SS(0) and excludes a
            // 2^64 wrap even when the owning MMU has paging disabled.
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rax, 4 * 8, OpWidth::W64);
            }
            self.code.emit_bytes(&[
                0x48, 0x89, 0xD1, // mov rcx,rdx
                0x48, 0xC1, 0xE1, 0x10, // shl rcx,16
                0x48, 0xC1, 0xF9, 0x10, // sar rcx,16
                0x48, 0x39, 0xD1, // cmp rcx,rdx
            ]);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::Ne));
            self.code.emit_bytes(&[
                0x48, 0x89, 0xD1, // mov rcx,rdx
                0x48, 0x83, 0xC1, // add rcx,imm8
                range_tail,
            ]);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::B));
            self.code.emit_bytes(&[
                0x48, 0x89, 0xCA, // mov rdx,rcx
                0x48, 0xC1, 0xE2, 0x10, // shl rdx,16
                0x48, 0xC1, 0xFA, 0x10, // sar rdx,16
                0x48, 0x39, 0xCA, // cmp rdx,rcx
            ]);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::Ne));
        }

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        let memory_source = matches!(
            &load.source,
            X86SystemSelectorSource::Memory { .. }
                | X86SystemSelectorSource::Stack { .. }
                | X86SystemSelectorSource::FarPointer { .. }
        );
        match &load.source {
            X86SystemSelectorSource::Register { src } => {
                let VReg::Arch(ArchReg::X86(reg)) = src else {
                    unreachable!("validated selector-load register source changed")
                };
                self.emit_struct_mov(
                    PhysReg::Rax,
                    6,
                    i32::from(reg.gpr_index().unwrap()) * 8,
                    false,
                );
            }
            X86SystemSelectorSource::Memory { addr, .. } => {
                self.emit_jit_mem_effective_address(addr, false)?;
            }
            X86SystemSelectorSource::Stack { .. } => {
                self.emit_struct_mov(PhysReg::Rax, 6, 4 * 8, false);
            }
            X86SystemSelectorSource::FarPointer { addr, .. } => {
                self.emit_jit_mem_effective_address(addr, false)?;
            }
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            let selector = match load.selector {
                X86SystemSelector::Ldtr => 0,
                X86SystemSelector::Tr => 1,
                X86SystemSelector::Es => 2,
                X86SystemSelector::Ss => 4,
                X86SystemSelector::Ds => 5,
                X86SystemSelector::Fs => 6,
                X86SystemSelector::Gs => 7,
                X86SystemSelector::Cs => unreachable!("validated selector-load kind changed"),
            };
            let memory64 = matches!(
                load.source,
                X86SystemSelectorSource::Memory {
                    width: MemWidth::B8,
                    ..
                } | X86SystemSelectorSource::Stack {
                    width: MemWidth::B8,
                    ..
                }
            );
            let stack_source = matches!(load.source, X86SystemSelectorSource::Stack { .. });
            let (far_pointer_source, far_dst, far_width) = match far_pointer {
                Some((VReg::Arch(ArchReg::X86(dst)), width)) => {
                    let width_code = match width {
                        OpWidth::W16 => 0_i64,
                        OpWidth::W32 => 1,
                        OpWidth::W64 => 2,
                        _ => unreachable!("validated far-pointer width changed"),
                    };
                    (1_i64, i64::from(dst.gpr_index().unwrap()), width_code)
                }
                Some(_) => unreachable!("validated far-pointer destination changed"),
                None => (0, 0, 0),
            };
            let encoding = i64::from(memory_source)
                | (i64::from(load.requires_apx) << 1)
                | (selector << 2)
                | (i64::from(memory64) << 5)
                | (i64::from(stack_source) << 6)
                | (far_pointer_source << 7)
                | (far_dst << 8)
                | (far_width << 13);
            emitter.emit_mov_ri(PhysReg::Rdx, encoding, OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_SYSTEM_SELECTOR_LOAD_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let helper_fault = self.emit_jcc_placeholder(X86Cond::E);

        if let Some(width) = stack_width {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rcx, 4 * 8, OpWidth::W64);
            emitter.emit_lea(PhysReg::Rax, PhysReg::Rax, width.bytes() as i32);
            emitter.emit_mov_mr(PhysReg::Rcx, 4 * 8, PhysReg::Rax, OpWidth::W64);
        }
        if matches!(
            load.selector,
            X86SystemSelector::Ldtr | X86SystemSelector::Tr
        ) {
            self.emit_x86_serialize();
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        self.emit_x86_retirement();
        self.emit_native_exit(load.next_pc);

        for branch in guard_faults {
            self.patch_rel32_to_current(branch)?;
        }
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }

    /// Execute VERR/VERW through the owning-vCPU descriptor helper. The helper
    /// returns zero for precise replay, one for a completed ZF=0 verification,
    /// and two for a completed ZF=1 verification. Native success patches only
    /// the saved ZF bit and continues within the current region.
    pub(crate) fn emit_x86_selector_verify(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86SelectorVerify requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86SelectorVerify requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_selector_verify_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86SelectorVerify".to_string(),
                operand: "requires an unhinted fixed-width x86 GPR or state-backed memory source, APX for every EGPR, and an exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86SelectorVerify(verify) = &op.kind else {
            unreachable!("validated X86SelectorVerify shape changed")
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; guest RAX is at [rsp+8]
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        let mut guard_faults = Vec::with_capacity(3);
        if verify.requires_apx {
            self.code.emit_bytes(&[0x83, 0xB8]); // cmp dword [rax+apx],0
            self.code.emit_u32(X86_GUEST_APX_ENABLED_OFFSET as u32);
            self.code.emit_u8(0);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
        }
        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],PE
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
        self.code.emit_bytes(&[0x48, 0xF7, 0x80]); // test qword [rax+rflags],VM
        self.code.emit_u32(X86_GUEST_RFLAGS_OFFSET as u32);
        self.code
            .emit_u32(crate::isa::x86_64::flags::bits::VM as u32);
        guard_faults.push(self.emit_jcc_placeholder(X86Cond::Ne));

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        match &verify.source {
            X86SelectorVerifySource::Register { src } => {
                let VReg::Arch(ArchReg::X86(reg)) = src else {
                    unreachable!("validated selector-verify register source changed")
                };
                self.emit_struct_mov(
                    PhysReg::Rax,
                    6,
                    i32::from(reg.gpr_index().unwrap()) * 8,
                    false,
                );
            }
            X86SelectorVerifySource::Memory { addr, .. } => {
                self.emit_jit_mem_effective_address(addr, false)?;
            }
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            let mut encoding = X86_SELECTOR_VERIFY_HELPER_TAG;
            if matches!(&verify.source, X86SelectorVerifySource::Memory { .. }) {
                encoding |= X86_SELECTOR_VERIFY_HELPER_MEMORY;
            }
            if verify.requires_apx {
                encoding |= X86_SELECTOR_VERIFY_HELPER_APX;
            }
            if verify.kind == X86SelectorVerifyKind::Write {
                encoding |= X86_SELECTOR_VERIFY_HELPER_WRITE;
            }
            emitter.emit_mov_ri(PhysReg::Rdx, i64::from(encoding), OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_SYSTEM_SELECTOR_LOAD_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let helper_fault = self.emit_jcc_placeholder(X86Cond::E);

        // Clear only saved ZF, then set it exactly when the helper returned 2.
        self.code
            .emit_bytes(&[0x48, 0x81, 0x24, 0x24, 0xBF, 0xFF, 0xFF, 0xFF]);
        self.code.emit_bytes(&[0x83, 0xF8, 0x02]); // cmp eax,2
        let zf_clear = self.emit_jcc_placeholder(X86Cond::Ne);
        self.code.emit_bytes(&[0x48, 0x83, 0x0C, 0x24, 0x40]); // or qword [rsp],ZF
        self.patch_rel32_to_current(zf_clear)?;

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq: commits the patched ZF only
        self.emit_flag_preserving_stack_pop8();
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        for branch in guard_faults {
            self.patch_rel32_to_current(branch)?;
        }
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }

    /// Execute LAR/LSL through the owning-vCPU descriptor helper. The helper
    /// updates the marshalled destination only on success and returns zero for
    /// replay, one for completed ZF=0, or two for completed ZF=1. Native code
    /// patches only saved ZF and continues within the current region.
    pub(crate) fn emit_x86_selector_query(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86SelectorQuery requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86SelectorQuery requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_selector_query_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86SelectorQuery".to_string(),
                operand: "requires an unhinted width-tagged x86 GPR destination, fixed-width x86 GPR or state-backed memory source, APX for every EGPR, and an exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86SelectorQuery(query) = &op.kind else {
            unreachable!("validated X86SelectorQuery shape changed")
        };
        let VReg::Arch(ArchReg::X86(dst)) = query.dst else {
            unreachable!("validated selector-query destination changed")
        };
        let dst_index = dst
            .gpr_index()
            .expect("validated selector-query GPR destination changed");
        let width_code = match query.width {
            OpWidth::W16 => 0,
            OpWidth::W32 => 1,
            OpWidth::W64 => 2,
            _ => unreachable!("validated selector-query width changed"),
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; guest RAX is at [rsp+8]
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        let mut guard_faults = Vec::with_capacity(3);
        if query.requires_apx {
            self.code.emit_bytes(&[0x83, 0xB8]); // cmp dword [rax+apx],0
            self.code.emit_u32(X86_GUEST_APX_ENABLED_OFFSET as u32);
            self.code.emit_u8(0);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
        }
        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],PE
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
        self.code.emit_bytes(&[0x48, 0xF7, 0x80]); // test qword [rax+rflags],VM
        self.code.emit_u32(X86_GUEST_RFLAGS_OFFSET as u32);
        self.code
            .emit_u32(crate::isa::x86_64::flags::bits::VM as u32);
        guard_faults.push(self.emit_jcc_placeholder(X86Cond::Ne));

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        match &query.source {
            X86SelectorQuerySource::Register { src } => {
                let VReg::Arch(ArchReg::X86(reg)) = src else {
                    unreachable!("validated selector-query register source changed")
                };
                self.emit_struct_mov(
                    PhysReg::Rax,
                    6,
                    i32::from(reg.gpr_index().unwrap()) * 8,
                    false,
                );
            }
            X86SelectorQuerySource::Memory { addr, .. } => {
                self.emit_jit_mem_effective_address(addr, false)?;
            }
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            let mut encoding = X86_SELECTOR_QUERY_HELPER_TAG
                | (u32::from(dst_index) << X86_SELECTOR_QUERY_HELPER_DST_SHIFT)
                | (width_code << X86_SELECTOR_QUERY_HELPER_WIDTH_SHIFT);
            if matches!(&query.source, X86SelectorQuerySource::Memory { .. }) {
                encoding |= X86_SELECTOR_QUERY_HELPER_MEMORY;
            }
            if query.requires_apx {
                encoding |= X86_SELECTOR_QUERY_HELPER_APX;
            }
            if query.kind == X86SelectorQueryKind::Limit {
                encoding |= X86_SELECTOR_QUERY_HELPER_LIMIT;
            }
            emitter.emit_mov_ri(PhysReg::Rdx, i64::from(encoding), OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_SYSTEM_SELECTOR_LOAD_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let helper_fault = self.emit_jcc_placeholder(X86Cond::E);

        self.code
            .emit_bytes(&[0x48, 0x81, 0x24, 0x24, 0xBF, 0xFF, 0xFF, 0xFF]);
        self.code.emit_bytes(&[0x83, 0xF8, 0x02]); // cmp eax,2
        let zf_clear = self.emit_jcc_placeholder(X86Cond::Ne);
        self.code.emit_bytes(&[0x48, 0x83, 0x0C, 0x24, 0x40]); // or qword [rsp],ZF
        self.patch_rel32_to_current(zf_clear)?;

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        if dst_index == 5 {
            self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
        }
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq: commits the patched ZF only
        self.emit_flag_preserving_stack_pop8();
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        for branch in guard_faults {
            self.patch_rel32_to_current(branch)?;
        }
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }
}
